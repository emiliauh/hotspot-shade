import Foundation
import Darwin

// One root-owned state directory and the small set of durable file operations
// the helper needs. The directory is created with mode 0700, owned by root, and
// verified through an open descriptor before any file operation. The parent
// directory is synced after the first create so the new directory entry itself
// is durable. Every file create, write, and removal syncs the file and the
// containing directory before the caller treats the change as complete.
//
// An extended ACL is never accepted on the state directory or on a state file.
// A mode bit alone is not the whole permission story: an ACL can grant another
// account access that the mode does not show. A failed ACL read is an error,
// not "no ACL". The helper refuses instead of guessing that the object is safe.
//
// The helper writes two files here. `cleanup-blocked` is append-only and never
// removed automatically. `engine-session` is the write-ahead launch intent and
// the durable helper start record; it is removed only after a verified clean
// engine stop. Every file fails closed when the directory or file is a symlink,
// has another owner, or is readable by a group or another account.
// `start-exclusion` is the helper and engine lock file: the helper never
// removes or replaces it. The installer coordinator holds a transition set and
// the canonical name and migration remain open, so the sides are not aligned
// yet. `install-journal.json` belongs to the installer coordinator; the helper
// only checks whether it is present.
enum RootStateDirectoryError: Error, Equatable {
    case unsafe
    case unreadable
    case writeFailed
    case alreadyPresent
    // A create failed after the name existed, and the rollback could not
    // prove that the record is gone. The object may remain, its removal may
    // not be durable, or it may no longer be the one this call created. The
    // caller must keep the start gate closed instead of retrying.
    case createRollbackUncertain
}

// A narrow seam for deterministic tests of the create-failure rollback. The
// production value uses the real write and sync calls and no callback. A test
// forces one failure after the file exists and can replace, link, or annotate
// the record before the rollback decides. The seam is internal and never used
// by production code. Production stores the immutable `production` value; the
// test closures run on one test thread and never cross a concurrency domain.
struct RootStateDirectorySeam: @unchecked Sendable {
    var writeAll: (Int32, [UInt8]) throws -> Void
    var syncFile: (Int32) -> Int32
    var syncDirectory: (Int32) -> Int32
    var beforeRollback: ((String) -> Void)?

    static let production = RootStateDirectorySeam(
        writeAll: { descriptor, bytes in
            try RootStateDirectory.writeAll(descriptor, bytes: bytes)
        },
        syncFile: { fsync($0) },
        syncDirectory: { fsync($0) },
        beforeRollback: nil
    )
}

struct RootStateDirectory {
    let path: String
    let expectedOwner: UInt32
    var seam: RootStateDirectorySeam = .production

    // Create the directory when it is missing and make the new entry durable.
    // A directory that already exists is left alone; only its ownership and
    // mode are checked.
    func ensure() throws {
        var status = stat()
        if lstat(path, &status) == 0 {
            guard Self.isSafeDirectory(status, expectedOwner: expectedOwner) else {
                throw RootStateDirectoryError.unsafe
            }
            try verifyOpenedDirectory()
            return
        }
        guard errno == ENOENT else { throw RootStateDirectoryError.unreadable }
        if mkdir(path, mode_t(0o700)) != 0 {
            guard errno == EEXIST else { throw RootStateDirectoryError.writeFailed }
        } else {
            try Self.fsyncParentDirectory(of: path)
        }
        guard lstat(path, &status) == 0,
              Self.isSafeDirectory(status, expectedOwner: expectedOwner)
        else {
            throw RootStateDirectoryError.unsafe
        }
        try verifyOpenedDirectory()
    }

    private func verifyOpenedDirectory() throws {
        let descriptor = Darwin.open(
            path,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK
        )
        guard descriptor >= 0 else { throw RootStateDirectoryError.unreadable }
        defer { close(descriptor) }
        try Self.verifySafeDirectory(descriptor, expectedOwner: expectedOwner)
    }

    // Open an existing directory, or return nil when it is absent. An absent
    // state directory means no helper state exists yet. Any other error is
    // returned to the caller, which treats it as blocked.
    func openIfPresent() throws -> Int32? {
        let descriptor = Darwin.open(
            path,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK
        )
        guard descriptor >= 0 else {
            if errno == ENOENT { return nil }
            throw RootStateDirectoryError.unreadable
        }
        do {
            try Self.verifySafeDirectory(descriptor, expectedOwner: expectedOwner)
        } catch {
            close(descriptor)
            throw error
        }
        return descriptor
    }

    func openExisting() throws -> Int32 {
        guard let descriptor = try openIfPresent() else {
            throw RootStateDirectoryError.unreadable
        }
        return descriptor
    }

    // True when a safe file with this name exists. A missing directory or file
    // is false. A symlink, a non-regular object, another owner, or a group or
    // other permission is unsafe, not false.
    func contains(_ name: String) throws -> Bool {
        guard let directory = try openIfPresent() else { return false }
        defer { close(directory) }
        return try contains(name, in: directory)
    }

    private func contains(_ name: String, in directory: Int32) throws -> Bool {
        var status = stat()
        guard fstatat(directory, name, &status, AT_SYMLINK_NOFOLLOW) == 0 else {
            if errno == ENOENT { return false }
            throw RootStateDirectoryError.unreadable
        }
        guard Self.isSafeFile(status, expectedOwner: expectedOwner) else {
            throw RootStateDirectoryError.unsafe
        }
        let descriptor = openat(
            directory,
            name,
            O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK
        )
        guard descriptor >= 0 else { throw RootStateDirectoryError.unreadable }
        defer { close(descriptor) }
        var opened = stat()
        guard fstat(descriptor, &opened) == 0,
              Self.isSafeFile(opened, expectedOwner: expectedOwner),
              opened.st_dev == status.st_dev,
              opened.st_ino == status.st_ino
        else {
            throw RootStateDirectoryError.unsafe
        }
        if try Self.hasExtendedACL(descriptor) {
            throw RootStateDirectoryError.unsafe
        }
        return true
    }

    // Create one new file with O_EXCL and make both its data and its directory
    // entry durable. A partial file from a failed write is removed again only
    // when its identity is still the inode this call created, it has one link,
    // it has no extended ACL, and the unlink is synced. Any other state is kept
    // as ambiguous evidence and reported as an uncertain create. A file that
    // already exists is never replaced, because the caller cannot prove that
    // the old file is stale.
    func createFile(_ name: String, contents: [UInt8]) throws {
        try ensure()
        let directory = try openExisting()
        defer { close(directory) }

        let descriptor = openat(
            directory,
            name,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK,
            mode_t(0o600)
        )
        guard descriptor >= 0 else {
            if errno == EEXIST { throw RootStateDirectoryError.alreadyPresent }
            throw RootStateDirectoryError.writeFailed
        }
        defer { close(descriptor) }

        do {
            var status = stat()
            guard fstat(descriptor, &status) == 0,
                  Self.isSafeFile(status, expectedOwner: expectedOwner),
                  status.st_nlink == 1
            else {
                throw RootStateDirectoryError.unsafe
            }
            if try Self.hasExtendedACL(descriptor) {
                throw RootStateDirectoryError.unsafe
            }
            try seam.writeAll(descriptor, contents)
            guard seam.syncFile(descriptor) == 0 else {
                throw RootStateDirectoryError.writeFailed
            }
            guard seam.syncDirectory(directory) == 0 else {
                throw RootStateDirectoryError.writeFailed
            }
        } catch {
            switch rollbackCreatedFile(
                name,
                directory: directory,
                descriptor: descriptor,
                seam: seam
            ) {
            case .removed:
                throw error
            case .retainedForeignRecord:
                // The name now reaches a different inode, most likely another
                // participant's record. Keep it and report a present record so
                // the caller refuses and re-reads it later.
                throw RootStateDirectoryError.alreadyPresent
            case .uncertain:
                throw RootStateDirectoryError.createRollbackUncertain
            }
        }
    }

    private enum CreateRollback {
        // The record this call created is provably gone and the removal is
        // synced.
        case removed
        // The name reaches a different inode. Another participant likely
        // replaced the record, so it is kept and re-read by the caller.
        case retainedForeignRecord
        // The object changed, gained a hard link or an ACL, cannot be read, or
        // its removal could not be synced. Nothing is deleted.
        case uncertain
    }

    // Roll back one failed create without trusting the name alone. The unlink
    // is allowed only after the held descriptor and the name both prove the
    // same regular file, with one link and no extended ACL, and the directory
    // sync succeeds. macOS has no unlink-by-inode call, so a cooperative root
    // participant is still assumed: another process that swaps the name
    // between the final check and the unlink cannot be stopped by this code.
    // When the proof is incomplete, the record is kept.
    private func rollbackCreatedFile(
        _ name: String,
        directory: Int32,
        descriptor: Int32,
        seam: RootStateDirectorySeam
    ) -> CreateRollback {
        seam.beforeRollback?(name)

        var held = stat()
        guard fstat(descriptor, &held) == 0,
              Self.isSafeFile(held, expectedOwner: expectedOwner),
              held.st_nlink == 1
        else {
            return .uncertain
        }
        do {
            guard try !Self.hasExtendedACL(descriptor) else { return .uncertain }
        } catch {
            return .uncertain
        }

        let named = name.withCString { pointer in
            openat(
                directory,
                pointer,
                O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK
            )
        }
        guard named >= 0 else {
            // ENOENT means the name is already absent, so no record of this
            // name remains to remove. Any other failure is not proof.
            return errno == ENOENT ? .removed : .uncertain
        }
        defer { close(named) }

        var opened = stat()
        guard fstat(named, &opened) == 0 else { return .uncertain }
        guard opened.st_dev == held.st_dev, opened.st_ino == held.st_ino else {
            return .retainedForeignRecord
        }
        guard Self.isSafeFile(opened, expectedOwner: expectedOwner),
              opened.st_nlink == 1
        else {
            return .uncertain
        }
        do {
            guard try !Self.hasExtendedACL(named) else { return .uncertain }
        } catch {
            return .uncertain
        }

        guard unlinkat(directory, name, 0) == 0 else {
            return errno == ENOENT ? .removed : .uncertain
        }
        guard seam.syncDirectory(directory) == 0 else {
            // The live directory no longer lists the record, but the removal
            // may not survive a crash. The caller must stay blocked.
            return .uncertain
        }
        return .removed
    }

    // Remove one safe file and make the removal durable. A missing file is
    // already clean. A symlink, a hard-linked record, or any other unsafe
    // object is refused instead of removed. The held descriptor and the name
    // must reach the same one-link inode, and the directory sync must succeed
    // before the caller treats the removal as complete.
    func removeFile(_ name: String) throws {
        guard let directory = try openIfPresent() else { return }
        defer { close(directory) }

        var status = stat()
        guard fstatat(directory, name, &status, AT_SYMLINK_NOFOLLOW) == 0 else {
            if errno == ENOENT { return }
            throw RootStateDirectoryError.unreadable
        }
        guard Self.isSafeFile(status, expectedOwner: expectedOwner),
              status.st_nlink == 1
        else {
            throw RootStateDirectoryError.unsafe
        }
        let descriptor = openat(
            directory,
            name,
            O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK
        )
        guard descriptor >= 0 else { throw RootStateDirectoryError.unreadable }
        defer { close(descriptor) }
        var opened = stat()
        guard fstat(descriptor, &opened) == 0,
              Self.isSafeFile(opened, expectedOwner: expectedOwner),
              opened.st_dev == status.st_dev,
              opened.st_ino == status.st_ino,
              opened.st_nlink == 1
        else {
            throw RootStateDirectoryError.unsafe
        }
        guard try !Self.hasExtendedACL(descriptor) else {
            throw RootStateDirectoryError.unsafe
        }
        guard unlinkat(directory, name, 0) == 0 else {
            if errno == ENOENT { return }
            throw RootStateDirectoryError.writeFailed
        }
        guard fsync(directory) == 0 else { throw RootStateDirectoryError.writeFailed }
    }

    fileprivate static func writeAll(_ descriptor: Int32, bytes: [UInt8]) throws {
        var sent = 0
        while sent < bytes.count {
            let written = bytes.withUnsafeBytes { buffer -> Int in
                guard let base = buffer.baseAddress else { return 0 }
                return write(descriptor, base.advanced(by: sent), bytes.count - sent)
            }
            if written > 0 {
                sent += written
                continue
            }
            if written < 0 && errno == EINTR { continue }
            throw RootStateDirectoryError.writeFailed
        }
    }

    // The directory entry for a newly created state directory is not durable
    // until the parent is synced. `/var/db` and the test roots already exist;
    // the helper creates only one level.
    private static func fsyncParentDirectory(of path: String) throws {
        let parent = (path as NSString).deletingLastPathComponent
        let parentPath = parent.isEmpty ? "." : parent
        let descriptor = parentPath.withCString { pointer -> Int32 in
            Darwin.open(pointer, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        }
        guard descriptor >= 0 else { throw RootStateDirectoryError.writeFailed }
        defer { close(descriptor) }
        guard fsync(descriptor) == 0 else { throw RootStateDirectoryError.writeFailed }
    }

    static func isSafeDirectory(_ status: stat, expectedOwner: UInt32) -> Bool {
        status.st_mode & S_IFMT == S_IFDIR
            && status.st_uid == expectedOwner
            && status.st_mode & 0o077 == 0
            && status.st_mode & 0o7000 == 0
    }

    static func isSafeFile(_ status: stat, expectedOwner: UInt32) -> Bool {
        status.st_mode & S_IFMT == S_IFREG
            && status.st_uid == expectedOwner
            && status.st_mode & 0o077 == 0
            && status.st_mode & 0o7000 == 0
    }

    // Verify an opened directory by descriptor, not by path, so a rename or a
    // symlink swap after the caller's check cannot substitute another object.
    // A non-nil extended ACL is rejected. A failed ACL read throws instead of
    // being treated as "no ACL".
    static func verifySafeDirectory(_ descriptor: Int32, expectedOwner: UInt32) throws {
        var status = stat()
        guard fstat(descriptor, &status) == 0,
              isSafeDirectory(status, expectedOwner: expectedOwner)
        else {
            throw RootStateDirectoryError.unsafe
        }
        if try hasExtendedACL(descriptor) {
            throw RootStateDirectoryError.unsafe
        }
    }

    static func hasExtendedACL(_ descriptor: Int32) throws -> Bool {
        errno = 0
        guard let acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
            // macOS reports an object without an extended ACL as ENOENT. Any
            // other failure means the ACL state is unknown, so it is an error.
            if errno == ENOENT { return false }
            throw RootStateDirectoryError.unreadable
        }
        acl_free(UnsafeMutableRawPointer(acl))
        return true
    }
}
