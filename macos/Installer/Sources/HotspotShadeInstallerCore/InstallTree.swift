import Foundation
import Darwin
import CryptoKit

public struct FileSnapshot: Equatable, Sendable {
    public let sha256: String
    public let size: Int
    public let mode: UInt16

    public init(sha256: String, size: Int, mode: UInt16) {
        self.sha256 = sha256
        self.size = size
        self.mode = mode
    }
}

public enum InstallTreeError: Error, Equatable {
    case rootUnsafe(String)
    case pathUnsafe(String)
    case directoryUnsafe(String)
    case missing(String)
    case notRegularFile(String)
    case wrongOwner(String)
    // The installed file must carry the exact group the layout requires. The
    // system preview uses wheel; a sandbox tree uses the installer's own group.
    case wrongGroup(String)
    case wrongLinkCount(String)
    case writableByOthers(String)
    case accessControlList(String)
    case tooLarge(String)
    case alreadyExists(String)
    case notEmpty(String)
    case digestMismatch(String)
    // The object mode is not the exact mode its owner requires. The generic
    // file check only rejects a group or other write bit, so a caller with a
    // stricter requirement passes it here.
    case wrongMode(String)
    // The atomic rename completed, so the new bytes are visible at the
    // destination name, but the following directory sync failed. The caller
    // cannot know whether the replacement survives a crash. This is never a
    // clean pre-rename failure.
    case writeUncertain(String)
    // The unlink completed, so the name is gone now, but the parent directory
    // sync failed. The removal may not survive a crash. This is never a clean
    // removal and the caller must not run another mutation in this run.
    case removeUncertain(String)
    case io(String, Int32)

    public var path: String {
        switch self {
        case .rootUnsafe(let path), .pathUnsafe(let path), .directoryUnsafe(let path),
             .missing(let path), .notRegularFile(let path), .wrongOwner(let path),
             .wrongGroup(let path), .wrongLinkCount(let path), .writableByOthers(let path),
             .accessControlList(let path), .tooLarge(let path), .alreadyExists(let path),
             .notEmpty(let path), .digestMismatch(let path), .wrongMode(let path),
             .writeUncertain(let path), .removeUncertain(let path), .io(let path, _):
            return path
        }
    }
}

// A cross-directory rename makes the new name durable first and the old name
// absent second. A crash between the two syncs can leave the file under both
// names, which recovery resolves. The reverse order could leave it under
// neither name. The role names the parent that is being made durable.
enum RenameSyncRole: Sendable, Equatable {
    case gained
    case lost
}

// Test-only syscall seams. Production passes `fsync` for every entry. The
// coordinator's internal initializer can supply a tree with one failing role so
// a hermetic test exercises the same classification path as a real sync error.
struct InstallTreeSyncHooks: Sendable {
    var copyDirectory: @Sendable (Int32) -> Int32
    var moveGained: @Sendable (Int32) -> Int32
    var moveLost: @Sendable (Int32) -> Int32
    var restoreGained: @Sendable (Int32) -> Int32
    var restoreLost: @Sendable (Int32) -> Int32
    var removeDirectory: @Sendable (Int32) -> Int32

    static let production = InstallTreeSyncHooks(
        copyDirectory: { fsync($0) },
        moveGained: { fsync($0) },
        moveLost: { fsync($0) },
        restoreGained: { fsync($0) },
        restoreLost: { fsync($0) },
        removeDirectory: { fsync($0) }
    )
}

// One target root, opened once. Every child operation walks from that
// descriptor with openat and O_NOFOLLOW. A relative path is checked by
// SafeRelativePath before the first system call. The coordinator never passes
// an absolute path from a journal or a manifest to open, rename, or unlink.
//
// Every file this tree writes is set to the expected owner and group. The
// group is verified, not inherited: the system preview installs root:wheel
// files, and the helper refuses an executable whose group is not wheel.
public final class InstallTree: @unchecked Sendable {
    public let rootPath: String
    private let expectedOwner: UInt32
    private let expectedGroup: UInt32
    private let rootDescriptor: Int32
    private let syncHooks: InstallTreeSyncHooks
    private let usePrivateVar: Bool

    public convenience init(rootPath requested: String, expectedOwner: UInt32) throws {
        try self.init(
            rootPath: requested,
            expectedOwner: expectedOwner,
            syncHooks: .production
        )
    }

    // The hooks seam exists for hermetic tests of each directory-sync boundary.
    // Production callers use the public initializer only. The group defaults to
    // the installer's own group, which is what a sandbox tree owns.
    init(
        rootPath requested: String,
        expectedOwner: UInt32,
        expectedGroup: UInt32 = UInt32(getegid()),
        syncHooks: InstallTreeSyncHooks,
        usePrivateVar: Bool = false
    ) throws {
        guard requested.hasPrefix("/"), !requested.contains("\0") else {
            throw InstallTreeError.rootUnsafe(requested)
        }
        guard let resolvedPointer = realpath(requested, nil) else {
            throw InstallTreeError.rootUnsafe(requested)
        }
        defer { free(resolvedPointer) }
        let resolved = String(cString: resolvedPointer)
        let descriptor = open(resolved, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw InstallTreeError.rootUnsafe(resolved) }
        var status = stat()
        guard fstat(descriptor, &status) == 0,
              status.st_mode & S_IFMT == S_IFDIR,
              status.st_uid == expectedOwner,
              status.st_mode & 0o022 == 0,
              !SystemSupport.hasExtendedACL(descriptor)
        else {
            close(descriptor)
            throw InstallTreeError.rootUnsafe(resolved)
        }
        self.rootPath = resolved
        self.expectedOwner = expectedOwner
        self.expectedGroup = expectedGroup
        self.rootDescriptor = descriptor
        self.syncHooks = syncHooks
        self.usePrivateVar = usePrivateVar
        if usePrivateVar {
            // Both components must already exist and pass the same owner and
            // no-follow checks used for every other directory.
            do {
                let privateVar = try openDirectory(["private", "var"], create: false, mode: 0)
                close(privateVar)
            } catch {
                close(descriptor)
                throw error
            }
        }
    }

    deinit {
        close(rootDescriptor)
    }

    public var owner: UInt32 { expectedOwner }
    public var group: UInt32 { expectedGroup }

    public func path(for relative: String) throws -> String {
        guard let parts = components(for: relative),
              let joined = SafeRelativePath.join(root: rootPath, relative: parts.joined(separator: "/")) else {
            throw InstallTreeError.pathUnsafe(relative)
        }
        return joined
    }

    public func directoryMode(_ relative: String) throws -> UInt16 {
        guard let parts = components(for: relative), !parts.isEmpty else {
            throw InstallTreeError.pathUnsafe(relative)
        }
        let descriptor = try openDirectory(parts, create: false, mode: 0)
        defer { close(descriptor) }
        var status = stat()
        guard fstat(descriptor, &status) == 0 else {
            throw InstallTreeError.io(relative, errno)
        }
        return UInt16(status.st_mode & 0o7777)
    }

    // Create missing components under the root and return the relative paths
    // that this call created, in order. An existing component is checked and
    // never changed. A new component is created with `mode`, synced, and
    // checked through its descriptor.
    @discardableResult
    public func ensureDirectory(_ relative: String, mode: mode_t, create: Bool) throws -> [String] {
        guard let parts = components(for: relative), !parts.isEmpty else {
            throw InstallTreeError.pathUnsafe(relative)
        }
        var created: [String] = []
        let descriptor = try openDirectoryRecording(
            parts, create: create, mode: mode, created: &created
        )
        close(descriptor)
        guard usePrivateVar, relative == "var" || relative.hasPrefix("var/") else {
            return created
        }
        return created.map { path in
            path.hasPrefix("private/var/") ? String(path.dropFirst("private/".count)) : path
        }
    }

    public func entryExists(_ relative: String) throws -> Bool {
        guard let parts = components(for: relative), let name = parts.last else {
            throw InstallTreeError.pathUnsafe(relative)
        }
        let parent: Int32
        do {
            parent = try openDirectory(Array(parts.dropLast()), create: false, mode: 0)
        } catch InstallTreeError.missing {
            return false
        }
        defer { close(parent) }
        var status = stat()
        let result = name.withCString {
            fstatat(parent, $0, &status, AT_SYMLINK_NOFOLLOW)
        }
        if result == 0 { return true }
        if errno == ENOENT { return false }
        throw InstallTreeError.io(relative, errno)
    }

    // A file is safe when it is one regular file, owned by the expected
    // account, with one link, no group or other write bit, and no access
    // control list. A zero-length file is not a valid installed artifact.
    public func snapshot(_ relative: String, maximumBytes: Int) throws -> FileSnapshot? {
        guard maximumBytes > 0,
              let parts = components(for: relative),
              let name = parts.last
        else { throw InstallTreeError.pathUnsafe(relative) }

        let parent: Int32
        do {
            parent = try openDirectory(Array(parts.dropLast()), create: false, mode: 0)
        } catch InstallTreeError.missing {
            return nil
        }
        defer { close(parent) }

        var named = stat()
        let result = name.withCString {
            fstatat(parent, $0, &named, AT_SYMLINK_NOFOLLOW)
        }
        if result != 0 {
            if errno == ENOENT { return nil }
            throw InstallTreeError.io(relative, errno)
        }
        try checkFileStatus(named, path: relative, maximumBytes: maximumBytes)

        let descriptor = name.withCString {
            openat(parent, $0, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        }
        guard descriptor >= 0 else { throw InstallTreeError.notRegularFile(relative) }
        defer { close(descriptor) }
        var opened = stat()
        guard fstat(descriptor, &opened) == 0,
              opened.st_dev == named.st_dev,
              opened.st_ino == named.st_ino
        else { throw InstallTreeError.io(relative, errno) }
        try checkFileStatus(opened, path: relative, maximumBytes: maximumBytes)
        guard !SystemSupport.hasExtendedACL(descriptor) else {
            throw InstallTreeError.accessControlList(relative)
        }
        let (digest, size) = try digest(descriptor, path: relative, maximumBytes: maximumBytes)
        return FileSnapshot(sha256: digest, size: size, mode: UInt16(opened.st_mode & 0o7777))
    }

    // Read one safe regular file. A caller that owns the record passes the
    // exact mode it wrote. A well-known journal is not accepted with a group
    // or other read bit, even though that bit is not writable by another
    // account.
    public func readFile(
        _ relative: String,
        maximumBytes: Int,
        requiredMode: UInt16? = nil
    ) throws -> Data? {
        guard maximumBytes > 0,
              let parts = components(for: relative),
              let name = parts.last
        else { throw InstallTreeError.pathUnsafe(relative) }
        let parent: Int32
        do {
            parent = try openDirectory(Array(parts.dropLast()), create: false, mode: 0)
        } catch InstallTreeError.missing {
            return nil
        }
        defer { close(parent) }

        var named = stat()
        let result = name.withCString {
            fstatat(parent, $0, &named, AT_SYMLINK_NOFOLLOW)
        }
        if result != 0 {
            if errno == ENOENT { return nil }
            throw InstallTreeError.io(relative, errno)
        }
        try checkFileStatus(named, path: relative, maximumBytes: maximumBytes)

        let descriptor = name.withCString {
            openat(parent, $0, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        }
        guard descriptor >= 0 else { throw InstallTreeError.notRegularFile(relative) }
        defer { close(descriptor) }
        var opened = stat()
        guard fstat(descriptor, &opened) == 0,
              opened.st_dev == named.st_dev,
              opened.st_ino == named.st_ino
        else { throw InstallTreeError.io(relative, errno) }
        try checkFileStatus(opened, path: relative, maximumBytes: maximumBytes)
        if let requiredMode, opened.st_mode & 0o7777 != mode_t(requiredMode) {
            throw InstallTreeError.wrongMode(relative)
        }
        guard !SystemSupport.hasExtendedACL(descriptor) else {
            throw InstallTreeError.accessControlList(relative)
        }
        guard let data = SystemSupport.readAll(descriptor, maximumBytes: maximumBytes),
              data.count == Int(opened.st_size)
        else { throw InstallTreeError.io(relative, EIO) }
        return data
    }

    // Write one new file through a temporary file in the destination
    // directory, sync it, then rename it into place and sync the directory.
    // The temporary file is removed after any failure before the rename.
    //
    // A failure before the rename leaves the destination untouched, so the
    // caller's previous record is still authoritative. The rename itself is
    // one atomic operation; a nonzero result leaves the destination name in
    // place. A failure after a successful rename is different: the new bytes
    // are visible, but the directory entry may not survive a crash. That case
    // is reported as `.writeUncertain` and must never be treated as a clean
    // failure. A read-back after the failed sync is only an observation of the
    // current namespace, so the outcome is classified by the failed step, not
    // by reading the file again.
    public func writeAtomic(
        _ relative: String,
        data: Data,
        mode: mode_t,
        temporarySuffix: String,
        replaceExisting: Bool
    ) throws {
        try writeAtomic(
            relative,
            data: data,
            mode: mode,
            temporarySuffix: temporarySuffix,
            replaceExisting: replaceExisting,
            directorySync: { fsync($0) }
        )
    }

    // The directory-sync seam exists for the hermetic post-rename and ordinary
    // pre-rename tests. Production uses the public method, which passes
    // `fsync` only.
    func writeAtomic(
        _ relative: String,
        data: Data,
        mode: mode_t,
        temporarySuffix: String,
        replaceExisting: Bool,
        directorySync: (Int32) -> Int32
    ) throws {
        guard SystemSupport.isSafeSuffix(temporarySuffix),
              let parts = components(for: relative),
              let name = parts.last
        else { throw InstallTreeError.pathUnsafe(relative) }
        let parent = try openDirectory(Array(parts.dropLast()), create: false, mode: 0)
        defer { close(parent) }

        if !replaceExisting {
            var status = stat()
            let found = name.withCString { fstatat(parent, $0, &status, AT_SYMLINK_NOFOLLOW) }
            if found == 0 { throw InstallTreeError.alreadyExists(relative) }
            guard errno == ENOENT else { throw InstallTreeError.io(relative, errno) }
        }

        let temporary = ".\(name).hs-\(temporarySuffix).tmp"
        guard temporary.utf8.count <= 255 else { throw InstallTreeError.pathUnsafe(relative) }
        let descriptor = temporary.withCString {
            openat(
                parent,
                $0,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                mode_t(0o600)
            )
        }
        guard descriptor >= 0 else { throw InstallTreeError.io(relative, errno) }
        var renamed = false
        defer {
            close(descriptor)
            if !renamed {
                _ = temporary.withCString { unlinkat(parent, $0, 0) }
            }
        }
        guard SystemSupport.writeAll(descriptor, data: data) else {
            throw InstallTreeError.io(relative, errno)
        }
        try setOwnerAndGroup(descriptor, path: relative)
        guard fchmod(descriptor, mode) == 0,
              fsync(descriptor) == 0
        else { throw InstallTreeError.io(relative, errno) }

        if !replaceExisting {
            var status = stat()
            let found = name.withCString { fstatat(parent, $0, &status, AT_SYMLINK_NOFOLLOW) }
            if found == 0 { throw InstallTreeError.alreadyExists(relative) }
            guard errno == ENOENT else { throw InstallTreeError.io(relative, errno) }
        }
        let moved: Int32
        if replaceExisting {
            moved = temporary.withCString { temporaryName in
                name.withCString { finalName in
                    renameat(parent, temporaryName, parent, finalName)
                }
            }
        } else {
            // The exclusive form cannot overwrite a file that appeared after
            // the check above. It is one system call, so the destination is
            // either absent or a foreign object; it is never replaced.
            moved = renameExclusive(
                parent,
                temporary,
                parent,
                name
            )
        }
        guard moved == 0 else {
            if !replaceExisting, errno == EEXIST {
                throw InstallTreeError.alreadyExists(relative)
            }
            throw InstallTreeError.io(relative, errno)
        }
        // The rename completed. From this point the destination name holds the
        // new bytes. A later failure cannot be rolled back as a clean no-op.
        renamed = true
        guard directorySync(parent) == 0 else {
            throw InstallTreeError.writeUncertain(relative)
        }
    }

    // Copy one staged file into the destination directory. The copy is hashed
    // while it is written and compared to the validated digest before the
    // rename. The destination must not exist: the previous file is moved to
    // the backup directory first.
    public func copyFromFile(
        sourcePath: String,
        expected: FileSnapshot,
        to relative: String,
        mode: mode_t,
        temporarySuffix: String
    ) throws {
        try copyFromFile(
            sourcePath: sourcePath,
            expected: expected,
            to: relative,
            mode: mode,
            temporarySuffix: temporarySuffix,
            directorySync: syncHooks.copyDirectory
        )
    }

    // The directory-sync seam exists for hermetic tests of the post-rename
    // boundary. Production passes the tree's `copyDirectory` hook, which is
    // `fsync` in a production tree.
    func copyFromFile(
        sourcePath: String,
        expected: FileSnapshot,
        to relative: String,
        mode: mode_t,
        temporarySuffix: String,
        directorySync: (Int32) -> Int32,
        beforeRename: () throws -> Void = {}
    ) throws {
        guard SystemSupport.isSafeSuffix(temporarySuffix),
              let parts = components(for: relative),
              let name = parts.last
        else { throw InstallTreeError.pathUnsafe(relative) }
        let source = open(sourcePath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard source >= 0 else { throw InstallTreeError.io(relative, errno) }
        defer { close(source) }
        var sourceStatus = stat()
        guard fstat(source, &sourceStatus) == 0,
              sourceStatus.st_mode & S_IFMT == S_IFREG,
              sourceStatus.st_uid == expectedOwner,
              sourceStatus.st_nlink == 1,
              sourceStatus.st_mode & 0o022 == 0,
              sourceStatus.st_size == off_t(expected.size),
              expected.size > 0,
              !SystemSupport.hasExtendedACL(source)
        else { throw InstallTreeError.notRegularFile(relative) }

        let parent = try openDirectory(Array(parts.dropLast()), create: false, mode: 0)
        defer { close(parent) }
        var existing = stat()
        let found = name.withCString { fstatat(parent, $0, &existing, AT_SYMLINK_NOFOLLOW) }
        if found == 0 { throw InstallTreeError.alreadyExists(relative) }
        guard errno == ENOENT else { throw InstallTreeError.io(relative, errno) }

        let temporary = ".\(name).hs-\(temporarySuffix).tmp"
        guard temporary.utf8.count <= 255 else { throw InstallTreeError.pathUnsafe(relative) }
        let destination = temporary.withCString {
            openat(
                parent,
                $0,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                mode_t(0o600)
            )
        }
        guard destination >= 0 else { throw InstallTreeError.io(relative, errno) }
        var renamed = false
        defer {
            close(destination)
            if !renamed {
                _ = temporary.withCString { unlinkat(parent, $0, 0) }
            }
        }

        var hasher = SHA256()
        var total = 0
        var buffer = [UInt8](repeating: 0, count: 1 << 16)
        while true {
            let count = buffer.withUnsafeMutableBytes { read(source, $0.baseAddress, $0.count) }
            if count < 0 {
                if errno == EINTR { continue }
                throw InstallTreeError.io(relative, errno)
            }
            if count == 0 { break }
            total += count
            guard total <= expected.size else { throw InstallTreeError.tooLarge(relative) }
            hasher.update(data: buffer[0..<count])
            var sent = 0
            while sent < count {
                let written = buffer.withUnsafeBytes {
                    write(destination, $0.baseAddress!.advanced(by: sent), count - sent)
                }
                if written < 0 {
                    if errno == EINTR { continue }
                    throw InstallTreeError.io(relative, errno)
                }
                sent += written
            }
        }
        guard total == expected.size,
              Self.hex(hasher.finalize()) == expected.sha256
        else { throw InstallTreeError.digestMismatch(relative) }
        try setOwnerAndGroup(destination, path: relative)
        guard fchmod(destination, mode) == 0, fsync(destination) == 0 else {
            throw InstallTreeError.io(relative, errno)
        }
        var again = stat()
        let stillThere = name.withCString { fstatat(parent, $0, &again, AT_SYMLINK_NOFOLLOW) }
        if stillThere == 0 { throw InstallTreeError.alreadyExists(relative) }
        guard errno == ENOENT else { throw InstallTreeError.io(relative, errno) }
        // The exclusive form cannot overwrite a file that appeared after the
        // check above. The destination must be absent for an install copy.
        try beforeRename()
        let moved = renameExclusive(parent, temporary, parent, name)
        guard moved == 0 else {
            if errno == EEXIST { throw InstallTreeError.alreadyExists(relative) }
            throw InstallTreeError.io(relative, errno)
        }
        // The rename completed. A failed parent sync is an unknown outcome,
        // not an ordinary pre-rename failure. The new bytes are visible now;
        // the caller must stop and let recovery re-observe the set.
        renamed = true
        guard directorySync(parent) == 0 else {
            throw InstallTreeError.writeUncertain(relative)
        }
    }

    // Move one existing file into the backup directory. Both paths are
    // relative to the target root, so the move stays inside one tree. A cross
    // device rename fails closed before any replacement. The gaining parent
    // (the backup directory) is synced before the losing parent (the
    // destination directory). A crash between the two syncs can leave the file
    // under both names; recovery resolves that. The reverse order could leave
    // the file under neither name.
    public func moveToBackup(
        _ relative: String,
        backupRelative: String,
        expected: FileSnapshot
    ) throws {
        try moveToBackup(
            relative,
            backupRelative: backupRelative,
            expected: expected,
            gainedSync: syncHooks.moveGained,
            lostSync: syncHooks.moveLost
        )
    }

    func moveToBackup(
        _ relative: String,
        backupRelative: String,
        expected: FileSnapshot,
        gainedSync: (Int32) -> Int32,
        lostSync: (Int32) -> Int32,
        beforeRename: () throws -> Void = {}
    ) throws {
        guard let sourceParts = components(for: relative),
              let sourceName = sourceParts.last,
              let backupParts = components(for: backupRelative),
              let backupName = backupParts.last
        else { throw InstallTreeError.pathUnsafe(relative) }
        guard let current = try snapshot(relative, maximumBytes: expected.size) else {
            throw InstallTreeError.missing(relative)
        }
        guard current == expected else { throw InstallTreeError.digestMismatch(relative) }

        let sourceParent = try openDirectory(Array(sourceParts.dropLast()), create: false, mode: 0)
        defer { close(sourceParent) }
        let backupParent = try openDirectory(Array(backupParts.dropLast()), create: false, mode: 0)
        defer { close(backupParent) }
        var status = stat()
        let exists = backupName.withCString {
            fstatat(backupParent, $0, &status, AT_SYMLINK_NOFOLLOW)
        }
        if exists == 0 { throw InstallTreeError.alreadyExists(backupRelative) }
        guard errno == ENOENT else { throw InstallTreeError.io(backupRelative, errno) }
        // The exclusive form cannot overwrite a backup that appeared after the
        // check above. A backup is never a replacement target.
        try beforeRename()
        let moved = renameExclusive(sourceParent, sourceName, backupParent, backupName)
        guard moved == 0 else {
            if errno == EEXIST { throw InstallTreeError.alreadyExists(backupRelative) }
            throw InstallTreeError.io(relative, errno)
        }
        // Gain the new name before losing the old one.
        guard gainedSync(backupParent) == 0 else {
            throw InstallTreeError.writeUncertain(backupRelative)
        }
        guard lostSync(sourceParent) == 0 else {
            throw InstallTreeError.writeUncertain(relative)
        }
    }

    // Move a verified backup file back over its destination. A destination
    // that exists must be a safe regular file; a directory or symlink is never
    // replaced. The gaining parent (the destination directory) is synced
    // before the losing parent (the backup directory).
    public func restoreFromBackup(
        _ backupRelative: String,
        to relative: String,
        expected: FileSnapshot
    ) throws {
        try restoreFromBackup(
            backupRelative,
            to: relative,
            expected: expected,
            gainedSync: syncHooks.restoreGained,
            lostSync: syncHooks.restoreLost
        )
    }

    func restoreFromBackup(
        _ backupRelative: String,
        to relative: String,
        expected: FileSnapshot,
        gainedSync: (Int32) -> Int32,
        lostSync: (Int32) -> Int32
    ) throws {
        guard let backupParts = components(for: backupRelative),
              let backupName = backupParts.last,
              let destinationParts = components(for: relative),
              let destinationName = destinationParts.last
        else { throw InstallTreeError.pathUnsafe(relative) }
        guard let backup = try snapshot(backupRelative, maximumBytes: expected.size),
              backup == expected
        else { throw InstallTreeError.digestMismatch(backupRelative) }

        let backupParent = try openDirectory(Array(backupParts.dropLast()), create: false, mode: 0)
        defer { close(backupParent) }
        let destinationParent = try openDirectory(
            Array(destinationParts.dropLast()), create: false, mode: 0
        )
        defer { close(destinationParent) }

        var status = stat()
        let result = destinationName.withCString {
            fstatat(destinationParent, $0, &status, AT_SYMLINK_NOFOLLOW)
        }
        if result == 0 {
            // A previous new file may be replaced. Any other object refuses.
            guard status.st_mode & S_IFMT == S_IFREG,
                  status.st_uid == expectedOwner,
                  status.st_nlink == 1,
                  status.st_mode & 0o022 == 0
            else { throw InstallTreeError.notRegularFile(relative) }
            let descriptor = destinationName.withCString {
                openat(destinationParent, $0, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
            }
            guard descriptor >= 0 else { throw InstallTreeError.notRegularFile(relative) }
            defer { close(descriptor) }
            guard !SystemSupport.hasExtendedACL(descriptor) else {
                throw InstallTreeError.accessControlList(relative)
            }
        } else if errno != ENOENT {
            throw InstallTreeError.io(relative, errno)
        }

        let moved = backupName.withCString { source in
            destinationName.withCString { destination in
                renameat(backupParent, source, destinationParent, destination)
            }
        }
        guard moved == 0 else { throw InstallTreeError.io(relative, errno) }
        // Gain the destination name before losing the backup name.
        guard gainedSync(destinationParent) == 0 else {
            throw InstallTreeError.writeUncertain(relative)
        }
        guard lostSync(backupParent) == 0 else {
            throw InstallTreeError.writeUncertain(backupRelative)
        }
    }

    // Remove one safe file. A missing file is already clean. When a digest is
    // given, the file must still match it, so a changed object is never
    // deleted. When a mode is given, the exact `st_mode & 0o7777` must still
    // match, so a record with a changed mode or a special bit is kept.
    @discardableResult
    public func removeFile(
        _ relative: String,
        expectedDigest: String?,
        expectedMode: UInt16? = nil
    ) throws -> Bool {
        guard let parts = components(for: relative), let name = parts.last else {
            throw InstallTreeError.pathUnsafe(relative)
        }
        let parent: Int32
        do {
            parent = try openDirectory(Array(parts.dropLast()), create: false, mode: 0)
        } catch InstallTreeError.missing {
            return false
        }
        defer { close(parent) }
        var status = stat()
        let result = name.withCString {
            fstatat(parent, $0, &status, AT_SYMLINK_NOFOLLOW)
        }
        if result != 0 {
            if errno == ENOENT { return false }
            throw InstallTreeError.io(relative, errno)
        }
        guard status.st_mode & S_IFMT == S_IFREG,
              status.st_uid == expectedOwner,
              status.st_nlink == 1,
              status.st_mode & 0o022 == 0
        else { throw InstallTreeError.notRegularFile(relative) }
        let descriptor = name.withCString {
            openat(parent, $0, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        }
        guard descriptor >= 0 else { throw InstallTreeError.notRegularFile(relative) }
        defer { close(descriptor) }
        var opened = stat()
        guard fstat(descriptor, &opened) == 0,
              opened.st_dev == status.st_dev,
              opened.st_ino == status.st_ino,
              opened.st_mode & S_IFMT == S_IFREG,
              opened.st_uid == expectedOwner,
              opened.st_nlink == 1,
              opened.st_mode & 0o022 == 0
        else { throw InstallTreeError.notRegularFile(relative) }
        guard !SystemSupport.hasExtendedACL(descriptor) else {
            throw InstallTreeError.accessControlList(relative)
        }
        if let expectedMode, opened.st_mode & 0o7777 != mode_t(expectedMode) {
            throw InstallTreeError.wrongMode(relative)
        }
        if let expectedDigest {
            let (digest, _) = try digest(
                descriptor, path: relative, maximumBytes: Int(opened.st_size)
            )
            guard digest == expectedDigest else {
                throw InstallTreeError.digestMismatch(relative)
            }
        }
        // Narrow the window between the descriptor checks and the name-based
        // unlink. Darwin has no unlink-by-descriptor or compare-and-unlink, so
        // this recheck cannot close a race with an uncooperative writer.
        var namedAgain = stat()
        let stillNamed = name.withCString {
            fstatat(parent, $0, &namedAgain, AT_SYMLINK_NOFOLLOW)
        }
        if stillNamed != 0 {
            if errno == ENOENT { return false }
            throw InstallTreeError.io(relative, errno)
        }
        guard namedAgain.st_dev == opened.st_dev,
              namedAgain.st_ino == opened.st_ino,
              namedAgain.st_mode & 0o7777 == opened.st_mode & 0o7777,
              namedAgain.st_nlink == 1
        else {
            throw InstallTreeError.notRegularFile(relative)
        }
        let removed = name.withCString { unlinkat(parent, $0, 0) }
        guard removed == 0 else { throw InstallTreeError.io(relative, errno) }
        guard syncHooks.removeDirectory(parent) == 0 else {
            throw InstallTreeError.removeUncertain(relative)
        }
        return true
    }

    // Remove one empty directory that this transaction created. The owner and
    // exact mode must still match, so an unrelated or changed directory is
    // never removed.
    @discardableResult
    public func removeDirectoryIfEmpty(_ relative: String, expectedMode: UInt16) throws -> Bool {
        guard let parts = components(for: relative), let name = parts.last else {
            throw InstallTreeError.pathUnsafe(relative)
        }
        let parent: Int32
        do {
            parent = try openDirectory(Array(parts.dropLast()), create: false, mode: 0)
        } catch InstallTreeError.missing {
            return false
        }
        defer { close(parent) }
        var status = stat()
        let result = name.withCString {
            fstatat(parent, $0, &status, AT_SYMLINK_NOFOLLOW)
        }
        if result != 0 {
            if errno == ENOENT { return false }
            throw InstallTreeError.io(relative, errno)
        }
        guard status.st_mode & S_IFMT == S_IFDIR,
              status.st_uid == expectedOwner,
              status.st_mode & 0o7777 == mode_t(expectedMode),
              status.st_mode & 0o022 == 0
        else { throw InstallTreeError.directoryUnsafe(relative) }
        // Open the named directory and match it to the checked status before
        // the name-based removal. Darwin has no unlink-by-descriptor, so this
        // narrows the window but cannot close it.
        let descriptor = name.withCString {
            openat(parent, $0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        }
        guard descriptor >= 0 else { throw InstallTreeError.directoryUnsafe(relative) }
        var opened = stat()
        guard fstat(descriptor, &opened) == 0,
              opened.st_dev == status.st_dev,
              opened.st_ino == status.st_ino,
              opened.st_mode & 0o7777 == mode_t(expectedMode)
        else {
            close(descriptor)
            throw InstallTreeError.directoryUnsafe(relative)
        }
        close(descriptor)
        let removed = name.withCString { unlinkat(parent, $0, AT_REMOVEDIR) }
        if removed != 0 {
            if errno == ENOTEMPTY { throw InstallTreeError.notEmpty(relative) }
            throw InstallTreeError.io(relative, errno)
        }
        guard syncHooks.removeDirectory(parent) == 0 else {
            throw InstallTreeError.removeUncertain(relative)
        }
        return true
    }

    public func listDirectory(_ relative: String) throws -> [String] {
        guard let parts = components(for: relative) else {
            throw InstallTreeError.pathUnsafe(relative)
        }
        let descriptor: Int32
        do {
            descriptor = try openDirectory(parts, create: false, mode: 0)
        } catch InstallTreeError.missing {
            return []
        }
        guard let directory = fdopendir(descriptor) else {
            close(descriptor)
            throw InstallTreeError.io(relative, errno)
        }
        defer { closedir(directory) }
        var names: [String] = []
        while let entry = readdir(directory) {
            let name = withUnsafeBytes(of: &entry.pointee.d_name) { raw -> String in
                let pointer = raw.baseAddress!.assumingMemoryBound(to: CChar.self)
                return String(cString: pointer)
            }
            if name == "." || name == ".." { continue }
            names.append(name)
        }
        return names.sorted()
    }

    // MARK: private

    // macOS exposes /var as a symlink to /private/var. The installer walks
    // descriptors without following symlinks, so a future live tree must name
    // the real directory. This is an explicit tree configuration, not a
    // general permission to follow symlinks.
    private func components(for relative: String) -> [String]? {
        guard let parts = SafeRelativePath.components(relative) else { return nil }
        guard usePrivateVar, parts.first == "var" else { return parts }
        return ["private"] + parts
    }

    private func openDirectory(
        _ parts: [String],
        create: Bool,
        mode: mode_t
    ) throws -> Int32 {
        var ignored: [String] = []
        return try openDirectoryRecording(parts, create: create, mode: mode, created: &ignored)
    }

    private func openDirectoryRecording(
        _ parts: [String],
        create: Bool,
        mode: mode_t,
        created: inout [String]
    ) throws -> Int32 {
        var descriptor = fcntl(rootDescriptor, F_DUPFD_CLOEXEC, 0)
        guard descriptor >= 0 else { throw InstallTreeError.io("/", errno) }
        if parts.isEmpty { return descriptor }

        for (index, component) in parts.enumerated() {
            let relative = parts[0...index].joined(separator: "/")
            let next = component.withCString {
                openat(descriptor, $0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            }
            if next >= 0 {
                do {
                    try checkDirectory(next, path: relative)
                } catch {
                    close(next)
                    close(descriptor)
                    throw error
                }
                close(descriptor)
                descriptor = next
                continue
            }
            let openError = errno
            guard openError == ENOENT, create else {
                close(descriptor)
                if openError == ENOENT { throw InstallTreeError.missing(relative) }
                throw InstallTreeError.directoryUnsafe(relative)
            }
            if mkdirat(descriptor, component, mode) != 0 && errno != EEXIST {
                let error = errno
                close(descriptor)
                throw InstallTreeError.io(relative, error)
            }
            let nextDescriptor = component.withCString {
                openat(descriptor, $0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            }
            guard nextDescriptor >= 0 else {
                close(descriptor)
                throw InstallTreeError.directoryUnsafe(relative)
            }
            do {
                guard fchmod(nextDescriptor, mode) == 0,
                      fsync(nextDescriptor) == 0,
                      fsync(descriptor) == 0
                else { throw InstallTreeError.io(relative, errno) }
                try checkDirectory(nextDescriptor, path: relative)
            } catch {
                close(nextDescriptor)
                close(descriptor)
                throw error
            }
            created.append(relative)
            close(descriptor)
            descriptor = nextDescriptor
        }
        return descriptor
    }

    private func checkDirectory(_ descriptor: Int32, path: String) throws {
        var status = stat()
        guard fstat(descriptor, &status) == 0,
              status.st_mode & S_IFMT == S_IFDIR,
              status.st_uid == expectedOwner,
              status.st_mode & 0o022 == 0,
              !SystemSupport.hasExtendedACL(descriptor)
        else { throw InstallTreeError.directoryUnsafe(path) }
    }

    private func checkFileStatus(_ status: stat, path: String, maximumBytes: Int) throws {
        guard status.st_mode & S_IFMT == S_IFREG else {
            throw InstallTreeError.notRegularFile(path)
        }
        guard status.st_uid == expectedOwner else { throw InstallTreeError.wrongOwner(path) }
        guard status.st_gid == gid_t(expectedGroup) else { throw InstallTreeError.wrongGroup(path) }
        guard status.st_nlink == 1 else { throw InstallTreeError.wrongLinkCount(path) }
        guard status.st_mode & 0o022 == 0 else { throw InstallTreeError.writableByOthers(path) }
        guard status.st_size > 0, status.st_size <= off_t(maximumBytes) else {
            throw InstallTreeError.tooLarge(path)
        }
    }

    // Set the exact owner and group before the mode. `fchown` clears the set-id
    // bits, so the mode must be applied afterwards. A failure is a clean
    // pre-rename failure and the caller removes its temporary file.
    private func setOwnerAndGroup(_ descriptor: Int32, path: String) throws {
        guard fchown(descriptor, uid_t(expectedOwner), gid_t(expectedGroup)) == 0 else {
            throw InstallTreeError.io(path, errno)
        }
    }

    // One exclusive rename. It never replaces an existing destination name.
    private func renameExclusive(
        _ fromDirectory: Int32,
        _ fromName: String,
        _ toDirectory: Int32,
        _ toName: String
    ) -> Int32 {
        fromName.withCString { fromPointer in
            toName.withCString { toPointer in
                renameatx_np(
                    fromDirectory,
                    fromPointer,
                    toDirectory,
                    toPointer,
                    UInt32(RENAME_EXCL)
                )
            }
        }
    }

    private func digest(
        _ descriptor: Int32,
        path: String,
        maximumBytes: Int
    ) throws -> (String, Int) {
        var hasher = SHA256()
        var total = 0
        var buffer = [UInt8](repeating: 0, count: 1 << 16)
        while true {
            let count = buffer.withUnsafeMutableBytes { read(descriptor, $0.baseAddress, $0.count) }
            if count < 0 {
                if errno == EINTR { continue }
                throw InstallTreeError.io(path, errno)
            }
            if count == 0 { break }
            total += count
            guard total <= maximumBytes else { throw InstallTreeError.tooLarge(path) }
            hasher.update(data: buffer[0..<count])
        }
        return (Self.hex(hasher.finalize()), total)
    }

    static func hex(_ digest: SHA256.Digest) -> String {
        digest.map { String(format: "%02x", $0) }.joined()
    }
}
