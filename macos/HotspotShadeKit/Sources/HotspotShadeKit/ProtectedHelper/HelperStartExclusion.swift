import Foundation
import Darwin

// The helper side of the reviewed macOS install/start exclusion contract. The
// helper and the Rust engine use one permanent lock file:
//
//   path      /var/db/hotspotshade/start-exclusion
//   open      O_RDONLY or O_RDWR, O_NOFOLLOW, O_CLOEXEC, O_NONBLOCK
//   check     regular file, expected owner, one link, no group or other access,
//             no extended ACL, held descriptor matches the recorded inode and
//             mode and the path names that same inode
//   lock      flock(fd, LOCK_SH) for a start participant
//             flock(fd, LOCK_EX | LOCK_NB) for the coordinator
//   lifetime  the helper holds its own shared lock from before it asks for a
//             spawn until that engine is stopped.
//
// The helper also passes a duplicate of its locked descriptor to the engine on
// descriptor 5. The Rust engine opens and locks the same inode independently,
// then validates the inherited descriptor, version, device, and inode. A
// partial or mismatched handoff is a start failure. Direct mode has no handoff
// and takes an independent shared lock. Darwin `flock` locks belong to the open
// file description: a duplicate shares the lock, and closing one copy does not
// release it while another copy remains open.
//
// The install coordinator currently holds a transition set that includes
// `start.lock`, `start-exclusion`, and `upgrade.lock`. The helper still does not
// claim install exclusion: the canonical name, the old-binary migration, and a
// cross-binary contention test remain open. The installer package remains
// build-only and its refusal gate is unchanged. The file owners must finish
// those steps before either side claims exclusion.
//
// The helper does not create a second start journal. Its existing launch
// intent, `engine-session`, is the durable write-ahead start record. The
// installer owns the separate `install-journal.json` file transaction record.
// The helper refuses a start while either the file or service transaction
// journal is present, including after an installer crash. It never writes,
// replaces, or removes either installer journal.
public enum HelperStartExclusionProtocol {
    public static let stateDirectoryPath = RootCleanupBlockStore.defaultDirectoryPath
    public static let lockFileName = "start-exclusion"
    public static let installJournalFileName = "install-journal.json"
    public static let serviceJournalFileName = "service-journal.json"
    public static let protocolVersion: UInt = 1
    // The engine receives the inherited lock descriptor on this number.
    public static let handoffDescriptor: Int32 = 5
}

public enum HelperStartExclusionAvailability: Equatable, Sendable {
    case available
    // Another process holds the exclusive lock. It is an install or upgrade.
    case busy
    // The lock or install journal state is unsafe or unreadable. The helper
    // refuses instead of guessing that the state is clean.
    case unavailable
}

public enum HelperStartExclusionError: Error, Equatable {
    case busy
    case unavailable
    case unsafe
    case writeFailed
    // The installer left a file transaction journal. A start must not run
    // until the coordinator recovery path has finished.
    case installJournalPresent
}

public struct HelperStartExclusionHandoff: Equatable, Sendable {
    public let descriptor: Int32
    public let lockPath: String
    public let lockDevice: UInt64
    public let lockInode: UInt64
    let expectedOwner: UInt32

    public init(
        descriptor: Int32,
        lockPath: String,
        lockDevice: UInt64,
        lockInode: UInt64
    ) {
        self.init(
            descriptor: descriptor,
            lockPath: lockPath,
            lockDevice: lockDevice,
            lockInode: lockInode,
            expectedOwner: 0
        )
    }

    init(
        descriptor: Int32,
        lockPath: String,
        lockDevice: UInt64,
        lockInode: UInt64,
        expectedOwner: UInt32
    ) {
        self.descriptor = descriptor
        self.lockPath = lockPath
        self.lockDevice = lockDevice
        self.lockInode = lockInode
        self.expectedOwner = expectedOwner
    }

    // Recheck the descriptor and the lock path immediately before spawn. A
    // replaced lock file means the engine would validate a different inode, so
    // this start must not begin. The check cannot prove the path is stable
    // through the spawn itself; only a cooperative root coordinator can.
    func verify() throws {
        guard descriptor >= 0, !lockPath.isEmpty else {
            throw HelperStartExclusionError.unavailable
        }
        // The held descriptor is the lock the helper will hand to the engine.
        // It must still be the recorded inode and a safe regular file. A path
        // check alone would accept a replaced path while the handoff still
        // names the old, or a different, object.
        var held = stat()
        guard fstat(descriptor, &held) == 0 else {
            throw HelperStartExclusionError.unavailable
        }
        guard RootStartExclusionStore.isSafeLockFile(held, expectedOwner: expectedOwner),
              UInt64(held.st_dev) == lockDevice,
              UInt64(held.st_ino) == lockInode
        else {
            throw HelperStartExclusionError.unsafe
        }
        let pathDescriptor = lockPath.withCString { pointer -> Int32 in
            Darwin.open(
                pointer,
                O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK
            )
        }
        guard pathDescriptor >= 0 else {
            throw HelperStartExclusionError.unavailable
        }
        defer { close(pathDescriptor) }
        var named = stat()
        guard fstat(pathDescriptor, &named) == 0,
              RootStartExclusionStore.isSafeLockFile(named, expectedOwner: expectedOwner),
              named.st_dev == held.st_dev,
              named.st_ino == held.st_ino,
              named.st_mode == held.st_mode,
              named.st_uid == held.st_uid,
              named.st_nlink == held.st_nlink
        else {
            throw HelperStartExclusionError.unsafe
        }
        if try RootStartExclusionStore.hasExtendedACL(pathDescriptor) {
            throw HelperStartExclusionError.unsafe
        }
    }
}

public protocol HelperStartExclusionLease: AnyObject {
    var handoff: HelperStartExclusionHandoff { get }
    // The engine stopped with a clean zero exit. Release the helper's shared
    // lock. The child's inherited copy, if any, closes when the engine exits.
    func releaseAfterCleanStop()
    // The engine may still own routes. Keep the shared lock until this helper
    // process exits. The caller retains this lease.
    func abandon()
}

public protocol HelperStartExclusionPreparing: Sendable {
    func isInstallJournalPresent() throws -> Bool
    func probeSharedAvailability() -> HelperStartExclusionAvailability
    func prepare(session: UUID) throws -> HelperStartExclusionLease
}

public struct RootStartExclusionStore: HelperStartExclusionPreparing {
    public static let defaultDirectoryPath = HelperStartExclusionProtocol.stateDirectoryPath
    public static let defaultLockFileName = HelperStartExclusionProtocol.lockFileName
    public static let defaultInstallJournalFileName =
        HelperStartExclusionProtocol.installJournalFileName

    private let directoryPath: String
    private let lockFileName: String
    private let installJournalFileName: String
    private let expectedOwner: UInt32

    public init(
        directoryPath: String = RootStartExclusionStore.defaultDirectoryPath,
        lockFileName: String = RootStartExclusionStore.defaultLockFileName,
        installJournalFileName: String = RootStartExclusionStore.defaultInstallJournalFileName
    ) {
        self.init(
            directoryPath: directoryPath,
            lockFileName: lockFileName,
            installJournalFileName: installJournalFileName,
            expectedOwner: 0
        )
    }

    // The owner seam exists for the hermetic tests, which cannot run as root.
    init(
        directoryPath: String,
        lockFileName: String,
        installJournalFileName: String,
        expectedOwner: UInt32
    ) {
        self.directoryPath = directoryPath
        self.lockFileName = lockFileName
        self.installJournalFileName = installJournalFileName
        self.expectedOwner = expectedOwner
    }

    public var lockPath: String { directoryPath + "/" + lockFileName }
    public var installJournalPath: String { directoryPath + "/" + installJournalFileName }

    private var state: RootStateDirectory {
        RootStateDirectory(path: directoryPath, expectedOwner: expectedOwner)
    }

    public func isInstallJournalPresent() throws -> Bool {
        do {
            return try state.contains(installJournalFileName)
                || state.contains(HelperStartExclusionProtocol.serviceJournalFileName)
        } catch let error as RootStateDirectoryError {
            switch error {
            case .unsafe: throw HelperStartExclusionError.unsafe
            case .unreadable, .writeFailed, .alreadyPresent, .createRollbackUncertain:
                throw HelperStartExclusionError.unavailable
            }
        } catch {
            throw HelperStartExclusionError.unavailable
        }
    }

    public func probeSharedAvailability() -> HelperStartExclusionAvailability {
        do {
            guard let directory = try state.openIfPresent() else { return .available }
            defer { close(directory) }
            var status = stat()
            guard fstatat(directory, lockFileName, &status, AT_SYMLINK_NOFOLLOW) == 0 else {
                if errno == ENOENT { return .available }
                return .unavailable
            }
            guard Self.isSafeLockFile(status, expectedOwner: expectedOwner) else {
                return .unavailable
            }
            let descriptor = openat(
                directory,
                lockFileName,
                O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK
            )
            guard descriptor >= 0 else { return .unavailable }
            defer { close(descriptor) }
            var opened = stat()
            guard fstat(descriptor, &opened) == 0,
                  Self.isSafeLockFile(opened, expectedOwner: expectedOwner),
                  opened.st_dev == status.st_dev,
                  opened.st_ino == status.st_ino,
                  opened.st_mode == status.st_mode,
                  opened.st_uid == status.st_uid,
                  opened.st_nlink == status.st_nlink,
                  try !Self.hasExtendedACL(descriptor)
            else {
                return .unavailable
            }
            if flock(descriptor, LOCK_SH | LOCK_NB) == 0 {
                _ = flock(descriptor, LOCK_UN)
                return .available
            }
            if errno == EWOULDBLOCK || errno == EAGAIN {
                return .busy
            }
            return .unavailable
        } catch {
            return .unavailable
        }
    }

    public func prepare(session: UUID) throws -> HelperStartExclusionLease {
        let ticket = try acquireSharedLock()
        let journalPresent: Bool
        do {
            journalPresent = try state.contains(installJournalFileName)
                || state.contains(HelperStartExclusionProtocol.serviceJournalFileName)
        } catch let error as RootStateDirectoryError {
            ticket.release()
            switch error {
            case .unsafe: throw HelperStartExclusionError.unsafe
            case .unreadable, .writeFailed, .alreadyPresent, .createRollbackUncertain:
                throw HelperStartExclusionError.unavailable
            }
        } catch {
            ticket.release()
            throw HelperStartExclusionError.unavailable
        }
        if journalPresent {
            ticket.release()
            throw HelperStartExclusionError.installJournalPresent
        }
        let handoff = HelperStartExclusionHandoff(
            descriptor: ticket.fileDescriptor,
            lockPath: lockPath,
            lockDevice: ticket.device,
            lockInode: ticket.inode,
            expectedOwner: expectedOwner
        )
        do {
            try handoff.verify()
        } catch {
            ticket.release()
            throw error
        }
        return RootStartExclusionLease(ticket: ticket, handoff: handoff)
    }

    private func acquireSharedLock() throws -> RootStartExclusionTicket {
        do {
            try state.ensure()
        } catch let error as RootStateDirectoryError {
            throw Self.map(error)
        } catch {
            throw HelperStartExclusionError.unavailable
        }
        let directory: Int32
        do {
            directory = try state.openExisting()
        } catch let error as RootStateDirectoryError {
            throw Self.map(error)
        } catch {
            throw HelperStartExclusionError.unavailable
        }
        defer { close(directory) }

        let opened = try openLockFile(directory: directory)
        let descriptor = opened.descriptor
        var complete = false
        defer {
            if !complete { close(descriptor) }
        }

        var status = stat()
        guard fstat(descriptor, &status) == 0,
              Self.isSafeLockFile(status, expectedOwner: expectedOwner),
              try !Self.hasExtendedACL(descriptor)
        else {
            throw HelperStartExclusionError.unsafe
        }
        if flock(descriptor, LOCK_SH | LOCK_NB) != 0 {
            if errno == EWOULDBLOCK || errno == EAGAIN {
                throw HelperStartExclusionError.busy
            }
            throw HelperStartExclusionError.unavailable
        }
        // The open and the lock are separate calls. A path replaced between
        // them names another inode, so a lock on the held descriptor protects
        // nothing. Refuse instead of adopting the replacement.
        var named = stat()
        let reached = lockFileName.withCString {
            fstatat(directory, $0, &named, AT_SYMLINK_NOFOLLOW)
        }
        guard reached == 0,
              Self.isSafeLockFile(named, expectedOwner: expectedOwner),
              named.st_dev == status.st_dev,
              named.st_ino == status.st_ino,
              named.st_mode == status.st_mode,
              named.st_uid == status.st_uid,
              named.st_nlink == status.st_nlink
        else {
            _ = flock(descriptor, LOCK_UN)
            throw HelperStartExclusionError.unsafe
        }
        if opened.created {
            guard fchmod(descriptor, mode_t(0o600)) == 0,
                  fsync(descriptor) == 0,
                  fsync(directory) == 0
            else {
                _ = flock(descriptor, LOCK_UN)
                throw HelperStartExclusionError.writeFailed
            }
        }
        // The fixed handoff descriptor is 5. Keep the helper's descriptor out
        // of that range so a spawn action cannot accidentally alias it.
        let moved = fcntl(descriptor, F_DUPFD_CLOEXEC, 10)
        guard moved >= 0 else {
            _ = flock(descriptor, LOCK_UN)
            throw HelperStartExclusionError.unavailable
        }
        close(descriptor)
        complete = true
        return RootStartExclusionTicket(
            descriptor: moved,
            path: lockPath,
            device: UInt64(status.st_dev),
            inode: UInt64(status.st_ino)
        )
    }

    private func openLockFile(directory: Int32) throws -> (descriptor: Int32, created: Bool) {
        let existing = lockFileName.withCString {
            openat(
                directory,
                $0,
                O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK
            )
        }
        if existing >= 0 {
            return (existing, false)
        }
        guard errno == ENOENT else { throw HelperStartExclusionError.unavailable }
        let created = lockFileName.withCString {
            openat(
                directory,
                $0,
                O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK,
                mode_t(0o600)
            )
        }
        if created >= 0 {
            return (created, true)
        }
        if errno == EEXIST {
            let retry = lockFileName.withCString {
                openat(
                    directory,
                    $0,
                    O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK
                )
            }
            guard retry >= 0 else { throw HelperStartExclusionError.unsafe }
            return (retry, false)
        }
        throw HelperStartExclusionError.writeFailed
    }

    static func isSafeLockFile(_ status: stat, expectedOwner: UInt32) -> Bool {
        status.st_mode & S_IFMT == S_IFREG
            && status.st_uid == expectedOwner
            && status.st_nlink == 1
            && status.st_mode & 0o077 == 0
            && status.st_mode & 0o7000 == 0
    }

    static func hasExtendedACL(_ descriptor: Int32) throws -> Bool {
        errno = 0
        guard let acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
            // macOS reports no extended ACL as ENOENT. Any other failure means
            // the ACL state is unknown, so the caller must refuse the start.
            if errno == ENOENT { return false }
            throw HelperStartExclusionError.unavailable
        }
        acl_free(UnsafeMutableRawPointer(acl))
        return true
    }

    private static func map(_ error: RootStateDirectoryError) -> HelperStartExclusionError {
        switch error {
        case .unsafe: return .unsafe
        case .unreadable, .writeFailed, .alreadyPresent, .createRollbackUncertain:
            return .unavailable
        }
    }
}

final class RootStartExclusionTicket: @unchecked Sendable {
    private let lock = NSLock()
    private var descriptor: Int32
    let path: String
    let device: UInt64
    let inode: UInt64

    init(descriptor: Int32, path: String, device: UInt64, inode: UInt64) {
        self.descriptor = descriptor
        self.path = path
        self.device = device
        self.inode = inode
    }

    var fileDescriptor: Int32 {
        lock.lock(); defer { lock.unlock() }
        return descriptor
    }

    func release() {
        lock.lock()
        let value = descriptor
        descriptor = -1
        lock.unlock()
        if value >= 0 { close(value) }
    }

    deinit { release() }
}

final class RootStartExclusionLease: HelperStartExclusionLease, @unchecked Sendable {
    private let lock = NSLock()
    private let ticket: RootStartExclusionTicket
    let handoff: HelperStartExclusionHandoff
    private var abandoned = false

    init(ticket: RootStartExclusionTicket, handoff: HelperStartExclusionHandoff) {
        self.ticket = ticket
        self.handoff = handoff
    }

    func releaseAfterCleanStop() {
        lock.lock()
        let keep = abandoned
        lock.unlock()
        guard !keep else { return }
        ticket.release()
    }

    func abandon() {
        lock.lock()
        abandoned = true
        lock.unlock()
    }

    deinit {
        lock.lock()
        let shouldRelease = !abandoned
        lock.unlock()
        if shouldRelease { ticket.release() }
    }
}

// Adds the inherited lock descriptor to a `posix_spawn` file action list. The
// target descriptor has close-on-exec cleared by the dup2 action. The source
// descriptor is closed in the child after the duplicate, so the child holds one
// copy of the same open file description and the parent keeps its own copy.
public enum HelperStartExclusionSpawn {
    @discardableResult
    public static func addHandoff(
        to actions: inout posix_spawn_file_actions_t?,
        handoff: HelperStartExclusionHandoff
    ) -> Bool {
        let target = HelperStartExclusionProtocol.handoffDescriptor
        guard handoff.descriptor >= 0, handoff.descriptor != target else {
            return false
        }
        guard posix_spawn_file_actions_adddup2(&actions, handoff.descriptor, target) == 0 else {
            return false
        }
        guard posix_spawn_file_actions_addclose(&actions, handoff.descriptor) == 0 else {
            return false
        }
        return true
    }
}
