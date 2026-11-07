import Foundation
import Darwin
import HotspotShadeKit

// One kernel-backed advisory lock set for every root start path and for the
// install coordinator.
//
// The final approved design is one permanent lock file. The helper and the
// Rust engine used different names while this work was in progress, so the
// coordinator currently takes an exclusive lock on every name in
// `InstallLockLayout.heldFileNames` for the whole transaction. A participant
// that uses any held name contends with the coordinator. A participant that
// uses another name does not. The set is a transition measure, not an approved
// final design.
//
// Contract:
//
//   paths     /var/db/hotspotshade/start.lock
//             /var/db/hotspotshade/start-exclusion
//             /var/db/hotspotshade/upgrade.lock
//   open      O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, mode 0600
//   check     regular file, owner, one link, no group or other permission,
//             no set-uid, set-gid, or sticky bit, no access control list
//   lock      flock(fd, LOCK_SH) for a start participant
//             flock(fd, LOCK_EX | LOCK_NB) for the coordinator
//   lifetime  the engine holds a shared lock from before the first route or
//             TUN change until route and device cleanup completes. The helper
//             holds its own shared lock from before it asks for a spawn until
//             that engine is stopped and cleaned up. The coordinator holds the
//             exclusive set for the whole file transaction.
//
// The kernel releases a lock when the owning process exits, including a crash.
// A pid file, a marker, a launchd job, pgrep, a bootout, or a recheck is not a
// substitute. Darwin `flock` contention is observed between processes. Two
// independent opens in one process are not a valid contention test; the tests
// use a separate compiled process. A duplicated descriptor shares one lock.
// Every participant therefore opens its own descriptor and keeps it until
// cleanup ends. `O_CLOEXEC` keeps the descriptor out of a spawned child; the
// helper passes a deliberate duplicate on descriptor 5, and the engine
// validates that handoff against its own lock.
//
// This file only implements the lock. The live coordinator mode is refused,
// the package preinstall still refuses, and installationApproved is false
// until the owners converge on one name and the live tests run.
public enum InstallLockMode: Sendable, Equatable {
    case shared
    case exclusive
}

public enum InstallLockLayout {
    public static let stateDirectory = "/var/db/hotspotshade"
    public static let stateDirectoryRelative = "var/db/hotspotshade"
    // The primary lock name. The final single name is still an open review
    // decision because the helper and the Rust engine have used different
    // names during migration. The coordinator holds every name in
    // `heldFileNames` for the whole transaction, so a participant that still
    // uses a transition name is not silently bypassed.
    public static let fileName = "start.lock"
    public static let transitionFileNames = ["start-exclusion", "upgrade.lock"]
    public static let heldFileNames = ([fileName] + transitionFileNames).sorted()
    public static let lockPath = stateDirectory + "/" + fileName
    public static let protocolVersion = 1

    // The names that the helper already owns. The lock lives beside them.
    public static let cleanupMarkerName = RootCleanupBlockStore.defaultFileName
    public static let launchIntentName = RootLaunchIntentStore.defaultFileName
    // The helper writes one start journal per prepared engine start. It is a
    // separate record from the coordinator install journal. A present start
    // journal blocks an install. The coordinator never removes it.
    public static let startJournalName = "start-journal"
    // The helper hands the locked descriptor to the engine on this number. The
    // Rust engine validates the handoff against the lock that it opened.
    public static let handoffDescriptor: Int32 = 5
    public static let handoffVersion = 1
    public static let handoffEnvironmentKeys = [
        "HOTSPOTSHADE_START_EXCLUSION_FD",
        "HOTSPOTSHADE_START_EXCLUSION_VERSION",
        "HOTSPOTSHADE_START_EXCLUSION_DEVICE",
        "HOTSPOTSHADE_START_EXCLUSION_INODE",
    ]
}

public enum InstallLockError: Error, Equatable, CustomStringConvertible {
    case unsafeDirectory(String)
    case unsafeLockFile(String)
    case busy
    case failed(String)

    public var description: String {
        switch self {
        case .unsafeDirectory(let path): return "The lock directory is unsafe: \(path)."
        case .unsafeLockFile(let path): return "The lock file is unsafe: \(path)."
        case .busy: return "Another process holds the install lock."
        case .failed(let why): return "The install lock failed: \(why)."
        }
    }
}

public final class InstallLock: @unchecked Sendable {
    public struct Identity: Equatable, Sendable {
        public let device: UInt64
        public let inode: UInt64
    }

    private let lock = NSLock()
    private var descriptor: Int32
    private var held: Bool
    public let identity: Identity

    private init(descriptor: Int32, identity: Identity) {
        self.descriptor = descriptor
        self.held = true
        self.identity = identity
    }

    deinit {
        release()
    }

    public var isHeld: Bool {
        lock.lock()
        defer { lock.unlock() }
        return held
    }

    // Release the lock and close the descriptor. The lock file itself stays in
    // place. Removing it would let a later process lock a different inode.
    public func release() {
        lock.lock()
        guard held, descriptor >= 0 else {
            lock.unlock()
            return
        }
        held = false
        let current = descriptor
        descriptor = -1
        lock.unlock()
        _ = flock(current, LOCK_UN)
        close(current)
    }

    // Open and take one non-blocking lock. The parent directory must already
    // exist and be safe. A missing lock file is created once with mode 0600 and
    // synced with its directory.
    public static func acquire(
        parentDirectory: String,
        fileName: String = InstallLockLayout.fileName,
        mode: InstallLockMode,
        expectedOwner: UInt32 = 0
    ) throws -> InstallLock {
        guard parentDirectory.hasPrefix("/"), !parentDirectory.contains("\0"),
              !fileName.isEmpty, !fileName.contains("/"), !fileName.contains("\0")
        else { throw InstallLockError.unsafeDirectory(parentDirectory) }

        let parent = open(parentDirectory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0 else { throw InstallLockError.unsafeDirectory(parentDirectory) }
        defer { close(parent) }
        try checkDirectory(parent, path: parentDirectory, expectedOwner: expectedOwner)

        let (descriptor, created) = try openLockFile(
            parent: parent,
            directoryPath: parentDirectory,
            fileName: fileName,
            expectedOwner: expectedOwner
        )
        var transferred = false
        defer {
            if !transferred {
                close(descriptor)
            }
        }

        let operation = mode == .exclusive ? LOCK_EX : LOCK_SH
        if flock(descriptor, operation | LOCK_NB) != 0 {
            if errno == EWOULDBLOCK || errno == EAGAIN {
                throw InstallLockError.busy
            }
            throw InstallLockError.failed("flock")
        }

        // The name must still reach the inode that was checked and locked.
        var opened = stat()
        guard fstat(descriptor, &opened) == 0 else {
            _ = flock(descriptor, LOCK_UN)
            throw InstallLockError.failed("fstat")
        }
        var named = stat()
        let reached = fileName.withCString {
            fstatat(parent, $0, &named, AT_SYMLINK_NOFOLLOW)
        }
        guard reached == 0,
              named.st_dev == opened.st_dev,
              named.st_ino == opened.st_ino,
              named.st_mode & S_IFMT == S_IFREG
        else {
            _ = flock(descriptor, LOCK_UN)
            throw InstallLockError.unsafeLockFile(parentDirectory + "/" + fileName)
        }
        if created {
            guard fsync(descriptor) == 0, fsync(parent) == 0 else {
                _ = flock(descriptor, LOCK_UN)
                throw InstallLockError.failed("sync")
            }
        }
        transferred = true
        return InstallLock(
            descriptor: descriptor,
            identity: Identity(
                device: UInt64(opened.st_dev),
                inode: UInt64(opened.st_ino)
            )
        )
    }

    // Read the canonical lock identity without taking a lock. The status view
    // uses it to compare a start journal with the lock inode. This is not an
    // exclusion check.
    public static func identity(
        parentDirectory: String,
        fileName: String = InstallLockLayout.fileName,
        expectedOwner: UInt32 = 0
    ) throws -> Identity? {
        guard parentDirectory.hasPrefix("/"), !parentDirectory.contains("\0"),
              !fileName.isEmpty, !fileName.contains("/"), !fileName.contains("\0")
        else { throw InstallLockError.unsafeDirectory(parentDirectory) }
        let parent = open(parentDirectory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        if parent < 0 {
            if errno == ENOENT { return nil }
            throw InstallLockError.unsafeDirectory(parentDirectory)
        }
        defer { close(parent) }
        try checkDirectory(parent, path: parentDirectory, expectedOwner: expectedOwner)
        let descriptor = fileName.withCString {
            openat(parent, $0, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        }
        if descriptor < 0 {
            if errno == ENOENT { return nil }
            throw InstallLockError.unsafeLockFile(parentDirectory + "/" + fileName)
        }
        defer { close(descriptor) }
        try checkLockFile(descriptor, path: parentDirectory + "/" + fileName, expectedOwner: expectedOwner)
        var status = stat()
        guard fstat(descriptor, &status) == 0 else {
            throw InstallLockError.failed("fstat")
        }
        return Identity(device: UInt64(status.st_dev), inode: UInt64(status.st_ino))
    }

    private static func openLockFile(
        parent: Int32,
        directoryPath: String,
        fileName: String,
        expectedOwner: UInt32
    ) throws -> (Int32, Bool) {
        let path = directoryPath + "/" + fileName
        // Try an existing file first. O_NOFOLLOW refuses a final symlink.
        let existing = fileName.withCString {
            openat(parent, $0, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
        }
        if existing >= 0 {
            do {
                try checkLockFile(existing, path: path, expectedOwner: expectedOwner)
                return (existing, false)
            } catch {
                close(existing)
                throw error
            }
        }
        guard errno == ENOENT else { throw InstallLockError.unsafeLockFile(path) }

        let created = fileName.withCString {
            openat(
                parent,
                $0,
                O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                mode_t(0o600)
            )
        }
        if created < 0 {
            if errno == EEXIST {
                // Another coordinator created the file between the two opens.
                let retry = fileName.withCString {
                    openat(parent, $0, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
                }
                guard retry >= 0 else { throw InstallLockError.unsafeLockFile(path) }
                do {
                    try checkLockFile(retry, path: path, expectedOwner: expectedOwner)
                    return (retry, false)
                } catch {
                    close(retry)
                    throw error
                }
            }
            throw InstallLockError.failed("open")
        }
        do {
            try checkLockFile(created, path: path, expectedOwner: expectedOwner)
            guard fchmod(created, mode_t(0o600)) == 0 else {
                throw InstallLockError.failed("chmod")
            }
            return (created, true)
        } catch {
            close(created)
            throw error
        }
    }

    private static func checkDirectory(_ descriptor: Int32, path: String, expectedOwner: UInt32) throws {
        var status = stat()
        guard fstat(descriptor, &status) == 0,
              status.st_mode & S_IFMT == S_IFDIR,
              status.st_uid == expectedOwner,
              status.st_mode & 0o077 == 0,
              status.st_mode & 0o7000 == 0,
              !SystemSupport.hasExtendedACL(descriptor)
        else {
            throw InstallLockError.unsafeDirectory(path)
        }
    }

    private static func checkLockFile(_ descriptor: Int32, path: String, expectedOwner: UInt32) throws {
        var status = stat()
        guard fstat(descriptor, &status) == 0,
              status.st_mode & S_IFMT == S_IFREG,
              status.st_uid == expectedOwner,
              status.st_nlink == 1,
              status.st_mode & 0o077 == 0,
              status.st_mode & 0o7000 == 0,
              !SystemSupport.hasExtendedACL(descriptor)
        else {
            throw InstallLockError.unsafeLockFile(path)
        }
    }
}

// The coordinator holds one exclusive lock for every name in
// `InstallLockLayout.heldFileNames`. The set is a transition measure, not the
// approved final design: the helper and the Rust engine used different names
// during migration. A participant that uses any listed name contends with the
// coordinator. A participant that uses another name does not. The gate stays
// off until all owners agree on one name and the live tests run.
//
// The coordinator is the only process that takes more than one of these locks.
// It sorts the names before acquisition and releases in reverse order. Do not
// add a participant that takes two names in another order.
public final class InstallExclusionLease: @unchecked Sendable {
    public let locks: [InstallLock]
    public let fileNameByIdentity: [String: InstallLock.Identity]
    private let guardLock = NSLock()
    private var released = false

    private init(locks: [InstallLock], fileNameByIdentity: [String: InstallLock.Identity]) {
        self.locks = locks
        self.fileNameByIdentity = fileNameByIdentity
    }

    deinit {
        release()
    }

    public var primaryIdentity: InstallLock.Identity? {
        locks.first?.identity
    }

    public func holdsIdentity(device: UInt64, inode: UInt64) -> Bool {
        locks.contains { $0.identity.device == device && $0.identity.inode == inode }
    }

    public func release() {
        guardLock.lock()
        guard !released else {
            guardLock.unlock()
            return
        }
        released = true
        let held = locks
        guardLock.unlock()
        for lock in held.reversed() {
            lock.release()
        }
    }

    public static func acquire(
        parentDirectory: String,
        fileNames: [String] = InstallLockLayout.heldFileNames,
        expectedOwner: UInt32 = 0
    ) throws -> InstallExclusionLease {
        guard !fileNames.isEmpty else { throw InstallLockError.failed("no lock name") }
        let sorted = fileNames.sorted()
        guard Set(sorted).count == sorted.count else {
            throw InstallLockError.failed("a duplicate lock name")
        }
        var held: [InstallLock] = []
        var identities: [String: InstallLock.Identity] = [:]
        do {
            for name in sorted {
                let lock = try InstallLock.acquire(
                    parentDirectory: parentDirectory,
                    fileName: name,
                    mode: .exclusive,
                    expectedOwner: expectedOwner
                )
                held.append(lock)
                identities[name] = lock.identity
            }
        } catch {
            for lock in held.reversed() { lock.release() }
            throw error
        }
        return InstallExclusionLease(locks: held, fileNameByIdentity: identities)
    }
}
