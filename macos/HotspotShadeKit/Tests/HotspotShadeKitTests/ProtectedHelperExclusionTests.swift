import XCTest
import Foundation
import Darwin
@testable import HotspotShadeKit

// These tests exercise the real Darwin `flock` file in a temporary directory.
// They do not run as root, install a helper, spawn an engine, create a route, or
// touch a TUN device.
final class ProtectedHelperExclusionTests: XCTestCase {
    private func temporaryDirectory() throws -> String {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("hotspotshade-exclusion-" + UUID().uuidString)
            .path
        try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: false)
        return path
    }

    private func store(root: String) -> RootStartExclusionStore {
        RootStartExclusionStore(
            directoryPath: root + "/state",
            lockFileName: HelperStartExclusionProtocol.lockFileName,
            installJournalFileName: HelperStartExclusionProtocol.installJournalFileName,
            expectedOwner: geteuid()
        )
    }

    private func openForLock(_ path: String, flags: Int32 = O_RDONLY) -> Int32 {
        path.withCString { pointer in
            Darwin.open(pointer, flags | O_NOFOLLOW | O_CLOEXEC)
        }
    }

    @discardableResult
    private func createEmptyFile(_ path: String, mode: mode_t = 0o600) -> Bool {
        let descriptor = path.withCString { pointer in
            Darwin.open(
                pointer,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                mode
            )
        }
        guard descriptor >= 0 else { return false }
        close(descriptor)
        return true
    }

    private func isExclusiveLockFree(_ path: String) -> Bool {
        let descriptor = openForLock(path)
        guard descriptor >= 0 else { return false }
        defer { close(descriptor) }
        return flock(descriptor, LOCK_EX | LOCK_NB) == 0
    }

    // Drift guard for the current helper and engine contract. The installer
    // coordinator still names `start.lock`, so the two sides do not contend
    // until that owner aligns. This test must change with every participant.
    func testProtocolNamesMatchTheCurrentHelperAndEngineContract() {
        XCTAssertEqual(HelperStartExclusionProtocol.stateDirectoryPath, "/var/db/hotspotshade")
        XCTAssertEqual(HelperStartExclusionProtocol.lockFileName, "start-exclusion")
        XCTAssertEqual(HelperStartExclusionProtocol.installJournalFileName, "install-journal.json")
        XCTAssertEqual(HelperStartExclusionProtocol.protocolVersion, 1)
        XCTAssertEqual(HelperStartExclusionProtocol.handoffDescriptor, 5)
    }

    func testFirstStartCreatesAPermanentPrivateLockFile() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let exclusion = store(root: root)
        let lease = try exclusion.prepare(session: UUID())
        let path = exclusion.lockPath
        var status = stat()
        XCTAssertEqual(lstat(path, &status), 0)
        XCTAssertEqual(status.st_mode & S_IFMT, S_IFREG)
        XCTAssertEqual(status.st_uid, geteuid())
        XCTAssertEqual(status.st_nlink, 1)
        XCTAssertEqual(status.st_mode & 0o777, 0o600)
        lease.releaseAfterCleanStop()
        XCTAssertEqual(lstat(path, &status), 0, "The lock file is permanent, not removed.")
    }

    func testStateDirectoryWithAnExtendedACLFailsClosed() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let state = root + "/state"
        try FileManager.default.createDirectory(atPath: state, withIntermediateDirectories: false)
        XCTAssertEqual(chmod(state, 0o700), 0)
        XCTAssertTrue(ProtectedHelperTestSupport.addExtendedACL(to: state))
        let exclusion = store(root: root)
        XCTAssertThrowsError(try exclusion.isInstallJournalPresent()) {
            XCTAssertEqual($0 as? HelperStartExclusionError, .unsafe)
        }
        XCTAssertEqual(exclusion.probeSharedAvailability(), .unavailable)
        XCTAssertThrowsError(try exclusion.prepare(session: UUID())) {
            XCTAssertEqual($0 as? HelperStartExclusionError, .unsafe)
        }
    }

    func testLockFileWithAnExtendedACLFailsClosed() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let exclusion = store(root: root)
        let setup = try exclusion.prepare(session: UUID())
        setup.releaseAfterCleanStop()
        XCTAssertTrue(ProtectedHelperTestSupport.addExtendedACL(to: exclusion.lockPath))
        XCTAssertEqual(exclusion.probeSharedAvailability(), .unavailable)
        XCTAssertThrowsError(try exclusion.prepare(session: UUID())) {
            XCTAssertEqual($0 as? HelperStartExclusionError, .unsafe)
        }
    }

    func testACLReadFailureIsAnErrorNotAnAbsentACL() {
        XCTAssertThrowsError(try RootStartExclusionStore.hasExtendedACL(-1)) {
            XCTAssertEqual($0 as? HelperStartExclusionError, .unavailable)
        }
        XCTAssertThrowsError(try RootStateDirectory.hasExtendedACL(-1)) {
            XCTAssertEqual($0 as? RootStateDirectoryError, .unreadable)
        }
    }

    // A shared lock from an independent open succeeds. An exclusive lock fails
    // until every shared holder is gone. This is the kernel behavior that the
    // installer coordinator relies on, not a process scan.
    func testSharedLocksCoexistAndBlockExclusive() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let exclusion = store(root: root)
        let lease = try exclusion.prepare(session: UUID())
        let lockPath = exclusion.lockPath

        let shared = openForLock(lockPath)
        XCTAssertGreaterThanOrEqual(shared, 0)
        XCTAssertEqual(flock(shared, LOCK_SH | LOCK_NB), 0)

        let exclusive = openForLock(lockPath)
        XCTAssertGreaterThanOrEqual(exclusive, 0)
        XCTAssertEqual(flock(exclusive, LOCK_EX | LOCK_NB), -1)
        XCTAssertEqual(errno, EWOULDBLOCK)
        close(exclusive)
        close(shared)

        lease.releaseAfterCleanStop()
        XCTAssertTrue(isExclusiveLockFree(lockPath))
    }

    func testExclusiveLockRefusesPrepareAndTheAdvisoryProbe() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let exclusion = store(root: root)
        let setup = try exclusion.prepare(session: UUID())
        setup.releaseAfterCleanStop()

        let exclusive = openForLock(exclusion.lockPath, flags: O_RDWR)
        XCTAssertGreaterThanOrEqual(exclusive, 0)
        defer { close(exclusive) }
        XCTAssertEqual(flock(exclusive, LOCK_EX | LOCK_NB), 0)
        XCTAssertEqual(exclusion.probeSharedAvailability(), .busy)
        XCTAssertThrowsError(try exclusion.prepare(session: UUID())) {
            XCTAssertEqual($0 as? HelperStartExclusionError, .busy)
        }

        XCTAssertEqual(flock(exclusive, LOCK_UN), 0)
        XCTAssertEqual(exclusion.probeSharedAvailability(), .available)
        let lease = try exclusion.prepare(session: UUID())
        lease.releaseAfterCleanStop()
    }

    // Another process, not another descriptor in this process, must also fail
    // to take the exclusive lock while the helper holds a shared lock. The
    // child opens its own descriptor on the same lock path.
    func testAnotherProcessCannotTakeExclusiveWhileHelperHoldsShared() throws {
        let perl = "/usr/bin/perl"
        guard FileManager.default.isExecutableFile(atPath: perl) else {
            throw XCTSkip("perl is not available for the cross-process lock probe")
        }
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let exclusion = store(root: root)
        let lease = try exclusion.prepare(session: UUID())
        defer { lease.releaseAfterCleanStop() }

        // Exit 0 means the exclusive lock was blocked. Exit 1 means the probe
        // acquired it, and exit 2 means the file could not be opened.
        let script = """
        use Fcntl qw(:flock O_RDONLY);
        sysopen(my $fh, $ARGV[0], O_RDONLY) or exit 2;
        flock($fh, LOCK_EX | LOCK_NB) or exit 0;
        exit 1;
        """
        let process = Process()
        process.executableURL = URL(fileURLWithPath: perl)
        process.arguments = ["-e", script, exclusion.lockPath]
        try process.run()
        process.waitUntilExit()
        XCTAssertEqual(
            process.terminationStatus,
            0,
            "Another process must not take the exclusive lock while the helper holds a shared lock."
        )
    }

    func testInstallJournalPresenceBlocksAPrepare() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let exclusion = store(root: root)
        let setup = try exclusion.prepare(session: UUID())
        setup.releaseAfterCleanStop()

        XCTAssertTrue(createEmptyFile(exclusion.installJournalPath))
        XCTAssertTrue(try exclusion.isInstallJournalPresent())
        XCTAssertThrowsError(try exclusion.prepare(session: UUID())) {
            XCTAssertEqual($0 as? HelperStartExclusionError, .installJournalPresent)
        }
        XCTAssertTrue(isExclusiveLockFree(exclusion.lockPath))

        XCTAssertEqual(unlink(exclusion.installJournalPath), 0)
        let lease = try exclusion.prepare(session: UUID())
        lease.releaseAfterCleanStop()
    }

    func testServiceJournalPresenceBlocksAPrepare() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let exclusion = store(root: root)
        let setup = try exclusion.prepare(session: UUID())
        setup.releaseAfterCleanStop()
        let path = root + "/state/" + HelperStartExclusionProtocol.serviceJournalFileName

        XCTAssertTrue(createEmptyFile(path))
        XCTAssertTrue(try exclusion.isInstallJournalPresent())
        XCTAssertThrowsError(try exclusion.prepare(session: UUID())) {
            XCTAssertEqual($0 as? HelperStartExclusionError, .installJournalPresent)
        }
        XCTAssertTrue(isExclusiveLockFree(exclusion.lockPath))
        XCTAssertEqual(unlink(path), 0)

        XCTAssertEqual(symlink(root + "/missing", path), 0)
        XCTAssertThrowsError(try exclusion.isInstallJournalPresent())
        XCTAssertThrowsError(try exclusion.prepare(session: UUID()))
    }

    func testUnsafeInstallJournalFailsClosed() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let state = root + "/state"
        try FileManager.default.createDirectory(atPath: state, withIntermediateDirectories: false)
        XCTAssertEqual(chmod(state, 0o700), 0)
        let target = root + "/journal-target"
        try Data("not a journal".utf8).write(to: URL(fileURLWithPath: target))
        XCTAssertEqual(
            symlink(target, state + "/" + HelperStartExclusionProtocol.installJournalFileName),
            0
        )
        let exclusion = store(root: root)
        XCTAssertThrowsError(try exclusion.isInstallJournalPresent()) {
            XCTAssertEqual($0 as? HelperStartExclusionError, .unsafe)
        }
        XCTAssertThrowsError(try exclusion.prepare(session: UUID())) {
            XCTAssertEqual($0 as? HelperStartExclusionError, .unsafe)
        }
    }

    func testLockFileRefusesGroupOrOtherPermission() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let exclusion = store(root: root)
        let setup = try exclusion.prepare(session: UUID())
        setup.releaseAfterCleanStop()

        XCTAssertEqual(chmod(exclusion.lockPath, 0o644), 0)
        XCTAssertThrowsError(try exclusion.prepare(session: UUID())) {
            XCTAssertEqual($0 as? HelperStartExclusionError, .unsafe)
        }

        XCTAssertEqual(chmod(exclusion.lockPath, 0o600), 0)
        let restored = try exclusion.prepare(session: UUID())
        restored.releaseAfterCleanStop()
    }

    func testLockFileRejectsASymlinkADirectoryAndMultipleLinks() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let state = root + "/state"
        try FileManager.default.createDirectory(atPath: state, withIntermediateDirectories: false)
        XCTAssertEqual(chmod(state, 0o700), 0)
        let target = root + "/target"
        try Data("not a lock".utf8).write(to: URL(fileURLWithPath: target))
        XCTAssertEqual(symlink(target, state + "/" + HelperStartExclusionProtocol.lockFileName), 0)
        let exclusion = store(root: root)
        XCTAssertThrowsError(try exclusion.prepare(session: UUID()))

        XCTAssertEqual(unlink(state + "/" + HelperStartExclusionProtocol.lockFileName), 0)
        XCTAssertEqual(mkdir(state + "/" + HelperStartExclusionProtocol.lockFileName, 0o700), 0)
        XCTAssertThrowsError(try exclusion.prepare(session: UUID()))

        XCTAssertEqual(rmdir(state + "/" + HelperStartExclusionProtocol.lockFileName), 0)
        let setup = try exclusion.prepare(session: UUID())
        setup.releaseAfterCleanStop()
        let second = root + "/second"
        XCTAssertEqual(link(exclusion.lockPath, second), 0)
        XCTAssertThrowsError(try exclusion.prepare(session: UUID())) {
            XCTAssertEqual($0 as? HelperStartExclusionError, .unsafe)
        }
    }

    // Replacing the lock path creates a different inode. A start that still
    // holds the old inode and a later start on the new inode do not exclude one
    // another. The coordinator must never replace the lock file; this test
    // records the counterexample instead of assuming otherwise.
    func testReplacingTheLockInodeCreatesASecondLock() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let exclusion = store(root: root)
        let first = try exclusion.prepare(session: UUID())
        XCTAssertEqual(unlink(exclusion.lockPath), 0)
        XCTAssertTrue(createEmptyFile(exclusion.lockPath))
        XCTAssertThrowsError(try first.handoff.verify()) {
            XCTAssertEqual($0 as? HelperStartExclusionError, .unsafe)
        }
        let second = try exclusion.prepare(session: UUID())
        first.releaseAfterCleanStop()
        second.releaseAfterCleanStop()
    }

    func testHandoffVerificationChecksTheHeldDescriptorInodeAndMode() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let exclusion = store(root: root)
        let lease = try exclusion.prepare(session: UUID())
        defer { lease.releaseAfterCleanStop() }

        var status = stat()
        XCTAssertEqual(lstat(exclusion.lockPath, &status), 0)
        let wrongInode = HelperStartExclusionHandoff(
            descriptor: lease.handoff.descriptor,
            lockPath: exclusion.lockPath,
            lockDevice: UInt64(status.st_dev),
            lockInode: UInt64(status.st_ino) + 1,
            expectedOwner: geteuid()
        )
        XCTAssertThrowsError(try wrongInode.verify()) {
            XCTAssertEqual($0 as? HelperStartExclusionError, .unsafe)
        }

        // The mode check must use the held descriptor as well as the path.
        XCTAssertEqual(chmod(exclusion.lockPath, 0o644), 0)
        XCTAssertThrowsError(try lease.handoff.verify()) {
            XCTAssertEqual($0 as? HelperStartExclusionError, .unsafe)
        }
        XCTAssertEqual(chmod(exclusion.lockPath, 0o600), 0)

        let invalid = HelperStartExclusionHandoff(
            descriptor: -1,
            lockPath: exclusion.lockPath,
            lockDevice: UInt64(status.st_dev),
            lockInode: UInt64(status.st_ino),
            expectedOwner: geteuid()
        )
        XCTAssertThrowsError(try invalid.verify()) {
            XCTAssertEqual($0 as? HelperStartExclusionError, .unavailable)
        }
    }

    // Opening a FIFO without O_NONBLOCK would stop the helper before it could
    // reject the object. The path verification must open nonblocking and then
    // fail the regular-file check.
    func testHandoffVerificationOpensThePathWithoutBlocking() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let exclusion = store(root: root)
        let lease = try exclusion.prepare(session: UUID())
        defer { lease.releaseAfterCleanStop() }
        XCTAssertEqual(unlink(exclusion.lockPath), 0)
        XCTAssertEqual(mkfifo(exclusion.lockPath, 0o600), 0)
        XCTAssertThrowsError(try lease.handoff.verify()) {
            XCTAssertEqual($0 as? HelperStartExclusionError, .unsafe)
        }
    }

    func testHandoffFileActionRejectsAnInvalidOrAliasedDescriptor() {
        var actions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&actions)
        defer { posix_spawn_file_actions_destroy(&actions) }
        let invalid = HelperStartExclusionHandoff(
            descriptor: -1,
            lockPath: "/tmp/unused",
            lockDevice: 0,
            lockInode: 0
        )
        XCTAssertFalse(HelperStartExclusionSpawn.addHandoff(to: &actions, handoff: invalid))
        let aliased = HelperStartExclusionHandoff(
            descriptor: HelperStartExclusionProtocol.handoffDescriptor,
            lockPath: "/tmp/unused",
            lockDevice: 0,
            lockInode: 0
        )
        XCTAssertFalse(HelperStartExclusionSpawn.addHandoff(to: &actions, handoff: aliased))
    }

    // The Rust engine expects the locked descriptor on descriptor 5. The child
    // inherits it through the exact file action that the launcher uses.
    func testSpawnedChildInheritsTheSharedLock() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let exclusion = store(root: root)
        let lease = try exclusion.prepare(session: UUID())
        defer { lease.abandon() }

        var inputPipe: [Int32] = [-1, -1]
        XCTAssertEqual(pipe(&inputPipe), 0)
        var inputWrite = inputPipe[1]
        defer {
            if inputWrite >= 0 { close(inputWrite) }
        }

        var actions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&actions)
        XCTAssertEqual(posix_spawn_file_actions_adddup2(&actions, inputPipe[0], 0), 0)
        XCTAssertEqual(posix_spawn_file_actions_addclose(&actions, inputPipe[0]), 0)
        XCTAssertTrue(HelperStartExclusionSpawn.addHandoff(to: &actions, handoff: lease.handoff))

        var attributes: posix_spawnattr_t?
        posix_spawnattr_init(&attributes)
        posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT))

        let argumentStrings: [String] = ["/bin/sh", "-c", "read line"]
        let environmentStrings: [String] = ["PATH=/usr/bin:/bin"]
        let arguments: [UnsafeMutablePointer<CChar>?] = argumentStrings.map { strdup($0) } + [nil]
        let environment: [UnsafeMutablePointer<CChar>?] = environmentStrings.map { strdup($0) } + [nil]
        defer {
            for pointer in arguments { free(pointer) }
            for pointer in environment { free(pointer) }
        }

        var child: pid_t = 0
        let result = posix_spawn(
            &child,
            "/bin/sh",
            &actions,
            &attributes,
            arguments,
            environment
        )
        posix_spawn_file_actions_destroy(&actions)
        posix_spawnattr_destroy(&attributes)
        close(inputPipe[0])
        XCTAssertEqual(result, 0)
        XCTAssertGreaterThan(child, 0)
        guard result == 0, child > 0 else { return }

        // The parent closes its own lock copy so only the child remains. The
        // lease is abandoned so it does not close the descriptor a second time.
        lease.abandon()
        close(lease.handoff.descriptor)
        XCTAssertFalse(isExclusiveLockFree(exclusion.lockPath))

        let newline = Array("\n".utf8)
        XCTAssertEqual(write(inputWrite, newline, newline.count), newline.count)
        close(inputWrite)
        inputWrite = -1
        var status: Int32 = 0
        XCTAssertEqual(waitpid(child, &status, 0), child)
        XCTAssertEqual((status & 0x7f), 0)
        XCTAssertTrue(isExclusiveLockFree(exclusion.lockPath))
    }

    func testClosingOneDuplicateKeepsTheSharedLock() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let exclusion = store(root: root)
        let lease = try exclusion.prepare(session: UUID())
        let independent = openForLock(exclusion.lockPath)
        XCTAssertGreaterThanOrEqual(independent, 0)
        XCTAssertEqual(flock(independent, LOCK_SH | LOCK_NB), 0)
        let duplicate = dup(independent)
        close(independent)
        XCTAssertGreaterThanOrEqual(duplicate, 0)
        // The lease and the duplicate are independent open file descriptions.
        // Closing the lease leaves the duplicate's shared lock in place.
        lease.releaseAfterCleanStop()
        XCTAssertFalse(isExclusiveLockFree(exclusion.lockPath))
        close(duplicate)
        XCTAssertTrue(isExclusiveLockFree(exclusion.lockPath))
    }
}
