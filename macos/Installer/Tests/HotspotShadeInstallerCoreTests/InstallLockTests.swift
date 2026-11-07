import Foundation
import XCTest
import Darwin
@testable import HotspotShadeInstallerCore

final class InstallLockTests: XCTestCase {
    private func lock(_ fixture: CoordinatorFixture, _ mode: InstallLockMode) throws -> InstallLock {
        try InstallLock.acquire(
            parentDirectory: fixture.sandbox + "/" + CoordinatorFixture.stateRelative,
            mode: mode,
            expectedOwner: UInt32(geteuid())
        )
    }

    private func lockPath(_ fixture: CoordinatorFixture, name: String = InstallLockLayout.fileName) -> String {
        fixture.sandbox + "/" + CoordinatorFixture.stateRelative + "/" + name
    }

    private func seedLockFiles(_ fixture: CoordinatorFixture) throws {
        let lease = try InstallExclusionLease.acquire(
            parentDirectory: fixture.sandbox + "/" + CoordinatorFixture.stateRelative,
            expectedOwner: UInt32(geteuid())
        )
        lease.release()
    }

    func testPathAndProtocolConstantsAreFixed() {
        XCTAssertEqual(InstallLockLayout.lockPath, "/var/db/hotspotshade/start.lock")
        XCTAssertEqual(InstallLockLayout.stateDirectoryRelative, "var/db/hotspotshade")
        XCTAssertEqual(InstallLockLayout.fileName, "start.lock")
        XCTAssertEqual(
            InstallLockLayout.heldFileNames,
            ["start-exclusion", "start.lock", "upgrade.lock"]
        )
        XCTAssertEqual(InstallLockLayout.transitionFileNames, ["start-exclusion", "upgrade.lock"])
        XCTAssertEqual(InstallLockLayout.protocolVersion, 1)
        XCTAssertEqual(InstallLockLayout.cleanupMarkerName, "cleanup-blocked")
        XCTAssertEqual(InstallLockLayout.launchIntentName, "engine-session")
        XCTAssertEqual(InstallLockLayout.startJournalName, "start-journal")
        XCTAssertEqual(InstallLockLayout.handoffDescriptor, 5)
        XCTAssertEqual(InstallLockLayout.handoffVersion, 1)
    }

    // Darwin `flock` does not report contention between two independent opens
    // in one process. A real participant is a separate process, so these tests
    // use a compiled probe that holds the same inode with the same syscall.
    private static let probeSource = #"""
    #include <fcntl.h>
    #include <sys/file.h>
    #include <unistd.h>
    #include <string.h>

    int main(int argc, char **argv) {
        if (argc != 3) return 2;
        int mode;
        int wait_for_input = 1;
        if (strcmp(argv[1], "shared") == 0) mode = LOCK_SH;
        else if (strcmp(argv[1], "exclusive") == 0) mode = LOCK_EX;
        else if (strcmp(argv[1], "try") == 0) { mode = LOCK_EX; wait_for_input = 0; }
        else return 2;
        int fd = open(argv[2], O_RDWR | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) return 3;
        if (flock(fd, mode | LOCK_NB) != 0) return 4;
        if (!wait_for_input) return 0;
        char ready = 'x';
        if (write(STDOUT_FILENO, &ready, 1) != 1) return 5;
        char byte;
        (void)read(STDIN_FILENO, &byte, 1);
        return 0;
    }
    """#

    private func compileProbe() throws -> (Workspace, String) {
        guard FileManager.default.isExecutableFile(atPath: "/usr/bin/clang") else {
            throw XCTSkip("no clang")
        }
        let workspace = try Workspace()
        let source = try workspace.write("lockprobe.c", Data(Self.probeSource.utf8), mode: 0o644)
        let binary = workspace.path("lockprobe")
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/clang")
        process.arguments = [source, "-o", binary]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw XCTSkip("clang cannot build the probe") }
        return (workspace, binary)
    }

    private func startProbe(
        binary: String,
        mode: String,
        path: String
    ) throws -> (Process, Pipe) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: binary)
        process.arguments = [mode, path]
        let input = Pipe()
        let output = Pipe()
        process.standardInput = input
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        try process.run()
        let ready = try output.fileHandleForReading.read(upToCount: 1)
        guard ready == Data([0x78]) else {
            process.terminate()
            process.waitUntilExit()
            throw XCTSkip("the lock probe did not take the lock")
        }
        return (process, input)
    }

    private func stopProbe(_ process: Process, _ input: Pipe) throws {
        try input.fileHandleForWriting.write(contentsOf: Data([0x0a]))
        try input.fileHandleForWriting.close()
        process.waitUntilExit()
    }

    private func seedLockFile(_ fixture: CoordinatorFixture) throws {
        try seedLockFiles(fixture)
    }

    private func runTryProbe(binary: String, path: String) throws -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: binary)
        process.arguments = ["try", path]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        return process.terminationStatus
    }

    func testHeldLeaseBlocksASeparateProcessAndReleaseRestoresAccess() throws {
        let fixture = try CoordinatorFixture()
        try fixture.makeStateDirectory()
        let (workspace, binary) = try compileProbe()
        _ = workspace
        let lease = try InstallExclusionLease.acquire(
            parentDirectory: fixture.sandbox + "/" + CoordinatorFixture.stateRelative,
            expectedOwner: UInt32(geteuid())
        )
        XCTAssertEqual(
            try runTryProbe(binary: binary, path: lockPath(fixture)),
            4,
            "the held coordinator lease did not block another process"
        )
        lease.release()
        XCTAssertEqual(
            try runTryProbe(binary: binary, path: lockPath(fixture)),
            0,
            "the released coordinator lease still blocked another process"
        )
    }

    func testHeldSharedLockBlocksAnExclusiveProbe() throws {
        let fixture = try CoordinatorFixture()
        try fixture.makeStateDirectory()
        let (workspace, binary) = try compileProbe()
        _ = workspace
        let shared = try lock(fixture, .shared)
        XCTAssertEqual(
            try runTryProbe(binary: binary, path: lockPath(fixture)),
            4,
            "the held shared lock did not block an exclusive process"
        )
        shared.release()
        XCTAssertEqual(
            try runTryProbe(binary: binary, path: lockPath(fixture)),
            0
        )
    }

    func testCrossProcessSharedLockBlocksTheCoordinatorForEveryHeldName() throws {
        let (workspace, binary) = try compileProbe()
        _ = workspace
        for name in InstallLockLayout.heldFileNames {
            let fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
            try fixture.makeStateDirectory()
            try seedLockFiles(fixture)
            let (process, input) = try startProbe(
                binary: binary,
                mode: "shared",
                path: lockPath(fixture, name: name)
            )
            defer {
                if process.isRunning {
                    process.terminate()
                    process.waitUntilExit()
                }
            }
            XCTAssertThrowsError(
                try fixture.coordinator().install(source: fixture.source),
                name
            ) {
                XCTAssertEqual($0 as? CoordinatorError, .lockUnavailable, name)
            }
            try fixture.assertOldSet()
            XCTAssertFalse(fixture.targetExists(CoordinatorFixture.journalRelative), name)
            try stopProbe(process, input)
            XCTAssertFalse(process.isRunning)
            let outcome = try fixture.coordinator().install(source: fixture.source)
            XCTAssertEqual(outcome.fileCount, 4, name)
            try fixture.assertNewSet()
        }
    }

    func testLeaseCreatesAndHoldsEveryKnownLockFile() throws {
        let fixture = try CoordinatorFixture()
        try fixture.makeStateDirectory()
        let lease = try InstallExclusionLease.acquire(
            parentDirectory: fixture.sandbox + "/" + CoordinatorFixture.stateRelative,
            expectedOwner: UInt32(geteuid())
        )
        XCTAssertEqual(lease.locks.count, InstallLockLayout.heldFileNames.count)
        XCTAssertEqual(lease.fileNameByIdentity.count, InstallLockLayout.heldFileNames.count)
        for name in InstallLockLayout.heldFileNames {
            let attributes = try FileManager.default.attributesOfItem(atPath: lockPath(fixture, name: name))
            XCTAssertEqual((attributes[.posixPermissions] as! NSNumber).intValue, 0o600, name)
            XCTAssertTrue(
                lease.holdsIdentity(
                    device: lease.fileNameByIdentity[name]!.device,
                    inode: lease.fileNameByIdentity[name]!.inode
                ),
                name
            )
        }
        lease.release()
        let after = try InstallExclusionLease.acquire(
            parentDirectory: fixture.sandbox + "/" + CoordinatorFixture.stateRelative,
            expectedOwner: UInt32(geteuid())
        )
        after.release()
    }

    func testCrossProcessExclusiveLockBlocksSharedAndExclusiveAcquisition() throws {
        let fixture = try CoordinatorFixture()
        try fixture.makeStateDirectory()
        let (workspace, binary) = try compileProbe()
        _ = workspace
        try seedLockFile(fixture)
        let (process, input) = try startProbe(
            binary: binary,
            mode: "exclusive",
            path: lockPath(fixture)
        )
        defer {
            if process.isRunning {
                process.terminate()
                process.waitUntilExit()
            }
        }
        XCTAssertThrowsError(try lock(fixture, .shared)) {
            XCTAssertEqual($0 as? InstallLockError, .busy)
        }
        XCTAssertThrowsError(try lock(fixture, .exclusive)) {
            XCTAssertEqual($0 as? InstallLockError, .busy)
        }
        try stopProbe(process, input)
        let after = try lock(fixture, .exclusive)
        after.release()
    }

    func testTerminatedHolderReleasesTheKernelLock() throws {
        let fixture = try CoordinatorFixture()
        try fixture.makeStateDirectory()
        let (workspace, binary) = try compileProbe()
        _ = workspace
        try seedLockFile(fixture)
        let (process, _) = try startProbe(
            binary: binary,
            mode: "exclusive",
            path: lockPath(fixture)
        )
        XCTAssertThrowsError(try lock(fixture, .exclusive)) {
            XCTAssertEqual($0 as? InstallLockError, .busy)
        }
        process.terminate()
        process.waitUntilExit()
        let after = try lock(fixture, .exclusive)
        after.release()
    }

    func testLockFileIsPrivateAndPersistent() throws {
        let fixture = try CoordinatorFixture()
        try fixture.makeStateDirectory()
        let first = try lock(fixture, .exclusive)
        first.release()
        let path = lockPath(fixture)
        let attributes = try FileManager.default.attributesOfItem(atPath: path)
        XCTAssertEqual((attributes[.posixPermissions] as! NSNumber).intValue, 0o600)
        XCTAssertEqual(attributes[.ownerAccountID] as? NSNumber, NSNumber(value: geteuid()))
        // A release never removes the object, so a later process locks the
        // same inode.
        XCTAssertTrue(FileManager.default.fileExists(atPath: path))
        let second = try lock(fixture, .shared)
        second.release()
    }

    func testLockIdentityIsStableAcrossAnOpenAndRelease() throws {
        let fixture = try CoordinatorFixture()
        try fixture.makeStateDirectory()
        let first = try lock(fixture, .exclusive)
        let identity = first.identity
        first.release()
        let read = try InstallLock.identity(
            parentDirectory: fixture.sandbox + "/" + CoordinatorFixture.stateRelative,
            expectedOwner: UInt32(geteuid())
        )
        XCTAssertEqual(read, identity)
    }

    func testSymlinkLockFileIsRefused() throws {
        let fixture = try CoordinatorFixture()
        try fixture.makeStateDirectory()
        let state = fixture.sandbox + "/" + CoordinatorFixture.stateRelative
        try Data("x".utf8).write(to: URL(fileURLWithPath: state + "/target"))
        try FileManager.default.createSymbolicLink(
            atPath: state + "/" + InstallLockLayout.fileName,
            withDestinationPath: state + "/target"
        )
        XCTAssertThrowsError(try lock(fixture, .exclusive)) {
            if case .unsafeLockFile? = $0 as? InstallLockError {} else { XCTFail("\($0)") }
        }
    }

    func testWritableLockFileIsRefused() throws {
        let fixture = try CoordinatorFixture()
        try fixture.makeStateDirectory()
        try fixture.writeFile(lockPath(fixture), Data(), mode: 0o666)
        XCTAssertThrowsError(try lock(fixture, .exclusive)) {
            if case .unsafeLockFile? = $0 as? InstallLockError {} else { XCTFail("\($0)") }
        }
    }

    func testStickyLockFileIsRefused() throws {
        let fixture = try CoordinatorFixture()
        try fixture.makeStateDirectory()
        let path = lockPath(fixture)
        try fixture.writeFile(path, Data(), mode: 0o600)
        XCTAssertEqual(chmod(path, mode_t(0o1600)), 0)
        var status = stat()
        XCTAssertEqual(lstat(path, &status), 0)
        XCTAssertNotEqual(status.st_mode & 0o1000, 0)
        XCTAssertThrowsError(try lock(fixture, .exclusive)) {
            if case .unsafeLockFile? = $0 as? InstallLockError {} else { XCTFail("\($0)") }
        }
    }

    func testDirectoryAtTheLockNameIsRefused() throws {
        let fixture = try CoordinatorFixture()
        try fixture.makeStateDirectory()
        try FileManager.default.createDirectory(atPath: lockPath(fixture), withIntermediateDirectories: false)
        XCTAssertThrowsError(try lock(fixture, .exclusive)) {
            if case .unsafeLockFile? = $0 as? InstallLockError {} else { XCTFail("\($0)") }
        }
    }

    func testHardLinkedLockFileIsRefused() throws {
        let fixture = try CoordinatorFixture()
        try fixture.makeStateDirectory()
        let state = fixture.sandbox + "/" + CoordinatorFixture.stateRelative
        let other = state + "/other"
        try Data().write(to: URL(fileURLWithPath: other))
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: other)
        XCTAssertEqual(link(other, lockPath(fixture)), 0)
        XCTAssertThrowsError(try lock(fixture, .exclusive)) {
            if case .unsafeLockFile? = $0 as? InstallLockError {} else { XCTFail("\($0)") }
        }
    }

    func testUnsafeStateDirectoryIsRefused() throws {
        let fixture = try CoordinatorFixture()
        try fixture.makeStateDirectory()
        let state = fixture.sandbox + "/" + CoordinatorFixture.stateRelative
        try FileManager.default.setAttributes([.posixPermissions: 0o777], ofItemAtPath: state)
        XCTAssertThrowsError(try lock(fixture, .exclusive)) {
            XCTAssertEqual($0 as? InstallLockError, .unsafeDirectory(state))
        }
    }

    func testStickyStateDirectoryIsRefused() throws {
        let fixture = try CoordinatorFixture()
        try fixture.makeStateDirectory()
        let state = fixture.sandbox + "/" + CoordinatorFixture.stateRelative
        XCTAssertEqual(chmod(state, mode_t(0o1700)), 0)
        var status = stat()
        XCTAssertEqual(lstat(state, &status), 0)
        XCTAssertNotEqual(status.st_mode & 0o1000, 0)
        XCTAssertThrowsError(try lock(fixture, .exclusive)) {
            XCTAssertEqual($0 as? InstallLockError, .unsafeDirectory(state))
        }
    }

    func testReadableStateDirectoryIsRefused() throws {
        let fixture = try CoordinatorFixture()
        try fixture.makeStateDirectory()
        let state = fixture.sandbox + "/" + CoordinatorFixture.stateRelative
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: state)
        XCTAssertThrowsError(try lock(fixture, .exclusive)) {
            XCTAssertEqual($0 as? InstallLockError, .unsafeDirectory(state))
        }
    }
}
