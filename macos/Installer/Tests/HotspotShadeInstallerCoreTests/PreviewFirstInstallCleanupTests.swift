import Darwin
import Foundation
import XCTest
import HotspotShadeKit
@testable import HotspotShadeInstallerCore

// The cleanup seam is exercised with a sandbox tree and a fake service runtime.
// These tests never run as root, never write a system path, never call
// launchctl or security authorizationdb, and never change a route or a TUN
// device. They prove the hermetic decision logic, not a live removal.
final class PreviewFirstInstallCleanupTests: XCTestCase {
    private struct Installed {
        let fixture: CoordinatorFixture
        let rights: FakeAuthorizationRightStore
        let launchd: FakeLaunchdJobController
        let runtime: FakeServiceRuntime
    }

    private var fileRelatives: [String] {
        InstallerLayout.entries.map { InstallJournal.relativeDestination($0.destination) }
    }

    private var installRoot: String {
        InstallJournal.relativeDestination(InstallerLayout.installLocation)
    }

    private var removableDirectories: [String] {
        PreviewFirstInstallCleanup.removableDirectories
    }

    private func installedPreview() throws -> Installed {
        let fixture = try CoordinatorFixture()
        let rights = FakeAuthorizationRightStore()
        let launchd = FakeLaunchdJobController()
        let runtime = FakeServiceRuntime(authorizationRights: rights, launchd: launchd)
        _ = try fixture.coordinator().installFirstTime(source: fixture.source, runtime: runtime)
        return Installed(fixture: fixture, rights: rights, launchd: launchd, runtime: runtime)
    }

    private func cleanup(
        _ installed: Installed,
        faults: PreviewCleanupFaultInjecting = NoPreviewCleanupFaults(),
        team: String = FakeSignatures.team
    ) throws -> PreviewFirstInstallCleanup {
        try PreviewFirstInstallCleanup(
            tree: try ServiceTestFixtures.tree(installed.fixture),
            runtime: installed.runtime,
            validator: InstallerValidator(signatures: FakeSignatures.standard),
            expectedTeamIdentifier: team,
            faults: faults
        )
    }

    private func assertNoServiceChange(
        _ installed: Installed,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertEqual(installed.launchd.bootoutCount, 0, file: file, line: line)
        XCTAssertEqual(installed.rights.removeCount, 0, file: file, line: line)
    }

    private func assertSetStillInstalled(
        _ installed: Installed,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        assertNoServiceChange(installed, file: file, line: line)
        for relative in fileRelatives {
            XCTAssertTrue(
                installed.fixture.targetExists(relative), relative, file: file, line: line
            )
        }
    }

    // MARK: the successful first install

    func testFullCleanupRemovesTheFixedSetAndKeepsSharedState() throws {
        let installed = try installedPreview()
        let report = try cleanup(installed).run()

        XCTAssertTrue(report.removedLaunchdJob)
        XCTAssertTrue(report.removedAuthorizationRight)
        XCTAssertEqual(report.removedFiles, fileRelatives)
        XCTAssertEqual(report.removedEmptyDirectories, removableDirectories)
        XCTAssertEqual(report.keptNonEmptyDirectories, [])
        XCTAssertTrue(report.changedAnything)
        XCTAssertEqual(installed.launchd.bootoutCount, 1)
        XCTAssertEqual(installed.rights.removeCount, 1)

        for relative in fileRelatives {
            XCTAssertFalse(installed.fixture.targetExists(relative), relative)
        }
        XCTAssertFalse(installed.fixture.targetExists(installRoot))
        // The standard parent and the standard helper directory stay.
        XCTAssertTrue(installed.fixture.targetExists("Library/Application Support"))
        XCTAssertTrue(installed.fixture.targetExists("Library/PrivilegedHelperTools"))
        // The state directory and its lock files are shared protocol files.
        XCTAssertTrue(installed.fixture.targetExists(CoordinatorFixture.stateRelative))
        for name in InstallLockLayout.heldFileNames {
            XCTAssertTrue(
                installed.fixture.targetExists(CoordinatorFixture.stateRelative + "/" + name), name
            )
        }
    }

    func testSecondRunRemovesNothing() throws {
        let installed = try installedPreview()
        _ = try cleanup(installed).run()

        let second = try cleanup(installed).run()
        XCTAssertEqual(second, PreviewCleanupReport.nothingToRemove)
        XCTAssertFalse(second.changedAnything)
        XCTAssertEqual(installed.launchd.bootoutCount, 1)
        XCTAssertEqual(installed.rights.removeCount, 1)
    }

    // MARK: an active tunnel

    func testHeldStartExclusionLockBlocksTheRemoval() throws {
        let installed = try installedPreview()
        let (workspace, probe) = try compileProbe()
        defer { _ = workspace }
        let lockPath = installed.fixture.sandbox + "/" + CoordinatorFixture.stateRelative
            + "/start-exclusion"
        let (process, input) = try startProbe(binary: probe, mode: "shared", path: lockPath)
        var stopped = false
        defer { if !stopped { try? stopProbe(process, input) } }

        XCTAssertThrowsError(try cleanup(installed).run()) {
            XCTAssertEqual($0 as? PreviewCleanupError, .lockUnavailable)
        }
        assertSetStillInstalled(installed)

        try stopProbe(process, input)
        stopped = true
        let report = try cleanup(installed).run()
        XCTAssertEqual(report.removedFiles, fileRelatives)
    }

    // MARK: foreign or uncertain service state

    func testUnexpectedOrUnknownLaunchdJobIsRefused() throws {
        let cases: [(LaunchdJobObservation, (PreviewCleanupError) -> Bool, String)] = [
            (.unexpected("a different program"), {
                guard case .launchdJobUnexpected(_) = $0 else { return false }
                return true
            }, "unexpected"),
            (.unknown("the tool failed"), {
                guard case .launchdJobUnknown(_) = $0 else { return false }
                return true
            }, "unknown"),
        ]
        for (observation, matches, label) in cases {
            let installed = try installedPreview()
            installed.launchd.observation = observation
            XCTAssertThrowsError(try cleanup(installed).run(), label) {
                guard let error = $0 as? PreviewCleanupError else {
                    return XCTFail("\(label): \($0)")
                }
                XCTAssertTrue(matches(error), "\(label): \(error)")
            }
            assertSetStillInstalled(installed)
        }
    }

    func testForeignStoredRightIsRefused() throws {
        let installed = try installedPreview()
        installed.rights.observation = .present(try ServiceTestFixtures.alternateRight())

        XCTAssertThrowsError(try cleanup(installed).run()) {
            guard case .some(.authorizationRightForeign(_)) = $0 as? PreviewCleanupError else {
                return XCTFail("\($0)")
            }
        }
        assertSetStillInstalled(installed)
    }

    func testUnreadableStoredRightIsRefused() throws {
        let installed = try installedPreview()
        installed.rights.observeError = AuthorizationRightDatabaseError.unreadable("injected")

        XCTAssertThrowsError(try cleanup(installed).run()) {
            guard case .some(.authorizationRightUnreadable(_)) = $0 as? PreviewCleanupError else {
                return XCTFail("\($0)")
            }
        }
        assertSetStillInstalled(installed)
    }

    func testStoredRightWithoutItsInstalledSourceIsRefused() throws {
        let installed = try installedPreview()
        try FileManager.default.removeItem(
            atPath: installed.fixture.sandbox + "/" + CoordinatorFixture.rightRelative
        )

        XCTAssertThrowsError(try cleanup(installed).run()) {
            guard case .some(.authorizationRightWithoutSource(_)) = $0 as? PreviewCleanupError else {
                return XCTFail("\($0)")
            }
        }
        assertNoServiceChange(installed)
        for relative in fileRelatives where relative != CoordinatorFixture.rightRelative {
            XCTAssertTrue(installed.fixture.targetExists(relative), relative)
        }
    }

    // MARK: foreign or unsafe installed files

    func testOrphanBackupBlocksRemovalBeforeServiceChanges() throws {
        let installed = try installedPreview()
        let orphan = InstallJournalStore.backupRootRelative + "/unaccounted"
        try installed.fixture.makeDirectory(orphan, mode: 0o700)
        XCTAssertThrowsError(try cleanup(installed).run()) {
            XCTAssertEqual($0 as? PreviewCleanupError, .orphanBackupPresent)
        }
        assertSetStillInstalled(installed)
        XCTAssertTrue(installed.fixture.targetExists(orphan))
    }

    func testForeignFileAtAFixedPathIsRefused() throws {
        let installed = try installedPreview()
        try installed.fixture.writeTarget(
            CoordinatorFixture.helperRelative, Data("foreign\n".utf8), mode: 0o755
        )

        XCTAssertThrowsError(try cleanup(installed).run()) {
            guard case .some(.installedFileMismatch(_)) = $0 as? PreviewCleanupError else {
                return XCTFail("\($0)")
            }
        }
        assertNoServiceChange(installed)
        XCTAssertTrue(installed.fixture.targetExists(CoordinatorFixture.engineRelative))
    }

    func testWrongModeAtAFixedPathIsRefused() throws {
        let installed = try installedPreview()
        try installed.fixture.writeTarget(
            CoordinatorFixture.engineRelative, installed.fixture.newEngine, mode: 0o644
        )

        XCTAssertThrowsError(try cleanup(installed).run()) {
            guard case .some(.installedFileUnsafe(let detail)) = $0 as? PreviewCleanupError else {
                return XCTFail("\($0)")
            }
            XCTAssertTrue(detail.contains("mode"), detail)
        }
        assertNoServiceChange(installed)
    }

    // A file that changes after validation is never removed on the old digest.
    // The run stops and the changed object stays for a person to inspect.
    func testFileChangedAfterValidationIsNotRemoved() throws {
        let installed = try installedPreview()
        let faults = CleanupActionAt(.filesValidated) {
            try installed.fixture.writeTarget(
                CoordinatorFixture.helperRelative, Data("changed\n".utf8), mode: 0o755
            )
        }

        XCTAssertThrowsError(try cleanup(installed, faults: faults).run()) {
            guard case .some(.removalFailed(let detail)) = $0 as? PreviewCleanupError else {
                return XCTFail("\($0)")
            }
            XCTAssertTrue(detail.contains(CoordinatorFixture.helperRelative), detail)
        }
        XCTAssertEqual(
            installed.fixture.readTarget(CoordinatorFixture.helperRelative),
            Data("changed\n".utf8)
        )
        // The changed object is now foreign. A retry refuses instead of
        // deleting an object that no longer matches the validated record.
        XCTAssertThrowsError(try cleanup(installed).run()) {
            guard case .some(.installedFileMismatch(_)) = $0 as? PreviewCleanupError else {
                return XCTFail("\($0)")
            }
        }
    }

    // MARK: unfinished transaction and participant records

    func testUnfinishedTransactionAndParticipantRecordsAreRefused() throws {
        enum Record: String, CaseIterable {
            case installJournal
            case serviceJournal
            case cleanupBlock
            case launchIntent
            case startJournal
        }
        for record in Record.allCases {
            let installed = try installedPreview()
            switch record {
            case .installJournal:
                try installed.fixture.writeState(
                    InstallJournalStore.fileName, Data("{}\n".utf8)
                )
            case .serviceJournal:
                try installed.fixture.writeState(
                    ServiceJournalStore.fileName, Data("{}\n".utf8)
                )
            case .cleanupBlock:
                try installed.fixture.writeState(
                    InstallLockLayout.cleanupMarkerName, Data("{}\n".utf8)
                )
            case .launchIntent:
                try installed.fixture.writeState(
                    InstallLockLayout.launchIntentName, Data("{}\n".utf8)
                )
            case .startJournal:
                try installed.fixture.writeState(
                    InstallLockLayout.startJournalName, Data("not a record\n".utf8)
                )
            }

            XCTAssertThrowsError(try cleanup(installed).run(), record.rawValue) {
                guard let error = $0 as? PreviewCleanupError else {
                    return XCTFail("\(record.rawValue): \($0)")
                }
                switch record {
                case .installJournal:
                    XCTAssertEqual(error, .installJournalPresent, record.rawValue)
                case .serviceJournal:
                    XCTAssertEqual(error, .serviceJournalPresent, record.rawValue)
                case .cleanupBlock, .launchIntent, .startJournal:
                    guard case .participantStateUnclean(_) = error else {
                        return XCTFail("\(record.rawValue): \(error)")
                    }
                }
            }
            assertSetStillInstalled(installed)
        }
    }

    // MARK: interruption and retry

    // Stop after every durable step. The next run must finish the removal from
    // the state that the interrupted run left.
    func testInterruptionAtEveryStepIsRetryable() throws {
        for step in PreviewCleanupStep.allCases {
            let installed = try installedPreview()
            XCTAssertThrowsError(
                try cleanup(installed, faults: PreviewCleanupFaultAt(step)).run(), step.rawValue
            ) {
                XCTAssertEqual(
                    $0 as? PreviewCleanupError, .simulatedCrash(step), step.rawValue
                )
            }

            _ = try cleanup(installed).run()
            for relative in fileRelatives {
                XCTAssertFalse(
                    installed.fixture.targetExists(relative),
                    "\(step.rawValue): \(relative)"
                )
            }
            XCTAssertFalse(
                installed.fixture.targetExists(installRoot), step.rawValue
            )
        }
    }

    func testRetryContinuesWhenTheServiceIsAlreadyGone() throws {
        let installed = try installedPreview()
        installed.launchd.observation = .absent

        let report = try cleanup(installed).run()
        XCTAssertFalse(report.removedLaunchdJob)
        XCTAssertTrue(report.removedAuthorizationRight)
        XCTAssertEqual(report.removedFiles, fileRelatives)
        XCTAssertEqual(installed.launchd.bootoutCount, 0)
        XCTAssertEqual(installed.rights.removeCount, 1)
    }

    func testRetryContinuesWhenSomeFilesAreAlreadyGone() throws {
        let installed = try installedPreview()
        for relative in [CoordinatorFixture.engineRelative, CoordinatorFixture.helperRelative] {
            try FileManager.default.removeItem(
                atPath: installed.fixture.sandbox + "/" + relative
            )
        }

        let report = try cleanup(installed).run()
        XCTAssertEqual(
            report.removedFiles,
            [CoordinatorFixture.daemonRelative, CoordinatorFixture.rightRelative]
        )
        for relative in fileRelatives {
            XCTAssertFalse(installed.fixture.targetExists(relative), relative)
        }
    }

    // MARK: directories

    func testANonEmptyInstallRootIsKeptAndNamed() throws {
        let installed = try installedPreview()
        try installed.fixture.writeTarget(
            installRoot + "/local-preview/notice.txt", Data("keep\n".utf8), mode: 0o644
        )

        let report = try cleanup(installed).run()
        XCTAssertEqual(report.keptNonEmptyDirectories, [installRoot])
        XCTAssertTrue(installed.fixture.targetExists(installRoot + "/local-preview/notice.txt"))
        XCTAssertFalse(installed.fixture.targetExists(installRoot + "/engine"))
        XCTAssertFalse(installed.fixture.targetExists(installRoot + "/install-support"))
        for relative in fileRelatives {
            XCTAssertFalse(installed.fixture.targetExists(relative), relative)
        }
    }

    // MARK: clean hosts

    func testAHostWithoutAPreviewStateDirectoryChangesNothing() throws {
        let fixture = try CoordinatorFixture()
        let rights = FakeAuthorizationRightStore()
        let launchd = FakeLaunchdJobController()
        let runtime = FakeServiceRuntime(authorizationRights: rights, launchd: launchd)
        let cleanup = try PreviewFirstInstallCleanup(
            tree: try ServiceTestFixtures.tree(fixture),
            runtime: runtime,
            validator: InstallerValidator(signatures: FakeSignatures.standard),
            expectedTeamIdentifier: FakeSignatures.team
        )

        let report = try cleanup.run()
        XCTAssertEqual(report, PreviewCleanupReport.nothingToRemove)
        XCTAssertFalse(fixture.targetExists(CoordinatorFixture.stateRelative))
        XCTAssertEqual(launchd.bootoutCount, 0)
        XCTAssertEqual(rights.removeCount, 0)
    }

    func testInstalledFileWithoutTheStateDirectoryIsRefused() throws {
        let fixture = try CoordinatorFixture()
        try fixture.writeTarget(
            CoordinatorFixture.engineRelative, fixture.newEngine, mode: 0o755
        )
        let runtime = FakeServiceRuntime(
            authorizationRights: FakeAuthorizationRightStore(),
            launchd: FakeLaunchdJobController()
        )
        let cleanup = try PreviewFirstInstallCleanup(
            tree: try ServiceTestFixtures.tree(fixture),
            runtime: runtime,
            validator: InstallerValidator(signatures: FakeSignatures.standard),
            expectedTeamIdentifier: FakeSignatures.team
        )

        XCTAssertThrowsError(try cleanup.run()) {
            guard case .some(.stateDirectoryUnsafe(_)) = $0 as? PreviewCleanupError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertTrue(fixture.targetExists(CoordinatorFixture.engineRelative))
    }

    func testServiceWithoutTheStateDirectoryIsRefused() throws {
        for present in ["right", "job"] {
            let fixture = try CoordinatorFixture()
            let rights = FakeAuthorizationRightStore()
            let launchd = FakeLaunchdJobController()
            if present == "right" {
                rights.observation = .present(try ServiceTestFixtures.installedRight())
            } else {
                launchd.observation = ServiceTestFixtures.loaded
            }
            let runtime = FakeServiceRuntime(authorizationRights: rights, launchd: launchd)
            let cleanup = try PreviewFirstInstallCleanup(
                tree: try ServiceTestFixtures.tree(fixture),
                runtime: runtime,
                validator: InstallerValidator(signatures: FakeSignatures.standard),
                expectedTeamIdentifier: FakeSignatures.team
            )

            XCTAssertThrowsError(try cleanup.run(), present) {
                guard case .some(.stateDirectoryUnsafe(_)) = $0 as? PreviewCleanupError else {
                    return XCTFail("\(present): \($0)")
                }
            }
            XCTAssertFalse(fixture.targetExists(CoordinatorFixture.stateRelative), present)
            XCTAssertEqual(launchd.bootoutCount, 0, present)
            XCTAssertEqual(rights.removeCount, 0, present)
        }
    }

    // MARK: the exclusion lease

    func testALeaseFromAnotherStateDirectoryIsRefused() throws {
        let installed = try installedPreview()
        let other = try CoordinatorFixture()
        try other.makeStateDirectory()
        let lease = try InstallExclusionLease.acquire(
            parentDirectory: other.sandbox + "/" + CoordinatorFixture.stateRelative,
            expectedOwner: UInt32(geteuid())
        )
        defer { lease.release() }

        XCTAssertThrowsError(try cleanup(installed).run(using: lease)) {
            XCTAssertEqual($0 as? PreviewCleanupError, .lockUnavailable)
        }
        assertSetStillInstalled(installed)
    }

    func testAPassedLeaseIsUsedAndNotReleased() throws {
        let installed = try installedPreview()
        let statePath = installed.fixture.sandbox + "/" + CoordinatorFixture.stateRelative
        let lease = try InstallExclusionLease.acquire(
            parentDirectory: statePath,
            expectedOwner: UInt32(geteuid())
        )
        defer { lease.release() }

        let report = try cleanup(installed).run(using: lease)
        XCTAssertEqual(report.removedFiles, fileRelatives)
        XCTAssertTrue(lease.locks.allSatisfy { $0.isHeld })
    }

    // MARK: the approval gate

    func testTheSystemUninstallGateStaysClosed() throws {
        #if HOTSPOTSHADE_LOCAL_PREVIEW && HOTSPOTSHADE_SYSTEM_PREVIEW_CANDIDATE
        XCTAssertTrue(CoordinatorPolicy.localPreviewInstallationApproved)
        #else
        XCTAssertFalse(CoordinatorPolicy.localPreviewInstallationApproved)
        #endif
        // The system entry point refuses through the same approval gate that
        // protects every other preview system command.
        XCTAssertThrowsError(try PreviewSystemInstaller.uninstall()) {
            #if HOTSPOTSHADE_LOCAL_PREVIEW && HOTSPOTSHADE_SYSTEM_PREVIEW_CANDIDATE
            XCTAssertEqual($0 as? PreviewCleanupError, .requiresRoot)
            #else
            XCTAssertEqual($0 as? PreviewCleanupError, .notApproved)
            #endif
        }
    }

    func testAnInvalidTeamIsRefused() throws {
        let installed = try installedPreview()
        XCTAssertThrowsError(try cleanup(installed, team: "bad")) {
            XCTAssertEqual($0 as? PreviewCleanupError, .requiresTeamIdentifier)
        }
        assertSetStillInstalled(installed)
    }

    // MARK: helpers

    private static let probeSource = #"""
    #include <fcntl.h>
    #include <sys/file.h>
    #include <unistd.h>

    int main(int argc, char **argv) {
        if (argc != 3) return 2;
        int mode;
        if (argv[1][0] == 's') mode = LOCK_SH;
        else if (argv[1][0] == 'e') mode = LOCK_EX;
        else return 2;
        int fd = open(argv[2], O_RDWR | O_CLOEXEC);
        if (fd < 0) return 3;
        if (flock(fd, mode | LOCK_NB) != 0) return 4;
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
        let source = try workspace.write(
            "cleanupprobe.c", Data(Self.probeSource.utf8), mode: 0o644
        )
        let binary = workspace.path("cleanupprobe")
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
}

// Runs a test action at one cleanup step, so a test can change an installed
// object after it was validated without a production hook.
private final class CleanupActionAt: PreviewCleanupFaultInjecting, @unchecked Sendable {
    private let step: PreviewCleanupStep
    private let action: () throws -> Void

    init(_ step: PreviewCleanupStep, action: @escaping () throws -> Void) {
        self.step = step
        self.action = action
    }

    func check(_ candidate: PreviewCleanupStep) throws {
        if candidate == step { try action() }
    }
}
