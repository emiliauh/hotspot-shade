import Foundation
import XCTest
import HotspotShadeKit
@testable import HotspotShadeInstallerCore

final class CoordinatorInstallTests: XCTestCase {
    func testPreviewSystemEntryPointsStayDisabled() throws {
        let fixture = try CoordinatorFixture()
        #if HOTSPOTSHADE_LOCAL_PREVIEW && HOTSPOTSHADE_SYSTEM_PREVIEW_CANDIDATE
        XCTAssertTrue(CoordinatorPolicy.localPreviewInstallationApproved)
        #else
        XCTAssertFalse(CoordinatorPolicy.localPreviewInstallationApproved)
        #endif
        for action: PreviewSystemInstaller.Action in [.install, .resume, .recoverFiles, .recoverService] {
            XCTAssertThrowsError(try PreviewSystemInstaller.run(
                action, appPath: "/not-an-app", payloadRoot: "/not-a-payload", manifest: fixture.staged.manifest
            )) {
                #if HOTSPOTSHADE_LOCAL_PREVIEW && HOTSPOTSHADE_SYSTEM_PREVIEW_CANDIDATE
                XCTAssertEqual($0 as? ServiceTransactionError, .requiresRoot)
                #else
                XCTAssertEqual($0 as? CoordinatorError, .notApproved)
                #endif
            }
        }
        XCTAssertFalse(fixture.targetExists(CoordinatorFixture.engineRelative))
    }

    func testPreviewBindingUsesTheAppAndCoordinatorTeams() throws {
        let fixture = try CoordinatorFixture()
        let app = try fixture.workspace.goodInputs().app
        let validator = InstallerValidator(signatures: FakeSignatures.standard)
        let bound = try PreviewIdentityBinding.source(
            appPath: app, payloadRoot: fixture.staged.payloadDirectory,
            manifest: fixture.staged.manifest, coordinatorTeam: FakeSignatures.team, validator: validator
        )
        XCTAssertEqual(bound.expectedTeamIdentifier, FakeSignatures.team)
        XCTAssertThrowsError(try PreviewIdentityBinding.source(
            appPath: app, payloadRoot: fixture.staged.payloadDirectory,
            manifest: fixture.staged.manifest, coordinatorTeam: "ABCDEFGHIJ", validator: validator
        )) {
            XCTAssertEqual($0 as? PreviewIdentityBinding.BindingError, .teamMismatch)
        }
    }

    func testPrivatePreviewCopyIsIndependentOfTheSuppliedFiles() throws {
        let fixture = try CoordinatorFixture()
        try fixture.makeStateDirectory()
        let tree = try ServiceTestFixtures.tree(fixture)
        let validator = InstallerValidator(signatures: FakeSignatures.standard)
        let copied = try PreviewPayloadCopy.copy(source: fixture.source, into: tree, validator: validator)
        defer { try? PreviewPayloadCopy.remove(copied, from: tree) }
        try fixture.writeFile(fixture.staged.payloadDirectory + "/engine/hotspotshade", Data("changed".utf8), mode: 0o755)
        let outcome = try fixture.coordinator().install(source: copied.source)
        XCTAssertEqual(outcome.fileCount, 4)
        try fixture.assertNewSet()
    }

    func testPrivatePreviewCopyRejectsChangedFilesAndCleansUp() throws {
        let fixture = try CoordinatorFixture()
        try fixture.makeStateDirectory()
        try fixture.writeFile(fixture.staged.payloadDirectory + "/engine/hotspotshade", Data("changed".utf8), mode: 0o755)
        let tree = try ServiceTestFixtures.tree(fixture)
        XCTAssertThrowsError(try PreviewPayloadCopy.copy(
            source: fixture.source, into: tree, validator: InstallerValidator(signatures: FakeSignatures.standard)
        ))
        let names = try tree.listDirectory(CoordinatorFixture.stateRelative)
        XCTAssertFalse(names.contains { $0.hasPrefix("preview-input-") })
        XCTAssertFalse(fixture.targetExists(CoordinatorFixture.engineRelative))
    }

    func testPrivatePreviewCopyRejectsSymlinkAndCleansUp() throws {
        let fixture = try CoordinatorFixture()
        try fixture.makeStateDirectory()
        let engine = fixture.staged.payloadDirectory + "/engine/hotspotshade"
        try FileManager.default.removeItem(atPath: engine)
        try FileManager.default.createSymbolicLink(atPath: engine, withDestinationPath: fixture.staged.payloadDirectory + "/install-support/dev.hotspotshade.mac.helper")
        let tree = try ServiceTestFixtures.tree(fixture)
        XCTAssertThrowsError(try PreviewPayloadCopy.copy(
            source: fixture.source, into: tree, validator: InstallerValidator(signatures: FakeSignatures.standard)
        ))
        let names = try tree.listDirectory(CoordinatorFixture.stateRelative)
        XCTAssertFalse(names.contains { $0.hasPrefix("preview-input-") })
        XCTAssertFalse(fixture.targetExists(CoordinatorFixture.engineRelative))
    }

    func testCombinedInstallUsesPrivateVarWithoutFollowingVarSymlink() throws {
        let fixture = try CoordinatorFixture()
        let manager = FileManager.default
        try manager.removeItem(atPath: fixture.sandbox + "/var")
        try fixture.makeDirectory("private", mode: 0o755)
        try fixture.makeDirectory("private/var", mode: 0o755)
        try fixture.makeDirectory("private/var/db", mode: 0o755)
        try manager.createSymbolicLink(atPath: fixture.sandbox + "/var", withDestinationPath: "private/var")

        let ordinary = try InstallTree(rootPath: fixture.sandbox, expectedOwner: UInt32(geteuid()))
        XCTAssertThrowsError(try ordinary.ensureDirectory("var/db", mode: 0o755, create: false))
        let coordinator = try InstallCoordinator(
            sandboxRoot: fixture.sandbox,
            validator: InstallerValidator(signatures: FakeSignatures.standard),
            journalStoreFactory: { InstallJournalStore(tree: $0) },
            treeFactory: { path, owner in
                try InstallTree(rootPath: path, expectedOwner: owner, syncHooks: .production, usePrivateVar: true)
            }
        )
        let rights = FakeAuthorizationRightStore()
        let launchd = FakeLaunchdJobController()
        let result = try coordinator.installFirstTime(
            source: fixture.source,
            runtime: FakeServiceRuntime(authorizationRights: rights, launchd: launchd)
        )
        XCTAssertTrue(result.service.launchdJobLoaded)
        try fixture.assertNewSet()
        XCTAssertTrue(manager.fileExists(atPath: fixture.sandbox + "/private/var/db/hotspotshade/start.lock"))
        fixture.assertNoJournal()
    }

    func testPrivateVarMappingRefusesASymlinkAtTheRealDirectory() throws {
        let fixture = try CoordinatorFixture()
        try fixture.makeDirectory("private", mode: 0o755)
        try FileManager.default.createSymbolicLink(
            atPath: fixture.sandbox + "/private/var", withDestinationPath: "../var"
        )
        XCTAssertThrowsError(try InstallTree(
            rootPath: fixture.sandbox, expectedOwner: UInt32(geteuid()),
            syncHooks: .production, usePrivateVar: true
        ))
    }

    func testPrivateVarMappingRecoversCrossDirectoryBackup() throws {
        let fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
        let manager = FileManager.default
        try manager.removeItem(atPath: fixture.sandbox + "/var")
        try fixture.makeDirectory("private", mode: 0o755)
        try fixture.makeDirectory("private/var", mode: 0o755)
        try fixture.makeDirectory("private/var/db", mode: 0o755)
        try manager.createSymbolicLink(atPath: fixture.sandbox + "/var", withDestinationPath: "private/var")
        func coordinator(_ faults: CoordinatorFaultInjecting = NoFaults()) throws -> InstallCoordinator {
            try InstallCoordinator(
                sandboxRoot: fixture.sandbox,
                validator: InstallerValidator(signatures: FakeSignatures.standard),
                faults: faults,
                journalStoreFactory: { InstallJournalStore(tree: $0) },
                treeFactory: { path, owner in
                    try InstallTree(rootPath: path, expectedOwner: owner, syncHooks: .production, usePrivateVar: true)
                }
            )
        }
        XCTAssertThrowsError(try coordinator(CoordinatorFaultAt(.backupMoved0)).install(source: fixture.source))
        guard case .rolledBack = try coordinator().recover() else { return XCTFail("expected rollback") }
        try fixture.assertOldSet()
        fixture.assertNoJournal()
    }

    func testCombinedFirstInstallWithSignedPreviewArtifacts() throws {
        guard let stage = ProcessInfo.processInfo.environment["HS_MAC_STAGED_PREVIEW"] else {
            throw XCTSkip("Set HS_MAC_STAGED_PREVIEW to a staged local preview to test its signed artifacts.")
        }
        let manifest = try JSONDecoder().decode(
            InstallerManifest.self,
            from: Data(contentsOf: URL(fileURLWithPath: stage + "/manifest.json"))
        )
        for mappedVar in [false, true] {
            let fixture = try CoordinatorFixture()
            if mappedVar {
                try FileManager.default.removeItem(atPath: fixture.sandbox + "/var")
                try fixture.makeDirectory("private", mode: 0o755)
                try fixture.makeDirectory("private/var", mode: 0o755)
                try fixture.makeDirectory("private/var/db", mode: 0o755)
                try FileManager.default.createSymbolicLink(
                    atPath: fixture.sandbox + "/var", withDestinationPath: "private/var"
                )
            }
            let coordinator = try InstallCoordinator(
                sandboxRoot: fixture.sandbox,
                journalStoreFactory: { InstallJournalStore(tree: $0) },
                treeFactory: { path, owner in
                    try InstallTree(rootPath: path, expectedOwner: owner, syncHooks: .production, usePrivateVar: mappedVar)
                }
            )
            let rights = FakeAuthorizationRightStore()
            let launchd = FakeLaunchdJobController()
            let runtime = FakeServiceRuntime(authorizationRights: rights, launchd: launchd)
            let outcome = try coordinator.installFirstTime(
                source: CoordinatorSource(
                    payloadRoot: stage + "/payload", manifest: manifest,
                    expectedTeamIdentifier: manifest.teamIdentifier
                ),
                runtime: runtime
            )
            XCTAssertTrue(outcome.service.launchdJobLoaded)
            let tree = try ServiceTestFixtures.tree(fixture)
            for file in manifest.files {
                let path = InstallJournal.relativeDestination(file.destination)
                let snapshot = try XCTUnwrap(tree.snapshot(path, maximumBytes: file.size))
                XCTAssertEqual(snapshot.sha256, file.sha256)
                XCTAssertEqual(snapshot.size, file.size)
            }
            XCTAssertEqual(rights.writes.count, 1)
            XCTAssertEqual(launchd.bootstrapCount, 1)
            let cleanupTree = try InstallTree(
                rootPath: fixture.sandbox,
                expectedOwner: UInt32(geteuid()),
                syncHooks: .production,
                usePrivateVar: mappedVar
            )
            let cleanup = try PreviewFirstInstallCleanup(
                tree: cleanupTree,
                runtime: runtime,
                validator: InstallerValidator(),
                expectedTeamIdentifier: manifest.teamIdentifier
            )
            let report = try cleanup.run()
            XCTAssertTrue(report.removedLaunchdJob)
            XCTAssertTrue(report.removedAuthorizationRight)
            XCTAssertEqual(report.removedFiles.count, manifest.files.count)
            for file in manifest.files {
                let path = InstallJournal.relativeDestination(file.destination)
                XCTAssertNil(try cleanupTree.snapshot(path, maximumBytes: file.size))
            }
        }
    }

    func testCombinedFirstInstallSetsUpFilesAndService() throws {
        let fixture = try CoordinatorFixture()
        let rights = FakeAuthorizationRightStore()
        let launchd = FakeLaunchdJobController()
        let runtime = FakeServiceRuntime(authorizationRights: rights, launchd: launchd)
        let result = try fixture.coordinator().installFirstTime(source: fixture.source, runtime: runtime)
        XCTAssertEqual(result.files.fileCount, 4)
        XCTAssertTrue(result.service.launchdJobLoaded)
        XCTAssertEqual(rights.writes.count, 1)
        XCTAssertEqual(launchd.bootstrapCount, 1)
        try fixture.assertNewSet()
        fixture.assertNoJournal()
    }

    func testCombinedFirstInstallRefusesAnExistingInstallationBeforeServiceChanges() throws {
        let fixture = try CoordinatorFixture(oldPadding: 64)
        let rights = FakeAuthorizationRightStore()
        let launchd = FakeLaunchdJobController()
        let runtime = FakeServiceRuntime(authorizationRights: rights, launchd: launchd)
        XCTAssertThrowsError(try fixture.coordinator().installFirstTime(source: fixture.source, runtime: runtime)) {
            guard case .existingFile = $0 as? CombinedInstallError else { return XCTFail("\($0)") }
        }
        try fixture.assertOldSet()
        XCTAssertTrue(rights.writes.isEmpty)
        XCTAssertEqual(launchd.bootstrapCount, 0)
    }

    func testCombinedFirstInstallRefusesAnExistingRightBeforeWritingFiles() throws {
        let fixture = try CoordinatorFixture()
        let rights = FakeAuthorizationRightStore()
        rights.observation = .present(try ServiceTestFixtures.previousRight())
        let launchd = FakeLaunchdJobController()
        let runtime = FakeServiceRuntime(authorizationRights: rights, launchd: launchd)
        XCTAssertThrowsError(try fixture.coordinator().installFirstTime(source: fixture.source, runtime: runtime)) {
            XCTAssertEqual($0 as? CombinedInstallError, .existingServiceState)
        }
        XCTAssertFalse(fixture.targetExists(CoordinatorFixture.engineRelative))
        XCTAssertTrue(rights.writes.isEmpty)
        XCTAssertEqual(launchd.bootstrapCount, 0)
    }

    func testCombinedFirstInstallRefusesAnExistingJobBeforeWritingFiles() throws {
        let fixture = try CoordinatorFixture()
        let rights = FakeAuthorizationRightStore()
        let launchd = FakeLaunchdJobController(observation: ServiceTestFixtures.loaded)
        let runtime = FakeServiceRuntime(authorizationRights: rights, launchd: launchd)
        XCTAssertThrowsError(try fixture.coordinator().installFirstTime(source: fixture.source, runtime: runtime)) {
            XCTAssertEqual($0 as? CombinedInstallError, .existingServiceState)
        }
        XCTAssertFalse(fixture.targetExists(CoordinatorFixture.engineRelative))
        XCTAssertTrue(rights.writes.isEmpty)
        XCTAssertEqual(launchd.bootoutCount, 0)
    }

    func testCombinedFirstInstallRefusesLiveRuntimeBeforeWritingFiles() throws {
        struct LiveRuntime: PrivilegedServiceRuntime {
            let isLiveSystem = true
            let authorizationRights: AuthorizationRightStoring = FakeAuthorizationRightStore()
            let launchd: LaunchdJobControlling = FakeLaunchdJobController()
        }
        let fixture = try CoordinatorFixture()
        XCTAssertThrowsError(try fixture.coordinator().installFirstTime(
            source: fixture.source, runtime: LiveRuntime()
        )) {
            XCTAssertEqual($0 as? CombinedInstallError, .liveRuntimeNotSupported)
        }
        XCTAssertFalse(fixture.targetExists(CoordinatorFixture.engineRelative))
    }

    func testCombinedFirstInstallStopsBeforeServiceOnFileCrash() throws {
        let fixture = try CoordinatorFixture()
        let rights = FakeAuthorizationRightStore()
        let launchd = FakeLaunchdJobController()
        let runtime = FakeServiceRuntime(authorizationRights: rights, launchd: launchd)
        XCTAssertThrowsError(try fixture.coordinator(faults: CoordinatorFaultAt(.fileInstalled0))
            .installFirstTime(source: fixture.source, runtime: runtime))
        XCTAssertTrue(rights.writes.isEmpty)
        XCTAssertEqual(launchd.bootstrapCount, 0)
        _ = try fixture.coordinator().recover()
        XCTAssertFalse(fixture.targetExists(CoordinatorFixture.engineRelative))
    }

    func testCombinedServiceRecoveryRefusesAnUnresolvedFileJournal() throws {
        let fixture = try CoordinatorFixture()
        let rights = FakeAuthorizationRightStore()
        let launchd = FakeLaunchdJobController()
        let runtime = FakeServiceRuntime(authorizationRights: rights, launchd: launchd)
        XCTAssertThrowsError(try fixture.coordinator(faults: CoordinatorFaultAt(.fileInstalled0))
            .installFirstTime(source: fixture.source, runtime: runtime))
        XCTAssertThrowsError(try fixture.coordinator().recoverFirstTimeService(
            runtime: runtime, teamIdentifier: FakeSignatures.team
        ))
        XCTAssertTrue(fixture.targetExists(CoordinatorFixture.journalRelative))
        XCTAssertTrue(rights.writes.isEmpty)
        XCTAssertEqual(launchd.bootstrapCount, 0)
        XCTAssertEqual(launchd.bootoutCount, 0)
    }

    func testFirstInstallCanResumeAfterServiceRollsBack() throws {
        let fixture = try CoordinatorFixture()
        let rights = FakeAuthorizationRightStore()
        let launchd = FakeLaunchdJobController()
        launchd.bootstrapError = LaunchdJobError.commandFailed("injected")
        let runtime = FakeServiceRuntime(authorizationRights: rights, launchd: launchd)
        let coordinator = try fixture.coordinator()
        XCTAssertThrowsError(try coordinator.installFirstTime(source: fixture.source, runtime: runtime))
        try fixture.assertNewSet()
        XCTAssertEqual(rights.observation, .absent)
        XCTAssertEqual(launchd.observation, .absent)
        let result = try coordinator.resumeFirstTime(source: fixture.source, runtime: runtime)
        XCTAssertTrue(result.launchdJobLoaded)
        XCTAssertEqual(launchd.observation, ServiceTestFixtures.loaded)
        try fixture.assertNewSet()
    }

    func testFirstInstallResumeRefusesChangedOrMissingFiles() throws {
        for remove in [false, true] {
            let fixture = try CoordinatorFixture()
            let rights = FakeAuthorizationRightStore()
            let launchd = FakeLaunchdJobController()
            launchd.bootstrapError = LaunchdJobError.commandFailed("injected")
            let runtime = FakeServiceRuntime(authorizationRights: rights, launchd: launchd)
            let coordinator = try fixture.coordinator()
            XCTAssertThrowsError(try coordinator.installFirstTime(source: fixture.source, runtime: runtime))
            let path = fixture.sandbox + "/" + CoordinatorFixture.engineRelative
            if remove {
                try FileManager.default.removeItem(atPath: path)
            } else {
                try fixture.writeFile(path, Data("changed".utf8), mode: 0o755)
            }
            let writesBefore = rights.writes.count
            let bootstrapBefore = launchd.bootstrapCount
            XCTAssertThrowsError(try coordinator.resumeFirstTime(source: fixture.source, runtime: runtime))
            XCTAssertEqual(rights.writes.count, writesBefore)
            XCTAssertEqual(launchd.bootstrapCount, bootstrapBefore)
        }
    }

    func testFirstInstallResumeDoesNotBypassAnUnresolvedServiceJournal() throws {
        let fixture = try CoordinatorFixture()
        let rights = FakeAuthorizationRightStore()
        let launchd = FakeLaunchdJobController()
        let runtime = FakeServiceRuntime(authorizationRights: rights, launchd: launchd)
        let coordinator = try fixture.coordinator()
        XCTAssertThrowsError(try coordinator.installFirstTime(
            source: fixture.source, runtime: runtime, serviceFaults: ServiceFaultAt(.bootstrapCompleted)
        ))
        let writesBefore = rights.writes.count
        let bootstrapBefore = launchd.bootstrapCount
        XCTAssertThrowsError(try coordinator.resumeFirstTime(source: fixture.source, runtime: runtime))
        XCTAssertEqual(rights.writes.count, writesBefore)
        XCTAssertEqual(launchd.bootstrapCount, bootstrapBefore)
        XCTAssertEqual(launchd.bootoutCount, 0)
    }

    func testCombinedFirstInstallKeepsServiceRecoveryAfterServiceCrash() throws {
        let steps: [ServiceTransactionStep] = [
            .journalPrepared, .rightWriteCompleted, .rightJournalWritten,
            .bootstrapCompleted, .bootstrapJournalWritten, .commitJournalWritten, .journalRemoved,
        ]
        for step in steps {
            let fixture = try CoordinatorFixture()
            let rights = FakeAuthorizationRightStore()
            let launchd = FakeLaunchdJobController()
            let runtime = FakeServiceRuntime(authorizationRights: rights, launchd: launchd)
            XCTAssertThrowsError(try fixture.coordinator().installFirstTime(
                source: fixture.source, runtime: runtime, serviceFaults: ServiceFaultAt(step)
            ), "\(step)")
            try fixture.assertNewSet()
            let coordinator = try fixture.coordinator()
            if step == .bootstrapCompleted {
                XCTAssertThrowsError(try coordinator.recoverFirstTimeService(
                    runtime: runtime, teamIdentifier: FakeSignatures.team
                )) {
                    guard case .recoveryRequired = $0 as? ServiceTransactionError else {
                        return XCTFail("\($0)")
                    }
                }
                XCTAssertEqual(launchd.observation, ServiceTestFixtures.loaded)
                XCTAssertEqual(launchd.bootoutCount, 0)
                continue
            }
            let recovery = try coordinator.recoverFirstTimeService(
                runtime: runtime, teamIdentifier: FakeSignatures.team
            )
            if step == .journalRemoved {
                XCTAssertEqual(recovery, .nothingToRecover)
            } else if case .nothingToRecover = recovery {
                XCTFail("service recovery record missing after \(step)")
            }
            XCTAssertEqual(launchd.observation, ServiceTestFixtures.loaded, "\(step)")
        }
    }

    func testCallerCanRetainExclusionAcrossFileInstall() throws {
        let fixture = try CoordinatorFixture()
        try fixture.makeDirectory(CoordinatorFixture.stateRelative, mode: 0o700)
        let lease = try InstallExclusionLease.acquire(
            parentDirectory: fixture.sandbox + "/" + CoordinatorFixture.stateRelative,
            expectedOwner: UInt32(geteuid())
        )
        defer { lease.release() }

        let outcome = try fixture.coordinator().install(source: fixture.source, using: lease)
        XCTAssertEqual(outcome.fileCount, 4)
        try fixture.assertNewSet()
        XCTAssertTrue(lease.locks.allSatisfy { $0.isHeld })
        XCTAssertThrowsError(try fixture.coordinator().install(source: fixture.source)) {
            XCTAssertEqual($0 as? CoordinatorError, .lockUnavailable)
        }

        // Exercise both existing installer phases under the same lease. The
        // runtime is fake; no system service or authorization right changes.
        let rights = FakeAuthorizationRightStore()
        let launchd = FakeLaunchdJobController()
        let runtime = FakeServiceRuntime(authorizationRights: rights, launchd: launchd)
        let transaction = try PrivilegedServiceTransaction(
            tree: ServiceTestFixtures.tree(fixture),
            runtime: runtime,
            validator: InstallerValidator(signatures: FakeSignatures.standard),
            expectedTeamIdentifier: FakeSignatures.team
        )
        let service = try transaction.apply(installTransactionID: outcome.transactionID, using: lease)
        XCTAssertTrue(service.launchdJobLoaded)
        XCTAssertEqual(rights.writes.count, 1)
        XCTAssertEqual(launchd.bootstrapCount, 1)
        XCTAssertTrue(lease.locks.allSatisfy { $0.isHeld })
    }

    func testFileInstallRejectsAnIncompleteOrForeignLease() throws {
        let fixture = try CoordinatorFixture()
        let other = try CoordinatorFixture()
        try fixture.makeDirectory(CoordinatorFixture.stateRelative, mode: 0o700)
        try other.makeDirectory(CoordinatorFixture.stateRelative, mode: 0o700)
        let state = fixture.sandbox + "/" + CoordinatorFixture.stateRelative
        let partial = try InstallExclusionLease.acquire(
            parentDirectory: state, fileNames: [InstallLockLayout.fileName],
            expectedOwner: UInt32(geteuid())
        )
        XCTAssertThrowsError(try fixture.coordinator().install(source: fixture.source, using: partial)) {
            XCTAssertEqual($0 as? CoordinatorError, .lockUnavailable)
        }
        XCTAssertFalse(fixture.targetExists(CoordinatorFixture.engineRelative))
        partial.release()

        let foreign = try InstallExclusionLease.acquire(
            parentDirectory: other.sandbox + "/" + CoordinatorFixture.stateRelative,
            expectedOwner: UInt32(geteuid())
        )
        defer { foreign.release() }
        XCTAssertThrowsError(try fixture.coordinator().install(source: fixture.source, using: foreign)) {
            XCTAssertEqual($0 as? CoordinatorError, .lockUnavailable)
        }
        XCTAssertFalse(fixture.targetExists(CoordinatorFixture.engineRelative))
        XCTAssertTrue(foreign.locks.allSatisfy { $0.isHeld })
    }

    func testCallerRetainsLeaseWhenFileInstallFails() throws {
        let fixture = try CoordinatorFixture()
        try fixture.makeDirectory(CoordinatorFixture.stateRelative, mode: 0o700)
        let lease = try InstallExclusionLease.acquire(
            parentDirectory: fixture.sandbox + "/" + CoordinatorFixture.stateRelative,
            expectedOwner: UInt32(geteuid())
        )
        defer { lease.release() }
        let coordinator = try fixture.coordinator(faults: CoordinatorFaultAt(.fileInstalled0))
        XCTAssertThrowsError(try coordinator.install(source: fixture.source, using: lease))
        XCTAssertTrue(lease.locks.allSatisfy { $0.isHeld })
        XCTAssertTrue(fixture.targetExists(CoordinatorFixture.journalRelative))
        XCTAssertThrowsError(try fixture.coordinator().recover()) {
            XCTAssertEqual($0 as? CoordinatorError, .lockUnavailable)
        }
        let recovered = try fixture.coordinator().recover(using: lease)
        guard case .rolledBack = recovered else { return XCTFail("\(recovered)") }
        XCTAssertFalse(fixture.targetExists(CoordinatorFixture.engineRelative))
        XCTAssertTrue(lease.locks.allSatisfy { $0.isHeld })
    }

    func testInitialInstallCreatesTheExactLayout() throws {
        let fixture = try CoordinatorFixture()
        let outcome = try fixture.coordinator().install(source: fixture.source)
        XCTAssertEqual(outcome.fileCount, 4)
        XCTAssertEqual(outcome.version, "2.0.0")
        try fixture.assertNewSet()
        XCTAssertEqual(try fixture.targetMode("Library/Application Support/HotspotShade"), 0o755)
        XCTAssertEqual(try fixture.targetMode("Library/Application Support/HotspotShade/engine"), 0o755)
        XCTAssertEqual(try fixture.targetMode("Library/Application Support/HotspotShade/install-support"), 0o755)
        XCTAssertEqual(try fixture.targetMode(CoordinatorFixture.stateRelative), 0o700)
        fixture.assertNoJournal()
        fixture.assertNoBackups()
        fixture.assertNoTemporaryFiles()
    }

    func testUpgradeReplacesTheSignedSetAndRemovesBackups() throws {
        let fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
        try fixture.assertOldSet()
        let outcome = try fixture.coordinator().install(source: fixture.source)
        XCTAssertEqual(outcome.fileCount, 4)
        try fixture.assertNewSet()
        fixture.assertNoJournal()
        fixture.assertNoBackups()
        fixture.assertNoTemporaryFiles()
        XCTAssertEqual(fixture.backupEntries(), [])
    }

    func testFaultAtEveryInstallStepRecoversToACoherentSet() throws {
        for step in CoordinatorStep.installFaultPoints {
            let fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
            let coordinator = try fixture.coordinator(faults: CoordinatorFaultAt(step))
            XCTAssertThrowsError(try coordinator.install(source: fixture.source), "\(step.rawValue)") {
                XCTAssertEqual($0 as? CoordinatorError, .simulatedCrash(step), "\(step.rawValue)")
            }
            let recovery = try fixture.coordinator().recover()
            if step.isAfterCommit {
                try fixture.assertNewSet()
                if step == .journalRemoved {
                    XCTAssertEqual(recovery, .nothingToRecover, "\(step.rawValue)")
                }
            } else {
                try fixture.assertOldSet()
                guard case .rolledBack(_, let version) = recovery else {
                    return XCTFail("\(step.rawValue): \(recovery)")
                }
                XCTAssertEqual(version, "2.0.0", "\(step.rawValue)")
            }
            fixture.assertNoJournal()
            fixture.assertNoBackups()
            fixture.assertNoTemporaryFiles()
        }
    }

    func testFirstInstallFaultsNeverLeaveAPartialLayout() throws {
        let steps: [CoordinatorStep] = [
            .journalPrepared,
            .directoriesCreated,
            .backupMoved0,
            .fileInstalled0,
            .replacementVerified,
            .commitJournalWritten,
            .backupsRemoved,
        ]
        for step in steps {
            let fixture = try CoordinatorFixture(newPadding: 192)
            let coordinator = try fixture.coordinator(faults: CoordinatorFaultAt(step))
            XCTAssertThrowsError(try coordinator.install(source: fixture.source), "\(step.rawValue)") {
                XCTAssertEqual($0 as? CoordinatorError, .simulatedCrash(step), "\(step.rawValue)")
            }
            _ = try fixture.coordinator().recover()
            if step.isAfterCommit {
                try fixture.assertNewSet()
            } else {
                XCTAssertFalse(
                    fixture.targetExists("Library/Application Support/HotspotShade"),
                    "a partial install directory remains after \(step.rawValue)"
                )
                fixture.assertNoJournal()
                fixture.assertNoBackups()
            }
            fixture.assertNoJournal()
            fixture.assertNoTemporaryFiles()
        }
    }

    func testCrashDuringRecoveryIsIdempotent() throws {
        let fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
        XCTAssertThrowsError(
            try fixture.coordinator(faults: CoordinatorFaultAt(.fileInstalled2))
                .install(source: fixture.source)
        )
        XCTAssertTrue(fixture.targetExists(CoordinatorFixture.journalRelative))
        XCTAssertThrowsError(
            try fixture.coordinator(faults: CoordinatorFaultAt(.recoveryRestored2)).recover()
        ) {
            XCTAssertEqual($0 as? CoordinatorError, .simulatedCrash(.recoveryRestored2))
        }
        XCTAssertTrue(fixture.targetExists(CoordinatorFixture.journalRelative))
        let second = try fixture.coordinator().recover()
        guard case .rolledBack(_, let version) = second else {
            return XCTFail("\(second)")
        }
        XCTAssertEqual(version, "2.0.0")
        try fixture.assertOldSet()
        fixture.assertNoJournal()
        fixture.assertNoBackups()
        fixture.assertNoTemporaryFiles()
    }

    // A rollback may move a verified backup back only when the destination is
    // absent or still holds exactly the file this transaction installed. An
    // unrelated object with the same owner and safe mode must never be
    // overwritten, and the journal and the backup must stay for a person to
    // inspect.
    func testRollbackRefusesAForeignDestinationAndKeepsTheJournal() throws {
        let cases: [(label: String, data: Data, mode: Int)] = [
            ("unrelated content", fakeMachO(tag: "engine", padding: 999), 0o755),
            ("the installed bytes with a wrong mode", fakeMachO(tag: "engine", padding: 192), 0o644),
            ("other content", Data("an unrelated object\n".utf8), 0o700),
        ]
        for testCase in cases {
            let fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
            XCTAssertThrowsError(
                try fixture.coordinator(faults: CoordinatorFaultAt(.fileInstalled1))
                    .install(source: fixture.source),
                testCase.label
            )
            guard let oldEngine = fixture.oldEngine else {
                return XCTFail("the fixture has no old set")
            }
            let journal = try XCTUnwrap(try fixture.readJournal(), testCase.label)
            XCTAssertEqual(journal.phase, .replacing, testCase.label)
            XCTAssertEqual(
                fixture.backupFileNames(transactionID: journal.transactionID),
                ["0", "1"],
                testCase.label
            )
            let backup = CoordinatorFixture.backupRootRelative + "/" + journal.transactionID + "/0"
            XCTAssertEqual(fixture.readTarget(backup), oldEngine, testCase.label)

            try fixture.writeTarget(
                CoordinatorFixture.engineRelative,
                testCase.data,
                mode: testCase.mode
            )

            // A second recovery sees the same ambiguity. It must not overwrite
            // the foreign file either.
            for attempt in 1...2 {
                let label = "\(testCase.label), recovery \(attempt)"
                XCTAssertThrowsError(try fixture.coordinator().recover(), label) { error in
                    guard case .recoveryRequired? = error as? CoordinatorError else {
                        return XCTFail("\(label): \(error)")
                    }
                    if attempt == 1 {
                        XCTAssertTrue(
                            (error as? CoordinatorError)?.description.contains(
                                "neither the previous file nor the installed file"
                            ) == true,
                            "\(label): \(error)"
                        )
                        // The recovery reason must not be wrapped in a second
                        // "Recovery did not complete" sentence.
                        let description = (error as? CoordinatorError)?.description ?? ""
                        XCTAssertEqual(
                            description.components(separatedBy: "Recovery did not complete").count,
                            2,
                            "\(label): \(description)"
                        )
                    }
                }
                XCTAssertEqual(
                    fixture.readTarget(CoordinatorFixture.engineRelative),
                    testCase.data,
                    "the rollback replaced a foreign file at \(label)"
                )
                XCTAssertEqual(
                    try fixture.targetMode(CoordinatorFixture.engineRelative),
                    testCase.mode,
                    "the rollback changed the mode of a foreign file at \(label)"
                )
                XCTAssertEqual(try fixture.readJournal(), journal, "the journal changed at \(label)")
                XCTAssertEqual(
                    fixture.backupFileNames(transactionID: journal.transactionID),
                    ["0"],
                    "the restored helper backup was not consumed at \(label)"
                )
                XCTAssertEqual(fixture.readTarget(backup), oldEngine, "the backup changed at \(label)")
                XCTAssertEqual(
                    fixture.readTarget(CoordinatorFixture.helperRelative),
                    fixture.oldHelper,
                    "the helper was not restored before the refusal at \(label)"
                )
            }
            XCTAssertEqual(try fixture.coordinator().status().journalPhase, .replacing)
        }
    }

    func testRollbackRestoresAPreviousFileOverTheInstalledFile() throws {
        let fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
        XCTAssertThrowsError(
            try fixture.coordinator(faults: CoordinatorFaultAt(.fileInstalled0))
                .install(source: fixture.source)
        )
        XCTAssertEqual(fixture.readTarget(CoordinatorFixture.engineRelative), fixture.newEngine)
        let journal = try XCTUnwrap(try fixture.readJournal())
        XCTAssertEqual(fixture.backupFileNames(transactionID: journal.transactionID), ["0"])
        let recovery = try fixture.coordinator().recover()
        guard case .rolledBack(_, let version) = recovery else {
            return XCTFail("\(recovery)")
        }
        XCTAssertEqual(version, "2.0.0")
        try fixture.assertOldSet()
        fixture.assertNoJournal()
        fixture.assertNoBackups()
        fixture.assertNoTemporaryFiles()
    }

    func testRollbackRestoresAPreviousFileIntoAnAbsentDestination() throws {
        let fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
        XCTAssertThrowsError(
            try fixture.coordinator(faults: CoordinatorFaultAt(.backupMoved0))
                .install(source: fixture.source)
        )
        XCTAssertFalse(fixture.targetExists(CoordinatorFixture.engineRelative))
        XCTAssertEqual(fixture.readTarget(CoordinatorFixture.helperRelative), fixture.oldHelper)
        let recovery = try fixture.coordinator().recover()
        guard case .rolledBack(_, _) = recovery else {
            return XCTFail("\(recovery)")
        }
        try fixture.assertOldSet()
        fixture.assertNoJournal()
        fixture.assertNoBackups()
        fixture.assertNoTemporaryFiles()
    }

    func testCleanupMarkerBlocksBeforeAnyChange() throws {
        let fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
        try fixture.writeState(InstallLockLayout.cleanupMarkerName, Data("blocked\n".utf8))
        XCTAssertThrowsError(try fixture.coordinator().install(source: fixture.source)) {
            XCTAssertEqual($0 as? CoordinatorError, .cleanupBlocked)
        }
        try fixture.assertOldSet()
        XCTAssertFalse(fixture.targetExists(CoordinatorFixture.journalRelative))
        XCTAssertTrue(fixture.targetExists(CoordinatorFixture.stateRelative + "/cleanup-blocked"))
    }

    func testLaunchIntentBlocksBeforeAnyChange() throws {
        let fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
        try fixture.writeState(InstallLockLayout.launchIntentName, Data("intent\n".utf8))
        XCTAssertThrowsError(try fixture.coordinator().install(source: fixture.source)) {
            XCTAssertEqual($0 as? CoordinatorError, .launchIntentPresent)
        }
        try fixture.assertOldSet()
        XCTAssertFalse(fixture.targetExists(CoordinatorFixture.journalRelative))
        XCTAssertTrue(fixture.targetExists(CoordinatorFixture.stateRelative + "/engine-session"))
    }

    func testJournalPresentRefusesASecondInstallUntilRecovery() throws {
        let fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
        XCTAssertThrowsError(
            try fixture.coordinator(faults: CoordinatorFaultAt(.journalPrepared))
                .install(source: fixture.source)
        )
        XCTAssertThrowsError(try fixture.coordinator().install(source: fixture.source)) {
            XCTAssertEqual($0 as? CoordinatorError, .journalPresent)
        }
        _ = try fixture.coordinator().recover()
        try fixture.assertOldSet()
        let outcome = try fixture.coordinator().install(source: fixture.source)
        XCTAssertEqual(outcome.version, "2.0.0")
        try fixture.assertNewSet()
    }

    func testServiceJournalBlocksFileInstallAndRecovery() throws {
        let fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
        XCTAssertThrowsError(
            try fixture.coordinator(faults: CoordinatorFaultAt(.journalPrepared))
                .install(source: fixture.source)
        )
        try fixture.writeState(ServiceJournalStore.fileName, Data("pending\n".utf8))
        XCTAssertTrue(try fixture.coordinator().status().serviceJournalPresent)
        for action in [
            { _ = try fixture.coordinator().install(source: fixture.source) },
            { _ = try fixture.coordinator().recover() }
        ] {
            XCTAssertThrowsError(try action()) {
                if case .recoveryRequired? = $0 as? CoordinatorError {} else { XCTFail("\($0)") }
            }
        }
        XCTAssertTrue(fixture.targetExists(CoordinatorFixture.journalRelative))
        XCTAssertTrue(fixture.targetExists(ServiceJournalStore.relativePath))
        try fixture.assertOldSet()
    }

    func testRuntimeMarkersBlockFileRecovery() throws {
        for (name, expected) in [
            (InstallLockLayout.cleanupMarkerName, CoordinatorError.cleanupBlocked),
            (InstallLockLayout.launchIntentName, CoordinatorError.launchIntentPresent)
        ] {
            let fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
            XCTAssertThrowsError(
                try fixture.coordinator(faults: CoordinatorFaultAt(.journalPrepared))
                    .install(source: fixture.source)
            )
            try fixture.writeState(name, Data("pending\n".utf8))
            XCTAssertThrowsError(try fixture.coordinator().recover()) {
                XCTAssertEqual($0 as? CoordinatorError, expected)
            }
            XCTAssertTrue(fixture.targetExists(CoordinatorFixture.journalRelative))
            XCTAssertTrue(fixture.targetExists(CoordinatorFixture.stateRelative + "/" + name))
            try fixture.assertOldSet()
        }
    }

    func testUnreadableJournalIsKeptAndRefused() throws {
        let fixture = try CoordinatorFixture()
        try fixture.makeStateDirectory()
        try fixture.writeRawJournal(Data("not a journal".utf8))
        XCTAssertThrowsError(try fixture.coordinator().recover()) {
            if case .journalUnreadable? = $0 as? CoordinatorError {} else { XCTFail("\($0)") }
        }
        XCTAssertTrue(fixture.targetExists(CoordinatorFixture.journalRelative))
        XCTAssertThrowsError(try fixture.coordinator().install(source: fixture.source)) {
            if case .journalUnreadable? = $0 as? CoordinatorError {} else { XCTFail("\($0)") }
        }
        XCTAssertTrue(fixture.targetExists(CoordinatorFixture.journalRelative))
    }

    func testCommittedStateDamageKeepsTheJournalAndBackups() throws {
        let fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
        XCTAssertThrowsError(
            try fixture.coordinator(faults: CoordinatorFaultAt(.commitJournalWritten))
                .install(source: fixture.source)
        )
        try fixture.assertNewSet()
        XCTAssertFalse(fixture.backupEntries().isEmpty)
        try fixture.writeTarget(
            CoordinatorFixture.engineRelative,
            fakeMachO(tag: "engine", padding: 777),
            mode: 0o755
        )
        XCTAssertThrowsError(try fixture.coordinator().recover()) {
            if case .committedStateDamaged? = $0 as? CoordinatorError {} else { XCTFail("\($0)") }
        }
        XCTAssertTrue(fixture.targetExists(CoordinatorFixture.journalRelative))
        XCTAssertFalse(fixture.backupEntries().isEmpty)
    }

    func testOrphanBackupDirectoryIsNotDeleted() throws {
        let fixture = try CoordinatorFixture()
        try fixture.makeStateDirectory()
        try fixture.makeDirectory(CoordinatorFixture.backupRootRelative + "/orphan", mode: 0o700)
        XCTAssertThrowsError(try fixture.coordinator().recover()) {
            if case .orphanArtifacts? = $0 as? CoordinatorError {} else { XCTFail("\($0)") }
        }
        XCTAssertThrowsError(try fixture.coordinator().install(source: fixture.source)) {
            if case .orphanArtifacts? = $0 as? CoordinatorError {} else { XCTFail("\($0)") }
        }
        XCTAssertTrue(
            fixture.targetExists(CoordinatorFixture.backupRootRelative + "/orphan"),
            "recovery deleted an object that no journal named"
        )
        XCTAssertFalse(fixture.targetExists(CoordinatorFixture.engineRelative))
    }

    func testUnsafeExistingDestinationIsRefused() throws {
        let fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
        let engine = fixture.sandbox + "/" + CoordinatorFixture.engineRelative
        try FileManager.default.removeItem(atPath: engine)
        let target = fixture.workspace.path("outside")
        try Data("outside".utf8).write(to: URL(fileURLWithPath: target))
        try FileManager.default.createSymbolicLink(atPath: engine, withDestinationPath: target)
        XCTAssertThrowsError(try fixture.coordinator().install(source: fixture.source)) {
            if case .existingFileUnsafe? = $0 as? CoordinatorError {} else { XCTFail("\($0)") }
        }
        XCTAssertEqual(fixture.readTarget(CoordinatorFixture.helperRelative), fixture.oldHelper)
        XCTAssertEqual(fixture.readTarget(CoordinatorFixture.daemonRelative), fixture.launchDaemonData)
        XCTAssertEqual(fixture.readTarget(CoordinatorFixture.rightRelative), fixture.startRightData)
        XCTAssertFalse(fixture.targetExists(CoordinatorFixture.journalRelative))
        XCTAssertTrue(FileManager.default.fileExists(atPath: engine))
    }

    func testPostRenameCommitJournalUncertaintyStopsWithoutRollback() throws {
        let fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
        let fault = InstallJournalWriteFault(phase: .committed, stage: .postRename)
        XCTAssertThrowsError(
            try fixture.coordinator(journalFault: fault).install(source: fixture.source)
        ) {
            guard case .journalWriteUncertain? = $0 as? CoordinatorError else {
                return XCTFail("\($0)")
            }
        }
        // The committed record is visible. The coordinator must not roll it
        // back with the old in-memory `replacing` phase, and it must keep the
        // verified backups for recovery.
        try fixture.assertNewSet()
        let journal = try XCTUnwrap(try fixture.readJournal())
        XCTAssertEqual(journal.phase, .committed)
        XCTAssertEqual(
            fixture.backupFileNames(transactionID: journal.transactionID),
            ["0", "1", "2", "3"]
        )
        let recovery = try fixture.coordinator().recover()
        XCTAssertEqual(
            recovery,
            .finishedCommit(transactionID: journal.transactionID, version: "2.0.0")
        )
        try fixture.assertNewSet()
        fixture.assertNoJournal()
        fixture.assertNoBackups()
        fixture.assertNoTemporaryFiles()
    }

    func testPostRenameReplacingJournalUncertaintyIsResolvedByRecovery() throws {
        let fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
        let fault = InstallJournalWriteFault(phase: .replacing, stage: .postRename)
        XCTAssertThrowsError(
            try fixture.coordinator(journalFault: fault).install(source: fixture.source)
        ) {
            guard case .journalWriteUncertain? = $0 as? CoordinatorError else {
                return XCTFail("\($0)")
            }
        }
        // No file has moved. The visible record is `replacing`, but a crash
        // could have kept `preparing`. Recovery decides from the record it
        // finds; the install path must not touch a file either way.
        try fixture.assertOldSet()
        let journal = try XCTUnwrap(try fixture.readJournal())
        XCTAssertEqual(journal.phase, .replacing)
        XCTAssertEqual(fixture.backupFileNames(transactionID: journal.transactionID), [])
        let recovery = try fixture.coordinator().recover()
        XCTAssertEqual(
            recovery,
            .rolledBack(transactionID: journal.transactionID, version: "2.0.0")
        )
        try fixture.assertOldSet()
        fixture.assertNoJournal()
        fixture.assertNoBackups()
        fixture.assertNoTemporaryFiles()
    }

    func testPostRenamePreparingJournalUncertaintyLeavesNoPartialLayout() throws {
        let fixture = try CoordinatorFixture(newPadding: 192)
        let fault = InstallJournalWriteFault(phase: .preparing, stage: .postRename)
        XCTAssertThrowsError(
            try fixture.coordinator(journalFault: fault).install(source: fixture.source)
        ) {
            guard case .journalWriteUncertain? = $0 as? CoordinatorError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertFalse(
            fixture.targetExists("Library/Application Support/HotspotShade"),
            "a directory was created after an unknown journal write"
        )
        let journal = try XCTUnwrap(try fixture.readJournal())
        XCTAssertEqual(journal.phase, .preparing)
        _ = try fixture.coordinator().recover()
        XCTAssertFalse(fixture.targetExists("Library/Application Support/HotspotShade"))
        fixture.assertNoJournal()
        fixture.assertNoBackups()
        fixture.assertNoTemporaryFiles()
    }

    // A failure before the rename is a known clean failure. The durable
    // `preparing` record is still authoritative, so the install rolls back
    // inline and does not leave a journal that needs a separate recovery.
    func testPreRenameReplacingJournalFailureRollsBackInline() throws {
        let fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
        let fault = InstallJournalWriteFault(phase: .replacing, stage: .preRename)
        XCTAssertThrowsError(
            try fixture.coordinator(journalFault: fault).install(source: fixture.source)
        ) {
            guard case .io? = $0 as? CoordinatorError else {
                return XCTFail("\($0)")
            }
        }
        try fixture.assertOldSet()
        fixture.assertNoJournal()
        fixture.assertNoBackups()
        fixture.assertNoTemporaryFiles()
    }

    // A real failure from a changed staged payload, not a simulated crash.
    // The action removes the helper source after the engine file is installed,
    // so the next copy fails through the production error path and the inline
    // rollback restores every previous file.
    func testRealStagedPayloadLossDuringInstallRollsBackInline() throws {
        let fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
        let helperSource = fixture.staged.payloadDirectory
            + "/" + "install-support/" + HelperRequirement.helperIdentifier
        let action = CoordinatorActionAt(.fileInstalled0) {
            try FileManager.default.removeItem(atPath: helperSource)
        }
        XCTAssertThrowsError(
            try fixture.coordinator(faults: action).install(source: fixture.source)
        ) {
            guard case .io? = $0 as? CoordinatorError else {
                return XCTFail("\($0)")
            }
        }
        try fixture.assertOldSet()
        fixture.assertNoJournal()
        fixture.assertNoBackups()
        fixture.assertNoTemporaryFiles()
        XCTAssertTrue(fixture.backupEntries().isEmpty)
    }

    func testJournalWithLoosePermissionsIsRefused() throws {
        let fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
        XCTAssertThrowsError(
            try fixture.coordinator(faults: CoordinatorFaultAt(.journalPrepared))
                .install(source: fixture.source)
        )
        let journalPath = fixture.sandbox + "/" + CoordinatorFixture.journalRelative
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o644],
            ofItemAtPath: journalPath
        )
        for action in [
            { _ = try fixture.coordinator().recover() },
            { _ = try fixture.coordinator().install(source: fixture.source) },
        ] {
            XCTAssertThrowsError(try action()) {
                guard case .journalUnreadable? = $0 as? CoordinatorError else {
                    return XCTFail("\($0)")
                }
            }
            XCTAssertTrue(fixture.targetExists(CoordinatorFixture.journalRelative))
            try fixture.assertOldSet()
        }
    }

    func testStatusReportsNoStateOnACleanSandbox() throws {
        let fixture = try CoordinatorFixture()
        let status = try fixture.coordinator().status()
        XCTAssertNil(status.journalPhase)
        XCTAssertFalse(status.serviceJournalPresent)
        XCTAssertFalse(status.cleanupBlocked)
        XCTAssertFalse(status.launchIntentPresent)
        XCTAssertFalse(status.startJournalPresent)
        XCTAssertNil(status.startJournalLockMatchesHeldLock)
        XCTAssertEqual(status.presentLockFileNames, [])
        XCTAssertEqual(status.backupOrphans, [])
        XCTAssertFalse(status.lockFilePresent)
    }

    func testCoordinatorRefusesTheRootUser() throws {
        let fixture = try CoordinatorFixture()
        XCTAssertThrowsError(
            try InstallCoordinator(
                sandboxRoot: fixture.sandbox,
                effectiveUserID: 0
            )
        ) {
            XCTAssertEqual($0 as? CoordinatorError, .runningAsRoot)
        }
    }

    func testPolicyRemainsUnapproved() {
        XCTAssertFalse(CoordinatorPolicy.liveInstallationApproved)
        XCTAssertFalse(InstallerScripts.installationApproved)
        XCTAssertFalse(InstallerManifest.notes.isEmpty)
        XCTAssertTrue(InstallerManifest.notes.contains {
            $0.contains("NOT APPROVED FOR INSTALLATION")
        })
        XCTAssertTrue(InstallerManifest.notes.contains {
            $0.contains("Do not install this package")
        })
    }
}
