import Foundation
import Darwin
import XCTest
import HotspotShadeKit
@testable import HotspotShadeInstallerCore

// The recovery path must not act on a phase record that is only visible in the
// namespace. These tests use the production atomic seam with one failing
// directory sync, so the rename is real and only the parent sync result is
// injected. They do not claim APFS power-loss behavior; they pin the order the
// code enforces and the state it keeps when the outcome is unknown.
final class JournalDurabilityTests: XCTestCase {
    private func tree(_ fixture: CoordinatorFixture) throws -> InstallTree {
        try InstallTree(rootPath: fixture.sandbox, expectedOwner: UInt32(geteuid()))
    }

    // The review counterexample: a visible `committed` record after a failed
    // parent sync. Recovery may not remove a backup until the exact record is
    // durably confirmed. A failed confirmation keeps every backup and the
    // journal; a later normal recovery finishes the commit.
    func testRecoveryDoesNotRemoveBackupsUntilTheCommittedRecordIsConfirmed() throws {
        let fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
        let fault = InstallJournalWriteFault(phase: .committed, stage: .postRename)
        XCTAssertThrowsError(
            try fixture.coordinator(journalFault: fault).install(source: fixture.source)
        ) {
            guard case .journalWriteUncertain? = $0 as? CoordinatorError else {
                return XCTFail("\($0)")
            }
        }
        try fixture.assertNewSet()
        let journal = try XCTUnwrap(try fixture.readJournal())
        XCTAssertEqual(journal.phase, .committed)
        XCTAssertEqual(
            fixture.backupFileNames(transactionID: journal.transactionID),
            ["0", "1", "2", "3"]
        )

        // The confirmation write is the same phase and fails after its rename.
        // Recovery must stop before the first backup removal.
        XCTAssertThrowsError(
            try fixture.coordinator(journalFault: fault).recover()
        ) {
            guard case .journalWriteUncertain? = $0 as? CoordinatorError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertEqual(try fixture.readJournal(), journal)
        XCTAssertEqual(
            fixture.backupFileNames(transactionID: journal.transactionID),
            ["0", "1", "2", "3"],
            "recovery removed a backup before the committed phase was durable"
        )
        try fixture.assertNewSet()

        let recovery = try fixture.coordinator().recover()
        XCTAssertEqual(
            recovery,
            .finishedCommit(transactionID: journal.transactionID, version: "2.0.0")
        )
        try fixture.assertNewSet()
        fixture.assertNoJournal()
        fixture.assertNoBackups()
        fixture.assertNoTemporaryFiles()
        XCTAssertEqual(try fixture.coordinator().recover(), .nothingToRecover)
    }

    // The same rule for a visible `replacing` record: a failed confirmation
    // keeps the journal and every file exactly as observed.
    func testRecoveryDoesNotRollBackUntilTheReplacingRecordIsConfirmed() throws {
        let fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
        let fault = InstallJournalWriteFault(phase: .replacing, stage: .postRename)
        XCTAssertThrowsError(
            try fixture.coordinator(journalFault: fault).install(source: fixture.source)
        ) {
            guard case .journalWriteUncertain? = $0 as? CoordinatorError else {
                return XCTFail("\($0)")
            }
        }
        try fixture.assertOldSet()
        let journal = try XCTUnwrap(try fixture.readJournal())
        XCTAssertEqual(journal.phase, .replacing)
        XCTAssertEqual(fixture.backupFileNames(transactionID: journal.transactionID), [])

        XCTAssertThrowsError(
            try fixture.coordinator(journalFault: fault).recover()
        ) {
            guard case .journalWriteUncertain? = $0 as? CoordinatorError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertEqual(try fixture.readJournal(), journal)
        try fixture.assertOldSet()

        let recovery = try fixture.coordinator().recover()
        XCTAssertEqual(
            recovery,
            .rolledBack(transactionID: journal.transactionID, version: "2.0.0")
        )
        try fixture.assertOldSet()
        fixture.assertNoJournal()
        fixture.assertNoBackups()
        XCTAssertEqual(try fixture.coordinator().recover(), .nothingToRecover)
    }

    // A post-rename copy sync failure is not an ordinary pre-rename error. The
    // install must stop before another file mutation and keep the journal for
    // recovery to confirm and re-observe.
    func testInstallStopsOnAnUncertainCopyAndRecoveryRestoresThePreviousSet() throws {
        let fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
        XCTAssertThrowsError(
            try fixture.coordinator(syncHooks: failingTreeHooks(.copyAfterRename))
                .install(source: fixture.source)
        ) {
            guard case .fileWriteUncertain? = $0 as? CoordinatorError else {
                return XCTFail("\($0)")
            }
        }
        let journal = try XCTUnwrap(try fixture.readJournal())
        XCTAssertEqual(journal.phase, .replacing)
        XCTAssertEqual(fixture.readTarget(CoordinatorFixture.engineRelative), fixture.newEngine)
        XCTAssertEqual(fixture.readTarget(CoordinatorFixture.helperRelative), fixture.oldHelper)
        XCTAssertEqual(
            fixture.backupFileNames(transactionID: journal.transactionID),
            ["0"]
        )

        let recovery = try fixture.coordinator().recover()
        guard case .rolledBack = recovery else { return XCTFail("\(recovery)") }
        try fixture.assertOldSet()
        fixture.assertNoJournal()
        fixture.assertNoBackups()
        fixture.assertNoTemporaryFiles()
    }

    // A post-rename backup-move sync failure also stops the install. The old
    // bytes are in the backup, so recovery can restore them.
    func testInstallStopsOnAnUncertainBackupMoveWithoutLosingTheFile() throws {
        for fault in [TreeSyncFault.moveGained, .moveLost] {
            let fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
            XCTAssertThrowsError(
                try fixture.coordinator(syncHooks: failingTreeHooks(fault))
                    .install(source: fixture.source),
                "\(fault)"
            ) {
                guard case .fileWriteUncertain? = $0 as? CoordinatorError else {
                    return XCTFail("\(fault): \($0)")
                }
            }
            let journal = try XCTUnwrap(try fixture.readJournal(), "\(fault)")
            XCTAssertEqual(journal.phase, .replacing, "\(fault)")
            XCTAssertFalse(
                fixture.targetExists(CoordinatorFixture.engineRelative),
                "\(fault): the destination is still named after the move"
            )
            let backup = CoordinatorFixture.backupRootRelative
                + "/" + journal.transactionID + "/0"
            XCTAssertEqual(fixture.readTarget(backup), fixture.oldEngine, "\(fault)")

            let recovery = try fixture.coordinator().recover()
            guard case .rolledBack = recovery else {
                return XCTFail("\(fault): \(recovery)")
            }
            try fixture.assertOldSet()
            fixture.assertNoJournal()
            fixture.assertNoBackups()
        }
    }

    // A restore-sync failure during recovery keeps the journal and the backup
    // so a later run can finish. The destination keeps the new bytes, which the
    // transaction owns.
    func testRecoveryRestoreSyncFailureKeepsTheJournalAndBackup() throws {
        let fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
        XCTAssertThrowsError(
            try fixture.coordinator(faults: CoordinatorFaultAt(.fileInstalled1))
                .install(source: fixture.source)
        )
        let journal = try XCTUnwrap(try fixture.readJournal())
        XCTAssertEqual(journal.phase, .replacing)
        XCTAssertEqual(
            fixture.backupFileNames(transactionID: journal.transactionID),
            ["0", "1"]
        )

        for fault in [TreeSyncFault.restoreGained, .restoreLost] {
            XCTAssertThrowsError(
                try fixture.coordinator(syncHooks: failingTreeHooks(fault)).recover(),
                "\(fault)"
            ) {
                guard case .recoveryRequired? = $0 as? CoordinatorError else {
                    return XCTFail("\(fault): \($0)")
                }
            }
            XCTAssertEqual(try fixture.readJournal(), journal, "\(fault)")
            XCTAssertTrue(
                fixture.targetExists(CoordinatorFixture.engineRelative)
                    || fixture.targetExists(
                        CoordinatorFixture.backupRootRelative
                            + "/" + journal.transactionID + "/0"
                    ),
                "\(fault): the engine bytes were lost"
            )
        }

        let recovery = try fixture.coordinator().recover()
        guard case .rolledBack = recovery else { return XCTFail("\(recovery)") }
        try fixture.assertOldSet()
        fixture.assertNoJournal()
        fixture.assertNoBackups()
    }

    // Both cross-directory renames make the gaining parent durable before the
    // losing parent. A crash between the two can duplicate a name but cannot
    // lose the file.
    func testCrossDirectoryRenamesSyncTheGainingParentFirst() throws {
        let fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
        let tree = try tree(fixture)
        let engine = try XCTUnwrap(
            try tree.snapshot(CoordinatorFixture.engineRelative, maximumBytes: 1 << 20)
        )
        let backup = CoordinatorFixture.backupRootRelative + "/rename-order/0"
        try fixture.makeDirectory(
            CoordinatorFixture.backupRootRelative + "/rename-order",
            mode: 0o700
        )

        var moveRoles: [RenameSyncRole] = []
        try tree.moveToBackup(
            CoordinatorFixture.engineRelative,
            backupRelative: backup,
            expected: engine,
            gainedSync: { _ in moveRoles.append(.gained); return 0 },
            lostSync: { _ in moveRoles.append(.lost); return 0 }
        )
        XCTAssertEqual(moveRoles, [.gained, .lost])
        XCTAssertFalse(fixture.targetExists(CoordinatorFixture.engineRelative))
        XCTAssertEqual(fixture.readTarget(backup), fixture.oldEngine)

        var restoreRoles: [RenameSyncRole] = []
        try tree.restoreFromBackup(
            backup,
            to: CoordinatorFixture.engineRelative,
            expected: engine,
            gainedSync: { _ in restoreRoles.append(.gained); return 0 },
            lostSync: { _ in restoreRoles.append(.lost); return 0 }
        )
        XCTAssertEqual(restoreRoles, [.gained, .lost])
        try fixture.assertOldSet()
        XCTAssertFalse(fixture.targetExists(backup))
    }

    // A private journal record is removed only when its exact observed digest
    // and mode still match. A changed mode, changed bytes, a hard link, a
    // read-only mode, and a special bit are all refused and kept.
    func testJournalRemovalRequiresTheExactObservedDigestAndMode() throws {
        let fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
        XCTAssertThrowsError(
            try fixture.coordinator(faults: CoordinatorFaultAt(.journalPrepared))
                .install(source: fixture.source)
        )
        let store = InstallJournalStore(tree: try tree(fixture))
        let preparing = try XCTUnwrap(try store.readObserved())
        try fixture.writeStateJournal(preparing.journal.withPhase(.committed))
        let committed = try XCTUnwrap(try store.readObserved())
        let journalPath = fixture.sandbox + "/" + CoordinatorFixture.journalRelative

        try FileManager.default.setAttributes(
            [.posixPermissions: 0o644],
            ofItemAtPath: journalPath
        )
        XCTAssertThrowsError(try store.remove(committed))
        XCTAssertEqual(try fixture.readJournal()?.phase, .committed)

        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: journalPath
        )
        try fixture.writeStateJournal(committed.journal.withPhase(.replacing))
        XCTAssertThrowsError(try store.remove(committed)) {
            guard case .journalUnreadable? = $0 as? CoordinatorError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertEqual(try fixture.readJournal()?.phase, .replacing)

        let duplicate = fixture.sandbox + "/" + CoordinatorFixture.stateRelative + "/journal-copy"
        XCTAssertEqual(
            link(journalPath, duplicate),
            0,
            "the test could not create a hard link"
        )
        XCTAssertThrowsError(try store.readObserved()) {
            guard case .journalUnreadable? = $0 as? CoordinatorError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertThrowsError(try store.remove(committed))
        XCTAssertTrue(FileManager.default.fileExists(atPath: journalPath))
        XCTAssertTrue(FileManager.default.fileExists(atPath: duplicate))
    }

    func testMoveToBackupAndCopyNeverOverwriteAForeignObject() throws {
        let fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
        let tree = try tree(fixture)
        let engine = try XCTUnwrap(
            try tree.snapshot(CoordinatorFixture.engineRelative, maximumBytes: 1 << 20)
        )
        let backup = CoordinatorFixture.backupRootRelative + "/foreign/0"
        try fixture.makeDirectory(
            CoordinatorFixture.backupRootRelative + "/foreign",
            mode: 0o700
        )
        let foreignBackup = Data("a foreign backup\n".utf8)
        try fixture.writeFile(fixture.sandbox + "/" + backup, foreignBackup, mode: 0o600)
        XCTAssertThrowsError(
            try tree.moveToBackup(
                CoordinatorFixture.engineRelative,
                backupRelative: backup,
                expected: engine
            )
        ) {
            XCTAssertEqual($0 as? InstallTreeError, .alreadyExists(backup))
        }
        XCTAssertEqual(fixture.readTarget(CoordinatorFixture.engineRelative), fixture.oldEngine)
        XCTAssertEqual(fixture.readTarget(backup), foreignBackup)

        let foreignDestination = Data("a foreign destination\n".utf8)
        try fixture.writeFile(
            fixture.sandbox + "/" + CoordinatorFixture.helperRelative,
            foreignDestination,
            mode: 0o755
        )
        let source = fixture.staged.payloadDirectory + "/engine/hotspotshade"
        let expected = FileSnapshot(
            sha256: ServiceHash.sha256Hex(fixture.newEngine),
            size: fixture.newEngine.count,
            mode: 0o755
        )
        XCTAssertThrowsError(
            try tree.copyFromFile(
                sourcePath: source,
                expected: expected,
                to: CoordinatorFixture.helperRelative,
                mode: 0o755,
                temporarySuffix: "abc123"
            )
        ) {
            XCTAssertEqual(
                $0 as? InstallTreeError,
                .alreadyExists(CoordinatorFixture.helperRelative)
            )
        }
        XCTAssertEqual(
            fixture.readTarget(CoordinatorFixture.helperRelative),
            foreignDestination,
            "the copy replaced a foreign destination"
        )
    }

    func testExclusiveRenamesRefuseAFileCreatedAfterTheLastCheck() throws {
        let fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
        let tree = try tree(fixture)
        let engine = try XCTUnwrap(
            try tree.snapshot(CoordinatorFixture.engineRelative, maximumBytes: 1 << 20)
        )
        let backup = CoordinatorFixture.backupRootRelative + "/rename-race/0"
        try fixture.makeDirectory(CoordinatorFixture.backupRootRelative + "/rename-race", mode: 0o700)
        let foreign = Data("foreign object\n".utf8)

        XCTAssertThrowsError(try tree.moveToBackup(
            CoordinatorFixture.engineRelative,
            backupRelative: backup,
            expected: engine,
            gainedSync: { fsync($0) },
            lostSync: { fsync($0) },
            beforeRename: { try fixture.writeFile(fixture.sandbox + "/" + backup, foreign, mode: 0o600) }
        )) { XCTAssertEqual($0 as? InstallTreeError, .alreadyExists(backup)) }
        XCTAssertEqual(fixture.readTarget(backup), foreign)
        XCTAssertEqual(fixture.readTarget(CoordinatorFixture.engineRelative), fixture.oldEngine)

        let destination = "Library/Application Support/HotspotShade/engine/rename-race"
        let expected = FileSnapshot(
            sha256: ServiceHash.sha256Hex(fixture.newEngine),
            size: fixture.newEngine.count,
            mode: 0o755
        )
        XCTAssertThrowsError(try tree.copyFromFile(
            sourcePath: fixture.staged.payloadDirectory + "/engine/hotspotshade",
            expected: expected,
            to: destination,
            mode: 0o755,
            temporarySuffix: "abc123",
            directorySync: { fsync($0) },
            beforeRename: { try fixture.writeFile(fixture.sandbox + "/" + destination, foreign, mode: 0o600) }
        )) { XCTAssertEqual($0 as? InstallTreeError, .alreadyExists(destination)) }
        XCTAssertEqual(fixture.readTarget(destination), foreign)
    }

    func testRecoveryStopsWhenJournalRemovalSyncIsUnknown() throws {
        for committed in [false, true] {
            let fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
            let cut: CoordinatorStep = committed ? .commitJournalWritten : .journalPrepared
            XCTAssertThrowsError(
                try fixture.coordinator(faults: CoordinatorFaultAt(cut)).install(source: fixture.source)
            )
            XCTAssertNotNil(try fixture.readJournal())

            // This fault after successful removal must not be reached when the
            // journal unlink's directory sync reports an unknown outcome.
            XCTAssertThrowsError(
                try fixture.coordinator(
                    faults: CoordinatorFaultAt(.recoveryJournalRemoved),
                    journalTreeHooks: failingTreeHooks(.removeAfterUnlink)
                ).recover()
            ) {
                guard case .recoveryRequired(let reason)? = $0 as? CoordinatorError else {
                    return XCTFail("\($0)")
                }
                XCTAssertTrue(reason.contains("sync failed"), reason)
            }
            XCTAssertNil(try fixture.readJournal(), "unlink is visible but its durability is unknown")
            if committed { try fixture.assertNewSet() } else { try fixture.assertOldSet() }
        }
    }

    func testCommittedInstallStopsWhenJournalRemovalSyncIsUnknown() throws {
        let fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
        XCTAssertThrowsError(
            try fixture.coordinator(
                faults: CoordinatorFaultAt(.journalRemoved),
                journalTreeHooks: failingTreeHooks(.removeAfterUnlink)
            ).install(source: fixture.source)
        ) {
            guard case .recoveryRequired(let reason)? = $0 as? CoordinatorError else {
                return XCTFail("\($0)")
            }
            XCTAssertTrue(reason.contains("sync failed"), reason)
        }
        XCTAssertNil(try fixture.readJournal(), "the unlink is visible but not proven durable")
        try fixture.assertNewSet()
        fixture.assertNoBackups()
    }

    // A removal whose parent sync fails is an unknown outcome. A committed
    // cleanup stops before the journal removal, so the durable record remains
    // for the next run.
    func testCommittedCleanupStopsWhenABackupRemovalIsUnknown() throws {
        let fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
        XCTAssertThrowsError(
            try fixture.coordinator(faults: CoordinatorFaultAt(.commitJournalWritten))
                .install(source: fixture.source)
        )
        let journal = try XCTUnwrap(try fixture.readJournal())
        XCTAssertEqual(journal.phase, .committed)
        XCTAssertFalse(fixture.backupEntries().isEmpty)

        XCTAssertThrowsError(
            try fixture.coordinator(syncHooks: failingTreeHooks(.removeAfterUnlink))
                .recover()
        ) {
            guard case .recoveryRequired? = $0 as? CoordinatorError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertEqual(try fixture.readJournal(), journal)
        try fixture.assertNewSet()

        let recovery = try fixture.coordinator().recover()
        guard case .finishedCommit = recovery else { return XCTFail("\(recovery)") }
        try fixture.assertNewSet()
        fixture.assertNoJournal()
        fixture.assertNoBackups()
    }

    func testJournalRemovalReportsAnUnknownUnlinkSync() throws {
        let fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
        XCTAssertThrowsError(
            try fixture.coordinator(faults: CoordinatorFaultAt(.journalPrepared))
                .install(source: fixture.source)
        )
        let plain = try InstallTree(rootPath: fixture.sandbox, expectedOwner: UInt32(geteuid()))
        let plainStore = InstallJournalStore(tree: plain)
        try fixture.writeStateJournal(
            try XCTUnwrap(try plainStore.readObserved()).journal.withPhase(.committed)
        )
        let observed = try XCTUnwrap(try plainStore.readObserved())
        let failing = try InstallTree(
            rootPath: fixture.sandbox,
            expectedOwner: UInt32(geteuid()),
            syncHooks: failingTreeHooks(.removeAfterUnlink)
        )
        XCTAssertThrowsError(try InstallJournalStore(tree: failing).remove(observed)) {
            guard case .journalRemoveUncertain? = $0 as? CoordinatorError else {
                return XCTFail("\($0)")
            }
        }
        // The unlink ran, so the name is gone now. The error says the removal
        // may not survive a crash; a later run must re-observe either state.
        XCTAssertNil(try plainStore.readObserved())
    }

    func testJournalReadRequiresExact0600AndOneLink() throws {
        let fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
        XCTAssertThrowsError(
            try fixture.coordinator(faults: CoordinatorFaultAt(.journalPrepared))
                .install(source: fixture.source)
        )
        let store = InstallJournalStore(tree: try tree(fixture))
        let journalPath = fixture.sandbox + "/" + CoordinatorFixture.journalRelative

        for mode in [0o400, 0o640, 0o4600, 0o2600, 0o1600] {
            try FileManager.default.setAttributes(
                [.posixPermissions: mode],
                ofItemAtPath: journalPath
            )
            XCTAssertThrowsError(try store.readObserved(), "mode \(String(mode, radix: 8))") {
                guard case .journalUnreadable? = $0 as? CoordinatorError else {
                    return XCTFail("\(String(mode, radix: 8)): \($0)")
                }
            }
        }

        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: journalPath
        )
        let duplicate = fixture.sandbox + "/" + CoordinatorFixture.stateRelative + "/journal-copy"
        XCTAssertEqual(link(journalPath, duplicate), 0)
        XCTAssertThrowsError(try store.readObserved())
    }
}
