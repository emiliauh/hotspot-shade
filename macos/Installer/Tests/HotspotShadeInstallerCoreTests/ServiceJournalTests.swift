import Foundation
import XCTest
import HotspotShadeKit
@testable import HotspotShadeInstallerCore

final class ServiceJournalTests: XCTestCase {
    private func installedValues(_ context: ServiceTestContext) throws -> (
        right: AuthorizationRightSnapshot,
        daemonSHA256: String
    ) {
        let rightData = try Data(
            contentsOf: URL(
                fileURLWithPath: context.fixture.sandbox
                    + "/" + PrivilegedServiceLayout.rightSourceRelative
            )
        )
        let right = try AuthorizationRightPolicyParser.parse(rightData)
        let daemonData = try Data(
            contentsOf: URL(
                fileURLWithPath: context.fixture.sandbox
                    + "/" + PrivilegedServiceLayout.launchDaemonRelative
            )
        )
        return (right, ServiceHash.sha256Hex(daemonData))
    }

    private func journal(
        _ context: ServiceTestContext,
        phase: ServiceJournal.Phase = .preparing,
        rightName: String = PrivilegedServiceLayout.rightName,
        launchdLabel: String = PrivilegedServiceLayout.launchdLabel,
        launchDaemonPath: String = PrivilegedServiceLayout.launchDaemonPath,
        helperPath: String = PrivilegedServiceLayout.helperPath,
        transactionID: String = String(repeating: "a", count: 32),
        previousRight: AuthorizationRightSnapshot? = nil,
        previousRightPresent: Bool? = nil,
        previousRightSHA256: String? = nil,
        previousJobLoaded: Bool = false,
        installedPolicy: AuthorizationRightPolicy? = nil
    ) throws -> ServiceJournal {
        let values = try installedValues(context)
        let present = previousRightPresent ?? (previousRight != nil)
        return ServiceJournal(
            transactionID: transactionID,
            installTransactionID: nil,
            rightName: rightName,
            launchdLabel: launchdLabel,
            launchDaemonPath: launchDaemonPath,
            helperPath: helperPath,
            installedRightSHA256: values.right.sha256,
            installedRightPolicy: installedPolicy ?? values.right.policy,
            installedLaunchDaemonSHA256: values.daemonSHA256,
            phase: phase,
            previousRightPresent: present,
            previousRightSHA256: previousRightSHA256 ?? previousRight?.sha256,
            previousRightPolicy: previousRight?.policy,
            previousRightPlistBase64: previousRight?.plist.base64EncodedString(),
            previousJobLoaded: previousJobLoaded
        )
    }

    func testJournalNamesMatchTheHelperAndRustSources() throws {
        XCTAssertEqual(
            ServiceJournalStore.fileName,
            HelperStartExclusionProtocol.serviceJournalFileName
        )
        XCTAssertEqual(
            InstallJournalStore.fileName,
            HelperStartExclusionProtocol.installJournalFileName
        )

        let rust = try String(
            contentsOf: Repo.root.appendingPathComponent("rust/src/macos_upgrade_lock.rs"),
            encoding: .utf8
        )
        XCTAssertTrue(
            rust.contains(
                "const INSTALL_JOURNAL_NAME: &str = \"\(InstallJournalStore.fileName)\""
            )
        )
        XCTAssertTrue(
            rust.contains(
                "const SERVICE_JOURNAL_NAME: &str = \"\(ServiceJournalStore.fileName)\""
            )
        )
    }

    func testValidJournalRoundTripsThroughTheStore() throws {
        let context = try ServiceTestContext()
        let value = try journal(context)
        try value.validate()
        let store = ServiceJournalStore(tree: context.tree)
        let observed = try XCTUnwrap(try store.write(value))
        let read = try store.read()
        XCTAssertEqual(read, value)
        try store.remove(observed)
        XCTAssertNil(try store.read())
    }

    func testFixedNamesPathsAndDigestsAreRefused() throws {
        let context = try ServiceTestContext()
        let values = [
            try journal(context, rightName: "another.right"),
            try journal(context, launchdLabel: "another.label"),
            try journal(context, launchDaemonPath: "/tmp/another.plist"),
            try journal(context, helperPath: "/tmp/another-helper"),
            try journal(context, transactionID: "not-hex"),
        ]
        for value in values {
            XCTAssertThrowsError(try value.validate())
        }
    }

    func testPreviousRightBackupIsChecked() throws {
        let context = try ServiceTestContext()
        let previous = try ServiceTestFixtures.previousRight()
        let valid = try journal(context, previousRight: previous)
        XCTAssertNoThrow(try valid.validate())

        let wrongDigest = try journal(
            context,
            previousRight: previous,
            previousRightSHA256: String(repeating: "b", count: 64)
        )
        XCTAssertThrowsError(try wrongDigest.validate())

        let missingBackup = try journal(
            context,
            previousRight: previous,
            previousRightPresent: true
        )
        // The helper sets the base64 from the snapshot, so remove it by
        // rebuilding the record without a backup.
        let noBackup = ServiceJournal(
            transactionID: missingBackup.transactionID,
            installTransactionID: missingBackup.installTransactionID,
            rightName: missingBackup.rightName,
            launchdLabel: missingBackup.launchdLabel,
            launchDaemonPath: missingBackup.launchDaemonPath,
            helperPath: missingBackup.helperPath,
            installedRightSHA256: missingBackup.installedRightSHA256,
            installedRightPolicy: missingBackup.installedRightPolicy,
            installedLaunchDaemonSHA256: missingBackup.installedLaunchDaemonSHA256,
            phase: missingBackup.phase,
            previousRightPresent: true,
            previousRightSHA256: previous.sha256,
            previousRightPolicy: previous.policy,
            previousRightPlistBase64: nil,
            previousJobLoaded: false
        )
        XCTAssertThrowsError(try noBackup.validate())
    }

    func testAnUnreviewedInstalledPolicyIsRefused() throws {
        let context = try ServiceTestContext()
        let values = try installedValues(context)
        let unsafePolicy = AuthorizationRightPolicy(
            rightClass: "user",
            group: "admin",
            authenticateUser: true,
            shared: false,
            allowRoot: true,
            timeout: HelperStartAuthorizationPolicy.startRightTimeoutSeconds,
            comment: values.right.policy.comment
        )
        let value = try journal(context, installedPolicy: unsafePolicy)
        XCTAssertThrowsError(try value.validate())
    }

    func testAnOutOfWindowTimeoutPolicyIsRefused() throws {
        let context = try ServiceTestContext()
        let values = try installedValues(context)
        for timeout in [0, -1, 61, 300] {
            let unsafePolicy = AuthorizationRightPolicy(
                rightClass: "user",
                group: "admin",
                authenticateUser: true,
                shared: false,
                allowRoot: false,
                timeout: timeout,
                comment: values.right.policy.comment
            )
            let value = try journal(context, installedPolicy: unsafePolicy)
            XCTAssertThrowsError(try value.validate(), "A timeout of \(timeout) must be refused.")
        }
    }

    func testAnInWindowTimeoutPolicyIsAccepted() throws {
        let context = try ServiceTestContext()
        let values = try installedValues(context)
        for timeout in [1, 10, 60] {
            let policy = AuthorizationRightPolicy(
                rightClass: "user",
                group: "admin",
                authenticateUser: true,
                shared: false,
                allowRoot: false,
                timeout: timeout,
                comment: values.right.policy.comment
            )
            let value = try journal(context, installedPolicy: policy)
            XCTAssertNoThrow(try value.validate(), "A timeout of \(timeout) must be accepted.")
        }
    }

    func testPostRenameSyncFailureIsReportedAsAnUnknownWrite() throws {
        let context = try ServiceTestContext()
        let value = try journal(context)
        let store = context.journalStore(failingAfter: .preparing)

        XCTAssertThrowsError(try store.write(value)) {
            guard let error = $0 as? ServiceJournalError,
                  case .writeOutcomeUnknown = error
            else {
                return XCTFail("\($0)")
            }
        }
        // The renamed record is visible even though its directory sync did not
        // complete. The caller must keep it rather than assume a clean failure.
        XCTAssertEqual(try ServiceJournalStore(tree: context.tree).read(), value)
    }

    func testJournalWithLoosePermissionsIsRefused() throws {
        let context = try ServiceTestContext()
        let value = try journal(context)
        let store = ServiceJournalStore(tree: context.tree)
        try store.write(value)
        let path = context.fixture.sandbox
            + "/" + PrivilegedServiceLayout.stateDirectoryRelative
            + "/" + ServiceJournalStore.fileName
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o644],
            ofItemAtPath: path
        )
        XCTAssertThrowsError(try store.read()) {
            guard case .unreadable? = $0 as? ServiceJournalError else {
                return XCTFail("\($0)")
            }
        }
    }

    func testPreRenameFailureRemainsAnOrdinaryIOError() throws {
        let context = try ServiceTestContext()
        let value = try journal(context)
        let store = ServiceJournalStore(tree: context.tree) { _, _, _, _, _ in
            throw ServiceJournalError.io("injected before the rename")
        }

        XCTAssertThrowsError(try store.write(value)) {
            guard let error = $0 as? ServiceJournalError,
                  case .io = error
            else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertNil(try ServiceJournalStore(tree: context.tree).read())
    }

    func testRollbackPhasesRoundTrip() throws {
        let context = try ServiceTestContext()
        let store = ServiceJournalStore(tree: context.tree)
        for phase in [ServiceJournal.Phase.rollbackStarted, .rolledBack] {
            let value = try journal(context, phase: phase)
            let observed = try store.write(value)
            XCTAssertEqual(try store.read(), value)
            try store.remove(observed)
        }
        XCTAssertNil(try store.read())
    }

    func testStoreRemovesOnlyItsOwnTemporaryNames() throws {
        let context = try ServiceTestContext()
        let transactionID = String(repeating: "c", count: 32)
        let temporary = context.fixture.sandbox
            + "/" + PrivilegedServiceLayout.stateDirectoryRelative
            + "/." + ServiceJournalStore.fileName + ".hs-" + transactionID + ".tmp"
        let other = context.fixture.sandbox
            + "/" + PrivilegedServiceLayout.stateDirectoryRelative
            + "/keep.tmp"
        try context.fixture.writeFile(temporary, Data("temporary".utf8), mode: 0o600)
        try context.fixture.writeFile(other, Data("other".utf8), mode: 0o600)
        try ServiceJournalStore(tree: context.tree).removeTemporaryFiles()
        XCTAssertFalse(FileManager.default.fileExists(atPath: temporary))
        XCTAssertTrue(FileManager.default.fileExists(atPath: other))
    }

    // Recovery rewrites the exact observed record and requires its file and
    // parent sync before it acts. A failed confirmation keeps the journal and
    // performs no service action.
    func testRecoveryDoesNotActUntilTheObservedRecordIsConfirmed() throws {
        let previous = try ServiceTestFixtures.previousRight()
        let context = try ServiceTestContext(previousRight: .present(previous))
        let fault = context.journalStore(failingAfter: .committed)
        XCTAssertThrowsError(try context.transaction(journalStore: fault).apply()) {
            guard case .recoveryRequired = $0 as? ServiceTransactionError else {
                return XCTFail("\($0)")
            }
        }
        let journal = try XCTUnwrap(try context.journal())
        XCTAssertEqual(journal.phase, .committed)
        let bootouts = context.launchd.bootoutCount
        let bootstraps = context.launchd.bootstrapCount
        let writes = context.rightStore.writes.count

        XCTAssertThrowsError(try context.transaction(journalStore: fault).recover()) {
            guard case .recoveryRequired = $0 as? ServiceTransactionError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertEqual(try context.journal(), journal)
        XCTAssertEqual(context.launchd.bootoutCount, bootouts)
        XCTAssertEqual(context.launchd.bootstrapCount, bootstraps)
        XCTAssertEqual(context.rightStore.writes.count, writes)

        let recovery = try context.transaction().recover()
        guard case .finishedCommit = recovery else { return XCTFail("\(recovery)") }
        XCTAssertFalse(context.journalExists())
        XCTAssertEqual(try context.transaction().recover(), .nothingToRecover)
    }

    // A record is removed only when the exact observed bytes and mode still
    // match. A changed mode, changed bytes, a hard link, a read-only mode, and
    // a special bit are kept.
    func testRemovalWithAnUnknownUnlinkSyncIsReported() throws {
        let context = try ServiceTestContext()
        let value = try journal(context)
        let observed = try ServiceJournalStore(tree: context.tree).write(value)
        let failing = try InstallTree(
            rootPath: context.fixture.sandbox,
            expectedOwner: UInt32(geteuid()),
            syncHooks: failingTreeHooks(.removeAfterUnlink)
        )
        XCTAssertThrowsError(
            try ServiceJournalStore(tree: failing).remove(observed)
        ) {
            guard let error = $0 as? ServiceJournalError,
                  case .removeOutcomeUnknown = error
            else {
                return XCTFail("\($0)")
            }
        }
        // The unlink ran. A later run must re-observe the name; it may be
        // absent now and restored by a crash if the parent sync did not land.
        XCTAssertNil(try ServiceJournalStore(tree: context.tree).readObserved())
    }

    func testRemovalRequiresTheExactObservedDigestAndMode() throws {        let context = try ServiceTestContext()
        let store = ServiceJournalStore(tree: context.tree)
        let value = try journal(context)
        let observed = try store.write(value)
        let path = context.fixture.sandbox
            + "/" + PrivilegedServiceLayout.stateDirectoryRelative
            + "/" + ServiceJournalStore.fileName

        for mode in [0o400, 0o644, 0o4600, 0o2600, 0o1600] {
            try FileManager.default.setAttributes(
                [.posixPermissions: mode],
                ofItemAtPath: path
            )
            XCTAssertThrowsError(try store.readObserved(), "mode \(String(mode, radix: 8))") {
                guard case .unreadable? = $0 as? ServiceJournalError else {
                    return XCTFail("\(String(mode, radix: 8)): \($0)")
                }
            }
            XCTAssertThrowsError(try store.remove(observed), "mode \(String(mode, radix: 8))")
            XCTAssertTrue(FileManager.default.fileExists(atPath: path))
        }

        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: path
        )
        _ = try store.write(value.withPhase(.rolledBack))
        XCTAssertThrowsError(try store.remove(observed)) {
            guard case .unsafe? = $0 as? ServiceJournalError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertEqual(try store.read()?.phase, .rolledBack)

        let duplicate = context.fixture.sandbox
            + "/" + PrivilegedServiceLayout.stateDirectoryRelative + "/service-journal-copy"
        XCTAssertEqual(link(path, duplicate), 0, "the test could not create a hard link")
        XCTAssertThrowsError(try store.readObserved())
        XCTAssertThrowsError(try store.remove(observed))
        XCTAssertTrue(FileManager.default.fileExists(atPath: path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: duplicate))
    }
}
