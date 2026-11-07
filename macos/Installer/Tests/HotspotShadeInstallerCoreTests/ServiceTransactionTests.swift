import Foundation
import XCTest
import HotspotShadeKit
@testable import HotspotShadeInstallerCore

final class ServiceTransactionTests: XCTestCase {
    func testInitialInstallWritesTheRightAndBootstrapsTheJob() throws {
        let context = try ServiceTestContext()
        let expected = try context.installedRightPolicy()
        let outcome = try context.transaction().apply()

        XCTAssertEqual(context.rightStore.writes.count, 1)
        XCTAssertEqual(context.launchd.bootoutCount, 0)
        XCTAssertEqual(context.launchd.bootstrapCount, 1)
        XCTAssertFalse(context.journalExists())
        XCTAssertEqual(outcome.previousRightPresent, false)
        XCTAssertEqual(outcome.previousJobLoaded, false)
        XCTAssertEqual(outcome.right, expected)
        XCTAssertTrue(outcome.launchdJobLoaded)

        guard case .present(let stored) = context.rightStore.observation else {
            return XCTFail("the start right is not present")
        }
        XCTAssertEqual(stored.policy, expected)
        guard case .loaded = context.launchd.observation else {
            return XCTFail("the launch daemon job is not loaded")
        }
    }

    func testUpgradeBootsOutTheLoadedJobAndReplacesTheRight() throws {
        let previous = try ServiceTestFixtures.previousRight()
        let context = try ServiceTestContext(
            previousRight: .present(previous),
            previousJob: ServiceTestFixtures.loaded
        )
        let expected = try context.installedRightPolicy()
        let outcome = try context.transaction().apply()

        XCTAssertEqual(context.rightStore.writes.count, 1)
        XCTAssertEqual(context.launchd.bootoutCount, 1)
        XCTAssertEqual(context.launchd.bootstrapCount, 1)
        XCTAssertFalse(context.journalExists())
        XCTAssertEqual(outcome.previousRightPresent, true)
        XCTAssertEqual(outcome.previousJobLoaded, true)
        XCTAssertEqual(outcome.right, expected)

        guard case .present(let stored) = context.rightStore.observation else {
            return XCTFail("the start right is not present")
        }
        XCTAssertEqual(stored.policy, expected)
        guard case .loaded = context.launchd.observation else {
            return XCTFail("the launch daemon job is not loaded")
        }
    }

    func testRightWriteFailureWithNoPreviousJobRestoresThePreviousRight() throws {
        let previous = try ServiceTestFixtures.previousRight()
        let context = try ServiceTestContext(previousRight: .present(previous))
        context.rightStore.writeError = AuthorizationRightDatabaseError.commandFailed("injected")

        XCTAssertThrowsError(try context.transaction().apply()) {
            guard case .operationFailed = $0 as? ServiceTransactionError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertFalse(context.journalExists())
        XCTAssertEqual(context.launchd.bootoutCount, 0)
        XCTAssertEqual(context.launchd.bootstrapCount, 0)
        guard case .present(let stored) = context.rightStore.observation else {
            return XCTFail("the previous start right was removed")
        }
        XCTAssertEqual(stored.policy, previous.policy)
    }

    func testFailedRightWriteReportsTheWriteCommandNotAnObservationFailure() throws {
        let previous = try ServiceTestFixtures.previousRight()
        let context = try ServiceTestContext(previousRight: .present(previous))
        context.rightStore.writeError = AuthorizationRightDatabaseError.commandFailed("injected")

        XCTAssertThrowsError(try context.transaction().apply()) {
            guard case .some(.operationFailed(let why)) =
                $0 as? ServiceTransactionError
            else {
                return XCTFail("\($0)")
            }
            XCTAssertTrue(why.contains("authorization right command failed"), why)
            XCTAssertFalse(why.contains("cannot be observed"), why)
        }
        XCTAssertFalse(context.journalExists())
        XCTAssertEqual(context.launchd.bootstrapCount, 0)
    }

    func testRightReadbackMismatchRestoresThePreviousRight() throws {
        let previous = try ServiceTestFixtures.previousRight()
        let context = try ServiceTestContext(previousRight: .present(previous))
        context.rightStore.nextWriteObservation = .absent

        XCTAssertThrowsError(try context.transaction().apply()) {
            guard case .operationFailed = $0 as? ServiceTransactionError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertFalse(context.journalExists())
        XCTAssertEqual(context.launchd.bootstrapCount, 0)
        XCTAssertEqual(context.rightStore.writes.count, 2)
        guard case .present(let stored) = context.rightStore.observation else {
            return XCTFail("the previous start right was not restored")
        }
        XCTAssertEqual(stored.policy, previous.policy)
    }

    func testRightRollbackThatGainsAuthdMetadataIsReportedAsInexact() throws {
        let previous = try ServiceTestFixtures.previousRight()
        let context = try ServiceTestContext(previousRight: .present(previous))
        context.rightStore.nextWriteObservation = .absent
        context.rightStore.addMetadataOnWrite = true

        XCTAssertThrowsError(try context.transaction().apply()) {
            guard case .operationFailedWithInexactRightRollback = $0 as? ServiceTransactionError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertFalse(context.journalExists())
        guard case .present(let stored) = context.rightStore.observation else {
            return XCTFail("the previous start right was not restored")
        }
        XCTAssertEqual(stored.policy, previous.policy)
        XCTAssertNotEqual(stored.plist, previous.plist)
    }

    func testBootstrapFailureWithNoPreviousJobRollsBackTheRight() throws {
        let previous = try ServiceTestFixtures.previousRight()
        let context = try ServiceTestContext(previousRight: .present(previous))
        context.launchd.bootstrapError = LaunchdJobError.commandFailed("injected")

        XCTAssertThrowsError(try context.transaction().apply()) {
            guard case .operationFailed = $0 as? ServiceTransactionError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertFalse(context.journalExists())
        XCTAssertEqual(context.launchd.bootstrapCount, 1)
        XCTAssertEqual(context.launchd.bootoutCount, 0)
        guard case .present(let stored) = context.rightStore.observation else {
            return XCTFail("the previous start right was not restored")
        }
        XCTAssertEqual(stored.policy, previous.policy)
        guard case .absent = context.launchd.observation else {
            return XCTFail("the failed bootstrap left a job loaded")
        }
    }

    func testFailureAfterBootstrapBootsOutTheNewJob() throws {
        let previous = try ServiceTestFixtures.previousRight()
        let context = try ServiceTestContext(previousRight: .present(previous))
        struct FailingFault: ServiceTransactionFaultInjecting {
            let step: ServiceTransactionStep
            func check(_ candidate: ServiceTransactionStep) throws {
                if candidate == step {
                    throw ServiceTransactionError.commandFailed("injected after bootstrap")
                }
            }
        }

        XCTAssertThrowsError(
            try context.transaction(faults: FailingFault(step: .bootstrapJournalWritten)).apply()
        ) {
            guard case .operationFailed = $0 as? ServiceTransactionError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertFalse(context.journalExists())
        XCTAssertEqual(context.launchd.bootoutCount, 1)
        XCTAssertEqual(context.launchd.bootstrapCount, 1)
        guard case .present(let stored) = context.rightStore.observation else {
            return XCTFail("the previous start right was not restored")
        }
        XCTAssertEqual(stored.policy, previous.policy)
        guard case .absent = context.launchd.observation else {
            return XCTFail("the new job was left loaded after rollback")
        }
    }

    func testBootoutFailureLeavesThePreviousJobAndRestoresTheRight() throws {
        let previous = try ServiceTestFixtures.previousRight()
        let context = try ServiceTestContext(
            previousRight: .present(previous),
            previousJob: ServiceTestFixtures.loaded
        )
        context.launchd.bootoutError = LaunchdJobError.commandFailed("injected")

        XCTAssertThrowsError(try context.transaction().apply()) {
            guard case .operationFailed = $0 as? ServiceTransactionError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertFalse(context.journalExists())
        XCTAssertEqual(context.launchd.bootoutCount, 1)
        XCTAssertEqual(context.launchd.bootstrapCount, 0)
        guard case .loaded = context.launchd.observation else {
            return XCTFail("the previous job was not left loaded")
        }
        guard case .present(let stored) = context.rightStore.observation else {
            return XCTFail("the previous start right was not restored")
        }
        XCTAssertEqual(stored.policy, previous.policy)
    }

    func testBootoutThatDoesNotTakeEffectIsRefused() throws {
        let previous = try ServiceTestFixtures.previousRight()
        let context = try ServiceTestContext(
            previousRight: .present(previous),
            previousJob: ServiceTestFixtures.loaded
        )
        context.launchd.keepObservationAfterBootout = true

        XCTAssertThrowsError(try context.transaction().apply()) {
            guard case .operationFailed = $0 as? ServiceTransactionError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertFalse(context.journalExists())
        XCTAssertEqual(context.launchd.bootstrapCount, 0)
        guard case .loaded = context.launchd.observation else {
            return XCTFail("the job state changed unexpectedly")
        }
    }

    func testFailedUpgradeAfterBootoutKeepsTheJournalForRecovery() throws {
        let previous = try ServiceTestFixtures.previousRight()
        let context = try ServiceTestContext(
            previousRight: .present(previous),
            previousJob: ServiceTestFixtures.loaded
        )
        context.launchd.bootstrapError = LaunchdJobError.commandFailed("injected")

        XCTAssertThrowsError(try context.transaction().apply()) {
            guard case .recoveryRequired = $0 as? ServiceTransactionError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertTrue(context.journalExists())
        XCTAssertEqual(try context.journal()?.phase, .rightReplaced)
        guard case .present(let stored) = context.rightStore.observation else {
            return XCTFail("the previous right was not restored")
        }
        XCTAssertEqual(stored.policy, previous.policy)
        guard case .absent = context.launchd.observation else {
            return XCTFail("the booted-out job is still loaded")
        }

        let journalID = try XCTUnwrap(context.journal()?.transactionID)
        let recovery = try context.transaction().recover()
        XCTAssertEqual(recovery, .finishedInstall(transactionID: journalID))
        XCTAssertFalse(context.journalExists())
        guard case .loaded = context.launchd.observation else {
            return XCTFail("recovery did not bootstrap the job")
        }
    }

    func testSamePolicyUpgradeRecoveryFromPreparingRefreshesTheRightAndBootsOutThePreviousJob() throws {
        let previous = try ServiceTestFixtures.samePolicyRightWithAuthdMetadata()
        let installed = try ServiceTestFixtures.installedRight()
        XCTAssertEqual(previous.policy, installed.policy)
        XCTAssertNotEqual(previous.plist, installed.plist)
        let context = try ServiceTestContext(
            previousRight: .present(previous),
            previousJob: ServiceTestFixtures.loaded
        )
        XCTAssertThrowsError(
            try context.transaction(faults: ServiceFaultAt(.journalPrepared)).apply()
        ) {
            XCTAssertEqual($0 as? ServiceTransactionError, .simulatedCrash(.journalPrepared))
        }
        XCTAssertEqual(try context.journal()?.phase, .preparing)
        XCTAssertEqual(context.launchd.bootoutCount, 0)
        XCTAssertEqual(context.rightStore.writes.count, 0)

        let journalID = try XCTUnwrap(context.journal()?.transactionID)
        let recovery = try context.transaction().recover()
        XCTAssertEqual(recovery, .finishedInstall(transactionID: journalID))
        XCTAssertFalse(context.journalExists())
        XCTAssertEqual(context.launchd.bootoutCount, 1)
        XCTAssertEqual(context.launchd.bootstrapCount, 1)
        // The previous policy is identical, but recovery must still write the
        // packaged definition before bootstrap instead of retaining old authd
        // metadata.
        XCTAssertEqual(context.rightStore.writes, [try context.installedRightData()])
        guard case .present(let stored) = context.rightStore.observation else {
            return XCTFail("the installed start right is absent")
        }
        XCTAssertEqual(stored.policy, installed.policy)
        guard case .loaded = context.launchd.observation else {
            return XCTFail("the launch daemon job is not loaded")
        }

        let again = try context.transaction().recover()
        XCTAssertEqual(again, .nothingToRecover)
        XCTAssertEqual(context.launchd.bootoutCount, 1)
        XCTAssertEqual(context.launchd.bootstrapCount, 1)
        XCTAssertEqual(context.rightStore.writes.count, 1)
    }

    func testSamePolicyForwardRecoveryRewritesAnExactPreviousBackupAfterRightReplaced() throws {
        let previous = try ServiceTestFixtures.samePolicyRightWithAuthdMetadata()
        let installed = try ServiceTestFixtures.installedRight()
        XCTAssertEqual(previous.policy, installed.policy)
        XCTAssertNotEqual(previous.plist, installed.plist)
        let context = try ServiceTestContext(
            previousRight: .present(previous),
            previousJob: .absent
        )
        XCTAssertThrowsError(
            try context.transaction(faults: ServiceFaultAt(.journalPrepared)).apply()
        )
        XCTAssertEqual(try context.journal()?.phase, .preparing)
        XCTAssertEqual(context.rightStore.writes.count, 0)

        // This is the record an earlier same-policy recovery could leave after
        // it treated the identical policy as installed and skipped the write.
        // The stored bytes are still exactly the previous backup.
        let store = ServiceJournalStore(tree: context.tree)
        let journal = try XCTUnwrap(try store.read())
        try store.write(journal.withPhase(.rightReplaced))

        let recovery = try context.transaction().recover()
        XCTAssertEqual(recovery, .finishedInstall(transactionID: journal.transactionID))
        XCTAssertFalse(context.journalExists())
        XCTAssertEqual(context.rightStore.writes, [try context.installedRightData()])
        XCTAssertEqual(context.launchd.bootstrapCount, 1)
        XCTAssertEqual(context.launchd.bootoutCount, 0)
        guard case .present(let stored) = context.rightStore.observation else {
            return XCTFail("the installed start right is absent")
        }
        XCTAssertEqual(stored.policy, installed.policy)
        XCTAssertNotEqual(stored.plist, previous.plist)
    }

    func testSamePolicyUpgradeRecoveryIsIdempotentAfterADurableBootstrap() throws {
        let previous = try ServiceTestFixtures.samePolicyRightWithAuthdMetadata()
        let context = try ServiceTestContext(
            previousRight: .present(previous),
            previousJob: ServiceTestFixtures.loaded
        )
        XCTAssertThrowsError(
            try context.transaction(faults: ServiceFaultAt(.journalPrepared)).apply()
        )
        XCTAssertThrowsError(
            try context.transaction(faults: ServiceFaultAt(.recoveryBootstrapCompleted)).recover()
        ) {
            XCTAssertEqual(
                $0 as? ServiceTransactionError,
                .simulatedCrash(.recoveryBootstrapCompleted)
            )
        }
        XCTAssertEqual(try context.journal()?.phase, .jobBootstrapped)
        XCTAssertEqual(context.launchd.bootoutCount, 1)
        XCTAssertEqual(context.launchd.bootstrapCount, 1)
        XCTAssertEqual(context.rightStore.writes.count, 1)

        let journalID = try XCTUnwrap(context.journal()?.transactionID)
        let recovery = try context.transaction().recover()
        XCTAssertEqual(recovery, .finishedInstall(transactionID: journalID))
        XCTAssertFalse(context.journalExists())
        XCTAssertEqual(context.launchd.bootoutCount, 1)
        XCTAssertEqual(context.launchd.bootstrapCount, 1)
        XCTAssertEqual(context.rightStore.writes.count, 1)
        guard case .loaded = context.launchd.observation else {
            return XCTFail("the launch daemon job is not loaded")
        }
    }

    func testSamePolicyTerminalRollbackRecoveryRemovesOnlyTheJournal() throws {
        let previous = try ServiceTestFixtures.samePolicyRightWithAuthdMetadata()
        let installed = try ServiceTestFixtures.installedRight()
        XCTAssertEqual(previous.policy, installed.policy)
        XCTAssertNotEqual(previous.plist, installed.plist)
        let context = try ServiceTestContext(previousRight: .present(previous))
        context.launchd.bootstrapError = LaunchdJobError.commandFailed("injected")

        XCTAssertThrowsError(
            try context.transaction(faults: ServiceFaultAt(.rollbackJournalWritten)).apply()
        ) {
            guard case .recoveryRequired = $0 as? ServiceTransactionError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertEqual(try context.journal()?.phase, .rolledBack)
        XCTAssertEqual(context.launchd.bootstrapCount, 1)
        XCTAssertEqual(context.launchd.bootoutCount, 0)
        XCTAssertEqual(context.rightStore.writes.count, 1)

        let journalID = try XCTUnwrap(context.journal()?.transactionID)
        let recovery = try context.transaction().recover()
        XCTAssertEqual(
            recovery,
            .finishedRollback(transactionID: journalID, rightMetadataChanged: true)
        )
        XCTAssertFalse(context.journalExists())
        XCTAssertEqual(context.launchd.bootstrapCount, 1)
        XCTAssertEqual(context.launchd.bootoutCount, 0)
        XCTAssertEqual(context.rightStore.writes.count, 1)
        guard case .present(let stored) = context.rightStore.observation else {
            return XCTFail("the previous start right is absent")
        }
        XCTAssertEqual(stored.policy, previous.policy)
        XCTAssertNotEqual(stored.plist, previous.plist)
    }

    func testSamePolicyTerminalRollbackWithALoadedPreviousJobRemovesOnlyTheJournal() throws {
        let previous = try ServiceTestFixtures.samePolicyRightWithAuthdMetadata()
        let context = try ServiceTestContext(
            previousRight: .present(previous),
            previousJob: ServiceTestFixtures.loaded
        )
        context.launchd.bootoutError = LaunchdJobError.commandFailed("injected")

        XCTAssertThrowsError(
            try context.transaction(faults: ServiceFaultAt(.rollbackJournalWritten)).apply()
        ) {
            guard case .recoveryRequired = $0 as? ServiceTransactionError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertEqual(try context.journal()?.phase, .rolledBack)
        XCTAssertTrue(try XCTUnwrap(context.journal()).previousJobLoaded)
        XCTAssertEqual(context.launchd.bootoutCount, 1)
        XCTAssertEqual(context.launchd.bootstrapCount, 0)
        XCTAssertEqual(context.rightStore.writes.count, 0)
        guard case .loaded = context.launchd.observation else {
            return XCTFail("the previous job is not loaded")
        }

        let journalID = try XCTUnwrap(context.journal()?.transactionID)
        let recovery = try context.transaction().recover()
        XCTAssertEqual(
            recovery,
            .finishedRollback(transactionID: journalID, rightMetadataChanged: false)
        )
        XCTAssertFalse(context.journalExists())
        XCTAssertEqual(context.launchd.bootoutCount, 1)
        XCTAssertEqual(context.launchd.bootstrapCount, 0)
        XCTAssertEqual(context.rightStore.writes.count, 0)
        guard case .loaded = context.launchd.observation else {
            return XCTFail("recovery removed the previous job")
        }
    }

    func testSamePolicyInterruptedRollbackDoesNotInstallOrBootstrap() throws {
        let previous = try ServiceTestFixtures.samePolicyRightWithAuthdMetadata()
        let context = try ServiceTestContext(
            previousRight: .present(previous),
            previousJob: ServiceTestFixtures.loaded
        )
        context.launchd.bootoutError = LaunchdJobError.commandFailed("injected")

        XCTAssertThrowsError(
            try context.transaction(faults: ServiceFaultAt(.rollbackStartJournalWritten)).apply()
        ) {
            guard case .recoveryRequired = $0 as? ServiceTransactionError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertEqual(try context.journal()?.phase, .rollbackStarted)
        XCTAssertEqual(context.launchd.bootoutCount, 1)
        XCTAssertEqual(context.launchd.bootstrapCount, 0)
        XCTAssertEqual(context.rightStore.writes.count, 0)
        guard case .present(let storedBeforeRecovery) = context.rightStore.observation else {
            return XCTFail("the previous start right is absent before recovery")
        }
        XCTAssertEqual(storedBeforeRecovery.policy, previous.policy)

        let journalID = try XCTUnwrap(context.journal()?.transactionID)
        let recovery = try context.transaction().recover()
        XCTAssertEqual(
            recovery,
            .finishedRollback(transactionID: journalID, rightMetadataChanged: false)
        )
        XCTAssertFalse(context.journalExists())
        XCTAssertEqual(context.launchd.bootoutCount, 1)
        XCTAssertEqual(context.launchd.bootstrapCount, 0)
        XCTAssertEqual(context.rightStore.writes.count, 0)
        XCTAssertEqual(context.rightStore.removeCount, 0)
        guard case .present(let stored) = context.rightStore.observation else {
            return XCTFail("recovery removed the previous start right")
        }
        XCTAssertEqual(stored.plist, previous.plist)

        XCTAssertEqual(try context.transaction().recover(), .nothingToRecover)
        XCTAssertEqual(context.launchd.bootstrapCount, 0)
        XCTAssertEqual(context.rightStore.writes.count, 0)
    }

    func testSamePolicyRollbackStartedDoesNotAttributeALoadedJobWhenThePreviousJobWasAbsent() throws {
        let previous = try ServiceTestFixtures.samePolicyRightWithAuthdMetadata()
        let context = try ServiceTestContext(
            previousRight: .present(previous),
            previousJob: .absent
        )
        XCTAssertThrowsError(
            try context.transaction(faults: ServiceFaultAt(.journalPrepared)).apply()
        )
        let store = ServiceJournalStore(tree: context.tree)
        let journal = try XCTUnwrap(try store.read())
        XCTAssertFalse(journal.previousJobLoaded)
        try store.write(journal.withPhase(.rollbackStarted))

        context.launchd.observation = ServiceTestFixtures.loaded
        XCTAssertThrowsError(try context.transaction().recover()) {
            guard case .recoveryRequired = $0 as? ServiceTransactionError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertTrue(context.journalExists())
        XCTAssertEqual(try context.journal()?.phase, .rollbackStarted)
        XCTAssertEqual(context.launchd.bootoutCount, 0)
        XCTAssertEqual(context.launchd.bootstrapCount, 0)
        XCTAssertEqual(context.rightStore.writes.count, 0)
        guard case .loaded = context.launchd.observation else {
            return XCTFail("recovery booted out a job it could not attribute")
        }
    }

    func testAJobThatAppearsBeforeBootstrapIsNotAttributed() throws {
        let context = try ServiceTestContext()
        context.launchd.observationQueue = [.absent, ServiceTestFixtures.loaded]
        context.launchd.observation = ServiceTestFixtures.loaded

        XCTAssertThrowsError(try context.transaction().apply()) {
            guard case .recoveryRequired = $0 as? ServiceTransactionError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertTrue(context.journalExists())
        XCTAssertEqual(context.launchd.bootstrapCount, 0)
        XCTAssertEqual(context.launchd.bootoutCount, 0)
        guard case .loaded = context.launchd.observation else {
            return XCTFail("the unexpected job was removed")
        }

        XCTAssertThrowsError(try context.transaction().recover()) {
            guard case .recoveryRequired = $0 as? ServiceTransactionError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertEqual(context.launchd.bootoutCount, 0)
    }

    func testBootstrapFailureWithALoadedJobIsNotAttributedToThisTransaction() throws {
        let context = try ServiceTestContext()
        context.launchd.bootstrapError = LaunchdJobError.commandFailed("injected")
        context.launchd.observationAfterFailedBootstrap = ServiceTestFixtures.loaded

        XCTAssertThrowsError(try context.transaction().apply()) {
            guard case .recoveryRequired = $0 as? ServiceTransactionError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertTrue(context.journalExists())
        XCTAssertEqual(try context.journal()?.phase, .rightReplaced)
        XCTAssertEqual(context.launchd.bootoutCount, 0)
        guard case .loaded = context.launchd.observation else {
            return XCTFail("the unexpected loaded job was removed")
        }

        XCTAssertThrowsError(try context.transaction().recover()) {
            guard case .recoveryRequired = $0 as? ServiceTransactionError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertTrue(context.journalExists())
        XCTAssertEqual(context.launchd.bootoutCount, 0)
        guard case .loaded = context.launchd.observation else {
            return XCTFail("recovery booted out a job it could not attribute")
        }
    }

    func testFaultAtEveryInstallStepRecoversOrFailsClosed() throws {
        for step in ServiceTransactionStep.installFaultPoints {
            let previous = try ServiceTestFixtures.previousRight()
            let context = try ServiceTestContext(
                previousRight: .present(previous),
                previousJob: ServiceTestFixtures.loaded
            )
            XCTAssertThrowsError(
                try context.transaction(faults: ServiceFaultAt(step)).apply(),
                step.rawValue
            ) {
                XCTAssertEqual($0 as? ServiceTransactionError, .simulatedCrash(step), step.rawValue)
            }

            if step == .bootstrapCompleted {
                XCTAssertTrue(context.journalExists(), step.rawValue)
                XCTAssertThrowsError(try context.transaction().recover(), step.rawValue) {
                    guard case .recoveryRequired = $0 as? ServiceTransactionError else {
                        return XCTFail("\(step.rawValue): \($0)")
                    }
                }
                XCTAssertTrue(context.journalExists(), step.rawValue)
                XCTAssertEqual(context.launchd.bootoutCount, 1, step.rawValue)
                continue
            }

            let recovery = try context.transaction().recover()
            if step == .journalRemoved {
                XCTAssertEqual(recovery, .nothingToRecover, step.rawValue)
            } else if step == .commitJournalWritten {
                guard case .finishedCommit = recovery else {
                    return XCTFail("\(step.rawValue): \(recovery)")
                }
            } else {
                guard case .finishedInstall = recovery else {
                    return XCTFail("\(step.rawValue): \(recovery)")
                }
            }
            XCTAssertFalse(context.journalExists(), step.rawValue)
            guard case .present(let stored) = context.rightStore.observation else {
                return XCTFail("\(step.rawValue): the start right is absent")
            }
            let expectedPolicy = try context.installedRightPolicy()
            XCTAssertEqual(stored.policy, expectedPolicy, step.rawValue)
            guard case .loaded = context.launchd.observation else {
                return XCTFail("\(step.rawValue): the launch daemon job is not loaded")
            }
        }
    }

    func testCrashDuringRecoveryIsIdempotent() throws {
        let previous = try ServiceTestFixtures.previousRight()
        let context = try ServiceTestContext(
            previousRight: .present(previous),
            previousJob: ServiceTestFixtures.loaded
        )
        XCTAssertThrowsError(
            try context.transaction(faults: ServiceFaultAt(.rightWriteCompleted)).apply()
        )
        XCTAssertTrue(context.journalExists())
        XCTAssertEqual(try context.journal()?.phase, .jobBootedOut)

        XCTAssertThrowsError(
            try context.transaction(faults: ServiceFaultAt(.recoveryBootstrapCompleted)).recover()
        ) {
            XCTAssertEqual($0 as? ServiceTransactionError, .simulatedCrash(.recoveryBootstrapCompleted))
        }
        XCTAssertTrue(context.journalExists())
        XCTAssertEqual(try context.journal()?.phase, .jobBootstrapped)

        let second = try context.transaction().recover()
        guard case .finishedInstall = second else { return XCTFail("\(second)") }
        XCTAssertFalse(context.journalExists())
        guard case .loaded = context.launchd.observation else {
            return XCTFail("the launch daemon job is not loaded")
        }
    }

    func testFaultAtEveryRecoveryStepIsIdempotent() throws {
        let recoverySteps: [ServiceTransactionStep] = [
            .recoveryRightObserved,
            .recoveryBootoutCompleted,
            .recoveryRightWritten,
            .recoveryBootstrapCompleted,
            .recoveryCommitJournalWritten,
            .recoveryJournalRemoved,
        ]
        for step in recoverySteps {
            let previous = try ServiceTestFixtures.previousRight()
            let context = try ServiceTestContext(
                previousRight: .present(previous),
                previousJob: ServiceTestFixtures.loaded
            )
            XCTAssertThrowsError(
                try context.transaction(faults: ServiceFaultAt(.journalPrepared)).apply(),
                step.rawValue
            )
            XCTAssertThrowsError(
                try context.transaction(faults: ServiceFaultAt(step)).recover(),
                step.rawValue
            ) {
                XCTAssertEqual(
                    $0 as? ServiceTransactionError,
                    .simulatedCrash(step),
                    step.rawValue
                )
            }
            if step == .recoveryJournalRemoved {
                XCTAssertFalse(context.journalExists(), step.rawValue)
            } else {
                XCTAssertTrue(context.journalExists(), step.rawValue)
            }

            let second = try context.transaction().recover()
            if step == .recoveryJournalRemoved {
                XCTAssertEqual(second, .nothingToRecover, step.rawValue)
            } else if step == .recoveryCommitJournalWritten {
                guard case .finishedCommit = second else {
                    return XCTFail("\(step.rawValue): \(second)")
                }
            } else {
                guard case .finishedInstall = second else {
                    return XCTFail("\(step.rawValue): \(second)")
                }
            }
            XCTAssertFalse(context.journalExists(), step.rawValue)
            let expected = try context.installedRightPolicy()
            guard case .present(let stored) = context.rightStore.observation else {
                return XCTFail("\(step.rawValue): the start right is absent")
            }
            XCTAssertEqual(stored.policy, expected, step.rawValue)
            guard case .loaded = context.launchd.observation else {
                return XCTFail("\(step.rawValue): the launch daemon job is not loaded")
            }
        }
    }

    func testUnsafePreviousRightIsRefusedBeforeAnyChange() throws {
        let context = try ServiceTestContext()
        context.rightStore.observeError = AuthorizationRightPolicyError.unsafeDefinition

        XCTAssertThrowsError(try context.transaction().apply()) {
            guard case .authorizationRightUnsafe = $0 as? ServiceTransactionError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertFalse(context.journalExists())
        XCTAssertEqual(context.rightStore.writes.count, 0)
        XCTAssertEqual(context.launchd.bootoutCount, 0)
        XCTAssertEqual(context.launchd.bootstrapCount, 0)
    }

    func testUnexpectedLoadedJobIsRefusedBeforeAnyChange() throws {
        let context = try ServiceTestContext(previousJob: .unexpected("another program"))
        XCTAssertThrowsError(try context.transaction().apply()) {
            guard case .launchdJobUnexpected = $0 as? ServiceTransactionError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertFalse(context.journalExists())
        XCTAssertEqual(context.launchd.bootoutCount, 0)
        XCTAssertEqual(context.rightStore.writes.count, 0)
    }

    func testParticipantStateRefusalsHappenBeforeTheServiceJournal() throws {
        for (name, data) in [
            (InstallLockLayout.cleanupMarkerName, Data("blocked\n".utf8)),
            (InstallLockLayout.launchIntentName, Data("intent\n".utf8)),
            (InstallLockLayout.startJournalName, Data("not a journal\n".utf8)),
        ] {
            let context = try ServiceTestContext()
            try context.fixture.writeState(name, data)
            XCTAssertThrowsError(try context.transaction().apply(), name) {
                guard case .participantStateUnclean = $0 as? ServiceTransactionError else {
                    return XCTFail("\(name): \($0)")
                }
            }
            XCTAssertFalse(context.journalExists(), name)
            XCTAssertEqual(context.launchd.bootstrapCount, 0, name)
        }
    }

    func testPresentServiceJournalRefusesASecondApply() throws {
        let context = try ServiceTestContext()
        XCTAssertThrowsError(
            try context.transaction(faults: ServiceFaultAt(.journalPrepared)).apply()
        )
        XCTAssertTrue(context.journalExists())
        XCTAssertThrowsError(try context.transaction().apply()) {
            XCTAssertEqual($0 as? ServiceTransactionError, .serviceJournalPresent)
        }
        XCTAssertTrue(context.journalExists())
    }

    func testLiveRuntimeIsRefusedWhileInstallationIsNotApproved() throws {
        let context = try ServiceTestContext()
        XCTAssertFalse(CoordinatorPolicy.liveInstallationApproved)
        XCTAssertThrowsError(
            try PrivilegedServiceTransaction(
                tree: context.tree,
                runtime: SystemPrivilegedServiceRuntime()
            )
        ) {
            #if HOTSPOTSHADE_LOCAL_PREVIEW && HOTSPOTSHADE_SYSTEM_PREVIEW_CANDIDATE
            XCTAssertEqual($0 as? ServiceTransactionError, .requiresRoot)
            #else
            XCTAssertEqual($0 as? ServiceTransactionError, .notApproved)
            #endif
        }
        XCTAssertFalse(context.journalExists())
    }

    func testFailureAfterTheCommitRecordDoesNotRollBack() throws {
        let previous = try ServiceTestFixtures.previousRight()
        let context = try ServiceTestContext(
            previousRight: .present(previous),
            previousJob: ServiceTestFixtures.loaded
        )
        struct FailingFault: ServiceTransactionFaultInjecting {
            let step: ServiceTransactionStep
            func check(_ candidate: ServiceTransactionStep) throws {
                if candidate == step {
                    throw ServiceTransactionError.commandFailed("injected after commit")
                }
            }
        }
        XCTAssertThrowsError(
            try context.transaction(faults: FailingFault(step: .commitJournalWritten)).apply()
        ) {
            guard case .recoveryRequired = $0 as? ServiceTransactionError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertTrue(context.journalExists())
        XCTAssertEqual(try context.journal()?.phase, .committed)
        XCTAssertEqual(context.launchd.bootoutCount, 1)
        XCTAssertEqual(context.launchd.bootstrapCount, 1)
        let expected = try context.installedRightPolicy()
        guard case .present(let stored) = context.rightStore.observation else {
            return XCTFail("the committed start right is absent")
        }
        XCTAssertEqual(stored.policy, expected)
        guard case .loaded = context.launchd.observation else {
            return XCTFail("the committed launch daemon job is not loaded")
        }

        let recovery = try context.transaction().recover()
        guard case .finishedCommit = recovery else { return XCTFail("\(recovery)") }
        XCTAssertFalse(context.journalExists())
    }

    func testInstallTransactionIdentifierIsBoundedAndRecorded() throws {
        let context = try ServiceTestContext()
        XCTAssertThrowsError(
            try context.transaction().apply(installTransactionID: "not-hex")
        ) {
            XCTAssertEqual($0 as? ServiceTransactionError, .invalidInstallTransactionID)
        }
        XCTAssertFalse(context.journalExists())
        XCTAssertEqual(context.rightStore.writes.count, 0)

        let identifier = String(repeating: "d", count: 32)
        XCTAssertThrowsError(
            try context.transaction(faults: ServiceFaultAt(.journalPrepared))
                .apply(installTransactionID: identifier)
        )
        XCTAssertEqual(try context.journal()?.installTransactionID, identifier)
    }

    func testALeaseFromAnotherStateDirectoryIsRefused() throws {
        let context = try ServiceTestContext()
        let other = try Workspace()
        let otherState = other.path("state")
        try FileManager.default.createDirectory(
            atPath: otherState,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let lease = try InstallExclusionLease.acquire(
            parentDirectory: otherState,
            expectedOwner: UInt32(geteuid())
        )
        defer { lease.release() }

        XCTAssertThrowsError(try context.transaction().apply(using: lease)) {
            XCTAssertEqual($0 as? ServiceTransactionError, .lockUnavailable)
        }
        XCTAssertFalse(context.journalExists())
        XCTAssertEqual(context.rightStore.writes.count, 0)
        XCTAssertEqual(context.launchd.bootstrapCount, 0)
    }

    func testAnExistingExclusionLeaseIsUsedAndNotReleased() throws {
        let context = try ServiceTestContext()
        let statePath = context.fixture.sandbox
            + "/" + PrivilegedServiceLayout.stateDirectoryRelative
        let lease = try InstallExclusionLease.acquire(
            parentDirectory: statePath,
            expectedOwner: UInt32(geteuid())
        )
        defer { lease.release() }
        _ = try context.transaction().apply(using: lease)
        XCTAssertTrue(lease.locks.allSatisfy { $0.isHeld })
        XCTAssertFalse(context.journalExists())
    }

    func testInstalledExecutableSignaturesAreRevalidated() throws {
        let context = try ServiceTestContext()
        try context.fixture.writeTarget(
            PrivilegedServiceLayout.helperRelative,
            fakeMachO(tag: "unknown-helper", padding: 999),
            mode: 0o755
        )
        XCTAssertThrowsError(try context.transaction().apply()) {
            guard case .installedFileUnsafe = $0 as? ServiceTransactionError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertFalse(context.journalExists())
        XCTAssertEqual(context.rightStore.writes.count, 0)
        XCTAssertEqual(context.launchd.bootstrapCount, 0)
    }

    func testAStateTreeCanUseTheResolvedPrivateVarPath() throws {
        let context = try ServiceTestContext()
        try context.fixture.makeDirectory("private", mode: 0o755)
        try context.fixture.makeDirectory("private/var", mode: 0o755)
        try context.fixture.makeDirectory("private/var/db", mode: 0o755)
        try context.fixture.makeDirectory(
            "private/var/db/hotspotshade",
            mode: 0o700
        )
        let privateRoot = context.fixture.sandbox + "/private"
        let stateTree = try InstallTree(
            rootPath: privateRoot,
            expectedOwner: UInt32(geteuid())
        )
        let transaction = try context.transaction(stateTree: stateTree)
        _ = try transaction.apply()

        let privateJournal = privateRoot
            + "/" + PrivilegedServiceLayout.stateDirectoryRelative
            + "/" + ServiceJournalStore.fileName
        let oldJournal = context.fixture.sandbox
            + "/" + PrivilegedServiceLayout.stateDirectoryRelative
            + "/" + ServiceJournalStore.fileName
        XCTAssertFalse(FileManager.default.fileExists(atPath: privateJournal))
        XCTAssertFalse(FileManager.default.fileExists(atPath: oldJournal))
        XCTAssertTrue(
            FileManager.default.fileExists(
                atPath: privateRoot + "/" + PrivilegedServiceLayout.stateDirectoryRelative
            )
        )
    }

    func testApprovalAndPreinstallGateRemainClosed() {
        XCTAssertFalse(CoordinatorPolicy.liveInstallationApproved)
        XCTAssertFalse(InstallerScripts.installationApproved)
        XCTAssertTrue(
            InstallerScripts.preinstall.contains(
                "this package is a build-only foundation and is not approved for installation"
            )
        )
    }

    func testRecoveryRefusesAJobThatAppearsImmediatelyBeforeBootstrap() throws {
        let context = try ServiceTestContext()
        XCTAssertThrowsError(
            try context.transaction(faults: ServiceFaultAt(.rightJournalWritten)).apply()
        )
        XCTAssertEqual(try context.journal()?.phase, .rightReplaced)

        // The first observation is absent. The job appears after the right
        // phase is durable and immediately before the bootstrap.
        context.launchd.observationQueue = [.absent, ServiceTestFixtures.loaded]
        context.launchd.observation = ServiceTestFixtures.loaded

        XCTAssertThrowsError(try context.transaction().recover()) {
            guard case .recoveryRequired = $0 as? ServiceTransactionError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertEqual(context.launchd.bootstrapCount, 0)
        XCTAssertEqual(context.launchd.bootoutCount, 0)
        XCTAssertTrue(context.journalExists())
        XCTAssertEqual(try context.journal()?.phase, .rightReplaced)
    }

    func testRecoveryDoesNotAttributeALoadedJobToAFailedBootstrap() throws {
        let context = try ServiceTestContext()
        XCTAssertThrowsError(
            try context.transaction(faults: ServiceFaultAt(.rightJournalWritten)).apply()
        )
        context.launchd.bootstrapError = LaunchdJobError.commandFailed("injected")
        context.launchd.observationAfterFailedBootstrap = ServiceTestFixtures.loaded
        context.launchd.observationQueue = [.absent, .absent]

        XCTAssertThrowsError(try context.transaction().recover()) {
            guard case .recoveryRequired = $0 as? ServiceTransactionError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertTrue(context.journalExists())
        XCTAssertEqual(try context.journal()?.phase, .rightReplaced)
        XCTAssertEqual(context.launchd.bootstrapCount, 1)
        XCTAssertEqual(context.launchd.bootoutCount, 0)
        guard case .loaded = context.launchd.observation else {
            return XCTFail("the unexpected loaded job was removed")
        }
    }

    func testRecoveryFaultsAfterASuccessfulBootstrapBeforeItsJournalRecord() throws {
        let context = try ServiceTestContext()
        XCTAssertThrowsError(
            try context.transaction(faults: ServiceFaultAt(.rightJournalWritten)).apply()
        )
        XCTAssertThrowsError(
            try context.transaction(faults: ServiceFaultAt(.recoveryBootstrapSucceeded)).recover()
        ) {
            XCTAssertEqual(
                $0 as? ServiceTransactionError,
                .simulatedCrash(.recoveryBootstrapSucceeded)
            )
        }
        XCTAssertTrue(context.journalExists())
        XCTAssertEqual(try context.journal()?.phase, .rightReplaced)
        XCTAssertEqual(context.launchd.bootstrapCount, 1)

        // The loaded job is in the same unproven window as a crashed install.
        // Recovery must not claim it or boot it out.
        XCTAssertThrowsError(try context.transaction().recover()) {
            guard case .recoveryRequired = $0 as? ServiceTransactionError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertEqual(context.launchd.bootoutCount, 0)
        XCTAssertTrue(context.journalExists())
        XCTAssertEqual(try context.journal()?.phase, .rightReplaced)
    }

    func testRecoveryKeepsTheJournalWhenTheLaunchDaemonChangesBeforeBootstrap() throws {
        let context = try ServiceTestContext()
        XCTAssertThrowsError(
            try context.transaction(faults: ServiceFaultAt(.journalPrepared)).apply()
        ) {
            XCTAssertEqual($0 as? ServiceTransactionError, .simulatedCrash(.journalPrepared))
        }
        XCTAssertEqual(try context.journal()?.phase, .preparing)

        // Recovery has already read and validated the installed inputs. Change
        // the daemon after the right record is durable but before bootstrap,
        // which is past the point where the journal can be discarded safely.
        let changed = Data("changed after the journal\n".utf8)
        let fault = ServiceFaultAction(.recoveryRightWritten) {
            try context.fixture.writeTarget(
                PrivilegedServiceLayout.launchDaemonRelative,
                changed,
                mode: 0o644
            )
        }
        XCTAssertThrowsError(try context.transaction(faults: fault).recover()) {
            guard case .recoveryRequired = $0 as? ServiceTransactionError else {
                return XCTFail("\($0)")
            }
        }

        XCTAssertTrue(context.journalExists())
        XCTAssertEqual(try context.journal()?.phase, .rightReplaced)
        XCTAssertEqual(context.rightStore.writes.count, 1)
        XCTAssertEqual(context.launchd.bootoutCount, 0)
        XCTAssertEqual(context.launchd.bootstrapCount, 0)
    }

    func testCompletedRollbackWhoseJournalRemovalFailsIsNotReinstalled() throws {
        let context = try ServiceTestContext()
        context.rightStore.nextWriteObservation = .absent

        XCTAssertThrowsError(
            try context.transaction(faults: ServiceFaultAt(.rollbackJournalWritten)).apply()
        ) {
            guard case .recoveryRequired = $0 as? ServiceTransactionError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertTrue(context.journalExists())
        XCTAssertEqual(try context.journal()?.phase, .rolledBack)
        XCTAssertEqual(context.rightStore.writes.count, 1)
        XCTAssertEqual(context.launchd.bootstrapCount, 0)
        XCTAssertEqual(context.launchd.bootoutCount, 0)
        guard case .absent = context.rightStore.observation else {
            return XCTFail("the rollback did not leave the previous absent right")
        }

        let journalID = try XCTUnwrap(context.journal()?.transactionID)
        let recovery = try context.transaction().recover()
        XCTAssertEqual(
            recovery,
            .finishedRollback(transactionID: journalID, rightMetadataChanged: false)
        )
        XCTAssertFalse(context.journalExists())
        XCTAssertEqual(context.rightStore.writes.count, 1)
        XCTAssertEqual(context.launchd.bootstrapCount, 0)
        guard case .absent = context.rightStore.observation else {
            return XCTFail("recovery installed a right after a completed rollback")
        }
    }

    func testRecoveryReportsAnInexactCompletedRollback() throws {
        let previous = try ServiceTestFixtures.previousRight()
        let context = try ServiceTestContext(previousRight: .present(previous))
        context.rightStore.addMetadataOnWrite = true
        context.launchd.bootstrapError = LaunchdJobError.commandFailed("injected")

        XCTAssertThrowsError(
            try context.transaction(faults: ServiceFaultAt(.rollbackJournalWritten)).apply()
        ) {
            guard case .recoveryRequired = $0 as? ServiceTransactionError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertEqual(try context.journal()?.phase, .rolledBack)
        let journalID = try XCTUnwrap(context.journal()?.transactionID)

        let recovery = try context.transaction().recover()
        XCTAssertEqual(
            recovery,
            .finishedRollback(transactionID: journalID, rightMetadataChanged: true)
        )
        XCTAssertFalse(context.journalExists())
        XCTAssertEqual(context.launchd.bootoutCount, 0)
        guard case .present(let stored) = context.rightStore.observation else {
            return XCTFail("the previous start right is absent")
        }
        XCTAssertEqual(stored.policy, previous.policy)
        XCTAssertNotEqual(stored.plist, previous.plist)
    }

    func testTerminalRollbackRecoveryRefusesAChangedPreviousState() throws {
        let context = try ServiceTestContext()
        context.rightStore.nextWriteObservation = .absent
        XCTAssertThrowsError(
            try context.transaction(faults: ServiceFaultAt(.rollbackJournalWritten)).apply()
        )
        XCTAssertEqual(try context.journal()?.phase, .rolledBack)

        let installedData = try Data(
            contentsOf: URL(
                fileURLWithPath: context.fixture.sandbox
                    + "/" + PrivilegedServiceLayout.rightSourceRelative
            )
        )
        context.rightStore.observation = .present(
            try AuthorizationRightPolicyParser.parse(installedData)
        )

        XCTAssertThrowsError(try context.transaction().recover()) {
            guard case .recoveryRequired = $0 as? ServiceTransactionError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertTrue(context.journalExists())
        XCTAssertEqual(try context.journal()?.phase, .rolledBack)
        XCTAssertEqual(context.launchd.bootstrapCount, 0)
        XCTAssertEqual(context.rightStore.writes.count, 1)
    }

    func testInexactRollbackIsReportedWhenThePreviousRightWasAlreadyPresent() throws {
        let previous = try ServiceTestFixtures.previousRight()
        let previousWithMetadata = try ServiceTestFixtures.previousRightWithAuthdMetadata()
        let context = try ServiceTestContext(previousRight: .present(previous))
        context.rightStore.nextWriteObservation = .present(previousWithMetadata)

        XCTAssertThrowsError(try context.transaction().apply()) {
            guard case .operationFailedWithInexactRightRollback =
                $0 as? ServiceTransactionError
            else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertFalse(context.journalExists())
        XCTAssertEqual(context.rightStore.writes.count, 1)
        guard case .present(let stored) = context.rightStore.observation else {
            return XCTFail("the previous start right is absent")
        }
        XCTAssertEqual(stored.policy, previous.policy)
        XCTAssertNotEqual(stored.plist, previous.plist)
    }

    func testInitialJournalWriteUncertaintyRequiresRecoveryAndKeepsTheJournal() throws {
        let context = try ServiceTestContext()
        let store = context.journalStore(failingAfter: .preparing)

        XCTAssertThrowsError(try context.transaction(journalStore: store).apply()) {
            guard case .recoveryRequired = $0 as? ServiceTransactionError else {
                return XCTFail("\($0)")
            }
        }

        // The visible preparing record may survive a power loss. No privileged
        // action ran, and the caller must keep the journal and block file
        // rollback instead of treating this as a clean failed write.
        XCTAssertTrue(context.journalExists())
        XCTAssertEqual(try context.journal()?.phase, .preparing)
        XCTAssertEqual(context.rightStore.writes.count, 0)
        XCTAssertEqual(context.launchd.bootoutCount, 0)
        XCTAssertEqual(context.launchd.bootstrapCount, 0)

        let journalID = try XCTUnwrap(context.journal()?.transactionID)
        let recovery = try context.transaction().recover()
        XCTAssertEqual(recovery, .finishedInstall(transactionID: journalID))
        XCTAssertFalse(context.journalExists())
    }

    func testPostRenameJournalSyncUncertaintyKeepsTheCommittedState() throws {
        let previous = try ServiceTestFixtures.previousRight()
        let context = try ServiceTestContext(previousRight: .present(previous))
        let store = context.journalStore(failingAfter: .committed)

        XCTAssertThrowsError(try context.transaction(journalStore: store).apply()) {
            guard case .recoveryRequired = $0 as? ServiceTransactionError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertTrue(context.journalExists())
        XCTAssertEqual(try context.journal()?.phase, .committed)
        XCTAssertEqual(context.launchd.bootstrapCount, 1)
        XCTAssertEqual(context.launchd.bootoutCount, 0)
        let expected = try context.installedRightPolicy()
        guard case .present(let stored) = context.rightStore.observation else {
            return XCTFail("the committed start right is absent")
        }
        XCTAssertEqual(stored.policy, expected)

        let recovery = try context.transaction().recover()
        guard case .finishedCommit = recovery else { return XCTFail("\(recovery)") }
        XCTAssertFalse(context.journalExists())
        XCTAssertEqual(context.launchd.bootoutCount, 0)
    }

    func testCommittedRecoveryStopsWhenJournalRemovalSyncIsUnknown() throws {
        let context = try ServiceTestContext()
        XCTAssertThrowsError(
            try context.transaction(faults: ServiceFaultAt(.commitJournalWritten)).apply()
        )
        XCTAssertEqual(try context.journal()?.phase, .committed)
        let failingTree = try InstallTree(
            rootPath: context.fixture.sandbox,
            expectedOwner: UInt32(geteuid()),
            syncHooks: failingTreeHooks(.removeAfterUnlink)
        )
        let writes = context.rightStore.writes.count
        let bootstraps = context.launchd.bootstrapCount
        let bootouts = context.launchd.bootoutCount
        XCTAssertThrowsError(
            try context.transaction(
                stateTree: failingTree,
                faults: ServiceFaultAt(.recoveryJournalRemoved)
            ).recover()
        ) {
            guard case .recoveryRequired(let reason)? = $0 as? ServiceTransactionError else {
                return XCTFail("\($0)")
            }
            XCTAssertTrue(reason.contains("sync failed"), reason)
        }
        XCTAssertFalse(context.journalExists(), "the unlink is visible but not proven durable")
        XCTAssertEqual(context.rightStore.writes.count, writes)
        XCTAssertEqual(context.launchd.bootstrapCount, bootstraps)
        XCTAssertEqual(context.launchd.bootoutCount, bootouts)
    }

    func testCommittedApplyStopsWhenJournalRemovalSyncIsUnknown() throws {
        let context = try ServiceTestContext()
        let failingTree = try InstallTree(
            rootPath: context.fixture.sandbox,
            expectedOwner: UInt32(geteuid()),
            syncHooks: failingTreeHooks(.removeAfterUnlink)
        )
        XCTAssertThrowsError(
            try context.transaction(stateTree: failingTree, faults: ServiceFaultAt(.journalRemoved)).apply()
        ) {
            guard case .recoveryRequired(let reason)? = $0 as? ServiceTransactionError else {
                return XCTFail("\($0)")
            }
            XCTAssertTrue(reason.contains("sync failed"), reason)
        }
        XCTAssertFalse(context.journalExists(), "the unlink is visible but not proven durable")
        XCTAssertEqual(context.rightStore.writes.count, 1)
        XCTAssertEqual(context.launchd.bootstrapCount, 1)
        XCTAssertEqual(context.launchd.bootoutCount, 0)
        guard case .loaded = context.launchd.observation else { return XCTFail("committed job was changed") }
    }

    func testTerminalRollbackRecoveryStopsWhenJournalRemovalSyncIsUnknown() throws {
        let previous = try ServiceTestFixtures.samePolicyRightWithAuthdMetadata()
        let context = try ServiceTestContext(previousRight: .present(previous))
        context.launchd.bootstrapError = LaunchdJobError.commandFailed("injected")
        XCTAssertThrowsError(try context.transaction(faults: ServiceFaultAt(.rollbackJournalWritten)).apply())
        XCTAssertEqual(try context.journal()?.phase, .rolledBack)
        let failingTree = try InstallTree(
            rootPath: context.fixture.sandbox,
            expectedOwner: UInt32(geteuid()),
            syncHooks: failingTreeHooks(.removeAfterUnlink)
        )
        let writes = context.rightStore.writes.count
        let bootstraps = context.launchd.bootstrapCount
        let bootouts = context.launchd.bootoutCount
        XCTAssertThrowsError(
            try context.transaction(stateTree: failingTree, faults: ServiceFaultAt(.recoveryJournalRemoved)).recover()
        ) {
            guard case .recoveryRequired(let reason)? = $0 as? ServiceTransactionError else {
                return XCTFail("\($0)")
            }
            XCTAssertTrue(reason.contains("sync failed"), reason)
        }
        XCTAssertFalse(context.journalExists(), "the unlink is visible but not proven durable")
        XCTAssertEqual(context.rightStore.writes.count, writes)
        XCTAssertEqual(context.launchd.bootstrapCount, bootstraps)
        XCTAssertEqual(context.launchd.bootoutCount, bootouts)
    }

    func testForwardRecoveryStopsWhenJournalRemovalSyncIsUnknown() throws {
        let context = try ServiceTestContext()
        XCTAssertThrowsError(try context.transaction(faults: ServiceFaultAt(.journalPrepared)).apply())
        XCTAssertEqual(try context.journal()?.phase, .preparing)
        let failingTree = try InstallTree(
            rootPath: context.fixture.sandbox,
            expectedOwner: UInt32(geteuid()),
            syncHooks: failingTreeHooks(.removeAfterUnlink)
        )
        XCTAssertThrowsError(
            try context.transaction(stateTree: failingTree, faults: ServiceFaultAt(.recoveryJournalRemoved)).recover()
        ) {
            guard case .recoveryRequired(let reason)? = $0 as? ServiceTransactionError else {
                return XCTFail("\($0)")
            }
            XCTAssertTrue(reason.contains("sync failed"), reason)
        }
        XCTAssertFalse(context.journalExists())
        XCTAssertEqual(context.rightStore.writes.count, 1)
        XCTAssertEqual(context.launchd.bootstrapCount, 1)
        XCTAssertEqual(context.launchd.bootoutCount, 0)
    }

    func testRollbackRecoveryStopsWhenJournalRemovalSyncIsUnknown() throws {
        let previous = try ServiceTestFixtures.samePolicyRightWithAuthdMetadata()
        let context = try ServiceTestContext(previousRight: .present(previous), previousJob: ServiceTestFixtures.loaded)
        context.launchd.bootoutError = LaunchdJobError.commandFailed("injected")
        XCTAssertThrowsError(try context.transaction(faults: ServiceFaultAt(.rollbackStartJournalWritten)).apply())
        XCTAssertEqual(try context.journal()?.phase, .rollbackStarted)
        let failingTree = try InstallTree(
            rootPath: context.fixture.sandbox,
            expectedOwner: UInt32(geteuid()),
            syncHooks: failingTreeHooks(.removeAfterUnlink)
        )
        let writes = context.rightStore.writes.count
        let bootstraps = context.launchd.bootstrapCount
        let bootouts = context.launchd.bootoutCount
        XCTAssertThrowsError(
            try context.transaction(stateTree: failingTree, faults: ServiceFaultAt(.recoveryJournalRemoved)).recover()
        ) {
            guard case .recoveryRequired(let reason)? = $0 as? ServiceTransactionError else {
                return XCTFail("\($0)")
            }
            XCTAssertTrue(reason.contains("sync failed"), reason)
        }
        XCTAssertFalse(context.journalExists())
        XCTAssertEqual(context.rightStore.writes.count, writes)
        XCTAssertEqual(context.launchd.bootstrapCount, bootstraps)
        XCTAssertEqual(context.launchd.bootoutCount, bootouts)
    }

    func testApplyRollbackStopsWhenJournalRemovalSyncIsUnknown() throws {
        let previous = try ServiceTestFixtures.samePolicyRightWithAuthdMetadata()
        let context = try ServiceTestContext(previousRight: .present(previous))
        context.launchd.bootstrapError = LaunchdJobError.commandFailed("injected")
        let failingTree = try InstallTree(
            rootPath: context.fixture.sandbox,
            expectedOwner: UInt32(geteuid()),
            syncHooks: failingTreeHooks(.removeAfterUnlink)
        )
        XCTAssertThrowsError(try context.transaction(stateTree: failingTree).apply()) {
            guard case .recoveryRequired(let reason)? = $0 as? ServiceTransactionError else {
                return XCTFail("\($0)")
            }
            XCTAssertTrue(reason.contains("journal cannot be removed"), reason)
        }
        XCTAssertFalse(context.journalExists())
        XCTAssertEqual(context.launchd.bootstrapCount, 1)
        XCTAssertEqual(context.launchd.bootoutCount, 0)
        guard case .present(let restored) = context.rightStore.observation else {
            return XCTFail("the previous right is absent")
        }
        XCTAssertEqual(restored.policy, previous.policy)
    }

    func testRecoveryRecordsDurablePhasesBeforeItsActions() throws {
        let previous = try ServiceTestFixtures.previousRight()
        let context = try ServiceTestContext(
            previousRight: .present(previous),
            previousJob: ServiceTestFixtures.loaded
        )
        XCTAssertThrowsError(
            try context.transaction(faults: ServiceFaultAt(.journalPrepared)).apply()
        )
        XCTAssertEqual(try context.journal()?.phase, .preparing)

        XCTAssertThrowsError(
            try context.transaction(faults: ServiceFaultAt(.recoveryBootoutCompleted)).recover()
        ) {
            XCTAssertEqual(
                $0 as? ServiceTransactionError,
                .simulatedCrash(.recoveryBootoutCompleted)
            )
        }
        XCTAssertEqual(try context.journal()?.phase, .jobBootedOut)
        XCTAssertEqual(context.launchd.bootoutCount, 1)

        XCTAssertThrowsError(
            try context.transaction(faults: ServiceFaultAt(.recoveryRightWritten)).recover()
        ) {
            XCTAssertEqual(
                $0 as? ServiceTransactionError,
                .simulatedCrash(.recoveryRightWritten)
            )
        }
        XCTAssertEqual(try context.journal()?.phase, .rightReplaced)
        let expected = try context.installedRightPolicy()
        guard case .present(let stored) = context.rightStore.observation else {
            return XCTFail("the installed start right is absent")
        }
        XCTAssertEqual(stored.policy, expected)

        let recovery = try context.transaction().recover()
        guard case .finishedInstall = recovery else { return XCTFail("\(recovery)") }
        XCTAssertFalse(context.journalExists())
        guard case .loaded = context.launchd.observation else {
            return XCTFail("the launch daemon job is not loaded")
        }
    }

    func testInstallJournalRefusesBothApplyAndRecover() throws {
        let previous = try ServiceTestFixtures.previousRight()
        let context = try ServiceTestContext(
            previousRight: .present(previous),
            previousJob: ServiceTestFixtures.loaded
        )
        let contents = Data("pending file install\n".utf8)
        try context.fixture.writeState(InstallJournalStore.fileName, contents)

        XCTAssertThrowsError(try context.transaction().apply()) {
            XCTAssertEqual($0 as? ServiceTransactionError, .installJournalPresent)
        }
        XCTAssertFalse(context.journalExists())
        XCTAssertEqual(context.rightStore.writes.count, 0)
        XCTAssertEqual(context.launchd.bootoutCount, 0)
        XCTAssertEqual(context.launchd.bootstrapCount, 0)
        XCTAssertEqual(context.fixture.readTarget(InstallJournalStore.relativePath), contents)

        XCTAssertThrowsError(try context.transaction().recover()) {
            XCTAssertEqual($0 as? ServiceTransactionError, .installJournalPresent)
        }
        XCTAssertFalse(context.journalExists())
        XCTAssertEqual(context.fixture.readTarget(InstallJournalStore.relativePath), contents)
    }

    func testRecoveryRefusesWhenTheInstalledFilesDifferFromTheJournal() throws {
        let context = try ServiceTestContext()
        XCTAssertThrowsError(
            try context.transaction(faults: ServiceFaultAt(.journalPrepared)).apply()
        )
        XCTAssertTrue(context.journalExists())
        let replacement = try ServiceTestFixtures.rightData(comment: "changed after the journal")
        try context.fixture.writeTarget(
            PrivilegedServiceLayout.rightSourceRelative,
            replacement,
            mode: 0o644
        )
        XCTAssertThrowsError(try context.transaction().recover()) {
            guard case .recoveryRequired = $0 as? ServiceTransactionError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertTrue(context.journalExists())
    }
}
