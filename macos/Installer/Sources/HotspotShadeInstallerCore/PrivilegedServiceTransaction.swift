import Foundation
import Darwin
import HotspotShadeKit

// The privileged service boundary of an install or upgrade. The file
// transaction in Coordinator.swift replaces the executable set inside the
// sandbox. This type advances the two actions that live outside a file tree:
//
//   1. boot out the old launch daemon job, write the start right, read it back,
//   2. bootstrap the new launch daemon job, read it back, and commit.
//
// It has no live mode in this build. The system runtime refuses to construct a
// transaction while CoordinatorPolicy.liveInstallationApproved is false, and
// SystemPrivilegedCommandRunner repeats the same gate before a child process.
// Every test uses an injected runtime whose isLiveSystem is false.
//
// It is structured for a future root coordinator with fixed paths: the
// installed input is read from InstallTree at the fixed relative paths, the
// service journal lives under the fixed state directory, and the command
// shapes are fixed by PrivilegedServiceCommand. The caller can pass the
// exclusive InstallExclusionLease that it already holds; otherwise this type
// acquires the same transition lock set for its own short transaction.
//
// Exact limits, stated rather than hidden:
//
// - launchd has no creator identity. If a crash happens after `bootstrap`
//   succeeds but before the `jobBootstrapped` journal record is durable,
//   recovery cannot prove that the loaded job belongs to this transaction. It
//   keeps the journal and refuses. It never boots out an unproven job.
// - authd normalizes and may merge a stored definition. A rollback restores the
//   previous definition and verifies the helper policy; byte equality is
//   reported separately and is not promised.
// - The exclusive lock excludes only processes that take it. A pre-lock helper
//   or engine, a direct start from an old binary, or an uncooperative root
//   process can still act during this transaction. Those are observations, not
//   exclusion. The initial migration of old binaries is a separate step.
public enum ServiceTransactionStep: String, CaseIterable, Equatable, Sendable {
    case journalPrepared
    case jobBootoutCompleted
    case jobBootoutJournalWritten
    case rightWriteCompleted
    case rightJournalWritten
    case bootstrapCompleted
    case bootstrapJournalWritten
    case commitJournalWritten
    case journalRemoved
    case rollbackStartJournalWritten
    case rollbackJournalWritten
    case recoveryRightObserved
    case recoveryBootoutCompleted
    case recoveryRightWritten
    // The bootstrap command succeeded and its read-back was verified, but the
    // jobBootstrapped record is not durable yet.
    case recoveryBootstrapSucceeded
    case recoveryBootstrapCompleted
    case recoveryCommitJournalWritten
    case recoveryJournalRemoved

    public static var installFaultPoints: [ServiceTransactionStep] {
        allCases.filter { step in
            switch step {
            case .rollbackStartJournalWritten, .rollbackJournalWritten,
                 .recoveryRightObserved, .recoveryBootoutCompleted, .recoveryRightWritten,
                 .recoveryBootstrapSucceeded, .recoveryBootstrapCompleted,
                 .recoveryCommitJournalWritten, .recoveryJournalRemoved:
                return false
            default:
                return true
            }
        }
    }
}

public protocol ServiceTransactionFaultInjecting: Sendable {
    func check(_ step: ServiceTransactionStep) throws
}

public struct NoServiceFaults: ServiceTransactionFaultInjecting {
    public init() {}
    public func check(_ step: ServiceTransactionStep) throws {}
}

public struct ServiceFaultAt: ServiceTransactionFaultInjecting {
    public let step: ServiceTransactionStep
    public init(_ step: ServiceTransactionStep) { self.step = step }
    public func check(_ candidate: ServiceTransactionStep) throws {
        if candidate == step { throw ServiceTransactionError.simulatedCrash(candidate) }
    }
}

public enum ServiceTransactionError: Error, Equatable, CustomStringConvertible {
    case notApproved
    case requiresRoot
    case requiresTeamIdentifier
    case invalidInstallTransactionID
    case stateDirectoryUnsafe(String)
    case installedFileUnsafe(String)
    case participantStateUnclean(String)
    case authorizationRightUnsafe(String)
    case authorizationRightUnreadable(String)
    case launchdJobUnexpected(String)
    case launchdJobUnknown(String)
    case launchdJobStillLoaded(String)
    case launchdJobNotLoaded(String)
    case bootstrapUnverified(String)
    case serviceJournalPresent
    case serviceJournalUnreadable(String)
    case serviceJournalUnsafe(String)
    // Internal mapping for an atomic journal write whose rename may have
    // happened without a durable directory entry. apply() converts this to
    // recoveryRequired before it reaches a caller: every caller must keep the
    // journal and block file rollback rather than treat the visible record as a
    // clean failure.
    case serviceJournalWriteOutcomeUnknown(String)
    // Internal mapping for a journal unlink whose parent sync failed. The
    // record may reappear after a crash, so no later removal may run.
    case serviceJournalRemoveOutcomeUnknown(String)
    case installJournalPresent
    case lockUnavailable
    case lockUnsafe(String)
    case io(String)
    case commandFailed(String)
    case rightReadbackMismatch(String)
    case operationFailed(String)
    case operationFailedWithInexactRightRollback(String)
    case recoveryRequired(String)
    case committedStateDamaged(String)
    case simulatedCrash(ServiceTransactionStep)

    public var description: String {
        switch self {
        case .notApproved:
            return "The privileged service transaction is not approved in this build."
        case .requiresRoot:
            return "A live privileged service transaction needs the root coordinator."
        case .requiresTeamIdentifier:
            return "A live privileged service transaction needs the expected Developer ID team."
        case .invalidInstallTransactionID:
            return "The file install transaction identifier is malformed."
        case .stateDirectoryUnsafe(let why):
            return "The root state directory is not safe for the service transaction: \(why)."
        case .installedFileUnsafe(let why):
            return "An installed file is not safe for the service transaction: \(why)."
        case .participantStateUnclean(let why):
            return "A start participant state is not clean: \(why)."
        case .authorizationRightUnsafe(let why):
            return "The start right is not safe for this transaction: \(why)."
        case .authorizationRightUnreadable(let why):
            return "The start right cannot be observed: \(why)."
        case .launchdJobUnexpected(let why):
            return "A launch daemon job with the fixed label is loaded but is not the installed one: \(why)."
        case .launchdJobUnknown(let why):
            return "The launch daemon job state cannot be proven: \(why)."
        case .launchdJobStillLoaded(let why):
            return "The previous launch daemon job is still loaded: \(why)."
        case .launchdJobNotLoaded(let why):
            return "The new launch daemon job is not loaded after bootstrap: \(why)."
        case .bootstrapUnverified(let why):
            return "A bootstrap command failed but a job with the fixed label is loaded, and this transaction cannot prove it created that job: \(why)."
        case .serviceJournalPresent:
            return "A service journal is present. Run service recovery before another service transaction."
        case .serviceJournalUnreadable(let why):
            return "The service journal cannot be used: \(why)."
        case .serviceJournalUnsafe(let why):
            return "The service journal is unsafe: \(why)."
        case .serviceJournalWriteOutcomeUnknown(let why):
            return "The service journal write outcome is unknown: \(why). The journal is kept, and no rollback is attempted because a durable phase cannot be proven."
        case .serviceJournalRemoveOutcomeUnknown(let why):
            return "The service journal removal outcome is unknown: \(why). No further removal is attempted."
        case .installJournalPresent:
            return "A file install journal is present. The service transaction does not run while the file transaction is unfinished; a reviewed two-journal recovery order is required."
        case .lockUnavailable:
            return "The install lock is held by a start participant or another coordinator."
        case .lockUnsafe(let why):
            return "The install lock cannot be used: \(why)."
        case .io(let why):
            return "A service transaction file operation failed: \(why)."
        case .commandFailed(let why):
            return "A privileged command failed: \(why)."
        case .rightReadbackMismatch(let why):
            return "The start right read-back does not match the installed definition: \(why)."
        case .operationFailed(let why):
            return "The service transaction failed and the previous observable state was restored: \(why)."
        case .operationFailedWithInexactRightRollback(let why):
            return "The service transaction failed. The previous start right policy was restored, but authd changed its metadata: \(why)."
        case .recoveryRequired(let why):
            return "The service transaction needs recovery: \(why). The service journal is kept."
        case .committedStateDamaged(let why):
            return "A committed service transaction no longer verifies: \(why). The service journal is kept."
        case .simulatedCrash(let step):
            return "Simulated service crash after \(step.rawValue)."
        }
    }
}

public protocol PrivilegedServiceRuntime: Sendable {
    var isLiveSystem: Bool { get }
    var authorizationRights: AuthorizationRightStoring { get }
    var launchd: LaunchdJobControlling { get }
}

public struct SystemPrivilegedServiceRuntime: PrivilegedServiceRuntime {
    public let isLiveSystem: Bool
    public let authorizationRights: AuthorizationRightStoring
    public let launchd: LaunchdJobControlling

    public init(runner: PrivilegedCommandRunning = SystemPrivilegedCommandRunner()) {
        self.isLiveSystem = runner.isLiveSystem
        self.authorizationRights = CommandAuthorizationRightDatabase(runner: runner)
        self.launchd = CommandLaunchdJobController(runner: runner)
    }
}

public struct ServiceInstallOutcome: Equatable, Sendable {
    public let transactionID: String
    public let previousRightPresent: Bool
    public let previousJobLoaded: Bool
    public let right: AuthorizationRightPolicy
    public let launchdJobLoaded: Bool
}

public enum ServiceRecoveryOutcome: Equatable, Sendable {
    case nothingToRecover
    case finishedInstall(transactionID: String)
    case finishedCommit(transactionID: String)
    // A durable rollback completed before its journal could be removed. The
    // recovery only removed the journal; it did not install. The flag reports
    // that authd changed the previous right metadata, so the restored bytes are
    // not the backed-up bytes.
    case finishedRollback(transactionID: String, rightMetadataChanged: Bool)
}

public final class PrivilegedServiceTransaction: @unchecked Sendable {
    private struct InstalledInputs {
        let right: AuthorizationRightSnapshot
        let launchDaemonSHA256: String
    }

    private struct ExecutionState {
        var bootoutAttempted = false
        var bootoutVerified = false
        var rightWriteAttempted = false
        var rightReplaced = false
        var bootstrapAttempted = false
        var bootstrapSucceeded = false
        var bootstrapAmbiguous = false
        var commitDurable = false
    }

    private struct RollbackResult {
        let completed: Bool
        let rightMetadataChanged: Bool
        let detail: String?
    }

    private struct RightRollbackResult {
        let metadataChanged: Bool
        let detail: String?

        var completed: Bool { detail == nil }
    }

    private enum RightState {
        case installed
        case previous
        // The previous and installed policies are identical, so the stored
        // definition is consistent with both states. Only the journal phase
        // can decide which meaning applies. This is not an installed state
        // during a rollback.
        case previousAndInstalled
        case previousAbsent
        case other

        var matchesInstalled: Bool {
            self == .installed || self == .previousAndInstalled
        }

        var matchesPrevious: Bool {
            self == .previous || self == .previousAndInstalled
        }
    }

    private let tree: InstallTree
    private let stateTree: InstallTree
    private let runtime: PrivilegedServiceRuntime
    private let faults: ServiceTransactionFaultInjecting
    private let validator: InstallerValidator
    private let expectedTeamIdentifier: String?
    private let journalStore: ServiceJournalStore

    public convenience init(
        tree: InstallTree,
        stateTree: InstallTree? = nil,
        runtime: PrivilegedServiceRuntime,
        faults: ServiceTransactionFaultInjecting = NoServiceFaults(),
        validator: InstallerValidator = InstallerValidator(),
        expectedTeamIdentifier: String? = nil,
        effectiveUserID: UInt32 = UInt32(geteuid())
    ) throws {
        try self.init(
            tree: tree,
            stateTree: stateTree,
            runtime: runtime,
            faults: faults,
            validator: validator,
            expectedTeamIdentifier: expectedTeamIdentifier,
            effectiveUserID: effectiveUserID,
            journalStore: nil
        )
    }

    // The journal store seam exists for the hermetic post-rename sync test.
    // Production callers use the initializer above.
    init(
        tree: InstallTree,
        stateTree: InstallTree? = nil,
        runtime: PrivilegedServiceRuntime,
        faults: ServiceTransactionFaultInjecting = NoServiceFaults(),
        validator: InstallerValidator = InstallerValidator(),
        expectedTeamIdentifier: String? = nil,
        effectiveUserID: UInt32 = UInt32(geteuid()),
        journalStore: ServiceJournalStore?
    ) throws {
        if runtime.isLiveSystem {
            guard CoordinatorPolicy.systemOperationsApproved else {
                throw ServiceTransactionError.notApproved
            }
            guard effectiveUserID == 0 else {
                throw ServiceTransactionError.requiresRoot
            }
            guard let expectedTeamIdentifier,
                  HelperRequirement.isValidTeamIdentifier(expectedTeamIdentifier)
            else {
                throw ServiceTransactionError.requiresTeamIdentifier
            }
        }
        let resolvedStateTree = stateTree ?? tree
        self.tree = tree
        self.stateTree = resolvedStateTree
        self.runtime = runtime
        self.faults = faults
        self.validator = validator
        self.expectedTeamIdentifier = expectedTeamIdentifier
        self.journalStore = journalStore ?? ServiceJournalStore(tree: resolvedStateTree)
    }

    public func apply(
        installTransactionID: String? = nil,
        using lease: InstallExclusionLease? = nil
    ) throws -> ServiceInstallOutcome {
        if let installTransactionID,
           !SystemSupport.isLowercaseHex(installTransactionID, count: 32) {
            throw ServiceTransactionError.invalidInstallTransactionID
        }
        try ensureStateDirectory()
        let lock = try acquireOrValidate(lease)
        defer { if lease == nil { lock.release() } }

        try refuseInstallJournal()
        try refuseParticipantState()
        let store = journalStore
        do {
            if try store.read() != nil {
                throw ServiceTransactionError.serviceJournalPresent
            }
            try store.removeTemporaryFiles()
        } catch let error as ServiceTransactionError {
            throw error
        } catch {
            throw mapError(error)
        }

        let inputs = try readInstalledInputs()
        let previousRight = try observePreviousRight()
        let previousJob = try observeJobForPreflight()

        let transactionID = SystemSupport.randomHex(byteCount: 16)
        let journal = ServiceJournal(
            transactionID: transactionID,
            installTransactionID: installTransactionID,
            installedRightSHA256: inputs.right.sha256,
            installedRightPolicy: inputs.right.policy,
            installedLaunchDaemonSHA256: inputs.launchDaemonSHA256,
            phase: .preparing,
            previousRightPresent: previousRight != nil,
            previousRightSHA256: previousRight?.sha256,
            previousRightPolicy: previousRight?.policy,
            previousRightPlistBase64: previousRight?.plist.base64EncodedString(),
            previousJobLoaded: previousJob.isLoaded
        )
        do {
            try store.write(journal)
        } catch {
            let mapped = mapError(error)
            if case .serviceJournalWriteOutcomeUnknown(let why) = mapped {
                // The rename may be visible, but its directory entry may not be
                // durable. No privileged action has run yet, and a caller
                // cannot tell a clean failure from a journal that will survive
                // a power loss. Report the one error every caller already
                // treats as "keep the journal and block file rollback".
                throw ServiceTransactionError.recoveryRequired(
                    "the preparing service journal write outcome is unknown: \(why) No privileged action was attempted. Block file rollback and run service recovery."
                )
            }
            throw mapped
        }
        try faults.check(.journalPrepared)

        var currentJournal = journal
        var state = ExecutionState()
        do {
            if previousJob.isLoaded {
                state.bootoutAttempted = true
                var bootoutError: Error?
                do { try runtime.launchd.bootout() } catch { bootoutError = error }
                let observation = try observeJobRaw()
                switch observation {
                case .absent:
                    state.bootoutVerified = true
                case .loaded:
                    if let bootoutError { throw bootoutError }
                    throw ServiceTransactionError.launchdJobStillLoaded(
                        "the job remains after bootout"
                    )
                case .unexpected(let why):
                    throw ServiceTransactionError.launchdJobUnexpected(why)
                case .unknown(let why):
                    throw ServiceTransactionError.launchdJobUnknown(why)
                }
                try faults.check(.jobBootoutCompleted)
            }

            currentJournal = currentJournal.withPhase(.jobBootedOut)
            try store.write(currentJournal)
            try faults.check(.jobBootoutJournalWritten)

            // Optimistic check before the first mutation of authd. The
            // exclusive lock excludes participating starts; it does not
            // exclude another root writer.
            let currentRight = try observeRightForPreflight()
            guard sameRight(currentRight, previousRight) else {
                throw ServiceTransactionError.authorizationRightUnreadable(
                    "the start right changed between observation and the write"
                )
            }

            state.rightWriteAttempted = true
            var writeError: Error?
            do { try runtime.authorizationRights.write(inputs.right.plist) } catch {
                writeError = error
            }
            let afterWrite = try observeRightForPreflight()
            guard case .present(let written) = afterWrite,
                  written.policy == inputs.right.policy
            else {
                if let writeError { throw writeError }
                throw ServiceTransactionError.rightReadbackMismatch(
                    "the stored definition is not the installed definition"
                )
            }
            state.rightReplaced = true
            try faults.check(.rightWriteCompleted)

            currentJournal = currentJournal.withPhase(.rightReplaced)
            try store.write(currentJournal)
            try faults.check(.rightJournalWritten)

            // A privileged actor outside the lock can still change authd or
            // launchd. Recheck both states immediately before the two actions
            // that make the new service visible.
            let beforeBootstrapRight = try observeRightForPreflight()
            guard case .present(let beforeBootstrapSnapshot) = beforeBootstrapRight,
                  beforeBootstrapSnapshot.policy == inputs.right.policy
            else {
                throw ServiceTransactionError.rightReadbackMismatch(
                    "the start right changed before bootstrap"
                )
            }
            switch try observeJobRaw() {
            case .absent:
                break
            case .loaded:
                throw ServiceTransactionError.bootstrapUnverified(
                    "a job with the fixed label is loaded before this transaction bootstrapped it"
                )
            case .unexpected(let why):
                throw ServiceTransactionError.launchdJobUnexpected(why)
            case .unknown(let why):
                throw ServiceTransactionError.launchdJobUnknown(why)
            }

            state.bootstrapAttempted = true
            try verifyInstalledLaunchDaemonDigest(inputs.launchDaemonSHA256)
            var bootstrapError: Error?
            do {
                try runtime.launchd.bootstrap()
                state.bootstrapSucceeded = true
            } catch {
                bootstrapError = error
            }
            let afterBootstrap = try observeJobRaw()
            switch afterBootstrap {
            case .loaded:
                if !state.bootstrapSucceeded {
                    state.bootstrapAmbiguous = true
                    throw ServiceTransactionError.bootstrapUnverified(
                        "the command failed but the job is loaded"
                    )
                }
            case .absent:
                if let bootstrapError { throw bootstrapError }
                throw ServiceTransactionError.launchdJobNotLoaded(
                    "the job is absent after a successful bootstrap command"
                )
            case .unexpected(let why):
                throw ServiceTransactionError.launchdJobUnexpected(why)
            case .unknown(let why):
                throw ServiceTransactionError.launchdJobUnknown(why)
            }
            try faults.check(.bootstrapCompleted)

            currentJournal = currentJournal.withPhase(.jobBootstrapped)
            try store.write(currentJournal)
            try faults.check(.bootstrapJournalWritten)

            let finalRight = try observeRightForPreflight()
            guard case .present(let finalRightSnapshot) = finalRight,
                  finalRightSnapshot.policy == inputs.right.policy
            else {
                throw ServiceTransactionError.rightReadbackMismatch(
                    "the start right changed before the commit record"
                )
            }
            switch try observeJobRaw() {
            case .loaded:
                break
            case .absent:
                throw ServiceTransactionError.launchdJobNotLoaded(
                    "the job is absent before the commit record"
                )
            case .unexpected(let why):
                throw ServiceTransactionError.launchdJobUnexpected(why)
            case .unknown(let why):
                throw ServiceTransactionError.launchdJobUnknown(why)
            }
            try verifyInstalledLaunchDaemonDigest(inputs.launchDaemonSHA256)

            currentJournal = currentJournal.withPhase(.committed)
            let committedObservation = try store.write(currentJournal)
            state.commitDurable = true
            try faults.check(.commitJournalWritten)

            try store.remove(committedObservation)
            try faults.check(.journalRemoved)

            return ServiceInstallOutcome(
                transactionID: transactionID,
                previousRightPresent: previousRight != nil,
                previousJobLoaded: previousJob.isLoaded,
                right: inputs.right.policy,
                launchdJobLoaded: true
            )
        } catch {
            let mapped = mapError(error)
            if case .simulatedCrash = mapped { throw mapped }
            if case .serviceJournalWriteOutcomeUnknown = mapped {
                throw ServiceTransactionError.recoveryRequired(
                    "\(mapped.description) The previous service state was not rolled back because a durable journal phase cannot be proven."
                )
            }
            if case .serviceJournalRemoveOutcomeUnknown = mapped {
                throw ServiceTransactionError.recoveryRequired(
                    "\(mapped.description) The committed service state is not rolled back. Run service recovery to re-observe the record."
                )
            }
            if state.commitDurable {
                throw ServiceTransactionError.recoveryRequired(
                    "\(mapped.description) The commit record is durable, so the service state is not rolled back. The service journal is kept for recovery."
                )
            }
            let rollback = rollback(
                journal: currentJournal,
                previousRight: previousRight,
                previousJob: previousJob,
                installedPolicy: inputs.right.policy,
                state: state,
                store: store
            )
            guard rollback.completed else {
                throw ServiceTransactionError.recoveryRequired(
                    "\(mapped.description) Rollback did not complete: "
                        + (rollback.detail ?? "an external state is uncertain")
                        + "."
                )
            }
            if rollback.rightMetadataChanged {
                throw ServiceTransactionError.operationFailedWithInexactRightRollback(
                    mapped.description
                )
            }
            throw ServiceTransactionError.operationFailed(mapped.description)
        }
    }

    public func recover(using lease: InstallExclusionLease? = nil) throws -> ServiceRecoveryOutcome {
        try ensureStateDirectory()
        let lock = try acquireOrValidate(lease)
        defer { if lease == nil { lock.release() } }

        try refuseInstallJournal()
        try refuseParticipantState()
        let store = journalStore
        do {
            try store.removeTemporaryFiles()
        } catch {
            throw mapError(error)
        }
        let journal: ServiceJournal
        let observed: ServiceJournalObservation
        do {
            guard let found = try store.readObserved() else { return .nothingToRecover }
            observed = found
            journal = found.journal
        } catch {
            throw mapError(error)
        }
        // A visible phase record is not a durable one. Rewrite the exact bytes
        // and require the file and parent sync before any recovery action.
        // An unknown confirmation stops with the journal untouched.
        do {
            try store.confirm(observed)
        } catch {
            throw ServiceTransactionError.recoveryRequired(
                "the service journal could not be durably confirmed before recovery: "
                    + mapError(error).description
            )
        }

        let inputs = try readInstalledInputs()
        guard inputs.right.sha256 == journal.installedRightSHA256,
              inputs.launchDaemonSHA256 == journal.installedLaunchDaemonSHA256
        else {
            throw ServiceTransactionError.recoveryRequired(
                "the installed right or launch daemon file does not match the service journal. Recover the file transaction first."
            )
        }

        let previousRight: AuthorizationRightSnapshot?
        do {
            previousRight = try previousRightSnapshot(from: journal)
        } catch {
            throw mapError(error)
        }

        var jobObservation: LaunchdJobObservation
        let rightObservation: AuthorizationRightObservation
        do {
            rightObservation = try observeRightForPreflight()
            jobObservation = try observeJobRaw()
        } catch {
            throw ServiceTransactionError.recoveryRequired(mapError(error).description)
        }
        try faults.check(.recoveryRightObserved)

        let rightState = classifyRight(
            rightObservation,
            previous: previousRight,
            installed: inputs.right
        )

        if journal.phase == .committed {
            guard rightState.matchesInstalled, case .loaded = jobObservation else {
                throw ServiceTransactionError.committedStateDamaged(
                    "the committed right or launch daemon state does not verify"
                )
            }
            do {
                try verifyInstalledLaunchDaemonDigest(journal.installedLaunchDaemonSHA256)
            } catch {
                throw ServiceTransactionError.committedStateDamaged(
                    "the committed launch daemon file does not verify: \(mapError(error).description)"
                )
            }
            do { try store.remove(observed) } catch {
                throw ServiceTransactionError.recoveryRequired(
                    "the service journal cannot be removed: \(mapError(error).description)"
                )
            }
            try faults.check(.recoveryJournalRemoved)
            return .finishedCommit(transactionID: journal.transactionID)
        }

        if journal.phase == .rolledBack {
            return try finishTerminalRollback(
                journal: journal,
                observed: observed,
                previousRight: previousRight,
                rightObservation: rightObservation,
                rightState: rightState,
                jobObservation: jobObservation,
                store: store
            )
        }

        if journal.phase == .rollbackStarted {
            return try finishInterruptedRollback(
                journal: journal,
                observed: observed,
                previousRight: previousRight,
                inputs: inputs,
                store: store
            )
        }

        switch jobObservation {
        case .unexpected(let why):
            throw ServiceTransactionError.recoveryRequired(
                "a launch daemon job with the fixed label is loaded but is not the installed one: \(why). The job was not booted out."
            )
        case .unknown(let why):
            throw ServiceTransactionError.recoveryRequired(
                "the launch daemon state cannot be proven: \(why). The service journal is kept."
            )
        case .absent, .loaded:
            break
        }

        // A loaded job is booted out only when it is the untouched previous job
        // from the preparing phase. A loaded job after the right write can be
        // this transaction's bootstrap in the crash window before the
        // jobBootstrapped record, and cannot be attributed.
        if rightState == .other {
            throw ServiceTransactionError.recoveryRequired(
                "the start right holds an object the journal does not own. The service journal is kept."
            )
        }
        var currentJournal = journal
        if case .loaded = jobObservation {
            let provenNew = (currentJournal.phase == .jobBootstrapped)
            if !provenNew {
                guard currentJournal.phase == .preparing,
                      journal.previousJobLoaded,
                      rightState != .installed
                else {
                    throw ServiceTransactionError.recoveryRequired(
                        "a launch daemon job with the fixed label is loaded and the journal cannot prove this transaction created it. The job was not booted out."
                    )
                }
                var bootoutError: Error?
                do { try runtime.launchd.bootout() } catch { bootoutError = error }
                let after = try observeJobRaw()
                guard case .absent = after else {
                    throw ServiceTransactionError.recoveryRequired(
                        "the previous launch daemon job could not be booted out: "
                            + (bootoutError.map { mapError($0).description } ?? "the job remains loaded")
                    )
                }
                jobObservation = .absent
                currentJournal = try writeRecoveryPhase(
                    .jobBootedOut,
                    journal: currentJournal,
                    store: store,
                    detail: "the service journal cannot record the bootout"
                ).journal
                try faults.check(.recoveryBootoutCompleted)
            }
        }

        if currentJournal.phase == .jobBootstrapped, case .absent = jobObservation {
            throw ServiceTransactionError.recoveryRequired(
                "the journal says the launch daemon was bootstrapped but the job is not loaded. The service journal is kept."
            )
        }

        // Record the bootout before the right write even when no job was
        // loaded, so a crash does not leave an unlabelled right write.
        if currentJournal.phase == .preparing {
            currentJournal = try writeRecoveryPhase(
                .jobBootedOut,
                journal: currentJournal,
                store: store,
                detail: "the service journal cannot record the pre-action bootout state"
            ).journal
        }

        // Before the rightReplaced record the journal does not prove that this
        // transaction wrote the installed definition. Write it even when the
        // observed policy already equals the installed policy, because the
        // previous policy may be identical and the stored bytes may still be
        // the old authd metadata. After rightReplaced, an installed or
        // ambiguous state is already the transaction's right, unless the
        // stored bytes are exactly the previous backup. That exact match is
        // the only evidence of an earlier recovery that skipped the write.
        let observedExactPreviousBackup: Bool
        if case .present(let observedSnapshot) = rightObservation,
           let previousRight
        {
            observedExactPreviousBackup = observedSnapshot.plist == previousRight.plist
                && previousRight.plist != inputs.right.plist
        } else {
            observedExactPreviousBackup = false
        }
        let mustWriteInstalledRight = !rightState.matchesInstalled
            || currentJournal.phase == .preparing
            || currentJournal.phase == .jobBootedOut
            || (currentJournal.phase == .rightReplaced && observedExactPreviousBackup)
        if mustWriteInstalledRight {
            let beforeWrite: AuthorizationRightObservation
            do {
                beforeWrite = try observeRightForPreflight()
            } catch {
                throw ServiceTransactionError.recoveryRequired(mapError(error).description)
            }
            guard classifyRight(
                beforeWrite,
                previous: previousRight,
                installed: inputs.right
            ) != .other else {
                throw ServiceTransactionError.recoveryRequired(
                    "the start right changed to an object the journal does not own before the write"
                )
            }
            var writeError: Error?
            do { try runtime.authorizationRights.write(inputs.right.plist) } catch {
                writeError = error
            }
            let readback = try observeRightForPreflight()
            guard case .present(let written) = readback,
                  written.policy == inputs.right.policy
            else {
                throw ServiceTransactionError.recoveryRequired(
                    "the installed start right could not be written: "
                        + (writeError.map { mapError($0).description } ?? "the read-back differs")
                )
            }
            if currentJournal.phase == .preparing || currentJournal.phase == .jobBootedOut {
                currentJournal = try writeRecoveryPhase(
                    .rightReplaced,
                    journal: currentJournal,
                    store: store,
                    detail: "the service journal cannot record the right replacement"
                ).journal
            }
            try faults.check(.recoveryRightWritten)
        }

        // A right that was already installed by an earlier recovery attempt
        // still needs its durable pre-action phase before bootstrap.
        if currentJournal.phase == .preparing || currentJournal.phase == .jobBootedOut {
            currentJournal = try writeRecoveryPhase(
                .rightReplaced,
                journal: currentJournal,
                store: store,
                detail: "the service journal cannot record the pre-action right state"
            ).journal
        }

        if case .absent = jobObservation {
            // Reobserve both states immediately before bootstrap. The job write
            // and the right write happened above; a job that appeared since the
            // first observation must not be attributed to this transaction.
            let beforeBootstrapJob: LaunchdJobObservation
            do {
                beforeBootstrapJob = try observeJobRaw()
            } catch {
                throw ServiceTransactionError.recoveryRequired(mapError(error).description)
            }
            switch beforeBootstrapJob {
            case .absent:
                break
            case .loaded:
                throw ServiceTransactionError.recoveryRequired(
                    "a launch daemon job with the fixed label is loaded before this recovery bootstrapped it. The job was not booted out and the service journal is kept."
                )
            case .unexpected(let why):
                throw ServiceTransactionError.recoveryRequired(
                    "a launch daemon job with the fixed label is loaded but is not the installed one: \(why). The job was not booted out."
                )
            case .unknown(let why):
                throw ServiceTransactionError.recoveryRequired(
                    "the launch daemon state cannot be proven before bootstrap: \(why). The service journal is kept."
                )
            }

            let beforeBootstrapRight: AuthorizationRightObservation
            do {
                beforeBootstrapRight = try observeRightForPreflight()
            } catch {
                throw ServiceTransactionError.recoveryRequired(mapError(error).description)
            }
            guard case .present(let beforeBootstrapPolicy) = beforeBootstrapRight,
                  beforeBootstrapPolicy.policy == inputs.right.policy
            else {
                throw ServiceTransactionError.recoveryRequired(
                    "the start right does not match the installed definition before bootstrap"
                )
            }
            do {
                try verifyInstalledLaunchDaemonDigest(inputs.launchDaemonSHA256)
            } catch {
                // The right replacement and its journal phase are already
                // durable. A raw installedFileUnsafe here would not tell the
                // caller that the journal must stay, so report the same
                // recovery contract as the later pre-commit check.
                throw ServiceTransactionError.recoveryRequired(
                    "the installed launch daemon file changed before bootstrap: \(mapError(error).description)"
                )
            }
            var bootstrapError: Error?
            var bootstrapSucceeded = false
            do {
                try runtime.launchd.bootstrap()
                bootstrapSucceeded = true
            } catch {
                bootstrapError = error
            }
            let readback = try observeJobRaw()
            switch readback {
            case .loaded:
                guard bootstrapSucceeded else {
                    throw ServiceTransactionError.recoveryRequired(
                        "the bootstrap command failed but a job with the fixed label is loaded, and this recovery cannot prove it created that job. The job was not booted out and the service journal is kept."
                    )
                }
                jobObservation = readback
            case .absent:
                throw ServiceTransactionError.recoveryRequired(
                    "the launch daemon job is absent after the bootstrap command: "
                        + (bootstrapError.map { mapError($0).description } ?? "the read-back differs")
                )
            case .unexpected(let why):
                throw ServiceTransactionError.recoveryRequired(
                    "a launch daemon job with the fixed label is loaded after bootstrap but is not the installed one: \(why). The job was not booted out."
                )
            case .unknown(let why):
                throw ServiceTransactionError.recoveryRequired(
                    "the launch daemon state cannot be proven after bootstrap: \(why). The service journal is kept."
                )
            }
            try faults.check(.recoveryBootstrapSucceeded)
            currentJournal = try writeRecoveryPhase(
                .jobBootstrapped,
                journal: currentJournal,
                store: store,
                detail: "the service journal cannot record the bootstrap"
            ).journal
            try faults.check(.recoveryBootstrapCompleted)
        }

        let finalRight: AuthorizationRightObservation
        let finalJob: LaunchdJobObservation
        do {
            finalRight = try observeRightForPreflight()
            finalJob = try observeJobRaw()
        } catch {
            throw ServiceTransactionError.recoveryRequired(mapError(error).description)
        }
        guard case .present(let finalRightSnapshot) = finalRight,
              finalRightSnapshot.policy == inputs.right.policy
        else {
            throw ServiceTransactionError.recoveryRequired(
                "the start right does not match the installed definition before the commit record"
            )
        }
        guard case .loaded = finalJob else {
            throw ServiceTransactionError.recoveryRequired(
                "the launch daemon job is not loaded before the commit record"
            )
        }
        do {
            try verifyInstalledLaunchDaemonDigest(inputs.launchDaemonSHA256)
        } catch {
            throw ServiceTransactionError.recoveryRequired(mapError(error).description)
        }

        let committedObservation = try writeRecoveryPhase(
            .committed,
            journal: currentJournal,
            store: store,
            detail: "the service journal cannot record the commit"
        )
        try faults.check(.recoveryCommitJournalWritten)

        do { try store.remove(committedObservation) } catch {
            throw ServiceTransactionError.recoveryRequired(
                "the service journal cannot be removed: \(mapError(error).description)"
            )
        }
        try faults.check(.recoveryJournalRemoved)
        return .finishedInstall(transactionID: journal.transactionID)
    }

    // A rolledBack journal is terminal. Verify that the previous right and job
    // are still in place, then remove only the journal. This path must never
    // write the installed right or bootstrap the new job.
    private func finishTerminalRollback(
        journal: ServiceJournal,
        observed: ServiceJournalObservation,
        previousRight: AuthorizationRightSnapshot?,
        rightObservation: AuthorizationRightObservation,
        rightState: RightState,
        jobObservation: LaunchdJobObservation,
        store: ServiceJournalStore
    ) throws -> ServiceRecoveryOutcome {
        guard isExpectedPreviousState(rightState, previousPresent: previousRight != nil) else {
            throw ServiceTransactionError.recoveryRequired(
                "the terminal rollback record is durable but the start right does not match the previous state. The service journal is kept."
            )
        }
        switch (journal.previousJobLoaded, jobObservation) {
        case (true, .loaded), (false, .absent):
            break
        default:
            throw ServiceTransactionError.recoveryRequired(
                "the terminal rollback record is durable but the launch daemon job does not match the previous state. The service journal is kept."
            )
        }
        do { try store.remove(observed) } catch {
            throw ServiceTransactionError.recoveryRequired(
                "the service journal cannot be removed after the terminal rollback: \(mapError(error).description)"
            )
        }
        try faults.check(.recoveryJournalRemoved)
        let metadataChanged: Bool
        if let previousRight, case .present(let snapshot) = rightObservation {
            metadataChanged = snapshot.plist != previousRight.plist
        } else {
            metadataChanged = false
        }
        return .finishedRollback(
            transactionID: journal.transactionID,
            rightMetadataChanged: metadataChanged
        )
    }

    // A rollbackStarted journal recorded the rollback intent before any
    // rollback mutation. Finish restoring the previous right and job state, or
    // refuse. This path must never install the new right or bootstrap the new
    // job.
    private func finishInterruptedRollback(
        journal: ServiceJournal,
        observed: ServiceJournalObservation,
        previousRight: AuthorizationRightSnapshot?,
        inputs: InstalledInputs,
        store: ServiceJournalStore
    ) throws -> ServiceRecoveryOutcome {
        let rightObservation: AuthorizationRightObservation
        let jobObservation: LaunchdJobObservation
        do {
            rightObservation = try observeRightForPreflight()
            jobObservation = try observeJobRaw()
        } catch {
            throw ServiceTransactionError.recoveryRequired(mapError(error).description)
        }

        let rightState = classifyRight(
            rightObservation,
            previous: previousRight,
            installed: inputs.right
        )
        switch jobObservation {
        case .unexpected(let why):
            throw ServiceTransactionError.recoveryRequired(
                "a launch daemon job with the fixed label is loaded but is not the installed one during rollback: \(why). The job was not booted out."
            )
        case .unknown(let why):
            throw ServiceTransactionError.recoveryRequired(
                "the launch daemon state cannot be proven during rollback: \(why). The service journal is kept."
            )
        case .absent, .loaded:
            break
        }
        guard rightState != .other else {
            throw ServiceTransactionError.recoveryRequired(
                "the start right holds an object the journal does not own during rollback. The service journal is kept."
            )
        }
        if case .loaded = jobObservation, rightState == .installed {
            throw ServiceTransactionError.recoveryRequired(
                "a launch daemon job is loaded after the installed right was written during rollback, and this recovery cannot prove it is the previous job. The job was not booted out."
            )
        }

        // A previous-and-installed state is the previous state during a
        // rollback. It must not cause the packaged definition to be written,
        // because that would turn the rollback into an install.
        if !rightState.matchesPrevious, rightState != .previousAbsent {
            guard rightState == .installed else {
                throw ServiceTransactionError.recoveryRequired(
                    "the start right cannot be classified for rollback. The service journal is kept."
                )
            }
            if let previousRight {
                var writeError: Error?
                do { try runtime.authorizationRights.write(previousRight.plist) } catch {
                    writeError = error
                }
                let readback: AuthorizationRightObservation
                do {
                    readback = try observeRightForPreflight()
                } catch {
                    throw ServiceTransactionError.recoveryRequired(
                        "the previous start right cannot be read back during rollback: \(mapError(error).description)"
                    )
                }
                guard case .present(let restored) = readback,
                      restored.policy == previousRight.policy
                else {
                    throw ServiceTransactionError.recoveryRequired(
                        "the previous start right could not be restored during rollback: "
                            + (writeError.map { mapError($0).description } ?? "the read-back differs")
                    )
                }
            } else {
                var removeError: Error?
                do { try runtime.authorizationRights.remove() } catch {
                    removeError = error
                }
                let readback: AuthorizationRightObservation
                do {
                    readback = try observeRightForPreflight()
                } catch {
                    throw ServiceTransactionError.recoveryRequired(
                        "the previous absent start right cannot be read back during rollback: \(mapError(error).description)"
                    )
                }
                guard case .absent = readback else {
                    throw ServiceTransactionError.recoveryRequired(
                        "the previous absent start right could not be restored during rollback: "
                            + (removeError.map { mapError($0).description } ?? "the read-back differs")
                    )
                }
            }
            do {
                _ = try observeRightForPreflight()
            } catch {
                throw ServiceTransactionError.recoveryRequired(
                    "the start right cannot be read back after rollback: \(mapError(error).description)"
                )
            }
            try faults.check(.recoveryRightWritten)
        }

        let finalRight: AuthorizationRightObservation
        let finalJob: LaunchdJobObservation
        do {
            finalRight = try observeRightForPreflight()
            finalJob = try observeJobRaw()
        } catch {
            throw ServiceTransactionError.recoveryRequired(mapError(error).description)
        }
        let finalRightState = classifyRight(
            finalRight,
            previous: previousRight,
            installed: inputs.right
        )
        guard isExpectedPreviousState(
            finalRightState,
            previousPresent: previousRight != nil
        ) else {
            throw ServiceTransactionError.recoveryRequired(
                "the previous start right is not restored after rollback. The service journal is kept."
            )
        }
        switch (journal.previousJobLoaded, finalJob) {
        case (true, .loaded), (false, .absent):
            break
        default:
            throw ServiceTransactionError.recoveryRequired(
                "the previous launch daemon job state is not restored after rollback. The service journal is kept."
            )
        }

        let rolledBack: ServiceJournalObservation
        do {
            rolledBack = try store.write(journal.withPhase(.rolledBack))
        } catch {
            throw ServiceTransactionError.recoveryRequired(
                "the service journal cannot record the completed rollback: \(mapError(error).description)"
            )
        }
        do { try store.remove(rolledBack) } catch {
            throw ServiceTransactionError.recoveryRequired(
                "the service journal cannot be removed after the completed rollback: \(mapError(error).description)"
            )
        }
        try faults.check(.recoveryJournalRemoved)
        let metadataChanged: Bool
        if let previousRight, case .present(let snapshot) = finalRight {
            metadataChanged = snapshot.plist != previousRight.plist
        } else {
            metadataChanged = false
        }
        return .finishedRollback(
            transactionID: journal.transactionID,
            rightMetadataChanged: metadataChanged
        )
    }

    private func writeRecoveryPhase(
        _ phase: ServiceJournal.Phase,
        journal: ServiceJournal,
        store: ServiceJournalStore,
        detail: String
    ) throws -> ServiceJournalObservation {
        let next = journal.withPhase(phase)
        do {
            return try store.write(next)
        } catch {
            throw ServiceTransactionError.recoveryRequired(
                "\(detail): \(mapError(error).description)"
            )
        }
    }

    // MARK: private

    private func ensureStateDirectory() throws {
        do {
            for parent in ["var", "var/db"] {
                _ = try stateTree.ensureDirectory(parent, mode: 0o755, create: true)
            }
            _ = try stateTree.ensureDirectory(
                PrivilegedServiceLayout.stateDirectoryRelative,
                mode: 0o700,
                create: true
            )
            let mode = try stateTree.directoryMode(PrivilegedServiceLayout.stateDirectoryRelative)
            guard mode == 0o700 else {
                throw ServiceTransactionError.stateDirectoryUnsafe(
                    "the directory mode is not 0700"
                )
            }
        } catch let error as ServiceTransactionError {
            throw error
        } catch {
            throw ServiceTransactionError.stateDirectoryUnsafe(
                "the directory cannot be created or checked"
            )
        }
    }

    private func acquireOrValidate(_ lease: InstallExclusionLease?) throws -> InstallExclusionLease {
        if let lease {
            guard lease.locks.allSatisfy({ $0.isHeld }) else {
                throw ServiceTransactionError.lockUnavailable
            }
            let statePath: String
            do {
                statePath = try stateTree.path(
                    for: PrivilegedServiceLayout.stateDirectoryRelative
                )
            } catch {
                throw ServiceTransactionError.io("the state directory path is unsafe")
            }
            do {
                for name in InstallLockLayout.heldFileNames {
                    guard let current = try InstallLock.identity(
                        parentDirectory: statePath,
                        fileName: name,
                        expectedOwner: stateTree.owner
                    ), let held = lease.fileNameByIdentity[name], held == current
                    else {
                        throw ServiceTransactionError.lockUnavailable
                    }
                }
            } catch let error as ServiceTransactionError {
                throw error
            } catch {
                throw ServiceTransactionError.lockUnsafe(
                    "the passed lease does not hold the state directory locks"
                )
            }
            return lease
        }
        let statePath: String
        do {
            statePath = try stateTree.path(for: PrivilegedServiceLayout.stateDirectoryRelative)
        } catch {
            throw ServiceTransactionError.io("the state directory path is unsafe")
        }
        do {
            return try InstallExclusionLease.acquire(
                parentDirectory: statePath,
                expectedOwner: stateTree.owner
            )
        } catch InstallLockError.busy {
            throw ServiceTransactionError.lockUnavailable
        } catch let error as InstallLockError {
            throw ServiceTransactionError.lockUnsafe(error.description)
        } catch {
            throw ServiceTransactionError.lockUnsafe("the install exclusion cannot be acquired")
        }
    }

    // The reverse fence of the file coordinator's service-journal refusal.
    // Neither journal may be recovered while the other is present because no
    // reviewed two-journal recovery order exists. This refuses before any
    // service action and never removes the file journal.
    private func refuseInstallJournal() throws {
        do {
            if try stateTree.entryExists(InstallJournalStore.relativePath) {
                throw ServiceTransactionError.installJournalPresent
            }
        } catch let error as ServiceTransactionError {
            throw error
        } catch {
            throw ServiceTransactionError.io(
                "the file install journal state cannot be inspected"
            )
        }
    }

    private func refuseParticipantState() throws {
        do {
            if try stateTree.entryExists(
                PrivilegedServiceLayout.stateDirectoryRelative
                    + "/" + InstallLockLayout.cleanupMarkerName
            ) {
                throw ServiceTransactionError.participantStateUnclean(
                    "a cleanup block is present"
                )
            }
            if try stateTree.entryExists(
                PrivilegedServiceLayout.stateDirectoryRelative
                    + "/" + InstallLockLayout.launchIntentName
            ) {
                throw ServiceTransactionError.participantStateUnclean(
                    "an engine launch intent is present"
                )
            }
            if try StartJournalProbe.read(stateTree) != nil {
                throw ServiceTransactionError.participantStateUnclean(
                    "a start journal is present"
                )
            }
        } catch let error as ServiceTransactionError {
            throw error
        } catch let error as CoordinatorError {
            switch error {
            case .startJournalUnreadable:
                throw ServiceTransactionError.participantStateUnclean(
                    "the start journal cannot be read safely"
                )
            default:
                throw ServiceTransactionError.participantStateUnclean(
                    "the helper state cannot be inspected safely"
                )
            }
        } catch {
            throw ServiceTransactionError.participantStateUnclean(
                "the helper state cannot be inspected safely"
            )
        }
    }

    private func readInstalledInputs() throws -> InstalledInputs {
        let rightSnapshot: FileSnapshot?
        do {
            rightSnapshot = try tree.snapshot(
                PrivilegedServiceLayout.rightSourceRelative,
                maximumBytes: PrivilegedServiceLayout.maximumRightBytes
            )
        } catch let error as InstallTreeError {
            throw ServiceTransactionError.installedFileUnsafe(error.path)
        } catch {
            throw ServiceTransactionError.installedFileUnsafe(
                "the installed start right cannot be inspected"
            )
        }
        guard let rightSnapshot, rightSnapshot.mode == 0o644 else {
            throw ServiceTransactionError.installedFileUnsafe(
                "the installed start right is missing or has the wrong mode"
            )
        }

        let rightData: Data
        do {
            guard let data = try tree.readFile(
                PrivilegedServiceLayout.rightSourceRelative,
                maximumBytes: PrivilegedServiceLayout.maximumRightBytes
            ) else {
                throw ServiceTransactionError.installedFileUnsafe(
                    "the installed start right is missing"
                )
            }
            guard ServiceHash.sha256Hex(data) == rightSnapshot.sha256 else {
                throw ServiceTransactionError.installedFileUnsafe(
                    "the installed start right changed while it was inspected"
                )
            }
            rightData = data
        } catch let error as ServiceTransactionError {
            throw error
        } catch {
            throw ServiceTransactionError.installedFileUnsafe(
                "the installed start right cannot be read"
            )
        }

        do {
            try validator.validateStartRight(rightData)
        } catch let error as InstallerError {
            throw ServiceTransactionError.installedFileUnsafe(error.description)
        } catch {
            throw ServiceTransactionError.installedFileUnsafe(
                "the installed start right cannot be checked"
            )
        }
        let right: AuthorizationRightSnapshot
        do {
            right = try AuthorizationRightPolicyParser.parse(rightData)
        } catch let error as AuthorizationRightPolicyError {
            throw ServiceTransactionError.installedFileUnsafe(error.description)
        } catch {
            throw ServiceTransactionError.installedFileUnsafe(
                "the installed start right cannot be parsed"
            )
        }

        let daemonSnapshot: FileSnapshot?
        do {
            daemonSnapshot = try tree.snapshot(
                PrivilegedServiceLayout.launchDaemonRelative,
                maximumBytes: PrivilegedServiceLayout.maximumRightBytes
            )
        } catch let error as InstallTreeError {
            throw ServiceTransactionError.installedFileUnsafe(error.path)
        } catch {
            throw ServiceTransactionError.installedFileUnsafe(
                "the installed launch daemon file cannot be inspected"
            )
        }
        guard let daemonSnapshot, daemonSnapshot.mode == 0o644 else {
            throw ServiceTransactionError.installedFileUnsafe(
                "the installed launch daemon file is missing or has the wrong mode"
            )
        }
        let daemonData: Data
        do {
            guard let data = try tree.readFile(
                PrivilegedServiceLayout.launchDaemonRelative,
                maximumBytes: PrivilegedServiceLayout.maximumRightBytes
            ) else {
                throw ServiceTransactionError.installedFileUnsafe(
                    "the installed launch daemon file is missing"
                )
            }
            guard ServiceHash.sha256Hex(data) == daemonSnapshot.sha256 else {
                throw ServiceTransactionError.installedFileUnsafe(
                    "the installed launch daemon file changed while it was inspected"
                )
            }
            daemonData = data
        } catch let error as ServiceTransactionError {
            throw error
        } catch {
            throw ServiceTransactionError.installedFileUnsafe(
                "the installed launch daemon file cannot be read"
            )
        }
        do {
            try validator.validateLaunchDaemon(daemonData)
        } catch let error as InstallerError {
            throw ServiceTransactionError.installedFileUnsafe(error.description)
        } catch {
            throw ServiceTransactionError.installedFileUnsafe(
                "the installed launch daemon file cannot be checked"
            )
        }

        let executables: [(relative: String, artifact: InstallerArtifact, identifier: String)] = [
            (
                PrivilegedServiceLayout.helperRelative,
                .helper,
                HelperRequirement.helperIdentifier
            ),
            (
                PrivilegedServiceLayout.engineRelative,
                .engine,
                HelperRequirement.engineIdentifier
            ),
        ]
        for executable in executables {
            let snapshot: FileSnapshot?
            do {
                snapshot = try tree.snapshot(
                    executable.relative,
                    maximumBytes: ArtifactIngest.maximumExecutableBytes
                )
            } catch {
                throw ServiceTransactionError.installedFileUnsafe(
                    "an installed executable cannot be inspected"
                )
            }
            guard let snapshot, snapshot.mode == 0o755 else {
                throw ServiceTransactionError.installedFileUnsafe(
                    "an installed executable is missing or has the wrong mode"
                )
            }
            if let expectedTeamIdentifier {
                do {
                    try validator.validateExecutable(
                        atPath: tree.path(for: executable.relative),
                        artifact: executable.artifact,
                        identifier: executable.identifier,
                        teamIdentifier: expectedTeamIdentifier
                    )
                } catch let error as InstallerError {
                    throw ServiceTransactionError.installedFileUnsafe(error.description)
                } catch {
                    throw ServiceTransactionError.installedFileUnsafe(
                        "an installed executable signature cannot be checked"
                    )
                }
            }
        }

        return InstalledInputs(
            right: right,
            launchDaemonSHA256: ServiceHash.sha256Hex(daemonData)
        )
    }

    private func verifyInstalledLaunchDaemonDigest(_ expected: String) throws {
        let data: Data?
        do {
            data = try tree.readFile(
                PrivilegedServiceLayout.launchDaemonRelative,
                maximumBytes: PrivilegedServiceLayout.maximumRightBytes
            )
        } catch {
            throw ServiceTransactionError.installedFileUnsafe(
                "the installed launch daemon file cannot be reread"
            )
        }
        guard let data, ServiceHash.sha256Hex(data) == expected else {
            throw ServiceTransactionError.installedFileUnsafe(
                "the installed launch daemon file changed during the service transaction"
            )
        }
    }

    private func observePreviousRight() throws -> AuthorizationRightSnapshot? {
        let observation = try observeRightForPreflight()
        switch observation {
        case .absent:
            return nil
        case .present(let snapshot):
            return snapshot
        }
    }

    private func observeRightForPreflight() throws -> AuthorizationRightObservation {
        do {
            return try runtime.authorizationRights.observe()
        } catch let error as AuthorizationRightPolicyError {
            throw ServiceTransactionError.authorizationRightUnsafe(error.description)
        } catch let error as AuthorizationRightDatabaseError {
            switch error {
            case .readbackInvalid:
                throw ServiceTransactionError.authorizationRightUnsafe(error.description)
            case .unreadable, .commandFailed:
                throw ServiceTransactionError.authorizationRightUnreadable(error.description)
            }
        } catch {
            throw ServiceTransactionError.authorizationRightUnreadable(
                "the start right cannot be observed"
            )
        }
    }

    private func observeJobRaw() throws -> LaunchdJobObservation {
        do {
            return try runtime.launchd.observe()
        } catch let error as LaunchdJobError {
            throw ServiceTransactionError.launchdJobUnknown(error.description)
        } catch {
            throw ServiceTransactionError.launchdJobUnknown(
                "the launch daemon state cannot be observed"
            )
        }
    }

    private func observeJobForPreflight() throws -> LaunchdJobObservation {
        let observation = try observeJobRaw()
        switch observation {
        case .absent, .loaded:
            return observation
        case .unexpected(let why):
            throw ServiceTransactionError.launchdJobUnexpected(why)
        case .unknown(let why):
            throw ServiceTransactionError.launchdJobUnknown(why)
        }
    }

    private func sameRight(
        _ observation: AuthorizationRightObservation,
        _ snapshot: AuthorizationRightSnapshot?
    ) -> Bool {
        switch (observation, snapshot) {
        case (.absent, nil):
            return true
        case (.present(let current), .some(let expected)):
            return current.policy == expected.policy
        default:
            return false
        }
    }

    private func previousRightSnapshot(
        from journal: ServiceJournal
    ) throws -> AuthorizationRightSnapshot? {
        guard journal.previousRightPresent else { return nil }
        guard let encoded = journal.previousRightPlistBase64,
              let data = Data(base64Encoded: encoded),
              let parsed = try? AuthorizationRightPolicyParser.parse(data),
              parsed.sha256 == journal.previousRightSHA256,
              parsed.policy == journal.previousRightPolicy
        else {
            throw ServiceTransactionError.serviceJournalUnsafe(
                "the previous right backup cannot be used"
            )
        }
        return parsed
    }

    private func classifyRight(
        _ observation: AuthorizationRightObservation,
        previous: AuthorizationRightSnapshot?,
        installed: AuthorizationRightSnapshot
    ) -> RightState {
        switch observation {
        case .present(let snapshot):
            let matchesInstalled = snapshot.policy == installed.policy
            let matchesPrevious = previous.map { snapshot.policy == $0.policy } ?? false
            switch (matchesInstalled, matchesPrevious) {
            case (true, true):
                // An ordinary upgrade can use the same right policy. Do not
                // call this installed first: the phase decides whether the
                // definition is the previous state or the new one.
                return .previousAndInstalled
            case (true, false):
                return .installed
            case (false, true):
                return .previous
            case (false, false):
                return .other
            }
        case .absent:
            return previous == nil ? .previousAbsent : .other
        }
    }

    private func isExpectedPreviousState(
        _ state: RightState,
        previousPresent: Bool
    ) -> Bool {
        if previousPresent {
            return state.matchesPrevious
        }
        return state == .previousAbsent
    }

    private func rollback(
        journal: ServiceJournal,
        previousRight: AuthorizationRightSnapshot?,
        previousJob: LaunchdJobObservation,
        installedPolicy: AuthorizationRightPolicy,
        state: ExecutionState,
        store: ServiceJournalStore
    ) -> RollbackResult {
        if state.bootstrapAmbiguous {
            return RollbackResult(
                completed: false,
                rightMetadataChanged: false,
                detail: "a bootstrap command failed but a job with the fixed label is loaded, so this transaction cannot prove it created that job"
            )
        }

        // If the previous job was loaded and this transaction booted it out,
        // the previous registration cannot be re-created from a replaced file
        // set. Preserve the existing forward-recovery behavior: boot out a new
        // job, restore the right, and keep the journal. Do not write a terminal
        // rollback phase because the previous job state is not restored.
        let previousJobWasBootedOut: Bool
        if case .loaded = previousJob, state.bootoutVerified {
            previousJobWasBootedOut = true
        } else {
            previousJobWasBootedOut = false
        }
        if previousJobWasBootedOut {
            if state.bootstrapSucceeded, let failure = bootOutNewJobForRollback() {
                return RollbackResult(
                    completed: false,
                    rightMetadataChanged: false,
                    detail: failure
                )
            }
            let right = restoreRightForRollback(
                previousRight: previousRight,
                installedPolicy: installedPolicy,
                state: state
            )
            return RollbackResult(
                completed: false,
                rightMetadataChanged: right.metadataChanged,
                detail: right.detail
                    ?? "the previous launch daemon job was booted out and cannot be re-created from a replaced file set"
            )
        }

        // Record the rollback intent before the first rollback mutation. A
        // crash after this record must never let recovery install or roll
        // forward from a rollback that may already be restoring the previous
        // state.
        do {
            try store.write(journal.withPhase(.rollbackStarted))
        } catch {
            return RollbackResult(
                completed: false,
                rightMetadataChanged: false,
                detail: "the rollback record cannot be written: \(mapError(error).description)"
            )
        }
        do {
            try faults.check(.rollbackStartJournalWritten)
        } catch {
            return RollbackResult(
                completed: false,
                rightMetadataChanged: false,
                detail: "the rollback was interrupted after its record was written"
            )
        }

        // Boot out only a job whose bootstrap command this process saw succeed
        // and whose read-back it verified. A failed bootstrap is never followed
        // by a bootout.
        if state.bootstrapSucceeded, let failure = bootOutNewJobForRollback() {
            return RollbackResult(
                completed: false,
                rightMetadataChanged: false,
                detail: failure
            )
        }

        let right = restoreRightForRollback(
            previousRight: previousRight,
            installedPolicy: installedPolicy,
            state: state
        )
        guard right.completed else {
            return RollbackResult(
                completed: false,
                rightMetadataChanged: right.metadataChanged,
                detail: right.detail
            )
        }

        let finalJob: LaunchdJobObservation
        do {
            finalJob = try observeJobRaw()
        } catch {
            return RollbackResult(
                completed: false,
                rightMetadataChanged: right.metadataChanged,
                detail: "the final launch daemon state cannot be read"
            )
        }
        switch (previousJob, finalJob) {
        case (.absent, .absent):
            break
        case (.loaded, .loaded):
            break
        case (.loaded, .absent):
            return RollbackResult(
                completed: false,
                rightMetadataChanged: right.metadataChanged,
                detail: "the previous launch daemon job was booted out and cannot be re-created from a replaced file set"
            )
        case (.absent, .loaded):
            return RollbackResult(
                completed: false,
                rightMetadataChanged: right.metadataChanged,
                detail: "a launch daemon job is loaded but the previous state was absent"
            )
        default:
            return RollbackResult(
                completed: false,
                rightMetadataChanged: right.metadataChanged,
                detail: "the launch daemon job is not in its previous state"
            )
        }

        let rolledBackObservation: ServiceJournalObservation
        do {
            rolledBackObservation = try store.write(journal.withPhase(.rolledBack))
        } catch {
            return RollbackResult(
                completed: false,
                rightMetadataChanged: right.metadataChanged,
                detail: "the completed rollback record cannot be written: \(mapError(error).description)"
            )
        }
        do {
            try faults.check(.rollbackJournalWritten)
        } catch {
            return RollbackResult(
                completed: false,
                rightMetadataChanged: right.metadataChanged,
                detail: "the rollback was interrupted after its terminal record was written"
            )
        }
        do {
            try store.remove(rolledBackObservation)
        } catch {
            return RollbackResult(
                completed: false,
                rightMetadataChanged: right.metadataChanged,
                detail: "the service journal cannot be removed after the completed rollback"
            )
        }
        return RollbackResult(
            completed: true,
            rightMetadataChanged: right.metadataChanged,
            detail: nil
        )
    }

    private func bootOutNewJobForRollback() -> String? {
        let observation: LaunchdJobObservation
        do {
            observation = try observeJobRaw()
        } catch {
            return "the new launch daemon job state cannot be read"
        }
        switch observation {
        case .loaded:
            do { try runtime.launchd.bootout() } catch { }
            let after: LaunchdJobObservation
            do {
                after = try observeJobRaw()
            } catch {
                return "the new launch daemon job state cannot be read after bootout"
            }
            guard case .absent = after else {
                return "the new launch daemon job is still loaded"
            }
            return nil
        case .absent:
            return nil
        case .unexpected(let why):
            return "the new launch daemon job cannot be attributed: \(why)"
        case .unknown(let why):
            return "the new launch daemon job state cannot be proven: \(why)"
        }
    }

    private func restoreRightForRollback(
        previousRight: AuthorizationRightSnapshot?,
        installedPolicy: AuthorizationRightPolicy,
        state: ExecutionState
    ) -> RightRollbackResult {
        guard state.rightWriteAttempted || state.rightReplaced else {
            return RightRollbackResult(metadataChanged: false, detail: nil)
        }
        let observed: AuthorizationRightObservation
        do {
            observed = try observeRightForPreflight()
        } catch {
            return RightRollbackResult(
                metadataChanged: false,
                detail: "the start right cannot be observed for rollback"
            )
        }

        var metadataChanged = false
        let alreadyPrevious: Bool
        switch observed {
        case .present(let snapshot):
            if let previousRight, snapshot.policy == previousRight.policy {
                alreadyPrevious = true
                // The policy already matches, but authd may have added
                // metadata before or during the failed write. Report that byte
                // difference even though no restore command is needed.
                if snapshot.plist != previousRight.plist { metadataChanged = true }
            } else if snapshot.policy == installedPolicy {
                alreadyPrevious = false
            } else {
                return RightRollbackResult(
                    metadataChanged: false,
                    detail: "the start right holds an object the journal does not own"
                )
            }
        case .absent:
            alreadyPrevious = (previousRight == nil)
        }

        if !alreadyPrevious {
            if let previousRight {
                do { try runtime.authorizationRights.write(previousRight.plist) } catch { }
                let restored: AuthorizationRightObservation
                do {
                    restored = try observeRightForPreflight()
                } catch {
                    return RightRollbackResult(
                        metadataChanged: metadataChanged,
                        detail: "the previous start right cannot be read back"
                    )
                }
                guard case .present(let snapshot) = restored,
                      snapshot.policy == previousRight.policy
                else {
                    return RightRollbackResult(
                        metadataChanged: metadataChanged,
                        detail: "the previous start right could not be restored"
                    )
                }
                if snapshot.plist != previousRight.plist { metadataChanged = true }
            } else {
                do { try runtime.authorizationRights.remove() } catch { }
                let restored: AuthorizationRightObservation
                do {
                    restored = try observeRightForPreflight()
                } catch {
                    return RightRollbackResult(
                        metadataChanged: metadataChanged,
                        detail: "the removed start right cannot be read back"
                    )
                }
                guard case .absent = restored else {
                    return RightRollbackResult(
                        metadataChanged: metadataChanged,
                        detail: "the new start right could not be removed"
                    )
                }
            }
        }

        return RightRollbackResult(metadataChanged: metadataChanged, detail: nil)
    }

    private func mapError(_ error: Error) -> ServiceTransactionError {
        if let error = error as? ServiceTransactionError { return error }
        if let error = error as? ServiceJournalError {
            switch error {
            case .unreadable:
                return .serviceJournalUnreadable(error.description)
            case .unsafe:
                return .serviceJournalUnsafe(error.description)
            case .io:
                return .io(error.description)
            case .writeOutcomeUnknown:
                return .serviceJournalWriteOutcomeUnknown(error.description)
            case .removeOutcomeUnknown:
                return .serviceJournalRemoveOutcomeUnknown(error.description)
            }
        }
        if let error = error as? AuthorizationRightPolicyError {
            return .authorizationRightUnsafe(error.description)
        }
        if let error = error as? AuthorizationRightDatabaseError {
            switch error {
            case .readbackInvalid:
                return .authorizationRightUnsafe(error.description)
            case .unreadable:
                return .authorizationRightUnreadable(error.description)
            case .commandFailed:
                // A write or remove command failure is not an observation
                // failure. Name it as a command failure so the diagnostic does
                // not claim the start right cannot be observed.
                return .commandFailed(error.description)
            }
        }
        if let error = error as? LaunchdJobError {
            return .commandFailed(error.description)
        }
        if let error = error as? PrivilegedCommandError {
            return .commandFailed(error.description)
        }
        if let error = error as? PrivilegedServiceCommandError {
            return .commandFailed(error.description)
        }
        if let error = error as? InstallerError {
            return .installedFileUnsafe(error.description)
        }
        if let error = error as? InstallLockError {
            switch error {
            case .busy:
                return .lockUnavailable
            case .unsafeDirectory, .unsafeLockFile, .failed:
                return .lockUnsafe(error.description)
            }
        }
        return .io("an unexpected error occurred")
    }
}

private extension LaunchdJobObservation {
    var isLoaded: Bool {
        if case .loaded = self { return true }
        return false
    }
}
