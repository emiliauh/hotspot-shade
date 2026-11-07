import Foundation
import Darwin
import HotspotShadeKit

public enum CombinedInstallError: Error, Equatable, CustomStringConvertible {
    case liveRuntimeNotSupported
    case existingFile(String)
    case existingServiceState
    case stageCleanupFailed
    case installedFilesMismatch(String)

    public var description: String {
        switch self {
        case .liveRuntimeNotSupported:
            return "The live service is not available to this installer."
        case .existingFile:
            return "An installed file already exists. Use recovery or resume only after checking the existing installation."
        case .existingServiceState:
            return "The service or its authorization right is already present, or its state could not be established."
        case .stageCleanupFailed:
            return "The private staging copy could not be removed. Installation may already have completed; inspect the service state before retrying."
        case .installedFilesMismatch:
            return "The installed files do not match this preview. Service setup was not resumed."
        }
    }
}

struct CombinedInstallOutcome: Equatable {
    let files: InstallOutcome
    let service: ServiceInstallOutcome
}

// File and service transactions share the same exclusion lease. The public
// initializer is sandbox-only. The separate preview system initializer below
// stays disabled except in the explicit local system-preview test candidate.
public final class InstallCoordinator: @unchecked Sendable {
    public let sandboxRoot: String
    // The journal store seam exists for the hermetic post-rename and ordinary
    // pre-rename tests. It stays internal. Production callers use the public
    // initializer above.
    typealias JournalStoreFactory = @Sendable (InstallTree) -> InstallJournalStore
    typealias TreeFactory = @Sendable (String, UInt32) throws -> InstallTree

    private let expectedOwner: UInt32
    private let validator: InstallerValidator
    private let faults: CoordinatorFaultInjecting
    private let journalStoreFactory: JournalStoreFactory
    private let treeFactory: TreeFactory

    public convenience init(
        sandboxRoot: String,
        validator: InstallerValidator = InstallerValidator(),
        faults: CoordinatorFaultInjecting = NoFaults(),
        effectiveUserID: UInt32 = UInt32(geteuid()),
        temporaryDirectory: String = NSTemporaryDirectory()
    ) throws {
        try self.init(
            sandboxRoot: sandboxRoot,
            validator: validator,
            faults: faults,
            effectiveUserID: effectiveUserID,
            temporaryDirectory: temporaryDirectory,
            journalStoreFactory: { InstallJournalStore(tree: $0) },
            treeFactory: { try InstallTree(rootPath: $0, expectedOwner: $1) }
        )
    }

    // The journal store and tree seams exist for the hermetic post-rename and
    // ordinary pre-rename tests. Production callers use the initializer above.
    init(
        sandboxRoot: String,
        validator: InstallerValidator = InstallerValidator(),
        faults: CoordinatorFaultInjecting = NoFaults(),
        effectiveUserID: UInt32 = UInt32(geteuid()),
        temporaryDirectory: String = NSTemporaryDirectory(),
        journalStoreFactory: @escaping JournalStoreFactory,
        treeFactory: @escaping TreeFactory = { try InstallTree(rootPath: $0, expectedOwner: $1) }
    ) throws {
        guard effectiveUserID != 0 else { throw CoordinatorError.runningAsRoot }
        guard CoordinatorPolicy.liveInstallationApproved == false else {
            throw CoordinatorError.notApproved
        }
        self.sandboxRoot = try CoordinatorSandboxPolicy.validate(
            sandboxRoot,
            effectiveUserID: effectiveUserID,
            temporaryDirectory: temporaryDirectory
        )
        self.expectedOwner = effectiveUserID
        self.validator = validator
        self.faults = faults
        self.journalStoreFactory = journalStoreFactory
        self.treeFactory = treeFactory
    }

    static func previewSystem() throws -> InstallCoordinator {
        guard HelperRequirement.isLocalPreview, CoordinatorPolicy.localPreviewInstallationApproved else {
            throw CoordinatorError.notApproved
        }
        guard geteuid() == 0 else { throw ServiceTransactionError.requiresRoot }
        return InstallCoordinator(previewSystemRoot: ())
    }

    // The system install writes root:wheel files. The helper trust check refuses
    // an executable whose group is not wheel, so the group is set and verified
    // rather than inherited from the process or the parent directory.
    static let systemOwner: UInt32 = 0
    static let systemGroup: UInt32 = 0

    private init(previewSystemRoot: Void) {
        self.sandboxRoot = "/"
        self.expectedOwner = Self.systemOwner
        self.validator = InstallerValidator()
        self.faults = NoFaults()
        self.journalStoreFactory = { InstallJournalStore(tree: $0) }
        self.treeFactory = { root, owner in
            try InstallTree(
                rootPath: root,
                expectedOwner: owner,
                expectedGroup: Self.systemGroup,
                syncHooks: .production,
                usePrivateVar: true
            )
        }
    }

    private func checkRuntime(_ runtime: PrivilegedServiceRuntime) throws {
        guard runtime.isLiveSystem else { return }
        guard CoordinatorPolicy.systemOperationsApproved, expectedOwner == 0,
              sandboxRoot == "/", geteuid() == 0 else {
            throw CombinedInstallError.liveRuntimeNotSupported
        }
    }

    public func install(source: CoordinatorSource) throws -> InstallOutcome {
        try install(source: source, using: nil)
    }

    // Exercise a first installation as two existing transactions under one
    // exclusion lease. A failure after the file commit
    // can leave the new files in place, so it is not an atomic transaction.
    // Existing installations are refused until their recovery is integrated.
    func installFirstTime(
        source: CoordinatorSource,
        runtime: PrivilegedServiceRuntime,
        serviceFaults: ServiceTransactionFaultInjecting = NoServiceFaults()
    ) throws -> CombinedInstallOutcome {
        try checkRuntime(runtime)
        let tree = try treeFactory(sandboxRoot, expectedOwner)
        try prepareStateDirectory(tree)
        let lease = try acquireExclusionLease(tree)
        defer { lease.release() }
        try preflight(tree, store: journalStoreFactory(tree), lock: lease)

        for entry in InstallerLayout.entries {
            let destination = InstallJournal.relativeDestination(entry.destination)
            let exists: Bool
            do {
                exists = try tree.entryExists(destination)
            } catch {
                throw mapError(error)
            }
            if exists { throw CombinedInstallError.existingFile(destination) }
        }
        guard case .absent = try runtime.authorizationRights.observe(),
              case .absent = try runtime.launchd.observe() else {
            throw CombinedInstallError.existingServiceState
        }

        let copied = try PreviewPayloadCopy.copy(source: source, into: tree, validator: validator)
        let outcome: CombinedInstallOutcome
        do {
            let files = try install(source: copied.source, using: lease)
            let service = try PrivilegedServiceTransaction(
                tree: tree,
                runtime: runtime,
                faults: serviceFaults,
                validator: validator,
                expectedTeamIdentifier: source.expectedTeamIdentifier,
                effectiveUserID: expectedOwner
            ).apply(installTransactionID: files.transactionID, using: lease)
            outcome = CombinedInstallOutcome(files: files, service: service)
        } catch {
            do { try PreviewPayloadCopy.remove(copied, from: tree) }
            catch { throw CombinedInstallError.stageCleanupFailed }
            throw error
        }
        do { try PreviewPayloadCopy.remove(copied, from: tree) }
        catch { throw CombinedInstallError.stageCleanupFailed }
        return outcome
    }

    // Resume a first install whose file transaction committed but whose
    // service transaction rolled back. A journal, a live service, a partial
    // file set, or bytes different from the validated payload all block it.
    func resumeFirstTime(
        source: CoordinatorSource,
        runtime: PrivilegedServiceRuntime
    ) throws -> ServiceInstallOutcome {
        try checkRuntime(runtime)
        let tree = try treeFactory(sandboxRoot, expectedOwner)
        try prepareStateDirectory(tree)
        let lease = try acquireExclusionLease(tree)
        defer { lease.release() }
        try preflight(tree, store: journalStoreFactory(tree), lock: lease)
        guard case .absent = try runtime.authorizationRights.observe(),
              case .absent = try runtime.launchd.observe() else {
            throw CombinedInstallError.existingServiceState
        }
        let copied = try PreviewPayloadCopy.copy(source: source, into: tree, validator: validator)
        let service: ServiceInstallOutcome
        do {
            let operations = try CoordinatorPayloadValidator.validate(
                copied.source, validator: validator, expectedOwner: expectedOwner
            )
            for operation in operations {
                // A wrong owner, group, link count, mode, or access control list
                // is not a resumable file set. Resume must not report success
                // when the installed file is incompatible with the layout.
                let current: FileSnapshot?
                do {
                    current = try tree.snapshot(
                        operation.destinationRelative, maximumBytes: operation.size
                    )
                } catch {
                    throw CombinedInstallError.installedFilesMismatch(
                        operation.destinationRelative
                    )
                }
                guard let current,
                      current.sha256 == operation.sha256, current.size == operation.size,
                      current.mode == operation.mode else {
                    throw CombinedInstallError.installedFilesMismatch(operation.destinationRelative)
                }
            }
            service = try PrivilegedServiceTransaction(
                tree: tree, runtime: runtime, validator: validator,
                expectedTeamIdentifier: source.expectedTeamIdentifier, effectiveUserID: expectedOwner
            ).apply(using: lease)
        } catch {
            do { try PreviewPayloadCopy.remove(copied, from: tree) }
            catch { throw CombinedInstallError.stageCleanupFailed }
            throw error
        }
        do { try PreviewPayloadCopy.remove(copied, from: tree) }
        catch { throw CombinedInstallError.stageCleanupFailed }
        return service
    }

    // Service recovery must retain the same exclusion set used for the file
    // transaction. The service transaction itself refuses an install journal
    // or runtime marker before it attempts a service action.
    func recoverFirstTimeService(
        runtime: PrivilegedServiceRuntime,
        teamIdentifier: String
    ) throws -> ServiceRecoveryOutcome {
        try checkRuntime(runtime)
        let tree = try treeFactory(sandboxRoot, expectedOwner)
        try prepareStateDirectory(tree)
        let lease = try acquireExclusionLease(tree)
        defer { lease.release() }
        return try PrivilegedServiceTransaction(
            tree: tree, runtime: runtime, validator: validator,
            expectedTeamIdentifier: teamIdentifier, effectiveUserID: expectedOwner
        ).recover(using: lease)
    }

    // A combined installer can retain one exclusion lease across the file and
    // service transactions. The caller owns a supplied lease and must keep it
    // held until both transactions and any required recovery have finished.
    // A shared lease prevents interleaving; it does not make the two journals
    // a single atomic transaction.
    func install(source: CoordinatorSource, using lease: InstallExclusionLease?) throws -> InstallOutcome {
        try run {
            let tree = try treeFactory(sandboxRoot, expectedOwner)
            try prepareStateDirectory(tree)
            let lock = try validateOrAcquireExclusionLease(lease, tree: tree)
            defer { if lease == nil { lock.release() } }

            let store = journalStoreFactory(tree)
            try preflight(tree, store: store, lock: lock)

            let operations = try CoordinatorPayloadValidator.validate(
                source,
                validator: validator,
                expectedOwner: expectedOwner
            )
            let transactionID = SystemSupport.randomHex(byteCount: 16)
            let previous = try previousRecords(
                tree,
                operations: operations,
                teamIdentifier: source.expectedTeamIdentifier
            )
            let createdDirectories = try plannedCreatedDirectories(tree, transactionID: transactionID)
            let journal = InstallJournal(
                schemaVersion: InstallJournal.currentSchemaVersion,
                transactionID: transactionID,
                fromVersion: nil,
                toVersion: source.manifest.version,
                teamIdentifier: source.expectedTeamIdentifier,
                phase: .preparing,
                createdDirectories: createdDirectories,
                operations: previous.map { record in
                    InstallJournal.Operation(
                        index: record.operation.index,
                        artifact: record.operation.artifact,
                        destination: record.operation.destinationRelative,
                        newSHA256: record.operation.sha256,
                        newSize: record.operation.size,
                        newMode: record.operation.mode,
                        previousPresent: record.previous != nil,
                        previousSHA256: record.previous?.sha256,
                        previousSize: record.previous?.size,
                        previousMode: record.previous?.mode
                    )
                }
            )
            try journal.validate()

            try store.removeTemporaryFiles()
            try store.write(journal)
            try faults.check(.journalPrepared)

            for (directory, mode) in try requiredDirectories(tree, transactionID: transactionID) {
                _ = try tree.ensureDirectory(directory, mode: mode, create: true)
            }
            try faults.check(.directoriesCreated)

            let replacing = journal.withPhase(.replacing)
            do {
                try store.write(replacing)
            } catch {
                let coordinatorError = mapError(error)
                // An unknown outcome is not a clean failure. The visible record
                // may be `preparing` or `replacing`, and only recovery may
                // decide which one is durable. Do not touch a file.
                if case .journalWriteUncertain = coordinatorError { throw coordinatorError }
                // A pre-rename failure leaves a visible `preparing` record and
                // no file has moved. Confirm the exact record durably before
                // the rollback removes anything, then roll back that known
                // state instead of leaving a journal for a clean failure.
                let observed: InstallJournalObservation
                do {
                    observed = try confirmJournalForRollback(
                        store,
                        transactionID: transactionID,
                        operations: journal.operations
                    )
                } catch {
                    let mapped = mapError(error)
                    if case .journalWriteUncertain = mapped { throw mapped }
                    throw CoordinatorError.recoveryRequired(
                        "the install failed before replacement and its journal could not "
                            + "be durably confirmed: \(failureReason(mapped))"
                    )
                }
                let rollbackError = performRollback(
                    tree,
                    observed: observed,
                    store: store,
                    faults: NoFaults()
                )
                if let rollbackError {
                    throw CoordinatorError.recoveryRequired(
                        "the install failed before replacement and rollback failed: "
                            + "\(failureReason(rollbackError))"
                    )
                }
                throw coordinatorError
            }
            try faults.check(.replacementStarted)

            var committed = false
            do {
                for record in previous {
                    let operation = record.operation
                    if let old = record.previous {
                        try tree.moveToBackup(
                            operation.destinationRelative,
                            backupRelative: replacing.backupRelativePath(for: replacing.operations[operation.index]),
                            expected: old
                        )
                    }
                    if let step = CoordinatorStep.backupMoved(operation.index) {
                        try faults.check(step)
                    }
                    let expected = FileSnapshot(
                        sha256: operation.sha256,
                        size: operation.size,
                        mode: operation.mode
                    )
                    try tree.copyFromFile(
                        sourcePath: operation.sourcePath,
                        expected: expected,
                        to: operation.destinationRelative,
                        mode: mode_t(operation.mode),
                        temporarySuffix: InstallJournal.temporarySuffix(
                            transactionID: transactionID,
                            index: operation.index
                        )
                    )
                    if let step = CoordinatorStep.fileInstalled(operation.index) {
                        try faults.check(step)
                    }
                }
                try verifyNewSet(tree, journal: replacing)
                try faults.check(.replacementVerified)

                let committedJournal = replacing.withPhase(.committed)
                let committedObservation = try store.write(committedJournal)
                committed = true
                try faults.check(.commitJournalWritten)
                try finishCommitted(
                    tree,
                    observed: committedObservation,
                    store: store,
                    journalRemovedStep: .journalRemoved
                )
                return InstallOutcome(
                    transactionID: transactionID,
                    version: journal.toVersion,
                    fileCount: journal.operations.count,
                    createdDirectories: journal.createdDirectories
                )
            } catch {
                let coordinatorError = mapError(error)
                if case .simulatedCrash = coordinatorError { throw coordinatorError }
                // A journal write that may have renamed a committed record is
                // not rolled back in process. The old in-memory phase cannot
                // prove what is durable, and a rollback under a durable
                // `committed` record would leave files that can never recover.
                // Stop every file mutation and keep the journal and backups.
                if case .journalWriteUncertain = coordinatorError { throw coordinatorError }
                if case .fileWriteUncertain = coordinatorError { throw coordinatorError }
                if committed {
                    throw CoordinatorError.recoveryRequired(
                        "the committed set did not finish cleanup: "
                            + "\(failureReason(coordinatorError))"
                    )
                }
                let observed: InstallJournalObservation
                do {
                    observed = try confirmJournalForRollback(
                        store,
                        transactionID: transactionID,
                        operations: journal.operations
                    )
                } catch {
                    let mapped = mapError(error)
                    if case .journalWriteUncertain = mapped { throw mapped }
                    throw CoordinatorError.recoveryRequired(
                        "the install failed and its journal could not be durably "
                            + "confirmed for rollback: \(failureReason(mapped))"
                    )
                }
                let rollbackError = performRollback(
                    tree,
                    observed: observed,
                    store: store,
                    faults: NoFaults()
                )
                if let rollbackError {
                    throw CoordinatorError.recoveryRequired(
                        "the install failed and rollback failed: "
                            + "\(failureReason(rollbackError))"
                    )
                }
                throw coordinatorError
            }
        }
    }

    public func recover() throws -> RecoveryOutcome {
        try recover(using: nil)
    }

    func recover(using lease: InstallExclusionLease?) throws -> RecoveryOutcome {
        try run {
            let tree = try treeFactory(sandboxRoot, expectedOwner)
            try prepareStateDirectory(tree)
            let lock = try validateOrAcquireExclusionLease(lease, tree: tree)
            defer { if lease == nil { lock.release() } }
            let store = journalStoreFactory(tree)
            try refuseRuntimeMarkers(tree)
            try refuseStartJournal(tree, lock: lock)
            try refuseServiceJournal(tree)

            guard let observed = try store.readObserved() else {
                let orphans = try store.hasOrphanBackupDirectories()
                if !orphans.isEmpty {
                    throw CoordinatorError.orphanArtifacts(orphans.joined(separator: ", "))
                }
                try store.removeTemporaryFiles()
                return .nothingToRecover
            }
            let journal = observed.journal
            // No recovery action may depend on a phase record that is only
            // visible in the namespace. Rewrite the exact observed bytes
            // through the atomic seam and require its file and parent sync.
            // An unknown confirmation stops before the first mutation, so the
            // journal and every backup are kept.
            do {
                try store.confirm(observed)
            } catch {
                let mapped = mapError(error)
                if case .journalWriteUncertain = mapped { throw mapped }
                throw CoordinatorError.recoveryRequired(
                    "the install journal could not be durably confirmed before recovery: "
                        + "\(failureReason(mapped))"
                )
            }

            if journal.phase == .committed {
                do {
                    try verifyNewSet(tree, journal: journal)
                } catch {
                    throw CoordinatorError.committedStateDamaged(
                        failureReason(mapError(error))
                    )
                }
                do {
                    try faults.check(.recoveryVerified)
                } catch {
                    throw mapError(error)
                }
                do {
                    try finishCommitted(
                        tree,
                        observed: observed,
                        store: store,
                        journalRemovedStep: .recoveryJournalRemoved
                    )
                } catch {
                    throw CoordinatorError.recoveryRequired(
                        failureReason(mapError(error))
                    )
                }
                return .finishedCommit(
                    transactionID: journal.transactionID,
                    version: journal.toVersion
                )
            }

            let rollbackError = performRollback(
                tree,
                observed: observed,
                store: store,
                faults: faults
            )
            if let rollbackError {
                if case .simulatedCrash = rollbackError { throw rollbackError }
                throw CoordinatorError.recoveryRequired(failureReason(rollbackError))
            }
            return .rolledBack(
                transactionID: journal.transactionID,
                version: journal.toVersion
            )
        }
    }

    public func status() throws -> CoordinatorStatus {
        try run {
            let tree = try treeFactory(sandboxRoot, expectedOwner)
            let store = journalStoreFactory(tree)
            let journal = try store.read()
            let blocked = try tree.entryExists(
                InstallLockLayout.stateDirectoryRelative + "/" + InstallLockLayout.cleanupMarkerName
            )
            let intent = try tree.entryExists(
                InstallLockLayout.stateDirectoryRelative + "/" + InstallLockLayout.launchIntentName
            )
            let startJournal = try StartJournalProbe.read(tree)
            let statePath = try tree.path(for: InstallLockLayout.stateDirectoryRelative)
            var identities: [String: InstallLock.Identity] = [:]
            for name in InstallLockLayout.heldFileNames {
                if let identity = try InstallLock.identity(
                    parentDirectory: statePath,
                    fileName: name,
                    expectedOwner: expectedOwner
                ) {
                    identities[name] = identity
                }
            }
            let matches: Bool? = startJournal.map { record in
                identities.values.contains {
                    $0.device == record.lockDevice && $0.inode == record.lockInode
                }
            }
            let orphans = try store.hasOrphanBackupDirectories()
            let presentNames = InstallLockLayout.heldFileNames.filter { identities[$0] != nil }
            return CoordinatorStatus(
                journalPhase: journal?.phase,
                serviceJournalPresent: try tree.entryExists(ServiceJournalStore.relativePath),
                cleanupBlocked: blocked,
                launchIntentPresent: intent,
                startJournalPresent: startJournal != nil,
                startJournalLockMatchesHeldLock: matches,
                backupOrphans: orphans,
                presentLockFileNames: presentNames,
                lockFilePresent: identities[InstallLockLayout.fileName] != nil
            )
        }
    }

    // MARK: private

    private struct PreviousRecord {
        let operation: CoordinatorOperation
        let previous: FileSnapshot?
    }

    private func prepareStateDirectory(_ tree: InstallTree) throws {
        for parent in ["var", "var/db"] {
            _ = try tree.ensureDirectory(parent, mode: 0o755, create: true)
        }
        _ = try tree.ensureDirectory(
            InstallLockLayout.stateDirectoryRelative,
            mode: 0o700,
            create: true
        )
        guard try tree.directoryMode(InstallLockLayout.stateDirectoryRelative) == 0o700 else {
            throw CoordinatorError.unsafeDirectory(InstallLockLayout.stateDirectory)
        }
    }

    private func acquireExclusionLease(_ tree: InstallTree) throws -> InstallExclusionLease {
        let statePath = try tree.path(for: InstallLockLayout.stateDirectoryRelative)
        do {
            return try InstallExclusionLease.acquire(
                parentDirectory: statePath,
                fileNames: InstallLockLayout.heldFileNames,
                expectedOwner: expectedOwner
            )
        } catch InstallLockError.busy {
            throw CoordinatorError.lockUnavailable
        } catch let error as InstallLockError {
            throw CoordinatorError.io(error.description)
        } catch {
            throw CoordinatorError.io("the install lock cannot be opened")
        }
    }

    private func validateOrAcquireExclusionLease(
        _ lease: InstallExclusionLease?, tree: InstallTree
    ) throws -> InstallExclusionLease {
        guard let lease else { return try acquireExclusionLease(tree) }
        guard lease.locks.allSatisfy({ $0.isHeld }) else {
            throw CoordinatorError.lockUnavailable
        }
        let statePath = try tree.path(for: InstallLockLayout.stateDirectoryRelative)
        do {
            for name in InstallLockLayout.heldFileNames {
                guard let current = try InstallLock.identity(
                    parentDirectory: statePath, fileName: name, expectedOwner: expectedOwner
                ), let held = lease.fileNameByIdentity[name], held == current else {
                    throw CoordinatorError.lockUnavailable
                }
            }
        } catch let error as CoordinatorError {
            throw error
        } catch {
            throw CoordinatorError.io("the passed lease does not hold the state directory locks")
        }
        return lease
    }

    private func preflight(
        _ tree: InstallTree,
        store: InstallJournalStore,
        lock: InstallExclusionLease
    ) throws {
        try refuseRuntimeMarkers(tree)
        try refuseStartJournal(tree, lock: lock)
        try refuseServiceJournal(tree)
        if try store.read() != nil {
            throw CoordinatorError.journalPresent
        }
        let orphans = try store.hasOrphanBackupDirectories()
        if !orphans.isEmpty {
            throw CoordinatorError.orphanArtifacts(orphans.joined(separator: ", "))
        }
    }

    // A crash can leave these records even after its lock holder exits. File
    // recovery must not replace or roll back a binary while either remains.
    private func refuseRuntimeMarkers(_ tree: InstallTree) throws {
        if try tree.entryExists(
            InstallLockLayout.stateDirectoryRelative + "/" + InstallLockLayout.cleanupMarkerName
        ) {
            _ = try tree.snapshot(
                InstallLockLayout.stateDirectoryRelative + "/" + InstallLockLayout.cleanupMarkerName,
                maximumBytes: 4096
            )
            throw CoordinatorError.cleanupBlocked
        }
        if try tree.entryExists(
            InstallLockLayout.stateDirectoryRelative + "/" + InstallLockLayout.launchIntentName
        ) {
            _ = try tree.snapshot(
                InstallLockLayout.stateDirectoryRelative + "/" + InstallLockLayout.launchIntentName,
                maximumBytes: 4096
            )
            throw CoordinatorError.launchIntentPresent
        }
    }

    // A service transaction can still refer to the installed files. Until a
    // reviewed two-journal recovery protocol exists, neither a file install
    // nor file rollback may proceed while its journal is present. A symlink
    // or other object at the fixed name also blocks; this check deletes none.
    private func refuseServiceJournal(_ tree: InstallTree) throws {
        if try tree.entryExists(ServiceJournalStore.relativePath) {
            throw CoordinatorError.recoveryRequired(
                "a service transaction journal is present; resolve it before file recovery"
            )
        }
    }

    // A start journal is a refusal record for an engine that may still own
    // routes. The coordinator never removes it. If it names a different lock
    // inode from the canonical lock, a participant is not actually excluded by
    // the coordinator's lock, so the mismatch is reported separately.
    private func refuseStartJournal(_ tree: InstallTree, lock: InstallExclusionLease) throws {
        guard let record = try StartJournalProbe.read(tree) else { return }
        if lock.holdsIdentity(device: record.lockDevice, inode: record.lockInode) {
            throw CoordinatorError.startJournalPresent
        }
        throw CoordinatorError.participantLockIncompatible(
            "the start journal records device \(record.lockDevice), inode \(record.lockInode); "
                + "the coordinator holds \(lock.locks.count) known lock inodes and none matches"
        )
    }

    private func previousRecords(
        _ tree: InstallTree,
        operations: [CoordinatorOperation],
        teamIdentifier: String
    ) throws -> [PreviousRecord] {
        var records: [PreviousRecord] = []
        for operation in operations {
            let maximum = maximumSize(forArtifact: operation.artifact)
            let snapshot: FileSnapshot?
            do {
                snapshot = try tree.snapshot(
                    operation.destinationRelative,
                    maximumBytes: maximum
                )
            } catch let error as InstallTreeError {
                throw CoordinatorError.existingFileUnsafe("\(error.path): \(describe(error))")
            }
            if let snapshot {
                guard snapshot.mode == operation.mode else {
                    throw CoordinatorError.existingFileUnsafe(
                        "\(operation.destinationRelative) has a mode that the layout does not expect"
                    )
                }
                do {
                    try validateInstalledArtifact(
                        tree,
                        artifact: operation.artifact,
                        destinationRelative: operation.destinationRelative,
                        teamIdentifier: teamIdentifier
                    )
                } catch let error as CoordinatorError {
                    throw CoordinatorError.existingFileUnsafe(error.description)
                }
            }
            records.append(PreviousRecord(operation: operation, previous: snapshot))
        }
        return records
    }

    private func plannedCreatedDirectories(
        _ tree: InstallTree,
        transactionID: String
    ) throws -> [String] {
        // System parents that must already exist. The coordinator never creates
        // a directory above the fixed layout, so a host without one of these
        // fails closed.
        for parent in Self.requiredParents {
            _ = try tree.ensureDirectory(parent, mode: 0o755, create: false)
        }
        for parent in Self.creatableParents {
            if try tree.entryExists(parent) {
                _ = try tree.ensureDirectory(parent, mode: 0o755, create: false)
            } else {
                // A clean macOS host can lack the helper directory. Only its
                // own parent must exist, so the later create cannot walk above
                // the layout. This directory is not recorded in the journal;
                // see requiredDirectories.
                _ = try tree.ensureDirectory(
                    Self.parent(of: parent), mode: 0o755, create: false
                )
            }
        }
        var planned: [String] = []
        for (directory, mode) in try directoryPlan(transactionID: transactionID) {
            if try tree.entryExists(directory) {
                _ = try tree.ensureDirectory(directory, mode: mode, create: false)
            } else {
                planned.append(directory)
            }
        }
        return planned
    }

    private func requiredDirectories(
        _ tree: InstallTree,
        transactionID: String
    ) throws -> [(String, mode_t)] {
        // Recheck each creatable directory's parent with create disabled, then
        // let ensureDirectory create only the missing leaf. An existing
        // directory is checked and never changed.
        var plan: [(String, mode_t)] = []
        for parent in Self.creatableParents {
            _ = try tree.ensureDirectory(Self.parent(of: parent), mode: 0o755, create: false)
            plan.append((parent, 0o755))
        }
        plan.append(contentsOf: try directoryPlan(transactionID: transactionID))
        return plan
    }

    // Parents that every supported macOS host already has. A missing one is a
    // host the installer does not understand, so it fails closed.
    private static let requiredParents = [
        "Library",
        "Library/Application Support",
        "Library/LaunchDaemons",
        "var",
        "var/db",
    ]

    // The helper directory is the one system directory a clean host can lack.
    // The package postinstall also creates it when it is absent. It is created
    // 0755, checked through its descriptor, and never recorded in the install
    // journal, so a rollback leaves an empty standard directory behind.
    private static let creatableParents = [
        InstallJournal.relativeDestination(InstallerLayout.helperInstallRoot),
    ]

    private static func parent(of relative: String) -> String {
        (relative as NSString).deletingLastPathComponent
    }

    private func directoryPlan(transactionID: String) throws -> [(String, mode_t)] {
        [
            (InstallJournal.installRootRelative, 0o755),
            (InstallJournal.installRootRelative + "/engine", 0o755),
            (InstallJournal.installRootRelative + "/install-support", 0o755),
            (InstallJournalStore.backupRootRelative, 0o700),
            (InstallJournal.backupDirectoryRelativePath(transactionID: transactionID), 0o700),
        ]
    }

    private func verifyNewSet(_ tree: InstallTree, journal: InstallJournal) throws {
        for operation in journal.operations {
            let maximum = max(operation.newSize, maximumSize(forArtifact: operation.artifact))
            guard let snapshot = try tree.snapshot(
                operation.destination,
                maximumBytes: maximum
            ), snapshot.sha256 == operation.newSHA256,
               snapshot.size == operation.newSize,
               snapshot.mode == operation.newMode
            else {
                throw CoordinatorError.digestMismatch(operation.destination)
            }
            try validateInstalledArtifact(
                tree,
                artifact: operation.artifact,
                destinationRelative: operation.destination,
                teamIdentifier: journal.teamIdentifier
            )
        }
    }

    private func verifyPreviousSet(_ tree: InstallTree, journal: InstallJournal) throws {
        for operation in journal.operations {
            if operation.previousPresent {
                guard let digest = operation.previousSHA256,
                      let size = operation.previousSize,
                      let mode = operation.previousMode
                else { throw CoordinatorError.journalUnsafe("a previous record is incomplete") }
                let expected = FileSnapshot(sha256: digest, size: size, mode: mode)
                guard let snapshot = try tree.snapshot(
                    operation.destination,
                    maximumBytes: max(size, maximumSize(forArtifact: operation.artifact))
                ), snapshot == expected
                else {
                    throw CoordinatorError.recoveryRequired(
                        "\(operation.destination) does not match the previous file record"
                    )
                }
                try validateInstalledArtifact(
                    tree,
                    artifact: operation.artifact,
                    destinationRelative: operation.destination,
                    teamIdentifier: journal.teamIdentifier
                )
            } else {
                let maximum = maximumSize(forArtifact: operation.artifact)
                guard try tree.snapshot(operation.destination, maximumBytes: maximum) == nil else {
                    throw CoordinatorError.recoveryRequired(
                        "\(operation.destination) exists but the journal says it did not"
                    )
                }
            }
        }
    }

    private func validateInstalledArtifact(
        _ tree: InstallTree,
        artifact: String,
        destinationRelative: String,
        teamIdentifier: String
    ) throws {
        let path = try tree.path(for: destinationRelative)
        switch artifact {
        case InstallerArtifact.helper.rawValue:
            do {
                try validator.validateExecutable(
                    atPath: path,
                    artifact: .helper,
                    identifier: HelperRequirement.helperIdentifier,
                    teamIdentifier: teamIdentifier
                )
            } catch let error as InstallerError {
                throw CoordinatorError.artifactRejected(error.description)
            } catch {
                throw CoordinatorError.artifactRejected("the helper signature cannot be checked")
            }
        case InstallerArtifact.engine.rawValue:
            do {
                try validator.validateExecutable(
                    atPath: path,
                    artifact: .engine,
                    identifier: HelperRequirement.engineIdentifier,
                    teamIdentifier: teamIdentifier
                )
            } catch let error as InstallerError {
                throw CoordinatorError.artifactRejected(error.description)
            } catch {
                throw CoordinatorError.artifactRejected("the engine signature cannot be checked")
            }
        case InstallerArtifact.launchDaemon.rawValue:
            guard let data = try tree.readFile(
                destinationRelative,
                maximumBytes: ArtifactIngest.maximumPlistBytes
            ) else { throw CoordinatorError.artifactRejected("the launch daemon file is missing") }
            do {
                try validator.validateLaunchDaemon(data)
            } catch let error as InstallerError {
                throw CoordinatorError.artifactRejected(error.description)
            } catch {
                throw CoordinatorError.artifactRejected("the launch daemon file cannot be checked")
            }
        case InstallerArtifact.startRight.rawValue:
            guard let data = try tree.readFile(
                destinationRelative,
                maximumBytes: ArtifactIngest.maximumPlistBytes
            ) else { throw CoordinatorError.artifactRejected("the start right is missing") }
            do {
                try validator.validateStartRight(data)
            } catch let error as InstallerError {
                throw CoordinatorError.artifactRejected(error.description)
            } catch {
                throw CoordinatorError.artifactRejected("the start right cannot be checked")
            }
        default:
            throw CoordinatorError.journalUnsafe("an operation names an unknown artifact")
        }
    }

    private func maximumSize(forArtifact artifact: String) -> Int {
        switch artifact {
        case InstallerArtifact.helper.rawValue, InstallerArtifact.engine.rawValue:
            return ArtifactIngest.maximumExecutableBytes
        case InstallerArtifact.launchDaemon.rawValue, InstallerArtifact.startRight.rawValue:
            return ArtifactIngest.maximumPlistBytes
        default:
            return 0
        }
    }

    // The in-process rollback must not act on an in-memory phase. It confirms
    // the exact visible record durably first, then uses that observation for
    // the final removal. A changed transaction or operation list is refused.
    private func confirmJournalForRollback(
        _ store: InstallJournalStore,
        transactionID: String,
        operations: [InstallJournal.Operation]
    ) throws -> InstallJournalObservation {
        guard let observed = try store.readObserved() else {
            throw CoordinatorError.recoveryRequired(
                "the install journal disappeared before its rollback could be confirmed"
            )
        }
        guard observed.journal.transactionID == transactionID,
              observed.journal.operations == operations,
              observed.journal.phase == .preparing || observed.journal.phase == .replacing
        else {
            throw CoordinatorError.recoveryRequired(
                "the install journal no longer matches the transaction this run recorded"
            )
        }
        do {
            try store.confirm(observed)
        } catch {
            throw mapError(error)
        }
        return observed
    }

    private func finishCommitted(
        _ tree: InstallTree,
        observed: InstallJournalObservation,
        store: InstallJournalStore,
        journalRemovedStep: CoordinatorStep
    ) throws {
        let journal = observed.journal
        guard journal.phase == .committed else {
            throw CoordinatorError.journalUnsafe(
                "the committed cleanup received a record that is not committed"
            )
        }
        for operation in journal.operations where operation.previousPresent {
            _ = try tree.removeFile(
                journal.backupRelativePath(for: operation),
                expectedDigest: operation.previousSHA256
            )
        }
        _ = try tree.removeDirectoryIfEmpty(
            InstallJournal.backupDirectoryRelativePath(transactionID: journal.transactionID),
            expectedMode: 0o700
        )
        try faults.check(.backupsRemoved)
        try store.removeTemporaryFiles()
        try store.remove(observed)
        try faults.check(journalRemovedStep)
    }

    private func performRollback(
        _ tree: InstallTree,
        observed: InstallJournalObservation,
        store: InstallJournalStore,
        faults: CoordinatorFaultInjecting
    ) -> CoordinatorError? {
        do {
            let journal = observed.journal
            for operation in journal.operations.reversed() {
                let backup = journal.backupRelativePath(for: operation)
                let backupSnapshot = try tree.snapshot(
                    backup,
                    maximumBytes: max(
                        operation.previousSize ?? 0,
                        maximumSize(forArtifact: operation.artifact)
                    )
                )
                let destinationSnapshot = try tree.snapshot(
                    operation.destination,
                    maximumBytes: max(
                        operation.newSize,
                        max(operation.previousSize ?? 0, maximumSize(forArtifact: operation.artifact))
                    )
                )

                if operation.previousPresent {
                    guard let digest = operation.previousSHA256,
                          let size = operation.previousSize,
                          let mode = operation.previousMode
                    else { throw CoordinatorError.journalUnsafe("a previous record is incomplete") }
                    let previous = FileSnapshot(sha256: digest, size: size, mode: mode)
                    let installed = FileSnapshot(
                        sha256: operation.newSHA256,
                        size: operation.newSize,
                        mode: operation.newMode
                    )
                    if let destinationSnapshot, destinationSnapshot == previous {
                        // The previous file is already in place. Only the
                        // verified backup is left to remove.
                        if let backupSnapshot {
                            guard backupSnapshot == previous else {
                                throw CoordinatorError.journalUnsafe(
                                    "\(backup) does not match the previous record"
                                )
                            }
                            _ = try tree.removeFile(backup, expectedDigest: digest)
                        }
                    } else if let destinationSnapshot, destinationSnapshot != installed {
                        // The destination holds neither the file this
                        // transaction found nor the file it installed. The
                        // object belongs to something else, so it is never
                        // replaced. The journal and the backup stay for a
                        // person to inspect.
                        throw CoordinatorError.recoveryRequired(
                            "\(operation.destination) holds an object that is neither the previous "
                                + "file nor the installed file"
                        )
                    } else {
                        // The destination is absent, or it is exactly the
                        // installed file. Only those two states may take the
                        // verified backup back.
                        guard let backupSnapshot else {
                            throw CoordinatorError.recoveryRequired(
                                "the previous file for \(operation.destination) is missing"
                            )
                        }
                        guard backupSnapshot == previous else {
                            throw CoordinatorError.journalUnsafe(
                                "\(backup) does not match the previous record"
                            )
                        }
                        try confirmRestorableDestination(
                            tree,
                            operation: operation,
                            installed: installed
                        )
                        try tree.restoreFromBackup(backup, to: operation.destination, expected: previous)
                    }
                } else {
                    if let destinationSnapshot {
                        guard destinationSnapshot.sha256 == operation.newSHA256,
                              destinationSnapshot.size == operation.newSize,
                              destinationSnapshot.mode == operation.newMode
                        else {
                            throw CoordinatorError.recoveryRequired(
                                "\(operation.destination) holds an object the journal does not own"
                            )
                        }
                        _ = try tree.removeFile(
                            operation.destination,
                            expectedDigest: operation.newSHA256
                        )
                    }
                    if backupSnapshot != nil {
                        throw CoordinatorError.recoveryRequired(
                            "\(backup) exists for an operation that had no previous file"
                        )
                    }
                }
                try removeTemporaryFile(tree, journal: journal, operation: operation)
                if let step = CoordinatorStep.recoveryRestored(operation.index) {
                    try faults.check(step)
                }
            }
            try verifyPreviousSet(tree, journal: journal)
            try faults.check(.recoveryVerified)

            for directory in journal.createdDirectories.reversed() {
                let mode = createdDirectoryMode(directory, transactionID: journal.transactionID)
                _ = try tree.removeDirectoryIfEmpty(directory, expectedMode: mode)
            }
            _ = try tree.removeDirectoryIfEmpty(
                InstallJournal.backupDirectoryRelativePath(transactionID: journal.transactionID),
                expectedMode: 0o700
            )
            try store.removeTemporaryFiles()
            try store.remove(observed)
            try faults.check(.recoveryJournalRemoved)
            return nil
        } catch {
            return mapError(error)
        }
    }

    // The destination check and the backup rename are separate system calls.
    // A cooperating participant cannot change the tree while the exclusive
    // lock is held, but an uncooperative process can. This second snapshot
    // narrows that window; it does not close it. Darwin has no whole-file
    // compare-and-rename, so the replacement is never atomic against an
    // outside writer.
    private func confirmRestorableDestination(
        _ tree: InstallTree,
        operation: InstallJournal.Operation,
        installed: FileSnapshot
    ) throws {
        let current = try tree.snapshot(
            operation.destination,
            maximumBytes: max(
                operation.newSize,
                max(operation.previousSize ?? 0, maximumSize(forArtifact: operation.artifact))
            )
        )
        guard let current else { return }
        guard current == installed else {
            throw CoordinatorError.recoveryRequired(
                "\(operation.destination) changed after the rollback check"
            )
        }
    }

    private func removeTemporaryFile(
        _ tree: InstallTree,
        journal: InstallJournal,
        operation: InstallJournal.Operation
    ) throws {
        guard let parts = SafeRelativePath.components(operation.destination),
              let name = parts.last
        else { throw CoordinatorError.journalUnsafe("a temporary path is unsafe") }
        let parent = parts.dropLast().joined(separator: "/")
        let temporary = (parent.isEmpty ? "" : parent + "/")
            + "." + name + ".hs-"
            + InstallJournal.temporarySuffix(transactionID: journal.transactionID, index: operation.index)
            + ".tmp"
        _ = try tree.removeFile(temporary, expectedDigest: nil)
    }

    private func createdDirectoryMode(_ directory: String, transactionID: String) -> UInt16 {
        if directory == InstallJournalStore.backupRootRelative
            || directory == InstallJournal.backupDirectoryRelativePath(transactionID: transactionID) {
            return 0o700
        }
        return 0o755
    }

    // A nested error already carries a full sentence. Reuse its reason instead
    // of wrapping "Recovery did not complete: ..." inside a second identical
    // sentence with a second "The journal is kept."
    private func failureReason(_ error: CoordinatorError) -> String {
        switch error {
        case .recoveryRequired(let why), .committedStateDamaged(let why),
             .journalWriteUncertain(let why), .journalRemoveUncertain(let why),
             .fileWriteUncertain(let why):
            return why
        default:
            return error.description
        }
    }

    private func describe(_ error: InstallTreeError) -> String {
        switch error {
        case .rootUnsafe: return "the root is unsafe"
        case .pathUnsafe: return "the path is unsafe"
        case .directoryUnsafe: return "the directory is unsafe"
        case .missing: return "the object is missing"
        case .notRegularFile: return "the object is not a regular file"
        case .wrongOwner: return "the owner is not the expected account"
        case .wrongGroup: return "the group is not the expected group"
        case .wrongLinkCount: return "the link count is not one"
        case .writableByOthers: return "a group or other account can write it"
        case .accessControlList: return "an access control list is present"
        case .tooLarge: return "the size is outside the bound"
        case .alreadyExists: return "the object already exists"
        case .notEmpty: return "the directory is not empty"
        case .digestMismatch: return "the digest differs"
        case .wrongMode: return "the mode is not the required mode"
        case .writeUncertain: return "the replacement is visible but its directory entry was not synced"
        case .removeUncertain: return "the name is removed but its directory entry was not synced"
        case .io(_, let code): return "the system call failed with code \(code)"
        }
    }

    private func mapError(_ error: Error) -> CoordinatorError {
        if let coordinator = error as? CoordinatorError { return coordinator }
        if let tree = error as? InstallTreeError {
            switch tree {
            case .rootUnsafe(let path):
                return .sandboxRootUnsafe(path)
            case .pathUnsafe(let path):
                return .unsafePath(path)
            case .directoryUnsafe(let path), .missing(let path):
                return .unsafeDirectory(path)
            case .notRegularFile(let path), .wrongOwner(let path), .wrongGroup(let path),
                 .wrongLinkCount(let path),
                 .writableByOthers(let path), .accessControlList(let path), .tooLarge(let path),
                 .wrongMode(let path):
                return .unsafeFile("\(path): \(describe(tree))")
            case .writeUncertain(let path):
                // A post-rename sync failure is not a clean pre-rename
                // failure. The install stops before another file mutation and
                // keeps the journal for recovery to confirm and re-observe.
                return .fileWriteUncertain("\(path): \(describe(tree))")
            case .removeUncertain(let path):
                return .io("\(path): \(describe(tree))")
            case .alreadyExists(let path):
                return .io("\(path) already exists")
            case .notEmpty(let path):
                return .recoveryRequired("the directory is not empty: \(path)")
            case .digestMismatch(let path):
                return .digestMismatch(path)
            case .io(let path, let code):
                return .io("\(path) failed with code \(code)")
            }
        }
        if let lock = error as? InstallLockError {
            switch lock {
            case .busy: return .lockUnavailable
            case .unsafeDirectory(let path): return .unsafeDirectory(path)
            case .unsafeLockFile(let path): return .unsafeFile(path)
            case .failed(let why): return .io(why)
            }
        }
        return .io("an unexpected error occurred")
    }

    private func run<T>(_ body: () throws -> T) throws -> T {
        do {
            return try body()
        } catch let error as CoordinatorError {
            throw error
        } catch {
            throw mapError(error)
        }
    }
}
