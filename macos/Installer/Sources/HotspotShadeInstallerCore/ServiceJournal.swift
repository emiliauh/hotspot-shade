import Foundation
import Darwin
import HotspotShadeKit

// The durable record of one launchd and authorization-right transaction. It is
// separate from the file install journal because the two actions are outside
// the file tree, but it is validated against the same fixed layout and it is
// kept until the service state is verified or a person resolves the ambiguity.
//
// The journal is not a command input. Every path, label, and right name in it
// must equal a fixed constant. A backup of the previous start right is stored
// here because authd has no file to move to a backup directory. The encoded
// previous definition is bounded and checked for its digest before use.
public struct ServiceJournal: Codable, Equatable, Sendable {
    public enum Phase: String, Codable, Equatable, Sendable {
        // The journal is durable and no privileged action has been recorded.
        case preparing
        // The previous launchd job was verified absent, or no job was loaded.
        case jobBootedOut
        // The start right was written and its read-back was verified.
        case rightReplaced
        // The launch daemon was bootstrapped and its read-back was verified.
        case jobBootstrapped
        // Both new states were verified and the commit record is durable.
        case committed
        // The transaction durably began restoring the previous service state.
        // Recovery must never install or roll forward from this phase.
        case rollbackStarted
        // The previous service state was verified restored. Recovery only
        // removes this journal; it never installs.
        case rolledBack
    }

    public static let currentSchemaVersion = 1

    public let schemaVersion: Int
    public let transactionID: String
    // The file install transaction that this service step belongs to, when the
    // future root coordinator supplies it. It is not a path and is never used
    // to find a file.
    public let installTransactionID: String?
    public let rightName: String
    public let launchdLabel: String
    public let launchDaemonPath: String
    public let helperPath: String
    public let installedRightSHA256: String
    public let installedRightPolicy: AuthorizationRightPolicy
    public let installedLaunchDaemonSHA256: String
    public let phase: Phase
    public let previousRightPresent: Bool
    public let previousRightSHA256: String?
    public let previousRightPolicy: AuthorizationRightPolicy?
    public let previousRightPlistBase64: String?
    public let previousJobLoaded: Bool

    public init(
        schemaVersion: Int = ServiceJournal.currentSchemaVersion,
        transactionID: String,
        installTransactionID: String?,
        rightName: String = PrivilegedServiceLayout.rightName,
        launchdLabel: String = PrivilegedServiceLayout.launchdLabel,
        launchDaemonPath: String = PrivilegedServiceLayout.launchDaemonPath,
        helperPath: String = PrivilegedServiceLayout.helperPath,
        installedRightSHA256: String,
        installedRightPolicy: AuthorizationRightPolicy,
        installedLaunchDaemonSHA256: String,
        phase: Phase,
        previousRightPresent: Bool,
        previousRightSHA256: String?,
        previousRightPolicy: AuthorizationRightPolicy?,
        previousRightPlistBase64: String?,
        previousJobLoaded: Bool
    ) {
        self.schemaVersion = schemaVersion
        self.transactionID = transactionID
        self.installTransactionID = installTransactionID
        self.rightName = rightName
        self.launchdLabel = launchdLabel
        self.launchDaemonPath = launchDaemonPath
        self.helperPath = helperPath
        self.installedRightSHA256 = installedRightSHA256
        self.installedRightPolicy = installedRightPolicy
        self.installedLaunchDaemonSHA256 = installedLaunchDaemonSHA256
        self.phase = phase
        self.previousRightPresent = previousRightPresent
        self.previousRightSHA256 = previousRightSHA256
        self.previousRightPolicy = previousRightPolicy
        self.previousRightPlistBase64 = previousRightPlistBase64
        self.previousJobLoaded = previousJobLoaded
    }

    public func withPhase(_ phase: Phase) -> ServiceJournal {
        ServiceJournal(
            schemaVersion: schemaVersion,
            transactionID: transactionID,
            installTransactionID: installTransactionID,
            rightName: rightName,
            launchdLabel: launchdLabel,
            launchDaemonPath: launchDaemonPath,
            helperPath: helperPath,
            installedRightSHA256: installedRightSHA256,
            installedRightPolicy: installedRightPolicy,
            installedLaunchDaemonSHA256: installedLaunchDaemonSHA256,
            phase: phase,
            previousRightPresent: previousRightPresent,
            previousRightSHA256: previousRightSHA256,
            previousRightPolicy: previousRightPolicy,
            previousRightPlistBase64: previousRightPlistBase64,
            previousJobLoaded: previousJobLoaded
        )
    }

    public func validate() throws {
        guard schemaVersion == Self.currentSchemaVersion else {
            throw ServiceJournalError.unsafe("the schema version is not supported")
        }
        guard SystemSupport.isLowercaseHex(transactionID, count: 32) else {
            throw ServiceJournalError.unsafe("the transaction identifier is malformed")
        }
        if let installTransactionID {
            guard SystemSupport.isLowercaseHex(installTransactionID, count: 32) else {
                throw ServiceJournalError.unsafe("the install transaction identifier is malformed")
            }
        }
        guard rightName == PrivilegedServiceLayout.rightName,
              launchdLabel == PrivilegedServiceLayout.launchdLabel,
              launchDaemonPath == PrivilegedServiceLayout.launchDaemonPath,
              helperPath == PrivilegedServiceLayout.helperPath
        else {
            throw ServiceJournalError.unsafe("a fixed name or path differs")
        }
        guard SystemSupport.isLowercaseHex(installedRightSHA256, count: 64),
              SystemSupport.isLowercaseHex(installedLaunchDaemonSHA256, count: 64)
        else {
            throw ServiceJournalError.unsafe("an installed digest is malformed")
        }
        guard isReviewedPolicy(installedRightPolicy) else {
            throw ServiceJournalError.unsafe("the installed right policy is not the reviewed shape")
        }
        guard previousRightPresent == (previousRightSHA256 != nil),
              previousRightPresent == (previousRightPolicy != nil),
              previousRightPresent == (previousRightPlistBase64 != nil)
        else {
            throw ServiceJournalError.unsafe("a previous right record is incomplete")
        }
        if previousRightPresent {
            guard let digest = previousRightSHA256,
                  let policy = previousRightPolicy,
                  let encoded = previousRightPlistBase64,
                  let data = Data(base64Encoded: encoded),
                  !data.isEmpty,
                  data.count <= PrivilegedServiceLayout.maximumRightBytes,
                  ServiceHash.sha256Hex(data) == digest
            else {
                throw ServiceJournalError.unsafe("the previous right backup is malformed")
            }
            guard let parsed = try? AuthorizationRightPolicyParser.parse(data),
                  parsed.policy == policy
            else {
                throw ServiceJournalError.unsafe("the previous right backup does not parse")
            }
        }
    }

    private func isReviewedPolicy(_ policy: AuthorizationRightPolicy) -> Bool {
        policy.rightClass == "user"
            && policy.group == "admin"
            && policy.authenticateUser
            && !policy.shared
            && !policy.allowRoot
            && HelperStartAuthorizationPolicy.isStartRightTimeout(policy.timeout)
    }
}

public enum ServiceJournalError: Error, Equatable, CustomStringConvertible {
    case unreadable(String)
    case unsafe(String)
    case io(String)
    // The atomic rename may have happened, but its directory sync did not
    // complete. The visible record cannot be treated as a clean, durable write.
    case writeOutcomeUnknown(String)
    // The unlink may have happened, but its directory sync did not complete.
    // The record may reappear after a crash. No later removal may run.
    case removeOutcomeUnknown(String)

    public var description: String {
        switch self {
        case .unreadable(let why):
            return "The service journal cannot be read: \(why)."
        case .unsafe(let why):
            return "The service journal is unsafe: \(why)."
        case .io(let why):
            return "The service journal operation failed: \(why)."
        case .writeOutcomeUnknown(let why):
            return "The service journal write outcome is unknown: \(why)."
        case .removeOutcomeUnknown(let why):
            return "The service journal removal outcome is unknown: \(why)."
        }
    }
}

// The exact bytes that one run observed. The digest and mode are the removal
// contract; a record that changed after the decision is never removed.
public struct ServiceJournalObservation: Equatable, Sendable {
    public let journal: ServiceJournal
    public let data: Data
    public let digestSHA256: String
    public let size: Int
    public let mode: UInt16
}

public struct ServiceJournalStore: Sendable {
    public static let fileName = "service-journal.json"
    public static let relativePath = PrivilegedServiceLayout.stateDirectoryRelative
        + "/" + fileName
    public static let maximumBytes = 256 * 1024
    // The record is written with this exact mode. A read requires it.
    public static let fileMode: UInt16 = 0o600

    public typealias AtomicWriter = @Sendable (
        _ relative: String,
        _ data: Data,
        _ mode: mode_t,
        _ temporarySuffix: String,
        _ replaceExisting: Bool
    ) throws -> Void

    private let tree: InstallTree
    private let atomicWriter: AtomicWriter

    public init(tree: InstallTree) {
        self.tree = tree
        self.atomicWriter = { relative, data, mode, temporarySuffix, replaceExisting in
            try tree.writeAtomic(
                relative,
                data: data,
                mode: mode,
                temporarySuffix: temporarySuffix,
                replaceExisting: replaceExisting
            )
        }
    }

    // The hermetic tests use this seam to exercise a directory sync failure
    // after the atomic rename. Production uses the initializer above only.
    init(tree: InstallTree, atomicWriter: @escaping AtomicWriter) {
        self.tree = tree
        self.atomicWriter = atomicWriter
    }

    public func read() throws -> ServiceJournal? {
        try readObserved()?.journal
    }

    public func readObserved() throws -> ServiceJournalObservation? {
        let data: Data?
        do {
            data = try tree.readFile(
                Self.relativePath,
                maximumBytes: Self.maximumBytes,
                requiredMode: Self.fileMode
            )
        } catch {
            throw ServiceJournalError.unreadable("the record cannot be read safely")
        }
        guard let data else { return nil }
        let journal: ServiceJournal
        do {
            journal = try JSONDecoder().decode(ServiceJournal.self, from: data)
        } catch {
            throw ServiceJournalError.unreadable("the record is not valid JSON")
        }
        do {
            try journal.validate()
        } catch let error as ServiceJournalError {
            throw error
        } catch {
            throw ServiceJournalError.unreadable("the record cannot be validated")
        }
        return ServiceJournalObservation(
            journal: journal,
            data: data,
            digestSHA256: ServiceHash.sha256Hex(data),
            size: data.count,
            mode: Self.fileMode
        )
    }

    @discardableResult
    public func write(_ journal: ServiceJournal) throws -> ServiceJournalObservation {
        try journal.validate()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data: Data
        do {
            data = try encoder.encode(journal)
        } catch {
            throw ServiceJournalError.unreadable("the record cannot be encoded")
        }
        guard data.count <= Self.maximumBytes else {
            throw ServiceJournalError.unsafe("the encoded record is too large")
        }
        try removeExactTemporary(suffix: journal.transactionID)
        do {
            try atomicWriter(
                Self.relativePath,
                data,
                mode_t(Self.fileMode),
                journal.transactionID,
                true
            )
        } catch {
            throw classifyWriteError(error, phase: journal.phase)
        }
        let readback: Data
        do {
            guard let value = try tree.readFile(
                Self.relativePath,
                maximumBytes: Self.maximumBytes,
                requiredMode: Self.fileMode
            ) else {
                throw ServiceJournalError.writeOutcomeUnknown(
                    "the \(journal.phase.rawValue) record is absent after its write"
                )
            }
            readback = value
        } catch let error as ServiceJournalError {
            throw error
        } catch {
            throw ServiceJournalError.writeOutcomeUnknown(
                "the \(journal.phase.rawValue) record could not be read back after its write"
            )
        }
        guard readback == data else {
            throw ServiceJournalError.writeOutcomeUnknown(
                "the \(journal.phase.rawValue) record did not read back exactly after its write"
            )
        }
        return ServiceJournalObservation(
            journal: journal,
            data: data,
            digestSHA256: ServiceHash.sha256Hex(data),
            size: data.count,
            mode: Self.fileMode
        )
    }

    // Durably confirm an exactly observed record before recovery acts on it.
    public func confirm(_ observation: ServiceJournalObservation) throws {
        try observation.journal.validate()
        let current: ServiceJournalObservation?
        do {
            current = try readObserved()
        } catch {
            throw ServiceJournalError.unreadable(
                "the record cannot be read before its durable confirmation"
            )
        }
        guard let current,
              current.digestSHA256 == observation.digestSHA256,
              current.size == observation.size,
              current.journal == observation.journal
        else {
            throw ServiceJournalError.unreadable(
                "the record changed before its durable confirmation"
            )
        }
        try removeExactTemporary(suffix: observation.journal.transactionID)
        do {
            try atomicWriter(
                Self.relativePath,
                observation.data,
                mode_t(Self.fileMode),
                observation.journal.transactionID,
                true
            )
        } catch {
            throw classifyWriteError(error, phase: observation.journal.phase)
        }
        let after: ServiceJournalObservation?
        do {
            after = try readObserved()
        } catch {
            throw ServiceJournalError.writeOutcomeUnknown(
                "the record could not be read back after its durable confirmation"
            )
        }
        guard let after,
              after.digestSHA256 == observation.digestSHA256,
              after.size == observation.size
        else {
            throw ServiceJournalError.writeOutcomeUnknown(
                "the record did not read back exactly after its durable confirmation"
            )
        }
    }

    // Remove only the exact record the decision observed. A changed digest,
    // mode, or unsafe object is kept.
    public func remove(_ observation: ServiceJournalObservation) throws {
        do {
            _ = try tree.removeFile(
                Self.relativePath,
                expectedDigest: observation.digestSHA256,
                expectedMode: observation.mode
            )
        } catch let error as InstallTreeError {
            switch error {
            case .digestMismatch, .wrongMode, .notRegularFile, .wrongOwner,
                 .wrongLinkCount, .writableByOthers, .accessControlList:
                throw ServiceJournalError.unsafe("the record changed before removal; it is kept")
            case .removeUncertain:
                throw ServiceJournalError.removeOutcomeUnknown(
                    "the unlink completed but the state directory sync failed"
                )
            default:
                throw ServiceJournalError.io("the record cannot be removed")
            }
        } catch {
            throw ServiceJournalError.io("the record cannot be removed")
        }
    }

    private func removeExactTemporary(suffix: String) throws {
        let relative = PrivilegedServiceLayout.stateDirectoryRelative
            + "/." + Self.fileName + ".hs-" + suffix + ".tmp"
        do {
            _ = try tree.removeFile(relative, expectedDigest: nil)
        } catch {
            throw ServiceJournalError.io("the journal temporary file cannot be removed")
        }
    }

    private func classifyWriteError(
        _ error: Error,
        phase: ServiceJournal.Phase
    ) -> ServiceJournalError {
        if let error = error as? ServiceJournalError { return error }
        if let error = error as? InstallTreeError, case .writeUncertain = error {
            // The atomic rename is one operation. A failure before it leaves
            // the previous record authoritative, so the write is a clean
            // failure. A failure after it means the new record is visible but
            // its directory entry may not be durable. Classify by the failed
            // step; a read-back only shows the current namespace and is not a
            // durability proof.
            return .writeOutcomeUnknown(
                "the \(phase.rawValue) record rename completed but its directory sync failed"
            )
        }
        return .io("the record cannot be written")
    }

    // A journal rewrite uses a temporary file named by the transaction. A
    // crash can leave one behind. Only exact temporary names under the private
    // state directory are removed.
    public func removeTemporaryFiles() throws {
        let names: [String]
        do {
            names = try tree.listDirectory(PrivilegedServiceLayout.stateDirectoryRelative)
        } catch {
            throw ServiceJournalError.io("the state directory cannot be read")
        }
        let prefix = "." + Self.fileName + ".hs-"
        for name in names where name.hasPrefix(prefix) && name.hasSuffix(".tmp") {
            do {
                _ = try tree.removeFile(
                    PrivilegedServiceLayout.stateDirectoryRelative + "/" + name,
                    expectedDigest: nil
                )
            } catch {
                throw ServiceJournalError.io("a journal temporary file cannot be removed")
            }
        }
    }
}
