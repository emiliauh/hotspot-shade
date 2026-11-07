import Foundation
import HotspotShadeKit

// The durable record of one file transaction. The journal is written before
// the first file is moved and is removed last. A crash at any point leaves
// either the previous file set, the new file set, or a journal that names every
// object the coordinator may restore or remove.
//
// The journal is not trusted as a path source. Every destination must be one
// of the four fixed layout paths. A backup path is derived from the transaction
// identifier and the operation index. A record that names anything else is
// refused and left in place for a person to inspect.
public struct InstallJournal: Codable, Equatable, Sendable {    public enum Phase: String, Codable, Equatable, Sendable {
        case preparing
        case replacing
        case committed
    }

    public struct Operation: Codable, Equatable, Sendable {
        public let index: Int
        public let artifact: String
        public let destination: String
        public let newSHA256: String
        public let newSize: Int
        public let newMode: UInt16
        public let previousPresent: Bool
        public let previousSHA256: String?
        public let previousSize: Int?
        public let previousMode: UInt16?
    }

    public let schemaVersion: Int
    public let transactionID: String
    public let fromVersion: String?
    public let toVersion: String
    public let teamIdentifier: String
    public let phase: Phase
    public let createdDirectories: [String]
    public let operations: [Operation]

    public static let currentSchemaVersion = 1
    public static let maximumBytes = 1 << 20

    public func withPhase(_ phase: Phase) -> InstallJournal {
        InstallJournal(
            schemaVersion: schemaVersion,
            transactionID: transactionID,
            fromVersion: fromVersion,
            toVersion: toVersion,
            teamIdentifier: teamIdentifier,
            phase: phase,
            createdDirectories: createdDirectories,
            operations: operations
        )
    }

    public static func backupRelativePath(transactionID: String, index: Int) -> String {
        InstallLockLayout.stateDirectoryRelative
            + "/" + InstallJournalStore.backupDirectoryName
            + "/" + transactionID
            + "/" + String(index)
    }

    public static func backupDirectoryRelativePath(transactionID: String) -> String {
        InstallLockLayout.stateDirectoryRelative
            + "/" + InstallJournalStore.backupDirectoryName
            + "/" + transactionID
    }

    public static func temporarySuffix(transactionID: String, index: Int) -> String {
        transactionID + "-" + String(index)
    }

    public func backupRelativePath(for operation: Operation) -> String {
        Self.backupRelativePath(transactionID: transactionID, index: operation.index)
    }

    public func validate() throws {
        guard schemaVersion == Self.currentSchemaVersion else {
            throw CoordinatorError.journalUnsafe("the schema version is not supported")
        }
        guard SystemSupport.isLowercaseHex(transactionID, count: 32) else {
            throw CoordinatorError.journalUnsafe("the transaction identifier is malformed")
        }
        guard InstallerBuilder.isValidVersion(toVersion) else {
            throw CoordinatorError.journalUnsafe("the target version is malformed")
        }
        if let fromVersion {
            guard InstallerBuilder.isValidVersion(fromVersion) else {
                throw CoordinatorError.journalUnsafe("the previous version is malformed")
            }
        }
        guard HelperRequirement.isValidTeamIdentifier(teamIdentifier) else {
            throw CoordinatorError.journalUnsafe("the team identifier is malformed")
        }
        guard operations.count == InstallerLayout.entries.count else {
            throw CoordinatorError.journalUnsafe("the operation count is not the fixed layout")
        }
        var seenDestinations = Set<String>()
        for (index, entry) in InstallerLayout.entries.enumerated() {
            guard index < operations.count else {
                throw CoordinatorError.journalUnsafe("the operation order is incomplete")
            }
            let operation = operations[index]
            guard operation.index == index,
                  operation.artifact == entry.artifact.rawValue,
                  operation.destination == Self.relativeDestination(entry.destination),
                  operation.newMode == entry.destinationMode,
                  SystemSupport.isLowercaseHex(operation.newSHA256, count: 64),
                  operation.newSize > 0,
                  operation.newSize <= Self.maximumSize(for: entry.artifact),
                  seenDestinations.insert(operation.destination).inserted
            else {
                throw CoordinatorError.journalUnsafe("an operation does not match the fixed layout")
            }
            if operation.previousPresent {
                guard let digest = operation.previousSHA256,
                      let size = operation.previousSize,
                      let mode = operation.previousMode,
                      SystemSupport.isLowercaseHex(digest, count: 64),
                      size > 0,
                      size <= Self.maximumSize(for: entry.artifact),
                      mode == entry.destinationMode
                else {
                    throw CoordinatorError.journalUnsafe("a previous file record is incomplete")
                }
            } else {
                guard operation.previousSHA256 == nil,
                      operation.previousSize == nil,
                      operation.previousMode == nil
                else {
                    throw CoordinatorError.journalUnsafe("an absent previous file has a record")
                }
            }
        }
        let allowedDirectories = Set([
            Self.installRootRelative,
            Self.installRootRelative + "/engine",
            Self.installRootRelative + "/install-support",
            InstallJournalStore.backupRootRelative,
            Self.backupDirectoryRelativePath(transactionID: transactionID),
        ])
        guard Set(createdDirectories).count == createdDirectories.count,
              createdDirectories.allSatisfy({ allowedDirectories.contains($0) })
        else {
            throw CoordinatorError.journalUnsafe("a created directory is not one the coordinator may own")
        }
    }

    static let installRootRelative = "Library/Application Support/HotspotShade"

    static func relativeDestination(_ absolute: String) -> String {
        absolute.hasPrefix("/") ? String(absolute.dropFirst()) : absolute
    }

    static func maximumSize(for artifact: InstallerArtifact) -> Int {
        switch artifact {
        case .helper, .engine, .app:
            return ArtifactIngest.maximumExecutableBytes
        case .launchDaemon, .startRight:
            return ArtifactIngest.maximumPlistBytes
        }
    }
}

// The exact bytes that one run observed, captured before a decision. The
// digest and mode are the removal contract: a record that changed after the
// decision is never removed. A read-back of a rewrite only shows the current
// namespace; the successful file and parent sync is the durability claim.
public struct InstallJournalObservation: Equatable, Sendable {
    public let journal: InstallJournal
    public let data: Data
    public let digestSHA256: String
    public let size: Int
    public let mode: UInt16
}

public struct InstallJournalStore: Sendable {
    public static let fileName = "install-journal.json"
    public static let backupDirectoryName = "install-backup"
    public static let relativePath = InstallLockLayout.stateDirectoryRelative + "/" + fileName
    public static let backupRootRelative = InstallLockLayout.stateDirectoryRelative
        + "/" + backupDirectoryName
    // The journal is written with this exact mode. A read requires it.
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

    // The hermetic tests use this seam to stop at one journal phase. A
    // production writer is always the one above, which calls the tree.
    init(tree: InstallTree, atomicWriter: @escaping AtomicWriter) {
        self.tree = tree
        self.atomicWriter = atomicWriter
    }

    public func read() throws -> InstallJournal? {
        try readObserved()?.journal
    }

    // Read the record and capture the exact bytes, size, digest, and mode that
    // the caller's decision is based on. Removal and durable confirmation use
    // that observation, not a fresh read.
    public func readObserved() throws -> InstallJournalObservation? {
        let data: Data?
        do {
            data = try tree.readFile(
                Self.relativePath,
                maximumBytes: InstallJournal.maximumBytes,
                requiredMode: Self.fileMode
            )
        } catch {
            throw CoordinatorError.journalUnreadable("the journal cannot be read safely")
        }
        guard let data else { return nil }
        let journal: InstallJournal
        do {
            journal = try JSONDecoder().decode(InstallJournal.self, from: data)
        } catch {
            throw CoordinatorError.journalUnreadable("the journal is not valid JSON")
        }
        do {
            try journal.validate()
        } catch let error as CoordinatorError {
            throw error
        } catch {
            throw CoordinatorError.journalUnreadable("the journal cannot be validated")
        }
        return InstallJournalObservation(
            journal: journal,
            data: data,
            digestSHA256: ServiceHash.sha256Hex(data),
            size: data.count,
            mode: Self.fileMode
        )
    }

    // A durable phase write: remove the exact temporary name, write through
    // the atomic seam (temporary file, file sync, rename, parent sync), then
    // read the exact bytes back. The sync success is the durability claim; the
    // read-back only proves the current namespace matches the intended bytes.
    @discardableResult
    public func write(_ journal: InstallJournal) throws -> InstallJournalObservation {
        try journal.validate()
        let data = try encode(journal)
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
                maximumBytes: InstallJournal.maximumBytes,
                requiredMode: Self.fileMode
            ) else {
                throw CoordinatorError.journalWriteUncertain(
                    "the \(journal.phase.rawValue) journal is absent after its write"
                )
            }
            readback = value
        } catch let error as CoordinatorError {
            throw error
        } catch {
            throw CoordinatorError.journalWriteUncertain(
                "the \(journal.phase.rawValue) journal could not be read back after its write"
            )
        }
        guard readback == data else {
            throw CoordinatorError.journalWriteUncertain(
                "the \(journal.phase.rawValue) journal did not read back exactly after its write"
            )
        }
        return InstallJournalObservation(
            journal: journal,
            data: data,
            digestSHA256: ServiceHash.sha256Hex(data),
            size: data.count,
            mode: Self.fileMode
        )
    }

    // Durably confirm an exactly observed record before any recovery action
    // depends on it. The same bytes are rewritten through the atomic seam and
    // read back. A successful file and parent sync is the durability claim. If
    // any part of the confirmation is unknown, the caller must stop before the
    // first mutation.
    public func confirm(_ observation: InstallJournalObservation) throws {
        try observation.journal.validate()
        let current: InstallJournalObservation?
        do {
            current = try readObserved()
        } catch {
            throw CoordinatorError.journalUnreadable(
                "the journal cannot be read before its durable confirmation"
            )
        }
        guard let current,
              current.digestSHA256 == observation.digestSHA256,
              current.size == observation.size,
              current.journal == observation.journal
        else {
            throw CoordinatorError.journalUnreadable(
                "the journal changed before its durable confirmation"
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
        let after: InstallJournalObservation?
        do {
            after = try readObserved()
        } catch {
            throw CoordinatorError.journalWriteUncertain(
                "the journal could not be read back after its durable confirmation"
            )
        }
        guard let after,
              after.digestSHA256 == observation.digestSHA256,
              after.size == observation.size
        else {
            throw CoordinatorError.journalWriteUncertain(
                "the journal did not read back exactly after its durable confirmation"
            )
        }
    }

    // Remove only the exact record that the decision observed. A changed
    // digest, a changed mode, a hard link, or another unsafe object is kept.
    // An unlink whose parent sync fails is an unknown removal and stops the
    // caller before any further mutation.
    public func remove(_ observation: InstallJournalObservation) throws {
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
                throw CoordinatorError.journalUnreadable(
                    "the journal changed before removal; it is kept"
                )
            case .removeUncertain:
                throw CoordinatorError.journalRemoveUncertain(
                    "the unlink completed but the state directory sync failed"
                )
            default:
                throw CoordinatorError.io("the journal cannot be removed")
            }
        } catch {
            throw CoordinatorError.io("the journal cannot be removed")
        }
    }

    // A journal rewrite uses a temporary file with the transaction identifier.
    // A crash can leave that file behind. The main journal stays the
    // authoritative record: it is removed last. Only exact temporary names
    // under the private state directory are removed.
    public func removeTemporaryFiles() throws {
        let names: [String]
        do {
            names = try tree.listDirectory(InstallLockLayout.stateDirectoryRelative)
        } catch {
            throw CoordinatorError.io("the state directory cannot be read")
        }
        let prefix = "." + Self.fileName + ".hs-"
        for name in names where name.hasPrefix(prefix) && name.hasSuffix(".tmp") {
            let relative = InstallLockLayout.stateDirectoryRelative + "/" + name
            do {
                _ = try tree.removeFile(relative, expectedDigest: nil)
            } catch {
                throw CoordinatorError.io("a journal temporary file cannot be removed")
            }
        }
    }

    private func encode(_ journal: InstallJournal) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        do {
            return try encoder.encode(journal)
        } catch {
            throw CoordinatorError.journalUnreadable("the journal cannot be encoded")
        }
    }

    private func removeExactTemporary(suffix: String) throws {
        let relative = InstallLockLayout.stateDirectoryRelative
            + "/." + Self.fileName + ".hs-" + suffix + ".tmp"
        do {
            _ = try tree.removeFile(relative, expectedDigest: nil)
        } catch {
            throw CoordinatorError.io("the journal temporary file cannot be removed")
        }
    }

    private func classifyWriteError(
        _ error: Error,
        phase: InstallJournal.Phase
    ) -> CoordinatorError {
        if let error = error as? CoordinatorError {
            // A specific error is never hidden behind a generic write error.
            return error
        }
        if let error = error as? InstallTreeError, case .writeUncertain(let path) = error {
            // The rename completed. The new record is visible, but its
            // directory entry may not survive a crash, so the previous record
            // cannot be assumed either. A read-back proves the current
            // namespace, not durability. The caller must stop and keep the
            // journal and backups.
            return .journalWriteUncertain(
                "the \(phase.rawValue) journal rename at \(path) completed "
                    + "but its directory sync failed"
            )
        }
        return .io("the journal cannot be written")
    }

    public func hasOrphanBackupDirectories() throws -> [String] {
        let names: [String]
        do {
            names = try tree.listDirectory(Self.backupRootRelative)
        } catch {
            throw CoordinatorError.io("the backup directory cannot be read")
        }
        return names
    }
}
