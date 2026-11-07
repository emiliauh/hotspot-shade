import Foundation
import Darwin
import HotspotShadeKit

// Remove the fixed file set, the launch daemon job, and the start right that
// a first-time local preview install attempt may have created.
//
// This is not a general uninstaller. The preview has no upgrade path: the
// system entry point calls `installFirstTime`, which refuses an existing file,
// an existing right, or an existing job. On a preview host the reviewed fixed
// set is consistent with a first-install attempt. Both journals are removed
// when an install commits, so there is no durable ownership record left to
// consult. The seam checks publisher and layout; it cannot prove which
// transaction created an object. It checks more than a path alone:
//
// - every present file must be a regular file owned by the tree account and
//   group, with one link, no group or other write bit, no access control list,
//   and the exact mode its layout entry requires;
// - the helper and the engine must carry a protected identity and the team of
//   the running signed coordinator;
// - the launch daemon file and the start right must pass the installer's own
//   plist checks;
// - a stored start right must carry the same policy as the installed right
//   file, and a loaded job must name the fixed helper and the fixed launch
//   daemon file.
//
// Anything else is a refusal, never a best guess. A present file journal, a
// service journal, a cleanup block, a launch intent, or a start journal blocks
// the run: those records mean another transaction may own routes or files.
//
// A running tunnel is kept out of the way by the same exclusion lease that the
// install takes. A participating engine or helper holds a shared lock, so this
// seam cannot take its exclusive lock and refuses. An old binary that takes no
// lock is not excluded; that limit is the same one the install documents.
//
// The seam never signals a process, never removes a journal, marker, or lock
// file, never removes the standard `/Library/PrivilegedHelperTools` directory,
// and never removes a file outside the fixed destinations and the three install
// directories. It removes a directory only when it is empty and carries the
// expected owner and mode, so the placed preview tree and any other object stop
// the removal instead of being deleted. Like the install, it may create the
// fixed lock files in an existing state directory.
//
// Ordinary builds refuse the system entry point before opening a system path.
// The explicit system-preview candidate enables it for live testing. The
// hermetic tests use a sandbox tree and a fake runtime; they do not prove a
// live removal.
public enum PreviewCleanupStep: String, CaseIterable, Equatable, Sendable {
    case filesValidated
    case serviceStateValidated
    case launchdJobRemoved
    case authorizationRightRemoved
    case fileRemoved0
    case fileRemoved1
    case fileRemoved2
    case fileRemoved3
    case directoriesRemoved

    static func fileRemoved(_ index: Int) -> PreviewCleanupStep? {
        switch index {
        case 0: return .fileRemoved0
        case 1: return .fileRemoved1
        case 2: return .fileRemoved2
        case 3: return .fileRemoved3
        default: return nil
        }
    }
}

public protocol PreviewCleanupFaultInjecting: Sendable {
    func check(_ step: PreviewCleanupStep) throws
}

public struct NoPreviewCleanupFaults: PreviewCleanupFaultInjecting {
    public init() {}
    public func check(_ step: PreviewCleanupStep) throws {}
}

public struct PreviewCleanupFaultAt: PreviewCleanupFaultInjecting {
    public let step: PreviewCleanupStep
    public init(_ step: PreviewCleanupStep) { self.step = step }
    public func check(_ candidate: PreviewCleanupStep) throws {
        if candidate == step { throw PreviewCleanupError.simulatedCrash(candidate) }
    }
}

public enum PreviewCleanupError: Error, Equatable, CustomStringConvertible {
    case notApproved
    case requiresRoot
    case requiresTeamIdentifier
    case stateDirectoryUnsafe(String)
    case lockUnavailable
    case lockUnsafe(String)
    case installJournalPresent
    case orphanBackupPresent
    case serviceJournalPresent
    case participantStateUnclean(String)
    case installedFileUnsafe(String)
    case installedFileMismatch(String)
    case authorizationRightUnreadable(String)
    case authorizationRightWithoutSource(String)
    case authorizationRightForeign(String)
    case authorizationRightStillPresent
    case launchdJobUnexpected(String)
    case launchdJobUnknown(String)
    case launchdJobStillLoaded(String)
    case removalFailed(String)
    case io(String)
    case simulatedCrash(PreviewCleanupStep)

    public var description: String {
        switch self {
        case .notApproved:
            return "Preview removal is not approved in this build."
        case .requiresRoot:
            return "A live preview removal needs the root coordinator."
        case .requiresTeamIdentifier:
            return "Preview removal needs the signing team of the running coordinator."
        case .stateDirectoryUnsafe(let why):
            return "The preview state directory is not safe to use: \(why)."
        case .lockUnavailable:
            return "Another install or start participant holds the preview exclusion lock. "
                + "Do not remove the preview while a tunnel is starting or running."
        case .lockUnsafe(let why):
            return "The preview exclusion lock cannot be used: \(why)."
        case .installJournalPresent:
            return "A file transaction record is present or cannot be read. "
                + "Run file recovery before removing the preview."
        case .orphanBackupPresent:
            return "An unaccounted install backup is present. Inspect it before removing the preview."
        case .serviceJournalPresent:
            return "A service transaction record is present. "
                + "Run service recovery before removing the preview."
        case .participantStateUnclean(let why):
            return "A start participant record is present: \(why). "
                + "An engine may still own routes. Inspect the host before removing the preview."
        case .installedFileUnsafe(let why):
            return "An installed object is not safe for preview removal: \(why)."
        case .installedFileMismatch(let why):
            return "An installed object is not this preview's file: \(why)."
        case .authorizationRightUnreadable(let why):
            return "The start right cannot be observed: \(why)."
        case .authorizationRightWithoutSource(let why):
            return "A start right is stored but its installed definition is missing: \(why)."
        case .authorizationRightForeign(let why):
            return "The stored start right does not belong to this preview: \(why)."
        case .authorizationRightStillPresent:
            return "The start right is still present after the removal."
        case .launchdJobUnexpected(let why):
            return "A launch daemon job with the fixed label is loaded but is not the installed one: \(why)."
        case .launchdJobUnknown(let why):
            return "The launch daemon job state cannot be proven: \(why)."
        case .launchdJobStillLoaded(let why):
            return "The launch daemon job is still loaded after the removal: \(why)."
        case .removalFailed(let why):
            return "A preview object could not be removed: \(why)."
        case .io(let why):
            return "A preview removal file operation failed: \(why)."
        case .simulatedCrash(let step):
            return "Simulated removal interruption after \(step.rawValue)."
        }
    }
}

public struct PreviewCleanupReport: Equatable, Sendable {
    public let removedLaunchdJob: Bool
    public let removedAuthorizationRight: Bool
    public let removedFiles: [String]
    public let removedEmptyDirectories: [String]
    public let keptNonEmptyDirectories: [String]

    public var changedAnything: Bool {
        removedLaunchdJob || removedAuthorizationRight
            || !removedFiles.isEmpty || !removedEmptyDirectories.isEmpty
    }

    static let nothingToRemove = PreviewCleanupReport(
        removedLaunchdJob: false,
        removedAuthorizationRight: false,
        removedFiles: [],
        removedEmptyDirectories: [],
        keptNonEmptyDirectories: []
    )
}

public final class PreviewFirstInstallCleanup: @unchecked Sendable {
    private struct InstalledFile {
        let index: Int
        let artifact: InstallerArtifact
        let relative: String
        let mode: UInt16
        let snapshot: FileSnapshot
        let path: String
    }

    private let tree: InstallTree
    private let runtime: PrivilegedServiceRuntime
    private let validator: InstallerValidator
    private let expectedTeamIdentifier: String
    private let faults: PreviewCleanupFaultInjecting

    // The only directories a first install creates under the fixed install
    // location. The standard helper directory and the state directory are never
    // removed, and the installed app and the placed preview tree are outside
    // this seam.
    static let removableDirectories = [
        InstallJournal.relativeDestination(InstallerLayout.engineRoot),
        InstallJournal.relativeDestination(InstallerLayout.installLocation) + "/"
            + InstallerLayout.supportDirectoryName,
        InstallJournal.relativeDestination(InstallerLayout.installLocation),
    ]

    init(
        tree: InstallTree,
        runtime: PrivilegedServiceRuntime,
        validator: InstallerValidator = InstallerValidator(),
        expectedTeamIdentifier: String,
        faults: PreviewCleanupFaultInjecting = NoPreviewCleanupFaults(),
        effectiveUserID: UInt32 = UInt32(geteuid())
    ) throws {
        // The team comes from the running signed coordinator in the system
        // path. A caller-supplied team is accepted only by this internal seam,
        // which the hermetic tests use. It is never read from a file, an
        // environment variable, or a command line.
        guard HelperRequirement.isValidTeamIdentifier(expectedTeamIdentifier) else {
            throw PreviewCleanupError.requiresTeamIdentifier
        }
        if runtime.isLiveSystem {
            guard CoordinatorPolicy.systemOperationsApproved else {
                throw PreviewCleanupError.notApproved
            }
            guard effectiveUserID == 0 else { throw PreviewCleanupError.requiresRoot }
        }
        self.tree = tree
        self.runtime = runtime
        self.validator = validator
        self.expectedTeamIdentifier = expectedTeamIdentifier
        self.faults = faults
    }

    // The system entry point. It repeats the install approval gate, takes the
    // team from the running coordinator's own signature, and uses the same
    // root:wheel tree as the system install. It is compiled for review and
    // refuses in ordinary builds because the gate is false.
    static func systemPreview() throws -> PreviewFirstInstallCleanup {
        guard HelperRequirement.isLocalPreview, CoordinatorPolicy.localPreviewInstallationApproved
        else { throw PreviewCleanupError.notApproved }
        guard geteuid() == 0 else { throw PreviewCleanupError.requiresRoot }
        let team = try InstallerSelfIdentity.teamIdentifier()
        let tree = try InstallTree(
            rootPath: "/",
            expectedOwner: 0,
            expectedGroup: 0,
            syncHooks: .production,
            usePrivateVar: true
        )
        return try PreviewFirstInstallCleanup(
            tree: tree,
            runtime: SystemPrivilegedServiceRuntime(),
            validator: InstallerValidator(),
            expectedTeamIdentifier: team,
            effectiveUserID: 0
        )
    }

    // Remove the fixed set. The whole plan is observed and validated before the
    // first mutation, so a foreign or uncertain object stops the run with
    // nothing removed. A run that is interrupted after a mutation leaves only
    // objects that the next run can identify again, so the caller can retry.
    public func run(using lease: InstallExclusionLease? = nil) throws -> PreviewCleanupReport {
        guard let statePath = try stateDirectoryPath() else {
            try refuseServiceWithoutState()
            return PreviewCleanupReport.nothingToRemove
        }
        let acquired = try validateOrAcquire(lease, statePath: statePath)
        defer { if lease == nil { acquired.release() } }
        try refuseUnfinishedState()

        let files = try observedFiles()
        let installedPolicy = try validate(files)
        try faults.check(.filesValidated)

        let storedRight = try observedRight()
        if let storedRight {
            guard let installedPolicy else {
                throw PreviewCleanupError.authorizationRightWithoutSource(
                    "the installed right file is absent"
                )
            }
            guard storedRight.policy == installedPolicy else {
                throw PreviewCleanupError.authorizationRightForeign(
                    "the stored policy differs from the installed policy"
                )
            }
        }
        let jobLoaded = try observedLaunchdJob()
        try faults.check(.serviceStateValidated)

        var removedLaunchdJob = false
        if jobLoaded {
            try stopLaunchdJob()
            removedLaunchdJob = true
            try faults.check(.launchdJobRemoved)
        }

        var removedAuthorizationRight = false
        if storedRight != nil {
            try removeAuthorizationRight(installedPolicy: installedPolicy)
            removedAuthorizationRight = true
            try faults.check(.authorizationRightRemoved)
        }

        var removedFiles: [String] = []
        for file in files {
            if try remove(file) {
                removedFiles.append(file.relative)
            }
            if let step = PreviewCleanupStep.fileRemoved(file.index) {
                try faults.check(step)
            }
        }

        let directories = try removeEmptyInstallDirectories()
        try faults.check(.directoriesRemoved)
        return PreviewCleanupReport(
            removedLaunchdJob: removedLaunchdJob,
            removedAuthorizationRight: removedAuthorizationRight,
            removedFiles: removedFiles,
            removedEmptyDirectories: directories.removed,
            keptNonEmptyDirectories: directories.kept
        )
    }

    // MARK: observation

    // A host without the preview state directory has no lock that can prove
    // exclusion, so this seam does not create one. It removes nothing and
    // changes nothing. An installed file, a preview right, or a preview job
    // without that directory is a state a person must inspect.
    private func stateDirectoryPath() throws -> String? {
        let relative = InstallLockLayout.stateDirectoryRelative
        do {
            _ = try tree.directoryMode(relative)
        } catch InstallTreeError.missing {
            if try anyDestinationExists() {
                throw PreviewCleanupError.stateDirectoryUnsafe(
                    "the state directory is absent but an installed file is present"
                )
            }
            return nil
        } catch let error as InstallTreeError {
            throw PreviewCleanupError.stateDirectoryUnsafe(Self.describe(error))
        } catch {
            throw PreviewCleanupError.stateDirectoryUnsafe("the state directory cannot be inspected")
        }
        do {
            return try tree.path(for: relative)
        } catch {
            throw PreviewCleanupError.stateDirectoryUnsafe("the state directory path is unsafe")
        }
    }

    private func anyDestinationExists() throws -> Bool {
        for entry in InstallerLayout.entries {
            let relative = InstallJournal.relativeDestination(entry.destination)
            do {
                if try tree.entryExists(relative) { return true }
            } catch {
                throw PreviewCleanupError.stateDirectoryUnsafe(
                    "an installed destination cannot be inspected"
                )
            }
        }
        return false
    }

    // A host without the state directory did not get it from this preview. A
    // preview service or right that exists anyway cannot be excluded or
    // attributed, so it is a refusal, not a clean removal.
    private func refuseServiceWithoutState() throws {
        if try observedRight() != nil {
            throw PreviewCleanupError.stateDirectoryUnsafe(
                "the state directory is absent but a preview start right is present"
            )
        }
        if try observedLaunchdJob() {
            throw PreviewCleanupError.stateDirectoryUnsafe(
                "the state directory is absent but a preview launch daemon job is loaded"
            )
        }
    }

    private func refuseUnfinishedState() throws {
        let store = InstallJournalStore(tree: tree)
        do {
            if try store.read() != nil { throw PreviewCleanupError.installJournalPresent }
        } catch let error as PreviewCleanupError {
            throw error
        } catch {
            // A damaged record is still a record. It keeps the preview in place
            // for the file recovery command.
            throw PreviewCleanupError.installJournalPresent
        }
        do {
            if try !store.hasOrphanBackupDirectories().isEmpty {
                throw PreviewCleanupError.orphanBackupPresent
            }
        } catch let error as PreviewCleanupError {
            throw error
        } catch {
            throw PreviewCleanupError.io("the install backup directory cannot be inspected")
        }
        try requireAbsent(
            ServiceJournalStore.relativePath,
            PreviewCleanupError.serviceJournalPresent
        )
        try requireAbsent(
            InstallLockLayout.stateDirectoryRelative + "/" + InstallLockLayout.cleanupMarkerName,
            PreviewCleanupError.participantStateUnclean("a cleanup block is present")
        )
        try requireAbsent(
            InstallLockLayout.stateDirectoryRelative + "/" + InstallLockLayout.launchIntentName,
            PreviewCleanupError.participantStateUnclean("an engine launch intent is present")
        )
        do {
            if try StartJournalProbe.read(tree) != nil {
                throw PreviewCleanupError.participantStateUnclean("a start journal is present")
            }
        } catch let error as PreviewCleanupError {
            throw error
        } catch {
            throw PreviewCleanupError.participantStateUnclean(
                "the start journal cannot be read safely"
            )
        }
    }

    private func requireAbsent(
        _ relative: String,
        _ failure: PreviewCleanupError
    ) throws {
        do {
            if try tree.entryExists(relative) { throw failure }
        } catch let error as PreviewCleanupError {
            throw error
        } catch {
            throw PreviewCleanupError.io("the state at \(relative) cannot be inspected")
        }
    }

    private func observedFiles() throws -> [InstalledFile] {
        var present: [InstalledFile] = []
        for (index, entry) in InstallerLayout.entries.enumerated() {
            let relative = InstallJournal.relativeDestination(entry.destination)
            let maximum = InstallJournal.maximumSize(for: entry.artifact)
            let snapshot: FileSnapshot?
            do {
                snapshot = try tree.snapshot(relative, maximumBytes: maximum)
            } catch let error as InstallTreeError {
                throw PreviewCleanupError.installedFileUnsafe(
                    "\(relative): \(Self.describe(error))"
                )
            } catch {
                throw PreviewCleanupError.installedFileUnsafe(
                    "\(relative): the object cannot be inspected"
                )
            }
            guard let snapshot else { continue }
            guard snapshot.mode == entry.destinationMode else {
                throw PreviewCleanupError.installedFileUnsafe(
                    "\(relative) has mode \(String(snapshot.mode, radix: 8)), "
                        + "not \(String(entry.destinationMode, radix: 8))"
                )
            }
            let path: String
            do {
                path = try tree.path(for: relative)
            } catch {
                throw PreviewCleanupError.installedFileUnsafe("\(relative): the path is unsafe")
            }
            present.append(
                InstalledFile(
                    index: index,
                    artifact: entry.artifact,
                    relative: relative,
                    mode: entry.destinationMode,
                    snapshot: snapshot,
                    path: path
                )
            )
        }
        return present
    }

    // Every present file must be this preview's. The installed right policy is
    // returned so the stored right can be compared with it.
    private func validate(_ files: [InstalledFile]) throws -> AuthorizationRightPolicy? {
        var installedPolicy: AuthorizationRightPolicy?
        for file in files {
            switch file.artifact {
            case .helper:
                try requireExecutable(file, identifier: HelperRequirement.helperIdentifier)
            case .engine:
                try requireExecutable(file, identifier: HelperRequirement.engineIdentifier)
            case .launchDaemon:
                let data = try read(file)
                do {
                    try validator.validateLaunchDaemon(data)
                } catch let error as InstallerError {
                    throw PreviewCleanupError.installedFileMismatch(
                        "\(file.relative): \(error.description)"
                    )
                } catch {
                    throw PreviewCleanupError.installedFileMismatch(
                        "\(file.relative): the launch daemon file cannot be checked"
                    )
                }
            case .startRight:
                let data = try read(file)
                do {
                    try validator.validateStartRight(data)
                    installedPolicy = try AuthorizationRightPolicyParser.parse(data).policy
                } catch let error as InstallerError {
                    throw PreviewCleanupError.installedFileMismatch(
                        "\(file.relative): \(error.description)"
                    )
                } catch {
                    throw PreviewCleanupError.installedFileMismatch(
                        "\(file.relative): the start right cannot be checked"
                    )
                }
            case .app:
                throw PreviewCleanupError.installedFileMismatch(
                    "\(file.relative): the layout does not install an app"
                )
            }
        }
        return installedPolicy
    }

    private func requireExecutable(
        _ file: InstalledFile,
        identifier: String
    ) throws {
        do {
            try validator.validateExecutable(
                atPath: file.path,
                artifact: file.artifact,
                identifier: identifier,
                teamIdentifier: expectedTeamIdentifier
            )
        } catch let error as InstallerError {
            throw PreviewCleanupError.installedFileMismatch(
                "\(file.relative): \(error.description)"
            )
        } catch {
            throw PreviewCleanupError.installedFileMismatch(
                "\(file.relative): the signature cannot be checked"
            )
        }
    }

    // The read-back digest must still equal the snapshot that will guard the
    // removal. A file that changed between the two reads is refused here; the
    // digest and mode passed to removeFile guard the remaining window.
    private func read(_ file: InstalledFile) throws -> Data {
        let maximum = InstallJournal.maximumSize(for: file.artifact)
        let data: Data?
        do {
            data = try tree.readFile(file.relative, maximumBytes: maximum, requiredMode: file.mode)
        } catch let error as InstallTreeError {
            throw PreviewCleanupError.installedFileUnsafe(
                "\(file.relative): \(Self.describe(error))"
            )
        } catch {
            throw PreviewCleanupError.installedFileUnsafe(
                "\(file.relative): the object cannot be read"
            )
        }
        guard let data else {
            throw PreviewCleanupError.installedFileMismatch(
                "\(file.relative) disappeared after it was checked"
            )
        }
        guard ServiceHash.sha256Hex(data) == file.snapshot.sha256 else {
            throw PreviewCleanupError.installedFileMismatch(
                "\(file.relative) changed after it was checked"
            )
        }
        return data
    }

    private func observedRight() throws -> AuthorizationRightSnapshot? {
        do {
            switch try runtime.authorizationRights.observe() {
            case .absent:
                return nil
            case .present(let snapshot):
                return snapshot
            }
        } catch let error as AuthorizationRightDatabaseError {
            throw PreviewCleanupError.authorizationRightUnreadable(error.description)
        } catch {
            throw PreviewCleanupError.authorizationRightUnreadable(
                "the start right cannot be observed"
            )
        }
    }

    private func observedLaunchdJob() throws -> Bool {
        let observation: LaunchdJobObservation
        do {
            observation = try runtime.launchd.observe()
        } catch {
            throw PreviewCleanupError.launchdJobUnknown("the job state cannot be observed")
        }
        switch observation {
        case .absent:
            return false
        case .loaded(let readback):
            // The production controller already checks these fields. Repeat the
            // check so an injected runtime cannot broaden the removal.
            guard readback.label == PrivilegedServiceLayout.launchdLabel,
                  readback.launchDaemonPath == PrivilegedServiceLayout.launchDaemonPath,
                  readback.helperPath == PrivilegedServiceLayout.helperPath
            else {
                throw PreviewCleanupError.launchdJobUnexpected(
                    "the loaded job does not name the fixed helper and launch daemon file"
                )
            }
            return true
        case .unexpected(let why):
            throw PreviewCleanupError.launchdJobUnexpected(why)
        case .unknown(let why):
            throw PreviewCleanupError.launchdJobUnknown(why)
        }
    }

    // MARK: removal

    private func stopLaunchdJob() throws {
        var commandError: Error?
        do { try runtime.launchd.bootout() } catch { commandError = error }
        // A command exit is not proof. A job that is still loaded is refused,
        // and an unreadable state is never treated as absence.
        let stillLoaded: Bool
        do {
            stillLoaded = try observedLaunchdJob()
        } catch let error as PreviewCleanupError {
            throw error
        }
        if stillLoaded {
            if commandError != nil {
                throw PreviewCleanupError.launchdJobStillLoaded(
                    "the command failed and the job remains"
                )
            }
            throw PreviewCleanupError.launchdJobStillLoaded("the job remains after the command")
        }
    }

    private func removeAuthorizationRight(
        installedPolicy: AuthorizationRightPolicy?
    ) throws {
        // A command exit is not proof either. An existing right after the call
        // is refused, and an unreadable database is never treated as absence.
        do {
            try runtime.authorizationRights.remove()
        } catch {
            // Observed below. A failed command that did remove the right is a
            // complete removal; a right that remains is a refusal.
        }
        let remaining: AuthorizationRightSnapshot?
        do {
            remaining = try observedRight()
        } catch let error as PreviewCleanupError {
            throw error
        }
        guard let remaining else { return }
        if let installedPolicy, remaining.policy != installedPolicy {
            throw PreviewCleanupError.authorizationRightForeign(
                "the stored policy changed during removal"
            )
        }
        throw PreviewCleanupError.authorizationRightStillPresent
    }

    private func remove(_ file: InstalledFile) throws -> Bool {
        do {
            return try tree.removeFile(
                file.relative,
                expectedDigest: file.snapshot.sha256,
                expectedMode: file.mode
            )
        } catch let error as InstallTreeError {
            throw PreviewCleanupError.removalFailed(
                "\(file.relative): \(Self.describe(error))"
            )
        } catch {
            throw PreviewCleanupError.removalFailed(
                "\(file.relative): the removal cannot complete"
            )
        }
    }

    private func removeEmptyInstallDirectories() throws -> (
        removed: [String], kept: [String]
    ) {
        var removed: [String] = []
        var kept: [String] = []
        // Deepest first. A non-empty directory is kept and named, never
        // deleted. The standard helper directory and the state directory are
        // not in this list.
        for relative in Self.removableDirectories {
            let exists: Bool
            do {
                exists = try tree.entryExists(relative)
            } catch {
                throw PreviewCleanupError.removalFailed(
                    "\(relative): the directory cannot be inspected"
                )
            }
            guard exists else { continue }
            do {
                _ = try tree.removeDirectoryIfEmpty(relative, expectedMode: 0o755)
                removed.append(relative)
            } catch InstallTreeError.notEmpty {
                kept.append(relative)
            } catch let error as InstallTreeError {
                throw PreviewCleanupError.removalFailed(
                    "\(relative): \(Self.describe(error))"
                )
            } catch {
                throw PreviewCleanupError.removalFailed(
                    "\(relative): the directory cannot be removed"
                )
            }
        }
        return (removed, kept)
    }

    // MARK: lease

    private func validateOrAcquire(
        _ lease: InstallExclusionLease?,
        statePath: String
    ) throws -> InstallExclusionLease {
        guard let lease else { return try acquire(statePath: statePath) }
        guard lease.locks.allSatisfy({ $0.isHeld }) else {
            throw PreviewCleanupError.lockUnavailable
        }
        do {
            for name in InstallLockLayout.heldFileNames {
                guard let current = try InstallLock.identity(
                    parentDirectory: statePath,
                    fileName: name,
                    expectedOwner: tree.owner
                ), let held = lease.fileNameByIdentity[name], held == current else {
                    throw PreviewCleanupError.lockUnavailable
                }
            }
        } catch let error as PreviewCleanupError {
            throw error
        } catch {
            throw PreviewCleanupError.lockUnsafe(
                "the passed lease does not hold this state directory's locks"
            )
        }
        return lease
    }

    private func acquire(statePath: String) throws -> InstallExclusionLease {
        do {
            return try InstallExclusionLease.acquire(
                parentDirectory: statePath,
                expectedOwner: tree.owner
            )
        } catch InstallLockError.busy {
            throw PreviewCleanupError.lockUnavailable
        } catch let error as InstallLockError {
            throw PreviewCleanupError.lockUnsafe(error.description)
        } catch {
            throw PreviewCleanupError.lockUnsafe("the exclusion lease cannot be acquired")
        }
    }

    private static func describe(_ error: InstallTreeError) -> String {
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
}
