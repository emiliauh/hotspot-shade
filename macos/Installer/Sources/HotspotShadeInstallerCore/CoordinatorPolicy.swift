import Foundation
import Darwin

public enum CoordinatorError: Error, Equatable, CustomStringConvertible {
    case runningAsRoot
    case notApproved
    case sandboxRootUnsafe(String)
    case sandboxMarkerUnsafe
    case unsafePath(String)
    case unsafeDirectory(String)
    case unsafeFile(String)
    case io(String)
    case lockUnavailable
    case cleanupBlocked
    case launchIntentPresent
    case startJournalPresent
    case startJournalUnreadable(String)
    case participantLockIncompatible(String)
    case journalPresent
    case journalUnreadable(String)
    case journalUnsafe(String)
    // The install journal rename completed but its directory sync failed. The
    // new record is visible and the previous record cannot be assumed. No
    // further file change may run; the journal and backups are kept.
    case journalWriteUncertain(String)
    // The install journal unlink completed but its directory sync failed. The
    // record may reappear after a crash. No further file change may run.
    case journalRemoveUncertain(String)
    // A file or backup rename completed but its parent sync failed. The visible
    // set is coherent, but its survival across a crash is unknown. No further
    // file change may run; recovery confirms the journal and re-observes.
    case fileWriteUncertain(String)
    case manifestInvalid(String)
    case manifestRefused(String)
    case payloadInvalid(String)
    case digestMismatch(String)
    case artifactRejected(String)
    case existingFileUnsafe(String)
    case orphanArtifacts(String)
    case nothingToRecover
    case recoveryRequired(String)
    case committedStateDamaged(String)
    case simulatedCrash(CoordinatorStep)

    public var description: String {
        switch self {
        case .runningAsRoot:
            return "The install coordinator must not run as root."
        case .notApproved:
            return "Live installation is not approved in this build."
        case .sandboxRootUnsafe(let why):
            return "The sandbox root is unsafe: \(why)."
        case .sandboxMarkerUnsafe:
            return "The sandbox marker is missing or unsafe."
        case .unsafePath(let path):
            return "The path is not one the coordinator may use: \(path)."
        case .unsafeDirectory(let path):
            return "A directory is not safe for the coordinator: \(path)."
        case .unsafeFile(let path):
            return "A file is not safe for the coordinator: \(path)."
        case .io(let why):
            return "The file operation failed: \(why)."
        case .lockUnavailable:
            return "The install lock is held by a start participant or another coordinator."
        case .cleanupBlocked:
            return "A cleanup block is present. Inspect the host before a start or an install."
        case .launchIntentPresent:
            return "An engine launch intent is present. Inspect the host before an install."
        case .startJournalPresent:
            return "A start journal is present. A started engine may still be live. Inspect the host before an install."
        case .startJournalUnreadable(let why):
            return "The start journal cannot be used: \(why)."
        case .participantLockIncompatible(let why):
            return "A start participant does not share the canonical install lock: \(why)."
        case .journalPresent:
            return "An install journal is present. Run recovery before another install."
        case .journalUnreadable(let why):
            return "The install journal cannot be used: \(why)."
        case .journalUnsafe(let why):
            return "The install journal is unsafe: \(why)."
        case .journalWriteUncertain(let why):
            return "The install journal write outcome is unknown: \(why). "
                + "No further file change was made. The journal and backups are kept. "
                + "Run recovery before another install."
        case .journalRemoveUncertain(let why):
            return "The install journal removal outcome is unknown: \(why). "
                + "No further file change was made. Run recovery before another install."
        case .fileWriteUncertain(let why):
            return "A file replacement outcome is unknown: \(why). "
                + "No further file change was made. The journal and backups are kept. "
                + "Run recovery before another install."
        case .manifestInvalid(let why):
            return "The installer manifest is invalid: \(why)."
        case .manifestRefused(let why):
            return "The installer manifest is refused: \(why)."
        case .payloadInvalid(let why):
            return "The staged payload is invalid: \(why)."
        case .digestMismatch(let path):
            return "A file digest does not match the validated record: \(path)."
        case .artifactRejected(let why):
            return "A staged artifact was rejected: \(why)."
        case .existingFileUnsafe(let detail):
            return "An existing installed file is unsafe to replace: \(detail)."
        case .orphanArtifacts(let detail):
            return "Backup objects exist without a journal: \(detail). A person must inspect them."
        case .nothingToRecover:
            return "There is no install journal to recover."
        case .recoveryRequired(let why):
            return "Recovery did not complete: \(why). The journal is kept."
        case .committedStateDamaged(let why):
            return "A committed install no longer verifies: \(why). The journal and backups are kept."
        case .simulatedCrash(let step):
            return "Simulated crash after \(step.rawValue)."
        }
    }
}

// A fault point that a hermetic test can stop at. Production code uses
// NoFaults. The names describe the durable step that has already completed.
public enum CoordinatorStep: String, CaseIterable, Equatable, Sendable {
    case journalPrepared
    case directoriesCreated
    case replacementStarted
    case backupMoved0
    case backupMoved1
    case backupMoved2
    case backupMoved3
    case fileInstalled0
    case fileInstalled1
    case fileInstalled2
    case fileInstalled3
    case replacementVerified
    case commitJournalWritten
    case backupsRemoved
    case journalRemoved
    case recoveryRestored0
    case recoveryRestored1
    case recoveryRestored2
    case recoveryRestored3
    case recoveryVerified
    case recoveryJournalRemoved

    public static func backupMoved(_ index: Int) -> CoordinatorStep? {
        switch index {
        case 0: return .backupMoved0
        case 1: return .backupMoved1
        case 2: return .backupMoved2
        case 3: return .backupMoved3
        default: return nil
        }
    }

    public static func fileInstalled(_ index: Int) -> CoordinatorStep? {
        switch index {
        case 0: return .fileInstalled0
        case 1: return .fileInstalled1
        case 2: return .fileInstalled2
        case 3: return .fileInstalled3
        default: return nil
        }
    }

    public static func recoveryRestored(_ index: Int) -> CoordinatorStep? {
        switch index {
        case 0: return .recoveryRestored0
        case 1: return .recoveryRestored1
        case 2: return .recoveryRestored2
        case 3: return .recoveryRestored3
        default: return nil
        }
    }

    // Fault points that are after the durable commit. Recovery finishes the
    // new file set from these points instead of rolling it back.
    public var isAfterCommit: Bool {
        switch self {
        case .commitJournalWritten, .backupsRemoved, .journalRemoved,
             .recoveryJournalRemoved:
            return true
        default:
            return false
        }
    }

    public static var installFaultPoints: [CoordinatorStep] {
        allCases.filter { step in
            switch step {
            case .recoveryRestored0, .recoveryRestored1, .recoveryRestored2,
                 .recoveryRestored3, .recoveryVerified, .recoveryJournalRemoved:
                return false
            default:
                return true
            }
        }
    }
}

public protocol CoordinatorFaultInjecting: Sendable {
    func check(_ step: CoordinatorStep) throws
}

public struct NoFaults: CoordinatorFaultInjecting {
    public init() {}
    public func check(_ step: CoordinatorStep) throws {}
}

public struct CoordinatorFaultAt: CoordinatorFaultInjecting {
    public let step: CoordinatorStep
    public init(_ step: CoordinatorStep) { self.step = step }
    public func check(_ candidate: CoordinatorStep) throws {
        if candidate == step { throw CoordinatorError.simulatedCrash(candidate) }
    }
}

public enum CoordinatorPolicy {
    // This value is not configurable from an argument, an environment
    // variable, or a file. Live file replacement needs compatible lock
    // participants, an initial migration, signed and notarized artifacts, the
    // privileged launchd and authorization steps, and an independent review.
    public static let liveInstallationApproved = false

    // A separate, explicitly compiled local test candidate can exercise the
    // system entry point. Normal and ordinary local-preview builds stay closed.
    // This is fixed at build time, never selected by runtime input.
    #if HOTSPOTSHADE_LOCAL_PREVIEW && HOTSPOTSHADE_SYSTEM_PREVIEW_CANDIDATE
    public static let localPreviewInstallationApproved = true
    #else
    public static let localPreviewInstallationApproved = false
    #endif

    static var systemOperationsApproved: Bool {
        #if HOTSPOTSHADE_LOCAL_PREVIEW
        return localPreviewInstallationApproved
        #else
        return liveInstallationApproved
        #endif
    }

    #if HOTSPOTSHADE_LOCAL_PREVIEW && HOTSPOTSHADE_SYSTEM_PREVIEW_CANDIDATE
    public static let refusal =
        "This is a local system-preview test candidate. The release package remains disabled."
    #else
    public static let refusal =
        "This build has no live install mode. The package preinstall refuses and installationApproved is false."
    #endif
}

// A sandbox root is an explicitly marked temporary directory owned by the
// current account. The coordinator never accepts "/" or a system directory as
// an install target, and this build has no option that turns a sandbox root
// into a live one.
public enum CoordinatorSandboxPolicy {
    public static let markerName = ".hotspotshade-installer-sandbox"
    public static let markerContents = "hotspotshade installer coordinator sandbox v1\n"

    public static func validate(
        _ requested: String,
        effectiveUserID: UInt32 = UInt32(geteuid()),
        temporaryDirectory: String = NSTemporaryDirectory()
    ) throws -> String {
        let resolved = try resolveRoot(
            requested,
            effectiveUserID: effectiveUserID,
            temporaryDirectory: temporaryDirectory
        )
        try checkMarker(in: resolved, expectedOwner: effectiveUserID)
        return resolved
    }

    // Create the fixed marker in a temporary root. This writes one file under
    // the caller's temporary directory and never a system path.
    @discardableResult
    public static func createMarker(
        _ requested: String,
        effectiveUserID: UInt32 = UInt32(geteuid()),
        temporaryDirectory: String = NSTemporaryDirectory()
    ) throws -> String {
        let resolved = try resolveRoot(
            requested,
            effectiveUserID: effectiveUserID,
            temporaryDirectory: temporaryDirectory
        )
        let parent = open(resolved, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0 else { throw CoordinatorError.sandboxRootUnsafe("the root cannot be opened") }
        defer { close(parent) }
        let marker = markerName
        let descriptor = marker.withCString {
            openat(
                parent,
                $0,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                mode_t(0o600)
            )
        }
        if descriptor < 0 {
            if errno == EEXIST {
                try checkMarker(in: resolved, expectedOwner: effectiveUserID)
                return resolved
            }
            throw CoordinatorError.sandboxMarkerUnsafe
        }
        var complete = false
        defer {
            close(descriptor)
            if !complete {
                _ = marker.withCString { unlinkat(parent, $0, 0) }
            }
        }
        guard SystemSupport.writeAll(descriptor, data: Data(markerContents.utf8)),
              fchmod(descriptor, mode_t(0o600)) == 0,
              fsync(descriptor) == 0,
              fsync(parent) == 0
        else { throw CoordinatorError.sandboxMarkerUnsafe }
        complete = true
        try checkMarker(in: resolved, expectedOwner: effectiveUserID)
        return resolved
    }

    private static func resolveRoot(
        _ requested: String,
        effectiveUserID: UInt32,
        temporaryDirectory: String
    ) throws -> String {
        guard effectiveUserID != 0 else { throw CoordinatorError.runningAsRoot }
        guard requested.hasPrefix("/"), !requested.contains("\0") else {
            throw CoordinatorError.sandboxRootUnsafe("the path must be absolute")
        }
        guard let resolvedPointer = realpath(requested, nil) else {
            throw CoordinatorError.sandboxRootUnsafe("the path does not exist")
        }
        defer { free(resolvedPointer) }
        let resolved = String(cString: resolvedPointer)
        guard resolved != "/" else {
            throw CoordinatorError.sandboxRootUnsafe("the path is the system root")
        }
        var prefixes = ["/private/var/folders/", "/private/tmp/"]
        if let tempResolved = realpath(temporaryDirectory, nil) {
            let temp = String(cString: tempResolved)
            free(tempResolved)
            prefixes.append(temp.hasSuffix("/") ? temp : temp + "/")
        }
        if temporaryDirectory.hasPrefix("/") {
            prefixes.append(temporaryDirectory.hasSuffix("/") ? temporaryDirectory : temporaryDirectory + "/")
        }
        let candidate = resolved.hasSuffix("/") ? resolved : resolved + "/"
        guard prefixes.contains(where: { candidate.hasPrefix($0) }) else {
            throw CoordinatorError.sandboxRootUnsafe("the path is not under the temporary directory")
        }
        var status = stat()
        guard lstat(resolved, &status) == 0,
              status.st_mode & S_IFMT == S_IFDIR,
              status.st_uid == effectiveUserID,
              status.st_mode & 0o077 == 0,
              !SystemSupport.hasExtendedACL(path: resolved)
        else {
            throw CoordinatorError.sandboxRootUnsafe("the directory owner or mode is wrong")
        }
        return resolved
    }

    private static func checkMarker(in root: String, expectedOwner: UInt32) throws {
        let path = root + "/" + markerName
        var status = stat()
        guard lstat(path, &status) == 0,
              status.st_mode & S_IFMT == S_IFREG,
              status.st_uid == expectedOwner,
              status.st_nlink == 1,
              status.st_mode & 0o7777 == 0o600,
              status.st_size > 0,
              status.st_size <= 128
        else { throw CoordinatorError.sandboxMarkerUnsafe }
        let descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw CoordinatorError.sandboxMarkerUnsafe }
        defer { close(descriptor) }
        guard !SystemSupport.hasExtendedACL(descriptor),
              let data = SystemSupport.readAll(descriptor, maximumBytes: 128),
              data == Data(markerContents.utf8)
        else { throw CoordinatorError.sandboxMarkerUnsafe }
    }
}

public struct InstallOutcome: Equatable, Sendable {
    public let transactionID: String
    public let version: String
    public let fileCount: Int
    public let createdDirectories: [String]
}

public enum RecoveryOutcome: Equatable, Sendable {
    case nothingToRecover
    case rolledBack(transactionID: String, version: String)
    case finishedCommit(transactionID: String, version: String)
}

public struct CoordinatorStatus: Equatable, Sendable {
    public let journalPhase: InstallJournal.Phase?
    public let serviceJournalPresent: Bool
    public let cleanupBlocked: Bool
    public let launchIntentPresent: Bool
    public let startJournalPresent: Bool
    public let startJournalLockMatchesHeldLock: Bool?
    public let backupOrphans: [String]
    public let presentLockFileNames: [String]
    public let lockFilePresent: Bool
}
