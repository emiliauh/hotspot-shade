import Foundation
import HotspotShadeKit

// The fixed install layout. Every destination comes from a constant that the
// helper itself checks at startup, so the installer cannot place a file where
// the helper will not look. No destination is read from an input, a plist, an
// environment variable, or a command line.
//
// The package payload lives under one directory that the package owns,
// `/Library/Application Support/HotspotShade`. The package install location is
// that directory, so the payload never lists `/Library`, `/Library/Application
// Support`, or any other system directory. The package marks its entries to
// overwrite permissions, and an existing system directory must keep its own
// owner, group, and mode. The helper and its launch daemon file go to their
// protected locations from the postinstall script.
public enum InstallerLayout {
    public static let packageIdentifier = "dev.hotspotshade.mac.installer"

    public static let installLocation = "/Library/Application Support/HotspotShade"
    public static let helperDestination = HelperRequirement.helperExecutablePath
    public static let launchDaemonDestination = HelperRequirement.launchDaemonPath
    public static let engineDestination = RootEnginePaths().enginePath
    public static let engineRoot = RootEnginePaths().engineInstallRoot
    public static let engineHome = RootEnginePaths().homeDirectory
    public static let stateDirectory = RootCleanupBlockStore.defaultDirectoryPath
    public static let cleanupMarkerName = RootCleanupBlockStore.defaultFileName
    public static let launchIntentName = RootLaunchIntentStore.defaultFileName
    public static let startRightName = HelperStartAuthorizationPolicy.startRight
    public static let helperLabel = HelperRequirement.helperServiceName
    public static let helperInstallRoot = HelperRequirement.helperInstallRoot
    public static let launchDaemonRoot = "/Library/LaunchDaemons"

    public static let supportDirectoryName = "install-support"
    public static let supportRoot = installLocation + "/" + supportDirectoryName
    public static let startRightDestination = supportRoot + "/" + startRightName + ".plist"
    public static let stagedHelperPath = supportRoot + "/" + HelperRequirement.helperIdentifier
    public static let stagedLaunchDaemonPath = supportRoot + "/" + HelperRequirement.helperIdentifier + ".plist"

    // One file that the package puts under the install location. The owner and
    // group are always root:wheel; pkgbuild applies them when it archives the
    // payload. `destination` is where the file ends up after the postinstall
    // script. It equals the payload path for the engine and the right.
    public struct Entry: Equatable, Sendable {
        public let artifact: InstallerArtifact
        // Relative to `installLocation`.
        public let payloadPath: String
        public let payloadMode: UInt16
        public let destination: String
        public let destinationMode: UInt16
    }

    public static let entries: [Entry] = [
        Entry(
            artifact: .engine,
            payloadPath: "engine/hotspotshade",
            payloadMode: 0o755,
            destination: engineDestination,
            destinationMode: 0o755
        ),
        // The helper copy under the support directory is not executable. The
        // postinstall script installs the executable copy.
        Entry(
            artifact: .helper,
            payloadPath: supportDirectoryName + "/" + HelperRequirement.helperIdentifier,
            payloadMode: 0o644,
            destination: helperDestination,
            destinationMode: 0o755
        ),
        Entry(
            artifact: .launchDaemon,
            payloadPath: supportDirectoryName + "/" + HelperRequirement.helperIdentifier + ".plist",
            payloadMode: 0o644,
            destination: launchDaemonDestination,
            destinationMode: 0o644
        ),
        Entry(
            artifact: .startRight,
            payloadPath: supportDirectoryName + "/" + startRightName + ".plist",
            payloadMode: 0o644,
            destination: startRightDestination,
            destinationMode: 0o644
        ),
    ]

    // Directories that the payload creates, relative to `installLocation`.
    public static let payloadDirectories: [String] = ["engine", supportDirectoryName]
}

public enum InstallerArtifact: String, Sendable, CaseIterable, Codable {
    case helper
    case engine
    case launchDaemon
    case startRight
    // The app is checked for the team identity but is not part of the payload.
    case app
}

public enum InstallerError: Error, Equatable, CustomStringConvertible {
    case runningAsRoot
    case invalidArgument(String)
    case inputUnreadable(InstallerArtifact)
    case inputNotRegularFile(InstallerArtifact)
    case inputTooLarge(InstallerArtifact)
    case notMachO(InstallerArtifact)
    case unsupportedArchitecture(InstallerArtifact)
    case appNotSigned
    case signatureRejected(InstallerArtifact)
    case teamMismatch(InstallerArtifact)
    case plistInvalid(InstallerArtifact)
    case plistUnsafe(InstallerArtifact, String)
    case outputUnsafe(String)
    case stagingFailed(String)
    case digestMismatch(InstallerArtifact)
    case packageBuildFailed
    case packageAuditFailed(String)

    public var description: String {
        switch self {
        case .runningAsRoot: return "The installer build must not run as root."
        case .invalidArgument(let name): return "Invalid value for \(name)."
        case .inputUnreadable(let a): return "The \(a.rawValue) input cannot be read."
        case .inputNotRegularFile(let a): return "The \(a.rawValue) input is not a regular file."
        case .inputTooLarge(let a): return "The \(a.rawValue) input is too large or empty."
        case .notMachO(let a): return "The \(a.rawValue) input is not a Mach-O executable."
        case .unsupportedArchitecture(let a):
            return "The \(a.rawValue) input is not one thin arm64 executable. A universal file is refused."
        case .appNotSigned:
            return HelperRequirement.isLocalPreview
                ? "The app does not carry a protected Apple Development identity."
                : "The app does not carry a protected Developer ID identity."
        case .signatureRejected(let a): return "The \(a.rawValue) signature is not trusted."
        case .teamMismatch(let a): return "The \(a.rawValue) team differs from the app team."
        case .plistInvalid(let a): return "The \(a.rawValue) plist cannot be parsed."
        case .plistUnsafe(let a, let why): return "The \(a.rawValue) plist is unsafe: \(why)."
        case .outputUnsafe(let why): return "The output location is unsafe: \(why)."
        case .stagingFailed(let why): return "Staging failed: \(why)."
        case .digestMismatch(let a): return "The staged \(a.rawValue) changed after validation."
        case .packageBuildFailed: return "pkgbuild failed."
        case .packageAuditFailed(let why): return "The package audit failed: \(why)."
        }
    }
}
