import Darwin
import Foundation
import HotspotShadeKit

// The system entry point is separate from the non-root sandbox coordinator.
// It is disabled unless both local-preview and system-candidate flags are set.
public enum PreviewSystemInstaller {
    public enum Action: String {
        case install
        case resume
        case recoverFiles
        case recoverService
    }

    public static func run(
        _ action: Action,
        appPath: String,
        payloadRoot: String,
        manifest: InstallerManifest
    ) throws {
        switch action {
        case .recoverFiles:
            _ = try recoverFiles()
            return
        case .recoverService:
            _ = try recoverService()
            return
        case .install, .resume:
            break
        }
        try requireSystemPreview()
        // The team is obtained from the running coordinator and verified app,
        // not from a command-line team or the manifest alone.
        let source = try PreviewIdentityBinding.source(
            appPath: appPath, payloadRoot: payloadRoot, manifest: manifest
        )
        let coordinator = try InstallCoordinator.previewSystem()
        let runtime = SystemPrivilegedServiceRuntime()
        switch action {
        case .install:
            _ = try coordinator.installFirstTime(source: source, runtime: runtime)
        case .resume:
            _ = try coordinator.resumeFirstTime(source: source, runtime: runtime)
        case .recoverFiles, .recoverService:
            // These cases return before opening the app or payload above.
            throw CoordinatorError.notApproved
        }
    }

    public static func recoverFiles() throws -> RecoveryOutcome {
        try requireSystemPreview()
        _ = try InstallerSelfIdentity.teamIdentifier()
        return try InstallCoordinator.previewSystem().recover()
    }

    public static func recoverService() throws -> ServiceRecoveryOutcome {
        try requireSystemPreview()
        let team = try InstallerSelfIdentity.teamIdentifier()
        return try InstallCoordinator.previewSystem().recoverFirstTimeService(
            runtime: SystemPrivilegedServiceRuntime(), teamIdentifier: team
        )
    }

    public static func status() throws -> CoordinatorStatus {
        try requireSystemPreview()
        _ = try InstallerSelfIdentity.teamIdentifier()
        return try InstallCoordinator.previewSystem().status()
    }

    // Remove the validated fixed set from a first-install attempt. The
    // same approval gate, root requirement, and coordinator identity apply. The
    // cleanup refuses an unfinished transaction, a start participant, a foreign
    // file, right, or job, and a held exclusion lock. It never removes a
    // journal, marker, lock file, the installed app, or the placed preview tree.
    public static func uninstall() throws -> PreviewCleanupReport {
        guard previewGateIsOpen else { throw PreviewCleanupError.notApproved }
        guard geteuid() == 0 else { throw PreviewCleanupError.requiresRoot }
        return try PreviewFirstInstallCleanup.systemPreview().run()
    }

    // Clear the durable cleanup block and the launch intent after the host
    // shows no helper, no root engine, no HotspotShade route, no journal,
    // and no start-exclusion holder. It never changes a route.
    public static func clearCleanupBlock() throws -> PreviewClearReport {
        guard previewGateIsOpen else { throw PreviewClearError.notApproved }
        guard geteuid() == 0 else { throw PreviewClearError.requiresRoot }
        return try PreviewCleanupBlockClear.systemPreview().run()
    }

    private static var previewGateIsOpen: Bool {
        HelperRequirement.isLocalPreview && CoordinatorPolicy.localPreviewInstallationApproved
    }

    private static func requireSystemPreview() throws {
        guard previewGateIsOpen else { throw CoordinatorError.notApproved }
        guard geteuid() == 0 else { throw ServiceTransactionError.requiresRoot }
    }
}
