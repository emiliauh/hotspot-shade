import Foundation

// Build a source from the running coordinator's verified identity and the
// signed app. The manifest and an argument supplied by a caller are not team
// authorities. This does not enable or perform installation.
public enum PreviewIdentityBinding {
    public enum BindingError: Error, Equatable {
        case teamMismatch
    }

    public static func source(
        appPath: String,
        payloadRoot: String,
        manifest: InstallerManifest
    ) throws -> CoordinatorSource {
        try source(
            appPath: appPath, payloadRoot: payloadRoot, manifest: manifest,
            coordinatorTeam: InstallerSelfIdentity.teamIdentifier(),
            validator: InstallerValidator()
        )
    }

    // The production entry point above always obtains the team from the
    // running signed process. This seam permits hermetic signature-policy tests.
    static func source(
        appPath: String,
        payloadRoot: String,
        manifest: InstallerManifest,
        coordinatorTeam: String,
        validator: InstallerValidator
    ) throws -> CoordinatorSource {
        let appTeam = try validator.teamIdentifier(ofApp: appPath)
        guard appTeam == coordinatorTeam, manifest.teamIdentifier == coordinatorTeam else {
            throw BindingError.teamMismatch
        }
        return CoordinatorSource(
            payloadRoot: payloadRoot, manifest: manifest, expectedTeamIdentifier: coordinatorTeam
        )
    }
}
