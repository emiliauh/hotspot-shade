import Foundation

// The record of what the package holds. It carries digests and fixed paths. It
// holds no secret, no signing identity, and no host name. The notes keep the
// unverified claims next to the artifact.
public struct InstallerManifest: Codable, Equatable, Sendable {
    public struct File: Codable, Equatable, Sendable {
        public let role: String
        // Relative to the install location; the script name for a script.
        public let payloadPath: String
        public let payloadMode: String
        public let destination: String
        public let destinationMode: String
        public let sha256: String
        public let size: Int
    }

    public let schemaVersion: Int
    public let packageIdentifier: String
    public let version: String
    public let installLocation: String
    public let teamIdentifier: String
    public let packageSigned: Bool
    // False on every build of this foundation. The preinstall script refuses
    // for the same reason: there is no exclusion held for the whole install
    // and shared by every start path. Do not treat the artifact as installable.
    public let installationApproved: Bool
    public let files: [File]
    public let scripts: [File]
    public let notes: [String]

    public static let notes: [String] = [
        "NOT APPROVED FOR INSTALLATION. The preinstall script refuses before any check or change.",
        "No exclusion is held for the whole installation and shared by the helper, the direct command line start, and every other root start path. Do not install this package.",
        "A sandbox-only coordinator core, install journal, and crash-recovery tests exist. They do not make this package installable.",
        "The helper and the Rust engine currently use different start lock names. The sandbox coordinator holds a transition set. One reviewed lock name and an initial migration are still required.",
        "The package is unsigned. Sign and notarize it in a separate release step after the exclusion design is approved and implemented.",
        "Signatures were checked statically before staging. A live install is unverified.",
        "The helper install, the start right write, and the XPC path have not run on a signed host.",
        "A later approved package would install under one directory it owns. Its postinstall script would copy the helper and launch daemon file to their protected paths.",
    ]

    public func encoded() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try encoder.encode(self)
    }
}
