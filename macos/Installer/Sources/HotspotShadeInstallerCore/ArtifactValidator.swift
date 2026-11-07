import Foundation
import CoreFoundation
import HotspotShadeKit

// Checks the supplied artifacts against the rules that the helper applies at
// runtime. A pass here does not replace the helper's own checks on the
// installed files. It stops a bad package from being built.
public struct InstallerValidator: Sendable {
    private let signatures: HelperCodeSignatureChecking

    public init(signatures: HelperCodeSignatureChecking = StrictSecurityCodeSignatureChecker()) {
        self.signatures = signatures
    }

    // The team comes from the app signature, the same source the helper uses.
    // It never comes from an argument, a plist, or an environment variable.
    public func teamIdentifier(ofApp path: String) throws -> String {
        var status = stat()
        guard lstat(path, &status) == 0,
              status.st_mode & S_IFMT == S_IFDIR,
              path.hasSuffix(".app")
        else {
            throw InstallerError.appNotSigned
        }
        let team: String
        do {
            team = try HelperInstallPolicy.developerTeamIdentifier(
                bundlePath: path,
                signatures: signatures
            )
        } catch {
            throw InstallerError.appNotSigned
        }
        // The signature passed. The app's main executable must also be one
        // thin arm64 file, so no other slice hides behind the signed one.
        try requireThinMainExecutable(ofApp: path)
        return team
    }

    // `Contents/Info.plist` names the main executable. The name must be one
    // plain path component, and the file must be a regular file under
    // `Contents/MacOS` that is one thin arm64 executable.
    func requireThinMainExecutable(ofApp path: String) throws {
        let infoPath = path + "/Contents/Info.plist"
        var status = stat()
        guard lstat(infoPath, &status) == 0, status.st_mode & S_IFMT == S_IFREG,
              status.st_size > 0, status.st_size <= off_t(ArtifactIngest.maximumPlistBytes) * 16,
              let data = try? Data(contentsOf: URL(fileURLWithPath: infoPath)),
              let parsed = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
              let info = parsed as? [String: Any],
              let name = info["CFBundleExecutable"] as? String,
              !name.isEmpty, name != ".", name != "..", !name.contains("/"), !name.contains("\0")
        else {
            throw InstallerError.appNotSigned
        }
        let executable = path + "/Contents/MacOS/" + name
        guard lstat(executable, &status) == 0, status.st_mode & S_IFMT == S_IFREG else {
            throw InstallerError.appNotSigned
        }
        try requireThinArm64(atPath: executable, artifact: .app)
    }

    func requireThinArm64(atPath path: String, artifact: InstallerArtifact) throws {
        switch MachOPolicy.classify(atPath: path) {
        case .thinArm64Executable: return
        case .notMachO: throw InstallerError.notMachO(artifact)
        case .unsupported: throw InstallerError.unsupportedArchitecture(artifact)
        }
    }

    public func validateExecutable(
        atPath path: String,
        artifact: InstallerArtifact,
        identifier: String,
        teamIdentifier: String
    ) throws {
        // Architecture first. The signature check below reads one slice of a
        // fat file, so a fat file never reaches it.
        try requireThinArm64(atPath: path, artifact: artifact)
        let requirement: String
        do {
            requirement = try HelperRequirement.make(identifier: identifier, teamIdentifier: teamIdentifier)
            try signatures.verifyStaticCode(atPath: path, requirement: requirement)
        } catch {
            throw InstallerError.signatureRejected(artifact)
        }
        let info: HelperSigningInfo
        do { info = try signatures.signingInfo(atPath: path) } catch {
            throw InstallerError.signatureRejected(artifact)
        }
        guard info.isProtectedIdentity, info.identifier == identifier else {
            throw InstallerError.signatureRejected(artifact)
        }
        guard info.teamIdentifier == teamIdentifier else {
            throw InstallerError.teamMismatch(artifact)
        }
    }

    // The launch daemon file is stricter than the helper's own check. The
    // helper's check ignores unknown keys. A root launchd job must not carry
    // a key that redirects output, adds a watch path, or sets an environment.
    public func validateLaunchDaemon(_ data: Data) throws {
        let object = try dictionary(data, artifact: .launchDaemon)
        let allowed: Set<String> = [
            "Label", "ProgramArguments", "MachServices", "RunAtLoad", "KeepAlive",
            "ProcessType", "ThrottleInterval", "ExitTimeOut",
        ]
        let extra = Set(object.keys).subtracting(allowed)
        guard extra.isEmpty else {
            throw InstallerError.plistUnsafe(.launchDaemon, "unexpected key")
        }
        guard Plist.isBoolean(object["RunAtLoad"], equalTo: false),
              Plist.isBoolean(object["KeepAlive"], equalTo: false)
        else {
            throw InstallerError.plistUnsafe(.launchDaemon, "RunAtLoad and KeepAlive must be false")
        }
        guard let services = object["MachServices"] as? [String: Any],
              services.count == 1,
              Plist.isBoolean(services[HelperRequirement.helperServiceName], equalTo: true)
        else {
            throw InstallerError.plistUnsafe(.launchDaemon, "MachServices must name only the helper")
        }
        if let processType = object["ProcessType"], processType as? String != "Interactive" {
            throw InstallerError.plistUnsafe(.launchDaemon, "ProcessType")
        }
        for (key, range) in [("ThrottleInterval", 1...60), ("ExitTimeOut", 60...600)] {
            if let value = object[key] {
                guard let number = value as? NSNumber, !Plist.isBoolean(value),
                      range.contains(number.intValue), number.doubleValue == Double(number.intValue)
                else {
                    throw InstallerError.plistUnsafe(.launchDaemon, key)
                }
            }
        }
        do {
            try HelperLaunchDaemonPolicy.validate(
                plistData: data,
                helperPath: InstallerLayout.helperDestination,
                serviceName: HelperRequirement.helperServiceName
            )
        } catch {
            throw InstallerError.plistUnsafe(.launchDaemon, "helper policy refused it")
        }
    }

    // The right definition must be the install-time shape. The authd metadata
    // keys that the helper tolerates on a read-back do not belong in a source
    // plist, so they are refused here.
    public func validateStartRight(_ data: Data) throws {
        let object = try dictionary(data, artifact: .startRight)
        let installed: Set<String> = [
            "class", "group", "authenticate-user", "shared", "allow-root", "timeout", "comment",
        ]
        guard Set(object.keys).isSubset(of: installed) else {
            throw InstallerError.plistUnsafe(.startRight, "unexpected key")
        }
        guard HelperStartRightValidator.isSafe(object) else {
            throw InstallerError.plistUnsafe(.startRight, "helper right policy refused it")
        }
    }

    private func dictionary(_ data: Data, artifact: InstallerArtifact) throws -> [String: Any] {
        guard data.count <= ArtifactIngest.maximumPlistBytes,
              let parsed = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
              let object = parsed as? [String: Any]
        else {
            throw InstallerError.plistInvalid(artifact)
        }
        return object
    }
}

enum Plist {
    // A number 0 or 1 also bridges to Bool, so test the real type.
    static func isBoolean(_ value: Any?, equalTo expected: Bool) -> Bool {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) == CFBooleanGetTypeID()
        else { return false }
        return number.boolValue == expected
    }

    static func isBoolean(_ value: Any) -> Bool {
        guard let number = value as? NSNumber else { return false }
        return CFGetTypeID(number) == CFBooleanGetTypeID()
    }
}
