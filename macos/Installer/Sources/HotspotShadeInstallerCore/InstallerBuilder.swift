import Foundation
import Darwin
import HotspotShadeKit

public struct InstallerInputs: Equatable, Sendable {
    public let helper: String
    public let engine: String
    public let launchDaemon: String
    public let startRight: String
    public let app: String

    public init(helper: String, engine: String, launchDaemon: String, startRight: String, app: String) {
        self.helper = helper
        self.engine = engine
        self.launchDaemon = launchDaemon
        self.startRight = startRight
        self.app = app
    }
}

public struct StagedInstaller: Equatable, Sendable {
    public let outputDirectory: String
    public let payloadDirectory: String
    public let scriptsDirectory: String
    public let manifestPath: String
    public let manifest: InstallerManifest
}

public struct BuiltInstaller: Equatable, Sendable {
    public let packagePath: String
    // SHA-256 of the package file that the audit read. The same value is in
    // `digestPath`, in the `shasum -a 256` line format.
    public let packageSHA256: String
    public let digestPath: String
    public let staged: StagedInstaller
}

// Runs pkgbuild and pkgutil. A test replaces it so that no tool runs.
public protocol InstallerToolRunning: Sendable {
    func run(_ tool: InstallerTool, arguments: [String]) throws -> String
}

public enum InstallerTool: String, Sendable {
    case pkgbuild = "/usr/bin/pkgbuild"
    case pkgutil = "/usr/sbin/pkgutil"
    case lsbom = "/usr/bin/lsbom"
}

public struct SystemInstallerToolRunner: InstallerToolRunning {
    public init() {}

    public func run(_ tool: InstallerTool, arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: tool.rawValue)
        process.arguments = arguments
        // A fixed, minimal environment. The tool path is absolute.
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"]
        let output = Pipe()
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        do { try process.run() } catch { throw InstallerError.packageBuildFailed }
        // Read before wait so a full pipe cannot block the tool.
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw InstallerError.packageBuildFailed }
        return String(decoding: data, as: UTF8.self)
    }
}

// Builds one unsigned component package from signed artifacts. The build writes
// only inside one new directory that it creates with mode 0700. It never runs
// as root, never installs, and never runs a script.
public struct InstallerBuilder: Sendable {
    private let validator: InstallerValidator
    private let tools: InstallerToolRunning
    private let effectiveUserID: @Sendable () -> UInt32

    public init(
        validator: InstallerValidator = InstallerValidator(),
        tools: InstallerToolRunning = SystemInstallerToolRunner(),
        effectiveUserID: @escaping @Sendable () -> UInt32 = { UInt32(geteuid()) }
    ) {
        self.validator = validator
        self.tools = tools
        self.effectiveUserID = effectiveUserID
    }

    public static func isValidVersion(_ value: String) -> Bool {
        let parts = value.split(separator: ".", omittingEmptySubsequences: false)
        guard (1...3).contains(parts.count) else { return false }
        return parts.allSatisfy { $0.count >= 1 && $0.count <= 4 && $0.allSatisfy { $0.isASCII && $0.isNumber } }
    }

    // Validate and stage. This is the whole check. It does not call pkgbuild.
    public func stage(inputs: InstallerInputs, version: String, outputDirectory: String) throws -> StagedInstaller {
        guard effectiveUserID() != 0 else { throw InstallerError.runningAsRoot }
        guard Self.isValidVersion(version) else { throw InstallerError.invalidArgument("version") }
        let team = try validator.teamIdentifier(ofApp: inputs.app)
        let output = try OutputPolicy.resolve(outputDirectory)
        guard mkdir(output, 0o700) == 0 else { throw InstallerError.outputUnsafe("cannot create it") }
        do {
            return try stageInside(output, inputs: inputs, version: version, team: team)
        } catch {
            Self.removeOwnedOutput(output)
            throw error
        }
    }

    public func build(inputs: InstallerInputs, version: String, outputDirectory: String) throws -> BuiltInstaller {
        let staged = try stage(inputs: inputs, version: version, outputDirectory: outputDirectory)
        do {
            let package = staged.outputDirectory + "/HotspotShade-\(version)-unsigned.pkg"
            _ = try tools.run(.pkgbuild, arguments: [
                "--root", staged.payloadDirectory,
                "--identifier", InstallerLayout.packageIdentifier,
                "--version", version,
                "--install-location", InstallerLayout.installLocation,
                "--scripts", staged.scriptsDirectory,
                "--ownership", "recommended",
                package,
            ])
            // Hash the package before the audit and again after it. A package
            // that changes while the audit reads it was not the audited file.
            let before = try Self.packageDigest(package)
            try PackageAudit(validator: validator, tools: tools).audit(
                packagePath: package,
                manifest: staged.manifest,
                scratchDirectory: staged.outputDirectory + "/audit"
            )
            let after = try Self.packageDigest(package)
            guard before == after else {
                throw InstallerError.packageAuditFailed("the package changed while it was audited")
            }
            let digestPath = package + ".sha256"
            let line = "\(after.sha256)  \((package as NSString).lastPathComponent)\n"
            guard writeFile(digestPath, data: Data(line.utf8), mode: 0o600) else {
                throw InstallerError.stagingFailed("cannot write the package digest")
            }
            return BuiltInstaller(
                packagePath: package,
                packageSHA256: after.sha256,
                digestPath: digestPath,
                staged: staged
            )
        } catch {
            Self.removeOwnedOutput(staged.outputDirectory)
            throw error
        }
    }

    private static func packageDigest(_ path: String) throws -> IngestedFile {
        do { return try ArtifactIngest.sha256(ofFileAt: path, artifact: .app) } catch {
            throw InstallerError.packageAuditFailed("the package cannot be read")
        }
    }

    private func stageInside(
        _ output: String,
        inputs: InstallerInputs,
        version: String,
        team: String
    ) throws -> StagedInstaller {
        let incoming = output + "/inputs"
        try makeDirectory(incoming, mode: 0o700)
        let sources: [(InstallerArtifact, String, String, Int)] = [
            (.helper, inputs.helper, incoming + "/helper", ArtifactIngest.maximumExecutableBytes),
            (.engine, inputs.engine, incoming + "/engine", ArtifactIngest.maximumExecutableBytes),
            (.launchDaemon, inputs.launchDaemon, incoming + "/launch-daemon.plist", ArtifactIngest.maximumPlistBytes),
            (.startRight, inputs.startRight, incoming + "/start-right.plist", ArtifactIngest.maximumPlistBytes),
        ]
        var copied: [InstallerArtifact: (path: String, file: IngestedFile)] = [:]
        for (artifact, source, destination, limit) in sources {
            copied[artifact] = (
                destination,
                try ArtifactIngest.copy(source: source, destination: destination, artifact: artifact, maximumBytes: limit)
            )
        }
        // Everything below reads the staged copies.
        try validator.validateExecutable(
            atPath: copied[.helper]!.path,
            artifact: .helper,
            identifier: HelperRequirement.helperIdentifier,
            teamIdentifier: team
        )
        try validator.validateExecutable(
            atPath: copied[.engine]!.path,
            artifact: .engine,
            identifier: HelperRequirement.engineIdentifier,
            teamIdentifier: team
        )
        try validator.validateLaunchDaemon(try Data(contentsOf: URL(fileURLWithPath: copied[.launchDaemon]!.path)))
        try validator.validateStartRight(try Data(contentsOf: URL(fileURLWithPath: copied[.startRight]!.path)))

        let payload = output + "/payload"
        try makeDirectory(payload, mode: 0o755)
        for directory in InstallerLayout.payloadDirectories {
            try makeDirectory(payload + "/" + directory, mode: 0o755)
        }
        var files: [InstallerManifest.File] = []
        for entry in InstallerLayout.entries {
            let item = copied[entry.artifact]!
            let target = payload + "/" + entry.payloadPath
            // The same inode moves into the payload. The content is not copied
            // again, and the digest check below confirms it.
            guard rename(item.path, target) == 0, chmod(target, mode_t(entry.payloadMode)) == 0 else {
                throw InstallerError.stagingFailed("cannot place a payload file")
            }
            files.append(InstallerManifest.File(
                role: entry.artifact.rawValue,
                payloadPath: entry.payloadPath,
                payloadMode: String(entry.payloadMode, radix: 8),
                destination: entry.destination,
                destinationMode: String(entry.destinationMode, radix: 8),
                sha256: item.file.sha256,
                size: item.file.size
            ))
        }
        try removeEmptyDirectory(incoming)

        let scriptsDirectory = output + "/scripts"
        try makeDirectory(scriptsDirectory, mode: 0o755)
        var scripts: [InstallerManifest.File] = []
        for (name, text) in [
            (InstallerScripts.preinstallName, InstallerScripts.preinstall),
            (InstallerScripts.postinstallName, InstallerScripts.postinstall),
        ] {
            let path = scriptsDirectory + "/" + name
            let data = Data(text.utf8)
            guard writeFile(path, data: data, mode: 0o755) else {
                throw InstallerError.stagingFailed("cannot write a script")
            }
            let digest = try ArtifactIngest.sha256(ofStagedFileAt: path)
            scripts.append(InstallerManifest.File(
                role: "script", payloadPath: name, payloadMode: "755",
                destination: "", destinationMode: "755", sha256: digest.sha256, size: digest.size
            ))
        }

        let manifest = InstallerManifest(
            schemaVersion: 1,
            packageIdentifier: InstallerLayout.packageIdentifier,
            version: version,
            installLocation: InstallerLayout.installLocation,
            teamIdentifier: team,
            packageSigned: false,
            installationApproved: InstallerScripts.installationApproved,
            files: files,
            scripts: scripts,
            notes: InstallerManifest.notes
        )
        let manifestPath = output + "/manifest.json"
        guard writeFile(manifestPath, data: try manifest.encoded(), mode: 0o600) else {
            throw InstallerError.stagingFailed("cannot write the manifest")
        }
        let staged = StagedInstaller(
            outputDirectory: output,
            payloadDirectory: payload,
            scriptsDirectory: scriptsDirectory,
            manifestPath: manifestPath,
            manifest: manifest
        )
        try verifyPayload(staged, team: team)
        return staged
    }

    // Re-hash the payload and re-check the signatures right before the package
    // is built, so a file that changed after the first check is caught.
    func verifyPayload(_ staged: StagedInstaller, team: String) throws {
        for entry in InstallerLayout.entries {
            let path = staged.payloadDirectory + "/" + entry.payloadPath
            guard let recorded = staged.manifest.files.first(where: { $0.role == entry.artifact.rawValue }),
                  let now = try? ArtifactIngest.sha256(ofFileAt: path, artifact: entry.artifact),
                  now.sha256 == recorded.sha256
            else {
                throw InstallerError.digestMismatch(entry.artifact)
            }
        }
        try PackageAudit.verifySignatures(
            validator: validator,
            root: staged.payloadDirectory,
            team: team
        )
    }

    private func makeDirectory(_ path: String, mode: mode_t) throws {
        // mkdir applies the umask. chmod sets the exact mode.
        guard mkdir(path, mode) == 0, chmod(path, mode) == 0 else {
            throw InstallerError.stagingFailed("cannot create a directory")
        }
    }

    private func removeEmptyDirectory(_ path: String) throws {
        guard rmdir(path) == 0 else { throw InstallerError.stagingFailed("a staged file was left behind") }
    }

    private func writeFile(_ path: String, data: Data, mode: mode_t) -> Bool {
        let descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { return false }
        defer { close(descriptor) }
        var written = 0
        let ok = data.withUnsafeBytes { buffer -> Bool in
            while written < buffer.count {
                let count = write(descriptor, buffer.baseAddress!.advanced(by: written), buffer.count - written)
                if count < 0 {
                    if errno == EINTR { continue }
                    return false
                }
                written += count
            }
            return true
        }
        return ok && fchmod(descriptor, mode) == 0 && fsync(descriptor) == 0
    }

    // Remove only the directory that this build just created, and only when it
    // is still a real directory owned by this user.
    static func removeOwnedOutput(_ path: String) {
        var status = stat()
        guard lstat(path, &status) == 0,
              status.st_mode & S_IFMT == S_IFDIR,
              status.st_uid == geteuid()
        else { return }
        try? FileManager.default.removeItem(atPath: path)
    }
}
