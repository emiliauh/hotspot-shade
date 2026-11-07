import Foundation
import Darwin
import HotspotShadeKit

public struct CoordinatorSource: Sendable {
    public let payloadRoot: String
    public let manifest: InstallerManifest
    public let expectedTeamIdentifier: String

    public init(
        payloadRoot: String,
        manifest: InstallerManifest,
        expectedTeamIdentifier: String
    ) {
        self.payloadRoot = payloadRoot
        self.manifest = manifest
        self.expectedTeamIdentifier = expectedTeamIdentifier
    }
}

public struct CoordinatorOperation: Equatable, Sendable {
    public let index: Int
    public let artifact: String
    public let sourcePath: String
    public let destinationRelative: String
    public let mode: UInt16
    public let sha256: String
    public let size: Int
}

// Checks the staged set that the coordinator will install. It repeats the
// build checks against the bytes that are about to be copied: the exact file
// set, the digests, the launch daemon file, the start right, and the helper and
// engine signatures. A pass here is not a live trust decision. The team still
// comes from a caller in this foundation, and no Developer ID chain has been
// tested.
public enum CoordinatorPayloadValidator {
    public static func validate(
        _ source: CoordinatorSource,
        validator: InstallerValidator,
        expectedOwner: UInt32
    ) throws -> [CoordinatorOperation] {
        let manifest = source.manifest
        guard manifest.schemaVersion == 1 else {
            throw CoordinatorError.manifestInvalid("the schema version is not supported")
        }
        guard manifest.packageIdentifier == InstallerLayout.packageIdentifier else {
            throw CoordinatorError.manifestInvalid("the package identifier is not the fixed value")
        }
        guard InstallerBuilder.isValidVersion(manifest.version) else {
            throw CoordinatorError.manifestInvalid("the version is malformed")
        }
        guard manifest.installLocation == InstallerLayout.installLocation else {
            throw CoordinatorError.manifestInvalid("the install location is not the fixed value")
        }
        guard HelperRequirement.isValidTeamIdentifier(source.expectedTeamIdentifier) else {
            throw CoordinatorError.manifestInvalid("the expected team identifier is malformed")
        }
        guard manifest.teamIdentifier == source.expectedTeamIdentifier else {
            throw CoordinatorError.manifestInvalid("the team identifier differs from the expected team")
        }
        // The preinstall refusal and installationApproved false stay in place
        // until every real blocker is resolved. A manifest that claims
        // approval cannot turn those into an install.
        guard !manifest.installationApproved else {
            throw CoordinatorError.manifestRefused("the manifest claims installation approval")
        }
        guard !manifest.packageSigned else {
            throw CoordinatorError.manifestRefused("the package signature cannot be verified here")
        }

        let resolvedRoot = try resolvePayloadRoot(source.payloadRoot, expectedOwner: expectedOwner)
        try validateExactTree(
            resolvedRoot,
            expectedOwner: expectedOwner,
            maximumBytes: InstallerLayout.entries.reduce(0) { value, entry in
                max(value, InstallJournal.maximumSize(for: entry.artifact))
            }
        )
        try validateScriptRecords(manifest)
        try validateFileRecords(manifest, payloadRoot: resolvedRoot)
        try validateArtifactContent(
            manifest,
            payloadRoot: resolvedRoot,
            validator: validator,
            teamIdentifier: source.expectedTeamIdentifier,
            expectedOwner: expectedOwner
        )

        return try InstallerLayout.entries.enumerated().map { index, entry in
            guard let record = manifest.files.first(where: { $0.role == entry.artifact.rawValue }),
                  let sourcePath = SafeRelativePath.join(root: resolvedRoot, relative: record.payloadPath)
            else {
                throw CoordinatorError.manifestInvalid("a layout entry has no file record")
            }
            return CoordinatorOperation(
                index: index,
                artifact: entry.artifact.rawValue,
                sourcePath: sourcePath,
                destinationRelative: InstallJournal.relativeDestination(entry.destination),
                mode: entry.destinationMode,
                sha256: record.sha256,
                size: record.size
            )
        }
    }

    private static func resolvePayloadRoot(_ requested: String, expectedOwner: UInt32) throws -> String {
        guard requested.hasPrefix("/"), !requested.contains("\0") else {
            throw CoordinatorError.payloadInvalid("the payload root must be absolute")
        }
        guard let resolvedPointer = realpath(requested, nil) else {
            throw CoordinatorError.payloadInvalid("the payload root does not exist")
        }
        defer { free(resolvedPointer) }
        let resolved = String(cString: resolvedPointer)
        var status = stat()
        guard lstat(resolved, &status) == 0,
              status.st_mode & S_IFMT == S_IFDIR,
              status.st_uid == expectedOwner,
              status.st_mode & 0o022 == 0,
              !SystemSupport.hasExtendedACL(path: resolved)
        else {
            throw CoordinatorError.payloadInvalid("the payload root owner or mode is wrong")
        }
        return resolved
    }

    private static func validateExactTree(
        _ root: String,
        expectedOwner: UInt32,
        maximumBytes: Int
    ) throws {
        var expected: [String: Bool] = [
            "engine": true,
            InstallerLayout.supportDirectoryName: true,
        ]
        for entry in InstallerLayout.entries {
            expected[entry.payloadPath] = false
        }
        guard let enumerator = FileManager.default.enumerator(atPath: root) else {
            throw CoordinatorError.payloadInvalid("the payload tree cannot be read")
        }
        var found: [String: Bool] = [:]
        for case let relative as String in enumerator {
            guard SafeRelativePath.isValid(relative),
                  let joined = SafeRelativePath.join(root: root, relative: relative)
            else { throw CoordinatorError.payloadInvalid("the payload holds an unsafe path") }
            var status = stat()
            guard lstat(joined, &status) == 0 else {
                throw CoordinatorError.payloadInvalid("a payload object cannot be read")
            }
            guard status.st_uid == expectedOwner,
                  !SystemSupport.hasExtendedACL(path: joined)
            else {
                throw CoordinatorError.payloadInvalid("a payload object has the wrong owner or an access control list")
            }
            switch status.st_mode & S_IFMT {
            case S_IFREG:
                guard status.st_nlink == 1 else {
                    throw CoordinatorError.payloadInvalid("a payload file has more than one link")
                }
                guard status.st_size > 0, status.st_size <= off_t(maximumBytes) else {
                    throw CoordinatorError.payloadInvalid("a payload file has a wrong size")
                }
                found[relative] = false
            case S_IFDIR:
                found[relative] = true
            default:
                throw CoordinatorError.payloadInvalid("the payload holds a link or special file")
            }
        }
        guard Set(found.keys) == Set(expected.keys) else {
            throw CoordinatorError.payloadInvalid("the payload holds a different set of objects")
        }
        for (path, isDirectory) in expected where found[path] != isDirectory {
            throw CoordinatorError.payloadInvalid("a payload object has the wrong type: \(path)")
        }
    }

    private static func validateScriptRecords(_ manifest: InstallerManifest) throws {
        guard manifest.scripts.count == 2 else {
            throw CoordinatorError.manifestInvalid("the script record count is not two")
        }
        let names = [InstallerScripts.preinstallName, InstallerScripts.postinstallName]
        guard Set(manifest.scripts.map(\.payloadPath)) == Set(names) else {
            throw CoordinatorError.manifestInvalid("the script names are not the fixed set")
        }
        for script in manifest.scripts {
            guard script.role == "script",
                  script.payloadMode == "755",
                  script.destination.isEmpty,
                  script.destinationMode == "755",
                  SystemSupport.isLowercaseHex(script.sha256, count: 64),
                  script.size > 0,
                  script.size <= ArtifactIngest.maximumPlistBytes
            else { throw CoordinatorError.manifestInvalid("a script record is malformed") }
        }
    }

    private static func validateFileRecords(_ manifest: InstallerManifest, payloadRoot: String) throws {
        guard manifest.files.count == InstallerLayout.entries.count else {
            throw CoordinatorError.manifestInvalid("the file record count is not the fixed layout")
        }
        var roles = Set<String>()
        for record in manifest.files {
            guard roles.insert(record.role).inserted else {
                throw CoordinatorError.manifestInvalid("a file role appears twice")
            }
        }
        let expectedRoles = Set(InstallerLayout.entries.map { $0.artifact.rawValue })
        guard roles == expectedRoles else {
            throw CoordinatorError.manifestInvalid("the file roles are not the fixed layout")
        }

        for entry in InstallerLayout.entries {
            guard let record = manifest.files.first(where: { $0.role == entry.artifact.rawValue }),
                  record.payloadPath == entry.payloadPath,
                  record.payloadMode == String(entry.payloadMode, radix: 8),
                  record.destination == entry.destination,
                  record.destinationMode == String(entry.destinationMode, radix: 8),
                  SystemSupport.isLowercaseHex(record.sha256, count: 64),
                  record.size > 0,
                  record.size <= InstallJournal.maximumSize(for: entry.artifact),
                  let path = SafeRelativePath.join(root: payloadRoot, relative: record.payloadPath)
            else {
                throw CoordinatorError.manifestInvalid("a file record does not match the layout")
            }
            let actual: IngestedFile
            do {
                actual = try ArtifactIngest.sha256(ofFileAt: path, artifact: entry.artifact)
            } catch {
                throw CoordinatorError.payloadInvalid("a payload file cannot be read")
            }
            guard actual.size == record.size, actual.sha256 == record.sha256 else {
                throw CoordinatorError.digestMismatch(entry.payloadPath)
            }
        }
    }

    private static func validateArtifactContent(
        _ manifest: InstallerManifest,
        payloadRoot: String,
        validator: InstallerValidator,
        teamIdentifier: String,
        expectedOwner: UInt32
    ) throws {
        func record(_ artifact: InstallerArtifact) throws -> String {
            guard let file = manifest.files.first(where: { $0.role == artifact.rawValue }),
                  let path = SafeRelativePath.join(root: payloadRoot, relative: file.payloadPath)
            else { throw CoordinatorError.manifestInvalid("a layout entry has no file record") }
            return path
        }

        let helperPath = try record(.helper)
        do {
            try validator.validateExecutable(
                atPath: helperPath,
                artifact: .helper,
                identifier: HelperRequirement.helperIdentifier,
                teamIdentifier: teamIdentifier
            )
        } catch let error as InstallerError {
            throw CoordinatorError.artifactRejected(error.description)
        } catch {
            throw CoordinatorError.artifactRejected("the helper signature cannot be checked")
        }

        let enginePath = try record(.engine)
        do {
            try validator.validateExecutable(
                atPath: enginePath,
                artifact: .engine,
                identifier: HelperRequirement.engineIdentifier,
                teamIdentifier: teamIdentifier
            )
        } catch let error as InstallerError {
            throw CoordinatorError.artifactRejected(error.description)
        } catch {
            throw CoordinatorError.artifactRejected("the engine signature cannot be checked")
        }

        let daemonPath = try record(.launchDaemon)
        let daemonData = try readBounded(
            daemonPath, maximumBytes: ArtifactIngest.maximumPlistBytes, expectedOwner: expectedOwner
        )
        do {
            try validator.validateLaunchDaemon(daemonData)
        } catch let error as InstallerError {
            throw CoordinatorError.artifactRejected(error.description)
        } catch {
            throw CoordinatorError.artifactRejected("the launch daemon file cannot be checked")
        }

        let rightPath = try record(.startRight)
        let rightData = try readBounded(
            rightPath, maximumBytes: ArtifactIngest.maximumPlistBytes, expectedOwner: expectedOwner
        )
        do {
            try validator.validateStartRight(rightData)
        } catch let error as InstallerError {
            throw CoordinatorError.artifactRejected(error.description)
        } catch {
            throw CoordinatorError.artifactRejected("the start right cannot be checked")
        }
    }

    private static func readBounded(
        _ path: String,
        maximumBytes: Int,
        expectedOwner: UInt32
    ) throws -> Data {
        let descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else {
            throw CoordinatorError.payloadInvalid("a payload file cannot be opened")
        }
        defer { close(descriptor) }
        var status = stat()
        guard fstat(descriptor, &status) == 0,
              status.st_mode & S_IFMT == S_IFREG,
              status.st_uid == expectedOwner,
              status.st_nlink == 1,
              status.st_size > 0,
              status.st_size <= off_t(maximumBytes),
              !SystemSupport.hasExtendedACL(descriptor)
        else { throw CoordinatorError.payloadInvalid("a payload file is not a safe regular file") }
        guard let data = SystemSupport.readAll(descriptor, maximumBytes: maximumBytes),
              data.count == Int(status.st_size)
        else { throw CoordinatorError.payloadInvalid("a payload file cannot be read") }
        return data
    }
}
