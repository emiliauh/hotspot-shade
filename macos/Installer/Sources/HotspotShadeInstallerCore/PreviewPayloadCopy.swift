import Darwin
import Foundation

// Copies a user-supplied preview into a private directory owned by the
// installing process. The returned source is validated against the manifest
// and signatures after the copy. This is not a live install entry point.
enum PreviewPayloadCopy {
    enum CopyError: Error, Equatable {
        case unsafeWorkspace
        case cannotCreateWorkspace
        case cannotSetMode
        case cleanupFailed
    }

    struct Result {
        let source: CoordinatorSource
        fileprivate let directory: String
    }

    static func copy(
        source: CoordinatorSource,
        into tree: InstallTree,
        validator: InstallerValidator
    ) throws -> Result {
        let parent = InstallLockLayout.stateDirectoryRelative
        guard source.payloadRoot.hasPrefix("/"), !source.payloadRoot.contains("\0"),
              tree.owner == UInt32(geteuid()), try tree.directoryMode(parent) == 0o700 else {
            throw CopyError.unsafeWorkspace
        }
        let directory = parent + "/preview-input-" + SystemSupport.randomHex(byteCount: 16)
        guard try !tree.entryExists(directory),
              try tree.ensureDirectory(directory, mode: 0o700, create: true) == [directory]
        else { throw CopyError.cannotCreateWorkspace }
        let result = Result(
            source: CoordinatorSource(
                payloadRoot: try tree.path(for: directory + "/payload"),
                manifest: source.manifest,
                expectedTeamIdentifier: source.expectedTeamIdentifier
            ),
            directory: directory
        )
        do {
            _ = try tree.ensureDirectory(directory + "/payload", mode: 0o700, create: true)
            for component in InstallerLayout.payloadDirectories {
                _ = try tree.ensureDirectory(directory + "/payload/" + component, mode: 0o700, create: true)
            }
            for entry in InstallerLayout.entries {
                guard let supplied = SafeRelativePath.join(root: source.payloadRoot, relative: entry.payloadPath) else {
                    throw CoordinatorError.payloadInvalid("the payload path is invalid")
                }
                let copied = try tree.path(for: directory + "/payload/" + entry.payloadPath)
                _ = try ArtifactIngest.copy(
                    source: supplied, destination: copied, artifact: entry.artifact,
                    maximumBytes: InstallJournal.maximumSize(for: entry.artifact)
                )
                guard chmod(copied, mode_t(entry.payloadMode)) == 0 else { throw CopyError.cannotSetMode }
            }
            _ = try CoordinatorPayloadValidator.validate(
                result.source, validator: validator, expectedOwner: tree.owner
            )
            return result
        } catch {
            do { try remove(result, from: tree) } catch { throw CopyError.cleanupFailed }
            throw error
        }
    }

    // The caller holds the install lease until it has finished using the copy.
    // Stop on a failed removal so an uncertain cleanup is not reported as clean.
    static func remove(_ result: Result, from tree: InstallTree) throws {
        for entry in InstallerLayout.entries {
            _ = try tree.removeFile(result.directory + "/payload/" + entry.payloadPath, expectedDigest: nil)
        }
        for component in InstallerLayout.payloadDirectories.reversed() {
            _ = try tree.removeDirectoryIfEmpty(result.directory + "/payload/" + component, expectedMode: 0o700)
        }
        _ = try tree.removeDirectoryIfEmpty(result.directory + "/payload", expectedMode: 0o700)
        _ = try tree.removeDirectoryIfEmpty(result.directory, expectedMode: 0o700)
    }
}
