import Foundation
import Darwin

// A durable cleanup block. A helper that cannot prove an engine stopped may
// leave root-owned routes behind. The block therefore has to outlive the helper
// process, not only its session. The store writes one root-owned marker under a
// root-owned directory. The marker is created once with O_EXCL and is never
// removed automatically, not on startup, not after a later stop, and not by an
// update. A person must follow the inspection steps in macos/Helper/README.md
// and escalate. That README does not approve removing the marker by hand.
//
// Reads fail closed. A missing directory or marker means no block. Any other
// condition, including a symlink, a non-root owner, a group or other write bit,
// or an unreadable path, throws so the caller treats the host as blocked. The
// helper never "repairs" an unsafe marker by deleting it.
public protocol HelperCleanupBlockStoring: Sendable {
    func isBlocked() throws -> Bool
    func recordBlock(reason: String) throws
}

public enum HelperCleanupBlockError: Error, Equatable {
    case unsafe
    case unreadable
    case writeFailed
}

public struct RootCleanupBlockStore: HelperCleanupBlockStoring {
    public static let defaultDirectoryPath = "/var/db/hotspotshade"
    public static let defaultFileName = "cleanup-blocked"

    private let directoryPath: String
    private let fileName: String
    private let expectedOwner: UInt32

    public init(
        directoryPath: String = RootCleanupBlockStore.defaultDirectoryPath,
        fileName: String = RootCleanupBlockStore.defaultFileName
    ) {
        self.init(directoryPath: directoryPath, fileName: fileName, expectedOwner: 0)
    }

    // The owner seam exists for the hermetic tests, which cannot run as root.
    // The public initializer always requires root.
    init(directoryPath: String, fileName: String, expectedOwner: UInt32) {
        self.directoryPath = directoryPath
        self.fileName = fileName
        self.expectedOwner = expectedOwner
    }

    public var markerPath: String { directoryPath + "/" + fileName }

    private var state: RootStateDirectory {
        RootStateDirectory(path: directoryPath, expectedOwner: expectedOwner)
    }

    public func isBlocked() throws -> Bool {
        do {
            return try state.contains(fileName)
        } catch let error as RootStateDirectoryError {
            throw Self.map(error)
        } catch {
            throw HelperCleanupBlockError.unreadable
        }
    }

    public func recordBlock(reason: String) throws {
        do {
            try state.ensure()
            let directory = try state.openExisting()
            defer { close(directory) }

            // Create the marker once with O_EXCL. An existing safe marker is
            // accepted and left in place: a block is never cleared here. If the
            // name exists as a symlink or any other unsafe object, the open
            // fails and the caller keeps the host blocked.
            var descriptor = openat(
                directory,
                fileName,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK,
                mode_t(0o600)
            )
            if descriptor < 0 && errno == EEXIST {
                descriptor = openat(
                    directory,
                    fileName,
                    O_WRONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK
                )
            }
            guard descriptor >= 0 else {
                throw HelperCleanupBlockError.writeFailed
            }
            defer { close(descriptor) }

            var status = stat()
            guard fstat(descriptor, &status) == 0,
                  status.st_mode & S_IFMT == S_IFREG,
                  status.st_uid == expectedOwner,
                  status.st_mode & 0o077 == 0,
                  try !RootStateDirectory.hasExtendedACL(descriptor)
            else {
                throw HelperCleanupBlockError.unsafe
            }
            if status.st_size == 0 {
                let text = String(reason.prefix(200)) + "\n"
                let bytes = Array(text.utf8)
                let written = bytes.withUnsafeBytes { buffer -> Int in
                    guard let base = buffer.baseAddress else { return 0 }
                    return write(descriptor, base, bytes.count)
                }
                guard written == bytes.count else {
                    throw HelperCleanupBlockError.writeFailed
                }
                guard fsync(descriptor) == 0 else {
                    throw HelperCleanupBlockError.writeFailed
                }
            }
            // The marker name must be durable before the caller trusts the
            // block, even when the file already existed from an earlier run.
            guard fsync(directory) == 0 else {
                throw HelperCleanupBlockError.writeFailed
            }
        } catch let error as HelperCleanupBlockError {
            throw error
        } catch let error as RootStateDirectoryError {
            throw Self.map(error)
        } catch {
            throw HelperCleanupBlockError.unreadable
        }
    }

    private static func map(_ error: RootStateDirectoryError) -> HelperCleanupBlockError {
        switch error {
        case .unsafe: return .unsafe
        case .unreadable: return .unreadable
        case .writeFailed, .alreadyPresent, .createRollbackUncertain: return .writeFailed
        }
    }
}
