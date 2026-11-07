import Foundation

// A durable write-ahead intent for one root engine launch. The controller
// creates the intent before it asks the launcher to spawn an engine, and the
// file is synced to disk with its containing directory before spawn returns.
// The intent closes the crash window in the cleanup marker: if the helper dies
// while an engine can exist, the marker alone cannot tell a later helper that
// the engine may still own routes.
//
// The intent is removed only after a verified clean engine stop. It is not
// removed on a failed spawn that cannot prove the absence of a child, on an
// unclean stop, on a timed-out stop, on an engine exit that nobody requested,
// or by a later helper. A record that another participant owns is re-read
// before a later start refuses; once that participant removes it, the helper
// may start. A record that this helper could not clear stays uncertain and is
// never cleared automatically. A helper restart with a present intent refuses
// every start until it is gone. The inspection steps in macos/Helper/README.md
// do not approve removing the file by hand. The intent stores no process id,
// so recovery never signals a recycled pid.
//
// A failed create rolls back only the inode that this call created. The
// rollback proves the held descriptor and the name still resolve to the same
// regular file, with one link and no extended ACL, and it syncs the removal.
// A changed, hard-linked, ACL-bearing, unreadable, or unsynced record is kept
// as ambiguous evidence. The store reports that case as `rollbackUncertain`,
// and the controller latches a block that a later absence read cannot clear.
// macOS has no unlink-by-inode call, so a cooperative root participant is
// assumed between the final identity check and the unlink.
public protocol HelperLaunchIntentStoring: Sendable {
    func isPresent() throws -> Bool
    func create() throws
    func clearAfterVerifiedCleanStop() throws
}

public enum HelperLaunchIntentError: Error, Equatable {
    case alreadyPresent
    case unsafe
    case unreadable
    case writeFailed
    // A create failed after the record name existed, and the store could not
    // prove that the record is gone. The controller must keep the start gate
    // closed and must never re-evaluate this uncertainty as a clean absence.
    case rollbackUncertain
}

public struct RootLaunchIntentStore: HelperLaunchIntentStoring {
    public static let defaultDirectoryPath = RootCleanupBlockStore.defaultDirectoryPath
    public static let defaultFileName = "engine-session"
    private static let contents = Array("hotspotshade engine launch intent\n".utf8)

    private let directoryPath: String
    private let fileName: String
    private let expectedOwner: UInt32
    private let seam: RootStateDirectorySeam

    public init(
        directoryPath: String = RootLaunchIntentStore.defaultDirectoryPath,
        fileName: String = RootLaunchIntentStore.defaultFileName
    ) {
        self.init(directoryPath: directoryPath, fileName: fileName, expectedOwner: 0)
    }

    // The owner and seam parameters exist for the hermetic tests, which cannot
    // run as root and need a deterministic create failure. The public
    // initializer always requires root and the real file operations.
    init(
        directoryPath: String,
        fileName: String,
        expectedOwner: UInt32,
        seam: RootStateDirectorySeam = .production
    ) {
        self.directoryPath = directoryPath
        self.fileName = fileName
        self.expectedOwner = expectedOwner
        self.seam = seam
    }

    public var intentPath: String { directoryPath + "/" + fileName }

    private var state: RootStateDirectory {
        RootStateDirectory(path: directoryPath, expectedOwner: expectedOwner, seam: seam)
    }

    public func isPresent() throws -> Bool {
        do {
            return try state.contains(fileName)
        } catch let error as RootStateDirectoryError {
            throw Self.map(error)
        } catch {
            throw HelperLaunchIntentError.unreadable
        }
    }

    public func create() throws {
        do {
            // O_EXCL, file fsync, and directory fsync all live in the state
            // store. An existing intent is refused, never overwritten.
            try state.createFile(fileName, contents: Self.contents)
        } catch let error as RootStateDirectoryError {
            throw Self.map(error)
        } catch {
            throw HelperLaunchIntentError.writeFailed
        }
    }

    public func clearAfterVerifiedCleanStop() throws {
        do {
            try state.removeFile(fileName)
        } catch let error as RootStateDirectoryError {
            throw Self.map(error)
        } catch {
            throw HelperLaunchIntentError.writeFailed
        }
    }

    private static func map(_ error: RootStateDirectoryError) -> HelperLaunchIntentError {
        switch error {
        case .alreadyPresent: return .alreadyPresent
        case .unsafe: return .unsafe
        case .unreadable: return .unreadable
        case .writeFailed: return .writeFailed
        case .createRollbackUncertain: return .rollbackUncertain
        }
    }
}
