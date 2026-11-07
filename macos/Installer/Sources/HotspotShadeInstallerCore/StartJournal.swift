import Foundation
import Darwin

// A read-only view of the helper start journal. The helper writes this record
// after it takes its shared lock and before it writes a launch intent. A
// present record means an engine start may still own routes. The coordinator
// never removes it and never treats it as an install journal.
//
// The record also names the lock device and inode that the helper used. A
// record for a different inode proves that the helper and the coordinator did
// not share one lock. The coordinator reports that mismatch instead of calling
// the lock exclusion.
public struct HelperStartJournalRecord: Equatable, Sendable {
    public let version: Int
    public let session: UUID
    public let lockDevice: UInt64
    public let lockInode: UInt64
    public let handoffDescriptor: Int32
}

public enum StartJournalProbe {
    public static let relativePath = InstallLockLayout.stateDirectoryRelative
        + "/" + InstallLockLayout.startJournalName
    public static let maximumBytes = 512
    public static let header = "hotspotshade-start-journal 1"
    public static let lineCount = 5
    // The helper writes this record with mode 0600, one link, and no special
    // bit. A reader requires the exact mode, so a 0644, 0400, set-id, or hard
    // linked record is refused rather than parsed.
    public static let fileMode: UInt16 = 0o600

    public static func read(_ tree: InstallTree) throws -> HelperStartJournalRecord? {
        let data: Data?
        do {
            data = try tree.readFile(
                relativePath,
                maximumBytes: maximumBytes,
                requiredMode: fileMode
            )
        } catch {
            throw CoordinatorError.startJournalUnreadable("the record cannot be read safely")
        }
        guard let data else { return nil }
        guard let text = String(data: data, encoding: .utf8), text.hasSuffix("\n") else {
            throw CoordinatorError.startJournalUnreadable("the record is not newline-terminated UTF-8")
        }
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false).dropLast()
        guard lines.count == lineCount,
              lines[0] == Substring(header),
              lines[1].hasPrefix("session "),
              lines[2].hasPrefix("lock-device "),
              lines[3].hasPrefix("lock-inode "),
              lines[4] == Substring("handoff-descriptor \(InstallLockLayout.handoffDescriptor)")
        else {
            throw CoordinatorError.startJournalUnreadable("the record shape is not protocol version 1")
        }
        guard let session = UUID(uuidString: String(lines[1].dropFirst("session ".count))) else {
            throw CoordinatorError.startJournalUnreadable("the session is malformed")
        }
        guard let device = decimal(String(lines[2].dropFirst("lock-device ".count))),
              let inode = decimal(String(lines[3].dropFirst("lock-inode ".count)))
        else {
            throw CoordinatorError.startJournalUnreadable("the lock identity is malformed")
        }
        return HelperStartJournalRecord(
            version: 1,
            session: session,
            lockDevice: device,
            lockInode: inode,
            handoffDescriptor: InstallLockLayout.handoffDescriptor
        )
    }

    private static func decimal(_ text: String) -> UInt64? {
        guard !text.isEmpty, text.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }) else {
            return nil
        }
        return UInt64(text)
    }
}
