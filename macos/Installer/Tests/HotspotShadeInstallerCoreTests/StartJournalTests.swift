import Foundation
import XCTest
@testable import HotspotShadeInstallerCore

final class StartJournalTests: XCTestCase {
    private func journalText(device: UInt64, inode: UInt64, session: UUID = UUID()) -> String {
        """
        hotspotshade-start-journal 1
        session \(session.uuidString.lowercased())
        lock-device \(device)
        lock-inode \(inode)
        handoff-descriptor 5

        """
    }

    private func lockIdentity(
        _ fixture: CoordinatorFixture
    ) throws -> InstallLock.Identity {
        let state = fixture.sandbox + "/" + CoordinatorFixture.stateRelative
        let held = try InstallLock.acquire(
            parentDirectory: state,
            mode: .exclusive,
            expectedOwner: UInt32(geteuid())
        )
        let identity = held.identity
        held.release()
        return identity
    }

    private func quotedValue(after marker: String, in source: String) -> String? {
        guard let range = source.range(of: marker) else { return nil }
        guard let end = source[range.upperBound...].firstIndex(of: "\"") else { return nil }
        return String(source[range.upperBound..<end])
    }

    func testCanonicalLockNameMatchesTheHelperAndRustEngineSource() throws {
        let rust = try String(
            contentsOf: Repo.root.appendingPathComponent("rust/src/macos_upgrade_lock.rs"),
            encoding: .utf8
        )
        let helper = try String(
            contentsOf: Repo.root.appendingPathComponent(
                "macos/HotspotShadeKit/Sources/HotspotShadeKit/ProtectedHelper/HelperStartExclusion.swift"
            ),
            encoding: .utf8
        )
        let rustName = quotedValue(after: "LOCK_FILE_NAME: &str = \"", in: rust)
        let helperName = quotedValue(after: "lockFileName = \"", in: helper)
        XCTAssertNotNil(rustName)
        XCTAssertNotNil(helperName)
        XCTAssertTrue(
            InstallLockLayout.heldFileNames.contains(rustName ?? ""),
            "the Rust engine uses a lock name outside the coordinator's held set"
        )
        XCTAssertTrue(
            InstallLockLayout.heldFileNames.contains(helperName ?? ""),
            "the helper uses a lock name outside the coordinator's held set"
        )
        XCTAssertTrue(
            rust.contains("LOCK_DIRECTORY: &str = \"/var/db/hotspotshade\""),
            "the Rust engine lock directory changed"
        )
        XCTAssertTrue(rust.contains("acquire_for_tunnel_start"))
        XCTAssertTrue(rust.contains("retain_until_exit"))
        XCTAssertTrue(rust.contains("HOTSPOTSHADE_START_EXCLUSION_FD"))
        XCTAssertTrue(helper.contains("handoffDescriptor: Int32 = 5"))
    }

    func testStartJournalForTheCanonicalLockBlocksInstallAndRecovery() throws {
        let fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
        try fixture.makeStateDirectory()
        let identity = try lockIdentity(fixture)
        try fixture.writeState(
            InstallLockLayout.startJournalName,
            Data(journalText(device: identity.device, inode: identity.inode).utf8)
        )

        XCTAssertThrowsError(try fixture.coordinator().install(source: fixture.source)) {
            XCTAssertEqual($0 as? CoordinatorError, .startJournalPresent)
        }
        try fixture.assertOldSet()
        XCTAssertTrue(fixture.targetExists(
            CoordinatorFixture.stateRelative + "/" + InstallLockLayout.startJournalName
        ))

        XCTAssertThrowsError(try fixture.coordinator().recover()) {
            XCTAssertEqual($0 as? CoordinatorError, .startJournalPresent)
        }
        XCTAssertTrue(fixture.targetExists(
            CoordinatorFixture.stateRelative + "/" + InstallLockLayout.startJournalName
        ), "recovery removed a start journal that it does not own")

        let status = try fixture.coordinator().status()
        XCTAssertTrue(status.startJournalPresent)
        XCTAssertEqual(status.startJournalLockMatchesHeldLock, true)
    }

    func testStartJournalForADifferentLockReportsTheIncompatibleContract() throws {
        let fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
        try fixture.makeStateDirectory()
        let identity = try lockIdentity(fixture)
        try fixture.writeState(
            InstallLockLayout.startJournalName,
            Data(journalText(device: identity.device, inode: identity.inode + 1).utf8)
        )
        XCTAssertThrowsError(try fixture.coordinator().install(source: fixture.source)) {
            if case .participantLockIncompatible? = $0 as? CoordinatorError {} else {
                XCTFail("\($0)")
            }
        }
        try fixture.assertOldSet()
        let status = try fixture.coordinator().status()
        XCTAssertTrue(status.startJournalPresent)
        XCTAssertEqual(status.startJournalLockMatchesHeldLock, false)
        XCTAssertTrue(fixture.targetExists(
            CoordinatorFixture.stateRelative + "/" + InstallLockLayout.startJournalName
        ))
    }

    func testMalformedStartJournalIsRefusedAndKept() throws {
        let fixture = try CoordinatorFixture()
        try fixture.makeStateDirectory()
        try fixture.writeState(
            InstallLockLayout.startJournalName,
            Data("not a start journal\n".utf8)
        )
        XCTAssertThrowsError(try fixture.coordinator().install(source: fixture.source)) {
            if case .startJournalUnreadable? = $0 as? CoordinatorError {} else { XCTFail("\($0)") }
        }
        XCTAssertThrowsError(try fixture.coordinator().recover()) {
            if case .startJournalUnreadable? = $0 as? CoordinatorError {} else { XCTFail("\($0)") }
        }
        XCTAssertTrue(fixture.targetExists(
            CoordinatorFixture.stateRelative + "/" + InstallLockLayout.startJournalName
        ))
        XCTAssertFalse(fixture.targetExists(CoordinatorFixture.engineRelative))
    }

    func testStartJournalWithTheWrongHandoffDescriptorIsUnreadable() throws {
        let fixture = try CoordinatorFixture()
        try fixture.makeStateDirectory()
        let identity = try lockIdentity(fixture)
        let wrong = journalText(device: identity.device, inode: identity.inode)
            .replacingOccurrences(of: "handoff-descriptor 5", with: "handoff-descriptor 6")
        try fixture.writeState(InstallLockLayout.startJournalName, Data(wrong.utf8))
        XCTAssertThrowsError(try fixture.coordinator().install(source: fixture.source)) {
            if case .startJournalUnreadable? = $0 as? CoordinatorError {} else { XCTFail("\($0)") }
        }
    }

    func testStartJournalDoesNotBecomeAnInstallJournal() throws {
        let fixture = try CoordinatorFixture()
        try fixture.makeStateDirectory()
        let identity = try lockIdentity(fixture)
        try fixture.writeState(
            InstallLockLayout.startJournalName,
            Data(journalText(device: identity.device, inode: identity.inode).utf8)
        )
        XCTAssertThrowsError(try fixture.coordinator().recover()) {
            XCTAssertEqual($0 as? CoordinatorError, .startJournalPresent)
        }
        XCTAssertTrue(fixture.targetExists(
            CoordinatorFixture.stateRelative + "/" + InstallLockLayout.startJournalName
        ))
        XCTAssertFalse(fixture.targetExists(CoordinatorFixture.journalRelative))
    }

    // The start journal contract is mode 0600, one link, no special bit. A
    // record with any other shape is refused, not parsed, and it is kept.
    func testStartJournalRequiresExact0600AndOneLink() throws {
        let fixture = try CoordinatorFixture()
        try fixture.makeStateDirectory()
        let identity = try lockIdentity(fixture)
        let text = journalText(device: identity.device, inode: identity.inode)
        let journalPath = fixture.sandbox
            + "/" + CoordinatorFixture.stateRelative
            + "/" + InstallLockLayout.startJournalName

        for mode in [0o644, 0o400, 0o4600, 0o2600, 0o1600] {
            // A read-only file from the previous iteration cannot be rewritten
            // in place. Reset the mode before the next fixture write.
            if FileManager.default.fileExists(atPath: journalPath) {
                try FileManager.default.setAttributes(
                    [.posixPermissions: 0o600],
                    ofItemAtPath: journalPath
                )
            }
            try fixture.writeState(
                InstallLockLayout.startJournalName,
                Data(text.utf8),
                mode: mode
            )
            XCTAssertThrowsError(
                try fixture.coordinator().install(source: fixture.source),
                "mode \(String(mode, radix: 8))"
            ) {
                guard case .startJournalUnreadable? = $0 as? CoordinatorError else {
                    return XCTFail("\(String(mode, radix: 8)): \($0)")
                }
            }
            XCTAssertTrue(FileManager.default.fileExists(atPath: journalPath))
        }

        try fixture.writeState(
            InstallLockLayout.startJournalName,
            Data(text.utf8),
            mode: 0o600
        )
        let duplicate = fixture.sandbox
            + "/" + CoordinatorFixture.stateRelative + "/start-journal-copy"
        XCTAssertEqual(
            link(journalPath, duplicate),
            0,
            "the test could not create a hard link"
        )
        XCTAssertThrowsError(try fixture.coordinator().install(source: fixture.source)) {
            guard case .startJournalUnreadable? = $0 as? CoordinatorError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertTrue(FileManager.default.fileExists(atPath: journalPath))
    }
}
