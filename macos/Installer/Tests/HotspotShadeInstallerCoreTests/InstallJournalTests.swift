import Foundation
import XCTest
import HotspotShadeKit
@testable import HotspotShadeInstallerCore

// The file journal decides whether recovery rolls forward or back. These tests
// pin the durable-write contract: a failure before the rename is a clean
// failure, and a failure after the rename is an unknown outcome that the
// caller must never treat as a no-op. No read-back is used to classify either
// case.
final class InstallJournalTests: XCTestCase {
    private func preparedFixture() throws -> (CoordinatorFixture, InstallTree, InstallJournal) {
        let fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
        XCTAssertThrowsError(
            try fixture.coordinator(faults: CoordinatorFaultAt(.journalPrepared))
                .install(source: fixture.source)
        ) {
            XCTAssertEqual($0 as? CoordinatorError, .simulatedCrash(.journalPrepared))
        }
        let tree = try InstallTree(
            rootPath: fixture.sandbox,
            expectedOwner: UInt32(geteuid())
        )
        let journal = try XCTUnwrap(try InstallJournalStore(tree: tree).read())
        XCTAssertEqual(journal.phase, .preparing)
        return (fixture, tree, journal)
    }

    func testPostRenameDirectorySyncFailureIsAnUnknownJournalWrite() throws {
        let (fixture, tree, journal) = try preparedFixture()
        let replacing = journal.withPhase(.replacing)
        let store = InstallJournalStore(tree: tree) {
            relative, data, mode, temporarySuffix, replaceExisting in
            try tree.writeAtomic(
                relative,
                data: data,
                mode: mode,
                temporarySuffix: temporarySuffix,
                replaceExisting: replaceExisting,
                directorySync: { _ in
                    errno = EIO
                    return -1
                }
            )
        }

        XCTAssertThrowsError(try store.write(replacing)) {
            guard case .journalWriteUncertain? = $0 as? CoordinatorError else {
                return XCTFail("\($0)")
            }
        }
        // The renamed record is visible. That observation is not a durability
        // proof, so the store reports an unknown outcome rather than a clean
        // failure or a successful write.
        XCTAssertEqual(try InstallJournalStore(tree: tree).read(), replacing)
        XCTAssertTrue(fixture.targetExists(CoordinatorFixture.journalRelative))
    }

    func testPreRenameJournalFailureLeavesThePreviousRecord() throws {
        let (fixture, tree, journal) = try preparedFixture()
        let store = InstallJournalStore(tree: tree) { relative, _, _, _, _ in
            throw InstallTreeError.io(relative, EIO)
        }

        XCTAssertThrowsError(try store.write(journal.withPhase(.replacing))) {
            guard case .io? = $0 as? CoordinatorError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertEqual(try InstallJournalStore(tree: tree).read(), journal)
        XCTAssertTrue(fixture.targetExists(CoordinatorFixture.journalRelative))
    }

    func testAtomicWriteReportsPostRenameSyncFailureAsUncertain() throws {
        let fixture = try CoordinatorFixture()
        try fixture.makeStateDirectory()
        let tree = try InstallTree(
            rootPath: fixture.sandbox,
            expectedOwner: UInt32(geteuid())
        )
        let relative = CoordinatorFixture.stateRelative + "/atomic-probe"
        let data = Data("the new bytes\n".utf8)

        XCTAssertThrowsError(
            try tree.writeAtomic(
                relative,
                data: data,
                mode: 0o600,
                temporarySuffix: "abcd",
                replaceExisting: true,
                directorySync: { _ in
                    errno = EIO
                    return -1
                }
            )
        ) {
            XCTAssertEqual($0 as? InstallTreeError, .writeUncertain(relative))
        }
        XCTAssertEqual(try tree.readFile(relative, maximumBytes: 64), data)
        XCTAssertEqual(try tree.snapshot(relative, maximumBytes: 64)?.mode, 0o600)
    }

    func testAtomicWritePreRenameFailureIsNotUncertain() throws {
        let fixture = try CoordinatorFixture()
        try fixture.makeStateDirectory()
        let tree = try InstallTree(
            rootPath: fixture.sandbox,
            expectedOwner: UInt32(geteuid())
        )
        let relative = CoordinatorFixture.stateRelative + "/atomic-probe"
        let data = Data("the first bytes\n".utf8)
        try tree.writeAtomic(
            relative,
            data: data,
            mode: 0o600,
            temporarySuffix: "aaaa",
            replaceExisting: true
        )

        XCTAssertThrowsError(
            try tree.writeAtomic(
                relative,
                data: Data("the replacement\n".utf8),
                mode: 0o600,
                temporarySuffix: "bbbb",
                replaceExisting: false,
                directorySync: { _ in
                    XCTFail("the directory sync ran after a pre-rename failure")
                    return 0
                }
            )
        ) {
            XCTAssertEqual($0 as? InstallTreeError, .alreadyExists(relative))
        }
        XCTAssertEqual(try tree.readFile(relative, maximumBytes: 64), data)
    }
}
