import Darwin
import Foundation
import XCTest
import HotspotShadeKit
@testable import HotspotShadeInstallerCore

// The installed file set is root:wheel on a live host. A sandbox tree uses the
// installer's own owner and group. These tests prove that the group is set and
// verified, and that a clean host without /Library/PrivilegedHelperTools gets
// that one standard directory created and checked.
final class InstallOwnershipTests: XCTestCase {
    func testSandboxTreeUsesTheProcessOwnerAndGroup() throws {
        let fixture = try CoordinatorFixture()
        let tree = try ServiceTestFixtures.tree(fixture)
        XCTAssertEqual(tree.owner, UInt32(geteuid()))
        XCTAssertEqual(tree.group, UInt32(getegid()))
    }

    func testSystemPreviewUsesRootWheel() throws {
        XCTAssertEqual(InstallCoordinator.systemOwner, 0)
        XCTAssertEqual(InstallCoordinator.systemGroup, 0)
    }

    func testInstalledFilesCarryTheTreeGroup() throws {
        let fixture = try CoordinatorFixture()
        let outcome = try fixture.coordinator().install(source: fixture.source)
        XCTAssertEqual(outcome.fileCount, 4)
        let group = UInt32(getegid())
        for relative in [
            CoordinatorFixture.engineRelative,
            CoordinatorFixture.helperRelative,
            CoordinatorFixture.daemonRelative,
            CoordinatorFixture.rightRelative,
        ] {
            XCTAssertEqual(try groupID(fixture.sandbox + "/" + relative), group, relative)
        }
    }

    // Verification reads the group through the same descriptor checks as the
    // owner and mode. A tree that expects another group refuses the file.
    func testSnapshotRefusesAFileWithAnotherGroup() throws {
        let fixture = try CoordinatorFixture(oldPadding: 64)
        let wrong = try InstallTree(
            rootPath: fixture.sandbox,
            expectedOwner: UInt32(geteuid()),
            expectedGroup: nonMemberGroup(),
            syncHooks: .production
        )
        XCTAssertThrowsError(try wrong.snapshot(
            CoordinatorFixture.helperRelative, maximumBytes: 1 << 20
        )) {
            XCTAssertEqual($0 as? InstallTreeError, .wrongGroup(CoordinatorFixture.helperRelative))
        }
    }

    // A file cannot be given a group the installer does not belong to. The
    // atomic writer stops before the rename and removes its temporary file.
    func testWriteAtomicFailsClosedWhenTheGroupCannotBeSet() throws {
        let fixture = try CoordinatorFixture()
        try fixture.makeStateDirectory()
        let tree = try InstallTree(
            rootPath: fixture.sandbox,
            expectedOwner: UInt32(geteuid()),
            expectedGroup: nonMemberGroup(),
            syncHooks: .production
        )
        let relative = CoordinatorFixture.stateRelative + "/probe"
        XCTAssertThrowsError(try tree.writeAtomic(
            relative,
            data: Data("probe\n".utf8),
            mode: 0o600,
            temporarySuffix: "abcd",
            replaceExisting: false
        )) {
            guard case .io(let path, let code)? = $0 as? InstallTreeError else {
                return XCTFail("\($0)")
            }
            XCTAssertEqual(path, relative)
            XCTAssertNotEqual(code, 0)
        }
        XCTAssertFalse(fixture.targetExists(relative))
        XCTAssertEqual(fixture.temporaryNames(in: CoordinatorFixture.stateRelative), [])
    }

    // An upgrade verifies the previous file before it moves it. A previous file
    // with an incompatible group is refused and left untouched.
    func testInstallRefusesAnExistingFileWithAnotherGroup() throws {
        guard let otherGroup = alternateGroup() else {
            throw XCTSkip("The test account has no second group to assign.")
        }
        let fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
        let path = fixture.sandbox + "/" + CoordinatorFixture.helperRelative
        try changeGroup(of: path, to: otherGroup)
        XCTAssertEqual(try groupID(path), otherGroup)

        XCTAssertThrowsError(try fixture.coordinator().install(source: fixture.source)) {
            guard case .existingFileUnsafe(let detail)? = $0 as? CoordinatorError else {
                return XCTFail("\($0)")
            }
            XCTAssertTrue(detail.contains("group"), detail)
        }
        XCTAssertEqual(fixture.readTarget(CoordinatorFixture.helperRelative), fixture.oldHelper)
        XCTAssertEqual(try groupID(path), otherGroup)
        XCTAssertFalse(fixture.targetExists(CoordinatorFixture.journalRelative))
    }

    // Resume must not report success for an installed file whose group differs.
    // The staged copy uses the process group, so its cleanup still runs.
    func testResumeRefusesAnInstalledFileWithAnotherGroup() throws {
        guard let otherGroup = alternateGroup() else {
            throw XCTSkip("The test account has no second group to assign.")
        }
        let fixture = try CoordinatorFixture()
        let rights = FakeAuthorizationRightStore()
        let launchd = FakeLaunchdJobController()
        launchd.bootstrapError = LaunchdJobError.commandFailed("injected")
        let runtime = FakeServiceRuntime(authorizationRights: rights, launchd: launchd)
        let coordinator = try fixture.coordinator()
        XCTAssertThrowsError(try coordinator.installFirstTime(source: fixture.source, runtime: runtime))
        try fixture.assertNewSet()

        let path = fixture.sandbox + "/" + CoordinatorFixture.engineRelative
        try changeGroup(of: path, to: otherGroup)
        let writesBefore = rights.writes.count
        let bootstrapBefore = launchd.bootstrapCount
        XCTAssertThrowsError(try coordinator.resumeFirstTime(source: fixture.source, runtime: runtime)) {
            XCTAssertEqual(
                $0 as? CombinedInstallError,
                .installedFilesMismatch(CoordinatorFixture.engineRelative)
            )
        }
        XCTAssertEqual(rights.writes.count, writesBefore)
        XCTAssertEqual(launchd.bootstrapCount, bootstrapBefore)
        XCTAssertEqual(try groupID(path), otherGroup)
    }

    // A clean host can lack the standard helper directory. The first install
    // creates it 0755 and installs into it.
    func testFirstInstallCreatesAMissingHelperToolsDirectory() throws {
        let fixture = try CoordinatorFixture()
        try FileManager.default.removeItem(atPath: fixture.sandbox + "/Library/PrivilegedHelperTools")
        XCTAssertFalse(fixture.targetExists("Library/PrivilegedHelperTools"))

        let rights = FakeAuthorizationRightStore()
        let launchd = FakeLaunchdJobController()
        let result = try fixture.coordinator().installFirstTime(
            source: fixture.source,
            runtime: FakeServiceRuntime(authorizationRights: rights, launchd: launchd)
        )
        XCTAssertTrue(result.service.launchdJobLoaded)
        XCTAssertEqual(try fixture.targetMode("Library/PrivilegedHelperTools"), 0o755)
        XCTAssertEqual(
            try groupID(fixture.sandbox + "/Library/PrivilegedHelperTools"),
            UInt32(getegid())
        )
        try fixture.assertNewSet()
        fixture.assertNoJournal()
    }

    // An existing helper directory is checked and never changed.
    func testFirstInstallKeepsAnExistingHelperToolsDirectory() throws {
        let fixture = try CoordinatorFixture()
        try fixture.makeDirectory("Library/PrivilegedHelperTools", mode: 0o750)
        _ = try fixture.coordinator().installFirstTime(
            source: fixture.source,
            runtime: FakeServiceRuntime(
                authorizationRights: FakeAuthorizationRightStore(),
                launchd: FakeLaunchdJobController()
            )
        )
        XCTAssertEqual(try fixture.targetMode("Library/PrivilegedHelperTools"), 0o750)
        try fixture.assertNewSet()
    }

    // A missing required parent is a host the installer does not understand.
    // It fails closed and does not recreate the directory.
    func testFirstInstallRefusesAMissingRequiredParent() throws {
        let fixture = try CoordinatorFixture()
        try FileManager.default.removeItem(atPath: fixture.sandbox + "/Library/LaunchDaemons")
        let rights = FakeAuthorizationRightStore()
        let launchd = FakeLaunchdJobController()
        XCTAssertThrowsError(try fixture.coordinator().installFirstTime(
            source: fixture.source,
            runtime: FakeServiceRuntime(authorizationRights: rights, launchd: launchd)
        )) {
            guard case .unsafeDirectory? = $0 as? CoordinatorError else {
                return XCTFail("\($0)")
            }
        }
        XCTAssertFalse(fixture.targetExists("Library/LaunchDaemons"))
        XCTAssertFalse(fixture.targetExists(CoordinatorFixture.engineRelative))
        XCTAssertTrue(rights.writes.isEmpty)
        XCTAssertEqual(launchd.bootstrapCount, 0)
    }

    // An unsafe object at the helper directory name is refused, not replaced.
    func testFirstInstallRefusesAnUnsafeHelperToolsDirectory() throws {
        enum Shape: String, CaseIterable {
            case symlink
            case writable
            case regularFile
        }
        for shape in Shape.allCases {
            let fixture = try CoordinatorFixture()
            let path = fixture.sandbox + "/Library/PrivilegedHelperTools"
            try FileManager.default.removeItem(atPath: path)
            switch shape {
            case .symlink:
                try FileManager.default.createSymbolicLink(
                    atPath: path,
                    withDestinationPath: "Application Support"
                )
            case .writable:
                try fixture.makeDirectory("Library/PrivilegedHelperTools", mode: 0o777)
            case .regularFile:
                try fixture.writeFile(path, Data("not a directory\n".utf8), mode: 0o755)
            }
            let rights = FakeAuthorizationRightStore()
            let launchd = FakeLaunchdJobController()
            XCTAssertThrowsError(try fixture.coordinator().installFirstTime(
                source: fixture.source,
                runtime: FakeServiceRuntime(authorizationRights: rights, launchd: launchd)
            ), shape.rawValue) {
                guard case .unsafeDirectory? = $0 as? CoordinatorError else {
                    return XCTFail("\(shape.rawValue): \($0)")
                }
            }
            XCTAssertFalse(
                fixture.targetExists(CoordinatorFixture.engineRelative),
                shape.rawValue
            )
            XCTAssertTrue(rights.writes.isEmpty, shape.rawValue)
            XCTAssertEqual(launchd.bootstrapCount, 0, shape.rawValue)
        }
    }

    // A rolled-back first install removes the directories the journal names.
    // The standard helper directory is not journaled, so it can remain empty.
    func testRolledBackFirstInstallLeavesOnlyAnEmptyHelperToolsDirectory() throws {
        let fixture = try CoordinatorFixture()
        try FileManager.default.removeItem(atPath: fixture.sandbox + "/Library/PrivilegedHelperTools")
        XCTAssertThrowsError(
            try fixture.coordinator(faults: CoordinatorFaultAt(.fileInstalled0))
                .install(source: fixture.source)
        )
        _ = try fixture.coordinator().recover()
        XCTAssertTrue(fixture.targetExists("Library/PrivilegedHelperTools"))
        XCTAssertEqual(try fixture.targetMode("Library/PrivilegedHelperTools"), 0o755)
        let tree = try ServiceTestFixtures.tree(fixture)
        XCTAssertEqual(try tree.listDirectory("Library/PrivilegedHelperTools"), [])
        XCTAssertFalse(fixture.targetExists("Library/Application Support/HotspotShade"))
        fixture.assertNoJournal()
        fixture.assertNoBackups()
    }

    // Committed recovery re-verifies the new set. A wrong group is damage, not
    // a successful recovery, and the journal is kept for inspection.
    func testCommittedRecoveryRefusesAnInstalledFileWithAnotherGroup() throws {
        guard let otherGroup = alternateGroup() else {
            throw XCTSkip("The test account has no second group to assign.")
        }
        let fixture = try CoordinatorFixture()
        XCTAssertThrowsError(
            try fixture.coordinator(faults: CoordinatorFaultAt(.commitJournalWritten))
                .install(source: fixture.source)
        )
        let path = fixture.sandbox + "/" + CoordinatorFixture.engineRelative
        try changeGroup(of: path, to: otherGroup)
        XCTAssertThrowsError(try fixture.coordinator().recover()) {
            guard case .committedStateDamaged(let why)? = $0 as? CoordinatorError else {
                return XCTFail("\($0)")
            }
            XCTAssertTrue(why.contains("group"), why)
        }
        XCTAssertTrue(fixture.targetExists(CoordinatorFixture.journalRelative))
        XCTAssertEqual(try groupID(path), otherGroup)
    }

    // MARK: helpers

    private func groupID(_ path: String) throws -> UInt32 {
        var status = stat()
        guard lstat(path, &status) == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        return status.st_gid
    }

    private func groupList() -> [UInt32] {
        var groups = [gid_t](repeating: 0, count: 64)
        let count = getgroups(Int32(groups.count), &groups)
        guard count > 0 else { return [UInt32(getegid())] }
        var list = groups[0..<Int(count)].map { UInt32($0) }
        list.append(UInt32(getegid()))
        return list
    }

    private func alternateGroup() -> UInt32? {
        let effective = UInt32(getegid())
        return groupList().first { $0 != effective }
    }

    private func nonMemberGroup() -> UInt32 {
        let known = Set(groupList())
        var candidate: UInt32 = 60_123
        while known.contains(candidate) { candidate += 1 }
        return candidate
    }

    private func changeGroup(of path: String, to group: UInt32) throws {
        guard chown(path, uid_t(geteuid()), gid_t(group)) == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
    }
}
