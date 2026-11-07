import Darwin
import Foundation
import XCTest
import HotspotShadeKit
@testable import HotspotShadeInstallerCore

// The clear command runs against a sandbox tree with fake process and route
// readers. These tests never run as root, never write a system path, and never
// read or change the host route table.
private struct FakeProcesses: HostProcessListing {
    var list: [HostProcess] = [
        HostProcess(pid: 1, effectiveUserID: 0, command: "launchd"),
        // The signed-in user's engine serves the dashboard. It is not root and
        // never owns a route.
        HostProcess(pid: 900, effectiveUserID: 501, command: "hotspotshade"),
    ]
    var failure: Error?
    func processes() throws -> [HostProcess] {
        if let failure { throw failure }
        return list
    }
}

private struct FakeRoutes: HostRouteTableReading {
    static let cleanInet = """
    Routing tables

    Internet:
    Destination        Gateway            Flags               Netif Expire
    default            172.20.10.1        UGScg                 en0
    127                127.0.0.1          UCS                   lo0
    172.20.10/28       link#14            UCS                   en0      !
    """
    static let cleanInet6 = """
    Routing tables

    Internet6:
    Destination                             Gateway                                 Flags               Netif Expire
    default                                 fe80::%utun0                            UGcIg               utun0
    ::1                                     ::1                                     UHL                   lo0
    """
    var inet = FakeRoutes.cleanInet
    var inet6 = FakeRoutes.cleanInet6
    var failure: Error?
    func routeTables() throws -> (inet: String, inet6: String) {
        if let failure { throw failure }
        return (inet, inet6)
    }
}

final class PreviewCleanupBlockClearTests: XCTestCase {
    private let marker = CoordinatorFixture.stateRelative + "/" + InstallLockLayout.cleanupMarkerName
    private let intent = CoordinatorFixture.stateRelative + "/" + InstallLockLayout.launchIntentName

    private func blockedHost() throws -> CoordinatorFixture {
        let fixture = try CoordinatorFixture()
        try fixture.writeState(InstallLockLayout.cleanupMarkerName, Data("launch stop was not clean\n".utf8))
        try fixture.writeState(InstallLockLayout.launchIntentName, Data("hotspotshade engine launch intent\n".utf8))
        return fixture
    }

    private func clear(
        _ fixture: CoordinatorFixture,
        processes: FakeProcesses = FakeProcesses(),
        routes: FakeRoutes = FakeRoutes()
    ) throws -> PreviewCleanupBlockClear {
        PreviewCleanupBlockClear(
            tree: try ServiceTestFixtures.tree(fixture),
            processes: processes,
            routes: routes
        )
    }

    private func assertKept(_ fixture: CoordinatorFixture, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertTrue(fixture.targetExists(marker), file: file, line: line)
        XCTAssertTrue(fixture.targetExists(intent), file: file, line: line)
    }

    func testAQuietHostClearsTheBlockAndTheIntentAndReportsEveryCheck() throws {
        let fixture = try blockedHost()
        try fixture.writeState(RootStartFailureStore.defaultFileName, Data("credentials_descriptor_invalid\n".utf8))
        let report = try clear(fixture).run()
        XCTAssertEqual(report.checks, PreviewClearCheck.allCases)
        XCTAssertEqual(report.removed, [InstallLockLayout.cleanupMarkerName, InstallLockLayout.launchIntentName])
        XCTAssertEqual(report.alreadyAbsent, [])
        XCTAssertFalse(fixture.targetExists(marker))
        XCTAssertFalse(fixture.targetExists(intent))
        // Diagnostics, lock files, and the state directory stay.
        XCTAssertTrue(fixture.targetExists(CoordinatorFixture.stateRelative + "/" + RootStartFailureStore.defaultFileName))
        XCTAssertTrue(fixture.targetExists(CoordinatorFixture.stateRelative + "/" + InstallLockLayout.fileName))

        // A second run has nothing left to remove.
        let again = try clear(fixture).run()
        XCTAssertEqual(again.removed, [])
        XCTAssertEqual(again.alreadyAbsent.count, 2)
    }

    func testARunningHelperOrRootEngineRefuses() throws {
        let fixture = try blockedHost()
        var helper = FakeProcesses()
        helper.list.append(HostProcess(pid: 22361, effectiveUserID: 0, command: "dev.hotspotshade"))
        XCTAssertThrowsError(try clear(fixture, processes: helper).run()) {
            XCTAssertEqual($0 as? PreviewClearError, .helperRunning)
        }
        var engine = FakeProcesses()
        engine.list.append(HostProcess(pid: 4242, effectiveUserID: 0, command: "hotspotshade"))
        XCTAssertThrowsError(try clear(fixture, processes: engine).run()) {
            XCTAssertEqual($0 as? PreviewClearError, .rootEngineRunning)
        }
        var unreadable = FakeProcesses()
        unreadable.failure = PreviewClearError.processListUnavailable
        XCTAssertThrowsError(try clear(fixture, processes: unreadable).run()) {
            XCTAssertEqual($0 as? PreviewClearError, .processListUnavailable)
        }
        var empty = FakeProcesses()
        empty.list = []
        XCTAssertThrowsError(try clear(fixture, processes: empty).run()) {
            XCTAssertEqual($0 as? PreviewClearError, .processListUnavailable)
        }
        assertKept(fixture)
    }

    func testAnyHotspotShadeRouteShapeRefusesAndNothingIsRemoved() throws {
        let fixture = try blockedHost()
        let cases: [(String, String, String)] = [
            ("0/1", FakeRoutes.cleanInet + "\n0/1                10.255.0.1         UGScg               utun7\n", FakeRoutes.cleanInet6),
            ("128.0/1", FakeRoutes.cleanInet + "\n128.0/1            10.255.0.1         UGSc                utun7\n", FakeRoutes.cleanInet6),
            ("2000::/3 lo0", FakeRoutes.cleanInet, FakeRoutes.cleanInet6 + "\n2000::/3                                ::1                                     UGSB                  lo0\n"),
            ("2000::/3 utun", FakeRoutes.cleanInet, FakeRoutes.cleanInet6 + "\n2000::/3                                fe80::%utun7                            UGSc                utun7\n"),
        ]
        for (label, inet, inet6) in cases {
            var routes = FakeRoutes()
            routes.inet = inet
            routes.inet6 = inet6
            XCTAssertThrowsError(try clear(fixture, routes: routes).run(), label) { error in
                guard case .ownedRoutePresent(let found)? = error as? PreviewClearError else {
                    return XCTFail("\(label): \(error)")
                }
                XCTAssertEqual(found.count, 1, label)
            }
        }
        assertKept(fixture)
    }

    func testAnOrdinaryHalfRouteOffAUtunIsNotHotspotShadeOwned() {
        let inet = FakeRoutes.cleanInet + "\n0/1                192.168.1.1        UGSc                  en0\n"
        XCTAssertEqual(PreviewOwnedRoutes.findings(inet: inet, inet6: FakeRoutes.cleanInet6), [])
    }

    func testAnUnreadableRouteTableRefuses() throws {
        let fixture = try blockedHost()
        var failing = FakeRoutes()
        failing.failure = PreviewClearError.routeTableUnavailable("netstat failed")
        XCTAssertThrowsError(try clear(fixture, routes: failing).run()) {
            XCTAssertEqual($0 as? PreviewClearError, .routeTableUnavailable("netstat failed"))
        }
        var headerless = FakeRoutes()
        headerless.inet = ""
        XCTAssertThrowsError(try clear(fixture, routes: headerless).run()) {
            guard case .routeTableUnavailable? = $0 as? PreviewClearError else { return XCTFail("\($0)") }
        }
        assertKept(fixture)
    }

    func testAJournalRefuses() throws {
        for relative in [InstallJournalStore.relativePath, ServiceJournalStore.relativePath, StartJournalProbe.relativePath] {
            let fixture = try blockedHost()
            try fixture.writeTarget(relative, Data("{}".utf8), mode: 0o600)
            XCTAssertThrowsError(try clear(fixture).run(), relative) {
                guard case .journalPresent? = $0 as? PreviewClearError else { return XCTFail("\($0)") }
            }
            assertKept(fixture)
        }
    }

    func testAHeldStartLockRefuses() throws {
        let fixture = try blockedHost()
        let tree = try ServiceTestFixtures.tree(fixture)
        let statePath = try tree.path(for: InstallLockLayout.stateDirectoryRelative)
        // A participant holds a shared lock, as the helper does for a live,
        // starting, or stopping session and after an unclean stop.
        let shared = try InstallLock.acquire(
            parentDirectory: statePath,
            fileName: InstallLockLayout.fileName,
            mode: .shared,
            expectedOwner: UInt32(geteuid())
        )
        defer { shared.release() }
        XCTAssertThrowsError(try clear(fixture).run()) {
            XCTAssertEqual($0 as? PreviewClearError, .lockUnavailable)
        }
        assertKept(fixture)
    }

    func testAnUnsafeRecordIsKept() throws {
        let fixture = try blockedHost()
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o644],
            ofItemAtPath: fixture.sandbox + "/" + marker
        )
        XCTAssertThrowsError(try clear(fixture).run()) {
            guard case .stateUnsafe? = $0 as? PreviewClearError else { return XCTFail("\($0)") }
        }
        assertKept(fixture)
    }

    func testAfterAClearThePreviewRemovalIsNoLongerRefusedByTheRecords() throws {
        let fixture = try CoordinatorFixture()
        let rights = FakeAuthorizationRightStore()
        let launchd = FakeLaunchdJobController()
        let runtime = FakeServiceRuntime(authorizationRights: rights, launchd: launchd)
        _ = try fixture.coordinator().installFirstTime(source: fixture.source, runtime: runtime)
        try fixture.writeState(InstallLockLayout.cleanupMarkerName, Data("launch stop was not clean\n".utf8))
        try fixture.writeState(InstallLockLayout.launchIntentName, Data("hotspotshade engine launch intent\n".utf8))
        let removal = { try PreviewFirstInstallCleanup(
            tree: try ServiceTestFixtures.tree(fixture),
            runtime: runtime,
            validator: InstallerValidator(signatures: FakeSignatures.standard),
            expectedTeamIdentifier: FakeSignatures.team
        ) }
        XCTAssertThrowsError(try removal().run()) {
            guard case .participantStateUnclean? = $0 as? PreviewCleanupError else { return XCTFail("\($0)") }
        }
        _ = try clear(fixture).run()
        let report = try removal().run()
        XCTAssertEqual(report.removedFiles.count, InstallerLayout.entries.count)
        // A fresh first install works again on the cleaned host.
        XCTAssertNoThrow(try fixture.coordinator().installFirstTime(source: fixture.source, runtime: runtime))
    }

    func testTheRealReadersWorkWithoutRoot() throws {
        // Read-only: the kernel process table and `netstat -rn`. Nothing is
        // changed. This host's own routes are not asserted.
        let processes = try KernelProcessList().processes()
        XCTAssertTrue(processes.contains { $0.pid == getpid() })
        let tables = try NetstatRouteTable().routeTables()
        XCTAssertTrue(tables.inet.contains("Destination"))
        XCTAssertTrue(tables.inet6.contains("Destination"))
    }
}
