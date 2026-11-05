import XCTest
import Foundation
import Network
@testable import HotspotShadeKit

@MainActor final class KitTests: XCTestCase {
    // A status from a real running phone tunnel. The shape comes from
    // rust/src/service.rs and rust/src/gui_backend.rs.
    private let runningTunnelStatus = """
    {"running":true,"mode":"phone","started_at":1762000000,
    "stats":{"packets_in":1200,"packets_out":900,"bytes_in":720000,"bytes_out":480000,
    "tcp_flows":12,"tcp_flows_closed":4,"ttl_bad":0,
    "input_queues":[{"packets_current":0,"packets_peak":8,"max_age_us":1200},{"packets_current":1,"packets_peak":6,"max_age_us":900}],
    "output_queue":{"packets_current":2,"packets_peak":9,"max_age_us":1500}},
    "error":null,
    "logs":[{"seq":7,"level":"info","msg":"Source device tunnel started.","ts":1762000000},{"seq":8,"level":"warning","msg":"Experimental source device ICMP is enabled.","ts":1762000001}],
    "demo":false,
    "platform":{"os":"macos","arch":"aarch64","admin":false,"default_iface":"en0","default_iface_name":"en0"},
    "api":1,
    "phone":{"state":"connected","message":"Connected.","port_changed":false,"connections":3},
    "paired":true,"phone_host":"172.20.10.1","phone_port":1080}
    """
    // A status with unknown keys and with optional fields of the wrong type.
    // Every field must fall back to nil. The decode must not fail.
    private let brokenStatus = """
    {"running":"yes","mode":7,"started_at":"yesterday","stats":"not an object",
    "error":{"code":1},
    "logs":[{"seq":"9","level":4,"msg":null,"ts":"now"},{"nope":true},17],
    "demo":"false","api":"one",
    "phone":{"state":5,"message":["x"],"port_changed":"no","connections":"three"},
    "paired":"true","phone_host":42,"phone_port":"1080",
    "extra_unknown":{"a":[1,2,3]},"another":null}
    """
    func testDecodesRunningTunnelStatus() throws {
        let status = try JSONDecoder().decode(Status.self, from: Data(runningTunnelStatus.utf8))
        XCTAssertEqual(status.running, true)
        XCTAssertEqual(status.mode, "phone")
        XCTAssertEqual(status.api, 1)
        XCTAssertEqual(status.demo, false)
        XCTAssertEqual(status.paired, true)
        XCTAssertEqual(status.phone_host, "172.20.10.1")
        XCTAssertEqual(status.phone_port, 1080)
        XCTAssertEqual(status.phone?.state, "connected")
        XCTAssertEqual(status.phone?.message, "Connected.")
        XCTAssertEqual(status.phone?.portChanged, false)
        XCTAssertEqual(status.phone?.connections, 3)
        XCTAssertNil(status.error)
        XCTAssertEqual(status.logs?.count, 2)
        XCTAssertEqual(status.logs?.first?.seq, 7)
        XCTAssertEqual(status.logs?.first?.level, "info")
        XCTAssertEqual(status.logs?.first?.msg, "Source device tunnel started.")
        XCTAssertEqual(status.logs?.last?.ts, 1762000001)
    }
    func testDecodesStatusWithUnknownKeysAndBadTypes() throws {
        let status = try JSONDecoder().decode(Status.self, from: Data(brokenStatus.utf8))
        XCTAssertNil(status.running)
        XCTAssertNil(status.mode)
        XCTAssertNil(status.started_at)
        XCTAssertNil(status.api)
        XCTAssertNil(status.demo)
        XCTAssertNil(status.paired)
        XCTAssertNil(status.phone_host)
        XCTAssertNil(status.phone_port)
        XCTAssertNil(status.error)
        XCTAssertNotNil(status.logs)
        XCTAssertEqual(status.logs?.count, 3)
        XCTAssertNil(status.logs?.first?.seq)
        XCTAssertNil(status.logs?.first?.level)
        XCTAssertNil(status.logs?.first?.msg)
        XCTAssertNil(status.logs?.first?.ts)
        XCTAssertNil(status.phone?.state)
        XCTAssertNil(status.phone?.message)
        XCTAssertNil(status.phone?.portChanged)
        XCTAssertNil(status.phone?.connections)
        let pair = try JSONDecoder().decode(PairState.self, from: Data("{\"state\":1,\"code\":null,\"host\":\"172.20.10.1\",\"port\":\"x\",\"error\":{\"a\":1}}".utf8))
        XCTAssertNil(pair.state)
        XCTAssertNil(pair.code)
        XCTAssertNil(pair.error)
    }
    func testDecodesNewPhoneStatesTolerantly() throws {
        let cases: [(String, PhoneState)] = [
            ("no_hotspot", .noHotspot), ("not_running", .notRunning), ("not_responding", .notResponding),
            ("proxy_off", .proxyOff), ("ready", .ready), ("connected", .connected),
            ("unpaired", .unpaired), ("not_trusted", .notTrusted), ("future_state", .unknown), ("", .unknown),
        ]
        for (raw, expected) in cases { XCTAssertEqual(PhoneState(raw: raw), expected, raw) }
        XCTAssertEqual(PhoneState(raw: nil), .unknown)
        let status = try JSONDecoder().decode(Status.self, from: Data("{\"phone\":{\"state\":\"not_trusted\",\"message\":\"The source device rejected this target device.\",\"connections\":null}}".utf8))
        XCTAssertEqual(PhoneState(raw: status.phone?.state), .notTrusted)
        XCTAssertEqual(status.phone?.message, "The source device rejected this target device.")
        XCTAssertNil(status.phone?.connections)
        let wrong = try JSONDecoder().decode(Status.self, from: Data("{\"phone\":{\"state\":\"unpaired\",\"connections\":\"4\"}}".utf8))
        XCTAssertNil(wrong.phone?.connections)
        let number = try JSONDecoder().decode(Status.self, from: Data("{\"phone\":{\"state\":\"connected\",\"connections\":4}}".utf8))
        XCTAssertEqual(number.phone?.connections, 4)
    }
    func testDecodesLiveDemoEngineStatus() async throws {
        guard let path = ProcessInfo.processInfo.environment["HS_TEST_DEMO_BINARY"] else { throw XCTSkip("No demo binary provided.") }
        let process = BackendProcess(executable: URL(fileURLWithPath: path), demo: true)
        try await process.start()
        do {
            let port = try XCTUnwrap(process.port)
            var request = URLRequest(url: URL(string: "http://127.0.0.1:\(port)/api/status")!)
            request.setValue("Bearer \(process.secret)", forHTTPHeaderField: "Authorization")
            request.setValue("127.0.0.1:\(port)", forHTTPHeaderField: "Host")
            let session = URLSession(configuration: HTTPBackend.configuration())
            let (data, response) = try await session.data(for: request)
            XCTAssertEqual((response as? HTTPURLResponse)?.statusCode, 200)
            let status = try JSONDecoder().decode(Status.self, from: data)
            XCTAssertEqual(status.demo, true)
            XCTAssertEqual(status.api, 1)
            XCTAssertNotNil(status.running)
            XCTAssertNotNil(status.phone?.state)
            XCTAssertNotNil(status.phone?.message)
        } catch {
            await process.stop()
            throw error
        }
        await process.stop()
    }

    private func result(running: Bool = false, paired: Bool = false, phone: PhoneState = .unpaired, message: String? = nil, pairing: PairingPhase = .idle, suppress: Bool = false, launch: LaunchPhase = .notAttempted, operation: TunnelOperation? = nil, error: String? = nil) -> DeriveResult {
        AppModel.derive(DeriveInput(running: running, paired: paired, phone: phone, phoneMessage: message, pairing: pairing, suppressAutoPair: suppress, launch: launch, operation: operation, error: error))
    }
    func testDeriveTable() {
        // The tunnel runs.
        var row = result(running: true, paired: true, phone: .connected, message: "Connected.")
        XCTAssertEqual(row.dashboard, DashboardState(screen: .on, title: "On", subtitle: "Connected.", action: .turnOff, pairedLine: "Paired"))
        XCTAssertFalse(row.startsAutoPair)
        // The tunnel runs and the source device stopped answering. The screen
        // stays On. The separate warning banner names the failure.
        row = result(running: true, paired: true, phone: .notResponding, message: "The tunnel is on.")
        XCTAssertEqual(row.dashboard.screen, .on)
        XCTAssertEqual(row.dashboard.action, .turnOff)
        XCTAssertEqual(row.dashboard.subtitle, "The tunnel is on.")

        // Unpaired, tunnel off.
        row = result(paired: false, phone: .unpaired)
        XCTAssertEqual(row.dashboard, DashboardState(screen: .unpaired, title: "Not paired", subtitle: "Pair with your source device to use it.", action: .pair, pairedLine: "Not paired"))
        XCTAssertTrue(row.startsAutoPair)
        // Cancel and Forget change only the automatic pairing decision.
        let suppressed = result(paired: false, phone: .unpaired, suppress: true)
        XCTAssertEqual(suppressed.dashboard, row.dashboard)
        XCTAssertFalse(suppressed.startsAutoPair)
        XCTAssertFalse(result(paired: false, phone: .unpaired, launch: .waiting).startsAutoPair)
        XCTAssertTrue(result(paired: false, phone: .unpaired, launch: .due).startsAutoPair)
        XCTAssertFalse(result(paired: false, phone: .unpaired, pairing: .starting).startsAutoPair)

        // Not trusted: a paired target with stale credentials.
        row = result(paired: true, phone: .notTrusted, launch: .due)
        XCTAssertEqual(row.dashboard, DashboardState(screen: .notTrusted, title: "Not trusted", subtitle: "The source device does not know this target device.", action: .pairAgain, pairedLine: "Paired"))
        XCTAssertFalse(row.startsAutoPair)
        XCTAssertFalse(result(paired: false, phone: .notTrusted).startsAutoPair)

        // The source device does not answer. The same rows apply with and
        // without credentials, and no Pair action is offered.
        for paired in [true, false] {
            row = result(paired: paired, phone: .notResponding, message: "Ignored.")
            XCTAssertEqual(row.dashboard, DashboardState(screen: .needsSourceDevice, title: "Waiting for your source device", subtitle: "Open HotspotShade on your source device and keep it open.", action: nil, pairedLine: paired ? "Paired" : "Not paired"))
            XCTAssertFalse(row.startsAutoPair)
            row = result(paired: paired, phone: .notRunning, message: "The source device is starting.")
            XCTAssertEqual(row.dashboard.screen, .needsSourceDevice)
            XCTAssertEqual(row.dashboard.subtitle, "The source device is starting.")
            XCTAssertNil(row.dashboard.action)
            XCTAssertFalse(row.startsAutoPair)
            row = result(paired: paired, phone: .noHotspot, message: "Connect this target device to the source device hotspot.")
            XCTAssertEqual(row.dashboard.screen, .needsSourceDevice)
            XCTAssertEqual(row.dashboard.subtitle, "Connect this target device to the source device hotspot.")
            XCTAssertNil(row.dashboard.action)
            XCTAssertFalse(row.startsAutoPair)
        }
        XCTAssertEqual(result(paired: false, phone: .noHotspot).dashboard.subtitle, "Connect this target device to the source device hotspot.")
        XCTAssertEqual(result(paired: false, phone: .notRunning).dashboard.subtitle, "Open HotspotShade on your source device.")

        // Paired, proxy off.
        row = result(paired: true, phone: .proxyOff)
        XCTAssertEqual(row.dashboard, DashboardState(screen: .proxyOff, title: "Paired", subtitle: "Start the proxy on your source device.", action: nil, pairedLine: "Paired"))
        XCTAssertFalse(row.startsAutoPair)

        // Paired, ready.
        row = result(paired: true, phone: .ready, message: "The source device is ready.")
        XCTAssertEqual(row.dashboard, DashboardState(screen: .ready, title: "Ready", subtitle: "The source device is ready.", action: .turnOn, pairedLine: "Paired"))
        XCTAssertFalse(row.startsAutoPair)

        // The old impossible combination: ready without credentials. It must
        // not show Ready and it must not pair from ready.
        row = result(paired: false, phone: .ready)
        XCTAssertEqual(row.dashboard, DashboardState(screen: .unpaired, title: "Not paired", subtitle: "Pair with your source device to use it.", action: .pair, pairedLine: "Not paired"))
        XCTAssertFalse(row.startsAutoPair)

        // Defensive rows. They never claim a state that the flags contradict.
        row = result(paired: true, phone: .unpaired)
        XCTAssertEqual(row.dashboard.screen, .needsSourceDevice)
        XCTAssertNil(row.dashboard.action)
        row = result(paired: false, phone: .proxyOff)
        XCTAssertEqual(row.dashboard.screen, .unpaired)
        XCTAssertEqual(row.dashboard.action, .pair)
        row = result(paired: true, phone: .connected)
        XCTAssertEqual(row.dashboard, DashboardState(screen: .ready, title: "Ready", subtitle: "The source device is ready.", action: .turnOn, pairedLine: "Paired"))

        // An unknown state shows the engine message.
        row = result(paired: true, phone: .unknown, message: "A new status.")
        XCTAssertEqual(row.dashboard, DashboardState(screen: .unknown, title: "Status unavailable", subtitle: "A new status.", action: nil, pairedLine: "Paired"))
        row = result(phone: .unknown)
        XCTAssertEqual(row.dashboard.subtitle, "The engine sent a status that this app does not know.")
        // The old product name never reaches the window.
        row = result(paired: true, phone: .unknown, message: "Open Hotspot Proxy on your source device.")
        XCTAssertEqual(row.dashboard.subtitle, "Open HotspotShade on your source device.")

        // Engine error.
        row = result(error: "Problem")
        XCTAssertEqual(row.dashboard, DashboardState(screen: .needsAttention("Problem"), title: "Needs attention", subtitle: "Problem", action: .retry, pairedLine: "Not paired"))
        XCTAssertFalse(row.startsAutoPair)

        // Tunnel operations.
        row = result(paired: true, phone: .ready, operation: .starting)
        XCTAssertEqual(row.dashboard, DashboardState(screen: .starting, title: "Starting the tunnel", subtitle: "This can take a minute.", action: nil, pairedLine: "Paired"))
        row = result(running: true, paired: true, phone: .connected, operation: .stopping)
        XCTAssertEqual(row.dashboard, DashboardState(screen: .stopping, title: "Turning off", subtitle: "This can take a minute.", action: nil, pairedLine: "Paired"))

        // Pairing in progress. A paired target shows it too when the user
        // pairs again after a trust failure.
        row = result(paired: false, phone: .unpaired, pairing: .starting)
        XCTAssertEqual(row.dashboard, DashboardState(screen: .pairing, title: "Pairing", subtitle: "Connecting to your source device.", action: nil, pairedLine: "Not paired"))
        XCTAssertFalse(row.startsAutoPair)
        row = result(paired: true, phone: .notTrusted, pairing: .starting)
        XCTAssertEqual(row.dashboard.screen, .pairing)
        XCTAssertEqual(row.dashboard.pairedLine, "Paired")
    }
    func testUnknownStateKeepsEngineMessage() throws {
        let status = try JSONDecoder().decode(Status.self, from: Data("{\"phone\":{\"state\":\"future_state\",\"message\":\"Ask the source device.\"}}".utf8))
        let row = AppModel.derive(DeriveInput(paired: true, phone: PhoneState(raw: status.phone?.state), phoneMessage: status.phone?.message)).dashboard
        XCTAssertEqual(row.screen, .unknown)
        XCTAssertEqual(row.title, "Status unavailable")
        XCTAssertEqual(row.subtitle, "Ask the source device.")
        XCTAssertNil(row.action)
    }
    func testStartingAndStopping() async throws {
        let fake = FakeBackend(); fake.operationDelay = 200_000_000
        let model = AppModel(backend: fake); fake.currentStatus = Status(paired: true, phone: Phone(state: "ready")); await model.refresh()
        XCTAssertEqual(model.screen, .ready)
        let start = Task { await model.toggle() }; try await Task.sleep(nanoseconds: 30_000_000); XCTAssertEqual(model.screen, .starting); await start.value
        fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "connected")); await model.refresh()
        XCTAssertEqual(model.screen, .on)
        let stop = Task { await model.toggle() }; try await Task.sleep(nanoseconds: 30_000_000); XCTAssertEqual(model.screen, .stopping); await stop.value
    }
    func testPairingTransitionsAndErrors() async {
        let fake = FakeBackend(); let model = AppModel(backend: fake)
        await model.beginPairing(); XCTAssertTrue(model.isPairing)
        fake.currentPair = PairState(state: "confirm", code: "123 456"); await model.refreshPairing(); XCTAssertEqual(model.pairing.code, "123 456")
        fake.currentStatus = Status(paired: true, phone: Phone(state: "ready")); fake.currentPair = PairState(state: "paired"); await model.refreshPairing(); XCTAssertFalse(model.isPairing); XCTAssertEqual(model.screen, .ready)
        await model.beginPairing(); fake.currentPair = PairState(state: "failed", error: "No"); await model.refreshPairing(); XCTAssertEqual(model.screen, .ready)
        // A status failure keeps the last screen. It becomes stale after 3 s.
        var clock = Date(timeIntervalSince1970: 100)
        let failingModel = AppModel(backend: fake, now: { clock })
        fake.currentStatus = Status(paired: true, phone: Phone(state: "ready"))
        await failingModel.refresh()
        fake.statusFailure = BackendError.unauthorized
        await failingModel.refresh()
        XCTAssertEqual(failingModel.screen, .ready)
        XCTAssertFalse(failingModel.statusIsStale)
        clock.addTimeInterval(3)
        await failingModel.refresh()
        XCTAssertTrue(failingModel.statusIsStale)
        XCTAssertEqual(failingModel.screen, .ready)
    }
    func testPairingFailureKeepsTheMessage() async {
        let fake = FakeBackend(); let model = AppModel(backend: fake)
        fake.currentStatus = Status(paired: false, phone: Phone(state: "unpaired"))
        await model.beginPairing()
        fake.currentPair = PairState(state: "failed", error: "The pairing code does not match.")
        await model.refreshPairing()
        XCTAssertEqual(model.pairing.error, "The pairing code does not match.")
        XCTAssertFalse(model.isPairing)
        await model.beginPairing()
        fake.failure = BackendError.timeout
        await model.refreshPairing()
        XCTAssertEqual(model.pairing.error, "The engine did not respond in time.")
    }
    func testPollingCancellation() async throws {
        let fake = FakeBackend(); let model = AppModel(backend: fake); model.startPolling(); try await Task.sleep(nanoseconds: 100_000_000); model.stopPolling(); let count = fake.calls.count; try await Task.sleep(nanoseconds: 1_100_000_000); XCTAssertEqual(fake.calls.count, count)
    }
    func testProcess() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString); try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true); defer { try? FileManager.default.removeItem(at: dir) }
        let marker = dir.appendingPathComponent("term"); let script = dir.appendingPathComponent("child"); try "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = --port-file ]; then shift; file=$1; fi; shift; done\nread secret <&3\ncase \"$secret\" in *[!0-9a-f]*|\"\") exit 1;; esac\n[ ${#secret} -eq 64 ] || exit 1\necho 54321 > \"$file\"\ntrap 'echo stopped > \"\(marker.path)\"; exit 0' TERM\nwhile :; do sleep 1; done\n".write(to: script, atomically: true, encoding: .utf8); try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: script.path)
        let process = BackendProcess(executable: script); try await process.start(); XCTAssertEqual(process.port, 54321); XCTAssertEqual(process.secret.count, 64); XCTAssertTrue(process.isRunning); await process.stop(); XCTAssertFalse(process.isRunning); XCTAssertTrue(FileManager.default.fileExists(atPath: marker.path))
    }
    func testChildDoesNotInheritOtherDescriptors() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString); try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true); defer { try? FileManager.default.removeItem(at: dir) }
        let marker = dir.appendingPathComponent("leak")
        let script = dir.appendingPathComponent("child")
        // Keep one extra descriptor open without close-on-exec.
        let spare = open("/dev/null", O_RDONLY)
        let inherited = fcntl(spare, F_DUPFD, 20)
        XCTAssertGreaterThanOrEqual(inherited, 20)
        if spare >= 0 { close(spare) }
        let text = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = --port-file ]; then shift; file=$1; fi; shift; done\nread secret <&3\n[ -n \"$secret\" ] || exit 1\nif [ -e /dev/fd/\(inherited) ]; then echo leaked > \"\(marker.path)\"; fi\necho 54321 > \"$file\"\ntrap 'exit 0' TERM\nwhile :; do sleep 1; done\n"
        try text.write(to: script, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: script.path)
        let process = BackendProcess(executable: script)
        do {
            try await process.start()
            XCTAssertTrue(process.isRunning)
            try await Task.sleep(nanoseconds: 300_000_000)
            XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))
        } catch {
            if inherited >= 0 { close(inherited) }
            await process.stop()
            throw error
        }
        if inherited >= 0 { close(inherited) }
        await process.stop()
    }
    func testRealDemoWhenProvided() async throws {
        guard let path = ProcessInfo.processInfo.environment["HS_TEST_DEMO_BINARY"] else { throw XCTSkip("No demo binary provided.") }
        let process = BackendProcess(executable: URL(fileURLWithPath: path), demo: true)
        try await process.start()
        let client = HTTPBackend(port: try XCTUnwrap(process.port), secret: process.secret)
        let status = try await client.status()
        XCTAssertNotNil(status.running)
        try await client.startPairing()
        var pair = PairState()
        for _ in 0..<50 {
            pair = try await client.pairState()
            if pair.state == "paired" || pair.state == "failed" { break }
            try await Task.sleep(nanoseconds: 200_000_000)
        }
        XCTAssertEqual(pair.state, "paired")
        try await client.startTunnel(); let on = try await client.status(); XCTAssertEqual(on.running, true)
        try await client.stopTunnel(); let off = try await client.status(); XCTAssertEqual(off.running, false)
        await process.stop()
    }
    func testStartIgnoresSIGPIPE() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let script = dir.appendingPathComponent("child")
        let text = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = --port-file ]; then shift; file=$1; fi; shift; done\nread secret <&3\n[ -n \"$secret\" ] || exit 1\necho 54321 > \"$file\"\ntrap 'exit 0' TERM\nwhile :; do sleep 1; done\n"
        try text.write(to: script, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: script.path)
        // Reset the disposition. start() must ignore SIGPIPE for the whole app.
        signal(SIGPIPE, SIG_DFL)
        let process = BackendProcess(executable: script)
        do {
            try await process.start()
            var fds = [Int32](repeating: -1, count: 2)
            XCTAssertEqual(pipe(&fds), 0)
            close(fds[0])
            // A write with no reader must return EPIPE, not kill this process.
            XCTAssertEqual(write(fds[1], "x", 1), -1)
            XCTAssertEqual(errno, EPIPE)
            close(fds[1])
        } catch {
            await process.stop()
            throw error
        }
        await process.stop()
    }
    func testParentPipeEOF() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let script = dir.appendingPathComponent("child")
        let text = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = --port-file ]; then shift; file=$1; fi; shift; done\nread secret <&3\necho 54321 > \"$file\"\nread ignored <&4\nexit 0\n"
        try text.write(to: script, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: script.path)
        let process = BackendProcess(executable: script); try await process.start()
        XCTAssertTrue(process.isRunning); process.closeParentPipe()
        for _ in 0..<100 { if !process.isRunning { break }; try await Task.sleep(nanoseconds: 20_000_000) }
        XCTAssertFalse(process.isRunning); await process.stop()
    }
    func testRestartBudgetResetsAfterHealthyRun() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let script = dir.appendingPathComponent("child")
        let text = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = --port-file ]; then shift; file=$1; fi; shift; done\nread secret <&3\n[ -n \"$secret\" ] || exit 1\necho 54321 > \"$file\"\ntrap 'exit 0' TERM\nwhile :; do sleep 1; done\n"
        try text.write(to: script, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: script.path)
        let process = BackendProcess(executable: script)
        do {
            try await process.start()
            try await process.restartOnce()
            do { try await process.restartOnce(); XCTFail("Expected one restart only") } catch BackendError.exited {}
            process.markHealthy()
            try await process.restartOnce()
            XCTAssertTrue(process.isRunning)
        } catch {
            await process.stop()
            throw error
        }
        await process.stop()
    }
    func testAutomaticPairingAndGuards() async throws {
        let fake = FakeBackend(); var clock = Date(timeIntervalSince1970: 100)
        let model = AppModel(backend: fake, now: { clock })
        fake.currentStatus = Status(paired: false, phone: Phone(state: "unpaired"))
        await model.refresh(); await model.refresh(); await model.beginPairing()
        XCTAssertEqual(fake.calls.filter { $0 == "startPairing" }.count, 1)
        XCTAssertEqual(model.screen, .pairing)
        fake.currentPair = PairState(state: "confirm", code: "123 456"); await model.refreshPairing()
        XCTAssertEqual(model.pairing.code, "123 456")
        fake.currentPair = PairState(state: "failed"); await model.refreshPairing()
        XCTAssertEqual(model.screen, .unpaired)
        clock.addTimeInterval(9); await model.refresh()
        XCTAssertEqual(fake.calls.filter { $0 == "startPairing" }.count, 1)
        clock.addTimeInterval(1); await model.refresh()
        XCTAssertEqual(fake.calls.filter { $0 == "startPairing" }.count, 2)
        model.stopPolling()
        let second = FakeBackend(); second.operationDelay = 200_000_000
        let other = AppModel(backend: second)
        async let a: Void = other.toggle(); async let b: Void = other.toggle()
        _ = await (a, b)
        XCTAssertEqual(second.calls.filter { $0 == "startTunnel" }.count, 1)
    }
    func testUnpairedStartsPairingOncePerLaunch() async {
        let fake = FakeBackend(); var clock = Date(timeIntervalSince1970: 100)
        let model = AppModel(backend: fake, now: { clock })
        fake.currentStatus = Status(paired: false, phone: Phone(state: "unpaired"))
        await model.refresh(); await model.refresh()
        clock.addTimeInterval(5); await model.refresh()
        XCTAssertEqual(fake.calls.filter { $0 == "startPairing" }.count, 1)
        fake.currentPair = PairState(state: "failed"); await model.refreshPairing()
        clock.addTimeInterval(4); await model.refresh()
        XCTAssertEqual(fake.calls.filter { $0 == "startPairing" }.count, 1)
        clock.addTimeInterval(1); await model.refresh()
        XCTAssertEqual(fake.calls.filter { $0 == "startPairing" }.count, 2)
        model.stopPolling()
    }
    func testCancelStopsAutomaticPairing() async {
        let fake = FakeBackend(); var clock = Date(timeIntervalSince1970: 100)
        let model = AppModel(backend: fake, now: { clock })
        fake.currentStatus = Status(paired: false, phone: Phone(state: "unpaired"))
        await model.refresh()
        XCTAssertEqual(fake.calls.filter { $0 == "startPairing" }.count, 1)
        fake.currentPair = PairState(state: "failed"); await model.refreshPairing()
        clock.addTimeInterval(11)
        await model.cancelPairing()
        await model.refresh(); await model.refresh()
        XCTAssertEqual(fake.calls.filter { $0 == "startPairing" }.count, 1)
        XCTAssertFalse(model.isPairing)
    }
    func testForgetStopsAutomaticPairing() async {
        let fake = FakeBackend(); var clock = Date(timeIntervalSince1970: 100)
        let model = AppModel(backend: fake, now: { clock })
        fake.currentStatus = Status(paired: false, phone: Phone(state: "unpaired"))
        await model.refresh()
        clock.addTimeInterval(11)
        await model.forget()
        await model.refresh(); await model.refresh()
        XCTAssertEqual(fake.calls.filter { $0 == "startPairing" }.count, 1)
    }
    func testExplicitPairAndRelaunchRestartAutomaticPairing() async {
        let fake = FakeBackend(); let clock = Date(timeIntervalSince1970: 100)
        let model = AppModel(backend: fake, now: { clock })
        fake.currentStatus = Status(paired: false, phone: Phone(state: "unpaired"))
        await model.refresh()
        await model.cancelPairing()
        XCTAssertEqual(fake.calls.filter { $0 == "startPairing" }.count, 1)
        // The Pair action clears the Cancel guard.
        await model.beginPairing()
        XCTAssertEqual(fake.calls.filter { $0 == "startPairing" }.count, 2)
        await model.cancelPairing()
        XCTAssertEqual(fake.calls.filter { $0 == "startPairing" }.count, 2)
        // A new engine launch pairs at most once by itself, even after a Cancel.
        let relaunched = AppModel(backend: fake, now: { clock })
        await relaunched.refresh(); await relaunched.refresh()
        XCTAssertEqual(fake.calls.filter { $0 == "startPairing" }.count, 3)
    }
    func testNotTrustedDoesNotAutoPairAndPairAgainWorks() async {
        let fake = FakeBackend(); var clock = Date(timeIntervalSince1970: 100)
        let model = AppModel(backend: fake, now: { clock })
        fake.currentStatus = Status(paired: true, phone: Phone(state: "not_trusted", message: "The source device rejected this target device."))
        await model.refresh(); await model.refresh()
        clock.addTimeInterval(11); await model.refresh()
        XCTAssertEqual(fake.calls.filter { $0 == "startPairing" }.count, 0)
        XCTAssertEqual(model.screen, .notTrusted)
        XCTAssertEqual(model.dashboard.action, .pairAgain)
        XCTAssertEqual(model.dashboard.pairedLine, "Paired")
        // Cancel suppresses automatic pairing. The Pair again action clears it.
        await model.cancelPairing()
        XCTAssertEqual(fake.calls.filter { $0 == "startPairing" }.count, 0)
        await model.perform(.pairAgain)
        XCTAssertEqual(fake.calls.filter { $0 == "startPairing" }.count, 1)
        XCTAssertEqual(model.screen, .pairing)
    }
    func testPairedDoesNotSendAnotherHello() async {
        let fake = FakeBackend(); var clock = Date(timeIntervalSince1970: 100)
        let model = AppModel(backend: fake, now: { clock })
        fake.currentStatus = Status(paired: true, phone: Phone(state: "ready"))
        await model.refresh(); clock.addTimeInterval(20); await model.refresh(); await model.refresh()
        XCTAssertEqual(fake.calls.filter { $0 == "startPairing" }.count, 0)
        XCTAssertEqual(model.screen, .ready)
    }
    func testSourceDeviceWarningNeedsTenSeconds() async {
        for state in ["not_responding", "not_running", "no_hotspot"] {
            let fake = FakeBackend(); var clock = Date(timeIntervalSince1970: 100)
            let model = AppModel(backend: fake, now: { clock })
            fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: state))
            await model.refresh()
            XCTAssertFalse(model.sourceDeviceWarning, state)
            clock.addTimeInterval(9); await model.refresh()
            XCTAssertFalse(model.sourceDeviceWarning, state)
            clock.addTimeInterval(2); await model.refresh()
            XCTAssertTrue(model.sourceDeviceWarning, state)
            XCTAssertEqual(model.screen, .on)
            // A ready state clears the banner at once.
            fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "ready"))
            clock.addTimeInterval(1); await model.refresh()
            XCTAssertFalse(model.sourceDeviceWarning, state)
            XCTAssertEqual(model.screen, .on)
        }
    }
    func testSingleProbeMissDoesNotFlash() async {
        let fake = FakeBackend(); var clock = Date(timeIntervalSince1970: 100)
        let model = AppModel(backend: fake, now: { clock })
        fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "not_responding"))
        await model.refresh()
        clock.addTimeInterval(1)
        fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "ready"))
        await model.refresh()
        clock.addTimeInterval(20); await model.refresh()
        XCTAssertFalse(model.sourceDeviceWarning)
        // A stop also clears the warning.
        fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "not_responding"))
        await model.refresh()
        clock.addTimeInterval(11); await model.refresh()
        XCTAssertTrue(model.sourceDeviceWarning)
        fake.currentStatus = Status(running: false, paired: true, phone: Phone(state: "ready"))
        await model.refresh()
        XCTAssertFalse(model.sourceDeviceWarning)
    }
    func testConnectionsLabel() async {
        let fake = FakeBackend(); let model = AppModel(backend: fake)
        fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "connected", connections: 3))
        await model.refresh()
        XCTAssertEqual(model.connectionsLabel, "The source device reports 3 active connections.")
        fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "connected", connections: 1))
        await model.refresh()
        XCTAssertEqual(model.connectionsLabel, "The source device reports 1 active connection.")
        fake.currentStatus = Status(running: false, paired: true, phone: Phone(state: "ready", connections: 3))
        await model.refresh()
        XCTAssertNil(model.connectionsLabel)
        fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "connected"))
        await model.refresh()
        XCTAssertNil(model.connectionsLabel)
    }
    func testQuitReadsLiveStatus() async {
        let fake = FakeBackend()
        let model = AppModel(backend: fake)
        fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "connected")); await model.refresh()
        XCTAssertEqual(model.screen, .on)
        // The engine reports off at quit time. Do not send stop.
        fake.currentStatus = Status(running: false, paired: true, phone: Phone(state: "ready"))
        await model.stopForQuit()
        XCTAssertEqual(model.screen, .stopping)
        XCTAssertEqual(fake.calls.filter { $0 == "stopTunnel" }.count, 0)
        // A failed status read keeps the safe choice.
        let failing = FakeBackend(); failing.statusFailure = BackendError.timeout
        let other = AppModel(backend: failing)
        await other.stopForQuit()
        XCTAssertEqual(failing.calls.filter { $0 == "stopTunnel" }.count, 1)
        XCTAssertEqual(other.screen, .stopping)
    }
    func testHTTPConfiguration() {
        let config = HTTPBackend.configuration()
        XCTAssertEqual(config.connectionProxyDictionary?.count, 0)
        XCTAssertNil(config.urlCache); XCTAssertNil(config.httpCookieStorage)
    }
    func testHTTPUnauthorizedAndTimeout() async throws {
        let server = try TestServer(); defer { server.stop() }
        let client = HTTPBackend(port: server.port, secret: String(repeating: "a", count: 64))
        do { _ = try await client.status(); XCTFail("Expected 401") } catch BackendError.unauthorized {} catch { XCTFail("Unexpected \(error)") }
        let redirect = try TestServer(redirect: true); defer { redirect.stop() }
        let redirected = HTTPBackend(port: redirect.port, secret: "secret")
        do { _ = try await redirected.status(); XCTFail("Expected redirect rejection") } catch BackendError.response { }
        let slow = try TestServer(slow: true); defer { slow.stop() }
        let slowClient = HTTPBackend(port: slow.port, secret: "a")
        do { _ = try await slowClient.status(); XCTFail("Expected timeout") } catch { XCTAssertTrue(error is URLError) }
    }
    func testLetPingWorkDefaultsToOn() {
        let name = "dev.hotspotshade.tests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name)!
        defer { defaults.removePersistentDomain(forName: name) }
        XCTAssertNil(defaults.object(forKey: UserDefaultsPingSetting.key))
        XCTAssertTrue(UserDefaultsPingSetting(defaults: defaults).letPingWork)
    }
    func testLetPingWorkPersists() {
        let name = "dev.hotspotshade.tests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name)!
        defer { defaults.removePersistentDomain(forName: name) }
        let first = UserDefaultsPingSetting(defaults: defaults)
        XCTAssertTrue(first.letPingWork)
        first.letPingWork = false
        XCTAssertEqual(defaults.object(forKey: UserDefaultsPingSetting.key) as? Bool, false)
        XCTAssertFalse(UserDefaultsPingSetting(defaults: defaults).letPingWork)
        UserDefaultsPingSetting(defaults: defaults).letPingWork = true
        XCTAssertTrue(UserDefaultsPingSetting(defaults: defaults).letPingWork)
    }
    func testStartBodySendsThePingSetting() async {
        for enabled in [true, false] {
            let fake = FakeBackend()
            let model = AppModel(backend: fake, pingSetting: FakePingSetting(enabled))
            fake.currentStatus = Status(paired: true, phone: Phone(state: "ready"))
            await model.refresh()
            await model.toggle()
            XCTAssertEqual(fake.startBodies, ["{\"mode\":\"phone\",\"options\":{\"experimental_icmp\":\(enabled)}}"], "\(enabled)")
        }
    }
    func testDefaultStartKeepsPingOn() async throws {
        let fake = FakeBackend()
        try await fake.startTunnel()
        XCTAssertEqual(fake.startBodies, ["{\"mode\":\"phone\",\"options\":{\"experimental_icmp\":true}}"])
    }
    func testHTTPStartBodyIsExact() async throws {
        for enabled in [true, false] {
            let server = try BodyServer()
            do {
                let client = HTTPBackend(port: server.port, secret: "secret")
                try await client.startTunnel(experimentalICMP: enabled)
                XCTAssertEqual(server.lastBody, "{\"mode\":\"phone\",\"options\":{\"experimental_icmp\":\(enabled)}}", "\(enabled)")
            } catch {
                server.stop()
                throw error
            }
            server.stop()
        }
    }
    func testPingLineMapping() {
        XCTAssertEqual(AppModel.pingLine(running: true, icmpEnabled: true), "Ping is on.")
        XCTAssertEqual(AppModel.pingLine(running: true, icmpEnabled: false), "Ping is off.")
        XCTAssertNil(AppModel.pingLine(running: true, icmpEnabled: nil))
        XCTAssertNil(AppModel.pingLine(running: false, icmpEnabled: true))
        XCTAssertNil(AppModel.pingLine(running: false, icmpEnabled: false))
        XCTAssertNil(AppModel.pingLine(running: false, icmpEnabled: nil))
    }
    func testPingLineFollowsStatus() async {
        let fake = FakeBackend()
        let model = AppModel(backend: fake)
        fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "connected"), icmpEnabled: true)
        await model.refresh()
        XCTAssertEqual(model.pingLine, "Ping is on.")
        fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "connected"), icmpEnabled: false)
        await model.refresh()
        XCTAssertEqual(model.pingLine, "Ping is off.")
        fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "connected"))
        await model.refresh()
        XCTAssertNil(model.pingLine)
        fake.currentStatus = Status(running: false, paired: true, phone: Phone(state: "ready"), icmpEnabled: true)
        await model.refresh()
        XCTAssertNil(model.pingLine)
    }
    func testDecodesICMPEnabledTolerantly() throws {
        func decode(_ text: String) throws -> Status { try JSONDecoder().decode(Status.self, from: Data(text.utf8)) }
        XCTAssertEqual(try decode("{\"icmp_enabled\":true}").icmp_enabled, true)
        XCTAssertEqual(try decode("{\"icmp_enabled\":false}").icmp_enabled, false)
        XCTAssertNil(try decode("{\"running\":true}").icmp_enabled)
        XCTAssertNil(try decode("{\"icmp_enabled\":\"true\"}").icmp_enabled)
        XCTAssertNil(try decode("{\"icmp_enabled\":null}").icmp_enabled)
        XCTAssertNil(try decode("{\"icmp_enabled\":1}").icmp_enabled)
        // One bad field must not fail the whole status decode.
        let status = try decode("{\"running\":true,\"icmp_enabled\":\"true\",\"phone\":{\"state\":\"connected\"}}")
        XCTAssertEqual(status.running, true)
        XCTAssertEqual(status.phone?.state, "connected")
        XCTAssertNil(status.icmp_enabled)
    }
    func testPingSettingChangeDoesNotRestartAndAppliesToTheNextStart() async {
        let fake = FakeBackend()
        let setting = FakePingSetting(true)
        let model = AppModel(backend: fake, pingSetting: setting)
        fake.currentStatus = Status(paired: true, phone: Phone(state: "ready"))
        await model.refresh()
        await model.toggle()
        XCTAssertEqual(fake.startBodies.count, 1)
        fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "connected"))
        await model.refresh()
        model.setLetPingWork(false)
        XCTAssertFalse(setting.letPingWork)
        // A change while the tunnel runs calls no tunnel action.
        XCTAssertEqual(fake.startBodies.count, 1)
        XCTAssertEqual(fake.calls.filter { $0 == "startTunnel" || $0 == "stopTunnel" }.count, 1)
        fake.currentStatus = Status(running: false, paired: true, phone: Phone(state: "ready"))
        await model.refresh()
        await model.toggle()
        XCTAssertEqual(fake.startBodies.last, "{\"mode\":\"phone\",\"options\":{\"experimental_icmp\":false}}")
    }
    func testPingStrings() {
        XCTAssertEqual(Strings.letPingWork, "Let ping work")
        XCTAssertEqual(Strings.letPingWorkHint, "Uses an experimental echo relay on the source device. Applies the next time you turn the tunnel on.")
        XCTAssertEqual(Strings.pingOn, "Ping is on.")
        XCTAssertEqual(Strings.pingOff, "Ping is off.")
        for text in [Strings.letPingWork, Strings.letPingWorkHint, Strings.pingOn, Strings.pingOff] {
            XCTAssertFalse(text.localizedCaseInsensitiveContains("hotspot proxy"), text)
            XCTAssertFalse(text.localizedCaseInsensitiveContains("iphone"), text)
            XCTAssertFalse(text.localizedCaseInsensitiveContains("laptop"), text)
        }
    }
    func testStringsUseTheProductName() {
        XCTAssertEqual(Strings.app, "HotspotShade")
        XCTAssertEqual(Strings.turnOn, "Turn on")
        XCTAssertEqual(Strings.turnOff, "Turn off")
        XCTAssertEqual(Strings.pair, "Pair with source device")
        XCTAssertEqual(Strings.pairAgain, "Pair again")
        XCTAssertEqual(Strings.paired, "Paired")
        XCTAssertEqual(Strings.notPaired, "Not paired")
        XCTAssertEqual(Strings.notTrustedTitle, "Not trusted")
        XCTAssertEqual(Strings.notRespondingSubtitle, "Open HotspotShade on your source device and keep it open.")
        XCTAssertEqual(Strings.sourceStoppedTitle, "The source device stopped answering. New connections fail.")
        XCTAssertEqual(Strings.sourceStoppedHint, "Open HotspotShade on your source device.")
        XCTAssertEqual(Strings.sanitized("Open Hotspot Proxy on your source device."), "Open HotspotShade on your source device.")
        XCTAssertNil(Strings.sanitized(nil))
        XCTAssertNil(Strings.sanitized(""))
        XCTAssertEqual(Strings.connections(1), "The source device reports 1 active connection.")
        XCTAssertEqual(Strings.connections(4), "The source device reports 4 active connections.")
        let visible = [Strings.waiting, Strings.pairingTitle, Strings.openSourceDeviceApp, Strings.notRespondingSubtitle, Strings.notTrustedSubtitle, Strings.proxyOffSubtitle, Strings.sourceStoppedTitle, Strings.sourceStoppedHint]
        for text in visible {
            XCTAssertFalse(text.localizedCaseInsensitiveContains("hotspot proxy"), text)
            XCTAssertFalse(text.localizedCaseInsensitiveContains("iphone"), text)
            XCTAssertFalse(text.localizedCaseInsensitiveContains("laptop"), text)
        }
    }
}
final class TestServer {
    let listener: NWListener; var port: UInt16 = 0; let queue = DispatchQueue(label: "test-server"); var connections: [NWConnection] = []
    init(slow: Bool = false, redirect: Bool = false) throws {
        listener = try NWListener(using: .tcp, on: .any); let ready = DispatchSemaphore(value: 0)
        listener.stateUpdateHandler = { [weak self] state in if case .ready = state { self?.port = self?.listener.port?.rawValue ?? 0; ready.signal() } }
        listener.newConnectionHandler = { [weak self] connection in self?.connections.append(connection); connection.start(queue: self!.queue); connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { _, _, _, _ in if !slow { let body = "{\"ok\":false,\"error\":\"unauthorized\"}"; let response = redirect ? "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" : "HTTP/1.1 401 Unauthorized\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)"; connection.send(content: Data(response.utf8), completion: .contentProcessed { _ in connection.cancel() }) } } }
        listener.start(queue: queue); guard ready.wait(timeout: .now() + 5) == .success else { throw BackendError.timeout }
    }
    func stop() { listener.cancel(); connections.forEach { $0.cancel() } }
}
// A test store for the ping setting. It holds the value in memory.
private final class FakePingSetting: PingSettingStore {
    var letPingWork: Bool
    init(_ letPingWork: Bool = true) { self.letPingWork = letPingWork }
}
// A loopback server that keeps the body of one POST. It answers with ok.
final class BodyServer {
    let listener: NWListener
    var port: UInt16 = 0
    private let queue = DispatchQueue(label: "body-server")
    private let lock = NSLock()
    private var storedBodies: [String] = []
    private var connections: [NWConnection] = []
    var lastBody: String? { lock.lock(); defer { lock.unlock() }; return storedBodies.last }
    init() throws {
        listener = try NWListener(using: .tcp, on: .any)
        let ready = DispatchSemaphore(value: 0)
        listener.stateUpdateHandler = { [weak self] state in if case .ready = state { self?.port = self?.listener.port?.rawValue ?? 0; ready.signal() } }
        listener.newConnectionHandler = { [weak self] connection in
            guard let self else { return }
            self.connections.append(connection)
            connection.start(queue: self.queue)
            self.receive(connection, buffer: Data())
        }
        listener.start(queue: queue)
        guard ready.wait(timeout: .now() + 5) == .success else { throw BackendError.timeout }
    }
    private func receive(_ connection: NWConnection, buffer: Data) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            var buffer = buffer
            if let data { buffer.append(data) }
            if let body = Self.requestBody(buffer) {
                self.lock.lock(); self.storedBodies.append(body); self.lock.unlock()
                let reply = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}"
                connection.send(content: Data(reply.utf8), completion: .contentProcessed { _ in connection.cancel() })
                return
            }
            if error != nil || isComplete { connection.cancel(); return }
            self.receive(connection, buffer: buffer)
        }
    }
    private static func requestBody(_ data: Data) -> String? {
        guard let text = String(data: data, encoding: .utf8), let headerEnd = text.range(of: "\r\n\r\n") else { return nil }
        let head = text[..<headerEnd.lowerBound]
        guard let line = head.components(separatedBy: "\r\n").first(where: { $0.lowercased().hasPrefix("content-length:") }),
              let value = Int(line.split(separator: ":", maxSplits: 1)[1].trimmingCharacters(in: .whitespaces)),
              text[headerEnd.upperBound...].utf8.count >= value else { return nil }
        return String(text[headerEnd.upperBound...].prefix(value))
    }
    func stop() { listener.cancel(); connections.forEach { $0.cancel() } }
}
