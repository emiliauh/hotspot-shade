import XCTest
import Foundation
import Network
@testable import HotspotShadeKit

// A loopback server with one fixed reply. It records the request line, the
// body, and the authorization header.
final class StubHTTPServer {
    let listener: NWListener
    let replyStatus: Int
    let replyBody: String
    var port: UInt16 = 0
    private let queue = DispatchQueue(label: "stub-http")
    private let lock = NSLock()
    private var storedPaths: [String] = []
    private var storedMethods: [String] = []
    private var storedBodies: [String] = []
    private var storedAuth: [String] = []
    private var connections: [NWConnection] = []
    var paths: [String] { lock.lock(); defer { lock.unlock() }; return storedPaths }
    var methods: [String] { lock.lock(); defer { lock.unlock() }; return storedMethods }
    var bodies: [String] { lock.lock(); defer { lock.unlock() }; return storedBodies }
    var auth: [String] { lock.lock(); defer { lock.unlock() }; return storedAuth }
    init(status: Int = 200, body: String = "{\"ok\":true}") throws {
        replyStatus = status; replyBody = body
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
            if let (head, body) = Self.parse(buffer) {
                let lines = head.components(separatedBy: "\r\n")
                let parts = (lines.first ?? "").split(separator: " ")
                self.lock.lock()
                self.storedMethods.append(parts.first.map(String.init) ?? "")
                self.storedPaths.append(parts.count > 1 ? String(parts[1]) : "")
                self.storedBodies.append(body)
                self.storedAuth.append(lines.first(where: { $0.lowercased().hasPrefix("authorization:") }) ?? "")
                self.lock.unlock()
                let reply = "HTTP/1.1 \(self.replyStatus) X\r\nContent-Type: application/json\r\nContent-Length: \(self.replyBody.utf8.count)\r\nConnection: close\r\n\r\n\(self.replyBody)"
                connection.send(content: Data(reply.utf8), completion: .contentProcessed { _ in connection.cancel() })
                return
            }
            if error != nil || isComplete { connection.cancel(); return }
            self.receive(connection, buffer: buffer)
        }
    }
    // Return the header text and the exact body once the request is complete.
    private static func parse(_ data: Data) -> (String, String)? {
        guard let text = String(data: data, encoding: .utf8), let end = text.range(of: "\r\n\r\n") else { return nil }
        let head = String(text[..<end.lowerBound])
        let first = head.components(separatedBy: "\r\n").first ?? ""
        let method = first.split(separator: " ").first.map(String.init) ?? "GET"
        let lengthLine = head.components(separatedBy: "\r\n").first(where: { $0.lowercased().hasPrefix("content-length:") })
        let length = lengthLine.flatMap { Int($0.split(separator: ":", maxSplits: 1)[1].trimmingCharacters(in: .whitespaces)) } ?? 0
        let body = String(text[end.upperBound...])
        if method == "GET" || body.utf8.count >= length { return (head, String(body.prefix(length))) }
        return nil
    }
    func stop() { listener.cancel(); connections.forEach { $0.cancel() } }
}

final class RecordingNotificationSink: NotificationSink {
    var status: NotificationAuthorization = .notDetermined
    var granted: NotificationAuthorization = .authorized
    var requests = 0
    var messages: [NotificationMessage] = []
    var clears = 0
    func authorizationStatus() async -> NotificationAuthorization { status }
    func requestAuthorization() async -> NotificationAuthorization { requests += 1; status = granted; return granted }
    func post(_ message: NotificationMessage) async { messages.append(message) }
    func clearDelivered() async { clears += 1 }
}

// A sink whose permission answer never arrives. The tunnel action must not
// wait for it.
final class SuspendedNotificationSink: NotificationSink {
    private(set) var statusCalls = 0
    func authorizationStatus() async -> NotificationAuthorization {
        statusCalls += 1
        await withCheckedContinuation { (_: CheckedContinuation<Void, Never>) in }
        return .notDetermined
    }
    func requestAuthorization() async -> NotificationAuthorization { .notDetermined }
    func post(_ message: NotificationMessage) async {}
    func clearDelivered() async {}
}

final class RecordingSettingsOpener: SettingsOpening {
    var opened = 0
    func openNotificationSettings() { opened += 1 }
}

final class W6RecordingPasteboard: PasteboardWriting {
    var texts: [String] = []
    func write(_ text: String) { texts.append(text) }
}

final class W6PingSetting: PingSettingStore {
    var letPingWork: Bool
    init(_ letPingWork: Bool = true) { self.letPingWork = letPingWork }
}

final class FakeLinkProvider: LinkInfoProvider {
    var link: WiFiLinkInfo?
    var calls = 0
    func currentLink() -> WiFiLinkInfo? { calls += 1; return link }
}

@MainActor final class W6ModelTests: XCTestCase {
    private func makeModel(_ fake: FakeBackend, now: @escaping () -> Date = Date.init, forgetIntent: ForgetIntentStore = MemoryForgetIntent(), sink: NotificationSink = NoNotificationSink(), link: LinkInfoProvider = NoLinkInfoProvider(), pasteboard: PasteboardWriting = NoPasteboard(), opener: SettingsOpening = NoSettingsOpener()) -> AppModel {
        AppModel(backend: fake, now: now, pingSetting: W6PingSetting(), pasteboard: pasteboard, forgetIntent: forgetIntent, notificationSink: sink, settingsOpener: opener, linkProvider: link, macOSVersion: "14.5", appVersion: "1.0 (1)")
    }

    // MARK: - Decode

    func testDecodesNewStatusFieldsTolerantly() throws {
        let json = """
        {"running":true,"paired":true,"iface":"en0",
        "phone":{"state":"connected","checked_at":1762000000,"trusted_by_source":true,"connections":2},
        "forget":{"state":"not_delivered","attempts":2},
        "last_stop":{"reason":"hotspot_lost","at":1761990000},"last_stop_message":"The hotspot turned off."}
        """
        let status = try JSONDecoder().decode(Status.self, from: Data(json.utf8))
        XCTAssertEqual(status.iface, "en0")
        XCTAssertEqual(status.phone?.checkedAt, 1762000000)
        XCTAssertEqual(status.phone?.trustedBySource, true)
        XCTAssertEqual(status.forget?.phase, .notDelivered)
        XCTAssertEqual(status.forget?.attempts, 2)
        XCTAssertEqual(status.last_stop?.kind, .hotspotLost)
        XCTAssertEqual(status.last_stop?.at, 1761990000)
        XCTAssertEqual(status.last_stop_message, "The hotspot turned off.")

        let bad = """
        {"iface":7,"phone":{"checked_at":"now","trusted_by_source":"yes","state":"ready"},
        "forget":{"state":4,"attempts":"two"},"last_stop":{"reason":[],"at":"yesterday"},"last_stop_message":{"a":1}}
        """
        let broken = try JSONDecoder().decode(Status.self, from: Data(bad.utf8))
        XCTAssertNil(broken.iface)
        XCTAssertNil(broken.phone?.checkedAt)
        XCTAssertNil(broken.phone?.trustedBySource)
        XCTAssertEqual(broken.phone?.state, "ready")
        XCTAssertNil(broken.forget?.state)
        XCTAssertNil(broken.forget?.attempts)
        XCTAssertNil(broken.last_stop?.reason)
        XCTAssertNil(broken.last_stop?.at)
        XCTAssertNil(broken.last_stop_message)
    }
    func testNullLastStopReasonIsNoStop() async throws {
        let json = "{\"last_stop\":{\"reason\":null,\"at\":null},\"last_stop_message\":null}"
        let status = try JSONDecoder().decode(Status.self, from: Data(json.utf8))
        XCTAssertEqual(status.last_stop?.kind, .unknown)
        let fake = FakeBackend()
        fake.currentStatus = status
        let model = makeModel(fake, forgetIntent: MemoryForgetIntent(true))
        await model.refresh()
        XCTAssertNil(model.lastStopLine)
        let text = DiagnosticsReport.text(diagnostics: nil, failures: nil, context: DiagnosticsContext(lastStop: status.last_stop))
        XCTAssertTrue(text.contains("Last stop: none"))
    }
    func testUnknownForgetAndStopReasonsAreSafe() throws {
        let status = try JSONDecoder().decode(Status.self, from: Data("{\"forget\":{\"state\":\"future\"},\"last_stop\":{\"reason\":\"future\"}}".utf8))
        XCTAssertEqual(status.forget?.phase, .unknown)
        XCTAssertEqual(status.last_stop?.kind, .unknown)
        XCTAssertNil(ForgetMessages.text(for: .unknown))
        XCTAssertNil(ForgetMessages.text(for: .none))
        XCTAssertEqual(ForgetMessages.text(for: .pending), "Forgetting...")
        XCTAssertEqual(ForgetMessages.text(for: .confirmed), "Forgotten. The source device removed this target device.")
        XCTAssertEqual(ForgetMessages.text(for: .notDelivered), "The source device did not answer. This target device forgot the pairing, but the source device may still trust it.")
    }
    func testDecodesDiagnosticsTolerantly() throws {
        let json = """
        {"ok":true,"running":true,
        "engine":{"version":"1.2.3","uptime_s":120,"workers":4},
        "setup":{"connect_ms":{"count":5,"p50":10,"p95":20,"max":30},"greeting_ms":{"count":0,"p50":null,"p95":null,"max":null}},
        "dns":{"lookups":10,"ok":9,"failed":1,"ms":{"count":10,"p50":2,"p95":9,"max":20}},
        "queues":{"input":[{"peak":8,"max_age_us":1200},{"peak":"bad"}],"output":{"peak":9,"max_age_us":1500}},
        "udp":{"flows":3,"age_drops":0},
        "tcp":{"flows_peak":12,"retransmits":1,"zero_window_ms":0},
        "failures":{"total":2,"dropped":0}}
        """
        let value = try JSONDecoder().decode(Diagnostics.self, from: Data(json.utf8))
        XCTAssertEqual(value.running, true)
        XCTAssertEqual(value.engine?.version, "1.2.3")
        XCTAssertEqual(value.engine?.uptime_s, 120)
        XCTAssertEqual(value.setup?.connect_ms?.p95, 20)
        XCTAssertEqual(value.setup?.greeting_ms?.count, 0)
        XCTAssertEqual(value.dns?.failed, 1)
        XCTAssertEqual(value.queues?.input?.count, 2)
        XCTAssertNil(value.queues?.input?.last?.peak)
        XCTAssertEqual(value.queues?.output?.max_age_us, 1500)
        XCTAssertEqual(value.udp?.flows, 3)
        XCTAssertEqual(value.tcp?.zero_window_ms, 0)
        XCTAssertEqual(value.failures?.total, 2)
        let broken = try JSONDecoder().decode(Diagnostics.self, from: Data("{\"engine\":\"x\",\"setup\":[],\"dns\":7,\"queues\":{\"input\":\"no\"},\"udp\":\"x\",\"tcp\":4,\"failures\":[]}".utf8))
        XCTAssertNil(broken.engine)
        XCTAssertNil(broken.setup)
        XCTAssertNil(broken.dns)
        XCTAssertNil(broken.queues?.input)
        XCTAssertNil(broken.udp)
        XCTAssertNil(broken.tcp)
        XCTAssertNil(broken.failures)
        XCTAssertThrowsError(try JSONDecoder().decode(Diagnostics.self, from: Data("[]".utf8)))
    }

    // MARK: - HTTP

    func testHTTPProbeUsesPostAndTheBearerSecret() async throws {
        let server = try StubHTTPServer(body: "{\"ok\":true,\"phone\":{\"state\":\"ready\",\"checked_at\":1762000000,\"trusted_by_source\":false}}")
        defer { server.stop() }
        let client = HTTPBackend(port: server.port, secret: "secret")
        let phone = try await client.probe()
        XCTAssertEqual(phone.state, "ready")
        XCTAssertEqual(phone.checkedAt, 1762000000)
        XCTAssertEqual(phone.trustedBySource, false)
        XCTAssertEqual(server.methods, ["POST"])
        XCTAssertEqual(server.paths, ["/api/phone/probe"])
        XCTAssertEqual(server.auth.first, "Authorization: Bearer secret")
    }
    func testHTTPMissingProbeAndDiagnosticsAreUnavailable() async throws {
        let probeServer = try StubHTTPServer(status: 404, body: "{}")
        defer { probeServer.stop() }
        let probeClient = HTTPBackend(port: probeServer.port, secret: "secret")
        do { _ = try await probeClient.probe(); XCTFail("Expected unavailable") } catch BackendError.unavailable {} catch { XCTFail("Unexpected \\(error)") }

        let diagnosticsServer = try StubHTTPServer(status: 404, body: "{}")
        defer { diagnosticsServer.stop() }
        let diagnosticsClient = HTTPBackend(port: diagnosticsServer.port, secret: "secret")
        do { _ = try await diagnosticsClient.diagnostics(); XCTFail("Expected unavailable") } catch BackendError.unavailable {} catch { XCTFail("Unexpected \\(error)") }
    }
    func testHTTPDiagnosticsDecode() async throws {
        let server = try StubHTTPServer(body: "{\"ok\":true,\"running\":true,\"engine\":{\"version\":\"1.0\",\"uptime_s\":5,\"workers\":2}}")
        defer { server.stop() }
        let value = try await HTTPBackend(port: server.port, secret: "secret").diagnostics()
        XCTAssertEqual(value.engine?.version, "1.0")
        XCTAssertEqual(server.paths, ["/api/diagnostics"])
    }
    func testHTTPForgetDecodesStateAndMapsTunnelRunning() async throws {
        let ok = try StubHTTPServer(body: "{\"ok\":true,\"forget\":{\"state\":\"pending\",\"attempts\":1}}")
        defer { ok.stop() }
        let state = try await HTTPBackend(port: ok.port, secret: "secret").forget()
        XCTAssertEqual(state.phase, .pending)
        XCTAssertEqual(state.attempts, 1)

        let blocked = try StubHTTPServer(status: 409, body: "{\"ok\":false,\"code\":\"tunnel_running\",\"error\":\"Turn off the tunnel first.\"}")
        defer { blocked.stop() }
        do { _ = try await HTTPBackend(port: blocked.port, secret: "secret").forget(); XCTFail("Expected blocked") } catch BackendError.forgetBlockedByTunnel {} catch { XCTFail("Unexpected \\(error)") }

        let old = try StubHTTPServer(body: "{\"ok\":true}")
        defer { old.stop() }
        let oldState = try await HTTPBackend(port: old.port, secret: "secret").forget()
        XCTAssertEqual(oldState.phase, .none)
    }
    func testHTTPStartTokenRejected() async throws {
        let server = try StubHTTPServer(status: 409, body: "{\"ok\":false,\"code\":\"phone_token_rejected\",\"error\":\"The source device changed its token. Open HotspotShade on your source device, then pair again.\"}")
        defer { server.stop() }
        do {
            try await HTTPBackend(port: server.port, secret: "secret").startTunnel(experimentalICMP: true)
            XCTFail("Expected a token error")
        } catch BackendError.phoneTokenRejected(let message) {
            XCTAssertEqual(message, "The source device changed its token. Open HotspotShade on your source device, then pair again.")
        } catch { XCTFail("Unexpected \\(error)") }
    }
    func testOldEngineNewEndpointsAreUnavailable() async throws {
        // An older engine sends the old status and has no new endpoints. Use a
        // stub, so the test does not depend on a demo binary in the build.
        let status = try StubHTTPServer(body: "{\"ok\":true,\"running\":false,\"paired\":false,\"phone\":{\"state\":\"unpaired\"}}")
        defer { status.stop() }
        let client = HTTPBackend(port: status.port, secret: "secret")
        let value = try await client.status()
        XCTAssertNil(value.iface)
        XCTAssertNil(value.last_stop)

        let missing = try StubHTTPServer(status: 404, body: "{}")
        defer { missing.stop() }
        let old = HTTPBackend(port: missing.port, secret: "secret")
        do { _ = try await old.probe(); XCTFail("Expected unavailable from the old engine") } catch BackendError.unavailable {}
        do { _ = try await old.diagnostics(); XCTFail("Expected unavailable from the old engine") } catch BackendError.unavailable {}
    }

    // MARK: - Forget

    func testForgetBlockedWhileRunningDoesNotCallTheEngine() async {
        let fake = FakeBackend(); let store = MemoryForgetIntent()
        fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "connected"))
        let model = makeModel(fake, forgetIntent: store)
        await model.refresh()
        let result = await model.forget()
        XCTAssertEqual(result, .blockedByTunnel)
        XCTAssertFalse(fake.calls.contains("forget"))
        XCTAssertTrue(store.forgotIntent)
        XCTAssertEqual(model.screen, .on)
        XCTAssertEqual(model.screenModel.primaryAction, .turnOff)
        XCTAssertEqual(model.screenModel.secondaryAction, .turnOffAndForget)
        XCTAssertTrue(model.screenModel.attentionItems.contains(Strings.forgetBlocked))
        XCTAssertEqual(result.message, "Turn off the tunnel to forget this source device.")
        XCTAssertEqual(ScreenModel.Action.turnOffAndForget.label, "Turn off and forget")
    }
    func testForgetBlockedWhenTheLiveStatusSaysRunning() async {
        let fake = FakeBackend()
        // The last screen says off, but the live read says on.
        fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "connected"))
        let model = makeModel(fake)
        let result = await model.forget()
        XCTAssertEqual(result, .blockedByTunnel)
        XCTAssertFalse(fake.calls.contains("forget"))
        XCTAssertTrue(model.forgetIsBlocked)
    }
    func testTurnOffAndForgetStopsThenForgets() async {
        let fake = FakeBackend(); let store = MemoryForgetIntent()
        fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "connected"))
        fake.stopClearsRunning = true
        fake.currentProbe = Phone(state: "unpaired")
        let model = makeModel(fake, forgetIntent: store)
        await model.refresh()
        XCTAssertEqual(model.screen, .on)
        let result = await model.turnOffAndForget()
        XCTAssertEqual(result, .done(.confirmed))
        let stop = fake.calls.firstIndex(of: "stopTunnel")
        let forget = fake.calls.firstIndex(of: "forget")
        XCTAssertNotNil(stop); XCTAssertNotNil(forget)
        XCTAssertLessThan(stop!, forget!)
        XCTAssertTrue(store.forgotIntent)
        XCTAssertEqual(model.screen, .unpaired)
        XCTAssertEqual(model.screenModel.primaryAction, .pair)
        XCTAssertEqual(model.screenModel.attentionItems.filter { $0 == Strings.forgetBlocked }.count, 0)
    }
    func testForgetResultFollowsTheLateEngineStatus() async {
        let fake = FakeBackend()
        fake.currentStatus = Status(paired: false, phone: Phone(state: "unpaired"))
        fake.currentForget = ForgetState(state: "pending")
        fake.currentProbe = Phone(state: "unpaired")
        let model = makeModel(fake, forgetIntent: MemoryForgetIntent(true))
        let result = await model.forget()
        XCTAssertEqual(result, .done(.pending))
        fake.currentStatus = Status(paired: false, phone: Phone(state: "unpaired"), forget: ForgetState(state: "confirmed", attempts: 1))
        await model.refresh()
        XCTAssertEqual(model.forgetProgress, .confirmed)
        XCTAssertEqual(model.forgetResult, .done(.confirmed))
        XCTAssertEqual(model.screenModel.subtitle, "Forgotten. The source device removed this target device.")
    }
    func testForgetMessagesForEveryEngineState() async {
        let cases: [(ForgetPhase, String)] = [
            (.pending, "Forgetting..."),
            (.confirmed, "Forgotten. The source device removed this target device."),
            (.notDelivered, "The source device did not answer. This target device forgot the pairing, but the source device may still trust it."),
        ]
        for (phase, text) in cases {
            let fake = FakeBackend()
            fake.currentStatus = Status(paired: false, phone: Phone(state: "unpaired"))
            fake.currentForget = ForgetState(state: phase.rawValue)
            fake.currentProbe = Phone(state: "unpaired")
            let model = makeModel(fake, forgetIntent: MemoryForgetIntent(true))
            let result = await model.forget()
            XCTAssertEqual(result, .done(phase), phase.rawValue)
            XCTAssertEqual(model.forgetProgress, phase)
            XCTAssertEqual(model.forgetMessage, text)
            XCTAssertEqual(model.screen, .unpaired)
            XCTAssertEqual(model.screenModel.subtitle, text)
            XCTAssertEqual(model.screenModel.primaryAction, .pair)
            XCTAssertEqual(model.screenModel.statusKind, .off)
            XCTAssertEqual(model.screenModel.attentionItems, [])
        }
    }
    func testForgetSetsIntentAndCancelsPairingFirst() async {
        let fake = FakeBackend(); let store = MemoryForgetIntent()
        fake.currentStatus = Status(paired: false, phone: Phone(state: "unpaired"))
        fake.currentProbe = Phone(state: "unpaired")
        let model = makeModel(fake, forgetIntent: store)
        await model.beginPairing()
        XCTAssertTrue(model.isPairing)
        let result = await model.forget()
        XCTAssertEqual(result, .done(.confirmed))
        let cancel = fake.calls.firstIndex(of: "cancelPairing")
        let forget = fake.calls.firstIndex(of: "forget")
        XCTAssertNotNil(cancel); XCTAssertNotNil(forget)
        XCTAssertLessThan(cancel!, forget!)
        XCTAssertFalse(model.isPairing)
        XCTAssertTrue(store.forgotIntent)
        XCTAssertEqual(model.screen, .unpaired)
    }
    func testCancelThenForgetQuicklyLeavesOneFinalState() async {
        let fake = FakeBackend(); let store = MemoryForgetIntent()
        fake.currentStatus = Status(paired: false, phone: Phone(state: "unpaired"))
        fake.currentProbe = Phone(state: "unpaired")
        let model = makeModel(fake, forgetIntent: store)
        await model.beginPairing()
        async let cancel: Void = model.cancelPairing()
        async let forget: ForgetResult = model.forget()
        let (_, result) = await (cancel, forget)
        await model.refresh()
        XCTAssertEqual(model.forgetResult, result)
        XCTAssertFalse(model.isPairing)
        XCTAssertTrue(store.forgotIntent)
        XCTAssertEqual(model.screen, .unpaired)
    }
    func testForgetIntentPersistsAndBlocksAutoPairingAfterRelaunch() async {
        let fake = FakeBackend(); let store = MemoryForgetIntent()
        fake.currentStatus = Status(paired: false, phone: Phone(state: "unpaired"))
        let first = makeModel(fake, forgetIntent: store)
        await first.refresh(); first.stopPolling()
        XCTAssertEqual(fake.calls.filter { $0 == "startPairing" }.count, 1)
        store.forgotIntent = true
        let second = makeModel(fake, forgetIntent: store)
        await second.refresh(); await second.refresh()
        XCTAssertEqual(fake.calls.filter { $0 == "startPairing" }.count, 1)
        XCTAssertFalse(second.screenModel.primaryAction == nil)
        await second.beginPairing()
        XCTAssertFalse(store.forgotIntent)
        XCTAssertEqual(fake.calls.filter { $0 == "startPairing" }.count, 2)
        second.stopPolling()
    }
    func testCancelSuppressesOnlyTheCurrentLaunch() async {
        let fake = FakeBackend()
        fake.currentStatus = Status(paired: false, phone: Phone(state: "unpaired"))
        let first = makeModel(fake)
        await first.refresh()
        await first.cancelPairing()
        XCTAssertEqual(fake.calls.filter { $0 == "startPairing" }.count, 1)
        first.stopPolling()
        let second = makeModel(fake)
        await second.refresh(); await second.refresh()
        XCTAssertEqual(fake.calls.filter { $0 == "startPairing" }.count, 2)
        second.stopPolling()
    }
    func testUserDefaultsForgetIntentPersists() {
        let name = "dev.hotspotshade.tests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name)!
        defer { defaults.removePersistentDomain(forName: name) }
        let store = UserDefaultsForgetIntent(defaults: defaults)
        XCTAssertFalse(store.forgotIntent)
        store.forgotIntent = true
        XCTAssertEqual(defaults.object(forKey: UserDefaultsForgetIntent.key) as? Bool, true)
        XCTAssertTrue(UserDefaultsForgetIntent(defaults: defaults).forgotIntent)
        UserDefaultsForgetIntent(defaults: defaults).forgotIntent = false
        XCTAssertFalse(UserDefaultsForgetIntent(defaults: defaults).forgotIntent)
    }

    // MARK: - Probe and checks

    func testForgetProbesImmediately() async {
        let fake = FakeBackend()
        fake.currentStatus = Status(paired: false, phone: Phone(state: "unpaired"))
        fake.currentProbe = Phone(state: "unpaired")
        let model = makeModel(fake, forgetIntent: MemoryForgetIntent(true))
        _ = await model.forget()
        let forget = fake.calls.firstIndex(of: "forget")
        let probe = fake.calls.firstIndex(of: "probe")
        XCTAssertNotNil(forget); XCTAssertNotNil(probe)
        XCTAssertLessThan(forget!, probe!)
    }
    func testPairProbesImmediately() async {
        let fake = FakeBackend()
        fake.currentStatus = Status(paired: false, phone: Phone(state: "unpaired"))
        let model = makeModel(fake)
        await model.beginPairing()
        fake.currentPair = PairState(state: "confirm", code: "123 456")
        fake.currentStatus = Status(paired: true, phone: Phone(state: "ready"))
        fake.currentProbe = Phone(state: "ready")
        fake.currentPair = PairState(state: "paired")
        await model.refreshPairing()
        XCTAssertTrue(fake.calls.contains("probe"))
        XCTAssertEqual(model.screen, .ready)
    }
    func testCheckNowProbesAndRefreshes() async {
        let fake = FakeBackend()
        fake.currentStatus = Status(paired: true, phone: Phone(state: "ready"))
        let model = makeModel(fake)
        await model.refresh()
        let before = fake.calls.filter { $0 == "probe" }.count
        await model.checkNow()
        XCTAssertEqual(fake.calls.filter { $0 == "probe" }.count, before + 1)
    }
    func testUnavailableProbeKeepsTheScreen() async {
        let fake = FakeBackend()
        fake.currentStatus = Status(paired: true, phone: Phone(state: "ready"))
        let model = makeModel(fake)
        await model.refresh()
        fake.probeError = BackendError.unavailable
        await model.checkNow()
        XCTAssertEqual(model.screen, .ready)
        XCTAssertNil(model.status.error)
    }

    // MARK: - Trust, token, last checked

    func testTrustedBySourceWhileUnpairedShowsThePairHint() {
        let result = AppModel.derive(DeriveInput(paired: false, phone: .unpaired, trustedBySource: true)).dashboard
        XCTAssertEqual(result.screen, .unpaired)
        XCTAssertEqual(result.title, "Not paired")
        XCTAssertEqual(result.subtitle, "The source device still knows this target device. Press Pair to continue.")
        XCTAssertEqual(result.action, .pair)
    }
    func testNotTrustedWhileRunningKeepsTheScreenOn() async {
        let fake = FakeBackend()
        fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "not_trusted"))
        let model = makeModel(fake)
        await model.refresh()
        XCTAssertEqual(model.screen, .on)
        XCTAssertEqual(model.screenModel.statusKind, .on)
        XCTAssertTrue(model.screenModel.attentionItems.contains("The source device forgot this target device. The tunnel keeps running until you turn it off."))
        XCTAssertEqual(model.screenModel.primaryAction, .turnOff)
    }
    func testTokenRejectedAtStartShowsPairAgain() async {
        let fake = FakeBackend()
        fake.currentStatus = Status(paired: true, phone: Phone(state: "ready"))
        let model = makeModel(fake)
        await model.refresh()
        fake.failure = BackendError.phoneTokenRejected("The source device changed its token. Open HotspotShade on your source device, then pair again.")
        await model.toggle()
        XCTAssertEqual(model.screenModel.title, "Pair again")
        XCTAssertEqual(model.screenModel.subtitle, "The source device changed its token. Open HotspotShade on your source device, then pair again.")
        XCTAssertEqual(model.screenModel.primaryAction, .pairAgain)
        XCTAssertEqual(model.screenModel.statusKind, .attention)
        XCTAssertFalse(model.screenModel.menuBar.actions.first { $0.kind == .turnOn }!.enabled)
    }
    func testLastCheckedTextUsesTheInjectedClock() async {
        var clock = Date(timeIntervalSince1970: 1_000)
        let fake = FakeBackend()
        let model = makeModel(fake, now: { clock })
        func set(_ checked: Double) { fake.currentStatus = Status(paired: true, phone: Phone(state: "ready", checkedAt: checked)) }
        set(1_000); await model.refresh()
        XCTAssertEqual(model.lastCheckedText, "Checked just now")
        clock.addTimeInterval(9); set(1_000); await model.refresh()
        XCTAssertEqual(model.lastCheckedText, "Checked just now")
        clock.addTimeInterval(21); set(1_000); await model.refresh()
        XCTAssertEqual(model.lastCheckedText, "Checked 30 seconds ago")
        clock.addTimeInterval(90); set(1_000); await model.refresh()
        XCTAssertEqual(model.lastCheckedText, "Checked 2 minutes ago")
        clock.addTimeInterval(10); set(clock.timeIntervalSince1970 + 5); await model.refresh()
        XCTAssertEqual(model.lastCheckedText, "Checked just now")
        set(-1e100); await model.refresh()
        XCTAssertNil(model.lastCheckedText)
        set(.nan); await model.refresh()
        XCTAssertNil(model.lastCheckedText)
        set(.infinity); await model.refresh()
        XCTAssertNil(model.lastCheckedText)
    }

    // MARK: - Freshness and polling

    func testStaleThenUnavailableNeverClaimsOnOrOff() async {
        var clock = Date(timeIntervalSince1970: 100)
        let fake = FakeBackend()
        fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "connected"), icmpEnabled: true, iface: "en0")
        let model = makeModel(fake, now: { clock })
        await model.refresh()
        XCTAssertEqual(model.screen, .on)
        fake.statusFailure = BackendError.timeout
        await model.refresh()
        XCTAssertEqual(model.screen, .on)
        XCTAssertFalse(model.statusIsStale)
        clock.addTimeInterval(3)
        await model.refresh()
        XCTAssertTrue(model.statusIsStale)
        XCTAssertFalse(model.statusUnavailable)
        XCTAssertEqual(model.staleStatusText, "The engine did not answer. This status may be out of date.")
        XCTAssertEqual(model.screen, .on)
        XCTAssertTrue(model.screenModel.attentionItems.contains("The engine did not answer. This status may be out of date."))
        clock.addTimeInterval(7)
        await model.refresh()
        XCTAssertTrue(model.statusUnavailable)
        XCTAssertEqual(model.screen, .unknown)
        XCTAssertEqual(model.screenModel.title, "Status unavailable")
        XCTAssertEqual(model.screenModel.subtitle, "The engine did not answer.")
        XCTAssertEqual(model.screenModel.primaryAction, .checkNow)
        XCTAssertEqual(model.screenModel.statusKind, .attention)
        XCTAssertTrue(model.screenModel.connection.lines.isEmpty)
        XCTAssertEqual(model.screenModel.menuBar.icon, .attention)
        // A fresh answer clears both flags and shows the real screen again.
        fake.statusFailure = nil
        await model.refresh()
        XCTAssertFalse(model.statusIsStale)
        XCTAssertFalse(model.statusUnavailable)
        XCTAssertEqual(model.screen, .on)
        XCTAssertEqual(model.statusIsStale, false)
    }
    func testWindowVisibilityChangesThePollIntervalAndRefreshesAtOnce() async throws {
        let fake = FakeBackend()
        fake.currentStatus = Status(paired: true, phone: Phone(state: "ready"))
        let model = makeModel(fake)
        XCTAssertEqual(model.statusPollInterval, 1)
        model.startPolling()
        try await Task.sleep(nanoseconds: 80_000_000)
        let before = fake.calls.count
        model.setWindowVisible(false)
        XCTAssertEqual(model.statusPollInterval, 5)
        try await Task.sleep(nanoseconds: 80_000_000)
        model.setWindowVisible(true)
        XCTAssertEqual(model.statusPollInterval, 1)
        try await Task.sleep(nanoseconds: 80_000_000)
        XCTAssertGreaterThan(fake.calls.count, before)
        XCTAssertTrue(model.windowVisible)
        model.stopPolling()
    }

    // MARK: - Link

    func testLinkAdviceBranches() {
        let slow = "This connection uses 2.4 GHz Wi-Fi, which is slower and less steady. On your source device, turn off Maximize Compatibility in the Personal Hotspot settings, or use a cable."
        let weak = "The Wi-Fi signal is weak. Move the target device closer to the source device."
        let slowLink = WiFiLinkInfo(band: .ghz2_4, channelWidthMHz: 40, rssi: -60, interfaceName: "en0")
        XCTAssertEqual(LinkAdvice.advice(running: true, statusIface: "en0", link: slowLink), [slow])
        let weakLink = WiFiLinkInfo(band: .ghz5, channelWidthMHz: 80, rssi: -76, interfaceName: "en0")
        XCTAssertEqual(LinkAdvice.advice(running: true, statusIface: "en0", link: weakLink), [weak])
        let both = WiFiLinkInfo(band: .ghz2_4, rssi: -80, interfaceName: "en0")
        XCTAssertEqual(LinkAdvice.advice(running: true, statusIface: "en0", link: both), [slow, weak])
        XCTAssertEqual(LinkAdvice.advice(running: false, statusIface: "en0", link: both), [])
        XCTAssertEqual(LinkAdvice.advice(running: true, statusIface: "en1", link: both), [])
        XCTAssertEqual(LinkAdvice.advice(running: true, statusIface: nil, link: both), [])
        XCTAssertEqual(LinkAdvice.advice(running: true, statusIface: "en0", link: nil), [])
        XCTAssertEqual(LinkAdvice.advice(running: true, statusIface: "en0", link: WiFiLinkInfo(band: .ghz6, rssi: -50, interfaceName: "en0")), [])
        XCTAssertEqual(LinkAdvice.advice(running: true, statusIface: "en0", link: WiFiLinkInfo(band: .ghz2_4, interfaceName: "en0", isWiFi: false)), [])
        XCTAssertEqual(LinkAdvice.advice(running: true, statusIface: "en0", link: WiFiLinkInfo(band: .ghz2_4, rssi: -75, interfaceName: "en0")), [slow])
    }
    func testModelPollsTheLinkEveryTenSecondsOnlyWhenVisible() async {
        var clock = Date(timeIntervalSince1970: 100)
        let fake = FakeBackend(); let link = FakeLinkProvider()
        link.link = WiFiLinkInfo(band: .ghz2_4, channelWidthMHz: 40, rssi: -80, interfaceName: "en0")
        fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "connected"), iface: "en0")
        let model = makeModel(fake, now: { clock }, link: link)
        await model.refresh()
        XCTAssertEqual(link.calls, 1)
        XCTAssertEqual(model.linkAdvice.count, 2)
        clock.addTimeInterval(9); model.refreshLinkIfNeeded()
        XCTAssertEqual(link.calls, 1)
        clock.addTimeInterval(1); model.refreshLinkIfNeeded()
        XCTAssertEqual(link.calls, 2)
        model.setWindowVisible(false)
        clock.addTimeInterval(30); model.refreshLinkIfNeeded(force: true)
        XCTAssertEqual(link.calls, 2)
        model.setWindowVisible(true)
        XCTAssertEqual(link.calls, 3)
    }

    // MARK: - Notifications

    func testNotificationPolicyAutoStopTexts() {
        var clock = Date(timeIntervalSince1970: 100)
        var policy = NotificationPolicy(now: { clock })
        var first = NotificationInput(lastStop: LastStop(reason: "hotspot_lost", at: 1))
        var output = policy.evaluate(first)
        XCTAssertEqual(output.messages.map(\.body), ["The hotspot turned off, so HotspotShade turned the tunnel off."])
        XCTAssertEqual(output.messages.first?.kind, .autoStopped)
        XCTAssertEqual(output.messages.first?.title, "HotspotShade")
        clock.addTimeInterval(61)
        first = NotificationInput(lastStop: LastStop(reason: "source_device_gone", at: 2))
        output = policy.evaluate(first)
        XCTAssertEqual(output.messages.map(\.body), ["The source device stopped answering, so HotspotShade turned the tunnel off."])
        clock.addTimeInterval(61)
        first = NotificationInput(lastStop: LastStop(reason: "hotspot_lost", at: 3), lastStopMessage: "The hotspot went away.")
        output = policy.evaluate(first)
        XCTAssertEqual(output.messages.map(\.body), ["The hotspot went away."])
    }
    func testNotificationPolicyNeverNotifiesAUserStop() {
        var clock = Date(timeIntervalSince1970: 100)
        let policy = NotificationPolicy(now: { clock })
        var mutable = policy
        let output = mutable.evaluate(NotificationInput(lastStop: LastStop(reason: "user", at: 1)))
        XCTAssertTrue(output.messages.isEmpty)
        clock.addTimeInterval(1)
        let again = mutable.evaluate(NotificationInput(running: false, phone: .ready))
        XCTAssertTrue(again.messages.isEmpty)
    }
    func testNotificationPolicySourceWarningDebounceAndRecovery() {
        var clock = Date(timeIntervalSince1970: 100)
        var policy = NotificationPolicy(now: { clock })
        let warning = NotificationInput(running: true, phone: .notResponding, sourceDeviceWarning: true)
        var output = policy.evaluate(warning)
        XCTAssertEqual(output.messages.map(\.body), ["The source device stopped answering. New connections fail."])
        clock.addTimeInterval(30)
        output = policy.evaluate(warning)
        XCTAssertTrue(output.messages.isEmpty)
        clock.addTimeInterval(31)
        output = policy.evaluate(warning)
        XCTAssertEqual(output.messages.count, 1)
        let healthy = NotificationInput(running: true, phone: .ready)
        output = policy.evaluate(healthy)
        XCTAssertTrue(output.messages.isEmpty)
        XCTAssertTrue(output.clearDelivered)
        output = policy.evaluate(healthy)
        XCTAssertFalse(output.clearDelivered)
    }
    func testNotificationPolicyFrontmostSuppressesAllButAutoStop() {
        var policy = NotificationPolicy(now: { Date(timeIntervalSince1970: 100) })
        let stop = policy.evaluate(NotificationInput(isFrontmost: true, lastStop: LastStop(reason: "hotspot_lost", at: 1)))
        XCTAssertEqual(stop.messages.count, 1)
        let warning = policy.evaluate(NotificationInput(isFrontmost: true, running: true, phone: .notResponding, sourceDeviceWarning: true))
        XCTAssertTrue(warning.messages.isEmpty)
        let pairing = policy.evaluate(NotificationInput(isFrontmost: true, pairingNeedsAttention: true))
        XCTAssertTrue(pairing.messages.isEmpty)
        let error = policy.evaluate(NotificationInput(isFrontmost: true, lastStop: LastStop(reason: "error", at: 2), lastStopMessage: "The engine stopped."))
        XCTAssertTrue(error.messages.isEmpty)
    }
    func testNotificationPolicyPairingAndError() {
        var policy = NotificationPolicy(now: { Date(timeIntervalSince1970: 100) })
        var output = policy.evaluate(NotificationInput(pairingNeedsAttention: true))
        XCTAssertEqual(output.messages.map(\.body), ["Check the code on your source device."])
        XCTAssertEqual(output.messages.first?.kind, .pairingAttention)
        output = policy.evaluate(NotificationInput(lastStop: LastStop(reason: "error", at: 1), lastStopMessage: "The engine stopped."))
        XCTAssertEqual(output.messages.map(\.body), ["The engine stopped."])
        XCTAssertEqual(output.messages.first?.kind, .tunnelError)
        // An error from an older engine without last_stop.
        let clock = Date(timeIntervalSince1970: 100)
        var other = NotificationPolicy(now: { clock })
        output = other.evaluate(NotificationInput(error: "The tunnel failed."))
        XCTAssertEqual(output.messages.map(\.body), ["The tunnel failed."])
    }
    func testNotificationPolicyReportsAStaticErrorOnce() {
        var clock = Date(timeIntervalSince1970: 100)
        var policy = NotificationPolicy(now: { clock })
        XCTAssertEqual(policy.evaluate(NotificationInput(error: "The tunnel failed.")).messages.count, 1)
        // The error stays on the screen. It is not a new event.
        clock.addTimeInterval(61)
        XCTAssertTrue(policy.evaluate(NotificationInput(error: "The tunnel failed.")).messages.isEmpty)
        // A cleared error can occur again.
        XCTAssertTrue(policy.evaluate(NotificationInput(error: nil)).messages.isEmpty)
        clock.addTimeInterval(61)
        XCTAssertEqual(policy.evaluate(NotificationInput(error: "The tunnel failed.")).messages.count, 1)
    }
    func testNotificationPolicyDebouncesEachEventTypeIndependently() {
        var clock = Date(timeIntervalSince1970: 100)
        var policy = NotificationPolicy(now: { clock })
        var output = policy.evaluate(NotificationInput(pairingNeedsAttention: true))
        XCTAssertEqual(output.messages.count, 1)
        output = policy.evaluate(NotificationInput(lastStop: LastStop(reason: "error", at: 1), lastStopMessage: "E"))
        XCTAssertEqual(output.messages.count, 1)
        clock.addTimeInterval(30)
        output = policy.evaluate(NotificationInput(pairingNeedsAttention: true, lastStop: LastStop(reason: "error", at: 2), lastStopMessage: "E2"))
        XCTAssertTrue(output.messages.isEmpty)
    }
    func testNotificationPolicyNeedsPermission() {
        var policy = NotificationPolicy(now: { Date(timeIntervalSince1970: 100) })
        let denied = policy.evaluate(NotificationInput(authorization: .denied, lastStop: LastStop(reason: "hotspot_lost", at: 1)))
        XCTAssertTrue(denied.messages.isEmpty)
        let notAsked = policy.evaluate(NotificationInput(authorization: .notDetermined, pairingNeedsAttention: true))
        XCTAssertTrue(notAsked.messages.isEmpty)
        XCTAssertTrue(NotificationPolicy.shouldAskForPermission(status: .notDetermined, asked: false))
        XCTAssertFalse(NotificationPolicy.shouldAskForPermission(status: .notDetermined, asked: true))
        XCTAssertFalse(NotificationPolicy.shouldAskForPermission(status: .authorized, asked: false))
        XCTAssertFalse(NotificationPolicy.shouldAskForPermission(status: .denied, asked: false))
    }
    func testModelAsksForNotificationPermissionOnce() async {
        let fake = FakeBackend(); let sink = RecordingNotificationSink()
        sink.status = .notDetermined; sink.granted = .authorized
        fake.currentStatus = Status(paired: true, phone: Phone(state: "ready"))
        let model = makeModel(fake, sink: sink)
        await model.refresh()
        await model.requestNotificationPermissionIfNeeded()
        XCTAssertEqual(sink.requests, 1)
        XCTAssertEqual(model.notificationAuthorization, .authorized)
        // The start path runs the same request in the background. A finished
        // ask is not repeated.
        await model.toggle()
        try? await Task.sleep(nanoseconds: 50_000_000)
        await model.requestNotificationPermissionIfNeeded()
        XCTAssertEqual(sink.requests, 1)
    }
    // A system permission alert can stay unanswered. The start must go out
    // and the screen must show Starting while the request waits.
    func testStartDoesNotWaitForNotificationPermission() async {
        let fake = FakeBackend(); let sink = SuspendedNotificationSink()
        fake.currentStatus = Status(paired: true, phone: Phone(state: "ready"))
        let model = makeModel(fake, sink: sink)
        await model.refresh()
        let action = Task { await model.toggle() }
        try? await Task.sleep(nanoseconds: 100_000_000)
        XCTAssertEqual(fake.startBodies.count, 1)
        XCTAssertGreaterThanOrEqual(sink.statusCalls, 1)
        action.cancel()
    }
    // A failed start keeps its text while the status polls. The Try again
    // button repeats the start.
    func testStartFailureStaysVisibleAndTryAgainStartsAgain() async {
        let fake = FakeBackend()
        fake.currentStatus = Status(paired: true, phone: Phone(state: "ready"))
        let model = makeModel(fake)
        await model.refresh()
        fake.failure = BackendError.response("The tunnel could not start.")
        await model.toggle()
        XCTAssertEqual(model.screenModel.title, Strings.attention)
        XCTAssertEqual(model.screenModel.subtitle, "The tunnel could not start.")
        XCTAssertEqual(model.screenModel.primaryAction, .retry)
        // A later status answer must not hide the start error.
        await model.refresh()
        XCTAssertEqual(model.screenModel.title, Strings.attention)
        XCTAssertEqual(model.screenModel.subtitle, "The tunnel could not start.")
        XCTAssertEqual(model.screenModel.primaryAction, .retry)
        XCTAssertEqual(fake.startBodies.count, 1)
        // Try again sends a new start, not only a status read.
        await model.perform(.retry)
        XCTAssertEqual(fake.startBodies.count, 2)
        XCTAssertEqual(model.screenModel.subtitle, "The tunnel could not start.")
        // A successful attempt clears the error and the retry state.
        fake.failure = nil
        await model.perform(.retry)
        XCTAssertEqual(fake.startBodies.count, 3)
        XCTAssertNotEqual(model.screenModel.title, Strings.attention)
    }
    func testForgetClearsAStartError() async {
        let fake = FakeBackend()
        fake.currentStatus = Status(paired: true, phone: Phone(state: "ready"))
        let model = makeModel(fake)
        await model.refresh()
        fake.failure = BackendError.response("The tunnel could not start.")
        await model.toggle()
        XCTAssertEqual(model.screenModel.title, Strings.attention)
        fake.failure = nil
        _ = await model.forget()
        XCTAssertEqual(model.screen, .unpaired)
        XCTAssertNotEqual(model.screenModel.title, Strings.attention)
    }
    func testModelDeniedNotificationsExposeTheSettingText() async {
        let fake = FakeBackend(); let sink = RecordingNotificationSink(); let opener = RecordingSettingsOpener()
        sink.status = .denied
        let model = makeModel(fake, sink: sink, opener: opener)
        await model.refreshNotificationAuthorization()
        XCTAssertTrue(model.notificationsDenied)
        XCTAssertEqual(model.notificationsSettingsText, "Notifications are off. You will not see a message when the tunnel turns off.")
        XCTAssertTrue(model.screenModel.attentionItems.contains(Strings.notificationsDenied))
        model.openNotificationSettings()
        XCTAssertEqual(opener.opened, 1)
    }
    func testModelPostsAnAutoStopToTheRecordingSink() async {
        let fake = FakeBackend(); let sink = RecordingNotificationSink()
        sink.status = .authorized
        fake.currentStatus = Status(paired: true, phone: Phone(state: "ready"))
        let model = makeModel(fake, sink: sink)
        await model.refreshNotificationAuthorization()
        await model.refresh()
        XCTAssertTrue(sink.messages.isEmpty)
        fake.currentStatus = Status(paired: true, phone: Phone(state: "ready"), lastStop: LastStop(reason: "hotspot_lost", at: 10))
        await model.refresh()
        XCTAssertEqual(sink.messages.map(\.body), ["The hotspot turned off, so HotspotShade turned the tunnel off."])
        XCTAssertEqual(sink.messages.first?.title, "HotspotShade")
        // The same stop does not send a second message.
        await model.refresh()
        XCTAssertEqual(sink.messages.count, 1)
    }
    func testModelPostsThePlainTunnelError() async {
        let fake = FakeBackend(); let sink = RecordingNotificationSink()
        sink.status = .authorized
        fake.currentStatus = Status(paired: true, phone: Phone(state: "ready"))
        let model = makeModel(fake, sink: sink)
        model.setFrontmost(false)
        await model.refreshNotificationAuthorization()
        await model.refresh()
        fake.currentStatus = Status(paired: true, phone: Phone(state: "ready"), error: "The engine lost the connection.", lastStop: LastStop(reason: "error", at: 10))
        await model.refresh()
        XCTAssertEqual(sink.messages.map(\.body), ["The engine lost the connection."])
        XCTAssertEqual(sink.messages.first?.kind, .tunnelError)
    }
    func testModelDoesNotNotifyForAUserStop() async {
        let fake = FakeBackend(); let sink = RecordingNotificationSink()
        sink.status = .authorized
        fake.currentStatus = Status(paired: true, phone: Phone(state: "ready"))
        let model = makeModel(fake, sink: sink)
        await model.refreshNotificationAuthorization()
        await model.refresh()
        fake.currentStatus = Status(paired: true, phone: Phone(state: "ready"), lastStop: LastStop(reason: "user", at: 10))
        await model.refresh()
        XCTAssertTrue(sink.messages.isEmpty)
    }

    // MARK: - Diagnostics

    private func diagnosticsFixture() -> Diagnostics {
        Diagnostics(
            running: true,
            engine: EngineDiagnostics(version: "1.2.3", uptime_s: 120, workers: 4),
            setup: SetupDiagnostics(connect: DurationStats(count: 5, p50: 10, p95: 20, max: 30), greeting: DurationStats(count: 0, p50: nil, p95: nil, max: nil)),
            dns: DNSDiagnostics(lookups: 10, ok: 9, failed: 1, ms: DurationStats(count: 10, p50: 2, p95: 9, max: 20)),
            queues: QueueDiagnostics(input: [QueueSample(peak: 8, max_age_us: 1200)], output: QueueSample(peak: 9, max_age_us: 1500)),
            udp: UDPDiagnostics(flows: 3, age_drops: 0),
            tcp: TCPDiagnostics(flows_peak: 12, retransmits: 1, zero_window_ms: 0),
            failures: FailureTotals(total: 2, dropped: 0)
        )
    }
    private func failuresFixture() -> Failures {
        Failures(since: 1762000000, total: 2, dropped: 0, demo: false, groups: [FailureGroup(proto: "tcp", family: "ipv4", port: 443, reason: "unreachable", phase: "request", count: 2, name: "example.com", exampleIp: "203.0.113.5", code: 4)], recent: [])
    }
    private func contextFixture() -> DiagnosticsContext {
        DiagnosticsContext(macOSVersion: "14.5", appVersion: "1.0 (1)", link: WiFiLinkInfo(band: .ghz5, channelWidthMHz: 80, rssi: -62, interfaceName: "en0"), interfaceName: "en0", icmpEnabled: true, lastStop: LastStop(reason: "source_device_gone", at: 1761990000), lastStopMessage: "The source device stopped answering.", notificationAuthorization: .authorized, now: Date(timeIntervalSince1970: 1762000000))
    }
    func testDiagnosticsReportExactText() {
        let text = DiagnosticsReport.text(diagnostics: diagnosticsFixture(), failures: failuresFixture(), context: contextFixture())
        let expected = """
        HotspotShade diagnostics
        Time: 2025-11-01T12:26:40Z
        macOS: 14.5
        App: 1.0 (1)
        Wi-Fi: 5 GHz, 80 MHz, -62 dBm, en0
        Ping: on
        Last stop: source_device_gone at 2025-11-01T09:40:00Z. The source device stopped answering.
        Notifications: allowed
        Engine: version 1.2.3, uptime 120 s, workers 4
        Setup: connect count 5, p50 10 ms, p95 20 ms, max 30 ms; greeting count 0, p50 unknown, p95 unknown, max unknown; auth count unknown, p50 unknown, p95 unknown, max unknown; request count unknown, p50 unknown, p95 unknown, max unknown
        DNS: 10 lookups, 9 ok, 1 failed; count 10, p50 2 ms, p95 9 ms, max 20 ms
        Queues: input peak 8, max age 1200 us; output peak 9, max age 1500 us
        UDP: 3 flows, 0 age drops
        TCP: 12 peak flows, 1 retransmits, 0 ms zero window
        Failures:
        HotspotShade failures since 2025-11-01T12:26:40Z: 2 failed connections, 0 dropped.
        2x tcp ipv4 443 unreachable request example.com 203.0.113.5 code 4
        """
        XCTAssertEqual(text, expected)
    }
    func testDiagnosticsReportUnavailableLines() {
        let text = DiagnosticsReport.text(diagnostics: nil, failures: nil, context: DiagnosticsContext(macOSVersion: "14.5", appVersion: "1.0", now: Date(timeIntervalSince1970: 0)))
        XCTAssertTrue(text.contains("Engine: unavailable."))
        XCTAssertTrue(text.contains("Failures: unavailable."))
        XCTAssertTrue(text.contains("Wi-Fi: unavailable"))
        XCTAssertTrue(text.contains("Ping: unknown"))
        XCTAssertTrue(text.contains("Last stop: none"))
        XCTAssertTrue(text.contains("Notifications: not asked"))
    }
    func testCopyDiagnosticsUsesThePasteboardAndHoldsNoSecret() async {
        let fake = FakeBackend(); let pasteboard = W6RecordingPasteboard()
        fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "connected", checkedAt: 1762000000), icmpEnabled: true, iface: "en0")
        fake.currentDiagnostics = diagnosticsFixture()
        fake.currentFailures = failuresFixture()
        let model = makeModel(fake, now: { Date(timeIntervalSince1970: 1762000000) }, pasteboard: pasteboard)
        await model.refresh()
        await model.copyDiagnostics()
        XCTAssertTrue(model.diagnosticsCopied)
        XCTAssertEqual(pasteboard.texts, [model.lastDiagnosticsText])
        let text = model.lastDiagnosticsText
        XCTAssertTrue(text.contains("HotspotShade diagnostics"))
        XCTAssertTrue(text.contains("Engine: version 1.2.3"))
        XCTAssertTrue(text.contains("Failures:"))
        XCTAssertFalse(text.localizedCaseInsensitiveContains("bearer"))
        XCTAssertFalse(text.localizedCaseInsensitiveContains("secret"))
    }
    func testCopyDiagnosticsToleratesMissingEndpoints() async {
        let fake = FakeBackend(); let pasteboard = W6RecordingPasteboard()
        fake.diagnosticsError = BackendError.unavailable
        fake.failuresError = BackendError.unavailable
        let model = makeModel(fake, pasteboard: pasteboard)
        await model.copyDiagnostics()
        XCTAssertTrue(model.lastDiagnosticsText.contains("Engine: unavailable."))
        XCTAssertTrue(model.lastDiagnosticsText.contains("Failures: unavailable."))
        XCTAssertEqual(pasteboard.texts.count, 1)
    }

    func testTrustedBySourceModelRow() async {
        let fake = FakeBackend()
        fake.currentStatus = Status(paired: false, phone: Phone(state: "unpaired", trustedBySource: true))
        let model = makeModel(fake, forgetIntent: MemoryForgetIntent(true))
        await model.refresh()
        XCTAssertEqual(model.screen, .unpaired)
        XCTAssertEqual(model.screenModel.subtitle, "The source device still knows this target device. Press Pair to continue.")
        XCTAssertEqual(model.screenModel.primaryAction, .pair)
    }
    func testModelPostsTheSourceWarningAndClearsItOnRecovery() async {
        var clock = Date(timeIntervalSince1970: 100)
        let fake = FakeBackend(); let sink = RecordingNotificationSink()
        sink.status = .authorized
        fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "connected"))
        let model = makeModel(fake, now: { clock }, sink: sink)
        model.setFrontmost(false)
        await model.refreshNotificationAuthorization()
        await model.refresh()
        XCTAssertTrue(sink.messages.isEmpty)
        fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "not_responding"))
        await model.refresh()
        clock.addTimeInterval(10)
        await model.refresh()
        XCTAssertEqual(sink.messages.map(\.body), ["The source device stopped answering. New connections fail."])
        XCTAssertEqual(sink.messages.first?.kind, .sourceStopped)
        fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "ready"))
        await model.refresh()
        XCTAssertEqual(sink.clears, 1)
    }
    func testModelIgnoresAStaleSourceProbe() async {
        var clock = Date(timeIntervalSince1970: 1_000)
        let fake = FakeBackend(); let sink = RecordingNotificationSink()
        sink.status = .authorized
        fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "not_responding", checkedAt: 900))
        let model = makeModel(fake, now: { clock }, sink: sink)
        model.setFrontmost(false)
        await model.refreshNotificationAuthorization()
        await model.refresh()
        clock.addTimeInterval(20)
        await model.refresh()
        XCTAssertFalse(model.sourceDeviceWarning)
        XCTAssertTrue(sink.messages.isEmpty)
        XCTAssertEqual(model.screen, .on)
    }
    func testModelWarnsForAFreshSourceProbe() async {
        var clock = Date(timeIntervalSince1970: 1_000)
        let fake = FakeBackend(); let sink = RecordingNotificationSink()
        sink.status = .authorized
        fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "not_responding", checkedAt: 1_000))
        let model = makeModel(fake, now: { clock }, sink: sink)
        model.setFrontmost(false)
        await model.refreshNotificationAuthorization()
        await model.refresh()
        clock.addTimeInterval(10)
        fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "not_responding", checkedAt: 1_010))
        await model.refresh()
        XCTAssertTrue(model.sourceDeviceWarning)
        XCTAssertEqual(sink.messages.map(\.kind), [.sourceStopped])
    }
    func testModelDoesNotWarnWhileCheckingTheSourceDevice() async {
        var clock = Date(timeIntervalSince1970: 1_000)
        let fake = FakeBackend(); let sink = RecordingNotificationSink()
        sink.status = .authorized
        fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "checking", message: "Checking the source device.", checkedAt: 1_000))
        let model = makeModel(fake, now: { clock }, sink: sink)
        model.setFrontmost(false)
        await model.refreshNotificationAuthorization()
        await model.refresh()
        clock.addTimeInterval(20)
        await model.refresh()
        XCTAssertFalse(model.sourceDeviceWarning)
        XCTAssertTrue(sink.messages.isEmpty)
        XCTAssertEqual(model.screen, .on)
        XCTAssertEqual(model.screenModel.subtitle, "Checking the source device.")
        XCTAssertTrue(model.screenModel.sourceDevice.lines.contains("Checking the source device."))
    }

    func testModelKeepsTheAutoStopMessageAfterRecovery() async {
        var clock = Date(timeIntervalSince1970: 100)
        let fake = FakeBackend(); let sink = RecordingNotificationSink()
        sink.status = .authorized
        fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "connected"))
        let model = makeModel(fake, now: { clock }, sink: sink)
        model.setFrontmost(false)
        await model.refreshNotificationAuthorization()
        await model.refresh()
        fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "not_responding"))
        await model.refresh()
        clock.addTimeInterval(10)
        await model.refresh()
        XCTAssertEqual(sink.messages.count, 1)
        fake.currentStatus = Status(running: false, paired: true, phone: Phone(state: "ready"), lastStop: LastStop(reason: "hotspot_lost", at: 110))
        await model.refresh()
        XCTAssertEqual(sink.clears, 1)
        XCTAssertEqual(sink.messages.count, 2)
        XCTAssertEqual(sink.messages.last?.kind, .autoStopped)
    }
    func testModelStaysQuietWhileFrontmost() async {
        var clock = Date(timeIntervalSince1970: 100)
        let fake = FakeBackend(); let sink = RecordingNotificationSink()
        sink.status = .authorized
        fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "connected"))
        let model = makeModel(fake, now: { clock }, sink: sink)
        model.setFrontmost(true)
        await model.refreshNotificationAuthorization()
        await model.refresh()
        fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "not_responding"))
        clock.addTimeInterval(10)
        await model.refresh()
        XCTAssertTrue(sink.messages.isEmpty)
    }
    func testModelPostsPairingAttention() async {
        let fake = FakeBackend(); let sink = RecordingNotificationSink()
        sink.status = .authorized
        fake.currentStatus = Status(paired: false, phone: Phone(state: "unpaired"))
        let model = makeModel(fake, sink: sink)
        model.setFrontmost(false)
        await model.refreshNotificationAuthorization()
        await model.refresh()
        fake.currentPair = PairState(state: "confirm", code: "123 456")
        await model.refreshPairing()
        XCTAssertEqual(sink.messages.map(\.body), ["Check the code on your source device."])
        XCTAssertEqual(sink.messages.first?.kind, .pairingAttention)
    }

    // MARK: - Launch options

    func testLaunchOptionsDemo() {
        XCTAssertTrue(LaunchOptions(arguments: ["HotspotShade", "--demo"], environment: [:]).demo)
        XCTAssertTrue(LaunchOptions(arguments: ["HotspotShade"], environment: ["HS_DEMO": "1"]).demo)
        XCTAssertFalse(LaunchOptions(arguments: ["HotspotShade"], environment: ["HS_DEMO": "0"]).demo)
        XCTAssertFalse(LaunchOptions(arguments: ["HotspotShade"], environment: [:]).demo)
    }
}
