import XCTest
import Foundation
import Network
@testable import HotspotShadeKit

// A response from the engine with every field of the failure contract.
private let fullResponse = """
{"ok":true,"since":1762000000,"total":37,"dropped":2,"demo":false,
"groups":[
{"proto":"tcp","family":"ipv4","port":443,"reason":"unreachable","phase":"request","count":12,"name":"example.com","example_ip":"203.0.113.5","code":4},
{"proto":"dns","family":"ipv6","port":53,"reason":"timed_out","phase":"request","count":1,"name":null,"example_ip":"2606:4700::1","code":null},
{"proto":"udp","family":"ipv4","port":443,"reason":"refused","phase":null,"count":3,"name":"media.example.net","example_ip":"198.51.100.7","code":null}
],
"recent":[{"ts":1762000010,"proto":"tcp","family":"ipv6","ip":"2606:4700::1","port":443,"reason":"unreachable","phase":"request","name":null,"code":4}]}
"""

private func sampleFailures() throws -> Failures {
    try JSONDecoder().decode(Failures.self, from: Data(fullResponse.utf8))
}

private func group(_ proto: String?, _ family: String?, _ port: Int?, _ reason: String?, _ count: Int?, _ name: String?, _ ip: String? = nil, _ code: Int? = nil, _ phase: String? = nil) -> FailureGroup {
    FailureGroup(proto: proto, family: family, port: port, reason: reason, phase: phase, count: count, name: name, exampleIp: ip, code: code)
}

final class FailureDecodeTests: XCTestCase {
    func testDecodesTheFullResponse() throws {
        let failures = try sampleFailures()
        XCTAssertEqual(failures.since, 1762000000)
        XCTAssertEqual(failures.total, 37)
        XCTAssertEqual(failures.dropped, 2)
        XCTAssertEqual(failures.demo, false)
        XCTAssertEqual(failures.groups?.count, 3)
        let first = try XCTUnwrap(failures.groups?.first)
        XCTAssertEqual(first.proto, "tcp")
        XCTAssertEqual(first.family, "ipv4")
        XCTAssertEqual(first.port, 443)
        XCTAssertEqual(first.reason, "unreachable")
        XCTAssertEqual(first.phase, "request")
        XCTAssertEqual(first.count, 12)
        XCTAssertEqual(first.name, "example.com")
        XCTAssertEqual(first.exampleIp, "203.0.113.5")
        XCTAssertEqual(first.code, 4)
        XCTAssertNil(failures.groups?[1].name)
        XCTAssertNil(failures.groups?[1].code)
        XCTAssertEqual(failures.groups?[1].phase, "request")
        XCTAssertNil(failures.groups?[2].phase)
        XCTAssertEqual(failures.recent?.count, 1)
        let recent = try XCTUnwrap(failures.recent?.first)
        XCTAssertEqual(recent.ts, 1762000010)
        XCTAssertEqual(recent.proto, "tcp")
        XCTAssertEqual(recent.family, "ipv6")
        XCTAssertEqual(recent.ip, "2606:4700::1")
        XCTAssertEqual(recent.port, 443)
        XCTAssertEqual(recent.reason, "unreachable")
        XCTAssertEqual(recent.phase, "request")
        XCTAssertNil(recent.name)
        XCTAssertEqual(recent.code, 4)
    }
    func testWrongTypesNeverFailTheDecode() throws {
        let text = """
        {"since":"yesterday","total":"37","dropped":true,"demo":"no","groups":{"proto":"tcp"},"recent":7}
        """
        let failures = try JSONDecoder().decode(Failures.self, from: Data(text.utf8))
        XCTAssertNil(failures.since)
        XCTAssertNil(failures.total)
        XCTAssertNil(failures.dropped)
        XCTAssertNil(failures.demo)
        XCTAssertNil(failures.groups)
        XCTAssertNil(failures.recent)
    }
    func testMissingFieldsStayNil() throws {
        let failures = try JSONDecoder().decode(Failures.self, from: Data("{\"groups\":[{}]}".utf8))
        XCTAssertNil(failures.since)
        XCTAssertNil(failures.total)
        XCTAssertEqual(failures.groups?.count, 1)
        let empty = try XCTUnwrap(failures.groups?.first)
        XCTAssertNil(empty.proto)
        XCTAssertNil(empty.family)
        XCTAssertNil(empty.port)
        XCTAssertNil(empty.reason)
        XCTAssertNil(empty.phase)
        XCTAssertNil(empty.count)
        XCTAssertNil(empty.name)
        XCTAssertNil(empty.exampleIp)
        XCTAssertNil(empty.code)
    }
    func testOneBadArrayElementDoesNotLoseTheList() throws {
        let text = """
        {"groups":[17,{"proto":"tcp","count":2},null,{"proto":"udp","count":"many"}]}
        """
        let failures = try JSONDecoder().decode(Failures.self, from: Data(text.utf8))
        XCTAssertEqual(failures.groups?.count, 2)
        XCTAssertEqual(failures.groups?.first?.proto, "tcp")
        XCTAssertEqual(failures.groups?.first?.count, 2)
        XCTAssertEqual(failures.groups?.last?.proto, "udp")
        XCTAssertNil(failures.groups?.last?.count)
    }
    func testUnknownReasonShowsAsOther() throws {
        let failures = try JSONDecoder().decode(Failures.self, from: Data("{\"groups\":[{\"proto\":\"tcp\",\"reason\":\"quantum\"}]}".utf8))
        XCTAssertEqual(failures.groups?.first?.reason, "quantum")
        XCTAssertEqual(FailureReason(raw: failures.groups?.first?.reason), .other)
        XCTAssertEqual(FailureReason(raw: "timed_out"), .timedOut)
        XCTAssertEqual(FailureReason(raw: "TIMED_OUT"), .timedOut)
        XCTAssertEqual(FailureReason(raw: nil), .other)
    }
    func testUnknownAndMissingPhaseStayTolerant() throws {
        let failures = try JSONDecoder().decode(Failures.self, from: Data("{\"groups\":[{\"phase\":\"quantum\"},{\"phase\":null},{\"phase\":7},{}]}".utf8))
        XCTAssertEqual(failures.groups?.count, 4)
        XCTAssertEqual(failures.groups?[0].phase, "quantum")
        XCTAssertNil(failures.groups?[1].phase)
        XCTAssertNil(failures.groups?[2].phase)
        XCTAssertNil(failures.groups?[3].phase)
        XCTAssertEqual(FailurePhase(raw: "quantum"), .unknown)
        XCTAssertEqual(FailurePhase(raw: "REQUEST"), .request)
        XCTAssertNil(FailurePhase(raw: nil))
        XCTAssertNil(FailurePhase(raw: "  "))
    }
}

final class FailureFormatterTests: XCTestCase {
    func testRowsUsePlainWords() throws {
        let rows = FailureFormat.rows(try sampleFailures())
        XCTAssertEqual(rows.count, 3)
        XCTAssertEqual(rows[0].summary, "12 times: web connection to example.com port 443 could not be reached while the source device checked the destination")
        XCTAssertEqual(rows[0].detail, "IPv4, 203.0.113.5, code 4")
        XCTAssertEqual(rows[0].phase, "Destination request")
        XCTAssertEqual(rows[0].reason, "Could not be reached")
        XCTAssertEqual(rows[1].summary, "3 times: UDP connection to media.example.net port 443 was refused")
        XCTAssertEqual(rows[1].detail, "IPv4, 198.51.100.7")
        XCTAssertEqual(rows[1].phase, "Not reported")
        XCTAssertEqual(rows[2].summary, "1 time: DNS lookup for 2606:4700::1 port 53 got no answer in time while the source device checked the destination")
        XCTAssertEqual(rows[2].detail, "IPv6")
        XCTAssertEqual(rows[2].phase, "Destination request")
    }
    func testReportTextIsExact() throws {
        let expected = """
        HotspotShade failures since 2025-11-01T12:26:40Z: 37 failed connections, 2 dropped.
        12x tcp ipv4 443 unreachable request example.com 203.0.113.5 code 4
        3x udp ipv4 443 refused - media.example.net 198.51.100.7
        1x dns ipv6 53 timed_out request - 2606:4700::1
        """
        XCTAssertEqual(FailureFormat.report(try sampleFailures()), expected)
    }
    func testPluralAndEmptyReport() {
        let one = Failures(since: nil, total: 1, dropped: 0, groups: [group("tcp", "ipv4", 80, "refused", 1, "example.com", "203.0.113.5")])
        XCTAssertEqual(FailureFormat.rows(one).first?.summary, "1 time: web connection to example.com port 80 was refused")
        XCTAssertEqual(FailureFormat.report(one), "HotspotShade failures since unknown: 1 failed connection, 0 dropped.\n1x tcp ipv4 80 refused - example.com 203.0.113.5")
        let none = Failures()
        XCTAssertEqual(FailureFormat.rows(none), [])
        XCTAssertEqual(FailureFormat.report(none), "HotspotShade failures since unknown: 0 failed connections, 0 dropped.")
    }
    func testUnknownReasonAndIpv6UseOtherAndTheAddress() {
        let failures = Failures(total: 2, dropped: 0, groups: [group("tcp", "ipv6", 443, "quantum", 2, nil, "2001:db8::1")])
        let row = FailureFormat.rows(failures).first
        XCTAssertEqual(row?.summary, "2 times: web connection to 2001:db8::1 port 443 failed")
        XCTAssertEqual(row?.detail, "IPv6")
        XCTAssertEqual(FailureFormat.report(failures), "HotspotShade failures since unknown: 2 failed connections, 0 dropped.\n2x tcp ipv6 443 other - - 2001:db8::1")
    }
    func testMissingFieldsUseSafeWords() {
        let failures = Failures(total: 1, dropped: 0, groups: [FailureGroup()])
        let row = FailureFormat.rows(failures).first
        XCTAssertEqual(row?.summary, "1 time: connection to an unknown address failed")
        XCTAssertEqual(row?.detail, "")
        XCTAssertEqual(row?.phase, "Not reported")
        XCTAssertEqual(FailureFormat.report(failures), "HotspotShade failures since unknown: 1 failed connection, 0 dropped.\n1x other other - other - - -")
    }
    func testOrderIsCountThenProtoThenFamilyThenPort() {
        let failures = Failures(total: 6, dropped: 0, groups: [
            group("udp", "ipv4", 53, "denied", 2, "b"),
            group("tcp", "ipv6", 443, "unreachable", 2, "c"),
            group("dns", "ipv4", 53, "refused", 2, "a"),
            group("tcp", "ipv4", 80, "refused", 5, "d"),
        ])
        XCTAssertEqual(FailureFormat.rows(failures).map { $0.summary }, [
            "5 times: web connection to d port 80 was refused",
            "2 times: DNS lookup for a port 53 was refused",
            "2 times: web connection to c port 443 could not be reached",
            "2 times: UDP connection to b port 53 was blocked",
        ])
    }
    func testPhaseKeepsGroupsApartAndUsesPlainWords() {
        let failures = Failures(total: 2, dropped: 0, groups: [
            group("tcp", "ipv4", 443, "other", 1, "example.com", "203.0.113.5", nil, "request"),
            group("tcp", "ipv4", 443, "other", 1, "example.com", "203.0.113.5", nil, "connect"),
        ])
        let rows = FailureFormat.rows(failures)
        XCTAssertEqual(rows.map { $0.phase }, ["Source connection", "Destination request"])
        XCTAssertEqual(rows.map { $0.summary }, [
            "1 time: web connection to example.com port 443 failed while the target device connected to the source device",
            "1 time: web connection to example.com port 443 failed while the source device checked the destination",
        ])
        XCTAssertNotEqual(rows[0].id, rows[1].id)
        XCTAssertEqual(FailureFormat.report(failures), """
        HotspotShade failures since unknown: 2 failed connections, 0 dropped.
        1x tcp ipv4 443 other connect example.com 203.0.113.5
        1x tcp ipv4 443 other request example.com 203.0.113.5
        """)
    }
    func testATimeoutDoesNotClaimThatTheDestinationTimedOut() {
        let failures = Failures(total: 1, dropped: 0, groups: [
            group("tcp", "ipv4", 443, "timed_out", 1, "example.com", "203.0.113.5", nil, "request"),
        ])
        let row = FailureFormat.rows(failures).first
        XCTAssertEqual(row?.reason, "No answer in time")
        XCTAssertEqual(row?.summary, "1 time: web connection to example.com port 443 got no answer in time while the source device checked the destination")
        XCTAssertFalse(row?.summary.localizedCaseInsensitiveContains("destination timed out") ?? true)
    }
    func testUnknownPhaseUsesANeutralStage() {
        let failures = Failures(total: 1, dropped: 0, groups: [
            group("tcp", "ipv4", 443, "other", 1, nil, "203.0.113.5", nil, "quantum"),
        ])
        let row = FailureFormat.rows(failures).first
        XCTAssertEqual(row?.phase, "Unknown stage")
        XCTAssertEqual(row?.summary, "1 time: web connection to 203.0.113.5 port 443 failed at an unknown stage")
        XCTAssertTrue(FailureFormat.report(failures).hasSuffix("443 other unknown - 203.0.113.5"))
    }
    func testSettingsTextIsExact() {
        XCTAssertEqual(Strings.recentFailures, "Recent failures")
        XCTAssertEqual(Strings.refresh, "Refresh")
        XCTAssertEqual(Strings.copyReport, "Copy report")
        XCTAssertEqual(Strings.loadingFailures, "Loading failures...")
        XCTAssertEqual(Strings.noFailures, "No failed connections yet.")
        XCTAssertEqual(Strings.failuresUnavailable, "This engine cannot list failures.")
        XCTAssertEqual(Strings.failuresTunnelOff, "Turn the tunnel on to see failures.")
        let visible = [Strings.recentFailures, Strings.refresh, Strings.copyReport, Strings.loadingFailures, Strings.failuresNotLoaded, Strings.noFailures, Strings.failuresUnavailable, Strings.failuresTunnelOff, Strings.failuresHint, Strings.reportCopied]
        for text in visible {
            XCTAssertFalse(text.localizedCaseInsensitiveContains("hotspot proxy"), text)
            XCTAssertFalse(text.localizedCaseInsensitiveContains("iphone"), text)
            XCTAssertFalse(text.localizedCaseInsensitiveContains("laptop"), text)
        }
    }
}

final class FailureHTTPTests: XCTestCase {
    func testRequestUsesTheAuthenticatedPath() async throws {
        let server = try CannedServer(status: "200 OK", body: "{\"ok\":true,\"groups\":[]}")
        defer { server.stop() }
        let client = HTTPBackend(port: server.port, secret: "secret")
        let failures = try await client.failures()
        XCTAssertEqual(failures.groups?.count, 0)
        let head = try XCTUnwrap(server.lastRequest)
        XCTAssertTrue(head.hasPrefix("GET /api/failures "), head)
        XCTAssertTrue(head.contains("Authorization: Bearer secret"), head)
        XCTAssertTrue(head.contains("Host: 127.0.0.1:\(server.port)"), head)
    }
    func testNotFoundIsUnavailable() async throws {
        let server = try CannedServer(status: "404 Not Found", body: "{\"error\":\"not found\"}")
        defer { server.stop() }
        let client = HTTPBackend(port: server.port, secret: "secret")
        do { _ = try await client.failures(); XCTFail("Expected unavailable") }
        catch BackendError.unavailable {} catch { XCTFail("Unexpected \(error)") }
    }
    func testBadBodyIsUnavailable() async throws {
        for body in ["[]", "not json", "{} trailing"] {
            let server = try CannedServer(status: "200 OK", body: body)
            let client = HTTPBackend(port: server.port, secret: "secret")
            do { _ = try await client.failures(); XCTFail("Expected unavailable for \(body)") }
            catch BackendError.unavailable {} catch { XCTFail("Unexpected \(error) for \(body)") }
            server.stop()
        }
    }
    // The engine contract for the failure report fields, read from the real
    // engine binary with its hidden test-data flag. The app never passes it,
    // and its HTTP client refuses this report.
    func testTestDataEngineFailureReportDecodes() async throws {
        guard let path = ProcessInfo.processInfo.environment["HS_TEST_DEMO_BINARY"] else { throw XCTSkip("No engine binary provided.") }
        let launch = try TestDataEngineLaunch(engine: path)
        let process = launch.process
        try await process.start()
        do {
            let (code, data) = try await launch.get("/api/failures")
            if code == 200 {
                // A newer engine has the endpoint. Every field must decode.
                let failures = try JSONDecoder().decode(Failures.self, from: data)
                XCTAssertEqual(failures.demo, true)
                XCTAssertNotNil(failures.total)
                XCTAssertNotNil(failures.groups)
                XCTAssertNotNil(failures.recent)
                let client = HTTPBackend(port: try XCTUnwrap(process.port), secret: process.secret)
                do { _ = try await client.failures(); XCTFail("The client must refuse engine test data.") }
                catch BackendError.testDataEngine {}
            } else {
                // An older engine has no failure endpoint.
                XCTAssertEqual(code, 404)
            }
        } catch {
            await process.stop()
            throw error
        }
        await process.stop()
    }
}

@MainActor final class FailureModelTests: XCTestCase {
    private func runningModel(_ fake: FakeBackend, pasteboard: PasteboardWriting = NoPasteboard()) async -> AppModel {
        let model = AppModel(backend: fake, pasteboard: pasteboard)
        fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "connected"))
        await model.refresh()
        return model
    }
    func testStateMachine() async throws {
        let fake = FakeBackend()
        let model = AppModel(backend: fake)
        XCTAssertEqual(model.failuresState, .idle)

        // The tunnel is off. The app does not ask the engine.
        await model.loadFailures()
        XCTAssertEqual(model.failuresState, .idle)
        XCTAssertEqual(fake.calls.filter { $0 == "failures" }.count, 0)

        fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "connected"))
        await model.refresh()
        fake.operationDelay = 200_000_000
        let loading = Task { await model.loadFailures() }
        try await Task.sleep(nanoseconds: 40_000_000)
        XCTAssertEqual(model.failuresState, .loading)
        await loading.value
        XCTAssertEqual(model.failuresState, .empty)
        XCTAssertEqual(model.failureRows, [])
        fake.operationDelay = 0

        fake.currentFailures = try sampleFailures()
        await model.loadFailures()
        XCTAssertEqual(model.failuresState, .loaded)
        XCTAssertEqual(model.failureRows.count, 3)
        XCTAssertEqual(model.failureRows.first?.summary, "12 times: web connection to example.com port 443 could not be reached while the source device checked the destination")

        fake.failuresError = BackendError.unavailable
        await model.loadFailures()
        XCTAssertEqual(model.failuresState, .unavailable)
        XCTAssertEqual(model.failureRows, [])
        XCTAssertEqual(model.failureReport, "")

        fake.failuresError = BackendError.timeout
        await model.loadFailures()
        XCTAssertEqual(model.failuresState, .error("The engine did not respond in time."))
        XCTAssertEqual(fake.calls.filter { $0 == "failures" }.count, 4)
    }
    func testLoadedStateReturnsAfterAnError() async throws {
        let fake = FakeBackend()
        let model = await runningModel(fake)
        fake.failuresError = BackendError.timeout
        await model.loadFailures()
        XCTAssertEqual(model.failuresState, .error("The engine did not respond in time."))
        fake.failuresError = nil
        fake.currentFailures = try sampleFailures()
        await model.loadFailures()
        XCTAssertEqual(model.failuresState, .loaded)
        XCTAssertEqual(model.failureRows.count, 3)
    }
    func testCopyReportUsesTheInjectedPasteboard() async throws {
        let fake = FakeBackend()
        let board = RecordingPasteboard()
        let model = await runningModel(fake, pasteboard: board)
        fake.currentFailures = try sampleFailures()
        await model.loadFailures()
        XCTAssertFalse(model.reportCopied)
        model.copyReport()
        XCTAssertEqual(board.text, FailureFormat.report(try sampleFailures()))
        XCTAssertTrue(model.reportCopied)
        // A refresh clears the copied note.
        await model.loadFailures()
        XCTAssertFalse(model.reportCopied)
    }
    func testCopyWithoutGroupsWritesTheHeader() async {
        let fake = FakeBackend()
        let board = RecordingPasteboard()
        let model = await runningModel(fake, pasteboard: board)
        await model.loadFailures()
        XCTAssertEqual(model.failuresState, .empty)
        model.copyReport()
        XCTAssertEqual(board.text, "HotspotShade failures since unknown: 0 failed connections, 0 dropped.")
        XCTAssertTrue(model.reportCopied)
    }
}

// A loopback server that answers every request with one fixed response.
final class CannedServer {
    let listener: NWListener
    var port: UInt16 = 0
    private let queue = DispatchQueue(label: "canned-server")
    private let lock = NSLock()
    private var storedRequest: String?
    private var storedConnections: [NWConnection] = []
    var lastRequest: String? { lock.lock(); defer { lock.unlock() }; return storedRequest }
    init(status: String, body: String) throws {
        listener = try NWListener(using: .tcp, on: .any)
        let ready = DispatchSemaphore(value: 0)
        listener.stateUpdateHandler = { [weak self] state in
            if case .ready = state { self?.port = self?.listener.port?.rawValue ?? 0; ready.signal() }
        }
        listener.newConnectionHandler = { [weak self] connection in
            guard let self else { return }
            self.lock.lock(); self.storedConnections.append(connection); self.lock.unlock()
            connection.start(queue: self.queue)
            connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, _, _ in
                if let data, let self {
                    self.lock.lock(); self.storedRequest = String(decoding: data, as: UTF8.self); self.lock.unlock()
                }
                let reply = "HTTP/1.1 \(status)\r\nContent-Type: application/json\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)"
                connection.send(content: Data(reply.utf8), completion: .contentProcessed { _ in connection.cancel() })
            }
        }
        listener.start(queue: queue)
        guard ready.wait(timeout: .now() + 5) == .success else { throw BackendError.timeout }
    }
    func stop() {
        listener.cancel()
        lock.lock(); let connections = storedConnections; storedConnections = []; lock.unlock()
        connections.forEach { $0.cancel() }
    }
}

final class RecordingPasteboard: PasteboardWriting {
    private let lock = NSLock()
    private var stored: String?
    var text: String? { lock.lock(); defer { lock.unlock() }; return stored }
    func write(_ text: String) { lock.lock(); stored = text; lock.unlock() }
}
