import XCTest
@testable import HotspotShadeKit

// The app has no demo mode. An engine that answers with its built-in test data
// is a wrong build or a wrong launch. These tests use the fake backend and a
// canned HTTP server, so they start no engine.
final class TestDataEngineTests: XCTestCase {
    func testTestDataIsAPlainEngineLaunchError() {
        let failure = EngineLaunchFailure.fromUserEngine(BackendError.testDataEngine)
        XCTAssertEqual(failure.kind, .engine)
        XCTAssertEqual(failure.message, EngineLaunchText.testDataEngine)
        XCTAssertEqual(failure.recovery, EngineLaunchText.testDataEngineRecovery)
        XCTAssertEqual(failure.diagnosticCode, "engine_test_data")
        let presentation = EngineLaunchState.failed(failure).presentation()
        XCTAssertEqual(presentation.action, .retry)
        XCTAssertTrue(presentation.isAttention)
        for text in [failure.message, failure.recovery] {
            XCTAssertFalse(text.lowercased().contains("demo"))
            XCTAssertFalse(text.lowercased().contains("simulated"))
        }
    }

    func testUserEngineCheckRefusesTestData() async throws {
        let fake = FakeBackend()
        var status = Status(running: false, paired: true, phone: Phone(state: "ready"))
        status.demo = true
        fake.currentStatus = status
        do {
            try await UserEngineCheck.verify(fake)
            XCTFail("A test-data engine must fail the launch.")
        } catch BackendError.testDataEngine {}
    }

    func testUserEngineCheckAcceptsARealStatus() async throws {
        let fake = FakeBackend()
        var status = Status(running: false, paired: false, phone: Phone(state: "unpaired"))
        status.demo = false
        fake.currentStatus = status
        try await UserEngineCheck.verify(fake)
    }

    func testUserEngineCheckLeavesOtherReadFailuresToThePoll() async throws {
        let fake = FakeBackend()
        fake.statusFailure = BackendError.timeout
        try await UserEngineCheck.verify(fake)
    }

    func testHTTPStatusRefusesTestData() async throws {
        let server = try CannedServer(status: "200 OK", body: #"{"demo":true,"api":1,"running":true,"paired":true}"#)
        defer { server.stop() }
        let client = HTTPBackend(port: server.port, secret: "secret")
        do {
            _ = try await client.status(timeout: 2)
            XCTFail("A test-data status must not decode as a status.")
        } catch BackendError.testDataEngine {}
    }

    func testHTTPFailuresRefuseTestData() async throws {
        let server = try CannedServer(status: "200 OK", body: #"{"since":1762000000,"total":3,"dropped":0,"demo":true,"groups":[],"recent":[]}"#)
        defer { server.stop() }
        let client = HTTPBackend(port: server.port, secret: "secret")
        do {
            _ = try await client.failures()
            XCTFail("A test-data failure report must not decode as a report.")
        } catch BackendError.testDataEngine {}
    }
}

@MainActor final class TestDataEngineModelTests: XCTestCase {
    func testTestDataStatusIsUnavailableAtOnceAndNeverShown() async {
        let fake = FakeBackend()
        let sink = RecordingNotificationSink()
        sink.status = .authorized
        fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "connected"))
        let model = AppModel(backend: fake, notificationSink: sink)
        model.setFrontmost(false)
        await model.refreshNotificationAuthorization()
        await model.refresh()
        XCTAssertEqual(model.screenModel.primaryAction, .turnOff)

        // The engine now answers with test data and a new stop record. The
        // app keeps the last real status, shows the engine error at once, and
        // posts no notification for the simulated stop.
        var simulated = Status(running: false, paired: true, phone: Phone(state: "ready"), lastStop: LastStop(reason: "phone_unreachable"))
        simulated.demo = true
        fake.currentStatus = simulated
        await model.refresh()
        XCTAssertEqual(model.status.running, true, "Test data must not replace the last real status.")
        XCTAssertNil(model.status.demo)
        XCTAssertEqual(model.statusFreshness, .unavailable)
        XCTAssertTrue(model.statusUnavailable)
        XCTAssertEqual(model.dashboard.title, Strings.unknownTitle)
        XCTAssertEqual(model.dashboard.subtitle, EngineLaunchText.testDataEngine)
        XCTAssertNotEqual(model.screenModel.primaryAction, .turnOff)
        XCTAssertNotEqual(model.screenModel.primaryAction, .turnOn)
        XCTAssertTrue(sink.messages.isEmpty)

        // A real status clears the engine error.
        fake.currentStatus = Status(running: false, paired: true, phone: Phone(state: "ready"))
        await model.refresh()
        XCTAssertEqual(model.statusFreshness, .fresh)
        XCTAssertNotEqual(model.dashboard.subtitle, EngineLaunchText.testDataEngine)
    }

    func testOtherReadFailuresKeepTheNormalUnavailableText() {
        let input = DeriveInput(running: false, paired: true, phone: .ready, freshness: .unavailable)
        XCTAssertEqual(AppModel.derive(input).dashboard.subtitle, Strings.statusUnavailableSubtitle)
        let testData = DeriveInput(running: false, paired: true, phone: .ready, freshness: .unavailable, testDataEngine: true)
        XCTAssertEqual(AppModel.derive(testData).dashboard.subtitle, EngineLaunchText.testDataEngine)
    }

    func testTestDataFailureReportIsAnError() async {
        let fake = FakeBackend()
        fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "connected"))
        let model = AppModel(backend: fake)
        await model.refresh()
        fake.currentFailures = Failures(since: 1_762_000_000, total: 2, dropped: 0, demo: true, groups: [FailureGroup(proto: "tcp", family: "ipv4", port: 443, reason: "unreachable", phase: "request", count: 2, name: "example.com", exampleIp: "203.0.113.5", code: 4)], recent: [])
        await model.loadFailures()
        XCTAssertEqual(model.failuresState, .error(EngineLaunchText.testDataEngine))
        XCTAssertTrue(model.failureRows.isEmpty)
    }
}

final class TestDataEngineRequestTests: XCTestCase {
    // Every engine answer passes through one request path. A pairing answer
    // with the test-data mark must not reach the pairing screen.
    func testHTTPPairStateRefusesTestData() async throws {
        let server = try CannedServer(status: "200 OK", body: #"{"state":"confirm","code":"482931","demo":true}"#)
        defer { server.stop() }
        let client = HTTPBackend(port: server.port, secret: "secret")
        do {
            _ = try await client.pairState()
            XCTFail("A test-data pairing answer must be refused.")
        } catch BackendError.testDataEngine {}
    }
}
