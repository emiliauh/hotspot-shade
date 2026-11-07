import XCTest
import Foundation
@testable import HotspotShadeKit

private final class HeldStatusBackend: BackendClient {
    let fake = FakeBackend()
    var stopError: Error?
    var holdCancel = false
    private let lock = NSLock()
    private var reads: [CheckedContinuation<Status, Error>] = []
    private var cancelRead: CheckedContinuation<Void, Error>?
    var readCount: Int { lock.lock(); defer { lock.unlock() }; return reads.count }
    var cancelPending: Bool { lock.lock(); defer { lock.unlock() }; return cancelRead != nil }
    func complete(_ index: Int, with status: Status) {
        lock.lock(); let read = reads[index]; lock.unlock()
        read.resume(returning: status)
    }
    func fail(_ index: Int) {
        lock.lock(); let read = reads[index]; lock.unlock()
        read.resume(throwing: BackendError.timeout)
    }
    func finishCancel(fail: Bool) {
        lock.lock(); let pending = cancelRead; cancelRead = nil; lock.unlock()
        if fail { pending?.resume(throwing: BackendError.timeout) }
        else { pending?.resume(returning: ()) }
    }
    func status(timeout: TimeInterval) async throws -> Status {
        try await withCheckedThrowingContinuation { read in
            lock.lock(); reads.append(read); lock.unlock()
        }
    }
    func logs(since: Int) async throws -> [LogLine] { try await fake.logs(since: since) }
    func pairState() async throws -> PairState { try await fake.pairState() }
    func startPairing() async throws { try await fake.startPairing() }
    func cancelPairing() async throws {
        if !holdCancel { try await fake.cancelPairing(); return }
        try await withCheckedThrowingContinuation { continuation in
            lock.lock(); cancelRead = continuation; lock.unlock()
        }
    }
    func forget() async throws -> ForgetState { try await fake.forget() }
    func startTunnel(experimentalICMP: Bool) async throws { try await fake.startTunnel(experimentalICMP: experimentalICMP) }
    func stopTunnel(timeout: TimeInterval) async throws {
        if let stopError { throw stopError }
        try await fake.stopTunnel(timeout: timeout)
    }
    func failures() async throws -> Failures { try await fake.failures() }
    func probe() async throws -> Phone { try await fake.probe() }
    func diagnostics() async throws -> Diagnostics { try await fake.diagnostics() }
}

// The engine reports an interrupted operation as a 200 status with
// `running: true`, `state: "unknown"`, and `cleanup_blocked: true`. The
// running flag is then a conservative guard, not evidence that a tunnel is
// on. These tests are hermetic: they use decoded bodies, a loopback stub, and
// the fake backend. They create no route, device, or tunnel.
@MainActor final class RecoveryStateTests: XCTestCase {
    private let interruptedBody = """
    {"running":true,"state":"unknown","cleanup_blocked":true,"error":"The service state is unavailable after an interrupted operation. Inspect routes, devices, and the start record before restarting.","mode":null,"iface":null,"last_stop":{"reason":null,"at":null},"icmp_enabled":false}
    """

    private func makeModel(_ backend: BackendClient, now: @escaping () -> Date = Date.init, sink: NotificationSink = NoNotificationSink(), link: LinkInfoProvider = NoLinkInfoProvider(), pasteboard: PasteboardWriting = NoPasteboard()) -> AppModel {
        AppModel(backend: backend, now: now, pingSetting: W6PingSetting(), pasteboard: pasteboard, forgetIntent: MemoryForgetIntent(), notificationSink: sink, settingsOpener: NoSettingsOpener(), linkProvider: link, macOSVersion: "14.5", appVersion: "1.0 (1)")
    }

    private func decode(_ body: String) throws -> Status {
        try JSONDecoder().decode(Status.self, from: Data(body.utf8))
    }

    // MARK: - Decoding

    func testDecodesTheInterruptedStatusShape() async throws {
        // Use the real HTTP path so the 200 body is the input, not only a
        // decoder call.
        let server = try StubHTTPServer(body: interruptedBody)
        defer { server.stop() }
        let status = try await HTTPBackend(port: server.port, secret: "secret").status()
        XCTAssertEqual(server.paths, ["/api/status"])
        XCTAssertEqual(status.running, true)
        XCTAssertEqual(status.state, "unknown")
        XCTAssertEqual(status.cleanup_blocked, true)
        XCTAssertEqual(status.serviceState, .unknown)
        XCTAssertEqual(status.engineHealth, .stateUnknown)
        XCTAssertEqual(status.error, Strings.serviceStateUnknownBody)
        XCTAssertNil(status.phone)
        XCTAssertNil(status.paired)
    }

    func testOldStatusWithoutStateKeepsTheRunningMeaning() async throws {
        // An older engine sends neither `state` nor `cleanup_blocked`. The
        // running flag keeps its old meaning.
        let running = try decode("{\"running\":true,\"paired\":true,\"phone\":{\"state\":\"connected\"}}")
        XCTAssertNil(running.state)
        XCTAssertNil(running.cleanup_blocked)
        XCTAssertEqual(running.serviceState, .ready)
        XCTAssertEqual(running.engineHealth, .normal)

        let stopped = try decode("{\"running\":false,\"paired\":true,\"phone\":{\"state\":\"ready\"}}")
        XCTAssertEqual(stopped.engineHealth, .normal)

        // The old running status still shows On. The fix must not turn every
        // old engine into a recovery screen.
        let fake = FakeBackend()
        fake.currentStatus = running
        let model = makeModel(fake)
        await model.refresh()
        XCTAssertEqual(model.screen, .on)
        XCTAssertEqual(model.dashboard.action, .turnOff)
        XCTAssertEqual(model.screenModel.statusKind, .on)

        let stoppedFake = FakeBackend()
        stoppedFake.currentStatus = stopped
        let stoppedModel = makeModel(stoppedFake)
        await stoppedModel.refresh()
        XCTAssertEqual(stoppedModel.screen, .ready)
        XCTAssertEqual(stoppedModel.dashboard.action, .turnOn)
    }

    func testMalformedRecoveryFieldsDoNotChangeAnOldStatus() throws {
        // A wrong type is not a recovery signal. It stays missing, so the
        // running flag keeps the old meaning.
        let malformed = try decode("{\"running\":true,\"state\":7,\"cleanup_blocked\":\"yes\"}")
        XCTAssertNil(malformed.state)
        XCTAssertNil(malformed.cleanup_blocked)
        XCTAssertEqual(malformed.engineHealth, .normal)

        // Explicit normal values are normal too.
        let normal = try decode("{\"running\":false,\"state\":\"ready\",\"cleanup_blocked\":false}")
        XCTAssertEqual(normal.engineHealth, .normal)

        // A missing running flag with a cleanup block is not proof of a
        // stopped tunnel.
        let guarded = try decode("{\"cleanup_blocked\":true}")
        XCTAssertEqual(guarded.engineHealth, .stateUnknown)

        // An unrecognized future state is not treated as normal.
        let future = try decode("{\"running\":false,\"state\":\"paused\"}")
        XCTAssertEqual(future.serviceState, .unknown)
        XCTAssertEqual(future.engineHealth, .stateUnknown)
        let explicitReady = try decode("{\"running\":false,\"state\":\"Ready\"}")
        XCTAssertEqual(explicitReady.engineHealth, .normal)
    }

    // MARK: - Model

    func testUnknownRunningStatusNeverShowsOnOrAllowsAnAction() async throws {
        let fake = FakeBackend()
        fake.currentStatus = try decode(interruptedBody)
        let sink = RecordingNotificationSink()
        sink.status = .authorized
        let link = FakeLinkProvider()
        link.link = WiFiLinkInfo(band: .ghz2_4, channelWidthMHz: 20, rssi: -80, interfaceName: "en0")
        let model = makeModel(fake, sink: sink, link: link)
        await model.refreshNotificationAuthorization()
        await model.refresh()

        XCTAssertEqual(model.screen, .unknown)
        XCTAssertEqual(model.dashboard.title, Strings.serviceStateUnknownTitle)
        XCTAssertEqual(model.dashboard.subtitle, Strings.serviceStateUnknownBody)
        XCTAssertEqual(model.dashboard.action, .checkNow)
        XCTAssertEqual(model.screenModel.statusKind, .attention)
        XCTAssertNotEqual(model.dashboard.title, Strings.on)
        XCTAssertNotEqual(model.screenModel.statusKind, .on)

        // No card claims a tunnel or a source device state.
        XCTAssertTrue(model.screenModel.sourceDevice.lines.isEmpty)
        XCTAssertTrue(model.screenModel.connection.lines.isEmpty)
        XCTAssertNil(model.connectionsLabel)
        XCTAssertNil(model.pingLine)
        XCTAssertNil(model.lastCheckedText)
        XCTAssertNil(model.lastStopLine)
        XCTAssertTrue(model.linkAdvice.isEmpty)
        XCTAssertFalse(model.screenModel.attentionItems.contains(Strings.sourceStoppedTitle))

        // Every mutating action stays disabled and the guard refuses a direct
        // call too.
        let turnOn = model.screenModel.menuBar.actions.first { $0.kind == .turnOn }
        let turnOff = model.screenModel.menuBar.actions.first { $0.kind == .turnOff }
        let pair = model.screenModel.menuBar.actions.first { $0.kind == .pair }
        XCTAssertEqual(turnOn?.enabled, false)
        XCTAssertEqual(turnOff?.enabled, false)
        XCTAssertEqual(pair?.enabled, false)
        XCTAssertEqual(turnOn?.reason, Strings.serviceStateUnknownBody)
        XCTAssertEqual(turnOff?.reason, Strings.serviceStateUnknownBody)
        XCTAssertEqual(pair?.reason, Strings.serviceStateUnknownBody)

        await model.turnOn()
        await model.turnOff()
        await model.beginPairing()
        await model.checkNow()
        let forgetResult = await model.forget()
        XCTAssertFalse(fake.calls.contains("startTunnel"))
        XCTAssertFalse(fake.calls.contains("stopTunnel"))
        XCTAssertFalse(fake.calls.contains("startPairing"))
        XCTAssertFalse(fake.calls.contains("forget"))
        XCTAssertEqual(forgetResult.message, Strings.serviceStateUnknownBody)

        await model.loadFailures()
        XCTAssertFalse(fake.calls.contains("failures"))
        XCTAssertEqual(model.failuresState, .idle)

        // No notification for the interrupted state. `checkNow` runs a probe
        // but the fake probe answer must not turn the screen into On.
        XCTAssertTrue(sink.messages.isEmpty)
        XCTAssertEqual(model.screen, .unknown)
    }

    func testUnknownStatusClearsASourceDeviceWarning() async throws {
        var clock = Date(timeIntervalSince1970: 1_000)
        let fake = FakeBackend()
        fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "not_responding"))
        let model = makeModel(fake, now: { clock })
        await model.refresh()
        XCTAssertFalse(model.sourceDeviceWarning)

        clock = clock.addingTimeInterval(11)
        await model.refresh()
        XCTAssertTrue(model.sourceDeviceWarning)

        fake.currentStatus = try decode(interruptedBody)
        await model.refresh()
        XCTAssertFalse(model.sourceDeviceWarning)
        XCTAssertFalse(model.screenModel.attentionItems.contains(Strings.sourceStoppedTitle))
        XCTAssertEqual(model.screen, .unknown)
    }

    func testUnavailableStatusDisablesPairTurnOffAndForget() async {
        var clock = Date(timeIntervalSince1970: 1_000)
        let fake = FakeBackend()
        fake.currentStatus = Status(running: false, paired: true, phone: Phone(state: "ready"))
        let model = makeModel(fake, now: { clock })
        await model.refresh()
        XCTAssertEqual(model.screen, .ready)
        // The engine stops answering. Ten seconds after the first failed read,
        // the status is unavailable and no action can claim it is safe to
        // change state.
        fake.statusFailure = BackendError.timeout
        await model.refresh()
        clock = clock.addingTimeInterval(11)
        await model.refresh()
        XCTAssertTrue(model.statusUnavailable)

        let menu = model.screenModel.menuBar
        XCTAssertEqual(menu.actions.first { $0.kind == .turnOn }?.enabled, false)
        XCTAssertEqual(menu.actions.first { $0.kind == .turnOff }?.enabled, false)
        XCTAssertEqual(menu.actions.first { $0.kind == .pair }?.enabled, false)
        XCTAssertEqual(menu.actions.first { $0.kind == .pair }?.reason, Strings.statusUnavailableSubtitle)
        XCTAssertEqual(model.dashboard.action, .checkNow)
        XCTAssertNil(model.screenModel.secondaryAction)

        await model.turnOn()
        await model.turnOff()
        await model.beginPairing()
        let forget = await model.forget()
        let turnOffAndForget = await model.turnOffAndForget()
        XCTAssertFalse(fake.calls.contains("startTunnel"))
        XCTAssertFalse(fake.calls.contains("stopTunnel"))
        XCTAssertFalse(fake.calls.contains("startPairing"))
        XCTAssertFalse(fake.calls.contains("forget"))
        XCTAssertEqual(forget.message, Strings.statusUnavailableSubtitle)
        XCTAssertEqual(turnOffAndForget.message, Strings.statusUnavailableSubtitle)

        await model.loadFailures()
        XCTAssertFalse(fake.calls.contains("failures"))
        XCTAssertEqual(model.failuresState, .idle)
    }

    func testUnavailablePresentationKeepsPairAndTurnOffDisabled() {
        let input = PresentationInput(
            derive: DeriveInput(running: true, paired: true, phone: .connected, freshness: .unavailable)
        )
        let model = ScreenPresentation.build(input)
        XCTAssertEqual(model.primaryAction, .checkNow)
        XCTAssertNil(model.secondaryAction)
        XCTAssertEqual(model.menuBar.actions.first { $0.kind == .turnOn }?.enabled, false)
        XCTAssertEqual(model.menuBar.actions.first { $0.kind == .turnOff }?.enabled, false)
        XCTAssertEqual(model.menuBar.actions.first { $0.kind == .pair }?.enabled, false)
        XCTAssertEqual(model.menuBar.actions.first { $0.kind == .turnOff }?.reason, Strings.statusUnavailableSubtitle)
    }

    func testARejectedUnavailableActionDoesNotStartOrStop() async throws {
        let fake = FakeBackend()
        fake.currentStatus = try decode("{\"running\":false,\"paired\":true,\"phone\":{\"state\":\"ready\"}}")
        var clock = Date(timeIntervalSince1970: 2_000)
        let model = makeModel(fake, now: { clock })
        await model.refresh()
        fake.statusFailure = BackendError.timeout
        await model.refresh()
        clock = clock.addingTimeInterval(20)
        await model.refresh()
        XCTAssertTrue(model.statusUnavailable)
        await model.toggle()
        XCTAssertFalse(fake.calls.contains("startTunnel"))
        XCTAssertFalse(fake.calls.contains("stopTunnel"))
    }

    func testCleanupBlockedStatusIsStoppedButBlocksARestart() async throws {
        let fake = FakeBackend()
        fake.currentStatus = try decode("{\"running\":false,\"paired\":true,\"phone\":{\"state\":\"ready\"},\"cleanup_blocked\":true,\"error\":\"Route cleanup failed. Inspect routes before restarting.\"}")
        let model = makeModel(fake)
        await model.refresh()

        XCTAssertEqual(model.cleanupBlocked, true)
        XCTAssertTrue(model.recoveryBlocked)
        XCTAssertEqual(model.screen, .needsAttention(Strings.cleanupBlockedTitle))
        XCTAssertEqual(model.dashboard.title, Strings.cleanupBlockedTitle)
        XCTAssertEqual(model.dashboard.subtitle, Strings.cleanupBlockedBody)
        XCTAssertEqual(model.dashboard.action, .checkNow)
        XCTAssertEqual(model.screenModel.statusKind, .attention)
        XCTAssertEqual(model.screenModel.menuBar.actions.first { $0.kind == .turnOn }?.enabled, false)
        XCTAssertEqual(model.screenModel.menuBar.actions.first { $0.kind == .turnOff }?.enabled, false)

        await model.turnOn()
        XCTAssertFalse(fake.calls.contains("startTunnel"))
        await model.loadFailures()
        XCTAssertFalse(fake.calls.contains("failures"))
        let result = await model.forget()
        XCTAssertFalse(fake.calls.contains("forget"))
        XCTAssertEqual(result.message, Strings.cleanupBlockedBody)
    }

    func testForgetRefusesWhenFreshStatusBecomesUncertain() async throws {
        for body in ["{\"running\":false,\"state\":\"unknown\"}",
                     "{\"running\":false,\"cleanup_blocked\":true}"] {
            let fake = FakeBackend()
            fake.currentStatus = Status(running: false, paired: true, phone: Phone(state: "ready"))
            let model = makeModel(fake)
            await model.refresh()
            fake.currentStatus = try decode(body)
            let result = await model.forget()
            XCTAssertFalse(fake.calls.contains("forget"))
            XCTAssertNotEqual(result, .blockedByTunnel)
            XCTAssertTrue(model.recoveryBlocked)
        }
    }

    func testForgetRefusesWhenFreshStatusCannotBeRead() async {
        let fake = FakeBackend()
        fake.currentStatus = Status(running: false, paired: true, phone: Phone(state: "ready"))
        let model = makeModel(fake)
        await model.refresh()
        fake.statusFailure = BackendError.timeout
        let result = await model.forget()
        XCTAssertFalse(fake.calls.contains("forget"))
        XCTAssertEqual(result.message, Strings.statusUnavailableSubtitle)
    }

    func testForgetRequiresAnExplicitStoppedStatus() async throws {
        let fake = FakeBackend()
        fake.currentStatus = Status(running: false, paired: true, phone: Phone(state: "ready"))
        let model = makeModel(fake)
        await model.refresh()
        fake.currentStatus = try decode("{\"paired\":true}")
        let result = await model.forget()
        XCTAssertFalse(fake.calls.contains("forget"))
        XCTAssertEqual(result.message, Strings.statusUnavailableSubtitle)
    }

    func testForgetRetriesOneSupersededStatusRead() async {
        let backend = HeldStatusBackend()
        let model = makeModel(backend)
        let ready = Status(running: false, paired: true, phone: Phone(state: "ready"))
        let initial = Task { await model.refresh() }
        while backend.readCount < 1 { await Task.yield() }
        backend.complete(0, with: ready)
        await initial.value
        let forget = Task { await model.forget() }
        while backend.readCount < 2 { await Task.yield() }
        let refresh = Task { await model.refresh() }
        while backend.readCount < 3 { await Task.yield() }
        backend.complete(2, with: ready)
        await refresh.value
        backend.complete(1, with: ready)
        while backend.readCount < 4 { await Task.yield() }
        backend.complete(3, with: ready)
        // Successful Forget triggers its own final refresh.
        while backend.readCount < 5 { await Task.yield() }
        backend.complete(4, with: ready)
        _ = await forget.value
        XCTAssertTrue(backend.fake.calls.contains("forget"))
    }

    func testForgetDoesNotRetryPastAConcurrentRecoveryObservation() async throws {
        let backend = HeldStatusBackend()
        let model = makeModel(backend)
        let ready = Status(running: false, paired: true, phone: Phone(state: "ready"))
        let initial = Task { await model.refresh() }
        while backend.readCount < 1 { await Task.yield() }
        backend.complete(0, with: ready)
        await initial.value
        let forget = Task { await model.forget() }
        while backend.readCount < 2 { await Task.yield() }
        let refresh = Task { await model.refresh() }
        while backend.readCount < 3 { await Task.yield() }
        backend.complete(2, with: try decode(interruptedBody))
        await refresh.value
        backend.complete(1, with: ready)
        let result = await forget.value
        XCTAssertEqual(result.message, Strings.serviceStateUnknownBody)
        XCTAssertEqual(backend.readCount, 3)
        XCTAssertFalse(backend.fake.calls.contains("forget"))
    }

    func testForgetRefusesCancellationStartedDuringItsStatusRead() async {
        for fails in [false, true] {
            let backend = HeldStatusBackend()
            backend.holdCancel = true
            let model = makeModel(backend)
            let ready = Status(running: false, paired: true, phone: Phone(state: "ready"))
            let initial = Task { await model.refresh() }
            while backend.readCount < 1 { await Task.yield() }
            backend.complete(0, with: ready)
            await initial.value
            await model.beginPairing()
            let forget = Task { await model.forget() }
            while backend.readCount < 2 { await Task.yield() }
            let cancel = Task { await model.cancelPairing() }
            while !backend.cancelPending { await Task.yield() }
            backend.complete(1, with: ready)
            let result = await forget.value
            XCTAssertEqual(result.message, "Wait for the current action to finish.")
            XCTAssertFalse(backend.fake.calls.contains("forget"))
            backend.finishCancel(fail: fails)
            if !fails {
                while backend.readCount < 3 { await Task.yield() }
                backend.complete(2, with: ready)
            }
            await cancel.value
            XCTAssertEqual(model.pairingCancelRequested, fails)
        }
    }

    func testForgetWaitsForAnExistingPairingCancellation() async {
        let fake = FakeBackend()
        fake.currentStatus = Status(running: false, paired: true, phone: Phone(state: "ready"))
        let backend = SlowPairingBackend(fake: fake, startPairingDelay: 0, cancelPairingDelay: 300_000_000)
        let model = makeModel(backend)
        await model.refresh()
        await model.beginPairing()
        let cancel = Task { await model.cancelPairing() }
        while !model.pairingCancelInFlight { await Task.yield() }
        let result = await model.forget()
        XCTAssertEqual(result.message, "Wait for the current action to finish.")
        XCTAssertFalse(fake.calls.contains("forget"))
        await cancel.value
    }

    func testForgetRefusesAfterAnUnconfirmedPairingCancellation() async {
        let fake = FakeBackend()
        fake.currentStatus = Status(running: false, paired: true, phone: Phone(state: "ready"))
        let model = makeModel(fake)
        await model.refresh()
        await model.beginPairing()
        fake.failure = BackendError.timeout
        await model.cancelPairing()
        fake.failure = nil
        XCTAssertTrue(model.pairingCancelRequested)
        let result = await model.forget()
        XCTAssertEqual(result.message, "Wait for the current action to finish.")
        XCTAssertFalse(fake.calls.contains("forget"))
    }

    func testSuccessfulCancellationRetryAllowsForget() async {
        let fake = FakeBackend()
        fake.currentStatus = Status(running: false, paired: true, phone: Phone(state: "ready"))
        let model = makeModel(fake)
        await model.refresh()
        await model.beginPairing()
        fake.failure = BackendError.timeout
        await model.cancelPairing()
        XCTAssertTrue(model.pairingCancelRequested)
        _ = await model.forget()
        XCTAssertFalse(fake.calls.contains("forget"))

        fake.failure = nil
        await model.cancelPairing()
        XCTAssertFalse(model.pairingCancelRequested)
        _ = await model.forget()
        XCTAssertTrue(fake.calls.contains("forget"))
    }

    func testForgetKeepsFenceWhenItsOwnPairingCancellationFails() async {
        let fake = FakeBackend()
        fake.currentStatus = Status(running: false, paired: true, phone: Phone(state: "ready"))
        let backend = ScriptedPairingBackend(fake: fake, cancelErrors: [BackendError.timeout])
        let model = makeModel(backend)
        await model.refresh()
        await model.beginPairing()
        let result = await model.forget()
        XCTAssertEqual(result.message, "Canceling pairing.")
        XCTAssertTrue(model.pairingCancelRequested)
        XCTAssertFalse(fake.calls.contains("forget"))
        let second = await model.forget()
        XCTAssertEqual(second.message, "Wait for the current action to finish.")
        XCTAssertFalse(fake.calls.contains("forget"))
    }

    func testMissingRunningCannotConfirmAStopAfterAnError() async throws {
        let backend = HeldStatusBackend()
        let model = makeModel(backend)
        let initial = Task { await model.refresh() }
        while backend.readCount < 1 { await Task.yield() }
        backend.complete(0, with: Status(running: true, paired: true, phone: Phone(state: "connected")))
        await initial.value
        backend.stopError = BackendError.timeout
        let stop = Task { await model.turnOff() }
        while backend.readCount < 2 { await Task.yield() }
        backend.complete(1, with: try decode("{\"paired\":true}"))
        await stop.value
        XCTAssertEqual(model.dashboard.action, .retry)
        XCTAssertNil(model.status.running)
        XCTAssertEqual(model.dashboard.subtitle, BackendError.timeout.localizedDescription)
        XCTAssertNotEqual(model.dashboard.title, Strings.ready)
    }

    func testOlderNormalStatusCannotReplaceNewerUnknownStatus() async throws {
        let backend = HeldStatusBackend()
        let model = makeModel(backend)
        let first = Task { await model.refresh() }
        while backend.readCount < 1 { await Task.yield() }
        let second = Task { await model.refresh() }
        while backend.readCount < 2 { await Task.yield() }
        backend.complete(1, with: try decode(interruptedBody))
        await second.value
        backend.complete(0, with: Status(running: false, paired: true, phone: Phone(state: "ready")))
        await first.value
        XCTAssertEqual(model.status.engineHealth, .stateUnknown)
        XCTAssertEqual(model.dashboard.action, .checkNow)
        XCTAssertFalse(backend.fake.calls.contains("startPairing"))
    }

    func testOlderUnknownStatusInvalidatesANewerPendingNormalRead() async throws {
        let backend = HeldStatusBackend()
        let model = makeModel(backend)
        let first = Task { await model.refresh() }
        while backend.readCount < 1 { await Task.yield() }
        let second = Task { await model.refresh() }
        while backend.readCount < 2 { await Task.yield() }
        backend.complete(0, with: try decode(interruptedBody))
        await first.value
        backend.complete(1, with: Status(running: false, paired: true, phone: Phone(state: "ready")))
        await second.value
        XCTAssertEqual(model.status.engineHealth, .stateUnknown)
        XCTAssertEqual(model.dashboard.action, .checkNow)
    }

    func testOlderFailedReadDoesNotMakeANewerStatusStale() async {
        let backend = HeldStatusBackend()
        let model = makeModel(backend)
        let first = Task { await model.refresh() }
        while backend.readCount < 1 { await Task.yield() }
        let second = Task { await model.refresh() }
        while backend.readCount < 2 { await Task.yield() }
        backend.complete(1, with: Status(running: false, paired: true, phone: Phone(state: "ready")))
        await second.value
        backend.fail(0)
        await first.value
        XCTAssertEqual(model.screen, .ready)
        XCTAssertFalse(model.statusIsStale)
        XCTAssertFalse(model.statusUnavailable)
    }

    func testQuitDoesNotStopAnUnknownService() async throws {
        let fake = FakeBackend()
        fake.currentStatus = try decode(interruptedBody)
        let model = makeModel(fake)
        await model.stopForQuit()
        XCTAssertFalse(fake.calls.contains("stopTunnel"))
    }

    func testQuitRequiresAConfirmedStatusAfterSuccessfulStop() async throws {
        let backend = HeldStatusBackend()
        let quit = Task { await TunnelQuitCheck.stop(backend) }
        while backend.readCount < 1 { await Task.yield() }
        backend.complete(0, with: Status(running: true))
        while backend.readCount < 2 { await Task.yield() }
        backend.complete(1, with: try decode("{\"running\":false,\"state\":\"unknown\"}"))
        let result = await quit.value
        XCTAssertTrue(backend.fake.calls.contains("stopTunnel"))
        XCTAssertEqual(result, .uncertain(Strings.serviceStateUnknownBody))
    }

    func testStopAndForgetRefusesAnUncertainStopResult() async throws {
        let fake = FakeBackend()
        fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "connected"))
        let model = makeModel(fake)
        await model.refresh()
        fake.currentStatus = try decode("{\"running\":false,\"state\":\"unknown\"}")
        let result = await model.turnOffAndForget()
        XCTAssertTrue(fake.calls.contains("stopTunnel"))
        XCTAssertFalse(fake.calls.contains("forget"))
        XCTAssertEqual(result.message, Strings.serviceStateUnknownBody)
    }

    func testRecoveryStateTakesPrecedenceOverTokenRejection() {
        for health in [EngineHealth.stateUnknown, .cleanupBlocked] {
            let result = AppModel.derive(DeriveInput(tokenRejected: "old rejection", engineHealth: health))
            XCTAssertEqual(result.dashboard.action, .checkNow)
            XCTAssertNotEqual(result.dashboard.title, Strings.pairAgain)
        }
    }

    // MARK: - Notifications

    func testUnknownStatusSuppressesMisleadingNotificationsAndNormalStopsStillNotify() async throws {
        let fake = FakeBackend()
        fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "connected"))
        let sink = RecordingNotificationSink()
        sink.status = .authorized
        let model = makeModel(fake, sink: sink)
        await model.refreshNotificationAuthorization()
        await model.refresh()

        // A new hotspot stop arrives with the interrupted status. The status
        // cannot prove that a stop happened, so the app must stay quiet.
        fake.currentStatus = try decode("{\"running\":true,\"state\":\"unknown\",\"cleanup_blocked\":true,\"error\":\"The service state is unavailable after an interrupted operation. Inspect routes, devices, and the start record before restarting.\",\"last_stop\":{\"reason\":\"hotspot_lost\",\"at\":200},\"last_stop_message\":\"The hotspot turned off.\"}")
        await model.refresh()
        XCTAssertEqual(model.screen, .unknown)
        XCTAssertTrue(sink.messages.isEmpty)

        // The same old-format stop on a normal engine still notifies, so the
        // suppression is limited to the unknown state.
        fake.currentStatus = Status(running: false, paired: true, phone: Phone(state: "ready"), lastStop: LastStop(reason: "hotspot_lost", at: 200), lastStopMessage: "The hotspot turned off.")
        await model.refresh()
        XCTAssertEqual(sink.messages.map(\.kind), [.autoStopped])
        XCTAssertEqual(sink.messages.map(\.body), ["The hotspot turned off."])
    }

    // MARK: - Presentation

    func testUnknownPresentationNeverClaimsOnOrOff() {
        let input = PresentationInput(
            derive: DeriveInput(running: true, paired: true, phone: .connected, sourceDeviceWarning: true, engineHealth: .stateUnknown),
            pingLine: "Ping is on.",
            connectionsLabel: "The source device reports 3 active connections.",
            lastStopLine: "Last stop: The hotspot turned off.",
            lastCheckedText: "Checked just now",
            linkAdvice: [Strings.slowWiFi]
        )
        let model = ScreenPresentation.build(input)
        XCTAssertEqual(model.title, Strings.serviceStateUnknownTitle)
        XCTAssertEqual(model.subtitle, Strings.serviceStateUnknownBody)
        XCTAssertEqual(model.primaryAction, .checkNow)
        XCTAssertEqual(model.secondaryAction, nil)
        XCTAssertEqual(model.statusKind, .attention)
        XCTAssertTrue(model.sourceDevice.lines.isEmpty)
        XCTAssertTrue(model.connection.lines.isEmpty)
        XCTAssertTrue(model.attentionItems.contains(Strings.serviceStateUnknownHint))
        XCTAssertFalse(model.attentionItems.contains(Strings.sourceStoppedTitle))
        XCTAssertEqual(model.menuBar.icon, .attention)
        XCTAssertEqual(model.menuBar.statusLine, Strings.serviceStateUnknownTitle)
        for kind in [ScreenModel.MenuBarAction.Kind.turnOn, .turnOff, .pair] {
            let action = model.menuBar.actions.first { $0.kind == kind }
            XCTAssertEqual(action?.enabled, false, "\(kind)")
            XCTAssertEqual(action?.reason, Strings.serviceStateUnknownBody, "\(kind)")
        }

        // The dashboard cards do not fall back to Tunnel off or Not paired.
        let content = DashboardContent.build(model)
        XCTAssertEqual(content.sourceDevice.value, UIStrings.unknownValue)
        XCTAssertEqual(content.connection.value, UIStrings.unknownValue)
        XCTAssertNotEqual(content.sourceDevice.value, Strings.notPaired)
        XCTAssertNotEqual(content.connection.value, UIStrings.tunnelOff)
    }

    func testCleanupBlockedPresentationShowsOffButKeepsStartDisabled() {
        let input = PresentationInput(
            derive: DeriveInput(running: false, paired: true, phone: .ready, engineHealth: .cleanupBlocked),
            lastStopLine: "Last stop: Route cleanup failed."
        )
        let model = ScreenPresentation.build(input)
        XCTAssertEqual(model.title, Strings.cleanupBlockedTitle)
        XCTAssertEqual(model.subtitle, Strings.cleanupBlockedBody)
        XCTAssertEqual(model.primaryAction, .checkNow)
        XCTAssertEqual(model.statusKind, .attention)
        XCTAssertEqual(model.menuBar.actions.first { $0.kind == .turnOn }?.enabled, false)
        XCTAssertEqual(model.menuBar.actions.first { $0.kind == .turnOff }?.enabled, false)
        XCTAssertTrue(model.attentionItems.contains(Strings.cleanupBlockedHint))
        // The known stop record stays visible.
        XCTAssertTrue(model.connection.lines.contains("Last stop: Route cleanup failed."))
    }

    // MARK: - Diagnostics

    func testDiagnosticsReportNamesTheRecoveryState() {
        let unknown = DiagnosticsReport.text(
            diagnostics: nil,
            failures: nil,
            context: DiagnosticsContext(macOSVersion: "14.5", appVersion: "1.0", serviceState: .unknown, cleanupBlocked: true, now: Date(timeIntervalSince1970: 0))
        )
        XCTAssertTrue(unknown.contains("Service: unknown, cleanup blocked"), unknown)
        XCTAssertFalse(unknown.contains("Tunnel on"), unknown)

        let blocked = DiagnosticsReport.text(
            diagnostics: nil,
            failures: nil,
            context: DiagnosticsContext(macOSVersion: "14.5", appVersion: "1.0", cleanupBlocked: true, now: Date(timeIntervalSince1970: 0))
        )
        XCTAssertTrue(blocked.contains("Service: ready, cleanup blocked"), blocked)

        // A normal status keeps the old report shape.
        let normal = DiagnosticsReport.text(
            diagnostics: nil,
            failures: nil,
            context: DiagnosticsContext(macOSVersion: "14.5", appVersion: "1.0", now: Date(timeIntervalSince1970: 0))
        )
        XCTAssertFalse(normal.contains("Service:"), normal)
    }

    func testCopyDiagnosticsReportsUnknownWithoutInventingInterfaceOrPing() async throws {
        let fake = FakeBackend()
        fake.currentStatus = try decode(interruptedBody)
        let pasteboard = W6RecordingPasteboard()
        let model = makeModel(fake, pasteboard: pasteboard)
        await model.refresh()
        await model.copyDiagnostics()
        XCTAssertTrue(model.lastDiagnosticsText.contains("Service: unknown, cleanup blocked"))
        XCTAssertTrue(model.lastDiagnosticsText.contains("Ping: unknown"))
        XCTAssertFalse(model.lastDiagnosticsText.localizedCaseInsensitiveContains("Tunnel on"))
        XCTAssertFalse(fake.calls.contains("failures"))
        XCTAssertEqual(pasteboard.texts, [model.lastDiagnosticsText])
    }

    func testDiagnosticsTreatsAnUnprovenCleanupBlockAsUnknown() async throws {
        let fake = FakeBackend()
        fake.currentStatus = try decode("{\"cleanup_blocked\":true,\"last_stop\":{\"reason\":\"hotspot_lost\",\"at\":200},\"last_stop_message\":\"unproven stop\"}")
        let model = makeModel(fake)
        await model.refresh()
        await model.copyDiagnostics()
        XCTAssertTrue(model.lastDiagnosticsText.contains("Service: unknown, cleanup blocked"))
        XCTAssertTrue(model.lastDiagnosticsText.contains("Last stop: unknown"))
        XCTAssertFalse(model.lastDiagnosticsText.contains("unproven stop"))
        XCTAssertFalse(fake.calls.contains("failures"))
    }
}
