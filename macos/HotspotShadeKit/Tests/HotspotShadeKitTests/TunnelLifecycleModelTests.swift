import XCTest
@testable import HotspotShadeKit

private final class ModelCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0
    func increment() { lock.lock(); value += 1; lock.unlock() }
    var count: Int { lock.lock(); defer { lock.unlock() }; return value }
}

// Hermetic lifecycle tests that exercise the real router and AppModel together.
// They use fake engines and no route, device, tunnel, helper, or network.
@MainActor final class TunnelLifecycleModelTests: XCTestCase {
    private func status(running: Bool) -> Status {
        Status(running: running, paired: true, phone: Phone(state: running ? "connected" : "ready"))
    }

    private func makeModel(_ backend: BackendClient, forgetIntent: ForgetIntentStore = MemoryForgetIntent()) -> AppModel {
        AppModel(
            backend: backend,
            pingSetting: W6PingSetting(),
            pasteboard: NoPasteboard(),
            forgetIntent: forgetIntent,
            notificationSink: NoNotificationSink(),
            settingsOpener: NoSettingsOpener(),
            linkProvider: NoLinkInfoProvider(),
            macOSVersion: "14.5",
            appVersion: "1.0 (1)"
        )
    }

    private func makeRouter(
        user: FakeBackend,
        helper: @escaping @Sendable () async -> TunnelStopResult = { .stopped },
        prepare: @escaping @Sendable () async throws -> BackendClient
    ) -> TunnelRoutingBackend {
        TunnelRoutingBackend(
            user: user,
            prepareElevated: prepare,
            stopElevated: helper
        )
    }

    func testTurnOffAndForgetDoesNotSwallowAStopFailure() async {
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        let elevated = FakeBackend()
        elevated.currentStatus = status(running: true)
        let router = makeRouter(
            user: user,
            helper: { .uncertain("The helper did not confirm the stop.") },
            prepare: { elevated }
        )
        let model = makeModel(router)
        await model.refresh()
        await model.turnOn()
        XCTAssertEqual(model.screen, .on)
        elevated.failure = BackendError.response("The stop reply was lost.")
        let result = await model.turnOffAndForget()
        guard case .failed(let message) = result else {
            XCTFail("A stop failure must stay visible.")
            return
        }
        XCTAssertTrue(message.contains("did not confirm"))
        XCTAssertFalse(user.calls.contains("forget"))
        XCTAssertTrue(router.hasPendingStop)
        XCTAssertTrue(router.activeBackendIsElevated)
    }

    func testTurnOffAndForgetStopsThenForgetsThroughTheRouter() async {
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        let elevated = FakeBackend()
        elevated.currentStatus = status(running: true)
        elevated.stopClearsRunning = true
        let router = makeRouter(user: user, prepare: { elevated })
        let model = makeModel(router)
        await model.refresh()
        await model.turnOn()
        XCTAssertEqual(model.screen, .on)
        let result = await model.turnOffAndForget()
        XCTAssertEqual(result, .done(.confirmed))
        XCTAssertTrue(elevated.calls.contains("stopTunnel"))
        XCTAssertTrue(user.calls.contains("forget"))
        XCTAssertFalse(router.activeBackendIsElevated)
        XCTAssertFalse(router.hasPendingStop)
        XCTAssertEqual(model.screen, .unpaired)
    }

    func testForgetIsBlockedWhileCleanupIsUncertain() async {
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        let router = makeRouter(user: user, prepare: { FakeBackend() })
        router.recordUncertainStop("The helper did not confirm the stop.")
        let model = makeModel(router)
        await model.refresh()
        let result = await model.forget()
        guard case .failed(let message) = result else {
            XCTFail("A cleanup block must refuse Forget.")
            return
        }
        XCTAssertTrue(message.contains("did not confirm"))
        XCTAssertFalse(user.calls.contains("forget"))
        XCTAssertTrue(router.hasPendingStop)
    }

    func testPairingIsBlockedWhileAnElevatedEngineExists() async {
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        let elevated = FakeBackend()
        elevated.currentStatus = status(running: true)
        let router = makeRouter(user: user, prepare: { elevated })
        let model = makeModel(router)
        await model.refresh()
        await model.turnOn()
        await model.beginPairing()
        XCTAssertFalse(user.calls.contains("startPairing"))
        XCTAssertEqual(model.dashboard.subtitle, TunnelRoutingError.pairingBlockedByTunnel.localizedDescription)
        XCTAssertEqual(model.dashboard.action, .retry)
    }

    func testAnAutoStoppedElevatedEngineRestartsThroughTheModel() async {
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        let first = FakeBackend()
        first.currentStatus = status(running: true)
        let second = FakeBackend()
        second.currentStatus = status(running: true)
        let prepares = ModelCounter()
        let helperStops = ModelCounter()
        let router = TunnelRoutingBackend(
            user: user,
            prepareElevated: {
                prepares.increment()
                return prepares.count == 1 ? first : second
            },
            stopElevated: {
                helperStops.increment()
                return .stopped
            }
        )
        let model = makeModel(router)
        await model.refresh()
        await model.turnOn()
        XCTAssertEqual(model.screen, .on)
        // The tunnel stopped itself. The root engine is still alive.
        first.currentStatus = status(running: false)
        await model.refresh()
        XCTAssertEqual(model.screen, .ready)
        await model.turnOn()
        XCTAssertEqual(helperStops.count, 1)
        XCTAssertEqual(prepares.count, 2)
        XCTAssertEqual(first.startBodies.count, 1)
        XCTAssertEqual(second.startBodies.count, 1)
        XCTAssertEqual(model.screen, .on)
    }

    func testADelayedStopCompletesBeforeForget() async {
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        let elevated = FakeBackend()
        elevated.currentStatus = status(running: true)
        elevated.stopClearsRunning = true
        let router = makeRouter(user: user, prepare: { elevated })
        let model = makeModel(router)
        await model.refresh()
        await model.turnOn()
        elevated.operationDelay = 150_000_000
        let result = await model.turnOffAndForget()
        XCTAssertEqual(result, .done(.confirmed))
        XCTAssertTrue(user.calls.contains("forget"))
        XCTAssertFalse(router.activeBackendIsElevated)
    }

    func testAnAutoStoppedElevatedEngineStillCountsAsAnUnresolvedLifecycle() async {
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        let elevated = FakeBackend()
        elevated.currentStatus = status(running: true)
        elevated.stopClearsRunning = true
        let router = makeRouter(user: user, prepare: { elevated })
        let model = makeModel(router)
        await model.refresh()
        await model.turnOn()
        XCTAssertTrue(model.hasUnresolvedTunnelLifecycle)
        // The tunnel stopped itself but the elevated engine still exists.
        elevated.currentStatus = status(running: false)
        await model.refresh()
        XCTAssertEqual(model.status.running, false)
        XCTAssertTrue(model.hasUnresolvedTunnelLifecycle)
        // A confirmed stop clears the elevated session and resolves the
        // lifecycle even though the last status was already running false.
        try? await router.stopTunnel(timeout: 1)
        await model.refresh()
        XCTAssertFalse(model.hasUnresolvedTunnelLifecycle)
    }

    func testAnUncertainStopIsNotClearedByARunningFalseStatus() async {
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        let elevated = FakeBackend()
        elevated.currentStatus = status(running: true)
        elevated.stopClearsRunning = true
        let router = makeRouter(
            user: user,
            helper: { .uncertain("The helper did not confirm the stop.") },
            prepare: { elevated }
        )
        let model = makeModel(router)
        await model.refresh()
        await model.turnOn()
        // The engine removes its own routes and reports off while the helper
        // still cannot confirm the process stop.
        elevated.currentStatus = status(running: false)
        await model.refresh()
        XCTAssertEqual(model.status.running, false)
        await model.turnOff()
        let message = model.dashboard.subtitle
        XCTAssertTrue(message.contains("did not confirm"))
        XCTAssertEqual(model.dashboard.action, .retry)
        XCTAssertNotEqual(model.screen, .ready)
    }

    func testTurnOffAndForgetRetriesAPendingStopBeforeForget() async {
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        let router = makeRouter(user: user, prepare: { FakeBackend() })
        router.recordUncertainStop("The helper did not confirm the stop.")
        let model = makeModel(router)
        await model.refresh()
        XCTAssertEqual(model.status.running, false)
        XCTAssertTrue(model.hasUnresolvedTunnelLifecycle)
        let result = await model.turnOffAndForget()
        XCTAssertEqual(result, .done(.confirmed))
        XCTAssertTrue(user.calls.contains("forget"))
        XCTAssertFalse(router.hasPendingStop)
    }
}
