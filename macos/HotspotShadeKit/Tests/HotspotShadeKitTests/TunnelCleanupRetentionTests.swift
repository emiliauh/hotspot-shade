import XCTest
@testable import HotspotShadeKit

// Hermetic lifecycle tests for the app-owned cleanup state. They use fake
// engines and no helper, route, device, or network.
@MainActor final class TunnelCleanupRetentionTests: XCTestCase {
    private func status(running: Bool) -> Status {
        Status(running: running, paired: true, phone: Phone(state: running ? "connected" : "ready"))
    }

    private func makeModel(_ backend: BackendClient) -> AppModel {
        AppModel(
            backend: backend,
            pingSetting: W6PingSetting(),
            pasteboard: NoPasteboard(),
            forgetIntent: MemoryForgetIntent(),
            notificationSink: NoNotificationSink(),
            settingsOpener: NoSettingsOpener(),
            linkProvider: NoLinkInfoProvider(),
            macOSVersion: "14.5",
            appVersion: "1.0 (1)"
        )
    }

    private func makeRouter(
        user: FakeBackend,
        elevated: FakeBackend? = nil,
        helper: @escaping @Sendable () async -> TunnelStopResult = { .stopped },
        prepare: @escaping @Sendable () async throws -> BackendClient,
        existing: @escaping @Sendable () -> BackendClient? = { nil },
        authorize: @escaping @Sendable () async throws -> Void = {},
        cleanup: TunnelCleanupState
    ) -> TunnelRoutingBackend {
        TunnelRoutingBackend(
            user: user,
            prepareElevated: prepare,
            stopElevated: helper,
            authorizeStart: authorize,
            existingElevated: existing,
            cleanup: cleanup
        )
    }

    // Finding 1: a retry rebuilds the model. The new router must still see the
    // old pending stop and the live elevated session.
    func testARebuiltRouterRetainsAnUncertainStopAndTheElevatedSession() async throws {
        let cleanup = TunnelCleanupState()
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        let elevated = FakeBackend()
        elevated.currentStatus = status(running: true)
        let prepares = RetentionCounter()

        let first = makeRouter(
            user: user,
            elevated: elevated,
            helper: { .uncertain("The helper did not confirm the stop.") },
            prepare: {
                prepares.increment()
                return elevated
            },
            cleanup: cleanup
        )
        try await first.startTunnel(experimentalICMP: false)
        do {
            try await first.stopTunnel(timeout: 1)
            XCTFail("The uncertain stop must fail.")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("did not confirm"))
        }
        XCTAssertTrue(cleanup.hasPendingStop)
        XCTAssertTrue(cleanup.hasElevatedSession)

        // The user engine restarted and the app built a new router with the
        // same app-owned cleanup state. It can still reach the session's
        // elevated backend.
        let second = makeRouter(
            user: user,
            elevated: elevated,
            prepare: {
                prepares.increment()
                return elevated
            },
            existing: { elevated },
            cleanup: cleanup
        )
        XCTAssertTrue(second.hasPendingStop)
        XCTAssertTrue(second.activeBackendIsElevated)
        do {
            try await second.startTunnel(experimentalICMP: false)
            XCTFail("A rebuilt router must refuse a start after an uncertain stop.")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("did not confirm"))
        }
        do {
            try await second.startPairing()
            XCTFail("A rebuilt router must refuse pairing after an uncertain stop.")
        } catch {}
        do {
            _ = try await second.forget()
            XCTFail("A rebuilt router must refuse forget after an uncertain stop.")
        } catch {}
        XCTAssertEqual(prepares.count, 1, "Neither rebuilt start reached the authorizer.")
        XCTAssertFalse(user.calls.contains("startPairing"))
        XCTAssertFalse(user.calls.contains("forget"))
    }

    // Finding 1: the rebuilt model must not show a clean On or Off and must
    // keep pairing and turn-on disabled while the stop is unconfirmed.
    func testARebuiltModelKeepsThePendingStopVisibleAndBlocksCleanActions() async {
        let cleanup = TunnelCleanupState()
        cleanup.recordPendingStop("The helper did not confirm the stop.")
        cleanup.retainElevatedSession()
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        let elevated = FakeBackend()
        elevated.currentStatus = status(running: false)
        let existing = RetentionBox<BackendClient>(elevated)
        let router = makeRouter(
            user: user,
            elevated: elevated,
            helper: {
                // The real session clears its elevated backend after a
                // confirmed helper stop.
                existing.value = nil
                return .stopped
            },
            prepare: { elevated },
            existing: { existing.value },
            cleanup: cleanup
        )
        let model = makeModel(router)
        await model.refresh()
        XCTAssertTrue(model.hasUnresolvedTunnelLifecycle)
        XCTAssertTrue(model.hasPendingCleanup)
        XCTAssertEqual(model.dashboard.title, Strings.cleanupBlockedTitle)
        XCTAssertTrue(model.dashboard.subtitle.contains("did not confirm"))
        XCTAssertNotEqual(model.screen, .ready)
        XCTAssertNotEqual(model.screen, .on)
        XCTAssertEqual(model.screenModel.menuBar.actions.first { $0.kind == .turnOn }?.enabled, false)
        XCTAssertEqual(model.screenModel.menuBar.actions.first { $0.kind == .pair }?.enabled, false)
        XCTAssertNil(model.screenModel.secondaryAction)
        let result = await model.forget()
        XCTAssertNotEqual(result, .done(.confirmed))
        XCTAssertFalse(user.calls.contains("forget"))
        // The dashboard Try again action is the same cleanup retry.
        await model.perform(.retry)
        XCTAssertFalse(cleanup.hasPendingStop)
        XCTAssertTrue(elevated.calls.contains("stopTunnel"))
    }

    // Finding 1: a retained elevated session with no reachable backend is not
    // a clean Off, even without an explicit pending stop message.
    func testARetainedElevatedSessionWithoutABackendIsNotShownAsCleanOff() async {
        let cleanup = TunnelCleanupState()
        cleanup.retainElevatedSession()
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        let router = makeRouter(
            user: user,
            prepare: { FakeBackend() },
            cleanup: cleanup
        )
        let model = makeModel(router)
        await model.refresh()
        XCTAssertEqual(model.pendingCleanupMessage, EngineLaunchText.elevatedSessionOpen)
        XCTAssertNotEqual(model.screen, .ready)
        XCTAssertEqual(model.screenModel.menuBar.actions.first { $0.kind == .turnOn }?.enabled, false)
        XCTAssertTrue(model.hasUnresolvedTunnelLifecycle)
    }

    // Finding 1: Stay must not restore a clean running screen when the
    // app-owned cleanup state still has a pending stop.
    func testStayKeepsACleanupRetryWhenTheStopIsStillPending() {
        let pending = TunnelCleanupPending(
            token: 1,
            message: "The helper did not confirm the stop.",
            kind: .retryable
        )
        let restored = EngineLaunchState.afterCancelledQuit(
            previous: .running,
            outcome: .stopped,
            pendingCleanup: pending
        )
        guard case .lost(let failure) = restored else {
            return XCTFail("A pending stop must keep the lost screen.")
        }
        XCTAssertEqual(failure.kind, .cleanup)
        XCTAssertTrue(failure.message.contains("did not confirm"))
        XCTAssertEqual(failure.recovery, EngineLaunchText.quitRecovery)
    }

    // Finding 2: a pending stop with no elevated process still has a
    // user-reachable retry. A confirmed helper snapshot clears it.
    func testAPendingStopWithoutAProcessIsConfirmedByAHelperRetry() async {
        let cleanup = TunnelCleanupState()
        cleanup.recordPendingStop("The helper did not confirm the stop.")
        cleanup.retainElevatedSession()
        let confirmations = RetentionCounter()
        let session = RealTunnelSession(
            user: FakeBackend(),
            handoffDescriptor: { 12 },
            isQuitting: { false },
            cleanup: cleanup,
            confirmation: {
                confirmations.increment()
                return .stopped
            }
        )
        let outcome = await session.stopElevated()
        XCTAssertEqual(outcome, .stopped)
        XCTAssertEqual(confirmations.count, 1)
        XCTAssertFalse(cleanup.hasPendingStop)
        XCTAssertFalse(cleanup.hasElevatedSession)
    }

    func testAPendingStopWithoutAProcessStaysLatchedWhenTheRetryIsNotConfirmed() async {
        let cleanup = TunnelCleanupState()
        cleanup.recordPendingStop("The helper did not confirm the stop.")
        let session = RealTunnelSession(
            user: FakeBackend(),
            handoffDescriptor: { 12 },
            isQuitting: { false },
            cleanup: cleanup,
            confirmation: { .uncertain("The helper is still stopping another session.") }
        )
        let outcome = await session.stopElevated()
        guard case .uncertain(let message) = outcome else {
            return XCTFail("An unconfirmed helper snapshot must stay uncertain.")
        }
        XCTAssertEqual(message, "The helper is still stopping another session.")
        XCTAssertTrue(cleanup.hasPendingStop)
    }

    // Finding 3: a dead user engine must not turn a confirmed helper stop into
    // a cleanup failure. The user engine never owns routes.
    func testADeadUserEngineDoesNotOverrideAConfirmedHelperStop() async {
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        user.failure = BackendError.timeout
        let router = makeRouter(
            user: user,
            helper: { .stopped },
            prepare: { FakeBackend() },
            cleanup: TunnelCleanupState()
        )
        let outcome = await router.stopForQuit()
        XCTAssertNil(outcome)
        XCTAssertFalse(router.hasPendingStop)
    }

    func testADeadUserEngineDoesNotBlockClearingAnEarlierPendingStop() async {
        let cleanup = TunnelCleanupState()
        cleanup.recordPendingStop("The helper did not confirm the stop.")
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        user.failure = BackendError.timeout
        let router = makeRouter(
            user: user,
            helper: { .stopped },
            prepare: { FakeBackend() },
            cleanup: cleanup
        )
        let outcome = await router.stopForQuit()
        XCTAssertNil(outcome)
        XCTAssertFalse(cleanup.hasPendingStop)
    }

    // An elevated engine's lost stop reply is route cleanup evidence that was
    // not observed. A confirmed helper process stop does not replace it.
    func testALostElevatedStopReplyStaysUncertainEvenAfterAConfirmedHelperStop() async {
        let elevated = FakeBackend()
        elevated.currentStatus = status(running: true)
        let cleanup = TunnelCleanupState()
        let router = makeRouter(
            user: FakeBackend(),
            elevated: elevated,
            helper: { .stopped },
            prepare: { elevated },
            cleanup: cleanup
        )
        try? await router.startTunnel(experimentalICMP: false)
        elevated.failure = BackendError.response("The stop reply was lost.")
        let outcome = await router.stopForQuit()
        XCTAssertTrue(outcome?.contains("stop reply was lost") == true)
        XCTAssertTrue(cleanup.hasPendingStop)
    }

    // Finding 1: a pending stop is refused before the app changes pairing or
    // trust intent, not only at the router.
    func testPendingCleanupDoesNotClearTheForgetIntentOrAskTheEngine() async {
        let cleanup = TunnelCleanupState()
        cleanup.recordPendingStop("The helper did not confirm the stop.")
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        let router = makeRouter(
            user: user,
            prepare: { FakeBackend() },
            cleanup: cleanup
        )
        let intent = MemoryForgetIntent()
        intent.forgotIntent = true
        let model = AppModel(
            backend: router,
            pingSetting: W6PingSetting(),
            pasteboard: NoPasteboard(),
            forgetIntent: intent,
            notificationSink: NoNotificationSink(),
            settingsOpener: NoSettingsOpener(),
            linkProvider: NoLinkInfoProvider(),
            macOSVersion: "14.5",
            appVersion: "1.0 (1)"
        )
        await model.refresh()
        await model.beginPairing()
        XCTAssertTrue(intent.forgotIntent, "An unconfirmed stop must not clear the forget intent.")
        await model.turnOn()
        XCTAssertFalse(user.calls.contains("startTunnel"))
        XCTAssertFalse(user.calls.contains("startPairing"))
        XCTAssertTrue(model.dashboard.subtitle.contains("did not confirm"))
    }

    // Finding 2: the diagnostics report names the app-owned pending cleanup
    // even though the status answer has no field for it.
    func testDiagnosticsNamePendingCleanup() async {
        let cleanup = TunnelCleanupState()
        cleanup.recordPendingStop("The helper did not confirm the stop.")
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        let router = makeRouter(
            user: user,
            prepare: { FakeBackend() },
            cleanup: cleanup
        )
        let model = makeModel(router)
        await model.refresh()
        await model.copyDiagnostics()
        XCTAssertTrue(model.lastDiagnosticsText.contains("Cleanup: The helper did not confirm the stop."))
        XCTAssertFalse(model.lastDiagnosticsText.lowercased().contains("token"))
    }

    // Finding 4: a quit waits for an in-flight tunnel action. A slow start is
    // observed as still running and is not overtaken by a clean claim.
    func testQuitWaitReportsAnInFlightStartAndCompletesAfterward() async {
        let fake = FakeBackend()
        fake.currentStatus = status(running: false)
        fake.operationDelay = 250_000_000
        let model = makeModel(fake)
        await model.refresh()
        let start = Task { await model.turnOn() }
        while !model.tunnelActionIsInFlight {
            await Task.yield()
        }
        let settledEarly = await model.waitForTunnelActionToSettle(within: 0.02)
        XCTAssertFalse(settledEarly)
        await start.value
        let settled = await model.waitForTunnelActionToSettle(within: 2)
        XCTAssertTrue(settled)
    }

    // Finding 4: a start generation that a quit aborts stays aborted even when
    // a later Stay clears the quit flag.
    func testAnAbortedStartCannotProceedAfterStay() {
        let fence = TunnelStartFence()
        let token = fence.current()
        XCTAssertTrue(fence.permits(token))
        fence.abortPendingStarts()
        XCTAssertFalse(fence.permits(token), "Stay must not revive the old start.")
        let next = fence.current()
        XCTAssertTrue(fence.permits(next), "A new start after Stay is allowed.")
    }

    // Finding 4: a confirmed stop clears only the exact mark it observed. A
    // newer mark with the same text stays.
    func testAConfirmedStopDoesNotClearANewerPendingMessage() {
        let cleanup = TunnelCleanupState()
        let first = cleanup.recordPendingStop("The first stop was not confirmed.")
        XCTAssertFalse(cleanup.clearPendingStop(ifToken: first &+ 1))
        XCTAssertEqual(cleanup.pendingMessage, "The first stop was not confirmed.")
        let second = cleanup.recordPendingStop("The first stop was not confirmed.")
        XCTAssertFalse(cleanup.clearPendingStop(ifToken: first), "The same text must not identify the newer mark.")
        XCTAssertEqual(cleanup.pendingMessage, "The first stop was not confirmed.")
        XCTAssertTrue(cleanup.clearPendingStop(ifToken: second))
        XCTAssertNil(cleanup.pendingMessage)
    }

    // Finding 4: an aborted start does not reach the pairing handoff, the
    // administrator prompt, or the root engine start.
    func testAnAbortedSessionStartStopsBeforeTheHandoff() async {
        let user = FakeBackend()
        let handoffs = RetentionCounter()
        let authorization = CleanupUnreachedAuthorization()
        let gate = CleanupRetryGate()
        let session = RealTunnelSession(
            user: user,
            handoffDescriptor: {
                handoffs.increment()
                return 12
            },
            isQuitting: { false },
            authorization: authorization,
            stopBeforeStart: {
                await gate.hold()
                return .stopped
            }
        )
        let start = Task { try await session.authorizeTunnelStart() }
        await gate.waitUntilHeld()
        session.abortPendingStarts()
        await gate.release()
        do {
            try await start.value
            XCTFail("The aborted start must fail.")
        } catch {
            XCTAssertTrue(error.localizedDescription.lowercased().contains("cancel"))
        }
        XCTAssertEqual(handoffs.count, 0)
        XCTAssertEqual(authorization.calls, 0)
        XCTAssertFalse(user.calls.contains("pairHandoff"))
    }
}

// A gate for the prior-stop step in RealTunnelSession.
actor CleanupRetryGate {
    private var entered = false
    private var enteredWaiter: CheckedContinuation<Void, Never>?
    private var releaseWaiter: CheckedContinuation<Void, Never>?

    func hold() async {
        entered = true
        enteredWaiter?.resume()
        enteredWaiter = nil
        await withCheckedContinuation { releaseWaiter = $0 }
    }

    func waitUntilHeld() async {
        if entered { return }
        await withCheckedContinuation { enteredWaiter = $0 }
    }

    func release() {
        releaseWaiter?.resume()
        releaseWaiter = nil
    }
}

final class RetentionCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0
    func increment() { lock.lock(); value += 1; lock.unlock() }
    var count: Int { lock.lock(); defer { lock.unlock() }; return value }
}

final class RetentionBox<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: Value?
    init(_ value: Value?) { stored = value }
    var value: Value? {
        get { lock.lock(); defer { lock.unlock() }; return stored }
        set { lock.lock(); stored = newValue; lock.unlock() }
    }
}

// A prompt that must never run. The count proves the authorization step was
// not reached.
final class CleanupUnreachedAuthorization: HelperStartAuthorizationProviding, @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0
    func beginStartAuthorization() throws -> HelperStartAuthorizationLease {
        lock.lock()
        value += 1
        lock.unlock()
        throw HelperTrustError.notAuthorized
    }
    var calls: Int {
        lock.lock(); defer { lock.unlock() }
        return value
    }
}
