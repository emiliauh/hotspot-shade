import XCTest
@testable import HotspotShadeKit

// Hold one async step until the test releases it. The test waits for the step
// to be entered, so no sleep is used as synchronization.
private actor FollowUpGate {
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

private final class FollowUpCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0
    func increment() -> Int { lock.lock(); defer { lock.unlock() }; value += 1; return value }
}

// Hermetic tests for the second lifecycle review: Stay after an early quit,
// a start that survives a model rebuild, and the stop flight end. They use
// fake engines and in-memory state. They create no helper connection, root
// engine, prompt, route, or device.
@MainActor final class TunnelLifecycleFollowUpTests: XCTestCase {
    private func makeModel(_ backend: BackendClient, gate: AppActionGate? = nil) -> AppModel {
        AppModel(
            backend: backend,
            isQuitting: { gate?.isQuitting ?? false },
            actionGate: gate,
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

    // MARK: - Stay after an early quit

    // A quit that returns early because a tunnel start did not settle leaves
    // the user engine and the model alive. The quit cancelled the user engine
    // monitor, so Stay must resume the monitor as well as the poll.
    func testStayAfterAnEarlyQuitResumesThePollAndTheUserEngineMonitor() {
        let mark = TunnelCleanupPending(token: 1, message: EngineLaunchText.stopUnverified, kind: .retryable)
        let restored = EngineLaunchState.afterCancelledQuit(
            previous: .running,
            outcome: .uncertain(EngineLaunchText.stopUnverified),
            pendingCleanup: mark
        )
        XCTAssertEqual(
            QuitStayPlan.after(engineAlive: true, modelAlive: true, pendingCleanup: mark, restored: restored),
            .resume(monitorEngine: true)
        )
        // The same holds without a mark, for example after a cleanup retry
        // that settled in time but a tunnel action that did not.
        XCTAssertEqual(
            QuitStayPlan.after(engineAlive: true, modelAlive: true, pendingCleanup: nil, restored: .running),
            .resume(monitorEngine: true)
        )
        // A model without an engine has nothing to monitor.
        XCTAssertEqual(
            QuitStayPlan.after(engineAlive: false, modelAlive: true, pendingCleanup: nil, restored: .running),
            .resume(monitorEngine: false)
        )
    }

    // A full quit stopped the user engine. Stay starts it again only when no
    // cleanup is pending; a pending stop keeps the Retry cleanup screen.
    func testStayAfterAFullQuitStartsTheUserEngineOnlyWithoutAPendingStop() {
        XCTAssertEqual(
            QuitStayPlan.after(engineAlive: false, modelAlive: false, pendingCleanup: nil, restored: .running),
            .startUserEngine
        )
        XCTAssertEqual(
            QuitStayPlan.after(engineAlive: false, modelAlive: false, pendingCleanup: nil, restored: .waiting),
            .startUserEngine
        )
        let mark = TunnelCleanupPending(token: 2, message: "The helper did not answer.", kind: .retryable)
        let restored = EngineLaunchState.afterCancelledQuit(
            previous: .running,
            outcome: .uncertain("The helper did not answer."),
            pendingCleanup: mark
        )
        XCTAssertEqual(
            QuitStayPlan.after(engineAlive: false, modelAlive: false, pendingCleanup: mark, restored: restored),
            .none
        )
        let failure = EngineLaunchFailure.fromUserEngine(BackendError.timeout)
        XCTAssertEqual(
            QuitStayPlan.after(engineAlive: false, modelAlive: false, pendingCleanup: nil, restored: .failed(failure)),
            .none
        )
    }

    // MARK: - A start that survives a rebuild

    // A start is in flight before the session stores any process handle. The
    // user engine dies and the app rebuilds the model and the router. The new
    // ones must still see that start: Pair, a pairing handoff, and Forget are
    // refused, the lifecycle is unresolved, and a quit waits. Once the start
    // settles, Pair and Forget work again.
    func testARebuiltModelAndRouterRefusePairAndForgetUntilAHeldStartSettles() async throws {
        let firstUser = FakeBackend()
        firstUser.currentStatus = Status(running: false, paired: true, phone: Phone(state: "ready"))
        let session = RealTunnelSession(
            user: firstUser,
            handoffDescriptor: { -1 },
            isQuitting: { false },
            stopBeforeStart: { .stopped },
            makeProcess: { throw HelperTrustError.helperUnavailable }
        )
        let hold = FollowUpGate()
        let firstRouter = session.makeRouter(user: firstUser, authorizeStart: {
            await hold.hold()
            throw TunnelAuthorizationFailure(message: "The administrator authorization was cancelled.")
        })
        let firstModel = makeModel(firstRouter)
        await firstModel.refresh()
        let start = Task { try await firstRouter.startTunnel(experimentalICMP: false) }
        await hold.waitUntilHeld()
        XCTAssertTrue(firstModel.hasUnresolvedTunnelLifecycle)
        // No process handle exists yet, so neither mark shows this start.
        XCTAssertFalse(session.hasElevatedSession)
        XCTAssertNil(session.cleanup.pending)

        // The rebuild after a lost user engine: a new user engine, router, and
        // model around the same session.
        let user = FakeBackend()
        user.currentStatus = Status(running: false, paired: true, phone: Phone(state: "ready"))
        session.updateUser(user)
        let router = session.makeRouter(user: user)
        let model = makeModel(router)
        await model.refresh()

        XCTAssertTrue(router.hasStartInFlight)
        XCTAssertTrue(model.hasUnresolvedTunnelLifecycle)
        XCTAssertTrue(model.tunnelActionIsInFlight)
        let settled = await model.waitForTunnelActionToSettle(within: 0.1)
        XCTAssertFalse(settled, "A quit must wait for the start, not skip it.")

        await model.beginPairing()
        XCTAssertFalse(model.isPairing)
        let forget = await model.forget()
        XCTAssertEqual(forget, .failed(AppModelActionText.waitForAction))
        do {
            try await router.startPairing()
            XCTFail("Pairing must wait for the start.")
        } catch {
            XCTAssertEqual(error as? TunnelRoutingError, .pairingBlockedByTunnel)
        }
        do {
            try await router.pairHandoff()
            XCTFail("A pairing handoff must wait for the start.")
        } catch {
            XCTAssertEqual(error as? TunnelRoutingError, .pairingBlockedByTunnel)
        }
        do {
            _ = try await router.forget()
            XCTFail("Forget must wait for the start.")
        } catch {
            if case BackendError.forgetBlockedByTunnel = error {} else {
                XCTFail("Expected the tunnel forget refusal, got \(error).")
            }
        }
        // A second start from the rebuilt router is refused too.
        do {
            try await router.startTunnel(experimentalICMP: false)
            XCTFail("A second start must wait for the first.")
        } catch {
            XCTAssertEqual(error as? TunnelRoutingError, .startAlreadyInProgress)
        }
        XCTAssertFalse(user.calls.contains("startPairing"))
        XCTAssertFalse(user.calls.contains("pairHandoff"))
        XCTAssertFalse(user.calls.contains("forget"))

        // The held start settles without a root engine.
        await hold.release()
        do {
            try await start.value
            XCTFail("The fake authorizer refuses the start.")
        } catch {}
        XCTAssertFalse(router.hasStartInFlight)
        XCTAssertFalse(model.hasUnresolvedTunnelLifecycle)
        let settledNow = await model.waitForTunnelActionToSettle(within: 0.1)
        XCTAssertTrue(settledNow)

        try await router.startPairing()
        XCTAssertTrue(user.calls.contains("startPairing"))
        try await router.cancelPairing()
        _ = try await router.forget()
        XCTAssertTrue(user.calls.contains("forget"))
    }

    // MARK: - Stop flight end

    // A caller that arrives after the stop finished starts a new stop. It
    // must not read the old result while the first caller is still resuming.
    func testAStopFlightEndsBeforeItsResultIsAvailable() async throws {
        // Hold the first caller after its result arrives, as a slow resume
        // would. Only the first caller is held.
        let resume = FollowUpGate()
        let held = FollowUpCounter()
        let flight = TunnelStopFlight(afterFirstResult: {
            if held.increment() == 1 { await resume.hold() }
        })
        let first = Task {
            await flight.run { .uncertain("The first stop was not confirmed.") }
        }
        await resume.waitUntilHeld()
        // The first stop finished; its caller has not resumed yet.
        let stillActive = await flight.isActive()
        XCTAssertFalse(stillActive, "The flight must end before its result is available.")
        // A caller that arrives now asks for a new stop and gets its result,
        // not the finished stop's old answer.
        let late = await flight.run { .stopped }
        XCTAssertEqual(late, .stopped)
        await resume.release()
        let firstResult = await first.value
        XCTAssertEqual(firstResult, .uncertain("The first stop was not confirmed."))
    }

    // Callers that join while the stop runs still share one result.
    func testConcurrentStopCallersStillShareOneFlight() async {
        let flight = TunnelStopFlight()
        let hold = FollowUpGate()
        let first = Task {
            await flight.run {
                await hold.hold()
                return .uncertain("The helper did not answer.")
            }
        }
        await hold.waitUntilHeld()
        let second = Task { await flight.run { .stopped } }
        while await flight.waiterCount() == 0 { await Task.yield() }
        await hold.release()
        let firstResult = await first.value
        let secondResult = await second.value
        XCTAssertEqual(firstResult, .uncertain("The helper did not answer."))
        XCTAssertEqual(secondResult, .uncertain("The helper did not answer."))
    }
}
