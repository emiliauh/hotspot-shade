import XCTest
@testable import HotspotShadeKit

private final class RaceCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0
    @discardableResult
    func increment() -> Int { lock.lock(); defer { lock.unlock() }; value += 1; return value }
    var count: Int { lock.lock(); defer { lock.unlock() }; return value }
}

// Hold one async step until the test releases it. The test waits for the
// step to be entered, so no sleep is used as synchronization.
private actor RaceGate {
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

// A prompt that must never be shown. The count proves that no administrator
// authorization was requested.
private final class CountingStartAuthorization: HelperStartAuthorizationProviding, @unchecked Sendable {
    let calls = RaceCounter()
    func beginStartAuthorization() throws -> HelperStartAuthorizationLease {
        calls.increment()
        throw HelperTrustError.notAuthorized
    }
}

private final class RouterBox: @unchecked Sendable {
    var router: TunnelRoutingBackend?
}

// Hermetic tests for the quit, Stay, stop, and cleanup races in the macOS
// target app. They use fake engines, fake helper answers, and in-memory state.
// They create no helper connection, root engine, prompt, route, or device.
@MainActor final class TunnelQuitRaceTests: XCTestCase {
    private func status(running: Bool) -> Status {
        Status(running: running, paired: true, phone: Phone(state: running ? "connected" : "ready"))
    }

    private func makeModel(_ backend: BackendClient, gate: AppActionGate) -> AppModel {
        AppModel(
            backend: backend,
            isQuitting: { gate.isQuitting },
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

    // A session whose root engine factory and prompt only count. Any call to
    // either one is a failure of the no-authorization-at-open rule.
    private func countingSession(
        user: FakeBackend,
        gate: AppActionGate,
        processes: RaceCounter,
        authorization: CountingStartAuthorization,
        handoffs: RaceCounter = RaceCounter(),
        descriptor: Int32 = -1
    ) -> RealTunnelSession {
        RealTunnelSession(
            user: user,
            handoffDescriptor: {
                handoffs.increment()
                return descriptor
            },
            isQuitting: { gate.isQuitting },
            actionGate: gate,
            authorization: authorization,
            stopBeforeStart: { .stopped },
            makeProcess: {
                processes.increment()
                throw HelperTrustError.helperUnavailable
            }
        )
    }

    // MARK: - Opening the app in real mode

    // The app builds the tunnel session and its router when the user engine
    // reports its port. Building them and using the dashboard, pairing,
    // settings, status, logs, failures, and diagnostics must not reach the
    // protected helper, start a root engine, or ask for authorization.
    func testOpeningTheRealWiringUsesOnlyTheUserEngine() async {
        let gate = AppActionGate()
        let user = FakeBackend()
        user.currentStatus = Status(running: false, paired: false, phone: Phone(state: "unpaired"))
        let processes = RaceCounter()
        let authorization = CountingStartAuthorization()
        let handoffs = RaceCounter()
        let session = countingSession(
            user: user,
            gate: gate,
            processes: processes,
            authorization: authorization,
            handoffs: handoffs
        )
        let router = session.makeRouter(user: user)
        let model = makeModel(router, gate: gate)

        await model.refresh()
        await model.beginPairing()
        await model.cancelPairing()
        await model.checkNow()
        model.setLetPingWork(true)
        await model.loadLogs()
        await model.loadFailures()
        await model.copyDiagnostics()
        await model.refresh()

        // Every request went to the user engine.
        XCTAssertTrue(user.calls.contains("status"))
        XCTAssertTrue(user.calls.contains("startPairing"))
        XCTAssertFalse(router.activeBackendIsElevated)
        // Nothing reached the root engine path.
        XCTAssertEqual(processes.count, 0)
        XCTAssertEqual(authorization.calls.count, 0)
        XCTAssertEqual(handoffs.count, 0)
        XCTAssertFalse(user.calls.contains("pairHandoff"))
        XCTAssertFalse(user.calls.contains("startTunnel"))
        XCTAssertFalse(session.hasElevatedSession)
        XCTAssertNil(session.cleanup.pending)
    }

    // MARK: - Quit before the start, then Stay

    // The press took its gate generation before the quit. Stay opens a new
    // generation, but the old press must stay cancelled when it reaches the
    // session late: no handoff, no root engine, and no prompt.
    func testAPressFromBeforeAQuitStaysCancelledAfterStay() async {
        let gate = AppActionGate()
        let user = FakeBackend()
        let processes = RaceCounter()
        let authorization = CountingStartAuthorization()
        let handoffs = RaceCounter()
        let session = countingSession(
            user: user,
            gate: gate,
            processes: processes,
            authorization: authorization,
            handoffs: handoffs
        )
        let press = gate.current()
        gate.beginQuit()
        gate.cancelQuit()
        XCTAssertFalse(gate.isQuitting)

        do {
            try await AppActionGate.$actionToken.withValue(press) {
                try await session.authorizeTunnelStart()
            }
            XCTFail("A press from before the quit must not start after Stay.")
        } catch {
            XCTAssertTrue(error.localizedDescription.lowercased().contains("cancel"), error.localizedDescription)
        }
        XCTAssertEqual(handoffs.count, 0)
        XCTAssertEqual(processes.count, 0)
        XCTAssertEqual(authorization.calls.count, 0)
        XCTAssertFalse(user.calls.contains("pairHandoff"))

        // A new press after Stay has the new generation and proceeds to the
        // descriptor check, which this fake fails before any engine start.
        do {
            try await AppActionGate.$actionToken.withValue(gate.current()) {
                try await session.authorizeTunnelStart()
            }
            XCTFail("The fake descriptor refuses the start.")
        } catch {
            XCTAssertFalse(error.localizedDescription.lowercased().contains("cancel"), error.localizedDescription)
        }
        XCTAssertEqual(handoffs.count, 1)
        XCTAssertEqual(processes.count, 0)
    }

    // The model takes the press token and carries it through the router to
    // the session as a task-local value. A quit and a Stay that land while the
    // router holds the start keep that press cancelled, and the stale result
    // does not replace the screen.
    func testAModelStartHeldAcrossQuitAndStayReachesNoRootEngine() async {
        let gate = AppActionGate()
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        let processes = RaceCounter()
        let authorization = CountingStartAuthorization()
        let handoffs = RaceCounter()
        let session = countingSession(
            user: user,
            gate: gate,
            processes: processes,
            authorization: authorization,
            handoffs: handoffs,
            descriptor: 12
        )
        let hold = RaceGate()
        // The app's own router wiring, with one hold before the session's
        // authorizer. The authorizer runs in the same task, so the press token
        // reaches it.
        let router = session.makeRouter(
            user: user,
            authorizeStart: {
                await hold.hold()
                try await session.authorizeTunnelStart()
            }
        )
        let model = makeModel(router, gate: gate)
        await model.refresh()
        XCTAssertEqual(model.screen, .ready)

        let start = Task { await model.turnOn() }
        await hold.waitUntilHeld()
        gate.beginQuit()
        gate.cancelQuit()
        await hold.release()
        await start.value

        XCTAssertEqual(handoffs.count, 0)
        XCTAssertFalse(user.calls.contains("pairHandoff"))
        XCTAssertEqual(processes.count, 0)
        XCTAssertEqual(authorization.calls.count, 0)
        XCTAssertFalse(router.activeBackendIsElevated)
        XCTAssertNil(session.cleanup.pending)
        // The cancelled press did not publish its failure.
        if case .needsAttention = model.screen {
            XCTFail("A press cancelled by the quit must not show its result after Stay.")
        }
    }

    // MARK: - A stop during a start

    // A Turn off, a quit, or a lost-engine stop that runs while the start is
    // inside its authorizer cancels that start. The engine that the authorizer
    // prepared is stopped and never published.
    func testAStopDuringTheAuthorizerPublishesNoEngine() async {
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        let elevated = FakeBackend()
        elevated.currentStatus = status(running: false)
        let helperStops = RaceCounter()
        let starts = RaceCounter()
        let box = RouterBox()
        let router = TunnelRoutingBackend(
            user: user,
            prepareElevated: { elevated },
            stopElevated: {
                helperStops.increment()
                return .stopped
            },
            authorizeStart: {
                // The first start's stop lands after the prompt and before
                // the publish.
                if starts.increment() == 1 {
                    try await box.router?.stopTunnel(timeout: 1)
                }
            },
            cleanup: TunnelCleanupState()
        )
        box.router = router
        do {
            try await router.startTunnel(experimentalICMP: false)
            XCTFail("A stop during the start must cancel it.")
        } catch {
            XCTAssertEqual(error as? TunnelRoutingError, .startCancelledByStop)
        }
        XCTAssertFalse(router.activeBackendIsElevated)
        XCTAssertFalse(elevated.calls.contains("startTunnel"))
        // One helper stop for Turn off, and one for the prepared engine.
        XCTAssertEqual(helperStops.count, 2)
        XCTAssertFalse(router.hasPendingStop)
        // The next start after the stop is a new start.
        try? await router.startTunnel(experimentalICMP: false)
        XCTAssertTrue(elevated.calls.contains("startTunnel"))
        XCTAssertTrue(router.activeBackendIsElevated)
    }

    // An explicit session stop cancels a session start that is still in its
    // prior-stop step, so the start cannot write a handoff or start a root
    // engine after the person turned the tunnel off.
    func testAnExplicitSessionStopCancelsAStartInFlight() async {
        let user = FakeBackend()
        let hold = RaceGate()
        let handoffs = RaceCounter()
        let processes = RaceCounter()
        let session = RealTunnelSession(
            user: user,
            handoffDescriptor: {
                handoffs.increment()
                return 12
            },
            isQuitting: { false },
            authorization: CountingStartAuthorization(),
            stopBeforeStart: {
                await hold.hold()
                return .stopped
            },
            makeProcess: {
                processes.increment()
                throw HelperTrustError.helperUnavailable
            }
        )
        let start = Task { try await session.authorizeTunnelStart() }
        await hold.waitUntilHeld()
        let stop = await session.stopElevated()
        XCTAssertEqual(stop, .stopped)
        await hold.release()
        do {
            try await start.value
            XCTFail("A start that began before the stop must stay cancelled.")
        } catch {
            XCTAssertTrue(error.localizedDescription.lowercased().contains("cancel"), error.localizedDescription)
        }
        XCTAssertEqual(handoffs.count, 0)
        XCTAssertEqual(processes.count, 0)
        XCTAssertFalse(user.calls.contains("pairHandoff"))
    }

    // MARK: - Stale updates

    // A Turn off whose answer arrives after a quit and a Stay belongs to the
    // old generation. It must not replace the screen with its own failure,
    // but the app-owned cleanup mark that the stop recorded stays visible.
    func testAStaleStopAnswerAfterStayDoesNotOverwriteTheScreenButKeepsTheMark() async throws {
        let gate = AppActionGate()
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        let elevated = FakeBackend()
        elevated.currentStatus = status(running: true)
        let hold = RaceGate()
        let cleanup = TunnelCleanupState()
        let router = TunnelRoutingBackend(
            user: user,
            prepareElevated: { elevated },
            stopElevated: {
                await hold.hold()
                return .uncertain("The helper did not answer.")
            },
            cleanup: cleanup
        )
        try await router.startTunnel(experimentalICMP: false)
        let model = makeModel(router, gate: gate)
        await model.refresh()
        XCTAssertEqual(model.screen, .on)

        let stop = Task { await model.turnOff() }
        await hold.waitUntilHeld()
        gate.beginQuit()
        gate.cancelQuit()
        await hold.release()
        await stop.value

        // The old press did not set its own failure or retry target.
        XCTAssertEqual(cleanup.pending?.message, "The helper did not answer.")
        // A fresh refresh after Stay shows the app-owned mark, not a clean Off.
        await model.refresh()
        XCTAssertEqual(model.screen, .needsAttention("The helper did not answer."))
        XCTAssertEqual(model.dashboard.action, .turnOff)
    }

    func testAnActionTokenFromBeforeAQuitIsNotPermittedAfterStay() {
        let gate = AppActionGate()
        let before = gate.current()
        XCTAssertTrue(gate.permits(before))
        gate.beginQuit()
        XCTAssertFalse(gate.permits(before))
        XCTAssertFalse(gate.permits(gate.current()))
        gate.cancelQuit()
        XCTAssertFalse(gate.permits(before), "Stay must not revive an older press.")
        XCTAssertTrue(gate.permits(gate.current()))
    }

    // MARK: - Lost route observation

    // The engine's own reply was lost in an earlier attempt. A newer
    // retryable mark that wins over the helper's clean answer must keep that
    // fact, so the next clean helper answer still becomes a final route mark.
    func testANewerRetryableMarkKeepsTheLostRouteObservation() async {
        let cleanup = TunnelCleanupState()
        cleanup.retainElevatedSession()
        cleanup.recordPendingStop("The first stop was not confirmed.")
        cleanup.recordLostRouteObservation()
        let confirmations = RaceCounter()
        let session = RealTunnelSession(
            user: FakeBackend(),
            handoffDescriptor: { -1 },
            isQuitting: { false },
            cleanup: cleanup,
            confirmation: {
                if confirmations.increment() == 1 {
                    // A concurrent caller records a newer retryable mark
                    // while this helper answer is in flight.
                    cleanup.recordPendingStop("A cleanup retry was still running when the quit began.")
                }
                return .stopped
            }
        )

        let first = await session.stopElevated()
        XCTAssertEqual(first, .uncertain("A cleanup retry was still running when the quit began."))
        XCTAssertTrue(cleanup.hasLostRouteObservation)

        let second = await session.stopElevated()
        XCTAssertEqual(second, .routesUnverified(EngineLaunchText.routeCleanupUnverified))
        XCTAssertEqual(cleanup.pending?.kind, .routesUnverified)
        XCTAssertFalse(cleanup.hasLostRouteObservation)
        XCTAssertEqual(confirmations.count, 2)
    }

    // The router path: the engine reply and the helper stop were both lost.
    // A later router stop whose engine still cannot answer gets a clean
    // helper answer. That is a final route mark, not a clean stop. The
    // helper-only Retry cleanup path is covered by the wired test in
    // ProtectedHelperTests.
    func testARouterRetryWhoseEngineStillCannotAnswerIsFinal() async throws {
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        let elevated = FakeBackend()
        elevated.currentStatus = status(running: true)
        let cleanup = TunnelCleanupState()
        let answers = RaceCounter()
        let router = TunnelRoutingBackend(
            user: user,
            prepareElevated: { elevated },
            stopElevated: {
                answers.increment() == 1 ? .uncertain("The helper did not answer.") : .stopped
            },
            cleanup: cleanup
        )
        try await router.startTunnel(experimentalICMP: false)
        elevated.failure = BackendError.response("The stop reply was lost.")
        do {
            try await router.stopTunnel(timeout: 1)
            XCTFail("A lost reply with an unanswered helper is not clean.")
        } catch {}
        XCTAssertEqual(cleanup.pending?.kind, .retryable)
        XCTAssertTrue(cleanup.hasLostRouteObservation)

        // The engine still cannot answer. The next router stop reaches the
        // helper, which now confirms.
        do {
            try await router.stopTunnel(timeout: 1)
            XCTFail("A helper-only answer after a lost reply is not clean.")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains(EngineLaunchText.routeCleanupUnverified))
        }
        XCTAssertEqual(cleanup.pending?.kind, .routesUnverified)
        XCTAssertFalse(cleanup.hasLostRouteObservation)
        XCTAssertFalse(router.activeBackendIsElevated)
    }

    // MARK: - Unrelated helper session

    // A stop reply that this connection did not own proves nothing about the
    // retained session unless the helper names that exact session with a
    // clean result and nothing is live, stopping, starting, or blocked.
    func testAnUnownedStopReplyNeedsTheExactRetainedSession() {
        let retained = UUID()
        let unrelated = UUID()
        func reply(_ status: HelperStatus) -> TunnelStopResult {
            TunnelStopResult.fromHelperStop(
                reply: HelperStopReply(owned: false, status: status),
                previous: .disconnected,
                session: retained,
                everStarted: true,
                requireExistingSession: true
            )
        }
        XCTAssertEqual(
            reply(HelperStatus(running: false, cleanupBlocked: false, lastSession: unrelated, lastResult: .stopped)),
            .routesUnverified(EngineLaunchText.stopUnverified)
        )
        XCTAssertEqual(
            reply(HelperStatus(running: false, cleanupBlocked: false)),
            .routesUnverified(EngineLaunchText.stopUnverified)
        )
        for live in [
            HelperStatus(running: true, cleanupBlocked: false, lastSession: retained, lastResult: .stopped),
            HelperStatus(running: false, cleanupBlocked: false, stopping: true, lastSession: retained, lastResult: .stopped),
            HelperStatus(running: false, cleanupBlocked: false, starting: true, lastSession: retained, lastResult: .stopped),
        ] {
            XCTAssertEqual(reply(live), .uncertain(EngineLaunchText.stopUnverified), "\(live)")
        }
        XCTAssertEqual(
            reply(HelperStatus(running: false, cleanupBlocked: true, lastSession: retained, lastResult: .stopped)),
            .durableBlock(Strings.helperCleanup)
        )
        XCTAssertEqual(
            reply(HelperStatus(running: false, cleanupBlocked: false, lastSession: retained, lastResult: .timedOut)),
            .routesUnverified(EngineLaunchText.stopTimedOut)
        )
        XCTAssertEqual(
            reply(HelperStatus(running: false, cleanupBlocked: false, lastSession: retained, lastResult: .stopped)),
            .stopped
        )
        // With no retained id, a reconnecting caller never accepts a record.
        XCTAssertEqual(
            TunnelStopResult.fromHelperStop(
                reply: HelperStopReply(
                    owned: false,
                    status: HelperStatus(running: false, cleanupBlocked: false, lastSession: unrelated, lastResult: .stopped)
                ),
                previous: .disconnected,
                session: nil,
                everStarted: false,
                requireExistingSession: true
            ),
            .routesUnverified(EngineLaunchText.stopUnverified)
        )
    }

    // MARK: - Recovery text by mark kind

    // A final mark offers no action, so the dashboard says what to do next.
    // The route mark names the check and says a relaunch forgets it. The
    // durable block keeps its own text once and never says that a relaunch
    // forgets it. A retryable mark keeps its stop action.
    func testTheDashboardRecoveryFollowsTheMarkKind() async {
        let gate = AppActionGate()
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        for (kind, message) in [
            (TunnelCleanupKind.routesUnverified, EngineLaunchText.routeCleanupUnverified),
            (.durableBlock, Strings.helperCleanup),
            (.retryable, EngineLaunchText.stopUnverified),
        ] {
            let cleanup = TunnelCleanupState()
            cleanup.recordPendingStop(message, kind: kind)
            let router = TunnelRoutingBackend(
                user: user,
                prepareElevated: { user },
                stopElevated: { .stopped },
                cleanup: cleanup
            )
            let model = makeModel(router, gate: gate)
            await model.refresh()
            let subtitle = model.dashboard.subtitle
            switch kind {
            case .routesUnverified:
                XCTAssertNil(model.dashboard.action)
                XCTAssertTrue(subtitle.contains(EngineLaunchText.routeCleanupRecovery), subtitle)
            case .durableBlock:
                XCTAssertNil(model.dashboard.action)
                XCTAssertFalse(subtitle.contains("Restarting the app"), subtitle)
                XCTAssertEqual(subtitle.components(separatedBy: EngineLaunchText.cleanupRecovery).count, 2, subtitle)
            case .retryable:
                XCTAssertEqual(model.dashboard.action, .retry)
                XCTAssertEqual(subtitle, message)
            }
            // A start is refused before any prompt for every kind.
            await model.turnOn()
            XCTAssertFalse(user.calls.contains("startTunnel"))
        }
    }

    // Stay after a quit restores the guidance of the current mark kind.
    func testStayRestoresTheRecoveryOfTheCurrentMarkKind() {
        let durable = EngineLaunchState.afterCancelledQuit(
            previous: .running,
            outcome: .uncertain(Strings.helperCleanup),
            pendingCleanup: TunnelCleanupPending(token: 1, message: Strings.helperCleanup, kind: .durableBlock)
        )
        XCTAssertEqual(durable.failure?.recovery, EngineLaunchText.cleanupRecovery)
        XCTAssertNil(durable.presentation().action)
        let retryable = EngineLaunchState.afterCancelledQuit(
            previous: .running,
            outcome: .uncertain(EngineLaunchText.stopUnverified),
            pendingCleanup: TunnelCleanupPending(token: 2, message: EngineLaunchText.stopUnverified, kind: .retryable)
        )
        XCTAssertEqual(retryable.failure?.recovery, EngineLaunchText.quitRecovery)
        XCTAssertEqual(retryable.presentation().action, .retryCleanup)
    }
}
