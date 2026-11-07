import XCTest
@testable import HotspotShadeKit

private final class LifecycleCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0
    func increment() { lock.lock(); value += 1; lock.unlock() }
    var count: Int { lock.lock(); defer { lock.unlock() }; return value }
}

// Hold the helper stop inside one stop flight so another router or the test can
// record a newer mark or session while the first caller waits.
private actor LifecycleStopGate {
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

// Hermetic tests for the independent review findings. They use fake engines,
// fake helper answers, and an in-memory cleanup state. They create no route,
// device, helper, or tunnel.
@MainActor final class LifecycleReviewTests: XCTestCase {
    private func status(running: Bool) -> Status {
        Status(running: running, paired: true, phone: Phone(state: running ? "connected" : "ready"))
    }

    private func makeModel(
        _ backend: BackendClient,
        gate: AppActionGate = AppActionGate()
    ) -> AppModel {
        AppModel(
            backend: backend,
            isQuitting: { gate.isQuitting },
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
        helper: @escaping @Sendable () async -> TunnelStopResult = { .stopped },
        prepare: @escaping @Sendable () async throws -> BackendClient,
        existing: @escaping @Sendable () -> BackendClient? = { nil },
        cleanup: TunnelCleanupState
    ) -> TunnelRoutingBackend {
        TunnelRoutingBackend(
            user: user,
            prepareElevated: prepare,
            stopElevated: helper,
            existingElevated: existing,
            cleanup: cleanup
        )
    }

    // MARK: - Finding 1: a confirmed helper stop after a lost route observation

    func testALostElevatedStopReplyBecomesTerminalAndDoesNotLoop() async throws {
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        let elevated = FakeBackend()
        elevated.currentStatus = status(running: true)
        elevated.stopClearsRunning = true
        let helperStops = LifecycleCounter()
        let router = makeRouter(
            user: user,
            helper: {
                helperStops.increment()
                return .stopped
            },
            prepare: { elevated },
            cleanup: TunnelCleanupState()
        )
        try await router.startTunnel(experimentalICMP: false)
        elevated.failure = BackendError.response("The stop reply was lost.")
        do {
            try await router.stopTunnel(timeout: 1)
            XCTFail("A lost elevated stop reply must not be a clean stop.")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("stop reply was lost"))
        }
        // The helper proved the process is gone, so the elevated backend is
        // cleared. The route observation is final and cannot be retried into a
        // clean answer.
        XCTAssertFalse(router.activeBackendIsElevated)
        XCTAssertEqual(router.pendingCleanup?.kind, .routesUnverified)
        let elevatedStops = elevated.calls.filter { $0 == "stopTunnel" }.count
        let helperCount = helperStops.count
        XCTAssertEqual(helperCount, 1)

        // The model shows the honest state and no retry action.
        let model = makeModel(router)
        await model.refresh()
        XCTAssertEqual(model.screen, .needsAttention(router.pendingCleanup?.message ?? ""))
        XCTAssertNil(model.dashboard.action)
        XCTAssertEqual(model.screenModel.menuBar.actions.first { $0.kind == .turnOn }?.enabled, false)
        XCTAssertEqual(model.screenModel.menuBar.actions.first { $0.kind == .turnOff }?.enabled, false)

        // A direct Try again, Turn on, or Turn off does not loop the helper.
        await model.perform(.retry)
        await model.turnOn()
        await model.turnOff()
        XCTAssertEqual(helperStops.count, helperCount)
        XCTAssertEqual(elevated.calls.filter { $0 == "stopTunnel" }.count, elevatedStops)
        XCTAssertTrue(router.hasPendingStop)
        XCTAssertNil(model.dashboard.action)
    }

    func testATerminalMarkReturnsTheSameAnswerOnAQuitRetry() async {
        let cleanup = TunnelCleanupState()
        cleanup.recordPendingStop("The route cleanup was not observed.", kind: .routesUnverified)
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        let helperStops = LifecycleCounter()
        let router = makeRouter(
            user: user,
            helper: {
                helperStops.increment()
                return .stopped
            },
            prepare: { FakeBackend() },
            cleanup: cleanup
        )
        let first = await router.stopForQuit()
        let second = await router.stopForQuit()
        XCTAssertEqual(first, "The route cleanup was not observed.")
        XCTAssertEqual(second, first)
        XCTAssertEqual(helperStops.count, 0, "A terminal mark has no helper retry.")
        XCTAssertEqual(cleanup.pending?.kind, .routesUnverified)
    }

    // MARK: - Finding 2: a retained elevated session without a backend

    func testARetainedElevatedSessionWithoutAHandleReachesTheHelper() async {
        let cleanup = TunnelCleanupState()
        cleanup.retainElevatedSession()
        let confirmations = LifecycleCounter()
        let session = RealTunnelSession(
            user: FakeBackend(),
            handoffDescriptor: { 12 },
            isQuitting: { false },
            cleanup: cleanup,
            confirmation: {
                confirmations.increment()
                return .routesUnverified("The helper has no record for the retained session.")
            }
        )
        let result = await session.stopElevated()
        XCTAssertEqual(result, .routesUnverified("The helper has no record for the retained session."))
        XCTAssertEqual(confirmations.count, 1, "The retained session must reach the helper.")
        XCTAssertFalse(cleanup.hasElevatedSession)
        XCTAssertEqual(cleanup.pending?.kind, .routesUnverified)
    }

    func testARetainedElevatedSessionWithoutAHandleReachesTheRouterHelper() async {
        let cleanup = TunnelCleanupState()
        cleanup.retainElevatedSession()
        let helperStops = LifecycleCounter()
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        let router = makeRouter(
            user: user,
            helper: {
                helperStops.increment()
                return .stopped
            },
            prepare: { FakeBackend() },
            cleanup: cleanup
        )
        let message = await router.stopForQuit()
        XCTAssertNil(message)
        XCTAssertEqual(helperStops.count, 1)
        XCTAssertFalse(user.calls.contains("stopTunnel"), "The idle user engine is not the retained session.")
        XCTAssertFalse(cleanup.hasElevatedSession)
    }

    // MARK: - Finding 3: one atomic app action gate

    func testAQuitGateRefusesEveryDashboardCall() async {
        let gate = AppActionGate()
        let fake = FakeBackend()
        fake.currentStatus = status(running: false)
        let model = makeModel(fake, gate: gate)
        await model.refresh()
        XCTAssertTrue(fake.calls.contains("status"))

        gate.beginQuit()
        await model.turnOn()
        await model.turnOff()
        await model.toggle()
        await model.beginPairing()
        await model.cancelPairing()
        await model.checkNow()
        await model.perform(.retry)
        _ = await model.forget()
        _ = await model.turnOffAndForget()
        await model.loadLogs()
        await model.loadFailures()

        XCTAssertFalse(fake.calls.contains("startTunnel"))
        XCTAssertFalse(fake.calls.contains("stopTunnel"))
        XCTAssertFalse(fake.calls.contains("startPairing"))
        XCTAssertFalse(fake.calls.contains("cancelPairing"))
        XCTAssertFalse(fake.calls.contains("forget"))
        XCTAssertFalse(fake.calls.contains("probe"))
        XCTAssertFalse(fake.calls.contains("logs"))
        XCTAssertFalse(fake.calls.contains("failures"))

        // Stay is a new generation. A new action after Stay is allowed.
        gate.cancelQuit()
        await model.turnOn()
        XCTAssertTrue(fake.calls.contains("startTunnel"))
    }

    func testAStartThatIsInFlightWhenQuitBeginsDoesNotRefreshOrPublish() async {
        let gate = AppActionGate()
        let fake = FakeBackend()
        fake.currentStatus = status(running: true)
        fake.operationDelay = 200_000_000
        let model = makeModel(fake, gate: gate)
        await model.refresh()
        let readsBefore = fake.calls.filter { $0 == "status" }.count

        let start = Task { await model.turnOn() }
        while !fake.calls.contains("startTunnel") {
            await Task.yield()
        }
        gate.beginQuit()
        await start.value

        XCTAssertEqual(
            fake.calls.filter { $0 == "status" }.count,
            readsBefore,
            "A start that resumes after the quit must not publish a status read."
        )
        XCTAssertNotEqual(model.screen, .on)
        XCTAssertNotEqual(model.screen, .ready)
    }

    func testTheSessionStartGenerationStaysCancelledAfterStay() async {
        let gate = LifecycleStopGate()
        let session = RealTunnelSession(
            user: FakeBackend(),
            handoffDescriptor: { 12 },
            isQuitting: { false },
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
            XCTFail("An aborted start must not proceed.")
        } catch {
            XCTAssertTrue(error.localizedDescription.lowercased().contains("cancel"))
        }
    }

    // MARK: - Finding 4: generation tokens for cleanup state

    func testSameMessageMarksAreDistinguishedByToken() {
        let cleanup = TunnelCleanupState()
        let first = cleanup.recordPendingStop("The same sentence.")
        let second = cleanup.recordPendingStop("The same sentence.")
        XCTAssertNotEqual(first, second)
        XCTAssertFalse(cleanup.clearPendingStop(ifToken: first))
        XCTAssertEqual(cleanup.pending?.token, second)
        XCTAssertTrue(cleanup.clearPendingStop(ifToken: second))
        XCTAssertNil(cleanup.pending)
    }

    func testAStaleRouterCannotClearANewerMarkWithTheSameMessage() async {
        let cleanup = TunnelCleanupState()
        let first = cleanup.recordPendingStop("The helper did not confirm the stop.")
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        let gate = LifecycleStopGate()
        let router = makeRouter(
            user: user,
            helper: {
                await gate.hold()
                return .stopped
            },
            prepare: { FakeBackend() },
            cleanup: cleanup
        )
        let stop = Task { await router.stopForQuit() }
        await gate.waitUntilHeld()
        // A rebuilt router records a newer uncertainty with the same text while
        // the first stop is in flight.
        let second = cleanup.recordPendingStop("The helper did not confirm the stop.")
        XCTAssertNotEqual(first, second)
        await gate.release()
        let message = await stop.value
        XCTAssertEqual(message, "The helper did not confirm the stop.")
        XCTAssertEqual(cleanup.pending?.token, second, "The newer mark must survive the older stop.")
    }

    func testAStaleStopCannotClearANewerElevatedSession() async throws {
        let cleanup = TunnelCleanupState()
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        let elevated = FakeBackend()
        elevated.currentStatus = status(running: true)
        let gate = LifecycleStopGate()
        let router = makeRouter(
            user: user,
            helper: {
                await gate.hold()
                return .routesUnverified("The route cleanup was not observed.")
            },
            prepare: { elevated },
            cleanup: cleanup
        )
        try await router.startTunnel(experimentalICMP: false)
        guard let firstToken = cleanup.currentElevatedSessionToken else {
            return XCTFail("The start must retain an elevated session.")
        }
        let stop = Task { try await router.stopTunnel(timeout: 1) }
        await gate.waitUntilHeld()
        // A concurrent start in another router retains a newer session.
        let newerToken = cleanup.retainElevatedSession()
        XCTAssertNotEqual(firstToken, newerToken)
        await gate.release()
        do {
            try await stop.value
            XCTFail("The route observation was lost.")
        } catch {}
        XCTAssertEqual(
            cleanup.currentElevatedSessionToken,
            newerToken,
            "The older stop must not clear the newer session."
        )
        XCTAssertTrue(cleanup.hasElevatedSession)
    }

    func testAConfirmedStopDoesNotClaimCleanWhileANewerSessionExists() async throws {
        let cleanup = TunnelCleanupState()
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        let elevated = FakeBackend()
        elevated.currentStatus = status(running: true)
        let gate = LifecycleStopGate()
        let router = makeRouter(
            user: user,
            helper: {
                await gate.hold()
                return .stopped
            },
            prepare: { elevated },
            cleanup: cleanup
        )
        try await router.startTunnel(experimentalICMP: false)
        let stop = Task { try await router.stopTunnel(timeout: 1) }
        await gate.waitUntilHeld()
        let newerToken = cleanup.retainElevatedSession()
        await gate.release()
        do {
            try await stop.value
            XCTFail("A stop must not report clean while a newer session exists.")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("still open"))
        }
        XCTAssertEqual(cleanup.currentElevatedSessionToken, newerToken)
        XCTAssertEqual(cleanup.pending?.kind, .retryable)
    }

    // MARK: - Finding 5: no unrelated clean session is proof

    func testANoSessionStopCannotUseAnUnrelatedCleanRecord() {
        let retained = UUID()
        let unrelated = UUID()
        let idle = HelperStatus(
            running: false,
            cleanupBlocked: false,
            lastSession: unrelated,
            lastResult: .stopped
        )
        XCTAssertEqual(
            TunnelStopResult.fromCleanupStatus(
                idle,
                session: nil,
                everStarted: true,
                previous: .disconnected
            ),
            .routesUnverified(EngineLaunchText.stopUnverified)
        )
        XCTAssertEqual(
            TunnelStopResult.fromCleanupStatus(
                idle,
                session: nil,
                everStarted: false,
                previous: .disconnected,
                requireExistingSession: true
            ),
            .routesUnverified(EngineLaunchText.stopUnverified)
        )
        let reply = HelperStopReply(
            owned: false,
            status: HelperStatus(
                running: false,
                cleanupBlocked: false,
                lastSession: unrelated,
                lastResult: .stopped
            )
        )
        XCTAssertEqual(
            TunnelStopResult.fromHelperStop(
                reply: reply,
                previous: .disconnected,
                session: nil,
                everStarted: true
            ),
            .routesUnverified(EngineLaunchText.stopUnverified)
        )
        // The exact retained session is still proof.
        XCTAssertEqual(
            TunnelStopResult.fromCleanupStatus(
                HelperStatus(
                    running: false,
                    cleanupBlocked: false,
                    lastSession: retained,
                    lastResult: .stopped
                ),
                session: retained,
                everStarted: true,
                previous: .disconnected
            ),
            .stopped
        )
    }

    func testAnEmptyIdleSnapshotIsNotCleanupProof() {
        XCTAssertEqual(
            TunnelStopResult.fromCleanupStatus(
                HelperStatus(running: false, cleanupBlocked: false),
                session: nil,
                everStarted: true,
                previous: .disconnected
            ),
            .routesUnverified(EngineLaunchText.stopUnverified)
        )
    }

    // MARK: - Finding 6: final cleanup marks are not retryable starts

    func testADurableLaunchFailureOffersNoRetry() {
        let failure = EngineLaunchFailure.fromHelper(HelperTrustError.cleanupBlocked)
        XCTAssertTrue(failure.cleanupIsFinal)
        let presentation = EngineLaunchState.lost(failure).presentation()
        XCTAssertNil(presentation.action)
        XCTAssertNil(presentation.actionTitle)
        // A timeout may change with a later helper read, so its retry stays.
        let timeout = EngineLaunchFailure.fromHelper(HelperTrustError.engineStopTimedOut)
        XCTAssertFalse(timeout.cleanupIsFinal)
        XCTAssertEqual(EngineLaunchState.lost(timeout).presentation().action, .retryCleanup)
    }

    func testAFinalPendingCleanupOffersNoDashboardActionOrStart() async {
        for kind in [TunnelCleanupKind.durableBlock, .routesUnverified] {
            let cleanup = TunnelCleanupState()
            cleanup.recordPendingStop("The cleanup cannot be retried.", kind: kind)
            let user = FakeBackend()
            user.currentStatus = status(running: false)
            let helperStops = LifecycleCounter()
            let router = makeRouter(
                user: user,
                helper: {
                    helperStops.increment()
                    return .stopped
                },
                prepare: { FakeBackend() },
                cleanup: cleanup
            )
            let model = makeModel(router)
            await model.refresh()
            XCTAssertNil(model.dashboard.action, "\(kind)")
            XCTAssertEqual(model.screenModel.menuBar.actions.first { $0.kind == .turnOn }?.enabled, false, "\(kind)")
            XCTAssertEqual(model.screenModel.menuBar.actions.first { $0.kind == .turnOff }?.enabled, false, "\(kind)")
            XCTAssertEqual(model.screenModel.menuBar.actions.first { $0.kind == .pair }?.enabled, false, "\(kind)")
            await model.perform(.retry)
            await model.turnOn()
            await model.turnOff()
            XCTAssertFalse(user.calls.contains("startTunnel"), "\(kind)")
            XCTAssertFalse(user.calls.contains("stopTunnel"), "\(kind)")
            XCTAssertEqual(helperStops.count, 0, "\(kind)")
        }
    }

    func testStayKeepsAFinalCleanupMarkAndItsRecovery() {
        let durable = TunnelCleanupPending(token: 1, message: "Durable block.", kind: .durableBlock)
        let routes = TunnelCleanupPending(token: 2, message: "Routes unverified.", kind: .routesUnverified)
        for pending in [durable, routes] {
            let restored = EngineLaunchState.afterCancelledQuit(
                previous: .running,
                outcome: .stopped,
                pendingCleanup: pending
            )
            guard case .lost(let failure) = restored else {
                return XCTFail("A final mark must keep the lost screen.")
            }
            XCTAssertTrue(failure.cleanupIsFinal)
            let expected = pending.kind == .durableBlock
                ? EngineLaunchText.cleanupRecovery
                : EngineLaunchText.routeCleanupRecovery
            XCTAssertEqual(failure.recovery, expected)
            XCTAssertNil(restored.presentation().action)
        }
    }
}
