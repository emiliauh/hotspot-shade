import XCTest
@testable import HotspotShadeKit

final class TunnelRoutingBackendTests: XCTestCase {
    private final class Events: @unchecked Sendable {
        private let lock = NSLock()
        private var values: [String] = []
        func append(_ value: String) { lock.lock(); values.append(value); lock.unlock() }
        var all: [String] { lock.lock(); defer { lock.unlock() }; return values }
    }

    private final class Counter: @unchecked Sendable {
        private let lock = NSLock()
        private var value = 0
        func increment() { lock.lock(); value += 1; lock.unlock() }
        var count: Int { lock.lock(); defer { lock.unlock() }; return value }
    }

    private final class StopSequence: @unchecked Sendable {
        private let lock = NSLock()
        private var values: [TunnelStopResult]
        private var calls = 0
        init(_ values: [TunnelStopResult]) { self.values = values }
        func next() -> TunnelStopResult {
            lock.lock(); defer { lock.unlock() }
            calls += 1
            if values.isEmpty { return .stopped }
            return values.removeFirst()
        }
        var callCount: Int { lock.lock(); defer { lock.unlock() }; return calls }
    }

    // Hold a helper stop inside its reply so a second stop or quit arrives
    // while the first flight is still active.
    private actor StopGate {
        private var entered = false
        private var enteredWaiter: CheckedContinuation<Void, Never>?
        private var releaseWaiter: CheckedContinuation<Void, Never>?

        func hold() async {
            entered = true
            enteredWaiter?.resume()
            enteredWaiter = nil
            await withCheckedContinuation { releaseWaiter = $0 }
        }

        func waitUntilEntered() async {
            if entered { return }
            await withCheckedContinuation { enteredWaiter = $0 }
        }

        func release() {
            releaseWaiter?.resume()
            releaseWaiter = nil
        }
    }

    private func status(running: Bool, paired: Bool = true) -> Status {
        Status(running: running, paired: paired, phone: Phone(state: running ? "connected" : "ready"))
    }

    func testTunnelUsesTheElevatedEngineOnlyWhileItRuns() async throws {
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        let elevated = FakeBackend()
        elevated.currentStatus = status(running: true)
        elevated.stopClearsRunning = true
        let events = Events()
        let router = TunnelRoutingBackend(
            user: user,
            prepareElevated: {
                events.append("prepare")
                return elevated
            },
            stopElevated: {
                events.append("stopElevated")
                return .stopped
            }
        )
        let before = try await router.status(timeout: 1)
        XCTAssertEqual(before.running, false)
        XCTAssertFalse(router.activeBackendIsElevated)

        try await router.startTunnel(experimentalICMP: false)
        XCTAssertTrue(router.activeBackendIsElevated)
        let live = try await router.status(timeout: 1)
        XCTAssertEqual(live.running, true)
        XCTAssertEqual(elevated.startBodies.count, 1)
        XCTAssertTrue(elevated.startBodies[0].contains("experimental_icmp\":false"))

        // Pairing stays with the user engine, never the elevated engine. It is
        // refused while the elevated session exists, because the user engine
        // cannot see the root tunnel.
        do {
            try await router.startPairing()
            XCTFail("Pairing must be refused while the elevated engine exists.")
        } catch {
            XCTAssertEqual(error.localizedDescription, TunnelRoutingError.pairingBlockedByTunnel.localizedDescription)
        }
        XCTAssertFalse(user.calls.contains("startPairing"))
        XCTAssertFalse(elevated.calls.contains("startPairing"))

        try await router.stopTunnel(timeout: 1)
        XCTAssertFalse(router.activeBackendIsElevated)
        // After a confirmed stop the user engine owns pairing again.
        try await router.startPairing()
        XCTAssertTrue(user.calls.contains("startPairing"))
        let after = try await router.status(timeout: 1)
        XCTAssertEqual(after.running, false)
        XCTAssertEqual(events.all, ["prepare", "stopElevated"])
        XCTAssertTrue(elevated.calls.contains("stopTunnel"))
    }

    func testAnUncertainCleanupOnStartFailureDoesNotReportTheUserEngineAsOff() async throws {
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        let elevated = FakeBackend()
        elevated.failure = BackendError.response("The source device did not answer.")
        let router = TunnelRoutingBackend(
            user: user,
            prepareElevated: { elevated },
            stopElevated: { .uncertain("The helper did not confirm the stop.") }
        )
        do {
            try await router.startTunnel(experimentalICMP: true)
            XCTFail("The failed start must throw.")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("did not confirm"))
        }
        // The user engine is idle, but that is not evidence that the failed
        // root engine removed its routes. Keep the elevated engine selected.
        XCTAssertTrue(router.activeBackendIsElevated)
        do {
            _ = try await router.status(timeout: 1)
            XCTFail("The dead elevated engine must not be replaced by the idle user engine.")
        } catch {
            // Expected: the elevated engine is unavailable, not Off.
        }
    }

    func testAnUncertainStopStaysUncertainOnQuit() async throws {
        let user = FakeBackend()
        let elevated = FakeBackend()
        elevated.currentStatus = status(running: true)
        elevated.stopClearsRunning = true
        let stops = Events()
        let router = TunnelRoutingBackend(
            user: user,
            prepareElevated: { elevated },
            stopElevated: {
                stops.append("stop")
                return .uncertain("The helper did not confirm the stop.")
            }
        )
        try await router.startTunnel(experimentalICMP: true)
        do {
            try await router.stopTunnel(timeout: 1)
            XCTFail("The uncertain stop must throw.")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("did not confirm"))
        }
        let outcome = await TunnelQuitCheck.stop(router)
        guard case .uncertain(let message) = outcome else {
            XCTFail("Quit must report an uncertain stop.")
            return
        }
        XCTAssertTrue(message.contains("did not confirm"))
        // Quit asks the helper again even though the earlier stop was
        // unconfirmed. The helper stop is idempotent, and only the helper owns
        // the process and its grant directory.
        XCTAssertEqual(stops.all, ["stop", "stop"])
        XCTAssertTrue(router.activeBackendIsElevated)
    }

    func testAQuitRetriesAPendingStopAndReportsAConfirmedHelperStop() async {
        let user = FakeBackend()
        let events = Events()
        let router = TunnelRoutingBackend(
            user: user,
            prepareElevated: { FakeBackend() },
            stopElevated: {
                events.append("stopElevated")
                return .stopped
            }
        )
        router.recordUncertainStop("The helper did not confirm the stop.")
        let outcome = await TunnelQuitCheck.stop(router)
        // A requested stop was never proven. A later helper stop that confirms
        // is new evidence, so the quit can report a clean stop.
        XCTAssertEqual(outcome, .stopped)
        XCTAssertEqual(events.all, ["stopElevated"])
        XCTAssertFalse(router.hasPendingStop)
        XCTAssertFalse(router.activeBackendIsElevated)
    }

    func testAnUnconfirmedStopRefusesTheStartBeforeAuthorization() async {
        let user = FakeBackend()
        let elevated = FakeBackend()
        elevated.failure = BackendError.response("The source device did not answer.")
        let events = Events()
        let router = TunnelRoutingBackend(
            user: user,
            prepareElevated: {
                events.append("prepare")
                return elevated
            },
            stopElevated: {
                events.append("stopElevated")
                return .uncertain("The helper did not confirm the stop.")
            },
            authorizeStart: { events.append("authorize") }
        )
        do {
            try await router.startTunnel(experimentalICMP: true)
            XCTFail("The failed start must throw.")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("did not confirm"))
        }
        XCTAssertEqual(events.all, ["authorize", "prepare", "stopElevated"])
        // A second attempt refuses before the prompt, the handoff, and the root
        // engine start. The authorizer is not asked a second time.
        do {
            try await router.startTunnel(experimentalICMP: true)
            XCTFail("The unconfirmed stop must refuse the next start.")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("did not confirm"))
        }
        XCTAssertEqual(events.all, ["authorize", "prepare", "stopElevated"])
        XCTAssertFalse(user.calls.contains("startTunnel"))
    }

    private final class RouterRef: @unchecked Sendable {
        var router: TunnelRoutingBackend?
    }

    func testAStartRefusedAfterAuthorizationStopsThePreparedSession() async {
        let user = FakeBackend()
        let elevated = FakeBackend()
        let events = Events()
        let ref = RouterRef()
        let router = TunnelRoutingBackend(
            user: user,
            prepareElevated: {
                events.append("prepare")
                return elevated
            },
            stopElevated: {
                events.append("stopElevated")
                return .stopped
            },
            authorizeStart: {
                events.append("authorize")
                // A quit or a failed stop can land while the prompt is open.
                ref.router?.recordUncertainStop("The helper did not confirm the stop.")
            }
        )
        ref.router = router
        do {
            try await router.startTunnel(experimentalICMP: true)
            XCTFail("The start must be refused after the pending stop appears.")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("did not confirm"))
        }
        // The root engine that the authorizer just prepared is stopped, and the
        // idle user engine is not presented as a clean start.
        XCTAssertEqual(events.all, ["authorize", "stopElevated"])
        XCTAssertFalse(router.activeBackendIsElevated)
        XCTAssertFalse(elevated.calls.contains("startTunnel"))
    }

    func testAStartFailureStopsTheElevatedEngineAndKeepsTheUserEngine() async throws {
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        let elevated = FakeBackend()
        elevated.failure = BackendError.response("The source device did not answer.")
        let events = Events()
        let router = TunnelRoutingBackend(
            user: user,
            prepareElevated: { elevated },
            stopElevated: {
                events.append("stopElevated")
                return .stopped
            }
        )
        do {
            try await router.startTunnel(experimentalICMP: true)
            XCTFail("The failed start must throw.")
        } catch {
            XCTAssertFalse(router.activeBackendIsElevated)
        }
        XCTAssertEqual(events.all, ["stopElevated"])
        let after = try await router.status(timeout: 1)
        XCTAssertEqual(after.running, false)
        XCTAssertFalse(user.calls.contains("startTunnel"))
    }

    func testAnUncertainHelperStopIsNotReportedAsACleanStop() async throws {
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        let elevated = FakeBackend()
        elevated.currentStatus = status(running: true)
        elevated.stopClearsRunning = true
        let router = TunnelRoutingBackend(
            user: user,
            prepareElevated: { elevated },
            stopElevated: { .uncertain("The helper did not confirm the stop.") }
        )
        try await router.startTunnel(experimentalICMP: true)
        do {
            try await router.stopTunnel(timeout: 1)
            XCTFail("An uncertain helper stop must throw.")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("did not confirm"))
        }
        // The user engine says the tunnel is off because it never owned it.
        // Keeping the elevated backend prevents that from becoming a clean
        // answer for the person.
        XCTAssertTrue(router.activeBackendIsElevated)
    }

    func testAQuitStopsTheHelperEvenWhenTheElevatedEngineSaysStopped() async throws {
        let user = FakeBackend()
        let elevated = FakeBackend()
        elevated.currentStatus = status(running: false)
        let events = Events()
        let router = TunnelRoutingBackend(
            user: user,
            prepareElevated: { elevated },
            stopElevated: {
                events.append("stopElevated")
                return .stopped
            }
        )
        try await router.startTunnel(experimentalICMP: true)
        let outcome = await TunnelQuitCheck.stop(router)
        XCTAssertEqual(outcome, .stopped)
        XCTAssertEqual(events.all, ["stopElevated"])
        XCTAssertFalse(router.activeBackendIsElevated)
    }

    func testAPrepareFailureAfterAuthorizationStopsThePreparedSession() async throws {
        let user = FakeBackend()
        let events = Events()
        let router = TunnelRoutingBackend(
            user: user,
            prepareElevated: { throw BackendError.notSupported },
            stopElevated: {
                events.append("stopElevated")
                return .stopped
            }
        )
        do {
            try await router.startTunnel(experimentalICMP: true)
            XCTFail("A missing elevated engine must fail the start.")
        } catch {
            XCTAssertFalse(router.activeBackendIsElevated)
        }
        // The authorizer may have started a root engine before the router
        // could address it. Stop it instead of leaving it for the next start.
        XCTAssertEqual(events.all, ["stopElevated"])
        XCTAssertFalse(user.calls.contains("startTunnel"))
    }

    func testARepeatedStartNeverStopsAKnownLiveElevatedSession() async throws {
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        let elevated = FakeBackend()
        elevated.currentStatus = status(running: true)
        let events = Events()
        let router = TunnelRoutingBackend(
            user: user,
            prepareElevated: {
                events.append("prepare")
                return elevated
            },
            stopElevated: {
                events.append("stopElevated")
                return .stopped
            }
        )
        try await router.startTunnel(experimentalICMP: true)
        do {
            try await router.startTunnel(experimentalICMP: true)
            XCTFail("A second start while the elevated engine is live must refuse.")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("already active"))
        }
        // The live elevated session is not stopped, not replaced, and not
        // prepared a second time. The person must stop it explicitly.
        XCTAssertEqual(events.all, ["prepare"])
        XCTAssertTrue(router.activeBackendIsElevated)
        XCTAssertEqual(elevated.startBodies.count, 1)
        XCTAssertFalse(elevated.calls.contains("stopTunnel"))
        let live = try await router.status(timeout: 1)
        XCTAssertEqual(live.running, true)
    }

    func testALostEngineStopReplyStillStopsTheHelperAndIsNotClean() async throws {
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        let elevated = FakeBackend()
        elevated.currentStatus = status(running: true)
        elevated.stopClearsRunning = true
        let events = Events()
        let router = TunnelRoutingBackend(
            user: user,
            prepareElevated: {
                events.append("prepare")
                return elevated
            },
            stopElevated: {
                events.append("stopElevated")
                return .stopped
            }
        )
        try await router.startTunnel(experimentalICMP: true)
        elevated.failure = BackendError.response("The stop reply was lost.")
        do {
            try await router.stopTunnel(timeout: 1)
            XCTFail("A lost engine stop reply must not be a clean stop.")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("stop reply was lost"))
        }
        // The helper still owns the process, so it is asked to stop.
        XCTAssertEqual(events.all, ["prepare", "stopElevated"])
        XCTAssertTrue(elevated.calls.contains("stopTunnel"))
        // The helper confirmed the process stop, but the elevated engine's own
        // route cleanup reply was lost. The process is gone, so the elevated
        // backend is cleared; the terminal route mark still refuses a start.
        XCTAssertFalse(router.activeBackendIsElevated)
        XCTAssertTrue(router.hasPendingStop)
        XCTAssertEqual(router.pendingCleanup?.kind, .routesUnverified)
        do {
            try await router.startTunnel(experimentalICMP: true)
            XCTFail("An unconfirmed stop must refuse a new start.")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("stop reply was lost"))
        }
        XCTAssertEqual(events.all, ["prepare", "stopElevated"])
    }

    func testALostEngineStopReplyOnQuitStillStopsTheHelperAndIsUncertain() async throws {
        let user = FakeBackend()
        let elevated = FakeBackend()
        elevated.currentStatus = status(running: true)
        elevated.stopClearsRunning = true
        let events = Events()
        let router = TunnelRoutingBackend(
            user: user,
            prepareElevated: {
                events.append("prepare")
                return elevated
            },
            stopElevated: {
                events.append("stopElevated")
                return .stopped
            }
        )
        try await router.startTunnel(experimentalICMP: true)
        elevated.failure = BackendError.response("The stop reply was lost.")
        let outcome = await TunnelQuitCheck.stop(router)
        guard case .uncertain(let message) = outcome else {
            XCTFail("A lost engine stop reply must be uncertain on quit.")
            return
        }
        XCTAssertTrue(message.contains("stop reply was lost"))
        XCTAssertEqual(events.all, ["prepare", "stopElevated"])
        // The helper confirmed that the root engine is gone, so the elevated
        // backend is cleared. The route observation is lost and stays terminal.
        XCTAssertFalse(router.activeBackendIsElevated)
        XCTAssertEqual(router.pendingCleanup?.kind, .routesUnverified)
    }

    // MARK: - Auto-stop reconciliation

    func testAnAutoStoppedElevatedEngineIsReconciledBeforeANewStart() async throws {
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        let first = FakeBackend()
        first.currentStatus = status(running: true)
        let second = FakeBackend()
        second.currentStatus = status(running: true)
        let events = Events()
        let prepares = Counter()
        let router = TunnelRoutingBackend(
            user: user,
            prepareElevated: {
                prepares.increment()
                events.append("prepare")
                return prepares.count == 1 ? first : second
            },
            stopElevated: {
                events.append("stopElevated")
                return .stopped
            },
            authorizeStart: { events.append("authorize") }
        )
        try await router.startTunnel(experimentalICMP: true)
        // The elevated engine removed its own routes after the hotspot went
        // away. Its status says off, but the root process still exists.
        first.currentStatus = status(running: false)
        try await router.startTunnel(experimentalICMP: true)
        // The old session gets a confirmed helper stop before the second
        // authorization and engine start.
        XCTAssertEqual(events.all, ["authorize", "prepare", "stopElevated", "authorize", "prepare"])
        XCTAssertEqual(first.startBodies.count, 1)
        XCTAssertEqual(second.startBodies.count, 1)
        XCTAssertTrue(router.activeBackendIsElevated)
        let live = try await router.status(timeout: 1)
        XCTAssertEqual(live.running, true)
    }

    func testAnAutoStoppedElevatedEngineIsNotClearedByRunningFalse() async throws {
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        let first = FakeBackend()
        first.currentStatus = status(running: true)
        let second = FakeBackend()
        second.currentStatus = status(running: true)
        let events = Events()
        let prepares = Counter()
        let authorizations = Counter()
        let router = TunnelRoutingBackend(
            user: user,
            prepareElevated: {
                prepares.increment()
                events.append("prepare")
                return prepares.count == 1 ? first : second
            },
            stopElevated: {
                events.append("stopElevated")
                return .uncertain("The helper did not confirm the stop.")
            },
            authorizeStart: { authorizations.increment() }
        )
        try await router.startTunnel(experimentalICMP: true)
        first.currentStatus = status(running: false)
        do {
            try await router.startTunnel(experimentalICMP: true)
            XCTFail("A running false status is not cleanup evidence.")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("did not confirm"))
        }
        XCTAssertEqual(events.all, ["prepare", "stopElevated"])
        XCTAssertEqual(authorizations.count, 1)
        XCTAssertTrue(router.activeBackendIsElevated)
        XCTAssertTrue(router.hasPendingStop)
        XCTAssertEqual(second.startBodies.count, 0)
        // The explicit latch refuses the next start before the status read,
        // the prompt, and the helper. Only an explicit stop may retry.
        do {
            try await router.startTunnel(experimentalICMP: true)
            XCTFail("The latched stop must refuse a new start.")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("did not confirm"))
        }
        XCTAssertEqual(events.all, ["prepare", "stopElevated"])
        XCTAssertEqual(authorizations.count, 1)
    }

    // MARK: - Pairing and forget boundary

    func testPairingAndForgetAreBlockedWhileAnElevatedEngineExists() async throws {
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        let elevated = FakeBackend()
        elevated.currentStatus = status(running: true)
        let router = TunnelRoutingBackend(
            user: user,
            prepareElevated: { elevated },
            stopElevated: { .stopped }
        )
        try await router.startTunnel(experimentalICMP: true)
        do {
            try await router.startPairing()
            XCTFail("Pairing must be refused while the elevated engine exists.")
        } catch {
            XCTAssertEqual(error.localizedDescription, TunnelRoutingError.pairingBlockedByTunnel.localizedDescription)
        }
        do {
            _ = try await router.forget()
            XCTFail("Forget must be refused while the elevated engine exists.")
        } catch BackendError.forgetBlockedByTunnel {
        } catch {
            XCTFail("Unexpected forget error: \(error)")
        }
        do {
            try await router.pairHandoff()
            XCTFail("A handoff must be refused while the elevated engine exists.")
        } catch {
            XCTAssertEqual(error.localizedDescription, TunnelRoutingError.pairingBlockedByTunnel.localizedDescription)
        }
        // A read-only state request and a cancel stay available.
        _ = try await router.pairState()
        try await router.cancelPairing()
        XCTAssertFalse(user.calls.contains("startPairing"))
        XCTAssertFalse(user.calls.contains("forget"))
        XCTAssertFalse(user.calls.contains("pairHandoff"))
        XCTAssertTrue(user.calls.contains("pairState"))
        XCTAssertTrue(user.calls.contains("cancelPairing"))
    }

    func testPairingAndForgetAreBlockedWhileCleanupIsUncertain() async {
        let user = FakeBackend()
        let router = TunnelRoutingBackend(
            user: user,
            prepareElevated: { FakeBackend() },
            stopElevated: { .stopped }
        )
        router.recordUncertainStop("The helper did not confirm the stop.")
        do {
            try await router.startPairing()
            XCTFail("Pairing must be refused while cleanup is uncertain.")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("did not confirm"))
        }
        do {
            _ = try await router.forget()
            XCTFail("Forget must be refused while cleanup is uncertain.")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("did not confirm"))
        }
        do {
            try await router.pairHandoff()
            XCTFail("A handoff must be refused while cleanup is uncertain.")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("did not confirm"))
        }
        XCTAssertFalse(user.calls.contains("startPairing"))
        XCTAssertFalse(user.calls.contains("forget"))
        XCTAssertFalse(user.calls.contains("pairHandoff"))
    }

    // MARK: - Stop retry and serialization

    func testASafeStopRetryClearsAnUncertainHelperStop() async throws {
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        let elevated = FakeBackend()
        elevated.currentStatus = status(running: true)
        let stops = StopSequence([
            .uncertain("The helper did not confirm the stop."),
            .stopped,
        ])
        let router = TunnelRoutingBackend(
            user: user,
            prepareElevated: { elevated },
            stopElevated: { stops.next() }
        )
        try await router.startTunnel(experimentalICMP: true)
        do {
            try await router.stopTunnel(timeout: 1)
            XCTFail("The first stop must be uncertain.")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("did not confirm"))
        }
        XCTAssertTrue(router.activeBackendIsElevated)
        XCTAssertTrue(router.hasPendingStop)
        // The same explicit stop can retry the helper. New confirmation is
        // evidence, not a status read.
        try await router.stopTunnel(timeout: 1)
        XCTAssertFalse(router.activeBackendIsElevated)
        XCTAssertFalse(router.hasPendingStop)
        XCTAssertEqual(stops.callCount, 2)
    }

    func testConcurrentStopAndQuitShareOneDelayedOutcome() async throws {
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        let elevated = FakeBackend()
        elevated.currentStatus = status(running: true)
        let gate = StopGate()
        let helperStops = Counter()
        let router = TunnelRoutingBackend(
            user: user,
            prepareElevated: { elevated },
            stopElevated: {
                helperStops.increment()
                await gate.hold()
                return .stopped
            }
        )
        try await router.startTunnel(experimentalICMP: true)
        let turningOff = Task { try await router.stopTunnel(timeout: 1) }
        await gate.waitUntilEntered()
        let quitting = Task { await router.stopForQuit() }
        // Wait until the quit is genuinely queued on the same flight. Without
        // coalescing it would start a second helper stop.
        var queued = false
        for _ in 0..<10_000 {
            if await router.stopWaiterCount() >= 1 { queued = true; break }
            await Task.yield()
        }
        XCTAssertTrue(queued, "The quit must join the stop flight.")
        await gate.release()
        let toggleResult: Result<Void, Error>
        do {
            try await turningOff.value
            toggleResult = .success(())
        } catch {
            toggleResult = .failure(error)
        }
        let quitMessage = await quitting.value
        guard case .success = toggleResult else {
            XCTFail("The delayed stop must confirm.")
            return
        }
        XCTAssertNil(quitMessage)
        XCTAssertEqual(helperStops.count, 1)
        XCTAssertFalse(router.activeBackendIsElevated)
        XCTAssertFalse(router.hasPendingStop)
    }

    // MARK: - Authorizer errors

    func testAnAuthorizerUncertainStopIsLatchedBeforeLaterActions() async {
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        let authorizations = Counter()
        let helperStops = Counter()
        let router = TunnelRoutingBackend(
            user: user,
            prepareElevated: { FakeBackend() },
            stopElevated: {
                helperStops.increment()
                return .stopped
            },
            authorizeStart: {
                authorizations.increment()
                throw TunnelAuthorizationFailure(
                    message: "The helper did not confirm the stop.",
                    cleanup: .uncertainStop
                )
            }
        )
        do {
            try await router.startTunnel(experimentalICMP: true)
            XCTFail("The authorizer must fail the start.")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("did not confirm"))
        }
        XCTAssertTrue(router.hasPendingStop)
        // The latch blocks the next start before a second authorization.
        do {
            try await router.startTunnel(experimentalICMP: true)
            XCTFail("The latched authorizer stop must refuse a new start.")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("did not confirm"))
        }
        XCTAssertEqual(authorizations.count, 1)
        // Pairing, handoff, and forget are blocked too.
        do { try await router.startPairing(); XCTFail("Pairing must be blocked.") } catch {}
        do { try await router.pairHandoff(); XCTFail("Handoff must be blocked.") } catch {}
        do { _ = try await router.forget(); XCTFail("Forget must be blocked.") } catch {}
        // Quit is the explicit stop that may retry the helper. A confirmed
        // helper stop resolves the latch.
        let outcome = await TunnelQuitCheck.stop(router)
        XCTAssertEqual(outcome, .stopped)
        XCTAssertEqual(helperStops.count, 1)
        XCTAssertFalse(router.hasPendingStop)
    }

    func testAnAuthorizerStartFailureWithoutCleanupDoesNotLatch() async {
        let user = FakeBackend()
        user.currentStatus = status(running: false)
        let router = TunnelRoutingBackend(
            user: user,
            prepareElevated: { FakeBackend() },
            stopElevated: { .stopped },
            authorizeStart: {
                throw TunnelAuthorizationFailure(message: "Administrator authorization was cancelled.")
            }
        )
        do {
            try await router.startTunnel(experimentalICMP: true)
            XCTFail("The authorizer must fail the start.")
        } catch {
            XCTAssertEqual(error.localizedDescription, "Administrator authorization was cancelled.")
        }
        XCTAssertFalse(router.hasPendingStop)
        // A cancelled prompt did not start an engine, so it is not a cleanup
        // block. The person can pair and try again.
        do {
            try await router.startPairing()
        } catch {
            XCTFail("A cancelled prompt must not block pairing: \(error)")
        }
    }
}
