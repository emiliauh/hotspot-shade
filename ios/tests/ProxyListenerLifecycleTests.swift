import Foundation
import Network

// Hermetic lifecycle tests for the main proxy listener.
//
// The test injects a fake listener factory into the real ProxyServer. The fake
// never opens a socket, so the test binds no port, sets no route, creates no
// interface, and reaches no other device. It drives the same state and
// connection handlers that Network.framework calls.
//
// The regression it covers: an NWListener can report `.cancelled` with no app
// call, for example while iOS suspends the app. The old server ignored that
// event, so the status could stay "Listening" with no listener, and a later
// start returned early because the old listener still held the slot.
//
// The test also proves the other side: an intentional stop changes the
// generation before it cancels the listener, so its late `.cancelled` and
// `.ready` callbacks cannot report a failure or revive Listening.
//
// A `.waiting` listener reports Starting, not Listening, and one waiting
// episode has one bound. A wait that passes the bound ends the run as a
// recoverable failure with no replacement listener. A waiting timer belongs to
// one run, so it cannot end a newer run.
//
// Activation reconciles the listener state. A cancellation, failure, or ready
// state that arrived with no callback is applied once, and a waiting state
// keeps its bound. Activation cannot revive an intentional stop.

/// One fake listener. It stores the handlers that the server installs and
/// delivers state callbacks on the server queue, as Network.framework does.
final class FakeProxyListener: ProxyListenerHandle {
    private let lock = NSLock()
    private var storedState: NWListener.State = .setup
    private var stateHandler: ((NWListener.State) -> Void)?
    private var connectionHandler: ((NWConnection) -> Void)?
    private var listenerQueue: DispatchQueue?
    private var startedFlag = false
    private var cancelCountValue = 0

    var state: NWListener.State {
        lock.lock()
        defer { lock.unlock() }
        return storedState
    }

    var isStarted: Bool {
        lock.lock()
        defer { lock.unlock() }
        return startedFlag
    }

    var cancelCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return cancelCountValue
    }

    func setStateUpdateHandler(_ handler: ((NWListener.State) -> Void)?) {
        lock.lock()
        stateHandler = handler
        lock.unlock()
    }

    func setNewConnectionHandler(_ handler: ((NWConnection) -> Void)?) {
        lock.lock()
        connectionHandler = handler
        lock.unlock()
    }

    func start(queue: DispatchQueue) {
        lock.lock()
        startedFlag = true
        listenerQueue = queue
        lock.unlock()
    }

    /// Cancel the listener and report `.cancelled`, as Network.framework does
    /// for an intentional cancel.
    func cancel() {
        lock.lock()
        cancelCountValue += 1
        lock.unlock()
        emit(.cancelled)
    }

    /// Report one state callback. It is delivered later on the server queue.
    func emit(_ state: NWListener.State) {
        lock.lock()
        storedState = state
        let handler = stateHandler
        let queue = listenerQueue
        lock.unlock()
        guard let queue = queue else { return }
        queue.async { handler?(state) }
    }

    /// Record a state change without a callback. This models a cancellation or
    /// failure that happened while the app was inactive and no event arrived.
    /// Activation reconciliation reads the stored state.
    func quiesce(_ state: NWListener.State) {
        lock.lock()
        storedState = state
        lock.unlock()
    }
}

/// Hand out fake listeners. The test runs on the server queue through the
/// real server, so the list is guarded.
final class FakeProxyListenerFactory: ProxyListenerFactory {
    enum Failure: LocalizedError {
        case refused

        var errorDescription: String? { "The fake listener refused to start." }
    }

    private let lock = NSLock()
    private var storedListeners: [FakeProxyListener] = []
    private var failNextValue = false

    var failNext: Bool {
        get {
            lock.lock()
            defer { lock.unlock() }
            return failNextValue
        }
        set {
            lock.lock()
            failNextValue = newValue
            lock.unlock()
        }
    }

    var listeners: [FakeProxyListener] {
        lock.lock()
        defer { lock.unlock() }
        return storedListeners
    }

    var latest: FakeProxyListener? {
        lock.lock()
        defer { lock.unlock() }
        return storedListeners.last
    }

    func makeListener(parameters: NWParameters) throws -> any ProxyListenerHandle {
        lock.lock()
        let shouldFail = failNextValue
        failNextValue = false
        lock.unlock()
        if shouldFail { throw Failure.refused }
        let listener = FakeProxyListener()
        lock.lock()
        storedListeners.append(listener)
        lock.unlock()
        return listener
    }
}

@main
struct ProxyListenerLifecycleTests {
    static let token = "proxy-listener-lifecycle-token-0123456789"
    static let port: UInt16 = 25001

    static func check(_ condition: Bool, _ message: String, line: Int = #line) {
        if !condition {
            print("FAIL line \(line): \(message)")
            exit(1)
        }
    }

    static func checkEqual<T: Equatable>(_ actual: T, _ expected: T,
                                         _ label: String, line: Int = #line) {
        check(actual == expected, "\(label): got \(actual), expected \(expected)", line: line)
    }

    /// Run the main run loop until the condition holds or the timeout passes.
    /// `ProxyServer` publishes its snapshot on the main queue.
    static func wait(until condition: () -> Bool, timeout: TimeInterval) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if condition() { return true }
            RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.02))
        }
        return condition()
    }

    static func settle(_ seconds: TimeInterval) {
        _ = wait(until: { false }, timeout: seconds)
    }

    static func main() {
        let factory = FakeProxyListenerFactory()
        // Use a short bound in the hermetic test. Production uses the default.
        let waitLimit: TimeInterval = 1.0
        let server = ProxyServer(trust: ObservableTrustStore(MemoryTrustStore()),
                                 listenerFactory: factory,
                                 listenerWaitSeconds: waitLimit)
        server.suppressICMPSelectorForLifecycleTest = true
        var latest = ProxyServer.Snapshot()
        var listeningSnapshots = 0
        server.onChange = { snapshot in
            latest = snapshot
            if snapshot.state == "Listening" { listeningSnapshots += 1 }
        }
        server.publishCurrentState()
        settle(0.1)

        // 0. The waiting policy has one bounded episode. A later waiting event
        // cannot extend it, a passed bound clears it, and a bad limit falls back
        // to the production default.
        var waitPolicy = ProxyListenerWaitPolicy(limit: 2)
        checkEqual(waitPolicy.limit, 2, "the waiting policy keeps a positive bound")
        check(!waitPolicy.isWaiting, "a new waiting policy has no bound")
        waitPolicy.begin(now: 100)
        check(waitPolicy.isWaiting, "a waiting event starts one episode")
        waitPolicy.begin(now: 105)
        checkEqual(waitPolicy.remaining(now: 101), 1,
                   "a later waiting event cannot extend the bound")
        check(!waitPolicy.expire(now: 101.9), "a bound that has not passed stays active")
        check(waitPolicy.expire(now: 102), "a bound expires at its deadline")
        check(!waitPolicy.isWaiting, "an expired bound is cleared")
        check(!waitPolicy.expire(now: 200), "an expired bound cannot expire twice")
        waitPolicy.begin(now: 0)
        waitPolicy.clear()
        check(!waitPolicy.isWaiting, "a recovered episode is cleared")
        checkEqual(ProxyListenerWaitPolicy(limit: 0).limit,
                   ProxyListenerWaitPolicy.seconds, "a zero bound uses the default")
        checkEqual(ProxyListenerWaitPolicy(limit: -TimeInterval.infinity).limit,
                   ProxyListenerWaitPolicy.seconds, "a non-finite bound uses the default")
        checkEqual(DashboardStatus.plainError(ProxyServer.listenerCancelledMessage),
                   "The proxy listener stopped unexpectedly. Start the proxy again.",
                   "the Dashboard shows the cancellation message")
        checkEqual(DashboardStatus.plainError(ProxyServer.listenerWaitingMessage),
                   "The proxy listener is waiting for the hotspot.",
                   "the Dashboard shows the waiting message")
        checkEqual(DashboardStatus.plainError(ProxyServer.listenerWaitExpiredMessage),
                   "The proxy listener stayed waiting for the hotspot. Start the proxy again.",
                   "the Dashboard shows the waiting expiry message")

        // 1. A ready fake reports Listening. Nothing binds a socket.
        server.start(port: port, token: token, hotspotAddress: "127.0.0.1")
        check(wait(until: { factory.latest?.isStarted == true }, timeout: 5),
              "the server creates and starts one listener")
        let first = factory.latest!
        check(wait(until: { latest.state == "Starting" }, timeout: 2),
              "a new run reports Starting, got \(latest.state)")
        first.emit(.ready)
        check(wait(until: { latest.state == "Listening" }, timeout: 2),
              "a ready listener reports Listening")
        checkEqual(latest.failureRevision, 0, "a ready listener reports no failure")
        // Let every publish from the ready transition reach the main queue.
        // The counter below must not move because of a delayed snapshot.
        settle(0.2)
        let listeningBeforeCancel = listeningSnapshots

        // 2. An unexpected cancellation must end the run. Reporting Listening
        // with no listener would be false, and the run must free its slot.
        first.emit(.cancelled)
        check(wait(until: { latest.state == "Failed" && latest.failureRevision == 1 }, timeout: 2),
              "an unexpected cancellation ends the run as a failure")
        settle(0.2)
        checkEqual(latest.error, ProxyServer.listenerCancelledMessage,
                   "the cancellation message is the plain listener message")
        check(listeningSnapshots == listeningBeforeCancel,
              "a cancelled listener publishes no later Listening state")
        checkEqual(latest.clients, 0, "a cancelled run reports no sessions")

        // A queued ready from the cancelled run cannot revive Listening.
        first.emit(.ready)
        settle(0.2)
        check(latest.state == "Failed" && latest.failureRevision == 1,
              "a late ready from the cancelled run cannot report Listening")

        // 3. A new start is accepted after the cancellation. The old slot is
        // released, and a late cancellation from the first run is ignored.
        server.start(port: port, token: token, hotspotAddress: "127.0.0.1")
        check(wait(until: { factory.listeners.count == 2 && factory.latest?.isStarted == true },
                   timeout: 5),
              "a start after an unexpected cancellation is accepted")
        let second = factory.latest!
        check(wait(until: { latest.state == "Starting" }, timeout: 2),
              "the replacement run reports Starting")
        first.emit(.cancelled)
        settle(0.2)
        check(latest.state == "Starting" && latest.failureRevision == 1,
              "a cancellation from the old run cannot end the new run")
        second.emit(.ready)
        check(wait(until: { latest.state == "Listening" }, timeout: 2),
              "the replacement listener reports Listening")

        // 4. An intentional stop is not a failure. Its late callbacks belong to
        // the old generation and must not change the Stopped state.
        server.stop(reason: "You stopped the proxy.")
        check(wait(until: { latest.state == "Stopped" }, timeout: 2),
              "an intentional stop reports Stopped")
        checkEqual(latest.failureRevision, 1, "an intentional stop does not report a failure")
        checkEqual(latest.error, "You stopped the proxy.", "the stop reason stays visible")
        checkEqual(second.cancelCount, 1, "a stop cancels its listener once")
        second.emit(.ready)
        settle(0.2)
        check(latest.state == "Stopped",
              "a late ready after an intentional stop cannot report Listening")

        // 5. A listener failure reports its own error, cancels the listener,
        // and releases the slot for another start.
        server.start(port: port, token: token, hotspotAddress: "127.0.0.1")
        check(wait(until: { factory.listeners.count == 3 && factory.latest?.isStarted == true },
                   timeout: 5),
              "a start after a stop creates a new listener")
        let third = factory.latest!
        third.emit(.failed(.posix(.EADDRINUSE)))
        check(wait(until: { latest.state == "Failed" && latest.failureRevision == 2 }, timeout: 2),
              "a listener failure ends the run")
        checkEqual(latest.error, "Port \(port) is in use. Choose another port.",
                   "a bind failure names the port")
        checkEqual(third.cancelCount, 1, "a failed listener is cancelled once")

        server.start(port: port, token: token, hotspotAddress: "127.0.0.1")
        check(wait(until: { factory.listeners.count == 4 && factory.latest?.isStarted == true },
                   timeout: 5),
              "a start after a listener failure is accepted")
        let fourth = factory.latest!
        fourth.emit(.ready)
        check(wait(until: { latest.state == "Listening" }, timeout: 2),
              "the listener after a failure reports Listening")

        // 6. A listener that cannot be created reports Failed and leaves no
        // slot behind. The next start must work.
        server.stop()
        check(wait(until: { latest.state == "Stopped" }, timeout: 2),
              "the run stops before the factory failure check")
        let revisionBeforeFactoryFailure = latest.failureRevision
        factory.failNext = true
        server.start(port: port, token: token, hotspotAddress: "127.0.0.1")
        check(wait(until: {
            latest.state == "Failed" && latest.failureRevision == revisionBeforeFactoryFailure + 1
        }, timeout: 2), "a listener factory error reports Failed")
        check(latest.error?.hasPrefix("Cannot start listener:") == true,
              "a listener factory error keeps the plain prefix")

        server.start(port: port, token: token, hotspotAddress: "127.0.0.1")
        check(wait(until: { factory.listeners.count == 5 && factory.latest?.isStarted == true },
                   timeout: 5),
              "a start after a listener factory error is accepted")
        let fifth = factory.latest!
        fifth.emit(.ready)
        check(wait(until: { latest.state == "Listening" }, timeout: 2),
              "the listener after a factory error reports Listening")

        // 7. A cancellation while the run is still starting is the same
        // failure, not a stuck Starting state.
        server.stop()
        check(wait(until: { latest.state == "Stopped" }, timeout: 2),
              "the run stops before the starting-state cancellation check")
        let revisionBeforeStartingCancel = latest.failureRevision
        server.start(port: port, token: token, hotspotAddress: "127.0.0.1")
        check(wait(until: { factory.listeners.count == 6 && factory.latest?.isStarted == true },
                   timeout: 5),
              "a new run starts before the cancellation check")
        let sixth = factory.latest!
        check(wait(until: { latest.state == "Starting" }, timeout: 2),
              "the run is still starting before the cancellation")
        sixth.emit(.cancelled)
        check(wait(until: {
            latest.state == "Failed" && latest.failureRevision == revisionBeforeStartingCancel + 1
        }, timeout: 2), "a cancellation while starting ends the run")

        // 8. A waiting listener is never reported as Listening. It may recover
        // inside its bound. The old bound must not end the recovered run.
        server.stop()
        check(wait(until: { latest.state == "Stopped" }, timeout: 2),
              "the run stops before the waiting recovery check")
        let revisionBeforeWaiting = latest.failureRevision
        server.start(port: port, token: token, hotspotAddress: "127.0.0.1")
        check(wait(until: { factory.listeners.count == 7 && factory.latest?.isStarted == true },
                   timeout: 5),
              "a new run starts before the waiting recovery check")
        let seventh = factory.latest!
        seventh.emit(.ready)
        check(wait(until: { latest.state == "Listening" }, timeout: 2),
              "the waiting recovery run reports Listening first")
        seventh.emit(.waiting(.posix(.ENETDOWN)))
        check(wait(until: { latest.state == "Starting" }, timeout: 2),
              "a waiting listener stops reporting Listening")
        checkEqual(latest.failureRevision, revisionBeforeWaiting,
                   "a waiting listener reports no failure")
        checkEqual(latest.error, ProxyServer.listenerWaitingMessage,
                   "a waiting listener keeps a plain message")
        seventh.emit(.ready)
        check(wait(until: { latest.state == "Listening" && latest.error == nil }, timeout: 2),
              "a recovered listener reports Listening again")
        settle(waitLimit + 0.4)
        check(latest.state == "Listening",
              "an old waiting bound cannot end the recovered run")
        checkEqual(latest.failureRevision, revisionBeforeWaiting,
                   "the old waiting bound reports no failure")
        seventh.emit(.waiting(.posix(.ENETDOWN)))
        check(wait(until: { latest.state == "Starting" }, timeout: 2),
              "a second waiting episode begins")
        seventh.quiesce(.ready)
        check(wait(until: { latest.state == "Listening" && latest.error == nil }, timeout: 3),
              "the waiting timer observes readiness when its callback is lost")
        checkEqual(latest.failureRevision, revisionBeforeWaiting,
                   "a ready listener is not failed by the waiting timer")

        // 9. A listener that stays waiting for its whole bound ends the run as
        // a recoverable failure. No replacement listener starts by itself.
        server.stop()
        check(wait(until: { latest.state == "Stopped" }, timeout: 2),
              "the run stops before the waiting expiry check")
        let revisionBeforeWaitExpiry = latest.failureRevision
        server.start(port: port, token: token, hotspotAddress: "127.0.0.1")
        check(wait(until: { factory.listeners.count == 8 && factory.latest?.isStarted == true },
                   timeout: 5),
              "a new run starts before the waiting expiry check")
        let eighth = factory.latest!
        eighth.emit(.waiting(.posix(.ENETDOWN)))
        check(wait(until: {
            latest.state == "Failed" && latest.failureRevision == revisionBeforeWaitExpiry + 1
        }, timeout: 3), "a listener that stays waiting ends the run")
        checkEqual(latest.error, ProxyServer.listenerWaitExpiredMessage,
                   "a waiting expiry keeps the plain message")
        checkEqual(eighth.cancelCount, 1, "a waiting expiry cancels the listener once")
        checkEqual(latest.clients, 0, "a waiting expiry reports no sessions")
        settle(waitLimit + 0.4)
        checkEqual(factory.listeners.count, 8,
                   "a waiting expiry does not start a replacement listener")
        check(latest.state == "Failed",
              "a waiting expiry stays failed until a person starts again")
        checkEqual(latest.failureRevision, revisionBeforeWaitExpiry + 1,
                   "the old waiting bound cannot report a second failure")

        // 10. A cancellation that happened while the app was inactive can
        // arrive with no callback. Activation reads the listener state and ends
        // the run once.
        server.stop()
        check(wait(until: { latest.state == "Stopped" }, timeout: 2),
              "the run stops before the activation cancellation check")
        let revisionBeforeActivationCancel = latest.failureRevision
        server.start(port: port, token: token, hotspotAddress: "127.0.0.1")
        check(wait(until: { factory.listeners.count == 9 && factory.latest?.isStarted == true },
                   timeout: 5),
              "a new run starts before the activation cancellation check")
        let ninth = factory.latest!
        check(wait(until: { latest.state == "Starting" }, timeout: 2),
              "the activation cancellation run is starting")
        server.setSceneActive(false)
        settle(0.1)
        ninth.quiesce(.cancelled)
        server.setSceneActive(true)
        check(wait(until: {
            latest.state == "Failed" && latest.failureRevision == revisionBeforeActivationCancel + 1
        }, timeout: 2), "activation reconciles a listener that was cancelled with no callback")
        checkEqual(latest.error, ProxyServer.listenerCancelledMessage,
                   "the reconciled cancellation keeps the plain message")
        checkEqual(ninth.cancelCount, 0,
                   "a listener that already reported cancelled is not cancelled again")
        settle(0.3)
        check(latest.state == "Failed" && latest.failureRevision == revisionBeforeActivationCancel + 1,
              "a late state cannot report the reconciled cancellation twice")
        checkEqual(factory.listeners.count, 9,
                   "a reconciled cancellation starts no replacement listener")

        // 11. A failed listener that changed while the app was inactive is
        // reconciled with the same message as its callback.
        let revisionBeforeActivationFailure = latest.failureRevision
        server.start(port: port, token: token, hotspotAddress: "127.0.0.1")
        check(wait(until: { factory.listeners.count == 10 && factory.latest?.isStarted == true },
                   timeout: 5),
              "a new run starts before the activation failure check")
        let tenth = factory.latest!
        check(wait(until: { latest.state == "Starting" }, timeout: 2),
              "the activation failure run is starting")
        server.setSceneActive(false)
        settle(0.1)
        tenth.quiesce(.failed(.posix(.EADDRINUSE)))
        server.setSceneActive(true)
        check(wait(until: {
            latest.state == "Failed" && latest.failureRevision == revisionBeforeActivationFailure + 1
        }, timeout: 2), "activation reconciles a listener that failed with no callback")
        checkEqual(latest.error, "Port \(port) is in use. Choose another port.",
                   "a reconciled failure names the port")
        checkEqual(tenth.cancelCount, 1, "a reconciled failed listener is cancelled once")

        // 12. A waiting state that arrived with no callback is reconciled on
        // activation, and its bound still applies.
        server.start(port: port, token: token, hotspotAddress: "127.0.0.1")
        check(wait(until: { factory.listeners.count == 11 && factory.latest?.isStarted == true },
                   timeout: 5),
              "a new run starts before the activation waiting check")
        let eleventh = factory.latest!
        check(wait(until: { latest.state == "Starting" }, timeout: 2),
              "the activation waiting run is starting")
        let revisionBeforeActivationWait = latest.failureRevision
        server.setSceneActive(false)
        settle(0.1)
        eleventh.quiesce(.waiting(.posix(.ENETDOWN)))
        server.setSceneActive(true)
        check(wait(until: {
            latest.state == "Starting" && latest.error == ProxyServer.listenerWaitingMessage
        }, timeout: 2), "activation reconciles a waiting listener")
        checkEqual(latest.failureRevision, revisionBeforeActivationWait,
                   "a reconciled waiting listener reports no failure")
        check(wait(until: {
            latest.state == "Failed" && latest.failureRevision == revisionBeforeActivationWait + 1
        }, timeout: 3), "a reconciled waiting listener still has a bound")
        checkEqual(latest.error, ProxyServer.listenerWaitExpiredMessage,
                   "a reconciled waiting expiry keeps the plain message")
        checkEqual(eleventh.cancelCount, 1,
                   "a reconciled waiting expiry cancels the listener once")

        // 13. A waiting bound belongs to one run. A newer run is not ended by
        // the old timer.
        server.stop()
        check(wait(until: { latest.state == "Stopped" }, timeout: 2),
              "the run stops before the old waiting timer check")
        let revisionBeforeOldWait = latest.failureRevision
        server.start(port: port, token: token, hotspotAddress: "127.0.0.1")
        check(wait(until: { factory.listeners.count == 12 && factory.latest?.isStarted == true },
                   timeout: 5),
              "the old waiting timer run starts")
        let twelfth = factory.latest!
        twelfth.emit(.waiting(.posix(.ENETDOWN)))
        check(wait(until: { latest.error == ProxyServer.listenerWaitingMessage }, timeout: 2),
              "the old waiting timer run waits")
        server.stop()
        check(wait(until: { latest.state == "Stopped" }, timeout: 2),
              "the waiting run stops before its bound")
        server.start(port: port, token: token, hotspotAddress: "127.0.0.1")
        check(wait(until: { factory.listeners.count == 13 && factory.latest?.isStarted == true },
                   timeout: 5),
              "a newer run starts while the old bound is pending")
        let thirteenth = factory.latest!
        settle(waitLimit + 0.4)
        check(latest.state == "Starting",
              "an old waiting bound cannot end a newer run")
        checkEqual(latest.failureRevision, revisionBeforeOldWait,
                   "an old waiting bound reports no failure for a newer run")
        thirteenth.emit(.ready)
        check(wait(until: { latest.state == "Listening" }, timeout: 2),
              "the newer run still reaches Listening")

        // 14. A ready state with no callback is reconciled too. Activation
        // after a stop cannot revive the listener.
        server.stop()
        check(wait(until: { latest.state == "Stopped" }, timeout: 2),
              "the run stops before the activation ready check")
        let revisionBeforeActivationReady = latest.failureRevision
        server.start(port: port, token: token, hotspotAddress: "127.0.0.1")
        check(wait(until: { factory.listeners.count == 14 && factory.latest?.isStarted == true },
                   timeout: 5),
              "a new run starts before the activation ready check")
        let fourteenth = factory.latest!
        check(wait(until: { latest.state == "Starting" }, timeout: 2),
              "the activation ready run is starting")
        server.setSceneActive(false)
        settle(0.1)
        fourteenth.quiesce(.ready)
        server.setSceneActive(true)
        check(wait(until: { latest.state == "Listening" }, timeout: 2),
              "activation reconciles a ready listener with no callback")
        checkEqual(latest.failureRevision, revisionBeforeActivationReady,
                   "a reconciled ready listener reports no failure")

        server.stop()
        check(wait(until: { latest.state == "Stopped" }, timeout: 2),
              "the activation ready run stops")
        server.setSceneActive(true)
        settle(0.3)
        check(latest.state == "Stopped",
              "activation cannot revive an intentional stop")

        // 15-16. A waiting timer must reconcile terminal states even when the
        // listener's callback is lost. It records exactly one failure.
        let terminalStates: [(NWListener.State, Int)] = [
            (.failed(.posix(.EADDRINUSE)), 1),
            (.cancelled, 0),
        ]
        for (index, (terminalState, expectedCancels)) in terminalStates.enumerated() {
            server.stop()
            check(wait(until: { latest.state == "Stopped" }, timeout: 2),
                  "the previous run stops before timer reconciliation")
            let revision = latest.failureRevision
            let expectedCount = 15 + index
            server.start(port: port, token: token, hotspotAddress: "127.0.0.1")
            check(wait(until: { factory.listeners.count == expectedCount && factory.latest?.isStarted == true },
                       timeout: 5), "the timer reconciliation run starts")
            let listener = factory.latest!
            listener.emit(.waiting(.posix(.ENETDOWN)))
            check(wait(until: { latest.error == ProxyServer.listenerWaitingMessage }, timeout: 2),
                  "the waiting timer is armed")
            listener.quiesce(terminalState)
            check(wait(until: { latest.state == "Failed" && latest.failureRevision == revision + 1 },
                       timeout: 3), "the timer reconciles the terminal listener state")
            checkEqual(listener.cancelCount, expectedCancels,
                       "timer reconciliation cancels only a failed listener")
            settle(waitLimit + 0.2)
            checkEqual(latest.failureRevision, revision + 1,
                       "the old timer cannot report a second failure")
        }

        server.stop()
        _ = wait(until: { latest.state == "Stopped" }, timeout: 2)
        print("Proxy listener lifecycle tests passed")
    }
}
