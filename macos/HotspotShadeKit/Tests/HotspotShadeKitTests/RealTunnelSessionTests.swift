import XCTest
@testable import HotspotShadeKit

private final class CallCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0
    func increment() {
        lock.lock()
        value += 1
        lock.unlock()
    }
    var count: Int {
        lock.lock(); defer { lock.unlock() }
        return value
    }
}

// A prompt that must never run. The count proves the authorization step was
// not reached.
private final class UnreachedStartAuthorization: HelperStartAuthorizationProviding, @unchecked Sendable {
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

// Hold the first start inside its prior-stop step so a second start arrives
// while the first is still in flight.
private actor StartGate {
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

final class RealTunnelSessionTests: XCTestCase {
    func testAnUncertainPriorStopRefusesANewStart() async {
        let user = FakeBackend()
        let stops = CallCounter()
        let handoffs = CallCounter()
        let authorization = UnreachedStartAuthorization()
        let session = RealTunnelSession(
            user: user,
            handoffDescriptor: {
                handoffs.increment()
                return 12
            },
            isQuitting: { false },
            authorization: authorization,
            stopBeforeStart: {
                stops.increment()
                return .uncertain("The helper did not confirm the stop.")
            }
        )
        do {
            try await session.authorizeTunnelStart()
            XCTFail("An uncertain prior stop must refuse the new start.")
        } catch {
            XCTAssertEqual(error.localizedDescription, "The helper did not confirm the stop.")
            let failure = error as? TunnelAuthorizationFailure
            XCTAssertEqual(failure?.cleanup, .uncertainStop)
            XCTAssertTrue(failure?.isUncertainStop == true)
        }
        // The refusal happens before the handoff is written, before any
        // administrator prompt, and before any root engine start.
        XCTAssertEqual(stops.count, 1)
        XCTAssertEqual(handoffs.count, 0)
        XCTAssertEqual(authorization.calls, 0)
        XCTAssertFalse(user.calls.contains("pairHandoff"))
    }

    func testConcurrentStartsCannotBothPrepareAnElevatedSession() async {
        let user = FakeBackend()
        let gate = StartGate()
        let stops = CallCounter()
        let handoffs = CallCounter()
        let authorization = UnreachedStartAuthorization()
        let session = RealTunnelSession(
            user: user,
            handoffDescriptor: {
                handoffs.increment()
                return -1
            },
            isQuitting: { false },
            authorization: authorization,
            stopBeforeStart: {
                stops.increment()
                await gate.hold()
                return .uncertain("The helper did not confirm the stop.")
            }
        )
        let first = Task { try await session.authorizeTunnelStart() }
        await gate.waitUntilHeld()
        do {
            try await session.authorizeTunnelStart()
            XCTFail("A second start must not run while the first is in flight.")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("already in progress"))
        }
        await gate.release()
        do {
            try await first.value
            XCTFail("The first start still refuses the pending stop.")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("did not confirm"))
        }
        // Only the first start reached the prior-stop step. The second one
        // never wrote a handoff, never prompted, and never started an engine.
        XCTAssertEqual(stops.count, 1)
        XCTAssertEqual(handoffs.count, 0)
        XCTAssertEqual(authorization.calls, 0)
        XCTAssertFalse(user.calls.contains("pairHandoff"))
    }

    func testAConfirmedPriorStopContinuesToTheHandoffCheck() async {
        let user = FakeBackend()
        let session = RealTunnelSession(
            user: user,
            handoffDescriptor: { -1 },
            isQuitting: { false },
            stopBeforeStart: { .stopped }
        )
        do {
            try await session.authorizeTunnelStart()
            XCTFail("A missing handoff descriptor must fail the start.")
        } catch {
            XCTAssertFalse(error.localizedDescription.lowercased().contains("stop"))
        }
        XCTAssertFalse(user.calls.contains("pairHandoff"))
    }

    func testARepeatedStartRefusesALiveElevatedSessionWithoutStoppingIt() async {
        let user = FakeBackend()
        let gate = NSLock()
        var didStop = false
        let session = RealTunnelSession(
            user: user,
            handoffDescriptor: { 12 },
            isQuitting: { false },
            stopBeforeStart: {
                gate.lock()
                didStop = true
                gate.unlock()
                return .stopped
            },
            liveSession: { true }
        )
        do {
            try await session.authorizeTunnelStart()
            XCTFail("A live elevated session must refuse a repeated start.")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("already active"))
        }
        // The live root engine is not stopped and no pairing handoff is
        // written for a second engine.
        gate.lock()
        let stopped = didStop
        gate.unlock()
        XCTAssertFalse(stopped)
        XCTAssertFalse(user.calls.contains("pairHandoff"))
    }

    func testDirectModeIsRefusedInsteadOfSendingAPhoneStart() async {
        let user = FakeBackend()
        let calledStop = NSLock()
        var didStop = false
        let session = RealTunnelSession(
            user: user,
            handoffDescriptor: { 12 },
            isQuitting: { false },
            mode: .direct,
            stopBeforeStart: {
                calledStop.lock()
                didStop = true
                calledStop.unlock()
                return .stopped
            }
        )
        do {
            try await session.authorizeTunnelStart()
            XCTFail("The app does not support direct mode yet.")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("direct mode"))
        }
        calledStop.lock()
        let stopped = didStop
        calledStop.unlock()
        XCTAssertFalse(stopped)
        XCTAssertFalse(user.calls.contains("pairHandoff"))
    }
}
