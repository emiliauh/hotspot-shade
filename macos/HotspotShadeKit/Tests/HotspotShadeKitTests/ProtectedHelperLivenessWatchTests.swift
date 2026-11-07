import XCTest
@testable import HotspotShadeKit

private final class FakeTimer {
    let id: Int
    init(id: Int) { self.id = id }
}

final class ProtectedHelperLivenessWatchTests: XCTestCase {
    private func makeWatch() -> (HelperLivenessWatch<FakeTimer>, () -> Int) {
        let watch = HelperLivenessWatch<FakeTimer>()
        var made = 0
        return (watch, {
            var created = 0
            watch.sessionStarted {
                made += 1
                created = made
                return FakeTimer(id: made)
            }
            return created
        })
    }

    func testOneTimerServesRepeatedStarts() {
        let (watch, start) = makeWatch()
        XCTAssertEqual(start(), 1)
        XCTAssertEqual(start(), 0, "a running timer is reused")
        XCTAssertTrue(watch.isActive)
    }

    func testIdleCheckKeepsTimerWhileASessionExists() {
        let (watch, start) = makeWatch()
        _ = start()
        XCTAssertNil(watch.stopIfIdle { true })
        XCTAssertTrue(watch.isActive)
    }

    func testIdleCheckStopsTimerWhenNoSessionExists() {
        let (watch, start) = makeWatch()
        _ = start()
        XCTAssertEqual(watch.stopIfIdle { false }?.id, 1)
        XCTAssertFalse(watch.isActive)
        XCTAssertEqual(start(), 2, "a later start creates a new timer")
    }

    // Session A ends (expired authorization, reaped engine, or stop) and the
    // controller frees the slot. Session B starts before the idle check
    // finishes. B must keep its liveness and authorization-deadline timer.
    func testSessionStartedDuringIdleCheckKeepsTimer() {
        let (watch, start) = makeWatch()
        _ = start()
        let stopped = watch.stopIfIdle {
            // The controller saw no session, then B started and counted.
            _ = start()
            return false
        }
        XCTAssertNil(stopped)
        XCTAssertTrue(watch.isActive)
        // The next tick sees B and keeps the watch.
        XCTAssertNil(watch.stopIfIdle { true })
        XCTAssertTrue(watch.isActive)
    }

    func testIdleCheckWithNoTimerReturnsNil() {
        let (watch, _) = makeWatch()
        XCTAssertNil(watch.stopIfIdle { false })
        XCTAssertFalse(watch.isActive)
    }

    func testShutdownStopsTimerUnconditionally() {
        let (watch, start) = makeWatch()
        _ = start()
        XCTAssertEqual(watch.stopForShutdown()?.id, 1)
        XCTAssertFalse(watch.isActive)
        XCTAssertNil(watch.stopForShutdown())
    }

    func testConcurrentStartsAndIdleChecksNeverLoseALiveSession() {
        let watch = HelperLivenessWatch<FakeTimer>()
        let lock = NSLock()
        var sessionLive = false
        let iterations = 2_000
        DispatchQueue.concurrentPerform(iterations: iterations * 2) { index in
            if index % 2 == 0 {
                lock.lock(); sessionLive = true; lock.unlock()
                watch.sessionStarted { FakeTimer(id: index) }
            } else {
                _ = watch.stopIfIdle {
                    lock.lock(); defer { lock.unlock() }
                    let live = sessionLive
                    sessionLive = false
                    return live
                }
            }
        }
        // A final start after every check has completed always leaves a timer.
        lock.lock(); sessionLive = true; lock.unlock()
        watch.sessionStarted { FakeTimer(id: -1) }
        XCTAssertNil(watch.stopIfIdle { true })
        XCTAssertTrue(watch.isActive)
    }
}
