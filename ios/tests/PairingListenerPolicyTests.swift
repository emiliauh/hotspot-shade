import Foundation

@main
struct PairingListenerPolicyTests {
    static func main() {
        var now: TimeInterval = 0
        var policy = PairingListenerPolicy(clock: { now })
        precondition(policy.observe(.absent, listening: false, pollInterval: 2) == .none)
        precondition(policy.observe(.present("hotspot"), listening: false, pollInterval: 2) == .start("hotspot"))
        precondition(policy.failed() == PairingListenerPolicy.failureMessage)
        // A failed bind waits 10 seconds before the next attempt.
        now = 9.9
        precondition(policy.observe(.present("hotspot"), listening: false, pollInterval: 2) == .none)
        now = 10
        precondition(policy.observe(.present("hotspot"), listening: false, pollInterval: 2) == .start("hotspot"))
        precondition(policy.failed() == nil)
        // The second failure counts no new activity entry, but it still waits.
        now = 15
        precondition(policy.observe(.present("hotspot"), listening: false, pollInterval: 2) == .none)
        now = 20
        precondition(policy.observe(.present("hotspot"), listening: false, pollInterval: 2) == .start("hotspot"))
        policy.ready()
        for _ in 0..<100 { precondition(policy.observe(.absent, listening: true, pollInterval: 2) == .none) }
        precondition(policy.observe(.unreadable, listening: true, pollInterval: 2) == .none)
        for _ in 0..<15 {
            precondition(policy.observe(.absent, listening: true, pollInterval: 2) == .none)
            now += 2
        }
        precondition(policy.observe(.absent, listening: true, pollInterval: 2) == .stop)
        precondition(policy.observe(.present("hotspot"), listening: false, pollInterval: 2) == .start("hotspot"))
        policy.ready()
        for _ in 0..<14 {
            precondition(policy.observe(.absent, listening: true, pollInterval: 2) == .none)
            now += 2
        }
        precondition(policy.observe(.present("hotspot"), listening: true, pollInterval: 2) == .none)
        precondition(policy.observe(.absent, listening: true, pollInterval: 2) == .none)

        // Unreadable results, long gaps, and scene changes reset the evidence.
        now += 28
        precondition(policy.observe(.absent, listening: true, pollInterval: 2) == .none)
        now += 2
        precondition(policy.observe(.unreadable, listening: true, pollInterval: 2) == .none)
        precondition(policy.observe(.absent, listening: true, pollInterval: 2) == .none)
        policy.resetObservations()
        for _ in 0..<15 {
            precondition(policy.observe(.present("new-hotspot"), listening: true, pollInterval: 2) == .none)
            now += 2
        }
        precondition(policy.observe(.present("new-hotspot"), listening: true, pollInterval: 2) == .stop)

        var slow = PairingListenerPolicy(clock: { now })
        _ = slow.observe(.present("hotspot"), listening: false, pollInterval: 5)
        for _ in 0..<15 {
            precondition(slow.observe(.absent, listening: true, pollInterval: 5) == .none)
            now += 5
        }
        precondition(slow.observe(.absent, listening: true, pollInterval: 5) == .stop)

        var interrupted = PairingListenerPolicy(clock: { now })
        _ = interrupted.observe(.present("hotspot"), listening: false, pollInterval: 2)
        for _ in 0..<15 {
            precondition(interrupted.observe(.absent, listening: true, pollInterval: 2) == .none)
            now += 2
        }
        precondition(interrupted.observe(.unreadable, listening: true, pollInterval: 2) == .none)
        precondition(interrupted.observe(.absent, listening: true, pollInterval: 2) == .none)
        now -= 1
        precondition(interrupted.observe(.absent, listening: true, pollInterval: 2) == .none)
        now += 30
        precondition(interrupted.observe(.absent, listening: true, pollInterval: 2) == .none)

        // An existing listener is not replaced while it starts or waits.
        var stale = PairingListenerPolicy(clock: { now })
        precondition(stale.observe(.present("hotspot"), listening: false, pollInterval: 2) == .start("hotspot"))
        stale.ready()
        precondition(stale.observe(.present("hotspot"), listening: true, pollInterval: 2) == .none)
        precondition(stale.observe(.present("hotspot"), listening: true, pollInterval: 2) == .none)
        // Once the grace expires and the listener fails, retry waits 10 seconds.
        precondition(stale.failed() == PairingListenerPolicy.failureMessage)
        precondition(stale.observe(.present("hotspot"), listening: false, pollInterval: 2) == .none)
        now += PairingListenerPolicy.retrySeconds
        precondition(stale.observe(.present("hotspot"), listening: false, pollInterval: 2) == .start("hotspot"))

        var grace = PairingListenerGrace()
        grace.begin(now: 100)
        grace.begin(now: 102)
        precondition(grace.deadline == 105)
        precondition(!grace.expire(now: 104.9))
        grace.clear() // The listener became ready or the scene became inactive.
        precondition(!grace.expire(now: 110))
        grace.begin(now: 110)
        precondition(!grace.expire(now: 114.9))
        precondition(grace.expire(now: 115))
        precondition(!grace.expire(now: 116))
        grace.begin(now: 120)
        grace.clear()
        grace.begin(now: 130)
        precondition(!grace.expire(now: 125))
        precondition(grace.expire(now: 135))

        // A stale listener does not stop twice when the hotspot disappears.
        var gone = PairingListenerPolicy(clock: { now })
        _ = gone.observe(.present("hotspot"), listening: false, pollInterval: 2)
        for _ in 0..<16 {
            _ = gone.observe(.absent, listening: false, pollInterval: 2)
            now += 2
        }
        precondition(gone.observe(.present("hotspot"), listening: false, pollInterval: 2) == .start("hotspot"))

        // The poll runs only while the app is active.
        precondition(HotspotPoll.interval(proxyRunning: false, active: true) == 5)
        precondition(HotspotPoll.interval(proxyRunning: true, active: true) == 2)
        precondition(HotspotPoll.interval(proxyRunning: false, active: false) == nil)
        precondition(HotspotPoll.interval(proxyRunning: true, active: false) == nil)
        precondition(HotspotPoll.stoppedSeconds == 5 && HotspotPoll.runningSeconds == 2)
        print("Pairing listener policy tests passed")
    }
}
