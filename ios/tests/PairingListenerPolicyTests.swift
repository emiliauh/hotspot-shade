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

        // A complete observation that names another interface at the same
        // address is a bridge replacement, not continued presence. A listener
        // bound to the old link stops at once. No absence interval is needed.
        var linkNow: HotspotInterface.LinkObservation? = .present(
            HotspotInterface.Identity(name: "bridge100", address: "hotspot"))
        var replaced = PairingListenerPolicy(clock: { now }, latestLink: { linkNow })
        precondition(replaced.observe(.present("hotspot"), listening: false, pollInterval: 2) == .start("hotspot"))
        replaced.ready()
        precondition(replaced.lastStopCause == nil)
        linkNow = .present(HotspotInterface.Identity(name: "bridge101", address: "hotspot"))
        now += 2
        precondition(replaced.observe(.present("hotspot"), listening: true, pollInterval: 2) == .stop)
        precondition(replaced.lastStopCause == .linkChanged)
        // A stale listener that reports itself down cannot stop twice. The next
        // complete observation may bind a fresh listener to the new link.
        now += 2
        precondition(replaced.observe(.present("hotspot"), listening: false, pollInterval: 2) == .start("hotspot"))
        precondition(replaced.lastStopCause == nil)
        replaced.ready()
        precondition(replaced.observe(.present("hotspot"), listening: true, pollInterval: 2) == .none)

        // The same address on an unsupported link is a known mismatch. The
        // legacy observation reports it as absent, but the identity store lets
        // the policy stop the stale listener at once.
        linkNow = .unsupported(HotspotInterface.Identity(name: "en0", address: "hotspot"))
        now += 2
        precondition(replaced.observe(.absent, listening: true, pollInterval: 2) == .stop)
        precondition(replaced.lastStopCause == .unsupportedLink)
        // With no listener, an unsupported link never starts one.
        now += 2
        precondition(replaced.observe(.present("hotspot"), listening: false, pollInterval: 2) == .none)
        precondition(replaced.lastStopCause == .unsupportedLink)

        // A missing address still needs the full absence interval and reports
        // its own cause.
        linkNow = nil
        var absent = PairingListenerPolicy(clock: { now }, latestLink: { linkNow })
        precondition(absent.observe(.present("hotspot"), listening: false, pollInterval: 2) == .start("hotspot"))
        absent.ready()
        for _ in 0..<15 {
            precondition(absent.observe(.absent, listening: true, pollInterval: 2) == .none)
            now += 2
        }
        precondition(absent.observe(.absent, listening: true, pollInterval: 2) == .stop)
        precondition(absent.lastStopCause == .absent)

        // Without an identity record, the policy keeps the old address-only
        // behavior. A same-address check cannot claim a replacement.
        var fallback = PairingListenerPolicy(clock: { now }, latestLink: { nil })
        precondition(fallback.observe(.present("hotspot"), listening: false, pollInterval: 2) == .start("hotspot"))
        fallback.ready()
        precondition(fallback.observe(.present("hotspot"), listening: true, pollInterval: 2) == .none)
        precondition(fallback.lastStopCause == nil)

        // The production path records the identity-aware observation and lets
        // the policy read the latest one. This is the seam that carries the
        // identity through the address-only pairing call.
        let productionAddress = "172.20.10.1"
        HotspotInterface.recordLinkObservation(.present(
            HotspotInterface.Identity(name: "bridge100", address: productionAddress)))
        var production = PairingListenerPolicy(clock: { now })
        precondition(production.observe(.present(productionAddress), listening: false, pollInterval: 2)
                     == .start(productionAddress))
        production.ready()
        precondition(production.observe(.present(productionAddress), listening: true, pollInterval: 2) == .none)
        HotspotInterface.recordLinkObservation(.present(
            HotspotInterface.Identity(name: "bridge101", address: productionAddress)))
        now += 2
        precondition(production.observe(.present(productionAddress), listening: true, pollInterval: 2) == .stop)
        precondition(production.lastStopCause == .linkChanged)
        HotspotInterface.recordLinkObservation(.unreadable)

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

        // Pairing sockets with no complete frame are idle slots. The listener
        // closes one after the first-frame bound and evicts the oldest one to
        // admit a new connection.
        precondition(PairingConnectionSlots.firstFrameSeconds == 10)
        var slots = PairingConnectionSlots(maximum: 4)
        precondition(slots.admit(0, protected: nil) == .accept)
        precondition(slots.admit(1, protected: nil) == .accept)
        precondition(slots.admit(2, protected: nil) == .accept)
        precondition(slots.admit(3, protected: nil) == .accept)
        precondition(slots.connections == [0, 1, 2, 3])
        precondition(slots.waiting == [0, 1, 2, 3])
        precondition(slots.isWaiting(0))
        // The fifth socket evicts the oldest idle socket.
        precondition(slots.admit(4, protected: nil) == .evict(0))
        precondition(slots.connections == [1, 2, 3, 4])
        // A complete frame leaves the idle set. The responder owns its deadline.
        slots.receivedFrame(1)
        precondition(!slots.isWaiting(1))
        slots.receivedFrame(1)
        precondition(!slots.isWaiting(1))
        // The next eviction skips the socket that already sent a frame.
        precondition(slots.admit(5, protected: nil) == .evict(2))
        precondition(slots.connections == [1, 3, 4, 5])

        // A live prompt is never evicted. With every socket active, the oldest
        // non-prompt socket is evicted instead.
        var busy = PairingConnectionSlots(maximum: 3)
        precondition(busy.admit(10, protected: nil) == .accept)
        busy.receivedFrame(10)
        precondition(busy.admit(11, protected: nil) == .accept)
        busy.receivedFrame(11)
        precondition(busy.admit(12, protected: nil) == .accept)
        busy.receivedFrame(12)
        precondition(busy.admit(13, protected: 11) == .evict(10))
        precondition(busy.connections == [11, 12, 13])

        // Only the protected prompt remains: refuse the new socket.
        var onlyPrompt = PairingConnectionSlots(maximum: 1)
        precondition(onlyPrompt.admit(20, protected: nil) == .accept)
        onlyPrompt.receivedFrame(20)
        precondition(onlyPrompt.admit(21, protected: 20) == .refuse)
        precondition(onlyPrompt.connections == [20])

        // A closed socket leaves the table and frees its slot.
        onlyPrompt.remove(20)
        precondition(onlyPrompt.connections.isEmpty)
        precondition(onlyPrompt.waiting.isEmpty)
        precondition(onlyPrompt.admit(22, protected: nil) == .accept)

        print("Pairing listener policy tests passed")
    }
}
