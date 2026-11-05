import Foundation

@main
struct SessionCapacityTests {
    static func check(_ condition: Bool, _ message: String, line: Int = #line) {
        if !condition {
            print("FAIL line \(line): \(message)")
            exit(1)
        }
    }

    static func id(_ last: String) -> UUID {
        UUID(uuidString: "00000000-0000-0000-0000-0000000000\(last)")!
    }

    static func idle(_ value: UUID, _ seconds: TimeInterval) -> SessionCapacity.IdleSession {
        SessionCapacity.IdleSession(id: value, idleSeconds: seconds)
    }

    static func numbered(_ value: Int) -> UUID {
        UUID(uuidString: String(format: "00000000-0000-0000-0000-%012X", value))!
    }

    static func session(_ value: UUID, _ phase: SessionCapacity.Phase,
                        phaseSeconds: TimeInterval = 0,
                        idleSeconds: TimeInterval = 0,
                        protected: Bool = false) -> SessionCapacity.PhaseSession {
        SessionCapacity.PhaseSession(id: value, phase: phase,
                                     phaseSeconds: phaseSeconds,
                                     idleSeconds: idleSeconds,
                                     protectedFromCapacity: protected)
    }

    static func admission(_ request: SessionCapacity.Request,
                          _ sessions: [SessionCapacity.PhaseSession],
                          limit: Int = SessionCapacity.maximumSessions)
        -> SessionCapacity.Admission {
        SessionCapacity.admission(
            for: request,
            occupancy: SessionCapacity.Occupancy(sessions: sessions, limit: limit))
    }

    static func presence(_ sessions: [SessionCapacity.PhaseSession],
                         limit: Int = SessionCapacity.maximumSessions)
        -> SessionCapacity.Presence {
        SessionCapacity.presenceCapacity(
            occupancy: SessionCapacity.Occupancy(sessions: sessions, limit: limit))
    }

    static func openRelays(_ range: Range<Int>) -> [SessionCapacity.PhaseSession] {
        range.map {
            session(numbered($0), .openTCP, phaseSeconds: 10_000, idleSeconds: 10_000)
        }
    }

    static func handshakes(_ range: Range<Int>,
                           phaseSeconds: TimeInterval = 1)
        -> [SessionCapacity.PhaseSession] {
        range.map { session(numbered($0), .handshake, phaseSeconds: phaseSeconds) }
    }

    static func main() {
        check(SessionCapacity.maximumRelays == 256, "the relay cap keeps 256")
        check(SessionCapacity.handshakeSlots == 32, "the setup reserve is 32")
        check(SessionCapacity.maximumSessions == 288, "the total is 288")
        check(SessionCapacity.idleEvictionSeconds == 30, "the idle window is 30 s")
        check(FileDescriptorLimit.ceiling == 4096, "the file limit ceiling")

        let a = id("0A")
        let b = id("0B")
        let c = id("0C")

        // Under the cap: accept.
        check(SessionCapacity.decision(sessionCount: 0, idle: []) == .accept, "empty")
        check(SessionCapacity.decision(sessionCount: 287, idle: [idle(a, 600)]) == .accept,
              "one free slot accepts")

        // At the cap: refuse unless a session was idle for longer than 30 s.
        check(SessionCapacity.decision(sessionCount: 288, idle: []) == .refuse, "full with no session")
        check(SessionCapacity.decision(sessionCount: 288, idle: [idle(a, 0), idle(b, 29.9)]) == .refuse,
              "a short idle time does not evict")
        check(SessionCapacity.decision(sessionCount: 288, idle: [idle(a, 30)]) == .refuse,
              "exactly 30 s is not longer than 30 s")
        check(SessionCapacity.decision(sessionCount: 300, idle: [idle(a, 1)]) == .refuse,
              "over the cap with a busy session refuses")

        // At the cap: evict the longest idle time.
        check(SessionCapacity.decision(sessionCount: 288, idle: [idle(a, 5), idle(b, 90), idle(c, 600)])
                == .evict(c), "the longest idle time wins")
        check(SessionCapacity.decision(sessionCount: 288, idle: [idle(a, 30.001)]) == .evict(a),
              "a session over the window is evicted")
        check(SessionCapacity.decision(sessionCount: 288, idle: [idle(a, 600), idle(b, 40)]) == .evict(a),
              "a busy session older than an idle one does not win")

        // A tie uses the lowest identifier, so the choice is stable.
        check(SessionCapacity.decision(sessionCount: 288, idle: [idle(c, 90), idle(b, 90)]) == .evict(b),
              "tie uses the lowest identifier")
        check(SessionCapacity.decision(sessionCount: 288, idle: [idle(b, 90), idle(c, 90)]) == .evict(b),
              "tie is independent of the order")

        // The idle timer: traffic arms one timer, not one timer per chunk.
        var idle = SessionIdleTimer(limit: 300)
        var arms = 0
        for _ in 0..<100_000 where idle.touch() { arms += 1 }
        check(arms == 1, "100000 chunks arm one idle timer")
        check(idle.armed, "the one timer stays armed")
        check(!idle.touch(), "traffic while armed does not arm a second timer")
        // A check that finds recent traffic keeps the timer armed.
        check(idle.fired(idle: 5) == .rearm(after: 295), "an active session checks again later")
        check(idle.armed, "the rearmed timer counts as armed")
        check(!idle.touch(), "a touch after a rearm does not arm another timer")
        // An idle session closes at the limit.
        check(idle.fired(idle: 300) == .close, "the idle limit closes")
        check(!idle.armed, "a closed session has no timer")
        var exact = SessionIdleTimer(limit: 300)
        _ = exact.touch()
        check(exact.fired(idle: 299.9) == .rearm(after: 1), "the rearm has a one second floor")
        var late = SessionIdleTimer(limit: 300)
        _ = late.touch()
        check(late.fired(idle: 3_600) == .close, "a late timer closes")
        var stopped = SessionIdleTimer(limit: 300)
        _ = stopped.touch()
        stopped.disarm()
        check(!stopped.armed, "a closed session disarms its timer")
        check(stopped.touch(), "a later touch can arm a timer again")
        // A long active session keeps one timer across many checks. This is
        // the upload case: traffic never creates a timer, and an active
        // session never closes.
        var long = SessionIdleTimer(limit: 300)
        check(long.touch(), "the first traffic arms the one timer")
        for _ in 0..<100 {
            check(long.fired(idle: 60) == .rearm(after: 240), "an active session checks again")
            check(!long.touch(), "traffic keeps the one timer")
        }
        check(long.armed, "the long active session still has one timer")

        // The file descriptor decision: min(hard, 4096), never lower the soft limit.
        check(FileDescriptorLimit.decision(soft: 256, hard: 1000) == .raise(to: 1000),
              "raise to the hard limit")
        check(FileDescriptorLimit.decision(soft: 256, hard: 10_000) == .raise(to: 4096),
              "raise to the ceiling")
        check(FileDescriptorLimit.decision(soft: 4096, hard: 10_000) == .unchanged(soft: 4096),
              "already at the ceiling")
        check(FileDescriptorLimit.decision(soft: 5000, hard: 10_000) == .unchanged(soft: 5000),
              "never lower a high soft limit")
        check(FileDescriptorLimit.decision(soft: 256, hard: Int.max) == .raise(to: 4096),
              "an unlimited hard limit uses the ceiling")
        check(FileDescriptorLimit.decision(soft: 256, hard: 128) == .unchanged(soft: 256),
              "a hard limit below the soft limit changes nothing")
        check(FileDescriptorLimit.decision(soft: 0, hard: 0) == .unchanged(soft: 0),
              "a zero limit changes nothing")

        // The plain outcome text.
        check(FileDescriptorLimit.Outcome.raised(soft: 4096).text == "File limit: 4096, raised.",
              "raised text")
        check(FileDescriptorLimit.Outcome.alreadyHigh(soft: 256).text == "File limit: 256, already high.",
              "already high text")
        check(FileDescriptorLimit.Outcome.refused(soft: 256).text == "File limit: 256, could not raise.",
              "refused text")

        // MARK: Phase-aware policy

        check(SessionCapacity.handshakePhaseSeconds == 30, "the handshake bound")
        check(SessionCapacity.connectPhaseSeconds == 8, "the connect bound")
        check(SessionCapacity.relayGrantPhaseSeconds == 2, "the relay request bound")
        check(SessionCapacity.relayIdleSeconds == 300, "the relay idle bound")
        check(SessionCapacity.openTCPRecheckSeconds == 300, "the open relay recheck")
        check(SessionCapacity.Phase.allCases.count == 6, "six phases")
        check(SessionCapacity.Phase.handshake.isSetup, "a handshake is setup")
        check(SessionCapacity.Phase.connecting.isSetup, "a connect is setup")
        check(SessionCapacity.Phase.awaitingRelay.isSetup, "a relay wait is setup")
        check(SessionCapacity.Phase.openTCP.isRelay, "an open relay is a relay")
        check(SessionCapacity.Phase.udp.isRelay, "UDP is a relay")
        check(SessionCapacity.Phase.halfClosed.isRelay, "a half-closed flow is a relay")

        // Phase selection. A presence probe authenticates and sends no
        // complete request, so it stays in the setup phase.
        check(SessionCapacity.phase(authenticated: false, requestComplete: false,
                                    destinationReady: false, datagram: false,
                                    halfClosed: false) == .handshake,
              "an unauthenticated session is in the handshake phase")
        check(SessionCapacity.phase(authenticated: true, requestComplete: false,
                                    destinationReady: false, datagram: false,
                                    halfClosed: false) == .handshake,
              "a presence probe is in the handshake phase")
        check(SessionCapacity.phase(authenticated: true, requestComplete: true,
                                    destinationReady: false, datagram: false,
                                    halfClosed: false) == .connecting,
              "a complete request waits in the connect phase")
        check(SessionCapacity.phase(authenticated: true, requestComplete: true,
                                    destinationReady: true, datagram: false,
                                    halfClosed: false) == .openTCP,
              "a ready TCP relay is open")
        check(SessionCapacity.phase(authenticated: true, requestComplete: true,
                                    destinationReady: true, datagram: true,
                                    halfClosed: false) == .udp,
              "a ready datagram flow is UDP")
        check(SessionCapacity.phase(authenticated: true, requestComplete: true,
                                    destinationReady: true, datagram: false,
                                    halfClosed: true) == .halfClosed,
              "a finished TCP direction is half-closed")

        // The limits follow the real file descriptor limit. Each session is
        // budgeted 3 sockets in each of 3 overlapping runs, and the reserve
        // stays proportional.
        check(SessionCapacity.socketsPerSession == 3, "one session can need 3 sockets")
        check(SessionCapacity.overlappingRuns == 3, "a rapid restart can overlap three runs")
        check(SessionCapacity.descriptorsPerSession == 9, "one session reserves 9 files")
        let nominal = SessionCapacity.limits(total: 288)
        check(nominal == SessionCapacity.Limits(total: 288, setupReserve: 32, relay: 256),
              "the nominal split keeps 256 relays")
        let fd24 = SessionCapacity.limits(total: SessionCapacity.sessionLimit(softFileLimit: 256))
        check(fd24 == SessionCapacity.Limits(total: 24, setupReserve: 3, relay: 21),
              "the split follows a lower total")
        let fd16 = SessionCapacity.limits(total: 16)
        check(fd16 == SessionCapacity.Limits(total: 16, setupReserve: 2, relay: 14),
              "a small total keeps a small reserve")
        check(SessionCapacity.limits(total: 2)
                == SessionCapacity.Limits(total: 2, setupReserve: 1, relay: 1),
              "a two-slot total keeps one setup slot")
        check(SessionCapacity.limits(total: 1)
                == SessionCapacity.Limits(total: 1, setupReserve: 0, relay: 1),
              "one slot goes to a relay")
        check(SessionCapacity.limits(total: 0)
                == SessionCapacity.Limits(total: 0, setupReserve: 0, relay: 0),
              "zero slots")
        check(SessionCapacity.limits(total: 1000).total == 288, "the total is clamped high")
        check(SessionCapacity.limits(total: -5).total == 0, "the total is clamped low")

        check(SessionCapacity.sessionLimit(softFileLimit: 4096) == 288, "4096 gives the cap")
        check(SessionCapacity.sessionLimit(softFileLimit: 100_000) == 288,
              "the cap is the maximum")
        check(SessionCapacity.sessionLimit(softFileLimit: 1024) == 110,
              "1024 gives 110 sessions")
        check(SessionCapacity.sessionLimit(softFileLimit: 512) == 53, "512 gives 53 sessions")
        check(SessionCapacity.sessionLimit(softFileLimit: 256) == 24, "256 gives 24 sessions")
        check(SessionCapacity.sessionLimit(softFileLimit: 64) == 3, "64 gives 3 sessions")
        check(SessionCapacity.sessionLimit(softFileLimit: 41) == 1,
              "41 gives one session")
        check(SessionCapacity.sessionLimit(softFileLimit: 40) == 0,
              "40 leaves no session")
        check(SessionCapacity.sessionLimit(softFileLimit: 32) == 0,
              "the reserve leaves no session")
        check(SessionCapacity.sessionLimit(softFileLimit: 33) == 0,
              "one usable descriptor gives no session")
        check(SessionCapacity.sessionLimit(softFileLimit: -1) == 0,
              "a negative limit gives no session")
        // One full run plus two previous runs fits at 4096. This is the
        // rapid stop/restart headroom that the limit assumes.
        check(SessionCapacity.descriptorFootprint(total: 288, previousRuns: [288, 288]) == 2_624,
              "the three-run footprint at the cap")
        check(SessionCapacity.descriptorFootprint(total: 288, previousRuns: [288, 288]) <= 4096,
              "the three-run footprint fits the raised limit")
        check(SessionCapacity.descriptorFootprint(total: 288, previousRuns: []) == 896,
              "one run fits with no previous run")
        check(FileDescriptorLimit.Outcome.raised(soft: 4096).softLimit == 4096,
              "the raised soft limit")
        check(FileDescriptorLimit.Outcome.refused(soft: 256).softLimit == 256,
              "a refused change keeps the soft limit")
        check(SessionCapacity.sessionLimit(fileLimit: .raised(soft: 4096)) == 288,
              "the outcome gives the limit")
        check(SessionCapacity.sessionLimit(fileLimit: nil) == nil,
              "an unknown limit stays unknown")

        // Availability is explicit. A low or unknown limit cannot listen.
        check(SessionCapacity.availability(softFileLimit: 4096)
                == .ready(SessionCapacity.Limits(total: 288, setupReserve: 32, relay: 256)),
              "4096 is ready")
        check(SessionCapacity.availability(softFileLimit: 32)
                == .tooLow(softFileLimit: 32), "32 is too low")
        check(!SessionCapacity.availability(softFileLimit: 32).isUsable,
              "a too-low limit is not usable")
        check(SessionCapacity.availability(fileLimit: nil) == .unknownFileLimit,
              "an unknown limit is explicit")
        check(!SessionCapacity.availability(fileLimit: nil).isUsable,
              "an unknown limit is not usable")
        check(SessionCapacity.availability(fileLimit: .refused(soft: 64))
                == .ready(SessionCapacity.Limits(total: 3, setupReserve: 1, relay: 2)),
              "a refused raise can still give a small limit")
        check(!SessionCapacity.availability(fileLimit: nil).startFailureMessage.isEmpty,
              "an unknown limit has a plain reason")
        check(SessionCapacity.availability(fileLimit: nil).startFailureMessage
                .contains("open-file"), "the reason names the open-file limit")

        // Phase bounds. An open TCP relay has no silence bound. A handshake
        // uses the phase age, so dribbled bytes cannot extend it.
        let open = session(a, .openTCP, phaseSeconds: 86_400, idleSeconds: 86_400)
        check(SessionCapacity.closeReason(for: open) == nil,
              "an open relay has no close reason")
        check(SessionCapacity.staleSession(in: [open]) == nil,
              "silence never selects an open relay")
        check(SessionCapacity.closeReason(for: session(a, .handshake, phaseSeconds: 29.9)) == nil,
              "a fresh handshake is retained")
        check(SessionCapacity.closeReason(for: session(a, .handshake, phaseSeconds: 30))
                == .handshakeExpired, "the handshake bound closes")
        check(SessionCapacity.closeReason(for: session(a, .handshake, phaseSeconds: 31,
                                                       idleSeconds: 0)) == .handshakeExpired,
              "the handshake bound uses the phase age, not silence")
        check(SessionCapacity.closeReason(for: session(a, .connecting, phaseSeconds: 7.9)) == nil,
              "a fresh connect is retained")
        check(SessionCapacity.closeReason(for: session(a, .connecting, phaseSeconds: 8))
                == .connectExpired, "the connect bound closes")
        check(SessionCapacity.closeReason(for: session(a, .awaitingRelay, phaseSeconds: 1.9)) == nil,
              "a fresh relay wait is retained")
        check(SessionCapacity.closeReason(for: session(a, .awaitingRelay, phaseSeconds: 2))
                == .relayGrantExpired, "the relay request bound closes")
        check(SessionCapacity.closeReason(for: session(a, .awaitingRelay, phaseSeconds: 60,
                                                        idleSeconds: 0)) == .relayGrantExpired,
              "the relay wait bound does not use the old connect time")
        check(SessionCapacity.closeReason(for: session(a, .udp, idleSeconds: 299.9)) == nil,
              "a fresh UDP flow is retained")
        check(SessionCapacity.closeReason(for: session(a, .udp, idleSeconds: 300)) == .udpIdle,
              "the UDP idle bound closes")
        check(SessionCapacity.closeReason(for: session(a, .halfClosed, idleSeconds: 299)) == nil,
              "a fresh half-closed flow is retained")
        check(SessionCapacity.closeReason(for: session(a, .halfClosed, idleSeconds: 300))
                == .halfClosedIdle, "the half-closed idle bound closes")
        check(SessionCapacity.staleSession(in: [
            session(a, .udp, idleSeconds: 0),
            session(b, .halfClosed, idleSeconds: 0),
            session(c, .openTCP, idleSeconds: 86_400)
        ]) == nil, "fresh relay phases are retained")

        // The stale choice is deterministic. It uses the most overdue
        // session, then the lowest identifier.
        let staleHandshake = session(a, .handshake, phaseSeconds: 40)
        let staleConnect = session(b, .connecting, phaseSeconds: 20)
        check(SessionCapacity.staleSession(in: [staleHandshake, staleConnect])?.id == b,
              "the most overdue session wins")
        let tieA = session(b, .udp, idleSeconds: 300)
        let tieB = session(c, .udp, idleSeconds: 300)
        check(SessionCapacity.staleSession(in: [tieA, tieB])?.id == b,
              "a tie uses the lowest identifier")
        check(SessionCapacity.staleSession(in: [tieB, tieA])?.id == b,
              "the tie is independent of the order")
        check(SessionCapacity.staleSession(in: [
            session(a, .handshake, phaseSeconds: 29),
            session(b, .udp, idleSeconds: 299)
        ]) == nil, "a table within the bounds has no stale session")

        // Admission. A session within its bound is never evicted.
        check(admission(.connection, []) == .accept, "an empty table accepts a connection")
        check(admission(.relay, []) == .accept, "an empty table accepts a relay")

        let fullSetup = handshakes(0..<288)
        check(admission(.connection, fullSetup)
                == .refuse(SessionCapacity.Refusal(reason: .totalLimit, affectsPresence: true)),
              "a full setup table refuses a connection")
        var staleSetupTable = fullSetup
        staleSetupTable[0] = session(numbered(0), .handshake, phaseSeconds: 31)
        check(admission(.connection, staleSetupTable)
                == .closeThenAccept(id: numbered(0), reason: .handshakeExpired),
              "a stale handshake frees a slot")

        let fullRelays = openRelays(0..<256)
        check(admission(.connection, fullRelays) == .accept,
              "the relay table has setup headroom")
        let fullHealthy = fullRelays + handshakes(3000..<3032)
        check(admission(.connection, fullHealthy)
                == .refuse(SessionCapacity.Refusal(reason: .totalLimit, affectsPresence: true)),
              "a full healthy table refuses without eviction")

        var atRelayCap = fullRelays + handshakes(3000..<3031)
        atRelayCap.append(session(numbered(5001), .connecting, phaseSeconds: 1))
        check(admission(.relay, atRelayCap)
                == .refuse(SessionCapacity.Refusal(reason: .relayLimit, affectsPresence: false)),
              "a connect at the relay cap never evicts an open relay")

        var underRelayCap = openRelays(0..<255) + handshakes(3000..<3032)
        underRelayCap.append(session(numbered(5001), .connecting, phaseSeconds: 1))
        check(admission(.relay, underRelayCap) == .accept,
              "a free relay slot accepts the connect")

        var withStaleUDP = openRelays(0..<255)
        withStaleUDP.append(session(numbered(5000), .udp, idleSeconds: 301))
        withStaleUDP.append(session(numbered(5001), .connecting, phaseSeconds: 1))
        withStaleUDP.append(contentsOf: handshakes(3000..<3031))
        check(withStaleUDP.count == 288, "the stale UDP table is full")
        check(admission(.relay, withStaleUDP)
                == .closeThenAccept(id: numbered(5000), reason: .udpIdle),
              "a stale UDP flow frees a relay slot")

        var withStaleSetup = fullRelays
        withStaleSetup.append(session(numbered(5000), .handshake, phaseSeconds: 31))
        withStaleSetup.append(session(numbered(5001), .connecting, phaseSeconds: 1))
        withStaleSetup.append(contentsOf: handshakes(3000..<3030))
        check(withStaleSetup.count == 288, "the stale setup table is full")
        check(admission(.relay, withStaleSetup)
                == .refuse(SessionCapacity.Refusal(reason: .relayLimit, affectsPresence: false)),
              "a stale setup session cannot free a relay slot")

        var withStaleRelay = openRelays(0..<255)
        withStaleRelay.append(session(numbered(5000), .udp, idleSeconds: 400))
        withStaleRelay.append(contentsOf: handshakes(3000..<3032))
        check(withStaleRelay.count == 288, "the stale relay table is full")
        check(admission(.connection, withStaleRelay)
                == .closeThenAccept(id: numbered(5000), reason: .udpIdle),
              "a stale relay frees a total slot")

        let fdFull = handshakes(0..<24)
        check(admission(.connection, fdFull, limit: 24)
                == .refuse(SessionCapacity.Refusal(reason: .totalLimit, affectsPresence: true)),
              "the descriptor limit refuses before the nominal cap")
        check(admission(.connection, handshakes(0..<23), limit: 24) == .accept,
              "one free slot under the descriptor limit accepts")

        // Presence. A probe uses a setup slot, so a full relay table leaves
        // the reserve. The reserve is not a guarantee. A setup flood blocks
        // the probe.
        let relayFull = presence(fullRelays)
        check(relayFull.state == .available,
              "a probe can use a setup slot when relays are full")
        check(relayFull.relayCapReached, "the relay cap is reached")
        check(relayFull.freeSetupSlots == 32, "32 setup slots are free")
        check(!relayFull.refusesPossiblePresenceProbe, "a probe can still start")

        let saturated = presence(fullRelays + handshakes(3000..<3032))
        check(saturated.state == .blocked, "unauthenticated saturation blocks a probe")
        check(saturated.freeSetupSlots == 0, "no setup slot is free")
        check(saturated.relayCapReached, "the relay cap is still reached")
        check(saturated.refusesPossiblePresenceProbe, "the refusal can refuse a probe")

        let oneFree = presence(fullRelays + handshakes(3000..<3031))
        check(oneFree.state == .available, "one free setup slot admits a probe")
        check(oneFree.freeSetupSlots == 1, "one setup slot is free")

        var staleProbeSlot = fullRelays + handshakes(3000..<3031)
        staleProbeSlot.append(session(numbered(5000), .handshake, phaseSeconds: 31))
        check(staleProbeSlot.count == 288, "the stale setup table is full")
        check(presence(staleProbeSlot).state == .afterStaleClose,
              "a stale setup session makes room for a probe")

        let unauthFlood = handshakes(0..<288)
        let flooded = presence(unauthFlood)
        check(flooded.state == .blocked, "a setup flood blocks a probe")
        check(!flooded.relayCapReached, "the relay cap is not reached")
        check(flooded.freeSetupSlots == 0, "the setup flood uses every slot")
        let expiredFlood = handshakes(0..<288, phaseSeconds: 31)
        check(presence(expiredFlood).state == .afterStaleClose,
              "the handshake bound releases an expired flood")

        // The idle policy. An open relay is rechecked and never closed.
        check(SessionCapacity.idleAction(phase: .openTCP, phaseSeconds: 86_400,
                                         idleSeconds: 86_400) == .rearm(after: 300),
              "an open relay rearms and never closes")
        // The first check after a phase starts uses the phase bound. A
        // handshake must not wait for the old 300 second timer.
        check(SessionCapacity.idleAction(phase: .handshake, phaseSeconds: 0,
                                         idleSeconds: 0) == .rearm(after: 30),
              "the first handshake check is at 30 seconds")
        check(SessionCapacity.idleAction(phase: .connecting, phaseSeconds: 0,
                                         idleSeconds: 0) == .rearm(after: 8),
              "the first connect check is at 8 seconds")
        check(SessionCapacity.idleAction(phase: .awaitingRelay, phaseSeconds: 0,
                                         idleSeconds: 0) == .rearm(after: 2),
              "the first relay wait check is at 2 seconds")
        check(SessionCapacity.idleAction(phase: .udp, phaseSeconds: 0,
                                         idleSeconds: 0) == .rearm(after: 300),
              "the first UDP check is at 300 seconds")
        check(SessionCapacity.idleAction(phase: .halfClosed, phaseSeconds: 0,
                                         idleSeconds: 0) == .rearm(after: 300),
              "the first half-closed check is at 300 seconds")
        check(SessionCapacity.idleAction(phase: .handshake, phaseSeconds: 10,
                                         idleSeconds: 0) == .rearm(after: 20),
              "a fresh handshake gets the remaining bound")
        check(SessionCapacity.idleAction(phase: .handshake, phaseSeconds: 30,
                                         idleSeconds: 0) == .close(.handshakeExpired),
              "the handshake timer closes at the bound")
        check(SessionCapacity.idleAction(phase: .handshake, phaseSeconds: 29.9,
                                         idleSeconds: 0) == .rearm(after: 1),
              "the rearm keeps a one second floor")
        check(SessionCapacity.idleAction(phase: .connecting, phaseSeconds: 4,
                                         idleSeconds: 4) == .rearm(after: 4),
              "a fresh connect gets the remaining bound")
        check(SessionCapacity.idleAction(phase: .connecting, phaseSeconds: 8,
                                         idleSeconds: 8) == .close(.connectExpired),
              "the connect timer closes at the bound")
        check(SessionCapacity.idleAction(phase: .awaitingRelay, phaseSeconds: 0.5,
                                         idleSeconds: 0.5) == .rearm(after: 1.5),
              "the relay wait gets its remaining bound")
        check(SessionCapacity.idleAction(phase: .awaitingRelay, phaseSeconds: 2,
                                         idleSeconds: 2) == .close(.relayGrantExpired),
              "the relay wait timer closes at the separate bound")
        check(SessionCapacity.idleAction(phase: .udp, phaseSeconds: 100,
                                         idleSeconds: 100) == .rearm(after: 200),
              "a fresh UDP flow gets the remaining idle")
        check(SessionCapacity.idleAction(phase: .udp, phaseSeconds: 100,
                                         idleSeconds: 300) == .close(.udpIdle),
              "the UDP timer closes at the idle bound")
        check(SessionCapacity.idleAction(phase: .halfClosed, phaseSeconds: 100,
                                         idleSeconds: 300) == .close(.halfClosedIdle),
              "the half-closed timer closes at the idle bound")
        check(SessionCapacity.idleAction(phase: .halfClosed, phaseSeconds: 100,
                                         idleSeconds: 299.9) == .rearm(after: 1),
              "the half-closed rearm keeps a one second floor")

        // The one-timer rule still holds for the phase-aware check.
        var openTimer = SessionIdleTimer(limit: 300)
        check(openTimer.touch(), "the first traffic arms one timer")
        for _ in 0..<1_000 {
            check(openTimer.fired(phase: .openTCP, phaseSeconds: 100_000,
                                  idleSeconds: 100_000) == .rearm(after: 300),
                  "an open relay rearms at every check")
        }
        check(openTimer.armed, "the open relay keeps one timer")

        var setupTimer = SessionIdleTimer(limit: 300)
        _ = setupTimer.touch()
        check(setupTimer.fired(phase: .handshake, phaseSeconds: 30,
                               idleSeconds: 0) == .close(.handshakeExpired),
              "the phase timer closes a stale handshake")
        check(!setupTimer.armed, "a closed phase has no timer")
        check(setupTimer.touch(), "a later touch can arm the timer again")

        var udpTimer = SessionIdleTimer(limit: 300)
        _ = udpTimer.touch()
        check(udpTimer.fired(phase: .udp, phaseSeconds: 1_000,
                             idleSeconds: 300) == .close(.udpIdle),
              "the phase timer closes a stale UDP flow")
        check(!udpTimer.armed, "a closed UDP flow has no timer")

        // MARK: Phase tracker

        var tracker = SessionCapacity.PhaseTracker(at: 100)
        check(tracker.phase == .handshake, "a new tracker is a handshake")
        check(tracker.phaseSeconds(at: 130) == 30, "the handshake age")
        check(!tracker.awaitsRelay, "a new tracker awaits nothing")
        check(!tracker.capacityProtected, "a new tracker is not capacity protected")
        check(!tracker.noteHalfClose(at: 130), "a handshake cannot half-close")
        check(!tracker.admitRelay(datagram: false, at: 130),
              "a handshake cannot become an open relay")
        check(tracker.beginConnecting(at: 130), "the handshake becomes a connect")
        check(!tracker.beginConnecting(at: 131), "the connect start is recorded once")
        check(tracker.phaseSeconds(at: 136) == 6, "the connect age")
        check(!tracker.noteHalfClose(at: 136), "a connect cannot half-close")
        check(!tracker.admitRelay(datagram: false, at: 136),
              "a connect without a relay request cannot open a relay")
        check(tracker.beginAwaitingRelay(at: 136), "the connect asks for a relay slot")
        check(tracker.awaitsRelay, "the request is visible")
        check(tracker.phase == .awaitingRelay, "the relay wait is its own phase")
        check(tracker.phaseSeconds(at: 137.5) == 1.5,
              "the relay wait has its own age")
        check(tracker.capacityProtected, "a pending relay is capacity protected")
        check(!tracker.beginAwaitingRelay(at: 137), "one relay request only")
        check(tracker.denyRelay(at: 137), "the server can deny the relay request")
        check(!tracker.awaitsRelay && tracker.relayRefused
                && tracker.phase == .connecting,
              "a denial keeps the connect phase and the protection")
        check(tracker.capacityProtected, "a refusal in flight is capacity protected")
        check(!tracker.admitRelay(datagram: false, at: 138),
              "a denied request does not open a relay")
        var grantTracker = SessionCapacity.PhaseTracker(at: 100)
        _ = grantTracker.beginConnecting(at: 130)
        check(grantTracker.beginAwaitingRelay(at: 131), "the relay request starts")
        check(grantTracker.phase == .awaitingRelay, "the request waits in its own phase")
        check(grantTracker.admitRelay(datagram: false, at: 132.5),
              "the granted slot opens the TCP relay")
        check(grantTracker.phase == .openTCP && !grantTracker.awaitsRelay
                && !grantTracker.relayRefused && !grantTracker.capacityProtected,
              "the open relay clears the request")
        check(grantTracker.phaseSeconds(at: 134.5) == 2, "the open phase age")
        check(grantTracker.noteHalfClose(at: 141), "an open TCP relay can half-close")
        check(grantTracker.phase == .halfClosed, "the half-closed phase")
        check(!grantTracker.admitRelay(datagram: false, at: 142),
              "a half-closed relay does not reopen")
        check(!grantTracker.noteHalfClose(at: 142), "the half-close is recorded once")
        var replyTracker = SessionCapacity.PhaseTracker(at: 0)
        _ = replyTracker.beginConnecting(at: 1)
        replyTracker.beginReply()
        check(replyTracker.capacityProtected, "a reply in flight is protected")
        check(!replyTracker.beginAwaitingRelay(at: 1),
              "a reply in flight cannot ask for a relay slot")
        check(!replyTracker.admitRelay(datagram: false, at: 2),
              "a reply in flight cannot open a relay")
        replyTracker.finishReply()
        check(!replyTracker.capacityProtected, "a sent success releases the protection")
        var echoTracker = SessionCapacity.PhaseTracker(at: 0)
        echoTracker.beginControl()
        check(echoTracker.capacityProtected, "an ICMP command is protected")
        check(!echoTracker.beginConnecting(at: 1),
              "an ICMP command does not become a connect")
        check(!echoTracker.beginAwaitingRelay(at: 1),
              "an ICMP command does not ask for a relay slot")
        var udpTracker = SessionCapacity.PhaseTracker(at: 0)
        _ = udpTracker.beginConnecting(at: 1)
        check(udpTracker.beginAwaitingRelay(at: 1), "the UDP relay request starts")
        check(udpTracker.admitRelay(datagram: true, at: 2), "the UDP relay opens")
        check(udpTracker.phase == .udp, "the UDP phase")
        check(!udpTracker.noteHalfClose(at: 3), "UDP has no half close")

        // A session that waits for a relay slot is not a stale capacity
        // candidate. Its own relay request bound still applies. The same
        // protection covers a refused request and a final SOCKS reply in
        // flight.
        let awaiting = session(numbered(6000), .awaitingRelay, phaseSeconds: 60,
                               protected: true)
        check(SessionCapacity.closeReason(for: awaiting) == .relayGrantExpired,
              "the relay request bound applies to a pending relay")
        check(SessionCapacity.staleSession(in: [awaiting]) == nil,
              "capacity never selects a pending relay")
        let protectedTable = openRelays(0..<256) + handshakes(7000..<7030)
            + [awaiting, session(numbered(7200), .handshake, phaseSeconds: 40)]
        check(protectedTable.count == 288, "the protected table is full")
        check(admission(.connection, protectedTable)
                == .closeThenAccept(id: numbered(7200), reason: .handshakeExpired),
              "a protected session is skipped while another stale session closes")
        let protectedStaleRelay = openRelays(0..<255)
            + [session(numbered(6500), .halfClosed, idleSeconds: 400, protected: true)]
        check(SessionCapacity.admission(
                for: .relay,
                occupancy: SessionCapacity.Occupancy(
                    sessions: protectedStaleRelay,
                    limit: SessionCapacity.maximumSessions))
                == .refuse(SessionCapacity.Refusal(reason: .relayLimit,
                                                   affectsPresence: false)),
              "a protected stale relay is not closed for capacity")

        // MARK: Relay reservations

        let reservedID = numbered(8000)
        let reservedTable = openRelays(0..<255)
            + [session(reservedID, .awaitingRelay, phaseSeconds: 1, protected: true)]
        let reservedOccupancy = SessionCapacity.Occupancy(
            sessions: reservedTable, limit: SessionCapacity.maximumSessions,
            reservedRelays: [reservedID])
        check(reservedOccupancy.relayCount == 256,
              "a reserved slot counts as a relay")
        check(reservedOccupancy.setupCount == 0,
              "a reserved relay is not a setup session")
        check(reservedOccupancy.relayCount + reservedOccupancy.setupCount
                == reservedTable.count, "the split adds up")
        let missingReservation = SessionCapacity.Occupancy(
            sessions: openRelays(0..<10), limit: SessionCapacity.maximumSessions,
            reservedRelays: [reservedID])
        check(missingReservation.relayCount == 10,
              "a reservation for a missing session is ignored")
        let observedReservation = SessionCapacity.Occupancy(
            sessions: openRelays(0..<256), limit: SessionCapacity.maximumSessions,
            reservedRelays: [numbered(0)])
        check(observedReservation.relayCount == 256,
              "an observed relay is not counted twice")
        check(SessionCapacity.admission(for: .relay, occupancy: reservedOccupancy)
                == .refuse(SessionCapacity.Refusal(reason: .relayLimit,
                                                   affectsPresence: false)),
              "a full relay table refuses without closing a reserved slot")

        var book = SessionCapacity.RelayBook()
        check(book.isEmpty, "a new relay book is empty")
        let first = numbered(8100)
        check(book.begin(first), "one request starts")
        check(book.pending == [first], "the request waits")
        check(!book.begin(first), "a duplicate request is refused")
        book.grant(first)
        check(book.reserved == [first] && book.pending.isEmpty,
              "a grant reserves the slot")
        check(!book.begin(first), "a reserved slot is not requested again")
        book.release(first)
        check(book.isEmpty, "a close releases the slot")
        check(book.begin(first), "a later request can reuse the slot")
        book.deny(first)
        check(book.isEmpty, "a denial releases the request")
        check(book.begin(first), "a denied session can ask again")
        book.grant(first)
        book.reconcile(with: [session(first, .openTCP)])
        check(book.isEmpty, "the reported relay phase replaces the reservation")
        check(book.begin(first), "a new request starts again")
        book.grant(first)
        book.reconcile(with: [])
        check(book.isEmpty, "a reservation for a missing session is dropped")
        check(book.begin(first), "a pending request stays pending")
        book.reconcile(with: [session(first, .connecting, protected: true)])
        check(book.pending == [first], "a present pending request stays")
        book.release(first)

        // MARK: A capacity sequence that mirrors the server

        var table = openRelays(0..<255)
        table.append(session(numbered(9000), .udp, idleSeconds: 301))
        var liveBook = SessionCapacity.RelayBook()
        let x = numbered(9001)
        check(liveBook.begin(x), "the server starts one relay request")
        var live = liveBook.occupancy(sessions: table,
                                      limit: SessionCapacity.maximumSessions)
        check(SessionCapacity.admission(for: .relay, occupancy: live)
                == .closeThenAccept(id: numbered(9000), reason: .udpIdle),
              "a stale UDP flow frees one relay slot")
        table.removeAll { $0.id == numbered(9000) }
        table.append(session(x, .awaitingRelay, phaseSeconds: 0.2, protected: true))
        liveBook.grant(x)
        live = liveBook.occupancy(sessions: table,
                                  limit: SessionCapacity.maximumSessions)
        check(live.relayCount == 256, "the table stays at the relay cap")
        let y = numbered(9002)
        check(liveBook.begin(y), "a second relay request starts")
        live = liveBook.occupancy(sessions: table,
                                  limit: SessionCapacity.maximumSessions)
        check(SessionCapacity.admission(for: .relay, occupancy: live)
                == .refuse(SessionCapacity.Refusal(reason: .relayLimit,
                                                   affectsPresence: false)),
              "the reserved slot is not granted twice")
        liveBook.deny(y)
        live = liveBook.occupancy(sessions: table,
                                  limit: SessionCapacity.maximumSessions)
        check(SessionCapacity.admission(for: .connection, occupancy: live) == .accept,
              "a probe can still take a setup slot at the relay cap")
        check(SessionCapacity.presenceCapacity(occupancy: live).state == .available,
              "presence is available while setup slots remain")
        table.append(contentsOf: handshakes(9100..<9132))
        live = liveBook.occupancy(sessions: table,
                                  limit: SessionCapacity.maximumSessions)
        check(live.sessions.count == 288, "the setup reserve fills the table")
        check(SessionCapacity.admission(for: .connection, occupancy: live)
                == .refuse(SessionCapacity.Refusal(reason: .totalLimit,
                                                   affectsPresence: true)),
              "a full setup flood refuses a new connection")
        check(SessionCapacity.presenceCapacity(occupancy: live).state == .blocked,
              "the setup flood can block a presence probe")

        // MARK: Runtime admission, reservation, release, and restart

        // These calls are the server-side lifecycle. The fake table stands in
        // for the session queue snapshots. No socket is opened.
        var nominalRuntime = SessionCapacity.Runtime(fileLimit: .raised(soft: 4096))
        check(nominalRuntime.sessionLimit == 288, "the runtime takes the 288 limit")
        check(nominalRuntime.startRun()
                == .started(SessionCapacity.Limits(total: 288, setupReserve: 32, relay: 256)),
              "the runtime starts with 256 relays and 32 setup slots")
        check(nominalRuntime.running && nominalRuntime.runNumber == 1,
              "the first run is active")
        let fullRun = openRelays(0..<256) + handshakes(10_000..<10_032)
        check(fullRun.count == 288, "the full run is 288 sessions")
        check(nominalRuntime.admitConnection(sessions: fullRun, now: 10)
                == .refuse(SessionCapacity.Refusal(reason: .totalLimit,
                                                   affectsPresence: true)),
              "the runtime refuses a connection at the full limit")
        check(nominalRuntime.admitRelay(id: numbered(10_500), sessions: fullRun, now: 10)
                == .refuse, "the runtime refuses a relay request for a missing session")

        // A relay reservation is visible to the next decision. It is granted
        // once, and another session cannot grant the same slot.
        let liveX = numbered(11_000)
        let liveY = numbered(11_001)
        var liveRuntime = nominalRuntime
        var liveTable = openRelays(0..<255)
        liveTable.append(session(liveX, .connecting, phaseSeconds: 1))
        liveTable.append(contentsOf: handshakes(12_000..<12_031))
        check(liveRuntime.admitRelay(id: liveX, sessions: liveTable, now: 20) == .grant,
              "the runtime grants the last relay slot")
        check(liveRuntime.isReserved(liveX), "the grant holds a reservation")
        check(liveRuntime.occupancy(sessions: liveTable).relayCount == 256,
              "the reservation counts at the relay cap")
        check(liveRuntime.admitRelay(id: liveX, sessions: liveTable, now: 20)
                == .alreadyGranted, "a duplicate request does not grant twice")
        liveTable.append(session(liveY, .connecting, phaseSeconds: 1))
        check(liveRuntime.admitRelay(id: liveY, sessions: liveTable, now: 20)
                == .refuse, "a second request is refused at the relay cap")
        check(!liveRuntime.isPending(liveY), "a refused request releases its claim")

        // The session reports its open phase. The reservation becomes an
        // observed relay, and a release frees the slot for the next request.
        liveTable = liveTable.map { view in
            view.id == liveX ? session(liveX, .openTCP, idleSeconds: 1) : view
        }
        check(!liveRuntime.occupancy(sessions: liveTable).reservedRelays.contains(liveX),
              "the reported relay phase replaces the reservation")
        check(liveRuntime.admitRelay(id: liveY, sessions: liveTable, now: 21) == .refuse,
              "the table is still at the relay cap")
        liveTable.removeAll { $0.id == numbered(0) }
        check(liveRuntime.admitRelay(id: liveY, sessions: liveTable, now: 22) == .grant,
              "a released relay frees one slot")
        let liveRunNumber = liveRuntime.runNumber
        check(liveRuntime.startRun()
                == .started(SessionCapacity.Limits(total: 288, setupReserve: 32, relay: 256)),
              "a repeated start is idempotent")
        check(liveRuntime.runNumber == liveRunNumber && liveRuntime.isReserved(liveY),
              "a repeated start keeps the run and its reservations")
        liveRuntime.release(liveY)
        check(!liveRuntime.isReserved(liveY), "a close releases the relay slot")

        // A stale relay phase is the only relay that a new request can close.
        let staleID = numbered(13_000)
        let newID = numbered(13_001)
        var staleRuntime = liveRuntime
        var staleTable = openRelays(0..<255)
        staleTable.append(session(staleID, .udp, idleSeconds: 400))
        staleTable.append(session(newID, .connecting, phaseSeconds: 1))
        staleTable.append(contentsOf: handshakes(14_000..<14_030))
        check(staleRuntime.admitRelay(id: newID, sessions: staleTable, now: 30)
                == .closeThenGrant(id: staleID, reason: .udpIdle),
              "the runtime selects only the stale UDP flow")
        staleTable.removeAll { $0.id == staleID }
        staleTable = staleTable.map { view in
            view.id == newID ? session(newID, .openTCP, idleSeconds: 1) : view
        }
        check(staleRuntime.occupancy(sessions: staleTable).relayCount == 256,
              "the runtime keeps the relay cap after the stale close")
        let laterID = numbered(13_002)
        staleTable.append(session(laterID, .connecting, phaseSeconds: 1))
        check(staleRuntime.admitRelay(id: laterID, sessions: staleTable, now: 31)
                == .refuse, "a full healthy set of relays is never evicted for silence")

        // A stop clears every reservation. A start after the stop works while
        // the previous run still owns its sockets, because the descriptor
        // limit budgeted both runs.
        let previousRun = openRelays(0..<256) + handshakes(15_000..<15_032)
        check(SessionCapacity.descriptorFootprint(total: previousRun.count,
                                                 previousRuns: [288, 288]) <= 4096,
              "the descriptor plan holds three full runs at 4096")
        staleRuntime.stopRun()
        check(!staleRuntime.running, "a stop ends the run")
        check(staleRuntime.pendingRelays.isEmpty && staleRuntime.reservedRelays.isEmpty,
              "a stop clears every reservation")
        check(staleRuntime.startRun()
                == .started(SessionCapacity.Limits(total: 288, setupReserve: 32, relay: 256)),
              "a start after a stop uses the same limit")
        check(staleRuntime.running && staleRuntime.runNumber == 2,
              "the restart is a new run")
        check(!staleRuntime.isReserved(newID), "the old run holds no reservation")

        // Low and unknown limits are explicit. Neither one reports Listening.
        var unknownRuntime = SessionCapacity.Runtime(fileLimit: nil)
        check(unknownRuntime.sessionLimit == nil, "an unknown limit has no value")
        check(unknownRuntime.startRun() == .unavailable(.unknownFileLimit),
              "an unknown limit refuses the start")
        check(unknownRuntime.admitConnection(sessions: [], now: 0)
                == .refuse(SessionCapacity.Refusal(reason: .totalLimit,
                                                   affectsPresence: true)),
              "an unknown runtime refuses a connection")
        check(!unknownRuntime.availability.startFailureMessage.isEmpty,
              "an unknown limit has a plain failure message")

        var lowRuntime = SessionCapacity.Runtime(fileLimit: .refused(soft: 32))
        check(lowRuntime.sessionLimit == nil, "a too-low limit has no session value")
        check(lowRuntime.startRun() == .unavailable(.tooLow(softFileLimit: 32)),
              "a too-low limit refuses the start")
        check(lowRuntime.availability.startFailureMessage.contains("32"),
              "the failure message names the observed limit")

        var smallRuntime = SessionCapacity.Runtime(fileLimit: .refused(soft: 64))
        check(smallRuntime.sessionLimit == 3, "64 files give 3 sessions")
        check(smallRuntime.startRun()
                == .started(SessionCapacity.Limits(total: 3, setupReserve: 1, relay: 2)),
              "a small limit still starts")
        check(smallRuntime.admitConnection(sessions: handshakes(16_000..<16_003), now: 0)
                == .refuse(SessionCapacity.Refusal(reason: .totalLimit,
                                                   affectsPresence: true)),
              "a small limit refuses at three sessions")
        check(smallRuntime.admitConnection(sessions: handshakes(16_000..<16_002), now: 0)
                == .accept, "a small limit accepts within three sessions")

        // MARK: Grant wait lifecycle

        // The connect bound ends when the request is complete. A request that
        // waits for the server keeps its own 2 second bound, even when the
        // connect used most of the 8 second window.
        var slowConnect = SessionCapacity.PhaseTracker(at: 100)
        check(slowConnect.beginConnecting(at: 107.9),
              "the connect starts near the connect bound")
        check(slowConnect.beginAwaitingRelay(at: 108),
              "the complete request starts the relay wait")
        check(SessionCapacity.closeReason(
                for: SessionCapacity.PhaseSession(
                    id: numbered(17_000), phase: slowConnect.phase,
                    phaseSeconds: slowConnect.phaseSeconds(at: 109.9)))
                == nil,
              "the old connect bound does not close the relay wait")
        check(SessionCapacity.closeReason(
                for: SessionCapacity.PhaseSession(
                    id: numbered(17_000), phase: slowConnect.phase,
                    phaseSeconds: slowConnect.phaseSeconds(at: 110)))
                == .relayGrantExpired,
              "the relay wait closes at its own bound")
        var grantedLate = slowConnect
        check(grantedLate.admitRelay(datagram: false, at: 109.9),
              "a grant inside the relay wait opens the relay")
        check(grantedLate.phase == .openTCP, "the granted relay is open")

        // A fake queue call that drains after the wait sends one failure. The
        // tracker cannot open a relay after its own timer closed it.
        var timedOut = SessionCapacity.PhaseTracker(at: 200)
        _ = timedOut.beginConnecting(at: 201)
        _ = timedOut.beginAwaitingRelay(at: 202)
        check(SessionCapacity.closeReason(
                for: SessionCapacity.PhaseSession(
                    id: numbered(17_001), phase: timedOut.phase,
                    phaseSeconds: timedOut.phaseSeconds(at: 204)))
                == .relayGrantExpired,
              "the fake queue drained after the relay wait bound")
        check(!timedOut.admitRelay(datagram: false, at: 204),
              "a late grant cannot open a relay after the wait bound")

        // MARK: One final failure reply

        var failureReply = SessionCapacity.FinalReplyGate()
        check(!failureReply.started && !failureReply.failureInFlight,
              "a new session has no final reply")
        check(failureReply.begin(.failure), "the first failure reply starts")
        check(failureReply.started && failureReply.failureInFlight,
              "the one failure reply is in flight")
        check(failureReply.defersClose, "a failure reply defers another close")
        check(!failureReply.begin(.failure), "a second failure does not start")
        check(!failureReply.begin(.success), "a failure blocks a later success")
        failureReply.settle()
        check(!failureReply.failureInFlight && !failureReply.defersClose,
              "the settled failure allows the close")
        var successReply = SessionCapacity.FinalReplyGate()
        check(successReply.begin(.success), "the success reply starts")
        check(!successReply.begin(.failure), "a late failure does not follow a success")
        check(!successReply.defersClose, "a sent success does not defer a close")

        // The relay wait timer and a late grant both run on the session queue.
        // Both orders must send exactly one failure reply. The one reply keeps
        // its deadline, so a second failure must not close the session.
        func fakeReplyOrder(grantDrainsFirst: Bool) -> (replies: Int, started: Bool, deferred: Bool) {
            var tracker = SessionCapacity.PhaseTracker(at: 0)
            _ = tracker.beginConnecting(at: 1)
            _ = tracker.beginAwaitingRelay(at: 2)
            var gate = SessionCapacity.FinalReplyGate()
            var replies = 0
            func failIfPossible() {
                if gate.begin(.failure) { replies += 1 }
            }
            // The relay wait bound is 2 seconds, so both callbacks are late.
            let timerFired = { failIfPossible() }
            let grantDrained = {
                _ = tracker.admitRelay(datagram: false, at: 4.1)
                failIfPossible()
            }
            if grantDrainsFirst {
                grantDrained()
                timerFired()
            } else {
                timerFired()
                grantDrained()
            }
            return (replies, gate.started, gate.defersClose)
        }
        let timerFirst = fakeReplyOrder(grantDrainsFirst: false)
        check(timerFirst.replies == 1 && timerFirst.started && timerFirst.deferred,
              "the relay wait timer sends the one failure reply")
        let grantFirst = fakeReplyOrder(grantDrainsFirst: true)
        check(grantFirst.replies == 1 && grantFirst.started && grantFirst.deferred,
              "a late grant sends one failure reply")

        // MARK: Capacity warning

        check(SessionCapacity.priorRelayBaseline == 224, "the earlier relay baseline")
        check(SessionCapacity.capacityWarning(limits: SessionCapacity.limits(total: 288)) == nil,
              "the full cap has no warning")
        check(SessionCapacity.capacityWarning(relayLimit: 224) == nil,
              "the baseline has no warning")
        let lowWarning = SessionCapacity.capacityWarning(relayLimit: 223)
        check(lowWarning?.contains("223") == true, "a lower cap warns with its count")
        check(lowWarning?.contains("224") == true, "the warning names the baseline")
        check(SessionCapacity.capacityWarning(limits: SessionCapacity.limits(total: 202)) != nil,
              "a reduced restart warns")
        check(SessionCapacity.capacityWarning(relayLimit: nil) == nil,
              "an unknown cap has no false claim")

        // MARK: Rapid restart uses the live descriptor budget

        // Five stopped runs can overlap while their sockets close. Each run
        // takes only the free budget. The fifth run is smaller. The sixth
        // start waits for a close callback.
        var restartRuntime = SessionCapacity.Runtime(fileLimit: .raised(soft: 4096))
        var restartNow = 0.0
        var opened: [[UUID]] = []
        let expectedLimits = [288, 288, 288, 288, 202]
        for run in 0..<5 {
            let start = restartRuntime.startRun(now: restartNow)
            guard case .started(let limits) = start else {
                check(false, "restart run \(run + 1) starts: \(start)")
                return
            }
            check(limits.total == expectedLimits[run],
                  "restart run \(run + 1) takes the free budget: \(limits)")
            let ids = (0..<limits.total).map { numbered(30_000 + run * 400 + $0) }
            for value in ids { restartRuntime.noteSessionOpened(value) }
            check(restartRuntime.active?.sessions.count == limits.total,
                  "the run counts every accepted session")
            opened.append(ids)
            restartRuntime.stopRun(now: restartNow, liveSessions: ids)
            check(!restartRuntime.running && restartRuntime.active == nil,
                  "a stop ends the run")
            restartNow += 0.5
        }
        check(restartRuntime.retiringSessionCount == 1_354,
              "five stopped runs keep their closing sessions")
        check(restartRuntime.unconfirmedCloses(now: restartNow) == 0,
              "a close inside the bound is not a loss")
        let busy = restartRuntime.startRun(now: restartNow)
        check(busy == .busy(retiringSessions: 1_354),
              "a sixth start waits for the descriptor budget")
        check(!SessionCapacity.Runtime.busyMessage(retiringSessions: 1_354).isEmpty,
              "the busy start has a plain reason")
        check(SessionCapacity.Runtime.busyMessage(retiringSessions: 1_354).contains("1354"),
              "the busy reason names the count")
        // One close completion frees exactly one session.
        restartRuntime.sessionClosed(opened[0][0])
        check(restartRuntime.retiringSessionCount == 1_353,
              "one close frees one session")
        restartRuntime.sessionClosed(opened[0][0])
        check(restartRuntime.retiringSessionCount == 1_353,
              "a repeated close frees nothing")
        guard case .started(let oneSlot) = restartRuntime.startRun(now: restartNow) else {
            check(false, "one free session starts a run")
            return
        }
        check(oneSlot.total == 1 && oneSlot.relay == 1,
              "the free session gives a one-slot run")
        check(restartRuntime.effectiveSessionLimit == 1,
              "the active run reports its reduced limit")
        check(restartRuntime.admitConnection(sessions: [], now: 3) == .accept,
              "the reduced run accepts within its one slot")
        check(restartRuntime.admitConnection(sessions: handshakes(41_000..<41_001), now: 3)
                == .refuse(SessionCapacity.Refusal(reason: .totalLimit,
                                                   affectsPresence: true)),
              "the reduced run refuses at its budget")
        // An old close callback cannot touch the active run.
        let activeID = numbered(40_000)
        restartRuntime.noteSessionOpened(activeID)
        restartRuntime.sessionClosed(opened[1][0])
        check(restartRuntime.active?.sessions.contains(activeID) == true,
              "an old close leaves the active session")
        restartRuntime.sessionClosed(activeID)
        check(restartRuntime.active?.sessions.isEmpty == true,
              "the active close clears the active session")
        restartRuntime.stopRun(now: restartNow)
        check(restartRuntime.retiringSessionCount == 1_352,
              "an empty active run adds no retirement")
        // Time alone does not prove that a close routine ran or free a slot.
        let lateRestart = restartNow + SessionCapacity.Runtime.retirementSeconds
        guard case .started(let limited) = restartRuntime.startRun(now: lateRestart) else {
            check(false, "two confirmed closes should allow two sessions")
            return
        }
        check(limited.total == 2, "missed callbacks keep their descriptor reservations")
        restartRuntime.stopRun(now: lateRestart)
        check(restartRuntime.unconfirmedCloses(now: lateRestart) == 1_352,
              "the report counts outstanding overdue callbacks")
        restartRuntime.sessionClosed(opened[0][1])
        check(restartRuntime.unconfirmedCloses(now: lateRestart) == 1_351,
              "a late callback removes its overdue count")
        for ids in opened { for id in ids { restartRuntime.sessionClosed(id) } }
        check(restartRuntime.unconfirmedCloses(now: lateRestart) == 0,
              "confirmed closes no longer appear as unconfirmed")
        guard case .started(let released) = restartRuntime.startRun(now: lateRestart) else {
            check(false, "all callbacks should release the budget")
            return
        }
        check(released.total == 288, "confirmed callbacks release the full budget")

        // The same rule follows a lower open-file limit. Three full runs fit.
        // The fourth start gets the small remainder.
        var lowRestart = SessionCapacity.Runtime(fileLimit: .refused(soft: 256))
        var lowNow = 0.0
        for run in 0..<3 {
            let start = lowRestart.startRun(now: lowNow)
            guard case .started(let limits) = start else {
                check(false, "low restart run \(run + 1) starts: \(start)")
                return
            }
            check(limits.total == 24, "a 256 file limit keeps 24 sessions")
            let ids = (0..<limits.total).map { numbered(50_000 + run * 40 + $0) }
            for value in ids { lowRestart.noteSessionOpened(value) }
            lowRestart.stopRun(now: lowNow, liveSessions: ids)
            lowNow += 0.5
        }
        guard case .started(let remainder) = lowRestart.startRun(now: lowNow) else {
            check(false, "the low limit keeps its remainder")
            return
        }
        check(remainder.total == 2 && remainder.relay == 1,
              "the fourth low run takes the remaining two slots")
        let lowIDs = [numbered(51_000), numbered(51_001)]
        for value in lowIDs { lowRestart.noteSessionOpened(value) }
        lowRestart.stopRun(now: lowNow, liveSessions: lowIDs)
        check(lowRestart.startRun(now: lowNow) == .busy(retiringSessions: 74),
              "the low limit has no room after four runs")
        check(lowRestart.startRun(now: lowNow + 1_000) == .busy(retiringSessions: 74),
              "time alone never frees an unconfirmed close")
        check(lowRestart.unconfirmedCloses(now: lowNow + 1_000) == 74,
              "all outstanding closes remain visible after a long delay")

        print("Session capacity tests passed")
    }
}
