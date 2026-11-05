import Foundation
import Darwin

// Capacity rules for the proxy. This file uses Foundation and Darwin only. The
// decision helpers are pure, so the tests call them without a socket.
//
// The phase-aware policies below are the runtime capacity rule. ProxyServer
// uses `Runtime`, `PhaseTracker`, `admission`, and `idleAction`. The legacy
// idle-only rule stays for reference and its tests.

/// The session cap and the idle eviction rule.
struct SessionCapacity {
    /// The most relay sessions that the proxy grants. This keeps the earlier
    /// 256-relay capacity when the open-file limit safely permits it.
    static let maximumRelays = 256
    /// The setup slots that relay sessions cannot use. A presence check uses
    /// one setup slot.
    static let handshakeSlots = 32
    /// The most open sessions. A relay session uses one of `maximumRelays`.
    /// A setup session can use any free slot. The effective limit also follows
    /// the open-file limit. See `sessionLimit(softFileLimit:)`.
    static let maximumSessions = maximumRelays + handshakeSlots
    /// A session that was idle for longer than this can be evicted. This is
    /// the legacy idle-only window. The phase-aware policy uses phase bounds.
    static let idleEvictionSeconds: TimeInterval = 30

    /// One open session, as the eviction rule sees it.
    struct IdleSession: Equatable {
        let id: UUID
        /// The time since the last traffic on the session.
        let idleSeconds: TimeInterval
    }

    enum Decision: Equatable {
        /// The new session fits under the cap.
        case accept
        /// Close this session, then accept the new one.
        case evict(UUID)
        /// The cap is reached and no session is idle enough. Refuse the new one.
        case refuse
    }

    /// Choose what to do for a new session. Evict only a session that was idle
    /// for longer than `idleEvictionSeconds`. Use the longest idle time. On a
    /// tie, use the lowest identifier, so the choice stays deterministic.
    ///
    /// This is the legacy idle-only rule. It does not know the session phase,
    /// so it can select a healthy open TCP relay. The runtime uses the
    /// phase-aware admission below. Keep this helper for its tests.
    static func decision(sessionCount: Int, idle: [IdleSession]) -> Decision {
        guard sessionCount >= maximumSessions else { return .accept }
        let candidates = idle.filter { $0.idleSeconds > idleEvictionSeconds }
        guard !candidates.isEmpty else { return .refuse }
        let chosen = candidates.sorted { left, right in
            if left.idleSeconds != right.idleSeconds { return left.idleSeconds > right.idleSeconds }
            return left.id.uuidString < right.id.uuidString
        }[0]
        return .evict(chosen.id)
    }
}

// MARK: Phase-aware capacity

// The old rules use silence. A quiet and healthy TCP relay looks the same as
// a dead flow, so an idle timer can close a working remote session. This
// policy uses the phase. Only a phase with a real bound closes.

extension SessionCapacity {
    /// One step in the life of an accepted session. The server sets the phase
    /// at each transition on the session queue. The capacity policy reads a
    /// snapshot of the phase.
    enum Phase: String, CaseIterable, Equatable {
        /// The client is in the SOCKS greeting or the authentication exchange.
        case handshake
        /// The client sent a request. The destination connect has no result.
        case connecting
        /// The destination answered and the server has not answered the relay
        /// request. This phase has its own bound. The connect bound no longer
        /// applies. The server normally answers on its next queue turn.
        case awaitingRelay
        /// Both directions of the TCP relay are open. The relay is healthy.
        case openTCP
        /// A datagram flow carries length-prefixed UDP frames over TCP.
        case udp
        /// One direction of a TCP relay finished. The other direction can send.
        case halfClosed

        /// A setup phase does not hold a relay slot.
        var isSetup: Bool {
            self == .handshake || self == .connecting || self == .awaitingRelay
        }
        /// A relay phase holds a relay slot.
        var isRelay: Bool { !isSetup }
    }

    /// Select the phase from the facts that the session already holds.
    ///
    /// A presence probe authenticates and sends no complete request. It stays
    /// in `handshake`, so it uses a setup slot and never a relay slot. A
    /// session that sent a complete request waits in `connecting` until the
    /// destination answers. The relay request then moves it to
    /// `awaitingRelay`. This classifier returns the phase before that request,
    /// so it never returns `awaitingRelay`. The ICMP echo commands do not use
    /// this classifier.
    static func phase(authenticated: Bool, requestComplete: Bool,
                      destinationReady: Bool, datagram: Bool,
                      halfClosed: Bool) -> Phase {
        guard authenticated, requestComplete else { return .handshake }
        guard destinationReady else { return .connecting }
        if datagram { return .udp }
        return halfClosed ? .halfClosed : .openTCP
    }

    /// The phase of one live session. The session queue owns this value. Use
    /// one lock around it when the server queue reads a snapshot.
    ///
    /// The phase moves forward only, except a refused relay request. That
    /// request returns to the connect phase for the one error reply. A
    /// handshake can become a connect. A connect can become an open TCP or UDP
    /// relay only after the server grants a relay slot. A TCP relay can become
    /// half-closed. No method turns a handshake into an open relay, so a
    /// presence probe can never hold a relay slot.
    struct PhaseTracker: Equatable {
        private(set) var phase: Phase = .handshake
        private(set) var phaseStartedAt: TimeInterval
        /// True after the session asked the server for a relay slot and before
        /// the answer. The capacity rule does not close this session as a stale
        /// connect. The relay request has its own bound.
        private(set) var awaitsRelay = false
        /// True after the server refused the relay slot and before the session
        /// closes. The session keeps its capacity protection while the SOCKS
        /// error is in flight.
        private(set) var relayRefused = false
        /// True after a final SOCKS reply started and before the session
        /// closes. The session keeps its capacity protection while the reply
        /// is in flight.
        private(set) var replyPending = false
        /// True while an ICMP echo command owns the session. The echo timers
        /// bound it, so a capacity decision must not close it as a stale
        /// handshake.
        private(set) var controlActive = false

        /// True while a capacity decision must not close this session. It
        /// asked for a relay slot, the server refused it, its final SOCKS
        /// reply is in flight, or an ICMP command owns it. The session's own
        /// phase bound still applies.
        var capacityProtected: Bool {
            awaitsRelay || relayRefused || replyPending || controlActive
        }

        init(at now: TimeInterval) {
            self.phaseStartedAt = max(0, now)
        }

        /// Seconds in the current phase.
        func phaseSeconds(at now: TimeInterval) -> TimeInterval {
            max(0, now - phaseStartedAt)
        }

        /// Move from the greeting and authentication exchange to the
        /// destination connect. A presence probe never calls this method.
        @discardableResult
        mutating func beginConnecting(at now: TimeInterval) -> Bool {
            guard phase == .handshake, !controlActive else { return false }
            phase = .connecting
            phaseStartedAt = max(0, now)
            return true
        }

        /// Record that the session asked for a relay slot. The session moves
        /// to `awaitingRelay`, so the old connect bound ends and the separate
        /// relay request bound starts. A handshake is never reported as an
        /// open TCP relay.
        @discardableResult
        mutating func beginAwaitingRelay(at now: TimeInterval) -> Bool {
            guard phase == .connecting, !capacityProtected else { return false }
            phase = .awaitingRelay
            phaseStartedAt = max(0, now)
            awaitsRelay = true
            return true
        }

        /// The server granted a relay slot. This is the only path to an open
        /// TCP or UDP phase. A denial calls `denyRelay` and keeps the session
        /// in the connect phase until it sends the SOCKS error. A session that
        /// did not ask, or already sent a final reply, cannot open a relay.
        @discardableResult
        mutating func admitRelay(datagram: Bool, at now: TimeInterval) -> Bool {
            guard phase == .awaitingRelay, awaitsRelay, !relayRefused,
                  !replyPending,
                  phaseSeconds(at: now) < relayGrantPhaseSeconds else { return false }
            phase = datagram ? .udp : .openTCP
            phaseStartedAt = max(0, now)
            awaitsRelay = false
            relayRefused = false
            return true
        }

        /// The server refused the relay slot. The session sends a SOCKS error
        /// before it closes. It never sends success. The session keeps the
        /// capacity protection while the error reply is in flight.
        @discardableResult
        mutating func denyRelay(at now: TimeInterval) -> Bool {
            guard phase == .awaitingRelay, awaitsRelay else { return false }
            phase = .connecting
            phaseStartedAt = max(0, now)
            awaitsRelay = false
            relayRefused = true
            return true
        }

        /// One direction of a TCP relay ended. A UDP flow has no half close.
        @discardableResult
        mutating func noteHalfClose(at now: TimeInterval) -> Bool {
            guard phase == .openTCP else { return false }
            phase = .halfClosed
            phaseStartedAt = max(0, now)
            awaitsRelay = false
            relayRefused = false
            return true
        }

        /// Record that the one final SOCKS reply started. A capacity decision
        /// must not close the session before the reply leaves.
        mutating func beginReply() { replyPending = true }

        /// The success reply left and the relay owns the session now. The
        /// relay phase bound governs it. A failure reply keeps the protection
        /// until the session closes.
        mutating func finishReply() { replyPending = false }

        /// Record that an ICMP echo command owns the session. The echo timers
        /// bound it. It is not a relay and holds no relay slot.
        mutating func beginControl() {
            guard phase == .handshake else { return }
            controlActive = true
        }
    }

    /// The one final SOCKS reply of one session. The session queue owns it.
    /// A relay wait timer and a late relay grant can both ask for a failure.
    /// Only the first request sends a reply. A failure reply stays in flight
    /// until its send completion or its bounded reply deadline closes the
    /// session. A second failure must not close the session early, because
    /// that would cancel the one reply.
    struct FinalReplyGate: Equatable {
        enum Kind: Equatable {
            case success
            case failure
        }

        private(set) var kind: Kind?
        /// True while the reply waits for its send completion.
        private(set) var inFlight = false

        /// True after any final reply started.
        var started: Bool { kind != nil }
        /// True while the one failure reply waits for its completion.
        var failureInFlight: Bool { kind == .failure && inFlight }
        /// True when a close from another path must not cancel the reply.
        var defersClose: Bool { failureInFlight }

        /// Start the one final reply. Return false after any reply started.
        mutating func begin(_ value: Kind) -> Bool {
            guard kind == nil else { return false }
            kind = value
            inFlight = true
            return true
        }

        /// The send completion ran or the reply deadline fired.
        mutating func settle() { inFlight = false }
    }

    /// One session as the phase-aware policy sees it.
    struct PhaseSession: Equatable {
        let id: UUID
        let phase: Phase
        /// Seconds in the current phase. It bounds a handshake and a connect.
        let phaseSeconds: TimeInterval
        /// Seconds since the last byte in either direction.
        let idleSeconds: TimeInterval
        /// True while the session must not be closed by a capacity decision.
        /// It asked for a relay slot, the server refused it, its final SOCKS
        /// reply is in flight, or an ICMP command owns it.
        let protectedFromCapacity: Bool

        init(id: UUID, phase: Phase,
             phaseSeconds: TimeInterval = 0, idleSeconds: TimeInterval = 0,
             protectedFromCapacity: Bool = false) {
            self.id = id
            self.phase = phase
            self.phaseSeconds = phaseSeconds
            self.idleSeconds = idleSeconds
            self.protectedFromCapacity = protectedFromCapacity
        }
    }

    // The setup bounds are policy values, not measured values. A live hotspot
    // test must confirm them on each supported iOS version.

    /// A handshake gets the old 30 second eviction window. The SOCKS exchange
    /// is small. A session that cannot finish it in this window is stale.
    static let handshakePhaseSeconds: TimeInterval = 30
    /// Twice the 4 second source device connect deadline. The second window is
    /// a safety net for a lost deadline callback. It stops when the request is
    /// complete.
    static let connectPhaseSeconds: TimeInterval = 8
    /// The server answers a relay request on its own queue. This bound is a
    /// safety net for a lost answer. It does not include the connect time.
    static let relayGrantPhaseSeconds: TimeInterval = 2
    /// UDP and half-closed sessions keep the current 300 second idle window.
    static let relayIdleSeconds: TimeInterval = 300
    /// Recheck an open TCP relay after this wait. This is not a close deadline.
    static let openTCPRecheckSeconds: TimeInterval = 300

    /// File descriptors outside the session table. This is a policy estimate.
    /// The listener, the pairing listener, the pairing connections, the echo
    /// sockets, and the standard streams need descriptors too.
    static let reservedFileDescriptors = 32
    /// One session can hold the client socket, the destination socket, and one
    /// retry socket. The retry socket exists only during a retry. The limit
    /// budgets it for every session, so a retry never overcommits the limit.
    static let socketsPerSession = 3
    /// A stop and a start can overlap. The previous run can still own its
    /// sockets while the next run accepts sessions. A second stop can also
    /// start before the first run released its sockets. The startup limit
    /// budgets three runs. The runtime also counts each session of a stopped
    /// run until its close completes, so a longer overlap cannot overcommit
    /// the limit.
    static let overlappingRuns = 3
    /// The descriptors that one session can need across three overlapping
    /// runs.
    static let descriptorsPerSession = socketsPerSession * overlappingRuns

    /// The relay capacity that the earlier 256-session total gave with this
    /// setup reserve. A lower relay cap is a real reduction, so the app warns
    /// about it before the person starts the proxy.
    static let priorRelayBaseline = maximumRelays - handshakeSlots

    /// A plain warning for a relay cap below the earlier baseline. The
    /// message holds counts only. A full cap returns nil, so the app never
    /// presents 256 as the limit unless the observed limit allows it.
    static func capacityWarning(relayLimit: Int?) -> String? {
        guard let relay = relayLimit, relay < priorRelayBaseline else { return nil }
        return "The effective limit is \(relay) relay sessions. The earlier app gave \(priorRelayBaseline). Close other apps and restart HotspotShade. A previous run can also lower the limit until it closes."
    }

    /// The warning for one split of the effective limit.
    static func capacityWarning(limits: Limits?) -> String? {
        capacityWarning(relayLimit: limits?.relay)
    }

    /// The session limit for one soft file descriptor limit. Each session is
    /// budgeted three sockets in each of three overlapping runs. A limit at or
    /// below the reserve gives no session. Use the value once at startup. Do
    /// not change it while sessions are open.
    static func sessionLimit(softFileLimit: Int) -> Int {
        let usable = softFileLimit > reservedFileDescriptors
            ? softFileLimit - reservedFileDescriptors : 0
        guard usable > 0 else { return 0 }
        return min(maximumSessions, usable / descriptorsPerSession)
    }

    /// The session limit for one startup result. A nil result means the limits
    /// cannot be read. Return nil so the caller records the unknown state
    /// instead of claiming a bound.
    static func sessionLimit(fileLimit: FileDescriptorLimit.Outcome?) -> Int? {
        guard let outcome = fileLimit else { return nil }
        return sessionLimit(softFileLimit: outcome.softLimit)
    }

    /// The open files that one table needs. `previousRuns` holds the session
    /// counts of earlier runs that can still own sockets during a restart.
    static func descriptorFootprint(total: Int, previousRuns: [Int] = []) -> Int {
        let previous = previousRuns.reduce(0) { $0 + max(0, $1) }
        return reservedFileDescriptors
            + (max(0, total) + previous) * socketsPerSession
    }

    /// The capacity state for one process. A missing limit is unknown. It is
    /// never the nominal maximum. A limit that gives no session is unusable.
    enum Availability: Equatable {
        /// The limit gives at least one session.
        case ready(Limits)
        /// The open-file limit cannot be read.
        case unknownFileLimit
        /// The open-file limit gives no session.
        case tooLow(softFileLimit: Int)

        var limits: Limits? {
            if case .ready(let limits) = self { return limits }
            return nil
        }

        var isUsable: Bool { (limits?.total ?? 0) > 0 }

        /// The plain reason for a refused start. It names no address.
        var startFailureMessage: String {
            switch self {
            case .ready:
                return ""
            case .unknownFileLimit:
                return "The app cannot read the open-file limit. Restart the app."
            case .tooLow(let soft):
                return "The open-file limit is \(soft). The proxy needs more open files. Restart the app."
            }
        }
    }

    /// Build the availability from one observed soft limit. A limit that gives
    /// no session is unusable, so the server never reports Listening with zero
    /// slots.
    static func availability(softFileLimit: Int) -> Availability {
        let total = sessionLimit(softFileLimit: softFileLimit)
        guard total > 0 else { return .tooLow(softFileLimit: softFileLimit) }
        return .ready(limits(total: total))
    }

    /// Build the availability from one startup result. A nil result stays
    /// unknown. Do not substitute the maximum.
    static func availability(fileLimit: FileDescriptorLimit.Outcome?) -> Availability {
        guard let outcome = fileLimit else { return .unknownFileLimit }
        return availability(softFileLimit: outcome.softLimit)
    }

    /// The split of one total limit.
    struct Limits: Equatable {
        let total: Int
        /// The slots that relay sessions cannot use. Setup sessions can use
        /// the whole total limit.
        let setupReserve: Int
        let relay: Int
    }

    /// Return the limits for one total. The setup reserve keeps the same share
    /// at a lower total, so a low file descriptor limit does not give every
    /// slot to the reserve. A total of one gives the one slot to a relay.
    static func limits(total: Int = maximumSessions) -> Limits {
        let total = max(0, min(total, maximumSessions))
        guard total > 1 else {
            return Limits(total: total, setupReserve: 0, relay: total)
        }
        // The share is ceil(total * 32 / 288), with a floor of one.
        let share = max(1, (total + maximumSessions / handshakeSlots - 1)
            / (maximumSessions / handshakeSlots))
        let reserve = min(handshakeSlots, share)
        return Limits(total: total, setupReserve: reserve, relay: total - reserve)
    }

    /// Why a session is stale.
    enum CloseReason: Equatable {
        case handshakeExpired
        case connectExpired
        case relayGrantExpired
        case udpIdle
        case halfClosedIdle
    }

    /// The reason to close one session, or nil when the phase has no bound.
    /// An open TCP relay never returns a reason. Silence alone never selects
    /// it. The caller must set `openTCP` only while both directions are open
    /// and no socket reported a terminal error.
    static func closeReason(for session: PhaseSession) -> CloseReason? {
        switch session.phase {
        case .handshake:
            return session.phaseSeconds >= handshakePhaseSeconds ? .handshakeExpired : nil
        case .connecting:
            return session.phaseSeconds >= connectPhaseSeconds ? .connectExpired : nil
        case .awaitingRelay:
            return session.phaseSeconds >= relayGrantPhaseSeconds ? .relayGrantExpired : nil
        case .udp:
            return session.idleSeconds >= relayIdleSeconds ? .udpIdle : nil
        case .halfClosed:
            return session.idleSeconds >= relayIdleSeconds ? .halfClosedIdle : nil
        case .openTCP:
            return nil
        }
    }

    /// The most overdue stale session, or nil when no session is past its
    /// phase bound. An open TCP relay is never a candidate. The most overdue
    /// session wins. A tie uses the lowest identifier, so the choice stays
    /// deterministic.
    static func staleSession(in sessions: [PhaseSession])
        -> (id: UUID, reason: CloseReason)? {
        guard let chosen = bestStale(in: sessions, protecting: [], where: { _ in true }) else {
            return nil
        }
        return (chosen.session.id, chosen.reason)
    }

    /// The stale session for one request. A relay request needs a stale relay
    /// slot. A stale setup session cannot make one. A session that is
    /// protected from capacity is not stale. Its own phase bound still closes
    /// it.
    private static func bestStale(in sessions: [PhaseSession],
                                  protecting protected: Set<UUID>,
                                  where allowed: (Phase) -> Bool)
        -> (session: PhaseSession, reason: CloseReason)? {
        var best: (session: PhaseSession, reason: CloseReason)?
        for session in sessions {
            guard !protected.contains(session.id), !session.protectedFromCapacity,
                  allowed(session.phase),
                  let reason = closeReason(for: session) else { continue }
            guard let current = best else {
                best = (session, reason)
                continue
            }
            let overdue = self.overdueSeconds(session)
            let currentOverdue = self.overdueSeconds(current.session)
            if overdue > currentOverdue
                || (overdue == currentOverdue
                    && session.id.uuidString < current.session.id.uuidString) {
                best = (session, reason)
            }
        }
        return best
    }

    /// Seconds past the phase bound. An open TCP relay never reaches this
    /// call.
    private static func overdueSeconds(_ session: PhaseSession) -> TimeInterval {
        switch session.phase {
        case .handshake: return session.phaseSeconds - handshakePhaseSeconds
        case .connecting: return session.phaseSeconds - connectPhaseSeconds
        case .awaitingRelay: return session.phaseSeconds - relayGrantPhaseSeconds
        case .udp, .halfClosed: return session.idleSeconds - relayIdleSeconds
        case .openTCP: return 0
        }
    }

    /// One requested admission.
    enum Request: Equatable {
        /// A new accepted connection. It starts in the handshake phase and
        /// needs one free total slot.
        case connection
        /// One setup session becomes a relay. It needs one free relay slot.
        /// The total count does not change.
        case relay
    }

    enum RefusalReason: Equatable {
        case totalLimit
        case relayLimit
    }

    struct Refusal: Equatable {
        let reason: RefusalReason
        /// True when the refused connection could have been a presence probe.
        /// A connection refusal always has this value. A relay refusal cannot
        /// be a probe, because the session already sent a request.
        let affectsPresence: Bool
    }

    enum Admission: Equatable {
        /// The request fits.
        case accept
        /// Close this stale session, then accept the request.
        case closeThenAccept(id: UUID, reason: CloseReason)
        /// Refuse the request. No healthy open relay is closed to make room.
        case refuse(Refusal)
    }

    /// One view of the session table. `limit` is the effective total limit.
    /// `reservedRelays` holds the relay slots that the server granted but the
    /// session has not reported yet. They count as relays, so the server never
    /// grants the same free slot twice.
    struct Occupancy: Equatable {
        let sessions: [PhaseSession]
        let limit: Int
        let reservedRelays: Set<UUID>

        init(sessions: [PhaseSession], limit: Int = SessionCapacity.maximumSessions,
             reservedRelays: Set<UUID> = []) {
            self.sessions = sessions
            self.limit = limit
            self.reservedRelays = reservedRelays
        }

        /// The sessions that hold a relay slot now. A reserved slot counts
        /// until the session reports its relay phase. The union makes the
        /// count correct across the two queues.
        var relayCount: Int {
            let present = Set(sessions.map(\.id))
            let observed = Set(sessions.lazy.filter { $0.phase.isRelay }.map(\.id))
            return observed.count
                + reservedRelays.intersection(present).subtracting(observed).count
        }

        /// The sessions that do not hold a relay slot. A reserved relay is a
        /// relay, not a setup session, so the two counts add up to the table
        /// size.
        var setupCount: Int { max(0, sessions.count - relayCount) }
    }

    /// Decide one admission. A session within its phase bound is retained.
    /// Only a stale session is closed. A fully open TCP relay is never stale,
    /// so the policy never selects it for silence. A session with a reserved
    /// relay slot, a pending reply, or an ICMP command is not stale either.
    static func admission(for request: Request, occupancy: Occupancy) -> Admission {
        let limits = limits(total: occupancy.limit)
        let total = occupancy.sessions.count
        let relay = occupancy.relayCount

        switch request {
        case .connection:
            guard total >= limits.total else { return .accept }
            if let chosen = bestStale(in: occupancy.sessions,
                                      protecting: occupancy.reservedRelays,
                                      where: { _ in true }) {
                return .closeThenAccept(id: chosen.session.id, reason: chosen.reason)
            }
            return .refuse(Refusal(reason: .totalLimit, affectsPresence: true))
        case .relay:
            guard relay >= limits.relay else { return .accept }
            if let chosen = bestStale(in: occupancy.sessions,
                                      protecting: occupancy.reservedRelays,
                                      where: { $0.isRelay }) {
                return .closeThenAccept(id: chosen.session.id, reason: chosen.reason)
            }
            return .refuse(Refusal(reason: .relayLimit, affectsPresence: false))
        }
    }

    /// The server-side relay reservations. The server queue owns this value.
    /// A reservation starts when the server receives a relay request and ends
    /// when the session reports the relay phase, closes, or is refused.
    struct RelayBook: Equatable {
        /// Requests that wait for a decision.
        private(set) var pending: Set<UUID> = []
        /// Granted relay slots that the session has not reported yet.
        private(set) var reserved: Set<UUID> = []

        var isEmpty: Bool { pending.isEmpty && reserved.isEmpty }

        /// Start one request. Return false for a duplicate request. The caller
        /// must not decide the same session twice.
        mutating func begin(_ id: UUID) -> Bool {
            guard !pending.contains(id), !reserved.contains(id) else { return false }
            pending.insert(id)
            return true
        }

        /// Grant the slot. The reservation stays until the session reports the
        /// relay phase or closes.
        mutating func grant(_ id: UUID) {
            pending.remove(id)
            reserved.insert(id)
        }

        /// Refuse the request. The session sends a SOCKS error and closes.
        mutating func deny(_ id: UUID) { pending.remove(id) }

        /// The session closed. It holds no setup or relay slot after this call.
        mutating func release(_ id: UUID) {
            pending.remove(id)
            reserved.remove(id)
        }

        mutating func removeAll() {
            pending.removeAll()
            reserved.removeAll()
        }

        /// Drop stale entries and reservations that the session already
        /// reports as a relay. A reported relay counts from its phase.
        mutating func reconcile(with sessions: [PhaseSession]) {
            let present = Set(sessions.map(\.id))
            pending.formIntersection(present)
            reserved.formIntersection(present)
            for session in sessions where session.phase.isRelay {
                pending.remove(session.id)
                reserved.remove(session.id)
            }
        }

        /// The occupancy for one decision. The caller reconciles first.
        func occupancy(sessions: [PhaseSession], limit: Int) -> Occupancy {
            Occupancy(sessions: sessions, limit: limit, reservedRelays: reserved)
        }
    }

    /// The server-side capacity state for one process. ProxyServer runs every
    /// method on its serial queue. The type owns the startup limit, the run
    /// state, and the relay reservations. The tests drive the same calls with
    /// a fake session table, so admission, release, and restart are covered
    /// without a socket.
    ///
    /// A stopped run can still own its sockets while the next run starts. The
    /// runtime counts each session of the stopped run until its close
    /// callback arrives. A new run gets the remaining estimated descriptor
    /// budget. A timeout alone does not prove that a session released sockets.
    struct Runtime: Equatable {
        /// One run that accepts sessions. The server adds each accepted
        /// session. The close callback removes it.
        struct LiveRun: Equatable {
            let number: Int
            let limits: Limits
            private(set) var sessions: Set<UUID> = []

            mutating func add(_ id: UUID) { sessions.insert(id) }

            @discardableResult
            mutating func remove(_ id: UUID) -> Bool { sessions.remove(id) != nil }
        }

        /// One run that stopped and still closes its sessions.
        struct RetiringRun: Equatable {
            let number: Int
            let deadline: TimeInterval
            private(set) var sessions: Set<UUID>

            @discardableResult
            mutating func remove(_ id: UUID) -> Bool { sessions.remove(id) != nil }

            func isExpired(at now: TimeInterval) -> Bool { now >= deadline }
        }

        /// The delay before a missing close callback appears in diagnostics.
        /// Passing this delay does not release its descriptor budget.
        static let retirementSeconds: TimeInterval = 10

        let availability: Availability
        /// True between a successful start and the next stop or failure.
        private(set) var running = false
        /// Counts successful starts. A stop does not reset it.
        private(set) var runNumber = 0
        /// The run that accepts sessions now.
        private(set) var active: LiveRun?
        /// The runs that stopped and still own closing sockets.
        private(set) var retiring: [RetiringRun] = []
        /// The sessions that still lack a callback after the diagnostic delay.
        func unconfirmedCloses(now: TimeInterval) -> Int {
            retiring.filter { $0.isExpired(at: now) }.reduce(0) { $0 + $1.sessions.count }
        }
        private var book = RelayBook()
        /// The observed soft limit. A nil value means unknown, so no start.
        private let softFileLimit: Int?

        init(fileLimit: FileDescriptorLimit.Outcome?) {
            self.availability = SessionCapacity.availability(fileLimit: fileLimit)
            self.softFileLimit = fileLimit?.softLimit
        }

        init(availability: Availability, softFileLimit: Int? = nil) {
            self.availability = availability
            self.softFileLimit = softFileLimit
        }

        /// The startup limit. It follows the observed open-file limit.
        var limits: Limits? { availability.limits }
        /// The limit of the current run. A rapid restart can reduce it while
        /// an earlier run still closes. It equals the startup limit while no
        /// run is active.
        var effectiveLimits: Limits? { active?.limits ?? limits }
        var sessionLimit: Int? { limits?.total }
        var effectiveSessionLimit: Int? { effectiveLimits?.total }
        var isUsable: Bool { availability.isUsable }
        var pendingRelays: Set<UUID> { book.pending }
        var reservedRelays: Set<UUID> { book.reserved }
        /// The sessions of stopped runs that can still own sockets.
        var retiringSessionCount: Int {
            retiring.reduce(0) { $0 + $1.sessions.count }
        }

        enum Start: Equatable {
            /// The run started with this effective split.
            case started(Limits)
            /// The server must not listen. The message says why.
            case unavailable(Availability)
            /// The stopped runs still own enough descriptors for the budget.
            /// Start again after enough close callbacks arrive.
            case busy(retiringSessions: Int)
        }

        /// The plain reason for a start that waits for retirement. It names
        /// no address and no session.
        static func busyMessage(retiringSessions: Int) -> String {
            "The previous run is still closing \(retiringSessions) sessions. Try again or reopen the app."
        }

        /// Start one run. A run with no usable limit refuses to start, so the
        /// server never reports Listening with zero slots. A rapid start
        /// takes the free descriptor budget after the stopped runs.
        mutating func startRun(now: TimeInterval = 0) -> Start {
            guard let nominal = limits, nominal.total > 0 else {
                return .unavailable(availability)
            }
            // A repeated start must not clear a live reservation.
            if running, let active = active {
                return .started(active.limits)
            }
            book.removeAll()
            let free = dynamicSessionLimit(retiringSessions: retiringSessionCount)
            guard free > 0 else {
                return .busy(retiringSessions: retiringSessionCount)
            }
            running = true
            runNumber += 1
            let run = LiveRun(number: runNumber,
                              limits: SessionCapacity.limits(total: min(nominal.total, free)))
            active = run
            return .started(run.limits)
        }

        /// Stop the run. No relay slot can stay reserved for a session that
        /// left the table. The observed limit stays. The run keeps its live
        /// sessions until each close callback arrives.
        mutating func stopRun(now: TimeInterval = 0, liveSessions: [UUID] = []) {
            book.removeAll()
            running = false
            var live = Set(liveSessions)
            if let run = active { live.formUnion(run.sessions) }
            active = nil
            if !live.isEmpty {
                retiring.append(RetiringRun(number: runNumber,
                                            deadline: now + Self.retirementSeconds,
                                            sessions: live))
            }
        }

        /// The server accepted one session in the active run.
        mutating func noteSessionOpened(_ id: UUID) {
            active?.add(id)
        }

        /// One session reported that its close routine requested cancellation.
        /// Network.framework does not report when every descriptor is released.
        /// A late callback from a stopped run releases that run only. It
        /// cannot touch the active run.
        mutating func sessionClosed(_ id: UUID) {
            if active?.remove(id) == true { return }
            for index in retiring.indices {
                retiring[index].remove(id)
            }
            retiring.removeAll { $0.sessions.isEmpty }
        }

        func isReserved(_ id: UUID) -> Bool { book.reserved.contains(id) }
        func isPending(_ id: UUID) -> Bool { book.pending.contains(id) }

        /// One occupancy view. The relay book drops reservations that the
        /// sessions already report. The active run supplies the limit, so a
        /// reduced restart never grants more slots than its budget.
        mutating func occupancy(sessions: [PhaseSession]) -> Occupancy {
            book.reconcile(with: sessions)
            return book.occupancy(sessions: sessions,
                                  limit: effectiveLimits?.total ?? 0)
        }

        /// One new connection admission. A server that is not running refuses.
        mutating func admitConnection(sessions: [PhaseSession], now: TimeInterval) -> Admission {
            guard running else {
                return .refuse(Refusal(reason: .totalLimit, affectsPresence: true))
            }
            let view = occupancy(sessions: sessions)
            return SessionCapacity.admission(for: .connection, occupancy: view)
        }

        enum RelayAdmission: Equatable {
            /// The session may open its relay.
            case grant
            /// The session already holds a reservation. Do not grant twice.
            case alreadyGranted
            /// Close this stale relay, then grant the requesting session.
            case closeThenGrant(id: UUID, reason: CloseReason)
            /// The session must send a SOCKS error. Do not close a healthy
            /// open relay.
            case refuse
            /// No run is active. The session must fail.
            case unavailable
        }

        /// Decide one relay request. The request starts a reservation before
        /// the decision. A grant keeps the reservation until the session
        /// reports its relay phase or closes.
        mutating func admitRelay(id: UUID, sessions: [PhaseSession],
                                 now: TimeInterval) -> RelayAdmission {
            guard running else { return .unavailable }
            guard sessions.contains(where: { $0.id == id }) else { return .refuse }
            if book.reserved.contains(id) { return .alreadyGranted }
            guard book.begin(id) else { return .refuse }
            let view = occupancy(sessions: sessions)
            switch SessionCapacity.admission(for: .relay, occupancy: view) {
            case .accept:
                book.grant(id)
                return .grant
            case .closeThenAccept(let victim, let reason):
                guard victim != id else {
                    book.deny(id)
                    return .refuse
                }
                book.grant(id)
                return .closeThenGrant(id: victim, reason: reason)
            case .refuse:
                book.deny(id)
                return .refuse
            }
        }

        /// The session left the table. It holds no relay slot after this
        /// call. Its descriptor stays counted until `sessionClosed`.
        mutating func release(_ id: UUID) {
            book.release(id)
        }

        /// The sessions that still fit after the stopped runs. Each session
        /// can need `socketsPerSession` files. The value is not capped by the
        /// startup limit here. The caller caps it.
        private func dynamicSessionLimit(retiringSessions: Int) -> Int {
            guard let soft = softFileLimit, soft > reservedFileDescriptors else { return 0 }
            let used = reservedFileDescriptors
                + max(0, retiringSessions) * socketsPerSession
            guard soft > used else { return 0 }
            return (soft - used) / socketsPerSession
        }

    }

    /// The idle action for one timer check. An open TCP relay is never closed
    /// for silence alone. It rearms a check, so a later phase change still has
    /// a timer. The caller must set the phase at every transition.
    enum IdleAction: Equatable {
        /// Close the session. The phase bound expired.
        case close(CloseReason)
        /// Keep the session open. Check again after this delay.
        case rearm(after: TimeInterval)
    }

    static func idleAction(phase: Phase, phaseSeconds: TimeInterval,
                           idleSeconds: TimeInterval) -> IdleAction {
        switch phase {
        case .handshake:
            return bounded(phaseSeconds, bound: handshakePhaseSeconds,
                           reason: .handshakeExpired)
        case .connecting:
            return bounded(phaseSeconds, bound: connectPhaseSeconds,
                           reason: .connectExpired)
        case .awaitingRelay:
            return bounded(phaseSeconds, bound: relayGrantPhaseSeconds,
                           reason: .relayGrantExpired)
        case .udp:
            return bounded(idleSeconds, bound: relayIdleSeconds, reason: .udpIdle)
        case .halfClosed:
            return bounded(idleSeconds, bound: relayIdleSeconds,
                           reason: .halfClosedIdle)
        case .openTCP:
            return .rearm(after: openTCPRecheckSeconds)
        }
    }

    private static func bounded(_ value: TimeInterval, bound: TimeInterval,
                                reason: CloseReason) -> IdleAction {
        guard value < bound else { return .close(reason) }
        return .rearm(after: max(SessionIdleTimer.minimumRearm, bound - value))
    }

    /// The presence capacity at one instant. A presence probe authenticates
    /// and sends no request. It uses a setup slot, not a relay slot.
    ///
    /// This type reports capacity only. It does not promise that a probe
    /// succeeds. An unauthenticated client can occupy every setup slot first.
    /// A fixed reserve cannot guarantee presence under that saturation.
    struct Presence: Equatable {
        enum State: Equatable {
            /// One new connection can start now. It may be a presence probe.
            case available
            /// A stale session must close first.
            case afterStaleClose
            /// No capacity is free. This can refuse a presence probe.
            case blocked
        }

        let state: State
        /// The free total slots now. A setup session can use any free total
        /// slot, so this is also the free setup-slot count.
        let freeSetupSlots: Int
        /// True when the relay cap is reached. The free setup slots are the
        /// only headroom for a probe.
        let relayCapReached: Bool

        /// True when a refusal now can also refuse a presence probe.
        var refusesPossiblePresenceProbe: Bool { state == .blocked }
    }

    static func presenceCapacity(occupancy: Occupancy) -> Presence {
        let limits = limits(total: occupancy.limit)
        let free = max(0, limits.total - occupancy.sessions.count)
        let state: Presence.State
        switch admission(for: .connection, occupancy: occupancy) {
        case .accept: state = .available
        case .closeThenAccept: state = .afterStaleClose
        case .refuse: state = .blocked
        }
        return Presence(state: state,
                        freeSetupSlots: free,
                        relayCapReached: occupancy.relayCount >= limits.relay)
    }
}

/// One idle timer for one proxy session.
///
/// Traffic must not create a timer. Each `touch` keeps the one pending timer.
/// When it fires, one check compares the last activity with the idle limit. A
/// session that moved traffic arms the next check. A silent session closes.
/// The pending timer count is therefore one, not one per byte. An idle timer
/// per received chunk would hold many timers for the whole idle limit, and the
/// memory would grow with throughput.
///
/// `fired(idle:)` is the legacy silence-only rule. `fired(phase:...)` applies
/// the phase-aware policy. That rule never closes an open TCP relay for
/// silence alone.
struct SessionIdleTimer: Equatable {
    enum Decision: Equatable {
        /// The session was idle for the whole limit.
        case close
        /// The session moved traffic. Check again after this wait.
        case rearm(after: TimeInterval)
    }

    /// The shortest wait before the next check. It stops a tight loop when
    /// traffic ends just below the limit.
    static let minimumRearm: TimeInterval = 1

    let limit: TimeInterval
    /// True while one timer is pending for this session.
    private(set) var armed = false

    init(limit: TimeInterval) {
        precondition(limit > 0)
        self.limit = limit
    }

    /// Record traffic. Return true only when the caller must arm a timer.
    mutating func touch() -> Bool {
        guard !armed else { return false }
        armed = true
        return true
    }

    /// Record that the timer fired. The caller closes the session or keeps the
    /// next check armed for the remaining idle time.
    mutating func fired(idle: TimeInterval) -> Decision {
        if idle >= limit {
            armed = false
            return .close
        }
        armed = true
        return .rearm(after: max(Self.minimumRearm, limit - idle))
    }

    /// Record that the timer fired for one phase. The caller closes the
    /// session or arms the next check. An open TCP relay returns `.rearm` at
    /// every check and never closes for silence.
    ///
    /// Arm the first check with `SessionCapacity.idleAction(phase:
    /// phaseSeconds: 0, idleSeconds: 0)`. A handshake must not wait for the
    /// old 300 second timer.
    mutating func fired(phase: SessionCapacity.Phase, phaseSeconds: TimeInterval,
                        idleSeconds: TimeInterval) -> SessionCapacity.IdleAction {
        let action = SessionCapacity.idleAction(phase: phase, phaseSeconds: phaseSeconds,
                                                idleSeconds: idleSeconds)
        switch action {
        case .close:
            armed = false
        case .rearm:
            armed = true
        }
        return action
    }

    /// The session closed. No timer can fire for it again.
    mutating func disarm() { armed = false }
}

/// Raise the file descriptor limit at startup. The soft limit on an iOS app
/// starts near 256. The session cap needs more. A failure is recorded only.
enum FileDescriptorLimit {
    /// The highest soft limit the app asks for.
    static let ceiling = 4096

    enum Decision: Equatable {
        /// Set the soft limit to this value.
        case raise(to: Int)
        /// The soft limit is high enough.
        case unchanged(soft: Int)
    }

    /// The result of one apply call. It holds counts only.
    enum Outcome: Equatable {
        case raised(soft: Int)
        case alreadyHigh(soft: Int)
        /// The platform refused the change, or the limits cannot be read.
        case refused(soft: Int)

        /// The plain diagnostics line.
        var text: String {
            switch self {
            case .raised(let soft): return "File limit: \(soft), raised."
            case .alreadyHigh(let soft): return "File limit: \(soft), already high."
            case .refused(let soft): return "File limit: \(soft), could not raise."
            }
        }
    }

    /// Ask for `min(hard, ceiling)`, but never lower the soft limit.
    static func decision(soft: Int, hard: Int) -> Decision {
        let target = min(hard, ceiling)
        if soft >= target { return .unchanged(soft: soft) }
        return .raise(to: target)
    }

    /// Apply the decision. This call is cheap and safe to run once at startup.
    /// A nil result means the limits cannot be read.
    static func apply() -> Outcome? {
        var limit = rlimit()
        guard getrlimit(RLIMIT_NOFILE, &limit) == 0 else { return nil }
        let soft = Int(clamping: limit.rlim_cur)
        // A value at or above the ceiling, including an unlimited hard limit,
        // gives the ceiling. Int(clamping:) turns a huge value into Int.max.
        let hard = Int(clamping: limit.rlim_max)
        switch decision(soft: soft, hard: hard) {
        case .unchanged:
            return .alreadyHigh(soft: soft)
        case .raise(let value):
            var next = limit
            next.rlim_cur = rlim_t(value)
            guard setrlimit(RLIMIT_NOFILE, &next) == 0 else { return .refused(soft: soft) }
            var check = rlimit()
            guard getrlimit(RLIMIT_NOFILE, &check) == 0 else { return .refused(soft: soft) }
            return .raised(soft: Int(clamping: check.rlim_cur))
        }
    }
}

extension FileDescriptorLimit.Outcome {
    /// The soft limit after the apply call. A refused change reports the value
    /// that stayed in place.
    var softLimit: Int {
        switch self {
        case .raised(let soft), .alreadyHigh(let soft), .refused(let soft):
            return soft
        }
    }
}
