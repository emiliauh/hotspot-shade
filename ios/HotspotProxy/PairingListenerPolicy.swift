import Foundation

/// Decide when the pairing listener needs to start or stop.
/// Pass `listening` as true while a listener exists, including while it starts
/// or waits. A separate grace period decides when a listener needs a retry.
///
/// The listener binds an address, not an interface name. Network.framework has
/// no public way to construct `NWInterface` from a name, so the policy keeps
/// the observed interface identity beside the address. A complete observation
/// that names another interface at the same address is a link change, not
/// continued presence. The name is one local record. It does not prove that
/// Personal Hotspot is on, and two links that reuse the same name and address
/// cannot be told apart.
struct PairingListenerPolicy {
    enum Observation { case present(String), absent, unreadable }
    enum Action: Equatable { case none, start(String), stop }

    /// Why the policy last ended a listener. The action stays `.stop` for
    /// every cause, so the server does not need a second path. A test can tell
    /// a missing address from a replaced or unsupported link.
    enum StopCause: Equatable {
        case absent
        case linkChanged
        case unsupportedLink
    }

    static let failureMessage = "Pairing is unavailable. The app will try again while it is open."
    /// A failed bind waits this long before the next attempt.
    static let retrySeconds: TimeInterval = 10
    /// Require this many poll intervals of observed absence.
    static let absenceIntervals: TimeInterval = 15
    private let clock: () -> TimeInterval
    /// The identity-aware observation. The pairing path receives only an
    /// address, so it reads the latest observation and uses it only when the
    /// address matches.
    private let latestLink: () -> HotspotInterface.LinkObservation?
    private var address: String?
    private var identity: HotspotInterface.Identity?
    private var firstMissingAt: TimeInterval?
    private var lastMissingAt: TimeInterval?
    private var retryAt: TimeInterval = 0
    private var failureReported = false
    private(set) var lastStopCause: StopCause?

    init(clock: @escaping () -> TimeInterval,
         latestLink: @escaping () -> HotspotInterface.LinkObservation? = {
             HotspotInterface.latestLinkObservation
         }) {
        self.clock = clock
        self.latestLink = latestLink
    }

    mutating func observe(_ observation: Observation, listening: Bool, pollInterval: TimeInterval) -> Action {
        let now = clock()
        let link = latestLink()
        switch observation {
        case .present(let found):
            // The hotspot address is now on a link type this build does not
            // support. Do not start or keep a pairing listener there.
            if case .unsupported(let observed)? = link, observed.address == found {
                return stopForMismatch(.unsupportedLink, listening: listening)
            }
            if let current = address, current != found {
                return observeMissing(now: now, listening: listening, pollInterval: pollInterval)
            }
            if case .present(let observed)? = link, observed.address == found {
                if let bound = identity, bound != observed {
                    // The address is the same, but the interface is not. The
                    // listener still points at an address that no longer
                    // belongs to the link it used.
                    return stopForMismatch(.linkChanged, listening: listening)
                }
                identity = observed
            }
            address = found
            resetObservations()
            if !listening && now >= retryAt {
                lastStopCause = nil
                return .start(found)
            }
        case .absent:
            // The legacy observation reports an unsupported link as absent.
            // The recorded identity can still tell it apart.
            if case .unsupported(let observed)? = link,
               let bound = identity, observed.address == bound.address {
                return stopForMismatch(.unsupportedLink, listening: listening)
            }
            if address != nil {
                return observeMissing(now: now, listening: listening, pollInterval: pollInterval)
            }
        case .unreadable:
            resetObservations()
        }
        return .none
    }

    /// A gap or an unreadable result cannot prove that the hotspot was absent.
    mutating func resetObservations() {
        firstMissingAt = nil
        lastMissingAt = nil
    }

    private mutating func stopForMismatch(_ cause: StopCause, listening: Bool) -> Action {
        address = nil
        identity = nil
        resetObservations()
        guard listening else { return .none }
        lastStopCause = cause
        return .stop
    }

    private mutating func observeMissing(now: TimeInterval, listening: Bool, pollInterval: TimeInterval) -> Action {
        guard now.isFinite, pollInterval.isFinite, pollInterval > 0 else {
            resetObservations()
            return .none
        }
        if let last = lastMissingAt, now >= last, now - last <= pollInterval * 3,
           let first = firstMissingAt {
            lastMissingAt = now
            if now - first >= pollInterval * Self.absenceIntervals {
                address = nil
                identity = nil
                resetObservations()
                guard listening else { return .none }
                lastStopCause = .absent
                return .stop
            }
        } else {
            firstMissingAt = now
            lastMissingAt = now
        }
        return .none
    }

    mutating func failed() -> String? {
        retryAt = clock() + Self.retrySeconds
        guard !failureReported else { return nil }
        failureReported = true
        return Self.failureMessage
    }

    mutating func ready() {
        failureReported = false
        retryAt = 0
        lastStopCause = nil
    }
}

/// Bound how long a starting or waiting listener can remain unready.
struct PairingListenerGrace {
    static let seconds: TimeInterval = 5
    private(set) var deadline: TimeInterval?

    mutating func begin(now: TimeInterval) {
        if deadline == nil { deadline = now + Self.seconds }
    }
    mutating func clear() { deadline = nil }
    mutating func expire(now: TimeInterval) -> Bool {
        guard let deadline, now >= deadline else { return false }
        self.deadline = nil
        return true
    }
}

/// Track the pairing sockets that have not sent a complete frame.
///
/// A socket with no complete frame does not own a responder session. It is a
/// slot that a silent client can hold, so the listener closes it after
/// `firstFrameSeconds` and may evict it to admit a new connection.
///
/// A socket that sent a complete frame is a real session. The responder owns
/// every later deadline, including the 60 second active prompt and its 120
/// second inactive extension. Do not add a second absolute connection bound:
/// it would cut a prompt that the person can still answer.
struct PairingConnectionSlots {
    enum Admission: Equatable {
        case accept
        /// Close this connection first, then admit the new one.
        case evict(Int)
        /// No connection can be evicted. Refuse the new one.
        case refuse
    }
    /// The longest a socket may take to send its first complete frame.
    static let firstFrameSeconds: TimeInterval = 10
    let maximum: Int
    private(set) var connections: [Int] = []
    private(set) var waiting: Set<Int> = []

    init(maximum: Int = 4) {
        precondition(maximum > 0)
        self.maximum = maximum
    }

    /// Admit one connection in accept order. Prefer the oldest socket with no
    /// complete frame. When every socket already sent a frame, evict the
    /// oldest socket other than the live prompt. Never evict the prompt
    /// connection, because the person may be looking at its code.
    mutating func admit(_ id: Int, protected: Int?) -> Admission {
        if connections.count >= maximum {
            if let victim = connections.first(where: { waiting.contains($0) }) {
                remove(victim)
                add(id)
                return .evict(victim)
            }
            if let victim = connections.first(where: { $0 != protected }) {
                remove(victim)
                add(id)
                return .evict(victim)
            }
            return .refuse
        }
        add(id)
        return .accept
    }

    /// The socket sent a complete frame. The responder owns its deadlines
    /// from now on.
    mutating func receivedFrame(_ id: Int) {
        waiting.remove(id)
    }

    /// The socket closed or the listener stopped.
    mutating func remove(_ id: Int) {
        waiting.remove(id)
        connections.removeAll { $0 == id }
    }

    func isWaiting(_ id: Int) -> Bool { waiting.contains(id) }

    private mutating func add(_ id: Int) {
        guard !connections.contains(id) else { return }
        connections.append(id)
        waiting.insert(id)
    }
}

/// The hotspot poll interval. It looks at the network interfaces, so it runs
/// only while the app is active.
enum HotspotPoll {
    /// The proxy runs. A lost hotspot must stop it soon.
    static let runningSeconds: TimeInterval = 2
    /// The proxy is stopped. The hotspot can still appear or disappear.
    static let stoppedSeconds: TimeInterval = 5

    /// Return the repeat interval, or nil when the app is inactive.
    static func interval(proxyRunning: Bool, active: Bool) -> TimeInterval? {
        guard active else { return nil }
        return proxyRunning ? runningSeconds : stoppedSeconds
    }
}
