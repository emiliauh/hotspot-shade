import Foundation

/// Decide when the pairing listener needs to start or stop.
/// Pass `listening` as true while a listener exists, including while it starts
/// or waits. A separate grace period decides when a listener needs a retry.
struct PairingListenerPolicy {
    enum Observation { case present(String), absent, unreadable }
    enum Action: Equatable { case none, start(String), stop }
    static let failureMessage = "Pairing is unavailable. The app will try again while it is open."
    /// A failed bind waits this long before the next attempt.
    static let retrySeconds: TimeInterval = 10
    /// Require this many poll intervals of observed absence.
    static let absenceIntervals: TimeInterval = 15
    private let clock: () -> TimeInterval
    private var address: String?
    private var firstMissingAt: TimeInterval?
    private var lastMissingAt: TimeInterval?
    private var retryAt: TimeInterval = 0
    private var failureReported = false

    init(clock: @escaping () -> TimeInterval) { self.clock = clock }

    mutating func observe(_ observation: Observation, listening: Bool, pollInterval: TimeInterval) -> Action {
        let now = clock()
        switch observation {
        case .present(let found):
            if let current = address, current != found {
                return observeMissing(now: now, listening: listening, pollInterval: pollInterval)
            }
            address = found
            resetObservations()
            if !listening && now >= retryAt { return .start(found) }
        case .absent:
            if address != nil {
                return observeMissing(now: now, listening: listening, pollInterval: pollInterval)
            }
        case .unreadable: resetObservations()
        }
        return .none
    }

    /// A gap or an unreadable result cannot prove that the hotspot was absent.
    mutating func resetObservations() {
        firstMissingAt = nil
        lastMissingAt = nil
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
                resetObservations()
                return listening ? .stop : .none
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

    mutating func ready() { failureReported = false; retryAt = 0 }
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
