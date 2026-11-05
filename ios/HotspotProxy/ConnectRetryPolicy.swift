import Foundation

// Decide whether one outbound connection needs a retry. This file uses
// Foundation only, and the caller injects the clock. No code here opens a
// socket.
//
// A `.waiting` state can come from a short cellular path change. Network
// framework keeps the connection and can make it ready when the path returns.
// A cancel after 250 ms threw away connections that were still viable. The
// policy now waits `retryDelay` seconds for that recovery. It then asks for one
// new connection with the same host, port, and cellular pin only when the wait
// is sustained. It never selects another interface. The attempt deadline stays
// outside this type, so the retry runs inside the same 4 seconds.
//
// Privacy: the counters hold class counts only. They hold no host, address,
// port, or token.

/// The retry decision for one outbound connection attempt.
struct ConnectRetryPolicy {
    /// The wait before the retry. A short path change often clears by itself,
    /// and a 250 ms cancel reset a connection that would have become ready.
    static let retryDelay: TimeInterval = 1.5
    /// One retry only. A second retry would eat the deadline.
    static let maximumRetries = 1

    /// One state event for the attempt. It mirrors `ConnectAttempt.Event` and
    /// adds `retryDue` for the retry timer.
    enum Event: Equatable {
        case waiting(ConnectAttempt.Failure)
        case ready
        case failed(ConnectAttempt.Failure)
        case cancelled
        case deadline
        /// The retry timer fired.
        case retryDue
    }

    enum Action: Equatable {
        /// Nothing to do.
        case none
        /// Schedule `retryDue` after `retryDelay` seconds.
        case waitForRetry
        /// Cancel the current connection. Start one new connection with the
        /// same parameters and the same cellular pin.
        case retry
        /// The attempt has a final state. The caller reports it.
        case finish
    }

    /// Wait counts by error. A wait is not a final state. A wait alone never
    /// makes the result unreachable.
    struct WaitCounts: Equatable {
        private(set) var unreachable = 0
        private(set) var refused = 0
        private(set) var other = 0

        var total: Int { unreachable + refused + other }

        mutating func record(_ failure: ConnectAttempt.Failure) {
            switch ConnectAttempt.failureReason(failure) {
            case .unreachable: unreachable += 1
            case .refused: refused += 1
            case .notReady, .timedOut, .other: other += 1
            }
        }

        mutating func add(_ counts: WaitCounts) {
            unreachable += counts.unreachable
            refused += counts.refused
            other += counts.other
        }
    }

    /// The counts from one attempt. The server adds them to the diagnostics.
    struct Totals: Equatable {
        var waits = WaitCounts()
        var retryStarts = 0
        var retrySuccesses = 0
        var deadlineFires = 0
    }

    private(set) var waits = WaitCounts()
    private(set) var retryStarts = 0
    private(set) var retrySuccesses = 0
    private(set) var deadlineFires = 0
    private var retryScheduled = false
    private var retryAt: TimeInterval = 0
    private var retrying = false
    private var resolved = false
    private let clock: () -> TimeInterval

    /// Pass the clock for the tests. The default is the monotonic system clock.
    init(clock: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }) {
        self.clock = clock
    }

    /// The counts after the events so far.
    var totals: Totals {
        Totals(waits: waits, retryStarts: retryStarts,
               retrySuccesses: retrySuccesses, deadlineFires: deadlineFires)
    }

    /// Handle one event. After a final state, every later event does nothing.
    mutating func handle(_ event: Event) -> Action {
        switch event {
        case .waiting(let failure):
            guard !resolved else { return .none }
            waits.record(failure)
            // The first wait schedules one retry. A second wait inside the
            // same delay keeps the first schedule.
            guard !retryScheduled, retryStarts < Self.maximumRetries else { return .none }
            retryScheduled = true
            retryAt = clock() + Self.retryDelay
            return .waitForRetry
        case .retryDue:
            guard !resolved, retryScheduled, retryStarts < Self.maximumRetries else { return .none }
            // A timer that fires early asks for a new schedule. Do not retry
            // before the full delay.
            guard clock() >= retryAt else { return .waitForRetry }
            retryScheduled = false
            retryStarts += 1
            retrying = true
            return .retry
        case .ready:
            guard !resolved else { return .none }
            resolved = true
            retryScheduled = false
            if retrying { retrySuccesses += 1 }
            retrying = false
            return .finish
        case .failed, .cancelled, .deadline:
            guard !resolved else { return .none }
            resolved = true
            retryScheduled = false
            retrying = false
            if case .deadline = event { deadlineFires += 1 }
            return .finish
        }
    }
}
