import Foundation

// The helper's liveness and authorization-deadline watch. One timer serves the
// current session. A path that ends one session (an expired authorization, a
// reaped engine, a stop) must not cancel the timer that a newer session needs.
//
// The watch counts every session start. An idle check reads that count, asks
// whether any session exists, and cancels the timer only when no session
// exists and no start was counted in between. A start that lands after the
// check keeps the timer, and a start after a cancel creates a new one.
public final class HelperLivenessWatch<Timer>: @unchecked Sendable {
    private let lock = NSLock()
    private var timer: Timer?
    private var starts: UInt64 = 0

    public init() {}

    public var isActive: Bool {
        lock.lock(); defer { lock.unlock() }
        return timer != nil
    }

    // Call after the controller started a session. `make` runs only when no
    // timer exists, under the watch lock.
    public func sessionStarted(make: () -> Timer) {
        lock.lock(); defer { lock.unlock() }
        starts &+= 1
        if timer == nil { timer = make() }
    }

    // Returns the timer to cancel, or nil when a session exists or a start was
    // counted while the check ran. `sessionExists` runs outside the watch lock.
    public func stopIfIdle(sessionExists: () -> Bool) -> Timer? {
        lock.lock()
        let observed = starts
        lock.unlock()
        if sessionExists() { return nil }
        lock.lock(); defer { lock.unlock() }
        guard starts == observed else { return nil }
        let stopped = timer
        timer = nil
        return stopped
    }

    // Shutdown only. The helper is about to stop every session and exit.
    public func stopForShutdown() -> Timer? {
        lock.lock(); defer { lock.unlock() }
        let stopped = timer
        timer = nil
        return stopped
    }
}
