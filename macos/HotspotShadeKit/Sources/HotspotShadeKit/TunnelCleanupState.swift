import Foundation

// What the app can still prove about an unconfirmed stop.
//
// A retryable mark means that a later helper stop or status read may produce
// new evidence. A terminal mark means that the helper already proved that no
// elevated engine remains, or reported a durable cleanup block, so another
// stop cannot add route evidence. The app must not present a terminal mark as
// an endlessly retryable action.
public enum TunnelCleanupKind: Equatable, Sendable {
    // A live helper session, a stop in flight, or a lost connection. A later
    // helper stop may still confirm the exact session.
    case retryable
    // The helper proved that no engine remains, but the elevated engine's own
    // stop reply was lost. Route removal was never observed, and no later
    // helper call can recover that observation.
    case routesUnverified
    // The helper reported its durable cleanup block. The helper refuses every
    // start until a person completes the documented recovery.
    case durableBlock
}

// One app-owned cleanup mark. The token is monotonic and never reused, so a
// slow stop cannot clear a newer mark that happens to have the same text.
public struct TunnelCleanupPending: Equatable, Sendable {
    public let token: UInt64
    public let message: String
    public let kind: TunnelCleanupKind

    public init(token: UInt64, message: String, kind: TunnelCleanupKind) {
        self.token = token
        self.message = message
        self.kind = kind
    }

    // A terminal mark has a defined answer. A retry repeats it and never turns
    // it into a clean stop.
    public var isTerminal: Bool { kind != .retryable }
}

// The cleanup state that belongs to the app, not to one built model. A user
// engine loss, a retry, or a quit that the person cancels can drop and rebuild
// the model. The app must not forget an unconfirmed helper stop or a live
// elevated session when that happens, because the idle user engine cannot prove
// either one away.
//
// One instance is shared by the tunnel session and by every routing backend
// that the app builds for that session. It holds no credential, address, or
// token other than its own monotonic generation values.
public final class TunnelCleanupState: @unchecked Sendable {
    private let lock = NSLock()
    private var pendingStop: TunnelCleanupPending?
    private var elevatedSessionToken: UInt64?
    private var nextToken: UInt64 = 0
    // True after the elevated engine's own stop reply was lost and the helper
    // could not settle the stop in the same attempt. A later helper answer
    // alone cannot replace that route observation. Only a later stop answer
    // from the same elevated engine clears it: an idle engine refuses a stop
    // while its own cleanup is uncertain. A helper that confirms the process
    // is gone turns it into a final route-unverified mark.
    private var routeObservationLost = false
    // True while a tunnel start runs, from the router's entry until it
    // returns. That covers the prompt, the pairing handoff, and the helper
    // start, including the window before the session stores a process handle.
    // A lost user engine or a quit Stay can rebuild the model and the router
    // in that window. The new ones read this shared flag, so a start that an
    // older router owns still refuses Pair, a pairing handoff, and Forget, and
    // a quit still waits for it.
    private var startInFlight = false

    public init() {}

    public var hasStartInFlight: Bool {
        lock.lock(); defer { lock.unlock() }
        return startInFlight
    }

    // Claim the one start slot. Returns false while another start, from this
    // router or from an earlier one, still runs.
    public func beginStart() -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard !startInFlight else { return false }
        startInFlight = true
        return true
    }

    public func endStart() {
        lock.lock(); startInFlight = false; lock.unlock()
    }

    // Wait a bounded time for a start to settle. A system authorization
    // prompt may never answer, so the caller gets false instead of blocking.
    public func waitForStartToSettle(within seconds: TimeInterval) async -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while hasStartInFlight {
            if Date() >= deadline { return false }
            try? await Task.sleep(nanoseconds: 40_000_000)
        }
        return true
    }

    public var hasLostRouteObservation: Bool {
        lock.lock(); defer { lock.unlock() }
        return routeObservationLost
    }

    public func recordLostRouteObservation() {
        lock.lock(); routeObservationLost = true; lock.unlock()
    }

    // The same elevated engine answered a later stop, or a final mark now
    // describes the lost observation.
    public func clearLostRouteObservation() {
        lock.lock(); routeObservationLost = false; lock.unlock()
    }

    // Every mark and every retained session gets a new token under the lock.
    // A caller can clear only the exact token that it observed.
    private func takeToken() -> UInt64 {
        nextToken &+= 1
        return nextToken
    }

    // The plain message for the last unconfirmed stop, or nil when cleanup is
    // confirmed. A running false status never clears this value.
    public var pending: TunnelCleanupPending? {
        lock.lock(); defer { lock.unlock() }
        return pendingStop
    }

    public var pendingMessage: String? {
        lock.lock(); defer { lock.unlock() }
        return pendingStop?.message
    }

    public var hasPendingStop: Bool {
        lock.lock(); defer { lock.unlock() }
        return pendingStop != nil
    }

    public var hasElevatedSession: Bool {
        lock.lock(); defer { lock.unlock() }
        return elevatedSessionToken != nil
    }

    // The token of the retained elevated session. A stop captures it before it
    // waits, and clears only that token.
    public var currentElevatedSessionToken: UInt64? {
        lock.lock(); defer { lock.unlock() }
        return elevatedSessionToken
    }

    @discardableResult
    public func recordPendingStop(
        _ message: String,
        kind: TunnelCleanupKind = .retryable
    ) -> UInt64 {
        lock.lock()
        let token = takeToken()
        pendingStop = TunnelCleanupPending(token: token, message: message, kind: kind)
        lock.unlock()
        return token
    }

    // Clear only the exact mark that a stop operation observed. A newer mark
    // that a concurrent authorizer or router recorded must stay, even when its
    // text is identical.
    @discardableResult
    public func clearPendingStop(ifToken token: UInt64?) -> Bool {
        guard let token else { return false }
        lock.lock()
        let cleared = pendingStop?.token == token
        if cleared { pendingStop = nil }
        lock.unlock()
        return cleared
    }

    // An elevated session is retained from the moment a process handle exists
    // until a helper stop confirms that it is gone. Each retention returns a
    // token so a stale stop cannot clear a newer session.
    @discardableResult
    public func retainElevatedSession() -> UInt64 {
        lock.lock()
        let token = takeToken()
        elevatedSessionToken = token
        lock.unlock()
        return token
    }

    @discardableResult
    public func clearElevatedSession(ifToken token: UInt64?) -> Bool {
        guard let token else { return false }
        lock.lock()
        let cleared = elevatedSessionToken == token
        if cleared { elevatedSessionToken = nil }
        lock.unlock()
        return cleared
    }
}

// One app-wide action gate. A quit closes the gate before it touches the
// tunnel, so every later dashboard, menu, or automatic action is refused,
// including a direct call that does not go through the Coordinator.
//
// Stay advances the generation again. An action that began before the quit
// keeps its old token and stays cancelled, while a new action after Stay can
// proceed.
public final class AppActionGate: @unchecked Sendable {
    public struct Token: Equatable, Sendable {
        public let generation: UInt64
        public init(generation: UInt64) { self.generation = generation }
    }

    // The token of the action that the current task serves. The model sets it
    // around a tunnel call, so the tunnel session can check the generation of
    // the press itself, not the generation at the moment the session runs. A
    // press from before a quit then stays cancelled after Stay, even when it
    // reaches the session late.
    @TaskLocal public static var actionToken: Token?

    private let lock = NSLock()
    private var generation: UInt64 = 0
    private var closed = false

    public init() {}

    public func current() -> Token {
        lock.lock(); defer { lock.unlock() }
        return Token(generation: generation)
    }

    public var isQuitting: Bool {
        lock.lock(); defer { lock.unlock() }
        return closed
    }

    // Close the gate and cancel every action that already holds a token.
    public func beginQuit() {
        lock.lock()
        generation &+= 1
        closed = true
        lock.unlock()
    }

    // Stay keeps the app open. A later action gets the new generation.
    public func cancelQuit() {
        lock.lock()
        generation &+= 1
        closed = false
        lock.unlock()
    }

    public func permits(_ token: Token) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return !closed && token.generation == generation
    }
}

// One start generation for the tunnel session. A quit or a stop cancels every
// start that began before it, even when the person later chooses Stay and a new
// start is allowed. The abort is a generation, not a boolean, so a new start
// after Stay can proceed while the older start stays cancelled.
public final class TunnelStartFence: @unchecked Sendable {
    private let lock = NSLock()
    private var generation: UInt64 = 0

    public init() {}

    public func current() -> UInt64 {
        lock.lock(); defer { lock.unlock() }
        return generation
    }

    // Cancel every start that has already begun. A start that finishes after
    // this call must not publish a tunnel or ask for an authorization.
    public func abortPendingStarts() {
        lock.lock()
        generation &+= 1
        lock.unlock()
    }

    public func permits(_ token: UInt64) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return token == generation
    }
}
