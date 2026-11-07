import Foundation

// A lifecycle refusal from the router. The app shows the sentence and never
// treats a stopped status as proof that routes were removed.
public enum TunnelRoutingError: LocalizedError, Equatable, Sendable {
    case tunnelAlreadyActive
    case startAlreadyInProgress
    case cleanupUncertain(String)
    case pairingBlockedByTunnel
    case startCancelledByStop

    public var errorDescription: String? {
        switch self {
        case .tunnelAlreadyActive:
            return "A tunnel is already active."
        case .startAlreadyInProgress:
            return "A tunnel start is already in progress."
        case .cleanupUncertain(let message):
            return message
        case .startCancelledByStop:
            return "The tunnel start was cancelled because the tunnel was turned off."
        case .pairingBlockedByTunnel:
            return "Turn off the tunnel before you pair with a source device."
        }
    }
}

// One stop flight serves every concurrent stop and quit caller. The first
// caller starts the operation and every later caller awaits the same result,
// so Turn off and Quit cannot observe two different outcomes for one stop.
// The waiter count is a hermetic test seam; it holds no state from a real stop.
actor TunnelStopFlight {
    private var active: (id: UInt64, task: Task<TunnelStopResult, Never>)?
    private var nextID: UInt64 = 0
    private var waiters = 0
    // A hermetic test seam that holds the first caller after its result
    // arrives, as a slow resume would. Production passes nil.
    private let afterFirstResult: (@Sendable () async -> Void)?

    init(afterFirstResult: (@Sendable () async -> Void)? = nil) {
        self.afterFirstResult = afterFirstResult
    }

    func run(_ operation: @escaping @Sendable () async -> TunnelStopResult) async -> TunnelStopResult {
        if let active {
            waiters += 1
            defer { waiters -= 1 }
            return await active.task.value
        }
        nextID &+= 1
        let id = nextID
        // The task starts after the flight is recorded. A second caller can
        // then only join the same task, never start a second helper stop.
        // The task ends the flight itself before its value is available, so a
        // caller that arrives after the stop finished starts a new stop
        // instead of reading the old result while the first caller resumes.
        let task = Task { [self] in
            let result = await operation()
            self.finish(id)
            return result
        }
        active = (id, task)
        let result = await task.value
        await afterFirstResult?()
        return result
    }

    private func finish(_ id: UInt64) {
        if active?.id == id { active = nil }
    }

    func waiterCount() -> Int { waiters }

    // A hermetic test seam: true while a flight has not ended.
    func isActive() -> Bool { active != nil }
}

// One app backend that serves the user-owned engine until a person turns the
// tunnel on. The user engine holds the pairing and the dashboard data. The
// elevated engine exists only for the duration of one tunnel and serves the
// live tunnel status, logs, diagnostics, and failures.
//
// The authorization step is a closure. In the app it asks for the one
// administrator prompt, writes the pairing handoff, and starts the root engine.
// This type runs that closure only after it proves that no earlier stop is
// unconfirmed. It never starts an elevated engine on its own, so a test or an
// unprivileged build cannot start one by accident.
public final class TunnelRoutingBackend: BackendClient, @unchecked Sendable {
    public typealias PrepareElevated = @Sendable () async throws -> BackendClient
    public typealias StopElevated = @Sendable () async -> TunnelStopResult
    public typealias AuthorizeStart = @Sendable () async throws -> Void
    // The model can be rebuilt after a user engine restart, a loss, or a quit
    // that the person cancelled. The session that already owns an elevated
    // engine outlives that model, so the router asks the session for the live
    // backend instead of forgetting it.
    public typealias ExistingElevated = @Sendable () -> BackendClient?

    private struct ElevatedSession {
        let id: UInt64
        let backend: BackendClient
        // The cleanup token this session retained. A stop clears only this
        // token, so a newer session installed by a concurrent start stays.
        let cleanupToken: UInt64
    }

    private let user: BackendClient
    private let prepareElevated: PrepareElevated
    private let stopElevated: StopElevated
    // The administrator prompt, the pairing handoff, and the root engine start
    // are one step. The router runs that step only after it proves that no
    // earlier stop is unconfirmed.
    private let authorizeStart: AuthorizeStart
    private let existingElevated: ExistingElevated
    // The app-owned cleanup state. It survives a model rebuild and is shared
    // with the tunnel session.
    private let cleanup: TunnelCleanupState
    private let lock = NSLock()
    private let stopFlight = TunnelStopFlight()
    private var elevated: ElevatedSession?
    private var nextSessionID: UInt64 = 0
    // Every stop moves this generation. A start that began before a stop must
    // not publish the engine that its authorizer prepared, because the person
    // or the quit asked for the tunnel to be off after the start began.
    private var stopGeneration: UInt64 = 0

    public init(
        user: BackendClient,
        prepareElevated: @escaping PrepareElevated,
        stopElevated: @escaping StopElevated,
        authorizeStart: @escaping AuthorizeStart = {},
        existingElevated: @escaping ExistingElevated = { nil },
        cleanup: TunnelCleanupState = TunnelCleanupState()
    ) {
        self.user = user
        self.prepareElevated = prepareElevated
        self.stopElevated = stopElevated
        self.authorizeStart = authorizeStart
        self.existingElevated = existingElevated
        self.cleanup = cleanup
    }

    // The session exists but no backend can describe it. A rebuilt model must
    // not show a clean Off or start a second root engine in that window. The
    // person can still run Turn off, which retries the helper stop.
    public var hasUnreachableElevatedSession: Bool {
        lock.lock()
        let local = elevated != nil
        lock.unlock()
        return !local && existingElevated() == nil && cleanup.hasElevatedSession
    }

    // The engine that answers a live status right now. The user engine answers
    // before a start and after a confirmed stop. The elevated engine answers
    // while a tunnel runs. A rebuilt model can still reach the session's live
    // backend.
    public var activeBackendIsElevated: Bool {
        lock.lock()
        let local = elevated != nil
        lock.unlock()
        return local || existingElevated() != nil || cleanup.hasElevatedSession
    }

    // A helper stop that did not confirm cleanup. The quit path must ask the
    // helper even when no elevated backend answered the last status.
    public var hasPendingStop: Bool {
        cleanup.hasPendingStop
    }

    // The plain message for the unconfirmed stop. The screen uses it so a
    // running false status cannot look like a clean Off.
    public var pendingStopMessage: String? {
        cleanup.pendingMessage
    }

    // The mark with its retry class. A terminal mark has no useful retry.
    public var pendingCleanup: TunnelCleanupPending? {
        cleanup.pending
    }

    // A tunnel start runs on this router or on one that an earlier model
    // built. It may not have stored a process handle yet, so neither the
    // elevated mark nor the pending mark shows it.
    public var hasStartInFlight: Bool {
        cleanup.hasStartInFlight
    }

    private func active() -> BackendClient {
        lock.lock()
        let local = elevated?.backend
        lock.unlock()
        return local ?? existingElevated() ?? user
    }

    private func currentElevated() -> ElevatedSession? {
        lock.lock(); defer { lock.unlock() }
        return elevated
    }

    // The live elevated backend, whether this model started it or a previous
    // model did.
    private func currentElevatedBackend() -> BackendClient? {
        currentElevated()?.backend ?? existingElevated()
    }

    private func clearElevated(id: UInt64? = nil) {
        lock.lock()
        var token: UInt64?
        if let id {
            if elevated?.id == id {
                token = elevated?.cleanupToken
                elevated = nil
            }
        } else {
            token = elevated?.cleanupToken
            elevated = nil
        }
        lock.unlock()
        // A stop for an older session must not clear the flag for a newer one
        // that a concurrent start installed. The token is the identity that
        // makes this check exact across routers and rebuilt models.
        cleanup.clearElevatedSession(ifToken: token)
    }

    // The tunnel session retains its own token when it stores the elevated
    // process. Adopt that token instead of retaining a second one: the shared
    // state holds one elevated token, and a second retention would overwrite
    // the session's token. The session could then never clear its own mark,
    // and every clean stop would look like a newer open session. A router
    // with no session (a test) retains its own.
    //
    // The stop generation is checked under the same lock that publishes the
    // session. A stop advances the generation and reads the published session
    // under that lock too, so either the stop sees this session and stops it,
    // or this start sees the stop and publishes nothing. Returns nil when a
    // stop ran after `stopMark`.
    private func setElevated(
        _ target: BackendClient,
        adopting adopted: UInt64?,
        ifNoStopSince stopMark: UInt64
    ) -> UInt64? {
        guard currentStopGeneration() == stopMark else { return nil }
        let token = adopted ?? cleanup.retainElevatedSession()
        lock.lock()
        let published = stopGeneration == stopMark
        if published {
            nextSessionID &+= 1
            elevated = ElevatedSession(id: nextSessionID, backend: target, cleanupToken: token)
        }
        let id = nextSessionID
        lock.unlock()
        guard published else {
            // A router-owned token for a session that is never published.
            if adopted == nil { cleanup.clearElevatedSession(ifToken: token) }
            return nil
        }
        return id
    }

    private func currentStopGeneration() -> UInt64 {
        lock.lock(); defer { lock.unlock() }
        return stopGeneration
    }

    // Cancel every start that began before this stop and read the session
    // that the stop must reach, in one step.
    private func beginStopGeneration() -> ElevatedSession? {
        lock.lock(); defer { lock.unlock() }
        stopGeneration &+= 1
        return elevated
    }

    // A final mark now describes a lost route observation, so the flag is
    // done. A newer retryable mark that won instead keeps the flag, so its
    // later helper confirmation still becomes a final mark.
    private func settleLostObservation(_ current: TunnelStopResult) -> TunnelStopResult {
        if current.cleanupKind != .retryable {
            cleanup.clearLostRouteObservation()
        }
        return current
    }

    private func pendingStop() -> String? {
        cleanup.pendingMessage
    }

    // Clear the exact latch that the stop operation observed. A latch that a
    // concurrent authorizer recorded while the stop was in flight stays.
    private func clearUncertainStop(ifToken token: UInt64?) {
        cleanup.clearPendingStop(ifToken: token)
    }

    // One start at a time. The authorizer may wait for a prompt, and a second
    // start must not prepare another root engine while the first is in flight.
    // The slot lives in the shared cleanup state, so a router rebuilt while an
    // older router still runs its start sees that start too.
    private func beginStart() throws {
        guard cleanup.beginStart() else {
            throw TunnelRoutingError.startAlreadyInProgress
        }
    }

    private func endStart() {
        cleanup.endStart()
    }

    // Record an unconfirmed helper stop. The stop paths use this, and a
    // hermetic test can simulate a quit that lands while a prompt is open.
    func recordUncertainStop(_ message: String, kind: TunnelCleanupKind = .retryable) {
        cleanup.recordPendingStop(message, kind: kind)
    }

    // MARK: - Tunnel

    public func startTunnel(experimentalICMP: Bool) async throws {
        try beginStart()
        defer { endStart() }
        // A stop that runs while this start waits for its prompt or its root
        // engine wins. This start must not publish an engine after it.
        let stopMark = currentStopGeneration()

        // These checks run before the administrator prompt, the credential
        // handoff, and the root engine start. A start that this router would
        // refuse must never prepare an elevated session first. An explicit
        // uncertain stop is a refusal. A running false status is not proof
        // that the earlier helper stop finished, so only a confirmed helper
        // stop clears it.
        if let pending = pendingStop() {
            throw TunnelRoutingError.cleanupUncertain(pending)
        }
        // A leftover elevated engine may have stopped its tunnel on its own
        // (hotspot loss or source device loss). Reconcile it with a confirmed
        // helper stop before this start asks for a new root engine. A retained
        // session with no backend cannot be inspected, so it stays a refusal
        // until a person stops it explicitly.
        if currentElevated() != nil || existingElevated() != nil {
            try await reconcileStoppedElevatedSession()
        } else if cleanup.hasElevatedSession {
            throw TunnelRoutingError.tunnelAlreadyActive
        }
        if let pending = pendingStop() {
            throw TunnelRoutingError.cleanupUncertain(pending)
        }
        if currentElevatedBackend() != nil || cleanup.hasElevatedSession {
            throw TunnelRoutingError.tunnelAlreadyActive
        }

        // The authorizer owns the prompt, the handoff, and the elevated engine
        // start. It is a separate step so a test or an unprivileged build
        // cannot start a root engine by accident.
        do {
            try await authorizeStart()
        } catch {
            // The authorizer can stop an engine that it could not start. If
            // it could not confirm that stop, latch it before any later start,
            // pairing request, forget, or quit can treat the app as idle.
            if let failure = error as? TunnelAuthorizationFailure, failure.isUncertainStop {
                recordUncertainStop(failure.message)
            }
            throw error
        }
        // The authorization is asynchronous. A quit or a failed stop can land
        // while the prompt or the engine start is in flight. A start that this
        // router now refuses must not leave the freshly prepared root engine
        // behind.
        if let pending = pendingStop() {
            let stop = await stopElevated()
            if let message = stop.message {
                recordUncertainStop(message, kind: stop.cleanupKind ?? .retryable)
            }
            throw TunnelRoutingError.cleanupUncertain(stop.message ?? pending)
        }
        // A stop that ran while the prompt or the engine start was in flight
        // cancels this start. Say so plainly, instead of the error that the
        // stopped engine would cause next.
        if currentStopGeneration() != stopMark {
            let stop = await stopElevated()
            if let message = stop.message {
                recordUncertainStop(message, kind: stop.cleanupKind ?? .retryable)
                throw TunnelRoutingError.cleanupUncertain(message)
            }
            throw TunnelRoutingError.startCancelledByStop
        }
        if currentElevated() != nil {
            // A concurrent start prepared an engine while this one waited. Do
            // not stop a session that may be serving a live prompt.
            throw TunnelRoutingError.tunnelAlreadyActive
        }
        // The session retained one token for the process it just stored.
        // Read it before the next await, so this router adopts the same
        // identity instead of retaining a second one.
        let adopted = cleanup.currentElevatedSessionToken
        // The authorizer has already asked for administrator authorization and
        // started the elevated engine with the pairing handoff. A failure here
        // is a failed start, not a second prompt.
        let target: BackendClient
        do {
            target = try await prepareElevated()
        } catch {
            // The authorizer may have started a root engine that this router
            // cannot address. Stop it instead of leaving it for the next start.
            let stop = await stopElevated()
            if let message = stop.message {
                recordUncertainStop(message, kind: stop.cleanupKind ?? .retryable)
                throw TunnelRoutingError.cleanupUncertain(message)
            }
            throw error
        }
        // A Turn off, a quit, or a lost-engine stop ran while this start was
        // in flight. That stop may have found no engine yet. Stop what the
        // authorizer prepared instead of publishing it.
        guard let sessionID = setElevated(target, adopting: adopted, ifNoStopSince: stopMark) else {
            let stop = await stopElevated()
            if let message = stop.message {
                recordUncertainStop(message, kind: stop.cleanupKind ?? .retryable)
                throw TunnelRoutingError.cleanupUncertain(message)
            }
            throw TunnelRoutingError.startCancelledByStop
        }
        do {
            try await target.startTunnel(experimentalICMP: experimentalICMP)
        } catch {
            let stop = await stopElevated()
            if let message = stop.message {
                // Keep the elevated engine as the only status source. The idle
                // user engine must not turn an unconfirmed helper stop into an
                // Off screen.
                recordUncertainStop(message, kind: stop.cleanupKind ?? .retryable)
                throw TunnelRoutingError.cleanupUncertain(message)
            }
            clearElevated(id: sessionID)
            throw error
        }
    }

    // A leftover elevated engine whose tunnel stopped on its own is not a new
    // start. Only a confirmed helper stop proves that its process and grant
    // directory are gone. A status that says running false is not enough.
    private func reconcileStoppedElevatedSession() async throws {
        guard let backend = currentElevatedBackend() else {
            throw TunnelRoutingError.tunnelAlreadyActive
        }
        let localID = currentElevated()?.id
        let live: Status
        do {
            live = try await backend.status(timeout: 2)
        } catch {
            throw TunnelRoutingError.cleanupUncertain(
                "The previous elevated engine did not answer, so HotspotShade cannot prove that its tunnel stopped."
            )
        }
        guard live.engineHealth.isNormal else {
            throw TunnelRoutingError.cleanupUncertain(
                live.engineHealth == .cleanupBlocked ? Strings.cleanupBlockedBody : Strings.serviceStateUnknownBody
            )
        }
        guard live.running != true else {
            throw TunnelRoutingError.tunnelAlreadyActive
        }
        // The status is only a reason to ask the helper. It is not cleanup
        // evidence and never clears the session by itself.
        let stop = await stopElevated()
        if let message = stop.message {
            recordUncertainStop(message, kind: stop.cleanupKind ?? .retryable)
            throw TunnelRoutingError.cleanupUncertain(message)
        }
        if let localID {
            clearElevated(id: localID)
        } else {
            clearElevated()
        }
    }

    public func stopTunnel(timeout: TimeInterval) async throws {
        let result = await stopFlight.run { [weak self] in
            guard let self else {
                return .uncertain("The app stopped before it could confirm the tunnel stop.")
            }
            return await self.performStop(timeout: timeout)
        }
        switch result {
        case .stopped, .notRunning:
            return
        case .uncertain(let message), .routesUnverified(let message), .durableBlock(let message):
            throw TunnelRoutingError.cleanupUncertain(message)
        }
    }

    // MARK: - Quit

    // The quit path must not skip the helper when the elevated engine already
    // reports a stopped tunnel. A previous helper stop may have been uncertain,
    // and only the helper owns that process and its grant directory. This
    // returns a plain error when the stop is not confirmed.
    public func stopForQuit() async -> String? {
        let result = await stopFlight.run { [weak self] in
            guard let self else {
                return .uncertain("The app stopped before it could confirm the tunnel stop.")
            }
            return await self.performStop(timeout: 45)
        }
        return result.message
    }

    // One stop for every caller. A concurrent Stop and Quit join the same
    // flight, so they see the same confirmed or uncertain result. A later
    // stand-alone stop can retry the helper when the session still exists.
    private func performStop(timeout: TimeInterval) async -> TunnelStopResult {
        // Cancel every start on this router that began before this stop, and
        // read the published session in the same step.
        let local = beginStopGeneration()
        let elevatedBackend = local?.backend ?? existingElevated()
        let pendingAtStart = cleanup.pending
        // Capture both generations before any await. A concurrent authorizer or
        // rebuilt router can record a newer mark or session while this stop
        // waits, and this call must not clear it.
        let pendingToken = pendingAtStart?.token
        let elevatedToken = cleanup.currentElevatedSessionToken
        let hadElevated = elevatedBackend != nil || cleanup.hasElevatedSession

        // A terminal mark has a defined answer. Without a handle or a backend
        // that could still own an engine, another helper call cannot add route
        // evidence, so return the same honest answer and do not loop.
        if let pending = pendingAtStart, pending.isTerminal,
           elevatedBackend == nil, !cleanup.hasElevatedSession {
            return pending.stopResult
        }

        var tunnelError: String?
        if let elevatedBackend {
            do {
                try await elevatedBackend.stopTunnel(timeout: timeout)
                // The same elevated engine answered this stop. An idle engine
                // refuses a stop while its own cleanup is uncertain, so this
                // answer replaces a route observation that an earlier attempt
                // lost.
                cleanup.clearLostRouteObservation()
            } catch {
                tunnelError = Strings.sanitized(error.localizedDescription)
                    ?? "The engine did not confirm the tunnel stop."
            }
        } else if !cleanup.hasElevatedSession {
            // The user engine never owns routes, and it is not the tunnel
            // engine. Ask it only when no elevated session exists at all.
            do {
                try await user.stopTunnel(timeout: timeout)
            } catch {
                tunnelError = Strings.sanitized(error.localizedDescription)
                    ?? "The engine did not confirm the tunnel stop."
            }
        }
        // Always reach the helper, even when an earlier stop was pending. The
        // helper stop is idempotent, and only the helper owns the process and
        // the grant directory.
        let stop = await stopElevated()
        switch stop {
        case .stopped, .notRunning:
            if hadElevated {
                if let local {
                    clearElevated(id: local.id)
                } else {
                    cleanup.clearElevatedSession(ifToken: elevatedToken)
                }
            }
            if hadElevated, tunnelError != nil || cleanup.hasLostRouteObservation {
                // The helper proved the root engine is gone, but that engine's
                // own stop reply was lost, in this attempt or an earlier one
                // that the engine never answered again. Route removal was never
                // observed, and no later helper call can recover that
                // observation. This is a final mark, not an endlessly retried
                // stop.
                let message = tunnelError.map { "\(EngineLaunchText.routeCleanupUnverified) \($0)" }
                    ?? EngineLaunchText.routeCleanupUnverified
                return settleLostObservation(
                    recordPendingUnlessNewer(
                        message,
                        kind: .routesUnverified,
                        observedToken: pendingToken
                    )
                )
            }
            clearUncertainStop(ifToken: pendingToken)
            if let newer = cleanup.pending {
                return newer.stopResult
            }
            // A concurrent start can install a newer elevated session while
            // this stop waits. The old token cannot clear it, and this stop is
            // not a clean answer for the newer session.
            if currentElevatedBackend() != nil || cleanup.hasElevatedSession {
                return recordPendingUnlessNewer(
                    EngineLaunchText.elevatedSessionOpen,
                    kind: .retryable,
                    observedToken: nil
                )
            }
            return .stopped
        case .uncertain(let message):
            // A helper session may still exist. Keep the elevated mark for a
            // later exact retry. When the engine's own reply was also lost,
            // remember that: a later retry that reaches only the helper, such
            // as the launch screen's Retry cleanup, must not turn this into a
            // clean stop.
            if hadElevated, tunnelError != nil {
                cleanup.recordLostRouteObservation()
            }
            return recordPendingUnlessNewer(
                message,
                kind: .retryable,
                observedToken: pendingToken
            )
        case .routesUnverified(let message):
            if hadElevated {
                if let local {
                    clearElevated(id: local.id)
                } else {
                    cleanup.clearElevatedSession(ifToken: elevatedToken)
                }
            }
            return settleLostObservation(
                recordPendingUnlessNewer(
                    message,
                    kind: .routesUnverified,
                    observedToken: pendingToken
                )
            )
        case .durableBlock(let message):
            // The helper may still own the process and refuses every start.
            // Keep the elevated mark and record a final block. No retry is
            // offered because it would return the same answer.
            return recordPendingUnlessNewer(
                message,
                kind: .durableBlock,
                observedToken: pendingToken
            )
        }
    }

    // Record one new mark unless a newer one appeared while this stop waited.
    // The returned result describes the mark that is now current.
    private func recordPendingUnlessNewer(
        _ message: String,
        kind: TunnelCleanupKind,
        observedToken: UInt64?
    ) -> TunnelStopResult {
        if let current = cleanup.pending, current.token != observedToken {
            return current.stopResult
        }
        cleanup.recordPendingStop(message, kind: kind)
        switch kind {
        case .retryable: return .uncertain(message)
        case .routesUnverified: return .routesUnverified(message)
        case .durableBlock: return .durableBlock(message)
        }
    }

    // MARK: - Status and run data

    public func status(timeout: TimeInterval) async throws -> Status {
        try await active().status(timeout: timeout)
    }

    public func logs(since: Int) async throws -> [LogLine] {
        try await active().logs(since: since)
    }

    public func failures() async throws -> Failures {
        try await active().failures()
    }

    public func probe() async throws -> Phone {
        try await active().probe()
    }

    public func diagnostics() async throws -> Diagnostics {
        try await active().diagnostics()
    }

    // MARK: - Pairing

    // Pairing belongs to the user engine. It is refused while an elevated
    // engine exists, a tunnel start is in flight, or an earlier stop is
    // unconfirmed. The user engine cannot see the root engine, so this
    // boundary must refuse before it asks. The session's own start handoff
    // goes to the user engine directly, not through this router.
    private func requirePairingAvailable() throws {
        if let pending = pendingStop() {
            throw TunnelRoutingError.cleanupUncertain(pending)
        }
        if currentElevatedBackend() != nil || cleanup.hasElevatedSession || cleanup.hasStartInFlight {
            throw TunnelRoutingError.pairingBlockedByTunnel
        }
    }

    public func pairState() async throws -> PairState {
        try await user.pairState()
    }

    public func startPairing() async throws {
        try requirePairingAvailable()
        try await user.startPairing()
    }

    // A cancel only settles a pairing that the user engine already owns. It
    // stays available while an elevated engine runs so a stuck request can
    // still be released.
    public func cancelPairing() async throws {
        try await user.cancelPairing()
    }

    public func forget() async throws -> ForgetState {
        if let pending = pendingStop() {
            throw TunnelRoutingError.cleanupUncertain(pending)
        }
        if currentElevatedBackend() != nil || cleanup.hasElevatedSession || cleanup.hasStartInFlight {
            throw BackendError.forgetBlockedByTunnel
        }
        return try await user.forget()
    }

    public func pairHandoff() async throws {
        try requirePairingAvailable()
        try await user.pairHandoff()
    }

    // MARK: - Test seams

    // The number of callers waiting on the current stop flight. A test uses
    // this to prove a quit joined a delayed Turn off instead of starting a
    // second helper stop.
    func stopWaiterCount() async -> Int {
        await stopFlight.waiterCount()
    }
}
