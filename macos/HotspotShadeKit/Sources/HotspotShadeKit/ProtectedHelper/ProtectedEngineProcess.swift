import Foundation

// One engine started as root by the protected XPC helper.
//
// The app never elevates the bundled engine itself. It asks the installed
// helper to start a root-owned, signed engine and receives that engine's
// loopback port, per-launch secret, and session id in an authenticated XPC
// reply. When the helper is absent or not signed for this app, construction
// fails and the app shows a plain unavailable state. There is no fallback to
// `osascript` and no restart after a lost connection.
//
// Starting the engine creates no route and no tunnel device, so it does not ask
// for an administrator authorization. The app starts this process only when a
// person turns the tunnel on; the user-owned engine serves the full interface
// and the pairing. Starting the tunnel changes the host's routes as root, so
// `authorizeStart` asks Authorization Services for one administrator
// authorization and the helper verifies it before it writes the one-time grant
// that the engine consumes. A cancelled, denied, or unavailable authorization
// is a failed tunnel start, never a start without a grant.
public final class ProtectedEngineProcess: @unchecked Sendable {
    private let client: ProtectedHelperClient
    private let authorization: HelperStartAuthorizationProviding
    private let startRightChecker: HelperStartRightConfigurationChecking
    private let lock = NSLock()
    // A start request and a stop request must not share one helper connection
    // at the same time. A quit can arrive while a delayed start is still
    // between its status read and its start request. The fence cancels that
    // start, and this lock serializes the transport calls.
    private let operationLock = NSLock()
    private let startFence = TunnelStartFence()
    private var storedPort: UInt16?
    private var storedSecret = ""
    // The helper's identity for the engine session. It survives an uncertain
    // stop so a later reconnect can ask about that exact session. A new
    // connection's own empty acknowledgement is never accepted in its place.
    private var storedSessionID: UUID?
    // True once this object asked the helper for an engine. It stays true while
    // a stop is unconfirmed, even when no session id arrived, because a lost
    // start reply may still have started an engine.
    private var everStartedSession = false
    // The last stop answer, including whether a retry can change it. A later
    // stop must reconnect and ask the helper about the retained session instead
    // of treating a new connection's acknowledgement as a clean stop.
    private var lastStopResult: TunnelStopResult = .notRunning

    public init(
        client: ProtectedHelperClient,
        authorization: HelperStartAuthorizationProviding,
        startRightChecker: HelperStartRightConfigurationChecking = SecurityStartRightConfigurationChecker()
    ) {
        self.client = client
        self.authorization = authorization
        self.startRightChecker = startRightChecker
    }

    // Build the production client from the running app's own signature. The
    // expected team never comes from a plist, an environment variable, or a
    // request. An unsigned or ad-hoc app fails here and cannot elevate.
    public convenience init(
        bundlePath: String = Bundle.main.bundlePath,
        signatures: HelperCodeSignatureChecking = SecurityHelperCodeSignatureChecker(),
        authorization: HelperStartAuthorizationProviding = AuthorizationServicesStartAuthorization()
    ) throws {
        let team = try HelperInstallPolicy.developerTeamIdentifier(
            bundlePath: bundlePath,
            signatures: signatures
        )
        let policy = HelperInstallPolicy(
            layout: .rootOwnedCopy,
            helperPath: HelperRequirement.helperExecutablePath,
            launchDaemonPlistPath: HelperRequirement.launchDaemonPath,
            expectedTeamIdentifier: team
        )
        let verifier = HelperInstallVerifier(policy: policy, signatures: signatures)
        let client = ProtectedHelperClient(verifier: verifier) { install in
            try XPCProtectedHelperTransport(install: install)
        }
        self.init(client: client, authorization: authorization)
    }

    // True while this object may own an engine session. An uncertain stop keeps
    // the retained session id, so this stays true until the helper confirms the
    // stop. That is what prevents a second root engine from being prepared.
    public var isRunning: Bool {
        if case .running = client.state { return true }
        lock.lock(); defer { lock.unlock() }
        return storedSessionID != nil || everStartedSession
    }

    // The reason the last helper interaction failed, when the client has one.
    // The app uses this to show the cleanup block instead of a plain stop.
    public var unavailableReason: HelperTrustError? {
        if case .unavailable(let error) = client.state { return error }
        return nil
    }

    public var port: UInt16? {
        lock.lock(); defer { lock.unlock() }
        return storedPort
    }

    public var secret: String {
        lock.lock(); defer { lock.unlock() }
        return storedSecret
    }

    // The fixed reason when the helper reported that this engine exited
    // before any grant, so the tunnel did not start and no route changed.
    public var startFailureReason: EngineStartFailureReason? {
        if let reason = client.startFailure { return reason }
        lock.lock(); defer { lock.unlock() }
        return observedStartFailure
    }

    // A helper stop or status answer can report the same failed start for the
    // exact retained session, for example when the engine exited before the
    // helper's liveness notice arrived.
    private var observedStartFailure: EngineStartFailureReason?

    private func noteStartFailure(_ status: HelperStatus?, session: UUID?) {
        guard let status, let session, status.lastSession == session,
              status.lastResult == .failedStart
        else { return }
        lock.lock()
        observedStartFailure = status.lastFailureReason ?? .exitedWithoutReason
        lock.unlock()
    }

    public var sessionID: UUID? {
        lock.lock(); defer { lock.unlock() }
        return storedSessionID
    }

    // The last helper stop or cleanup answer, with its retry class. The tunnel
    // session reads this after it calls stop or confirmCleanup.
    public var lastStop: TunnelStopResult {
        lock.lock(); defer { lock.unlock() }
        return lastStopResult
    }

    // A quit or a stop cancels a delayed start before it asks the helper for an
    // engine. The generation stays cancelled after Stay, so an old start cannot
    // resume. A new start is a new call with a new token.
    public func abortPendingStarts() {
        startFence.abortPendingStarts()
    }

    // This call blocks on the XPC reply. The app runs it off the main actor.
    // Starting the engine changes no route, so it never prompts. The helper
    // still checks its install, its caller, its session, and its cleanup state.
    public func start(
        timeout: TimeInterval = 20,
        cancellation: EngineLaunchCancellation? = nil,
        credentials: Int32? = nil
    ) throws {
        let token = startFence.current()
        try checkStartAllowed(token, cancellation)
        operationLock.lock()
        defer { operationLock.unlock() }
        // A quit can land while this call waits for the operation lock or for
        // any helper reply. Check again before the first side effect.
        try checkStartAllowed(token, cancellation)
        // A start must never paper over an earlier unconfirmed stop. The
        // routing layer retries the stop first; this guard keeps a direct
        // caller from starting a second engine in the meantime.
        lock.lock()
        let stopPending = lastStopResult.isUncertain
        lock.unlock()
        if stopPending { throw HelperTrustError.stopNotConfirmed }
        _ = try client.connect()
        do {
            try checkStartAllowed(token, cancellation)
            // Read the helper state through the authenticated connection. A
            // running engine, a stop still in flight, a durable cleanup block,
            // or an unreadable status must fail before the helper is asked to
            // start another one. The helper repeats every check on start.
            let status = try client.status()
            if status.cleanupBlocked { throw HelperTrustError.cleanupBlocked }
            if status.running || status.stopping || status.starting { throw HelperTrustError.helperBusy }
            try checkStartAllowed(token, cancellation)
        } catch {
            // A cancelled or failed start must not leave the helper connection
            // open with a handshake that could be reused later.
            client.close()
            throw error
        }
        let reply: HelperStartReply
        do {
            reply = try client.start(timeout: timeout, credentials: credentials)
        } catch {
            // A lost or ambiguous start reply can hide a running engine. Keep
            // that uncertainty so a later stop reconnects and checks the
            // helper instead of starting another engine.
            if Self.isAmbiguousStartFailure(error) {
                lock.lock()
                lastStopResult = .uncertain(EngineLaunchText.stopUnverified)
                everStartedSession = true
                lock.unlock()
            }
            client.close()
            throw error
        }
        // The helper may have started the engine after a quit began. Do not
        // publish that engine. Stop it on the same connection, and keep the
        // session id if the stop is not confirmed so a later stop can reach it.
        if !startFence.permits(token) || cancellation?.isCancelled == true {
            let result = stopStartedEngine(reply: reply)
            throw result.isUncertain ? HelperTrustError.stopNotConfirmed : HelperTrustError.cancelled
        }
        lock.lock()
        storedPort = reply.port
        storedSecret = reply.secret
        storedSessionID = reply.sessionID
        everStartedSession = true
        lastStopResult = .notRunning
        observedStartFailure = nil
        lock.unlock()
    }

    // Ask for one administrator authorization for the tunnel start and send it
    // to the helper on the live engine connection. The helper verifies the form
    // and writes the one-time grant that the engine consumes before it changes
    // a route. The authorization lease stays held until the reply arrives,
    // because the helper checks the form during the request.
    public func authorizeStart(
        timeout: TimeInterval = 20,
        isCancelled: @Sendable () -> Bool = { false }
    ) throws {
        let token = startFence.current()
        try checkAuthorizeAllowed(token, isCancelled)
        // The helper already reported that this engine exited before any
        // grant. Say why the tunnel did not start instead of prompting.
        if let reason = client.startFailure {
            throw HelperEngineDidNotStart(reason: reason)
        }
        // A prompt for a tunnel that cannot start is noise. The model only
        // exists while the engine runs, but the connection can be lost in
        // between.
        guard isRunning else { throw HelperTrustError.tunnelNotRunning }
        // Read the installed right before any prompt. The helper repeats this
        // check, but a missing right must not reach a person as an
        // administrator prompt that can never succeed.
        try startRightChecker.checkStartRight(HelperStartAuthorizationPolicy.startRight)
        try checkAuthorizeAllowed(token, isCancelled)
        // A fresh handshake on the same connection proves the live helper
        // before the form is sent. It does not open a second connection. Do it
        // before the prompt so the form reaches the helper inside the right's
        // short authorization window.
        try client.performHandshake()
        try checkAuthorizeAllowed(token, isCancelled)
        let lease = try authorization.beginStartAuthorization()
        defer { lease.release() }
        // A quit that began while the prompt was open must not send the form.
        try checkAuthorizeAllowed(token, isCancelled)
        try client.authorizeStart(authorization: lease.externalForm, timeout: timeout)
    }

    // Ask the helper to stop the session that this object started. The reply
    // carries the helper's ownership flag and the exact session result, so a
    // reconnect can never read a different connection's success as proof that
    // this engine stopped.
    //
    // A retry after an uncertain stop reconnects first. The previous stop
    // closed its transport, so a missing transport is not evidence that the
    // helper session is gone.
    @discardableResult
    public func stop(requireExistingSession: Bool = false) -> EngineStopOutcome {
        stopResult(requireExistingSession: requireExistingSession).outcome
    }

    // The richer stop result for the tunnel lifecycle. The engine process API
    // keeps the older outcome type for its existing callers.
    public func stopResult(requireExistingSession: Bool = false) -> TunnelStopResult {
        // A stop invalidates every start that has not sent its helper request
        // yet. Do this before the operation lock so a delayed start cannot slip
        // its request in while this stop waits.
        startFence.abortPendingStarts()
        operationLock.lock()
        defer { operationLock.unlock() }
        return finish(performStop(requireExistingSession: requireExistingSession))
    }

    // Confirm that no engine session remains when there is no retained process
    // handle. A reconnect reads the helper's session snapshot. A live or
    // stopping session, a different last session, an unprompted exit, or a
    // durable cleanup block keeps the uncertainty. This is the user-reachable
    // retry for a pending stop that has no elevated process to stop.
    public func confirmCleanup(
        force: Bool = false,
        requireExistingSession: Bool = false
    ) -> EngineStopOutcome {
        confirmCleanupResult(force: force, requireExistingSession: requireExistingSession).outcome
    }

    public func confirmCleanupResult(
        force: Bool = false,
        requireExistingSession: Bool = false
    ) -> TunnelStopResult {
        startFence.abortPendingStarts()
        operationLock.lock()
        defer { operationLock.unlock() }
        return finish(performConfirmCleanup(force: force, requireExistingSession: requireExistingSession))
    }

    private func performStop(requireExistingSession: Bool) -> TunnelStopResult {
        lock.lock()
        let session = storedSessionID
        let everStarted = everStartedSession
        let cached = lastStopResult
        lock.unlock()
        let needsRetry = cached.isUncertain
        if session == nil && !everStarted && !needsRetry && !requireExistingSession {
            client.close()
            return .notRunning
        }
        if !client.isConnected {
            // A reconnect creates a new connection that owns nothing. Its stop
            // reply can never prove that the old connection's engine stopped.
            // Read the helper's session record instead and require the exact
            // retained session id and a clean result.
            do {
                _ = try client.connect()
            } catch {
                let retained = cached.isUncertain ? cached : .uncertain(EngineLaunchText.stopUnverified)
                retain(retained, session: session)
                return retained
            }
            let previous = client.state
            let status: HelperStatus
            do {
                status = try client.status()
            } catch {
                client.close()
                let outcome = stopResult(for: error, cached: cached)
                retain(outcome, session: session)
                return outcome
            }
            client.close()
            noteStartFailure(status, session: session)
            let outcome = TunnelStopResult.fromCleanupStatus(
                status,
                session: session,
                everStarted: everStarted,
                previous: previous,
                requireExistingSession: requireExistingSession
            )
            return outcome
        }
        let reply = client.stop()
        let after = client.state
        client.close()
        noteStartFailure(reply?.status, session: session)
        return TunnelStopResult.fromHelperStop(
            reply: reply,
            previous: after,
            session: session,
            everStarted: everStarted,
            requireExistingSession: requireExistingSession
        )
    }

    private func performConfirmCleanup(force: Bool, requireExistingSession: Bool) -> TunnelStopResult {
        lock.lock()
        let session = storedSessionID
        let everStarted = everStartedSession
        let cached = lastStopResult
        lock.unlock()
        guard force || cached.isUncertain || session != nil || everStarted || requireExistingSession else {
            client.close()
            return .notRunning
        }
        do {
            _ = try client.connect()
        } catch {
            let retained = cached.isUncertain ? cached : .uncertain(EngineLaunchText.stopUnverified)
            retain(retained, session: session)
            return retained
        }
        let previous = client.state
        let status: HelperStatus
        do {
            status = try client.status()
        } catch {
            client.close()
            return stopResult(for: error, cached: cached)
        }
        client.close()
        return TunnelStopResult.fromCleanupStatus(
            status,
            session: session,
            everStarted: everStarted,
            previous: previous,
            requireExistingSession: requireExistingSession || force
        )
    }

    // Stop an engine that the helper just started after the start generation
    // was cancelled. The same connection owns the session, so its stop reply is
    // proof when it is clean. A lost reply keeps the session id for a later
    // exact retry.
    private func stopStartedEngine(reply: HelperStartReply) -> TunnelStopResult {
        let stopReply = client.stop()
        let after = client.state
        client.close()
        let result = TunnelStopResult.fromHelperStop(
            reply: stopReply,
            previous: after,
            session: reply.sessionID,
            everStarted: true
        )
        lock.lock()
        storedPort = nil
        storedSecret = ""
        if result.isUncertain {
            storedSessionID = reply.sessionID
            everStartedSession = true
        } else {
            storedSessionID = nil
            everStartedSession = false
        }
        lastStopResult = result
        lock.unlock()
        return result
    }

    private func finish(_ result: TunnelStopResult) -> TunnelStopResult {
        lock.lock()
        // The secret and port are stale after any stop attempt. Keep the
        // session id only while the outcome is unconfirmed and a live engine
        // may still exist. A route-unverified result means the helper proved
        // that no engine remains, so no process handle is retained.
        storedPort = nil
        storedSecret = ""
        switch result {
        case .stopped, .notRunning:
            storedSessionID = nil
            everStartedSession = false
        case .routesUnverified:
            // No live engine was reported, but the retained identity is the
            // only exact reference a later stop can name. Keep it with the
            // terminal mark; a new start is refused by the mark anyway.
            break
        case .uncertain, .durableBlock:
            break
        }
        lastStopResult = result
        lock.unlock()
        return result
    }

    private func retain(_ result: TunnelStopResult, session: UUID?) {
        lock.lock()
        lastStopResult = result
        storedSessionID = session
        lock.unlock()
    }

    private func stopResult(
        for error: Error,
        cached: TunnelStopResult
    ) -> TunnelStopResult {
        if let helper = error as? HelperTrustError {
            switch helper {
            case .cleanupBlocked:
                return .durableBlock(Strings.helperCleanup)
            case .engineStopTimedOut, .helperTimeout, .stopNotConfirmed:
                return .uncertain(EngineLaunchText.stopTimedOut)
            case .authorizationTimedOut:
                return .uncertain(EngineLaunchText.stopAuthorizationTimedOut)
            case .engineExitUnclean, .engineExited:
                return .uncertain(EngineLaunchText.stopUnclean)
            case .notConnected, .helperUnavailable, .responseRejected:
                return .uncertain(Strings.helperLost)
            default:
                return cached.isUncertain ? cached : .uncertain(EngineLaunchText.stopUnverified)
            }
        }
        return cached.isUncertain ? cached : .uncertain(EngineLaunchText.stopUnverified)
    }

    private static func isAmbiguousStartFailure(_ error: Error) -> Bool {
        guard let helper = error as? HelperTrustError else { return false }
        switch helper {
        case .helperTimeout, .helperUnavailable, .notConnected:
            return true
        default:
            return false
        }
    }

    private func checkStartAllowed(
        _ token: UInt64,
        _ cancellation: EngineLaunchCancellation?
    ) throws {
        if cancellation?.isCancelled == true { throw HelperTrustError.cancelled }
        if !startFence.permits(token) { throw HelperTrustError.cancelled }
        // The app gate is separate from this process fence. The tunnel session
        // passes its own cancellation token here, built from its start fence
        // and the press token, so a quit that only closes the app gate, or a
        // fence move that this call read too late, still reaches the process.
    }

    private func checkAuthorizeAllowed(
        _ token: UInt64,
        _ isCancelled: @Sendable () -> Bool
    ) throws {
        if isCancelled() { throw HelperTrustError.cancelled }
        if !startFence.permits(token) { throw HelperTrustError.cancelled }
    }

    public func markHealthy() {}
}
