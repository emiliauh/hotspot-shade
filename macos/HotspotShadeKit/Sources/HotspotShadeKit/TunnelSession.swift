import Foundation

// The macOS app exposes the source device proxy tunnel. Direct mode stays a
// command-line feature until the app has a mode choice and a direct start body.
// This authorizer refuses a direct start instead of sending a phone request or
// silently skipping the pairing handoff.
public enum TunnelStartMode: Equatable, Sendable {
    case sourceDeviceProxy
    case direct
}

// One elevated tunnel for one start. The user engine stays alive and keeps the
// pairing, the dashboard, and the settings. This type asks the protected helper
// for a root engine only after the person presses Turn on, hands that engine
// the same identity and credentials over the private descriptor, asks for the
// one administrator authorization, and then exposes the root engine's
// loopback API to the app.
//
// The helper process and the elevated engine are stopped on every stop path.
// The user engine is not touched, so the paired state survives the tunnel.
public final class RealTunnelSession: TunnelStartAuthorizing, @unchecked Sendable {
    typealias ProcessFactory = @Sendable () throws -> ProtectedEngineProcess
    // One start is cancelled by either fence. The session fence moves on a
    // quit or an explicit stop. The action token is the app gate generation of
    // the press that asked for this start, so a press from before a quit stays
    // cancelled after Stay even when it reaches this session late.
    private struct StartTicket: Sendable {
        let fence: UInt64
        let action: AppActionGate.Token?
    }

    private let handoffDescriptor: @Sendable () -> Int32
    private let isQuitting: @Sendable () -> Bool
    private let actionGate: AppActionGate?
    private let authorization: HelperStartAuthorizationProviding
    private let mode: TunnelStartMode
    private let stopBeforeStart: (@Sendable () async -> TunnelStopResult)?
    private let liveSession: (@Sendable () -> Bool)?
    private let confirmation: (@Sendable () async -> TunnelStopResult)?
    // The app-owned cleanup state, shared with every routing backend that this
    // session serves. A rebuilt model must see the same pending stop and the
    // same live elevated session.
    public let cleanup: TunnelCleanupState
    private let startFence = TunnelStartFence()
    private let makeProcess: ProcessFactory
    private let lock = NSLock()
    private let stopFlight = TunnelStopFlight()
    private var user: BackendClient
    private var process: ProtectedEngineProcess?
    // The cleanup token that this process retained. A stop clears only this
    // token, so a newer session that a concurrent start installed stays.
    private var processCleanupToken: UInt64?
    private var backend: BackendClient?
    private var startInFlight = false

    public convenience init(
        user: BackendClient,
        handoffDescriptor: @escaping @Sendable () -> Int32,
        isQuitting: @escaping @Sendable () -> Bool,
        actionGate: AppActionGate? = nil,
        authorization: HelperStartAuthorizationProviding = AuthorizationServicesStartAuthorization(),
        mode: TunnelStartMode = .sourceDeviceProxy
    ) {
        self.init(
            user: user,
            handoffDescriptor: handoffDescriptor,
            isQuitting: isQuitting,
            actionGate: actionGate,
            authorization: authorization,
            mode: mode,
            stopBeforeStart: nil,
            liveSession: nil,
            cleanup: TunnelCleanupState(),
            makeProcess: nil,
            confirmation: nil
        )
    }

    // The test seams stay internal. They prove that an uncertain cleanup from
    // an earlier attempt refuses a new start before any prompt, handoff, or
    // engine start, that a repeated start refuses a known live elevated
    // session before it stops anything, and that a canceled start cannot
    // publish a late engine.
    init(
        user: BackendClient,
        handoffDescriptor: @escaping @Sendable () -> Int32,
        isQuitting: @escaping @Sendable () -> Bool,
        actionGate: AppActionGate? = nil,
        authorization: HelperStartAuthorizationProviding = AuthorizationServicesStartAuthorization(),
        mode: TunnelStartMode = .sourceDeviceProxy,
        stopBeforeStart: (@Sendable () async -> TunnelStopResult)? = nil,
        liveSession: (@Sendable () -> Bool)? = nil,
        cleanup: TunnelCleanupState = TunnelCleanupState(),
        makeProcess: ProcessFactory? = nil,
        confirmation: (@Sendable () async -> TunnelStopResult)? = nil
    ) {
        self.user = user
        self.handoffDescriptor = handoffDescriptor
        self.isQuitting = isQuitting
        self.actionGate = actionGate
        self.authorization = authorization
        self.mode = mode
        // Production uses the real helper stop. A test supplies the pending
        // stop message without a helper.
        self.stopBeforeStart = stopBeforeStart
        // Production reads the process that this session started. A test can
        // name a live elevated session without a helper.
        self.liveSession = liveSession
        self.cleanup = cleanup
        self.makeProcess = makeProcess ?? { try ProtectedEngineProcess(authorization: authorization) }
        self.confirmation = confirmation
    }

    // A user engine restart uses a new loopback port and secret, and a new
    // handoff descriptor. The elevated session and its cleanup state outlive
    // that user engine, so the app updates them here instead of building a new
    // session that would forget an unconfirmed stop.
    public func updateUser(_ value: BackendClient) {
        lock.lock()
        user = value
        lock.unlock()
    }

    // The routing backend asks for the engine that the authorizer prepared.
    // It never starts one on its own.
    public func elevatedBackend() throws -> BackendClient {
        lock.lock(); defer { lock.unlock() }
        guard let backend else {
            throw TunnelAuthorizationFailure(message: "The tunnel needs administrator authorization first.")
        }
        return backend
    }

    // A rebuilt router can use this to reconcile a session that a previous
    // model prepared.
    public func existingElevatedBackend() -> BackendClient? {
        lock.lock(); defer { lock.unlock() }
        return backend
    }

    // Cancel every start that began before a quit or an explicit stop. The
    // abort is a generation, so a new start after Stay is still allowed. The
    // process has its own fence, because a delayed start can be inside its
    // helper status read when this call arrives.
    public func abortPendingStarts() {
        startFence.abortPendingStarts()
        lock.lock()
        let current = process
        lock.unlock()
        current?.abortPendingStarts()
    }

    public var hasPendingCleanup: Bool { cleanup.hasPendingStop }
    public var pendingCleanup: TunnelCleanupPending? { cleanup.pending }
    public var hasElevatedSession: Bool {
        if cleanup.hasElevatedSession { return true }
        lock.lock(); defer { lock.unlock() }
        return process != nil
    }

    // The one routing backend wiring that the app uses for this session. The
    // router reads the session's prepared engine, stops through the session,
    // runs the session's authorizer only for a tunnel start, and shares the
    // session's cleanup state. Building the router starts nothing: no helper
    // connection, no root engine, and no administrator authorization.
    public func makeRouter(user: BackendClient) -> TunnelRoutingBackend {
        makeRouter(user: user, authorizeStart: nil)
    }

    // A hermetic test replaces only the authorizer, which would otherwise ask
    // for a prompt, write the handoff, and start a root engine. Every other
    // closure is the app's wiring.
    func makeRouter(
        user: BackendClient,
        authorizeStart override: TunnelRoutingBackend.AuthorizeStart?
    ) -> TunnelRoutingBackend {
        TunnelRoutingBackend(
            user: user,
            prepareElevated: { [self] in try self.elevatedBackend() },
            stopElevated: { [self] in await self.stopElevated() },
            authorizeStart: override ?? { [self] in try await self.authorizeTunnelStart() },
            existingElevated: { [self] in self.existingElevatedBackend() },
            cleanup: cleanup
        )
    }

    // MARK: - TunnelStartAuthorizing

    public func authorizeTunnelStart() async throws {
        // Read the press token here, before any await. It stays with this
        // start even when a quit and a Stay land while the start waits.
        let startToken = StartTicket(fence: startFence.current(), action: AppActionGate.actionToken)
        guard !isStartCancelled(startToken) else {
            throw TunnelAuthorizationFailure(
                message: EngineLaunchFailure.fromHelper(HelperTrustError.cancelled).message
            )
        }
        guard mode == .sourceDeviceProxy else {
            throw TunnelAuthorizationFailure(
                message: "The macOS app does not support direct mode yet. Use the hotspotshade command-line tunnel for direct mode."
            )
        }
        // An uncertain stop from an earlier attempt is a refusal until the
        // helper confirms. If the process still exists, ask the helper again;
        // this is the one safe retry. A missing process is not proof, so the
        // latch stays and the start is refused before any prompt.
        var priorStopCompleted = false
        if currentUncertainStop() != nil {
            let retry = await stopForStart()
            if let message = retry.message {
                throw uncertainStopFailure(message)
            }
            priorStopCompleted = true
        }
        // A repeated start must never stop a known live elevated session. Only
        // an explicit stop, a quit, or the routing backend's own failed-start
        // cleanup owns that process. Refuse before the prior-stop step instead
        // of closing a root engine that may be serving a live tunnel.
        if liveElevatedSession() {
            throw TunnelAuthorizationFailure(message: "A tunnel is already active.")
        }
        // One authorization owns one elevated engine. Two concurrent starts
        // must not both prompt, both write the handoff, and both start a root
        // engine.
        guard beginStartFlight() else {
            throw TunnelAuthorizationFailure(message: "A tunnel start is already in progress.")
        }
        defer { endStartFlight() }
        // A retry after a lost reply must not leave an older helper session
        // behind. The app offers Turn on only when no tunnel runs. An uncertain
        // stop is a refusal, not permission to start a second root engine.
        let priorStop: TunnelStopResult
        if priorStopCompleted {
            priorStop = .stopped
        } else if let stopBeforeStart {
            priorStop = await stopBeforeStart()
        } else {
            priorStop = await stopForStart()
        }
        guard !isStartCancelled(startToken) else {
            throw cancelledFailure()
        }
        if let pending = priorStop.message {
            throw uncertainStopFailure(pending)
        }
        guard handoffDescriptor() >= 0 else {
            throw TunnelAuthorizationFailure(message: EngineLaunchFailure.fromUserEngine(BackendError.notSupported).message)
        }
        // Move one copy of the pairing into the private descriptor before the
        // root engine starts. The app never reads the descriptor and never
        // holds the token.
        do {
            try await currentUser().pairHandoff()
        } catch {
            throw TunnelAuthorizationFailure(
                message: Strings.sanitized(error.localizedDescription) ?? Strings.pairAgain
            )
        }
        guard !isStartCancelled(startToken) else {
            throw cancelledFailure()
        }
        let created: ProtectedEngineProcess
        do {
            created = try await Task.detached(priority: .userInitiated) {
                try self.makeProcess()
            }.value
        } catch {
            throw authorizationFailure(error)
        }
        // Store the process before it starts. A quit or a failed start can then
        // stop a late engine, and an uncertain stop keeps this handle so a
        // later retry reaches the same helper session.
        storeProcess(created)
        guard !isStartCancelled(startToken) else {
            let stop = await stopForStart()
            if let message = stop.message { throw uncertainStopFailure(message) }
            throw cancelledFailure()
        }
        // The process reads its own fence only when start() runs. A quit or a
        // stop that lands after the check above and before that read would
        // leave the fence looking current, so pass this start's own fence and
        // press token too. The helper start then refuses after Stay as well.
        let cancellation = EngineLaunchCancellation(cancelledWhen: { [self] in
            self.isStartCancelled(startToken)
        })
        do {
            try await Task.detached(priority: .userInitiated) {
                try created.start(
                    timeout: 20,
                    cancellation: cancellation,
                    credentials: self.handoffDescriptor()
                )
            }.value
        } catch {
            let stop = await stopForStart()
            // A helper exit can leave a durable cleanup block. Surface that
            // reason instead of a generic start failure, so the person sees
            // that routes or the start record need a check.
            if let message = stop.message {
                throw uncertainStopFailure(message)
            }
            throw authorizationFailure(error)
        }
        guard let port = created.port else {
            let stop = await stopForStart()
            if let message = stop.message {
                throw uncertainStopFailure(message)
            }
            throw TunnelAuthorizationFailure(message: EngineLaunchFailure.fromHelper(BackendError.timeout).message)
        }
        // Prove that the elevated engine imported the pairing before a person
        // sees an administrator prompt. A missing descriptor, a malformed
        // frame, or a different identity is a failed start, not a prompt.
        let candidate = HTTPBackend(port: port, secret: created.secret)
        do {
            let live = try await candidate.status(timeout: 3)
            guard live.paired == true else {
                throw TunnelAuthorizationFailure(message: Strings.pairAgain)
            }
        } catch {
            let stop = await stopForStart()
            if let message = stop.message {
                throw uncertainStopFailure(message)
            }
            // The engine did not answer because it exited before any grant.
            // Say that the tunnel did not start and why.
            if !(error is TunnelAuthorizationFailure), let reason = created.startFailureReason {
                throw TunnelAuthorizationFailure(message: Strings.tunnelDidNotStart(reason))
            }
            throw error as? TunnelAuthorizationFailure
                ?? TunnelAuthorizationFailure(message: Strings.pairAgain)
        }
        guard !isStartCancelled(startToken) else {
            let stop = await stopForStart()
            if let message = stop.message {
                throw uncertainStopFailure(message)
            }
            throw cancelledFailure()
        }
        do {
            try await Task.detached(priority: .userInitiated) {
                try created.authorizeStart(isCancelled: { self.isStartCancelled(startToken) })
            }.value
        } catch {
            let stop = await stopForStart()
            if let message = stop.message {
                throw uncertainStopFailure(message)
            }
            if Self.engineEndedBeforeAuthorization(error), let reason = created.startFailureReason {
                throw TunnelAuthorizationFailure(message: Strings.tunnelDidNotStart(reason))
            }
            throw authorizationFailure(error)
        }
        // A quit that began while the authorization was in flight must not
        // publish the backend. Check the fence before and after the store.
        guard !isStartCancelled(startToken) else {
            let stop = await stopForStart()
            if let message = stop.message {
                throw uncertainStopFailure(message)
            }
            throw cancelledFailure()
        }
        // Publish the backend only while this start's process is still the
        // stored one. A stop that ran between the check above and this store
        // already cleared the process; a late store would leave a backend for
        // an engine that no process handle owns.
        guard storeBackend(candidate, for: created) else {
            let stop = await stopForStart()
            if let message = stop.message {
                throw uncertainStopFailure(message)
            }
            throw cancelledFailure()
        }
        if isStartCancelled(startToken) {
            let stop = await stopForStart()
            if let message = stop.message {
                throw uncertainStopFailure(message)
            }
            throw cancelledFailure()
        }
    }

    // Stop the elevated engine and the helper session. Concurrent stop and
    // quit callers join one flight, so they observe the same confirmed or
    // uncertain result. Only a confirmed helper stop clears the process.
    //
    // An explicit stop cancels every start that began before it. Without this
    // fence, a start that is still in its pairing handoff or process setup
    // when Turn off, a cleanup retry, or a lost user engine stops the session
    // would find no process to stop, and would then start a root engine and
    // ask for authorization after the person asked for the tunnel to be off.
    public func stopElevated() async -> TunnelStopResult {
        startFence.abortPendingStarts()
        return await stopForStart()
    }

    // The start's own stops join the same flight but do not cancel the start
    // that asked for them.
    private func stopForStart() async -> TunnelStopResult {
        await stopFlight.run { [weak self] in
            guard let self else {
                return .uncertain("The app stopped before it could confirm the tunnel stop.")
            }
            return await self.performStopElevated()
        }
    }

    // A timeout keeps the process handle so a later stop can ask the same
    // helper session again; without a handle the latch stays as a refusal.
    private func performStopElevated() async -> TunnelStopResult {
        let (process, retained) = stopState()
        let pendingToken = retained?.token
        let elevatedToken = cleanup.currentElevatedSessionToken

        // A terminal mark has a defined answer. A process handle should not
        // survive one, but if it does, stop it rather than short-circuit. With
        // no handle, asking the helper again cannot produce new route evidence,
        // so the same honest answer is returned once and the UI offers no
        // retry.
        if process == nil, let retained, retained.isTerminal {
            return retained.stopResult
        }
        guard let process else {
            // A retained elevated session without a process handle is not a
            // clean stop. Reach the helper even when no pending message exists:
            // only its exact session record can confirm cleanup.
            if retained != nil || cleanup.hasElevatedSession {
                let outcome: TunnelStopResult
                if let confirmation = self.confirmation {
                    outcome = await confirmation()
                } else {
                    let probe: ProtectedEngineProcess
                    do {
                        probe = try makeProcess()
                    } catch {
                        return recordPending(
                            retained?.message ?? EngineLaunchText.stopUnverified,
                            kind: .retryable,
                            observedToken: pendingToken
                        )
                    }
                    outcome = await Task.detached(priority: .userInitiated) {
                        probe.confirmCleanupResult(force: true, requireExistingSession: true)
                    }.value
                }
                return finish(outcome, process: nil, pendingToken: pendingToken, elevatedToken: elevatedToken)
            }
            return .stopped
        }
        let outcome = await Task.detached(priority: .userInitiated) {
            process.stopResult()
        }.value
        return finish(outcome, process: process, pendingToken: pendingToken, elevatedToken: elevatedToken)
    }

    // Apply one helper answer to the app-owned state. A confirmed stop clears
    // only the mark and the elevated token that this call observed. A newer
    // mark or session stays, even when its text is identical.
    private func finish(
        _ result: TunnelStopResult,
        process stopped: ProtectedEngineProcess?,
        pendingToken: UInt64?,
        elevatedToken: UInt64?
    ) -> TunnelStopResult {
        switch result {
        case .stopped, .notRunning:
            if let stopped {
                clearProcess(ifSame: stopped)
            } else {
                cleanup.clearElevatedSession(ifToken: elevatedToken)
            }
            // The elevated engine's own stop reply was lost in an earlier
            // attempt, and this confirmation came from the helper alone. The
            // helper proved that the process is gone, but no later call can
            // recover the engine's route observation. Record the final mark
            // instead of a clean stop.
            if cleanup.hasLostRouteObservation {
                return settleLostObservation(
                    recordPending(
                        EngineLaunchText.routeCleanupUnverified,
                        kind: .routesUnverified,
                        observedToken: pendingToken
                    )
                )
            }
            let cleared = cleanup.clearPendingStop(ifToken: pendingToken)
            if !cleared, let newer = cleanup.pending {
                return newer.stopResult
            }
            // A concurrent start can install a newer process while this stop
            // waits. The old handle cannot clear it, and this stop is not a
            // clean answer for the newer session. Read the stored process, not
            // the handle that this call stopped.
            lock.lock()
            let newerProcess = self.process != nil
            lock.unlock()
            if newerProcess || cleanup.hasElevatedSession {
                return recordPending(
                    EngineLaunchText.elevatedSessionOpen,
                    kind: .retryable,
                    observedToken: nil
                )
            }
            return .stopped
        case .uncertain(let message):
            // A live helper session may still exist. Keep the process handle and
            // the elevated mark for a later stop.
            return recordPending(message, kind: .retryable, observedToken: pendingToken)
        case .routesUnverified(let message):
            // The helper proved that no engine remains. Its route cleanup was
            // not observed and no retry can recover it.
            if let stopped {
                clearProcess(ifSame: stopped)
            } else {
                cleanup.clearElevatedSession(ifToken: elevatedToken)
            }
            return settleLostObservation(
                recordPending(message, kind: .routesUnverified, observedToken: pendingToken)
            )
        case .durableBlock(let message):
            // The helper refuses every start and may still own an engine. Keep
            // the elevated mark and record a final block. No retry is offered.
            return recordPending(message, kind: .durableBlock, observedToken: pendingToken)
        }
    }

    // A final mark now describes the lost route observation, so the flag is
    // done. When a newer retryable mark won instead, keep the flag: a later
    // helper confirmation of that mark must still become a final mark, not a
    // clean stop.
    private func settleLostObservation(_ current: TunnelStopResult) -> TunnelStopResult {
        if current.cleanupKind != .retryable {
            cleanup.clearLostRouteObservation()
        }
        return current
    }

    // Record one new mark unless a newer one appeared while this stop waited.
    // The returned result describes the mark that is now current.
    private func recordPending(
        _ message: String,
        kind: TunnelCleanupKind,
        observedToken: UInt64?
    ) -> TunnelStopResult {
        if let current = cleanup.pending, current.token != observedToken {
            return current.stopResult
        }
        cleanup.recordPendingStop(message, kind: kind)
        return kind == .retryable
            ? .uncertain(message)
            : (kind == .durableBlock ? .durableBlock(message) : .routesUnverified(message))
    }

    private func beginStartFlight() -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard !startInFlight else { return false }
        startInFlight = true
        return true
    }

    private func currentUser() -> BackendClient {
        lock.lock(); defer { lock.unlock() }
        return user
    }

    private func endStartFlight() {
        lock.lock()
        startInFlight = false
        lock.unlock()
    }

    private func storeProcess(_ value: ProtectedEngineProcess) {
        let token = cleanup.retainElevatedSession()
        lock.lock()
        process = value
        processCleanupToken = token
        lock.unlock()
    }

    // Store the backend only for the process that is still stored. Returns
    // false when a stop cleared or replaced that process first.
    private func storeBackend(_ value: BackendClient, for owner: ProtectedEngineProcess) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard process === owner else { return false }
        backend = value
        return true
    }

    // A hermetic test installs a process that a fake helper transport started
    // and a fake elevated backend. It runs no prompt, handoff, or root engine.
    // It proves the stop path that the app wires through the router.
    func installForTesting(process value: ProtectedEngineProcess, backend elevated: BackendClient) {
        storeProcess(value)
        _ = storeBackend(elevated, for: value)
    }

    private func stopState() -> (ProtectedEngineProcess?, TunnelCleanupPending?) {
        lock.lock()
        let value = process
        lock.unlock()
        return (value, cleanup.pending)
    }

    private func clearProcess(ifSame value: ProtectedEngineProcess) {
        lock.lock()
        var token: UInt64?
        if process === value {
            process = nil
            backend = nil
            token = processCleanupToken
            processCleanupToken = nil
        }
        lock.unlock()
        if let token { cleanup.clearElevatedSession(ifToken: token) }
    }

    // `pendingMessage` is kept for the existing session tests and the
    // no-process retry path.
    private func currentUncertainStop() -> String? {
        cleanup.pendingMessage
    }

    private func uncertainStopFailure(_ message: String) -> TunnelAuthorizationFailure {
        TunnelAuthorizationFailure(message: message, cleanup: .uncertainStop)
    }

    private func liveElevatedSession() -> Bool {
        if let liveSession { return liveSession() }
        if cleanup.hasElevatedSession { return true }
        lock.lock()
        let current = process
        lock.unlock()
        return current?.isRunning == true
    }

    // A quit or an explicit stop aborts this start generation. `isQuitting`
    // alone is not enough, because the person can choose Stay and clear it
    // before the old start resumes. The press token covers a start that had
    // not reached this session when the quit began.
    private func isStartCancelled(_ ticket: StartTicket) -> Bool {
        if isQuitting() || !startFence.permits(ticket.fence) { return true }
        if let action = ticket.action, let actionGate, !actionGate.permits(action) {
            return true
        }
        return false
    }

    private func cancelledFailure() -> TunnelAuthorizationFailure {
        TunnelAuthorizationFailure(
            message: EngineLaunchFailure.fromHelper(HelperTrustError.cancelled).message
        )
    }

    private func authorizationFailure(_ error: Error) -> TunnelAuthorizationFailure {
        let failure = EngineLaunchFailure.fromHelper(error)
        return TunnelAuthorizationFailure(message: failure.message)
    }

    // True for an authorization error that comes from the engine or its
    // helper session ending, not from the person or the administrator right.
    // Only then does a reported failed start explain the error.
    private static func engineEndedBeforeAuthorization(_ error: Error) -> Bool {
        if error is HelperEngineDidNotStart { return true }
        guard let helper = error as? HelperTrustError else { return false }
        switch helper {
        case .tunnelNotRunning, .notConnected, .helperUnavailable, .handshakeRequired,
             .engineStartFailed, .engineExited:
            return true
        default:
            return false
        }
    }
}
