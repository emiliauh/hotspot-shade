import Foundation
import Security
import XPC
import Dispatch
import Darwin
import HotspotShadeKit

// This executable is the protected helper. It runs only from a root-owned
// install path with a Developer ID signature. It opens no listener when that
// proof fails. The XPC runtime enforces the caller's code signing requirement
// on the listener, and the helper checks the live caller again before it serves
// a request.
//
// The helper never starts a tunnel by itself. It starts one root engine for one
// authenticated connection, and only when the app asks for a tunnel start. The
// app's user-owned engine serves the full interface, pairing, and status first.
// A tunnel start needs a separate administrator authorization. The app sends one
// external form, the helper verifies the one fixed right, and only then writes
// the one-time grant that the engine consumes before it changes a route. The app
// may send one private pairing handoff descriptor with the start; the helper
// passes it to the root engine and never reads it. The helper returns the
// engine's loopback port and per-launch secret, and stops the engine when the
// connection closes, a stop request arrives, the engine exits, or no verified
// authorization arrives within `HelperAuthorizationDeadline.unauthorizedSession`.
// It does not restart a stopped engine.

private func failClosed() -> Never {
    fputs("HotspotShade helper unavailable.\n", stderr)
    exit(1)
}

private func startProtectedHelper() -> HelperRuntime {
    // A helper must survive a write to a descriptor whose reader is gone. The
    // engine can exit between spawn and the secret write. SIGPIPE would end
    // this root process in the middle of a start and leave the engine unowned.
    signal(SIGPIPE, SIG_IGN)

    guard geteuid() == 0, CommandLine.arguments.count == 1 else { failClosed() }
    let executable = URL(fileURLWithPath: CommandLine.arguments.first ?? "").standardizedFileURL.path
    guard executable == HelperRequirement.helperExecutablePath else { failClosed() }

    let checker = SecurityHelperCodeSignatureChecker()
    do {
        let selfInfo = try checker.signingInfo(atPath: executable)
        guard selfInfo.isProtectedIdentity,
              selfInfo.identifier == HelperRequirement.helperIdentifier,
              let team = selfInfo.teamIdentifier
        else {
            failClosed()
        }
        try checker.verifyStaticCode(
            atPath: executable,
            requirement: HelperRequirement.makeSelf(identifier: HelperRequirement.helperIdentifier)
        )
        let policy = HelperInstallPolicy(
            layout: .rootOwnedCopy,
            helperPath: executable,
            launchDaemonPlistPath: HelperRequirement.launchDaemonPath,
            expectedTeamIdentifier: team
        )
        _ = try HelperInstallVerifier(policy: policy).verify()
        // The start right is checked before every tunnel authorization, not
        // before the listener. Starting the engine creates no route and no
        // tunnel device, so a stale or missing right must not hide the
        // dashboard. The authorization gate still fails closed and never
        // guesses at a default rule.
        return try HelperRuntime(teamIdentifier: team)
    } catch {
        failClosed()
    }
}

let runtime = startProtectedHelper()
runtime.start()

final class HelperRuntime: @unchecked Sendable {
    private let serviceName = HelperRequirement.helperServiceName
    private let authorizer: HelperCallerAuthorizer
    private let controller: HelperSessionController
    private let startGate: HelperStartGate
    private let handshakeGate = HelperHandshakeGate()
    private let lock = NSLock()
    private var listener: xpc_connection_t?
    private var signalSources: [DispatchSourceSignal] = []
    // The connection that owns the current engine. The helper uses it to send
    // one engine-exited notice. It carries no port, secret, address, or path.
    private var ownedPeer: xpc_connection_t?
    private var ownedConnection: UUID?
    private let livenessWatch = HelperLivenessWatch<DispatchSourceTimer>()

    init(teamIdentifier: String) throws {
        let caller = try HelperCallerPolicy(teamIdentifier: teamIdentifier)
        self.authorizer = HelperCallerAuthorizer(policy: caller)
        let controller = HelperSessionController(
            launcher: RootEngineLauncher(teamIdentifier: teamIdentifier),
            cleanupStore: RootCleanupBlockStore(),
            intentStore: RootLaunchIntentStore(),
            exclusion: RootStartExclusionStore(),
            // One fixed code for the last failed start, root-only 0600 in the
            // state directory. Diagnostics only; no decision reads it.
            failureRecord: RootStartFailureStore()
        )
        self.controller = controller
        // The production gate always uses Authorization Services and the
        // installed right definition. There is no alternative verifier,
        // environment switch, or demo bypass in the helper executable.
        self.startGate = HelperStartGate(
            verifier: AuthorizationServicesStartAuthorizationVerifier(),
            rightChecker: SecurityStartRightConfigurationChecker(),
            controller: controller
        )
    }

    func start() -> Never {
        guard let requirement = try? authorizer.requirement, !requirement.isEmpty else {
            failClosed()
        }

        let listener = xpc_connection_create_mach_service(
            serviceName,
            nil,
            UInt64(XPC_CONNECTION_MACH_SERVICE_LISTENER)
        )
        // The XPC runtime drops every request from a peer that does not satisfy
        // this requirement. It is a second boundary in front of the helper.
        guard xpc_connection_set_peer_code_signing_requirement(listener, requirement) == 0 else {
            failClosed()
        }
        lock.lock()
        self.listener = listener
        lock.unlock()

        xpc_connection_set_event_handler(listener) { [weak self] event in
            self?.listenerEvent(event)
        }
        xpc_connection_resume(listener)
        installSignalHandlers()
        dispatchMain()
    }

    private func installSignalHandlers() {
        let queue = DispatchQueue(label: "hotspotshade-helper-signals")
        for signalNumber in [SIGTERM, SIGINT] {
            signal(signalNumber, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: signalNumber, queue: queue)
            source.setEventHandler { [weak self] in
                self?.stopOwnedEngineThenExit()
            }
            source.resume()
            signalSources.append(source)
        }
    }

    // Stop the owned engine before the process exits. A stop that timed out or
    // came back unclean leaves an engine that may still own routes, so keep the
    // daemon alive and let an operator inspect the host. Exiting here would
    // orphan that engine. A durable marker from an earlier run does not by
    // itself keep this process alive: the marker still blocks every later start
    // after a restart.
    private func stopOwnedEngineThenExit() {
        stopLivenessWatchForShutdown()
        clearOwnedPeer()
        let result = controller.shutDown()
        if result == .timedOut || result == .failed {
            fputs("HotspotShade helper could not stop the engine.\n", stderr)
            return
        }
        exit(0)
    }

    private func listenerEvent(_ event: xpc_object_t) {
        if xpc_get_type(event) == XPC_TYPE_ERROR {
            // The XPC runtime is going away. Stop the owned engine before the
            // process exits. The engine also sees the parent descriptor close.
            stopOwnedEngineThenExit()
            return
        }
        guard xpc_get_type(event) == XPC_TYPE_CONNECTION else { return }
        let peer: xpc_connection_t = event
        accept(peer)
    }

    private func accept(_ peer: xpc_connection_t) {
        let connection = UUID()
        xpc_connection_set_event_handler(peer) { [weak self] event in
            self?.peerEvent(peer, connection: connection, event: event)
        }
        xpc_connection_resume(peer)
    }

    private func peerEvent(_ peer: xpc_connection_t, connection: UUID, event: xpc_object_t) {
        let type = xpc_get_type(event)
        if type == XPC_TYPE_ERROR {
            handshakeGate.clear(connection: connection)
            forgetOwnedPeer(connection: connection)
            controller.connectionClosed(connection)
            xpc_connection_cancel(peer)
            return
        }
        guard type == XPC_TYPE_DICTIONARY else { return }
        handle(peer, connection: connection, message: event)
    }

    private func handle(_ peer: xpc_connection_t, connection: UUID, message: xpc_object_t) {
        // The kernel audit token names the live process. A PID from the
        // connection can be recycled; the token cannot be chosen by the caller.
        guard let token = HelperXPCConnection.auditToken(for: peer),
              (try? authorizer.authorize(auditToken: token)) != nil
        else {
            replyError(peer, message: message, code: "caller_rejected")
            handshakeGate.clear(connection: connection)
            forgetOwnedPeer(connection: connection)
            controller.connectionClosed(connection)
            xpc_connection_cancel(peer)
            return
        }
        let action = xpc_dictionary_get_string(message, "action").map { String(cString: $0) } ?? ""
        switch action {
        case "hello":
            // A harmless, fresh handshake. The reply proves the pinned helper
            // answers this connection. The app asks for an administrator
            // authorization only after this reply arrives.
            let clientNonce = data(from: message, key: "nonce") ?? Data()
            guard xpc_dictionary_get_uint64(message, "protocol") == 2,
                  let handshake = handshakeGate.issue(connection: connection, clientNonce: clientNonce)
            else {
                replyError(peer, message: message, code: "bad_handshake")
                return
            }
            replyHandshake(peer, message: message, clientNonce: clientNonce, handshake: handshake)
        case "start":
            let serverNonce = data(from: message, key: "server_nonce") ?? Data()
            guard handshakeGate.consume(connection: connection, serverNonce: serverNonce) else {
                replyError(peer, message: message, code: "not_handshaken")
                return
            }
            // Starting the engine is not a tunnel start. It creates no route
            // and no tunnel device, so this request does not ask for an
            // administrator authorization. The optional descriptor carries the
            // one pairing handoff. Only the root engine reads it.
            let credentials = xpc_dictionary_dup_fd(message, "credentials")
            let result = startGate.startEngine(
                connection: connection,
                credentials: credentials >= 0 ? credentials : nil
            )
            if credentials >= 0 { close(credentials) }
            switch result {
            case .started(let session):
                rememberOwnedPeer(peer, connection: connection)
                startLivenessWatch()
                replyStart(peer, message: message, session: session)
            case .busy:
                replyError(peer, message: message, code: "busy")
            case .cleanupBlocked:
                replyError(peer, message: message, code: "cleanup_blocked")
            case .launchFailed:
                replyError(peer, message: message, code: "engine_start")
            case .engineDidNotStart(let reason):
                // The engine exited before it was ready and before any grant.
                // No route changed and no cleanup block was set. The reason is
                // one fixed code, never engine output.
                fputs("HotspotShade helper: the engine did not start (\(reason.rawValue)).\n", stderr)
                replyError(peer, message: message, code: "engine_start", reason: reason.rawValue)
            case .startExclusionBusy:
                replyError(peer, message: message, code: "start_exclusion_busy")
            case .startExclusionUnavailable:
                replyError(peer, message: message, code: "start_exclusion_unavailable")
            case .connectionClosed:
                replyError(peer, message: message, code: "connection_closed")
            case .cancelled:
                replyError(peer, message: message, code: "cancelled")
            case .notAuthorized:
                replyError(peer, message: message, code: "not_authorized")
            case .authorizationBusy:
                replyError(peer, message: message, code: "authorization_busy")
            case .notConfigured:
                replyError(peer, message: message, code: "not_configured")
            }
        case "authorize":
            // One administrator authorization for one tunnel start. The form
            // is checked against the fixed right, then the helper writes the
            // one-time grant into the engine's private runtime directory.
            let serverNonce = data(from: message, key: "server_nonce") ?? Data()
            guard handshakeGate.consume(connection: connection, serverNonce: serverNonce) else {
                replyError(peer, message: message, code: "not_handshaken")
                return
            }
            let form = authorizationForm(from: message)
            switch startGate.authorize(connection: connection, form: form) {
            case .authorized:
                replyOK(peer, message: message)
            case .notRunning:
                replyError(peer, message: message, code: "not_running")
            case .notConfigured:
                replyError(peer, message: message, code: "not_configured")
            case .notAuthorized:
                replyError(peer, message: message, code: "not_authorized")
            case .grantFailed:
                replyError(peer, message: message, code: "authorization_failed")
            }
        case "stop":
            let report = controller.stopReportingOwnership(connection: connection, reason: .user)
            handshakeGate.clear(connection: connection)
            forgetOwnedPeer(connection: connection)
            replyStopped(peer, message: message, report: report)
        case "cancel":
            let report = controller.stopReportingOwnership(connection: connection, reason: .cancelled)
            handshakeGate.clear(connection: connection)
            forgetOwnedPeer(connection: connection)
            replyStopped(peer, message: message, report: report)
        case "status":
            // A status request also collects an engine that already exited.
            reapExitedEngine()
            replyStatus(peer, message: message)
        default:
            replyError(peer, message: message, code: "unknown_action")
        }
    }

    private func data(from message: xpc_object_t, key: String) -> Data? {
        var length = 0
        guard let bytes = xpc_dictionary_get_data(message, key, &length),
              length > 0
        else {
            return nil
        }
        return Data(bytes: bytes, count: length)
    }

    private func authorizationForm(from message: xpc_object_t) -> Data {
        var length = 0
        guard let bytes = xpc_dictionary_get_data(message, "authorization", &length),
              length > 0, length <= HelperStartAuthorizationPolicy.externalFormByteCount
        else {
            return Data()
        }
        return Data(bytes: bytes, count: length)
    }

    // MARK: - Engine liveness

    private func rememberOwnedPeer(_ peer: xpc_connection_t, connection: UUID) {
        lock.lock()
        ownedPeer = peer
        ownedConnection = connection
        lock.unlock()
    }

    private func clearOwnedPeer() {
        lock.lock()
        ownedPeer = nil
        ownedConnection = nil
        lock.unlock()
    }

    private func startLivenessWatch() {
        livenessWatch.sessionStarted {
            let timer = DispatchSource.makeTimerSource(
                queue: DispatchQueue(label: "hotspotshade-helper-liveness")
            )
            timer.schedule(deadline: .now() + 1, repeating: 1)
            timer.setEventHandler { [weak self] in
                self?.checkEngineLiveness()
            }
            timer.resume()
            return timer
        }
    }

    // Shutdown only. Every other path leaves the timer to the idle check, so
    // the end of one session cannot cancel the watch that a newer session
    // started in the meantime.
    private func stopLivenessWatchForShutdown() {
        livenessWatch.stopForShutdown()?.cancel()
    }

    private func checkEngineLiveness() {
        if reapExitedEngine() { return }
        if expireUnauthorizedEngine() { return }
        let stopped = livenessWatch.stopIfIdle { [controller] in
            let snapshot = controller.snapshot()
            return snapshot.running || snapshot.starting
        }
        stopped?.cancel()
    }

    // The root engine starts before the person answers the administrator
    // prompt and can hold the imported pairing token. A session with no
    // verified authorization within the deadline is stopped on the normal
    // stop path, never with SIGKILL. The owner gets the same notice as any
    // other helper-side stop, with the fixed reason `authorization_timeout`
    // and the helper's cleanup state. It is a stop, never a restart.
    @discardableResult
    private func expireUnauthorizedEngine() -> Bool {
        guard let expired = controller.expireUnauthorizedSession() else { return false }
        handshakeGate.clear(connection: expired.connection)
        fputs("HotspotShade helper stopped an engine that was not authorized in time.\n", stderr)
        lock.lock()
        let peer = ownedConnection == expired.connection ? ownedPeer : nil
        if ownedConnection == expired.connection {
            ownedPeer = nil
            ownedConnection = nil
        }
        lock.unlock()
        guard let peer else { return true }
        let event = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_string(event, "event", "engine_exited")
        xpc_dictionary_set_string(event, "reason", HelperAuthorizationDeadline.timeoutReason)
        xpc_dictionary_set_bool(event, "cleanup_blocked", controller.requiresCleanup)
        xpc_connection_send_message(peer, event)
        return true
    }

    // The engine can exit on its own, for example after a fatal startup error.
    // Free the session slot so a later start is possible, and tell the owning
    // connection. It is a stop, never a restart.
    @discardableResult
    private func reapExitedEngine() -> Bool {
        guard let reaped = controller.reapExitedEngineReport() else { return false }
        let connection = reaped.connection
        lock.lock()
        // Only the connection that owned this engine gets the notice. A second
        // connection must not consume or clear another session's ownership.
        let peer = ownedConnection == connection ? ownedPeer : nil
        if ownedConnection == connection {
            ownedPeer = nil
            ownedConnection = nil
        }
        lock.unlock()
        guard let peer else { return true }
        let event = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_string(event, "event", "engine_exited")
        xpc_dictionary_set_bool(event, "cleanup_blocked", controller.requiresCleanup)
        // An engine that exited before any grant is a failed start. The app
        // shows that the tunnel did not start and why, not a cleanup block.
        if reaped.failedStart {
            xpc_dictionary_set_bool(event, "failed_start", true)
            if let reason = reaped.reason {
                xpc_dictionary_set_string(event, "reason", reason.rawValue)
            }
        }
        xpc_connection_send_message(peer, event)
        return true
    }

    // A stop, a cancelled start, a caller rejection, or shutdown clears the
    // owner without sending an exit notice. Only a real engine exit sends one.
    // A request from a different connection must not clear the owner. No path
    // here stops the liveness watch: the next tick stops it only when no
    // session exists, so a session started meanwhile keeps its deadline.
    private func forgetOwnedPeer(connection: UUID) {
        lock.lock()
        if ownedConnection == connection {
            ownedPeer = nil
            ownedConnection = nil
        }
        lock.unlock()
    }

    // MARK: - Replies

    private func replyHandshake(
        _ peer: xpc_connection_t,
        message: xpc_object_t,
        clientNonce: Data,
        handshake: HelperHandshake
    ) {
        guard let reply = xpc_dictionary_create_reply(message) else { return }
        xpc_dictionary_set_string(reply, "ok", "1")
        xpc_dictionary_set_uint64(reply, "protocol", 2)
        clientNonce.withUnsafeBytes { buffer in
            guard let base = buffer.baseAddress else { return }
            xpc_dictionary_set_data(reply, "nonce", base, buffer.count)
        }
        handshake.serverNonce.withUnsafeBytes { buffer in
            guard let base = buffer.baseAddress else { return }
            xpc_dictionary_set_data(reply, "server_nonce", base, buffer.count)
        }
        xpc_connection_send_message(peer, reply)
    }

    private func replyStart(_ peer: xpc_connection_t, message: xpc_object_t, session: HelperEngineSession) {
        guard let reply = xpc_dictionary_create_reply(message) else { return }
        xpc_dictionary_set_string(reply, "ok", "1")
        xpc_dictionary_set_uint64(reply, "port", UInt64(session.port))
        xpc_dictionary_set_string(reply, "session", session.sessionID.uuidString)
        // The secret stays in this authenticated XPC message. It is never
        // written to disk, a command line, a log, or a status answer.
        xpc_dictionary_set_string(reply, "secret", session.secret)
        xpc_connection_send_message(peer, reply)
    }

    private func replyOK(_ peer: xpc_connection_t, message: xpc_object_t) {
        guard let reply = xpc_dictionary_create_reply(message) else { return }
        xpc_dictionary_set_string(reply, "ok", "1")
        xpc_connection_send_message(peer, reply)
    }

    // Write the helper's session state. A stop reply also carries `owned`, so a
    // reconnecting caller can tell its own stop from another connection's
    // acknowledgement.
    private func writeStatus(_ reply: xpc_object_t) {
        let snapshot = controller.snapshot()
        let cleanupBlocked = controller.requiresCleanup
        xpc_dictionary_set_bool(reply, "running", snapshot.running)
        xpc_dictionary_set_bool(reply, "stopping", snapshot.stopping)
        xpc_dictionary_set_bool(reply, "starting", snapshot.starting)
        xpc_dictionary_set_bool(reply, "cleanup_blocked", cleanupBlocked)
        if let current = snapshot.currentSession {
            xpc_dictionary_set_string(reply, "current_session", current.uuidString)
        }
        if let last = snapshot.lastSession {
            xpc_dictionary_set_string(reply, "last_session", last.uuidString)
        }
        xpc_dictionary_set_string(reply, "last_result", snapshot.lastResult.rawValue)
        if let reason = snapshot.lastFailureReason {
            xpc_dictionary_set_string(reply, "last_reason", reason.rawValue)
        }
    }

    private func replyStopped(_ peer: xpc_connection_t, message: xpc_object_t, report: HelperSessionController.StopReport) {
        guard let reply = xpc_dictionary_create_reply(message) else { return }
        xpc_dictionary_set_string(reply, "ok", "1")
        xpc_dictionary_set_bool(reply, "owned", report.owned)
        writeStatus(reply)
        xpc_connection_send_message(peer, reply)
    }

    private func replyStatus(_ peer: xpc_connection_t, message: xpc_object_t) {
        guard let reply = xpc_dictionary_create_reply(message) else { return }
        xpc_dictionary_set_string(reply, "ok", "1")
        writeStatus(reply)
        xpc_connection_send_message(peer, reply)
    }

    private func replyError(_ peer: xpc_connection_t, message: xpc_object_t, code: String, reason: String? = nil) {
        guard let reply = xpc_dictionary_create_reply(message) else { return }
        xpc_dictionary_set_string(reply, "ok", "0")
        xpc_dictionary_set_string(reply, "error", code)
        if let reason { xpc_dictionary_set_string(reply, "reason", reason) }
        xpc_connection_send_message(peer, reply)
    }
}
