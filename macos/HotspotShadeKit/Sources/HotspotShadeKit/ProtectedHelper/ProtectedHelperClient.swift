import Foundation
import XPC
import Dispatch

public struct HelperStartReply: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let port: UInt16
    public let secret: String
    // The helper's identity for this engine session. The app retains it and
    // sends it with a later stop or status check, so a reconnect can describe
    // exactly which session it needs to confirm.
    public let sessionID: UUID
    public init(port: UInt16, secret: String, sessionID: UUID = UUID()) {
        self.port = port
        self.secret = secret
        self.sessionID = sessionID
    }
    // The per-launch secret is a credential. A log or a debugger must not
    // print it as part of a value description.
    public var description: String { "HelperStartReply(port: \(port), session: \(sessionID.uuidString), secret: <redacted>)" }
    public var debugDescription: String { description }
}

public enum ProtectedHelperClientState: Equatable, Sendable {
    case disconnected
    case running(HelperStartReply)
    case unavailable(HelperTrustError)
}

// Why a helper connection became unusable. The app never restarts after any of
// these. The reason selects the sentence that the app shows.
public enum HelperInvalidation: Equatable, Sendable {
    case connectionLost
    case callerRejected
    case engineExited
    // The engine exited and the helper recorded a durable cleanup block. The
    // app must not present this as a normal stop.
    case cleanupBlocked
    // The helper stopped the engine because the administrator authorization
    // was not completed within its deadline. The stop and cleanup handling is
    // the same as for any helper stop; only the sentence differs.
    case authorizationTimedOut
    // The engine exited before the helper wrote any grant for it. No route
    // changed and the helper set no cleanup block. The tunnel did not start.
    case startFailed(EngineStartFailureReason?)

    // Read the helper's out-of-band `engine_exited` notice. A cleanup block
    // always wins over the reason.
    public static func engineExitedNotice(
        reason: String?,
        cleanupBlocked: Bool,
        failedStart: Bool = false
    ) -> HelperInvalidation {
        if cleanupBlocked { return .cleanupBlocked }
        if failedStart { return .startFailed(reason.flatMap(EngineStartFailureReason.init(rawValue:))) }
        if reason == HelperAuthorizationDeadline.timeoutReason { return .authorizationTimedOut }
        return .engineExited
    }
}

public protocol ProtectedHelperTransport: AnyObject {
    var onInvalidation: ((HelperInvalidation) -> Void)? { get set }
    // Complete a harmless, fresh handshake. This must run before the app asks
    // Authorization Services for any grant. It returns the server nonce that a
    // start request must echo.
    func handshake() throws -> HelperHandshake
    // Start the engine. Starting it changes no route, so it carries no
    // administrator form. The tunnel start is authorized separately. The
    // optional descriptor carries the one pairing handoff. The helper passes
    // it to the root engine and never reads it.
    func start(serverNonce: Data, timeout: TimeInterval, credentials: Int32?) throws -> HelperStartReply
    // Verify one administrator authorization for the tunnel start. The helper
    // writes the one-time grant that the engine consumes.
    func authorizeStart(authorization: Data, serverNonce: Data, timeout: TimeInterval) throws
    func stop() throws -> HelperStopReply
    func cancel() throws
    func status() throws -> HelperStatus
    func close()
}

// The app side must verify the helper install and pin the helper's code
// signature before it sends a start request. The XPC runtime then drops a
// reply from any other code. A lost connection is a stop, never a restart.
public final class ProtectedHelperClient: @unchecked Sendable {
    private let verifier: HelperInstallVerifier
    private let factory: @Sendable (VerifiedHelperInstall) throws -> ProtectedHelperTransport
    private let lock = NSLock()
    private var transport: ProtectedHelperTransport?
    private var storedState: ProtectedHelperClientState = .disconnected
    // One handshake authorizes one request. A start or an authorization
    // consumes it, even when the helper refuses the request. A later request
    // needs a new handshake on the same live connection.
    private var handshake: HelperHandshake?
    // Set when the helper reported that its engine exited before any grant.
    private var storedStartFailure: EngineStartFailureReason?

    // The fixed reason of a start that failed before any authorization on
    // the current or last connection, or nil.
    public var startFailure: EngineStartFailureReason? {
        lock.lock(); defer { lock.unlock() }
        return storedStartFailure
    }

    public init(
        verifier: HelperInstallVerifier,
        transportFactory: @escaping @Sendable (VerifiedHelperInstall) throws -> ProtectedHelperTransport
    ) {
        self.verifier = verifier
        self.factory = transportFactory
    }

    public var state: ProtectedHelperClientState {
        lock.lock(); defer { lock.unlock() }
        return storedState
    }

    public func connect() throws -> VerifiedHelperInstall {
        let install = try verifier.verify()
        // A reconnect replaces the old transport instead of leaking it.
        lock.lock()
        let previous = self.transport
        self.transport = nil
        self.handshake = nil
        lock.unlock()
        previous?.close()
        let transport = try factory(install)
        transport.onInvalidation = { [weak self] reason in
            self?.invalidate(reason)
        }
        // The handshake runs before the caller can ask for an authorization.
        // It proves the pinned peer answers this connection with a fresh nonce.
        let handshake: HelperHandshake
        do {
            handshake = try transport.handshake()
        } catch {
            transport.close()
            throw error
        }
        lock.lock()
        self.transport = transport
        self.handshake = handshake
        storedState = .disconnected
        storedStartFailure = nil
        lock.unlock()
        return install
    }

    public var isConnected: Bool {
        currentTransport() != nil
    }

    // Complete a fresh handshake on the live connection without replacing it.
    // The engine session belongs to this connection, so an authorization must
    // not open a second connection: closing this one would stop the engine.
    public func performHandshake() throws {
        guard let transport = currentTransport() else { throw missingTransportError() }
        lock.lock()
        // A failed handshake must not leave an older nonce for a later request.
        self.handshake = nil
        lock.unlock()
        let value = try transport.handshake()
        lock.lock()
        self.handshake = value
        lock.unlock()
    }

    public func start(timeout: TimeInterval = 15, credentials: Int32? = nil) throws -> HelperStartReply {
        guard let transport = currentTransport() else { throw HelperTrustError.notConnected }
        lock.lock()
        let handshake = self.handshake
        // Consume the handshake before the request. A lost reply must not let
        // the app reuse it for a second start.
        self.handshake = nil
        lock.unlock()
        guard let handshake else { throw HelperTrustError.handshakeRequired }
        do {
            let reply = try transport.start(
                serverNonce: handshake.serverNonce,
                timeout: timeout,
                credentials: credentials
            )
            lock.lock()
            storedState = .running(reply)
            lock.unlock()
            return reply
        } catch let error as HelperTrustError {
            if error == .helperTimeout || error == .helperUnavailable || error == .notConnected {
                // A timeout is ambiguous: the helper may have started an engine
                // whose reply did not arrive. Cancel and close the connection
                // so the helper's connection-loss path stops that engine. The
                // app must not leave a root engine serving a request that it
                // counted as failed.
                try? transport.cancel()
                transport.close()
                lock.lock()
                if (self.transport as AnyObject?) === transport {
                    self.transport = nil
                }
                storedState = .unavailable(error)
                lock.unlock()
            } else {
                lock.lock()
                storedState = .unavailable(error)
                lock.unlock()
            }
            throw error
        }
    }

    // Send one administrator authorization for the tunnel start. The helper
    // verifies the form and writes the one-time grant. A failure here does not
    // close the connection: the engine still runs and the person can retry.
    public func authorizeStart(authorization: Data, timeout: TimeInterval = 20) throws {
        guard let transport = currentTransport() else { throw missingTransportError() }
        lock.lock()
        let handshake = self.handshake
        // One handshake authorizes one request.
        self.handshake = nil
        lock.unlock()
        guard let handshake else { throw HelperTrustError.handshakeRequired }
        do {
            try transport.authorizeStart(
                authorization: authorization,
                serverNonce: handshake.serverNonce,
                timeout: timeout
            )
        } catch HelperTrustError.tunnelNotRunning where missingTransportError() == .authorizationTimedOut {
            // The deadline notice arrived before this reply. The engine is
            // gone because the authorization took too long.
            throw HelperTrustError.authorizationTimedOut
        }
    }

    public func status() throws -> HelperStatus {
        guard let transport = currentTransport() else { throw HelperTrustError.notConnected }
        let status = try transport.status()
        if status.cleanupBlocked {
            lock.lock()
            storedState = .unavailable(.cleanupBlocked)
            lock.unlock()
        }
        return status
    }

    @discardableResult
    public func stop() -> HelperStopReply? {
        guard let transport = currentTransport() else { return nil }
        clearHandshake()
        do {
            let reply = try transport.stop()
            lock.lock()
            if reply.status.cleanupBlocked {
                storedState = .unavailable(.cleanupBlocked)
            } else if reply.owned && !reply.status.running && !reply.status.stopping {
                storedState = .disconnected
            } else {
                // The transport answered, but this connection did not stop its
                // own engine or a stop is still in flight. Never record that as
                // a clean state for a later caller to trust.
                storedState = .unavailable(.stopNotConfirmed)
            }
            lock.unlock()
            return reply
        } catch let error as HelperTrustError {
            // A stop reply can be lost while the helper still stops the engine.
            // Close the connection so the helper's connection-loss path applies
            // and report the failure instead of claiming a clean stop.
            transport.close()
            lock.lock()
            if (self.transport as AnyObject?) === transport {
                self.transport = nil
            }
            storedState = .unavailable(error)
            lock.unlock()
            return nil
        } catch {
            transport.close()
            lock.lock()
            self.transport = nil
            storedState = .unavailable(.helperUnavailable)
            lock.unlock()
            return nil
        }
    }

    public func cancel() {
        guard let transport = currentTransport() else { return }
        clearHandshake()
        do {
            try transport.cancel()
            lock.lock()
            storedState = .disconnected
            lock.unlock()
        } catch let error as HelperTrustError {
            transport.close()
            lock.lock()
            if (self.transport as AnyObject?) === transport {
                self.transport = nil
            }
            storedState = .unavailable(error)
            lock.unlock()
        } catch {
            transport.close()
            lock.lock()
            self.transport = nil
            storedState = .unavailable(.helperUnavailable)
            lock.unlock()
        }
    }

    public func close() {
        lock.lock()
        let transport = self.transport
        self.transport = nil
        self.handshake = nil
        storedState = .disconnected
        lock.unlock()
        transport?.close()
    }

    private func currentTransport() -> ProtectedHelperTransport? {
        lock.lock(); defer { lock.unlock() }
        return transport
    }

    private func clearHandshake() {
        lock.lock()
        handshake = nil
        lock.unlock()
    }

    private func invalidate(_ reason: HelperInvalidation) {
        lock.lock()
        transport = nil
        handshake = nil
        switch reason {
        case .connectionLost:
            storedState = .unavailable(.helperUnavailable)
        case .callerRejected:
            storedState = .unavailable(.callerRejected)
        case .engineExited:
            storedState = .unavailable(.engineExited)
        case .cleanupBlocked:
            storedState = .unavailable(.cleanupBlocked)
        case .authorizationTimedOut:
            storedState = .unavailable(.authorizationTimedOut)
        case .startFailed(let reason):
            storedState = .unavailable(.engineStartFailed)
            storedStartFailure = reason ?? .exitedWithoutReason
        }
        lock.unlock()
    }

    // A request on a connection the helper already invalidated. After an
    // authorization deadline stop, name that reason instead of a lost helper.
    private func missingTransportError() -> HelperTrustError {
        lock.lock(); defer { lock.unlock() }
        if case .unavailable(.authorizationTimedOut) = storedState { return .authorizationTimedOut }
        return .notConnected
    }
}

// A timeout can return while the XPC reply handler is still pending. Keep the
// reply in a lock-protected box so the handler and the caller never race on a
// captured local variable.
private final class ReplyBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: xpc_object_t?
    func store(_ event: xpc_object_t) {
        lock.lock(); value = event; lock.unlock()
    }
    func load() -> xpc_object_t? {
        lock.lock(); defer { lock.unlock() }
        return value
    }
}

// The production transport is thin. It sets the server requirement on the XPC
// connection, uses the privileged bootstrap lookup so a per-user agent cannot
// shadow the system service name, completes a harmless handshake, and only
// then sends the authorization form. It never passes a token in an XPC message.
public final class XPCProtectedHelperTransport: ProtectedHelperTransport, @unchecked Sendable {
    private let connection: xpc_connection_t
    private let queue = DispatchQueue(label: "hotspotshade-helper-client")
    private let lock = NSLock()
    private var closed = false
    private var serverNonce: Data?
    public var onInvalidation: ((HelperInvalidation) -> Void)?

    public init(install: VerifiedHelperInstall) throws {
        let requirement = try HelperRequirement.make(
            identifier: HelperRequirement.helperIdentifier,
            teamIdentifier: install.teamIdentifier
        )
        let connection = xpc_connection_create_mach_service(
            HelperRequirement.helperServiceName,
            nil,
            UInt64(XPC_CONNECTION_MACH_SERVICE_PRIVILEGED)
        )
        guard xpc_connection_set_peer_code_signing_requirement(connection, requirement) == 0 else {
            throw HelperTrustError.signatureRejected
        }
        self.connection = connection
        xpc_connection_set_event_handler(connection) { [weak self] event in
            guard let self else { return }
            switch xpc_get_type(event) {
            case XPC_TYPE_ERROR:
                self.invalidate(.connectionLost)
            case XPC_TYPE_DICTIONARY:
                // The helper sends this out-of-band message when its engine
                // exits. It carries no port, secret, address, or path. A stop at
                // the authorization deadline uses the same notice with the
                // fixed reason `authorization_timeout`; the app handles it
                // like any other helper stop, but names the reason in its sentence.
                if let name = xpc_dictionary_get_string(event, "event"),
                   String(cString: name) == "engine_exited" {
                    let reason = xpc_dictionary_get_string(event, "reason").map { String(cString: $0) }
                    self.invalidate(HelperInvalidation.engineExitedNotice(
                        reason: reason,
                        cleanupBlocked: xpc_dictionary_get_bool(event, "cleanup_blocked"),
                        failedStart: xpc_dictionary_get_bool(event, "failed_start")
                    ))
                }
            default:
                break
            }
        }
        xpc_connection_resume(connection)
    }

    public func handshake() throws -> HelperHandshake {
        guard let clientNonce = HelperHandshakeGate.randomNonce() else {
            throw HelperTrustError.responseRejected
        }
        let message = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_string(message, "action", "hello")
        xpc_dictionary_set_uint64(message, "protocol", 2)
        clientNonce.withUnsafeBytes { buffer in
            guard let base = buffer.baseAddress else { return }
            xpc_dictionary_set_data(message, "nonce", base, buffer.count)
        }
        let reply = try send(message, timeout: 10)
        guard xpc_dictionary_get_uint64(reply, "protocol") == 2,
              let echoed = data(reply, "nonce"),
              constantTimeEqual(echoed, clientNonce),
              let nonce = data(reply, "server_nonce"),
              nonce.count == HelperHandshakeGate.nonceByteCount
        else {
            throw HelperTrustError.responseRejected
        }
        lock.lock()
        serverNonce = nonce
        lock.unlock()
        return HelperHandshake(serverNonce: nonce)
    }

    public func start(serverNonce: Data, timeout: TimeInterval, credentials: Int32?) throws -> HelperStartReply {
        let message = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_string(message, "action", "start")
        serverNonce.withUnsafeBytes { buffer in
            guard let base = buffer.baseAddress else { return }
            xpc_dictionary_set_data(message, "server_nonce", base, buffer.count)
        }
        if let credentials, credentials >= 0 {
            xpc_dictionary_set_fd(message, "credentials", credentials)
        }
        lock.lock()
        self.serverNonce = nil
        lock.unlock()
        let reply = try send(message, timeout: timeout)
        let port = xpc_dictionary_get_uint64(reply, "port")
        guard let text = xpc_dictionary_get_string(reply, "secret") else {
            throw HelperTrustError.engineStartFailed
        }
        guard port > 0, port <= UInt64(UInt16.max) else {
            throw HelperTrustError.engineStartFailed
        }
        let secret = String(cString: text)
        guard secret.count == 64,
              secret.allSatisfy({ $0.isHexDigit })
        else {
            throw HelperTrustError.engineStartFailed
        }
        guard let sessionText = xpc_dictionary_get_string(reply, "session"),
              let sessionID = UUID(uuidString: String(cString: sessionText))
        else {
            throw HelperTrustError.engineStartFailed
        }
        return HelperStartReply(port: UInt16(port), secret: secret, sessionID: sessionID)
    }

    public func authorizeStart(authorization: Data, serverNonce: Data, timeout: TimeInterval) throws {
        let message = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_string(message, "action", "authorize")
        serverNonce.withUnsafeBytes { buffer in
            guard let base = buffer.baseAddress else { return }
            xpc_dictionary_set_data(message, "server_nonce", base, buffer.count)
        }
        authorization.withUnsafeBytes { buffer in
            guard let base = buffer.baseAddress, buffer.count > 0 else { return }
            xpc_dictionary_set_data(message, "authorization", base, buffer.count)
        }
        lock.lock()
        self.serverNonce = nil
        lock.unlock()
        _ = try send(message, timeout: timeout)
    }

    public func stop() throws -> HelperStopReply {
        // The helper may spend its full engine-stop bound before it replies.
        // Use the shared client deadline so the app does not declare a timeout
        // while the helper is still stopping the engine.
        let reply = try call(action: "stop", timeout: HelperEngineStopDeadline.clientStop)
        return try stopReply(from: reply)
    }

    public func cancel() throws {
        let reply = try call(action: "cancel", timeout: HelperEngineStopDeadline.clientStop)
        _ = try stopReply(from: reply)
    }

    public func status() throws -> HelperStatus {
        let reply = try call(action: "status", timeout: 5)
        return try helperStatus(from: reply)
    }

    // The helper protocol reports a stop result with its own ownership flag and
    // the session snapshot. A missing field is a malformed reply, never a clean
    // stop. An old helper that lacks the fields fails the protocol handshake
    // before it can answer this request.
    private func stopReply(from reply: xpc_object_t) throws -> HelperStopReply {
        guard let owned = bool(reply, "owned") else {
            throw HelperTrustError.responseRejected
        }
        return HelperStopReply(owned: owned, status: try helperStatus(from: reply))
    }

    private func helperStatus(from reply: xpc_object_t) throws -> HelperStatus {
        guard let running = bool(reply, "running"),
              let stopping = bool(reply, "stopping"),
              let starting = bool(reply, "starting"),
              let cleanupBlocked = bool(reply, "cleanup_blocked")
        else {
            throw HelperTrustError.responseRejected
        }
        let lastResult = string(reply, "last_result")
            .flatMap(HelperSessionStopResult.init(rawValue:)) ?? .none
        return HelperStatus(
            running: running,
            cleanupBlocked: cleanupBlocked,
            stopping: stopping,
            starting: starting,
            currentSession: string(reply, "current_session").flatMap(UUID.init(uuidString:)),
            lastSession: string(reply, "last_session").flatMap(UUID.init(uuidString:)),
            lastResult: lastResult,
            lastFailureReason: string(reply, "last_reason").flatMap(EngineStartFailureReason.init(rawValue:))
        )
    }

    public func close() {
        lock.lock()
        let alreadyClosed = closed
        closed = true
        serverNonce = nil
        lock.unlock()
        if !alreadyClosed { xpc_connection_cancel(connection) }
    }

    private func invalidate(_ reason: HelperInvalidation) {
        lock.lock()
        let alreadyClosed = closed
        closed = true
        serverNonce = nil
        lock.unlock()
        guard !alreadyClosed else { return }
        onInvalidation?(reason)
        xpc_connection_cancel(connection)
    }

    private func data(_ reply: xpc_object_t, _ key: String) -> Data? {
        var length = 0
        guard let bytes = xpc_dictionary_get_data(reply, key, &length),
              length > 0
        else {
            return nil
        }
        return Data(bytes: bytes, count: length)
    }

    // A missing boolean or string is not silently false or empty. The reply
    // parser needs to reject a partial answer instead of reading it as a clean
    // stop.
    private func bool(_ reply: xpc_object_t, _ key: String) -> Bool? {
        guard xpc_dictionary_get_value(reply, key) != nil else { return nil }
        return xpc_dictionary_get_bool(reply, key)
    }

    private func string(_ reply: xpc_object_t, _ key: String) -> String? {
        guard let value = xpc_dictionary_get_string(reply, key) else { return nil }
        return String(cString: value)
    }

    private func constantTimeEqual(_ left: Data, _ right: Data) -> Bool {
        guard left.count == right.count else { return false }
        var difference: UInt8 = 0
        for (a, b) in zip(left, right) {
            difference |= a ^ b
        }
        return difference == 0
    }

    private func call(
        action: String,
        authorization: Data? = nil,
        timeout: TimeInterval
    ) throws -> xpc_object_t {
        let message = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_string(message, "action", action)
        if let authorization {
            authorization.withUnsafeBytes { buffer in
                guard let base = buffer.baseAddress, buffer.count > 0 else { return }
                xpc_dictionary_set_data(message, "authorization", base, buffer.count)
            }
        }
        return try send(message, timeout: timeout)
    }

    private func send(_ message: xpc_object_t, timeout: TimeInterval) throws -> xpc_object_t {
        lock.lock()
        let isClosed = closed
        lock.unlock()
        guard !isClosed else { throw HelperTrustError.notConnected }

        let semaphore = DispatchSemaphore(value: 0)
        let box = ReplyBox()
        xpc_connection_send_message_with_reply(connection, message, queue) { event in
            box.store(event)
            semaphore.signal()
        }
        guard semaphore.wait(timeout: .now() + timeout) == .success else {
            throw HelperTrustError.helperTimeout
        }
        guard let reply = box.load() else { throw HelperTrustError.notConnected }
        guard xpc_get_type(reply) == XPC_TYPE_DICTIONARY else {
            if xpc_get_type(reply) == XPC_TYPE_ERROR { throw HelperTrustError.helperUnavailable }
            throw HelperTrustError.responseRejected
        }
        guard xpc_dictionary_get_string(reply, "ok").map({ String(cString: $0) }) == "1" else {
            let code = xpc_dictionary_get_string(reply, "error").map { String(cString: $0) } ?? ""
            switch code {
            case "busy": throw HelperTrustError.helperBusy
            case "cleanup_blocked": throw HelperTrustError.cleanupBlocked
            case "engine_start":
                // A fixed reason means the engine exited before it was ready
                // and before any grant. Without one, keep the older answer.
                if let reason = xpc_dictionary_get_string(reply, "reason")
                    .flatMap({ EngineStartFailureReason(rawValue: String(cString: $0)) }) {
                    throw HelperEngineDidNotStart(reason: reason)
                }
                throw HelperTrustError.engineStartFailed
            case "start_exclusion_busy": throw HelperTrustError.startExclusionBusy
            case "start_exclusion_unavailable": throw HelperTrustError.startExclusionUnavailable
            case "connection_closed": throw HelperTrustError.notConnected
            case "cancelled": throw HelperTrustError.cancelled
            case "caller_rejected": throw HelperTrustError.callerRejected
            case "not_authorized": throw HelperTrustError.notAuthorized
            case "authorization_busy": throw HelperTrustError.authorizationBusy
            case "not_configured": throw HelperTrustError.startRightNotConfigured
            case "not_handshaken": throw HelperTrustError.handshakeRequired
            case "not_running": throw HelperTrustError.tunnelNotRunning
            case "authorization_failed": throw HelperTrustError.grantFailed
            default: throw HelperTrustError.responseRejected
            }
        }
        return reply
    }
}
