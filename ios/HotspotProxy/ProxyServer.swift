import Foundation
import Network
import Darwin

/// The TCP options for the listener and the cellular outbound connection.
/// Small writes leave at once and do not wait for a delayed ACK. Keepalive
/// keeps an idle carrier mapping and detects a peer that is gone. It is not
/// application traffic. An open TCP relay is not closed for application
/// silence. UDP and half-closed flows keep their idle bounds.
func makeNoDelayTCPOptions() -> NWProtocolTCP.Options {
    let options = NWProtocolTCP.Options()
    options.noDelay = true
    options.enableKeepalive = true
    options.keepaliveIdle = 60
    options.keepaliveInterval = 10
    options.keepaliveCount = 3
    return options
}

func makeNoDelayTCPParameters() -> NWParameters {
    NWParameters(tls: nil, tcp: makeNoDelayTCPOptions())
}

/// The listener operations that the proxy uses.
///
/// `NetworkProxyListener` is the only production implementation of this seam.
/// A test injects a fake through `ProxyListenerFactory` and drives the same
/// state and connection handlers that Network.framework calls. The seam is
/// always compiled, so the test exercises the same server path as production
/// and only the listener object changes.
protocol ProxyListenerHandle: AnyObject {
    var state: NWListener.State { get }
    func setStateUpdateHandler(_ handler: ((NWListener.State) -> Void)?)
    func setNewConnectionHandler(_ handler: ((NWConnection) -> Void)?)
    func start(queue: DispatchQueue)
    func cancel()
}

/// Bridge the seam to `NWListener`. It keeps the handler types simple for a
/// fake and does not add methods to the SDK type.
final class NetworkProxyListener: ProxyListenerHandle {
    private let listener: NWListener

    init(parameters: NWParameters) throws {
        listener = try NWListener(using: parameters)
    }

    var state: NWListener.State { listener.state }

    func setStateUpdateHandler(_ handler: ((NWListener.State) -> Void)?) {
        listener.stateUpdateHandler = handler
    }

    func setNewConnectionHandler(_ handler: ((NWConnection) -> Void)?) {
        listener.newConnectionHandler = handler
    }

    func start(queue: DispatchQueue) {
        listener.start(queue: queue)
    }

    func cancel() {
        listener.cancel()
    }
}

/// Create the listener for one proxy run. `NetworkProxyListenerFactory` is the
/// production path. A test supplies a fake that never opens a socket.
protocol ProxyListenerFactory {
    func makeListener(parameters: NWParameters) throws -> any ProxyListenerHandle
}

struct NetworkProxyListenerFactory: ProxyListenerFactory {
    func makeListener(parameters: NWParameters) throws -> any ProxyListenerHandle {
        try NetworkProxyListener(parameters: parameters)
    }
}

/// The bounded waiting policy for the main proxy listener.
///
/// A listener reports `.waiting` while its required local endpoint is not
/// available. The condition can clear by itself, so the server allows one
/// bounded wait. It never waits without a bound: a listener that stays waiting
/// accepts no connection, so `Listening` and `Starting` would both be
/// misleading after the bound. When the bound passes, the run ends as a
/// recoverable failure and the person starts the proxy again. Nothing starts a
/// replacement listener.
struct ProxyListenerWaitPolicy {
    /// The longest one waiting episode may last.
    static let seconds: TimeInterval = 10

    /// The bound for one waiting episode.
    let limit: TimeInterval
    /// The end of the current episode, or nil when no wait is active.
    private(set) var deadline: TimeInterval?

    init(limit: TimeInterval = ProxyListenerWaitPolicy.seconds) {
        // A zero, negative, or non-finite limit cannot bound the wait. Keep
        // the default in that case.
        self.limit = limit.isFinite && limit > 0 ? limit : Self.seconds
    }

    /// True while a bound is active.
    var isWaiting: Bool { deadline != nil }

    /// Start the one bound of this episode. A later waiting event in the same
    /// episode does not extend it.
    mutating func begin(now: TimeInterval) {
        guard deadline == nil else { return }
        deadline = (now.isFinite ? now : 0) + limit
    }

    /// The time left before the bound, in seconds. An absent or passed bound
    /// gives zero.
    func remaining(now: TimeInterval) -> TimeInterval {
        guard let deadline, now.isFinite else { return 0 }
        return max(0, deadline - now)
    }

    /// True once the bound passed. It ends the episode.
    mutating func expire(now: TimeInterval) -> Bool {
        guard let deadline, now.isFinite, now >= deadline else { return false }
        self.deadline = nil
        return true
    }

    /// End the episode with no failure.
    mutating func clear() {
        deadline = nil
    }
}

/// Compare two byte strings without an early return.
///
/// The loop runs over the longer input. A length difference is folded into the
/// result, so a matching prefix with a different length is not equal. Every
/// byte is read and combined, so the time does not follow the first differing
/// byte. Use it for the source device token check. The token still crosses the
/// hotspot link in cleartext; this is a timing hardening, not encryption.
func constantTimeEquals(_ lhs: [UInt8], _ rhs: [UInt8]) -> Bool {
    var difference = lhs.count ^ rhs.count
    let count = max(lhs.count, rhs.count)
    for index in 0..<count {
        let left = index < lhs.count ? lhs[index] : 0
        let right = index < rhs.count ? rhs[index] : 0
        difference |= Int(left ^ right)
    }
    return difference == 0
}

/// The parameters for one destination TCP connection.
///
/// Every Release build and every device build pins the outer connection to the
/// cellular interface. A Debug Simulator build with the explicit test keys can
/// use the host path instead, so a test destination on loopback is reachable
/// without a cellular bearer. See "Simulator test override" in `ios/README.md`.
func makeOutboundTCPParameters() -> NWParameters {
    let parameters = makeNoDelayTCPParameters()
    parameters.requiredInterfaceType = .cellular
    #if DEBUG
    if HotspotInterface.testCellularPathActive() { return makeNoDelayTCPParameters() }
    #endif
    return parameters
}

/// The UDP form of `makeOutboundTCPParameters`. The mocked path is the same
/// explicit Debug Simulator override.
func makeOutboundUDPParameters() -> NWParameters {
    let parameters = NWParameters.udp
    parameters.requiredInterfaceType = .cellular
    #if DEBUG
    if HotspotInterface.testCellularPathActive() { return NWParameters.udp }
    #endif
    return parameters
}

extension RelayHalfClose.Side {
    /// The end reason for a failed socket operation on this side. A failed FIN
    /// write on the connection to the target device is a client socket error.
    var socketErrorEnd: EstablishedEnd {
        self == .client ? .clientSocketError : .destinationSocketError
    }
}

/// Reframe the first TLS ClientHello on one relay direction.
///
/// The relay carries opaque bytes. This shaper changes only the TLS record
/// framing of the first ClientHello handshake message. It does not change one
/// handshake byte, so the transcript hash is unchanged. TLS peers reassemble
/// handshake messages across records (RFC 8446 section 5.1), so small records
/// are legal.
///
/// It does not hide SNI, JA3/JA4, the destination address, DNS names, flow
/// size, or timing. It does not change the TLS version: a byte relay cannot
/// force the client's TLS version, and this shaper does not try. It does not
/// control TCP segmentation; the writes are small, but the local stack and the
/// network can coalesce them.
///
/// The first record or records of the flow are buffered until the first
/// ClientHello is complete. That message is written again as records with 1 to
/// 8 payload bytes. Every later byte passes through unchanged. A non-TLS
/// first byte, a record that is not a handshake record, a message that is not
/// a ClientHello, a message above the cap, or a record count above the cap
/// turns the whole flow into a plain pass-through, byte for byte. The shaper
/// rejects a byte as soon as it rules out a ClientHello, so a short
/// request/response protocol does not wait for a five byte record header or a
/// complete handshake message.
///
/// The parse runs before the buffer cap check. A complete ClientHello is
/// reframed even when the same call also delivered a large tail. With a small
/// custom cap, a split prefix may exceed the cap before its record completes
/// and pass through. The cap bounds bytes held while awaiting a decision.
///
/// A client that ends the stream before the ClientHello is complete must call
/// `finish` before the half-close. `finish` releases the held bytes unchanged,
/// in order, exactly once. Dropping the shaper instead would lose them.
///
/// This is a port of `rust/src/tls_shape.rs`. Shaping is off unless a caller
/// creates a shaper. It holds no address, host name, or SNI value, and it must
/// not log one.
struct ClientHelloShaper {
    enum State: Equatable {
        /// Waiting for a record header or a complete ClientHello.
        case buffering
        /// The first ClientHello was reframed. Later bytes pass through.
        case reframed
        /// The flow is not a shapeable TLS ClientHello. All bytes pass through.
        case passThrough
    }

    /// A TLS handshake record content type.
    static let handshakeContentType: UInt8 = 22
    /// The TLS major version. A record that does not start with 3 is not TLS.
    static let tlsMajor: UInt8 = 3
    /// The handshake type of a ClientHello.
    static let clientHelloType: UInt8 = 1
    /// The largest record payload in TLS 1.2 and 1.3.
    static let maxRecordPayload = 16_384
    /// The fixed part of a ClientHello: handshake header, version, random, and
    /// session id length.
    static let minClientHelloMessage = 4 + 2 + 32 + 1

    private enum RecordStep {
        case needMore
        case passThrough
        case progress
    }

    let maxChunk: Int
    let maxClientHello: Int
    let maxRecords: Int
    let maxBuffered: Int

    private var raw: [UInt8] = []
    private var payload: [UInt8] = []
    private var consumed = 0
    private var records = 0
    private var version: (UInt8, UInt8) = (3, 1)

    private(set) var state: State = .buffering

    init(maxChunk: Int = 8,
         maxClientHello: Int = 16 * 1024,
         maxRecords: Int = 4096,
         maxBuffered: Int = 64 * 1024) {
        self.maxChunk = min(max(1, maxChunk), 8)
        self.maxClientHello = max(maxClientHello, Self.minClientHelloMessage)
        self.maxRecords = max(1, maxRecords)
        self.maxBuffered = max(maxBuffered, self.maxClientHello)
    }

    var isBuffering: Bool { state == .buffering }

    /// The number of bytes held while the flow waits for a ClientHello.
    var bufferedCount: Int { raw.count }

    /// Release the bytes still held, unchanged and in order, once, when the
    /// client ends the stream. Call it before the half-close. A second call
    /// returns nothing, and no later byte is shaped. Without this call the
    /// bytes of an incomplete ClientHello are lost at end of stream.
    mutating func finish() -> [Data] {
        guard state == .buffering else { return [] }
        return passThrough()
    }

    /// Feed the next bytes from the client. The returned pieces go out in
    /// order. While the ClientHello is shaped, each piece is one complete TLS
    /// record. A pass-through piece is the unmodified input.
    mutating func feed(_ data: Data) -> [Data] {
        guard state == .buffering else { return data.isEmpty ? [] : [data] }
        guard !data.isEmpty else { return [] }
        raw.append(contentsOf: data)
        while true {
            if payload.count < 4 {
                switch takeRecord() {
                case .needMore:
                    // Parse before the buffer cap. A complete ClientHello is
                    // reframed even when this feed also carried a large tail,
                    // so the result does not depend on where the stream was
                    // split. The cap applies only to bytes still waiting for
                    // a decision.
                    return raw.count > maxBuffered ? passThrough() : []
                case .passThrough: return passThrough()
                case .progress: continue
                }
            }
            if payload[0] != Self.clientHelloType { return passThrough() }
            let declared = (Int(payload[1]) << 16) | (Int(payload[2]) << 8) | Int(payload[3])
            let messageLength = declared + 4
            if messageLength < Self.minClientHelloMessage || messageLength > maxClientHello {
                return passThrough()
            }
            if payload.count < messageLength {
                switch takeRecord() {
                case .needMore:
                    return raw.count > maxBuffered ? passThrough() : []
                case .passThrough: return passThrough()
                case .progress: continue
                }
            }
            return reframe(messageLength)
        }
    }

    /// Read one handshake record from the raw buffer.
    ///
    /// Each header byte is checked as soon as it is available. A record that
    /// cannot be a handshake record is rejected without waiting for the rest
    /// of the header or payload.
    private mutating func takeRecord() -> RecordStep {
        let available = raw.count - consumed
        if available == 0 { return .needMore }
        if raw[consumed] != Self.handshakeContentType { return .passThrough }
        if available < 2 { return .needMore }
        if raw[consumed + 1] != Self.tlsMajor { return .passThrough }
        if available < 5 { return .needMore }
        let length = (Int(raw[consumed + 3]) << 8) | Int(raw[consumed + 4])
        if length == 0 || length > Self.maxRecordPayload { return .passThrough }
        if payload.count < 4 {
            // Handshake header bytes can span records. Only the bytes inside
            // the current record belong to this prefix.
            let inRecord = min(available - 5, length)
            let needed = min(4 - payload.count, inRecord)
            var prefix = payload
            prefix.append(contentsOf: raw[(consumed + 5)..<(consumed + 5 + needed)])
            if !prefix.isEmpty && prefix[0] != Self.clientHelloType {
                return .passThrough
            }
            if prefix.count >= 4 {
                let declared = (Int(prefix[1]) << 16)
                    | (Int(prefix[2]) << 8)
                    | Int(prefix[3])
                let messageLength = declared + 4
                if messageLength < Self.minClientHelloMessage || messageLength > maxClientHello {
                    return .passThrough
                }
            }
        }
        if available - 5 < length { return .needMore }
        if records == 0 { version = (raw[consumed + 1], raw[consumed + 2]) }
        let start = consumed + 5
        payload.append(contentsOf: raw[start..<(start + length)])
        consumed = start + length
        records += 1
        if records > maxRecords { return .passThrough }
        return .progress
    }

    /// Emit the ClientHello as small records, then the bytes after it.
    private mutating func reframe(_ messageLength: Int) -> [Data] {
        // The cap covers every record written back, including the records that
        // carry handshake bytes after the ClientHello. Without the leftover
        // count, a hello plus a full record of later handshake bytes could pass
        // the cap check and then emit more records than the cap allows.
        let leftoverBytes = payload.count - messageLength
        let leftoverRecords = (leftoverBytes + Self.maxRecordPayload - 1) / Self.maxRecordPayload
        if recordsFor(messageLength) + leftoverRecords > maxRecords { return passThrough() }
        var chunks: [Data] = []
        var offset = 0
        var index = 0
        while offset < messageLength {
            let size = min(1 + (index % maxChunk), messageLength - offset)
            chunks.append(frame(version: version, payload: payload[offset..<(offset + size)]))
            offset += size
            index += 1
        }
        // Handshake bytes that followed the ClientHello in the same records
        // stay in order and unchanged. Only their record framing is new.
        var rest = messageLength
        while rest < payload.count {
            let size = min(Self.maxRecordPayload, payload.count - rest)
            chunks.append(frame(version: version, payload: payload[rest..<(rest + size)]))
            rest += size
        }
        // Bytes after the records that carried the ClientHello were never
        // touched. They go out exactly as they arrived.
        if consumed < raw.count {
            chunks.append(Data(raw[consumed...]))
        }
        state = .reframed
        raw.removeAll(keepingCapacity: false)
        payload.removeAll(keepingCapacity: false)
        consumed = 0
        records = 0
        return chunks
    }

    /// Build one handshake record.
    private func frame(version: (UInt8, UInt8), payload: ArraySlice<UInt8>) -> Data {
        let length = UInt16(payload.count)
        var out = Data(capacity: 5 + payload.count)
        out.append(Self.handshakeContentType)
        out.append(version.0)
        out.append(version.1)
        out.append(UInt8(length >> 8))
        out.append(UInt8(length & 0xff))
        out.append(contentsOf: payload)
        return out
    }

    /// Give up shaping and release every buffered byte unchanged.
    private mutating func passThrough() -> [Data] {
        let bytes = Data(raw)
        state = .passThrough
        raw.removeAll(keepingCapacity: false)
        payload.removeAll(keepingCapacity: false)
        consumed = 0
        records = 0
        return bytes.isEmpty ? [] : [bytes]
    }

    /// The number of records that a split of `length` bytes needs.
    private func recordsFor(_ length: Int) -> Int {
        var count = 0
        var offset = 0
        while offset < length {
            offset += 1 + (count % maxChunk)
            count += 1
        }
        return count
    }
}

final class ProxyServer {
    struct Snapshot {
        var state = "Stopped"
        /// Counts each failure that the server reports. The app records the
        /// value when it requests a start, so a queued snapshot from an older
        /// failure cannot end the new request.
        var failureRevision = 0
        var clients = 0
        /// Open sessions that passed the SOCKS authentication.
        var authenticatedSessions = 0
        /// The wall time of the last traffic from an authenticated session.
        var lastAuthenticatedTraffic: Date?
        var error: String?
        var logs: [String] = []
        /// A plain warning when the effective relay capacity is below the
        /// earlier baseline. It holds counts only.
        var capacityWarning: String?
        /// Aggregate connection counters. The line holds no addresses.
        var connections = ConnectCounters().summary
        /// The cancelled attempts in plain words. It holds no addresses.
        var connectionCancellations: String?
        /// The failed attempts by kind in plain words. It holds no addresses.
        var connectionKinds: String?
        /// The largest failure reason in plain words. It holds no addresses.
        var connectionReasons: String?
        /// The pairing code while the phone user must decide, else nil.
        var pairingCode: String?
        /// The identifier of that exact pairing prompt.
        var pairingPromptID: UUID?
        var pairingReady = false
        var pairingFailureCount = 0
        /// True when the pairing listener could not bind or become ready. The
        /// Dashboard and Settings show a plain pairing-unavailable line.
        var pairingUnavailable = false
        /// The last pairing timeout, denial, or lockout. The app shows it for
        /// 60 seconds or until the next pairing event. It holds no code.
        var pairingNotice: PairingNotice?
        /// The trusted target device count. It follows every trust change.
        var trustedCount = 0
        /// Counts once for every trust change, so the app records one line.
        var trustRevision = 0
        /// The last trust change, with no name or address.
        var lastTrustChange: TrustChange?
        /// The counters and environment for the diagnostics report.
        var diagnostics = DiagnosticsReport()
    }

    var onChange: ((Snapshot) -> Void)?
    // Queue rule:
    // - `queue` owns all shared state: the session table, the counters, the
    //   trust count, the snapshot, and the pairing state.
    // - Each session owns one serial queue. A session queue runs the socket
    //   handlers of that session only, so one slow session cannot delay
    //   another session.
    // - A session callback returns to `queue` with `queue.async` before it
    //   touches shared state. A session queue never reads or writes shared
    //   state.
    // - The ICMP echo selector and its tasks run on `queue`, because they share
    //   the selector cache.
    private let queue = DispatchQueue(label: "hotspotproxy.server")
    private let queueKey = DispatchSpecificKey<Bool>()
    /// The parent of every session queue. It is concurrent, so the sessions
    /// run in parallel.
    private static let sessionTarget = DispatchQueue(label: "hotspotproxy.sessions",
                                                     qos: .userInitiated, attributes: .concurrent)
    private let listenerFactory: any ProxyListenerFactory
    private var listener: (any ProxyListenerHandle)?
    /// The bound for one waiting episode. Production uses the default. The
    /// hermetic test passes a short value.
    private var listenerWait: ProxyListenerWaitPolicy
    /// Guards the one waiting timer for the current run and episode. A timer
    /// from an older run or an older episode cannot end a newer run.
    private var listenerWaitTimer: DispatchWorkItem?
    private var listenerWaitID: UUID?
    /// The endpoint of the current run. The ready line and an activation
    /// reconciliation use it. It is cleared with the run.
    private var listenerEndpoint: (address: String, port: UInt16)?
    private var sessions: [UUID: ProxySession] = [:]
    private var echoSelector: ExperimentalICMPSelector?
    #if PROXY_LISTENER_LIFECYCLE_TESTING
    /// The fake-listener test must not start real cellular preflight probes.
    var suppressICMPSelectorForLifecycleTest = false
    #endif
    private let echoTiming = ExperimentalICMPTimingAggregate()
    private var snapshot = Snapshot()
    private var generation = UUID()
    private var connectCounters = ConnectCounters()
    private var diagnostics = DiagnosticsCounters()
    /// The capacity state for this process. It follows the open-file soft
    /// limit and stays fixed while sessions are open. The limit covers three
    /// runs, so a restart while old sockets close stays inside the open-file
    /// limit. The server queue owns it.
    private var capacity = SessionCapacity.Runtime(availability: .unknownFileLimit)
    /// The sessions whose established start reached the counters in this run.
    /// The set pairs an end with its start when the start event is still
    /// pending. A new run clears it.
    private var establishedStarts: Set<UUID> = []
    private var trustRevision = 0
    private var connectLimiter = ConnectLogLimiter()
    private var connectFlushScheduled = false
    /// Count only sessions that passed authentication. The Dashboard uses this.
    private var authenticatedSessions = 0
    private var lastAuthenticatedTraffic: Date?
    private var lastTrafficPublish: Date?
    /// Reframe the first ClientHello on each new TCP flow. Off by default.
    /// Only an explicit `configureTlsShape(true)` turns it on. This changes
    /// TLS record framing only. It does not hide SNI or the destination.
    private var tlsShapeEnabled = false
    // Pairing runs independently of the proxy listener.
    private let trust: ObservableTrustStore
    // Use the responder on `queue` only. It reads the credentials there.
    private lazy var responder = PairingResponder(trust: trust, credentials: { [weak self] in
        self?.pairingCredentials
    }, status: { [weak self] in
        self?.pairingInfo()
    })
    private var pairingCredentials: PairingCredentials?
    private var pairingListener: NWListener?
    /// True only after the current listener reported `.ready`. iOS can stop a
    /// listener during suspension and send no event, so the app clears this
    /// flag when the scene becomes inactive.
    private var pairingReady = false
    private var pairingGeneration = UUID()
    private var pairingPolicy = PairingListenerPolicy(clock: { ProxySession.clock() })
    private var pairingTimer: DispatchSourceTimer?
    private var pairingGrace = PairingListenerGrace()
    private var pairingGraceTimer: DispatchWorkItem?
    private var pairingGraceID: UUID?
    private var pairingPort: UInt16 = 0
    private var pairingToken = ""
    private var pairingConnections: [Int: NWConnection] = [:]
    private var pairingReaders: [Int: PairingFrameReader] = [:]
    private var nextPairingID = 0
    private var pairingTick: DispatchWorkItem?
    private var sceneActive = true
    /// The accept order and the first-frame state of the pairing sockets. A
    /// socket with no complete frame is not yet a responder session.
    private var pairingSlots = PairingConnectionSlots(maximum: 4)
    /// The bound on a socket that has not sent a complete frame. The responder
    /// owns every later deadline, so no second absolute bound can cut a prompt.
    private var pairingFirstFrameTimers: [Int: DispatchWorkItem] = [:]
    /// The bound on the final reply send. The responder removes its session
    /// before a terminal reply, so its deadline no longer covers the socket.
    /// This timer starts only after a terminal reply, never while a prompt is
    /// live.
    private var pairingReplyTimers: [Int: DispatchWorkItem] = [:]
    private static let pairingReplySeconds: TimeInterval = 5

    init(trust: ObservableTrustStore,
         listenerFactory: any ProxyListenerFactory = NetworkProxyListenerFactory(),
         listenerWaitSeconds: TimeInterval = ProxyListenerWaitPolicy.seconds) {
        self.trust = trust
        self.listenerFactory = listenerFactory
        self.listenerWait = ProxyListenerWaitPolicy(limit: listenerWaitSeconds)
        queue.setSpecific(key: queueKey, value: true)
        // Raise the file limit once. A failure is recorded only. The capacity
        // state follows the observed soft limit. An unknown limit stays
        // unknown, so the start fails instead of claiming the nominal cap.
        let fileLimit = FileDescriptorLimit.apply()
        diagnostics.recordFileLimit(fileLimit)
        capacity = SessionCapacity.Runtime(fileLimit: fileLimit)
        snapshot.capacityWarning = SessionCapacity.capacityWarning(limits: capacity.limits)
        snapshot.trustedCount = trust.count
        var report = diagnostics.report()
        report.sessionLimit = capacity.sessionLimit
        report.relayLimit = capacity.limits?.relay
        report.setupReserve = capacity.limits?.setupReserve
        snapshot.diagnostics = report
        trust.setChangeHandler { [weak self] change in self?.trustDidChange(change) }
    }

    /// Publish the trusted count on every change. A remote FORGET comes through
    /// the responder, and Forget all comes from the app. Both use the wrapper.
    private func trustDidChange(_ change: TrustChange) {
        queue.async { [weak self] in
            guard let self = self else { return }
            self.trustRevision += 1
            self.snapshot.trustedCount = self.trust.count
            self.snapshot.trustRevision = self.trustRevision
            self.snapshot.lastTrustChange = change
            self.publish()
        }
    }

    /// Publish the current state once. The app calls this after it installs
    /// the change handler, so the Dashboard shows the startup capacity before
    /// the first start.
    func publishCurrentState() {
        queue.async { [weak self] in self?.publish() }
    }

    func start(port: UInt16, token: String, hotspotAddress: String) {
        queue.async { [weak self] in
            guard let self = self else { return }
            guard self.listener == nil else { return }
            self.echoTiming.reset()
            self.connectCounters = ConnectCounters()
            self.diagnostics.reset()
            self.establishedStarts.removeAll()
            self.connectLimiter = ConnectLogLimiter()
            self.authenticatedSessions = 0
            self.lastAuthenticatedTraffic = nil
            self.lastTrafficPublish = nil
            self.snapshot.connections = self.connectCounters.summary
            self.snapshot.connectionCancellations = nil
            self.snapshot.connectionKinds = nil
            self.snapshot.connectionReasons = nil
            self.snapshot.authenticatedSessions = 0
            self.snapshot.lastAuthenticatedTraffic = nil
            self.snapshot.trustedCount = self.trust.count
            guard let endpointPort = NWEndpoint.Port(rawValue: port), port != 0 else {
                self.snapshot.state = "Failed"
                self.snapshot.failureRevision += 1
                self.snapshot.error = "The proxy port is not valid. Choose another port."
                self.log(self.snapshot.error!)
                return
            }
            switch self.capacity.startRun(now: ProxySession.clock()) {
            case .unavailable(let availability):
                // Do not create a listener that cannot accept one session.
                // The Dashboard hides an unknown error text, so the plain
                // reason goes in the capacity line.
                self.snapshot.state = "Failed"
                self.snapshot.failureRevision += 1
                self.snapshot.error = PlainMessage.startFailed
                self.snapshot.capacityWarning = availability.startFailureMessage
                self.snapshot.clients = 0
                self.snapshot.authenticatedSessions = 0
                self.log(availability.startFailureMessage)
                return
            case .busy(let retiring):
                // A stopped run still owns closing sockets. A start with no
                // free descriptor budget fails. The app does not retry.
                self.snapshot.state = "Failed"
                self.snapshot.failureRevision += 1
                self.snapshot.error = PlainMessage.startFailed
                self.snapshot.capacityWarning =
                    SessionCapacity.Runtime.busyMessage(retiringSessions: retiring)
                self.snapshot.clients = 0
                self.snapshot.authenticatedSessions = 0
                self.log(self.snapshot.capacityWarning!)
                return
            case .started(let limits):
                // The effective limit can be lower than the startup limit
                // after a rapid restart. Show the warning before Listening.
                self.snapshot.capacityWarning = SessionCapacity.capacityWarning(limits: limits)
            }
            do {
                // Read once. A later configuration change applies to the next
                // run, not to flows this listener already accepts.
                let tlsShape = self.tlsShapeEnabled
                let parameters = makeNoDelayTCPParameters()
                parameters.requiredLocalEndpoint = .hostPort(host: NWEndpoint.Host(hotspotAddress), port: endpointPort)
                let listener = try self.listenerFactory.makeListener(parameters: parameters)
                let generation = UUID()
                self.generation = generation
                self.listener = listener
                self.listenerEndpoint = (hotspotAddress, port)
                self.clearListenerWait()
                self.updatePairingTimer()
                self.snapshot.state = "Starting"
                self.snapshot.error = nil
                self.publish()
                if let warning = self.snapshot.capacityWarning {
                    self.log(warning)
                }
                listener.setStateUpdateHandler { [weak self, weak listener] state in
                    // The generation ties this callback to one run. The
                    // identity check rejects a late callback after the slot
                    // moved to another listener. An intentional stop changes
                    // the generation before it cancels the listener, so its
                    // cancelled callback never reaches a case here.
                    guard let self = self, let listener = listener,
                          self.generation == generation,
                          let current = self.listener, current === listener else { return }
                    switch state {
                    case .ready:
                        self.listenerReady()
                    case .waiting:
                        self.listenerWaiting(listener)
                    case .failed(let error):
                        self.listenerFailed(listener, error: Self.listenerError(error, port: port))
                    case .cancelled:
                        self.listenerWasCancelled(listener)
                    default: break
                    }
                }
                listener.setNewConnectionHandler { [weak self] connection in
                    guard let self = self, self.generation == generation else {
                        connection.cancel()
                        return
                    }
                    guard self.admitSession() else {
                        connection.cancel()
                        return
                    }
                    let id = UUID()
                    // One serial queue per session. The concurrent parent lets
                    // the sessions run in parallel.
                    let sessionQueue = DispatchQueue(label: "hotspotproxy.session",
                                                     qos: .userInitiated, target: Self.sessionTarget)
                    let session = ProxySession(id: id, client: connection, token: token,
                                               tlsShape: tlsShape,
                                               queue: sessionQueue, controlQueue: self.queue,
                                               echoSelector: self.echoSelector, onEchoTiming: { [weak self] sample in
                        // A late echo sample from an earlier run must not
                        // enter the counters of the current run.
                        guard let self = self, self.generation == generation else { return }
                        if let message = self.echoTiming.add(sample) { self.log(message) }
                    }, onConnect: { [weak self] report in
                        guard let self = self, self.generation == generation else { return }
                        self.connectReport(report)
                    }, onAuthentication: { [weak self] authenticated in
                        guard let self = self, self.generation == generation else { return }
                        self.authenticatedSessions = max(0, self.authenticatedSessions + (authenticated ? 1 : -1))
                        self.snapshot.authenticatedSessions = self.authenticatedSessions
                        self.publish()
                    }, onConnected: { [weak self] in
                        guard let self = self, self.generation == generation else { return }
                        self.log("Client connected.")
                    }, onAuthenticatedTraffic: { [weak self] in
                        guard let self = self, self.generation == generation else { return }
                        let now = Date()
                        self.lastAuthenticatedTraffic = now
                        self.snapshot.lastAuthenticatedTraffic = now
                        // A busy relay must not publish a snapshot for every packet.
                        if let last = self.lastTrafficPublish, now.timeIntervalSince(last) < 1 { return }
                        self.lastTrafficPublish = now
                        self.publish()
                    }, onEstablished: { [weak self] transport in
                        // A session that left the table was already counted by
                        // an eviction, a stop, or a listener failure. Ignore
                        // its late start event, so the start counts once.
                        guard let self = self, self.generation == generation,
                              self.sessions[id] != nil else { return }
                        self.noteEstablishedStart(id: id, transport: transport)
                        self.publish()
                    }, onRelayAdmission: { [weak self] datagram, completion in
                        // The session queue calls this. The server queue owns
                        // the capacity table and the reservations.
                        guard let self = self else { completion(false); return }
                        self.queue.async {
                            guard self.generation == generation else {
                                completion(false)
                                return
                            }
                            self.admitRelay(id: id, datagram: datagram, completion: completion)
                        }
                    }, onDatagramQueue: { [weak self] peak, dropped in
                        guard let self = self, self.generation == generation else { return }
                        self.diagnostics.recordUDPQueue(peak: peak, dropped: dropped)
                        self.publish()
                    }) { [weak self] close in
                        guard let self = self else { return }
                        // The close callback releases the estimated budget
                        // of its run after it requested cancellation. A late
                        // callback cannot release an active run's session.
                        self.capacity.sessionClosed(id)
                        guard let session = self.sessions.removeValue(forKey: id) else { return }
                        // The session closed by itself. Release any relay slot
                        // that the server reserved for it.
                        self.releaseCapacity(id)
                        // This is the one place that records a natural end. A
                        // stop or an eviction removes the session first and
                        // records the end there, so the end counts once.
                        if let end = session.takeEstablishedEnd() {
                            self.noteEstablishedEnd(id: id, transport: end.transport,
                                                    end: end.end)
                        }
                        self.snapshot.clients = self.sessions.count
                        self.diagnostics.recordSessionCount(self.sessions.count)
                        // A successful authentication-only presence check has
                        // no activity line. The session count above still
                        // changes, and the cleanup still runs.
                        if let line = close.activityLine { self.log(line) } else { self.publish() }
                    }
                    self.sessions[id] = session
                    // Count the descriptor budget of this session. The close
                    // completion releases it.
                    self.capacity.noteSessionOpened(id)
                    self.snapshot.clients = self.sessions.count
                    self.diagnostics.recordSessionCount(self.sessions.count)
                    self.publish()
                    session.start()
                }
                listener.start(queue: self.queue)
            } catch {
                self.capacity.stopRun(now: ProxySession.clock())
                self.snapshot.state = "Failed"
                self.snapshot.failureRevision += 1
                self.snapshot.error = "Cannot start listener: \(error.localizedDescription)"
                self.log(self.snapshot.error!)
            }
        }
    }

    /// End the current run after the listener reported `.failed`. Run it on
    /// `queue` from the matching state callback. The caller already checked the
    /// generation and the listener identity.
    private func listenerFailed(_ listener: any ProxyListenerHandle, error: String) {
        snapshot.state = "Failed"
        snapshot.failureRevision += 1
        snapshot.error = error
        // End the run before the cancel. The cancelled callback belongs to the
        // old generation, so it cannot end a later run or overwrite the error.
        endListenerRun()
        listener.cancel()
        log(error)
    }

    /// End a run whose listener reported `.cancelled` with no app stop.
    ///
    /// iOS can cancel a listener while it suspends the app, without any app
    /// call. Reporting `Listening` then would be false, and the old listener
    /// slot would make a later start return early with no visible change.
    /// Generation separates this event from an intentional stop: `stop`
    /// changes the generation before it cancels the listener, so its
    /// `.cancelled` callback is ignored. This ends the run and releases the
    /// slot. It does not start a replacement, because the proxy is not
    /// persistent and iOS can suspend the app again. The person starts the
    /// proxy again when they choose.
    private func listenerWasCancelled(_ listener: any ProxyListenerHandle) {
        snapshot.state = "Failed"
        snapshot.failureRevision += 1
        snapshot.error = Self.listenerCancelledMessage
        // The listener reported its own cancellation. Do not cancel it again.
        endListenerRun()
        log(Self.listenerCancelledMessage)
    }

    /// Record a ready listener. Run it on `queue` from the matching state
    /// callback, or from activation reconciliation when the callback was lost.
    /// The caller already checked the generation and the listener identity.
    private func listenerReady() {
        let wasListening = snapshot.state == "Listening"
        clearListenerWait()
        snapshot.state = "Listening"
        snapshot.error = nil
        if wasListening {
            publish()
        } else if let endpoint = listenerEndpoint {
            log("Listening on \(endpoint.address):\(endpoint.port).")
        } else {
            log("Listening.")
        }
        #if PROXY_LISTENER_LIFECYCLE_TESTING
        if suppressICMPSelectorForLifecycleTest { return }
        #endif
        if echoSelector == nil {
            let selector = ExperimentalICMPSelector(queue: queue) { [weak self] message in
                self?.log(message)
            }
            echoSelector = selector
            selector.start()
        }
    }

    /// Record a listener that waits for its required local endpoint. Run it on
    /// `queue` from the matching callback, or from activation reconciliation.
    ///
    /// A listener that waits accepts no connection, so do not report
    /// `Listening` during the wait. `Starting` covers both the first start and
    /// a later recovery. One waiting episode has one bound: a repeated waiting
    /// event does not extend it. A new episode starts only after the listener
    /// reports ready again.
    private func listenerWaiting(_ listener: any ProxyListenerHandle, resuming: Bool = false) {
        let now = ProxySession.clock()
        let wasWaiting = listenerWait.isWaiting
        if resuming, listenerWait.expire(now: now) {
            // The bound passed while the app was inactive and the timer did
            // not run. End the run now instead of waiting forever.
            listenerWaitTimedOut(listener)
            return
        }
        listenerWait.begin(now: now)
        snapshot.state = "Starting"
        snapshot.error = Self.listenerWaitingMessage
        if wasWaiting {
            publish()
        } else {
            log(Self.listenerWaitingMessage)
        }
        scheduleListenerWaitTimer(now: now)
    }

    /// Arm the one timer for the current waiting episode. It checks the run,
    /// the episode, and the listener before it acts, so a cancelled timer or a
    /// late callback cannot end a newer run.
    private func scheduleListenerWaitTimer(now: TimeInterval) {
        listenerWaitTimer?.cancel()
        listenerWaitTimer = nil
        listenerWaitID = nil
        guard listenerWait.isWaiting, let listener = listener else { return }
        let generation = self.generation
        let id = UUID()
        listenerWaitID = id
        let delay = listenerWait.remaining(now: now) + 0.05
        let item = DispatchWorkItem { [weak self, weak listener] in
            guard let self = self, let listener = listener,
                  self.generation == generation,
                  self.listenerWaitID == id,
                  self.listener === listener else { return }
            // A state callback may have been delayed while the app was
            // suspended. Reconcile before a due timer cancels a ready listener.
            switch listener.state {
            case .ready:
                self.listenerReady()
                return
            case .failed(let error):
                let message = self.listenerEndpoint.map { Self.listenerError(error, port: $0.port) }
                    ?? "Cannot start listener: \(error.localizedDescription)"
                self.listenerFailed(listener, error: message)
                return
            case .cancelled:
                self.listenerWasCancelled(listener)
                return
            default:
                break
            }
            let now = ProxySession.clock()
            if self.listenerWait.expire(now: now) {
                self.listenerWaitTimedOut(listener)
            } else if self.listenerWait.isWaiting {
                // A timer that fired before its deadline waits for the rest.
                self.scheduleListenerWaitTimer(now: now)
            }
        }
        listenerWaitTimer = item
        queue.asyncAfter(deadline: .now() + max(0, delay), execute: item)
    }

    /// End a run whose listener stayed waiting for its whole bound.
    ///
    /// The listener accepts no connection while it waits. After the bound, the
    /// run ends as a recoverable failure instead of reporting Listening or
    /// Starting forever. The person starts the proxy again. No replacement
    /// listener starts by itself.
    private func listenerWaitTimedOut(_ listener: any ProxyListenerHandle) {
        snapshot.state = "Failed"
        snapshot.failureRevision += 1
        snapshot.error = Self.listenerWaitExpiredMessage
        // End the run before the cancel, so the cancelled callback belongs to
        // the old generation and cannot touch a later run.
        endListenerRun()
        listener.cancel()
        log(Self.listenerWaitExpiredMessage)
    }

    /// End the current waiting episode with no failure.
    private func clearListenerWait() {
        listenerWaitTimer?.cancel()
        listenerWaitTimer = nil
        listenerWaitID = nil
        listenerWait.clear()
    }

    /// Reconcile the main listener when the app becomes active.
    ///
    /// iOS can cancel or fail a listener while it suspends the app, and the
    /// state callback may never arrive. A waiting listener can also pass its
    /// bound while the app does not run. Read the current listener once: end
    /// its run, or restore a bound that is still valid. The check uses the
    /// listener slot, so an old listener cannot affect a newer run.
    private func reconcileProxyListenerOnActivation() {
        guard let listener = listener else { return }
        switch listener.state {
        case .ready:
            // The ready callback may have been lost while the app was inactive.
            listenerReady()
        case .waiting:
            listenerWaiting(listener, resuming: true)
        case .failed(let error):
            let message = listenerEndpoint.map { Self.listenerError(error, port: $0.port) }
                ?? "Cannot start listener: \(error.localizedDescription)"
            listenerFailed(listener, error: message)
        case .cancelled:
            listenerWasCancelled(listener)
        default:
            break
        }
    }

    /// Release the listener and the state owned by its run. The caller sets the
    /// visible state and error first, then logs, so this method publishes
    /// nothing.
    ///
    /// The generation changes before the caller cancels the listener. A late
    /// `.ready`, `.cancelled`, session start, or connect report from this run
    /// then fails its generation guard and cannot reach the next run.
    private func endListenerRun() {
        clearListenerWait()
        listenerEndpoint = nil
        listener = nil
        // Record the end of every established relay in this run before the
        // generation changes. A late callback from this run cannot then reach
        // the next run.
        closeSessions()
        generation = UUID()
        updatePairingTimer()
        echoSelector?.stop()
        echoSelector = nil
    }

    /// Make room for one new session. The phase-aware rule closes only a
    /// session that passed its phase bound. It never closes a healthy open TCP
    /// relay for silence. A session that waits for a relay slot is protected.
    private func admitSession() -> Bool {
        diagnostics.recordSessionCount(sessions.count)
        let now = ProxySession.clock()
        switch capacity.admitConnection(sessions: capacityViews(now: now), now: now) {
        case .accept:
            return true
        case .refuse:
            diagnostics.recordCapRefusal()
            log("Session limit reached. A new connection was refused.")
            return false
        case .closeThenAccept(let id, let reason):
            guard let victim = sessions.removeValue(forKey: id) else {
                // The stale session left already, so its slot is free.
                return true
            }
            releaseCapacity(id)
            // Claim the end before the session queue closes the sockets. The
            // claim makes the later close callback skip the end. An idle
            // half-closed or UDP flow keeps its idle end.
            if let end = victim.takeEstablishedEnd(default: EstablishedEnd.capacityEviction(reason)) {
                noteEstablishedEnd(id: id, transport: end.transport, end: end.end)
            }
            diagnostics.recordEviction(reason: reason)
            let message = Self.evictionMessage(reason)
            victim.closeOnOwnQueue(message)
            snapshot.clients = sessions.count
            diagnostics.recordSessionCount(sessions.count)
            log("Session limit reached. \(message)")
            return true
        }
    }

    /// Decide one relay request on the server queue. Grant a relay slot only
    /// when the relay cap has room or a stale relay phase can close. Never
    /// close an open TCP relay. Call `completion` exactly once.
    private func admitRelay(id: UUID, datagram: Bool,
                            completion: @escaping (Bool) -> Void) {
        guard sessions[id] != nil else {
            completion(false)
            return
        }
        let now = ProxySession.clock()
        switch capacity.admitRelay(id: id, sessions: capacityViews(now: now), now: now) {
        case .grant:
            publish()
            completion(true)
        case .alreadyGranted:
            // A duplicate request after a grant. The slot is already held.
            completion(true)
        case .closeThenGrant(let victimID, let reason):
            if let victim = sessions.removeValue(forKey: victimID) {
                releaseCapacity(victimID)
                if let end = victim.takeEstablishedEnd(default: EstablishedEnd.capacityEviction(reason)) {
                    noteEstablishedEnd(id: victimID, transport: end.transport,
                                       end: end.end)
                }
                diagnostics.recordEviction(reason: reason)
                snapshot.clients = sessions.count
                diagnostics.recordSessionCount(sessions.count)
                let message = Self.evictionMessage(reason)
                victim.closeOnOwnQueue(message)
                log("Session limit reached. \(message)")
            }
            publish()
            completion(true)
        case .refuse, .unavailable:
            diagnostics.recordRelayRefusal()
            completion(false)
        }
    }

    /// Build the capacity view for one decision. Run it on the server queue.
    /// The runtime drops reservations that the sessions already report.
    private func capacityViews(now: TimeInterval) -> [SessionCapacity.PhaseSession] {
        sessions.map { _, session in session.capacitySnapshot(now: now) }
    }

    private func capacityOccupancy(now: TimeInterval) -> SessionCapacity.Occupancy {
        capacity.occupancy(sessions: capacityViews(now: now))
    }

    /// The session left the table. It holds no capacity after this call.
    private func releaseCapacity(_ id: UUID) {
        capacity.release(id)
    }

    /// The plain words for one capacity close. The message names the phase
    /// bound. It never names a destination.
    private static func evictionMessage(_ reason: SessionCapacity.CloseReason) -> String {
        switch reason {
        case .handshakeExpired:
            return "A client did not finish the handshake in time."
        case .connectExpired:
            return "A destination connection did not finish in time."
        case .relayGrantExpired:
            return "A relay slot decision did not finish in time."
        case .udpIdle:
            return "An idle UDP flow was closed."
        case .halfClosedIdle:
            return "An idle half-closed flow was closed."
        }
    }

    private static func listenerError(_ error: NWError, port: UInt16) -> String {
        if case .posix(.EADDRINUSE) = error {
            return "Port \(port) is in use. Choose another port."
        }
        return "Cannot start listener: \(error.localizedDescription)"
    }

    /// The plain message for a listener that the system cancelled. It names no
    /// address, port, or error. iOS can suspend the app and cancel the listener
    /// without an app call, so the server reports the end and waits for the
    /// person to start the proxy again.
    static let listenerCancelledMessage = ListenerDisplayText.cancelled

    /// The plain message while a listener waits for its local endpoint. It
    /// names no address, port, or error. The wait is bounded, so the message
    /// never claims that the proxy is listening.
    static let listenerWaitingMessage = ListenerDisplayText.waiting

    /// The plain message for a listener that stayed waiting for its whole
    /// bound. It names no address, port, or error. The run is recoverable: the
    /// person starts the proxy again, and nothing starts it by itself.
    static let listenerWaitExpiredMessage = ListenerDisplayText.waitExpired

    /// Stop the listener and close every session. Pass `reason` when the app
    /// stops the proxy by itself. The reason stays visible in the status.
    func stop(reason: String? = nil) {
        queue.async { [weak self] in
            guard let self = self else { return }
            let listener = self.listener
            // Release the run before the cancel. The generation change makes
            // the cancelled callback from this listener an old-run event, so
            // an intentional stop never reports a failure.
            self.endListenerRun()
            listener?.cancel()
            self.snapshot.capacityWarning =
                SessionCapacity.capacityWarning(limits: self.capacity.limits)
            self.snapshot.state = "Stopped"
            self.snapshot.error = reason
            self.log(reason ?? "Server stopped.")
        }
    }

    /// Reframe the first ClientHello on each new TCP flow.
    ///
    /// Off by default. Call this before `start`. It changes TLS record framing
    /// only. It does not hide SNI, the destination, DNS names, or flow shape,
    /// and it does not control TCP segmentation. It never changes one
    /// handshake byte. The app has no visible control for it yet.
    func configureTlsShape(_ enabled: Bool) {
        queue.async { [weak self] in
            self?.tlsShapeEnabled = enabled
        }
    }

    // MARK: Pairing
    // The pairing listener binds to the hotspot address only.
    //
    // A listener needs both a port and a non-empty token. The app calls
    // `suspendPairing` when it has no usable token, and every later scene
    // change must keep the listener down. These guards are the one place that
    // decides. Pairing must never hand out a token the app cannot use.
    private var pairingConfigured: Bool {
        pairingPort != 0 && !pairingToken.isEmpty
    }

    func configurePairing(port: UInt16, token: String) {
        queue.async { [weak self] in
            guard let self = self else { return }
            guard PairingProtocol.isUsableProxyPort(port), PairingProtocol.isValidToken(token) else {
                self.suspendPairingOnQueue()
                return
            }
            self.pairingPort = port
            self.pairingToken = token
            if let credentials = self.pairingCredentials {
                // Both values passed the guard above. A nil here would mean an
                // unusable host, so the status answer then has no credentials.
                self.pairingCredentials = PairingCredentials(host: credentials.host, port: port, token: token)
            }
            self.updatePairingTimer()
            // Resume at once after a token load that succeeded later. The app
            // may already be active when it retries the keychain read.
            if self.sceneActive { self.checkPairingHotspot() }
        }
    }

    /// Acknowledge suspension on the server queue before returning. Work
    /// already sent to Network.framework can still reach its peer; cancellation
    /// cannot recall an in-flight frame. No later frame is started by this
    /// listener after the queue has processed the suspension.
    func suspendPairing() {
        if DispatchQueue.getSpecific(key: queueKey) != nil {
            suspendPairingOnQueue()
        } else {
            queue.sync { suspendPairingOnQueue() }
        }
    }

    #if DEBUG
    /// Lets the hermetic wiring test hold the server queue at a known point.
    func enqueuePairingTestWork(_ work: @escaping () -> Void) {
        queue.async(execute: work)
    }
    #endif

    /// Run on `queue`.
    private func suspendPairingOnQueue() {
        pairingPort = 0
        pairingToken = ""
        pairingTimer?.cancel()
        pairingTimer = nil
        stopPairingListener()
    }

    private func checkPairingHotspot() {
        // A scene change, the poll timer, and the policy all pass through here.
        // Without a port and a token there is nothing to offer, so the listener
        // stays down until `configurePairing` supplies both.
        guard pairingConfigured else {
            if pairingListener != nil { stopPairingListener() }
            return
        }
        let observation: PairingListenerPolicy.Observation
        switch HotspotInterface.observe() {
        case .present(let address): observation = .present(address)
        case .absent: observation = .absent
        case .unreadable: observation = .unreadable
        }
        let interval = listener != nil ? HotspotPoll.runningSeconds : HotspotPoll.stoppedSeconds
        switch pairingPolicy.observe(observation, listening: pairingListener != nil, pollInterval: interval) {
        case .start(let address):
            // The pairing credentials need a usable IPv4 hotspot address. Any
            // other address is a failed start, not a listener with no result.
            guard let credentials = PairingCredentials(host: address, port: pairingPort, token: pairingToken) else {
                pairingFailed()
                return
            }
            pairingCredentials = credentials
            startPairingListener(hotspotAddress: address)
        case .stop: stopPairingListener()
        case .none: break
        }
    }

    private func pairingFailed() {
        // Keep the unavailable line through a retry failure. A normal stop
        // clears it, so a missing hotspot does not blame the pairing port.
        stopPairingListener(clearUnavailable: false)
        let firstFailure = pairingPolicy.failed() != nil
        snapshot.pairingUnavailable = true
        if firstFailure { snapshot.pairingFailureCount += 1 }
        publish()
    }

    private func clearPairingGrace() {
        pairingGraceTimer?.cancel()
        pairingGraceTimer = nil
        pairingGraceID = nil
        pairingGrace.clear()
    }

    private func beginPairingGrace() {
        guard sceneActive, pairingListener != nil, pairingGraceTimer == nil else { return }
        let now = ProxySession.clock()
        pairingGrace.begin(now: now)
        guard let deadline = pairingGrace.deadline else { return }
        let generation = pairingGeneration
        let id = UUID()
        pairingGraceID = id
        let item = DispatchWorkItem { [weak self] in
            guard let self = self, self.pairingGeneration == generation,
                  self.pairingGraceID == id else { return }
            self.pairingGraceTimer = nil
            self.pairingGraceID = nil
            if self.sceneActive && !self.pairingReady {
                if self.pairingGrace.expire(now: ProxySession.clock()) {
                    self.pairingFailed()
                } else {
                    self.beginPairingGrace()
                }
            }
        }
        pairingGraceTimer = item
        queue.asyncAfter(deadline: .now() + max(0, deadline - now) + 0.05, execute: item)
    }

    /// Tell the server whether the app scene is active. Pairing needs an active app.
    func setSceneActive(_ active: Bool) {
        queue.async { [weak self] in
            guard let self = self else { return }
            if self.sceneActive != active { self.pairingPolicy.resetObservations() }
            self.sceneActive = active
            if active {
                // A cancellation, failure, or expired wait can happen while the
                // app is inactive and send no callback. Reconcile it before the
                // Dashboard shows an old state.
                self.reconcileProxyListenerOnActivation()
                self.checkPairingHotspot()
                if self.pairingConfigured, let listener = self.pairingListener {
                    if case .ready = listener.state {
                        self.clearPairingGrace()
                        self.pairingReady = true
                        self.snapshot.pairingReady = true
                        self.publish()
                    } else {
                        self.beginPairingGrace()
                    }
                }
                // The pending prompt is visible again. A later timeout then counts.
                self.responder.activate()
            } else {
                self.clearPairingGrace()
                // iOS can stop a listener during suspension and send no event.
                // Do not report it as ready after the app returns.
                self.pairingReady = false
                self.snapshot.pairingReady = false
                self.publish()
                if let output = self.responder.deactivate(now: ProxySession.clock()) {
                    self.applyPairing(output)
                }
            }
            self.updatePairingTimer()
            self.refreshPairingPrompt()
        }
    }

    /// Start or stop the hotspot poll. The poll runs only while the app is
    /// active, and it checks more often while the proxy runs.
    private func updatePairingTimer() {
        pairingTimer?.cancel()
        pairingTimer = nil
        // No token and no port means no listener to keep alive. A scene change
        // must not restart the poll for a suspended listener.
        guard pairingConfigured else { return }
        guard let interval = HotspotPoll.interval(proxyRunning: listener != nil, active: sceneActive) else { return }
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + interval, repeating: interval)
        timer.setEventHandler { [weak self] in self?.checkPairingHotspot() }
        pairingTimer = timer
        timer.resume()
    }

    /// The phone user allowed or denied the target device that waits.
    func decidePairing(promptID: UUID, allow: Bool) {
        queue.async {
            // Bind the decision to the prompt that the person saw. The
            // responder rejects a stale connection, a stale prompt, a
            // different code, or an expired deadline.
            if let prompt = self.responder.pendingPrompt, prompt.id == promptID,
               let output = self.responder.decide(connection: prompt.connection, promptID: prompt.id,
                                                  code: prompt.code, allow: allow,
                                                  now: ProxySession.clock()) {
                self.applyPairing(output)
            }
            self.refreshPairingPrompt()
        }
    }

    private func startPairingListener(hotspotAddress: String) {
        // Check the guard first. A second call must not replace the generation
        // of the live listener and stop its callbacks. A suspended listener has
        // no port and no token, so it never binds.
        guard pairingConfigured,
              pairingListener == nil,
              let port = NWEndpoint.Port(rawValue: PairingProtocol.port) else { return }
        // A new bind attempt is the next pairing event, so an old timeout line
        // no longer describes the current state.
        snapshot.pairingNotice = nil
        let generation = UUID()
        pairingGeneration = generation
        do {
            let parameters = makeNoDelayTCPParameters()
            parameters.requiredLocalEndpoint = .hostPort(host: NWEndpoint.Host(hotspotAddress), port: port)
            let listener = try NWListener(using: parameters)
            pairingListener = listener
            listener.stateUpdateHandler = { [weak self] state in
                guard let self = self, self.pairingGeneration == generation else { return }
                switch state {
                case .ready:
                    self.clearPairingGrace()
                    self.pairingReady = self.sceneActive
                    self.pairingPolicy.ready()
                    self.snapshot.pairingReady = self.sceneActive
                    self.snapshot.pairingUnavailable = false
                    self.publish()
                case .failed:
                    self.pairingFailed()
                case .waiting:
                    self.pairingReady = false
                    self.snapshot.pairingReady = false
                    self.publish()
                    self.beginPairingGrace()
                case .cancelled:
                    self.pairingFailed()
                default: break
                }
            }
            listener.newConnectionHandler = { [weak self] connection in
                guard let self = self, self.pairingGeneration == generation else {
                    connection.cancel()
                    return
                }
                let id = self.nextPairingID
                self.nextPairingID += 1
                // The live prompt is never evicted. Every other socket can be
                // closed to admit a legitimate target check.
                let protected = self.responder.pendingPrompt?.connection
                switch self.pairingSlots.admit(id, protected: protected) {
                case .accept:
                    break
                case .evict(let victim):
                    self.closePairing(victim)
                case .refuse:
                    connection.cancel()
                    return
                }
                self.pairingConnections[id] = connection
                self.pairingReaders[id] = PairingFrameReader()
                connection.stateUpdateHandler = { [weak self] state in
                    switch state {
                    case .ready: self?.receivePairing(id)
                    case .failed, .cancelled: self?.closePairing(id)
                    default: break
                    }
                }
                connection.start(queue: self.queue)
                self.schedulePairingFirstFrameLimit(id)
            }
            listener.start(queue: queue)
            beginPairingGrace()
        } catch {
            pairingFailed()
        }
    }

    private func stopPairingListener(clearUnavailable: Bool = true) {
        clearPairingGrace()
        pairingGeneration = UUID()
        pairingListener?.cancel()
        pairingListener = nil
        pairingReady = false
        pairingCredentials = nil
        snapshot.pairingReady = false
        if clearUnavailable { snapshot.pairingUnavailable = false }
        // A listener stop is a pairing event, so an old result line no longer
        // applies. The unavailable line is set separately by `pairingFailed`.
        snapshot.pairingNotice = nil
        publish()
        pairingTick?.cancel()
        pairingTick = nil
        for id in Array(pairingConnections.keys) { closePairing(id) }
        refreshPairingPrompt()
    }

    private func receivePairing(_ id: Int) {
        guard let connection = pairingConnections[id] else { return }
        connection.receive(minimumIncompleteLength: 1, maximumLength: 1024) { [weak self] data, _, eof, error in
            guard let self = self, self.pairingConnections[id] != nil, var reader = self.pairingReaders[id] else { return }
            do {
                // The reader refuses a push that passes its cap. The catch
                // below closes the connection through `receiveInvalid`.
                if let data = data, !data.isEmpty { try reader.push(data) }
                while let frame = try reader.next() {
                    self.pairingReaders[id] = reader
                    // A complete frame makes this a real session. The responder
                    // owns every deadline from here, including the prompt.
                    self.notePairingFrame(id)
                    let now = ProxySession.clock()
                    if let expired = self.responder.tick(now: now) {
                        self.applyPairing(expired)
                        // This connection got its final reply. Ignore its later frames.
                        if expired.connection == id { self.refreshPairingPrompt(); return }
                    }
                    let output: PairingResponder.Output
                    do {
                        output = try self.responder.receive(frame, connection: id, now: now, active: self.sceneActive,
                                                           peer: Self.peerString(connection))
                    } catch {
                        // The responder refuses an unusable source address.
                        // Close the connection. It holds no session for it.
                        self.closePairing(id)
                        return
                    }
                    self.applyPairing(output)
                    self.refreshPairingPrompt()
                    if output.close { return }
                    guard let current = self.pairingReaders[id] else { return }
                    reader = current
                }
                self.pairingReaders[id] = reader
            } catch {
                if let output = try? self.responder.receiveInvalid(connection: id, now: ProxySession.clock(),
                                                                   peer: Self.peerString(connection)) {
                    self.applyPairing(output)
                } else {
                    self.closePairing(id)
                }
                self.refreshPairingPrompt()
                return
            }
            if eof || error != nil { self.closePairing(id) } else { self.receivePairing(id) }
        }
    }

    private func applyPairing(_ output: PairingResponder.Output) {
        let id = output.connection
        if let notice = Self.pairingNotice(for: output.status) {
            snapshot.pairingNotice = notice
        } else if output.status != nil {
            // Any other pairing result is the next event. An old timeout line
            // no longer describes it.
            snapshot.pairingNotice = nil
        }
        if let status = output.status { log(Self.pairingMessage(status)) }
        guard let connection = pairingConnections[id] else { return }
        if output.close { schedulePairingReplyLimit(id) }
        for (index, frame) in output.frames.enumerated() {
            let last = index == output.frames.count - 1
            connection.send(content: frame, completion: .contentProcessed { [weak self] _ in
                if last && output.close { self?.closePairing(id) }
            })
        }
        if output.close && output.frames.isEmpty { closePairing(id) }
    }

    /// The source address of a pairing connection. The responder uses it for its
    /// per-source budget. It holds no key and no token.
    private static func peerString(_ connection: NWConnection) -> String {
        if case let .hostPort(host, _) = connection.endpoint { return "\(host)" }
        return ""
    }

    /// The live phone state for a status request from a paired target device. Run it on `queue`.
    private func pairingInfo() -> PairingPhoneInfo? {
        // A suspended listener has no credentials to report. A port of 0 would
        // tell a target device to connect nowhere.
        guard pairingConfigured, let credentials = pairingCredentials else { return nil }
        return PairingPhoneInfo(proxyRunning: listener != nil && snapshot.state == "Listening",
                                foreground: sceneActive,
                                connections: UInt16(min(authenticatedSessions, Int(UInt16.max))),
                                port: credentials.port,
                                host: credentials.host)
    }

    /// A complete frame arrived. The responder session now owns the deadline.
    /// Cancel the first-frame bound and stop treating the socket as idle.
    private func notePairingFrame(_ id: Int) {
        guard pairingSlots.isWaiting(id) else { return }
        pairingSlots.receivedFrame(id)
        pairingFirstFrameTimers.removeValue(forKey: id)?.cancel()
    }

    /// Bound a socket that has not sent a complete frame. This is the only
    /// absolute connection bound. A socket that sent a frame is governed by
    /// the responder deadline, so the inactive prompt extension is not cut.
    private func schedulePairingFirstFrameLimit(_ id: Int) {
        let item = DispatchWorkItem { [weak self] in
            guard let self = self, self.pairingSlots.isWaiting(id) else { return }
            self.closePairing(id)
        }
        pairingFirstFrameTimers[id] = item
        queue.asyncAfter(deadline: .now() + PairingConnectionSlots.firstFrameSeconds,
                         execute: item)
    }

    /// Bound the final reply send. The responder removed its session before
    /// this output, so the session deadline cannot close a stuck socket. The
    /// timer starts only for a terminal reply, so it cannot cut a live prompt.
    private func schedulePairingReplyLimit(_ id: Int) {
        pairingReplyTimers.removeValue(forKey: id)?.cancel()
        let item = DispatchWorkItem { [weak self] in
            guard let self = self, self.pairingConnections[id] != nil else { return }
            self.closePairing(id)
        }
        pairingReplyTimers[id] = item
        queue.asyncAfter(deadline: .now() + Self.pairingReplySeconds, execute: item)
    }

    private func closePairing(_ id: Int) {
        pairingFirstFrameTimers.removeValue(forKey: id)?.cancel()
        pairingReplyTimers.removeValue(forKey: id)?.cancel()
        pairingSlots.remove(id)
        pairingReaders.removeValue(forKey: id)
        if let connection = pairingConnections.removeValue(forKey: id) {
            connection.cancel()
            responder.connectionClosed(id)
            refreshPairingPrompt()
        }
    }

    private func refreshPairingPrompt() {
        pairingTick?.cancel()
        pairingTick = nil
        if let deadline = responder.nextDeadline {
            let item = DispatchWorkItem { [weak self] in
                guard let self = self else { return }
                if let output = self.responder.tick(now: ProxySession.clock()) { self.applyPairing(output) }
                self.refreshPairingPrompt()
            }
            pairingTick = item
            queue.asyncAfter(deadline: .now() + max(0, deadline - ProxySession.clock()) + 0.05, execute: item)
        }
        let prompt = responder.pendingPrompt
        if snapshot.pairingCode != prompt?.code || snapshot.pairingPromptID != prompt?.id {
            // A new prompt is the next pairing event. An old timeout line no
            // longer applies. A prompt that just ended keeps its result line
            // until the expiry or the next event.
            if prompt != nil { snapshot.pairingNotice = nil }
            snapshot.pairingCode = prompt?.code
            snapshot.pairingPromptID = prompt?.id
            publish()
        }
    }

    // These lines hold no key and no token.
    private static func pairingNotice(for status: PairingStatus?) -> PairingNotice? {
        let message: String
        switch status {
        case .denied: message = PairingNoticeText.denied
        case .timedOut: message = PairingNoticeText.expired
        case .lockedOut: message = PairingNoticeText.lockedOut
        default: return nil
        }
        return PairingNotice(message: message, at: Date())
    }

    private static func pairingMessage(_ status: PairingStatus) -> String {
        switch status {
        case .ok: return "Pairing finished. The target device received the proxy port and token."
        case .denied: return "Pairing denied."
        case .busy: return "Pairing refused. Another pairing runs."
        case .rejected: return "Pairing rejected. The target device sent an invalid message."
        case .timedOut: return "Pairing timed out."
        case .notActive: return "Pairing refused. Open the app to pair."
        case .lockedOut: return "Pairing refused for 30 seconds after repeated failures."
        }
    }

    private func closeSessions() {
        let active = sessions
        sessions.removeAll()
        // A stop or a listener failure closes every session. No relay slot can
        // stay reserved for a session that left the table. Each session stays
        // in the estimated budget until its close callback arrives.
        capacity.stopRun(now: ProxySession.clock(), liveSessions: Array(active.keys))
        for (id, session) in active {
            // Claim the end before the session queue closes the sockets. The
            // claim makes the later close callback skip the end.
            if let end = session.takeEstablishedEnd() {
                noteEstablishedEnd(id: id, transport: end.transport, end: end.end)
            }
            session.closeOnOwnQueue("Client disconnected.", force: true)
        }
        snapshot.clients = 0
        authenticatedSessions = 0
        snapshot.authenticatedSessions = 0
        diagnostics.recordSessionCount(0)
    }

    /// Record one established relay start for this run. The start counts once.
    private func noteEstablishedStart(id: UUID, transport: EstablishedTransport) {
        guard establishedStarts.insert(id).inserted else { return }
        diagnostics.recordEstablishedStart(transport, at: ProxySession.clock())
    }

    /// Record one established relay end. When the start event is still
    /// pending, record the start first, so the report never shows an end
    /// without a start. The session table removes the session once, so the
    /// same end cannot count twice.
    private func noteEstablishedEnd(id: UUID, transport: EstablishedTransport,
                                    end: EstablishedEnd) {
        let now = ProxySession.clock()
        if establishedStarts.remove(id) == nil {
            diagnostics.recordEstablishedStart(transport, at: now)
        }
        diagnostics.recordEstablishedEnd(transport, end: end, at: now)
    }

    // The connect log lines name the kind and the result in plain words. They
    // hold no destination address. Keep them in the on-screen log only. Never
    // persist them, never send them to the target device, and never write them
    // to a file.
    private func connectReport(_ report: ConnectReport) {
        switch report {
        case .started:
            connectCounters.recordStart()
        case .closedBeforeResult(let retry, let family):
            connectCounters.recordClosedBeforeResult()
            diagnostics.record(retry, family: family)
            refreshConnectCounters()
            publish()
        case .finished(let conclusion, let line, let duration, let retry, let family):
            connectCounters.record(conclusion)
            diagnostics.record(duration: duration)
            diagnostics.record(retry, family: family, failed: conclusion.result == .didNotWork)
            refreshConnectCounters()
            guard let line = line else { publish(); return }
            let now = ProxySession.clock()
            let lines = connectLimiter.submit(line, now: now)
            lines.forEach { log($0) }
            if lines.isEmpty { publish() }
            scheduleConnectFlush(now: now)
        }
    }

    private func refreshConnectCounters() {
        snapshot.connections = connectCounters.summary
        snapshot.connectionCancellations = connectCounters.cancelledSummary
        snapshot.connectionKinds = connectCounters.failureKindSummary
        snapshot.connectionReasons = connectCounters.reasonSummary
    }

    private func scheduleConnectFlush(now: TimeInterval) {
        guard !connectFlushScheduled, let due = connectLimiter.flushDue else { return }
        connectFlushScheduled = true
        let generation = self.generation
        queue.asyncAfter(deadline: .now() + max(0, due - now)) { [weak self] in
            guard let self = self else { return }
            self.connectFlushScheduled = false
            guard self.generation == generation else { return }
            if let line = self.connectLimiter.flush(now: ProxySession.clock()) { self.log(line) }
        }
    }

    private func log(_ message: String) {
        snapshot.logs.append(message)
        if snapshot.logs.count > 50 { snapshot.logs.removeFirst(snapshot.logs.count - 50) }
        publish()
    }

    private func publish() {
        refreshDiagnostics()
        let value = snapshot
        DispatchQueue.main.async { [weak self] in self?.onChange?(value) }
    }

    /// Fill the diagnostics report from the current counters and state.
    private func refreshDiagnostics() {
        let now = ProxySession.clock()
        var report = diagnostics.report(now: now)
        report.connections = connectCounters
        report.proxyState = DisplayState.label(snapshot.state)
        let occupancy = capacityOccupancy(now: now)
        // The current run can be smaller than the startup limit after a
        // rapid restart. The report names the limit that is in force.
        let limits = capacity.effectiveLimits
        report.sessionLimit = limits?.total
        report.relayLimit = limits?.relay
        report.setupReserve = limits?.setupReserve
        report.setupSessions = occupancy.setupCount
        report.relaySessions = occupancy.relayCount
        report.unconfirmedCloses = capacity.unconfirmedCloses(now: now)
        snapshot.diagnostics = report
    }
}

enum ConnectReport {
    case started
    /// The final result of one attempt. The line names the kind and the result
    /// in plain words, with no destination. `duration` is the time from the
    /// first connection start. `retry` holds the wait and retry counts.
    /// `family` is the destination family for the diagnostics.
    case finished(ConnectConclusion, String?, TimeInterval, ConnectRetryPolicy.Totals,
                  ConnectTargetFamily)
    /// The session closed before the attempt had a result. This is not a failure.
    case closedBeforeResult(ConnectRetryPolicy.Totals, ConnectTargetFamily)
}

/// Classify the end of one accepted session for Recent activity.
///
/// A presence check passes SOCKS authentication, sends no request byte, and
/// then closes with a clean EOF. It still counts as a session. Its counters and
/// its cleanup stay the same. Only its activity lines are omitted.
///
/// Every other end stays in the activity log: a failed authentication, an
/// invalid greeting, a truncated request, a socket error, and a timeout.
struct SessionPresence: Equatable {
    enum ReceiveEnd: Equatable { case none, cleanEOF, error }
    struct Receive: Equatable {
        let firstRequestByte: Bool
        let end: ReceiveEnd
    }
    enum End: Equatable {
        /// The session only checked the proxy. Omit its activity lines.
        case presenceCheck
        /// The session is a real client or an error. Show its activity lines.
        case session
    }

    private(set) var authenticated = false
    private(set) var requestStarted = false

    /// Record a successful SOCKS authentication.
    mutating func authenticationSucceeded() {
        authenticated = true
    }

    /// Record the first byte of a SOCKS request. It stays set after the first
    /// byte, so a later close can never look like a presence check.
    mutating func noteRequestByte() {
        requestStarted = true
    }

    /// Record data before classifying EOF. An error always takes precedence.
    mutating func receive(hasData: Bool, eof: Bool, failed: Bool) -> Receive {
        let firstRequestByte = authenticated && hasData && !requestStarted
        if authenticated && hasData { noteRequestByte() }
        return Receive(firstRequestByte: firstRequestByte,
                       end: failed ? .error : (eof ? .cleanEOF : .none))
    }

    /// Classify the end of the session. Pass `cleanEOF` as true only when the
    /// socket reported a clean end of stream with no error.
    func end(cleanEOF: Bool) -> End {
        guard cleanEOF, authenticated, !requestStarted else { return .session }
        return .presenceCheck
    }
}

/// The last event of one session, in a form that the server can show.
struct SessionClose {
    let message: String
    /// True only for a successful authentication-only presence check.
    let isPresenceCheck: Bool

    /// The line for Recent activity. A presence check has no line.
    var activityLine: String? {
        isPresenceCheck ? nil : message
    }
}

/// Preserve a clean client EOF across protocol fields and into the relay.
struct HandshakeReadEnd {
    enum Step: Equatable { case complete, readAgain, cleanEOF, error }
    private(set) var clientEOF = false
    var shouldReadClient: Bool { !clientEOF }

    mutating func receive(complete: Bool, end: SessionPresence.ReceiveEnd) -> Step {
        if end == .error { return .error }
        if end == .cleanEOF { clientEOF = true }
        if complete { return .complete }
        return clientEOF ? .cleanEOF : .readAgain
    }
}

private final class ProxySession {
    private static let echoLimitLock = NSLock()
    private static var persistentEchoCount = 0
    private static let maximumPersistentEchoSessions = 16
    private let id: UUID
    private let client: NWConnection
    private var outbound: NWConnection?
    /// The clean EOF state of the TCP relay. The session queue owns it.
    private var relayHalfClose = RelayHalfClose()
    /// Reframe the first ClientHello of the client to destination direction.
    /// Nil is off. A value is released after the first ClientHello.
    private var clientHelloShaper: ClientHelloShaper?
    private let token: [UInt8]
    /// The one serial queue for this session. All socket handlers and all
    /// session state run here.
    private let queue: DispatchQueue
    /// The server queue. A callback returns here before it touches shared state.
    private let controlQueue: DispatchQueue
    private let echoSelector: ExperimentalICMPSelector?
    private let onEchoTiming: (ExperimentalICMPTiming.Sample) -> Void
    private let onConnect: (ConnectReport) -> Void
    private let onAuthentication: (Bool) -> Void
    private let onConnected: () -> Void
    private let onAuthenticatedTraffic: () -> Void
    private let onEstablished: (EstablishedTransport) -> Void
    /// Ask the server for one relay slot. The server queue answers on the
    /// session queue. A refusal means the session must send the SOCKS error
    /// before any success reply.
    private let onRelayAdmission: (Bool, @escaping (Bool) -> Void) -> Void
    private let onDatagramQueue: (Int, Int) -> Void
    private let onClose: (SessionClose) -> Void
    /// The established relay state. The session queue records events. The
    /// server queue takes the one end record. The lock keeps the two queues
    /// apart.
    private let establishedLock = NSLock()
    private var established = EstablishedSessionRecord()
    private var closed = false
    /// True after the server showed "Client connected." for this session.
    /// The session queue owns it, so the line appears at most once.
    private var connectedReported = false
    /// The presence-check classification for this session.
    private var presence = SessionPresence()
    private var handshakeReadEnd = HandshakeReadEnd()
    private var connectAttempt: ConnectAttempt?
    /// True after the attempt has a final result.
    private var connectResolved = false
    /// True after this session asked for a relay slot. One request only.
    private var relayRequested = false
    /// The one final SOCKS reply, success or failure. A late grant cannot
    /// send a success after a failure. Only a failure reply's own deadline
    /// may close the session while the reply is in flight.
    private var finalReply = SessionCapacity.FinalReplyGate()
    /// The retry decision for the current attempt.
    private var connectPolicy = ConnectRetryPolicy()
    private var connectDeadline: DispatchWorkItem?
    private var connectRetryTimer: DispatchWorkItem?
    private var connectTransport: ConnectAttempt.Transport = .tcp
    /// Build a new outbound connection with the same parameters as the first.
    private var connectMaker: (() -> NWConnection)?
    /// Start the relay or the datagram loop on the accepted connection.
    private var connectReady: ((NWConnection) -> Void)?
    /// The connection that waits for the SOCKS reply.
    private var connectConnection: NWConnection?
    private var authenticated = false
    /// The one phase timer of this session. Traffic never schedules another.
    /// The phase rule supplies each delay. The timer constructor value is the
    /// relay idle bound, not a separate close rule.
    private var timeout: DispatchWorkItem?
    private var phaseTimer = SessionIdleTimer(limit: SessionCapacity.relayIdleSeconds)
    /// True while an ICMP echo command owns the session. The echo timers bound
    /// it, so the handshake bound does not close it.
    private var phaseTimerSuspended = false
    /// The one deadline for the final SOCKS reply. A lost send completion must
    /// not hold a setup or relay slot.
    private var replyDeadline: DispatchWorkItem?
    private static let replyDeadlineSeconds: TimeInterval = 5
    private var echoInputTimeout: DispatchWorkItem?
    private var echoTask: ExperimentalICMPEchoTask?
    private var persistentEchoSlot = false
    private var echoLifetime: DispatchWorkItem?
    private let echoReader = ExperimentalICMPFrameReader()
    /// The last traffic time and the phase. The session queue writes both.
    /// The server queue reads one snapshot for a capacity decision. The lock
    /// keeps the two queues apart.
    private let stateLock = NSLock()
    private var lastActivity: TimeInterval = 0
    private var phase = SessionCapacity.PhaseTracker(at: 0)
    /// The last time this session reported traffic to the server.
    private var lastTrafficReport: TimeInterval = 0
    // Consecutive transient UDP errors on the cellular connection (UDP over TCP).
    private var datagramSendErrors = 0
    private var datagramReceiveErrors = 0
    // Datagrams dropped after a transient cellular error. The close message reports them.
    private var datagramSendDropped = 0
    private var datagramReceiveDropped = 0
    // One queue per direction. One writer sends in order, so the reads stay
    // outstanding and do not wait for the previous write.
    private var outboundDatagrams = DatagramQueue()
    private var inboundDatagrams = DatagramQueue()
    private var outboundDatagramWriting = false
    private var inboundDatagramWriting = false
    private var outboundDatagramConnection: NWConnection?

    init(id: UUID, client: NWConnection, token: String, tlsShape: Bool, queue: DispatchQueue,
         controlQueue: DispatchQueue,
         echoSelector: ExperimentalICMPSelector?, onEchoTiming: @escaping (ExperimentalICMPTiming.Sample) -> Void,
         onConnect: @escaping (ConnectReport) -> Void,
         onAuthentication: @escaping (Bool) -> Void,
         onConnected: @escaping () -> Void,
         onAuthenticatedTraffic: @escaping () -> Void,
         onEstablished: @escaping (EstablishedTransport) -> Void,
         onRelayAdmission: @escaping (Bool, @escaping (Bool) -> Void) -> Void,
         onDatagramQueue: @escaping (Int, Int) -> Void,
         onClose: @escaping (SessionClose) -> Void) {
        self.id = id
        self.client = client
        self.token = Array(token.utf8)
        self.clientHelloShaper = tlsShape ? ClientHelloShaper() : nil
        self.queue = queue
        self.controlQueue = controlQueue
        self.echoSelector = echoSelector
        self.onEchoTiming = onEchoTiming
        self.onConnect = onConnect
        self.onAuthentication = onAuthentication
        self.onConnected = onConnected
        self.onAuthenticatedTraffic = onAuthenticatedTraffic
        self.onEstablished = onEstablished
        self.onRelayAdmission = onRelayAdmission
        self.onDatagramQueue = onDatagramQueue
        self.onClose = onClose
        // A new session starts in the handshake phase and is active now, so
        // the capacity rule never sees it as stale before its first traffic.
        let now = ProxySession.clock()
        self.lastActivity = now
        self.phase = SessionCapacity.PhaseTracker(at: now)
    }

    /// The capacity view of this session. Safe to call from the server queue.
    /// The phase and the last activity come from one locked snapshot, so the
    /// server never mixes an old phase with a new timer.
    func capacitySnapshot(now: TimeInterval) -> SessionCapacity.PhaseSession {
        stateLock.lock()
        let tracker = phase
        let idle = max(0, now - lastActivity)
        stateLock.unlock()
        return SessionCapacity.PhaseSession(
            id: id, phase: tracker.phase, phaseSeconds: tracker.phaseSeconds(at: now),
            idleSeconds: idle, protectedFromCapacity: tracker.capacityProtected)
    }

    private func markActivity(_ now: TimeInterval) {
        stateLock.lock()
        lastActivity = now
        stateLock.unlock()
    }

    /// The server calls this. Start the socket work on the session queue.
    func start() {
        queue.async { [weak self] in self?.startOnQueue() }
    }

    private func startOnQueue() {
        guard !closed else { return }
        client.stateUpdateHandler = { [weak self] state in
            guard let self = self else { return }
            switch state {
            case .ready: self.touch(); self.readGreeting()
            case .failed:
                // A failed client socket is a client-side error. It is not a
                // destination failure and not proof of packet loss.
                self.markEstablishedEnd(.clientSocketError)
                self.close("Client disconnected.")
            case .cancelled:
                self.close("Client disconnected.")
            default: break
            }
        }
        touch()
        // A handshake has its own bound. Do not wait for the 300 second relay
        // idle window.
        restartPhaseCheck()
        client.start(queue: queue)
    }

    /// The server calls this. Close on the session queue. The block holds this
    /// session strongly until the close runs, so an eviction or a stop cannot
    /// release the last reference before the sockets close. Pass `force` only
    /// for an explicit stop or listener failure. An eviction keeps a failure
    /// reply that is already in flight.
    func closeOnOwnQueue(_ message: String, force: Bool = false) {
        queue.async { self.close(message, force: force) }
    }

    /// Close this session. Pass `cleanEOF` as true only for a clean end of
    /// stream from the client, with no socket error. A successful
    /// authentication-only session then omits its activity lines.
    ///
    /// `force` is for an explicit stop or eviction. A failure reply in flight
    /// otherwise keeps the session open until its send completion or its
    /// bounded deadline. This stops a late grant from cancelling the one
    /// failure reply.
    func close(_ message: String, cleanEOF: Bool = false, force: Bool = false) {
        guard !closed else { return }
        guard force || !finalReply.defersClose else { return }
        let end = presence.end(cleanEOF: cleanEOF)
        // A presence check shows no line. Any other end is a real client or a
        // real error, so show the connect line once before the close line.
        if end == .session { reportConnected() }
        closed = true
        if authenticated { reportAuthentication(false) }
        if let attempt = connectAttempt, !connectResolved {
            reportConnect(.closedBeforeResult(connectPolicy.totals, attempt.family))
        }
        timeout?.cancel()
        timeout = nil
        phaseTimer.disarm()
        phaseTimerSuspended = false
        replyDeadline?.cancel()
        replyDeadline = nil
        connectDeadline?.cancel()
        connectDeadline = nil
        connectRetryTimer?.cancel()
        connectRetryTimer = nil
        echoInputTimeout?.cancel()
        echoLifetime?.cancel()
        echoTask?.cancel()
        echoTask = nil
        if persistentEchoSlot {
            Self.echoLimitLock.lock()
            Self.persistentEchoCount -= 1
            Self.echoLimitLock.unlock()
            persistentEchoSlot = false
        }
        outboundDatagrams.removeAll()
        inboundDatagrams.removeAll()
        reportDatagramQueue()
        connectMaker = nil
        connectReady = nil
        connectConnection?.cancel()
        connectConnection = nil
        outboundDatagramConnection = nil
        client.cancel()
        outbound?.cancel()
        let closeMessage = datagramSendDropped > 0 || datagramReceiveDropped > 0
            ? "\(message) Cellular errors dropped \(datagramSendDropped) sent and \(datagramReceiveDropped) received datagrams."
            : message
        reportClose(SessionClose(message: closeMessage, isPresenceCheck: end == .presenceCheck))
    }

    // MARK: Server callbacks
    // These run on the session queue. Each one returns to the control queue
    // before it touches shared server state.

    private func reportConnect(_ report: ConnectReport) {
        controlQueue.async { self.onConnect(report) }
    }

    private func reportAuthentication(_ authenticated: Bool) {
        controlQueue.async { self.onAuthentication(authenticated) }
    }

    /// Show "Client connected." once. The session queue owns the flag, and the
    /// connect line always reaches the control queue before the close line.
    private func reportConnected() {
        guard !connectedReported else { return }
        connectedReported = true
        controlQueue.async { self.onConnected() }
    }

    private func reportTraffic() {
        controlQueue.async { self.onAuthenticatedTraffic() }
    }

    /// Record the first payload after the destination answered. A setup
    /// attempt is not an established relay. A destination that only became
    /// ready is not an established relay.
    private func reportPayload(_ transport: EstablishedTransport) {
        establishedLock.lock()
        let started = established.recordPayload(transport)
        establishedLock.unlock()
        guard let started = started else { return }
        controlQueue.async { self.onEstablished(started) }
    }

    /// Keep the first end reason. A later close path does not replace it.
    private func markEstablishedEnd(_ end: EstablishedEnd) {
        establishedLock.lock()
        established.recordEnd(end)
        establishedLock.unlock()
    }

    /// Take the one end record for the diagnostics report. Safe to call from
    /// the server queue. The first caller gets the record. A stop, an eviction,
    /// and an asynchronous close cannot count the same end twice.
    func takeEstablishedEnd(default fallback: EstablishedEnd = .other)
        -> (transport: EstablishedTransport, end: EstablishedEnd)? {
        establishedLock.lock()
        defer { establishedLock.unlock() }
        return established.takeEnd(default: fallback)
    }

    private func reportClose(_ close: SessionClose) {
        controlQueue.async { self.onClose(close) }
    }

    private func reportDatagramQueue() {
        let peak = max(outboundDatagrams.peak, inboundDatagrams.peak)
        let dropped = outboundDatagrams.dropped + inboundDatagrams.dropped
        guard peak > 0 || dropped > 0 else { return }
        controlQueue.async { self.onDatagramQueue(peak, dropped) }
    }

    private func touch() {
        let now = Self.clock()
        markActivity(now)
        // Only traffic from an authenticated session says that the target
        // device is using the proxy now. Report at most once a second.
        if authenticated, now - lastTrafficReport >= 1 {
            lastTrafficReport = now
            reportTraffic()
        }
        // Do not arm a timer for every chunk. One phase timer stays pending.
        // An idle phase reads the last activity when that timer fires.
    }

    /// Read the phase and the timers from one locked value.
    private func phaseSnapshot(now: TimeInterval)
        -> (phase: SessionCapacity.Phase, phaseSeconds: TimeInterval,
            idleSeconds: TimeInterval) {
        stateLock.lock()
        let tracker = phase
        let idle = max(0, now - lastActivity)
        stateLock.unlock()
        return (tracker.phase, tracker.phaseSeconds(at: now), idle)
    }

    /// Move to the connect phase. The full SOCKS request is read.
    private func beginConnecting() {
        let now = Self.clock()
        stateLock.lock()
        let changed = phase.beginConnecting(at: now)
        stateLock.unlock()
        if changed { restartPhaseCheck() }
    }

    /// Move to the open relay phase after the server granted a relay slot.
    /// Return false when the session is not in the connect phase, so the
    /// caller can send an error instead of a success.
    @discardableResult
    private func beginRelay(datagram: Bool) -> Bool {
        let now = Self.clock()
        stateLock.lock()
        let changed = phase.admitRelay(datagram: datagram, at: now)
        stateLock.unlock()
        if changed { restartPhaseCheck() }
        return changed
    }

    /// The server refused the relay slot. The session stays in the connect
    /// phase until it sends the SOCKS error and closes.
    private func denyRelay() {
        let now = Self.clock()
        stateLock.lock()
        phase.denyRelay(at: now)
        stateLock.unlock()
    }

    /// Keep the session out of capacity eviction while its final SOCKS reply
    /// is in flight. A capacity decision can run on the server queue before
    /// the send completion closes the session.
    private func markReplyPending() {
        stateLock.lock()
        phase.beginReply()
        stateLock.unlock()
    }

    /// The success reply left. The relay phase bound now governs the session.
    private func settleReply() {
        stateLock.lock()
        phase.finishReply()
        stateLock.unlock()
    }

    /// Bound the one final SOCKS reply. A lost send completion closes the
    /// session instead of holding a setup or relay slot.
    private func armReplyDeadline(_ message: String) {
        replyDeadline?.cancel()
        let item = DispatchWorkItem { [weak self] in
            guard let self = self, !self.closed else { return }
            // The bounded reply deadline is the only close path that may end
            // a failure reply that is still in flight.
            self.finalReply.settle()
            self.close(message)
        }
        replyDeadline = item
        queue.asyncAfter(deadline: .now() + Self.replyDeadlineSeconds, execute: item)
    }

    private func cancelReplyDeadline() {
        replyDeadline?.cancel()
        replyDeadline = nil
    }

    /// An ICMP echo command owns the session. The echo timers bound it, and
    /// a capacity decision must not close it as a stale handshake.
    private func markControlActive() {
        stateLock.lock()
        phase.beginControl()
        stateLock.unlock()
    }

    /// One direction of a TCP relay ended.
    private func noteRelayHalfClose() {
        let now = Self.clock()
        stateLock.lock()
        let changed = phase.noteHalfClose(at: now)
        stateLock.unlock()
        if changed { restartPhaseCheck() }
    }

    /// Arm or rearm the one phase timer for the current phase.
    private func restartPhaseCheck() {
        guard !closed, !phaseTimerSuspended, !finalReply.defersClose else { return }
        let now = Self.clock()
        let snapshot = phaseSnapshot(now: now)
        switch SessionCapacity.idleAction(phase: snapshot.phase,
                                          phaseSeconds: snapshot.phaseSeconds,
                                          idleSeconds: snapshot.idleSeconds) {
        case .close(let reason):
            phaseCheckClosed(reason)
        case .rearm(let delay):
            armPhaseCheck(after: delay)
        }
    }

    /// Schedule the one pending check. Cancel the old timer first, so the
    /// count stays one.
    private func armPhaseCheck(after delay: TimeInterval) {
        timeout?.cancel()
        phaseTimer.disarm()
        _ = phaseTimer.touch()
        let item = DispatchWorkItem { [weak self] in self?.phaseCheckFired() }
        timeout = item
        queue.asyncAfter(deadline: .now() + max(0, delay), execute: item)
    }

    /// The one phase timer fired. Compare the current phase and activity with
    /// the phase bound. An open TCP relay always rearms and never closes for
    /// silence.
    private func phaseCheckFired() {
        guard !closed, !phaseTimerSuspended, !finalReply.defersClose else { return }
        timeout = nil
        let now = Self.clock()
        let snapshot = phaseSnapshot(now: now)
        switch phaseTimer.fired(phase: snapshot.phase,
                                phaseSeconds: snapshot.phaseSeconds,
                                idleSeconds: snapshot.idleSeconds) {
        case .close(let reason):
            phaseCheckClosed(reason)
        case .rearm(let delay):
            armPhaseCheck(after: delay)
        }
    }

    /// Close for one phase bound. A connect that misses its deadline sends the
    /// SOCKS error first. A UDP or half-closed flow records an idle end.
    private func phaseCheckClosed(_ reason: SessionCapacity.CloseReason) {
        switch reason {
        case .handshakeExpired:
            close("Client timed out during the handshake.")
        case .connectExpired:
            sendFailure(1, message: "Destination connection timed out.")
        case .relayGrantExpired:
            // The server did not answer the relay request in its own bound.
            // The session has not sent a success reply, so it sends an error.
            sendFailure(1, message: "Relay slot decision timed out.")
        case .udpIdle:
            markEstablishedEnd(.idle)
            close("UDP flow timed out.")
        case .halfClosedIdle:
            markEstablishedEnd(.idle)
            close("Half-closed session timed out.")
        }
    }

    /// Stop the phase timer for an ICMP echo command. The echo deadlines bound
    /// the session. An echo command is not a relay phase.
    private func suspendPhaseCheck() {
        phaseTimerSuspended = true
        timeout?.cancel()
        timeout = nil
        phaseTimer.disarm()
    }

    /// Start the one relay request. The server queue decides. A refusal sends
    /// the SOCKS error before any success reply.
    private func requestRelaySlot(datagram: Bool) {
        guard !closed, !relayRequested, !finalReply.started else { return }
        relayRequested = true
        let now = Self.clock()
        stateLock.lock()
        let requested = phase.beginAwaitingRelay(at: now)
        stateLock.unlock()
        guard requested else {
            sendFailure(1, message: "SOCKS request failed (1).")
            return
        }
        // The relay request has its own bound. The old connect bound ended
        // when the request became complete. The server normally answers on
        // its next queue turn, so this bound is only a safety net.
        restartPhaseCheck()
        guard !closed, !finalReply.started else { return }
        onRelayAdmission(datagram) { [weak self] granted in
            guard let self = self else { return }
            self.queue.async {
                // A queued grant can drain after the relay wait bound sent its
                // one failure reply. Do not start a second one.
                guard !self.closed, !self.finalReply.started else { return }
                if granted {
                    guard self.beginRelay(datagram: datagram) else {
                        self.sendFailure(1, message: "SOCKS request failed (1).")
                        return
                    }
                    self.sendSuccess()
                } else {
                    self.denyRelay()
                    self.sendFailure(1,
                                     message: "Session limit reached. The request was refused.")
                }
            }
        }
    }

    /// Send the one SOCKS success reply and start the relay.
    private func sendSuccess() {
        guard !finalReply.started else { return }
        guard let connection = connectConnection else {
            sendFailure(1, message: "SOCKS request failed (1).")
            return
        }
        guard finalReply.begin(.success) else { return }
        markReplyPending()
        armReplyDeadline("Client send timed out.")
        send([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]) { [weak self] in
            guard let self = self else { return }
            self.finalReply.settle()
            self.cancelReplyDeadline()
            self.settleReply()
            self.connectReady?(connection)
        }
    }

    /// Send one SOCKS error reply, then close. The session never sends a
    /// success reply after this call.
    ///
    /// A second failure path must not close the session. The one failure
    /// reply has its own bounded deadline. Its send completion or that
    /// deadline closes the session.
    private func sendFailure(_ code: UInt8, message: String) {
        guard !closed else { return }
        guard finalReply.begin(.failure) else {
            if !finalReply.failureInFlight {
                // A success reply already left. The relay owns the session, so
                // a later destination end closes it normally.
                close(message)
            }
            return
        }
        markReplyPending()
        // The session is closing. Stop the phase timer so it cannot cancel the
        // error reply before the send completion runs.
        timeout?.cancel()
        timeout = nil
        phaseTimer.disarm()
        armReplyDeadline(message)
        client.send(content: Data([5, code, 0, 1, 0, 0, 0, 0, 0, 0]),
                    completion: .contentProcessed { [weak self] error in
            guard let self = self else { return }
            self.finalReply.settle()
            self.cancelReplyDeadline()
            guard !self.closed else { return }
            if error != nil {
                self.markEstablishedEnd(.clientSocketError)
                self.close("Client send failed.")
                return
            }
            self.touch()
            self.close(message)
        })
    }

    // Read no more than the current protocol field. This preserves later bytes.
    private func read(_ count: Int, completion: @escaping ([UInt8]) -> Void) {
        guard !closed else { return }
        guard count > 0 else { completion([]); return }
        guard handshakeReadEnd.shouldReadClient else {
            close("Client disconnected.", cleanEOF: true)
            return
        }
        var bytes: [UInt8] = []
        func receiveMore() {
            client.receive(minimumIncompleteLength: 1, maximumLength: count - bytes.count) { [weak self] data, _, eof, error in
                guard let self = self, !self.closed else { return }
                let event = self.presence.receive(hasData: !(data?.isEmpty ?? true), eof: eof, failed: error != nil)
                if event.firstRequestByte { self.reportConnected() }
                if let data = data, !data.isEmpty {
                    // Any byte after a successful authentication belongs to a
                    // real request. The session is then never a presence
                    // check, even if it closes before the request completes.
                    bytes.append(contentsOf: data)
                    self.touch()
                }
                switch self.handshakeReadEnd.receive(complete: bytes.count == count, end: event.end) {
                case .error:
                    self.close("Client disconnected during handshake.")
                case .cleanEOF:
                    // A clean end of stream with no request byte after a
                    // successful authentication is a presence check.
                    self.close("Client disconnected during handshake.", cleanEOF: true)
                case .complete:
                    completion(bytes)
                case .readAgain:
                    receiveMore()
                }
            }
        }
        receiveMore()
    }

    private func send(_ bytes: [UInt8], completion: @escaping () -> Void) {
        guard !closed else { return }
        client.send(content: Data(bytes), completion: .contentProcessed { [weak self] error in
            guard let self = self, !self.closed else { return }
            if error != nil {
                self.markEstablishedEnd(.clientSocketError)
                // A failed final send must close. Clear the in-flight flag so
                // the close is not deferred to the reply deadline.
                self.finalReply.settle()
                self.close("Client send failed.")
                return
            }
            self.touch()
            completion()
        })
    }

    private func readGreeting() {
        read(2) { [weak self] header in
            guard let self = self else { return }
            guard header[0] == 5, header[1] > 0 else { self.close("Invalid SOCKS greeting."); return }
            self.read(Int(header[1])) { methods in
                guard methods.contains(2) else {
                    self.send([5, 255]) { self.close("Client did not offer password authentication.") }
                    return
                }
                self.send([5, 2]) { self.readAuth() }
            }
        }
    }

    private func readAuth() {
        read(2) { [weak self] header in
            guard let self = self else { return }
            guard header[0] == 1, header[1] > 0 else { self.close("Invalid authentication request."); return }
            self.read(Int(header[1])) { username in
                self.read(1) { length in
                    guard length[0] > 0 else { self.send([1, 1]) { self.close("Authentication failed.") }; return }
                    self.read(Int(length[0])) { password in
                        // Compare both fields in constant time. Do not stop
                        // after the user name, and do not compare the token
                        // with an early-return equality.
                        let userValid = constantTimeEquals(
                            username, Array(ProxyProtocol.socksUsername.utf8))
                        let tokenValid = constantTimeEquals(password, self.token)
                        let valid = userValid && tokenValid
                        self.send([1, valid ? 0 : 1]) {
                            if valid {
                                self.authenticated = true
                                self.presence.authenticationSucceeded()
                                self.reportAuthentication(true)
                                self.readRequest()
                            } else {
                                self.close("Authentication failed.")
                            }
                        }
                    }
                }
            }
        }
    }

    private func readRequest() {
        read(4) { [weak self] header in
            guard let self = self else { return }
            guard header[0] == 5, header[2] == 0 else { self.close("Invalid SOCKS request."); return }
            guard self.authenticated else { self.close("Authentication required."); return }
            if ExperimentalICMPCommand.isPermitted(command: header[1], authenticated: self.authenticated) {
                switch header[3] {
                case 1: self.readEchoAddress(length: 4, type: 1, persistent: header[1] == ExperimentalICMPCommand.persistentCommand)
                case 4: self.readEchoAddress(length: 16, type: 4, persistent: header[1] == ExperimentalICMPCommand.persistentCommand)
                default: self.replyFailure(8)
                }
                return
            }
            guard header[1] == 1 || header[1] == 0x80 else { self.replyFailure(7); return }
            let datagram = header[1] == 0x80
            switch header[3] {
            case 1: self.readAddress(length: 4, type: 1, datagram: datagram)
            case 4: self.readAddress(length: 16, type: 4, datagram: datagram)
            case 3:
                self.read(1) { length in
                    guard length[0] > 0 else { self.replyFailure(8); return }
                    self.readAddress(length: Int(length[0]), type: 3, datagram: datagram)
                }
            default: self.replyFailure(8)
            }
        }
    }

    // Echo commands require a numeric unicast target and port zero.
    private func readEchoAddress(length: Int, type: UInt8, persistent: Bool) {
        read(length) { [weak self] address in
            guard let self = self else { return }
            self.read(2) { portBytes in
                let port = UInt16(portBytes[0]) << 8 | UInt16(portBytes[1])
                guard let target = try? ExperimentalICMPCommand.target(type: type, address: address, port: port) else {
                    self.replyFailure(8)
                    return
                }
                if persistent {
                    Self.echoLimitLock.lock()
                    let available = Self.persistentEchoCount < Self.maximumPersistentEchoSessions
                    if available { Self.persistentEchoCount += 1; self.persistentEchoSlot = true }
                    Self.echoLimitLock.unlock()
                    guard available else { self.replyFailure(1); return }
                }
                // The echo command is not a relay. Its own request, idle, and
                // lifetime timers bound it, so stop the handshake bound. Set
                // the capacity protection first, so the server never sees an
                // unprotected stale handshake.
                self.markControlActive()
                self.suspendPhaseCheck()
                guard self.finalReply.begin(.success) else { return }
                self.armReplyDeadline("Echo response timed out.")
                self.send([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]) {
                    self.finalReply.settle()
                    self.cancelReplyDeadline()
                    if persistent { self.startPersistentEcho(target: target) }
                    else { self.readEchoPayload(target: target) }
                }
            }
        }
    }

    private func resetEchoIdleTimeout() {
        echoInputTimeout?.cancel()
        let item = DispatchWorkItem { [weak self] in self?.close("Echo session timed out.") }
        echoInputTimeout = item
        queue.asyncAfter(deadline: .now() + 30, execute: item)
    }

    private func startPersistentEcho(target: ExperimentalICMPCommand.Target) {
        let item = DispatchWorkItem { [weak self] in self?.close("Echo session expired.") }
        echoLifetime = item
        queue.asyncAfter(deadline: .now() + 300, execute: item)
        resetEchoIdleTimeout()
        receivePersistentEcho(target: target)
    }

    // Keep one receive pending during each probe to detect EOF and extra data.
    private func receivePersistentEcho(target: ExperimentalICMPCommand.Target) {
        guard !closed else { return }
        guard !handshakeReadEnd.clientEOF else { close("Echo client disconnected."); return }
        client.receive(minimumIncompleteLength: 1, maximumLength: ExperimentalICMPCommand.maximumPayload + 3) { [weak self] data, _, eof, error in
            guard let self = self, !self.closed else { return }
            // Treat a write-half close as a disconnect, even with final data.
            guard !ExperimentalICMPCommand.persistentShouldClose(eof: eof, failed: error != nil) else {
                self.close("Echo client disconnected.")
                return
            }
            if let data = data, !data.isEmpty {
                self.handlePersistentEcho(self.echoReader.receive(data), target: target)
            }
            self.receivePersistentEcho(target: target)
        }
    }

    private func handlePersistentEcho(_ result: ExperimentalICMPFrameReader.Result,
                                      target: ExperimentalICMPCommand.Target) {
        guard !closed else { return }
        switch result {
        case .invalid:
            close("Invalid echo frame.")
        case .pending:
            break
        case .frame(let payload):
            resetEchoIdleTimeout()
            // The echo selector and its tasks run on the server queue, because
            // they share the selector cache. The completion returns to this
            // session queue.
            let task = ExperimentalICMPEchoTask(queue: controlQueue, selector: echoSelector, onTiming: onEchoTiming)
            echoTask = task
            task.start(target: target, payload: payload) { [weak self] status, reply in
                guard let self = self else { return }
                self.queue.async {
                    guard !self.closed else { return }
                    self.echoTask = nil
                    guard let frame = try? ExperimentalICMPCommand.response(status: status, payload: reply) else {
                        self.close("Echo response failed.")
                        return
                    }
                    self.echoReader.responsePending()
                    self.send(Array(frame)) {
                        guard status == .success else { self.close("Echo request failed."); return }
                        let next = self.echoReader.finish()
                        self.resetEchoIdleTimeout()
                        self.handlePersistentEcho(next, target: target)
                    }
                }
            }
        }
    }

    private func readEchoPayload(target: ExperimentalICMPCommand.Target) {
        let timeout = DispatchWorkItem { [weak self] in self?.close("Echo request timed out.") }
        echoInputTimeout = timeout
        queue.asyncAfter(deadline: .now() + 5, execute: timeout)
        read(2) { [weak self] header in
            guard let self = self else { return }
            guard let length = try? ExperimentalICMPCommand.payloadLength(header) else {
                self.sendEchoResponse(status: .failed, payload: Data())
                return
            }
            self.read(length) { [weak self] bytes in
                guard let self = self else { return }
                self.echoInputTimeout?.cancel()
                self.echoInputTimeout = nil
                // The echo selector runs on the server queue. The completion
                // returns to this session queue.
                let task = ExperimentalICMPEchoTask(queue: self.controlQueue, selector: self.echoSelector)
                self.echoTask = task
                // A client that finished writing can still receive the reply.
                if self.handshakeReadEnd.shouldReadClient { self.watchEchoClient() }
                task.start(target: target, payload: Data(bytes)) { [weak self] status, payload in
                    guard let self = self else { return }
                    self.queue.async {
                        guard !self.closed else { return }
                        self.sendEchoResponse(status: status, payload: payload)
                    }
                }
            }
        }
    }

    // The echo command has no further client data. Keep a receive pending so
    // a disconnect or an extra frame cancels a queued or active echo.
    private func watchEchoClient() {
        guard !closed else { return }
        client.receive(minimumIncompleteLength: 1, maximumLength: 1) { [weak self] data, _, eof, error in
            guard let self = self, !self.closed else { return }
            if ExperimentalICMPCommand.shouldCancel(clientDataCount: data?.count ?? 0,
                                                    eof: eof, failed: error != nil) {
                self.close("Echo client disconnected or sent extra data.")
            } else {
                self.watchEchoClient()
            }
        }
    }

    private func sendEchoResponse(status: ExperimentalICMPCommand.Status, payload: Data) {
        guard let frame = try? ExperimentalICMPCommand.response(status: status, payload: payload) else {
            close("Echo response failed.")
            return
        }
        echoInputTimeout?.cancel()
        echoInputTimeout = nil
        send(Array(frame)) { self.close("Echo request finished.") }
    }

    private func readAddress(length: Int, type: UInt8, datagram: Bool) {
        read(length) { [weak self] address in
            guard let self = self else { return }
            self.read(2) { portBytes in
                let port = UInt16(portBytes[0]) << 8 | UInt16(portBytes[1])
                guard let endpointPort = NWEndpoint.Port(rawValue: port), port != 0 else { self.replyFailure(1); return }
                let host: String
                if type == 3 {
                    guard let name = String(bytes: address, encoding: .utf8), !name.isEmpty, !name.contains("\0") else { self.replyFailure(8); return }
                    host = name
                } else {
                    var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                    let family = type == 1 ? AF_INET : AF_INET6
                    let converted = address.withUnsafeBytes { ptr in inet_ntop(family, ptr.baseAddress, &buffer, socklen_t(buffer.count)) }
                    guard converted != nil else { self.replyFailure(8); return }
                    host = String(cString: buffer)
                }
                if datagram { self.connectDatagram(host: host, port: endpointPort) }
                else { self.connect(host: host, port: endpointPort) }
            }
        }
    }

    // Command 0x80 carries one UDP flow in length-prefixed TCP frames.
    // Build the connection from the same parameters on a retry. Never select
    // another interface.
    private func connectDatagram(host: String, port: NWEndpoint.Port) {
        beginConnecting()
        let maker = {
            let parameters = makeOutboundUDPParameters()
            return NWConnection(host: NWEndpoint.Host(host), port: port, using: parameters)
        }
        watchConnect(maker: maker, transport: .udp, host: host, port: port) { [weak self] connection in
            guard let self = self else { return }
            self.readDatagramFrames(to: connection)
            self.receiveDatagram(from: connection)
        }
    }

    // Keep one read pending for the next frame. The read does not wait for the
    // writer. The queue drops the oldest datagram when it is full, and the
    // session counts it.
    private func readDatagramFrames(to destination: NWConnection) {
        read(2) { [weak self] header in
            guard let self = self else { return }
            let length = Int(header[0]) * 256 + Int(header[1])
            guard length <= 1472 else { self.close("UDP datagram is too large."); return }
            self.read(length) { [weak self] bytes in
                guard let self = self, !self.closed else { return }
                self.reportPayload(.udp)
                self.outboundDatagramConnection = destination
                self.outboundDatagrams.push(Data(bytes))
                self.touch()
                self.pumpOutboundDatagrams()
                self.readDatagramFrames(to: destination)
            }
        }
    }

    // One writer sends the outbound datagrams in order.
    private func pumpOutboundDatagrams() {
        guard !closed, !outboundDatagramWriting,
              let destination = outboundDatagramConnection,
              let next = outboundDatagrams.pop() else { return }
        outboundDatagramWriting = true
        destination.send(content: next, contentContext: .defaultMessage, isComplete: true,
                         completion: .contentProcessed { [weak self] error in
            guard let self = self, !self.closed else { return }
            self.outboundDatagramWriting = false
            if let error = error {
                // A transient error affects one datagram. Drop it and keep the flow.
                self.datagramSendErrors += 1
                self.datagramSendDropped += 1
                guard TransientNetworkErrors.isTransient(error),
                      self.datagramSendErrors < TransientNetworkErrors.consecutiveLimit
                else {
                    self.markEstablishedEnd(.destinationSocketError)
                    self.close("UDP send failed.")
                    return
                }
            } else {
                self.datagramSendErrors = 0
                self.touch()
            }
            self.pumpOutboundDatagrams()
        })
    }

    // Keep one receive pending, so a read does not wait for the writer.
    private func receiveDatagram(from source: NWConnection) {
        source.receiveMessage { [weak self] data, _, _, error in
            guard let self = self, !self.closed else { return }
            if let error = error {
                self.datagramReceiveErrors += 1
                self.datagramReceiveDropped += 1
                guard TransientNetworkErrors.isTransient(error),
                      self.datagramReceiveErrors < TransientNetworkErrors.consecutiveLimit
                else {
                    self.markEstablishedEnd(.destinationSocketError)
                    self.close("UDP receive failed.")
                    return
                }
                self.receiveDatagram(from: source); return
            }
            self.datagramReceiveErrors = 0
            guard let data = data else { self.receiveDatagram(from: source); return }
            guard data.count <= 1472 else { self.close("UDP reply is too large."); return }
            self.reportPayload(.udp)
            self.inboundDatagrams.push(Data(data))
            self.touch()
            self.pumpInboundDatagrams()
            self.receiveDatagram(from: source)
        }
    }

    // One writer sends the replies to the target device in order.
    private func pumpInboundDatagrams() {
        guard !closed, !inboundDatagramWriting, let next = inboundDatagrams.pop() else { return }
        inboundDatagramWriting = true
        let length = next.count
        send([UInt8(length >> 8), UInt8(length & 255)] + Array(next)) {
            self.inboundDatagramWriting = false
            self.pumpInboundDatagrams()
        }
    }

    private func connect(host: String, port: NWEndpoint.Port) {
        beginConnecting()
        let maker = {
            let parameters = makeOutboundTCPParameters()
            return NWConnection(host: NWEndpoint.Host(host), port: port, using: parameters)
        }
        watchConnect(maker: maker, transport: .tcp, host: host, port: port) { [weak self] connection in
            guard let self = self else { return }
            self.relayHalfClose = RelayHalfClose()
            // The port is the last field of a TCP request. A recorded EOF
            // therefore belongs to the relay's client read side.
            if !self.handshakeReadEnd.shouldReadClient {
                _ = self.relayHalfClose.receive(hasData: false, eof: true, side: .client)
                // The half-close event starts the half-closed idle window.
                self.touch()
                self.noteRelayHalfClose()
                self.finishWrite(to: connection, side: .destination)
            } else {
                self.relay(from: self.client, to: connection, side: .client)
            }
            self.relay(from: connection, to: self.client, side: .destination)
        }
    }

    /// A monotonic clock in seconds.
    static func clock() -> TimeInterval { ProcessInfo.processInfo.systemUptime }

    // Start the outbound connection with a deadline. The SOCKS reply goes out
    // exactly once: success when the connection is ready, failure when it
    // fails or is not ready by the deadline. `onReady` runs after the success
    // reply. A waiting state retries once with the same parameters.
    private func watchConnect(maker: @escaping () -> NWConnection, transport: ConnectAttempt.Transport,
                              host: String, port: NWEndpoint.Port,
                              onReady: @escaping (NWConnection) -> Void) {
        guard !closed else { return }
        connectAttempt = ConnectAttempt(transport: transport, host: host, port: port.rawValue,
                                        startedAt: Self.clock())
        connectPolicy = ConnectRetryPolicy()
        connectTransport = transport
        connectResolved = false
        connectMaker = maker
        connectReady = onReady
        reportConnect(.started)
        let deadline = DispatchWorkItem { [weak self] in self?.connectEvent(.deadline) }
        connectDeadline = deadline
        queue.asyncAfter(deadline: .now() + ConnectAttempt.deadlineSeconds, execute: deadline)
        openOutbound()
    }

    /// Open one outbound connection with the stored parameters. A retry makes
    /// a fresh connection with the same host, port, and cellular pin.
    private func openOutbound() {
        guard !closed, let maker = connectMaker else { return }
        let previous = outbound
        previous?.stateUpdateHandler = nil
        previous?.cancel()
        let connection = maker()
        outbound = connection
        connectConnection = connection
        connection.stateUpdateHandler = { [weak self, weak connection] state in
            guard let self = self, let connection = connection,
                  connection === self.outbound else { return }
            switch state {
            case .waiting(let error): self.connectEvent(.waiting(Self.failure(error)))
            case .ready: self.connectEvent(.ready)
            case .failed(let error): self.connectEvent(.failed(Self.failure(error)))
            case .cancelled: self.connectEvent(.cancelled)
            default: break
            }
        }
        connection.start(queue: queue)
    }

    private func scheduleConnectRetry() {
        connectRetryTimer?.cancel()
        let item = DispatchWorkItem { [weak self] in
            self?.connectRetryTimer = nil
            self?.connectEvent(.retryDue)
        }
        connectRetryTimer = item
        queue.asyncAfter(deadline: .now() + ConnectRetryPolicy.retryDelay, execute: item)
    }

    private func connectEvent(_ event: ConnectRetryPolicy.Event) {
        guard !closed, var attempt = connectAttempt else { return }
        // A replied attempt only needs the close decision. The retry policy is
        // done, so it does not see these events.
        if connectResolved {
            guard let attemptEvent = Self.attemptEvent(event) else { return }
            let result = attempt.handle(attemptEvent, now: Self.clock())
            connectAttempt = attempt
            apply(result, event: attemptEvent)
            return
        }

        var policy = connectPolicy
        let action = policy.handle(event)
        connectPolicy = policy

        if case .waiting(let failure) = event {
            _ = attempt.handle(.waiting(failure), now: Self.clock())
            connectAttempt = attempt
            if action == .waitForRetry { scheduleConnectRetry() }
            return
        }
        switch action {
        case .retry:
            // The old connection may have reported a wait. The new connection
            // has its own state, so a later deadline must not inherit it.
            attempt.retryStarted()
            connectAttempt = attempt
            openOutbound()
        case .waitForRetry:
            scheduleConnectRetry()
        case .none:
            break
        case .finish:
            guard let attemptEvent = Self.attemptEvent(event) else { return }
            let result = attempt.handle(attemptEvent, now: Self.clock())
            connectAttempt = attempt
            if result.conclusion != nil {
                connectResolved = true
                connectDeadline?.cancel()
                connectDeadline = nil
                connectRetryTimer?.cancel()
                connectRetryTimer = nil
                let duration = max(0, Self.clock() - attempt.startedAt)
                reportConnect(.finished(result.conclusion!, result.log, duration,
                                       policy.totals, attempt.family))
            }
            apply(result, event: attemptEvent)
        }
    }

    private static func attemptEvent(_ event: ConnectRetryPolicy.Event) -> ConnectAttempt.Event? {
        switch event {
        case .ready: return .ready
        case .failed(let failure): return .failed(failure)
        case .cancelled: return .cancelled
        case .deadline: return .deadline
        case .waiting(let failure): return .waiting(failure)
        case .retryDue: return nil
        }
    }

    private func apply(_ result: ConnectAttempt.Result, event: ConnectAttempt.Event) {
        switch result.decision {
        case .none:
            break
        case .replySuccess:
            // The destination answered. Ask the server for one relay slot
            // before the SOCKS success reply. A refusal sends an error instead.
            requestRelaySlot(datagram: connectTransport == .udp)
        case .replyFailure(let code):
            connectConnection?.cancel()
            replyFailure(code)
        case .close:
            let failed: Bool
            if case .failed = event { failed = true } else { failed = false }
            if failed { markEstablishedEnd(.destinationSocketError) }
            let message: String
            switch connectTransport {
            case .tcp:
                message = failed ? "Destination connection failed."
                                 : "Destination connection closed."
            case .udp:
                message = failed ? "UDP destination failed." : "UDP destination closed."
            }
            if !finalReply.started {
                // The destination ended after it reported ready but before the
                // relay slot and the success reply. Send the one SOCKS error.
                sendFailure(1, message: message)
            } else {
                close(message)
            }
        }
    }

    private static func failure(_ error: NWError) -> ConnectAttempt.Failure {
        switch error {
        case .posix(let code):
            return ConnectAttempt.Failure(errno: code.rawValue, description: String(cString: strerror(code.rawValue)))
        case .dns(let code):
            return ConnectAttempt.Failure(errno: nil, description: "DNS error \(code)")
        default:
            return ConnectAttempt.Failure(errno: nil, description: error.localizedDescription)
        }
    }

    private func replyFailure(_ code: UInt8) {
        sendFailure(code, message: "SOCKS request failed (\(code)).")
    }

    // One receive runs in each direction. A clean EOF forwards the final data
    // first and then sends a write-side FIN to the other connection. The FIN
    // does not close the read side. The opposite direction stays open until it
    // also finishes. An error, a phase bound, or a stop closes both connections
    // at once.
    private func relay(from source: NWConnection, to destination: NWConnection,
                       side: RelayHalfClose.Side) {
        guard !closed, !relayHalfClose.isReadFinished(side) else { return }
        source.receive(minimumIncompleteLength: 1, maximumLength: 16384) { [weak self] data, _, eof, error in
            guard let self = self, !self.closed else { return }
            if error != nil {
                self.markEstablishedEnd(side.socketErrorEnd)
                self.close("Relay failed.")
                return
            }
            let hasData = data?.isEmpty == false
            if hasData { self.reportPayload(.tcp) }
            switch self.relayHalfClose.receive(hasData: hasData, eof: eof, side: side) {
            case .ignore:
                // The guard above makes this unreachable for an active read.
                return
            case .readAgain:
                self.relay(from: source, to: destination, side: side)
            case .forward:
                self.touch()
                self.forward(data ?? Data(), to: destination, side: side) { [weak self] in
                    self?.relay(from: source, to: destination, side: side)
                }
            case .forwardThenFinish:
                // The half-close event starts the half-closed idle window.
                // Record it before the phase change, so a long idle open relay
                // does not close before it forwards the final data.
                self.touch()
                self.noteRelayHalfClose()
                self.forward(data ?? Data(), to: destination, side: side) { [weak self] in
                    self?.flushShaper(to: destination, side: side) { [weak self] in
                        self?.finishWrite(to: destination, side: side.other)
                    }
                }
            case .finish:
                self.touch()
                self.noteRelayHalfClose()
                self.flushShaper(to: destination, side: side) { [weak self] in
                    self?.finishWrite(to: destination, side: side.other)
                }
            }
        }
    }

    // Send one piece of data. The completion runs after the stack processed it.
    // Only the client to destination direction is shaped. The destination to
    // client bytes are never rewritten.
    private func forward(_ data: Data, to destination: NWConnection,
                         side: RelayHalfClose.Side,
                         completion: @escaping () -> Void) {
        if side == .client, var shaper = clientHelloShaper, shaper.isBuffering {
            let chunks = shaper.feed(data)
            clientHelloShaper = shaper.isBuffering ? shaper : nil
            sendShaped(chunks, at: 0, to: destination, side: side, completion: completion)
            return
        }
        destination.send(content: data, completion: .contentProcessed { [weak self] error in
            guard let self = self, !self.closed else { return }
            if error != nil {
                self.markEstablishedEnd(side.other.socketErrorEnd)
                self.close("Relay failed.")
                return
            }
            self.touch()
            completion()
        })
    }

    // Release any bytes the shaper still holds when the client half-closes.
    // They left in order and unchanged, once, before the FIN. Only the client
    // to destination direction has a shaper.
    private func flushShaper(to destination: NWConnection, side: RelayHalfClose.Side,
                             completion: @escaping () -> Void) {
        guard side == .client, var shaper = clientHelloShaper else {
            completion()
            return
        }
        clientHelloShaper = nil
        sendShaped(shaper.finish(), at: 0, to: destination, side: side,
                   completion: completion)
    }

    // Send the shaped pieces in order. One send completion starts the next, so
    // a busy destination socket applies backpressure.
    private func sendShaped(_ chunks: [Data], at index: Int, to destination: NWConnection,
                            side: RelayHalfClose.Side,
                            completion: @escaping () -> Void) {
        guard index < chunks.count else {
            completion()
            return
        }
        destination.send(content: chunks[index], completion: .contentProcessed { [weak self] error in
            guard let self = self, !self.closed else { return }
            if error != nil {
                self.markEstablishedEnd(side.other.socketErrorEnd)
                self.close("Relay failed.")
                return
            }
            self.touch()
            self.sendShaped(chunks, at: index + 1, to: destination, side: side,
                            completion: completion)
        })
    }

    // Finish the write side of `connection`. A nil content with the final
    // message context sends a FIN and leaves the read side open. Close the
    // session only after both sides sent a clean EOF and both FINs left the
    // stack. `side` is the side of `connection`, so a failed write is an error
    // on that side.
    private func finishWrite(to connection: NWConnection, side: RelayHalfClose.Side) {
        connection.send(content: nil, contentContext: .finalMessage, isComplete: true,
                        completion: .contentProcessed { [weak self] error in
            guard let self = self, !self.closed else { return }
            if error != nil {
                self.markEstablishedEnd(side.socketErrorEnd)
                self.close("Relay failed.")
                return
            }
            self.touch()
            self.relayHalfClose.writeFinished(side)
            guard self.relayHalfClose.canClose else { return }
            self.markEstablishedEnd(.clean)
            self.close("Client disconnected.")
        })
    }
}
