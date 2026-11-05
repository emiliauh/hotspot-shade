import Foundation

// Decode one optional field. A field with an unexpected type becomes nil.
// This keeps one bad field from failing the whole status decode.
func decodeField<K: CodingKey, T: Decodable>(_ container: KeyedDecodingContainer<K>?, _ key: K, as type: T.Type) -> T? {
    guard let container, let value = try? container.decodeIfPresent(T.self, forKey: key) else { return nil }
    return value
}

// The source device state from the engine. An unknown string is a safe case.
// It keeps the raw message visible instead of failing the decode.
public enum PhoneState: Equatable {
    case noHotspot, notRunning, notResponding, proxyOff, ready, connected, unpaired, notTrusted, unknown
    public init(raw: String?) {
        switch raw {
        case "no_hotspot": self = .noHotspot
        case "not_running": self = .notRunning
        case "not_responding": self = .notResponding
        case "proxy_off": self = .proxyOff
        case "ready": self = .ready
        case "connected": self = .connected
        case "unpaired": self = .unpaired
        case "not_trusted": self = .notTrusted
        default: self = .unknown
        }
    }
}
public struct Phone: Codable, Equatable {
    public var state: String?; public var message: String?; public var portChanged: Bool?; public var connections: Int?
    // The engine adds these fields. An older engine sends neither.
    public var checkedAt: Double?; public var trustedBySource: Bool?
    public init(state: String? = nil, message: String? = nil, portChanged: Bool? = nil, connections: Int? = nil, checkedAt: Double? = nil, trustedBySource: Bool? = nil) {
        self.state = state; self.message = message; self.portChanged = portChanged; self.connections = connections
        self.checkedAt = checkedAt; self.trustedBySource = trustedBySource
    }
    enum CodingKeys: String, CodingKey { case state, message, portChanged = "port_changed", connections, checkedAt = "checked_at", trustedBySource = "trusted_by_source" }
    public init(from decoder: Decoder) throws {
        let container = try? decoder.container(keyedBy: CodingKeys.self)
        state = decodeField(container, .state, as: String.self)
        message = decodeField(container, .message, as: String.self)
        portChanged = decodeField(container, .portChanged, as: Bool.self)
        connections = decodeField(container, .connections, as: Int.self)
        checkedAt = decodeField(container, .checkedAt, as: Double.self)
        trustedBySource = decodeField(container, .trustedBySource, as: Bool.self)
    }
}
public struct LogLine: Codable, Identifiable {
    public var seq: Int?; public var level: String?; public var msg: String?; public var ts: Double?
    public var id: Int { seq ?? 0 }
    public init(seq: Int? = nil, level: String? = nil, msg: String? = nil, ts: Double? = nil) { self.seq = seq; self.level = level; self.msg = msg; self.ts = ts }
    enum CodingKeys: String, CodingKey { case seq, level, msg, ts }
    public init(from decoder: Decoder) throws {
        let container = try? decoder.container(keyedBy: CodingKeys.self)
        seq = decodeField(container, .seq, as: Int.self)
        level = decodeField(container, .level, as: String.self)
        msg = decodeField(container, .msg, as: String.self)
        ts = decodeField(container, .ts, as: Double.self)
    }
}

// The state of the last FORGET request. An older engine sends no value.
public enum ForgetPhase: String, Equatable {
    case none, pending, confirmed, notDelivered = "not_delivered", unknown
    public init(raw: String?) {
        switch raw {
        case "none": self = .none
        case "pending": self = .pending
        case "confirmed": self = .confirmed
        case "not_delivered": self = .notDelivered
        default: self = .unknown
        }
    }
    // A missing value is not a failure of the whole status decode.
    public init(optional raw: String?) {
        guard let raw, !raw.isEmpty else { self = .none; return }
        self.init(raw: raw)
    }
}
public struct ForgetState: Codable, Equatable {
    public var state: String?
    public var attempts: Int?
    public init(state: String? = nil, attempts: Int? = nil) { self.state = state; self.attempts = attempts }
    public var phase: ForgetPhase { ForgetPhase(optional: state) }
    enum CodingKeys: String, CodingKey { case state, attempts }
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        state = decodeField(container, .state, as: String.self)
        attempts = decodeField(container, .attempts, as: Int.self)
    }
}

// Why the engine turned the tunnel off.
public enum LastStopReason: String, Equatable {
    case user, hotspotLost = "hotspot_lost", sourceDeviceGone = "source_device_gone", error, unknown
    public init(raw: String?) {
        switch raw {
        case "user": self = .user
        case "hotspot_lost": self = .hotspotLost
        case "source_device_gone": self = .sourceDeviceGone
        case "error": self = .error
        default: self = .unknown
        }
    }
}
public struct LastStop: Codable, Equatable {
    public var reason: String?
    public var at: Double?
    public init(reason: String? = nil, at: Double? = nil) { self.reason = reason; self.at = at }
    public var kind: LastStopReason { LastStopReason(raw: reason) }
    // A stable key for one stop event. Notifications use it to send once.
    public var stableKey: String {
        let atText = at.map { String($0) } ?? ""
        return "\(reason ?? "")|\(atText)"
    }
    enum CodingKeys: String, CodingKey { case reason, at }
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        reason = decodeField(container, .reason, as: String.self)
        at = decodeField(container, .at, as: Double.self)
    }
}

public struct Status: Codable {
    public var demo: Bool?; public var api: Int?; public var running: Bool?; public var mode: String?; public var error: String?; public var started_at: Double?; public var paired: Bool?; public var phone_host: String?; public var phone_port: Int?; public var phone: Phone?; public var logs: [LogLine]?; public var icmp_enabled: Bool?
    // New fields from the current engine. Every one is optional.
    public var iface: String?
    public var forget: ForgetState?
    public var last_stop: LastStop?
    public var last_stop_message: String?
    public init(running: Bool? = nil, paired: Bool? = nil, phone: Phone? = nil, error: String? = nil, icmpEnabled: Bool? = nil, iface: String? = nil, forget: ForgetState? = nil, lastStop: LastStop? = nil, lastStopMessage: String? = nil) {
        self.running = running; self.paired = paired; self.phone = phone; self.error = error; self.icmp_enabled = icmpEnabled
        self.iface = iface; self.forget = forget; self.last_stop = lastStop; self.last_stop_message = lastStopMessage
    }
    enum CodingKeys: String, CodingKey { case demo, api, running, mode, error, started_at, paired, phone_host, phone_port, phone, logs, icmp_enabled, iface, forget, last_stop, last_stop_message }
    public init(from decoder: Decoder) throws {
        let container = try? decoder.container(keyedBy: CodingKeys.self)
        demo = decodeField(container, .demo, as: Bool.self)
        api = decodeField(container, .api, as: Int.self)
        running = decodeField(container, .running, as: Bool.self)
        mode = decodeField(container, .mode, as: String.self)
        error = decodeField(container, .error, as: String.self)
        started_at = decodeField(container, .started_at, as: Double.self)
        paired = decodeField(container, .paired, as: Bool.self)
        phone_host = decodeField(container, .phone_host, as: String.self)
        phone_port = decodeField(container, .phone_port, as: Int.self)
        phone = decodeField(container, .phone, as: Phone.self)
        logs = decodeField(container, .logs, as: [LogLine].self)
        // The engine can be older. A missing or wrong-typed value stays nil.
        icmp_enabled = decodeField(container, .icmp_enabled, as: Bool.self)
        iface = decodeField(container, .iface, as: String.self)
        forget = decodeField(container, .forget, as: ForgetState.self)
        last_stop = decodeField(container, .last_stop, as: LastStop.self)
        last_stop_message = decodeField(container, .last_stop_message, as: String.self)
    }
}
public struct PairState: Codable {
    public var state: String?; public var code: String?; public var error: String?
    public init(state: String? = nil, code: String? = nil, error: String? = nil) { self.state = state; self.code = code; self.error = error }
    enum CodingKeys: String, CodingKey { case state, code, error }
    public init(from decoder: Decoder) throws {
        let container = try? decoder.container(keyedBy: CodingKeys.self)
        state = decodeField(container, .state, as: String.self)
        code = decodeField(container, .code, as: String.self)
        error = decodeField(container, .error, as: String.self)
    }
}

// One timing group from GET /api/diagnostics. Every value is optional. An
// older engine sends no diagnostics endpoint at all.
public struct DurationStats: Codable, Equatable {
    public var count: Int?; public var p50: Double?; public var p95: Double?; public var max: Double?
    public init(count: Int? = nil, p50: Double? = nil, p95: Double? = nil, max: Double? = nil) { self.count = count; self.p50 = p50; self.p95 = p95; self.max = max }
    enum CodingKeys: String, CodingKey { case count, p50, p95, max }
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        count = decodeField(container, .count, as: Int.self)
        p50 = decodeField(container, .p50, as: Double.self)
        p95 = decodeField(container, .p95, as: Double.self)
        max = decodeField(container, .max, as: Double.self)
    }
}
public struct EngineDiagnostics: Codable, Equatable {
    public var version: String?; public var uptime_s: Double?; public var workers: Int?
    public init(version: String? = nil, uptime_s: Double? = nil, workers: Int? = nil) { self.version = version; self.uptime_s = uptime_s; self.workers = workers }
    enum CodingKeys: String, CodingKey { case version, uptime_s, workers }
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = decodeField(container, .version, as: String.self)
        uptime_s = decodeField(container, .uptime_s, as: Double.self)
        workers = decodeField(container, .workers, as: Int.self)
    }
}
public struct SetupDiagnostics: Codable, Equatable {
    public var connect_ms: DurationStats?; public var greeting_ms: DurationStats?; public var auth_ms: DurationStats?; public var request_ms: DurationStats?
    public init(connect: DurationStats? = nil, greeting: DurationStats? = nil, auth: DurationStats? = nil, request: DurationStats? = nil) {
        connect_ms = connect; greeting_ms = greeting; auth_ms = auth; request_ms = request
    }
    enum CodingKeys: String, CodingKey { case connect_ms, greeting_ms, auth_ms, request_ms }
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        connect_ms = decodeField(container, .connect_ms, as: DurationStats.self)
        greeting_ms = decodeField(container, .greeting_ms, as: DurationStats.self)
        auth_ms = decodeField(container, .auth_ms, as: DurationStats.self)
        request_ms = decodeField(container, .request_ms, as: DurationStats.self)
    }
}
public struct DNSDiagnostics: Codable, Equatable {
    public var lookups: Int?; public var ok: Int?; public var failed: Int?; public var ms: DurationStats?
    public init(lookups: Int? = nil, ok: Int? = nil, failed: Int? = nil, ms: DurationStats? = nil) { self.lookups = lookups; self.ok = ok; self.failed = failed; self.ms = ms }
    enum CodingKeys: String, CodingKey { case lookups, ok, failed, ms }
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        lookups = decodeField(container, .lookups, as: Int.self)
        ok = decodeField(container, .ok, as: Int.self)
        failed = decodeField(container, .failed, as: Int.self)
        ms = decodeField(container, .ms, as: DurationStats.self)
    }
}
public struct QueueSample: Codable, Equatable {
    public var peak: Int?; public var max_age_us: Double?
    public init(peak: Int? = nil, max_age_us: Double? = nil) { self.peak = peak; self.max_age_us = max_age_us }
    enum CodingKeys: String, CodingKey { case peak, max_age_us }
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        peak = decodeField(container, .peak, as: Int.self)
        max_age_us = decodeField(container, .max_age_us, as: Double.self)
    }
}
public struct QueueDiagnostics: Codable, Equatable {
    public var input: [QueueSample]?; public var output: QueueSample?
    public init(input: [QueueSample]? = nil, output: QueueSample? = nil) { self.input = input; self.output = output }
    enum CodingKeys: String, CodingKey { case input, output }
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        input = decodeField(container, .input, as: [QueueSample].self)
        output = decodeField(container, .output, as: QueueSample.self)
    }
}
public struct UDPDiagnostics: Codable, Equatable {
    public var flows: Int?; public var age_drops: Int?
    public init(flows: Int? = nil, age_drops: Int? = nil) { self.flows = flows; self.age_drops = age_drops }
    enum CodingKeys: String, CodingKey { case flows, age_drops }
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        flows = decodeField(container, .flows, as: Int.self)
        age_drops = decodeField(container, .age_drops, as: Int.self)
    }
}
public struct TCPDiagnostics: Codable, Equatable {
    public var flows_peak: Int?; public var retransmits: Int?; public var zero_window_ms: Double?
    public init(flows_peak: Int? = nil, retransmits: Int? = nil, zero_window_ms: Double? = nil) { self.flows_peak = flows_peak; self.retransmits = retransmits; self.zero_window_ms = zero_window_ms }
    enum CodingKeys: String, CodingKey { case flows_peak, retransmits, zero_window_ms }
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        flows_peak = decodeField(container, .flows_peak, as: Int.self)
        retransmits = decodeField(container, .retransmits, as: Int.self)
        zero_window_ms = decodeField(container, .zero_window_ms, as: Double.self)
    }
}
public struct FailureTotals: Codable, Equatable {
    public var total: Int?; public var dropped: Int?
    public init(total: Int? = nil, dropped: Int? = nil) { self.total = total; self.dropped = dropped }
    enum CodingKeys: String, CodingKey { case total, dropped }
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        total = decodeField(container, .total, as: Int.self)
        dropped = decodeField(container, .dropped, as: Int.self)
    }
}
// One local relay observation. Missing fields stay unknown for older engines.
public struct EstablishedBucket: Codable, Equatable {
    public var age_s: Int?
    public var observed: Bool?
    public var tcp_retransmits: Int?
    public var window_limited_ms: Int?
    public var tcp_teardowns: Int?
    public var udp_teardowns: Int?
    public var udp_drops: Int?
    public var relay_drops: Int?
    public var outer_errors: Int?
    enum CodingKeys: String, CodingKey {
        case age_s, observed, tcp_retransmits, window_limited_ms, tcp_teardowns
        case udp_teardowns, udp_drops, relay_drops, outer_errors
    }
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        age_s = decodeField(container, .age_s, as: Int.self)
        observed = decodeField(container, .observed, as: Bool.self)
        tcp_retransmits = decodeField(container, .tcp_retransmits, as: Int.self)
        window_limited_ms = decodeField(container, .window_limited_ms, as: Int.self)
        tcp_teardowns = decodeField(container, .tcp_teardowns, as: Int.self)
        udp_teardowns = decodeField(container, .udp_teardowns, as: Int.self)
        udp_drops = decodeField(container, .udp_drops, as: Int.self)
        relay_drops = decodeField(container, .relay_drops, as: Int.self)
        outer_errors = decodeField(container, .outer_errors, as: Int.self)
    }
}
public struct EstablishedDiagnostics: Codable, Equatable {
    public var bucket_s: Int?
    public var window_s: Int?
    public var buckets: [EstablishedBucket]?
    enum CodingKeys: String, CodingKey { case bucket_s, window_s, buckets }
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        bucket_s = decodeField(container, .bucket_s, as: Int.self)
        window_s = decodeField(container, .window_s, as: Int.self)
        buckets = decodeField(container, .buckets, as: [EstablishedBucket].self)
    }
}
public struct Diagnostics: Codable, Equatable {
    public var ok: Bool?; public var running: Bool?
    public var engine: EngineDiagnostics?; public var setup: SetupDiagnostics?; public var dns: DNSDiagnostics?
    public var queues: QueueDiagnostics?; public var udp: UDPDiagnostics?; public var tcp: TCPDiagnostics?
    public var failures: FailureTotals?
    public var established: EstablishedDiagnostics?
    public init(running: Bool? = nil, engine: EngineDiagnostics? = nil, setup: SetupDiagnostics? = nil, dns: DNSDiagnostics? = nil, queues: QueueDiagnostics? = nil, udp: UDPDiagnostics? = nil, tcp: TCPDiagnostics? = nil, failures: FailureTotals? = nil) {
        self.ok = true; self.running = running; self.engine = engine; self.setup = setup; self.dns = dns
        self.queues = queues; self.udp = udp; self.tcp = tcp; self.failures = failures; self.established = nil
    }
    enum CodingKeys: String, CodingKey { case ok, running, engine, setup, dns, queues, udp, tcp, failures, established }
    public init(from decoder: Decoder) throws {
        // The root must be an object. A wrong-shaped body becomes unavailable.
        let container = try decoder.container(keyedBy: CodingKeys.self)
        ok = decodeField(container, .ok, as: Bool.self)
        running = decodeField(container, .running, as: Bool.self)
        engine = decodeField(container, .engine, as: EngineDiagnostics.self)
        setup = decodeField(container, .setup, as: SetupDiagnostics.self)
        dns = decodeField(container, .dns, as: DNSDiagnostics.self)
        queues = decodeField(container, .queues, as: QueueDiagnostics.self)
        udp = decodeField(container, .udp, as: UDPDiagnostics.self)
        tcp = decodeField(container, .tcp, as: TCPDiagnostics.self)
        failures = decodeField(container, .failures, as: FailureTotals.self)
        established = decodeField(container, .established, as: EstablishedDiagnostics.self)
    }
}

// The body of POST /api/start. The ping option is always present, so the
// engine never has to guess the setting.
public struct StartBody: Encodable, Equatable {
    public var mode: String
    public var options: Options
    public struct Options: Encodable, Equatable {
        public var experimentalICMP: Bool
        public init(experimentalICMP: Bool) { self.experimentalICMP = experimentalICMP }
        enum CodingKeys: String, CodingKey { case experimentalICMP = "experimental_icmp" }
    }
    public init(experimentalICMP: Bool, mode: String = "phone") {
        self.mode = mode
        self.options = Options(experimentalICMP: experimentalICMP)
    }
    // Sorted keys make the bytes stable, so a test can compare the exact body.
    public func json() throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return String(decoding: try encoder.encode(self), as: UTF8.self)
    }
}
public protocol BackendClient {
    func status(timeout: TimeInterval) async throws -> Status
    func logs(since: Int) async throws -> [LogLine]
    func pairState() async throws -> PairState
    func startPairing() async throws
    func cancelPairing() async throws
    // Forget the pairing. The engine refuses this while the tunnel runs.
    func forget() async throws -> ForgetState
    func startTunnel(experimentalICMP: Bool) async throws
    func stopTunnel(timeout: TimeInterval) async throws
    func failures() async throws -> Failures
    // Run one presence probe now. The default timeout is 2 seconds.
    func probe() async throws -> Phone
    // Read the engine counters. An older engine has no endpoint.
    func diagnostics() async throws -> Diagnostics
}
public extension BackendClient {
    func status() async throws -> Status { try await status(timeout: 3) }
    func stopTunnel() async throws { try await stopTunnel(timeout: 70) }
    // Old call sites keep the product default: ping works.
    func startTunnel() async throws { try await startTunnel(experimentalICMP: true) }
}
public enum BackendError: LocalizedError {
    case unauthorized
    case response(String)
    case missingEngine
    case timeout
    case exited
    case unavailable
    // The source device no longer accepts the saved token. The app must pair
    // again. The text comes from the engine.
    case phoneTokenRejected(String)
    // The engine refused FORGET because the tunnel still runs. This is a
    // normal state, not an error screen.
    case forgetBlockedByTunnel
    // An engine before the current build has no endpoint for this request.
    case notSupported
    public var errorDescription: String? {
        switch self {
        case .unauthorized: return "The engine rejected the request."
        case .response(let message): return message
        case .missingEngine: return "The engine is missing."
        case .timeout: return "The engine did not respond in time."
        case .exited: return "The engine stopped."
        case .unavailable: return "This engine cannot list failures."
        case .phoneTokenRejected(let message): return message
        case .forgetBlockedByTunnel: return "Turn off the tunnel first."
        case .notSupported: return "This engine does not support the request."
        }
    }
}
// Read the error code and the plain text from an engine error body. The body
// can hold the code at the top level or inside the error object.
private func engineError(_ data: Data) -> (String?, String) {
    guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return (nil, "The engine request failed.") }
    let nested = obj["error"] as? [String: Any]
    let raw = obj["error"] as? String ?? nested?["message"] as? String
    let code = obj["code"] as? String ?? nested?["code"] as? String ?? raw
    let message = (raw?.isEmpty == false ? raw! : "The engine request failed.")
    return (code, message)
}

private final class RequestDelegate: NSObject, URLSessionDataDelegate, URLSessionTaskDelegate {
    var data = Data()
    var response: URLResponse?
    var continuation: CheckedContinuation<(Data, URLResponse), Error>?
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse, completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) { self.response = response; completionHandler(.allow) }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) { if self.data.count + data.count > 1_048_576 { dataTask.cancel() } else { self.data.append(data) } }
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if let error { continuation?.resume(throwing: error) }
        else if let response { continuation?.resume(returning: (data, response)) }
        else { continuation?.resume(throwing: BackendError.response("Invalid engine response.")) }
        continuation = nil; session.finishTasksAndInvalidate()
    }
}
public final class HTTPBackend: BackendClient {

    public let port: UInt16
    private let secret: String
    public static func configuration() -> URLSessionConfiguration {
        let config = URLSessionConfiguration.ephemeral
        config.connectionProxyDictionary = [:]; config.urlCache = nil; config.httpCookieStorage = nil
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        return config
    }
    public init(port: UInt16, secret: String) { self.port = port; self.secret = secret }
    private func request(_ path: String, body: String? = nil, timeout: TimeInterval = 3, allowNotFound: Bool = false) async throws -> Data {
        var req = URLRequest(url: URL(string: "http://127.0.0.1:\(port)\(path)")!, timeoutInterval: timeout)
        req.setValue("Bearer \(secret)", forHTTPHeaderField: "Authorization")
        req.setValue("127.0.0.1:\(port)", forHTTPHeaderField: "Host")
        if let body { req.httpMethod = "POST"; req.httpBody = Data(body.utf8); req.setValue("application/json", forHTTPHeaderField: "Content-Type") }
        let delegate = RequestDelegate()
        let session = URLSession(configuration: Self.configuration(), delegate: delegate, delegateQueue: nil)
        let (data, response): (Data, URLResponse) = try await withCheckedThrowingContinuation { continuation in
            delegate.continuation = continuation
            session.dataTask(with: req).resume()
        }
        guard let response = response as? HTTPURLResponse else { throw BackendError.response("Invalid engine response.") }
        // An older engine has no failure endpoint. That is not an app error.
        if response.statusCode == 404 && allowNotFound { throw BackendError.unavailable }
        if response.statusCode == 401 { throw BackendError.unauthorized }
        guard (200..<300).contains(response.statusCode) else {
            let (code, message) = engineError(data)
            if code == "phone_token_rejected" { throw BackendError.phoneTokenRejected(message) }
            if code == "tunnel_running" { throw BackendError.forgetBlockedByTunnel }
            throw BackendError.response(message)
        }
        if let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any], obj["ok"] as? Bool == false {
            let (code, message) = engineError(data)
            if code == "phone_token_rejected" { throw BackendError.phoneTokenRejected(message) }
            if code == "tunnel_running" { throw BackendError.forgetBlockedByTunnel }
            throw BackendError.response(message)
        }
        return data
    }
    public func status(timeout: TimeInterval) async throws -> Status { try JSONDecoder().decode(Status.self, from: await request("/api/status", timeout: timeout)) }
    public func logs(since: Int) async throws -> [LogLine] {
        let data = try await request("/api/logs?since=\(since)")
        struct Result: Decodable {
            var logs: [LogLine]?
            enum CodingKeys: String, CodingKey { case logs }
            init(from decoder: Decoder) throws {
                let container = try? decoder.container(keyedBy: CodingKeys.self)
                logs = decodeField(container, .logs, as: [LogLine].self)
            }
        }
        return try JSONDecoder().decode(Result.self, from: data).logs ?? []
    }
    public func pairState() async throws -> PairState { try JSONDecoder().decode(PairState.self, from: await request("/api/phone/pair")) }
    public func startPairing() async throws { _ = try await request("/api/phone/pair", body: "{}") }
    public func cancelPairing() async throws { _ = try await request("/api/phone/pair/cancel", body: "{}") }
    public func forget() async throws -> ForgetState {
        let data: Data
        do {
            data = try await request("/api/phone/forget", body: "{}")
        } catch BackendError.response(let message) where message == "Turn off the tunnel first." {
            throw BackendError.forgetBlockedByTunnel
        }
        // The current engine returns the new forget state. An older engine
        // returns only {"ok":true}. A missing value is not an error.
        struct Result: Decodable {
            var forget: ForgetState?
            init(from decoder: Decoder) throws {
                let container = try? decoder.container(keyedBy: CodingKeys.self)
                forget = try? container?.decodeIfPresent(ForgetState.self, forKey: .forget)
            }
            enum CodingKeys: String, CodingKey { case forget }
        }
        return (try? JSONDecoder().decode(Result.self, from: data).forget) ?? ForgetState()
    }
    public func stopTunnel(timeout: TimeInterval) async throws { _ = try await request("/api/stop", body: "{}", timeout: timeout) }
    public func startTunnel(experimentalICMP: Bool) async throws {
        _ = try await request("/api/start", body: try StartBody(experimentalICMP: experimentalICMP).json(), timeout: 90)
    }
    // Read the failure record. A 404 or a body that this app cannot read means
    // that the engine cannot list failures. It is not an app error screen.
    public func failures() async throws -> Failures {
        let data = try await request("/api/failures", timeout: 2, allowNotFound: true)
        do { return try JSONDecoder().decode(Failures.self, from: data) }
        catch { throw BackendError.unavailable }
    }
    // Run one probe. A missing endpoint or a body that this app cannot read
    // means that this engine has no probe. The caller keeps the old status.
    public func probe() async throws -> Phone {
        let data = try await request("/api/phone/probe", body: "{}", timeout: 2, allowNotFound: true)
        struct Result: Decodable {
            var phone: Phone?
            init(from decoder: Decoder) throws {
                let container = try? decoder.container(keyedBy: CodingKeys.self)
                phone = try? container?.decodeIfPresent(Phone.self, forKey: .phone)
            }
            enum CodingKeys: String, CodingKey { case phone }
        }
        guard let phone = (try? JSONDecoder().decode(Result.self, from: data))?.phone else { throw BackendError.unavailable }
        return phone
    }
    // Read the engine counters. A 404 or an unreadable body means that this
    // engine cannot send diagnostics. It is never an error screen.
    public func diagnostics() async throws -> Diagnostics {
        let data = try await request("/api/diagnostics", timeout: 2, allowNotFound: true)
        do { return try JSONDecoder().decode(Diagnostics.self, from: data) }
        catch { throw BackendError.unavailable }
    }
}
public final class FakeBackend: BackendClient {
    // The engine client calls this double from the main actor and from the
    // concurrent executor. Guard every stored value with one lock.
    private let lock = NSLock()
    private var storedStatus = Status()
    private var storedPair = PairState()
    private var storedFailures = Failures()
    private var storedProbe = Phone(state: "ready")
    private var storedDiagnostics = Diagnostics()
    private var storedForget = ForgetState(state: "confirmed")
    private var storedFailure: Error?
    private var storedStatusFailure: Error?
    private var storedFailuresError: Error?
    private var storedProbeError: Error?
    private var storedDiagnosticsError: Error?
    private var storedForgetError: Error?
    private var storedOperationDelay: UInt64 = 0
    private var storedCalls: [String] = []
    private var storedStartBodies: [String] = []
    // Tests use this to model the engine that turns the tunnel off.
    public var stopClearsRunning = false
    public init() {}
    public var currentStatus: Status {
        get { lock.lock(); defer { lock.unlock() }; return storedStatus }
        set { lock.lock(); defer { lock.unlock() }; storedStatus = newValue }
    }
    public var currentPair: PairState {
        get { lock.lock(); defer { lock.unlock() }; return storedPair }
        set { lock.lock(); defer { lock.unlock() }; storedPair = newValue }
    }
    public var currentFailures: Failures {
        get { lock.lock(); defer { lock.unlock() }; return storedFailures }
        set { lock.lock(); defer { lock.unlock() }; storedFailures = newValue }
    }
    public var currentProbe: Phone {
        get { lock.lock(); defer { lock.unlock() }; return storedProbe }
        set { lock.lock(); defer { lock.unlock() }; storedProbe = newValue }
    }
    public var currentDiagnostics: Diagnostics {
        get { lock.lock(); defer { lock.unlock() }; return storedDiagnostics }
        set { lock.lock(); defer { lock.unlock() }; storedDiagnostics = newValue }
    }
    public var currentForget: ForgetState {
        get { lock.lock(); defer { lock.unlock() }; return storedForget }
        set { lock.lock(); defer { lock.unlock() }; storedForget = newValue }
    }
    // The failure endpoint has its own failure. A status failure must not
    // change the failure list test.
    public var failuresError: Error? {
        get { lock.lock(); defer { lock.unlock() }; return storedFailuresError }
        set { lock.lock(); defer { lock.unlock() }; storedFailuresError = newValue }
    }
    public var probeError: Error? {
        get { lock.lock(); defer { lock.unlock() }; return storedProbeError }
        set { lock.lock(); defer { lock.unlock() }; storedProbeError = newValue }
    }
    public var diagnosticsError: Error? {
        get { lock.lock(); defer { lock.unlock() }; return storedDiagnosticsError }
        set { lock.lock(); defer { lock.unlock() }; storedDiagnosticsError = newValue }
    }
    public var forgetError: Error? {
        get { lock.lock(); defer { lock.unlock() }; return storedForgetError }
        set { lock.lock(); defer { lock.unlock() }; storedForgetError = newValue }
    }
    public var failure: Error? {
        get { lock.lock(); defer { lock.unlock() }; return storedFailure }
        set { lock.lock(); defer { lock.unlock() }; storedFailure = newValue }
    }
    public var statusFailure: Error? {
        get { lock.lock(); defer { lock.unlock() }; return storedStatusFailure }
        set { lock.lock(); defer { lock.unlock() }; storedStatusFailure = newValue }
    }
    public var operationDelay: UInt64 {
        get { lock.lock(); defer { lock.unlock() }; return storedOperationDelay }
        set { lock.lock(); defer { lock.unlock() }; storedOperationDelay = newValue }
    }
    public var calls: [String] { lock.lock(); defer { lock.unlock() }; return storedCalls }
    // The exact start bodies that the app sent, in order.
    public var startBodies: [String] { lock.lock(); defer { lock.unlock() }; return storedStartBodies }
    private func record(_ name: String) -> Error? {
        lock.lock(); defer { lock.unlock() }
        storedCalls.append(name)
        return storedFailure
    }
    private func call(_ name: String) throws { if let failure = record(name) { throw failure } }
    private func takeStatus() -> (Status, Error?) {
        lock.lock(); defer { lock.unlock() }
        storedCalls.append("status")
        return (storedStatus, storedStatusFailure ?? storedFailure)
    }
    private func takeFailures() -> (Failures, Error?, UInt64) {
        lock.lock(); defer { lock.unlock() }
        storedCalls.append("failures")
        return (storedFailures, storedFailuresError ?? storedFailure, storedOperationDelay)
    }
    private func takeForget() -> (ForgetState, Error?) {
        lock.lock(); defer { lock.unlock() }
        storedCalls.append("forget")
        return (storedForget, storedForgetError ?? storedFailure)
    }
    private func applyForget(_ value: ForgetState) {
        lock.lock(); defer { lock.unlock() }
        storedStatus.forget = value
        storedStatus.paired = false
        storedStatus.phone = Phone(state: "unpaired")
    }
    private func takeStart(_ body: String) -> Error? {
        lock.lock(); defer { lock.unlock() }
        storedCalls.append("startTunnel")
        storedStartBodies.append(body)
        return storedFailure
    }
    private func applyStop() {
        guard stopClearsRunning else { return }
        lock.lock(); defer { lock.unlock() }
        storedStatus.running = false
    }
    private func takeProbe() -> (Phone, Error?) {
        lock.lock(); defer { lock.unlock() }
        storedCalls.append("probe")
        return (storedProbe, storedProbeError ?? storedFailure)
    }
    private func applyProbe(_ phone: Phone) {
        lock.lock(); defer { lock.unlock() }
        storedStatus.phone = phone
    }
    private func takeDiagnostics() -> (Diagnostics, Error?) {
        lock.lock(); defer { lock.unlock() }
        storedCalls.append("diagnostics")
        return (storedDiagnostics, storedDiagnosticsError ?? storedFailure)
    }
    public func status(timeout: TimeInterval) async throws -> Status {
        let (status, failure) = takeStatus()
        if let failure { throw failure }
        return status
    }
    public func logs(since: Int) async throws -> [LogLine] { try call("logs"); return currentStatus.logs ?? [] }
    public func pairState() async throws -> PairState { try call("pairState"); return currentPair }
    public func startPairing() async throws { try call("startPairing") }
    public func cancelPairing() async throws { try call("cancelPairing") }
    public func forget() async throws -> ForgetState {
        let (value, failure) = takeForget()
        if let failure { throw failure }
        applyForget(value)
        let delay = operationDelay
        if delay > 0 { try await Task.sleep(nanoseconds: delay) }
        return value
    }
    public func startTunnel(experimentalICMP: Bool) async throws {
        let body = try StartBody(experimentalICMP: experimentalICMP).json()
        if let failure = takeStart(body) { throw failure }
        let delay = operationDelay
        if delay > 0 { try await Task.sleep(nanoseconds: delay) }
    }
    public func stopTunnel(timeout: TimeInterval) async throws {
        try call("stopTunnel")
        let delay = operationDelay
        if delay > 0 { try await Task.sleep(nanoseconds: delay) }
        applyStop()
    }
    public func failures() async throws -> Failures {
        let (value, error, delay) = takeFailures()
        if delay > 0 { try await Task.sleep(nanoseconds: delay) }
        if let error { throw error }
        return value
    }
    public func probe() async throws -> Phone {
        let (phone, failure) = takeProbe()
        if let failure { throw failure }
        applyProbe(phone)
        return phone
    }
    public func diagnostics() async throws -> Diagnostics {
        let (value, failure) = takeDiagnostics()
        if let failure { throw failure }
        return value
    }
}
