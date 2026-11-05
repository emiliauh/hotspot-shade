import Foundation

// The Mac side values for the report. The model fills them from the status,
// the link provider, and the app bundle.
public struct DiagnosticsContext: Equatable {
    public var macOSVersion: String
    public var appVersion: String
    public var link: WiFiLinkInfo?
    public var interfaceName: String?
    public var icmpEnabled: Bool?
    public var lastStop: LastStop?
    public var lastStopMessage: String?
    public var notificationAuthorization: NotificationAuthorization
    public var now: Date
    public init(macOSVersion: String = "unknown", appVersion: String = "unknown", link: WiFiLinkInfo? = nil, interfaceName: String? = nil, icmpEnabled: Bool? = nil, lastStop: LastStop? = nil, lastStopMessage: String? = nil, notificationAuthorization: NotificationAuthorization = .notDetermined, now: Date = Date()) {
        self.macOSVersion = macOSVersion; self.appVersion = appVersion; self.link = link
        self.interfaceName = interfaceName; self.icmpEnabled = icmpEnabled
        self.lastStop = lastStop; self.lastStopMessage = lastStopMessage
        self.notificationAuthorization = notificationAuthorization; self.now = now
    }
}

// Render one plain-text report. The report holds no tokens and no addresses
// beyond the ones that the failure report already shows.
public enum DiagnosticsReport {
    public static func text(diagnostics: Diagnostics?, failures: Failures?, context: DiagnosticsContext) -> String {
        var lines: [String] = []
        lines.append("HotspotShade diagnostics")
        lines.append("Time: \(timeWord(context.now))")
        lines.append("macOS: \(context.macOSVersion)")
        lines.append("App: \(context.appVersion)")
        lines.append(wifiLine(context))
        lines.append("Ping: \(switchWord(context.icmpEnabled, on: "on", off: "off"))")
        lines.append(lastStopLine(context))
        lines.append("Notifications: \(authorizationWord(context.notificationAuthorization))")
        if let diagnostics {
            lines.append(engineLine(diagnostics.engine))
            lines.append(setupLine(diagnostics.setup))
            lines.append(dnsLine(diagnostics.dns))
            lines.append(queuesLine(diagnostics.queues))
            lines.append(udpLine(diagnostics.udp))
            lines.append(tcpLine(diagnostics.tcp))
            if let established = diagnostics.established {
                lines.append(contentsOf: establishedLines(established))
            }
        } else {
            lines.append("Engine: unavailable.")
        }
        if let failures {
            lines.append("Failures:")
            lines.append(FailureFormat.report(failures))
        } else {
            lines.append("Failures: unavailable.")
        }
        return lines.joined(separator: "\n")
    }

    // MARK: - Mac side

    private static func wifiLine(_ context: DiagnosticsContext) -> String {
        guard let link = context.link else {
            if let name = context.interfaceName, !name.isEmpty { return "Wi-Fi: unavailable, \(name)" }
            return "Wi-Fi: unavailable"
        }
        var parts: [String] = [link.band.rawValue]
        if let width = link.channelWidthMHz { parts.append("\(width) MHz") }
        if let rssi = link.rssi { parts.append("\(rssi) dBm") }
        if let name = link.interfaceName ?? context.interfaceName { parts.append(name) }
        return "Wi-Fi: \(parts.joined(separator: ", "))"
    }

    private static func lastStopLine(_ context: DiagnosticsContext) -> String {
        guard let stop = context.lastStop, let reason = stop.reason, !reason.isEmpty else { return "Last stop: none" }
        var line = "Last stop: \(reason)"
        if let at = stop.at { line += " at \(timeWord(Date(timeIntervalSince1970: at)))" }
        if let message = Strings.sanitized(context.lastStopMessage), !message.isEmpty { line += ". \(message)" }
        return line
    }

    private static func authorizationWord(_ value: NotificationAuthorization) -> String {
        switch value {
        case .notDetermined: return "not asked"
        case .authorized: return "allowed"
        case .denied: return "denied"
        }
    }

    private static func switchWord(_ value: Bool?, on: String, off: String) -> String {
        guard let value else { return "unknown" }
        return value ? on : off
    }

    // MARK: - Engine side

    private static func engineLine(_ engine: EngineDiagnostics?) -> String {
        var parts = ["version \(engine?.version ?? "unknown")"]
        parts.append("uptime \(number(engine?.uptime_s)) s")
        parts.append("workers \(engine?.workers.map(String.init) ?? "unknown")")
        return "Engine: \(parts.joined(separator: ", "))"
    }

    private static func setupLine(_ setup: SetupDiagnostics?) -> String {
        var parts: [String] = []
        for (name, value) in [("connect", setup?.connect_ms), ("greeting", setup?.greeting_ms), ("auth", setup?.auth_ms), ("request", setup?.request_ms)] {
            parts.append("\(name) \(timing(value))")
        }
        return "Setup: \(parts.joined(separator: "; "))"
    }

    private static func dnsLine(_ dns: DNSDiagnostics?) -> String {
        let counts = "\(dns?.lookups.map(String.init) ?? "unknown") lookups, \(dns?.ok.map(String.init) ?? "unknown") ok, \(dns?.failed.map(String.init) ?? "unknown") failed"
        return "DNS: \(counts); \(timing(dns?.ms))"
    }

    private static func queuesLine(_ queues: QueueDiagnostics?) -> String {
        let input = (queues?.input ?? []).map { "peak \($0.peak.map(String.init) ?? "unknown"), max age \(number($0.max_age_us)) us" }
        let output = "output peak \(queues?.output?.peak.map(String.init) ?? "unknown"), max age \(number(queues?.output?.max_age_us)) us"
        if input.isEmpty { return "Queues: input unknown; \(output)" }
        return "Queues: input \(input.joined(separator: ", ")); \(output)"
    }

    private static func udpLine(_ udp: UDPDiagnostics?) -> String {
        "UDP: \(udp?.flows.map(String.init) ?? "unknown") flows, \(udp?.age_drops.map(String.init) ?? "unknown") age drops"
    }

    private static func tcpLine(_ tcp: TCPDiagnostics?) -> String {
        "TCP: \(tcp?.flows_peak.map(String.init) ?? "unknown") peak flows, \(tcp?.retransmits.map(String.init) ?? "unknown") retransmits, \(number(tcp?.zero_window_ms)) ms zero window"
    }

    // These are local relay events, not end-to-end packet loss. Do not turn
    // missing observations or missing counters into a claim of health.
    private static func establishedLines(_ established: EstablishedDiagnostics) -> [String] {
        guard let buckets = established.buckets, !buckets.isEmpty else {
            return ["Established relay: no observation."]
        }
        let recent = Array(buckets.suffix(60))
        let known = recent.filter { $0.observed != nil }.count
        let observed = recent.filter { $0.observed == true }.count
        let summary = known == 0 ? "observation unavailable" : "\(observed) of \(known) reported buckets observed an established flow"
        var lines = ["Established relay: \(summary). Local events do not prove end-to-end loss."]
        let events = recent.filter { bucket in
            [bucket.tcp_retransmits, bucket.window_limited_ms, bucket.tcp_teardowns,
             bucket.udp_teardowns, bucket.udp_drops, bucket.relay_drops, bucket.outer_errors]
                .contains { ($0 ?? 0) > 0 }
        }
        if events.isEmpty {
            let hasCounters = recent.contains { bucket in
                [bucket.tcp_retransmits, bucket.window_limited_ms, bucket.tcp_teardowns,
                 bucket.udp_teardowns, bucket.udp_drops, bucket.relay_drops, bucket.outer_errors]
                    .contains { $0 != nil }
            }
            lines.append(hasCounters ? "Established events: no nonzero events in the reported counters." : "Established events: unavailable.")
        } else {
            for bucket in events.suffix(8).reversed() {
                func value(_ count: Int?) -> String { count.map(String.init) ?? "unknown" }
                let age = bucket.age_s.map(String.init) ?? "unknown"
                let seen = bucket.observed.map { $0 ? "yes" : "no" } ?? "unknown"
                lines.append("Established \(age) s ago: retransmits \(value(bucket.tcp_retransmits)), window \(value(bucket.window_limited_ms)) ms, TCP ends \(value(bucket.tcp_teardowns)), UDP ends \(value(bucket.udp_teardowns)), UDP drops \(value(bucket.udp_drops)), relay drops \(value(bucket.relay_drops)), outer errors \(value(bucket.outer_errors)), observed \(seen).")
            }
        }
        return lines
    }

    private static func timing(_ value: DurationStats?) -> String {
        guard let value else { return "count unknown, p50 unknown, p95 unknown, max unknown" }
        return "count \(value.count.map(String.init) ?? "unknown"), p50 \(msWord(value.p50)), p95 \(msWord(value.p95)), max \(msWord(value.max))"
    }

    // A whole number shows without a decimal point. A missing value shows as
    // "unknown".
    private static func msWord(_ value: Double?) -> String {
        guard let value else { return "unknown" }
        return "\(number(value)) ms"
    }

    private static func number(_ value: Double?) -> String {
        guard let value, value.isFinite else { return "unknown" }
        if abs(value) >= 1e15 { return String(format: "%.3g", value) }
        if let integer = Int(exactly: value) { return String(integer) }
        return String(format: "%.1f", value)
    }

    // All times use UTC. The format is stable for a test.
    private static func timeWord(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.string(from: date)
    }
}
