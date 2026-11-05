import Foundation

// The engine keeps a short record of connections that did not work. The
// record stays in the engine memory and never leaves the target device.
public struct Failures: Codable, Equatable {
    public var since: Double?
    public var total: Int?
    public var dropped: Int?
    public var demo: Bool?
    public var groups: [FailureGroup]?
    public var recent: [FailureRecent]?
    public init(since: Double? = nil, total: Int? = nil, dropped: Int? = nil, demo: Bool? = nil, groups: [FailureGroup]? = nil, recent: [FailureRecent]? = nil) {
        self.since = since; self.total = total; self.dropped = dropped; self.demo = demo; self.groups = groups; self.recent = recent
    }
    enum CodingKeys: String, CodingKey { case since, total, dropped, demo, groups, recent }
    public init(from decoder: Decoder) throws {
        // The root must be an object. A body of the wrong shape is not an
        // empty list. The backend maps it to the unavailable state.
        let container = try decoder.container(keyedBy: CodingKeys.self)
        since = decodeField(container, .since, as: Double.self)
        total = decodeField(container, .total, as: Int.self)
        dropped = decodeField(container, .dropped, as: Int.self)
        demo = decodeField(container, .demo, as: Bool.self)
        groups = decodeField(container, .groups, as: LenientArray<FailureGroup>.self)?.values
        recent = decodeField(container, .recent, as: LenientArray<FailureRecent>.self)?.values
    }
}

public struct FailureGroup: Codable, Equatable {
    public var proto: String?
    public var family: String?
    public var port: Int?
    public var reason: String?
    public var phase: String?
    public var count: Int?
    public var name: String?
    public var exampleIp: String?
    public var code: Int?
    public init(proto: String? = nil, family: String? = nil, port: Int? = nil, reason: String? = nil, phase: String? = nil, count: Int? = nil, name: String? = nil, exampleIp: String? = nil, code: Int? = nil) {
        self.proto = proto; self.family = family; self.port = port; self.reason = reason; self.phase = phase
        self.count = count; self.name = name; self.exampleIp = exampleIp; self.code = code
    }
    enum CodingKeys: String, CodingKey { case proto, family, port, reason, phase, count, name, exampleIp = "example_ip", code }
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        proto = decodeField(container, .proto, as: String.self)
        family = decodeField(container, .family, as: String.self)
        port = decodeField(container, .port, as: Int.self)
        reason = decodeField(container, .reason, as: String.self)
        phase = decodeField(container, .phase, as: String.self)
        count = decodeField(container, .count, as: Int.self)
        name = decodeField(container, .name, as: String.self)
        exampleIp = decodeField(container, .exampleIp, as: String.self)
        code = decodeField(container, .code, as: Int.self)
    }
}

public struct FailureRecent: Codable, Equatable {
    public var ts: Double?
    public var proto: String?
    public var family: String?
    public var ip: String?
    public var port: Int?
    public var reason: String?
    public var phase: String?
    public var name: String?
    public var code: Int?
    public init(ts: Double? = nil, proto: String? = nil, family: String? = nil, ip: String? = nil, port: Int? = nil, reason: String? = nil, phase: String? = nil, name: String? = nil, code: Int? = nil) {
        self.ts = ts; self.proto = proto; self.family = family; self.ip = ip; self.port = port
        self.reason = reason; self.phase = phase; self.name = name; self.code = code
    }
    enum CodingKeys: String, CodingKey { case ts, proto, family, ip, port, reason, phase, name, code }
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        ts = decodeField(container, .ts, as: Double.self)
        proto = decodeField(container, .proto, as: String.self)
        family = decodeField(container, .family, as: String.self)
        ip = decodeField(container, .ip, as: String.self)
        port = decodeField(container, .port, as: Int.self)
        reason = decodeField(container, .reason, as: String.self)
        phase = decodeField(container, .phase, as: String.self)
        name = decodeField(container, .name, as: String.self)
        code = decodeField(container, .code, as: Int.self)
    }
}

// One wrong element must not lose the whole list. Decode each element on its
// own and skip the ones that do not fit.
private struct LenientArray<Element: Decodable>: Decodable {
    var values: [Element]
    init(from decoder: Decoder) throws {
        var container = try decoder.unkeyedContainer()
        var values: [Element] = []
        while !container.isAtEnd {
            if let value = try? container.decode(Element.self) {
                values.append(value)
            } else {
                // Move past the element that this type cannot read.
                let before = container.currentIndex
                _ = try? container.superDecoder()
                if container.currentIndex == before { break }
            }
        }
        self.values = values
    }
}

// The reason word from the engine. An unknown word is "other".
public enum FailureReason: String, Equatable {
    case unreachable, refused, timedOut = "timed_out", denied, other
    public init(raw: String?) {
        switch (raw ?? "").lowercased() {
        case "unreachable": self = .unreachable
        case "refused": self = .refused
        case "timed_out": self = .timedOut
        case "denied": self = .denied
        default: self = .other
        }
    }
    // Plain words for the window. A connection timeout does not prove that the
    // destination timed out. The target device can stop waiting for the source
    // device first.
    public var phrase: String {
        switch self {
        case .unreachable: return "could not be reached"
        case .refused: return "was refused"
        case .timedOut: return "got no answer in time"
        case .denied: return "was blocked"
        case .other: return "failed"
        }
    }
    // Short words for a table cell.
    public var tablePhrase: String {
        switch self {
        case .unreachable: return "Could not be reached"
        case .refused: return "Refused"
        case .timedOut: return "No answer in time"
        case .denied: return "Blocked"
        case .other: return "Failed"
        }
    }
}

// The setup stage of a source device connection. An older engine sends no
// phase. A newer engine can send a word that this app does not know.
public enum FailurePhase: Equatable {
    case connect, greeting, auth, request, unknown
    public init?(raw: String?) {
        guard let value = raw?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(), !value.isEmpty else { return nil }
        switch value {
        case "connect": self = .connect
        case "greeting": self = .greeting
        case "auth": self = .auth
        case "request": self = .request
        default: self = .unknown
        }
    }
    // A plain clause for the row sentence.
    public var phrase: String {
        switch self {
        case .connect: return "while the target device connected to the source device"
        case .greeting: return "while the target device greeted the source device"
        case .auth: return "while the target device signed in to the source device"
        case .request: return "while the source device checked the destination"
        case .unknown: return "at an unknown stage"
        }
    }
    // Short words for the table cell.
    public var tablePhrase: String {
        switch self {
        case .connect: return "Source connection"
        case .greeting: return "Greeting"
        case .auth: return "Sign-in"
        case .request: return "Destination request"
        case .unknown: return "Unknown stage"
        }
    }
    // The fixed word for the copied report.
    public var reportWord: String {
        switch self {
        case .connect: return "connect"
        case .greeting: return "greeting"
        case .auth: return "auth"
        case .request: return "request"
        case .unknown: return "unknown"
        }
    }
}

// One line in the Settings list.
public struct FailureRow: Equatable, Identifiable {
    public var id: String
    public var summary: String
    public var detail: String
    // The fields for the table columns.
    public var count: Int
    public var kind: String
    public var target: String
    public var phase: String
    public var reason: String
    public init(id: String, summary: String, detail: String, count: Int = 0, kind: String = "", target: String = "", phase: String = "", reason: String = "") {
        self.id = id; self.summary = summary; self.detail = detail
        self.count = count; self.kind = kind; self.target = target; self.phase = phase; self.reason = reason
    }
}

// Turn the engine response into plain text. The function uses Foundation
// only and it never reads the network.
public enum FailureFormat {
    // The report for sharing: one header line and one line per group.
    public static func report(_ failures: Failures) -> String {
        var lines = [header(failures)]
        for group in ordered(failures.groups ?? []) { lines.append(reportLine(group)) }
        return lines.joined(separator: "\n")
    }

    // The rows for the window, in the same order as the report.
    public static func rows(_ failures: Failures) -> [FailureRow] {
        ordered(failures.groups ?? []).enumerated().map { index, group in
            FailureRow(
                id: "\(index)-\(identity(group))",
                summary: summary(group),
                detail: detail(group),
                count: max(group.count ?? 1, 1),
                kind: tableKind(group),
                target: targetWord(group),
                phase: FailurePhase(raw: group.phase)?.tablePhrase ?? "Not reported",
                reason: FailureReason(raw: group.reason).tablePhrase
            )
        }
    }

    // A high count comes first. Equal counts follow a stable field order.
    private static func ordered(_ groups: [FailureGroup]) -> [FailureGroup] {
        groups.sorted { a, b in
            let left = max(a.count ?? 1, 1), right = max(b.count ?? 1, 1)
            if left != right { return left > right }
            if protoWord(a) != protoWord(b) { return protoWord(a) < protoWord(b) }
            if familyWord(a) != familyWord(b) { return familyWord(a) < familyWord(b) }
            let leftReason = (a.reason ?? "").lowercased()
            let rightReason = (b.reason ?? "").lowercased()
            if leftReason != rightReason { return leftReason < rightReason }
            let leftPhase = (a.phase ?? "").lowercased()
            let rightPhase = (b.phase ?? "").lowercased()
            if leftPhase != rightPhase { return leftPhase < rightPhase }
            if (a.port ?? Int.max) != (b.port ?? Int.max) { return (a.port ?? Int.max) < (b.port ?? Int.max) }
            let leftName = a.name ?? a.exampleIp ?? "", rightName = b.name ?? b.exampleIp ?? ""
            if leftName != rightName { return leftName < rightName }
            return (a.exampleIp ?? "") < (b.exampleIp ?? "")
        }
    }

    private static func header(_ failures: Failures) -> String {
        let total = max(failures.total ?? 0, 0)
        let dropped = max(failures.dropped ?? 0, 0)
        let connections = "\(total) failed connection\(total == 1 ? "" : "s")"
        return "HotspotShade failures since \(timeWord(failures.since)): \(connections), \(dropped) dropped."
    }

    private static func timeWord(_ since: Double?) -> String {
        guard let since else { return "unknown" }
        let formatter = ISO8601DateFormatter()
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.string(from: Date(timeIntervalSince1970: since))
    }

    // One line per group. A missing field shows as a dash. The phase appears
    // after the reason. The code appears only when the engine sends one.
    private static func reportLine(_ group: FailureGroup) -> String {
        var parts = [
            "\(max(group.count ?? 1, 1))x",
            protoWord(group),
            familyWord(group),
            group.port.map(String.init) ?? "-",
            FailureReason(raw: group.reason).rawValue,
            phaseWord(group),
            trimmed(group.name) ?? "-",
            trimmed(group.exampleIp) ?? "-",
        ]
        if let code = group.code { parts.append("code \(code)") }
        return parts.joined(separator: " ")
    }

    private static func summary(_ group: FailureGroup) -> String {
        let count = max(group.count ?? 1, 1)
        let times = "\(count) \(count == 1 ? "time" : "times")"
        let target = targetWord(group)
        let port = group.port.map { " port \($0)" } ?? ""
        let reason = FailureReason(raw: group.reason).phrase
        let stage = FailurePhase(raw: group.phase).map { " \($0.phrase)" } ?? ""
        if kind(group) == .dns { return "\(times): DNS lookup for \(target)\(port) \(reason)\(stage)" }
        return "\(times): \(kindWord(group)) to \(target)\(port) \(reason)\(stage)"
    }

    private static func detail(_ group: FailureGroup) -> String {
        var parts: [String] = []
        switch familyWord(group) {
        case "ipv4": parts.append("IPv4")
        case "ipv6": parts.append("IPv6")
        default: break
        }
        // Show the address only when the name is the main target. Otherwise
        // the row already names the address.
        if trimmed(group.name) != nil, let ip = trimmed(group.exampleIp) { parts.append(ip) }
        if let code = group.code { parts.append("code \(code)") }
        return parts.joined(separator: ", ")
    }

    private enum Kind { case web, tcp, udp, dns, unknown }
    private static func kind(_ group: FailureGroup) -> Kind {
        switch protoWord(group) {
        case "tcp": return group.port == 80 || group.port == 443 ? .web : .tcp
        case "udp": return .udp
        case "dns": return .dns
        default: return .unknown
        }
    }
    private static func kindWord(_ group: FailureGroup) -> String {
        switch kind(group) {
        case .web: return "web connection"
        case .tcp: return "tcp connection"
        case .udp: return "UDP connection"
        case .dns: return "DNS lookup"
        case .unknown: return "connection"
        }
    }
    private static func tableKind(_ group: FailureGroup) -> String {
        switch kind(group) {
        case .web: return "Web"
        case .tcp: return "TCP"
        case .udp: return "UDP"
        case .dns: return "DNS"
        case .unknown: return "Other"
        }
    }
    private static func protoWord(_ group: FailureGroup) -> String {
        switch (group.proto ?? "").lowercased() {
        case "tcp", "udp", "dns": return (group.proto ?? "").lowercased()
        default: return "other"
        }
    }
    private static func familyWord(_ group: FailureGroup) -> String {
        switch (group.family ?? "").lowercased() {
        case "ipv4", "ipv6": return (group.family ?? "").lowercased()
        default: return "other"
        }
    }
    private static func targetWord(_ group: FailureGroup) -> String {
        if let name = trimmed(group.name) { return name }
        if let ip = trimmed(group.exampleIp) { return ip }
        return "an unknown address"
    }
    private static func identity(_ group: FailureGroup) -> String {
        [group.proto ?? "", group.family ?? "", group.port.map(String.init) ?? "", group.reason ?? "", group.phase ?? "", group.name ?? "", group.exampleIp ?? ""].joined(separator: "|")
    }
    private static func phaseWord(_ group: FailureGroup) -> String {
        FailurePhase(raw: group.phase)?.reportWord ?? "-"
    }
    private static func trimmed(_ text: String?) -> String? {
        guard let value = text?.trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty else { return nil }
        return value
    }
}

// The window writes the report to this. Tests use a recording double.
public protocol PasteboardWriting {
    func write(_ text: String)
}

// The default writes nowhere. The app injects the system pasteboard.
public struct NoPasteboard: PasteboardWriting {
    public init() {}
    public func write(_ text: String) {}
}
