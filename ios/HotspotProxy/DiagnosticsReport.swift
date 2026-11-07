import Foundation

// A technical report for the person to copy from Settings, Advanced. This file
// uses Foundation only. The tests inject the environment values. The text
// holds counts, states, and versions. It holds no address, host, port, token,
// or destination.

/// The connect duration buckets. A value below a bound goes in that bucket.
enum ConnectDurationBucket: String, CaseIterable {
    case under100
    case under250
    case under500
    case under1000
    case under2000
    case under4000
    case atLeast4000

    /// The plain words for the report.
    var label: String {
        switch self {
        case .under100: return "under 100 ms"
        case .under250: return "under 250 ms"
        case .under500: return "under 500 ms"
        case .under1000: return "under 1 s"
        case .under2000: return "under 2 s"
        case .under4000: return "under 4 s"
        case .atLeast4000: return "at 4 s or more"
        }
    }

    /// The bucket for one connect duration in seconds.
    static func bucket(_ seconds: TimeInterval) -> ConnectDurationBucket {
        if seconds < 0.1 { return .under100 }
        if seconds < 0.25 { return .under250 }
        if seconds < 0.5 { return .under500 }
        if seconds < 1 { return .under1000 }
        if seconds < 2 { return .under2000 }
        if seconds < 4 { return .under4000 }
        return .atLeast4000
    }
}

/// The thermal state in plain words. The app maps the system value here, so
/// the report type stays free of platform types.
enum ThermalLevel: String, CaseIterable {
    case nominal = "Nominal"
    case fair = "Fair"
    case serious = "Serious"
    case critical = "Critical"
}

/// The transport that carried one established relay session.
enum EstablishedTransport: Equatable {
    case tcp
    case udp
}

/// Track the first payload of one relay. A destination that answered is not an
/// established relay. The relay starts when it carries payload in either
/// direction.
struct EstablishedRelay: Equatable {
    private(set) var transport: EstablishedTransport?

    /// True after the first payload.
    var started: Bool { transport != nil }

    /// Record one payload. Return the transport only for the first payload.
    mutating func recordPayload(_ transport: EstablishedTransport) -> EstablishedTransport? {
        guard self.transport == nil else { return nil }
        self.transport = transport
        return transport
    }
}

/// How an established relay session ended. A socket error keeps its side. It
/// does not prove packet loss on the cellular path. A proxy stop or a listener
/// failure uses `other`.
///
/// The report keeps the side and the reason for a TCP end. It counts a UDP end
/// only as a total. A UDP flow has no half close, so the report cannot keep the
/// UDP end side or reason. See `EstablishedCounters.recordEnd`.
enum EstablishedEnd: Equatable {
    case clean
    /// A socket error on the connection to the target device.
    case clientSocketError
    /// A socket error on the cellular connection to the destination.
    case destinationSocketError
    case idle
    case other

    /// The established end for one capacity close. An idle UDP or half-closed
    /// flow keeps its idle end. A setup phase has no established end of its
    /// own.
    static func capacityEviction(_ reason: SessionCapacity.CloseReason) -> EstablishedEnd {
        switch reason {
        case .udpIdle, .halfClosedIdle:
            return .idle
        case .handshakeExpired, .connectExpired, .relayGrantExpired:
            return .other
        }
    }
}

/// The established relay state of one session. The session queue records the
/// first payload and the first end. The server queue takes one end record.
/// The owner uses a lock around this value, because the two queues run apart.
struct EstablishedSessionRecord: Equatable {
    private(set) var relay = EstablishedRelay()
    private(set) var end: EstablishedEnd?
    private(set) var endTaken = false

    /// Record one payload. Return the transport only for the first payload.
    mutating func recordPayload(_ transport: EstablishedTransport) -> EstablishedTransport? {
        relay.recordPayload(transport)
    }

    /// Keep the first end reason. A later close path does not replace it.
    mutating func recordEnd(_ end: EstablishedEnd) {
        guard relay.started, self.end == nil else { return }
        self.end = end
    }

    /// Take the one end record. The first caller gets it, so a stop, an
    /// eviction, and an asynchronous close cannot count the same end twice.
    /// Return nil before the relay carried a payload or after the first take.
    mutating func takeEnd(default fallback: EstablishedEnd = .other)
        -> (transport: EstablishedTransport, end: EstablishedEnd)? {
        guard let transport = relay.transport, !endTaken else { return nil }
        endTaken = true
        return (transport, end ?? fallback)
    }
}

/// One 10 second bucket of established relay events. It holds no address.
struct EstablishedBucket: Equatable {
    var tcpStarts = 0
    var udpStarts = 0
    var tcpClean = 0
    var tcpClientErrors = 0
    var tcpDestinationErrors = 0
    var tcpIdle = 0
    var tcpOther = 0
    var udpEnds = 0

    var hasTeardown: Bool {
        tcpClean + tcpClientErrors + tcpDestinationErrors + tcpIdle + tcpOther + udpEnds > 0
    }
}

/// One bucket with its age in seconds for the report.
struct EstablishedWindowRow: Equatable {
    var ageSeconds: Int
    var bucket: EstablishedBucket
}

/// The established relay counters for one run. The event timeline keeps the
/// last 30 buckets of 10 seconds. The type holds counts only.
struct EstablishedCounters: Equatable {
    static let bucketSeconds: TimeInterval = 10
    static let windowBuckets = 30

    private(set) var buckets: [Int: EstablishedBucket] = [:]
    /// The newest bucket seen. A late event never moves it back.
    private(set) var newestBucket: Int?
    private(set) var tcpStarts = 0
    private(set) var udpStarts = 0
    private(set) var tcpClean = 0
    private(set) var tcpClientErrors = 0
    private(set) var tcpDestinationErrors = 0
    private(set) var tcpIdle = 0
    private(set) var tcpOther = 0
    private(set) var udpEnds = 0

    mutating func reset() {
        buckets.removeAll()
        newestBucket = nil
        tcpStarts = 0
        udpStarts = 0
        tcpClean = 0
        tcpClientErrors = 0
        tcpDestinationErrors = 0
        tcpIdle = 0
        tcpOther = 0
        udpEnds = 0
    }

    mutating func recordStart(_ transport: EstablishedTransport, at now: TimeInterval) {
        switch transport {
        case .tcp: tcpStarts += 1
        case .udp: udpStarts += 1
        }
        add(at: now) { bucket in
            switch transport {
            case .tcp: bucket.tcpStarts += 1
            case .udp: bucket.udpStarts += 1
            }
        }
    }

    /// Record one end. A TCP end keeps its side and reason. A UDP end adds one
    /// to `udpEnds` only. The report does not keep the UDP side or reason,
    /// because a UDP flow has no half close. The report says so.
    mutating func recordEnd(_ transport: EstablishedTransport, end: EstablishedEnd,
                            at now: TimeInterval) {
        switch transport {
        case .tcp:
            switch end {
            case .clean: tcpClean += 1
            case .clientSocketError: tcpClientErrors += 1
            case .destinationSocketError: tcpDestinationErrors += 1
            case .idle: tcpIdle += 1
            case .other: tcpOther += 1
            }
        case .udp:
            udpEnds += 1
        }
        add(at: now) { bucket in
            switch transport {
            case .tcp:
                switch end {
                case .clean: bucket.tcpClean += 1
                case .clientSocketError: bucket.tcpClientErrors += 1
                case .destinationSocketError: bucket.tcpDestinationErrors += 1
                case .idle: bucket.tcpIdle += 1
                case .other: bucket.tcpOther += 1
                }
            case .udp:
                bucket.udpEnds += 1
            }
        }
    }

    /// The buckets in the window, newest first.
    func rows(now: TimeInterval) -> [EstablishedWindowRow] {
        let newest = Self.key(now)
        let oldest = newest - Self.windowBuckets + 1
        return buckets.keys.filter { $0 >= oldest && $0 <= newest }.sorted(by: >).map {
            EstablishedWindowRow(ageSeconds: (newest - $0) * Int(Self.bucketSeconds),
                                 bucket: buckets[$0] ?? EstablishedBucket())
        }
    }

    /// True before any relay started or ended.
    var isEmpty: Bool { buckets.isEmpty && tcpStarts == 0 && udpStarts == 0 }

    private mutating func add(at now: TimeInterval, _ change: (inout EstablishedBucket) -> Void) {
        let key = Self.key(now)
        let newest = max(newestBucket ?? key, key)
        if newestBucket != newest {
            newestBucket = newest
            let oldest = newest - Self.windowBuckets + 1
            buckets = buckets.filter { $0.key >= oldest }
        }
        // A late event outside the window still counts in the totals. It must
        // not reinsert a bucket that the window already dropped.
        let oldest = newest - Self.windowBuckets + 1
        guard key >= oldest else { return }
        var bucket = buckets[key] ?? EstablishedBucket()
        change(&bucket)
        buckets[key] = bucket
    }

    private static func key(_ now: TimeInterval) -> Int {
        Int(max(0, now) / bucketSeconds)
    }
}

/// The counters that the proxy server owns for the diagnostics report.
struct DiagnosticsCounters: Equatable {
    private(set) var buckets: [ConnectDurationBucket: Int] = [:]
    private(set) var waits = ConnectRetryPolicy.WaitCounts()
    /// Every wait in this run, by destination family. It holds no address.
    private(set) var waitsByFamily: [ConnectTargetFamily: Int] = [:]
    /// Every failed result in this run, by destination family.
    private(set) var failuresByFamily: [ConnectTargetFamily: Int] = [:]
    private(set) var retryStarts = 0
    private(set) var retrySuccesses = 0
    private(set) var deadlineFires = 0
    private(set) var peakSessions = 0
    private(set) var capRefusals = 0
    private(set) var relayRefusals = 0
    private(set) var evictions = 0
    private(set) var handshakeEvictions = 0
    private(set) var connectEvictions = 0
    private(set) var relayGrantEvictions = 0
    private(set) var udpEvictions = 0
    private(set) var halfClosedEvictions = 0
    private(set) var udpQueuePeak = 0
    private(set) var udpQueueDrops = 0
    /// Established relay starts and teardowns in bounded 10 second buckets.
    private(set) var established = EstablishedCounters()
    /// The startup value. It survives `reset`.
    private(set) var fileLimit: FileDescriptorLimit.Outcome?

    /// Clear the run counters. Keep the startup value.
    mutating func reset() {
        buckets.removeAll()
        waits = ConnectRetryPolicy.WaitCounts()
        waitsByFamily.removeAll()
        failuresByFamily.removeAll()
        retryStarts = 0
        retrySuccesses = 0
        deadlineFires = 0
        peakSessions = 0
        capRefusals = 0
        relayRefusals = 0
        evictions = 0
        handshakeEvictions = 0
        connectEvictions = 0
        relayGrantEvictions = 0
        udpEvictions = 0
        halfClosedEvictions = 0
        udpQueuePeak = 0
        udpQueueDrops = 0
        established.reset()
    }

    mutating func record(duration: TimeInterval) {
        buckets[ConnectDurationBucket.bucket(max(0, duration)), default: 0] += 1
    }

    /// Fold one attempt. `family` is the destination family. `failed` is true
    /// only for a result that did not work. A cancelled or closed attempt is
    /// not a failure.
    mutating func record(_ totals: ConnectRetryPolicy.Totals,
                         family: ConnectTargetFamily,
                         failed: Bool = false) {
        waits.add(totals.waits)
        waitsByFamily[family, default: 0] += totals.waits.total
        retryStarts += totals.retryStarts
        retrySuccesses += totals.retrySuccesses
        deadlineFires += totals.deadlineFires
        if failed { failuresByFamily[family, default: 0] += 1 }
    }

    /// Track the peak number of open sessions.
    mutating func recordSessionCount(_ count: Int) {
        peakSessions = max(peakSessions, max(0, count))
    }

    mutating func recordCapRefusal() { capRefusals += 1 }
    mutating func recordRelayRefusal() { relayRefusals += 1 }

    /// Count one capacity eviction. The reason names the phase bound that
    /// expired. No other reason closes a session for capacity.
    mutating func recordEviction(reason: SessionCapacity.CloseReason? = nil) {
        evictions += 1
        guard let reason = reason else { return }
        switch reason {
        case .handshakeExpired: handshakeEvictions += 1
        case .connectExpired: connectEvictions += 1
        case .relayGrantExpired: relayGrantEvictions += 1
        case .udpIdle: udpEvictions += 1
        case .halfClosedIdle: halfClosedEvictions += 1
        }
    }

    /// Fold in one session. The peak is the largest queue, the drops add up.
    mutating func recordUDPQueue(peak: Int, dropped: Int) {
        udpQueuePeak = max(udpQueuePeak, max(0, peak))
        udpQueueDrops += max(0, dropped)
    }

    mutating func recordFileLimit(_ outcome: FileDescriptorLimit.Outcome?) {
        fileLimit = outcome
    }

    mutating func recordEstablishedStart(_ transport: EstablishedTransport, at now: TimeInterval) {
        established.recordStart(transport, at: now)
    }

    mutating func recordEstablishedEnd(_ transport: EstablishedTransport, end: EstablishedEnd,
                                       at now: TimeInterval) {
        established.recordEnd(transport, end: end, at: now)
    }

    /// The counters with no environment values. The app fills the rest. `now`
    /// is monotonic seconds. It sets the age of each timeline bucket.
    func report(now: TimeInterval = 0) -> DiagnosticsReport {
        DiagnosticsReport(buckets: buckets, waits: waits, waitsByFamily: waitsByFamily,
                          failuresByFamily: failuresByFamily, retryStarts: retryStarts,
                          retrySuccesses: retrySuccesses, deadlineFires: deadlineFires,
                          peakSessions: peakSessions, capRefusals: capRefusals,
                          relayRefusals: relayRefusals, evictions: evictions,
                          handshakeEvictions: handshakeEvictions,
                          connectEvictions: connectEvictions,
                          relayGrantEvictions: relayGrantEvictions,
                          udpEvictions: udpEvictions,
                          halfClosedEvictions: halfClosedEvictions,
                          udpQueuePeak: udpQueuePeak,
                          udpQueueDrops: udpQueueDrops, established: established,
                          establishedRows: established.rows(now: now),
                          fileLimit: fileLimit)
    }
}

/// The plain text that "Copy diagnostics" writes to the pasteboard.
struct DiagnosticsReport: Equatable {
    static let header = "HotspotShade diagnostics"

    var connections = ConnectCounters()
    var buckets: [ConnectDurationBucket: Int] = [:]
    var waits = ConnectRetryPolicy.WaitCounts()
    var waitsByFamily: [ConnectTargetFamily: Int] = [:]
    var failuresByFamily: [ConnectTargetFamily: Int] = [:]
    var retryStarts = 0
    var retrySuccesses = 0
    var deadlineFires = 0
    var peakSessions = 0
    var capRefusals = 0
    var relayRefusals = 0
    var evictions = 0
    var handshakeEvictions = 0
    var connectEvictions = 0
    var relayGrantEvictions = 0
    var udpEvictions = 0
    var halfClosedEvictions = 0
    /// The effective session limit. nil means the runtime did not claim one.
    var sessionLimit: Int?
    /// The relay slots under the effective limit. nil means unknown.
    var relayLimit: Int?
    /// The setup slots under the effective limit. nil means unknown.
    var setupReserve: Int?
    /// The sessions in a setup phase now. They do not hold a relay slot.
    var setupSessions = 0
    /// The sessions that hold a relay slot now, including reserved slots.
    var relaySessions = 0
    /// The close callbacks still missing after the diagnostic delay.
    var unconfirmedCloses = 0
    var udpQueuePeak = 0
    var udpQueueDrops = 0
    var established = EstablishedCounters()
    var establishedRows: [EstablishedWindowRow] = []
    var fileLimit: FileDescriptorLimit.Outcome?
    var lowPowerMode = false
    var thermal: ThermalLevel = .nominal
    var locationHealth = ""
    var appVersion = "Unknown"
    var systemVersion = "Unknown"
    var proxyState = "Off"
    /// The plain attention line for the current proxy state. It is the same
    /// text that the Dashboard shows for a Start failure or a token problem.
    /// It holds no token and no address. Empty keeps the report unchanged.
    var proxyDetail = ""
    /// The source device capability lines. The app fills them from the iOS
    /// capability model. They are plain lines, so this file keeps no dependency
    /// on the Settings screen. Empty keeps the report unchanged.
    var capabilityLines: [String] = []

    /// The report text. One fact per line. The first line is the plain header.
    func text() -> String {
        var lines: [String] = [
            Self.header,
            "App \(appVersion). iOS \(systemVersion).",
            "Proxy: \(proxyState).",
            "Connections: \(connections.summary)"
        ]
        if !proxyDetail.isEmpty {
            lines.append("Proxy detail: \(proxyDetail)")
        }
        if let cancelled = connections.cancelledSummary {
            lines.append("Cancelled: \(cancelled)")
        }
        lines.append(connectTimeLine)
        lines.append(waitsLine)
        lines.append(familyLine)
        lines.append("Retries: \(retryStarts) started, \(retrySuccesses) worked.")
        lines.append("Deadline fires: \(deadlineFires).")
        lines.append(sessionLine)
        lines.append(capacityLine)
        if let warning = capacityWarning {
            lines.append("Capacity warning: \(warning)")
        }
        lines.append("UDP queue: peak \(udpQueuePeak). Dropped \(udpQueueDrops).")
        lines.append(establishedLine)
        lines.append(establishedEndLine)
        lines.append(establishedWindowLine)
        lines.append(fileLimit?.text ?? "File limit: unknown.")
        lines.append(fileBudgetLine)
        if unconfirmedCloses > 0 {
            lines.append("Unconfirmed closes: \(unconfirmedCloses).")
        }
        lines.append("Low Power Mode: \(lowPowerMode ? "On" : "Off").")
        lines.append("Thermal state: \(thermal.rawValue).")
        lines.append(locationHealth.isEmpty ? "Keep-awake: unknown." : "Keep-awake: \(locationHealth)")
        if !capabilityLines.isEmpty {
            lines.append(contentsOf: capabilityLines)
        }
        return lines.joined(separator: "\n")
    }

    /// One line with every duration bucket, in a fixed order.
    var connectTimeLine: String {
        let parts = ConnectDurationBucket.allCases.map { bucket in
            "\(buckets[bucket] ?? 0) \(bucket.label)"
        }
        return "Connect time: " + parts.joined(separator: ", ") + "."
    }

    /// The wait counts by error.
    var waitsLine: String {
        let total = waits.total
        guard total > 0 else { return "Waits: 0." }
        return "Waits: \(total) (\(waits.unreachable) unreachable, \(waits.refused) refused, \(waits.other) other)."
    }

    /// The wait and failure counts by destination family. The line holds no
    /// address, host, or port.
    var familyLine: String {
        "Waits by family: \(familyCounts(waitsByFamily)). "
            + "Failures by family: \(familyCounts(failuresByFamily))."
    }

    private func familyCounts(_ counts: [ConnectTargetFamily: Int]) -> String {
        ConnectTargetFamily.allCases.map { family in
            let count = counts[family] ?? 0
            return "\(count) \(family.label(count: count))"
        }.joined(separator: ", ")
    }

    /// The session peak, the effective limit, and the current split. A setup
    /// session holds no relay slot. A reserved relay slot counts as a relay.
    var sessionLine: String {
        let relayWord = relaySessions == 1 ? "relay" : "relays"
        guard let limit = sessionLimit else {
            let reason = fileLimit == nil ? "with an unknown limit"
                                          : "with no usable limit"
            return "Sessions: peak \(peakSessions) \(reason). "
                + "Now \(setupSessions) setup, \(relaySessions) \(relayWord)."
        }
        let split: String
        if let relay = relayLimit, let reserve = setupReserve {
            split = " (relay cap \(relay), setup reserve \(reserve))"
        } else {
            split = ""
        }
        return "Sessions: peak \(peakSessions) of \(limit)\(split). "
            + "Now \(setupSessions) setup, \(relaySessions) \(relayWord)."
    }

    /// The capacity refusals and the phase of every evicted session. An open
    /// TCP relay is never in this count.
    var capacityLine: String {
        "Capacity: connection refusals \(capRefusals). Relay refusals \(relayRefusals). "
            + "Evicted \(evictions): \(handshakeEvictions) handshake, "
            + "\(connectEvictions) connect, \(relayGrantEvictions) relay wait, "
            + "\(udpEvictions) UDP, \(halfClosedEvictions) half-closed."
    }

    /// The plain warning when the effective relay capacity is below the
    /// earlier baseline. It holds counts only.
    var capacityWarning: String? {
        SessionCapacity.capacityWarning(relayLimit: relayLimit)
    }

    /// Recompute the timeline ages for a report that was copied later. The
    /// snapshot ages are correct at publish time. The copy can happen many
    /// seconds later, so it must not show stale ages.
    mutating func refreshEstablishedRows(now: TimeInterval) {
        establishedRows = established.rows(now: now)
    }

    /// The open-file budget behind the session limit. It is a policy estimate,
    /// not a guarantee.
    var fileBudgetLine: String {
        "Open files: estimate \(SessionCapacity.socketsPerSession) for each session, "
            + "\(SessionCapacity.reservedFileDescriptors) reserved. "
            + "A stopped run counts until every close finishes."
    }

    /// The number of relay sessions that carried payload after the destination
    /// answered. It does not count setup attempts or a destination that only
    /// became ready.
    var establishedLine: String {
        if established.isEmpty { return "Established: no observation." }
        return "Established: \(established.tcpStarts) TCP relay starts, "
            + "\(established.udpStarts) UDP relay starts."
    }

    /// The established session ends by kind. A socket error is an error after
    /// the relay started. It is not proof of packet loss. A TCP end keeps its
    /// side and reason. A UDP end is a total only, so the line says that the
    /// side and reason are not kept.
    var establishedEndLine: String {
        "Established ends: \(established.tcpClean) clean, "
            + "\(established.tcpClientErrors) client socket errors, "
            + "\(established.tcpDestinationErrors) destination socket errors, "
            + "\(established.tcpIdle) idle, \(established.tcpOther) other, "
            + "\(established.udpEnds) UDP (side and reason not kept)."
    }

    /// The newest buckets with an end or a socket error. The line holds no
    /// address. Eight buckets keep the report short.
    var establishedWindowLine: String {
        let rows = establishedRows.filter { $0.bucket.hasTeardown }.prefix(8)
        guard !rows.isEmpty else {
            return "Established ends by 10 s bucket: none in the last 300 s."
        }
        let parts = rows.map { row in
            let b = row.bucket
            return "\(row.ageSeconds) s ago: \(b.tcpClean) clean, "
                + "\(b.tcpClientErrors) client errors, "
                + "\(b.tcpDestinationErrors) destination errors, \(b.tcpIdle) idle, "
                + "\(b.tcpOther) other, \(b.udpEnds) UDP"
        }
        return "Established ends by 10 s bucket: " + parts.joined(separator: "; ") + "."
    }
}
