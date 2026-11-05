import Foundation

// Pure decision logic for one outbound destination connection. This file uses
// Foundation only. The tests inject the clock. No code here opens a socket.
//
// Privacy: the log lines from this file name the flow kind and the result in
// plain words. They hold no host name, address, port, or elapsed time. The app
// shows them in the on-screen log only. The app never persists them, never
// sends them to the target device, and never writes them to a file.

/// The destination address family for the diagnostics. It holds no address,
/// host, or port. The target device already groups failures by family. These
/// source device counts also include waits, so a failure that the target
/// device never saw is still visible.
enum ConnectTargetFamily: String, CaseIterable {
    case ipv4
    case ipv6
    case name

    /// The label for the diagnostics report. A name is singular only for one.
    func label(count: Int) -> String {
        switch self {
        case .ipv4: return "IPv4"
        case .ipv6: return "IPv6"
        case .name: return count == 1 ? "name" : "names"
        }
    }

    /// Classify a destination host. A colon means an IPv6 literal. Four
    /// decimal octets mean an IPv4 literal. Everything else is a name.
    static func of(host: String) -> ConnectTargetFamily {
        if host.contains(":") { return .ipv6 }
        let parts = host.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return .name }
        for part in parts {
            guard !part.isEmpty, part.count <= 3, UInt8(part) != nil else {
                return .name
            }
        }
        return .ipv4
    }
}

/// The final conclusion of one attempt. The counters count only conclusions.
/// An attempt that ends before a conclusion is not a failure. The counters keep
/// it separate as `closedBeforeResult`.
struct ConnectConclusion: Equatable {
    /// The flow kind. Port 53 is a DNS lookup.
    enum Kind: Hashable { case web, otherTCP, udp, dnsLookup }

    /// Why an attempt did not work. `notReady` is a deadline after a wait on
    /// the path. `timedOut` is a deadline with no such wait. Neither reason
    /// proves that the destination is at fault. `other` covers an unknown
    /// error, including a local interface error.
    enum Reason: Hashable { case refused, notReady, timedOut, unreachable, other }

    /// A cancelled attempt is a final result. It is not a failure and not a
    /// success, because the target device gave up on the connection.
    enum Result: Equatable { case worked, slow, didNotWork, cancelled }

    let kind: Kind
    let result: Result
    /// Set only when `result` is `.didNotWork`.
    let reason: Reason?

    /// The reason in plain words. It does not claim that the tunnel failed.
    var reasonText: String { Self.reasonText(reason ?? .other) }

    static func reasonText(_ reason: Reason) -> String {
        switch reason {
        case .refused: return "Most common reason: the website refused the connection."
        case .notReady: return "Most common reason: the connection did not become ready in time."
        // A deadline with no definitive answer does not prove that the
        // destination was at fault.
        case .timedOut: return "Most common reason: the connection timed out."
        case .unreachable: return "Most common reason: the website could not be reached."
        case .other: return "Most common reason: something else went wrong."
        }
    }

    /// A plain line for the on-screen log. It names the kind and the reason in
    /// words. It holds no host, address, port, or count.
    static func logLine(kind: Kind, result: Result, reason: Reason?) -> String {
        let subject: String
        switch kind {
        case .web: subject = "A web connection"
        case .otherTCP: subject = "A connection to another service"
        case .udp: subject = "A UDP flow"
        case .dnsLookup: subject = "A name lookup"
        }
        switch result {
        case .worked: return "\(subject) worked."
        case .slow: return "\(subject) was slow."
        case .cancelled: return "\(subject) was cancelled by the target device."
        case .didNotWork:
            switch reason ?? .other {
            case .refused: return "\(subject) was refused."
            case .notReady: return "\(subject) did not become ready in time."
            case .timedOut: return "\(subject) timed out."
            case .unreachable:
                return kind == .dnsLookup ? "\(subject) did not finish." : "\(subject) could not be reached."
            case .other: return "\(subject) stopped with an error."
            }
        }
    }
}

/// One outbound connection attempt, from `start` until the SOCKS reply.
struct ConnectAttempt {
    /// The source device deadline. It starts when the connect request reaches
    /// the source device. The target device CONNECT timeout is 5 seconds and
    /// starts earlier. The target timer can fire first. The source deadline
    /// does not guarantee an answer before it.
    static let deadlineSeconds: TimeInterval = 4
    /// A connection that becomes ready later than this is logged as slow.
    static let slowSeconds: TimeInterval = 1.5

    enum Transport: String { case tcp, udp }

    /// An error from the network stack. `errno` is set for a POSIX error.
    struct Failure: Equatable {
        let errno: Int32?
        let description: String
    }

    enum Event: Equatable {
        case waiting(Failure)
        case ready
        case failed(Failure)
        case cancelled
        case deadline
    }

    enum Decision: Equatable {
        /// Do nothing.
        case none
        /// Send the SOCKS success reply and start the relay.
        case replySuccess
        /// Cancel the connection, send this SOCKS reply code, and close the session.
        case replyFailure(UInt8)
        /// The connection ended after the success reply. Close the session.
        case close
    }

    enum Outcome: Equatable { case ok, slow, failed, timedOut, cancelled }

    struct Result: Equatable {
        var decision: Decision
        /// A plain line for the on-screen log. It holds no destination.
        var log: String?
        /// Set once, when the attempt has a final result.
        var outcome: Outcome?
        /// The final result for the counters. Set with `outcome`.
        var conclusion: ConnectConclusion?
    }

    let transport: Transport
    let host: String
    let port: UInt16
    let startedAt: TimeInterval
    private(set) var replied = false
    private(set) var succeeded = false
    /// The last wait on the current connection. The deadline reply code uses
    /// it. A retry clears it.
    private(set) var lastWaiting: Failure?
    /// The last wait in the whole attempt. A retry keeps it, because the
    /// deadline reason belongs to the attempt.
    private(set) var attemptWaiting: Failure?

    init(transport: Transport, host: String, port: UInt16, startedAt: TimeInterval) {
        self.transport = transport
        self.host = host
        self.port = port
        self.startedAt = startedAt
    }

    /// Return the time at which the deadline fires.
    var deadline: TimeInterval { startedAt + Self.deadlineSeconds }

    /// Handle one event. After the first reply, no event causes a second reply.
    mutating func handle(_ event: Event, now: TimeInterval) -> Result {
        if replied {
            // After a failure reply, the session closes when the reply is sent.
            guard succeeded else { return Result(decision: .none) }
            switch event {
            case .failed, .cancelled: return Result(decision: .close)
            default: return Result(decision: .none)
            }
        }
        switch event {
        case .waiting(let failure):
            lastWaiting = failure
            attemptWaiting = failure
            return Result(decision: .none)
        case .ready:
            replied = true
            succeeded = true
            let slow = now - startedAt > Self.slowSeconds
            let conclusion = ConnectConclusion(kind: kind,
                                               result: slow ? .slow : .worked,
                                               reason: nil)
            if slow {
                return Result(decision: .replySuccess,
                              log: ConnectConclusion.logLine(kind: kind, result: .slow, reason: nil),
                              outcome: .slow,
                              conclusion: conclusion)
            }
            return Result(decision: .replySuccess, outcome: .ok, conclusion: conclusion)
        case .failed(let failure):
            replied = true
            let reason = Self.failureReason(failure)
            return Result(decision: .replyFailure(Self.failureCode(failure.errno)),
                          log: ConnectConclusion.logLine(kind: kind, result: .didNotWork, reason: reason),
                          outcome: .failed,
                          conclusion: ConnectConclusion(kind: kind, result: .didNotWork, reason: reason))
        case .cancelled:
            replied = true
            return Result(decision: .replyFailure(1),
                          log: ConnectConclusion.logLine(kind: kind, result: .cancelled, reason: nil),
                          outcome: .cancelled,
                          conclusion: ConnectConclusion(kind: kind, result: .cancelled, reason: nil))
        case .deadline:
            replied = true
            let reason = Self.deadlineReason(attemptWaiting)
            return Result(decision: .replyFailure(Self.deadlineCode(lastWaiting?.errno)),
                          log: ConnectConclusion.logLine(kind: kind, result: .didNotWork, reason: reason),
                          outcome: .timedOut,
                          conclusion: ConnectConclusion(kind: kind, result: .didNotWork, reason: reason))
        }
    }

    /// The kind of flow for the counters. Port 53 is a DNS lookup for TCP and UDP.
    var kind: ConnectConclusion.Kind {
        if port == 53 { return .dnsLookup }
        switch transport {
        case .udp: return .udp
        case .tcp: return port == 80 || port == 443 ? .web : .otherTCP
        }
    }

    /// The destination family for the diagnostics. It holds no address.
    var family: ConnectTargetFamily { ConnectTargetFamily.of(host: host) }

    /// Start a new connection for the same attempt. The old connection may
    /// have reported a wait. The new connection has its own wait for the reply
    /// code, so `lastWaiting` is cleared. The deadline reason belongs to the
    /// whole attempt, so `attemptWaiting` stays. A deadline after a retry
    /// still reports `notReady` when the attempt waited.
    mutating func retryStarted() {
        lastWaiting = nil
    }

    /// The reason for a failure that ended the attempt before a reply. A local
    /// interface error is not a destination failure. `ENETDOWN` and
    /// `EHOSTDOWN` say that the cellular path on this device is down. They use
    /// `other`, not `unreachable`.
    static func failureReason(_ failure: Failure?) -> ConnectConclusion.Reason {
        guard let errno = failure?.errno else { return .other }
        if errno == ECONNREFUSED { return .refused }
        return isDestinationUnreachable(errno) ? .unreachable : .other
    }

    /// The reason for a deadline. A waiting error is not a final state. An
    /// unreachable wait can come from a short cellular path change. A local
    /// interface error is also a wait. Neither proves that the website is
    /// unreachable, and neither proves that the website was slow. Report
    /// `notReady` instead. A refusal is an answer from the network, so it
    /// keeps the refused reason.
    static func deadlineReason(_ failure: Failure?) -> ConnectConclusion.Reason {
        guard let errno = failure?.errno else { return .timedOut }
        if errno == ECONNREFUSED { return .refused }
        return isWaitPathError(errno) ? .notReady : .timedOut
    }

    /// A destination network or host that reported unreachable.
    static func isDestinationUnreachable(_ errno: Int32?) -> Bool {
        switch errno {
        case ENETUNREACH, EHOSTUNREACH: return true
        default: return false
        }
    }

    /// The local cellular interface is down. This is not a destination
    /// failure. The target device still has a working path to the source
    /// device, so an unreachable SOCKS reply would blame the wrong side.
    static func isLocalLinkDown(_ errno: Int32?) -> Bool {
        switch errno {
        case ENETDOWN, EHOSTDOWN: return true
        default: return false
        }
    }

    /// A wait that can come from a path change on either side.
    private static func isWaitPathError(_ errno: Int32) -> Bool {
        isDestinationUnreachable(errno) || isLocalLinkDown(errno)
    }

    /// The reply code when the deadline fires. Code 5 (connection refused) for
    /// ECONNREFUSED, because a refusal is an answer from the network. Code 1
    /// (general failure) for every other case, because a deadline does not
    /// prove that the destination is unreachable. Code 4 would blame the
    /// destination and would make the target device record an unreachable
    /// host. A real unreachable failure still uses code 4.
    static func deadlineCode(_ errno: Int32?) -> UInt8 {
        errno == ECONNREFUSED ? 5 : 1
    }

    /// The reply code for a failed connection. Code 4 for a destination
    /// network or host that reported unreachable. Code 5 for a refusal,
    /// because the destination answered. Code 1 (general failure) for every
    /// other error, including a local interface error (`ENETDOWN` or
    /// `EHOSTDOWN`), a DNS error, a reset, or a local permission error. A
    /// local error does not prove that the destination is unreachable or that
    /// it refused the connection.
    static func failureCode(_ errno: Int32?) -> UInt8 {
        switch errno {
        case ECONNREFUSED: return 5
        case ENETUNREACH, EHOSTUNREACH: return 4
        default: return 1
        }
    }
}

/// Limit the connect log lines so a burst of failures cannot flood the log.
/// Each window admits `limit` lines. The first line after the window reports
/// how many lines it suppressed.
struct ConnectLogLimiter {
    let limit: Int
    let window: TimeInterval
    private(set) var windowStart: TimeInterval?
    private(set) var admitted = 0
    private(set) var suppressed = 0

    init(limit: Int = 8, window: TimeInterval = 10) {
        precondition(limit > 0 && window > 0)
        self.limit = limit
        self.window = window
    }

    /// Return the lines to show now. The result is empty when the line is suppressed.
    mutating func submit(_ line: String, now: TimeInterval) -> [String] {
        var out: [String] = []
        if let start = windowStart, now - start < window {
            // Same window.
        } else {
            if let summary = flushLine() { out.append(summary) }
            windowStart = now
            admitted = 0
        }
        if admitted < limit {
            admitted += 1
            out.append(line)
        } else {
            suppressed += 1
        }
        return out
    }

    /// Return the summary line when the window has ended and lines were suppressed.
    mutating func flush(now: TimeInterval) -> String? {
        guard let start = windowStart, now - start >= window else { return nil }
        let line = flushLine()
        windowStart = nil
        admitted = 0
        return line
    }

    /// The time at which a pending summary is due, or nil when none is pending.
    var flushDue: TimeInterval? {
        guard suppressed > 0, let start = windowStart else { return nil }
        return start + window
    }

    private mutating func flushLine() -> String? {
        guard suppressed > 0 else { return nil }
        let count = suppressed
        suppressed = 0
        return count == 1 ? "1 more connect log line suppressed" : "\(count) more connect log lines suppressed"
    }
}

/// Aggregate connection counters. They hold no addresses. One attempt ends in
/// exactly one of these states, so the full ledger is:
///
///     attempts = worked + failed + cancelled + closedBeforeResult + pending
///
/// `worked` includes slow results. `failed` is "did not work". A cancelled
/// attempt is not a failure and is not a success: the target device gave up on
/// the connection. An attempt that ends before a result is not a failure. The
/// counters keep it in `closedBeforeResult`. The first line counts the finished
/// attempts: worked + failed + cancelled.
struct ConnectCounters: Equatable {
    /// The number of attempts that started.
    private(set) var started = 0
    /// Final results that worked.
    private(set) var worked = 0
    /// Worked, and took longer than the slow threshold.
    private(set) var slow = 0
    /// Final results that did not work.
    private(set) var failed = 0
    /// Final results that the target device cancelled.
    private(set) var cancelled = 0
    /// Attempts that ended before a result. They are not failures.
    private(set) var closedBeforeResult = 0
    /// Attempts that are still in flight.
    private(set) var pending = 0
    /// Every final result by kind, including worked and cancelled results.
    private(set) var byKind: [ConnectConclusion.Kind: Int] = [:]
    /// The failed results by kind. This feeds the "Did not work" line.
    private(set) var failedByKind: [ConnectConclusion.Kind: Int] = [:]
    /// The failed results by reason. A cancelled result is not here.
    private(set) var byReason: [ConnectConclusion.Reason: Int] = [:]

    mutating func recordStart() {
        started += 1
        pending += 1
    }

    mutating func record(_ conclusion: ConnectConclusion) {
        pending = max(0, pending - 1)
        byKind[conclusion.kind, default: 0] += 1
        switch conclusion.result {
        case .worked:
            worked += 1
        case .slow:
            worked += 1
            slow += 1
        case .didNotWork:
            failed += 1
            failedByKind[conclusion.kind, default: 0] += 1
            byReason[conclusion.reason ?? .other, default: 0] += 1
        case .cancelled:
            cancelled += 1
        }
    }

    /// The session closed before the attempt had a result. This is not a failure.
    mutating func recordClosedBeforeResult() {
        closedBeforeResult += 1
        pending = max(0, pending - 1)
    }

    /// The attempts with a final result. A pending or closed attempt has none.
    var finished: Int { worked + failed + cancelled }

    /// The first line: attempts, worked, and did not work. It never shows
    /// "0 worked" while an attempt is still in flight. A cancelled attempt is
    /// in the attempt count, but it is not in either result count.
    var summary: String {
        if started == 0 && closedBeforeResult == 0 { return "No connections yet." }
        if finished == 0 { return "No finished connections yet." }
        let attempts = "\(finished) \(finished == 1 ? "attempt" : "attempts")"
        return "\(attempts). \(worked) worked. \(failed) did not."
    }

    /// The line for cancelled attempts. It is nil when none were cancelled.
    /// A cancelled connection is one that the target device gave up on.
    var cancelledSummary: String? {
        guard cancelled > 0 else { return nil }
        return cancelled == 1
            ? "1 was cancelled by the target device."
            : "\(cancelled) were cancelled by the target device."
    }

    /// The line for the failed results by kind. It is nil when none failed.
    var failureKindSummary: String? {
        ConnectSummary.didNotWorkKinds(failedByKind)
    }

    /// The largest failed reason in plain words. It is nil when nothing failed.
    /// A cancelled attempt is not a failure, so it never selects this line.
    var reasonSummary: String? {
        guard failed > 0 else { return nil }
        let order: [ConnectConclusion.Reason] = [.refused, .notReady, .timedOut, .unreachable, .other]
        var best: (reason: ConnectConclusion.Reason, count: Int)?
        for reason in order {
            let count = byReason[reason] ?? 0
            if count > (best?.count ?? 0) { best = (reason, count) }
        }
        guard let best = best, best.count > 0 else { return nil }
        if best.reason == .unreachable, topFailedKind == .dnsLookup {
            return "Most common reason: the name lookup did not finish."
        }
        return ConnectConclusion.reasonText(best.reason)
    }

    /// The most common failed kind. A tie uses `ConnectSummary.kindOrder`.
    private var topFailedKind: ConnectConclusion.Kind? {
        var best: (kind: ConnectConclusion.Kind, count: Int)?
        for kind in ConnectSummary.kindOrder {
            let count = failedByKind[kind] ?? 0
            if count > (best?.count ?? 0) { best = (kind, count) }
        }
        guard let best = best, best.count > 0 else { return nil }
        return best.kind
    }
}
