import Foundation

@main
struct ConnectWatchTests {
    static func check(_ condition: Bool, _ message: String, line: Int = #line) {
        if !condition {
            print("FAIL line \(line): \(message)")
            exit(1)
        }
    }

    static func attempt(_ transport: ConnectAttempt.Transport = .tcp, host: String = "example.net",
                        port: UInt16 = 443) -> ConnectAttempt {
        ConnectAttempt(transport: transport, host: host, port: port, startedAt: 100)
    }

    static func main() {
        let unreachable = ConnectAttempt.Failure(errno: ENETUNREACH, description: "Network is unreachable")
        let hostUnreachable = ConnectAttempt.Failure(errno: EHOSTUNREACH, description: "No route to host")
        let localDown = ConnectAttempt.Failure(errno: ENETDOWN, description: "Network is down")
        let localHostDown = ConnectAttempt.Failure(errno: EHOSTDOWN, description: "Host is down")
        let refused = ConnectAttempt.Failure(errno: ECONNREFUSED, description: "Connection refused")

        // The source device deadline is 4 seconds. The target device CONNECT
        // timeout is 5 seconds and starts earlier. The source deadline cannot
        // guarantee an answer before it.
        check(ConnectAttempt.deadlineSeconds == 4, "deadline is 4 s")
        check(attempt().deadline == 104, "deadline time")

        // The diagnostics classify the destination family. They keep no
        // address, host, or port.
        check(ConnectTargetFamily.of(host: "203.0.113.9") == .ipv4, "ipv4 family")
        check(ConnectTargetFamily.of(host: "2001:db8::1") == .ipv6, "ipv6 family")
        check(ConnectTargetFamily.of(host: "example.net") == .name, "name family")
        check(ConnectTargetFamily.of(host: "999.1.1.1") == .name, "an invalid octet is a name")
        check(ConnectTargetFamily.of(host: "::ffff:203.0.113.9") == .ipv6,
              "a mapped address is ipv6")
        check(attempt(host: "2001:db8::1").family == .ipv6, "attempt family")
        check(ConnectTargetFamily.ipv4.label(count: 1) == "IPv4", "ipv4 label")
        check(ConnectTargetFamily.name.label(count: 1) == "name", "one name label")
        check(ConnectTargetFamily.name.label(count: 2) == "names", "two names label")

        // Ready before the deadline: one success reply, no log, outcome ok.
        var fast = attempt()
        let ready = fast.handle(.ready, now: 100.2)
        check(ready == .init(decision: .replySuccess, log: nil, outcome: .ok,
                             conclusion: ConnectConclusion(kind: .web, result: .worked, reason: nil)),
              "fast ready")
        check(fast.handle(.deadline, now: 104) == .init(decision: .none), "deadline after ready does nothing")
        check(fast.handle(.ready, now: 104.5) == .init(decision: .none), "second ready does nothing")

        // Slow ready: success reply and one slow line. It still counts as worked.
        var slow = attempt()
        let slowResult = slow.handle(.ready, now: 102.3)
        check(slowResult.decision == .replySuccess, "slow ready replies success")
        check(slowResult.outcome == .slow, "slow outcome")
        check(slowResult.log == "A web connection was slow.", "slow line: \(slowResult.log ?? "nil")")
        check(slowResult.conclusion == ConnectConclusion(kind: .web, result: .slow, reason: nil), "slow conclusion")
        // Exactly at the threshold is not slow.
        var edge = attempt()
        check(edge.handle(.ready, now: 101.5).outcome == .ok, "1500 ms is not slow")

        // Waiting, then the deadline: code 1 (general failure), because an
        // unreachable wait is not proof that the website failed. A short
        // cellular path change is not an unreachable destination.
        var waiting = attempt()
        check(waiting.handle(.waiting(unreachable), now: 100.1) == .init(decision: .none), "waiting does not reply")
        let notReady = waiting.handle(.deadline, now: 104)
        check(notReady.decision == .replyFailure(1), "waiting maps to code 1")
        check(notReady.outcome == .timedOut, "timed out outcome")
        check(notReady.conclusion == ConnectConclusion(kind: .web, result: .didNotWork, reason: .notReady),
              "a wait alone reports notReady")
        check(notReady.log == "A web connection did not become ready in time.", "notReady line: \(notReady.log ?? "nil")")
        // Only a real failure state reports an unreachable destination.
        var realUnreachable = attempt()
        check(realUnreachable.handle(.failed(unreachable), now: 100.2).conclusion?.reason == .unreachable,
              "a real unreachable failure reports unreachable")
        check(ConnectAttempt.deadlineReason(unreachable) == .notReady, "a deadline keeps an unreachable wait separate")
        check(ConnectAttempt.deadlineReason(nil) == .timedOut, "no wait is a timeout")
        check(ConnectAttempt.deadlineReason(refused) == .refused, "a refused wait keeps refused")
        check(ConnectAttempt.deadlineReason(localDown) == .notReady,
              "a local interface wait is not ready")
        let timedOutWait = ConnectAttempt.Failure(errno: ETIMEDOUT, description: "Timed out")
        check(ConnectAttempt.deadlineReason(timedOutWait) == .timedOut, "a non-unreachable wait is a timeout")
        // A local interface error is not a destination that reported
        // unreachable.
        check(ConnectAttempt.isDestinationUnreachable(ENETUNREACH)
                && ConnectAttempt.isDestinationUnreachable(EHOSTUNREACH),
              "only a destination network or host is unreachable")
        check(!ConnectAttempt.isDestinationUnreachable(ENETDOWN)
                && !ConnectAttempt.isDestinationUnreachable(EHOSTDOWN),
              "a local interface error is not a destination failure")
        check(ConnectAttempt.isLocalLinkDown(ENETDOWN) && ConnectAttempt.isLocalLinkDown(EHOSTDOWN),
              "the local interface errors are known")
        check(!ConnectAttempt.isLocalLinkDown(ENETUNREACH), "a destination error is not local")
        check(waiting.handle(.cancelled, now: 104.1) == .init(decision: .none), "cancel after failure reply does nothing")
        check(waiting.handle(.ready, now: 104.2) == .init(decision: .none), "ready after failure reply does nothing")

        // No state change before the deadline: code 1, "no response".
        var silent = attempt(.udp)
        let silentResult = silent.handle(.deadline, now: 104)
        check(silentResult.decision == .replyFailure(1), "no state change maps to code 1")
        check(silentResult.log == "A UDP flow timed out.", "silent line: \(silentResult.log ?? "nil")")
        check(silentResult.conclusion == ConnectConclusion(kind: .udp, result: .didNotWork, reason: .timedOut),
              "a silent wait reports a timeout")

        // Refused while waiting maps to code 5 at the deadline, with the refused reason.
        var refusedWait = attempt()
        _ = refusedWait.handle(.waiting(unreachable), now: 100.1)
        _ = refusedWait.handle(.waiting(refused), now: 100.2)
        let refusedDeadline = refusedWait.handle(.deadline, now: 104)
        check(refusedDeadline.decision == .replyFailure(5), "refused maps to code 5")
        check(refusedDeadline.conclusion?.reason == .refused, "refused at the deadline")
        check(ConnectAttempt.deadlineCode(ECONNREFUSED) == 5, "deadline code refused")
        check(ConnectAttempt.deadlineCode(nil) == 1, "deadline code none")

        // A retry starts a new connection inside the same attempt. The wait
        // stays with the attempt, so a deadline after the retry still reports
        // not ready. It must not become a plain timeout.
        var retried = attempt()
        _ = retried.handle(.waiting(unreachable), now: 100.1)
        retried.retryStarted()
        check(retried.lastWaiting == nil, "a retry clears the current connection wait")
        check(retried.attemptWaiting == unreachable, "a retry keeps the attempt wait")
        let retriedDeadline = retried.handle(.deadline, now: 104)
        check(retriedDeadline.decision == .replyFailure(1),
              "a retry deadline is a general failure")
        check(retriedDeadline.conclusion?.reason == .notReady,
              "a retry keeps the wait for the deadline reason")
        // A wait on the new connection replaces the old wait.
        var retriedWait = attempt()
        _ = retriedWait.handle(.waiting(unreachable), now: 100.1)
        retriedWait.retryStarted()
        _ = retriedWait.handle(.waiting(refused), now: 101)
        let retriedWaitDeadline = retriedWait.handle(.deadline, now: 104)
        check(retriedWaitDeadline.conclusion?.reason == .refused,
              "a wait after the retry is used")
        // The reply code uses the current connection only. A refusal on the
        // old connection must not become a refusal reply after a retry that
        // never answered.
        var retriedRefused = attempt()
        _ = retriedRefused.handle(.waiting(refused), now: 100.1)
        retriedRefused.retryStarted()
        let retriedRefusedDeadline = retriedRefused.handle(.deadline, now: 104)
        check(retriedRefusedDeadline.decision == .replyFailure(1),
              "a retry does not send a stale refusal code")
        check(retriedRefusedDeadline.conclusion?.reason == .refused,
              "the attempt keeps the refused wait reason")

        // A failure before ready replies once, with the mapped code.
        var failedRefused = attempt()
        let failedResult = failedRefused.handle(.failed(refused), now: 100.05)
        check(failedResult.decision == .replyFailure(5), "failed refused is code 5")
        check(failedResult.outcome == .failed, "failed outcome")
        check(failedResult.conclusion == ConnectConclusion(kind: .web, result: .didNotWork, reason: .refused),
              "refused conclusion")
        check(failedResult.log == "A web connection was refused.", "failed line: \(failedResult.log ?? "nil")")
        check(failedRefused.handle(.deadline, now: 104) == .init(decision: .none), "deadline after failure reply does nothing")
        var failedUnreachable = attempt()
        let unreachableResult = failedUnreachable.handle(.failed(unreachable), now: 101)
        check(unreachableResult.decision == .replyFailure(4), "unreachable is code 4")
        check(unreachableResult.conclusion?.reason == .unreachable, "unreachable conclusion")
        check(ConnectAttempt.failureCode(nil) == 1, "an unknown failure is a general failure")
        check(ConnectAttempt.failureCode(EACCES) == 1, "a local error is a general failure")
        check(ConnectAttempt.failureCode(refused.errno) == 5, "a refusal is code 5")
        check(ConnectAttempt.failureCode(ENETUNREACH) == 4, "a destination network error is code 4")
        check(ConnectAttempt.failureCode(EHOSTUNREACH) == 4, "a destination host error is code 4")
        // A local interface error does not prove that the destination is
        // unreachable. Code 4 would blame the destination.
        check(ConnectAttempt.failureCode(localDown.errno) == 1,
              "a local network down error is a general failure")
        check(ConnectAttempt.failureCode(localHostDown.errno) == 1,
              "a local host down error is a general failure")
        check(ConnectAttempt.failureReason(nil) == .other, "unknown reason")
        check(ConnectAttempt.failureReason(ConnectAttempt.Failure(errno: EACCES, description: "Denied")) == .other,
              "other errno")
        check(ConnectAttempt.failureReason(localDown) == .other,
              "a local interface error is not an unreachable destination")
        check(ConnectAttempt.failureReason(hostUnreachable) == .unreachable,
              "a destination host error is unreachable")
        var failedLocal = attempt()
        let localResult = failedLocal.handle(.failed(localDown), now: 100.1)
        check(localResult.decision == .replyFailure(1),
              "a local interface failure is a general failure")
        check(localResult.conclusion?.reason == .other,
              "a local interface failure does not blame the destination")

        // A cancellation is a final result. It is not a failure and not a success.
        var cancelled = attempt()
        let cancelledResult = cancelled.handle(.cancelled, now: 100.5)
        check(cancelledResult.outcome == .cancelled, "cancel outcome")
        check(cancelledResult.conclusion == ConnectConclusion(kind: .web, result: .cancelled, reason: nil),
              "cancel conclusion")
        check(cancelledResult.log == "A web connection was cancelled by the target device.",
              "cancel line: \(cancelledResult.log ?? "nil")")

        // A failure after ready closes the session and never replies again.
        var late = attempt()
        _ = late.handle(.ready, now: 100.1)
        check(late.handle(.failed(unreachable), now: 110) == .init(decision: .close), "failure after ready closes")
        check(late.handle(.cancelled, now: 111) == .init(decision: .close), "cancel after ready closes")

        // The log line never holds the host, the address, the port, or a count.
        var six = ConnectAttempt(transport: .tcp, host: "2001:db8::1", port: 80, startedAt: 0)
        let sixLine = six.handle(.deadline, now: 4).log ?? ""
        check(sixLine == "A web connection timed out.", "ipv6 line: \(sixLine)")
        check(!sixLine.contains("2001") && !sixLine.contains("80"), "the line holds no destination")
        var ip = ConnectAttempt(transport: .tcp, host: "203.0.113.9", port: 8443, startedAt: 0)
        let ipLine = ip.handle(.failed(refused), now: 0.1).log ?? ""
        check(ipLine == "A connection to another service was refused.", "ipv4 line: \(ipLine)")
        check(!ipLine.contains(where: \.isNumber), "the line holds no address or port: \(ipLine)")

        // Every log line uses words only. No address, port, or count.
        let allKinds: [ConnectConclusion.Kind] = [.web, .otherTCP, .udp, .dnsLookup]
        let allReasons: [ConnectConclusion.Reason] = [.refused, .notReady, .timedOut, .unreachable, .other]
        for kind in allKinds {
            for result in [ConnectConclusion.Result.worked, .slow, .cancelled] {
                let line = ConnectConclusion.logLine(kind: kind, result: result, reason: nil)
                check(!line.contains(where: \.isNumber), "no digit in log line: \(line)")
            }
            for reason in allReasons {
                let line = ConnectConclusion.logLine(kind: kind, result: .didNotWork, reason: reason)
                check(!line.contains(where: \.isNumber), "no digit in log line: \(line)")
                check(!line.contains(":"), "no address in log line: \(line)")
            }
        }

        // The kind comes from the flow, and port 53 is a DNS lookup.
        check(attempt().kind == .web, "tcp 443 is web")
        check(attempt(port: 80).kind == .web, "tcp 80 is web")
        check(attempt(port: 8080).kind == .otherTCP, "tcp 8080 is other TCP")
        check(attempt(.udp).kind == .udp, "udp is udp")
        check(attempt(port: 53).kind == .dnsLookup, "tcp 53 is a DNS lookup")
        check(attempt(.udp, port: 53).kind == .dnsLookup, "udp 53 is a DNS lookup")

        // Exactly one reply across any event sequence, and one conclusion per reply.
        let events: [ConnectAttempt.Event] = [.waiting(unreachable), .ready, .failed(refused), .cancelled, .deadline]
        for first in events {
            for second in events {
                for third in events {
                    var a = attempt()
                    var replies = 0
                    var outcomes = 0
                    var conclusions = 0
                    for (index, event) in [first, second, third].enumerated() {
                        let result = a.handle(event, now: 100 + Double(index))
                        switch result.decision {
                        case .replySuccess, .replyFailure: replies += 1
                        default: break
                        }
                        if result.outcome != nil { outcomes += 1 }
                        if result.conclusion != nil { conclusions += 1 }
                    }
                    let onlyWaiting = [first, second, third].allSatisfy {
                        if case .waiting = $0 { return true } else { return false }
                    }
                    check(replies == (onlyWaiting ? 0 : 1), "exactly one reply for \([first, second, third])")
                    check(outcomes == replies, "one outcome per reply")
                    check(conclusions == replies, "one conclusion per reply")
                }
            }
        }

        // Rate limiter: 8 lines per 10 seconds, then a summary line.
        var limiter = ConnectLogLimiter()
        var shown: [String] = []
        for i in 0..<20 { shown += limiter.submit("line \(i)", now: 200 + Double(i) * 0.1) }
        check(shown == (0..<8).map { "line \($0)" }, "first 8 lines pass: \(shown)")
        check(limiter.suppressed == 12, "12 lines suppressed")
        check(limiter.flushDue == 210, "flush due at window end")
        check(limiter.flush(now: 209.9) == nil, "no flush inside the window")
        check(limiter.flush(now: 210) == "12 more connect log lines suppressed", "flush summary")
        check(limiter.flushDue == nil, "nothing pending after flush")
        check(limiter.flush(now: 230) == nil, "no second summary")
        // A new window admits lines again.
        check(limiter.submit("next", now: 231) == ["next"], "new window admits")
        // A suppressed line followed by a line in the next window: summary first.
        var limiter2 = ConnectLogLimiter(limit: 1, window: 10)
        check(limiter2.submit("a", now: 0) == ["a"], "first line")
        check(limiter2.submit("b", now: 1).isEmpty, "second line suppressed")
        check(limiter2.submit("c", now: 10) == ["1 more connect log line suppressed", "c"], "summary before next line")
        // No summary when nothing was suppressed.
        var limiter3 = ConnectLogLimiter()
        _ = limiter3.submit("x", now: 0)
        check(limiter3.flushDue == nil, "no pending summary")
        check(limiter3.flush(now: 20) == nil, "no summary line")

        // Counters count final results only. The summary holds no addresses.
        var counters = ConnectCounters()
        for _ in 0..<5 { counters.recordStart() }
        counters.record(ConnectConclusion(kind: .web, result: .worked, reason: nil))
        counters.record(ConnectConclusion(kind: .web, result: .worked, reason: nil))
        counters.record(ConnectConclusion(kind: .dnsLookup, result: .slow, reason: nil))
        counters.record(ConnectConclusion(kind: .otherTCP, result: .didNotWork, reason: .refused))
        counters.record(ConnectConclusion(kind: .udp, result: .didNotWork, reason: .timedOut))
        check(counters.started == 5, "started")
        check(counters.worked == 3 && counters.slow == 1, "worked includes slow")
        check(counters.failed == 2, "did not work")
        check(counters.cancelled == 0, "no cancellations")
        check(counters.closedBeforeResult == 0 && counters.pending == 0, "no leftovers")
        check(counters.finished == 5, "five finished attempts")
        check(counters.summary == "5 attempts. 3 worked. 2 did not.", "summary: \(counters.summary)")
        check(counters.byKind == [.web: 2, .dnsLookup: 1, .otherTCP: 1, .udp: 1], "kinds: \(counters.byKind)")
        check(counters.failedByKind == [.otherTCP: 1, .udp: 1], "failed kinds: \(counters.failedByKind)")
        check(counters.byReason == [.refused: 1, .timedOut: 1], "reasons: \(counters.byReason)")
        check(counters.cancelledSummary == nil, "no cancelled line")
        // A tie uses the fixed reason order.
        check(counters.reasonSummary == "Most common reason: the website refused the connection.",
              "tie summary: \(counters.reasonSummary ?? "nil")")
        // A tie uses the fixed kind order: web, other TCP, UDP, DNS lookup.
        check(counters.failureKindSummary == "Did not work: 1 other connection, 1 UDP.",
              "kind summary: \(counters.failureKindSummary ?? "nil")")

        // A cancelled attempt is its own bucket. It is in no result total.
        var mixed = ConnectCounters()
        for _ in 0..<4 { mixed.recordStart() }
        mixed.record(ConnectConclusion(kind: .web, result: .worked, reason: nil))
        mixed.record(ConnectConclusion(kind: .web, result: .didNotWork, reason: .refused))
        mixed.record(ConnectConclusion(kind: .web, result: .cancelled, reason: nil))
        mixed.record(ConnectConclusion(kind: .dnsLookup, result: .cancelled, reason: nil))
        check(mixed.worked == 1 && mixed.failed == 1 && mixed.cancelled == 2, "three result buckets")
        check(mixed.finished == 4, "cancelled attempts are finished")
        check(mixed.summary == "4 attempts. 1 worked. 1 did not.", "mixed summary: \(mixed.summary)")
        check(mixed.cancelledSummary == "2 were cancelled by the target device.",
              "cancelled line: \(mixed.cancelledSummary ?? "nil")")
        check(mixed.failureKindSummary == "Did not work: 1 web.",
              "failed kinds exclude cancelled: \(mixed.failureKindSummary ?? "nil")")
        check(mixed.reasonSummary == "Most common reason: the website refused the connection.",
              "reason ignores cancelled: \(mixed.reasonSummary ?? "nil")")
        check(mixed.byReason == [.refused: 1], "cancelled is not a failed reason")
        var oneCancelled = ConnectCounters()
        oneCancelled.recordStart()
        oneCancelled.record(ConnectConclusion(kind: .web, result: .cancelled, reason: nil))
        check(oneCancelled.cancelledSummary == "1 was cancelled by the target device.",
              "one cancelled line: \(oneCancelled.cancelledSummary ?? "nil")")
        check(oneCancelled.summary == "1 attempt. 0 worked. 0 did not.", "cancel-only summary")
        check(oneCancelled.reasonSummary == nil, "a cancelled attempt has no failed reason")

        // The in-flight case does not claim that zero worked.
        var live = ConnectCounters()
        live.recordStart()
        live.recordStart()
        check(live.summary == "No finished connections yet.", "in-flight summary: \(live.summary)")
        check(live.reasonSummary == nil, "no reason while in flight")
        check(live.failureKindSummary == nil, "no kind breakdown while in flight")
        live.record(ConnectConclusion(kind: .web, result: .worked, reason: nil))
        check(live.summary == "1 attempt. 1 worked. 0 did not.", "one finished: \(live.summary)")
        check(live.pending == 1, "one still in flight")

        // A session that closes before a result is not a failure.
        var closed = ConnectCounters()
        closed.recordStart()
        closed.recordClosedBeforeResult()
        check(closed.closedBeforeResult == 1, "closed before a result")
        check(closed.failed == 0 && closed.worked == 0, "not a failure")
        check(closed.summary == "No finished connections yet.", "closed summary: \(closed.summary)")

        // The largest reason wins when it is clear.
        var reasons = ConnectCounters()
        for _ in 0..<3 { reasons.recordStart() }
        reasons.record(ConnectConclusion(kind: .web, result: .didNotWork, reason: .timedOut))
        reasons.record(ConnectConclusion(kind: .web, result: .didNotWork, reason: .timedOut))
        reasons.record(ConnectConclusion(kind: .web, result: .didNotWork, reason: .refused))
        check(reasons.reasonSummary == "Most common reason: the connection timed out.",
              "largest reason: \(reasons.reasonSummary ?? "nil")")
        // A deadline with no definitive answer does not blame the website.
        check(!ConnectConclusion.reasonText(.timedOut).lowercased().contains("website"),
              "a timeout does not blame the website")
        check(!ConnectConclusion.logLine(kind: .web, result: .didNotWork, reason: .timedOut)
                .lowercased().contains("website"),
              "a timeout log line does not blame the website")
        check(ConnectConclusion.reasonText(.unreachable) == "Most common reason: the website could not be reached.", "unreachable text")
        check(ConnectConclusion.reasonText(.notReady) == "Most common reason: the connection did not become ready in time.", "notReady text")
        check(ConnectConclusion.reasonText(.other) == "Most common reason: something else went wrong.", "other text")

        // A deadline after an unreachable wait is not a slow website. It is a
        // connection that did not become ready. The report says so.
        var notReadyCounters = ConnectCounters()
        for _ in 0..<3 { notReadyCounters.recordStart() }
        notReadyCounters.record(ConnectConclusion(kind: .web, result: .didNotWork, reason: .notReady))
        notReadyCounters.record(ConnectConclusion(kind: .web, result: .didNotWork, reason: .notReady))
        notReadyCounters.record(ConnectConclusion(kind: .web, result: .didNotWork, reason: .refused))
        check(notReadyCounters.reasonSummary == "Most common reason: the connection did not become ready in time.",
              "notReady summary: \(notReadyCounters.reasonSummary ?? "nil")")

        // An unreachable DNS lookup says that the name lookup did not finish.
        var dns = ConnectCounters()
        for _ in 0..<3 { dns.recordStart() }
        dns.record(ConnectConclusion(kind: .dnsLookup, result: .didNotWork, reason: .unreachable))
        dns.record(ConnectConclusion(kind: .dnsLookup, result: .didNotWork, reason: .unreachable))
        dns.record(ConnectConclusion(kind: .web, result: .didNotWork, reason: .refused))
        check(dns.reasonSummary == "Most common reason: the name lookup did not finish.",
              "dns reason: \(dns.reasonSummary ?? "nil")")
        check(dns.failureKindSummary == "Did not work: 2 DNS lookups, 1 web.",
              "dns kinds: \(dns.failureKindSummary ?? "nil")")
        // The same reason with a web top kind keeps the website text.
        var webUnreachable = ConnectCounters()
        for _ in 0..<3 { webUnreachable.recordStart() }
        webUnreachable.record(ConnectConclusion(kind: .web, result: .didNotWork, reason: .unreachable))
        webUnreachable.record(ConnectConclusion(kind: .web, result: .didNotWork, reason: .unreachable))
        webUnreachable.record(ConnectConclusion(kind: .dnsLookup, result: .didNotWork, reason: .refused))
        check(webUnreachable.reasonSummary == "Most common reason: the website could not be reached.",
              "web unreachable: \(webUnreachable.reasonSummary ?? "nil")")
        // A DNS top kind with another top reason keeps the reason text.
        var dnsRefused = ConnectCounters()
        for _ in 0..<3 { dnsRefused.recordStart() }
        dnsRefused.record(ConnectConclusion(kind: .dnsLookup, result: .didNotWork, reason: .refused))
        dnsRefused.record(ConnectConclusion(kind: .dnsLookup, result: .didNotWork, reason: .refused))
        dnsRefused.record(ConnectConclusion(kind: .web, result: .didNotWork, reason: .timedOut))
        check(dnsRefused.reasonSummary == "Most common reason: the website refused the connection.",
              "dns refused: \(dnsRefused.reasonSummary ?? "nil")")

        var success = ConnectCounters()
        success.recordStart()
        success.record(ConnectConclusion(kind: .web, result: .worked, reason: nil))
        check(success.summary == "1 attempt. 1 worked. 0 did not.", "single success summary: \(success.summary)")
        check(success.failureKindSummary == nil && success.cancelledSummary == nil, "no empty counter lines")
        check(ConnectCounters().summary == "No connections yet.", "empty summary")
        check(ConnectCounters().reasonSummary == nil, "empty reason summary")
        check(ConnectCounters().failureKindSummary == nil, "empty kind summary")
        check(ConnectCounters().cancelledSummary == nil, "empty cancelled summary")

        print("Connect watch tests passed")
    }
}
