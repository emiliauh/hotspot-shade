import Foundation

@main
struct ConnectRetryPolicyTests {
    static func check(_ condition: Bool, _ message: String, line: Int = #line) {
        if !condition {
            print("FAIL line \(line): \(message)")
            exit(1)
        }
    }

    static func main() {
        let unreachable = ConnectAttempt.Failure(errno: ENETUNREACH, description: "Network is unreachable")
        let hostUnreachable = ConnectAttempt.Failure(errno: EHOSTUNREACH, description: "No route to host")
        let localDown = ConnectAttempt.Failure(errno: ENETDOWN, description: "Network is down")
        let localHostDown = ConnectAttempt.Failure(errno: EHOSTDOWN, description: "Host is down")
        let refused = ConnectAttempt.Failure(errno: ECONNREFUSED, description: "Connection refused")
        let other = ConnectAttempt.Failure(errno: EACCES, description: "Denied")

        // The policy takes the clock from the caller, so these tests control
        // every delay exactly.
        var now: TimeInterval = 0
        func makePolicy() -> ConnectRetryPolicy { ConnectRetryPolicy(clock: { now }) }

        // One retry after a sustained wait. It runs inside the 4 s deadline.
        check(ConnectRetryPolicy.retryDelay == 1.5, "retry delay")
        check(ConnectRetryPolicy.maximumRetries == 1, "one retry")

        // Ready first: no wait and no retry.
        var readyFirst = makePolicy()
        check(readyFirst.handle(.ready) == .finish, "ready first finishes")
        check(readyFirst.handle(.deadline) == .none, "a deadline after ready does nothing")
        check(readyFirst.totals == ConnectRetryPolicy.Totals(), "ready first has no counts")
        check(readyFirst.totals.retryStarts == 0 && readyFirst.totals.retrySuccesses == 0,
              "ready first retries nothing")

        // Waiting then ready inside the delay: the path recovered by itself.
        now = 100
        var recovered = makePolicy()
        check(recovered.handle(.waiting(unreachable)) == .waitForRetry, "first wait schedules a retry")
        now = 100.1
        check(recovered.handle(.ready) == .finish, "ready during the delay finishes")
        check(recovered.totals.waits.total == 1 && recovered.totals.waits.unreachable == 1,
              "one unreachable wait")
        check(recovered.totals.retryStarts == 0 && recovered.totals.retrySuccesses == 0,
              "a recovered path needs no retry")
        now = 101
        check(recovered.handle(.retryDue) == .none, "no retry after the final state")

        // Waiting twice inside the delay keeps one schedule and counts both waits.
        now = 0
        var twice = makePolicy()
        check(twice.handle(.waiting(unreachable)) == .waitForRetry, "first wait schedules")
        now = 0.1
        check(twice.handle(.waiting(hostUnreachable)) == .none, "second wait keeps the schedule")
        check(twice.totals.waits.total == 2, "two waits are counted")
        check(twice.totals.waits.unreachable == 2, "both waits are unreachable")
        // A short wait must not cancel the connection. Network framework can
        // still make the same connection ready.
        now = 0.25
        check(twice.handle(.retryDue) == .waitForRetry, "a short wait keeps the connection")
        check(twice.totals.retryStarts == 0, "a short wait does not retry")
        now = 1.499
        check(twice.handle(.retryDue) == .waitForRetry, "an early timer asks for a new schedule")
        check(twice.totals.retryStarts == 0, "an early timer does not retry")
        now = 1.5
        check(twice.handle(.retryDue) == .retry, "the sustained wait starts one retry")
        check(twice.totals.retryStarts == 1, "one retry started")
        // A third wait after the retry does not start a second retry.
        now = 1.6
        check(twice.handle(.waiting(refused)) == .none, "no waitForRetry after the one retry")
        now = 2.0
        check(twice.handle(.retryDue) == .none, "no second retry")
        check(twice.totals.retryStarts == 1, "still one retry")
        now = 2.1
        check(twice.handle(.ready) == .finish, "the retried connection is ready")
        check(twice.totals.retrySuccesses == 1, "the retry worked")
        check(twice.totals.waits.total == 3, "all waits are counted")

        // Waiting then the deadline: no retry, one deadline fire.
        now = 0
        var waitingDeadline = makePolicy()
        check(waitingDeadline.handle(.waiting(unreachable)) == .waitForRetry, "the wait schedules")
        now = 0.1
        check(waitingDeadline.handle(.deadline) == .finish, "the deadline is final")
        check(waitingDeadline.totals.deadlineFires == 1, "one deadline fire")
        check(waitingDeadline.totals.retryStarts == 0, "the deadline wins over the retry")
        now = 1
        check(waitingDeadline.handle(.retryDue) == .none, "no retry after the deadline")

        // Cancelled during the delay: no retry.
        now = 0
        var cancelled = makePolicy()
        check(cancelled.handle(.waiting(unreachable)) == .waitForRetry, "the wait schedules")
        now = 0.1
        check(cancelled.handle(.cancelled) == .finish, "a cancel during the delay is final")
        now = 1
        check(cancelled.handle(.retryDue) == .none, "no retry after a cancel")
        check(cancelled.totals.retryStarts == 0, "the cancel wins over the retry")
        check(cancelled.totals.waits.total == 1, "the wait is counted")

        // A failure during the delay is final.
        now = 0
        var failed = makePolicy()
        _ = failed.handle(.waiting(unreachable))
        now = 0.1
        check(failed.handle(.failed(refused)) == .finish, "a failure during the delay is final")
        now = 1
        check(failed.handle(.retryDue) == .none, "no retry after a failure")
        check(failed.totals.retryStarts == 0, "the failure wins over the retry")
        check(failed.totals.deadlineFires == 0, "a failure is not a deadline")

        // A deadline after a retry is a timeout with one retry.
        now = 0
        var retriedDeadline = makePolicy()
        _ = retriedDeadline.handle(.waiting(unreachable))
        now = 1.5
        check(retriedDeadline.handle(.retryDue) == .retry, "the retry starts")
        now = 1.6
        check(retriedDeadline.handle(.deadline) == .finish, "the deadline after a retry is final")
        check(retriedDeadline.totals.retryStarts == 1 && retriedDeadline.totals.deadlineFires == 1,
              "one retry and one deadline")
        check(retriedDeadline.totals.retrySuccesses == 0, "the retry did not work")

        // Wait counts by error.
        var counts = ConnectRetryPolicy.WaitCounts()
        check(counts.total == 0, "empty counts")
        counts.record(unreachable)
        counts.record(refused)
        counts.record(other)
        counts.record(localDown)
        check(counts.unreachable == 1 && counts.refused == 1 && counts.other == 2,
              "a local interface wait is not unreachable")
        check(counts.total == 4, "four waits")
        var more = ConnectRetryPolicy.WaitCounts()
        more.record(hostUnreachable)
        more.record(refused)
        more.record(localHostDown)
        counts.add(more)
        check(counts.unreachable == 2 && counts.refused == 2 && counts.other == 3, "folded counts")
        check(counts.total == 7, "seven waits")

        // The totals snapshot is a value.
        now = 0
        var snapshot = makePolicy()
        _ = snapshot.handle(.waiting(unreachable))
        now = 1
        _ = snapshot.handle(.retryDue)
        _ = snapshot.handle(.ready)
        let totals = snapshot.totals
        _ = snapshot.handle(.deadline)
        check(snapshot.totals == totals, "the deadline after ready changes nothing")

        print("Connect retry policy tests passed")
    }
}
