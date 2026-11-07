import Foundation

// The pending-start regression. A start queues a pairing update before the
// server runs the start. That update can publish the previous run's "Stopped"
// or "Failed" state. Only a failure newer than the request may clear the
// request and stop the hotspot watch.

@main
struct ProxyStartPolicyTests {
    static func check(_ condition: Bool, _ message: String, line: Int = #line) {
        if !condition {
            print("FAIL line \(line): \(message)")
            exit(1)
        }
    }

    static func main() {
        // The previous run failed at revision 4. The new request records 4.
        var request = 4
        check(ProxyStartPolicy.isStaleForPendingStart(state: "Failed",
                                                      snapshotFailureRevision: 4,
                                                      requestFailureRevision: request),
              "the old Failed snapshot is stale")
        check(ProxyStartPolicy.isStaleForPendingStart(state: "Failed",
                                                      snapshotFailureRevision: 3,
                                                      requestFailureRevision: request),
              "an older Failed snapshot is stale")
        check(!ProxyStartPolicy.isStaleForPendingStart(state: "Failed",
                                                       snapshotFailureRevision: 6,
                                                       requestFailureRevision: request),
              "a genuine failure ends a pending start")

        // The server keeps the old failure revision while it is still
        // processing the start. Its own state must not be treated as stale.
        check(!ProxyStartPolicy.isStaleForPendingStart(state: "Starting",
                                                       snapshotFailureRevision: 4,
                                                       requestFailureRevision: request),
              "Starting is not stale")
        check(!ProxyStartPolicy.isStaleForPendingStart(state: "Listening",
                                                       snapshotFailureRevision: 4,
                                                       requestFailureRevision: request),
              "Listening is not stale")

        // The exact sequence from the bug. The model records revision 4,
        // marks the start requested, and keeps the hotspot watch. A queued
        // Failed snapshot from the previous run arrives first. It must be
        // shown as Starting, not clear the request, and not stop the watch.
        // The server then reports Starting. A later failure with revision 5
        // is genuine and ends the request.
        var proxyRequested = true
        var watcherRunning = true
        var modelState = "Starting"
        func apply(_ incomingState: String, _ incomingRevision: Int) -> String {
            var state = incomingState
            if proxyRequested
                && ProxyStartPolicy.isStaleForPendingStart(
                    state: state,
                    snapshotFailureRevision: incomingRevision,
                    requestFailureRevision: request) {
                state = "Starting"
            }
            modelState = state
            if state == "Failed" {
                proxyRequested = false
                watcherRunning = false
            }
            return state
        }

        check(apply("Failed", 4) == "Starting",
              "the stale failure is shown as Starting")
        check(proxyRequested, "the stale failure keeps the start requested")
        check(watcherRunning, "the stale failure keeps the hotspot watch")
        check(modelState == "Starting", "the stale failure does not show Failed")

        check(apply("Starting", 4) == "Starting",
              "the server start replaces the stale state")
        check(proxyRequested && watcherRunning,
              "the requested start continues while it starts")

        check(apply("Failed", 5) == "Failed",
              "a newer failure ends the requested start")
        check(!proxyRequested, "a genuine failure clears the request")
        check(!watcherRunning, "a genuine failure stops the hotspot watch")

        // A failure from another run after a later request still ends it, even
        // if the revision moved by more than one.
        request = 5
        check(!ProxyStartPolicy.isStaleForPendingStart(state: "Failed",
                                                       snapshotFailureRevision: 9,
                                                       requestFailureRevision: request),
              "a later failure revision ends the request")

        // A queued Stopped snapshot is stale too. The server's start report
        // follows it, and the watch must survive the gap.
        check(ProxyStartPolicy.isStaleForPendingStart(state: "Stopped",
                                                      snapshotFailureRevision: 5,
                                                      requestFailureRevision: request),
              "a queued Stopped snapshot is stale for the request")

        print("Proxy start policy tests passed")
    }
}
