import Foundation

/// Decide whether a snapshot still reports the state from before a requested
/// start.
///
/// `ProxyServer` publishes snapshots on the main queue, and it runs a start on
/// its own queue. A pairing update from a new start can reach the main queue
/// first and publish the previous run's "Stopped" or "Failed" state. The app
/// records the server failure revision it saw when it requested the start, so
/// only a newer failure ends that request. A stale snapshot must not clear the
/// request, stop the hotspot watch, or stop location.
enum ProxyStartPolicy {
    /// True when the snapshot belongs to the run before the requested start.
    /// A "Failed" snapshot is stale while its revision is not newer than the
    /// revision seen at the request. A "Stopped" snapshot has no failure
    /// revision, so it is stale until the server reports its own state.
    static func isStaleForPendingStart(state: String,
                                       snapshotFailureRevision: Int,
                                       requestFailureRevision: Int) -> Bool {
        switch state {
        case "Stopped":
            return true
        case "Failed":
            return snapshotFailureRevision <= requestFailureRevision
        default:
            return false
        }
    }
}
