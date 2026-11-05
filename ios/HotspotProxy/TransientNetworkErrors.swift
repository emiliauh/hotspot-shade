import Foundation
import Network

// A UDP send or receive error can affect one datagram only. Examples are a full
// interface queue or an ICMP error for an earlier datagram. Count these errors and
// keep the flow. Close it after a bounded run of consecutive errors.
enum TransientNetworkErrors {
    static let consecutiveLimit = 16
    static func isTransient(_ error: NWError) -> Bool {
        guard case let .posix(code) = error else { return false }
        return [.ENOBUFS, .EAGAIN, .ECONNREFUSED, .EHOSTUNREACH, .ENETUNREACH].contains(code)
    }
}
