import Foundation
import Network

@main
struct TransientNetworkErrorsTests {
    static func main() {
        // These errors affect one datagram. The flow stays open.
        for code in [POSIXErrorCode.ENOBUFS, .EAGAIN, .ECONNREFUSED, .EHOSTUNREACH, .ENETUNREACH] {
            precondition(TransientNetworkErrors.isTransient(.posix(code)), "\(code) must be transient")
        }
        // Other errors close the flow at once.
        for code in [POSIXErrorCode.EPIPE, .ECONNRESET, .EBADF, .EACCES] {
            precondition(!TransientNetworkErrors.isTransient(.posix(code)), "\(code) must not be transient")
        }
        precondition(!TransientNetworkErrors.isTransient(.posix(.ETIMEDOUT)))
        precondition(!TransientNetworkErrors.isTransient(.dns(0)))
        precondition(TransientNetworkErrors.consecutiveLimit == 16)
        print("Transient network error tests passed")
    }
}
