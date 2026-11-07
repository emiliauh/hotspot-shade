import Foundation
import Darwin
import XPC

// Read the kernel audit token of one XPC peer.
//
// `xpc_connection_get_pid` is public but a PID is not an identity: the kernel
// recycles it. libxpc exposes the audit token getter, but the macOS SDK does not
// declare it. Resolve the symbol once and fail closed when it is absent. Do not
// fall back to the PID, because that fallback would reintroduce the race that
// this check exists to close.
public enum HelperXPCConnection {
    private typealias AuditTokenGetter =
        @convention(c) (xpc_connection_t, UnsafeMutablePointer<audit_token_t>) -> Void

    private static let getter: AuditTokenGetter? = {
        // RTLD_DEFAULT on Darwin.
        guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "xpc_connection_get_audit_token") else {
            return nil
        }
        return unsafeBitCast(symbol, to: AuditTokenGetter.self)
    }()

    public static var supportsAuditToken: Bool { getter != nil }

    public static func auditToken(for connection: xpc_connection_t) -> HelperAuditToken? {
        guard let getter else { return nil }
        var token = audit_token_t()
        getter(connection, &token)
        return HelperAuditToken(
            auditToken: token,
            processIdentifier: xpc_connection_get_pid(connection)
        )
    }
}
