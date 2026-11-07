import Foundation
import Security

// A connection must complete a harmless, fresh handshake before the app asks
// for a start authorization. The authorization external form is a bearer
// credential for one administrator right, so it must not be the first message
// on a connection. The transport pins the helper's code signature with the XPC
// peer requirement, and the handshake proves that the live peer on that pinned
// connection is the helper process that will serve the start. The app only
// prompts after the handshake reply arrives.
//
// The helper issues one server nonce per connection. A start request must
// return it, and one nonce is accepted at most once. A wrong or expired nonce
// consumes the entry, so a caller must handshake again. The handshake carries
// no secret and grants nothing by itself.
public struct HelperHandshake: Equatable, Sendable {
    public let serverNonce: Data

    public init(serverNonce: Data) {
        self.serverNonce = serverNonce
    }
}

public final class HelperHandshakeGate: @unchecked Sendable {
    public static let nonceByteCount = 32
    // An administrator prompt can stay open for minutes. The nonce is a fresh
    // single-use value on one authenticated connection, so a long bound does
    // not weaken it. A start after the bound must handshake again.
    public static let lifetime: TimeInterval = 600
    private static let maximumEntries = 64

    private struct Entry {
        let nonce: Data
        let issuedAt: Date
    }

    private let lock = NSLock()
    private var entries: [UUID: Entry] = [:]
    private let now: () -> Date
    private let makeNonce: () -> Data?

    public init(
        now: @escaping () -> Date = Date.init,
        makeNonce: @escaping () -> Data? = HelperHandshakeGate.randomNonce
    ) {
        self.now = now
        self.makeNonce = makeNonce
    }

    // Return a new server nonce for this connection. A malformed client nonce
    // or an unavailable random source returns nil. The client nonce is not a
    // secret; it only binds the reply to the request.
    public func issue(connection: UUID, clientNonce: Data) -> HelperHandshake? {
        guard clientNonce.count == Self.nonceByteCount,
              let nonce = makeNonce(),
              nonce.count == Self.nonceByteCount
        else {
            return nil
        }
        lock.lock()
        pruneExpiredLocked()
        if entries.count >= Self.maximumEntries {
            // The connection ids are never reused. Dropping the oldest entry
            // only forces that peer to handshake again.
            if let oldest = entries.min(by: { $0.value.issuedAt < $1.value.issuedAt })?.key {
                entries.removeValue(forKey: oldest)
            }
        }
        entries[connection] = Entry(nonce: nonce, issuedAt: now())
        lock.unlock()
        return HelperHandshake(serverNonce: nonce)
    }

    // Consume the single server nonce for this connection. A mismatch removes
    // the entry and returns false. An expired entry is removed and refused.
    public func consume(connection: UUID, serverNonce: Data) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard let entry = entries.removeValue(forKey: connection) else { return false }
        guard now().timeIntervalSince(entry.issuedAt) <= Self.lifetime else { return false }
        guard entry.nonce.count == serverNonce.count else { return false }
        return constantTimeEqual(entry.nonce, serverNonce)
    }

    public func clear(connection: UUID) {
        lock.lock()
        entries.removeValue(forKey: connection)
        lock.unlock()
    }

    public func clearAll() {
        lock.lock()
        entries.removeAll()
        lock.unlock()
    }

    private func pruneExpiredLocked() {
        let cutoff = now().addingTimeInterval(-Self.lifetime)
        entries = entries.filter { $0.value.issuedAt >= cutoff }
    }

    private func constantTimeEqual(_ left: Data, _ right: Data) -> Bool {
        guard left.count == right.count else { return false }
        var difference: UInt8 = 0
        for (a, b) in zip(left, right) {
            difference |= a ^ b
        }
        return difference == 0
    }

    public static func randomNonce() -> Data? {
        var bytes = [UInt8](repeating: 0, count: nonceByteCount)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            return nil
        }
        return Data(bytes)
    }
}
