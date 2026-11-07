import Foundation
import Network
import Darwin

// Hermetic wiring test: the real TokenLifecycle drives the real ProxyServer.
//
// TokenLifecycleTests proves the lifecycle with a recording sink. This test
// proves the same calls take the real pairing listener down and bring it back.
// It runs ProxyServer on this Mac with the Debug hotspot override on the
// loopback pair. It sets no route, creates no interface, and reaches no other
// device. Token storage is fake, so it never opens the keychain. The rotation
// part opts in to the dormant staged transaction because the app keeps the
// review gate closed. It binds TCP port 18090 while the listener is up, so the
// test fails when that port is busy. It never skips the resume checks.
//
// ProxyModel needs UIKit and cannot run here. It calls exactly these lifecycle
// methods, so this is the strongest real wiring that a macOS test can reach.

// The app declares this conformance next to ProxyModel. It is empty because
// ProxyServer already has both methods.
extension ProxyServer: PairingCredentialSink {}

final class ServerHost: TokenLifecycleHost {
    var requested = false
    var state = "Stopped"
    var port: UInt16 = 25000
    weak var lifecycle: TokenLifecycle?
    var tokenProxyRequested: Bool { requested }
    var tokenProxyState: String { state }
    var tokenPairingPort: UInt16 { port }
    func tokenActivity(_ message: String) {}
    func tokenStateDidChange() {}
}

@main
struct TokenLifecycleServerTests {
    static let keychainToken = "0123456789abcdef0123456789abcdef"
    static let legacyToken = "fedcba9876543210fedcba9876543210"
    static let newToken = "00112233445566778899aabbccddeeff"
    static let invalid = "bad token"

    static func check(_ condition: Bool, _ message: String, line: Int = #line) {
        if !condition {
            print("FAIL line \(line): \(message)")
            exit(1)
        }
    }

    static func checkEqual<T: Equatable>(_ actual: T, _ expected: T,
                                         _ label: String, line: Int = #line) {
        check(actual == expected, "\(label): got \(actual), expected \(expected)", line: line)
    }

    /// Run the main run loop until the condition holds or the timeout passes.
    /// `ProxyServer` publishes its snapshot on the main queue.
    static func wait(until condition: () -> Bool, timeout: TimeInterval) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if condition() { return true }
            RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.02))
        }
        return condition()
    }

    static func settle(_ seconds: TimeInterval) {
        _ = wait(until: { false }, timeout: seconds)
    }

    /// A plain bind without SO_REUSEADDR. True means no listener holds the port.
    static func canBind(_ port: UInt16) -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
        return withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        } == 0
    }

    static func main() {
        let defaults = UserDefaults.standard
        defaults.set(HotspotInterface.testLoopback.name, forKey: HotspotInterface.testInterfaceKey)
        defaults.set(HotspotInterface.testLoopback.address, forKey: HotspotInterface.testAddressKey)
        defer {
            defaults.removeObject(forKey: HotspotInterface.testInterfaceKey)
            defaults.removeObject(forKey: HotspotInterface.testAddressKey)
            defaults.removeObject(forKey: HotspotInterface.testCellularPathKey)
        }
        guard HotspotInterface.current == HotspotInterface.testLoopback else {
            print("FAIL: the Debug hotspot override is not active. Build with -DDEBUG.")
            exit(1)
        }
        guard canBind(PairingProtocol.port) else {
            print("FAIL: port \(PairingProtocol.port) is already in use. Free it and rerun.")
            exit(1)
        }

        let server = ProxyServer(trust: ObservableTrustStore(MemoryTrustStore()))
        var latest = ProxyServer.Snapshot()
        server.onChange = { snapshot in latest = snapshot }
        server.publishCurrentState()
        settle(0.1)

        // The keychain loses its item while a valid old copy exists.
        let storage = FakeTokenStorage(stored: keychainToken)
        let legacy = FakeLegacyStore(value: nil)
        let feed = TokenFeed([newToken])
        let intent = FakeRecoveryIntentStore()
        let store = SecureTokenStore(storage: storage, legacy: legacy,
                                     recoveryIntent: intent,
                                     generate: { feed.next() })
        // This test exercises the dormant staged transaction against the real
        // listener. The app uses the default false review gate.
        let lifecycle = TokenLifecycle(store: store, pairing: server,
                                       rotationReviewed: true)
        let host = ServerHost()
        host.lifecycle = lifecycle
        lifecycle.attach(host: host)

        // 1. A stored token brings the real listener up.
        lifecycle.launch()
        check(wait(until: { latest.pairingReady }, timeout: 10),
              "a loaded token starts the real pairing listener")

        // A call made from the server queue must not synchronously dispatch to
        // itself. This also exercises the acknowledged stop on that path.
        let sameQueueDone = DispatchSemaphore(value: 0)
        server.enqueuePairingTestWork {
            server.suspendPairing()
            sameQueueDone.signal()
        }
        check(sameQueueDone.wait(timeout: .now() + 5) == .success,
              "suspension on the server queue does not deadlock")
        lifecycle.syncPairing()
        check(wait(until: { latest.pairingReady }, timeout: 10), "pairing resumes after same-queue suspension")

        // A real rotation suspends the live listener, replaces the confirmed
        // credential, and brings the listener back with the new token.
        check(lifecycle.canRotate, "rotation is available while idle")
        lifecycle.rotate()
        checkEqual(lifecycle.token, newToken, "rotation adopts the new token")
        checkEqual(storage.stored, newToken, "rotation stores the new token")
        check(intent.data == nil, "rotation clears its intent")
        check(wait(until: { latest.pairingReady }, timeout: 10),
              "rotation restores pairing with the new token")

        // An invalid item on a subsequent launch suspends the real listener.
        storage.stored = invalid
        let writesBeforeRepair = storage.writeCount
        let deletesBeforeRepair = storage.deleteCount
        let second = TokenLifecycle(store: SecureTokenStore(storage: storage, legacy: legacy,
                                                           recoveryIntent: FakeRecoveryIntentStore()),
                                   pairing: server)
        let secondHost = ServerHost()
        secondHost.lifecycle = second
        second.attach(host: secondHost)
        second.launch()
        check(wait(until: { !latest.pairingReady }, timeout: 5), "invalid storage suspends listener")
        check(wait(until: { canBind(PairingProtocol.port) }, timeout: 5), "suspension releases port")
        second.replaceInvalid()
        second.restoreLegacy()
        server.setSceneActive(false)
        settle(0.2)
        server.setSceneActive(true)
        settle(1.2)
        check(!latest.pairingReady && canBind(PairingProtocol.port), "refused repair and scene change keep listener down")
        check(storage.stored == invalid && storage.writeCount == writesBeforeRepair &&
              storage.deleteCount == deletesBeforeRepair, "invalid item is preserved")

        // A locked read suspends pairing; a retry may adopt an existing token.
        storage.stored = keychainToken
        storage.readSteps = [.failure(.keychainUnavailable(-25308))]
        let third = TokenLifecycle(store: SecureTokenStore(storage: storage, legacy: legacy,
                                                           recoveryIntent: FakeRecoveryIntentStore()),
                                   pairing: server)
        let thirdHost = ServerHost()
        thirdHost.lifecycle = third
        third.attach(host: thirdHost)
        third.launch()
        check(!latest.pairingReady, "locked launch stays suspended")
        third.retryLoadIfNeeded()
        check(third.token == keychainToken, "retry adopts confirmed existing token")
        check(wait(until: { latest.pairingReady }, timeout: 10), "confirmed retry resumes listener")

        server.suspendPairing()
        check(wait(until: { canBind(PairingProtocol.port) }, timeout: 5), "cleanup frees the port")
        print("TokenLifecycleServerTests passed")
    }
}
