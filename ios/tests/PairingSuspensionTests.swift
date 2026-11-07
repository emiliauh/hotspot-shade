import Foundation
import Network
import Darwin

// Hermetic lifecycle tests for the pairing listener while the app has no
// usable token.
//
// The test runs the real ProxyServer on this Mac with the Debug hotspot
// override on the loopback pair. It sets no route, creates no interface, and
// never reaches another device. It does bind TCP port 18090 when the listener
// is supposed to run. The test fails when that port is busy; it never skips the
// resume checks and passes.
//
// The regression it covers: a missing token suspends pairing, and a later scene
// change must not bring the listener back with an empty token and port 0.

@main
struct PairingSuspensionTests {
    static let token = "pairing-suspension-test-token-0123456789"
    static let proxyPort: UInt16 = 25000

    static func check(_ condition: Bool, _ message: String, line: Int = #line) {
        if !condition {
            print("FAIL line \(line): \(message)")
            exit(1)
        }
    }

    /// Run the main run loop until the condition holds or the timeout passes.
    /// `ProxyServer` publishes its snapshot on the main queue, so a plain sleep
    /// would never see the update.
    static func wait(until condition: () -> Bool, timeout: TimeInterval) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if condition() { return true }
            RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.02))
        }
        return condition()
    }

    /// A plain bind without SO_REUSEADDR. True means no listener holds the port
    /// on 127.0.0.1.
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

    static func setOverride() {
        let defaults = UserDefaults.standard
        defaults.set(HotspotInterface.testLoopback.name, forKey: HotspotInterface.testInterfaceKey)
        defaults.set(HotspotInterface.testLoopback.address, forKey: HotspotInterface.testAddressKey)
    }

    static func clearOverride() {
        let defaults = UserDefaults.standard
        defaults.removeObject(forKey: HotspotInterface.testInterfaceKey)
        defaults.removeObject(forKey: HotspotInterface.testAddressKey)
        defaults.removeObject(forKey: HotspotInterface.testCellularPathKey)
    }

    static func main() {
        setOverride()
        defer { clearOverride() }
        guard HotspotInterface.current == HotspotInterface.testLoopback else {
            print("FAIL: the Debug hotspot override is not active. Build with -DDEBUG.")
            exit(1)
        }

        // Nothing may hold the pairing port before the test starts. The resume
        // checks are the point of this test, so a busy port is a failure, not a
        // skip that passes.
        guard canBind(PairingProtocol.port) else {
            print("FAIL: port \(PairingProtocol.port) is already in use. Free it and rerun. The resume checks must not be skipped.")
            exit(1)
        }

        let server = ProxyServer(trust: ObservableTrustStore(MemoryTrustStore()))
        var latest = ProxyServer.Snapshot()
        server.onChange = { snapshot in latest = snapshot }
        server.publishCurrentState()
        _ = wait(until: { true }, timeout: 0.1)

        // Each server failure advances the failure revision. The app records
        // the value at a start request, so it can tell a queued snapshot from
        // an earlier run from a genuine failure of the new start. Port 0 fails
        // before any listener is created.
        server.start(port: 0, token: token, hotspotAddress: "127.0.0.1")
        check(wait(until: { latest.state == "Failed" && latest.failureRevision == 1 }, timeout: 2),
              "the first failed start reports revision 1")
        server.start(port: 0, token: token, hotspotAddress: "127.0.0.1")
        check(wait(until: { latest.state == "Failed" && latest.failureRevision == 2 }, timeout: 2),
              "the second failed start reports revision 2")

        // 1. A missing token suspends pairing. No configure call happens, which
        // is what the app does when the keychain load fails.
        server.suspendPairing()
        _ = wait(until: { true }, timeout: 0.3)
        check(!latest.pairingReady, "a suspended listener is not ready")

        // 2. A scene change must not bring it back. The poll timer, the policy,
        // and the credentials all run from here.
        server.setSceneActive(false)
        _ = wait(until: { true }, timeout: 0.2)
        server.setSceneActive(true)
        _ = wait(until: { true }, timeout: 1.2)
        check(!latest.pairingReady, "a scene change does not revive a suspended listener")
        check(latest.pairingCode == nil, "a suspended listener shows no pairing prompt")
        check(canBind(PairingProtocol.port),
              "a suspended listener does not bind port \(PairingProtocol.port)")

        // 3. A later valid token resumes the listener. This proves the guard
        // does not break the normal path.
        server.configurePairing(port: proxyPort, token: token)
        let resumed = wait(until: { latest.pairingReady }, timeout: 10)
        check(resumed, "a valid token starts the pairing listener again")

        // 4. Suspending again stops it, and the port is free.
        server.suspendPairing()
        let stopped = wait(until: { !latest.pairingReady }, timeout: 5)
        check(stopped, "suspending stops a live pairing listener")
        let released = wait(until: { canBind(PairingProtocol.port) }, timeout: 5)
        check(released, "a suspended listener releases port \(PairingProtocol.port)")

        // 5. The regression itself: scene changes after a second suspension
        // stay suspended, and the status reply has no port to hand out.
        server.setSceneActive(false)
        _ = wait(until: { true }, timeout: 0.2)
        server.setSceneActive(true)
        _ = wait(until: { true }, timeout: 1.2)
        check(!latest.pairingReady, "the listener stays suspended across another scene change")
        check(latest.pairingCode == nil, "the suspended listener still shows no prompt")
        check(canBind(PairingProtocol.port),
              "the suspended listener still does not bind port \(PairingProtocol.port)")

        // 6. An empty token or a zero port is a suspension, not a listener
        // with no credentials. The app never calls this, but the server
        // must not trust the caller.
        server.configurePairing(port: proxyPort, token: token)
        check(wait(until: { latest.pairingReady }, timeout: 10),
              "the listener starts before the empty-token check")
        server.configurePairing(port: proxyPort, token: "")
        check(wait(until: { !latest.pairingReady }, timeout: 5),
              "an empty token suspends the listener")
        check(wait(until: { canBind(PairingProtocol.port) }, timeout: 5),
              "an empty token releases port \(PairingProtocol.port)")
        server.configurePairing(port: proxyPort, token: token)
        check(wait(until: { latest.pairingReady }, timeout: 10),
              "a valid token starts the listener after an empty one")
        server.configurePairing(port: 0, token: token)
        check(wait(until: { !latest.pairingReady }, timeout: 5),
              "a zero port suspends the listener")
        check(wait(until: { canBind(PairingProtocol.port) }, timeout: 5),
              "a zero port releases port \(PairingProtocol.port)")

        server.stop()
        _ = wait(until: { true }, timeout: 0.2)
        print("Pairing suspension tests passed")
    }
}
