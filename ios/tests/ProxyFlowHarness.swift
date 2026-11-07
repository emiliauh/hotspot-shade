import Foundation
import Network
import Darwin

// A host test harness for the real Swift source proxy.
//
// It runs the same ProxyServer, pairing responder, relay, and connect policy
// code as the iOS app, on this Mac, with the Debug test override. The Rust
// target client in `rust/tests/ios_simulator_proxy_flow.rs` pairs with it and
// runs one TCP destination, a wrong-token check, and one refused destination.
//
// The harness is not the app. It does not prove the app lifecycle, the
// Simulator network stack, carrier behavior, or a physical hotspot. It sets no
// route, creates no interface, and uses no cellular path.
//
// The harness approves the pairing prompt itself. That is a test behavior, not
// an app behavior. The app always asks the person.

@main
struct ProxyFlowHarness {
    static let token = "ios-source-proxy-flow-harness-token"
    static var signalSources: [DispatchSourceSignal] = []
    static var stopping = false

    static func main() {
        let defaults = UserDefaults.standard
        defaults.set(HotspotInterface.testLoopback.name, forKey: HotspotInterface.testInterfaceKey)
        defaults.set(HotspotInterface.testLoopback.address, forKey: HotspotInterface.testAddressKey)
        defaults.set(true, forKey: HotspotInterface.testCellularPathKey)
        guard HotspotInterface.current == HotspotInterface.testLoopback,
              HotspotInterface.testCellularPathActive() else {
            fputs("HARNESS_SETUP_FAILED: the test override is not active\n", stderr)
            exit(2)
        }
        guard let port = freePort() else {
            fputs("HARNESS_SETUP_FAILED: no free proxy port\n", stderr)
            exit(2)
        }

        let server = ProxyServer(trust: ObservableTrustStore(MemoryTrustStore()))
        // The loopback integration test must not start cellular preflights.
        server.suppressICMPSelectorForLifecycleTest = true
        var announced = false
        var approved: UUID?
        var latest = ProxyServer.Snapshot()
        server.onChange = { snapshot in
            latest = snapshot
            // A test harness decides the prompt itself. The app shows it.
            if let id = snapshot.pairingPromptID, snapshot.pairingCode != nil,
               approved != id {
                approved = id
                server.decidePairing(promptID: id, allow: true)
            }
            if !announced, snapshot.state == "Listening", snapshot.pairingReady {
                announced = true
                print("HARNESS_READY port=\(port)")
                fflush(stdout)
            }
        }
        server.configurePairing(port: port, token: token)
        server.start(port: port, token: token,
                     hotspotAddress: HotspotInterface.testLoopback.address)
        server.setSceneActive(true)

        DispatchQueue.main.asyncAfter(deadline: .now() + 15) {
            guard !announced else { return }
            fputs("HARNESS_START_FAILED state=\(latest.state) "
                  + "pairingReady=\(latest.pairingReady)\n", stderr)
            exit(3)
        }
        installStopHandlers(server)
        DispatchQueue.main.asyncAfter(deadline: .now() + 180) { stopAndExit(server) }
        dispatchMain()
    }

    static func installStopHandlers(_ server: ProxyServer) {
        for number in [SIGTERM, SIGINT] {
            let source = DispatchSource.makeSignalSource(signal: number, queue: .main)
            source.setEventHandler { stopAndExit(server) }
            source.resume()
            signal(number, SIG_IGN)
            signalSources.append(source)
        }
    }

    static func stopAndExit(_ server: ProxyServer) {
        guard !stopping else { return }
        stopping = true
        let defaults = UserDefaults.standard
        defaults.removeObject(forKey: HotspotInterface.testInterfaceKey)
        defaults.removeObject(forKey: HotspotInterface.testAddressKey)
        defaults.removeObject(forKey: HotspotInterface.testCellularPathKey)
        server.stop()
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) { exit(0) }
    }

    /// A free loopback port in the app's proxy range (20000 to 59999). The
    /// harness releases it before the listener starts.
    static func freePort() -> UInt16? {
        let start = Int(arc4random_uniform(40000))
        for offset in 0..<200 {
            let candidate = UInt16(20000 + (start + offset) % 40000)
            if canBind(candidate) { return candidate }
        }
        return nil
    }

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
}
