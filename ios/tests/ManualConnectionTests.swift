import Foundation

// The values that another SOCKS5 client needs. The type never holds the
// source token, so a copy cannot expose it. The tests cover the empty states
// and the port rule that the listener also enforces.

@main
struct ManualConnectionTests {
    static func check(_ condition: Bool, _ message: String, line: Int = #line) {
        if !condition {
            print("FAIL line \(line): \(message)")
            exit(1)
        }
    }

    static func main() {
        check(ManualConnection.username == "hotspotshade",
              "the SOCKS5 user name matches the proxy and the Rust client")

        let ready = ManualConnection(address: "172.20.10.1", port: 41234, running: true, starting: false)
        check(ready.isUsable, "an address and a valid port are usable")
        check(ready.portText == "41234", "the port line is plain")
        check(ready.stateText == "The proxy is on. Another device can connect now.",
              "the running state says a connection can work")
        guard let copy = ready.copyText else {
            print("FAIL: a usable connection must have copy text")
            exit(1)
        }
        check(copy.contains("172.20.10.1:41234"), "the copy names the address and port")
        check(copy.contains("Username: hotspotshade"), "the copy names the SOCKS5 user name")
        check(copy.contains("socks5h"), "the copy tells the person to use remote DNS")
        check(copy.contains("the source token"), "the copy names the password source")
        check(!copy.contains("proxyToken"), "the copy does not name a stored key")

        let stopped = ManualConnection(address: "172.20.10.1", port: 41234, running: false, starting: false)
        check(stopped.stateText == "Start the proxy before another device connects.",
              "the stopped state asks the person to start the proxy")
        check(stopped.copyText == ready.copyText, "the copy text does not depend on the run state")

        let starting = ManualConnection(address: "172.20.10.1", port: 41234, running: false, starting: true)
        check(starting.stateText == "The proxy is starting. Wait until it reports On.",
              "the starting state does not claim that the proxy is on")

        let noAddress = ManualConnection(address: nil, port: 41234, running: false, starting: false)
        check(!noAddress.isUsable, "no address is not usable")
        check(noAddress.copyText == nil, "there is no copy text without an address")
        check(noAddress.stateText == "The app has no hotspot address yet. A connection will not work.",
              "the no-address state is plain")

        let noPort = ManualConnection(address: "172.20.10.1", port: nil, running: false, starting: false)
        check(!noPort.isUsable, "no port is not usable")
        check(noPort.copyText == nil, "there is no copy text without a port")
        check(noPort.portText == "No valid port. Set one in Advanced.",
              "the missing-port line names the place to fix it")

        // Port 18090 belongs to pairing. The proxy must never present it.
        let reserved = ManualConnection(address: "172.20.10.1", port: 18090, running: true, starting: false)
        check(!reserved.isUsable, "the pairing port is not a proxy port")
        check(reserved.copyText == nil, "the pairing port is never copied")
        check(reserved.portText == "No valid port. Set one in Advanced.",
              "the reserved port is not shown as usable")

        let privileged = ManualConnection(address: "172.20.10.1", port: 80, running: true, starting: false)
        check(!privileged.isUsable, "a privileged port is not usable")

        let high = ManualConnection(address: "172.20.10.1", port: 65535, running: true, starting: false)
        check(high.isUsable, "the highest port is usable")

        print("Manual connection tests passed")
    }
}
