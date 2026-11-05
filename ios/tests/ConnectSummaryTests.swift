import Foundation

@main
struct ConnectSummaryTests {
    static func check(_ condition: Bool, _ message: String, line: Int = #line) {
        if !condition {
            print("FAIL line \(line): \(message)")
            exit(1)
        }
    }

    static func main() {
        // All zero: no line.
        check(ConnectSummary.didNotWorkKinds([:]) == nil, "empty counts")
        check(ConnectSummary.didNotWorkKinds([.web: 0, .otherTCP: 0, .udp: 0, .dnsLookup: 0]) == nil,
              "zero counts")
        check(ConnectSummary.didNotWorkKinds([.web: -2]) == nil, "negative counts are zero")

        // One kind.
        check(ConnectSummary.didNotWorkKinds([.web: 3]) == "Did not work: 3 web.", "one web")
        check(ConnectSummary.didNotWorkKinds([.dnsLookup: 24]) == "Did not work: 24 DNS lookups.",
              "one DNS kind")
        check(ConnectSummary.didNotWorkKinds([.udp: 1]) == "Did not work: 1 UDP.", "one UDP kind")
        check(ConnectSummary.didNotWorkKinds([.otherTCP: 1]) == "Did not work: 1 other connection.",
              "one other connection")
        check(ConnectSummary.didNotWorkKinds([.otherTCP: 15]) == "Did not work: 15 other connections.",
              "many other connections")

        // All kinds. The order is by count first.
        check(ConnectSummary.didNotWorkKinds([.web: 96, .dnsLookup: 24, .otherTCP: 15, .udp: 4])
                == "Did not work: 96 web, 24 DNS lookups, 15 other connections, 4 UDP.",
              "all kinds")

        // Large numbers.
        check(ConnectSummary.didNotWorkKinds([.web: 1_234_567, .dnsLookup: 987_654])
                == "Did not work: 1234567 web, 987654 DNS lookups.",
              "large numbers")

        // A tie uses the fixed kind order: web, other TCP, UDP, DNS lookup.
        check(ConnectSummary.didNotWorkKinds([.web: 2, .otherTCP: 2, .udp: 2, .dnsLookup: 2])
                == "Did not work: 2 web, 2 other connections, 2 UDP, 2 DNS lookups.",
              "full tie")
        check(ConnectSummary.didNotWorkKinds([.udp: 5, .otherTCP: 3, .web: 3])
                == "Did not work: 5 UDP, 3 web, 3 other connections.",
              "count order then kind order")

        print("Connect summary tests passed")
    }
}
