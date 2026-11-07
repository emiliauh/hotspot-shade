import Foundation
import Darwin

@main
struct HotspotWatchTests {
    /// A defaults suite for the tests. The tests never touch the standard
    /// defaults.
    static let testSuite = "local.hotspotproxy.hotspotwatch.tests"

    static func main() {
        checkDiscovery()
        checkPendingDiscovery()
        checkLossDetector()
        checkLinkContinuity()
        checkLinkObservationStore()

        #if DEBUG
        checkTestOverride()
        #else
        checkNoTestOverride()
        #endif

        switch HotspotInterface.observe() {
        case .present(let address): precondition(address == HotspotInterface.hotspotAddress)
        case .absent, .unreadable: break
        }
        print("Hotspot watch tests passed")
    }

    /// Discovery accepts one bridge on the supported hotspot subnet. It fails
    /// closed for a missing, conflicting, or second match.
    static func checkDiscovery() {
        let bridge100 = HotspotInterface.Link(name: "bridge100", type: UInt8(IFT_BRIDGE))
        let bridge101 = HotspotInterface.Link(name: "bridge101", type: UInt8(IFT_BRIDGE))
        let wifi = HotspotInterface.Link(name: "en0", type: UInt8(IFT_ETHER))
        let etherBridge = HotspotInterface.Link(name: "bridge100", type: UInt8(IFT_ETHER))
        let unknown = HotspotInterface.Link(name: "bridge102", type: nil)
        let loopback = HotspotInterface.Link(name: "lo0", type: UInt8(IFT_LOOP))

        func ipv4(_ name: String,
                  address: String? = HotspotInterface.hotspotAddress,
                  netmask: String? = HotspotInterface.hotspotNetmask,
                  up: Bool = true,
                  loopback: Bool = false) -> HotspotInterface.Address {
            HotspotInterface.Address(name: name, isUp: up, isLoopback: loopback,
                                     address: address, netmask: netmask)
        }

        func snapshot(_ links: [HotspotInterface.Link],
                      _ addresses: [HotspotInterface.Address]) -> HotspotInterface.Snapshot {
            HotspotInterface.Snapshot(links: links, addresses: addresses)
        }

        precondition(HotspotInterface.discover(snapshot([], [])) == .absent)
        precondition(HotspotInterface.discover(snapshot([bridge100], [ipv4("bridge100")]))
                     == .found(HotspotInterface.Identity(name: "bridge100",
                                                        address: HotspotInterface.hotspotAddress)))
        // The old code required bridge100. A renamed bridge still works.
        precondition(HotspotInterface.discover(snapshot([bridge101], [ipv4("bridge101")]))
                     == .found(HotspotInterface.Identity(name: "bridge101",
                                                        address: HotspotInterface.hotspotAddress)))
        // Duplicate records for one link do not make the result ambiguous.
        precondition(HotspotInterface.discover(snapshot([bridge100, bridge100],
                                                        [ipv4("bridge100"), ipv4("bridge100")]))
                     == .found(HotspotInterface.Identity(name: "bridge100",
                                                        address: HotspotInterface.hotspotAddress)))
        // Two different bridges cannot both be the listener target.
        precondition(HotspotInterface.discover(snapshot([bridge100, bridge101],
                                                        [ipv4("bridge100"), ipv4("bridge101")]))
                     == .ambiguous)
        // The identity-aware pass keeps ambiguous apart from unreadable, so
        // Start can say which one it saw. Decisions treat both the same.
        precondition(HotspotInterface.classify(.ambiguous) == .ambiguous)
        precondition(HotspotInterface.classify(.unreadable) == .unreadable)
        var ambiguousDetector = HotspotLossDetector(boundIdentity: HotspotInterface.Identity(
            name: "bridge100", address: HotspotInterface.hotspotAddress))
        precondition(ambiguousDetector.observe(.ambiguous, now: 0) == .keepRunning)
        // A missing or conflicting link type is inconclusive.
        precondition(HotspotInterface.discover(snapshot([], [ipv4("bridge100")])) == .unreadable)
        precondition(HotspotInterface.discover(snapshot([unknown], [ipv4("bridge102")])) == .unreadable)
        precondition(HotspotInterface.discover(snapshot([bridge100, etherBridge], [ipv4("bridge100")]))
                     == .unreadable)
        // A Wi-Fi or loopback link never matches, even with the same address.
        // A known non-bridge link is reported as unsupported, not absence.
        precondition(HotspotInterface.discover(snapshot([wifi], [ipv4("en0")]))
                     == .unsupported(HotspotInterface.Identity(name: "en0",
                                                              address: HotspotInterface.hotspotAddress)))
        precondition(HotspotInterface.discover(snapshot([etherBridge], [ipv4("bridge100")]))
                     == .unsupported(HotspotInterface.Identity(name: "bridge100",
                                                              address: HotspotInterface.hotspotAddress)))
        precondition(HotspotInterface.discover(snapshot([loopback], [ipv4("lo0", loopback: true)]))
                     == .absent)
        // Two complete non-bridge links at the same address cannot pick one.
        let wifiOther = HotspotInterface.Link(name: "en1", type: UInt8(IFT_ETHER))
        precondition(HotspotInterface.discover(snapshot([wifi, wifiOther],
                                                        [ipv4("en0"), ipv4("en1")]))
                     == .ambiguous)
        // An arbitrary private bridge is not a Personal Hotspot.
        let otherBridge = HotspotInterface.Link(name: "bridge102", type: UInt8(IFT_BRIDGE))
        precondition(HotspotInterface.discover(snapshot([otherBridge],
                                                        [ipv4("bridge102", address: "10.1.2.1",
                                                              netmask: "255.255.255.0")]))
                     == .absent)
        precondition(HotspotInterface.discover(snapshot([bridge100],
                                                        [ipv4("bridge100", address: "172.20.10.2")]))
                     == .absent)
        precondition(HotspotInterface.discover(snapshot([bridge100],
                                                        [ipv4("bridge100", netmask: "255.255.255.0")]))
                     == .absent)
        // A missing value on the hotspot link is not proof of absence.
        precondition(HotspotInterface.discover(snapshot([bridge100],
                                                        [ipv4("bridge100", netmask: nil)]))
                     == .unreadable)
        precondition(HotspotInterface.discover(snapshot([bridge100],
                                                        [ipv4("bridge100", address: nil)]))
                     == .unreadable)
        // A down link is absent, and an unreadable unrelated address is still
        // inconclusive because it could be the hotspot.
        precondition(HotspotInterface.discover(snapshot([], [ipv4("bridge100", up: false)]))
                     == .absent)
        precondition(HotspotInterface.discover(snapshot([wifi], [ipv4("en0", address: nil)]))
                     == .unreadable)
    }

    /// The real read must return a snapshot or nil. A found result can only
    /// name the supported hotspot address.
    static func checkPendingDiscovery() {
        if let snapshot = HotspotInterface.readSnapshot() {
            switch HotspotInterface.discover(snapshot) {
            case .found(let identity):
                precondition(identity.address == HotspotInterface.hotspotAddress)
            case .absent, .unsupported, .ambiguous, .unreadable:
                break
            }
        }
    }

    /// The loss detector needs a continuous interval of observed absence for a
    /// missing address, and stops at once on a known identity change.
    static func checkLossDetector() {
        let bound = HotspotInterface.hotspotAddress
        let real = HotspotInterface.builtIn
        // A failed address read is not evidence that the hotspot is absent.
        precondition(HotspotInterface.classifyAddresses([], identity: real) == .absent)
        precondition(HotspotInterface.classifyAddresses(["172.20.10.9"], identity: real) == .absent)
        precondition(HotspotInterface.classifyAddresses(["172.20.10.9", nil], identity: real) == .unreadable)
        precondition(HotspotInterface.classifyAddresses([nil, bound], identity: real) == .present(bound))
        // The default argument reads the one accessor.
        let effective = HotspotInterface.current
        precondition(HotspotInterface.classifyAddresses([effective.address])
                     == .present(effective.address))
        // The identity-aware classifier keeps the interface name.
        precondition(HotspotInterface.classifyLink([], identity: real) == .absent)
        precondition(HotspotInterface.classifyLink([bound], identity: real) == .present(real))
        precondition(HotspotInterface.classifyLink([nil, bound], identity: real) == .present(real))
        precondition(HotspotInterface.classifyLink([nil], identity: real) == .unreadable)

        var present = HotspotLossDetector(boundIdentity: real)
        for time in 0...30 {
            precondition(present.observe(.present(real), now: Double(time)) == .keepRunning)
        }

        // Extra checks cannot make time pass.
        var lost = HotspotLossDetector(boundIdentity: real)
        for _ in 0..<100 { precondition(lost.observe(.absent, now: 0) == .keepRunning) }
        for time in 1..<20 {
            precondition(lost.observe(.absent, now: Double(time)) == .keepRunning)
        }
        precondition(lost.observe(.absent, now: 20) == .lost)

        // A recovered address starts a fresh absence interval.
        var flap = HotspotLossDetector(boundIdentity: real)
        for time in 0...10 {
            precondition(flap.observe(.absent, now: Double(time)) == .keepRunning)
        }
        precondition(flap.observe(.present(real), now: 11) == .keepRunning)
        for time in 12..<32 {
            precondition(flap.observe(.absent, now: Double(time)) == .keepRunning)
        }
        precondition(flap.observe(.absent, now: 32) == .lost)

        // Unreadable observations and long observation gaps break the evidence.
        var unknown = HotspotLossDetector(boundIdentity: real)
        for time in 0...19 {
            precondition(unknown.observe(.absent, now: Double(time)) == .keepRunning)
        }
        precondition(unknown.observe(.unreadable, now: 20) == .keepRunning)
        precondition(unknown.observe(.absent, now: 21) == .keepRunning)
        precondition(unknown.observe(.absent, now: 40) == .keepRunning)
        for time in 41..<60 {
            precondition(unknown.observe(.absent, now: Double(time)) == .keepRunning)
        }
        precondition(unknown.observe(.absent, now: 60) == .lost)

        // A different interface at the same address is a known change. It does
        // not wait for the absence interval.
        var moved = HotspotLossDetector(boundIdentity: real)
        let otherInterface = HotspotInterface.Identity(name: "bridge101", address: bound)
        precondition(moved.observe(.present(otherInterface), now: 0) == .identityChanged(otherInterface))
        // A present link with a different address is also a change.
        let otherAddress = HotspotInterface.Identity(name: "bridge100", address: "172.20.10.9")
        precondition(moved.observe(.present(otherAddress), now: 1) == .identityChanged(otherAddress))
        // Clock regression and scene reset are bounded.
        for time in 2...12 {
            precondition(moved.observe(.absent, now: Double(time)) == .keepRunning)
        }
        precondition(moved.observe(.absent, now: 7) == .keepRunning)
        moved.reset()
        for time in 13..<33 {
            precondition(moved.observe(.absent, now: Double(time)) == .keepRunning)
        }
        precondition(moved.observe(.absent, now: 33) == .lost)
        precondition(moved.observe(.absent, now: .nan) == .keepRunning)
        precondition(moved.absentSince == nil)

        // The hotspot address on an unsupported link is a known mismatch, not
        // a missing address. An unsupported link at another address says
        // nothing about the bound link.
        var unsupported = HotspotLossDetector(boundIdentity: real)
        let wifi = HotspotInterface.Identity(name: "en0", address: bound)
        precondition(unsupported.observe(.unsupported(wifi), now: 0) == .unsupportedLink(wifi))
        let otherWifi = HotspotInterface.Identity(name: "en0", address: "10.1.2.3")
        precondition(unsupported.observe(.unsupported(otherWifi), now: 1) == .keepRunning)
    }

    /// The same address on a different interface is a replacement, not
    /// continued presence. This is the regression the identity-aware watch
    /// covers.
    static func checkLinkContinuity() {
        let first = HotspotInterface.Identity(name: "bridge100",
                                              address: HotspotInterface.hotspotAddress)
        let second = HotspotInterface.Identity(name: "bridge101",
                                               address: HotspotInterface.hotspotAddress)
        var detector = HotspotLossDetector(boundIdentity: first)
        precondition(detector.observe(.present(first), now: 0) == .keepRunning)
        precondition(detector.observe(.present(second), now: 1) == .identityChanged(second))
        precondition(detector.observe(.present(second), now: 1.1) == .identityChanged(second))
        // A fresh detector does not use the second identity as its bound link.
        var fresh = HotspotLossDetector(boundIdentity: first)
        precondition(fresh.observe(.present(second), now: 0) == .identityChanged(second))
    }

    /// The store carries the latest identity-aware observation for the
    /// address-only pairing path.
    static func checkLinkObservationStore() {
        let first = HotspotInterface.Identity(name: "bridge100",
                                              address: HotspotInterface.hotspotAddress)
        HotspotInterface.recordLinkObservation(.present(first))
        precondition(HotspotInterface.latestLinkObservation == .present(first))
        let second = HotspotInterface.Identity(name: "bridge101",
                                               address: HotspotInterface.hotspotAddress)
        HotspotInterface.recordLinkObservation(.present(second))
        precondition(HotspotInterface.latestLinkObservation == .present(second))
        HotspotInterface.recordLinkObservation(.unreadable)
        precondition(HotspotInterface.latestLinkObservation == .unreadable)
    }

    #if DEBUG
    /// The override exists in a Debug build only.
    static func checkTestOverride() {
        guard let defaults = UserDefaults(suiteName: testSuite) else {
            print("FAIL: cannot make a test defaults suite")
            exit(1)
        }
        defaults.removePersistentDomain(forName: testSuite)
        defer { defaults.removePersistentDomain(forName: testSuite) }

        func set(_ interface: String?, _ address: String?) {
            defaults.removeObject(forKey: HotspotInterface.testInterfaceKey)
            defaults.removeObject(forKey: HotspotInterface.testAddressKey)
            if let interface = interface {
                defaults.set(interface, forKey: HotspotInterface.testInterfaceKey)
            }
            if let address = address {
                defaults.set(address, forKey: HotspotInterface.testAddressKey)
            }
        }

        func expectBuiltIn(line: Int = #line) {
            if HotspotInterface.current(in: defaults) != HotspotInterface.builtIn {
                print("FAIL line \(line): the invalid override must be ignored")
                exit(1)
            }
        }

        // A valid pair replaces the built-in pair.
        set("en0", "10.1.2.3")
        precondition(HotspotInterface.current(in: defaults)
                     == HotspotInterface.Identity(name: "en0", address: "10.1.2.3"))
        precondition(HotspotInterface.testOverrideNote(in: defaults)
                     == "Test hotspot override is active")
        // The built-in pair stays valid on bridge100.
        precondition(HotspotInterface.testOverride(interface: "bridge100", address: "172.20.10.1")
                     == HotspotInterface.builtIn)
        // Every private range and boundary is valid.
        for address in ["10.0.0.0", "10.255.255.255", "172.16.0.0", "172.31.255.255",
                        "192.168.0.0", "192.168.255.255"] {
            set("en0", address)
            precondition(HotspotInterface.current(in: defaults)
                         == HotspotInterface.Identity(name: "en0", address: address), address)
        }
        // Every valid interface name shape is accepted.
        for name in ["en", "en0", "abc", "abcdefgh", "abcdefgh123", "br0", "bridge100"] {
            set(name, "10.1.2.3")
            precondition(HotspotInterface.current(in: defaults)
                         == HotspotInterface.Identity(name: name, address: "10.1.2.3"), name)
        }

        // A partial pair keeps the built-in pair.
        set("en0", nil)
        expectBuiltIn()
        set(nil, "10.1.2.3")
        expectBuiltIn()
        set(nil, nil)
        expectBuiltIn()
        precondition(HotspotInterface.testOverrideNote(in: defaults) == nil)
        set("", "")
        expectBuiltIn()

        // A public address is not a test hotspot.
        for address in ["8.8.8.8", "1.1.1.1", "126.0.0.1", "172.15.0.1",
                        "172.32.0.1", "192.169.1.1", "11.0.0.1"] {
            set("en0", address)
            expectBuiltIn()
        }

        // A malformed address keeps the built-in pair.
        for address in ["", "10.0.0", "10.0.0.1.5", "10.0.0.256", "10.0.0.-1",
                        "10.0.0. 1", "10.0.0.01", "010.0.0.1", "10.0.0.1 ",
                        " 10.0.0.1", "10..0.1", "abc"] {
            set("en0", address)
            expectBuiltIn()
        }

        // A malformed interface name keeps the built-in pair.
        for name in ["", "EN0", "en-0", "en 0", " en0", "en0 ", "abcdefghi",
                     "en1234", "en0x", "0en"] {
            set(name, "10.1.2.3")
            expectBuiltIn()
        }

        // The supported hotspot address stays on a bridge name.
        set("bridge100", "172.20.10.1")
        precondition(HotspotInterface.current(in: defaults) == HotspotInterface.builtIn)
        precondition(HotspotInterface.testOverride(in: defaults) != nil)
        precondition(HotspotInterface.testOverride(interface: "bridge101", address: "172.20.10.1")
                     == HotspotInterface.Identity(name: "bridge101", address: "172.20.10.1"))
        for name in ["en0", "br0", "utun3", "bridge", "bridge01", "bridge1000"] {
            precondition(HotspotInterface.testOverride(interface: name, address: "172.20.10.1") == nil,
                         name)
        }
        // The bridge name shape is explicit, so a test cannot widen it.
        for name in ["bridge0", "bridge100", "bridge101", "bridge999"] {
            precondition(HotspotInterface.isBridgeName(name), name)
        }
        for name in ["bridge", "bridge01", "bridge1000", "bridge9999", "Bridge100", "bridge100x", "br100"] {
            precondition(!HotspotInterface.isBridgeName(name), name)
        }

        // The loopback pair is the Simulator test pair, and only on lo0.
        set("lo0", "127.0.0.1")
        precondition(HotspotInterface.current(in: defaults) == HotspotInterface.testLoopback)
        // A Debug build uses the pair as the identity-aware link too.
        precondition(HotspotInterface.observeLink(in: defaults)
                     == .present(HotspotInterface.testLoopback))
        set("en0", "127.0.0.1")
        expectBuiltIn()
        set("lo0", "127.0.0.2")
        expectBuiltIn()
        set("lo0", "127.0.0.1")

        // The mocked cellular path needs the explicit key and an active pair.
        defaults.removeObject(forKey: HotspotInterface.testCellularPathKey)
        precondition(!HotspotInterface.testCellularPathRequested(in: defaults))
        defaults.set(true, forKey: HotspotInterface.testCellularPathKey)
        precondition(HotspotInterface.testCellularPathRequested(in: defaults))
        set(nil, nil)
        precondition(!HotspotInterface.testCellularPathRequested(in: defaults))
        set("lo0", "127.0.0.1")
        precondition(HotspotInterface.testCellularPathRequested(in: defaults))
        defaults.removeObject(forKey: HotspotInterface.testCellularPathKey)
    }
    #else
    /// A build without DEBUG reads no override. The built-in pair stays.
    static func checkNoTestOverride() {
        guard let defaults = UserDefaults(suiteName: testSuite) else {
            print("FAIL: cannot make a test defaults suite")
            exit(1)
        }
        defaults.removePersistentDomain(forName: testSuite)
        defer { defaults.removePersistentDomain(forName: testSuite) }
        defaults.set("en0", forKey: "debug.hotspotInterface")
        defaults.set("10.1.2.3", forKey: "debug.hotspotAddress")
        precondition(HotspotInterface.current(in: defaults) == HotspotInterface.builtIn)
        // The Debug pair does not reach the identity-aware reader in Release.
        defaults.set("lo0", forKey: "debug.hotspotInterface")
        defaults.set("127.0.0.1", forKey: "debug.hotspotAddress")
        let debugPair = HotspotInterface.Identity(name: "lo0", address: "127.0.0.1")
        precondition(HotspotInterface.observeLink(in: defaults) != .present(debugPair),
                     "a Release build ignores the Debug hotspot pair")
    }
    #endif
}
