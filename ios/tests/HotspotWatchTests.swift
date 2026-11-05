import Foundation

@main
struct HotspotWatchTests {
    /// A defaults suite for the tests. The tests never touch the standard
    /// defaults.
    static let testSuite = "local.hotspotproxy.hotspotwatch.tests"

    static func main() {
        let bound = "172.20.10.1"
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
        var present = HotspotLossDetector(boundAddress: bound)
        for time in 0...30 { precondition(!present.observe(.present(bound), now: Double(time))) }

        // Extra checks cannot make time pass.
        var lost = HotspotLossDetector(boundAddress: bound)
        for _ in 0..<100 { precondition(!lost.observe(.absent, now: 0)) }
        for time in 1..<20 { precondition(!lost.observe(.absent, now: Double(time))) }
        precondition(lost.observe(.absent, now: 20))

        // A recovered address starts a fresh absence interval.
        var flap = HotspotLossDetector(boundAddress: bound)
        for time in 0...10 { precondition(!flap.observe(.absent, now: Double(time))) }
        precondition(!flap.observe(.present(bound), now: 11))
        for time in 12..<32 { precondition(!flap.observe(.absent, now: Double(time))) }
        precondition(flap.observe(.absent, now: 32))

        // Unreadable observations and long observation gaps break the evidence.
        var unknown = HotspotLossDetector(boundAddress: bound)
        for time in 0...19 { precondition(!unknown.observe(.absent, now: Double(time))) }
        precondition(!unknown.observe(HotspotInterface.classifyAddresses([nil], identity: real), now: 20))
        precondition(!unknown.observe(.absent, now: 21))
        precondition(!unknown.observe(.absent, now: 40))
        for time in 41..<60 { precondition(!unknown.observe(.absent, now: Double(time))) }
        precondition(unknown.observe(.absent, now: 60))

        // A different address, clock regression, and scene reset are bounded.
        var moved = HotspotLossDetector(boundAddress: bound)
        for time in 0...10 { precondition(!moved.observe(.present("172.20.10.9"), now: Double(time))) }
        precondition(!moved.observe(.absent, now: 5))
        moved.reset()
        for time in 6..<26 { precondition(!moved.observe(.absent, now: Double(time))) }
        precondition(moved.observe(.absent, now: 26))
        precondition(!moved.observe(.absent, now: .nan))
        precondition(moved.absentSince == nil)

        #if DEBUG
        checkTestOverride()
        #else
        checkNoTestOverride()
        #endif

        switch HotspotInterface.observe() {
        case .present(let address): precondition(address == HotspotInterface.current.address)
        case .absent, .unreadable: break
        }
        print("Hotspot watch tests passed")
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

        // 172.20.10.1 is valid only on bridge100.
        set("en0", "172.20.10.1")
        expectBuiltIn()
        set("bridge100", "172.20.10.1")
        precondition(HotspotInterface.current(in: defaults) == HotspotInterface.builtIn)
        precondition(HotspotInterface.testOverride(in: defaults) != nil)
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
    }
    #endif
}
