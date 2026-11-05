import Foundation
import Darwin

/// The Personal Hotspot network that the proxy binds to. A real Personal
/// Hotspot uses `bridge100` and `172.20.10.1`. A Debug build can use a test
/// pair for the iOS Simulator. See "Simulator test override" in
/// `ios/README.md`.
enum HotspotInterface {
    /// One interface name and IPv4 address pair.
    struct Identity: Equatable {
        let name: String
        let address: String
    }

    /// The pair of a real Personal Hotspot.
    static let builtIn = Identity(name: "bridge100", address: "172.20.10.1")

    /// The effective pair. Use this accessor for every interface read and
    /// every listener bind.
    static var current: Identity { current(in: .standard) }

    /// The effective pair for one defaults store. A Debug build reads the
    /// test override. A Release build returns `builtIn` and reads no key.
    static func current(in defaults: UserDefaults) -> Identity {
        #if DEBUG
        if let override = testOverride(in: defaults) { return override }
        #endif
        return builtIn
    }

    #if DEBUG
    // The app reads two UserDefaults keys. Both keys must hold a valid pair.
    // A missing or invalid value keeps `builtIn`. A Release build holds no
    // code from this section, so it cannot read an override.

    static let testInterfaceKey = "debug.hotspotInterface"
    static let testAddressKey = "debug.hotspotAddress"
    /// The diagnostics line for an active override.
    static let testOverrideLabel = "Test hotspot override is active"

    /// The override pair from one defaults store. Return nil when either key
    /// is absent or the pair is invalid.
    static func testOverride(in defaults: UserDefaults) -> Identity? {
        guard let name = defaults.string(forKey: testInterfaceKey),
              let address = defaults.string(forKey: testAddressKey) else { return nil }
        return testOverride(interface: name, address: address)
    }

    /// The diagnostics line for an active override, or nil.
    static func testOverrideNote(in defaults: UserDefaults = .standard) -> String? {
        testOverride(in: defaults) == nil ? nil : testOverrideLabel
    }

    /// Validate one pair. Reject the whole pair when one value is invalid.
    static func testOverride(interface: String, address: String) -> Identity? {
        guard isValidInterfaceName(interface), isPrivateIPv4(address) else { return nil }
        // 172.20.10.1 belongs to bridge100. Do not use it on another interface.
        if address == builtIn.address && interface != builtIn.name { return nil }
        return Identity(name: interface, address: address)
    }

    /// True for 1 to 8 lower case letters and up to 3 digits.
    static func isValidInterfaceName(_ name: String) -> Bool {
        var letters = 0
        var digits = 0
        var sawDigit = false
        for scalar in name.unicodeScalars {
            switch scalar.value {
            case 0x61...0x7A:
                guard !sawDigit else { return false }
                letters += 1
            case 0x30...0x39:
                sawDigit = true
                digits += 1
            default:
                return false
            }
        }
        return letters >= 1 && letters <= 8 && digits <= 3
    }

    /// True for a dotted quad in 10.0.0.0/8, 172.16.0.0/12, or
    /// 192.168.0.0/16.
    static func isPrivateIPv4(_ text: String) -> Bool {
        guard let octets = ipv4Octets(text) else { return false }
        switch (octets[0], octets[1]) {
        case (10, _): return true
        case (172, 16...31): return true
        case (192, 168): return true
        default: return false
        }
    }

    /// The four octets of a dotted quad, or nil. Reject a sign, a space, a
    /// leading zero, and a value above 255.
    static func ipv4Octets(_ text: String) -> [Int]? {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var octets: [Int] = []
        for part in parts {
            guard (1...3).contains(part.count),
                  part.allSatisfy({ $0 >= "0" && $0 <= "9" }),
                  part.first != "0" || part.count == 1,
                  let value = Int(part), (0...255).contains(value) else { return nil }
            octets.append(value)
        }
        return octets
    }
    #endif

    /// What one look at the network interfaces shows.
    enum Observation: Equatable {
        /// The hotspot interface is up and holds the hotspot IPv4 address.
        case present(String)
        /// The interface list was read, and the hotspot address is not in it.
        case absent
        /// The interface list or a hotspot address could not be read.
        case unreadable
    }

    /// A failed address read is inconclusive unless another entry proves
    /// presence. The default pair comes from the one accessor.
    static func classifyAddresses(_ addresses: [String?],
                                  identity: Identity = HotspotInterface.current) -> Observation {
        if addresses.contains(where: { $0 == identity.address }) {
            return .present(identity.address)
        }
        return addresses.contains(where: { $0 == nil }) ? .unreadable : .absent
    }

    static func observe() -> Observation {
        let identity = current
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0 else { return .unreadable }
        defer { freeifaddrs(list) }
        var cursor = list
        var addresses: [String?] = []
        while let entry = cursor {
            let item = entry.pointee
            if let addr = item.ifa_addr, addr.pointee.sa_family == UInt8(AF_INET),
               (item.ifa_flags & UInt32(IFF_UP)) != 0,
               String(cString: item.ifa_name) == identity.name {
                var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                if getnameinfo(addr, socklen_t(addr.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 {
                    addresses.append(String(cString: host))
                } else {
                    addresses.append(nil)
                }
            }
            cursor = item.ifa_next
        }
        return classifyAddresses(addresses, identity: identity)
    }
}

/// Decide when the bound hotspot address is gone. Require a continuous
/// interval of observed absence. An unreadable list or a long gap is not proof
/// that the address stayed absent.
struct HotspotLossDetector {
    let boundAddress: String
    let absenceRequired: TimeInterval
    let maximumObservationGap: TimeInterval
    private(set) var absentSince: TimeInterval?
    private(set) var lastAbsentAt: TimeInterval?

    init(boundAddress: String, absenceRequired: TimeInterval = 20, maximumObservationGap: TimeInterval = 5) {
        precondition(absenceRequired > 0 && absenceRequired.isFinite)
        precondition(maximumObservationGap > 0 && maximumObservationGap.isFinite)
        self.boundAddress = boundAddress
        self.absenceRequired = absenceRequired
        self.maximumObservationGap = maximumObservationGap
    }

    mutating func reset() {
        absentSince = nil
        lastAbsentAt = nil
    }

    /// Return true after at least two observations over the absence interval.
    mutating func observe(_ observation: HotspotInterface.Observation,
                          now: TimeInterval = ProcessInfo.processInfo.systemUptime) -> Bool {
        guard now.isFinite else {
            reset()
            return false
        }
        switch observation {
        case .unreadable:
            reset()
            return false
        case .present(let address) where address == boundAddress:
            reset()
            return false
        case .present, .absent:
            // A different address means the proxy no longer listens on the hotspot.
            guard let last = lastAbsentAt, let start = absentSince,
                  now >= last, now - last <= maximumObservationGap else {
                absentSince = now
                lastAbsentAt = now
                return false
            }
            lastAbsentAt = now
            return now - start >= absenceRequired
        }
    }
}
