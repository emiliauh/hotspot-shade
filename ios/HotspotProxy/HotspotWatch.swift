import Foundation
import Darwin

/// The Personal Hotspot network that the proxy binds to.
///
/// iOS has no public API that names the Personal Hotspot link. The app reads
/// the host interface table with `getifaddrs`, which is a POSIX API. It accepts
/// one link only when all of these hold:
///
/// - the link type is `IFT_BRIDGE`;
/// - the link is up and is not loopback;
/// - its IPv4 address is `172.20.10.1`;
/// - its IPv4 netmask is `255.255.255.240`.
///
/// The address and prefix are the observed Personal Hotspot convention. No
/// public API guarantees them. The link type check removes the old dependency
/// on the `bridge100` name, so a renamed bridge still works. If the address or
/// prefix changes, the app reports no hotspot and binds nothing. It never
/// falls back to Wi-Fi, cellular, or another interface.
///
/// Apple treats Personal Hotspot as a user feature, not a developer API. A
/// physical source device must confirm that its bridge reports `IFT_BRIDGE`
/// and the supported address. If either value differs, discovery fails closed
/// with no listener. It does not guess another interface.
///
/// A Debug build can use a test pair for the iOS Simulator. See "Simulator
/// test override" in `ios/README.md`. Release code holds no override.
enum HotspotInterface {
    /// One interface name and IPv4 address pair.
    struct Identity: Equatable, Hashable {
        let name: String
        let address: String
    }

    /// The compatibility pair for the documented Personal Hotspot subnet. It
    /// is the Debug override default and a fallback for callers that have no
    /// interface table. Discovery does not require this name.
    static let builtIn = Identity(name: "bridge100", address: "172.20.10.1")

    /// The only Personal Hotspot IPv4 address and prefix this build supports.
    static let hotspotAddress = "172.20.10.1"
    static let hotspotNetmask = "255.255.255.240"

    /// One link record from `getifaddrs`. A nil type means that the address
    /// family data was absent or unreadable.
    struct Link: Equatable {
        let name: String
        let type: UInt8?
    }

    /// One IPv4 record from `getifaddrs`. A nil address or netmask means that
    /// the numeric conversion failed.
    struct Address: Equatable {
        let name: String
        let isUp: Bool
        let isLoopback: Bool
        let address: String?
        let netmask: String?
    }

    /// One read of the interface table. Tests build the lists directly.
    struct Snapshot: Equatable {
        var links: [Link] = []
        var addresses: [Address] = []
    }

    /// The result of one discovery pass. `unsupported`, `ambiguous`, and
    /// `unreadable` fail closed. They are separate so a caller can tell a
    /// known link that this build cannot use from a link that is missing.
    enum Discovery: Equatable {
        case found(Identity)
        /// One complete up link holds the hotspot address and prefix, but its
        /// link type is not a bridge. The link is known, so a caller can report
        /// an unsupported link instead of claiming the address is absent.
        case unsupported(Identity)
        case absent
        case ambiguous
        case unreadable
    }

    /// The configured pair. A Debug build reads the test override. A Release
    /// build returns `builtIn` and reads no key. `observe()` uses discovery in
    /// a Release build, not this value.
    static var current: Identity { current(in: .standard) }

    /// The configured pair for one defaults store. A Debug build reads the
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
    /// A Debug Simulator build, or the host flow harness, can also replace the
    /// cellular pin with the host path. The key alone does nothing: the hotspot
    /// override must be active.
    static let testCellularPathKey = "debug.mockCellularPath"
    /// The loopback pair for a Simulator test. It never reaches another device.
    static let testLoopback = Identity(name: "lo0", address: "127.0.0.1")
    /// The diagnostics line for an active override.
    static let testOverrideLabel = "Test hotspot override is active"
    /// The diagnostics line for an active mocked cellular path.
    static let testCellularPathLabel = "The mocked cellular path is active"

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
        // The loopback pair is for a Simulator test only. It lets the Rust
        // target client in the same host reach the listener without a
        // mimicked hotspot interface. A Release build holds no code from
        // this section, so it cannot read the pair.
        if address == testLoopback.address {
            return interface == testLoopback.name ? testLoopback : nil
        }
        guard isValidInterfaceName(interface), isPrivateIPv4(address) else { return nil }
        // 172.20.10.1 is the hotspot address. Keep it on a bridge name so a
        // Debug test cannot point the supported address at Wi-Fi or cellular.
        if address == hotspotAddress && !isBridgeName(interface) { return nil }
        return Identity(name: interface, address: address)
    }

    /// True for the bridge name shape iOS uses, for example `bridge100`.
    static func isBridgeName(_ name: String) -> Bool {
        guard name.hasPrefix("bridge") else { return false }
        let suffix = name.dropFirst("bridge".count)
        guard (1...3).contains(suffix.count),
              suffix.first != "0" || suffix.count == 1,
              suffix.allSatisfy({ $0 >= "0" && $0 <= "9" }) else { return false }
        return true
    }

    /// True when the defaults ask for the mocked cellular path and a hotspot
    /// override is active. This is the pure part that the logic tests check.
    /// The path is used only from `testCellularPathActive`.
    static func testCellularPathRequested(in defaults: UserDefaults) -> Bool {
        defaults.bool(forKey: testCellularPathKey) && testOverride(in: defaults) != nil
    }

    /// True only in a Debug Simulator build or the host flow harness. A device
    /// build and a Release build keep the cellular pin. The mocked path uses
    /// the host path, so a test can reach a loopback destination without a
    /// cellular bearer. The macOS branch is compiled only when the same source
    /// runs in the host harness, never in the iOS app.
    static func testCellularPathActive(in defaults: UserDefaults = .standard) -> Bool {
        #if DEBUG
        #if targetEnvironment(simulator)
        return testCellularPathRequested(in: defaults)
        #elseif os(macOS)
        return testCellularPathRequested(in: defaults)
        #else
        return false
        #endif
        #else
        return false
        #endif
    }

    /// The diagnostics line for an active mocked path, or nil. The line holds
    /// no address.
    static func testCellularPathNote(in defaults: UserDefaults = .standard) -> String? {
        testCellularPathActive(in: defaults) ? testCellularPathLabel : nil
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

    /// One identity-aware look at the hotspot link.
    ///
    /// Unlike `Observation`, this keeps the interface name. A caller can then
    /// tell the link it used from a new link that reused the same address. The
    /// name is one local interface record. It does not prove that Personal
    /// Hotspot is on, that a target device is connected, or that another
    /// source device is not using the same name and address.
    enum LinkObservation: Equatable {
        /// One supported bridge is up with the hotspot address.
        case present(Identity)
        /// The hotspot address and prefix are on one complete up link whose
        /// link type this build does not support. The link is known, so this is
        /// not the same as a missing address.
        case unsupported(Identity)
        /// The interface list was read, and the hotspot address is not in it.
        case absent
        /// More than one complete up link could be the hotspot, so the pass
        /// cannot tell which one it is. A caller treats it like an unreadable
        /// list for decisions, and uses its own words for the person.
        case ambiguous
        /// The interface list or a hotspot address could not be read.
        case unreadable
    }

    /// A failed address read is inconclusive unless another entry proves
    /// presence. The Debug override uses this path because a test interface is
    /// not a Personal Hotspot bridge.
    static func classifyAddresses(_ addresses: [String?],
                                  identity: Identity = HotspotInterface.current) -> Observation {
        if addresses.contains(where: { $0 == identity.address }) {
            return .present(identity.address)
        }
        return addresses.contains(where: { $0 == nil }) ? .unreadable : .absent
    }

    /// Classify the addresses of one exact interface for a Debug override.
    /// The override names its own supported pair, so a matching address is a
    /// present link and is never reported as an unsupported type.
    static func classifyLink(_ addresses: [String?],
                             identity: Identity = HotspotInterface.current) -> LinkObservation {
        switch classifyAddresses(addresses, identity: identity) {
        case .present(let address): return .present(Identity(name: identity.name, address: address))
        case .absent: return .absent
        case .unreadable: return .unreadable
        }
    }

    /// Pick the one Personal Hotspot link from a snapshot.
    ///
    /// The result is `absent` only when every IPv4 record was readable and no
    /// link with the hotspot address and prefix matched. A failed IPv4 read
    /// makes the pass `unreadable`, because the failed record could be the
    /// hotspot. A second supported match makes the pass `ambiguous`. A single
    /// complete match whose link type is not a bridge is `unsupported`. Every
    /// non-`found` result fails closed.
    static func discover(_ snapshot: Snapshot) -> Discovery {
        var knownTypes: [String: Set<UInt8>] = [:]
        var unknownTypes: Set<String> = []
        for link in snapshot.links {
            if let type = link.type {
                knownTypes[link.name, default: []].insert(type)
            } else {
                unknownTypes.insert(link.name)
            }
        }

        var supported: Set<Identity> = []
        var unsupported: Set<Identity> = []
        for address in snapshot.addresses {
            guard address.isUp, !address.isLoopback else { continue }
            guard let value = address.address else {
                // The failed record could be the hotspot address.
                return .unreadable
            }
            guard value == hotspotAddress else { continue }
            guard let netmask = address.netmask else {
                // The address matches, so the missing mask is inconclusive.
                return .unreadable
            }
            // A different mask is a different network. Do not accept an
            // arbitrary private bridge.
            guard netmask == hotspotNetmask else { continue }
            guard !unknownTypes.contains(address.name) else { return .unreadable }
            let types = knownTypes[address.name] ?? []
            guard types.count == 1, let type = types.first else {
                // A missing or conflicting link type cannot prove a bridge.
                return .unreadable
            }
            let identity = Identity(name: address.name, address: value)
            if type == UInt8(IFT_BRIDGE) {
                supported.insert(identity)
            } else {
                unsupported.insert(identity)
            }
        }

        // One supported link is the only result a listener may use. A second
        // supported link, or a supported link beside another complete link at
        // the same address, is ambiguous.
        if supported.count == 1 && unsupported.isEmpty { return .found(supported.first!) }
        if supported.isEmpty && unsupported.count == 1 { return .unsupported(unsupported.first!) }
        if supported.isEmpty && unsupported.isEmpty { return .absent }
        return .ambiguous
    }

    /// Map one discovery result to the identity-aware observation.
    static func classify(_ discovery: Discovery) -> LinkObservation {
        switch discovery {
        case .found(let identity): return .present(identity)
        case .unsupported(let identity): return .unsupported(identity)
        case .absent: return .absent
        case .ambiguous: return .ambiguous
        case .unreadable: return .unreadable
        }
    }

    /// Read the interface table once. Return nil when the table cannot be
    /// read. A failed numeric conversion stays in the snapshot as a nil value,
    /// so discovery can fail closed.
    static func readSnapshot() -> Snapshot? {
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0 else { return nil }
        defer { freeifaddrs(list) }
        var snapshot = Snapshot()
        var cursor = list
        while let entry = cursor {
            let item = entry.pointee
            let name = String(cString: item.ifa_name)
            let isUp = (item.ifa_flags & UInt32(IFF_UP)) != 0
            if let addr = item.ifa_addr, addr.pointee.sa_family == UInt8(AF_LINK) {
                let type = item.ifa_data.map {
                    $0.assumingMemoryBound(to: if_data.self).pointee.ifi_type
                }
                snapshot.links.append(Link(name: name, type: type))
            } else if let addr = item.ifa_addr, addr.pointee.sa_family == UInt8(AF_INET) {
                let netmask = item.ifa_netmask.flatMap { numericHost($0) }
                snapshot.addresses.append(Address(
                    name: name,
                    isUp: isUp,
                    isLoopback: (item.ifa_flags & UInt32(IFF_LOOPBACK)) != 0,
                    address: numericHost(addr),
                    netmask: netmask))
            }
            cursor = item.ifa_next
        }
        return snapshot
    }

    private static func numericHost(_ address: UnsafeMutablePointer<sockaddr>) -> String? {
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        guard getnameinfo(address, socklen_t(address.pointee.sa_len),
                          &host, socklen_t(host.count),
                          nil, 0, NI_NUMERICHOST) == 0 else { return nil }
        return String(cString: host)
    }

    /// The address-only observation. The pairing path reads this form. It
    /// cannot name the interface behind the address, so it reports an
    /// unsupported link as absent. Use `observeLink()` when the caller needs
    /// to tell a replaced link from continuous presence.
    static func observe() -> Observation {
        switch observeLink() {
        case .present(let identity): return .present(identity.address)
        case .unsupported, .absent: return .absent
        case .ambiguous, .unreadable: return .unreadable
        }
    }

    /// The identity-aware observation. Every call records the result as the
    /// latest link observation, so a caller that receives only the address can
    /// check the interface name without reading the interface table again.
    static func observeLink(in defaults: UserDefaults = .standard) -> LinkObservation {
        let observation = readLinkObservation(in: defaults)
        recordLinkObservation(observation)
        return observation
    }

    private static func readLinkObservation(in defaults: UserDefaults) -> LinkObservation {
        #if DEBUG
        if let override = testOverride(in: defaults) {
            return observeIdentity(override)
        }
        #endif
        guard let snapshot = readSnapshot() else { return .unreadable }
        return classify(discover(snapshot))
    }

    /// Read the addresses of one exact interface for a Debug override.
    private static func observeIdentity(_ identity: Identity) -> LinkObservation {
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
                addresses.append(numericHost(addr))
            }
            cursor = item.ifa_next
        }
        return classifyLink(addresses, identity: identity)
    }

    // MARK: Link observation store

    /// The latest identity-aware observation. This is one value, not a
    /// history. It exists because the pairing path receives only the address:
    /// `ProxyServer.checkPairingHotspot()` calls `observe()` and then hands the
    /// address to `PairingListenerPolicy`. The policy reads this value and uses
    /// it only when its address matches the address it was given. A caller
    /// that can pass the identity should use `observeLink()` directly.
    private static let linkObservationLock = NSLock()
    private static var lastLinkObservation: LinkObservation?

    /// Record one identity-aware observation. `observeLink()` calls this for
    /// every read. A test can call it to seed the value for a policy.
    static func recordLinkObservation(_ observation: LinkObservation) {
        linkObservationLock.lock()
        lastLinkObservation = observation
        linkObservationLock.unlock()
    }

    /// The latest recorded observation, or nil before the first read.
    static var latestLinkObservation: LinkObservation? {
        linkObservationLock.lock()
        defer { linkObservationLock.unlock() }
        return lastLinkObservation
    }
}

/// Decide when the bound hotspot link is gone or replaced.
///
/// A missing address needs a continuous interval of observed absence. A
/// complete observation that names a different interface at the same address
/// is a known link change, so the detector reports it at once. So does an
/// unsupported link at the bound address. An unreadable list or a long gap is
/// not proof of either.
///
/// The interface name is one local record. It does not prove that Personal
/// Hotspot is on, that a target device is connected, or that a replacement
/// upstream network is different when it reuses the same name and address.
struct HotspotLossDetector {
    enum Decision: Equatable {
        case keepRunning
        /// The bound address stayed absent for the full interval.
        case lost
        /// A complete observation named another interface at the same address.
        case identityChanged(HotspotInterface.Identity)
        /// The hotspot address is on a link type this build does not support.
        case unsupportedLink(HotspotInterface.Identity)
    }

    let boundIdentity: HotspotInterface.Identity
    let absenceRequired: TimeInterval
    let maximumObservationGap: TimeInterval
    private(set) var absentSince: TimeInterval?
    private(set) var lastAbsentAt: TimeInterval?

    init(boundIdentity: HotspotInterface.Identity,
         absenceRequired: TimeInterval = 20,
         maximumObservationGap: TimeInterval = 5) {
        precondition(absenceRequired > 0 && absenceRequired.isFinite)
        precondition(maximumObservationGap > 0 && maximumObservationGap.isFinite)
        self.boundIdentity = boundIdentity
        self.absenceRequired = absenceRequired
        self.maximumObservationGap = maximumObservationGap
    }

    mutating func reset() {
        absentSince = nil
        lastAbsentAt = nil
    }

    /// Return the decision for one identity-aware observation.
    mutating func observe(_ observation: HotspotInterface.LinkObservation,
                          now: TimeInterval = ProcessInfo.processInfo.systemUptime) -> Decision {
        guard now.isFinite else {
            reset()
            return .keepRunning
        }
        switch observation {
        case .unreadable, .ambiguous:
            reset()
            return .keepRunning
        case .present(let identity) where identity == boundIdentity:
            reset()
            return .keepRunning
        case .present(let identity):
            // A complete read found one supported bridge at the bound address,
            // and it is not the bridge this run used. Do not keep a listener
            // that cannot prove it still uses the bound link.
            reset()
            return .identityChanged(identity)
        case .unsupported(let identity) where identity.address == boundIdentity.address:
            reset()
            return .unsupportedLink(identity)
        case .unsupported:
            // An unsupported link at another address says nothing about the
            // bound address.
            reset()
            return .keepRunning
        case .absent:
            guard let last = lastAbsentAt, let start = absentSince,
                  now >= last, now - last <= maximumObservationGap else {
                absentSince = now
                lastAbsentAt = now
                return .keepRunning
            }
            lastAbsentAt = now
            return now - start >= absenceRequired ? .lost : .keepRunning
        }
    }
}
