import Foundation

#if canImport(CoreWLAN)
import CoreWLAN
#endif

// What the target device knows about its Wi-Fi link. The app never reads the
// network name and never asks for location permission.
public struct WiFiLinkInfo: Equatable {
    public enum Band: String, Equatable {
        case ghz2_4 = "2.4 GHz", ghz5 = "5 GHz", ghz6 = "6 GHz", unknown = "unknown"
    }
    public var band: Band
    public var channelWidthMHz: Int?
    public var rssi: Int?
    public var interfaceName: String?
    public var isWiFi: Bool
    public init(band: Band = .unknown, channelWidthMHz: Int? = nil, rssi: Int? = nil, interfaceName: String? = nil, isWiFi: Bool = true) {
        self.band = band; self.channelWidthMHz = channelWidthMHz; self.rssi = rssi; self.interfaceName = interfaceName; self.isWiFi = isWiFi
    }
}

// The link reader. The model calls it at most once every 10 seconds while the
// window is visible. Tests use a fake.
public protocol LinkInfoProvider: AnyObject {
    func currentLink() -> WiFiLinkInfo?
}

public final class NoLinkInfoProvider: LinkInfoProvider {
    public init() {}
    public func currentLink() -> WiFiLinkInfo? { nil }
}

// The plain advice lines for the window. It is pure, so every branch is a test.
public enum LinkAdvice {
    // Return the advice for the current link. The line applies only when the
    // tunnel runs and the pinned interface is the Wi-Fi interface.
    public static func advice(running: Bool, statusIface: String?, link: WiFiLinkInfo?) -> [String] {
        guard running, let link, link.isWiFi else { return [] }
        // Compare names only when both sides name the interface. A missing
        // name on either side is not proof that the link is not pinned.
        guard let statusIface, let linkIface = link.interfaceName, statusIface == linkIface else { return [] }
        var lines: [String] = []
        if link.band == .ghz2_4 { lines.append(Strings.slowWiFi) }
        if let rssi = link.rssi, rssi < -75 { lines.append(Strings.weakWiFi) }
        return lines
    }
}

#if canImport(CoreWLAN)
// Read the current Wi-Fi channel and signal. The type returns nil when macOS
// gives no interface. It needs no permission for these values.
public final class CoreWLANLinkInfoProvider: LinkInfoProvider {
    public init() {}
    public func currentLink() -> WiFiLinkInfo? {
        guard let interface = CWWiFiClient.shared().interface() else { return nil }
        let channel = interface.wlanChannel()
        let band: WiFiLinkInfo.Band
        switch channel?.channelBand {
        case .band2GHz: band = .ghz2_4
        case .band5GHz: band = .ghz5
        case .band6GHz: band = .ghz6
        default: band = .unknown
        }
        let width: Int?
        switch channel?.channelWidth {
        case .width20MHz: width = 20
        case .width40MHz: width = 40
        case .width80MHz: width = 80
        case .width160MHz: width = 160
        default: width = nil
        }
        // A value of 0 means that macOS has no measurement, not a real signal.
        let rssi = interface.rssiValue()
        return WiFiLinkInfo(band: band, channelWidthMHz: width, rssi: rssi == 0 ? nil : rssi, interfaceName: interface.interfaceName, isWiFi: true)
    }
}
#endif
