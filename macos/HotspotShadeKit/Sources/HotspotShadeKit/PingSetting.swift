import Foundation

// The stored "Let ping work" setting. The app keeps it across launches.
public protocol PingSettingStore: AnyObject {
    var letPingWork: Bool { get set }
}

public final class UserDefaultsPingSetting: PingSettingStore {
    public static let key = "letPingWork"
    private let defaults: UserDefaults

    public init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    // A missing value means on. This is the product default.
    public var letPingWork: Bool {
        get { defaults.object(forKey: Self.key) as? Bool ?? true }
        set { defaults.set(newValue, forKey: Self.key) }
    }
}
