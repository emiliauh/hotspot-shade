import Foundation

// The stored "I forgot this source device" intent. While the flag is set, the
// app never starts automatic pairing. Only an explicit Pair clears the flag.
public protocol ForgetIntentStore: AnyObject {
    var forgotIntent: Bool { get set }
}

// The product store. The key is stable so a relaunch keeps the intent.
public final class UserDefaultsForgetIntent: ForgetIntentStore {
    public static let key = "forgotIntent"
    private let defaults: UserDefaults

    public init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    public var forgotIntent: Bool {
        get {
            guard defaults.object(forKey: Self.key) != nil else { return false }
            return defaults.bool(forKey: Self.key)
        }
        set { defaults.set(newValue, forKey: Self.key) }
    }
}

// An in-memory store. It is the model default, so tests stay isolated. The app
// injects UserDefaultsForgetIntent to keep the intent across launches.
public final class MemoryForgetIntent: ForgetIntentStore {
    public var forgotIntent: Bool
    public init(_ forgotIntent: Bool = false) { self.forgotIntent = forgotIntent }
}
