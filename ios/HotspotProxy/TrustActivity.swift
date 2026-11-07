import Foundation
import CryptoKit

// One change to the trusted target device list, and the list that Settings
// shows. This file uses Foundation and CryptoKit only. The activity line holds
// no name, address, port, code, or token.

/// A change to the trusted list. The app records one plain activity line.
enum TrustChange: Equatable {
    /// A new target device paired.
    case added
    /// A paired target device asked this source device to forget it.
    case removed
    /// The person forgot every target device.
    case forgottenAll

    /// The plain Recent activity line.
    var activity: String {
        switch self {
        case .added: return PlainMessage.paired
        case .removed: return PlainMessage.targetRemoved
        case .forgottenAll: return PlainMessage.forgotten
        }
    }

    /// Map a change in the trusted count to one change. A Forget all wins over
    /// the count. No change gives nil, so the app records no line.
    static func change(previous: Int, current: Int, forgottenAll: Bool = false) -> TrustChange? {
        if forgottenAll { return .forgottenAll }
        if current > previous { return .added }
        if current < previous { return .removed }
        return nil
    }
}

/// Wrap the trusted key list, so the server publishes the count on every
/// change. A remote FORGET calls this wrapper through the responder. Forget all
/// calls it from the app. The wrapper holds no key in its own state.
final class ObservableTrustStore: PairingTrustStore {
    private let base: PairingTrustStore
    private let lock = NSLock()
    private var handler: ((TrustChange) -> Void)?

    init(_ base: PairingTrustStore) {
        self.base = base
    }

    /// Set the change handler. The handler runs on the caller's queue.
    func setChangeHandler(_ handler: ((TrustChange) -> Void)?) {
        lock.lock()
        self.handler = handler
        lock.unlock()
    }

    func contains(_ key: Data) -> Bool { base.contains(key) }

    func add(_ key: Data) {
        let before = base.count
        base.add(key)
        guard let change = TrustChange.change(previous: before, current: base.count) else { return }
        notify(change)
    }

    func remove(_ key: Data) {
        let before = base.count
        base.remove(key)
        guard let change = TrustChange.change(previous: before, current: base.count) else { return }
        notify(change)
    }

    func removeAll() {
        let before = base.count
        base.removeAll()
        guard before > 0,
              let change = TrustChange.change(previous: before, current: base.count, forgottenAll: true) else { return }
        notify(change)
    }

    var count: Int { base.count }
    var keys: [Data] { base.keys }

    private func notify(_ change: TrustChange) {
        lock.lock()
        let handler = self.handler
        lock.unlock()
        handler?(change)
    }
}

/// One trusted target device in Settings. It carries the public key, which is
/// the only thing the app stores about a target device, and a short label. The
/// label does not show the key. It matches the Android label for the same key.
struct TrustedTarget: Equatable, Identifiable {
    let key: Data
    var id: Data { key }
    var label: String { TrustFingerprint.label(for: key) }

    /// The text for assistive technology on the per-row Forget button.
    var forgetAccessibilityLabel: String { "Forget \(label)" }

    /// Build the Settings list from the stored keys, in stored order. A repeated
    /// key is listed once.
    static func list(_ keys: [Data]) -> [TrustedTarget] {
        var seen = Set<Data>()
        return keys.filter { seen.insert($0).inserted }.map { TrustedTarget(key: $0) }
    }
}

enum TrustFingerprint {
    /// "Target device " and the first four bytes of the SHA-256 digest of the
    /// public key, as eight lowercase hex digits. Two keys can share a label
    /// with a low probability. The Forget action uses the full key, never the
    /// label.
    static func label(for key: Data) -> String {
        let digest = SHA256.hash(data: key)
        let hex = digest.prefix(4).map { String(format: "%02x", $0) }.joined()
        return "Target device \(hex)"
    }
}
