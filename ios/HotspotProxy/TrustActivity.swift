import Foundation

// One change to the trusted target device list. This file uses Foundation
// only. The activity line holds no name, address, port, code, or token.

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

    private func notify(_ change: TrustChange) {
        lock.lock()
        let handler = self.handler
        lock.unlock()
        handler?(change)
    }
}
