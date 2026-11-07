import Foundation

// Hermetic tests for the token lifecycle that ProxyModel runs.
//
// `TokenLifecycle` is the code that ProxyModel calls for launch, retry,
// rotation, restore, and replacement. These tests drive it with fake storage
// and a recording pairing sink, so they exercise the real wiring between the
// token store and the pairing listener. They open no keychain, no socket, and
// no network. ProxyModel itself needs UIKit and cannot run in this harness;
// TokenLifecycleServerTests runs the same lifecycle against the real
// ProxyServer.
//
// The invariant checked after every step: the pairing listener runs exactly
// when the app holds a usable token, and then the listener, the in-memory
// token, and the stored token are the same value.

final class RecordingSink: PairingCredentialSink {
    enum Event: Equatable {
        case suspend
        case configure(UInt16, String)
    }

    private(set) var events: [Event] = []

    func suspendPairing() { events.append(.suspend) }

    func configurePairing(port: UInt16, token: String) {
        events.append(.configure(port, token))
    }

    /// The listener state. The real server treats an empty token or a zero
    /// port as a suspension, so this does too.
    var configured: (port: UInt16, token: String)? {
        guard case .configure(let port, let token)? = events.last,
              port != 0, !token.isEmpty else { return nil }
        return (port, token)
    }

    var listening: Bool { configured != nil }
    var suspendCount: Int { events.filter { $0 == .suspend }.count }
}

final class FakeHost: TokenLifecycleHost {
    var requested = false
    var state = "Stopped"
    var port: UInt16 = 25000
    private(set) var activities: [String] = []
    private(set) var changes = 0
    // The mirror that ProxyModel keeps in its published fields.
    private(set) var token = ""
    private(set) var failure: String?
    private(set) var ready = false
    private(set) var conflict = false
    private(set) var recovery: TokenRecoveryKind = .none
    weak var lifecycle: TokenLifecycle?

    var tokenProxyRequested: Bool { requested }
    var tokenProxyState: String { state }
    var tokenPairingPort: UInt16 { port }
    func tokenActivity(_ message: String) { activities.append(message) }
    func tokenStateDidChange() {
        changes += 1
        guard let lifecycle else { return }
        token = lifecycle.token
        failure = lifecycle.storageFailure
        ready = lifecycle.storageReady
        conflict = lifecycle.conflict
        recovery = lifecycle.recovery
    }
}

final class Rig {
    let storage: FakeTokenStorage
    let legacy: FakeLegacyStore
    let sink = RecordingSink()
    let host = FakeHost()
    let lifecycle: TokenLifecycle

    init(stored: String?, legacy legacyValue: String?, generated: [String?] = []) {
        storage = FakeTokenStorage(stored: stored)
        legacy = FakeLegacyStore(value: legacyValue)
        let feed = TokenFeed(generated)
        let store = SecureTokenStore(storage: storage, legacy: legacy,
                                     recoveryIntent: FakeRecoveryIntentStore(),
                                     generate: { feed.next() })
        // These tests keep the dormant staged transaction covered. The app
        // uses the default false gate and never reaches the store.
        lifecycle = TokenLifecycle(store: store, pairing: sink, rotationReviewed: true)
        host.lifecycle = lifecycle
        lifecycle.attach(host: host)
    }
}

@main
struct TokenLifecycleTests {
    static let keychainToken = "0123456789abcdef0123456789abcdef"
    static let legacyToken = "fedcba9876543210fedcba9876543210"
    static let otherLegacy = "aaaaaaaabbbbbbbbccccccccdddddddd"
    static let newToken = "00112233445566778899aabbccddeeff"
    static let laterToken = "ffeeddccbbaa99887766554433221100"
    static let invalid = "bad token"
    static let port: UInt16 = 25000

    static func check(_ condition: Bool, _ message: String, line: Int = #line) {
        if !condition {
            print("FAIL line \(line): \(message)")
            exit(1)
        }
    }

    static func checkEqual<T: Equatable>(_ actual: T, _ expected: T, _ label: String,
                                         line: Int = #line) {
        check(actual == expected, "\(label): got \(actual), expected \(expected)", line: line)
    }

    /// The listener runs exactly when the app holds a usable token, and then
    /// the listener, the memory copy, and the stored copy agree. The published
    /// mirror must match the lifecycle. A listener must never have been
    /// configured with an unusable token.
    static func invariant(_ rig: Rig, _ label: String, line: Int = #line) {
        let lifecycle = rig.lifecycle
        checkEqual(rig.sink.listening, lifecycle.tokenIsUsable,
                   "\(label): listener runs exactly when a usable token exists", line: line)
        if let configured = rig.sink.configured {
            checkEqual(configured.token, lifecycle.token,
                       "\(label): the listener holds the in-memory token", line: line)
            checkEqual(rig.storage.stored, lifecycle.token,
                       "\(label): the stored token is the one that pairing hands out", line: line)
            checkEqual(configured.port, port, "\(label): the saved port", line: line)
        } else {
            checkEqual(lifecycle.token, "", "\(label): no token in memory while suspended", line: line)
        }
        for event in rig.sink.events {
            if case .configure(_, let token) = event {
                check(SecureTokenRules.isValid(token),
                      "\(label): never configured with an unusable token", line: line)
            }
        }
        checkEqual(rig.host.token, lifecycle.token, "\(label): mirrored token", line: line)
        checkEqual(rig.host.failure, lifecycle.storageFailure, "\(label): mirrored failure", line: line)
        checkEqual(rig.host.ready, lifecycle.storageReady, "\(label): mirrored ready", line: line)
        checkEqual(rig.host.conflict, lifecycle.conflict, "\(label): mirrored conflict", line: line)
        checkEqual(rig.host.recovery, lifecycle.recovery, "\(label): mirrored recovery", line: line)
    }

    static func launched(stored: String?, legacy: String?,
                         generated: [String?] = []) -> Rig {
        let rig = Rig(stored: stored, legacy: legacy, generated: generated)
        rig.lifecycle.launch()
        return rig
    }

    // MARK: Launch

    static func main() {
        // Production leaves the review gate closed. The button and the action
        // must both refuse without touching storage.
        do {
            let sink = RecordingSink(), host = FakeHost()
            let storage = FakeTokenStorage(stored: keychainToken)
            let store = SecureTokenStore(storage: storage, legacy: FakeLegacyStore(),
                                         recoveryIntent: FakeRecoveryIntentStore(),
                                         generate: { newToken })
            let lifecycle = TokenLifecycle(store: store, pairing: sink)
            host.lifecycle = lifecycle
            lifecycle.attach(host: host)
            lifecycle.launch()
            check(!lifecycle.rotationReviewApproved, "the app review gate is closed")
            check(!lifecycle.canRotate, "the default review gate refuses rotation")
            check(!TokenRotationPolicy.canRotate(proxyRequested: false, state: "Stopped",
                                                 tokenUsable: true, storageReady: true),
                  "the default policy refuses rotation")
            lifecycle.rotate()
            checkEqual(storage.stored, keychainToken, "a refused rotation changes no token")
            checkEqual(storage.writeCount, 0, "a refused rotation writes no token")
            checkEqual(store.diagnostics.rotateAttempts, 0, "a refused rotation never reaches the store")
            checkEqual(sink.configured?.token, keychainToken, "pairing keeps the saved token")
        }
        let loaded = launched(stored: keychainToken, legacy: nil, generated: [newToken])
        invariant(loaded, "loaded")
        check(loaded.lifecycle.rotationReviewApproved, "the test review gate is open")
        check(loaded.lifecycle.canRotate, "rotation available while the review gate is open")
        loaded.lifecycle.rotate()
        invariant(loaded, "rotated")
        checkEqual(loaded.lifecycle.token, newToken, "rotation adopts the new token")
        checkEqual(loaded.storage.stored, newToken, "rotation stores the new token")
        check(loaded.host.activities.contains(PlainMessage.tokenRotated), "rotation announced")
        // A second rotation needs another generated token. With an empty feed
        // it refuses without changing storage or pairing.
        loaded.lifecycle.rotate()
        invariant(loaded, "second rotation refused")
        checkEqual(loaded.storage.stored, newToken, "failed rotation keeps the token")
        let created = launched(stored: nil, legacy: nil, generated: [newToken])
        invariant(created, "created")
        checkEqual(created.lifecycle.token, newToken, "fresh token confirmed")
        check(created.host.activities.contains(PlainMessage.tokenRecreated), "creation announced")
        let migrated = launched(stored: nil, legacy: legacyToken)
        invariant(migrated, "migrated")
        checkEqual(migrated.legacy.value, legacyToken, "old copy retained")
        checkEqual(migrated.lifecycle.token, legacyToken, "confirmed migration adopted")
        let conflict = launched(stored: keychainToken, legacy: legacyToken, generated: [newToken])
        check(conflict.lifecycle.conflict && !conflict.sink.listening, "conflict suspends pairing")
        check(!conflict.lifecycle.canRotate, "conflict refuses rotation")
        conflict.lifecycle.rotate()
        let conflictReads = conflict.storage.readCount
        let conflictLegacyReads = conflict.legacy.loadCount
        conflict.lifecycle.retryLoadIfNeeded()
        checkEqual(conflict.storage.readCount, conflictReads,
                   "a fixed conflict is not re-read during the launch")
        checkEqual(conflict.legacy.loadCount, conflictLegacyReads,
                   "a fixed conflict is not re-read during the launch")
        checkEqual(conflict.storage.stored, keychainToken, "conflict preserves item")
        checkEqual(conflict.legacy.value, legacyToken, "conflict preserves old copy")
        check(!conflict.sink.listening, "conflict stays suspended")
        let invalidRig = launched(stored: invalid, legacy: legacyToken, generated: [newToken])
        checkEqual(invalidRig.lifecycle.recovery, .none, "repair unavailable")
        invalidRig.lifecycle.restoreLegacy()
        invalidRig.lifecycle.replaceInvalid()
        checkEqual(invalidRig.storage.stored, invalid, "invalid item retained")
        checkEqual(invalidRig.legacy.value, legacyToken, "legacy credential retained")
        check(invalidRig.storage.writeCount == 0 && invalidRig.storage.deleteCount == 0 && !invalidRig.sink.listening, "repair attempt is non-destructive and suspended")
        let locked = Rig(stored: nil, legacy: nil, generated: [newToken])
        locked.storage.readSteps = [.failure(.keychainUnavailable(-25308))]
        locked.lifecycle.launch()
        locked.lifecycle.retryLoadIfNeeded()
        checkEqual(locked.storage.readCount, 2, "a transient failure is read again on retry")
        checkEqual(locked.storage.writeCount, 0, "failed load cannot create on retry")
        checkEqual(locked.lifecycle.lastError, .tokenUnavailableAfterFailure, "missing retry reports read-only state")
        check(!locked.sink.listening, "missing retry remains suspended")
        let unlocked = Rig(stored: keychainToken, legacy: nil)
        unlocked.storage.readSteps = [.failure(.keychainUnavailable(-25308))]
        unlocked.lifecycle.launch()
        check(!unlocked.sink.listening, "locked launch suspended")
        unlocked.lifecycle.retryLoadIfNeeded()
        invariant(unlocked, "confirmed retry")
        checkEqual(unlocked.lifecycle.token, keychainToken, "retry adopts existing token")
        // A start reservation refuses rotation across the start boundary.
        let reserved = launched(stored: keychainToken, legacy: nil, generated: [newToken])
        checkEqual(reserved.lifecycle.beginStart(), keychainToken, "start reservation returns the token")
        check(!reserved.lifecycle.canRotate, "rotation refused during a start reservation")
        reserved.lifecycle.rotate()
        checkEqual(reserved.storage.stored, keychainToken, "reserved start blocks rotation")
        reserved.lifecycle.endStart()
        check(reserved.lifecycle.canRotate, "rotation returns after the start reservation")
        let marker = FakeRecoveryIntentStore()
        marker.data = Data([1])
        let storage = FakeTokenStorage()
        let sink = RecordingSink(), host = FakeHost()
        let lifecycle = TokenLifecycle(store: SecureTokenStore(storage: storage,
                                                               legacy: FakeLegacyStore(),
                                                               recoveryIntent: marker,
                                                               generate: { newToken }),
                                       pairing: sink,
                                       rotationReviewed: true)
        host.lifecycle = lifecycle
        lifecycle.attach(host: host)
        lifecycle.launch()
        lifecycle.retryLoadIfNeeded()
        checkEqual(lifecycle.lastError, .invalidRecoveryIntent, "unknown marker blocks restarted lifecycle")
        checkEqual(marker.readCount, 1, "a damaged rotation record is not re-read during the launch")
        check(!sink.listening && storage.writeCount == 0 && marker.data != nil, "marker prevents pairing and creation")
        print("TokenLifecycleTests passed")
    }
}
