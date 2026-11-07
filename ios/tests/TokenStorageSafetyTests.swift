import Foundation
import Security

private final class SafetySink: PairingCredentialSink {
    var token: String?
    func suspendPairing() { token = nil }
    func configurePairing(port: UInt16, token: String) { self.token = token }
}
private final class SafetyHost: TokenLifecycleHost {
    var tokenProxyRequested = false
    var tokenProxyState = "Stopped"
    var tokenPairingPort: UInt16 = 25000
    var activities: [String] = []
    func tokenActivity(_ message: String) { activities.append(message) }
    func tokenStateDidChange() {}
}

@main struct TokenStorageSafetyTests {
    static func main() {
        let old = "old-token", other = "other-token", next = "new-token"
        // Decode without accessing a real UserDefaults domain. A present value
        // of an unexpected type must not look like an absent credential.
        precondition(UserDefaultsLegacyTokenStore.decode(nil) == nil)
        precondition(UserDefaultsLegacyTokenStore.decode(old) == old)
        for value: Any in [42, Data([1]), ["unexpected"], ""] {
            let decoded = UserDefaultsLegacyTokenStore.decode(value)!
            let storage = FakeTokenStorage()
            let legacy = FakeLegacyStore(value: decoded)
            var generated = 0
            func makeStore() -> SecureTokenStore {
                SecureTokenStore(storage: storage, legacy: legacy,
                                 recoveryIntent: FakeRecoveryIntentStore(),
                                 generate: {
                    generated += 1
                    return next
                })
            }
            for _ in 0..<2 {
                precondition(makeStore().loadOrMigrate() == .failed(.invalidLegacyToken))
                precondition(makeStore().createInitial() == .unchanged(.tokenAlreadyPresent))
            }
            precondition(generated == 0 && storage.writeCount == 0 && legacy.removeCount == 0)
        }
        // An add can land even when both the write and its immediate read
        // report failure. A fresh store must adopt it, not generate another.
        do {
            let storage = FakeTokenStorage()
            storage.writeSteps = [.failureButStore(.keychainWriteFailed(-1))]
            storage.readSteps = [.value(nil), .failure(.keychainReadFailed(-2))]
            let legacy = FakeLegacyStore()
            var generated = 0
            func makeStore() -> SecureTokenStore {
                SecureTokenStore(storage: storage, legacy: legacy,
                                 recoveryIntent: FakeRecoveryIntentStore(),
                                 generate: {
                    generated += 1
                    return next
                })
            }
            precondition(makeStore().createInitial() == .uncertain(.keychainWriteFailed(-1)))
            precondition(makeStore().loadOrMigrate() == .loaded(next))
            precondition(generated == 1 && storage.writeCount == 1 && storage.deleteCount == 0)
        }
        let api = StatefulKeychainAPI()
        let item = KeychainItemID(service: "local.hotspotproxy.app", account: "proxyToken", synchronizable: false)
        let legacy = FakeLegacyStore(value: old)
        let marker = FakeRecoveryIntentStore()
        func store() -> SecureTokenStore {
            SecureTokenStore(storage: KeychainTokenStorage(api: api), legacy: legacy,
                             recoveryIntent: marker, generate: { next })
        }
        precondition(store().loadOrMigrate() == .migrated(old, legacyRemoved: false))
        precondition(legacy.value == old && legacy.removeCount == 0)
        precondition(store().loadOrMigrate() == .loaded(old))
        legacy.value = other
        for _ in 0..<3 {
            let s = store()
            precondition(s.loadOrMigrate() == .failed(.legacyConflict))
            precondition(s.rotate() == .conflict(.legacyConflict))
        }
        precondition(try! KeychainTokenStorage(api: api).readToken() == old)
        precondition(legacy.value == other && legacy.removeCount == 0)
        api.set(item, Data([0xff]))
        legacy.value = old
        precondition(store().restoreValidLegacyToken() == .unchanged(.recoveryRefused))
        precondition(store().replaceInvalidToken() == .unchanged(.recoveryRefused))
        precondition(legacy.value == old && legacy.removeCount == 0)
        marker.data = Data([1])
        api.set(item, nil)
        legacy.value = nil
        let restarted = store()
        precondition(restarted.loadOrMigrate() == .failed(.invalidRecoveryIntent))
        precondition(restarted.createInitial() == .unchanged(.invalidRecoveryIntent))
        precondition(marker.data != nil && (try! KeychainTokenStorage(api: api).readToken()) == nil)
        marker.data = nil
        marker.readError = .keychainReadFailed(-99)
        precondition(store().loadOrMigrate() == .failed(.keychainReadFailed(-99)))
        precondition(store().createInitial() == .unchanged(.keychainReadFailed(-99)))
        precondition(api.copy(item).data == nil && legacy.value == nil)
        let markerSink = SafetySink(), markerHost = SafetyHost()
        let markerLifecycle = TokenLifecycle(store: store(), pairing: markerSink)
        markerLifecycle.attach(host: markerHost)
        markerLifecycle.launch()
        markerLifecycle.retryLoadIfNeeded()
        precondition(markerSink.token == nil && api.copy(item).data == nil)
        marker.readError = nil
        let markerAPI = FakeKeychainAPI()
        markerAPI.defaultCopy = (errSecInteractionNotAllowed, nil)
        let markerStorage = FakeTokenStorage()
        let markerStore = SecureTokenStore(storage: markerStorage, legacy: FakeLegacyStore(), recoveryIntent: KeychainRecoveryIntentStore(api: markerAPI), generate: { next })
        precondition(markerStore.loadOrMigrate() == .failed(.keychainReadFailed(errSecInteractionNotAllowed)))
        precondition(markerStore.createInitial() == .unchanged(.keychainReadFailed(errSecInteractionNotAllowed)))
        precondition(markerStorage.readCount == 0 && markerStorage.writeCount == 0 && markerAPI.addCount == 0 && markerAPI.deleteCount == 0)
        let fake = FakeTokenStorage()
        do {
            try fake.writeToken(old)
            preconditionFailure("an update must not create a missing item")
        } catch let error as SecureTokenError {
            precondition(error == .keychainWriteFailed(errSecItemNotFound))
        } catch {
            preconditionFailure("unexpected update error")
        }
        precondition(fake.stored == nil)
        fake.readSteps = [.failure(.keychainReadFailed(-1))]
        let retryLegacy = FakeLegacyStore()
        let sink = SafetySink(), host = SafetyHost()
        let lifecycle = TokenLifecycle(store: SecureTokenStore(storage: fake, legacy: retryLegacy,
                                                               recoveryIntent: FakeRecoveryIntentStore(),
                                                               generate: { next }),
                                       pairing: sink)
        lifecycle.attach(host: host)
        lifecycle.launch()
        lifecycle.retryLoadIfNeeded()
        precondition(fake.writeCount == 1 && sink.token == nil)
        retryLegacy.value = old
        lifecycle.retryLoadIfNeeded()
        precondition(fake.writeCount == 1 && sink.token == nil)
        fake.stored = old
        lifecycle.retryLoadIfNeeded()
        precondition(fake.writeCount == 1 && sink.token == old)
        #if TOKEN_LIFECYCLE_TESTING
        // Exercise the dormant post-rotation failure branch without enabling
        // rotation in the app. A later retry may read but must never create or
        // migrate a credential during this launch.
        do {
            let storage = FakeTokenStorage(stored: old)
            let prior = FakeLegacyStore()
            let postSink = SafetySink(), postHost = SafetyHost()
            var generated = 0
            let post = TokenLifecycle(store: SecureTokenStore(storage: storage, legacy: prior,
                                                              recoveryIntent: FakeRecoveryIntentStore(),
                                                              generate: {
                generated += 1
                return next
            }), pairing: postSink)
            post.attach(host: postHost)
            post.launch()
            precondition(postSink.token == old)
            post.testReloadAfterRotationFailure()
            precondition(postSink.token == old)
            precondition(post.storageFailure == PlainMessage.tokenRotationReloaded)
            precondition(postHost.activities.last == PlainMessage.tokenRotationReloaded)
            storage.stored = nil
            post.testReloadAfterRotationFailure()
            precondition(post.lastError == .tokenUnavailableAfterFailure)
            for _ in 0..<2 { post.retryLoadIfNeeded() }
            precondition(post.lastError == .tokenUnavailableAfterFailure)
            precondition(postSink.token == nil && generated == 0 && storage.writeCount == 0)
            prior.value = old
            post.retryLoadIfNeeded()
            precondition(postSink.token == nil && storage.writeCount == 0 && prior.removeCount == 0)
            storage.stored = old
            post.retryLoadIfNeeded()
            precondition(postSink.token == old && generated == 0 && storage.writeCount == 0)
        }
        #endif
        // A later launch also adopts the existing value without creating one.
        let resumed = TokenLifecycle(store: SecureTokenStore(storage: fake, legacy: FakeLegacyStore(),
                                                             recoveryIntent: FakeRecoveryIntentStore()),
                                     pairing: sink)
        resumed.attach(host: host)
        resumed.launch()
        host.tokenProxyRequested = true
        resumed.rotate()
        precondition(fake.stored == old && sink.token == old && fake.writeCount == 1)
        print("Token storage safety tests passed")
    }
}
