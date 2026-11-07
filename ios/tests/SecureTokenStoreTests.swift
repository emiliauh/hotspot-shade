import Foundation
import Security

// Hermetic tests for SecureTokenStore. They never open the real keychain.
// Every keychain call goes through FakeKeychainAPI or FakeTokenStorage.

@main
struct SecureTokenStoreTests {
    static let legacyToken = "0123456789abcdef0123456789abcdef"
    static let keychainToken = "fedcba9876543210fedcba9876543210"
    static let newToken = "00112233445566778899aabbccddeeff"

    static func check(_ condition: Bool, _ message: String, line: Int = #line) {
        if !condition {
            print("FAIL line \(line): \(message)")
            exit(1)
        }
    }

    static func checkEqual<T: Equatable>(_ actual: T,
                                         _ expected: T,
                                         _ label: String,
                                         line: Int = #line) {
        check(actual == expected, "\(label): got \(actual), expected \(expected)", line: line)
    }

    static func expectError<T>(_ expression: @autoclosure () throws -> T,
                               _ expected: SecureTokenError,
                               _ label: String,
                               line: Int = #line) {
        do {
            _ = try expression()
            check(false, "\(label): expected \(expected.code)", line: line)
        } catch let error as SecureTokenError {
            checkEqual(error, expected, label, line: line)
        } catch {
            check(false, "\(label): wrong error type \(error)", line: line)
        }
    }

    static func checkNoThrow(_ expression: @autoclosure () throws -> Void,
                             _ label: String,
                             line: Int = #line) {
        do {
            try expression()
        } catch {
            check(false, "\(label): \(error)", line: line)
        }
    }

    static func readValue(_ storage: TokenStorage,
                          _ label: String,
                          line: Int = #line) -> String? {
        do {
            return try storage.readToken()
        } catch {
            check(false, "\(label): \(error)", line: line)
            return nil
        }
    }

    static func makeStore(_ storage: FakeTokenStorage,
                          _ legacy: FakeLegacyStore,
                          _ feed: TokenFeed) -> SecureTokenStore {
        SecureTokenStore(storage: storage, legacy: legacy,
                         recoveryIntent: FakeRecoveryIntentStore(), generate: { feed.next() })
    }

    /// A valid keychain token and a different old copy are two credentials.
    /// The app must keep both and use neither.
    static func checkTokenConflict(stored: String,
                                   legacyValue: String,
                                   label: String,
                                   line: Int = #line) {
        let storage = FakeTokenStorage(stored: stored)
        let legacy = FakeLegacyStore(value: legacyValue)
        let store = makeStore(storage, legacy, TokenFeed([]))
        let result = store.loadOrMigrate()

        checkEqual(result, .failed(.legacyConflict),
                   "\(label): the load reports a conflict", line: line)
        check(result.token == nil, "\(label): neither token is used", line: line)
        checkEqual(storage.writeCount, 0,
                   "\(label): a loaded conflict is not rewritten", line: line)
        check(storage.stored == stored, "\(label): the keychain token stays", line: line)
        check(legacy.value == legacyValue, "\(label): the old copy stays", line: line)
        checkEqual(legacy.removeCount, 0, "\(label): the old copy is not deleted", line: line)
        checkEqual(store.diagnostics.legacyConflict, true,
                   "\(label): diagnostics report the conflict", line: line)
        check(store.diagnostics.text().contains("legacy_conflict"),
              "\(label): the conflict code is present", line: line)
        check(!store.diagnostics.text().contains(stored),
              "\(label): diagnostics hold no token", line: line)
    }

    static func chunks(of text: String, size: Int) -> [String] {
        let characters = Array(text)
        var result: [String] = []
        var index = 0
        while index + size <= characters.count {
            result.append(String(characters[index..<(index + size)]))
            index += size
        }
        return result
    }

    static func main() {
        testStatefulRecoveryAndRaces()
        // A concurrent insertion wins an add-only create.
        do {
            let storage = FakeTokenStorage()
            storage.onWrite = { storage.stored = keychainToken }
            let result = makeStore(storage, FakeLegacyStore(), TokenFeed([newToken])).createInitial()
            checkEqual(result, .uncertain(.tokenAlreadyPresent), "concurrent insert")
            checkEqual(storage.stored, keychainToken, "concurrent item survives")
        }
        // Nested store work is refused instead of deadlocking or mutating midway.
        do {
            let storage = FakeTokenStorage()
            let legacy = FakeLegacyStore()
            let nested = makeStore(storage, legacy, TokenFeed([keychainToken]))
            var nestedResult: TokenWriteResult?
            storage.onWrite = { nestedResult = nested.createInitial() }
            _ = makeStore(storage, legacy, TokenFeed([newToken])).createInitial()
            checkEqual(nestedResult, .unchanged(.recoveryRefused), "reentrant transaction")
            checkEqual(storage.stored, newToken, "outer transaction completes")
        }
        testRules()
        testMigration()
        testCreate()
        testRotation()
        testRotationPolicy()
        testRecoveryPolicy()
        testRecoveryKind()
        testRecovery()
        testRestoreLegacy()
        testKeychainAdapter()
        testAmbiguousStateMessages()
        testDiagnostics()
        print("Secure token store tests passed")
    }

    static func testStatefulRecoveryAndRaces() {
        let item = KeychainItemID(service: KeychainTokenStorage.defaultService, account: KeychainTokenStorage.defaultAccount, synchronizable: false)
        let api = StatefulKeychainAPI()
        let storage = KeychainTokenStorage(api: api)
        let legacy = FakeLegacyStore()
        let marker = FakeRecoveryIntentStore()
        func store() -> SecureTokenStore { SecureTokenStore(storage: storage, legacy: legacy, recoveryIntent: marker, generate: { newToken }) }
        api.beforeAdd = { id in if id == item { api.set(id, Data(keychainToken.utf8)) } }
        checkEqual(store().createInitial(), .uncertain(.tokenAlreadyPresent), "concurrent add")
        checkEqual(try? storage.readToken(), keychainToken, "concurrent item retained")
        api.beforeAdd = nil
        legacy.value = legacyToken
        checkEqual(store().loadOrMigrate(), .failed(.legacyConflict), "conflict detected")
        checkEqual(store().rotate(), .conflict(.legacyConflict), "conflict rotation refused")
        checkEqual(try? storage.readToken(), keychainToken, "keychain conflict retained")
        checkEqual(legacy.value, legacyToken, "legacy conflict retained")
        api.set(item, Data([0xff]))
        checkEqual(store().restoreValidLegacyToken(), .unchanged(.recoveryRefused), "invalid item restore refused")
        checkEqual(store().replaceInvalidToken(), .unchanged(.recoveryRefused), "invalid item replacement refused")
        checkEqual(api.copy(item).data, Data([0xff]), "unknown bytes retained")
        marker.data = Data([1])
        api.set(item, nil)
        legacy.value = nil
        checkEqual(store().loadOrMigrate(), .failed(.invalidRecoveryIntent), "unknown marker survives restart")
        checkEqual(store().createInitial(), .unchanged(.invalidRecoveryIntent), "unknown marker blocks create")
        check(marker.data != nil && api.copy(item).data == nil, "marker and empty item retained")
    }


    // MARK: Rules

    static func testRules() {
        checkEqual(UserDefaultsLegacyTokenStore.defaultKey, "proxyToken",
                   "the old token key stays proxyToken")
        check(SecureTokenRules.isValid(legacyToken), "a 32 character hex token is valid")
        check(SecureTokenRules.isValid("A"), "one printable character is valid")
        check(!SecureTokenRules.isValid(""), "an empty token is invalid")
        check(!SecureTokenRules.isValid("bad token"), "a space is invalid")
        check(!SecureTokenRules.isValid("bad\ntoken"), "a control character is invalid")
        check(!SecureTokenRules.isValid("tökén"), "a non ASCII token is invalid")
        check(!SecureTokenRules.isValid(String(repeating: "a", count: 256)), "over 255 is invalid")
        check(SecureTokenRules.isValid(String(repeating: "a", count: 255)), "255 is valid")

        let first = SecureRandomToken.make()
        let second = SecureRandomToken.make()
        check(first != nil, "the random source returns a token")
        check(second != nil, "the random source returns a second token")
        check(first?.count == 32, "the token is 32 hex characters")
        check(first != second, "two generated tokens differ")
        let hex = CharacterSet(charactersIn: "0123456789abcdef")
        if let first {
            check(first.unicodeScalars.allSatisfy { hex.contains($0) },
                  "the token uses lowercase hex only")
        }
        check(SecureRandomToken.make(byteCount: 0) == nil, "a zero length token is refused")
        check(SecureRandomToken.make(byteCount: -1) == nil, "a negative length token is refused")
    }

    // MARK: Migration

    static func testMigration() {
        // A valid old token is saved and confirmed; the old copy remains.
        do {
            let storage = FakeTokenStorage()
            let legacy = FakeLegacyStore(value: legacyToken)
            let feed = TokenFeed([])
            let store = makeStore(storage, legacy, feed)
            let result = store.loadOrMigrate()

            checkEqual(result, .migrated(legacyToken, legacyRemoved: false),
                       "a valid legacy token migrates")
            check(storage.stored == legacyToken, "the keychain holds the migrated token")
            checkEqual(storage.writeCount, 1, "one keychain write")
            checkEqual(storage.readCount, 2, "the write is read back")
            checkEqual(legacy.removeCount, 0, "the old copy is retained")
            check(legacy.value == legacyToken, "the old copy remains")
            checkEqual(feed.calls, 0, "migration never creates a new token")
            checkEqual(store.diagnostics.migrations, 1, "the migration is counted")
            checkEqual(store.diagnostics.confirmedWrites, 0, "migration is not a rotation write")
        }

        // An upgrade can find a keychain token from the newer store and a
        // different old copy created by a build that still used UserDefaults.
        checkTokenConflict(stored: keychainToken, legacyValue: legacyToken,
                           label: "upgrade conflict")

        // A downgrade can write a new token to UserDefaults while the older
        // keychain token stays. The next upgrade sees the same conflict.
        checkTokenConflict(stored: legacyToken, legacyValue: keychainToken,
                           label: "downgrade conflict")

        // The same token in both places is a duplicate, not an update.
        do {
            let storage = FakeTokenStorage(stored: legacyToken)
            let legacy = FakeLegacyStore(value: legacyToken)
            let feed = TokenFeed([])
            let result = makeStore(storage, legacy, feed).loadOrMigrate()

            checkEqual(result, .loaded(legacyToken), "a duplicate loads the keychain copy")
            checkEqual(storage.writeCount, 0, "a duplicate is not rewritten")
            checkEqual(legacy.removeCount, 0, "the duplicate old copy remains")
        }

        // A keychain error fails closed. The old copy stays.
        do {
            let storage = FakeTokenStorage()
            storage.readSteps = [.failure(.keychainUnavailable(-25308))]
            let legacy = FakeLegacyStore(value: legacyToken)
            let feed = TokenFeed([])
            let result = makeStore(storage, legacy, feed).loadOrMigrate()

            checkEqual(result, .failed(.keychainUnavailable(-25308)),
                       "unavailable keychain fails closed")
            checkEqual(storage.writeCount, 0, "no write after a read error")
            checkEqual(legacy.removeCount, 0, "the old copy is not removed")
            check(legacy.value == legacyToken, "the old copy stays")
            checkEqual(feed.calls, 0, "no new credential after a read error")
        }

        // Invalid keychain data fails closed. It does not fall back to legacy.
        do {
            let storage = FakeTokenStorage(stored: "bad token")
            let legacy = FakeLegacyStore(value: legacyToken)
            let feed = TokenFeed([])
            let result = makeStore(storage, legacy, feed).loadOrMigrate()

            checkEqual(result, .failed(.invalidStoredToken),
                       "invalid keychain data fails closed")
            checkEqual(storage.writeCount, 0, "invalid keychain data is not overwritten")
            checkEqual(legacy.removeCount, 0, "the old copy stays for recovery")
        }

        // No token anywhere is a normal missing result. Nothing is written.
        do {
            let storage = FakeTokenStorage()
            let legacy = FakeLegacyStore()
            let feed = TokenFeed([])
            let result = makeStore(storage, legacy, feed).loadOrMigrate()

            checkEqual(result, .missing, "no token is missing")
            checkEqual(storage.writeCount, 0, "missing makes no write")
            checkEqual(legacy.removeCount, 0, "missing removes nothing")
        }

        // A present empty value is ambiguous, not evidence of first use.
        do {
            let storage = FakeTokenStorage()
            let legacy = FakeLegacyStore(value: "")
            let feed = TokenFeed([])
            let result = makeStore(storage, legacy, feed).loadOrMigrate()

            checkEqual(result, .failed(.invalidLegacyToken), "an empty old value blocks creation")
            checkEqual(storage.writeCount, 0, "an empty old value is not written")
            checkEqual(feed.calls, 0, "an empty old value does not generate a token")
        }

        // Invalid old data fails closed and is not deleted.
        do {
            let storage = FakeTokenStorage()
            let legacy = FakeLegacyStore(value: "bad token")
            let feed = TokenFeed([])
            let result = makeStore(storage, legacy, feed).loadOrMigrate()

            checkEqual(result, .failed(.invalidLegacyToken),
                       "invalid old data fails closed")
            checkEqual(storage.writeCount, 0, "invalid old data is not written")
            checkEqual(legacy.removeCount, 0, "invalid old data is not deleted")
            check(legacy.value == "bad token", "the invalid old value stays")
        }

        // A failed keychain write leaves the old copy in place.
        do {
            let storage = FakeTokenStorage()
            storage.writeSteps = [.failure(.keychainWriteFailed(-34018))]
            let legacy = FakeLegacyStore(value: legacyToken)
            let feed = TokenFeed([])
            let result = makeStore(storage, legacy, feed).loadOrMigrate()

            checkEqual(result, .failed(.keychainWriteFailed(-34018)),
                       "a failed write fails the migration")
            checkEqual(legacy.removeCount, 0, "no deletion before confirmed persistence")
            check(legacy.value == legacyToken, "the old copy stays")
            check(storage.stored == nil, "no unconfirmed token is stored")
        }

        // A write that reports an error but persisted still counts as confirmed.
        do {
            let storage = FakeTokenStorage()
            storage.writeSteps = [.failureButStore(.keychainWriteFailed(-34018))]
            let legacy = FakeLegacyStore(value: legacyToken)
            let feed = TokenFeed([])
            let result = makeStore(storage, legacy, feed).loadOrMigrate()

            checkEqual(result, .migrated(legacyToken, legacyRemoved: false),
                       "a readable write is confirmed")
            check(storage.stored == legacyToken, "the token is in the keychain")
            check(legacy.value == legacyToken, "the old copy is retained after confirmation")
        }

        // A read-back failure keeps both the old copy and the unknown item.
        do {
            let storage = FakeTokenStorage()
            storage.readSteps = [.value(nil), .failureAndStore(.keychainUnavailable(-25308), "different-token")]
            let legacy = FakeLegacyStore(value: legacyToken)
            let feed = TokenFeed([])
            let result = makeStore(storage, legacy, feed).loadOrMigrate()

            checkEqual(result, .failed(.keychainUnavailable(-25308)),
                       "a read-back failure fails the migration")
            checkEqual(storage.deleteCount, 0, "the unknown item is not deleted")
            check(storage.stored == "different-token", "the concurrent item stays")
            checkEqual(legacy.removeCount, 0, "no deletion before confirmed persistence")
            check(legacy.value == legacyToken, "the old copy stays")
        }

        // A mismatched read-back is a verification failure. The old copy stays.
        do {
            let storage = FakeTokenStorage()
            storage.readSteps = [.value(nil), .valueAndStore("different-token")]
            let legacy = FakeLegacyStore(value: legacyToken)
            let feed = TokenFeed([])
            let result = makeStore(storage, legacy, feed).loadOrMigrate()

            checkEqual(result, .failed(.verificationFailed),
                       "a mismatch is a verification failure")
            checkEqual(storage.deleteCount, 0, "the different item is not deleted")
            check(storage.stored == "different-token", "the concurrent item stays")
            checkEqual(legacy.removeCount, 0, "the old copy stays")
            check(legacy.value == legacyToken, "the old copy is unchanged")
        }

        // A failed write followed by an unreadable concurrent item keeps both stores.
        do {
            let storage = FakeTokenStorage()
            storage.writeSteps = [.failure(.keychainWriteFailed(-34018))]
            storage.readSteps = [.value(nil), .failureAndStore(.keychainUnavailable(-25308), "different-token")]
            let legacy = FakeLegacyStore(value: legacyToken)
            let result = makeStore(storage, legacy, TokenFeed([])).loadOrMigrate()
            checkEqual(result, .failed(.keychainWriteFailed(-34018)), "the write error is reported")
            check(storage.stored == "different-token", "the unknown item stays")
            check(legacy.value == legacyToken, "the old copy stays")
            checkEqual(storage.deleteCount, 0, "no cleanup delete runs")
        }
        
        // A replacement legacy copy during migration is retained.
        do {
            let storage = FakeTokenStorage()
            let legacy = FakeLegacyStore(value: legacyToken)
            storage.onWrite = { legacy.value = keychainToken }
            let result = makeStore(storage, legacy, TokenFeed([])).loadOrMigrate()
            checkEqual(result, .failed(.legacyConflict), "a changed legacy copy is a conflict")
            check(legacy.value == keychainToken, "the concurrent legacy copy stays")
            checkEqual(legacy.removeCount, 0, "the changed legacy copy is not removed")
        }
        
        // A failed old-copy removal is reported, but the verified token is used.
        do {
            let storage = FakeTokenStorage()
            let legacy = FakeLegacyStore(value: legacyToken)
            legacy.removeResult = false
            let feed = TokenFeed([])
            let store = makeStore(storage, legacy, feed)
            let result = store.loadOrMigrate()

            checkEqual(result, .migrated(legacyToken, legacyRemoved: false),
                       "the verified token is reported")
            check(storage.stored == legacyToken, "the keychain token is kept")
            check(legacy.value == legacyToken, "the old copy still exists")
            check(store.diagnostics.legacyCleanupPending, "cleanup is pending")
        }
    }

    // MARK: Create

    static func testCreate() {
        // First run writes one token and reads it back.
        do {
            let storage = FakeTokenStorage()
            let legacy = FakeLegacyStore()
            let feed = TokenFeed([newToken])
            let store = makeStore(storage, legacy, feed)
            let result = store.createInitial()

            checkEqual(result, .saved(newToken), "the first token is saved")
            check(storage.stored == newToken, "the keychain holds the first token")
            checkEqual(feed.calls, 1, "one token is generated")
            checkEqual(storage.readCount, 2, "the first write is read back")
            checkEqual(store.diagnostics.confirmedWrites, 1, "the write is confirmed")
        }

        // An existing keychain token is not replaced.
        do {
            let storage = FakeTokenStorage(stored: keychainToken)
            let legacy = FakeLegacyStore()
            let feed = TokenFeed([newToken])
            let store = makeStore(storage, legacy, feed)
            let result = store.createInitial()

            checkEqual(result, .unchanged(.tokenAlreadyPresent),
                       "an existing token is not replaced")
            checkEqual(feed.calls, 0, "no token is generated")
            checkEqual(storage.writeCount, 0, "no write happens")
            check(storage.stored == keychainToken, "the existing token stays")
        }

        // A legacy token that appeared after startup is not replaced.
        do {
            let storage = FakeTokenStorage()
            let legacy = FakeLegacyStore(value: legacyToken)
            let feed = TokenFeed([newToken])
            let result = makeStore(storage, legacy, feed).createInitial()

            checkEqual(result, .unchanged(.tokenAlreadyPresent),
                       "a legacy token blocks creation")
            checkEqual(feed.calls, 0, "no token is generated")
            checkEqual(storage.writeCount, 0, "no write happens")
        }

        // A failed generator creates no credential.
        do {
            let storage = FakeTokenStorage()
            let legacy = FakeLegacyStore()
            let feed = TokenFeed([nil])
            let result = makeStore(storage, legacy, feed).createInitial()

            checkEqual(result, .unchanged(.generatorFailed),
                       "a failed generator creates nothing")
            checkEqual(storage.writeCount, 0, "no write happens")
            check(storage.stored == nil, "the keychain stays empty")
        }

        // An invalid generated token creates no credential.
        do {
            let storage = FakeTokenStorage()
            let legacy = FakeLegacyStore()
            let feed = TokenFeed(["bad token"])
            let result = makeStore(storage, legacy, feed).createInitial()

            checkEqual(result, .unchanged(.invalidNewToken),
                       "an invalid generated token is refused")
            checkEqual(storage.writeCount, 0, "no write happens")
            check(storage.stored == nil, "the keychain stays empty")
        }

        // A failed first write leaves an empty keychain and no new credential.
        do {
            let storage = FakeTokenStorage()
            storage.writeSteps = [.failure(.keychainWriteFailed(-34018))]
            let legacy = FakeLegacyStore()
            let feed = TokenFeed([newToken])
            let result = makeStore(storage, legacy, feed).createInitial()

            checkEqual(result, .unchanged(.keychainWriteFailed(-34018)),
                       "a failed first write is unchanged")
            check(storage.stored == nil, "no token is stored")
        }

        // A write error with a readable new value is still a confirmed save.
        do {
            let storage = FakeTokenStorage()
            storage.writeSteps = [.failureButStore(.keychainWriteFailed(-34018))]
            let legacy = FakeLegacyStore()
            let feed = TokenFeed([newToken])
            let result = makeStore(storage, legacy, feed).createInitial()

            checkEqual(result, .saved(newToken), "a readable write is saved")
            check(storage.stored == newToken, "the token is stored")
        }

        // A different writer's item survives an unconfirmed first write.
        do {
            let storage = FakeTokenStorage()
            storage.readSteps = [.value(nil), .valueAndStore("different-token")]
            let result = makeStore(storage, FakeLegacyStore(), TokenFeed([newToken])).createInitial()
            checkEqual(result, .uncertain(.verificationFailed), "a mismatch is uncertain")
            checkEqual(storage.deleteCount, 0, "no cleanup delete runs")
            check(storage.stored == "different-token", "the concurrent item stays")
        }
        
        // An unreadable first write also leaves the unknown item alone.
        do {
            let storage = FakeTokenStorage()
            storage.readSteps = [.value(nil), .failureAndStore(.keychainUnavailable(-25308), "different-token")]
            let result = makeStore(storage, FakeLegacyStore(), TokenFeed([newToken])).createInitial()
            checkEqual(result, .uncertain(.keychainUnavailable(-25308)), "an unreadable item is uncertain")
            checkEqual(storage.deleteCount, 0, "no cleanup delete runs")
            check(storage.stored == "different-token", "the concurrent item stays")
        }
        
        // A different old copy that appears during the first write is a
        // conflict. The new keychain value stays, the old copy stays, and the
        // app uses neither. There is no in-app resolution.
        do {
            let storage = FakeTokenStorage()
            let legacy = FakeLegacyStore()
            let store = SecureTokenStore(storage: storage, legacy: legacy,
                                         recoveryIntent: FakeRecoveryIntentStore(),
                                         generate: {
                legacy.value = legacyToken
                return newToken
            })
            let result = store.createInitial()

            checkEqual(result, .conflict(.legacyConflict),
                       "a different old copy during create is a conflict")
            check(storage.stored == newToken, "the new keychain token stays")
            check(legacy.value == legacyToken, "the old copy stays")
            checkEqual(legacy.removeCount, 0, "the old copy is not deleted")
            check(store.diagnostics.legacyConflict, "the conflict is recorded")
            checkEqual(store.diagnostics.text().contains("legacy_conflict"), true,
                       "the conflict code is present")
        }
    }

    // MARK: Rotation

    static func testRotation() {
        // A complete rotation confirms the new token, removes the observed old
        // copy, and clears the intent.
        do {
            let storage = FakeTokenStorage(stored: keychainToken)
            let legacy = FakeLegacyStore(value: keychainToken)
            let insight = FakeRecoveryIntentStore()
            let store = SecureTokenStore(storage: storage, legacy: legacy,
                                         recoveryIntent: insight,
                                         generate: { newToken })
            checkEqual(store.rotate(), .saved(newToken), "rotation saves the new token")
            checkEqual(storage.stored, newToken, "keychain holds the new token")
            check(legacy.value == nil, "observed old copy removed")
            check(insight.data == nil, "intent cleared")
            checkEqual(store.diagnostics.confirmedRotations, 1, "rotation confirmed")
            checkEqual(store.diagnostics.rotateAttempts, 1, "rotation attempted once")
            check(!store.diagnostics.text().contains(newToken), "diagnostics hold no token")
            check(!store.diagnostics.text().contains(keychainToken), "diagnostics hold no old token")
        }

        // A store without the intent item refuses rotation and cannot load.
        do {
            let storage = FakeTokenStorage(stored: keychainToken)
            let legacy = FakeLegacyStore(value: keychainToken)
            let store = SecureTokenStore(storage: storage, legacy: legacy,
                                         recoveryIntent: nil,
                                         generate: { newToken })
            check(!store.supportsRotation, "no intent means no rotation")
            checkEqual(store.rotate(), .unchanged(.recoveryIntentUnavailable),
                       "rotation refused")
            checkEqual(store.loadOrMigrate(), .failed(.recoveryIntentUnavailable),
                       "load cannot prove no rotation is pending")
            checkEqual(storage.stored, keychainToken, "stored item retained")
            checkEqual(storage.writeCount, 0, "no token write")
        }

        // A different old copy is a conflict. Nothing is written or deleted.
        do {
            let storage = FakeTokenStorage(stored: keychainToken)
            let legacy = FakeLegacyStore(value: legacyToken)
            let insight = FakeRecoveryIntentStore()
            let store = SecureTokenStore(storage: storage, legacy: legacy,
                                         recoveryIntent: insight,
                                         generate: { newToken })
            checkEqual(store.rotate(), .conflict(.legacyConflict), "conflict refused")
            checkEqual(storage.stored, keychainToken, "stored item retained")
            checkEqual(legacy.value, legacyToken, "old copy retained")
            checkEqual(storage.writeCount, 0, "no token write")
            checkEqual(insight.writeCount, 0, "no intent written")
        }

        // An invalid or repeated generated token creates nothing.
        for generated in [nil, "bad token", keychainToken] as [String?] {
            let storage = FakeTokenStorage(stored: keychainToken)
            let legacy = FakeLegacyStore(value: keychainToken)
            let insight = FakeRecoveryIntentStore()
            let store = SecureTokenStore(storage: storage, legacy: legacy,
                                         recoveryIntent: insight,
                                         generate: { generated })
            let result = store.rotate()
            let expected: TokenWriteResult = generated == nil
                ? .unchanged(.generatorFailed)
                : .unchanged(.invalidNewToken)
            checkEqual(result, expected, "refused generated token")
            checkEqual(storage.stored, keychainToken, "stored item retained")
            checkEqual(storage.writeCount, 0, "no token write")
            checkEqual(insight.writeCount, 0, "no intent written")
        }

        // A read failure before the intent is written changes nothing.
        do {
            let storage = FakeTokenStorage(stored: keychainToken)
            storage.readSteps = [.failure(.keychainUnavailable(-25308))]
            let insight = FakeRecoveryIntentStore()
            let store = SecureTokenStore(storage: storage,
                                         legacy: FakeLegacyStore(value: keychainToken),
                                         recoveryIntent: insight,
                                         generate: { newToken })
            checkEqual(store.rotate(), .unchanged(.keychainUnavailable(-25308)),
                       "read failure refused")
            checkEqual(insight.writeCount, 0, "no intent written")
        }

        // A failed intent write leaves the old token current and unchanged.
        do {
            let storage = FakeTokenStorage(stored: keychainToken)
            let legacy = FakeLegacyStore(value: keychainToken)
            let insight = FakeRecoveryIntentStore()
            insight.writeError = .keychainWriteFailed(-34018)
            let store = SecureTokenStore(storage: storage, legacy: legacy,
                                         recoveryIntent: insight,
                                         generate: { newToken })
            checkEqual(store.rotate(), .uncertain(.keychainWriteFailed(-34018)),
                       "intent failure is uncertain")
            checkEqual(storage.stored, keychainToken, "old token retained")
            checkEqual(legacy.value, keychainToken, "old copy retained")
            checkEqual(storage.writeCount, 0, "no token write")
        }

        // A failed token write with the old value still readable keeps the old
        // token and clears the intent.
        do {
            let storage = FakeTokenStorage(stored: keychainToken)
            storage.writeSteps = [.failure(.keychainWriteFailed(-34018))]
            let legacy = FakeLegacyStore(value: keychainToken)
            let insight = FakeRecoveryIntentStore()
            let store = SecureTokenStore(storage: storage, legacy: legacy,
                                         recoveryIntent: insight,
                                         generate: { newToken })
            checkEqual(store.rotate(), .unchanged(.keychainWriteFailed(-34018)),
                       "failed write is unchanged")
            checkEqual(storage.stored, keychainToken, "old token retained")
            checkEqual(legacy.value, keychainToken, "old copy retained")
            check(insight.data == nil, "intent cleared")
        }

        // A write that reports an error but persisted still counts as saved.
        do {
            let storage = FakeTokenStorage(stored: keychainToken)
            storage.writeSteps = [.failureButStore(.keychainWriteFailed(-34018))]
            let legacy = FakeLegacyStore(value: keychainToken)
            let insight = FakeRecoveryIntentStore()
            let store = SecureTokenStore(storage: storage, legacy: legacy,
                                         recoveryIntent: insight,
                                         generate: { newToken })
            checkEqual(store.rotate(), .saved(newToken), "readable write is saved")
            checkEqual(storage.stored, newToken, "new token stored")
            check(legacy.value == nil, "old copy removed")
            check(insight.data == nil, "intent cleared")
        }

        // A post-write read failure leaves the intent for recovery.
        do {
            let storage = FakeTokenStorage(stored: keychainToken)
            // The first read sees the old token, the pre-write read sees it
            // again, and the post-write read fails.
            storage.readSteps = [.value(keychainToken), .value(keychainToken),
                                 .failure(.keychainReadFailed(-1))]
            let insight = FakeRecoveryIntentStore()
            let store = SecureTokenStore(storage: storage,
                                         legacy: FakeLegacyStore(value: keychainToken),
                                         recoveryIntent: insight,
                                         generate: { newToken })
            checkEqual(store.rotate(), .uncertain(.keychainReadFailed(-1)),
                       "unconfirmed write is uncertain")
            checkEqual(storage.stored, newToken, "write may have landed")
            check(insight.data != nil, "intent retained")
        }
    }


    // MARK: Rotation control

    static func testRotationPolicy() {
        // The reviewed gate is closed by default. Even the most permissive
        // idle state must refuse until a caller explicitly opts in.
        for requested in [false, true] {
            for state in ["Stopped", "Starting", "Listening"] {
                for conflict in [false, true] {
                    check(!TokenRotationPolicy.canRotate(proxyRequested: requested,
                                                         state: state,
                                                         tokenUsable: true,
                                                         storageReady: true,
                                                         legacyConflict: conflict,
                                                         lifecycleFree: true),
                          "the default gate refuses rotation")
                }
            }
        }
        // With the gate explicitly open, the old boundary rules still apply.
        for requested in [false, true] {
            for state in ["Stopped", "Starting", "Listening"] {
                for conflict in [false, true] {
                    let expected = !requested && state == "Stopped" && !conflict
                    checkEqual(TokenRotationPolicy.canRotate(proxyRequested: requested,
                                                             state: state,
                                                             tokenUsable: true,
                                                             storageReady: true,
                                                             legacyConflict: conflict,
                                                             lifecycleFree: true,
                                                             rotationReviewed: true),
                               expected,
                               "rotation follows the idle and conflict rule")
                }
            }
        }
        check(!TokenRotationPolicy.canRotate(proxyRequested: false, state: "Stopped",
                                             tokenUsable: false, storageReady: true,
                                             legacyConflict: false, lifecycleFree: true,
                                             rotationReviewed: true),
              "unusable token blocks rotation")
        check(!TokenRotationPolicy.canRotate(proxyRequested: false, state: "Stopped",
                                             tokenUsable: true, storageReady: false,
                                             legacyConflict: false, lifecycleFree: true,
                                             rotationReviewed: true),
              "unreadable store blocks rotation")
        check(!TokenRotationPolicy.canRotate(proxyRequested: false, state: "Stopped",
                                             tokenUsable: true, storageReady: true,
                                             legacyConflict: false, lifecycleFree: false,
                                             rotationReviewed: true),
              "busy lifecycle blocks rotation")
        check(TokenRotationPolicy.proxyActive(proxyRequested: true, state: "Stopped"), "pending start is active")
        check(TokenRotationPolicy.proxyActive(proxyRequested: false, state: "Listening"), "listener is active")
        check(!TokenRotationPolicy.proxyActive(proxyRequested: false, state: "Stopped"), "stopped is idle")
        for error in [SecureTokenError.invalidRecoveryIntent, .rotationRecoveryPending, .recoveryRefused] {
            check(TokenRotationPolicy.storageUnavailable(error),
                  "unresolved recovery leaves storage unavailable for rotation")
        }
        check(TokenLoadRetry.canRetry(after: .keychainUnavailable(-1)), "locked read retryable")
        check(TokenLoadRetry.canRetry(after: .rotationRecoveryPending), "pending rotation cleanup retryable")
        check(!TokenLoadRetry.canRetry(after: .recoveryRefused), "recovery refusal is not retryable")
        check(!TokenLoadRetry.canRetry(after: .recoveryIntentUnavailable),
              "a missing intent backend is not retryable")
        check(!TokenLoadRetry.canRetry(after: .invalidRecoveryIntent), "damaged intent is not retryable")
    }


    // MARK: Recovery control

    static func testRecoveryPolicy() {
        check(TokenRecoveryPolicy.isInvalidState(.invalidStoredToken),
              "an invalid keychain token is a recoverable state")
        check(TokenRecoveryPolicy.isInvalidState(.invalidLegacyToken),
              "an invalid old copy is a recoverable state")
        check(!TokenRecoveryPolicy.isInvalidState(nil),
              "a missing error is not a recoverable state")
        check(!TokenRecoveryPolicy.isInvalidState(.legacyConflict),
              "a conflict is not a recoverable state")

        check(TokenRecoveryPolicy.canReplace(proxyRequested: false, state: "Stopped",
                                             error: .invalidStoredToken,
                                             kind: .replaceInvalid),
              "replacement is the right action for an invalid keychain token")
        check(TokenRecoveryPolicy.canReplace(proxyRequested: false, state: "Failed",
                                             error: .invalidLegacyToken,
                                             kind: .replaceInvalid),
              "replacement is the right action for an invalid old copy")

        // The restore action is a different action. It needs the restore kind
        // and an invalid state, and it never runs while the proxy is active.
        check(TokenRecoveryPolicy.canRestore(proxyRequested: false, state: "Stopped",
                                             error: .invalidStoredToken,
                                             kind: .restoreLegacy),
              "restore is the right action for a valid old copy")
        check(!TokenRecoveryPolicy.canRestore(proxyRequested: false, state: "Stopped",
                                              error: .invalidStoredToken,
                                              kind: .replaceInvalid),
              "a restore is not enabled by the replace kind")
        check(!TokenRecoveryPolicy.canReplace(proxyRequested: false, state: "Stopped",
                                              error: .invalidStoredToken,
                                              kind: .restoreLegacy),
              "a replace is not enabled by the restore kind")
        check(!TokenRecoveryPolicy.canRestore(proxyRequested: false, state: "Stopped",
                                              error: nil,
                                              kind: .restoreLegacy),
              "a restore needs an invalid state")

        check(!TokenRecoveryPolicy.canReplace(proxyRequested: true, state: "Stopped",
                                              error: .invalidStoredToken,
                                              kind: .replaceInvalid),
              "a pending start blocks replacement")
        check(!TokenRecoveryPolicy.canReplace(proxyRequested: false, state: "Starting",
                                              error: .invalidStoredToken,
                                              kind: .replaceInvalid),
              "the starting state blocks replacement")
        check(!TokenRecoveryPolicy.canReplace(proxyRequested: false, state: "Listening",
                                              error: .invalidLegacyToken,
                                              kind: .replaceInvalid),
              "a running proxy blocks replacement")
        check(!TokenRecoveryPolicy.canRestore(proxyRequested: true, state: "Stopped",
                                              error: .invalidStoredToken,
                                              kind: .restoreLegacy),
              "a pending start blocks a restore")
        check(!TokenRecoveryPolicy.canRestore(proxyRequested: false, state: "Starting",
                                              error: .invalidStoredToken,
                                              kind: .restoreLegacy),
              "the starting state blocks a restore")
        check(!TokenRecoveryPolicy.canRestore(proxyRequested: false, state: "Listening",
                                              error: .invalidStoredToken,
                                              kind: .restoreLegacy),
              "a running proxy blocks a restore")

        // Every other storage state has a different remedy and must never
        // enable a destructive action.
        let refused: [SecureTokenError] = [
            .keychainUnavailable(-25308), .keychainReadFailed(-34018),
            .keychainWriteFailed(-34018), .keychainDeleteFailed(-34018),
            .verificationFailed, .generatorFailed, .tokenAlreadyPresent, .tokenUnavailableAfterFailure,
            .invalidNewToken, .legacyNotMigrated, .legacyRemovalFailed,
            .legacyConflict, .recoveryRefused, .recoveryIntentUnavailable,
            .invalidRecoveryIntent, .rotationRecoveryPending,
        ]
        for error in refused {
            check(!TokenRecoveryPolicy.canReplace(proxyRequested: false, state: "Stopped",
                                                  error: error, kind: .replaceInvalid),
                  "replacement is refused for \(error.code)")
            check(!TokenRecoveryPolicy.canRestore(proxyRequested: false, state: "Stopped",
                                                  error: error, kind: .restoreLegacy),
                  "a restore is refused for \(error.code)")
        }

        checkEqual(TokenRecoveryPolicy.allowedAction(proxyRequested: false, state: "Stopped",
                                                     error: .invalidStoredToken,
                                                     kind: .none),
                   .none,
                   "a missing kind enables no action")
        check(TokenRecoveryPolicy.needsRefresh(error: .invalidStoredToken, kind: .none),
              "an invalid state with no cached action is refreshed")
        check(TokenRecoveryPolicy.needsRefresh(error: .invalidLegacyToken, kind: .none),
              "an invalid old copy with no cached action is refreshed")
        check(!TokenRecoveryPolicy.needsRefresh(error: .invalidStoredToken,
                                                kind: .replaceInvalid),
              "a cached replacement is not refreshed")
        check(!TokenRecoveryPolicy.needsRefresh(error: .invalidStoredToken,
                                                kind: .restoreLegacy),
              "a cached restore is not refreshed")
        check(!TokenRecoveryPolicy.needsRefresh(error: .keychainUnavailable(-25308),
                                                kind: .none),
              "a transient error is not a stale recovery state")
        check(!TokenRecoveryPolicy.needsRefresh(error: nil, kind: .none),
              "a missing error needs no recovery refresh")

        check(!TokenLoadRetry.canRetry(after: .recoveryRefused),
              "a refused recovery is not retried automatically")
    }

    // MARK: Recovery classification

    static func testRecoveryKind() {
        for stored in [nil, keychainToken, "bad token"] as [String?] {
            for old in [nil, legacyToken, "bad legacy"] as [String?] {
                let storage = FakeTokenStorage(stored: stored)
                let legacy = FakeLegacyStore(value: old)
                checkEqual(makeStore(storage, legacy, TokenFeed([newToken])).recoveryKind(), .none, "no destructive action offered")
                check(storage.writeCount == 0 && storage.deleteCount == 0 && legacy.removeCount == 0, "classification is read only")
            }
        }
    }


    // MARK: Recovery

    static func testRecovery() {
        for stored in [nil, keychainToken, "bad token"] as [String?] {
            for old in [nil, legacyToken, "bad legacy"] as [String?] {
                let storage = FakeTokenStorage(stored: stored)
                let legacy = FakeLegacyStore(value: old)
                let feed = TokenFeed([newToken])
                let store = makeStore(storage, legacy, feed)
                checkEqual(store.replaceInvalidToken(), .unchanged(.recoveryRefused), "replacement refused")
                checkEqual(storage.stored, stored, "stored value preserved")
                checkEqual(legacy.value, old, "legacy value preserved")
                check(storage.writeCount == 0 && storage.deleteCount == 0 && legacy.removeCount == 0 && feed.calls == 0, "replacement makes no mutations")
            }
        }
    }


    // MARK: Restore a valid old copy

    static func testRestoreLegacy() {
        let storage = FakeTokenStorage(stored: "bad token")
        let legacy = FakeLegacyStore(value: legacyToken)
        let store = makeStore(storage, legacy, TokenFeed([newToken]))
        checkEqual(store.restoreValidLegacyToken(), .unchanged(.recoveryRefused), "restore refused")
        checkEqual(storage.stored, "bad token", "invalid item preserved")
        checkEqual(legacy.value, legacyToken, "old credential preserved")
        check(storage.writeCount == 0 && storage.deleteCount == 0 && legacy.removeCount == 0, "restore makes no mutations")
    }


    // MARK: Keychain adapter

    static func testKeychainAdapter() {
        // The item identity is fixed and never synchronizes.
        do {
            let api = FakeKeychainAPI()
            let storage = KeychainTokenStorage(api: api)
            checkNoThrow(try storage.deleteToken(), "a missing item deletes without error")
            checkEqual(api.lastItem,
                       KeychainItemID(service: "local.hotspotproxy.app",
                                      account: "proxyToken",
                                      synchronizable: false),
                       "the item identity")
        }

        // Reading a missing, valid, and invalid item.
        do {
            let api = FakeKeychainAPI()
            let storage = KeychainTokenStorage(api: api)

            api.copyResults = [(errSecItemNotFound, nil)]
            check(readValue(storage, "a missing item reads as nil") == nil,
                  "a missing item reads as nil")

            api.copyResults = [(errSecSuccess, Data(newToken.utf8))]
            check(readValue(storage, "a valid item reads as text") == newToken,
                  "a valid item reads as text")

            api.copyResults = [(errSecSuccess, Data([0xFF, 0xFE]))]
            expectError(try storage.readToken(), .invalidStoredToken,
                        "invalid UTF-8 is refused")

            api.copyResults = [(errSecSuccess, Data("bad token".utf8))]
            expectError(try storage.readToken(), .invalidStoredToken,
                        "invalid text is refused")

            api.copyResults = [(errSecSuccess, Data())]
            expectError(try storage.readToken(), .invalidStoredToken,
                        "empty data is refused")

            api.copyResults = [(errSecInteractionNotAllowed, nil)]
            expectError(try storage.readToken(),
                        .keychainUnavailable(errSecInteractionNotAllowed),
                        "a locked keychain is unavailable")

            api.copyResults = [(errSecAuthFailed, nil)]
            expectError(try storage.readToken(), .keychainReadFailed(errSecAuthFailed),
                        "another read error is a read failure")
        }

        // Insert is add-only. A duplicate never falls back to an update.
        do {
            let api = FakeKeychainAPI()
            let storage = KeychainTokenStorage(api: api)
            checkNoThrow(try storage.addToken(newToken), "initial add succeeds")
            checkEqual(api.addCount, 1, "one add")
            checkEqual(api.updateCount, 0, "no update")
            checkEqual(api.lastAccessible, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String,
                       "item protection")
            check(api.addItems.last?.synchronizable == false, "item never syncs")
            api.addResults = [errSecDuplicateItem, errSecInteractionNotAllowed]
            expectError(try storage.addToken(newToken), .tokenAlreadyPresent, "duplicate is preserved")
            expectError(try storage.addToken(newToken), .keychainUnavailable(errSecInteractionNotAllowed),
                        "locked add is unavailable")
            checkEqual(api.updateCount, 0, "duplicate does not update")
        }
        
        // Rotation updates an existing item only; a missing item is not inserted.
        do {
            let api = FakeKeychainAPI()
            let storage = KeychainTokenStorage(api: api)
            checkNoThrow(try storage.writeToken(newToken), "update succeeds")
            api.updateResults = [errSecItemNotFound]
            expectError(try storage.writeToken(newToken), .keychainWriteFailed(errSecItemNotFound),
                        "missing update fails")
            checkEqual(api.addCount, 0, "update never inserts")
        }
        
        // An invalid token never reaches the keychain.
        do {
            let api = FakeKeychainAPI()
            let storage = KeychainTokenStorage(api: api)
            expectError(try storage.writeToken("bad token"), .invalidNewToken,
                        "an invalid write token is refused")
            checkEqual(api.updateCount, 0, "no update for an invalid token")
            checkEqual(api.addCount, 0, "no add for an invalid token")
        }

        // Delete treats a missing item as success and maps other errors.
        do {
            let api = FakeKeychainAPI()
            let storage = KeychainTokenStorage(api: api)

            api.deleteResults = [errSecSuccess]
            checkNoThrow(try storage.deleteToken(), "delete succeeds")

            api.deleteResults = [errSecItemNotFound]
            checkNoThrow(try storage.deleteToken(), "a missing delete succeeds")

            api.deleteResults = [errSecAuthFailed]
            expectError(try storage.deleteToken(),
                        .keychainDeleteFailed(errSecAuthFailed),
                        "another delete error is a delete failure")

            api.deleteResults = [errSecInteractionNotAllowed]
            expectError(try storage.deleteToken(),
                        .keychainUnavailable(errSecInteractionNotAllowed),
                        "a locked delete is unavailable")
        }
    }

    // MARK: Fixed texts for ambiguous saved state

    static func testAmbiguousStateMessages() {
        let conflict = SecureTokenError.legacyConflict.message
        check(conflict.contains("Two saved tokens differ"), "the conflict names two values")
        check(conflict.contains("cannot prove which one is current"),
              "the conflict states the ambiguity")
        check(conflict.contains("kept both"), "the conflict says both copies remain")
        check(conflict.contains("uses neither"), "the conflict says neither copy is used")

        let refused = SecureTokenError.recoveryRefused.message
        check(refused.contains("cannot prove which saved token is current"),
              "the refusal states the ambiguity")
        check(refused.contains("cannot safely change token storage"),
              "the refusal covers a refused storage change")
        check(refused.contains("changed nothing"), "the refusal says nothing changed")

        for error in [SecureTokenError.legacyConflict, .recoveryRefused] {
            for token in [keychainToken, legacyToken, newToken] {
                check(!error.message.contains(token), "the fixed text holds no token")
                for chunk in chunks(of: token, size: 8) {
                    check(!error.message.contains(chunk), "the fixed text holds no token chunk")
                }
            }
        }
    }

    // MARK: Diagnostics

    static func testDiagnostics() {
        // A failed load records counts and a code, never the token.
        do {
            let storage = FakeTokenStorage()
            storage.readSteps = [.failure(.keychainUnavailable(-25308))]
            let legacy = FakeLegacyStore(value: legacyToken)
            let store = makeStore(storage, legacy, TokenFeed([]))
            let result = store.loadOrMigrate()
            checkEqual(result, .failed(.keychainUnavailable(-25308)), "the load fails")

            let text = store.diagnostics.text()
            check(text.contains("Token storage: Keychain"), "the storage line is present")
            check(text.contains("Token storage loads: 1"), "the load count is present")
            check(text.contains("Token operation failures: 1"), "the failure count is present")
            check(text.contains("keychain_unavailable(-25308)"), "the status code is present")
            check(text.contains("Old token copy present: yes"), "only presence is reported")
            check(!text.contains(legacyToken), "the full token is not in diagnostics")
            check(!text.contains(String(keychainToken.prefix(8))),
                  "no token prefix is in diagnostics")
            for chunk in chunks(of: legacyToken, size: 8) {
                check(!text.contains(chunk), "no token chunk is in diagnostics: \(chunk)")
            }
            check(!String(describing: store.diagnostics).contains(legacyToken),
                  "the diagnostics value holds no token")
        }

        // The old-copy cleanup state is visible without a value.
        do {
            let storage = FakeTokenStorage()
            let legacy = FakeLegacyStore(value: legacyToken)
            legacy.removeResult = false
            let store = makeStore(storage, legacy, TokenFeed([]))
            _ = store.loadOrMigrate()

            let text = store.diagnostics.text()
            check(text.contains("Old token copy present: yes"), "the old copy is present")
            check(text.contains("Old token cleanup pending: yes"), "cleanup is pending")
            check(!text.contains("legacy_removal_failed"), "retention is not a failed removal")
            check(!text.contains(legacyToken), "the old token value is not in diagnostics")
        }

        // Errors carry plain text and no token.
        do {
            let error = SecureTokenError.keychainReadFailed(-25308)
            check(!error.description.contains(legacyToken), "the error has no token")
            check(!error.message.contains(legacyToken), "the message has no token")
            check(error.code.contains("-25308"), "the code keeps the status")
            checkEqual(SecureTokenError.legacyNotMigrated.code, "legacy_not_migrated",
                       "the unmigrated-copy code is stable")
            check(!SecureTokenError.legacyNotMigrated.message.contains(legacyToken),
                  "the unmigrated-copy message has no token")
            checkEqual(SecureTokenError.recoveryIntentUnavailable.code,
                       "recovery_intent_unavailable",
                       "the missing-intent code is stable")
            check(!SecureTokenError.recoveryIntentUnavailable.message.contains(legacyToken),
                  "the missing-intent message has no token")
        }
    }
}
