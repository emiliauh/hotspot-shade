import Foundation
import Security

// Hermetic restart and fault tests for staged token rotation.
//
// Each test uses fake Keychain and UserDefaults stores. A "restart" builds a
// fresh SecureTokenStore and TokenLifecycle over the same fake bytes. That
// models what a restart would read if both stores kept those bytes. It does not
// prove that Keychain or UserDefaults survive a crash or power loss. No test
// opens a real Keychain, a socket, or a file.
//
// The safety rule checked after every step: pairing runs exactly when the app
// has a confirmed usable token, and a rotation that cannot prove the stored
// value changes nothing and keeps pairing down.

final class RotationSink: PairingCredentialSink {
    enum Event: Equatable {
        case suspend
        case configure(UInt16, String)
    }

    private(set) var events: [Event] = []
    /// Runs at the start of a configure call. A test uses it to prove that no
    /// store transaction is active while the pairing sink runs.
    var onConfigure: (() -> Void)?

    func suspendPairing() { events.append(.suspend) }

    func configurePairing(port: UInt16, token: String) {
        onConfigure?()
        events.append(.configure(port, token))
    }

    var configured: (port: UInt16, token: String)? {
        guard case .configure(let port, let token)? = events.last,
              port != 0, !token.isEmpty else { return nil }
        return (port, token)
    }

    var listening: Bool { configured != nil }
    var suspendCount: Int { events.filter { $0 == .suspend }.count }
}

final class RotationHost: TokenLifecycleHost {
    var requested = false
    var state = "Stopped"
    var port: UInt16 = 26000
    private(set) var activities: [String] = []
    private(set) var changes = 0
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

final class RotationRig {
    let storage: FakeTokenStorage
    let legacy: FakeLegacyStore
    let intent: FakeRecoveryIntentStore
    let feed: TokenFeed
    let store: SecureTokenStore
    let sink = RotationSink()
    let host = RotationHost()
    let lifecycle: TokenLifecycle

    init(storage: FakeTokenStorage,
         legacy: FakeLegacyStore,
         intent: FakeRecoveryIntentStore,
         feed: TokenFeed) {
        self.storage = storage
        self.legacy = legacy
        self.intent = intent
        self.feed = feed
        store = SecureTokenStore(storage: storage, legacy: legacy,
                                 recoveryIntent: intent,
                                 generate: { feed.next() })
        // These tests exercise the dormant staged transaction. The app keeps
        // the review gate closed.
        lifecycle = TokenLifecycle(store: store, pairing: sink,
                                   rotationReviewed: true)
        host.lifecycle = lifecycle
        lifecycle.attach(host: host)
    }

    convenience init(stored: String?,
                     legacyValue: String?,
                     intentData: Data? = nil,
                     generated: [String?] = []) {
        let intent = FakeRecoveryIntentStore()
        intent.data = intentData
        self.init(storage: FakeTokenStorage(stored: stored),
                  legacy: FakeLegacyStore(value: legacyValue),
                  intent: intent,
                  feed: TokenFeed(generated))
    }

    @discardableResult
    func launch() -> RotationRig {
        lifecycle.launch()
        return self
    }

    /// A restart keeps the fake bytes and drops the process objects. This is a
    /// model of the bytes a restart would read, not a durability proof.
    func restart() -> RotationRig {
        RotationRig(storage: storage, legacy: legacy, intent: intent, feed: feed)
    }
}

@main
struct TokenRotationRecoveryTests {
    static let old = "0123456789abcdef0123456789abcdef"
    static let new = "00112233445566778899aabbccddeeff"
    static let third = "ffeeddccbbaa99887766554433221100"
    static let other = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    static let invalid = "bad token"
    static let port: UInt16 = 26000

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

    static func intent(_ stage: TokenRotationIntent.Stage,
                       old: String = TokenRotationRecoveryTests.old,
                       new: String = TokenRotationRecoveryTests.new) -> Data {
        guard let value = TokenRotationIntent.make(stage: stage,
                                                   oldToken: old,
                                                   newToken: new) else {
            preconditionFailure("test intent did not encode")
        }
        return value.encoded()
    }

    static func invariant(_ rig: RotationRig, _ label: String, line: Int = #line) {
        let lifecycle = rig.lifecycle
        checkEqual(rig.sink.listening,
                   lifecycle.tokenIsUsable && lifecycle.storageReady && !lifecycle.conflict,
                   "\(label): pairing runs only for a confirmed usable token", line: line)
        if let configured = rig.sink.configured {
            checkEqual(configured.token, lifecycle.token,
                       "\(label): listener token", line: line)
            checkEqual(rig.storage.stored, lifecycle.token,
                       "\(label): listener token is the stored token", line: line)
            checkEqual(configured.port, port, "\(label): pairing port", line: line)
        } else {
            checkEqual(lifecycle.token, "",
                       "\(label): no token in memory while suspended", line: line)
        }
        for event in rig.sink.events {
            if case .configure(_, let token) = event {
                check(SecureTokenRules.isValid(token),
                      "\(label): never configured with an unusable token", line: line)
            }
        }
        checkEqual(rig.host.token, lifecycle.token, "\(label): mirrored token", line: line)
        checkEqual(rig.host.failure, lifecycle.storageFailure,
                   "\(label): mirrored failure", line: line)
        checkEqual(rig.host.ready, lifecycle.storageReady,
                   "\(label): mirrored ready", line: line)
        checkEqual(rig.host.conflict, lifecycle.conflict,
                   "\(label): mirrored conflict", line: line)
        checkEqual(rig.host.recovery, lifecycle.recovery,
                   "\(label): mirrored recovery", line: line)
    }

    static func main() {
        testEncoding()
        testKeychainIntentStore()
        testSuccess()
        testRefusedWhileActiveOrReserved()
        testConflictRefuses()
        testPreparedBeforeTokenWriteRestart()
        testPreparedWithNewTokenRestart()
        testCommittedWithNewTokenRestart()
        testCommittedWithDuplicateNewCopyRestart()
        testCommittedWithOldTokenBlocks()
        testMissingOrUnknownTokenBlocks()
        testMissingTokenWithIntentRetries()
        testUnknownLegacyBlocksCommitted()
        testPreparedAbortKeepsUnknownLegacyAndIntent()
        testLegacyRemovalFailureRetries()
        testIntentClearFailureRetries()
        testPreparedIntentClearFailureRetries()
        testDamagedIntentBlocks()
        testIntentReadFailureBlocks()
        testTokenReadFailureBlocks()
        testMissingIntentBackendBlocks()
        testWriteReportedFailureStillSucceeds()
        testPostWriteReadFailureReloads()
        testWriteFailureKeepsOldToken()
        testCommittedIntentAppearsDuringRun()
        testPreparedIntentAbortDuringRunKeepsCache()
        testExternalTokenChangeBeforeFailedWrite()
        testUnconfirmedTokenAfterFailedRotationSuspendsPairing()
        testRecoveryConfirmationLockOrder()
        testIntentWriteLandedThenFailed()
        testIntentClearFailureAfterCommit()
        testIntentClearLandedThenFailed()
        testLegacyRemovalFailureAfterCommit()
        testExternalTokenChangeBeforeWrite()
        testExternalTokenOverwriteAfterLastRead()
        testExternalLegacyChangeDuringWrite()
        testExternalLegacyRemovalRace()
        testIntentLostAfterTokenWriteIsConflict()
        testDowngradeCopyAfterRotation()
        testDowngradeCreatesLegacyToken()
        testReadBackDoesNotProveDurability()
        testNoAutomaticReplacementOnUnknown()
        testDiagnosticsHoldNoToken()
        print("Token rotation recovery tests passed")
    }

    // MARK: Encoding

    static func testEncoding() {
        let transaction = Data(repeating: 0x5a, count: TokenRotationIntent.transactionBytes)
        guard let prepared = TokenRotationIntent.make(stage: .prepared,
                                                      oldToken: old, newToken: new,
                                                      transaction: transaction) else {
            check(false, "intent encodes")
            return
        }
        checkEqual(prepared.version, TokenRotationIntent.formatVersion, "format version")
        checkEqual(prepared.transaction, transaction, "transaction bytes")
        checkEqual(prepared.oldDigest.count, TokenRotationIntent.digestBytes, "old digest size")
        checkEqual(prepared.newDigest.count, TokenRotationIntent.digestBytes, "new digest size")
        check(prepared.matchesOld(old), "old digest matches")
        check(!prepared.matchesOld(new), "old digest is not the new token")
        check(prepared.matchesNew(new), "new digest matches")
        check(!prepared.matchesNew(old), "new digest is not the old token")

        let committed = prepared.advancing(to: .committed)
        checkEqual(committed.stage, .committed, "stage advances")
        checkEqual(committed.transaction, prepared.transaction, "stage keeps transaction")
        checkEqual(committed.oldDigest, prepared.oldDigest, "stage keeps old digest")
        checkEqual(committed.newDigest, prepared.newDigest, "stage keeps new digest")

        let encoded = prepared.encoded()
        checkEqual(encoded.count, TokenRotationIntent.encodedBytes, "encoded size")
        checkEqual(TokenRotationIntent.decode(encoded), prepared, "decode round trip")
        check(TokenRotationIntent.decode(Data([1])) == nil, "old one-byte marker is unknown")
        check(TokenRotationIntent.decode(encoded.dropLast()) == nil, "short record is refused")
        check(TokenRotationIntent.decode(encoded + Data([0])) == nil, "long record is refused")
        var unknown = encoded
        unknown[0] = 0x7f
        check(TokenRotationIntent.decode(unknown) == nil, "unknown version is refused")
        var badStage = encoded
        badStage[1 + TokenRotationIntent.transactionBytes] = 0x7f
        check(TokenRotationIntent.decode(badStage) == nil, "unknown stage is refused")
        check(TokenRotationIntent.make(stage: .prepared, oldToken: old, newToken: new,
                                       transaction: Data([1])) == nil,
              "short transaction is refused")
        check(TokenRotationIntent.make(stage: .prepared, oldToken: invalid, newToken: new) == nil,
              "invalid old token is refused")
        check(TokenRotationIntent.make(stage: .prepared, oldToken: old, newToken: invalid) == nil,
              "invalid new token is refused")
        check(TokenRotationIntent.make(stage: .prepared, oldToken: old, newToken: old) == nil,
              "equal old and new tokens are refused")

        // A damaged record with equal digests cannot name two sides of a
        // rotation. It must decode as damaged, not match either value.
        var equalDigests = encoded
        let oldStart = 2 + TokenRotationIntent.transactionBytes
        for offset in 0..<TokenRotationIntent.digestBytes {
            equalDigests[oldStart + TokenRotationIntent.digestBytes + offset] =
                equalDigests[oldStart + offset]
        }
        check(TokenRotationIntent.decode(equalDigests) == nil,
              "equal old and new digests are refused")
    }

    static func testKeychainIntentStore() {
        let api = StatefulKeychainAPI()
        let store = KeychainRecoveryIntentStore(api: api)
        let item = KeychainItemID(service: KeychainTokenStorage.defaultService,
                                  account: "proxyToken.recoveryIntent",
                                  synchronizable: false)
        check(try! store.read() == nil, "no intent at first")

        let first = intent(.prepared)
        try! store.write(first)
        checkEqual(try! store.read(), first, "intent added and read back")
        checkEqual(api.copy(item).data, first, "intent bytes stored")

        let second = intent(.committed)
        try! store.write(second)
        checkEqual(try! store.read(), second, "intent updated and read back")
        checkEqual(api.copy(item).data, second, "updated bytes stored")

        try! store.clear()
        check(try! store.read() == nil, "intent cleared")
        check(api.copy(item).status == errSecItemNotFound, "intent item removed")
        try! store.clear()
        check(try! store.read() == nil, "clearing a missing intent is harmless")

        do {
            let api = FakeKeychainAPI()
            api.defaultUpdate = errSecItemNotFound
            api.defaultAdd = errSecAuthFailed
            let store = KeychainRecoveryIntentStore(api: api)
            do {
                try store.write(first)
                check(false, "failed add throws")
            } catch let error as SecureTokenError {
                checkEqual(error, .keychainWriteFailed(errSecAuthFailed), "add error maps")
            } catch {
                check(false, "wrong add error")
            }
        }

        do {
            let api = FakeKeychainAPI()
            api.defaultUpdate = errSecInteractionNotAllowed
            let store = KeychainRecoveryIntentStore(api: api)
            do {
                try store.write(second)
                check(false, "locked update throws")
            } catch let error as SecureTokenError {
                checkEqual(error, .keychainUnavailable(errSecInteractionNotAllowed),
                           "locked update maps")
            } catch {
                check(false, "wrong update error")
            }
        }

        do {
            let api = FakeKeychainAPI()
            api.defaultDelete = errSecAuthFailed
            let store = KeychainRecoveryIntentStore(api: api)
            do {
                try store.clear()
                check(false, "failed clear throws")
            } catch let error as SecureTokenError {
                checkEqual(error, .keychainDeleteFailed(errSecAuthFailed), "delete error maps")
            } catch {
                check(false, "wrong delete error")
            }
        }

        // Success without data is not proof that the recovery item is absent.
        do {
            let api = FakeKeychainAPI()
            api.defaultCopy = (errSecSuccess, nil)
            let intentStore = KeychainRecoveryIntentStore(api: api)
            let storage = FakeTokenStorage()
            let legacy = FakeLegacyStore()
            let tokenStore = SecureTokenStore(storage: storage, legacy: legacy,
                                              recoveryIntent: intentStore,
                                              generate: { new })
            checkEqual(tokenStore.loadOrMigrate(), .failed(.invalidRecoveryIntent),
                       "success without intent data blocks loading")
            checkEqual(tokenStore.createInitial(), .unchanged(.invalidRecoveryIntent),
                       "success without intent data blocks creation")
            checkEqual(storage.readCount, 0, "intent failure precedes token reads")
            checkEqual(legacy.loadCount, 0, "intent failure precedes legacy reads")
            checkEqual(storage.writeCount, 0, "missing intent data writes no token")
            checkEqual(storage.deleteCount, 0, "missing intent data deletes no token")
            check(tokenStore.diagnostics.text().contains("Rotation recovery record present: unknown"),
                  "success without data leaves presence unknown")
            checkEqual(tokenStore.diagnostics.lastErrorCode, "invalid_recovery_intent",
                       "success without data has the fixed error code")
            do {
                try intentStore.clear()
                check(false, "success without data cannot confirm intent removal")
            } catch let error as SecureTokenError {
                checkEqual(error, .invalidRecoveryIntent, "unconfirmed intent clear")
            } catch {
                check(false, "wrong missing intent data error")
            }
        }

        // A duplicate add falls back to one update.
        do {
            let api = FakeKeychainAPI()
            api.updateResults = [errSecItemNotFound, errSecSuccess]
            api.addResults = [errSecDuplicateItem]
            api.copyResults = [(errSecSuccess, first), (errSecSuccess, first)]
            let store = KeychainRecoveryIntentStore(api: api)
            try! store.write(first)
            checkEqual(api.addCount, 1, "duplicate add falls back")
            checkEqual(api.updateCount, 2, "one failed update, one fallback update")
        }

        // A read-back that does not match the written bytes is a verification
        // failure, not a successful write.
        do {
            let api = FakeKeychainAPI()
            api.defaultUpdate = errSecSuccess
            api.copyResults = [(errSecSuccess, second)]
            let store = KeychainRecoveryIntentStore(api: api)
            do {
                try store.write(first)
                check(false, "mismatched read-back throws")
            } catch let error as SecureTokenError {
                checkEqual(error, .verificationFailed, "mismatched write read-back")
            } catch {
                check(false, "wrong read-back error")
            }
        }

        // A delete that reports success while the item is still readable is a
        // verification failure.
        do {
            let api = FakeKeychainAPI()
            api.defaultDelete = errSecSuccess
            api.copyResults = [(errSecSuccess, first)]
            let store = KeychainRecoveryIntentStore(api: api)
            do {
                try store.clear()
                check(false, "unconfirmed clear throws")
            } catch let error as SecureTokenError {
                checkEqual(error, .verificationFailed, "unconfirmed clear read-back")
            } catch {
                check(false, "wrong clear read-back error")
            }
        }
    }

    // MARK: Success and refusal

    static func testSuccess() {
        let rig = RotationRig(stored: old, legacyValue: old, generated: [new]).launch()
        invariant(rig, "loaded")
        check(rig.lifecycle.canRotate, "rotation available while idle")
        var intentAtWrite: Data?
        var pairingWasDown = false
        rig.storage.onWrite = {
            intentAtWrite = rig.intent.data
            pairingWasDown = !rig.sink.listening
        }

        rig.lifecycle.rotate()
        invariant(rig, "rotated")
        checkEqual(rig.lifecycle.token, new, "new token adopted")
        checkEqual(rig.storage.stored, new, "new token stored")
        check(rig.legacy.value == nil, "observed old copy removed")
        checkEqual(rig.legacy.removeCount, 1, "old copy removed once")
        check(rig.intent.data == nil, "intent cleared")
        checkEqual(rig.intent.clearCount, 1, "intent cleared once")
        checkEqual(rig.storage.writeCount, 1, "one token write")
        checkEqual(rig.intent.writeCount, 2, "prepared and committed records")
        check(pairingWasDown, "pairing was down before the token write")
        check(intentAtWrite != nil, "intent was stored before the token write")
        checkEqual(TokenRotationIntent.decode(intentAtWrite ?? Data())?.stage, .prepared,
                   "the first record is prepared")
        check(rig.sink.suspendCount >= 1, "pairing suspended before the change")
        check(rig.sink.configured?.token == new, "pairing offers the new token")
        check(rig.host.activities.contains(PlainMessage.tokenRotated), "rotation announced")
        check(!rig.host.activities.contains(new), "activity holds no token")
        check(!rig.host.activities.contains(old), "activity holds no old token")
        checkEqual(rig.lifecycle.diagnostics.confirmedRotations, 1, "rotation confirmed")
        checkEqual(rig.lifecycle.diagnostics.rotationRecoveries, 0, "no recovery")
        checkEqual(rig.lifecycle.diagnostics.rotationAborts, 0, "no abort")
        checkEqual(rig.lifecycle.diagnostics.rotationBlocked, 0, "no block")

        // The rotated state survives a restart without another write.
        let restarted = rig.restart().launch()
        invariant(restarted, "restart after rotation")
        checkEqual(restarted.lifecycle.token, new, "restart adopts new token")
        checkEqual(restarted.storage.writeCount, 1, "restart writes nothing")
        checkEqual(restarted.intent.writeCount, 2, "restart leaves the intent alone")
    }

    static func testRefusedWhileActiveOrReserved() {
        let rig = RotationRig(stored: old, legacyValue: old, generated: [new]).launch()
        for state in ["Starting", "Listening"] {
            rig.host.state = state
            check(!rig.lifecycle.canRotate, "rotation refused while \(state)")
            rig.lifecycle.rotate()
            checkEqual(rig.storage.stored, old, "rotation leaves \(state) token")
            checkEqual(rig.storage.writeCount, 0, "rotation writes nothing in \(state)")
        }
        rig.host.state = "Stopped"
        rig.host.requested = true
        check(!rig.lifecycle.canRotate, "rotation refused while a start is pending")
        rig.lifecycle.rotate()
        checkEqual(rig.storage.stored, old, "pending start keeps token")
        rig.host.requested = false
        check(rig.lifecycle.canRotate, "rotation returns when idle")

        checkEqual(rig.lifecycle.beginStart(), old, "start reserves the token")
        check(!rig.lifecycle.canRotate, "rotation refused during a start reservation")
        rig.lifecycle.rotate()
        checkEqual(rig.storage.stored, old, "reserved start blocks rotation")
        checkEqual(rig.storage.writeCount, 0, "reserved start writes nothing")
        rig.lifecycle.endStart()
        check(rig.lifecycle.canRotate, "rotation returns after the reservation")
        invariant(rig, "reservation released")
    }

    static func testConflictRefuses() {
        let rig = RotationRig(stored: old, legacyValue: other, generated: [new]).launch()
        check(rig.lifecycle.conflict, "conflict is reported")
        check(!rig.sink.listening, "conflict suspends pairing")
        check(!rig.lifecycle.canRotate, "conflict refuses rotation")
        rig.lifecycle.rotate()
        checkEqual(rig.storage.stored, old, "conflict keeps keychain token")
        checkEqual(rig.legacy.value, other, "conflict keeps old copy")
        checkEqual(rig.storage.writeCount, 0, "conflict writes nothing")
        checkEqual(rig.intent.writeCount, 0, "conflict writes no intent")
        invariant(rig, "conflict")
    }

    // MARK: Restart after each crash point

    static func testPreparedBeforeTokenWriteRestart() {
        let rig = RotationRig(stored: old, legacyValue: old,
                              intentData: intent(.prepared),
                              generated: [new]).launch()
        invariant(rig, "prepared/old restart")
        checkEqual(rig.lifecycle.token, old, "old token remains")
        checkEqual(rig.storage.stored, old, "keychain keeps old token")
        checkEqual(rig.legacy.value, old, "old copy remains after an aborted rotation")
        check(rig.intent.data == nil, "aborted intent cleared")
        checkEqual(rig.storage.writeCount, 0, "aborted rotation writes no token")
        checkEqual(rig.legacy.removeCount, 0, "aborted rotation removes nothing")
        checkEqual(rig.lifecycle.diagnostics.rotationAborts, 1, "abort counted")
        check(rig.host.activities.contains(PlainMessage.tokenRotationAborted), "abort announced")
        check(rig.lifecycle.canRotate, "rotation can run again")
    }

    static func testPreparedWithNewTokenRestart() {
        let rig = RotationRig(stored: new, legacyValue: old,
                              intentData: intent(.prepared),
                              generated: []).launch()
        invariant(rig, "prepared/new restart")
        checkEqual(rig.lifecycle.token, new, "prepared new token adopted")
        checkEqual(rig.storage.stored, new, "keychain keeps new token")
        check(rig.legacy.value == nil, "stale old copy removed")
        check(rig.intent.data == nil, "prepared intent cleared")
        checkEqual(rig.lifecycle.diagnostics.rotationRecoveries, 1, "recovery counted")
        check(rig.host.activities.contains(PlainMessage.tokenRotationRecovered), "recovery announced")
        checkEqual(rig.storage.writeCount, 0, "recovery writes no token")
        checkEqual(rig.feed.calls, 0, "recovery generates no token")
    }

    static func testCommittedWithNewTokenRestart() {
        let rig = RotationRig(stored: new, legacyValue: old,
                              intentData: intent(.committed),
                              generated: []).launch()
        invariant(rig, "committed/new restart")
        checkEqual(rig.lifecycle.token, new, "committed new token adopted")
        check(rig.legacy.value == nil, "committed old copy removed")
        check(rig.intent.data == nil, "committed intent cleared")
        checkEqual(rig.lifecycle.diagnostics.rotationRecoveries, 1, "recovery counted")
        checkEqual(rig.storage.deleteCount, 0, "recovery deletes no keychain item")
    }

    static func testCommittedWithDuplicateNewCopyRestart() {
        let rig = RotationRig(stored: new, legacyValue: new,
                              intentData: intent(.committed),
                              generated: []).launch()
        invariant(rig, "committed/duplicate restart")
        checkEqual(rig.lifecycle.token, new, "duplicate new token adopted")
        check(rig.legacy.value == nil, "duplicate new copy removed")
        check(rig.intent.data == nil, "intent cleared")
    }

    static func testCommittedWithOldTokenBlocks() {
        let rig = RotationRig(stored: old, legacyValue: old,
                              intentData: intent(.committed),
                              generated: [new]).launch()
        invariant(rig, "committed/old restart")
        checkEqual(rig.lifecycle.token, "", "inconsistent state holds no token")
        checkEqual(rig.storage.stored, old, "keychain item retained")
        checkEqual(rig.legacy.value, old, "old copy retained")
        check(rig.intent.data != nil, "inconsistent intent retained")
        checkEqual(rig.storage.writeCount, 0, "no token write")
        checkEqual(rig.storage.deleteCount, 0, "no keychain delete")
        checkEqual(rig.legacy.removeCount, 0, "no old-copy removal")
        checkEqual(rig.feed.calls, 0, "no replacement generated")
        check(!rig.sink.listening, "pairing stays down")
        check(rig.lifecycle.diagnostics.rotationBlocked >= 1, "block counted")
    }

    static func testMissingOrUnknownTokenBlocks() {
        let rig = RotationRig(stored: third, legacyValue: old,
                              intentData: intent(.prepared),
                              generated: [new]).launch()
        invariant(rig, "unknown token")
        checkEqual(rig.lifecycle.lastError, .recoveryRefused,
                   "a third value is not retryable")
        checkEqual(rig.lifecycle.token, "", "unknown state holds no token")
        checkEqual(rig.storage.stored, third, "unknown token retained")
        checkEqual(rig.legacy.value, old, "old copy retained")
        check(rig.intent.data != nil, "intent retained")
        check(rig.lifecycle.diagnostics.text().contains("Rotation recovery record present: yes"),
              "an observed retained intent is reported")
        checkEqual(rig.storage.writeCount, 0, "no token write")
        checkEqual(rig.storage.deleteCount, 0, "no keychain delete")
        checkEqual(rig.legacy.removeCount, 0, "no old-copy removal")
        checkEqual(rig.feed.calls, 0, "no replacement generated")
        check(!rig.sink.listening, "pairing stays down")
    }

    static func testMissingTokenWithIntentRetries() {
        // A missing token beside an intent is not proof that the rotation
        // aborted. Keep the intent and allow a later read to resolve it.
        do {
            let rig = RotationRig(stored: nil, legacyValue: old,
                                  intentData: intent(.prepared),
                                  generated: [new]).launch()
            invariant(rig, "missing token")
            checkEqual(rig.lifecycle.lastError, .rotationRecoveryPending,
                       "a missing token is retryable")
            checkEqual(rig.lifecycle.token, "", "missing token holds no token")
            checkEqual(rig.storage.stored, nil, "missing token stays missing")
            checkEqual(rig.legacy.value, old, "old copy retained")
            check(rig.intent.data != nil, "intent retained")
            check(!rig.sink.listening, "pairing stays down")

            // A later read finds the old value. The prepared intent aborts.
            rig.storage.stored = old
            rig.lifecycle.retryLoadIfNeeded()
            invariant(rig, "missing token retry to old")
            checkEqual(rig.lifecycle.token, old, "retry adopts the old token")
            checkEqual(rig.legacy.value, old, "old copy stays after the abort")
            check(rig.intent.data == nil, "aborted intent cleared")
            checkEqual(rig.lifecycle.diagnostics.rotationAborts, 1, "abort counted")
        }

        // A later read finds the new value. The prepared intent completes.
        do {
            let rig = RotationRig(stored: nil, legacyValue: old,
                                  intentData: intent(.prepared),
                                  generated: [new]).launch()
            checkEqual(rig.lifecycle.lastError, .rotationRecoveryPending,
                       "a missing token is retryable")
            rig.storage.stored = new
            rig.lifecycle.retryLoadIfNeeded()
            invariant(rig, "missing token retry to new")
            checkEqual(rig.lifecycle.token, new, "retry adopts the new token")
            check(rig.legacy.value == nil, "retry removes the old copy")
            check(rig.intent.data == nil, "recovered intent cleared")
            checkEqual(rig.lifecycle.diagnostics.rotationRecoveries, 1,
                       "recovery counted")
        }
    }

    static func testUnknownLegacyBlocksCommitted() {
        let rig = RotationRig(stored: new, legacyValue: other,
                              intentData: intent(.committed),
                              generated: [new]).launch()
        invariant(rig, "unknown old copy")
        checkEqual(rig.lifecycle.token, "", "unknown old copy holds no token")
        checkEqual(rig.storage.stored, new, "confirmed new token retained")
        checkEqual(rig.legacy.value, other, "unknown old copy retained")
        check(rig.intent.data != nil, "intent retained")
        checkEqual(rig.legacy.removeCount, 0, "unknown old copy is not deleted")
        checkEqual(rig.storage.deleteCount, 0, "no keychain delete")
        checkEqual(rig.feed.calls, 0, "no replacement generated")
        check(!rig.sink.listening, "pairing stays down")
    }

    static func testPreparedAbortKeepsUnknownLegacyAndIntent() {
        // The prepared token is still the old value, but the old copy changed
        // to a third value. Clearing the intent would lose the only record of
        // the attempted rotation, so keep it and block.
        let rig = RotationRig(stored: old, legacyValue: other,
                              intentData: intent(.prepared),
                              generated: [new]).launch()
        invariant(rig, "prepared abort with unknown old copy")
        checkEqual(rig.lifecycle.lastError, .legacyConflict,
                   "the unknown old copy is a conflict")
        checkEqual(rig.lifecycle.token, "", "the conflict holds no token")
        checkEqual(rig.storage.stored, old, "keychain item retained")
        checkEqual(rig.legacy.value, other, "unknown old copy retained")
        check(rig.intent.data != nil, "intent retained for inspection")
        checkEqual(rig.legacy.removeCount, 0, "unknown old copy is not deleted")
        checkEqual(rig.storage.writeCount, 0, "no token write")
        checkEqual(rig.feed.calls, 0, "no replacement generated")
        check(!rig.sink.listening, "pairing stays down")
        checkEqual(rig.lifecycle.diagnostics.rotationAborts, 0,
                   "the abort did not complete")
    }

    static func testLegacyRemovalFailureRetries() {
        let rig = RotationRig(stored: new, legacyValue: old,
                              intentData: intent(.committed),
                              generated: [])
        rig.legacy.removeResult = false
        rig.launch()
        invariant(rig, "cleanup failure")
        checkEqual(rig.lifecycle.lastError, .rotationRecoveryPending,
                   "cleanup failure is retryable")
        checkEqual(rig.lifecycle.token, "", "cleanup failure holds no token")
        checkEqual(rig.storage.stored, new, "confirmed new token retained")
        checkEqual(rig.legacy.value, old, "old copy retained after failure")
        check(rig.intent.data != nil, "intent retained")
        check(!rig.sink.listening, "pairing stays down")

        rig.legacy.removeResult = true
        rig.lifecycle.retryLoadIfNeeded()
        invariant(rig, "cleanup retry")
        checkEqual(rig.lifecycle.token, new, "retry adopts new token")
        check(rig.legacy.value == nil, "retry removes old copy")
        check(rig.intent.data == nil, "retry clears intent")
        checkEqual(rig.lifecycle.diagnostics.rotationRecoveries, 1, "recovery counted")
    }

    static func testIntentClearFailureRetries() {
        let rig = RotationRig(stored: new, legacyValue: nil,
                              intentData: intent(.committed),
                              generated: [])
        rig.intent.clearError = .keychainDeleteFailed(-1)
        rig.launch()
        invariant(rig, "intent clear failure")
        checkEqual(rig.lifecycle.lastError, .keychainDeleteFailed(-1),
                   "clear failure is reported")
        checkEqual(rig.lifecycle.token, "", "clear failure holds no token")
        check(rig.intent.data != nil, "intent retained after clear failure")
        check(rig.lifecycle.diagnostics.text().contains("Rotation recovery record present: unknown"),
              "failed clear leaves intent presence unknown")
        check(!rig.sink.listening, "pairing stays down")

        rig.intent.clearError = nil
        rig.lifecycle.retryLoadIfNeeded()
        invariant(rig, "intent clear retry")
        checkEqual(rig.lifecycle.token, new, "retry adopts new token")
        check(rig.intent.data == nil, "retry clears intent")
        checkEqual(rig.lifecycle.diagnostics.rotationRecoveries, 1, "recovery counted")
    }

    static func testPreparedIntentClearFailureRetries() {
        // The prepared intent names the old token, so the abort is safe, but
        // the clear failed. Keep pairing down until a later read clears it.
        let rig = RotationRig(stored: old, legacyValue: old,
                              intentData: intent(.prepared),
                              generated: [])
        rig.intent.clearError = .keychainDeleteFailed(-1)
        rig.launch()
        invariant(rig, "prepared clear failure")
        checkEqual(rig.lifecycle.lastError, .keychainDeleteFailed(-1),
                   "prepared clear failure is reported")
        checkEqual(rig.lifecycle.token, "", "prepared clear failure holds no token")
        checkEqual(rig.storage.stored, old, "old token retained")
        check(rig.intent.data != nil, "intent retained after clear failure")
        checkEqual(rig.lifecycle.diagnostics.rotationAborts, 0,
                   "the abort did not complete")
        check(!rig.sink.listening, "pairing stays down")

        rig.intent.clearError = nil
        rig.lifecycle.retryLoadIfNeeded()
        invariant(rig, "prepared clear retry")
        checkEqual(rig.lifecycle.token, old, "retry adopts the old token")
        check(rig.intent.data == nil, "retry clears the intent")
        check(rig.lifecycle.diagnostics.text().contains("Rotation recovery record present: no"),
              "successful clear reports no intent")
        checkEqual(rig.lifecycle.diagnostics.rotationAborts, 1, "abort counted")
    }

    static func testDamagedIntentBlocks() {
        var equalDigests = intent(.prepared)
        let oldStart = 2 + TokenRotationIntent.transactionBytes
        for offset in 0..<TokenRotationIntent.digestBytes {
            equalDigests[oldStart + TokenRotationIntent.digestBytes + offset] =
                equalDigests[oldStart + offset]
        }
        for data in [Data([1]),
                     Data(repeating: 0, count: TokenRotationIntent.encodedBytes),
                     equalDigests] {
            let rig = RotationRig(stored: old, legacyValue: old,
                                  intentData: data,
                                  generated: [new]).launch()
            invariant(rig, "damaged intent")
            checkEqual(rig.lifecycle.lastError, .invalidRecoveryIntent,
                       "damaged intent is refused")
            checkEqual(rig.lifecycle.token, "", "damaged intent holds no token")
            checkEqual(rig.storage.stored, old, "keychain item retained")
            checkEqual(rig.legacy.value, old, "old copy retained")
            checkEqual(rig.intent.data, data, "damaged intent retained")
            checkEqual(rig.storage.writeCount, 0, "no token write")
            checkEqual(rig.storage.deleteCount, 0, "no keychain delete")
            checkEqual(rig.feed.calls, 0, "no replacement generated")
            check(!rig.sink.listening, "pairing stays down")
        }
    }

    static func testIntentReadFailureBlocks() {
        let rig = RotationRig(stored: old, legacyValue: old, generated: [new])
        rig.intent.readError = .keychainUnavailable(-25308)
        rig.launch()
        invariant(rig, "intent read failure")
        checkEqual(rig.lifecycle.lastError, .keychainUnavailable(-25308),
                   "intent read failure is reported")
        check(rig.lifecycle.diagnostics.text().contains("Rotation recovery record present: unknown"),
              "unreadable intent presence is unknown")
        check(rig.lifecycle.diagnostics.text().contains("Old token copy present: unknown"),
              "an unread legacy copy is not reported absent")
        checkEqual(rig.lifecycle.token, "", "intent read failure holds no token")
        checkEqual(rig.storage.writeCount, 0, "no token write")
        checkEqual(rig.storage.deleteCount, 0, "no keychain delete")
        checkEqual(rig.legacy.removeCount, 0, "no old-copy removal")
        check(!rig.sink.listening, "pairing stays down")
    }

    static func testTokenReadFailureBlocks() {
        let rig = RotationRig(stored: old, legacyValue: old,
                              intentData: intent(.prepared),
                              generated: [new])
        rig.storage.readSteps = [.failure(.keychainUnavailable(-25308))]
        rig.launch()
        invariant(rig, "token read failure")
        checkEqual(rig.lifecycle.lastError, .keychainUnavailable(-25308),
                   "token read failure is reported")
        checkEqual(rig.lifecycle.token, "", "token read failure holds no token")
        check(rig.intent.data != nil, "intent retained")
        checkEqual(rig.storage.writeCount, 0, "no token write")
        checkEqual(rig.storage.deleteCount, 0, "no keychain delete")
        checkEqual(rig.legacy.removeCount, 0, "no old-copy removal")
        check(!rig.sink.listening, "pairing stays down")
    }

    static func testMissingIntentBackendBlocks() {
        // A nil backend is not evidence that no rotation is pending. A previous
        // build may have left an intent that this store cannot read.
        let storage = FakeTokenStorage(stored: old)
        let legacy = FakeLegacyStore(value: old)
        let sink = RotationSink(), host = RotationHost()
        let store = SecureTokenStore(storage: storage, legacy: legacy,
                                     recoveryIntent: nil,
                                     generate: { new })
        let lifecycle = TokenLifecycle(store: store, pairing: sink,
                                       rotationReviewed: true)
        host.lifecycle = lifecycle
        lifecycle.attach(host: host)
        lifecycle.launch()
        checkEqual(lifecycle.lastError, .recoveryIntentUnavailable,
                   "a nil intent backend fails closed")
        check(lifecycle.diagnostics.text().contains("Rotation recovery record present: unknown"),
              "a missing backend cannot prove intent absence")
        check(!lifecycle.canRotate, "a nil intent backend refuses rotation")
        checkEqual(lifecycle.token, "", "a nil intent backend holds no token")
        check(!sink.listening, "a nil intent backend suspends pairing")
        checkEqual(storage.writeCount, 0, "a nil intent backend writes no token")
        checkEqual(storage.deleteCount, 0, "a nil intent backend deletes no item")
        checkEqual(legacy.removeCount, 0, "a nil intent backend removes no old copy")
        checkEqual(store.createInitial(), .unchanged(.recoveryIntentUnavailable),
                   "a nil intent backend refuses creation")
        checkEqual(store.rotate(), .unchanged(.recoveryIntentUnavailable),
                   "a nil intent backend refuses rotation")
        checkEqual(store.recoverRotationIfNeeded(),
                   .blocked(.recoveryIntentUnavailable),
                   "a nil intent backend cannot prove absence")
    }

    // MARK: Write outcomes

    static func testWriteReportedFailureStillSucceeds() {
        let rig = RotationRig(stored: old, legacyValue: old, generated: [new]).launch()
        rig.storage.writeSteps = [.failureButStore(.keychainWriteFailed(-34018))]
        rig.lifecycle.rotate()
        invariant(rig, "readable write")
        checkEqual(rig.lifecycle.token, new, "readable write adopts new token")
        checkEqual(rig.storage.stored, new, "readable write stored new token")
        check(rig.legacy.value == nil, "readable write removes old copy")
        check(rig.intent.data == nil, "readable write clears intent")
    }

    static func testPostWriteReadFailureReloads() {
        let rig = RotationRig(stored: old, legacyValue: old, generated: [new]).launch()
        // The next reads are: rotation's initial read, the pre-write read, and
        // the post-write confirmation. Only the last one fails.
        rig.storage.readSteps = [.value(old), .value(old),
                                 .failure(.keychainReadFailed(-1))]
        rig.lifecycle.rotate()
        invariant(rig, "post-write read failure")
        checkEqual(rig.lifecycle.token, new, "reload resolves the new token")
        checkEqual(rig.storage.stored, new, "new token remained stored")
        check(rig.legacy.value == nil, "reload removes the old copy")
        check(rig.intent.data == nil, "reload clears the intent")
        checkEqual(rig.lifecycle.diagnostics.rotationRecoveries, 1, "recovery counted")
        checkEqual(rig.storage.writeCount, 1, "only the rotation write ran")
    }

    static func testWriteFailureKeepsOldToken() {
        let rig = RotationRig(stored: old, legacyValue: old, generated: [new]).launch()
        rig.storage.writeSteps = [.failure(.keychainWriteFailed(-34018))]
        rig.lifecycle.rotate()
        invariant(rig, "failed token write")
        checkEqual(rig.lifecycle.token, old, "failed write keeps old token")
        checkEqual(rig.storage.stored, old, "failed write keeps stored token")
        checkEqual(rig.legacy.value, old, "failed write keeps old copy")
        check(rig.intent.data == nil, "failed write clears intent")
        check(rig.sink.configured?.token == old, "pairing keeps old token")
        checkEqual(rig.lifecycle.diagnostics.confirmedRotations, 0, "no rotation confirmed")
    }

    // MARK: A stored value that changes while the app runs
    //
    // `store.rotate` resolves a pending intent before it starts. That recovery
    // can move storage to a token the app never adopted. A failed rotation that
    // does not invalidate the cache must not leave the listener on the old
    // value, and it must never offer a token that storage no longer holds.

    static func testCommittedIntentAppearsDuringRun() {
        let rig = RotationRig(stored: old, legacyValue: old, generated: [third]).launch()
        checkEqual(rig.sink.configured?.token, old, "launch offers the stored token")
        let eventsBefore = rig.sink.events.count

        // A committed intent appears while the app runs and storage already
        // holds the token that intent names. Nothing in the app adopted it.
        rig.intent.data = intent(.committed, old: old, new: new)
        rig.storage.stored = new
        // The rotation's own write fails with a result that does not
        // invalidate the cached token on its own.
        rig.storage.writeSteps = [.failure(.keychainWriteFailed(-34018))]
        check(!TokenRotationPolicy.invalidatesMemoryToken(.keychainWriteFailed(-34018)),
              "the failed write is a non-invalidating result")

        rig.lifecycle.rotate()
        invariant(rig, "committed intent appeared during the run")
        checkEqual(rig.lifecycle.token, new, "the reloaded token replaces the cache")
        checkEqual(rig.storage.stored, new, "storage keeps the recovered token")
        checkEqual(rig.sink.configured?.token, new, "pairing offers the stored token")
        check(rig.legacy.value == nil, "recovery removed the stale old copy")
        check(rig.intent.data == nil, "recovery cleared the intent")
        checkEqual(rig.lifecycle.diagnostics.rotationRecoveries, 1,
                   "the interrupted rotation was recovered")
        checkEqual(rig.lifecycle.diagnostics.confirmedRotations, 0,
                   "the failed rotation is not counted")
        checkEqual(rig.lifecycle.lastError, nil, "a confirmed reload clears the rotation error")
        checkEqual(rig.lifecycle.storageFailure, PlainMessage.tokenRotationReloaded,
                   "the reload is reported")
        check(rig.host.activities.contains(PlainMessage.tokenRotationReloaded),
              "the reload is announced")
        checkEqual(rig.storage.writeCount, 1, "one failed token write")
        checkEqual(rig.storage.written, [third], "only the failed new token was written")

        // The listener must never be configured with the cached value again
        // after storage proved a different token.
        let eventsAfter = Array(rig.sink.events.dropFirst(eventsBefore))
        check(!eventsAfter.contains(.configure(port, old)),
              "the stale cached token never reaches the listener")
        check(!rig.host.activities.contains(old), "no activity names the old token")
    }

    static func testPreparedIntentAbortDuringRunKeepsCache() {
        let rig = RotationRig(stored: old, legacyValue: old, generated: [nil]).launch()

        // A prepared intent appears while the app runs, and the token item
        // still holds the old value. Recovery aborts the intent, so the cached
        // token is still current. The rotation then fails before a write.
        rig.intent.data = intent(.prepared, old: old, new: new)
        rig.lifecycle.rotate()
        invariant(rig, "prepared intent aborted during the run")
        checkEqual(rig.lifecycle.token, old, "the cached token is still stored")
        checkEqual(rig.sink.configured?.token, old, "pairing keeps the stored token")
        checkEqual(rig.lifecycle.lastError, .generatorFailed, "the rotation failure is reported")
        checkEqual(rig.lifecycle.storageFailure, SecureTokenError.generatorFailed.message,
                   "the rotation failure text is kept")
        check(rig.intent.data == nil, "the aborted intent is cleared")
        checkEqual(rig.lifecycle.diagnostics.rotationAborts, 1, "the abort is counted")
        check(!rig.host.activities.contains(PlainMessage.tokenRotationReloaded),
              "an unchanged cached token is not reported as reloaded")
    }

    static func testExternalTokenChangeBeforeFailedWrite() {
        let rig = RotationRig(stored: old, legacyValue: old, generated: [third]).launch()

        // Another writer replaces the keychain item and removes the old copy
        // while the app runs. No intent records the change.
        rig.storage.stored = new
        rig.storage.readSteps = [.value(new)]
        rig.legacy.value = nil
        rig.storage.writeSteps = [.failure(.keychainWriteFailed(-34018))]

        rig.lifecycle.rotate()
        invariant(rig, "external token change before a failed write")
        checkEqual(rig.lifecycle.token, new, "the stored token replaces the cache")
        checkEqual(rig.storage.stored, new, "the external token is retained")
        checkEqual(rig.sink.configured?.token, new, "pairing offers the stored token")
        checkEqual(rig.lifecycle.lastError, nil, "a confirmed reload clears the rotation error")
        checkEqual(rig.lifecycle.storageFailure, PlainMessage.tokenRotationReloaded,
                   "the reload is reported")
        checkEqual(rig.storage.writeCount, 1, "one failed token write")
        check(!rig.host.activities.contains(old), "no activity names the cached token")
    }

    static func testUnconfirmedTokenAfterFailedRotationSuspendsPairing() {
        for missing in [false, true] {
            let rig = RotationRig(stored: old, legacyValue: nil, generated: [nil]).launch()
            let eventsBefore = rig.sink.events.count
            // Rotation reads the old token, then generation fails. The
            // separate confirmation cannot read it or finds it gone.
            rig.storage.readSteps = [
                .value(old),
                missing ? .valueAndStore(nil) : .failure(.keychainReadFailed(-1))
            ]

            rig.lifecycle.rotate()

            checkEqual(rig.lifecycle.token, "", "unconfirmed token is discarded")
            check(!rig.lifecycle.storageReady, "unconfirmed storage is not ready")
            check(!rig.sink.listening, "pairing stays suspended")
            checkEqual(rig.storage.writeCount, 0, "confirmation writes no token")
            checkEqual(rig.legacy.removeCount, 0, "confirmation removes no legacy token")
            let laterEvents = Array(rig.sink.events.dropFirst(eventsBefore))
            check(!laterEvents.contains(.configure(port, old)), "old token is not re-offered")
            checkEqual(rig.lifecycle.lastError,
                       missing ? .tokenUnavailableAfterFailure : .keychainReadFailed(-1),
                       "confirmation reports the read outcome")
        }
    }

    static func testRecoveryConfirmationLockOrder() {
        let rig = RotationRig(stored: old, legacyValue: old, generated: [third]).launch()
        rig.intent.data = intent(.committed, old: old, new: new)
        rig.storage.stored = new
        rig.storage.writeSteps = [.failure(.keychainWriteFailed(-34018))]

        // A nested store call made from inside the rotation's write callback is
        // refused. The lifecycle's confirmation must therefore be a new
        // transaction after `rotate` returns, never work done inside a store
        // callback.
        var nestedLoad: TokenLoadResult?
        rig.storage.onWrite = { nestedLoad = rig.store.loadOrMigrate(allowMigration: false) }

        // The pairing sink runs after the store transaction is released. A
        // read from that callback succeeds instead of reporting a reentrant
        // transaction, so the order is lifecycle, store, then sink.
        var sinkRead: TokenLoadResult?
        var sinkReadCount = 0
        rig.sink.onConfigure = {
            sinkReadCount += 1
            sinkRead = rig.store.loadOrMigrate(allowMigration: false)
        }

        rig.lifecycle.rotate()
        checkEqual(nestedLoad, .some(.failed(.recoveryRefused)),
                   "a store callback cannot start another transaction")
        checkEqual(sinkRead, .some(.loaded(new)),
                   "the pairing sink runs with no active store transaction")
        checkEqual(sinkReadCount, 1, "one pairing update after the reload")
        invariant(rig, "confirmation lock order")
        checkEqual(rig.lifecycle.token, new, "the reloaded token is adopted")
        checkEqual(rig.sink.configured?.token, new, "pairing offers the reloaded token")
    }

    static func testIntentWriteLandedThenFailed() {
        let rig = RotationRig(stored: old, legacyValue: old, generated: [new]).launch()
        rig.intent.writeErrorAfterStore = .keychainWriteFailed(-34018)
        rig.lifecycle.rotate()
        invariant(rig, "intent write landed then failed")
        checkEqual(rig.lifecycle.token, old, "prepared intent aborts to old token")
        checkEqual(rig.storage.stored, old, "token write never ran")
        checkEqual(rig.legacy.value, old, "old copy retained")
        check(rig.intent.data == nil, "aborted intent cleared")
        checkEqual(rig.storage.writeCount, 0, "no token write")
        check(rig.sink.configured?.token == old, "pairing keeps old token")
        checkEqual(rig.lifecycle.diagnostics.rotationAborts, 1, "abort counted")
    }

    static func testIntentClearFailureAfterCommit() {
        let rig = RotationRig(stored: old, legacyValue: old, generated: [new]).launch()
        rig.intent.clearError = .keychainDeleteFailed(-1)
        rig.lifecycle.rotate()
        invariant(rig, "intent clear failure after commit")
        checkEqual(rig.lifecycle.token, "", "unconfirmed cleanup holds no token")
        checkEqual(rig.storage.stored, new, "committed token retained")
        check(rig.legacy.value == nil, "old copy already removed")
        check(rig.intent.data != nil, "intent retained")
        check(!rig.sink.listening, "pairing stays down")

        rig.intent.clearError = nil
        rig.lifecycle.retryLoadIfNeeded()
        invariant(rig, "intent clear retry")
        checkEqual(rig.lifecycle.token, new, "retry adopts committed token")
        check(rig.intent.data == nil, "retry clears intent")
        checkEqual(rig.lifecycle.diagnostics.rotationRecoveries, 1, "recovery counted")
    }

    static func testLegacyRemovalFailureAfterCommit() {
        let rig = RotationRig(stored: old, legacyValue: old, generated: [new]).launch()
        rig.legacy.removeResult = false
        rig.lifecycle.rotate()
        invariant(rig, "old-copy removal failure after commit")
        checkEqual(rig.lifecycle.token, "", "unconfirmed cleanup holds no token")
        checkEqual(rig.storage.stored, new, "committed token retained")
        checkEqual(rig.legacy.value, old, "old copy retained")
        check(rig.intent.data != nil, "intent retained")
        check(!rig.sink.listening, "pairing stays down")

        rig.legacy.removeResult = true
        rig.lifecycle.retryLoadIfNeeded()
        invariant(rig, "old-copy removal retry")
        checkEqual(rig.lifecycle.token, new, "retry adopts committed token")
        check(rig.legacy.value == nil, "retry removes old copy")
        check(rig.intent.data == nil, "retry clears intent")
        checkEqual(rig.lifecycle.diagnostics.rotationRecoveries, 1, "recovery counted")
    }

    static func testIntentClearLandedThenFailed() {
        let rig = RotationRig(stored: old, legacyValue: old, generated: [new]).launch()
        rig.intent.clearErrorAfterClear = .keychainDeleteFailed(-1)
        rig.lifecycle.rotate()
        invariant(rig, "intent clear landed then failed")
        checkEqual(rig.lifecycle.token, new, "reload adopts the committed token")
        checkEqual(rig.storage.stored, new, "committed token retained")
        check(rig.legacy.value == nil, "old copy removed")
        check(rig.intent.data == nil, "intent is gone")
        check(rig.sink.configured?.token == new, "pairing offers the new token")
        checkEqual(rig.lifecycle.diagnostics.confirmedRotations, 0,
                   "the reported error is not counted as a clean rotation")
    }

    static func testExternalTokenChangeBeforeWrite() {
        let rig = RotationRig(stored: old, legacyValue: old, generated: [new]).launch()
        // Rotation sees the old token, then an external writer replaces it
        // before the pre-write confirmation read.
        rig.storage.readSteps = [.value(old), .value(other)]
        rig.storage.stored = other
        rig.lifecycle.rotate()
        invariant(rig, "external token change")
        checkEqual(rig.lifecycle.token, "", "external change holds no token")
        checkEqual(rig.storage.stored, other, "external token retained")
        checkEqual(rig.legacy.value, old, "old copy retained")
        check(rig.intent.data != nil, "external change keeps intent")
        checkEqual(rig.storage.writeCount, 0, "no write over the external token")
        checkEqual(rig.storage.deleteCount, 0, "no keychain delete")
        check(!rig.sink.listening, "pairing stays down")
    }

    static func testExternalTokenOverwriteAfterLastRead() {
        // The Keychain update is unconditional. A different writer that replaces
        // the item after the pre-write read is overwritten by this rotation.
        // The read-back sees only this transaction's value, so the store cannot
        // detect the lost write. This test records the residual window; it does
        // not make the window safe.
        let rig = RotationRig(stored: old, legacyValue: old, generated: [new]).launch()
        rig.storage.onWrite = { rig.storage.stored = other }
        rig.lifecycle.rotate()
        invariant(rig, "external token overwrite")
        checkEqual(rig.lifecycle.token, new, "the rotation adopts its own token")
        checkEqual(rig.storage.stored, new, "the rotation overwrites the external token")
        checkEqual(rig.storage.written, [new], "only the rotation write remains visible")
        check(rig.legacy.value == nil, "the observed old copy is removed")
        check(rig.intent.data == nil, "the intent is cleared")
        checkEqual(rig.lifecycle.diagnostics.confirmedRotations, 1,
                   "the store cannot report the overwritten writer")
    }

    static func testExternalLegacyChangeDuringWrite() {
        let rig = RotationRig(stored: old, legacyValue: old, generated: [new]).launch()
        rig.storage.onWrite = { rig.legacy.value = other }
        rig.lifecycle.rotate()
        invariant(rig, "external old-copy change")
        checkEqual(rig.lifecycle.token, "", "external old copy holds no token")
        checkEqual(rig.storage.stored, new, "confirmed new token retained")
        checkEqual(rig.legacy.value, other, "external old copy retained")
        checkEqual(rig.legacy.removeCount, 0, "external old copy is not deleted")
        check(rig.intent.data != nil, "intent retained for inspection")
        check(rig.lifecycle.conflict, "external old copy is a conflict")
        check(!rig.sink.listening, "pairing stays down")
    }

    static func testExternalLegacyRemovalRace() {
        // A different writer replaces the old copy after the store's check but
        // before its removal. The removal fails, so the rotation cannot claim a
        // clean result. The later recovery read sees the third value and blocks.
        let rig = RotationRig(stored: old, legacyValue: old, generated: [new]).launch()
        rig.legacy.onRemove = { rig.legacy.value = other }
        rig.legacy.removeResult = false
        rig.lifecycle.rotate()
        invariant(rig, "external old-copy removal race")
        checkEqual(rig.lifecycle.lastError, .legacyConflict,
                   "the third old copy is a conflict")
        checkEqual(rig.lifecycle.token, "", "the race holds no token")
        checkEqual(rig.storage.stored, new, "the confirmed new token remains")
        checkEqual(rig.legacy.value, other, "the external old copy remains")
        check(rig.intent.data != nil, "the intent remains for inspection")
        check(!rig.sink.listening, "pairing stays down")
    }

    static func testDowngradeCopyAfterRotation() {
        let rig = RotationRig(stored: old, legacyValue: old, generated: [new]).launch()
        rig.lifecycle.rotate()
        checkEqual(rig.storage.stored, new, "rotation completed")
        // A downgrade or a restored backup writes the old token to UserDefaults.
        rig.legacy.value = old
        let restarted = rig.restart().launch()
        invariant(restarted, "downgrade copy")
        checkEqual(restarted.lifecycle.token, "", "downgrade copy holds no token")
        checkEqual(restarted.storage.stored, new, "rotated token retained")
        checkEqual(restarted.legacy.value, old, "downgrade copy retained")
        check(!restarted.sink.listening, "downgrade copy suspends pairing")
        checkEqual(restarted.storage.writeCount, 1, "downgrade copy writes nothing")
        checkEqual(restarted.intent.writeCount, 2, "downgrade copy writes no intent")
    }

    static func testIntentLostAfterTokenWriteIsConflict() {
        // The token write survived, but the intent did not. The old copy is
        // still present, so the next launch sees two working credentials and
        // cannot tell which one is current.
        let rig = RotationRig(stored: new, legacyValue: old,
                              intentData: nil, generated: []).launch()
        invariant(rig, "intent lost after token write")
        checkEqual(rig.lifecycle.lastError, .legacyConflict,
                   "the two copies are a conflict")
        checkEqual(rig.lifecycle.token, "", "the conflict holds no token")
        checkEqual(rig.storage.stored, new, "the newer item is retained")
        checkEqual(rig.legacy.value, old, "the older copy is retained")
        check(rig.intent.data == nil, "there is no intent to resolve")
        checkEqual(rig.storage.writeCount, 0, "the conflict writes nothing")
        checkEqual(rig.storage.deleteCount, 0, "the conflict deletes nothing")
        checkEqual(rig.legacy.removeCount, 0, "the conflict removes no old copy")
        check(!rig.sink.listening, "pairing stays down")
    }

    static func testDowngradeCreatesLegacyToken() {
        // A downgrade can write a token to UserDefaults while the Keychain
        // still holds the newer value. Keep both and use neither.
        do {
            let rig = RotationRig(stored: new, legacyValue: other,
                                  intentData: nil, generated: []).launch()
            invariant(rig, "downgrade copy beside keychain")
            checkEqual(rig.lifecycle.lastError, .legacyConflict,
                       "the downgrade copy is a conflict")
            checkEqual(rig.lifecycle.token, "", "the conflict holds no token")
            checkEqual(rig.storage.stored, new, "the keychain value is retained")
            checkEqual(rig.legacy.value, other, "the downgrade copy is retained")
            checkEqual(rig.storage.writeCount, 0, "the conflict writes nothing")
            checkEqual(rig.legacy.removeCount, 0, "the conflict removes nothing")
            check(!rig.sink.listening, "pairing stays down")
        }

        // If the Keychain item is gone, the downgrade copy is the only
        // credential. Migration uses it and cannot know it predates a rotation.
        do {
            let rig = RotationRig(stored: nil, legacyValue: old,
                                  intentData: nil, generated: [new]).launch()
            invariant(rig, "downgrade copy only")
            checkEqual(rig.lifecycle.token, old, "the only copy is adopted")
            checkEqual(rig.storage.stored, old, "the only copy is migrated")
            checkEqual(rig.legacy.value, old, "the old copy is retained")
            checkEqual(rig.storage.writeCount, 1, "migration writes once")
            checkEqual(rig.feed.calls, 0, "migration generates no token")
            checkEqual(rig.lifecycle.diagnostics.migrations, 1, "migration counted")
        }
    }

    static func testReadBackDoesNotProveDurability() {
        // The committed intent was read back, but the token write did not
        // survive. A later read sees the old token beside a committed intent.
        // It blocks instead of choosing a value.
        let rig = RotationRig(stored: old, legacyValue: old, generated: [new]).launch()
        rig.intent.clearError = .keychainDeleteFailed(-1)
        rig.lifecycle.rotate()
        checkEqual(rig.storage.stored, new, "the rotation read back the new token")
        check(rig.legacy.value == nil, "the rotation removed the old copy")
        check(rig.intent.data != nil, "the committed intent remains")
        checkEqual(rig.lifecycle.token, "", "the failed clear holds no token")

        let writesBefore = rig.storage.writeCount
        let deletesBefore = rig.storage.deleteCount
        let removalsBefore = rig.legacy.removeCount
        rig.storage.stored = old
        rig.intent.clearError = nil
        let restarted = rig.restart().launch()
        invariant(restarted, "token write lost after read-back")
        checkEqual(restarted.lifecycle.lastError, .recoveryRefused,
                   "the inconsistent state blocks")
        checkEqual(restarted.lifecycle.token, "", "the inconsistent state holds no token")
        checkEqual(restarted.storage.stored, old, "the old token is retained")
        check(restarted.intent.data != nil, "the committed intent is retained")
        check(!restarted.sink.listening, "pairing stays down")
        checkEqual(restarted.storage.writeCount, writesBefore,
                   "the restart writes no token")
        checkEqual(restarted.storage.deleteCount, deletesBefore,
                   "the restart deletes no item")
        checkEqual(restarted.legacy.removeCount, removalsBefore,
                   "the restart removes no old copy")
    }

    static func testNoAutomaticReplacementOnUnknown() {
        let rig = RotationRig(stored: third, legacyValue: other,
                              intentData: intent(.prepared),
                              generated: [new]).launch()
        invariant(rig, "no automatic replacement")
        checkEqual(rig.feed.calls, 0, "unknown state generates no token")
        checkEqual(rig.storage.writeCount, 0, "unknown state writes no token")
        checkEqual(rig.storage.deleteCount, 0, "unknown state deletes nothing")
        checkEqual(rig.legacy.removeCount, 0, "unknown state removes no old copy")
        checkEqual(rig.intent.writeCount, 0, "unknown state writes no intent")
        checkEqual(rig.intent.clearCount, 0, "unknown state clears no intent")
    }

    // MARK: Diagnostics

    static func testDiagnosticsHoldNoToken() {
        let rig = RotationRig(stored: old, legacyValue: old, generated: [new]).launch()
        rig.lifecycle.rotate()
        let text = rig.lifecycle.diagnostics.text()
        check(text.contains("Token rotations confirmed: 1"), "confirmed count present")
        check(text.contains("Rotation recovery record present: no"), "intent state present")
        for token in [old, new] {
            check(!text.contains(token), "diagnostics hold no token")
            for start in stride(from: 0, to: token.count, by: 8) {
                let begin = token.index(token.startIndex, offsetBy: start)
                let end = token.index(begin, offsetBy: min(8, token.count - start))
                check(!text.contains(String(token[begin..<end])),
                      "diagnostics hold no token chunk")
            }
        }
        check(!String(describing: rig.lifecycle.diagnostics).contains(new),
              "diagnostics value holds no token")
    }
}
