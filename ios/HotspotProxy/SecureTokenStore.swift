import CryptoKit
import Foundation
import Security

/// Rules for a source device proxy token.
///
/// The app creates 32 lowercase hex characters from 16 random bytes. The rule
/// here is wider on purpose. It keeps a token that an older build saved, as
/// long as the token is printable ASCII with no spaces or control characters.
enum SecureTokenRules {
    /// The SOCKS5 password field is one byte, so a token over 255 bytes
    /// cannot cross the proxy. The app itself uses 32 hex characters.
    static let maxLength = 255

    static func isValid(_ token: String) -> Bool {
        guard !token.isEmpty, token.utf8.count <= maxLength else { return false }
        return token.utf8.allSatisfy { byte in byte >= 0x21 && byte <= 0x7E }
    }
}

/// The rule for the Rotate token control.
///
/// The proxy keeps its own copy of the token for each relay, and pairing hands
/// out the stored token. A rotation while the proxy runs or a start is pending
/// leaves the running proxy on the old token while pairing hands out the new
/// one. A rotation also needs a readable stored token. A new token must not
/// replace an item that the app could not read.
///
/// The staged transaction is not enabled. Keychain and UserDefaults have no
/// shared transaction and no compare-and-swap. A different writer can change an
/// item between the final read and the update, and a read-back does not prove
/// that the bytes survive a crash or power loss. A restart only resolves the
/// state that the stored bytes describe. Until a reviewed protocol closes those
/// windows, the app uses the default `reviewed: false`. Tests pass `true` to
/// exercise the dormant store transaction.
enum TokenRotationPolicy {
    /// The independent review gate. Production stays false until a reviewed
    /// protocol proves the staged rotation safe.
    static let reviewed = false

    /// True while the proxy runs or the app asked for a start that has not
    /// reached the server yet.
    static func proxyActive(proxyRequested: Bool, state: String) -> Bool {
        proxyRequested || state == "Listening" || state == "Starting"
    }

    static func canRotate(proxyRequested: Bool,
                          state: String,
                          tokenUsable: Bool,
                          storageReady: Bool,
                          legacyConflict: Bool = false,
                          lifecycleFree: Bool = true,
                          rotationReviewed: Bool = reviewed) -> Bool {
        guard rotationReviewed else { return false }
        guard !proxyActive(proxyRequested: proxyRequested, state: state) else {
            return false
        }
        guard lifecycleFree, tokenUsable, storageReady, !legacyConflict else {
            return false
        }
        return true
    }

    /// A failure that means the stored token can no longer be read. Rotation
    /// stays disabled until a later load succeeds.
    static func storageUnavailable(_ error: SecureTokenError) -> Bool {
        switch error {
        case .keychainUnavailable, .keychainReadFailed, .invalidStoredToken, .invalidLegacyToken,
             .tokenUnavailableAfterFailure, .recoveryIntentUnavailable,
             .invalidRecoveryIntent, .rotationRecoveryPending, .recoveryRefused,
             .legacyNotMigrated:
            return true
        default:
            return false
        }
    }

    /// True when a failed rotation must drop the in-memory token and take the
    /// pairing listener down. An invalid or missing Keychain item with a legacy
    /// copy may no longer hold the value the app would hand out. An intent
    /// record that cannot be resolved has the same effect: the app cannot prove
    /// which credential storage holds. A transient failure can return
    /// `unchanged`, but this does not prove that a cached token is current.
    /// The lifecycle confirms it with a separate store read before resuming
    /// pairing.
    static func invalidatesMemoryToken(_ error: SecureTokenError) -> Bool {
        switch error {
        case .invalidStoredToken, .invalidLegacyToken, .legacyNotMigrated,
             .tokenUnavailableAfterFailure, .legacyConflict,
             .invalidRecoveryIntent, .rotationRecoveryPending,
             .recoveryRefused, .recoveryIntentUnavailable: return true
        default: return false
        }
    }
}

/// The explicit recovery action that applies to the stored token.
///
/// The two actions are not interchangeable. `restoreLegacy` would write a valid
/// old copy back into the Keychain. `replaceInvalid` would create a new
/// credential, so every target device that holds the old token must pair again.
///
/// The store refuses both actions today. It cannot conditionally delete an
/// invalid Keychain item, and a valid old copy can predate a rotation. The kinds
/// keep the intended meaning for a reviewed repair protocol; they do not mean
/// that the app can perform the action now. Do not promise that access stays
/// the same.
enum TokenRecoveryKind: Equatable {
    case none
    case replaceInvalid
    case restoreLegacy
}

/// The rule for repairing a saved token that is not valid.
///
/// A transient Keychain error, a missing token, and a conflict all have a
/// different remedy. The recovery controls are only for an invalid Keychain
/// item or an invalid old UserDefaults copy. The store refuses both actions
/// until it can identify an item for a conditional delete. A future action
/// would delete something and need an explicit confirmation from the person who
/// uses the source device.
enum TokenRecoveryPolicy {
    /// Retain the refresh policy for a future reviewed repair action. The
    /// current store returns `.none` without reading or offering an action.
    static func needsRefresh(error: SecureTokenError?,
                             kind: TokenRecoveryKind) -> Bool {
        isInvalidState(error) && kind == .none
    }

    /// True only for the two storage states that no retry and no in-app repair
    /// can clear.
    static func isInvalidState(_ error: SecureTokenError?) -> Bool {
        switch error {
        case .invalidStoredToken, .invalidLegacyToken:
            return true
        default:
            return false
        }
    }

    /// The action that the person may run now, or `.none`. The proxy keeps its
    /// own copy of the token, and a start can be pending before the snapshot
    /// shows "Starting". Both block either action. The current store always
    /// returns `.none` without re-reading the stores and refuses both actions.
    /// A future repair must safely reclassify the state before offering either
    /// action; this policy alone does not establish that the error is current.
    static func allowedAction(proxyRequested: Bool,
                              state: String,
                              error: SecureTokenError?,
                              kind: TokenRecoveryKind) -> TokenRecoveryKind {
        guard !TokenRotationPolicy.proxyActive(proxyRequested: proxyRequested,
                                               state: state) else {
            return .none
        }
        guard isInvalidState(error) else { return .none }
        return kind
    }

    /// True only when a new credential would be the right action. The store
    /// still refuses it. A valid old copy is working material, so it selects
    /// `restoreLegacy` instead.
    static func canReplace(proxyRequested: Bool,
                           state: String,
                           error: SecureTokenError?,
                           kind: TokenRecoveryKind) -> Bool {
        allowedAction(proxyRequested: proxyRequested, state: state,
                      error: error, kind: kind) == .replaceInvalid
    }

    /// True only when a valid old copy would be the right action. The store
    /// still refuses it. This action would reuse an existing credential, but
    /// that copy may predate a rotation whose cleanup failed, so it can also
    /// take access away from a newer token. The caller must not promise that
    /// access stays the same.
    static func canRestore(proxyRequested: Bool,
                           state: String,
                           error: SecureTokenError?,
                           kind: TokenRecoveryKind) -> Bool {
        allowedAction(proxyRequested: proxyRequested, state: state,
                      error: error, kind: kind) == .restoreLegacy
    }
}

/// Decide whether a later scene change or unlock may retry the token load.
///
/// A locked keychain, a read or write failure, a generator failure, or a token
/// that appeared between the read and the create can clear on a later attempt.
/// Invalid stored data and an unresolved rotation need a person, not a retry.
/// The app has no automatic repair or delete for those states, so a retry
/// during the same launch would repeat the same classification. A later launch
/// reads the stores again.
enum TokenLoadRetry {
    static func canRetry(after error: SecureTokenError?) -> Bool {
        guard let error else { return true }
        switch error {
        case .keychainUnavailable, .keychainReadFailed, .keychainWriteFailed,
             .keychainDeleteFailed, .generatorFailed, .tokenAlreadyPresent,
             .verificationFailed, .legacyNotMigrated, .tokenUnavailableAfterFailure,
             .rotationRecoveryPending:
            return true
        case .invalidStoredToken, .invalidLegacyToken, .invalidNewToken,
             .legacyRemovalFailed, .legacyConflict,
             .recoveryRefused, .invalidRecoveryIntent,
             .recoveryIntentUnavailable:
            return false
        }
    }
}

/// A storage failure. The code is safe for diagnostics. No case holds a token.
enum SecureTokenError: Error, Equatable {
    case invalidLegacyToken
    case invalidStoredToken
    case invalidNewToken
    case keychainUnavailable(Int32)
    case keychainReadFailed(Int32)
    case keychainWriteFailed(Int32)
    case keychainDeleteFailed(Int32)
    case verificationFailed
    case generatorFailed
    case tokenAlreadyPresent
    case tokenUnavailableAfterFailure
    case legacyNotMigrated
    case legacyRemovalFailed
    case legacyConflict
    case recoveryRefused
    case recoveryIntentUnavailable
    case invalidRecoveryIntent
    case rotationRecoveryPending

    /// A stable code for a diagnostics line. It holds no secret.
    var code: String {
        switch self {
        case .invalidLegacyToken: return "invalid_legacy_token"
        case .invalidStoredToken: return "invalid_stored_token"
        case .invalidNewToken: return "invalid_new_token"
        case .keychainUnavailable(let status): return "keychain_unavailable(\(status))"
        case .keychainReadFailed(let status): return "keychain_read_failed(\(status))"
        case .keychainWriteFailed(let status): return "keychain_write_failed(\(status))"
        case .keychainDeleteFailed(let status): return "keychain_delete_failed(\(status))"
        case .verificationFailed: return "verification_failed"
        case .generatorFailed: return "generator_failed"
        case .tokenAlreadyPresent: return "token_already_present"
        case .tokenUnavailableAfterFailure: return "token_unavailable_after_failure"
        case .legacyNotMigrated: return "legacy_not_migrated"
        case .legacyRemovalFailed: return "legacy_removal_failed"
        case .legacyConflict: return "legacy_conflict"
        case .recoveryRefused: return "recovery_refused"
        case .recoveryIntentUnavailable: return "recovery_intent_unavailable"
        case .invalidRecoveryIntent: return "invalid_recovery_intent"
        case .rotationRecoveryPending: return "rotation_recovery_pending"
        }
    }

    /// Plain text for the person using the app. It holds no token or address.
    var message: String {
        switch self {
        case .invalidLegacyToken:
            return "The saved token is invalid and cannot be repaired safely in the app. Contact support before removing saved data."
        case .invalidStoredToken:
            return "The keychain token is invalid and cannot be repaired safely in the app. Contact support before removing saved data."
        case .invalidNewToken:
            return "The app cannot use the new token. Nothing changed."
        case .keychainUnavailable:
            return "The keychain is locked or unavailable. Unlock the device and try again."
        case .keychainReadFailed:
            return "The app cannot read the keychain token."
        case .keychainWriteFailed:
            return "The app cannot save the token in the keychain."
        case .keychainDeleteFailed:
            return "The app cannot remove the token from the keychain."
        case .verificationFailed:
            return "The app could not confirm a saved change. Check the token status before trying again."
        case .generatorFailed:
            return "The app cannot create a secure token."
        case .tokenAlreadyPresent:
            return "A token already exists. The app did not replace it."
        case .tokenUnavailableAfterFailure:
            return "No saved token was found after a storage problem. The app only retries reads during this launch. Reopen the app to retry setup."
        case .legacyNotMigrated:
            return "The app could not move the old saved token. Restart the app to retry. If the problem continues, contact support before removing saved data."
        case .legacyRemovalFailed:
            return "An old token copy remains in app storage. The app cannot remove it safely."
        case .legacyConflict:
            return "Two saved tokens differ. The app cannot prove which one is current, so it kept both and uses neither. Pairing and the proxy stay off. Contact support before removing saved data."
        case .recoveryRefused:
            return "The app cannot prove which saved token is current, or it cannot safely change token storage. It changed nothing. Contact support before removing saved data."
        case .recoveryIntentUnavailable:
            return "The app cannot check for an unfinished token rotation. It did not change the saved token. Contact support before removing saved data."
        case .invalidRecoveryIntent:
            return "The saved token rotation record is damaged. The app cannot tell which saved token is current, so it is not using or replacing either one. Contact support before removing saved data."
        case .rotationRecoveryPending:
            return "A token rotation did not finish. The app kept the saved token state and can retry the read on a later launch or unlock. Pairing and the proxy stay off until a saved token is confirmed."
        }
    }
}

extension SecureTokenError: LocalizedError {
    var errorDescription: String? { message }
}

extension SecureTokenError: CustomStringConvertible {
    var description: String { "SecureTokenError(\(code))" }
}

/// The result of reading the token at startup.
enum TokenLoadResult: Equatable {
    /// The Keychain held a valid token. An old copy is retained.
    case loaded(String)
    /// The keychain was empty. A valid old token was saved and read back.
    /// `legacyRemoved` is false when the old copy is still on disk.
    case migrated(String, legacyRemoved: Bool)
    /// There is no token and no usable old token. The caller may create one.
    case missing
    /// The app must not create or use a token. The old copy stays in place.
    case failed(SecureTokenError)

    var token: String? {
        switch self {
        case .loaded(let token): return token
        case .migrated(let token, _): return token
        case .missing, .failed: return nil
        }
    }
}

/// The result of a write. The distinction between `unchanged` and `uncertain`
/// matters. In `unchanged` the stored token is still the old one. In `uncertain`
/// the stored token may be different, so a caller must not keep using the old
/// token for the proxy.
enum TokenWriteResult: Equatable {
    case saved(String)
    case unchanged(SecureTokenError)
    case uncertain(SecureTokenError)
    /// The new token was confirmed in the keychain, but a different old copy
    /// remains. The app must use neither value until the conflict is resolved.
    case conflict(SecureTokenError)

    var token: String? {
        if case .saved(let token) = self { return token }
        return nil
    }
}

/// A token storage backend. Tests inject a fake. The app uses the keychain.
protocol TokenStorage: AnyObject {
    func readToken() throws -> String?
    func writeToken(_ token: String) throws
    func addToken(_ token: String) throws
    func deleteToken() throws
}

/// The old UserDefaults token. The key must stay `proxyToken`.
protocol LegacyTokenStore: AnyObject {
    func loadToken() -> String?
    /// Remove the old copy and report whether it is gone.
    @discardableResult
    func removeToken() -> Bool
}

/// A stored record of one rotation attempt.
///
/// The record holds SHA-256 digests, not tokens. It is written before the token
/// item changes, so a later read can sometimes tell which of the two expected
/// values is stored. The Keychain has no transaction or compare-and-swap. The
/// intent and the token can survive a crash independently, and another process
/// can change either item. A later read does not prove crash durability.
///
/// A record that is damaged, has an unknown version or stage, has equal old and
/// new digests, or matches neither value blocks token use. The app never
/// guesses and never creates a replacement from an intent.
struct TokenRotationIntent: Equatable {
    static let formatVersion: UInt8 = 1
    static let digestBytes = 32
    static let transactionBytes = 16
    static let encodedBytes = 1 + transactionBytes + 1 + digestBytes + digestBytes

    enum Stage: UInt8, Equatable {
        /// The intent was read back, but the new token is not confirmed.
        case prepared = 1
        /// The new token was read back from the keychain.
        case committed = 2
    }

    let version: UInt8
    let transaction: Data
    let stage: Stage
    let oldDigest: Data
    let newDigest: Data

    private init(version: UInt8, transaction: Data, stage: Stage,
                 oldDigest: Data, newDigest: Data) {
        self.version = version
        self.transaction = transaction
        self.stage = stage
        self.oldDigest = oldDigest
        self.newDigest = newDigest
    }

    /// Build a record for one rotation. Refuses an unknown version, an invalid
    /// token, or a transaction identifier of the wrong size.
    static func make(stage: Stage,
                     oldToken: String,
                     newToken: String,
                     version: UInt8 = formatVersion,
                     transaction: Data = newTransaction()) -> TokenRotationIntent? {
        guard version == formatVersion,
              transaction.count == transactionBytes,
              let oldDigest = digest(oldToken),
              let newDigest = digest(newToken),
              oldDigest != newDigest else { return nil }
        return TokenRotationIntent(version: version, transaction: transaction,
                                   stage: stage, oldDigest: oldDigest,
                                   newDigest: newDigest)
    }

    static func newTransaction() -> Data {
        var bytes = [UInt8](repeating: 0, count: transactionBytes)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        if status == errSecSuccess { return Data(bytes) }
        return withUnsafeBytes(of: UUID().uuid) { Data($0) }
    }

    static func digest(_ token: String) -> Data? {
        guard SecureTokenRules.isValid(token) else { return nil }
        return Data(SHA256.hash(data: Data(token.utf8)))
    }

    func encoded() -> Data {
        var data = Data([version])
        data.append(transaction)
        data.append(stage.rawValue)
        data.append(oldDigest)
        data.append(newDigest)
        return data
    }

    static func decode(_ data: Data) -> TokenRotationIntent? {
        guard data.count == encodedBytes else { return nil }
        let bytes = [UInt8](data)
        guard bytes[0] == formatVersion,
              let stage = Stage(rawValue: bytes[1 + transactionBytes]) else { return nil }
        let transaction = Data(bytes[1..<(1 + transactionBytes)])
        let oldStart = 2 + transactionBytes
        let oldDigest = Data(bytes[oldStart..<(oldStart + digestBytes)])
        let newDigest = Data(bytes[(oldStart + digestBytes)..<(oldStart + 2 * digestBytes)])
        // Equal digests cannot describe a rotation between two values. Treat
        // the record as damaged instead of matching it to either side.
        guard oldDigest != newDigest else { return nil }
        return TokenRotationIntent(version: bytes[0], transaction: transaction,
                                   stage: stage, oldDigest: oldDigest,
                                   newDigest: newDigest)
    }

    func advancing(to stage: Stage) -> TokenRotationIntent {
        TokenRotationIntent(version: version, transaction: transaction,
                            stage: stage, oldDigest: oldDigest,
                            newDigest: newDigest)
    }

    func matchesOld(_ token: String) -> Bool {
        TokenRotationIntent.digest(token) == oldDigest
    }

    func matchesNew(_ token: String) -> Bool {
        TokenRotationIntent.digest(token) == newDigest
    }
}

/// The outcome of resolving a stored rotation intent.
enum TokenRotationRecovery: Equatable {
    case none
    /// The new token was confirmed and the old copy was removed.
    case completed(String)
    /// The new token never became current, so the old token remains.
    case aborted
    /// The app cannot prove the stored state. It changed nothing.
    case blocked(SecureTokenError)
}

/// A separate Keychain item records a rotation that has not finished.
///
/// The item is versioned and holds no token. A record that is short, damaged,
/// or from an unknown version is not a known format, so it blocks instead of
/// guessing. A successful read shows only the bytes present at that moment. It
/// does not prove that the item and the token survived a crash together.
protocol RecoveryIntentStore: AnyObject {
    func read() throws -> Data?
    func write(_ data: Data) throws
    func clear() throws
}

final class KeychainRecoveryIntentStore: RecoveryIntentStore {
    private let api: KeychainAPI
    private let item = KeychainItemID(service: KeychainTokenStorage.defaultService,
                                      account: "proxyToken.recoveryIntent", synchronizable: false)
    private let accessible = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String

    init(api: KeychainAPI = SystemKeychainAPI()) { self.api = api }

    func read() throws -> Data? {
        let result = api.copy(item)
        if result.status == errSecItemNotFound { return nil }
        guard result.status == errSecSuccess else {
            throw SecureTokenError.keychainReadFailed(result.status)
        }
        guard let data = result.data else {
            // A successful query without data is not item-not-found. Treat an
            // unexpected Keychain response as a damaged recovery record.
            throw SecureTokenError.invalidRecoveryIntent
        }
        return data
    }

    /// Add the first intent or update an existing one. A read-back confirms the
    /// exact bytes for this process before the caller changes the token. It is
    /// not a durability proof.
    func write(_ data: Data) throws {
        var status = api.update(item, data: data, accessible: accessible)
        if status == errSecItemNotFound {
            status = api.add(item, data: data, accessible: accessible)
            if status == errSecDuplicateItem {
                status = api.update(item, data: data, accessible: accessible)
            }
        }
        guard status == errSecSuccess else {
            throw writeError(status)
        }
        guard try read() == data else { throw SecureTokenError.verificationFailed }
    }

    func clear() throws {
        let status = api.delete(item)
        if status != errSecSuccess && status != errSecItemNotFound {
            throw deleteError(status)
        }
        guard try read() == nil else { throw SecureTokenError.verificationFailed }
    }

    private func writeError(_ status: Int32) -> SecureTokenError {
        if status == errSecInteractionNotAllowed || status == errSecNotAvailable {
            return .keychainUnavailable(status)
        }
        return .keychainWriteFailed(status)
    }

    private func deleteError(_ status: Int32) -> SecureTokenError {
        if status == errSecInteractionNotAllowed || status == errSecNotAvailable {
            return .keychainUnavailable(status)
        }
        return .keychainDeleteFailed(status)
    }
}

/// Store the old token in UserDefaults until migration is confirmed.
final class UserDefaultsLegacyTokenStore: LegacyTokenStore {
    static let defaultKey = "proxyToken"

    private let defaults: UserDefaults
    private let key: String

    init(defaults: UserDefaults = .standard,
         key: String = UserDefaultsLegacyTokenStore.defaultKey) {
        self.defaults = defaults
        self.key = key
    }

    // A present non-string value is not evidence of first use. Preserve it
    // and return an invalid sentinel so the store refuses to create a token.
    static func decode(_ value: Any?) -> String? {
        guard let value else { return nil }
        return (value as? String) ?? "\u{0}"
    }

    func loadToken() -> String? { Self.decode(defaults.object(forKey: key)) }

    @discardableResult
    func removeToken() -> Bool {
        defaults.removeObject(forKey: key)
        return defaults.object(forKey: key) == nil
    }
}

/// One keychain generic-password item. `synchronizable` stays false, so the
/// token never leaves this device through iCloud Keychain.
struct KeychainItemID: Equatable {
    let service: String
    let account: String
    let synchronizable: Bool
}

/// The Security calls that the keychain store needs. Tests replace this with a
/// fake. No test ever reaches the system keychain.
protocol KeychainAPI: AnyObject {
    func copy(_ item: KeychainItemID) -> (status: Int32, data: Data?)
    func add(_ item: KeychainItemID, data: Data, accessible: String) -> Int32
    func update(_ item: KeychainItemID, data: Data, accessible: String) -> Int32
    func delete(_ item: KeychainItemID) -> Int32
}

/// The real keychain calls.
///
/// The item is a generic password with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`.
/// This class keeps the token available to a background proxy after the first
/// unlock, and it prevents backup migration or iCloud sync. A read before the
/// first unlock fails closed. That is the correct trade for a shared secret.
final class SystemKeychainAPI: KeychainAPI {
    private func baseQuery(_ item: KeychainItemID) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: item.service,
            kSecAttrAccount as String: item.account,
            kSecAttrSynchronizable as String: item.synchronizable,
        ]
    }

    func copy(_ item: KeychainItemID) -> (status: Int32, data: Data?) {
        var query = baseQuery(item)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        return (status, result as? Data)
    }

    func add(_ item: KeychainItemID, data: Data, accessible: String) -> Int32 {
        var attributes = baseQuery(item)
        attributes[kSecValueData as String] = data
        attributes[kSecAttrAccessible as String] = accessible
        return SecItemAdd(attributes as CFDictionary, nil)
    }

    func update(_ item: KeychainItemID, data: Data, accessible: String) -> Int32 {
        let query = baseQuery(item)
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: accessible,
        ]
        return SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
    }

    func delete(_ item: KeychainItemID) -> Int32 {
        SecItemDelete(baseQuery(item) as CFDictionary)
    }
}

/// Store the token as one keychain item and validate it on every read.
final class KeychainTokenStorage: TokenStorage {
    /// The app bundle identifier. The token stays in this app only.
    static let defaultService = "local.hotspotproxy.app"
    /// The keychain account. The old UserDefaults key had the same name.
    static let defaultAccount = "proxyToken"

    private let api: KeychainAPI
    private let item: KeychainItemID
    private let accessible = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String

    init(api: KeychainAPI = SystemKeychainAPI(),
         service: String = KeychainTokenStorage.defaultService,
         account: String = KeychainTokenStorage.defaultAccount) {
        self.api = api
        self.item = KeychainItemID(service: service, account: account, synchronizable: false)
    }

    func readToken() throws -> String? {
        let result = api.copy(item)
        switch result.status {
        case errSecSuccess:
            guard let data = result.data,
                  let text = String(data: data, encoding: .utf8),
                  SecureTokenRules.isValid(text) else {
                throw SecureTokenError.invalidStoredToken
            }
            return text
        case errSecItemNotFound:
            return nil
        default:
            throw readError(result.status)
        }
    }

    func addToken(_ token: String) throws {
        guard SecureTokenRules.isValid(token) else { throw SecureTokenError.invalidNewToken }
        let status = api.add(item, data: Data(token.utf8), accessible: accessible)
        if status == errSecDuplicateItem { throw SecureTokenError.tokenAlreadyPresent }
        guard status == errSecSuccess else { throw writeError(status) }
    }

    func writeToken(_ token: String) throws {
        guard SecureTokenRules.isValid(token) else { throw SecureTokenError.invalidNewToken }
        let status = api.update(item, data: Data(token.utf8), accessible: accessible)
        guard status == errSecSuccess else { throw writeError(status) }
    }

    func deleteToken() throws {
        let status = api.delete(item)
        if status == errSecSuccess || status == errSecItemNotFound { return }
        throw deleteError(status)
    }

    private func isUnavailable(_ status: Int32) -> Bool {
        status == errSecInteractionNotAllowed || status == errSecNotAvailable
    }

    private func readError(_ status: Int32) -> SecureTokenError {
        isUnavailable(status) ? .keychainUnavailable(status) : .keychainReadFailed(status)
    }

    private func writeError(_ status: Int32) -> SecureTokenError {
        isUnavailable(status) ? .keychainUnavailable(status) : .keychainWriteFailed(status)
    }

    private func deleteError(_ status: Int32) -> SecureTokenError {
        isUnavailable(status) ? .keychainUnavailable(status) : .keychainDeleteFailed(status)
    }
}

/// Counters for the Copy diagnostics action. The text holds no token, no part
/// of a token, and no keychain value.
struct SecureTokenDiagnostics: Equatable {
    var loadAttempts = 0
    var migrations = 0
    var createAttempts = 0
    var rotateAttempts = 0
    var recoveryAttempts = 0
    var restoreAttempts = 0
    var confirmedWrites = 0
    var confirmedRotations = 0
    var rotationRecoveries = 0
    var rotationAborts = 0
    var rotationBlocked = 0
    var confirmedRecoveries = 0
    var confirmedRestores = 0
    var failures = 0
    var legacyPresent = false {
        didSet { legacyPresenceObserved = true }
    }
    private(set) var legacyPresenceObserved = false
    var legacyCleanupPending = false
    var legacyConflict = false
    // Nil means the record has not been read, or a read or mutation was
    // inconclusive. It must not be reported as a confirmed absence.
    var recoveryIntentPresent: Bool?
    var lastErrorCode: String?

    func text() -> String {
        var lines: [String] = []
        lines.append("Token storage: Keychain, after first unlock, this device only")
        lines.append("Token storage loads: \(loadAttempts)")
        lines.append("Token migrations: \(migrations)")
        lines.append("Token create attempts: \(createAttempts)")
        lines.append("Token rotation attempts: \(rotateAttempts)")
        lines.append("Token recoveries: \(recoveryAttempts)")
        lines.append("Token restore attempts: \(restoreAttempts)")
        lines.append("Token writes confirmed: \(confirmedWrites)")
        lines.append("Token rotations confirmed: \(confirmedRotations)")
        lines.append("Token rotations recovered: \(rotationRecoveries)")
        lines.append("Token rotations aborted: \(rotationAborts)")
        lines.append("Token rotations blocked: \(rotationBlocked)")
        lines.append("Token recoveries confirmed: \(confirmedRecoveries)")
        lines.append("Token restores confirmed: \(confirmedRestores)")
        lines.append("Token operation failures: \(failures)")
        let legacyPresence = legacyPresenceObserved ? (legacyPresent ? "yes" : "no") : "unknown"
        lines.append("Old token copy present: \(legacyPresence)")
        lines.append("Old token cleanup pending: \(legacyCleanupPending ? "yes" : "no")")
        lines.append("Old token copy conflict: \(legacyConflict ? "yes" : "no")")
        let intentPresence = recoveryIntentPresent.map { $0 ? "yes" : "no" } ?? "unknown"
        lines.append("Rotation recovery record present: \(intentPresence)")
        lines.append("Last token storage error: \(lastErrorCode ?? "none")")
        return lines.joined(separator: "\n")
    }
}

/// Move the proxy token from UserDefaults to the keychain.
///
/// Safety rules:
/// - Read the keychain first. A valid keychain token wins over any old copy.
/// - Do not delete the old copy until a keychain write is read back.
/// - Never create a replacement token after a storage failure, an invalid
///   stored token, or an invalid old token. A caller must stop and report.
/// - A write is confirmed by reading the item back. If a write reports an error
///   but the new token is readable, the write counts as saved. If the read-back
///   cannot confirm the new token, the caller gets `uncertain` and the item
///   stays untouched.
/// - A read-back is not proof that the bytes survive a crash or power loss. It
///   shows only the value that this process can read now.
/// - An invalid Keychain item is not deleted: validation does not establish
///   an identity that can be used for a conditional delete.
// The process lock covers cooperating store transactions only. Keychain and
// UserDefaults have no compare-and-swap here; an external process can change a
// value between an identity check and a destructive operation. The staged
// order narrows the ambiguous window. It does not close it.
final class SecureTokenStore {
    private enum StorageRead {
        case token(String?)
        case failure(SecureTokenError)
    }

    private let storage: TokenStorage
    private let legacy: LegacyTokenStore
    private let generate: () -> String?
    private let recoveryIntent: RecoveryIntentStore?
    // Serializes every store instance in this process. Reentrant mutations are
    // refused: callbacks supplied by a backend must not enter another transaction.
    private static let lock = NSRecursiveLock()
    private static var transactionActive = false
    private func beginTransaction() -> Bool {
        Self.lock.lock()
        if Self.transactionActive {
            Self.lock.unlock()
            return false
        }
        Self.transactionActive = true
        return true
    }
    private func endTransaction() {
        Self.transactionActive = false
        Self.lock.unlock()
    }
    private var state = SecureTokenDiagnostics()

    /// The recovery-intent backend is required. A caller that passes `nil`
    /// cannot prove that no rotation is pending, so load, create, and rotate
    /// fail closed. Production always supplies the Keychain item.
    init(storage: TokenStorage,
         legacy: LegacyTokenStore,
         recoveryIntent: RecoveryIntentStore?,
         generate: @escaping () -> String? = { SecureRandomToken.make() }) {
        self.storage = storage
        self.legacy = legacy
        self.recoveryIntent = recoveryIntent
        self.generate = generate
    }

    /// The production store. The old value is read from UserDefaults under
    /// `proxyToken`, and the new value lives in the system keychain.
    convenience init(legacy: LegacyTokenStore = UserDefaultsLegacyTokenStore(),
                     generate: @escaping () -> String? = { SecureRandomToken.make() }) {
        self.init(storage: KeychainTokenStorage(), legacy: legacy,
                  recoveryIntent: KeychainRecoveryIntentStore(), generate: generate)
    }

    var diagnostics: SecureTokenDiagnostics {
        Self.lock.lock()
        defer { Self.lock.unlock() }
        return state
    }

    /// True only when the store has a recovery-intent backend. A store without
    /// one cannot prove that no rotation is pending, so load, create, and
    /// rotate fail closed. The production store always supplies the Keychain
    /// item.
    var supportsRotation: Bool { recoveryIntent != nil }

    /// No destructive repair of an invalid item is safe without a conditional
    /// delete. An unfinished rotation is different: its intent names the two
    /// expected values, so the recovery paths below can resolve it.
    func recoveryKind() -> TokenRecoveryKind {
        // Neither store supports a conditional destructive repair. The
        // recovery path reads any intent separately; this classification has
        // no action to offer and must not perform an unreported read.
        return .none
    }

    /// Read the token for startup. An unfinished rotation is resolved first.
    /// Migration adds an existing legacy token only when the caller permits a
    /// storage write. A store without an intent backend fails closed because it
    /// cannot rule out a pending rotation.
    func loadOrMigrate(allowMigration: Bool = true) -> TokenLoadResult {
        guard beginTransaction() else { return .failed(.recoveryRefused) }
        defer { endTransaction() }

        if case .blocked(let error) = recoverRotationLocked() {
            return loadFailure(error)
        }

        state.lastErrorCode = nil
        state.loadAttempts += 1
        state.legacyCleanupPending = false
        state.legacyConflict = false
        let legacyValue = legacy.loadToken()
        state.legacyPresent = legacyValue != nil

        switch readStorage() {
        case .failure(let error):
            return loadFailure(error)
        case .token(let stored):
            if let stored {
                guard SecureTokenRules.isValid(stored) else {
                    return loadFailure(.invalidStoredToken)
                }
                // Remove the old copy only when it is the same token or it is
                // empty. A different old copy is a working credential from
                // another build. Keep both and use neither.
                if let legacyValue, legacyValue != stored {
                    state.legacyConflict = true
                    state.legacyCleanupPending = false
                    return loadFailure(.legacyConflict)
                }
                // The legacy copy is retained on load. Rotation removes the
                // observed old copy after its new token is confirmed.
                return .loaded(stored)
            }
        }

        guard let legacyValue else { return .missing }
        guard SecureTokenRules.isValid(legacyValue) else {
            return loadFailure(.invalidLegacyToken)
        }
        // After an uncertain load or recovery, a retry must be read-only.
        guard allowMigration else { return loadFailure(.legacyNotMigrated) }

        var writeError: SecureTokenError?
        do {
            try storage.addToken(legacyValue)
        } catch let error as SecureTokenError {
            writeError = error
        } catch {
            writeError = .keychainWriteFailed(-1)
        }

        if writeError == .tokenAlreadyPresent { return loadFailure(.tokenAlreadyPresent) }
        switch readStorage() {
        case .token(let readBack) where readBack == legacyValue:
            // A confirmed read-back is what gates deletion of the old copy.
            // This also covers a write call that reported an error but did
            // persist the value.
            let currentLegacy = legacy.loadToken()
            guard currentLegacy == legacyValue else {
                state.legacyPresent = currentLegacy != nil
                state.legacyConflict = true
                return loadFailure(.legacyConflict)
            }
            state.migrations += 1
            state.legacyPresent = true
            state.legacyCleanupPending = true
            return .migrated(legacyValue, legacyRemoved: false)
        case .token:
            if let writeError {
                // The write failed and the read-back does not show the old
                // token. Leave the old copy in place.
                return loadFailure(writeError)
            }
            // The current item may belong to another writer. Leave it in place.
            return loadFailure(.verificationFailed)
        case .failure(let readError):
            if let writeError { return loadFailure(writeError) }
            // An unreadable item has unknown ownership. Leave it in place.
            return loadFailure(readError)
        }
    }

    /// Create the first token. Call this only after `loadOrMigrate` returns
    /// `.missing`. It refuses when a token already exists.
    func createInitial() -> TokenWriteResult {
        guard beginTransaction() else { return .unchanged(.recoveryRefused) }
        defer { endTransaction() }

        if case .blocked(let error) = recoverRotationLocked() {
            return writeFailure(error, uncertain: false)
        }

        state.createAttempts += 1
        state.legacyCleanupPending = false
        state.legacyConflict = false
        let legacyValue = legacy.loadToken()
        state.legacyPresent = legacyValue != nil

        switch readStorage() {
        case .failure(let error):
            return writeFailure(error, uncertain: false)
        case .token(let current):
            if let current {
                guard SecureTokenRules.isValid(current) else {
                    return writeFailure(.invalidStoredToken, uncertain: false)
                }
                return writeFailure(.tokenAlreadyPresent, uncertain: false)
            }
        }

        if legacyValue != nil {
            // The old token appeared after the startup read. Do not replace it.
            return writeFailure(.tokenAlreadyPresent, uncertain: false)
        }

        guard let token = generate() else {
            return writeFailure(.generatorFailed, uncertain: false)
        }
        guard SecureTokenRules.isValid(token) else {
            return writeFailure(.invalidNewToken, uncertain: false)
        }
        return commitInitial(token: token)
    }

    /// Rotate the source token through a stored, versioned intent record.
    ///
    /// This is dormant in the app: `TokenLifecycle` refuses rotation unless its
    /// caller opts in after review. The caller must first stop the proxy and
    /// suspend pairing. This method then performs one transaction: write the
    /// intent, write the new token, read it back, confirm the commit stage,
    /// remove only the observed old copy, and clear the intent. A failure after
    /// any write returns `uncertain` unless the store can prove the old token
    /// is still current. An interrupted rotation is resolved by
    /// `loadOrMigrate` after a restart when the stored bytes allow it.
    ///
    /// The staged order narrows the crash window. It does not prove that the
    /// Keychain or UserDefaults survive a crash, and it cannot exclude a
    /// different writer that changes an item between the last read and the
    /// update. A read-back is not a durability or ownership proof. The app
    /// detects a changed value at every read boundary and blocks. It does not
    /// delete a Keychain item it cannot match to its own intent.
    ///
    /// An `unchanged` result does not prove that a caller's cached token is
    /// still current. This method resolves a pending intent before it starts,
    /// and that resolution can change the stored value. A caller that keeps a
    /// cached token after `unchanged` must read storage again first.
    func rotate() -> TokenWriteResult {
        guard beginTransaction() else { return .unchanged(.recoveryRefused) }
        defer { endTransaction() }
        state.rotateAttempts += 1
        guard let recoveryIntent else {
            return writeFailure(.recoveryIntentUnavailable, uncertain: false)
        }

        switch recoverRotationLocked() {
        case .blocked(let error):
            return writeFailure(error, uncertain: true)
        case .none, .aborted, .completed:
            break
        }

        state.legacyCleanupPending = false
        state.legacyConflict = false

        let previous: String
        switch readStorage() {
        case .failure(let error):
            return writeFailure(error, uncertain: false)
        case .token(let current):
            guard let current else {
                return writeFailure(.tokenUnavailableAfterFailure, uncertain: false)
            }
            guard SecureTokenRules.isValid(current) else {
                return writeFailure(.invalidStoredToken, uncertain: false)
            }
            previous = current
        }

        let legacyBaseline = legacy.loadToken()
        state.legacyPresent = legacyBaseline != nil
        if let legacyBaseline, legacyBaseline != previous {
            state.legacyConflict = true
            return conflictFailure(.legacyConflict)
        }

        guard let token = generate() else {
            return writeFailure(.generatorFailed, uncertain: false)
        }
        guard SecureTokenRules.isValid(token), token != previous else {
            return writeFailure(.invalidNewToken, uncertain: false)
        }
        guard let prepared = TokenRotationIntent.make(stage: .prepared,
                                                      oldToken: previous,
                                                      newToken: token) else {
            return writeFailure(.invalidNewToken, uncertain: false)
        }

        state.recoveryIntentPresent = nil
        do {
            try recoveryIntent.write(prepared.encoded())
        } catch let error as SecureTokenError {
            return writeFailure(error, uncertain: true)
        } catch {
            return writeFailure(.keychainWriteFailed(-1), uncertain: true)
        }

        state.recoveryIntentPresent = true
        // Re-read before the single token overwrite. A changed value is not this
        // transaction's item, so leave the intent for recovery. This narrows
        // the window; it cannot exclude a writer that runs after this read.
        switch readStorage() {
        case .token(let current) where current == previous:
            break
        case .failure(let error):
            return writeFailure(error, uncertain: true)
        case .token:
            return writeFailure(.recoveryRefused, uncertain: true)
        }

        var writeError: SecureTokenError?
        do {
            try storage.writeToken(token)
        } catch let error as SecureTokenError {
            writeError = error
        } catch {
            writeError = .keychainWriteFailed(-1)
        }

        let readBack: String?
        switch readStorage() {
        case .token(let current):
            readBack = current
        case .failure(let error):
            return writeFailure(error, uncertain: true)
        }

        guard readBack == token else {
            if readBack == previous {
                // The read-back still shows the old token. The rotation did not
                // land, so clear the intent and keep the old token.
                state.recoveryIntentPresent = nil
                do {
                    try recoveryIntent.clear()
                } catch let error as SecureTokenError {
                    return writeFailure(error, uncertain: true)
                } catch {
                    return writeFailure(.rotationRecoveryPending, uncertain: true)
                }
                state.recoveryIntentPresent = false
                return writeFailure(writeError ?? .verificationFailed, uncertain: false)
            }
            return writeFailure(.verificationFailed, uncertain: true)
        }

        // The new token was read back. Record the commit stage before cleanup.
        // A failure leaves the prepared record, which recovery completes from
        // the new value it can read.
        state.recoveryIntentPresent = nil
        do {
            try recoveryIntent.write(prepared.advancing(to: .committed).encoded())
        } catch let error as SecureTokenError {
            return writeFailure(error, uncertain: true)
        } catch {
            return writeFailure(.keychainWriteFailed(-1), uncertain: true)
        }

        state.recoveryIntentPresent = true
        // Remove only a copy this transaction observed or a duplicate of the
        // new token. A third value is an external writer; keep it and block.
        let currentLegacy = legacy.loadToken()
        state.legacyPresent = currentLegacy != nil
        if let currentLegacy {
            let observed = currentLegacy == legacyBaseline
            guard currentLegacy == token || (observed && currentLegacy == previous) else {
                state.legacyConflict = true
                return conflictFailure(.legacyConflict)
            }
            guard removeLegacyMatching(currentLegacy) else {
                state.legacyCleanupPending = true
                return writeFailure(.rotationRecoveryPending, uncertain: true)
            }
        }

        state.recoveryIntentPresent = nil
        do {
            try recoveryIntent.clear()
        } catch let error as SecureTokenError {
            return writeFailure(error, uncertain: true)
        } catch {
            return writeFailure(.rotationRecoveryPending, uncertain: true)
        }

        state.confirmedWrites += 1
        state.confirmedRotations += 1
        state.recoveryIntentPresent = false
        state.legacyCleanupPending = false
        state.legacyConflict = false
        state.lastErrorCode = nil
        return .saved(token)
    }

    /// Resolve an unfinished rotation now. `loadOrMigrate` calls the same code.
    func recoverRotationIfNeeded() -> TokenRotationRecovery {
        guard beginTransaction() else { return .blocked(.recoveryRefused) }
        defer { endTransaction() }
        return recoverRotationLocked()
    }

    /// Keep invalid items until a conditional repair is available.
    func replaceInvalidToken() -> TokenWriteResult {
        guard beginTransaction() else { return .unchanged(.recoveryRefused) }
        defer { endTransaction() }
        state.recoveryAttempts += 1

        if case .blocked(let error) = recoverRotationLocked() {
            return writeFailure(error, uncertain: false)
        }
        return writeFailure(.recoveryRefused, uncertain: false)
    }

    /// Refuse restoration while the invalid Keychain item cannot be deleted
    /// conditionally. Keep the valid legacy copy for later inspection.
    func restoreValidLegacyToken() -> TokenWriteResult {
        guard beginTransaction() else { return .unchanged(.recoveryRefused) }
        defer { endTransaction() }

        if case .blocked(let error) = recoverRotationLocked() {
            return writeFailure(error, uncertain: false)
        }

        state.restoreAttempts += 1
        state.legacyCleanupPending = false
        state.legacyConflict = false
        let legacyValue = legacy.loadToken()
        state.legacyPresent = legacyValue != nil

        // Reclassify the Keychain item before anything is deleted. A valid
        // item, an empty Keychain, or a transient error is not this action.
        var invalidStored = false
        switch readStorage() {
        case .failure(.invalidStoredToken):
            invalidStored = true
        case .failure(let error):
            return writeFailure(error, uncertain: false)
        case .token(let current):
            if let current {
                guard !SecureTokenRules.isValid(current) else {
                    return writeFailure(.recoveryRefused, uncertain: false)
                }
                invalidStored = true
            } else {
                // The normal load migrates a valid old copy into an empty
                // Keychain. Only an invalid item justifies this action.
                return writeFailure(.recoveryRefused, uncertain: false)
            }
        }

        // The old copy is the credential here. It must still be present and
        // valid on this second read.
        guard invalidStored,
              let legacyValue, !legacyValue.isEmpty,
              SecureTokenRules.isValid(legacyValue) else {
            return writeFailure(.recoveryRefused, uncertain: false)
        }

        // The validation error does not identify the item. Refuse deletion.
        return writeFailure(.recoveryRefused, uncertain: false)
    }

    // MARK: Private

    private func readStorage() -> StorageRead {
        do {
            return .token(try storage.readToken())
        } catch let error as SecureTokenError {
            return .failure(error)
        } catch {
            return .failure(.keychainReadFailed(-1))
        }
    }

    /// Add the first token and read it back. An unconfirmed item is never
    /// changed by cleanup because another writer may have installed it.
    private func commitInitial(token: String) -> TokenWriteResult {
        var writeError: SecureTokenError?
        do {
            try storage.addToken(token)
        } catch let error as SecureTokenError {
            writeError = error
        } catch {
            writeError = .keychainWriteFailed(-1)
        }

        if writeError == .tokenAlreadyPresent {
            return writeFailure(.tokenAlreadyPresent, uncertain: true)
        }
        switch readStorage() {
        case .token(let current) where current == token:
            // Confirm before any old copy is removed and before the caller
            // treats the new token as current.
            state.confirmedWrites += 1
            let legacyValue = legacy.loadToken()
            if let legacyValue, legacyValue != token {
                state.legacyPresent = true
                state.legacyCleanupPending = false
                state.legacyConflict = true
                return conflictFailure(.legacyConflict)
            }
            return .saved(token)
        case .token(let current):
            if let writeError {
                if current == nil {
                    return writeFailure(writeError, uncertain: false)
                }
                return writeFailure(writeError, uncertain: true)
            }
            return writeFailure(.verificationFailed, uncertain: true)
        case .failure(let readError):
            if let writeError {
                // The write may have landed and the confirmation read failed.
                return writeFailure(writeError, uncertain: true)
            }
            return writeFailure(readError, uncertain: true)
        }
    }

    // MARK: Rotation recovery

    /// Resolve one stored intent. Run it inside a store transaction.
    ///
    /// The decision uses only values the intent names. A value that matches
    /// neither digest blocks. A missing or unreadable item blocks. A blocked
    /// recovery changes nothing and keeps the intent for a later read. A later
    /// read can clear a transient condition. It does not prove that the intent
    /// and token survived a crash together.
    private func recoverRotationLocked() -> TokenRotationRecovery {
        state.recoveryIntentPresent = nil
        guard let recoveryIntent else {
            // An absent backend is not evidence that no rotation is pending.
            // A previous build may have left an intent item that this store
            // cannot read. Fail closed instead of treating nil as "none".
            return blockedRecovery(.recoveryIntentUnavailable)
        }
        let data: Data?
        do {
            data = try recoveryIntent.read()
        } catch let error as SecureTokenError {
            return blockedRecovery(error)
        } catch {
            return blockedRecovery(.keychainReadFailed(-1))
        }
        guard let data else {
            state.recoveryIntentPresent = false
            return .none
        }
        state.recoveryIntentPresent = true

        guard let intent = TokenRotationIntent.decode(data) else {
            return blockedRecovery(.invalidRecoveryIntent)
        }

        let current: String
        switch readStorage() {
        case .failure(let error):
            return blockedRecovery(error)
        case .token(let value):
            guard let value else {
                // The intent is present but the token is missing. A later read
                // may find the value that a slow or interrupted write left.
                return blockedRecovery(.rotationRecoveryPending)
            }
            guard SecureTokenRules.isValid(value) else {
                return blockedRecovery(.invalidStoredToken)
            }
            current = value
        }

        if intent.matchesNew(current) {
            return finishCommittedRotation(intent: intent, token: current,
                                           store: recoveryIntent)
        }
        if intent.matchesOld(current) {
            // A prepared intent whose token never changed is an aborted
            // rotation. A committed intent that sees the old token is
            // inconsistent, so it blocks instead of guessing.
            guard intent.stage == .prepared else {
                return blockedRecovery(.recoveryRefused)
            }
            // Do not clear the intent if a different old copy appeared. That
            // copy is not the one this rotation observed, so keeping the intent
            // preserves the only record of the attempted change.
            let legacyValue = legacy.loadToken()
            state.legacyPresent = legacyValue != nil
            if let legacyValue, legacyValue != current {
                state.legacyConflict = true
                state.legacyCleanupPending = false
                return blockedRecovery(.legacyConflict)
            }
            state.recoveryIntentPresent = nil
            do {
                try recoveryIntent.clear()
            } catch let error as SecureTokenError {
                return blockedRecovery(error)
            } catch {
                return blockedRecovery(.rotationRecoveryPending)
            }
            state.rotationAborts += 1
            state.recoveryIntentPresent = false
            state.legacyCleanupPending = false
            state.legacyConflict = false
            return .aborted
        }
        return blockedRecovery(.recoveryRefused)
    }

    /// The new token is current. Remove a stale old copy if it is one the
    /// intent names, then clear the intent. Any third value blocks. A read-back
    /// and removal confirm the value for this process only; they do not prove
    /// crash durability.
    private func finishCommittedRotation(intent: TokenRotationIntent,
                                         token: String,
                                         store: RecoveryIntentStore) -> TokenRotationRecovery {
        let legacyValue = legacy.loadToken()
        state.legacyPresent = legacyValue != nil
        if let legacyValue {
            guard legacyValue == token || intent.matchesOld(legacyValue) else {
                state.legacyConflict = true
                state.legacyCleanupPending = false
                return blockedRecovery(.legacyConflict)
            }
            guard removeLegacyMatching(legacyValue) else {
                state.legacyCleanupPending = true
                return blockedRecovery(.rotationRecoveryPending)
            }
        }
        state.recoveryIntentPresent = nil
        do {
            try store.clear()
        } catch let error as SecureTokenError {
            return blockedRecovery(error)
        } catch {
            return blockedRecovery(.rotationRecoveryPending)
        }
        state.rotationRecoveries += 1
        state.recoveryIntentPresent = false
        state.legacyCleanupPending = false
        state.legacyConflict = false
        state.lastErrorCode = nil
        return .completed(token)
    }

    /// Remove the old copy only when it is still the value this call observed.
    /// UserDefaults has no conditional delete, so a different writer between
    /// the read and the removal is not excluded. The re-read before the call
    /// narrows that window; it does not close it.
    private func removeLegacyMatching(_ expected: String) -> Bool {
        guard legacy.loadToken() == expected else { return false }
        let removed = legacy.removeToken()
        return removed && legacy.loadToken() == nil
    }

    private func blockedRecovery(_ error: SecureTokenError) -> TokenRotationRecovery {
        state.rotationBlocked += 1
        state.lastErrorCode = error.code
        return .blocked(error)
    }

    private func loadFailure(_ error: SecureTokenError) -> TokenLoadResult {
        state.failures += 1
        state.lastErrorCode = error.code
        return .failed(error)
    }

    private func writeFailure(_ error: SecureTokenError,
                              uncertain: Bool) -> TokenWriteResult {
        state.failures += 1
        state.lastErrorCode = error.code
        return uncertain ? .uncertain(error) : .unchanged(error)
    }

    private func conflictFailure(_ error: SecureTokenError) -> TokenWriteResult {
        state.failures += 1
        state.lastErrorCode = error.code
        return .conflict(error)
    }
}

/// Create a new token from the system random source. The app uses 16 random
/// bytes, which is 32 lowercase hex characters.
enum SecureRandomToken {
    static let byteCount = 16

    static func make(byteCount: Int = SecureRandomToken.byteCount) -> String? {
        guard byteCount > 0 else { return nil }
        var bytes = [UInt8](repeating: 0, count: byteCount)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else { return nil }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }
}
