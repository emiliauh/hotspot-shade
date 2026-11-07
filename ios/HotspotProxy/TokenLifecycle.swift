import Foundation

/// The two pairing listener controls that the token lifecycle drives.
/// `ProxyServer` is the production conformance. A test supplies a recorder.
protocol PairingCredentialSink: AnyObject {
    /// Stop the pairing listener and acknowledge suspension before returning.
    func suspendPairing()
    /// Offer pairing with this proxy port and token.
    func configurePairing(port: UInt16, token: String)
}

/// What `TokenLifecycle` needs from the object that owns it. `ProxyModel` is
/// the production host.
protocol TokenLifecycleHost: AnyObject {
    /// True when a start was requested. The proxy keeps its own copy of the
    /// token, so rotation and recovery are refused while it is set.
    var tokenProxyRequested: Bool { get }
    /// The proxy state name from the last snapshot.
    var tokenProxyState: String { get }
    /// The proxy port that pairing hands out.
    var tokenPairingPort: UInt16 { get }
    /// One plain line for Recent activity. It never holds a token.
    func tokenActivity(_ message: String)
    /// The lifecycle changed. The host copies the state it shows.
    func tokenStateDidChange()
}

/// The token state machine of the source device app.
///
/// It owns the in-memory token, the storage flags, and the recovery action. It
/// is the only code that calls the token store's mutating operations and the
/// only code that tells the pairing listener to start or stop. Keeping it free
/// of UIKit lets the hermetic tests drive the same code that the app runs,
/// with fake storage and a recording pairing sink.
///
/// Invariant: the pairing listener runs only while `token` is a valid token
/// that a store read returned and no conflict is open. Every path that clears
/// the token suspends pairing before it returns.
final class TokenLifecycle {
    /// The adoption result of a load at launch or on a retry.
    enum Adoption {
        case ready(String)
        /// No usable token remained, so a new one was created. This replaces
        /// the old credential, so paired target devices must pair again.
        case created(String)
        case failed(SecureTokenError)
    }

    private(set) var token = ""
    /// The last token storage failure. It holds no token. A missing token
    /// blocks a proxy start until a later load succeeds.
    private(set) var storageFailure: String?
    /// True when the keychain holds a token the app can use, or holds a
    /// readable item next to a conflicting old copy. Rotation needs this.
    private(set) var storageReady = false
    /// True when a valid keychain token and a different old UserDefaults token
    /// both exist. The app keeps both and uses neither.
    private(set) var conflict = false
    /// The explicit recovery action that the real stores allow.
    private(set) var recovery: TokenRecoveryKind = .none
    /// The last token storage error. It decides whether a later scene change
    /// may retry the load.
    private(set) var lastError: SecureTokenError?

    private var creationAllowed = true
    private let store: SecureTokenStore
    private let pairing: PairingCredentialSink
    /// The independent-review gate for staged rotation. Production leaves this
    /// false. A test or a future reviewed caller opts in explicitly.
    private let rotationReviewed: Bool
    private weak var host: TokenLifecycleHost?
    /// Serializes launch, retry, start reservation, rotation, recovery, and
    /// pairing updates. The host calls run on the main thread today; the lock
    /// makes the boundary real for tests and for any later caller.
    private let lock = NSRecursiveLock()
    private var operationActive = false
    private var startReserved = false

    init(store: SecureTokenStore,
         pairing: PairingCredentialSink,
         rotationReviewed: Bool = TokenRotationPolicy.reviewed) {
        self.store = store
        self.pairing = pairing
        self.rotationReviewed = rotationReviewed
    }

    /// Set once, right after the host finished its own initialization.
    func attach(host: TokenLifecycleHost) {
        self.host = host
    }

    var diagnostics: SecureTokenDiagnostics { store.diagnostics }

    // MARK: Derived rules

    private var proxyRequested: Bool { host?.tokenProxyRequested ?? false }
    private var proxyState: String { host?.tokenProxyState ?? "" }

    private func locked<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }

    var tokenIsUsable: Bool { SecureTokenRules.isValid(token) }

    /// True only when this lifecycle was built for a reviewed rotation
    /// protocol. The app leaves it false. The UI can use this to explain that
    /// rotation is unavailable in this build rather than blaming the current
    /// token state.
    var rotationReviewApproved: Bool { rotationReviewed }

    /// Rotation needs the independent-review gate, a usable token, a readable
    /// store, the intent item, and a free lifecycle boundary. The button and
    /// the action read the same rule. Production uses the default gate value
    /// `false` until a reviewed protocol proves the staged change safe.
    var canRotate: Bool {
        locked {
            guard !operationActive, !startReserved else { return false }
            guard store.supportsRotation else { return false }
            return TokenRotationPolicy.canRotate(proxyRequested: proxyRequested,
                                                 state: proxyState,
                                                 tokenUsable: tokenIsUsable,
                                                 storageReady: storageReady,
                                                 legacyConflict: conflict,
                                                 lifecycleFree: true,
                                                 rotationReviewed: rotationReviewed)
        }
    }

    /// The explicit recovery action that may run now. A running proxy or a
    /// pending start refuses both actions.
    var recoveryAction: TokenRecoveryKind {
        TokenRecoveryPolicy.allowedAction(proxyRequested: proxyRequested,
                                          state: proxyState,
                                          error: lastError,
                                          kind: recovery)
    }

    var needsReplacement: Bool {
        TokenRecoveryPolicy.isInvalidState(lastError) && recovery == .replaceInvalid
    }

    var needsRestore: Bool {
        TokenRecoveryPolicy.isInvalidState(lastError) && recovery == .restoreLegacy
    }

    var canReplaceInvalid: Bool {
        locked {
            !operationActive && !startReserved && recoveryAction == .replaceInvalid
        }
    }
    var canRestoreLegacy: Bool {
        locked {
            !operationActive && !startReserved && recoveryAction == .restoreLegacy
        }
    }

    // MARK: Start boundary

    /// Reserve the proxy start and return the token to use. Rotation and
    /// recovery are refused until `endStart`. The caller keeps this reservation
    /// across the token copy and the point where its own start request becomes
    /// visible, so a rotation cannot slip between them.
    func beginStart() -> String? {
        locked {
            guard !operationActive, !startReserved else { return nil }
            guard tokenIsUsable, storageReady, !conflict else { return nil }
            startReserved = true
            return token
        }
    }

    func endStart() {
        locked { startReserved = false }
    }

    // MARK: Launch and retry

    /// Read the token at startup. The old UserDefaults copy moves to the
    /// keychain only after a read-back shows the write for this process. A
    /// read-back is not a crash-durability proof. A failure keeps the old copy
    /// and blocks a new credential.
    func loadForLaunch() -> Adoption {
        locked {
            let recoveriesBefore = store.diagnostics.rotationRecoveries
            let abortsBefore = store.diagnostics.rotationAborts
            defer {
                let now = store.diagnostics
                if now.rotationRecoveries > recoveriesBefore {
                    host?.tokenActivity(PlainMessage.tokenRotationRecovered)
                } else if now.rotationAborts > abortsBefore {
                    host?.tokenActivity(PlainMessage.tokenRotationAborted)
                }
            }
            switch store.loadOrMigrate(allowMigration: creationAllowed) {
            case .loaded(let value), .migrated(let value, _):
                return .ready(value)
            case .failed(let error):
                return .failed(error)
            case .missing:
                // A missing retry must not create a replacement after an earlier
                // failure. Preserve the retryable error so a later confirmed load
                // can still recover during this launch.
                guard creationAllowed else { return .failed(.tokenUnavailableAfterFailure) }
                switch store.createInitial() {
                case .saved(let value): return .created(value)
                case .unchanged(let error), .uncertain(let error), .conflict(let error):
                    return .failed(error)
                }
            }
        }
    }

    /// Load at launch and adopt the result.
    func launch() {
        locked {
            let adoption = loadForLaunch()
            if case .created = adoption { host?.tokenActivity(PlainMessage.tokenRecreated) }
            adopt(adoption)
            syncPairing()
            host?.tokenStateDidChange()
        }
    }

    /// A keychain that was locked at launch can work later. Retry when the app
    /// has no usable token, or when a transient write failure left the stored
    /// token unconfirmed. After a failed load, retries are read-only for the
    /// rest of this launch; a missing token does not create a replacement. An
    /// unfinished rotation is resolved by the same
    /// read when the stored bytes allow it. The retry does not prove that a
    /// Keychain or UserDefaults write survived a crash.
    ///
    /// A state that no retry can clear is not re-read during this launch. A
    /// conflict, a damaged rotation record, or a refused recovery needs a
    /// person or a later launch, because the app has no automatic repair or
    /// delete for those states. This gate assumes the saved bytes stay as they
    /// were. An external writer or a restore can change them, and a retry would
    /// then see a different state, but the app does not spend an automatic read
    /// on a state it cannot resolve. Reopen the app to read the stores again.
    /// That is a deliberate stale block, not a proof that the saved bytes stay
    /// unchanged.
    func retryLoadIfNeeded() {
        locked {
            // Activation and the protected-data notification both come through
            // here. Reclassify a stale `.none` first, even when the load itself is
            // not retryable.
            refreshRecoveryKindIfNeeded()
            // A usable token can still need a retry after a transient rotation
            // failure that left the old value in the keychain. The conflict case
            // has no usable token and cannot be resolved in the app.
            guard token.isEmpty || !storageReady else {
                host?.tokenStateDidChange()
                return
            }
            guard TokenLoadRetry.canRetry(after: lastError) else {
                host?.tokenStateDidChange()
                return
            }
            let adoption = loadForLaunch()
            adopt(adoption)
            // Report a new credential if this call ever runs before a failure.
            // After a failure, loadForLaunch permits reads only for this launch.
            if case .created = adoption { host?.tokenActivity(PlainMessage.tokenRecreated) }
            host?.tokenStateDidChange()
        }
    }

    /// Start the pairing listener with the current token, or take it down when
    /// the app has no usable token.
    func syncPairing() {
        locked {
            guard tokenIsUsable && storageReady && !conflict else {
                pairing.suspendPairing()
                return
            }
            let port = host?.tokenPairingPort ?? 0
            pairing.configurePairing(port: port, token: token)
        }
    }

    // MARK: Rotation and recovery

    /// Run the staged rotation. Production does not reach the store because
    /// `canRotate` is false unless the caller opted in after review. Tests opt
    /// in to keep the dormant transaction covered.
    ///
    /// A failure that does not invalidate the saved token still re-reads the
    /// stores before the app keeps the cached value. `store.rotate` resolves an
    /// existing intent before it starts, and that intent may name a token that
    /// changed while the app ran. Another writer can change the token item too.
    /// The listener must never offer a value that a store read no longer
    /// returns.
    func rotate() {
        locked {
            // The proxy keeps its own copy of the token, and a start can be
            // pending before the snapshot shows "Starting". A reserved start
            // and the operation flag cover both.
            guard canRotate else { return }
            operationActive = true
            defer { operationActive = false }
            // Stop the listener before storage changes. A handshake already
            // sent to the network cannot be recalled, but no later frame can
            // read the old credential.
            pairing.suspendPairing()
            switch store.rotate() {
            case .saved(let value):
                token = value
                storageReady = true
                conflict = false
                lastError = nil
                recovery = .none
                storageFailure = warning()
                host?.tokenActivity(PlainMessage.tokenRotated)
                syncPairing()
            case .unchanged(let error):
                // The store read the old token back after the write and
                // cleared its intent. That alone does not prove the cached
                // value is still current. Confirm it with a fresh read before
                // the app keeps offering it.
                if TokenRotationPolicy.invalidatesMemoryToken(error) {
                    reloadAfterRotation()
                } else {
                    confirmCachedTokenAfterRotation(error)
                }
            case .conflict(let error):
                // A different old copy appeared during the write. Keep both
                // and use neither. Rotation is not an in-app resolution while
                // the review gate is closed.
                token = ""
                storageReady = true
                conflict = true
                lastError = error
                storageFailure = error.message
                host?.tokenActivity(error.message)
                syncPairing()
            case .uncertain:
                // The write or cleanup may have changed storage. Only a fresh
                // read, which resolves the intent, can confirm the value to
                // offer. Until then pairing stays down.
                reloadAfterRotation()
            }
            refreshRecoveryKind()
            host?.tokenStateDidChange()
        }
    }

    /// Replace an invalid legacy value after confirmation. The store currently
    /// refuses because it cannot delete an invalid Keychain item
    /// conditionally. A failure leaves no token in memory and resumes no
    /// pairing.
    func replaceInvalid() {
        locked {
            guard canReplaceInvalid else { return }
            operationActive = true
            defer { operationActive = false }
            switch store.replaceInvalidToken() {
            case .saved(let value):
                token = value
                storageReady = true
                conflict = false
                lastError = nil
                recovery = .none
                storageFailure = warning()
                host?.tokenActivity(PlainMessage.tokenReplaced)
                syncPairing()
            case .unchanged(let error), .uncertain(let error):
                failRecovery(error)
            case .conflict(let error):
                // A same-token-only commit reports a conflict when a different
                // old copy arrived during the write. Keep the fail-closed
                // behavior.
                token = ""
                storageReady = true
                conflict = true
                lastError = error
                storageFailure = error.message
                host?.tokenActivity(error.message)
                pairing.suspendPairing()
                refreshRecoveryKind()
            }
            host?.tokenStateDidChange()
        }
    }

    /// Ask the store to restore a valid old token. It currently refuses because
    /// it cannot conditionally delete the invalid Keychain item.
    func restoreLegacy() {
        locked {
            guard canRestoreLegacy else { return }
            operationActive = true
            defer { operationActive = false }
            switch store.restoreValidLegacyToken() {
            case .saved(let value):
                token = value
                storageReady = true
                conflict = false
                lastError = nil
                recovery = .none
                storageFailure = warning()
                host?.tokenActivity(PlainMessage.tokenRestored)
                syncPairing()
            case .unchanged(let error), .uncertain(let error):
                failRecovery(error)
            case .conflict(let error):
                // A different old copy arrived during the write. Keep both and
                // use neither. The app has no in-app resolution for this state.
                token = ""
                storageReady = true
                conflict = true
                lastError = error
                storageFailure = error.message
                host?.tokenActivity(error.message)
                pairing.suspendPairing()
                refreshRecoveryKind()
            }
            host?.tokenStateDidChange()
        }
    }

    // MARK: Private

    /// Keep the cached token after a failed rotation only when a fresh read
    /// still returns it.
    ///
    /// `store.rotate` may resolve an intent that another writer or an
    /// interrupted attempt left before it starts. Completing that intent
    /// changes the stored token to a value the lifecycle never adopted. The
    /// store can then fail without a new token, and `unchanged` would keep the
    /// old cached value. The pairing listener would hand out a credential that
    /// storage no longer holds. Another writer can change the item the same
    /// way with no intent at all.
    ///
    /// The read is a new store transaction. `store.rotate` has returned, so its
    /// transaction lock is released. A nested call from inside a store callback
    /// is refused, so this confirmation cannot run there. The lifecycle lock
    /// stays held across both calls. The store transaction finishes before the
    /// pairing sink runs; suspension occurs before the storage operation.
    private func confirmCachedTokenAfterRotation(_ error: SecureTokenError) {
        let cached = token
        switch store.loadOrMigrate(allowMigration: false) {
        case .loaded(let value), .migrated(let value, _):
            if value == cached {
                // The cached value is still the stored one. Report the
                // rotation failure and keep pairing up with it.
                lastError = error
                storageFailure = error.message
                host?.tokenActivity(error.message)
                syncPairing()
                return
            }
            // Storage holds a different token. It came from a store read, so
            // pairing may offer it. The rotation did not confirm a new token,
            // so report that the stored token was reloaded. That value may
            // differ from the one the listener last offered, so target devices
            // with the earlier token may need to pair again.
            token = value
            storageReady = true
            conflict = false
            lastError = nil
            recovery = .none
            storageFailure = PlainMessage.tokenRotationReloaded
            host?.tokenActivity(PlainMessage.tokenRotationReloaded)
            syncPairing()
        case .failed(let readError):
            // The follow-up read cannot prove the cached value. Drop it and
            // keep pairing down. This also stops an automatic replacement.
            adopt(.failed(readError))
        case .missing:
            adopt(.failed(.tokenUnavailableAfterFailure))
        }
    }

    /// Classify the stores after a failed rotation. Later retries in this
    /// launch must remain read-only, including when no token is found here.
    private func reloadAfterRotation() {
        creationAllowed = false
        token = ""
        storageReady = false
        conflict = false
        let message: String
        switch store.loadOrMigrate(allowMigration: false) {
        case .loaded(let value), .migrated(let value, _):
            token = value
            storageReady = true
            lastError = nil
            message = PlainMessage.tokenRotationReloaded
        case .failed(let error):
            conflict = error == .legacyConflict
            storageReady = conflict
            lastError = error
            message = error.message
        case .missing:
            lastError = .tokenUnavailableAfterFailure
            message = SecureTokenError.tokenUnavailableAfterFailure.message
        }
        storageFailure = message
        host?.tokenActivity(message)
        syncPairing()
    }

    #if TOKEN_LIFECYCLE_TESTING
    func testReloadAfterRotationFailure() {
        reloadAfterRotation()
    }
    #endif

    /// A failed recovery attempt. Re-read the real storage state so a
    /// still-invalid item keeps its recovery action. A load that returns a
    /// usable token may resume pairing; a failed load cannot.
    private func failRecovery(_ error: SecureTokenError) {
        creationAllowed = false
        token = ""
        storageReady = false
        conflict = false
        host?.tokenActivity(error.message)
        pairing.suspendPairing()
        switch store.loadOrMigrate(allowMigration: false) {
        case .loaded(let value), .migrated(let value, _):
            adopt(.ready(value))
        case .failed(let readError):
            adopt(.failed(readError))
        case .missing:
            // A failed recovery does not authorize creating a replacement.
            adopt(.failed(error))
        }
    }

    private func adopt(_ adoption: Adoption) {
        switch adoption {
        case .ready(let value), .created(let value):
            token = value
            storageReady = true
            conflict = false
            lastError = nil
            recovery = .none
            storageFailure = warning()
            // A later load can succeed after a locked keychain at launch.
            // Pairing must come back with the token the app can use.
            syncPairing()
        case .failed(let error):
            creationAllowed = false
            let message = error.message
            let changed = storageFailure != message
            token = ""
            conflict = error == .legacyConflict
            // Both copies are retained; the app cannot resolve the conflict.
            storageReady = conflict
            lastError = error
            storageFailure = message
            // Never leave a pairing listener that can hand out a token the
            // app cannot use.
            pairing.suspendPairing()
            if changed { host?.tokenActivity(message) }
            refreshRecoveryKind()
        }
    }

    /// Ask which recovery action is available. The current store offers none.
    private func refreshRecoveryKind() {
        recovery = tokenIsUsable ? .none : store.recoveryKind()
    }

    /// Reapply the refresh policy. The current store does not expose an
    /// in-app repair action or read the stores during classification.
    private func refreshRecoveryKindIfNeeded() {
        guard TokenRecoveryPolicy.needsRefresh(error: lastError, kind: recovery) else { return }
        refreshRecoveryKind()
    }

    /// A token that works but still has an old copy in UserDefaults. A later
    /// load may report a conflict if the old copy differs from the token.
    private func warning() -> String? {
        store.diagnostics.legacyCleanupPending
            ? SecureTokenError.legacyRemovalFailed.message
            : nil
    }
}
