import Foundation
import CoreFoundation
import Security

// Starting the tunnel changes this Mac's routes as root. The signed app alone
// is not a user authorization: any process running as this account can run the
// app. The app therefore asks Authorization Services for one administrator
// authorization per tunnel start, and the helper refuses to write the engine's
// one-time tunnel grant until it has checked that authorization. Starting the
// engine itself creates no route and no tunnel device, so it is not gated by
// this right.
//
// The right is not a built-in signed right. A root installer must write and
// verify its definition explicitly. A local process may be able to create the
// right before installation, depending on authd policy. The helper never assumes
// that a missing or pre-existing right falls to a safe
// default: it reads the configured definition, requires a rule that authenticates
// an administrator, and fails closed when the right is absent, delegated, or
// allows root or shared reuse. The same right and the same check run before
// every tunnel authorization. Starting the engine is not gated by the right,
// so a stale or missing right does not hide the dashboard.
//
// The app creates the authorization in its own GUI session, so the system
// prompts in the session that a person can see. It sends the opaque external
// form to the helper in the authorization request. The helper turns the form
// back into an authorization session and checks the one fixed right. No request
// can name another right, and there is no flag or fallback that skips the
// check.
public enum HelperStartAuthorizationPolicy {
    // A custom right deliberately. The stock `system.privilege.admin` rule has
    // `allow-root` set, so a root helper would satisfy it without a person.
    // The installer must add this right; see Helper/README.md.
    public static let startRight = "dev.hotspotshade.tunnel.start"

    // Shown in the authorization dialog. Fixed text, never from a request.
    public static let prompt =
        "HotspotShade needs administrator authorization to start a tunnel that changes this Mac's network routes."

    // Prompt in the app's session and extend the rights for this one start.
    public static let requestFlags: AuthorizationFlags = [.interactionAllowed, .extendRights]

    // The helper checks an existing grant only. It never prompts and never
    // extends rights on its own authority.
    public static let verifyFlags: AuthorizationFlags = []

    // AuthorizationExternalForm is a fixed 32-byte record. Anything else is
    // rejected before Security sees it.
    public static var externalFormByteCount: Int { MemoryLayout<AuthorizationExternalForm>.size }

    // The installed right caches one granted authorization for a bounded
    // window. Authorization Services treats `timeout=0` as no cached
    // credential at all, so the helper's check a few milliseconds after the
    // person approves fails with a denial even though the prompt succeeded.
    // A positive value lets the check read the grant, and the ceiling keeps
    // the credential from staying reusable for a long time. The reviewed
    // source value is 30 seconds; the helper accepts the whole bounded range
    // so a reviewed value inside it does not need a helper change.
    public static let startRightTimeoutSeconds = 30
    public static let startRightTimeoutBounds: ClosedRange<Int64> = 1...60

    public static func isStartRightTimeout(_ seconds: Int) -> Bool {
        startRightTimeoutBounds.contains(Int64(seconds))
    }

    // The prompt reports a person's cancel as its own status. Keep that
    // outcome distinct so the app can say the authorization was cancelled
    // rather than claim the account is not permitted.
    public static func trustError(forAuthorizationStatus status: OSStatus) -> HelperTrustError {
        status == errAuthorizationCanceled ? .cancelled : .notAuthorized
    }
}

// One audited caller session. The session id is read from the kernel audit
// token. It must be positive, and the helper records it as evidence. It is not
// a value that the request can choose; the authorization check never trusts a
// session named by the caller. The external authorization form itself does not
// expose the session that created it, so the helper cannot prove the form came
// from this exact session. It proves the caller is the signed app in a login
// session and that the form carries the fixed right.
public struct HelperPeerSession: Equatable, Sendable {
    public let sessionIdentifier: Int32
    public let processIdentifier: Int32

    public init?(sessionIdentifier: Int32, processIdentifier: Int32) {
        guard sessionIdentifier > 0, processIdentifier > 0 else { return nil }
        self.sessionIdentifier = sessionIdentifier
        self.processIdentifier = processIdentifier
    }
}

// The app side of one start authorization. The form stays valid while the
// lease is held. The app releases the lease after the start reply arrives, so
// the helper can check the form during the whole request.
public protocol HelperStartAuthorizationLease: AnyObject {
    var externalForm: Data { get }
    func release()
}

public protocol HelperStartAuthorizationProviding: Sendable {
    func beginStartAuthorization() throws -> HelperStartAuthorizationLease
}

// Seam for the app tests. The production value uses Authorization Services.
public protocol HelperAuthorizationFormCreating: Sendable {
    func createStartAuthorization(rightName: String, prompt: String) throws -> HelperStartAuthorizationLease
}

// Seam for the helper tests. The production value uses Authorization Services.
public protocol HelperAuthorizationFormChecking: Sendable {
    func checkStartAuthorization(form: [UInt8], rightName: String) throws
}

public final class AuthorizationServicesStartAuthorization: HelperStartAuthorizationProviding, @unchecked Sendable {
    private let creator: HelperAuthorizationFormCreating

    public init(creator: HelperAuthorizationFormCreating = SecurityAuthorizationFormCreator()) {
        self.creator = creator
    }

    public func beginStartAuthorization() throws -> HelperStartAuthorizationLease {
        let lease = try creator.createStartAuthorization(
            rightName: HelperStartAuthorizationPolicy.startRight,
            prompt: HelperStartAuthorizationPolicy.prompt
        )
        // A creator that returns a malformed form must not reach the helper.
        guard lease.externalForm.count == HelperStartAuthorizationPolicy.externalFormByteCount else {
            lease.release()
            throw HelperTrustError.notAuthorized
        }
        return lease
    }
}

public final class AuthorizationServicesStartAuthorizationVerifier: @unchecked Sendable {
    private let checker: HelperAuthorizationFormChecking

    public init(checker: HelperAuthorizationFormChecking = SecurityAuthorizationFormChecker()) {
        self.checker = checker
    }

    public func verify(_ form: Data) throws {
        guard form.count == HelperStartAuthorizationPolicy.externalFormByteCount else {
            throw HelperTrustError.notAuthorized
        }
        let bytes = [UInt8](form)
        do {
            try checker.checkStartAuthorization(
                form: bytes,
                rightName: HelperStartAuthorizationPolicy.startRight
            )
        } catch {
            throw HelperTrustError.notAuthorized
        }
    }
}

// The real app-side prompt. A person authorizes one start. The rights are
// destroyed on release, so the next start asks again and no credential is left
// for another program to reuse.
public struct SecurityAuthorizationFormCreator: HelperAuthorizationFormCreating {
    public init() {}

    public func createStartAuthorization(
        rightName: String,
        prompt: String
    ) throws -> HelperStartAuthorizationLease {
        var reference: AuthorizationRef?
        guard AuthorizationCreate(nil, nil, [], &reference) == errAuthorizationSuccess,
              let reference
        else {
            throw HelperTrustError.notAuthorized
        }

        let status: OSStatus = rightName.withCString { name -> OSStatus in
            prompt.withCString { promptPointer -> OSStatus in
                kAuthorizationEnvironmentPrompt.withCString { promptName -> OSStatus in
                    var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
                    var promptItem = AuthorizationItem(
                        name: promptName,
                        valueLength: strlen(promptPointer),
                        value: UnsafeMutableRawPointer(mutating: promptPointer),
                        flags: 0
                    )
                    return withUnsafeMutablePointer(to: &item) { itemPointer -> OSStatus in
                        withUnsafeMutablePointer(to: &promptItem) { promptItemPointer -> OSStatus in
                            var rights = AuthorizationRights(count: 1, items: itemPointer)
                            var environment = AuthorizationEnvironment(count: 1, items: promptItemPointer)
                            return AuthorizationCopyRights(
                                reference,
                                &rights,
                                &environment,
                                HelperStartAuthorizationPolicy.requestFlags,
                                nil
                            )
                        }
                    }
                }
            }
        }
        guard status == errAuthorizationSuccess else {
            AuthorizationFree(reference, [.destroyRights])
            throw HelperStartAuthorizationPolicy.trustError(forAuthorizationStatus: status)
        }

        var form = AuthorizationExternalForm()
        guard AuthorizationMakeExternalForm(reference, &form) == errAuthorizationSuccess else {
            AuthorizationFree(reference, [.destroyRights])
            throw HelperTrustError.notAuthorized
        }
        let bytes = withUnsafeBytes(of: &form) { Data($0) }
        guard bytes.count == HelperStartAuthorizationPolicy.externalFormByteCount else {
            AuthorizationFree(reference, [.destroyRights])
            throw HelperTrustError.notAuthorized
        }
        return SecurityAuthorizationLease(reference: reference, form: bytes)
    }
}

private final class SecurityAuthorizationLease: HelperStartAuthorizationLease, @unchecked Sendable {
    private let reference: AuthorizationRef
    private let lock = NSLock()
    private var released = false
    public let externalForm: Data

    init(reference: AuthorizationRef, form: Data) {
        self.reference = reference
        self.externalForm = form
    }

    func release() {
        lock.lock()
        if released {
            lock.unlock()
            return
        }
        released = true
        lock.unlock()
        // Destroy the rights so the next start asks again and no cached
        // credential remains for this right.
        AuthorizationFree(reference, [.destroyRights])
    }

    deinit { release() }
}

// The real helper-side check. It checks one fixed right on an authorization
// session created from the app's form. It never prompts and never asks for more
// rights.
public struct SecurityAuthorizationFormChecker: HelperAuthorizationFormChecking {
    public init() {}

    public func checkStartAuthorization(form: [UInt8], rightName: String) throws {
        guard form.count == HelperStartAuthorizationPolicy.externalFormByteCount else {
            throw HelperTrustError.notAuthorized
        }
        var externalForm = AuthorizationExternalForm()
        withUnsafeMutableBytes(of: &externalForm) { destination in
            destination.copyBytes(from: form)
        }
        var reference: AuthorizationRef?
        guard AuthorizationCreateFromExternalForm(&externalForm, &reference) == errAuthorizationSuccess,
              let reference
        else {
            throw HelperTrustError.notAuthorized
        }
        defer { AuthorizationFree(reference, [.destroyRights]) }

        let status: OSStatus = rightName.withCString { name -> OSStatus in
            var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
            return withUnsafeMutablePointer(to: &item) { itemPointer -> OSStatus in
                var rights = AuthorizationRights(count: 1, items: itemPointer)
                return AuthorizationCopyRights(
                    reference,
                    &rights,
                    nil,
                    HelperStartAuthorizationPolicy.verifyFlags,
                    nil
                )
            }
        }
        guard status == errAuthorizationSuccess else {
            throw HelperTrustError.notAuthorized
        }
    }
}

// The helper reads the installed right definition before it trusts a form. A
// missing definition is not safe: on some systems an unknown right is denied,
// but that is not a contract to rely on. The accepted shape is the one in
// `Helper/dev.hotspotshade.tunnel.start.plist`: an administrator prompt with
// `class=user`, `group=admin`, `authenticate-user=true`, and the explicit
// values `shared=false`, `allow-root=false`, and a positive `timeout` in
// `startRightTimeoutBounds`. A missing key is
// not a default: it is a refusal, because an omitted `shared` or `allow-root`
// is not the same promise as an explicit false, and an omitted `timeout` is
// not the reviewed window. The optional `comment` is the
// only other installed key.
//
// authd writes metadata back into a stored definition. A read-only
// `security authorizationdb read` adds `created`, `modified`, `session-owner`,
// `tries`, and `version` even when the source plist did not contain them. A
// right installed by another application can also hold `identifier` and
// `requirement`, which record that application's code signing identity.
// The helper tolerates these keys only with a fixed type and value range; it
// never treats them as a substitute for the required authorization settings.
// Their effect on later changes to the right has not been verified live.
//
// `session-owner` and `tries` are real authorization fields, not comments.
// The installed class is a plain user right, so `session-owner` must be absent
// or the authd default `false`. `tries` must be absent or a positive integer no
// greater than the authd default of 10000, so a stored value cannot weaken the
// attempt budget.
//
// The canned `authenticate-admin` class and every delegated, rule, k-of-n,
// entitlement, password, prompt, or mechanism definition are refused because
// this helper does not validate their semantics. An unknown key is refused for
// the same reason.
public enum HelperStartRightValidator {
    private static let installedKeys: Set<String> = [
        "class",
        "group",
        "authenticate-user",
        "shared",
        "allow-root",
        "timeout",
        "comment",
    ]

    // Fields authd adds to the stored definition. They are not install-time
    // settings. None of them grants access; `session-owner` and `tries` are
    // real authorization fields and are constrained below.
    private static let authdMetadataKeys: Set<String> = [
        "created",
        "modified",
        "version",
        "identifier",
        "requirement",
        "session-owner",
        "tries",
    ]

    public static func isSafe(_ definition: [String: Any]) -> Bool {
        // An unknown key can carry a semantics this validator does not model,
        // such as a delegate rule or an extra authentication mechanism.
        guard Set(definition.keys).isSubset(of: installedKeys.union(authdMetadataKeys)) else {
            return false
        }
        guard string(definition["class"]) == "user",
              string(definition["group"]) == "admin",
              boolean(definition["authenticate-user"]) == true,
              boolean(definition["shared"]) == false,
              boolean(definition["allow-root"]) == false,
              isInteger(
                  definition["timeout"],
                  in: HelperStartAuthorizationPolicy.startRightTimeoutBounds
              )
        else {
            return false
        }
        if let comment = definition["comment"], !(comment is String) {
            return false
        }

        // Metadata from authd. A missing key is the source-plist state. A
        // present key must have the type and range that authd uses.
        if let created = definition["created"], !isTimestamp(created) {
            return false
        }
        if let modified = definition["modified"], !isTimestamp(modified) {
            return false
        }
        if let version = definition["version"],
           !isInteger(version, in: 0...1_000_000) {
            return false
        }
        if let identifier = definition["identifier"],
           !isMetadataString(identifier, maximumBytes: 1024, allowsNewlines: false) {
            return false
        }
        if let requirement = definition["requirement"],
           !isMetadataString(requirement, maximumBytes: 4096, allowsNewlines: true) {
            return false
        }

        // authd normalizes these authorization fields. A present value must
        // keep the installed promise rather than broadening it.
        if let sessionOwner = definition["session-owner"], boolean(sessionOwner) != false {
            return false
        }
        if let tries = definition["tries"], !isInteger(tries, in: 1...10_000) {
            return false
        }
        return true
    }

    private static func string(_ value: Any?) -> String? {
        if let value = value as? String { return value }
        if let value = value as? NSString { return value as String }
        return nil
    }

    // The stored booleans must be real CFBoolean values. A number or a string
    // is a different type and is refused, even when it might bridge to Bool.
    private static func boolean(_ value: Any?) -> Bool? {
        guard let value else { return nil }
        guard CFGetTypeID(value as CFTypeRef) == CFBooleanGetTypeID() else {
            return nil
        }
        return value as? Bool
    }

    private static func number(_ value: Any?) -> NSNumber? {
        guard let value else { return nil }
        guard CFGetTypeID(value as CFTypeRef) == CFNumberGetTypeID() else {
            return nil
        }
        return value as? NSNumber
    }

    // `created` and `modified` are audit timestamps. authd stores a real value
    // or a zero default. A negative, non-finite, or non-numeric value is not a
    // timestamp this validator accepts.
    private static func isTimestamp(_ value: Any?) -> Bool {
        guard let number = number(value) else { return false }
        let timestamp = number.doubleValue
        return timestamp.isFinite && timestamp >= 0
    }

    // An integer field must stay an integer. A floating-point value is refused
    // even when its fractional part is zero, because authd writes integers for
    // `timeout`, `tries`, and `version`. `timeout` must land inside the
    // reviewed positive window. Zero is refused because Authorization Services
    // then stores no credential for the helper check that follows the prompt.
    private static func isInteger(_ value: Any?, in range: ClosedRange<Int64>) -> Bool {
        guard let number = number(value) else { return false }
        switch CFNumberGetType(number) {
        case .float32Type, .float64Type, .cgFloatType:
            return false
        default:
            break
        }
        return range.contains(number.int64Value)
    }

    // `identifier` and `requirement` are text recorded by authd. They
    // must be non-empty printable ASCII. A requirement may contain the line
    // breaks that a code signing requirement uses. Binary data, control
    // characters, and an oversized value are refused.
    private static func isMetadataString(
        _ value: Any?,
        maximumBytes: Int,
        allowsNewlines: Bool
    ) -> Bool {
        guard let value = value as? String else { return false }
        let bytes = Array(value.utf8)
        guard !bytes.isEmpty, bytes.count <= maximumBytes else { return false }
        for byte in bytes {
            if byte == 0x09 { continue }
            if allowsNewlines, byte == 0x0a || byte == 0x0d { continue }
            guard byte >= 0x20, byte <= 0x7e else { return false }
        }
        return true
    }
}

public protocol HelperStartRightConfigurationChecking: Sendable {
    func checkStartRight(_ name: String) throws
}

// Read the right definition from the authorization policy database. A missing
// right, an unreadable database, or a definition weaker than the policy is a
// refusal. This check runs at helper startup and before every launch.
public struct SecurityStartRightConfigurationChecker: HelperStartRightConfigurationChecking {
    public init() {}

    public func checkStartRight(_ name: String) throws {
        var raw: CFDictionary?
        let status = AuthorizationRightGet(name, &raw)
        guard status == errAuthorizationSuccess,
              let raw,
              let definition = (raw as NSDictionary) as? [String: Any],
              HelperStartRightValidator.isSafe(definition)
        else {
            throw HelperTrustError.startRightNotConfigured
        }
    }
}

// One gate for the helper. Starting the engine creates no route and no
// tunnel device, so it does not ask for an administrator authorization. The
// dashboard, pairing, status, and settings must work before any privileged
// network work. The administrator authorization is checked at the tunnel start
// instead: the app sends one external form, the helper verifies the fixed
// right, and only then writes the one-time grant that the running engine
// consumes before it changes a route.
public final class HelperStartGate: @unchecked Sendable {
    private let verifier: AuthorizationServicesStartAuthorizationVerifier
    private let rightChecker: HelperStartRightConfigurationChecking
    private let controller: HelperSessionController

    public init(
        verifier: AuthorizationServicesStartAuthorizationVerifier,
        rightChecker: HelperStartRightConfigurationChecking,
        controller: HelperSessionController
    ) {
        self.verifier = verifier
        self.rightChecker = rightChecker
        self.controller = controller
    }

    // Start the engine for the signed app. The controller's preflight still
    // refuses a running session, a cleanup block, or an install transition.
    public func startEngine(connection: UUID) -> HelperSessionStartResult {
        startEngine(connection: connection, credentials: nil)
    }

    public func startEngine(connection: UUID, credentials: Int32?) -> HelperSessionStartResult {
        if let refusal = controller.preflightStart(connection: connection) {
            return refusal
        }
        return controller.start(connection: connection, credentials: credentials)
    }

    // Verify one administrator authorization for the tunnel start and write
    // the grant. The fixed right is read before the form, so a missing or
    // weaker right refuses without trusting the caller's form.
    public func authorize(connection: UUID, form: Data) -> HelperTunnelAuthorizationResult {
        do {
            try rightChecker.checkStartRight(HelperStartAuthorizationPolicy.startRight)
        } catch {
            return .notConfigured
        }
        do {
            try verifier.verify(form)
        } catch {
            return .notAuthorized
        }
        return controller.authorizeStart(connection: connection)
    }
}
