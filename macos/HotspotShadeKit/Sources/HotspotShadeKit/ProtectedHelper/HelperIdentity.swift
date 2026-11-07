import Foundation
import Security
#if os(macOS)
import Darwin
#endif

// The signing facts that the helper and the app use to decide whether to
// trust one another. A Developer ID signature has a team identifier and is not
// ad-hoc. An ad-hoc signature has neither a team identifier nor a stable
// identity, so it never satisfies a protected helper policy.
public struct HelperSigningInfo: Equatable, Sendable {
    public let identifier: String
    public let teamIdentifier: String?
    public let isAdHoc: Bool
    /// True when the code signature carries the hardened runtime flag. A
    /// development signature often lacks it, and a debugger can attach to such
    /// a process.
    public let hasHardenedRuntime: Bool
    /// True when the signature carries `com.apple.security.get-task-allow`. A
    /// development build carries it, so the helper must not trust that build.
    public let allowsDebugging: Bool
    /// `com.apple.security.cs.disable-library-validation` lets a process load
    /// code that the team did not sign. A root helper must not allow it.
    public let disablesLibraryValidation: Bool
    /// `com.apple.security.cs.allow-dyld-environment-variables` lets the
    /// environment inject a dynamic library into a hardened process. A root
    /// helper must not allow it.
    public let allowsDyldEnvironmentVariables: Bool

    public init(
        identifier: String,
        teamIdentifier: String?,
        isAdHoc: Bool,
        hasHardenedRuntime: Bool = false,
        allowsDebugging: Bool = false,
        disablesLibraryValidation: Bool = false,
        allowsDyldEnvironmentVariables: Bool = false
    ) {
        self.identifier = identifier
        self.teamIdentifier = teamIdentifier
        self.isAdHoc = isAdHoc
        self.hasHardenedRuntime = hasHardenedRuntime
        self.allowsDebugging = allowsDebugging
        self.disablesLibraryValidation = disablesLibraryValidation
        self.allowsDyldEnvironmentVariables = allowsDyldEnvironmentVariables
    }

    /// A Developer ID identity has a team identifier and is not ad-hoc.
    public var hasDeveloperIdentity: Bool {
        guard !isAdHoc, let teamIdentifier else { return false }
        return !teamIdentifier.isEmpty && !identifier.isEmpty
    }

    /// The full policy identity: Developer ID, hardened runtime, and no
    /// entitlement that weakens the runtime or allows a debugger.
    public var isProtectedIdentity: Bool {
        hasDeveloperIdentity
            && hasHardenedRuntime
            && !allowsDebugging
            && !disablesLibraryValidation
            && !allowsDyldEnvironmentVariables
    }
}

// A fixed-size audit token from the kernel. The helper never accepts a caller
// identity that the caller supplies in a message. The audit session names the
// login session that must see an authorization prompt. A token with no session
// cannot authorize a start.
//
// The token is opaque. The public header says only the BSM accessors may read
// it. This type resolves `audit_token_to_asid` and `audit_token_to_pid` from
// libbsm and requires the documented fixed word positions to agree with those
// accessors. If either accessor is missing, or the two disagree, the token is
// rejected. A changed kernel representation therefore fails closed instead of
// comparing the wrong field.
public struct HelperAuditToken: Equatable, Sendable {
    public static let byteCount = 32
    // The kernel puts the audit session id in word 6 and the process id in
    // word 5. These are the values that audit_token_to_asid() and
    // audit_token_to_pid() return.
    public static let sessionIdentifierWord = 6
    public static let processIdentifierWord = 5
    public let bytes: [UInt8]
    public let processIdentifier: Int32
    public let sessionIdentifier: Int32

    public init?(bytes: [UInt8], processIdentifier: Int32, sessionIdentifier: Int32 = 0) {
        guard bytes.count == Self.byteCount, processIdentifier > 0 else { return nil }
        self.bytes = bytes
        self.processIdentifier = processIdentifier
        self.sessionIdentifier = sessionIdentifier
    }

    #if os(macOS)
    public init?(auditToken token: audit_token_t, processIdentifier: Int32) {
        var value = token
        let bytes = withUnsafeBytes(of: &value) { Array($0) }
        let words = withUnsafeBytes(of: &value) { buffer in
            Array(buffer.bindMemory(to: UInt32.self))
        }
        guard processIdentifier > 0,
              words.count == 8,
              let parsedSession = Self.sessionIdentifier(fromWords: words),
              let parsedProcess = Self.processIdentifier(fromWords: words),
              parsedProcess == processIdentifier,
              let session = BSMAuditTokenAccessors.sessionIdentifier(of: value),
              let process = BSMAuditTokenAccessors.processIdentifier(of: value),
              session == parsedSession,
              process == parsedProcess
        else {
            return nil
        }
        self.init(
            bytes: bytes,
            processIdentifier: processIdentifier,
            sessionIdentifier: session
        )
    }

    // The fixed word positions, exposed for the hermetic tests. A caller must
    // still use the audit token initializer, which also requires the BSM
    // accessors to agree.
    public static func sessionIdentifier(fromWords words: [UInt32]) -> Int32? {
        guard words.count == 8 else { return nil }
        let value = Int32(bitPattern: words[sessionIdentifierWord])
        return value > 0 ? value : nil
    }

    public static func processIdentifier(fromWords words: [UInt32]) -> Int32? {
        guard words.count == 8 else { return nil }
        let value = Int32(bitPattern: words[processIdentifierWord])
        return value > 0 ? value : nil
    }
    #endif
}

#if os(macOS)
// libbsm owns the only supported way to read an audit token. The macOS SDK
// declares these functions, but libSystem does not export them. Load libbsm
// once and resolve the two accessors. A missing library or symbol is a closed
// result, never a fallback to a fixed word position.
private enum BSMAuditTokenAccessors {
    private typealias SessionGetter = @convention(c) (audit_token_t) -> Int32
    private typealias ProcessGetter = @convention(c) (audit_token_t) -> Int32

    private static let handle: UnsafeMutableRawPointer? = {
        dlopen("/usr/lib/libbsm.0.dylib", RTLD_NOW)
    }()

    private static func resolve<T>(_ name: String, as type: T.Type) -> T? {
        let symbol = handle.flatMap { dlsym($0, name) }
            ?? dlsym(UnsafeMutableRawPointer(bitPattern: -2), name)
        guard let symbol else { return nil }
        return unsafeBitCast(symbol, to: T.self)
    }

    private static let session: SessionGetter? = resolve("audit_token_to_asid", as: SessionGetter.self)
    private static let process: ProcessGetter? = resolve("audit_token_to_pid", as: ProcessGetter.self)

    static func sessionIdentifier(of token: audit_token_t) -> Int32? {
        guard let session else { return nil }
        let value = session(token)
        return value > 0 ? value : nil
    }

    static func processIdentifier(of token: audit_token_t) -> Int32? {
        guard let process else { return nil }
        let value = process(token)
        return value > 0 ? value : nil
    }
}
#endif

public enum HelperTrustError: Error, Equatable {
    case missingSigningIdentity
    case invalidSigningPolicy
    case signatureUnavailable
    case signatureRejected
    case notInstalledPath
    case pathIsNotCanonical
    case executableNotRegularFile
    case executableNotOwnedByRoot
    case executableWritable
    case unsafeParentDirectory
    case unsafeInstallRoot
    case launchDaemonPlistMissing
    case launchDaemonPlistUnsafe
    case launchDaemonPlistMismatch
    case bundleOutsideApplications
    case helperOutsideBundle
    case bundleNotOwnedByRoot
    case bundleWritable
    case signedAppMissing
    case callerRejected
    case helperBusy
    case cleanupBlocked
    case requiresRoot
    case engineStartFailed
    case engineStopTimedOut
    // A stop request reached the helper, but the reply cannot prove that this
    // app's engine session stopped. Another connection owns it, or a stop is
    // still in flight. The app keeps its uncertainty and retries the stop.
    case stopNotConfirmed
    case notConnected
    case helperTimeout
    case helperUnavailable
    case responseRejected
    case aclUnavailable
    case cancelled
    case notAuthorized
    case authorizationBusy
    case startRightNotConfigured
    case handshakeRequired
    case engineExited
    case engineExitUnclean
    case startExclusionBusy
    case startExclusionUnavailable
    // The engine is not running, so there is no tunnel to authorize. This is
    // not a failed administrator prompt.
    case tunnelNotRunning
    // The helper verified the administrator authorization but could not write
    // the one-time grant that the engine requires before it changes a route.
    case grantFailed
    // The helper stopped the engine because the administrator authorization
    // was not completed within the deadline. The helper records a clean stop.
    case authorizationTimedOut

    public var errorDescription: String? {
        switch self {
        case .missingSigningIdentity: return "The helper signing identity is missing."
        case .invalidSigningPolicy: return "The helper signing policy is invalid."
        case .signatureUnavailable: return "The helper signature cannot be read."
        case .signatureRejected: return "The helper signature is not trusted."
        case .notInstalledPath: return "The helper is not installed in a protected location."
        case .pathIsNotCanonical: return "The helper path is not canonical."
        case .executableNotRegularFile: return "The helper is not a regular file."
        case .executableNotOwnedByRoot: return "The helper is not owned by root."
        case .executableWritable: return "The helper can be changed by a user."
        case .unsafeParentDirectory: return "A helper parent directory is not protected."
        case .unsafeInstallRoot: return "The helper install root is not protected."
        case .launchDaemonPlistMissing: return "The helper launch daemon file is missing."
        case .launchDaemonPlistUnsafe: return "The helper launch daemon file is not protected."
        case .launchDaemonPlistMismatch: return "The helper launch daemon file names another program."
        case .bundleOutsideApplications: return "The app is not in a protected Applications folder."
        case .helperOutsideBundle: return "The helper is outside the signed app bundle."
        case .bundleNotOwnedByRoot: return "The app bundle is not owned by root."
        case .bundleWritable: return "The app bundle can be changed by a user."
        case .signedAppMissing: return "The signed app bundle is missing."
        case .callerRejected: return "The caller is not the signed HotspotShade app."
        case .helperBusy: return "The helper already serves another connection."
        case .cleanupBlocked: return "A previous tunnel did not stop cleanly."
        case .requiresRoot: return "The helper must run as root."
        case .engineStartFailed: return "The engine could not start."
        case .engineStopTimedOut: return "The engine did not stop in time."
        case .stopNotConfirmed: return "A previous tunnel stop was not confirmed."
        case .notConnected: return "The helper is not connected."
        case .helperTimeout: return "The helper did not answer in time."
        case .helperUnavailable: return "The helper is unavailable."
        case .responseRejected: return "The helper rejected the request."
        case .aclUnavailable: return "The helper file permissions cannot be read."
        case .cancelled: return "The start was cancelled."
        case .notAuthorized: return "This account is not authorized to start the tunnel."
        case .authorizationBusy: return "Another authorization prompt is open."
        case .startRightNotConfigured: return "The helper administrator right is not configured."
        case .handshakeRequired: return "The helper connection was not authenticated."
        case .engineExited: return "The engine exited."
        case .engineExitUnclean: return "The engine exited without a clean stop."
        case .startExclusionBusy: return Strings.helperStartExclusionBusy
        case .startExclusionUnavailable: return Strings.helperStartExclusionUnavailable
        case .tunnelNotRunning: return Strings.helperTunnelNotRunning
        case .grantFailed: return Strings.helperGrantFailed
        case .authorizationTimedOut: return Strings.helperAuthorizationTimedOut
        }
    }
}

// Build a code signing requirement from two allowlisted values. Never accept a
// whole requirement string from a request, a plist, or a browser.
public enum HelperRequirement {
    public static let appIdentifier = "dev.hotspotshade.mac"
    public static let helperIdentifier = "dev.hotspotshade.mac.helper"
    public static let engineIdentifier = "dev.hotspotshade.engine"
    public static let helperServiceName = "dev.hotspotshade.mac.helper"
    public static let helperInstallRoot = "/Library/PrivilegedHelperTools"
    public static let helperExecutablePath = "/Library/PrivilegedHelperTools/dev.hotspotshade.mac.helper"
    public static let launchDaemonPath = "/Library/LaunchDaemons/dev.hotspotshade.mac.helper.plist"

    // The ordinary build accepts only Developer ID. A local preview must be
    // explicitly compiled with HOTSPOTSHADE_LOCAL_PREVIEW in the app, helper,
    // and installer. It accepts Apple Development instead, so a personal team
    // can test on its own Mac. A request or environment variable cannot select
    // the policy at runtime. Both policies still require the same team and
    // identifier, hardened runtime, and the denied entitlements below.
    public static let developerIdIntermediateMarker = "1.2.840.113635.100.6.2.6"
    public static let developerIdApplicationMarker = "1.2.840.113635.100.6.1.13"
    public static let developmentIntermediateMarker = "1.2.840.113635.100.6.2.1"
    public static let developmentApplicationMarker = "1.2.840.113635.100.6.1.12"

    #if HOTSPOTSHADE_LOCAL_PREVIEW
    public static let isLocalPreview = true
    private static let intermediateMarker = developmentIntermediateMarker
    private static let applicationMarker = developmentApplicationMarker
    #else
    public static let isLocalPreview = false
    private static let intermediateMarker = developerIdIntermediateMarker
    private static let applicationMarker = developerIdApplicationMarker
    #endif

    // Entitlements that weaken a protected root process. A requirement can
    // test entitlement presence, so these are part of the signing policy and
    // not only a separate signing-info check.
    public static let deniedEntitlementClauses = [
        "!entitlement[\"com.apple.security.get-task-allow\"]",
        "!entitlement[\"com.apple.security.cs.disable-library-validation\"]",
        "!entitlement[\"com.apple.security.cs.allow-dyld-environment-variables\"]",
    ]

    public static func make(identifier: String, teamIdentifier: String) throws -> String {
        guard isValidIdentifier(identifier), isValidTeamIdentifier(teamIdentifier) else {
            throw HelperTrustError.invalidSigningPolicy
        }
        var clauses = [
            "anchor apple generic",
            "identifier \"\(identifier)\"",
            "certificate leaf[subject.OU] = \"\(teamIdentifier)\"",
            "certificate 1[field.\(intermediateMarker)] exists",
            "certificate leaf[field.\(applicationMarker)] exists",
        ]
        clauses.append(contentsOf: deniedEntitlementClauses)
        return clauses.joined(separator: " and ")
    }

    // The helper validates its own signature before it reads a team identifier
    // from that signature. A self-signed or ad-hoc file cannot reach the next
    // check. The compile-time signing policy applies here too.
    public static func makeSelf(identifier: String) throws -> String {
        guard isValidIdentifier(identifier) else { throw HelperTrustError.invalidSigningPolicy }
        var clauses = [
            "anchor apple generic",
            "identifier \"\(identifier)\"",
            "certificate 1[field.\(intermediateMarker)] exists",
            "certificate leaf[field.\(applicationMarker)] exists",
        ]
        clauses.append(contentsOf: deniedEntitlementClauses)
        return clauses.joined(separator: " and ")
    }

    public static func isValidIdentifier(_ value: String) -> Bool {
        guard !value.isEmpty, value.count <= 255 else { return false }
        return value.allSatisfy { character in
            character.isASCII
                && (character.isLetter || character.isNumber || character == "." || character == "-")
        }
    }

    public static func isValidTeamIdentifier(_ value: String) -> Bool {
        guard value.count == 10 else { return false }
        return value.allSatisfy { character in
            character.isASCII && (character.isLetter || character.isNumber)
        }
    }
}

public protocol HelperCodeSignatureChecking: Sendable {
    func signingInfo(atPath path: String) throws -> HelperSigningInfo
    func verifyStaticCode(atPath path: String, requirement: String) throws
    /// Identify a running process by its kernel audit token, never by a PID
    /// that the caller supplies. A PID can be recycled between the check and
    /// the request.
    func verifyRunningCode(
        auditToken: [UInt8],
        processIdentifier: Int32,
        requirement: String
    ) throws
}

// The real Security framework checks. Every call returns a plain error. No
// OSStatus, path, or identity is put in a helper response or a log.
public struct SecurityHelperCodeSignatureChecker: HelperCodeSignatureChecking {
    public init() {}

    public func signingInfo(atPath path: String) throws -> HelperSigningInfo {
        var code: SecStaticCode?
        let created = SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code)
        guard created == errSecSuccess, let code else {
            throw HelperTrustError.signatureUnavailable
        }
        return try signingInfo(for: code)
    }

    private func signingInfo(for code: SecStaticCode) throws -> HelperSigningInfo {
        var information: CFDictionary?
        let copied = SecCodeCopySigningInformation(
            code,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &information
        )
        guard copied == errSecSuccess,
              let dictionary = information as? [String: Any]
        else {
            throw HelperTrustError.signatureUnavailable
        }
        let identifier = dictionary[kSecCodeInfoIdentifier as String] as? String ?? ""
        let team = dictionary[kSecCodeInfoTeamIdentifier as String] as? String
        let flags = (dictionary[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0
        let adHoc = flags & 0x0000_0002 != 0
        let hardened = flags & 0x0001_0000 != 0
        let entitlements = dictionary[kSecCodeInfoEntitlementsDict as String] as? [String: Any]
        let debuggerValue = entitlements?["com.apple.security.get-task-allow"]
        let debugger = (debuggerValue as? Bool) == true
            || (debuggerValue as? NSNumber)?.boolValue == true
        let libraryValue = entitlements?["com.apple.security.cs.disable-library-validation"]
        let library = (libraryValue as? Bool) == true
            || (libraryValue as? NSNumber)?.boolValue == true
        let dyldValue = entitlements?["com.apple.security.cs.allow-dyld-environment-variables"]
        let dyld = (dyldValue as? Bool) == true
            || (dyldValue as? NSNumber)?.boolValue == true
        return HelperSigningInfo(
            identifier: identifier,
            teamIdentifier: team,
            isAdHoc: adHoc,
            hasHardenedRuntime: hardened,
            allowsDebugging: debugger,
            disablesLibraryValidation: library,
            allowsDyldEnvironmentVariables: dyld
        )
    }

    public func verifyStaticCode(atPath path: String, requirement: String) throws {
        var code: SecStaticCode?
        let created = SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code)
        guard created == errSecSuccess, let code else {
            throw HelperTrustError.signatureUnavailable
        }
        var requirementRef: SecRequirement?
        let made = SecRequirementCreateWithString(requirement as CFString, [], &requirementRef)
        guard made == errSecSuccess, let requirementRef else {
            throw HelperTrustError.invalidSigningPolicy
        }
        let checked = SecStaticCodeCheckValidity(code, [], requirementRef)
        guard checked == errSecSuccess else { throw HelperTrustError.signatureRejected }
    }

    public func verifyRunningCode(
        auditToken: [UInt8],
        processIdentifier: Int32,
        requirement: String
    ) throws {
        // A PID alone is not an identity. The kernel audit token names the
        // exact process that ran when the XPC message arrived. The PID is only
        // a secondary sanity value.
        guard processIdentifier > 0,
              auditToken.count == HelperAuditToken.byteCount
        else {
            throw HelperTrustError.callerRejected
        }
        var code: SecCode?
        let attributes = [
            kSecGuestAttributeAudit as String: Data(auditToken)
        ] as CFDictionary
        let copied = SecCodeCopyGuestWithAttributes(nil, attributes, [], &code)
        guard copied == errSecSuccess, let code else {
            throw HelperTrustError.callerRejected
        }
        var requirementRef: SecRequirement?
        let made = SecRequirementCreateWithString(requirement as CFString, [], &requirementRef)
        guard made == errSecSuccess, let requirementRef else {
            throw HelperTrustError.invalidSigningPolicy
        }
        let checked = SecCodeCheckValidity(code, [], requirementRef)
        guard checked == errSecSuccess else { throw HelperTrustError.callerRejected }
        // The requirement cannot test the hardened runtime flag or the
        // debugger entitlement. Read the live code's signing information and
        // require both here.
        var staticCode: SecStaticCode?
        let copiedStatic = SecCodeCopyStaticCode(code, [], &staticCode)
        guard copiedStatic == errSecSuccess, let staticCode else {
            throw HelperTrustError.callerRejected
        }
        let info = try signingInfo(for: staticCode)
        guard info.hasHardenedRuntime, !info.allowsDebugging else {
            throw HelperTrustError.callerRejected
        }
    }
}

// The XPC runtime enforces this requirement on every message from a peer. The
// helper also checks the process again with the Security framework. A message
// never carries a caller name, token, or path that the helper would trust.
public struct HelperCallerPolicy: Equatable, Sendable {
    public let teamIdentifier: String
    public let identifier: String

    public init(teamIdentifier: String, identifier: String = HelperRequirement.appIdentifier) throws {
        guard HelperRequirement.isValidTeamIdentifier(teamIdentifier),
              HelperRequirement.isValidIdentifier(identifier)
        else {
            throw HelperTrustError.invalidSigningPolicy
        }
        self.teamIdentifier = teamIdentifier
        self.identifier = identifier
    }

    public func requirement() throws -> String {
        try HelperRequirement.make(identifier: identifier, teamIdentifier: teamIdentifier)
    }
}

public struct AuthorizedHelperCaller: Equatable, Sendable {
    public let processIdentifier: Int32
    public let sessionIdentifier: Int32
}

// The XPC runtime already drops a peer that fails the code signing
// requirement on the listener. This second check runs against the live process
// before any request is served. It uses the kernel audit token, not a PID that
// the peer could have supplied or that the kernel could have recycled. It also
// requires a real login session. A token without a positive audit session is a
// system or launchd context, not a person who could see an authorization
// prompt, so it is rejected. The session is evidence and a admission check; it
// is not a substitute for the code signature check or the start right.
public final class HelperCallerAuthorizer: Sendable {
    private let policy: HelperCallerPolicy
    private let checker: HelperCodeSignatureChecking

    public init(
        policy: HelperCallerPolicy,
        checker: HelperCodeSignatureChecking = SecurityHelperCodeSignatureChecker()
    ) {
        self.policy = policy
        self.checker = checker
    }

    public func authorize(auditToken: HelperAuditToken) throws -> AuthorizedHelperCaller {
        guard auditToken.bytes.count == HelperAuditToken.byteCount,
              auditToken.processIdentifier > 0,
              let session = HelperPeerSession(
                  sessionIdentifier: auditToken.sessionIdentifier,
                  processIdentifier: auditToken.processIdentifier
              )
        else {
            throw HelperTrustError.callerRejected
        }
        let requirement = try policy.requirement()
        try checker.verifyRunningCode(
            auditToken: auditToken.bytes,
            processIdentifier: auditToken.processIdentifier,
            requirement: requirement
        )
        return AuthorizedHelperCaller(
            processIdentifier: session.processIdentifier,
            sessionIdentifier: session.sessionIdentifier
        )
    }

    public var requirement: String {
        get throws { try policy.requirement() }
    }
}
