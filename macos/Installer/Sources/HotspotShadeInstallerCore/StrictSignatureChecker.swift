import Foundation
import Security
import HotspotShadeKit

// The kit checker runs the requirement check with default flags. Those flags
// check one architecture slice and skip strict and nested-code validation. The
// installer adds a second, strict pass over the same path: every architecture,
// the strict resource rules, and nested code. The installer also refuses any
// file that is not one thin arm64 Mach-O (see `MachOPolicy`), so the all
// architecture flag is a second guard, not the only one.
//
// This pass does not check revocation, notarization, or a stapled ticket. A
// Developer ID chain has not been verified in this repository.
public struct StrictSecurityCodeSignatureChecker: HelperCodeSignatureChecking {
    private let base = SecurityHelperCodeSignatureChecker()

    public init() {}

    public func signingInfo(atPath path: String) throws -> HelperSigningInfo {
        try base.signingInfo(atPath: path)
    }

    public func verifyStaticCode(atPath path: String, requirement: String) throws {
        try base.verifyStaticCode(atPath: path, requirement: requirement)
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess,
              let code
        else {
            throw HelperTrustError.signatureUnavailable
        }
        var requirementRef: SecRequirement?
        guard SecRequirementCreateWithString(requirement as CFString, [], &requirementRef) == errSecSuccess,
              let requirementRef
        else {
            throw HelperTrustError.invalidSigningPolicy
        }
        let flags = SecCSFlags(rawValue:
            kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSCheckNestedCode)
        guard SecStaticCodeCheckValidityWithErrors(code, flags, requirementRef, nil) == errSecSuccess else {
            throw HelperTrustError.signatureRejected
        }
    }

    public func verifyRunningCode(
        auditToken: [UInt8],
        processIdentifier: Int32,
        requirement: String
    ) throws {
        try base.verifyRunningCode(
            auditToken: auditToken,
            processIdentifier: processIdentifier,
            requirement: requirement
        )
    }
}
