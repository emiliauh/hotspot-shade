import Foundation
import Security
import HotspotShadeKit

// Identifies the running coordinator, rather than trusting a team supplied by
// its caller. This checks only the coordinator; it does not enable installation.
public enum InstallerSelfIdentity {
    public static let identifier = "dev.hotspotshade.mac.installer.coordinator"

    public enum IdentityError: Error {
        case unavailable
        case rejected
    }

    public static func teamIdentifier() throws -> String {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else {
            throw IdentityError.unavailable
        }
        try verify(code, requirement: HelperRequirement.makeSelf(identifier: identifier))

        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else {
            throw IdentityError.unavailable
        }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(
            staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information
        ) == errSecSuccess, let values = information as? [String: Any],
              let team = values[kSecCodeInfoTeamIdentifier as String] as? String,
              HelperRequirement.isValidTeamIdentifier(team),
              values[kSecCodeInfoIdentifier as String] as? String == identifier,
              let flags = values[kSecCodeInfoFlags as String] as? NSNumber,
              flags.uint32Value & 0x0001_0000 != 0,
              flags.uint32Value & 0x0000_0002 == 0
        else { throw IdentityError.rejected }

        let entitlements = values[kSecCodeInfoEntitlementsDict as String] as? [String: Any] ?? [:]
        for name in [
            "com.apple.security.get-task-allow",
            "com.apple.security.cs.disable-library-validation",
            "com.apple.security.cs.allow-dyld-environment-variables",
        ] {
            if (entitlements[name] as? NSNumber)?.boolValue == true { throw IdentityError.rejected }
        }
        try verify(code, requirement: HelperRequirement.make(identifier: identifier, teamIdentifier: team))
        return team
    }

    private static func verify(_ code: SecCode, requirement: String) throws {
        var compiled: SecRequirement?
        guard SecRequirementCreateWithString(requirement as CFString, [], &compiled) == errSecSuccess,
              let compiled,
              SecCodeCheckValidity(code, [], compiled) == errSecSuccess
        else { throw IdentityError.rejected }
    }
}
