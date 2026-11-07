import Foundation
import CoreFoundation
import CryptoKit
import HotspotShadeKit

// The semantic part of one stored start right. Authorization Services adds
// metadata keys to a definition when authd stores it, so byte comparison is
// not a stable contract. The policy record keeps the keys whose values are the
// helper's actual start gate: class, group, authenticate-user, shared,
// allow-root, timeout, and the optional comment.
public struct AuthorizationRightPolicy: Codable, Equatable, Sendable {
    public let rightClass: String
    public let group: String
    public let authenticateUser: Bool
    public let shared: Bool
    public let allowRoot: Bool
    public let timeout: Int
    public let comment: String?

    public init(
        rightClass: String,
        group: String,
        authenticateUser: Bool,
        shared: Bool,
        allowRoot: Bool,
        timeout: Int,
        comment: String?
    ) {
        self.rightClass = rightClass
        self.group = group
        self.authenticateUser = authenticateUser
        self.shared = shared
        self.allowRoot = allowRoot
        self.timeout = timeout
        self.comment = comment
    }
}

public struct AuthorizationRightSnapshot: Equatable, Sendable {
    public let plist: Data
    public let policy: AuthorizationRightPolicy
    public let sha256: String

    public init(plist: Data, policy: AuthorizationRightPolicy, sha256: String) {
        self.plist = plist
        self.policy = policy
        self.sha256 = sha256
    }
}

public enum AuthorizationRightPolicyError: Error, Equatable, CustomStringConvertible {
    case tooLarge
    case notPropertyList
    case unsafeDefinition

    public var description: String {
        switch self {
        case .tooLarge:
            return "The start right definition is empty or larger than the fixed bound."
        case .notPropertyList:
            return "The start right is not a property list dictionary."
        case .unsafeDefinition:
            return "The start right is not the reviewed administrator prompt definition."
        }
    }
}

// One parser for both the packaged source plist and the authd read-back. The
// helper's own validator stays the authority. A stored definition may carry
// the authd metadata keys; the source plist may not, and InstallerValidator
// checks that separately before this parser runs.
public enum AuthorizationRightPolicyParser {
    public static func parse(_ data: Data) throws -> AuthorizationRightSnapshot {
        guard !data.isEmpty, data.count <= PrivilegedServiceLayout.maximumRightBytes else {
            throw AuthorizationRightPolicyError.tooLarge
        }
        guard let object = try? PropertyListSerialization.propertyList(
            from: data,
            options: [],
            format: nil
        ), let dictionary = object as? [String: Any]
        else { throw AuthorizationRightPolicyError.notPropertyList }
        guard HelperStartRightValidator.isSafe(dictionary) else {
            throw AuthorizationRightPolicyError.unsafeDefinition
        }
        guard let policy = policy(from: dictionary) else {
            throw AuthorizationRightPolicyError.unsafeDefinition
        }
        return AuthorizationRightSnapshot(
            plist: data,
            policy: policy,
            sha256: ServiceHash.sha256Hex(data)
        )
    }

    public static func policy(from dictionary: [String: Any]) -> AuthorizationRightPolicy? {
        guard let rightClass = dictionary["class"] as? String,
              rightClass == "user",
              let group = dictionary["group"] as? String,
              group == "admin",
              boolean(dictionary["authenticate-user"]) == true,
              boolean(dictionary["shared"]) == false,
              boolean(dictionary["allow-root"]) == false,
              let timeout = integer(dictionary["timeout"]),
              HelperStartAuthorizationPolicy.isStartRightTimeout(timeout)
        else { return nil }

        let comment: String?
        if let value = dictionary["comment"] {
            guard let text = value as? String else { return nil }
            comment = text
        } else {
            comment = nil
        }
        return AuthorizationRightPolicy(
            rightClass: rightClass,
            group: group,
            authenticateUser: true,
            shared: false,
            allowRoot: false,
            timeout: timeout,
            comment: comment
        )
    }

    private static func boolean(_ value: Any?) -> Bool? {
        guard let value, CFGetTypeID(value as CFTypeRef) == CFBooleanGetTypeID() else {
            return nil
        }
        return value as? Bool
    }

    private static func integer(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) == CFNumberGetTypeID()
        else { return nil }
        switch CFNumberGetType(number) {
        case .float32Type, .float64Type, .cgFloatType:
            return nil
        default:
            return number.intValue
        }
    }
}

enum ServiceHash {
    static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
