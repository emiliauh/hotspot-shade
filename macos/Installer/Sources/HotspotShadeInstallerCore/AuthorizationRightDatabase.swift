import Foundation
import Security

// The authorization database is not a file tree and it has no transaction. The
// installer writes one fixed right, reads it back, and validates the stored
// definition with the helper's own policy. A read command that fails is
// ambiguous: the right may be absent, or the database may be unreadable. The
// absence probe uses AuthorizationRightGet, whose documented result for a
// missing definition is errAuthorizationDenied, so an unreadable database is
// not mistaken for a clean first install.
public enum AuthorizationRightObservation: Equatable, Sendable {
    case absent
    case present(AuthorizationRightSnapshot)
}

public protocol AuthorizationRightStoring: Sendable {
    func observe() throws -> AuthorizationRightObservation
    func write(_ definition: Data) throws
    func remove() throws
}

public protocol AuthorizationRightExistenceProbing: Sendable {
    func isPresent() throws -> Bool
}

public enum AuthorizationRightDatabaseError: Error, Equatable, CustomStringConvertible {
    case unreadable(String)
    case readbackInvalid(String)
    case commandFailed(String)

    public var description: String {
        switch self {
        case .unreadable(let why):
            return "The authorization right database cannot be read: \(why)."
        case .readbackInvalid(let why):
            return "The stored authorization right is not accepted: \(why)."
        case .commandFailed(let why):
            return "The authorization right command failed: \(why)."
        }
    }
}

// The read-back parser is AuthorizationRightPolicyParser. It accepts the authd
// metadata keys that the helper tolerates and refuses every unknown key and
// every weaker or delegated definition. The command layer only supplies bytes;
// it never decides that a write succeeded because the command exited zero.
public struct CommandAuthorizationRightDatabase: AuthorizationRightStoring {
    private let runner: PrivilegedCommandRunning
    private let presence: AuthorizationRightExistenceProbing

    public init(
        runner: PrivilegedCommandRunning,
        presence: AuthorizationRightExistenceProbing = SecurityAuthorizationRightExistenceProbe()
    ) {
        self.runner = runner
        self.presence = presence
    }

    public func observe() throws -> AuthorizationRightObservation {
        let result: PrivilegedCommandResult
        do {
            result = try runner.run(.authorizationRightRead())
        } catch let error as PrivilegedCommandError {
            throw AuthorizationRightDatabaseError.unreadable(error.description)
        } catch {
            throw AuthorizationRightDatabaseError.unreadable("the read command did not run")
        }

        if result.exitCode == 0 {
            do {
                return .present(try AuthorizationRightPolicyParser.parse(result.standardOutput))
            } catch let error as AuthorizationRightPolicyError {
                throw AuthorizationRightDatabaseError.readbackInvalid(error.description)
            } catch {
                throw AuthorizationRightDatabaseError.readbackInvalid(
                    "the stored definition is not a property list"
                )
            }
        }

        let present: Bool
        do {
            present = try presence.isPresent()
        } catch {
            throw AuthorizationRightDatabaseError.unreadable(
                "the read failed and the existence probe did not answer"
            )
        }
        if present {
            throw AuthorizationRightDatabaseError.unreadable(
                "the right exists but the read command did not return it"
            )
        }
        return .absent
    }

    public func write(_ definition: Data) throws {
        let command: PrivilegedServiceCommand
        do {
            command = try PrivilegedServiceCommand.authorizationRightWrite(definition)
        } catch let error as PrivilegedServiceCommandError {
            throw AuthorizationRightDatabaseError.commandFailed(error.description)
        } catch {
            throw AuthorizationRightDatabaseError.commandFailed("the definition is not bounded")
        }
        let result: PrivilegedCommandResult
        do {
            result = try runner.run(command)
        } catch let error as PrivilegedCommandError {
            throw AuthorizationRightDatabaseError.commandFailed(error.description)
        } catch {
            throw AuthorizationRightDatabaseError.commandFailed("the write command did not run")
        }
        guard result.exitCode == 0 else {
            throw AuthorizationRightDatabaseError.commandFailed(
                "authorizationdb write exited with status \(result.exitCode)"
            )
        }
    }

    public func remove() throws {
        let result: PrivilegedCommandResult
        do {
            result = try runner.run(.authorizationRightRemove())
        } catch let error as PrivilegedCommandError {
            throw AuthorizationRightDatabaseError.commandFailed(error.description)
        } catch {
            throw AuthorizationRightDatabaseError.commandFailed("the remove command did not run")
        }
        guard result.exitCode == 0 else {
            throw AuthorizationRightDatabaseError.commandFailed(
                "authorizationdb remove exited with status \(result.exitCode)"
            )
        }
    }
}

// This probe answers only whether a definition exists. It does not read or
// trust the definition; the command read is the source for the actual check.
// A status other than success or denied is an error, never absence.
public struct SecurityAuthorizationRightExistenceProbe: AuthorizationRightExistenceProbing {
    private let lookup: @Sendable (String) -> OSStatus

    public init() {
        self.lookup = { name in AuthorizationRightGet(name, nil) }
    }

    // The hermetic tests use this seam to exercise the documented status
    // mapping. It never calls the authorization database.
    init(lookup: @escaping @Sendable (String) -> OSStatus) {
        self.lookup = lookup
    }

    public func isPresent() throws -> Bool {
        // The definition pointer is nil: this probe needs only presence. The
        // API documents errAuthorizationDenied as "No definition found".
        let status = lookup(PrivilegedServiceLayout.rightName)
        switch status {
        case errAuthorizationSuccess:
            return true
        case errAuthorizationDenied:
            return false
        default:
            throw AuthorizationRightDatabaseError.unreadable(
                "AuthorizationRightGet returned status \(status)"
            )
        }
    }
}
