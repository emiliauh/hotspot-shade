import Foundation
import HotspotShadeKit

// The launch daemon has no transaction and no creator identity. launchctl can
// say whether a job is loaded, but it cannot say which process bootstrapped it.
// The transaction therefore treats one exact read-back as its loaded state:
// the job label, the installed launch daemon file, and the installed helper
// executable must all appear on their own lines in `launchctl print`.
//
// This is a conservative parser for the printed format. A macOS change that
// renames a line fails closed and keeps the service journal. That is better
// than trusting an exit status alone.
public struct LaunchdJobReadback: Equatable, Sendable {
    public let label: String
    public let launchDaemonPath: String
    public let helperPath: String
    public let rawOutput: Data

    public init(label: String, launchDaemonPath: String, helperPath: String, rawOutput: Data) {
        self.label = label
        self.launchDaemonPath = launchDaemonPath
        self.helperPath = helperPath
        self.rawOutput = rawOutput
    }

    public static func matches(
        output: Data,
        label: String,
        launchDaemonPath: String,
        helperPath: String
    ) -> Bool {
        guard let text = String(data: output, encoding: .utf8) else { return false }
        let lines = text
            .split(separator: "\n", omittingEmptySubsequences: false)
            .map { String($0).trimmingCharacters(in: .whitespaces) }
        return lines.contains("system/\(label) = {")
            && lines.contains("path = \(launchDaemonPath)")
            && lines.contains("program = \(helperPath)")
    }
}

public enum LaunchdJobObservation: Equatable, Sendable {
    case absent
    case loaded(LaunchdJobReadback)
    // A job with the fixed label is loaded, but its printed program or path is
    // not the installed one. Never boot it out automatically.
    case unexpected(String)
    // The tool failed in a way that does not prove absence.
    case unknown(String)
}

public protocol LaunchdJobControlling: Sendable {
    func observe() throws -> LaunchdJobObservation
    func bootout() throws
    func bootstrap() throws
}

public enum LaunchdJobError: Error, Equatable, CustomStringConvertible {
    case commandFailed(String)

    public var description: String {
        switch self {
        case .commandFailed(let why):
            return "The launch daemon command failed: \(why)."
        }
    }
}

public struct CommandLaunchdJobController: LaunchdJobControlling {
    private let runner: PrivilegedCommandRunning

    public init(runner: PrivilegedCommandRunning) {
        self.runner = runner
    }

    public func observe() throws -> LaunchdJobObservation {
        let result: PrivilegedCommandResult
        do {
            result = try runner.run(.launchdPrint())
        } catch let error as PrivilegedCommandError {
            return .unknown(error.description)
        } catch {
            return .unknown("the print command did not run")
        }

        if result.exitCode == 0 {
            guard LaunchdJobReadback.matches(
                output: result.standardOutput,
                label: PrivilegedServiceLayout.launchdLabel,
                launchDaemonPath: PrivilegedServiceLayout.launchDaemonPath,
                helperPath: PrivilegedServiceLayout.helperPath
            ) else {
                return .unexpected(
                    "the loaded job does not name the installed helper and launch daemon file"
                )
            }
            return .loaded(
                LaunchdJobReadback(
                    label: PrivilegedServiceLayout.launchdLabel,
                    launchDaemonPath: PrivilegedServiceLayout.launchDaemonPath,
                    helperPath: PrivilegedServiceLayout.helperPath,
                    rawOutput: result.standardOutput
                )
            )
        }

        // launchctl returns 113 with "Could not find service" on the macOS
        // versions observed during this work. Both the status and the fixed
        // diagnostic must agree. Any other status or text is unknown, never
        // absence. A version that changes either one fails closed.
        if result.exitCode == 113,
           let text = String(data: result.standardError, encoding: .utf8),
           text.contains("Could not find service")
        {
            return .absent
        }
        return .unknown("launchctl print exited with status \(result.exitCode)")
    }

    public func bootout() throws {
        let result: PrivilegedCommandResult
        do {
            result = try runner.run(.launchdBootout())
        } catch let error as PrivilegedCommandError {
            throw LaunchdJobError.commandFailed(error.description)
        } catch {
            throw LaunchdJobError.commandFailed("the bootout command did not run")
        }
        guard result.exitCode == 0 else {
            throw LaunchdJobError.commandFailed(
                "launchctl bootout exited with status \(result.exitCode)"
            )
        }
    }

    public func bootstrap() throws {
        let result: PrivilegedCommandResult
        do {
            result = try runner.run(.launchdBootstrap())
        } catch let error as PrivilegedCommandError {
            throw LaunchdJobError.commandFailed(error.description)
        } catch {
            throw LaunchdJobError.commandFailed("the bootstrap command did not run")
        }
        guard result.exitCode == 0 else {
            throw LaunchdJobError.commandFailed(
                "launchctl bootstrap exited with status \(result.exitCode)"
            )
        }
    }
}
