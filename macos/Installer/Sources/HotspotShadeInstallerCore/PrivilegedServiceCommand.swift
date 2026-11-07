import Foundation
import Darwin
import HotspotShadeKit

// Fixed paths and fixed command shapes for the two privileged actions that are
// not file replacement: the launch daemon registration and the authorization
// right write.
//
// The service transaction never builds a command from an input. It has no
// shell, no environment override, no PATH lookup, and no argument that names a
// path or a right. A command is one of the six fixed shapes below, with the
// destinations from InstallerLayout and the helper constants in
// HotspotShadeKit. No public caller can construct another command.
public enum PrivilegedServiceLayout {
    public static let rightName = HelperStartAuthorizationPolicy.startRight
    public static let launchdLabel = HelperRequirement.helperServiceName
    public static let helperPath = InstallerLayout.helperDestination
    public static let enginePath = InstallerLayout.engineDestination
    public static let launchDaemonPath = InstallerLayout.launchDaemonDestination

    public static let securityToolPath = "/usr/bin/security"
    public static let launchctlToolPath = "/bin/launchctl"

    public static let stateDirectoryRelative = InstallLockLayout.stateDirectoryRelative
    public static let rightSourceRelative =
        InstallJournal.relativeDestination(InstallerLayout.startRightDestination)
    public static let launchDaemonRelative =
        InstallJournal.relativeDestination(InstallerLayout.launchDaemonDestination)
    public static let helperRelative =
        InstallJournal.relativeDestination(InstallerLayout.helperDestination)
    public static let engineRelative =
        InstallJournal.relativeDestination(InstallerLayout.engineDestination)

    public static let maximumRightBytes = ArtifactIngest.maximumPlistBytes
    public static let maximumStandardInputBytes = maximumRightBytes
    // One fixed cap on the total stdout plus stderr bytes for one command.
    public static let maximumCommandOutputBytes = 256 * 1024
    public static let maximumArgumentCount = 8
    public static let maximumArgumentBytes = 4096
    public static let maximumToolPathBytes = 1024

    public static let inspectionTimeout: TimeInterval = 10
    public static let mutationTimeout: TimeInterval = 30
    public static let maximumTimeout = mutationTimeout

    // A fixed, minimal environment. The two tools read no value from it that
    // changes the target of an action. The command line and the executable
    // path are absolute and fixed.
    public static let commandEnvironment = [
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LC_ALL": "C",
    ]
}

public enum PrivilegedServiceCommandError: Error, Equatable, CustomStringConvertible {
    case definitionTooLarge
    case invalidShape(String)

    public var description: String {
        switch self {
        case .definitionTooLarge:
            return "The start right definition is larger than the fixed bound."
        case .invalidShape(let field):
            return "The privileged command does not match its fixed shape: \(field)."
        }
    }
}

// One fixed privileged command. The fields are public for tests and for
// diagnostics, but the initializer is private. The only production
// constructors are the static factories, and they use fixed constants only.
public struct PrivilegedServiceCommand: Equatable, Sendable {
    public enum Operation: String, Equatable, Sendable {
        case authorizationRightRead = "authorization-right-read"
        case authorizationRightWrite = "authorization-right-write"
        case authorizationRightRemove = "authorization-right-remove"
        case launchdPrint = "launchd-print"
        case launchdBootout = "launchd-bootout"
        case launchdBootstrap = "launchd-bootstrap"
    }

    public let operation: Operation
    public let toolPath: String
    public let arguments: [String]
    public let standardInput: Data?
    public let timeout: TimeInterval
    // The cap applies to stdout plus stderr for the whole command.
    public let maximumOutputBytes: Int

    private init(
        operation: Operation,
        toolPath: String,
        arguments: [String],
        standardInput: Data? = nil,
        timeout: TimeInterval,
        maximumOutputBytes: Int = PrivilegedServiceLayout.maximumCommandOutputBytes
    ) {
        self.operation = operation
        self.toolPath = toolPath
        self.arguments = arguments
        self.standardInput = standardInput
        self.timeout = timeout
        self.maximumOutputBytes = maximumOutputBytes
    }

    public static func authorizationRightRead() -> PrivilegedServiceCommand {
        PrivilegedServiceCommand(
            operation: .authorizationRightRead,
            toolPath: PrivilegedServiceLayout.securityToolPath,
            arguments: ["authorizationdb", "read", PrivilegedServiceLayout.rightName],
            timeout: PrivilegedServiceLayout.inspectionTimeout
        )
    }

    public static func authorizationRightWrite(
        _ definition: Data
    ) throws -> PrivilegedServiceCommand {
        guard definition.count > 0,
              definition.count <= PrivilegedServiceLayout.maximumRightBytes
        else { throw PrivilegedServiceCommandError.definitionTooLarge }
        return PrivilegedServiceCommand(
            operation: .authorizationRightWrite,
            toolPath: PrivilegedServiceLayout.securityToolPath,
            arguments: ["authorizationdb", "write", PrivilegedServiceLayout.rightName],
            standardInput: definition,
            timeout: PrivilegedServiceLayout.mutationTimeout
        )
    }

    public static func authorizationRightRemove() -> PrivilegedServiceCommand {
        PrivilegedServiceCommand(
            operation: .authorizationRightRemove,
            toolPath: PrivilegedServiceLayout.securityToolPath,
            arguments: ["authorizationdb", "remove", PrivilegedServiceLayout.rightName],
            timeout: PrivilegedServiceLayout.mutationTimeout
        )
    }

    public static func launchdPrint() -> PrivilegedServiceCommand {
        PrivilegedServiceCommand(
            operation: .launchdPrint,
            toolPath: PrivilegedServiceLayout.launchctlToolPath,
            arguments: ["print", "system/" + PrivilegedServiceLayout.launchdLabel],
            timeout: PrivilegedServiceLayout.inspectionTimeout
        )
    }

    public static func launchdBootout() -> PrivilegedServiceCommand {
        PrivilegedServiceCommand(
            operation: .launchdBootout,
            toolPath: PrivilegedServiceLayout.launchctlToolPath,
            arguments: ["bootout", "system/" + PrivilegedServiceLayout.launchdLabel],
            timeout: PrivilegedServiceLayout.mutationTimeout
        )
    }

    public static func launchdBootstrap() -> PrivilegedServiceCommand {
        PrivilegedServiceCommand(
            operation: .launchdBootstrap,
            toolPath: PrivilegedServiceLayout.launchctlToolPath,
            arguments: [
                "bootstrap",
                "system",
                PrivilegedServiceLayout.launchDaemonPath,
            ],
            timeout: PrivilegedServiceLayout.mutationTimeout
        )
    }

    // The runner checks the command before it reaches a spawn. The six
    // factories above always pass. An internal caller that bypasses the
    // factories fails here.
    public func validateFixedShape() throws {
        let expectedTool: String
        let expectedArguments: [String]
        let expectedTimeout: TimeInterval
        switch operation {
        case .authorizationRightRead:
            expectedTool = PrivilegedServiceLayout.securityToolPath
            expectedArguments = ["authorizationdb", "read", PrivilegedServiceLayout.rightName]
            expectedTimeout = PrivilegedServiceLayout.inspectionTimeout
        case .authorizationRightWrite:
            expectedTool = PrivilegedServiceLayout.securityToolPath
            expectedArguments = ["authorizationdb", "write", PrivilegedServiceLayout.rightName]
            expectedTimeout = PrivilegedServiceLayout.mutationTimeout
        case .authorizationRightRemove:
            expectedTool = PrivilegedServiceLayout.securityToolPath
            expectedArguments = ["authorizationdb", "remove", PrivilegedServiceLayout.rightName]
            expectedTimeout = PrivilegedServiceLayout.mutationTimeout
        case .launchdPrint:
            expectedTool = PrivilegedServiceLayout.launchctlToolPath
            expectedArguments = ["print", "system/" + PrivilegedServiceLayout.launchdLabel]
            expectedTimeout = PrivilegedServiceLayout.inspectionTimeout
        case .launchdBootout:
            expectedTool = PrivilegedServiceLayout.launchctlToolPath
            expectedArguments = ["bootout", "system/" + PrivilegedServiceLayout.launchdLabel]
            expectedTimeout = PrivilegedServiceLayout.mutationTimeout
        case .launchdBootstrap:
            expectedTool = PrivilegedServiceLayout.launchctlToolPath
            expectedArguments = [
                "bootstrap",
                "system",
                PrivilegedServiceLayout.launchDaemonPath,
            ]
            expectedTimeout = PrivilegedServiceLayout.mutationTimeout
        }

        guard toolPath == expectedTool else {
            throw PrivilegedServiceCommandError.invalidShape("tool")
        }
        guard arguments == expectedArguments else {
            throw PrivilegedServiceCommandError.invalidShape("arguments")
        }
        guard timeout == expectedTimeout else {
            throw PrivilegedServiceCommandError.invalidShape("timeout")
        }
        guard maximumOutputBytes == PrivilegedServiceLayout.maximumCommandOutputBytes else {
            throw PrivilegedServiceCommandError.invalidShape("output limit")
        }
        switch operation {
        case .authorizationRightWrite:
            guard let standardInput, !standardInput.isEmpty else {
                throw PrivilegedServiceCommandError.invalidShape("input")
            }
            guard standardInput.count <= PrivilegedServiceLayout.maximumStandardInputBytes else {
                throw PrivilegedServiceCommandError.definitionTooLarge
            }
        default:
            guard standardInput == nil else {
                throw PrivilegedServiceCommandError.invalidShape("input")
            }
        }
    }

    var executionPlan: CommandExecutionPlan {
        CommandExecutionPlan(
            executablePath: toolPath,
            arguments: arguments,
            standardInput: standardInput,
            timeout: timeout,
            maximumOutputBytes: maximumOutputBytes
        )
    }

    // Internal only. It exists so the tests can build a deliberately malformed
    // command and prove that validateFixedShape refuses it. No production code
    // calls this factory.
    static func testCommand(
        operation: Operation,
        toolPath: String,
        arguments: [String],
        standardInput: Data? = nil,
        timeout: TimeInterval,
        maximumOutputBytes: Int = PrivilegedServiceLayout.maximumCommandOutputBytes
    ) -> PrivilegedServiceCommand {
        PrivilegedServiceCommand(
            operation: operation,
            toolPath: toolPath,
            arguments: arguments,
            standardInput: standardInput,
            timeout: timeout,
            maximumOutputBytes: maximumOutputBytes
        )
    }
}

public struct PrivilegedCommandResult: Equatable, Sendable {
    public let exitCode: Int32
    public let standardOutput: Data
    public let standardError: Data

    public init(exitCode: Int32, standardOutput: Data, standardError: Data = Data()) {
        self.exitCode = exitCode
        self.standardOutput = standardOutput
        self.standardError = standardError
    }

    public var standardOutputText: String {
        String(decoding: standardOutput, as: UTF8.self)
    }
}

public enum PrivilegedCommandError: Error, Equatable, CustomStringConvertible {
    case notApproved
    case requiresRoot
    case invalidCommand
    case toolMissing(String)
    case toolUntrusted(String)
    case spawnFailed(String)
    case timedOut
    case outputTooLarge
    case outputIncomplete
    case inputWriteFailed

    public var description: String {
        switch self {
        case .notApproved:
            return "Live privileged commands are not approved in this build."
        case .requiresRoot:
            return "A live privileged command needs the root coordinator."
        case .invalidCommand:
            return "The privileged command does not match its fixed shape."
        case .toolMissing(let path):
            return "The fixed privileged tool is missing: \(path)."
        case .toolUntrusted(let why):
            return "The fixed privileged tool is not trusted: \(why)."
        case .spawnFailed:
            return "The privileged command could not start."
        case .timedOut:
            return "The privileged command did not finish within its bound."
        case .outputTooLarge:
            return "The privileged command produced more output than the fixed bound."
        case .outputIncomplete:
            return "The privileged command output did not close within its bound."
        case .inputWriteFailed:
            return "The privileged command input could not be written."
        }
    }
}

public protocol PrivilegedCommandRunning: Sendable {
    // True only for the system runner. The transaction refuses a live runtime
    // while CoordinatorPolicy.liveInstallationApproved is false.
    var isLiveSystem: Bool { get }
    func run(_ command: PrivilegedServiceCommand) throws -> PrivilegedCommandResult
}

// The facts that the fixed-tool policy checks. The reader is a seam so the
// tests can exercise every refusal without touching a real system file.
enum FixedToolTrustError: Error, Equatable, CustomStringConvertible {
    case notAllowlisted
    case missing
    case unreadable
    case notRegularFile
    case notExecutable
    case notOwnedByRoot
    case writableByNonRoot
    case setIdentifier
    case extendedACL

    var description: String {
        switch self {
        case .notAllowlisted:
            return "the path is not one of the two fixed tools"
        case .missing:
            return "the fixed tool is missing"
        case .unreadable:
            return "the fixed tool metadata cannot be read"
        case .notRegularFile:
            return "the fixed tool is not a regular file"
        case .notExecutable:
            return "the fixed tool is not executable"
        case .notOwnedByRoot:
            return "the fixed tool is not owned by root"
        case .writableByNonRoot:
            return "the fixed tool is writable by a group or another account"
        case .setIdentifier:
            return "the fixed tool carries a set-identifier bit"
        case .extendedACL:
            return "the fixed tool carries an extended access control list"
        }
    }
}

struct FixedToolFacts: Equatable, Sendable {
    let isRegularFile: Bool
    let isSymbolicLink: Bool
    let owner: UInt32
    let mode: UInt16
    let hasExtendedACL: Bool
}

protocol FixedToolFactReading: Sendable {
    func facts(atPath path: String) throws -> FixedToolFacts
}

struct SystemFixedToolFactReader: FixedToolFactReading {
    func facts(atPath path: String) throws -> FixedToolFacts {
        var status = stat()
        guard lstat(path, &status) == 0 else {
            if errno == ENOENT { throw FixedToolTrustError.missing }
            throw FixedToolTrustError.unreadable
        }
        let type = status.st_mode & S_IFMT
        return FixedToolFacts(
            isRegularFile: type == S_IFREG,
            isSymbolicLink: type == S_IFLNK,
            owner: UInt32(status.st_uid),
            mode: UInt16(status.st_mode),
            hasExtendedACL: try Self.hasExtendedACL(path, original: status)
        )
    }

    private static func hasExtendedACL(_ path: String, original: stat) throws -> Bool {
        errno = 0
        guard let acl = acl_get_file(path, ACL_TYPE_EXTENDED) else {
            // ENOENT also means the path disappeared. Confirm that the same
            // non-symlink object remains before accepting the no-ACL result.
            if errno == ENOENT {
                var current = stat()
                guard lstat(path, &current) == 0,
                      current.st_mode & S_IFMT != S_IFLNK,
                      current.st_dev == original.st_dev,
                      current.st_ino == original.st_ino else {
                    throw FixedToolTrustError.unreadable
                }
                return false
            }
            throw FixedToolTrustError.unreadable
        }
        acl_free(UnsafeMutableRawPointer(acl))
        return true
    }
}

// The live path is still disabled. These checks are what a future root
// coordinator would need before it may spawn either fixed tool: the path must
// be one of two Apple system tools, a regular file, root owned, not writable by
// group or another account, without a set-id bit, and without an extended ACL.
// They do not verify the Apple code signature or pin the inode across spawn.
// Those remain live-mode blockers, and CoordinatorPolicy.liveInstallationApproved
// stays false.
struct FixedPrivilegedToolPolicy: Sendable {
    static let allowedPaths: Set<String> = [
        PrivilegedServiceLayout.securityToolPath,
        PrivilegedServiceLayout.launchctlToolPath,
    ]

    private let reader: any FixedToolFactReading

    init(reader: any FixedToolFactReading = SystemFixedToolFactReader()) {
        self.reader = reader
    }

    func verify(path: String) throws {
        guard Self.allowedPaths.contains(path) else {
            throw FixedToolTrustError.notAllowlisted
        }
        let facts = try reader.facts(atPath: path)
        guard facts.isRegularFile, !facts.isSymbolicLink else {
            throw FixedToolTrustError.notRegularFile
        }
        guard facts.owner == 0 else { throw FixedToolTrustError.notOwnedByRoot }
        guard facts.mode & UInt16(0o022) == 0 else {
            throw FixedToolTrustError.writableByNonRoot
        }
        guard facts.mode & UInt16(S_ISUID) == 0,
              facts.mode & UInt16(S_ISGID) == 0
        else { throw FixedToolTrustError.setIdentifier }
        guard facts.mode & UInt16(0o111) != 0 else {
            throw FixedToolTrustError.notExecutable
        }
        guard !facts.hasExtendedACL else { throw FixedToolTrustError.extendedACL }
    }
}

// The real runner. It is compiled and linked, but this build cannot reach an
// execution because the approval gate is false and the coordinator refuses
// root. The runner repeats both checks itself, so a future caller cannot use
// it by mistake while the package is still a build-only foundation.
//
// The command is validated against its six fixed shapes, the tool path is
// checked against the fixed-tool policy, then the bounded supervisor runs one
// absolute executable with one fixed argument array. There is no /bin/sh, no
// login shell, no PATH lookup, and no command string.
public struct SystemPrivilegedCommandRunner: PrivilegedCommandRunning {
    public let isLiveSystem = true

    private let trust: FixedPrivilegedToolPolicy
    private let supervisor: CommandProcessSupervisor

    public init() {
        self.init(
            trust: FixedPrivilegedToolPolicy(),
            supervisor: CommandProcessSupervisor()
        )
    }

    // Internal test seam. Production code uses the public initializer and the
    // system trust policy and spawner. No public caller can inject either.
    init(
        trust: FixedPrivilegedToolPolicy,
        supervisor: CommandProcessSupervisor
    ) {
        self.trust = trust
        self.supervisor = supervisor
    }

    public func run(_ command: PrivilegedServiceCommand) throws -> PrivilegedCommandResult {
        guard CoordinatorPolicy.systemOperationsApproved else {
            throw PrivilegedCommandError.notApproved
        }
        guard geteuid() == 0 else {
            throw PrivilegedCommandError.requiresRoot
        }
        do {
            try command.validateFixedShape()
        } catch {
            throw PrivilegedCommandError.invalidCommand
        }
        do {
            try trust.verify(path: command.toolPath)
        } catch let error as FixedToolTrustError {
            if error == .missing {
                throw PrivilegedCommandError.toolMissing(command.toolPath)
            }
            throw PrivilegedCommandError.toolUntrusted(error.description)
        } catch {
            throw PrivilegedCommandError.toolUntrusted("the fixed tool cannot be verified")
        }
        return try supervisor.run(command.executionPlan)
    }
}

// One validated execution plan. The supervisor is internal and exists only
// behind SystemPrivilegedCommandRunner. The tests drive it with a fake
// spawner, so no test starts a child process.
struct CommandExecutionPlan: Equatable, Sendable {
    let executablePath: String
    // These are the arguments after argv[0]. The spawner inserts the executable
    // path as argv[0] itself.
    let arguments: [String]
    let standardInput: Data?
    let timeout: TimeInterval
    let maximumOutputBytes: Int
}

enum CommandPlanError: Error, Equatable, CustomStringConvertible {
    case pathNotAbsolute
    case pathTooLong
    case argumentCount
    case argumentBytes
    case invalidArgument
    case inputTooLarge
    case outputLimit
    case timeout

    var description: String {
        switch self {
        case .pathNotAbsolute:
            return "The command path is not absolute."
        case .pathTooLong:
            return "The command path is longer than the fixed bound."
        case .argumentCount:
            return "The command has more arguments than the fixed bound."
        case .argumentBytes:
            return "The command arguments are larger than the fixed bound."
        case .invalidArgument:
            return "A command argument carries a forbidden byte."
        case .inputTooLarge:
            return "The command input is larger than the fixed bound."
        case .outputLimit:
            return "The command output limit is outside the fixed bound."
        case .timeout:
            return "The command timeout is outside the fixed bound."
        }
    }
}

struct CommandExit: Equatable, Sendable {
    let exitCode: Int32
    let termSignal: Int32?
}

// The supervisor never signals a process after it has been reaped. The PID is
// not reused between a successful spawn and the first waitpid that reaps it,
// so a signal sent in that window cannot reach another process. The real child
// takes its waitpid and signal calls from this seam so the tests can prove the
// ordering without a real process.
protocol CommandChildKernel: Sendable {
    func wait(pid: pid_t, options: Int32) -> (result: pid_t, status: Int32, code: Int32)
    func killGroup(_ pid: pid_t, _ signal: Int32) -> Int32
    func killProcess(_ pid: pid_t, _ signal: Int32) -> Int32
}

struct SystemCommandChildKernel: CommandChildKernel {
    func wait(pid: pid_t, options: Int32) -> (result: pid_t, status: Int32, code: Int32) {
        var status: Int32 = 0
        let result = waitpid(pid, &status, options)
        return (result, status, result < 0 ? errno : 0)
    }

    func killGroup(_ pid: pid_t, _ signal: Int32) -> Int32 {
        killpg(pid, signal)
    }

    func killProcess(_ pid: pid_t, _ signal: Int32) -> Int32 {
        kill(pid, signal)
    }
}

protocol SpawnedCommand: AnyObject, Sendable {
    var standardInputDescriptor: Int32 { get }
    var standardOutputDescriptor: Int32 { get }
    var standardErrorDescriptor: Int32 { get }
    func pollExit() -> CommandExit?
    func signal(_ signal: Int32)
}

protocol CommandSpawning: Sendable {
    func spawn(_ plan: CommandExecutionPlan) throws -> any SpawnedCommand
}

// One POSIX child in its own process group. The group lets the supervisor stop
// a tool and any helper it forked, which is what keeps a descendant from
// holding the output pipes open forever. If the kernel did not put the child in
// its own group, the fallback signals the PID only. In both cases the PID is
// unreaped until the signal has been sent, so a later signal cannot hit a reused
// PID.
final class PosixSpawnedCommand: SpawnedCommand, @unchecked Sendable {
    private let lock = NSLock()
    private let processIdentifier: pid_t
    private let usesProcessGroup: Bool
    private let kernel: any CommandChildKernel
    private var reaped = false
    private var capturedExit: CommandExit?

    let standardInputDescriptor: Int32
    let standardOutputDescriptor: Int32
    let standardErrorDescriptor: Int32

    init(
        processIdentifier: pid_t,
        usesProcessGroup: Bool,
        standardInputDescriptor: Int32,
        standardOutputDescriptor: Int32,
        standardErrorDescriptor: Int32,
        kernel: any CommandChildKernel = SystemCommandChildKernel()
    ) {
        self.processIdentifier = processIdentifier
        self.usesProcessGroup = usesProcessGroup
        self.standardInputDescriptor = standardInputDescriptor
        self.standardOutputDescriptor = standardOutputDescriptor
        self.standardErrorDescriptor = standardErrorDescriptor
        self.kernel = kernel
    }

    func pollExit() -> CommandExit? {
        lock.lock()
        defer { lock.unlock() }
        if let capturedExit { return capturedExit }
        guard !reaped else { return nil }

        let result = kernel.wait(pid: processIdentifier, options: WNOHANG)
        if result.result == processIdentifier {
            reaped = true
            let exit = Self.decode(result.status)
            capturedExit = exit
            return exit
        }
        if result.result == 0 { return nil }
        if result.code == EINTR { return nil }
        guard result.code == ECHILD else { return nil }
        // ECHILD means another waiter reaped the child. The exit status is no
        // longer available. Report a failure, never success.
        reaped = true
        let exit = CommandExit(exitCode: 127, termSignal: nil)
        capturedExit = exit
        return exit
    }

    func signal(_ signal: Int32) {
        lock.lock()
        defer { lock.unlock() }
        guard !reaped else { return }
        if usesProcessGroup {
            _ = kernel.killGroup(processIdentifier, signal)
        } else {
            _ = kernel.killProcess(processIdentifier, signal)
        }
    }

    private static func decode(_ status: Int32) -> CommandExit {
        let term = status & 0x7f
        if term == 0 {
            return CommandExit(exitCode: (status >> 8) & 0xff, termSignal: nil)
        }
        return CommandExit(exitCode: 128 + term, termSignal: term)
    }
}

// The argv vector always starts with the executable path. The command
// arguments in PrivilegedServiceCommand are the arguments after argv[0]; a
// spawn that omits argv[0] makes tools such as cat and sleep misread their
// input. This pure function keeps that rule testable without a child process.
enum CommandArgumentVector {
    static func argv(executablePath: String, arguments: [String]) -> [String] {
        [executablePath] + arguments
    }
}

struct PosixCommandSpawner: CommandSpawning {
    // This spawner is compiled and linked but unreachable while the approval
    // gate is false. The committed tests drive the supervisor with an injected
    // spawner and start no process. A live root test of process-group signaling,
    // reaping, and a descendant that survives the group remains a release
    // blocker.
    func spawn(_ plan: CommandExecutionPlan) throws -> any SpawnedCommand {
        var inputPipe: [Int32] = [-1, -1]
        var outputPipe: [Int32] = [-1, -1]
        var errorPipe: [Int32] = [-1, -1]
        guard pipe(&inputPipe) == 0 else {
            throw PrivilegedCommandError.spawnFailed("the input pipe did not open")
        }
        guard pipe(&outputPipe) == 0 else {
            closeDescriptors(inputPipe)
            throw PrivilegedCommandError.spawnFailed("the output pipe did not open")
        }
        guard pipe(&errorPipe) == 0 else {
            closeDescriptors(inputPipe)
            closeDescriptors(outputPipe)
            throw PrivilegedCommandError.spawnFailed("the error pipe did not open")
        }
        // Move every pipe descriptor above the three standard descriptors. If
        // the coordinator started with a closed stdin, stdout, or stderr, pipe
        // could otherwise return fd 0, 1, or 2, and the child-close actions
        // would close the very descriptor that dup2 just installed.
        let originals = inputPipe + outputPipe + errorPipe
        var moved: [Int32] = []
        for descriptor in originals {
            let copy = fcntl(descriptor, F_DUPFD_CLOEXEC, 10)
            guard copy >= 0 else {
                closeDescriptors(moved)
                closeDescriptors(originals)
                throw PrivilegedCommandError.spawnFailed("a pipe descriptor cannot be moved")
            }
            moved.append(copy)
        }
        closeDescriptors(originals)
        inputPipe = [moved[0], moved[1]]
        outputPipe = [moved[2], moved[3]]
        errorPipe = [moved[4], moved[5]]
        let descriptors = moved
        for descriptor in descriptors {
            guard fcntl(descriptor, F_SETFD, FD_CLOEXEC) != -1 else {
                closeDescriptors(descriptors)
                throw PrivilegedCommandError.spawnFailed("a pipe descriptor is not close-on-exec")
            }
        }

        var actions: posix_spawn_file_actions_t?
        var attributes: posix_spawnattr_t?
        var actionsInitialized = false
        var attributesInitialized = false
        func cleanup() {
            if actionsInitialized {
                posix_spawn_file_actions_destroy(&actions)
                actionsInitialized = false
            }
            if attributesInitialized {
                posix_spawnattr_destroy(&attributes)
                attributesInitialized = false
            }
            closeDescriptors(descriptors)
        }

        guard posix_spawn_file_actions_init(&actions) == 0 else {
            cleanup()
            throw PrivilegedCommandError.spawnFailed("the spawn actions did not initialize")
        }
        actionsInitialized = true
        guard posix_spawn_file_actions_adddup2(&actions, inputPipe[0], STDIN_FILENO) == 0,
              posix_spawn_file_actions_adddup2(&actions, outputPipe[1], STDOUT_FILENO) == 0,
              posix_spawn_file_actions_adddup2(&actions, errorPipe[1], STDERR_FILENO) == 0,
              posix_spawn_file_actions_addclose(&actions, inputPipe[0]) == 0,
              posix_spawn_file_actions_addclose(&actions, inputPipe[1]) == 0,
              posix_spawn_file_actions_addclose(&actions, outputPipe[0]) == 0,
              posix_spawn_file_actions_addclose(&actions, outputPipe[1]) == 0,
              posix_spawn_file_actions_addclose(&actions, errorPipe[0]) == 0,
              posix_spawn_file_actions_addclose(&actions, errorPipe[1]) == 0
        else {
            cleanup()
            throw PrivilegedCommandError.spawnFailed("the spawn actions are not safe")
        }

        guard posix_spawnattr_init(&attributes) == 0 else {
            cleanup()
            throw PrivilegedCommandError.spawnFailed("the spawn attributes did not initialize")
        }
        attributesInitialized = true
        var defaults = sigset_t()
        sigemptyset(&defaults)
        sigaddset(&defaults, SIGTERM)
        sigaddset(&defaults, SIGINT)
        sigaddset(&defaults, SIGPIPE)
        var mask = sigset_t()
        sigemptyset(&mask)
        guard posix_spawnattr_setpgroup(&attributes, 0) == 0,
              posix_spawnattr_setsigdefault(&attributes, &defaults) == 0,
              posix_spawnattr_setsigmask(&attributes, &mask) == 0,
              posix_spawnattr_setflags(
                  &attributes,
                  Int16(
                      POSIX_SPAWN_SETPGROUP
                          | POSIX_SPAWN_SETSIGDEF
                          | POSIX_SPAWN_SETSIGMASK
                          | POSIX_SPAWN_CLOEXEC_DEFAULT
                  )
              ) == 0
        else {
            cleanup()
            throw PrivilegedCommandError.spawnFailed("the spawn attributes are not safe")
        }

        let argumentPointers = CommandArgumentVector.argv(
            executablePath: plan.executablePath,
            arguments: plan.arguments
        ).map { strdup($0) }
        let environment = PrivilegedServiceLayout.commandEnvironment
            .sorted { $0.key < $1.key }
            .map { "\($0.key)=\($0.value)" }
        let environmentPointers = environment.map { strdup($0) }
        guard argumentPointers.allSatisfy({ $0 != nil }),
              environmentPointers.allSatisfy({ $0 != nil })
        else {
            for pointer in argumentPointers { free(pointer) }
            for pointer in environmentPointers { free(pointer) }
            cleanup()
            throw PrivilegedCommandError.spawnFailed("the fixed command could not be built")
        }
        let argumentVector = argumentPointers + [nil]
        let environmentVector = environmentPointers + [nil]

        var child: pid_t = 0
        let spawned = plan.executablePath.withCString { path in
            posix_spawn(
                &child,
                path,
                &actions,
                &attributes,
                argumentVector,
                environmentVector
            )
        }

        posix_spawn_file_actions_destroy(&actions)
        actionsInitialized = false
        posix_spawnattr_destroy(&attributes)
        attributesInitialized = false
        for pointer in argumentVector { free(pointer) }
        for pointer in environmentVector { free(pointer) }

        guard spawned == 0, child > 0 else {
            closeDescriptors(descriptors)
            let reason = spawned == 0 ? "the fixed tool did not start" : String(cString: strerror(spawned))
            throw PrivilegedCommandError.spawnFailed(reason)
        }

        // The child owns the child ends after spawn. The parent keeps only the
        // write end of stdin and the read ends of stdout and stderr.
        close(inputPipe[0])
        close(outputPipe[1])
        close(errorPipe[1])

        // Both fixed tools use absolute arguments and read no relative path. A
        // future live mode should still pin the child working directory;
        // addchdir_np is deprecated on this SDK, so this build leaves the
        // inherited directory in place.

        // The attributes requested a new process group. Verify it before using
        // killpg; if the kernel did not apply it, signal the PID only. This
        // prevents a signal from reaching the coordinator's own process group.
        let usesProcessGroup = getpgid(child) == child
        return PosixSpawnedCommand(
            processIdentifier: child,
            usesProcessGroup: usesProcessGroup,
            standardInputDescriptor: inputPipe[1],
            standardOutputDescriptor: outputPipe[0],
            standardErrorDescriptor: errorPipe[0]
        )
    }

    private func closeDescriptors(_ descriptors: [Int32]) {
        for descriptor in descriptors where descriptor >= 0 {
            close(descriptor)
        }
    }
}

struct CommandProcessLimits: Sendable {
    static let standard = CommandProcessLimits(
        terminationGrace: 2,
        killGrace: 2,
        drainGrace: 1,
        joinGrace: 0.5
    )

    let terminationGrace: TimeInterval
    let killGrace: TimeInterval
    let drainGrace: TimeInterval
    let joinGrace: TimeInterval
}

// Bounded command supervision. Every wait after the initial timeout has a fixed
// deadline. Output readers poll with a short interval and stop when asked, so a
// descendant that keeps a pipe open cannot hold the transaction forever. The
// direct child is signaled before waitpid reaps it, and never after.
//
// These commands are not the tunnel engine. A stuck installer tool gets SIGTERM
// and a fixed grace, then SIGKILL to its process group. The engine's no-SIGKILL
// rule does not apply to this boundary.
struct CommandProcessSupervisor: Sendable {
    private let spawner: any CommandSpawning
    private let limits: CommandProcessLimits

    // Internal test seam. Production code uses the defaults. The tests inject a
    // fake spawner and short limits, and start no child process.
    init(
        spawner: any CommandSpawning = PosixCommandSpawner(),
        limits: CommandProcessLimits = .standard
    ) {
        self.spawner = spawner
        self.limits = limits
    }

    func run(_ plan: CommandExecutionPlan) throws -> PrivilegedCommandResult {
        try Self.validate(plan)

        let child = try spawner.spawn(plan)
        let capture = CommandOutputCapture(limit: plan.maximumOutputBytes)
        let outputPump = CommandPipePump(
            descriptor: child.standardOutputDescriptor,
            stream: .standardOutput,
            capture: capture
        )
        let errorPump = CommandPipePump(
            descriptor: child.standardErrorDescriptor,
            stream: .standardError,
            capture: capture
        )
        let inputWriter = CommandInputWriter(
            descriptor: child.standardInputDescriptor,
            data: plan.standardInput ?? Data()
        )
        outputPump.start()
        errorPump.start()
        inputWriter.start()

        let deadline = MonotonicClock.now() + plan.timeout
        var observedExit: CommandExit?
        while true {
            if let exit = child.pollExit() {
                observedExit = exit
                break
            }
            if capture.hasOverflowed { break }
            if MonotonicClock.now() >= deadline { break }
            usleep(10_000)
        }

        guard let exit = observedExit else {
            let overflowed = capture.hasOverflowed
            inputWriter.stop()
            _ = inputWriter.wait(limits.joinGrace)
            terminate(child)
            outputPump.stop()
            errorPump.stop()
            _ = outputPump.wait(limits.joinGrace)
            _ = errorPump.wait(limits.joinGrace)
            if overflowed { throw PrivilegedCommandError.outputTooLarge }
            throw PrivilegedCommandError.timedOut
        }

        // The direct child has exited. Stop an unfinished input writer, then
        // give the readers one fixed drain grace. A descendant that still holds
        // a pipe produces a bounded stop, not an unbounded wait.
        inputWriter.stop()
        _ = inputWriter.wait(limits.joinGrace)
        var outputDrained = outputPump.wait(limits.drainGrace)
        var errorDrained = errorPump.wait(limits.drainGrace)
        if !outputDrained {
            outputPump.stop()
            outputDrained = outputPump.wait(limits.joinGrace)
        }
        if !errorDrained {
            errorPump.stop()
            errorDrained = errorPump.wait(limits.joinGrace)
        }

        if capture.hasOverflowed { throw PrivilegedCommandError.outputTooLarge }
        // A pipe that is still open after the direct child exits cannot prove
        // that all output was captured. Fail closed instead of trusting a
        // prefix.
        if !outputDrained || !errorDrained || !outputPump.reachedEOF || !errorPump.reachedEOF {
            throw PrivilegedCommandError.outputIncomplete
        }
        if exit.exitCode == 0, inputWriter.failed || !inputWriter.wroteAllInput {
            throw PrivilegedCommandError.inputWriteFailed
        }

        let snapshot = capture.snapshot()
        return PrivilegedCommandResult(
            exitCode: exit.exitCode,
            standardOutput: snapshot.output,
            standardError: snapshot.error
        )
    }

    static func validate(_ plan: CommandExecutionPlan) throws {
        guard plan.executablePath.hasPrefix("/"),
              !plan.executablePath.contains("\0")
        else { throw CommandPlanError.pathNotAbsolute }
        guard plan.executablePath.utf8.count <= PrivilegedServiceLayout.maximumToolPathBytes else {
            throw CommandPlanError.pathTooLong
        }
        guard plan.arguments.count <= PrivilegedServiceLayout.maximumArgumentCount else {
            throw CommandPlanError.argumentCount
        }
        var argumentBytes = 0
        for argument in plan.arguments {
            guard !argument.isEmpty,
                  !argument.contains("\0"),
                  !argument.contains("\n"),
                  !argument.contains("\r")
            else { throw CommandPlanError.invalidArgument }
            argumentBytes += argument.utf8.count
        }
        guard argumentBytes <= PrivilegedServiceLayout.maximumArgumentBytes else {
            throw CommandPlanError.argumentBytes
        }
        if let input = plan.standardInput,
           input.count > PrivilegedServiceLayout.maximumStandardInputBytes
        {
            throw CommandPlanError.inputTooLarge
        }
        guard plan.maximumOutputBytes > 0,
              plan.maximumOutputBytes <= PrivilegedServiceLayout.maximumCommandOutputBytes
        else { throw CommandPlanError.outputLimit }
        guard plan.timeout > 0, plan.timeout <= PrivilegedServiceLayout.maximumTimeout else {
            throw CommandPlanError.timeout
        }
    }

    private func terminate(_ child: any SpawnedCommand) {
        child.signal(SIGTERM)
        if waitForExit(child, grace: limits.terminationGrace) != nil { return }
        child.signal(SIGKILL)
        _ = waitForExit(child, grace: limits.killGrace)
        // If SIGKILL does not produce a wait status within the fixed grace,
        // return without blocking. That child remains unreaped. A live root
        // test must prove this path is unreachable for the two fixed tools.
    }

    private func waitForExit(
        _ child: any SpawnedCommand,
        grace: TimeInterval
    ) -> CommandExit? {
        let deadline = MonotonicClock.now() + grace
        while true {
            if let exit = child.pollExit() { return exit }
            if MonotonicClock.now() >= deadline { return nil }
            usleep(10_000)
        }
    }
}

private enum CommandStream {
    case standardOutput
    case standardError
}

private final class CommandOutputCapture: @unchecked Sendable {
    private let lock = NSLock()
    private let limit: Int
    private var output = Data()
    private var error = Data()
    private var total = 0
    private var overflow = false

    init(limit: Int) {
        self.limit = limit
    }

    func append(_ stream: CommandStream, _ data: Data) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !overflow else { return false }
        guard total + data.count <= limit else {
            overflow = true
            return false
        }
        total += data.count
        switch stream {
        case .standardOutput:
            output.append(data)
        case .standardError:
            error.append(data)
        }
        return true
    }

    var hasOverflowed: Bool {
        lock.lock()
        defer { lock.unlock() }
        return overflow
    }

    func snapshot() -> (output: Data, error: Data) {
        lock.lock()
        defer { lock.unlock() }
        return (output, error)
    }
}

private final class CommandFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false

    func set() {
        lock.lock()
        value = true
        lock.unlock()
    }

    var isSet: Bool {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}

// Poll with a short timeout, never a blocking read. The stop flag is visible
// within one poll interval even when a descendant keeps the write end open.
private final class CommandPipePump: @unchecked Sendable {
    private let readDescriptor: Int32
    private let stream: CommandStream
    private let capture: CommandOutputCapture
    private let stopped = CommandFlag()
    private let eof = CommandFlag()
    private let finished = DispatchSemaphore(value: 0)

    init(descriptor: Int32, stream: CommandStream, capture: CommandOutputCapture) {
        self.readDescriptor = descriptor
        self.stream = stream
        self.capture = capture
    }

    func start() {
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            run()
        }
    }

    func stop() {
        stopped.set()
    }

    func wait(_ timeout: TimeInterval) -> Bool {
        finished.wait(timeout: .now() + timeout) == .success
    }

    var reachedEOF: Bool { eof.isSet }

    private func run() {
        defer {
            close(readDescriptor)
            finished.signal()
        }
        let flags = fcntl(readDescriptor, F_GETFL)
        guard flags >= 0, fcntl(readDescriptor, F_SETFL, flags | O_NONBLOCK) != -1 else {
            return
        }
        var buffer = [UInt8](repeating: 0, count: 16 * 1024)
        while !stopped.isSet {
            var descriptor = pollfd(fd: readDescriptor, events: Int16(POLLIN), revents: 0)
            let ready = poll(&descriptor, 1, 50)
            if ready < 0 {
                if errno == EINTR { continue }
                return
            }
            if ready == 0 { continue }
            let events = descriptor.revents
            if events & Int16(POLLNVAL) != 0 { return }
            if events & Int16(POLLIN) == 0,
               events & Int16(POLLHUP) == 0,
               events & Int16(POLLERR) == 0
            {
                continue
            }
            let count = buffer.withUnsafeMutableBytes { bytes in
                read(readDescriptor, bytes.baseAddress, bytes.count)
            }
            if count > 0 {
                if !capture.append(stream, Data(buffer[0..<count])) { return }
                continue
            }
            if count == 0 {
                eof.set()
                return
            }
            if errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR {
                continue
            }
            return
        }
    }
}

private final class CommandInputWriter: @unchecked Sendable {
    private let writeDescriptor: Int32
    private let data: Data
    private let stopped = CommandFlag()
    private let finished = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var didFail = false
    private var didWriteAll = false

    init(descriptor: Int32, data: Data) {
        self.writeDescriptor = descriptor
        self.data = data
        self.didWriteAll = data.isEmpty
    }

    func start() {
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            run()
        }
    }

    func stop() {
        stopped.set()
    }

    func wait(_ timeout: TimeInterval) -> Bool {
        finished.wait(timeout: .now() + timeout) == .success
    }

    var failed: Bool {
        lock.lock()
        defer { lock.unlock() }
        return didFail
    }

    var wroteAllInput: Bool {
        lock.lock()
        defer { lock.unlock() }
        return didWriteAll
    }

    private func run() {
        defer {
            close(writeDescriptor)
            finished.signal()
        }
        guard !data.isEmpty else { return }
        // A child can exit before it reads stdin. Without this flag, the parent
        // would receive SIGPIPE and die in the middle of the transaction.
        guard fcntl(writeDescriptor, F_SETNOSIGPIPE, 1) != -1 else {
            recordFailure()
            return
        }
        let flags = fcntl(writeDescriptor, F_GETFL)
        guard flags >= 0, fcntl(writeDescriptor, F_SETFL, flags | O_NONBLOCK) != -1 else {
            recordFailure()
            return
        }
        var offset = 0
        while offset < data.count, !stopped.isSet {
            var descriptor = pollfd(fd: writeDescriptor, events: Int16(POLLOUT), revents: 0)
            let ready = poll(&descriptor, 1, 50)
            if ready < 0 {
                if errno == EINTR { continue }
                recordFailure()
                return
            }
            if ready == 0 { continue }
            if descriptor.revents & Int16(POLLNVAL) != 0 {
                recordFailure()
                return
            }
            if descriptor.revents & Int16(POLLERR) != 0 {
                recordFailure()
                return
            }
            if stopped.isSet { return }
            let written = data.withUnsafeBytes { bytes -> Int in
                guard let base = bytes.baseAddress else { return 0 }
                return write(
                    writeDescriptor,
                    base.advanced(by: offset),
                    min(data.count - offset, 16 * 1024)
                )
            }
            if written > 0 {
                offset += written
                if offset == data.count { markWroteAll() }
                continue
            }
            if written < 0, errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR {
                continue
            }
            recordFailure()
            return
        }
    }

    private func markWroteAll() {
        lock.lock()
        didWriteAll = true
        lock.unlock()
    }

    private func recordFailure() {
        lock.lock()
        didFail = true
        lock.unlock()
    }
}

private enum MonotonicClock {
    static func now() -> TimeInterval {
        var value = timespec()
        clock_gettime(CLOCK_MONOTONIC, &value)
        return TimeInterval(value.tv_sec) + TimeInterval(value.tv_nsec) / 1_000_000_000
    }
}
