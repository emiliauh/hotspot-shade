import Foundation
import Darwin
import HotspotShadeKit

// Clear the helper's durable cleanup block on a preview host, after the host
// shows no sign that a HotspotShade engine still owns a route.
//
// The helper records `cleanup-blocked` and keeps `engine-session` when it
// cannot prove that an engine removed its routes. No helper path removes
// them. This command is the reviewed human step for a preview host. It
// removes the two records, and only these two, when every check passes:
//
// - no protected helper process runs, so no helper holds an in-memory block,
//   a session, or a retained lock;
// - no root process named `hotspotshade` runs, so no helper or direct engine
//   remains;
// - `netstat -rn` shows no 0/1 or 128.0/1 IPv4 route through a utun and no
//   IPv6 2000::/3 route on any interface (the engine's blackhole uses lo0);
// - no file journal, service journal, or start journal is present;
// - the coordinator holds the exclusive lease on every start-exclusion lock,
//   so no participating start is starting, running, or stopping.
//
// It never deletes, adds, or changes a route or an interface, and never
// signals a process. Another VPN can use the same route shapes; the command
// refuses then too, because it cannot tell them apart. A check that cannot
// complete is a refusal.
public enum PreviewClearCheck: String, CaseIterable, Equatable, Sendable {
    case noHelperProcess = "no protected helper process is running"
    case noRootEngineProcess = "no root HotspotShade engine process is running"
    case noOwnedRoute = "netstat shows no 0/1 or 128.0/1 route through a utun and no 2000::/3 route"
    case noJournal = "no file, service, or start journal is present"
    case exclusionLeaseHeld = "the exclusive start-exclusion lease is held, so no session is starting, running, or stopping"
}

public struct PreviewClearReport: Equatable, Sendable {
    public let checks: [PreviewClearCheck]
    public let removed: [String]
    public let alreadyAbsent: [String]
}

public enum PreviewClearError: Error, Equatable, CustomStringConvertible {
    case notApproved
    case requiresRoot
    case helperRunning
    case rootEngineRunning
    case processListUnavailable
    case ownedRoutePresent([String])
    case routeTableUnavailable(String)
    case journalPresent(String)
    case lockUnavailable
    case lockUnsafe(String)
    case stateUnsafe(String)
    case removalNotConfirmed(String)

    public var description: String {
        switch self {
        case .notApproved:
            return "Clearing the cleanup block is not approved in this build."
        case .requiresRoot:
            return "Clearing the cleanup block needs the root coordinator."
        case .helperRunning:
            return "The protected helper is running. Stop it first with "
                + "sudo launchctl bootout system/dev.hotspotshade.mac.helper, then check again."
        case .rootEngineRunning:
            return "A root HotspotShade engine is running. Turn the tunnel off and wait for it to exit. "
                + "Do not send SIGKILL."
        case .processListUnavailable:
            return "The process list cannot be read, so a running engine cannot be ruled out."
        case .ownedRoutePresent(let routes):
            return "A route that HotspotShade may own is present: \(routes.joined(separator: "; ")). "
                + "Do not delete it by guesswork. Stop and escalate."
        case .routeTableUnavailable(let why):
            return "The route table cannot be read (\(why)), so leftover routes cannot be ruled out."
        case .journalPresent(let name):
            return "\(name) is present. Use the matching recovery command first."
        case .lockUnavailable:
            return "A start participant holds the start-exclusion lock, so a session may be starting, "
                + "running, or stopping."
        case .lockUnsafe(let why):
            return "The start-exclusion lock cannot be used: \(why)."
        case .stateUnsafe(let why):
            return "The state directory is not safe to change: \(why)."
        case .removalNotConfirmed(let name):
            return "\(name) is still present after its removal."
        }
    }
}

// One process from the kernel process table.
public struct HostProcess: Equatable, Sendable {
    public let pid: Int32
    public let effectiveUserID: UInt32
    // The kernel command name, at most 16 bytes.
    public let command: String
    public init(pid: Int32, effectiveUserID: UInt32, command: String) {
        self.pid = pid
        self.effectiveUserID = effectiveUserID
        self.command = command
    }
}

public protocol HostProcessListing: Sendable {
    func processes() throws -> [HostProcess]
}

public protocol HostRouteTableReading: Sendable {
    // The text of `netstat -rn -f inet` and `netstat -rn -f inet6`.
    func routeTables() throws -> (inet: String, inet6: String)
}

public struct KernelProcessList: HostProcessListing {
    public init() {}

    public func processes() throws -> [HostProcess] {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        for _ in 0..<4 {
            var size = 0
            guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 0 else {
                throw PreviewClearError.processListUnavailable
            }
            // Room for processes that start between the two calls.
            size += size / 4
            let count = size / MemoryLayout<kinfo_proc>.stride
            var entries = [kinfo_proc](repeating: kinfo_proc(), count: count)
            let result = entries.withUnsafeMutableBytes { buffer -> Int32 in
                sysctl(&mib, 3, buffer.baseAddress, &size, nil, 0)
            }
            if result != 0 {
                if errno == ENOMEM { continue }
                throw PreviewClearError.processListUnavailable
            }
            let filled = size / MemoryLayout<kinfo_proc>.stride
            return entries.prefix(filled).map { entry in
                var name = entry.kp_proc.p_comm
                let command = withUnsafeBytes(of: &name) { raw -> String in
                    let bytes = raw.prefix { $0 != 0 }
                    return String(decoding: bytes, as: UTF8.self)
                }
                return HostProcess(
                    pid: entry.kp_proc.p_pid,
                    effectiveUserID: entry.kp_eproc.e_ucred.cr_uid,
                    command: command
                )
            }
        }
        throw PreviewClearError.processListUnavailable
    }
}

// Runs the fixed netstat binary with fixed arguments. No shell, no input from
// a file or the environment, bounded output.
public struct NetstatRouteTable: HostRouteTableReading {
    public static let executable = "/usr/sbin/netstat"
    public static let maximumBytes = 4 << 20

    public init() {}

    public func routeTables() throws -> (inet: String, inet6: String) {
        (try run(["-rn", "-f", "inet"]), try run(["-rn", "-f", "inet6"]))
    }

    private func run(_ arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: Self.executable)
        process.arguments = arguments
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"]
        let output = Pipe()
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        process.standardInput = FileHandle.nullDevice
        do {
            try process.run()
        } catch {
            throw PreviewClearError.routeTableUnavailable("netstat did not start")
        }
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationReason == .exit, process.terminationStatus == 0 else {
            throw PreviewClearError.routeTableUnavailable("netstat failed")
        }
        guard data.count <= Self.maximumBytes, let text = String(data: data, encoding: .utf8) else {
            throw PreviewClearError.routeTableUnavailable("the netstat output is not readable")
        }
        return text
    }
}

public enum PreviewOwnedRoutes {
    // The routes a HotspotShade engine adds, as `netstat -rn` prints them.
    // IPv4: 0/1 and 128.0/1 through a utun. IPv6: 2000::/3 on any interface,
    // since the engine's blackhole uses lo0 and a tunnel route uses a utun.
    public static func findings(inet: String, inet6: String) -> [String] {
        var found: [String] = []
        for line in inet.split(separator: "\n") {
            let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            guard fields.count >= 4, ["0/1", "128.0/1"].contains(fields[0]) else { continue }
            if let interface = fields.dropFirst(2).first(where: { $0.hasPrefix("utun") }) {
                found.append("\(fields[0]) via \(interface)")
            }
        }
        for line in inet6.split(separator: "\n") {
            let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            guard let destination = fields.first,
                  destination == "2000::/3" || destination.hasPrefix("2000::/3%")
            else { continue }
            let interface = fields.count >= 4 ? fields[3] : "an unknown interface"
            found.append("2000::/3 via \(interface)")
        }
        return found
    }
}

public final class PreviewCleanupBlockClear: @unchecked Sendable {
    public static let helperCommandPrefix = "dev.hotspotshade"
    public static let engineCommand = "hotspotshade"
    static let records = [
        InstallLockLayout.cleanupMarkerName,
        InstallLockLayout.launchIntentName,
    ]
    static let recordMode: UInt16 = 0o600
    static let recordMaximumBytes = 4096

    private let tree: InstallTree
    private let processes: HostProcessListing
    private let routes: HostRouteTableReading

    init(tree: InstallTree, processes: HostProcessListing, routes: HostRouteTableReading) {
        self.tree = tree
        self.processes = processes
        self.routes = routes
    }

    // The root entry point. The same approval gate, root requirement, and
    // coordinator signing identity as the other preview commands apply.
    static func systemPreview() throws -> PreviewCleanupBlockClear {
        guard HelperRequirement.isLocalPreview, CoordinatorPolicy.localPreviewInstallationApproved
        else { throw PreviewClearError.notApproved }
        guard geteuid() == 0 else { throw PreviewClearError.requiresRoot }
        _ = try InstallerSelfIdentity.teamIdentifier()
        let tree = try InstallTree(
            rootPath: "/",
            expectedOwner: 0,
            expectedGroup: 0,
            syncHooks: .production,
            usePrivateVar: true
        )
        return PreviewCleanupBlockClear(
            tree: tree,
            processes: KernelProcessList(),
            routes: NetstatRouteTable()
        )
    }

    public func run() throws -> PreviewClearReport {
        var checks: [PreviewClearCheck] = []
        try refuseRunningParticipants()
        checks += [.noHelperProcess, .noRootEngineProcess]
        try refuseOwnedRoutes()
        checks.append(.noOwnedRoute)
        try refuseJournals()
        checks.append(.noJournal)

        let statePath: String
        do {
            guard try tree.directoryMode(InstallLockLayout.stateDirectoryRelative) == 0o700 else {
                throw PreviewClearError.stateUnsafe("the state directory mode is not 0700")
            }
            statePath = try tree.path(for: InstallLockLayout.stateDirectoryRelative)
        } catch let error as PreviewClearError {
            throw error
        } catch InstallTreeError.missing {
            return PreviewClearReport(checks: checks, removed: [], alreadyAbsent: Self.records)
        } catch {
            throw PreviewClearError.stateUnsafe("the state directory cannot be inspected")
        }
        let lease: InstallExclusionLease
        do {
            lease = try InstallExclusionLease.acquire(parentDirectory: statePath, expectedOwner: tree.owner)
        } catch InstallLockError.busy {
            throw PreviewClearError.lockUnavailable
        } catch let error as InstallLockError {
            throw PreviewClearError.lockUnsafe(error.description)
        } catch {
            throw PreviewClearError.lockUnsafe("the lease cannot be acquired")
        }
        defer { lease.release() }
        checks.append(.exclusionLeaseHeld)
        // Under the lease nothing new can start. Repeat the checks that a
        // participant could have changed before the lease was taken.
        try refuseRunningParticipants()
        try refuseOwnedRoutes()
        try refuseJournals()

        var removed: [String] = []
        var absent: [String] = []
        for name in Self.records {
            let relative = InstallLockLayout.stateDirectoryRelative + "/" + name
            let snapshot: FileSnapshot?
            do {
                snapshot = try tree.snapshot(relative, maximumBytes: Self.recordMaximumBytes)
            } catch {
                throw PreviewClearError.stateUnsafe("\(name) is not a safe private file")
            }
            guard let snapshot else {
                absent.append(name)
                continue
            }
            do {
                try tree.removeFile(relative, expectedDigest: snapshot.sha256, expectedMode: Self.recordMode)
            } catch {
                throw PreviewClearError.stateUnsafe("\(name) could not be removed safely")
            }
            // Read back: the name must be gone.
            let stillThere: Bool
            do {
                stillThere = try tree.entryExists(relative)
            } catch {
                throw PreviewClearError.removalNotConfirmed(name)
            }
            if stillThere { throw PreviewClearError.removalNotConfirmed(name) }
            removed.append(name)
        }
        return PreviewClearReport(checks: checks, removed: removed, alreadyAbsent: absent)
    }

    private func refuseRunningParticipants() throws {
        let list: [HostProcess]
        do {
            list = try processes.processes()
        } catch {
            throw PreviewClearError.processListUnavailable
        }
        guard !list.isEmpty else { throw PreviewClearError.processListUnavailable }
        if list.contains(where: { $0.command.hasPrefix(Self.helperCommandPrefix) }) {
            throw PreviewClearError.helperRunning
        }
        if list.contains(where: { $0.command == Self.engineCommand && $0.effectiveUserID == 0 }) {
            throw PreviewClearError.rootEngineRunning
        }
    }

    private func refuseOwnedRoutes() throws {
        let tables: (inet: String, inet6: String)
        do {
            tables = try routes.routeTables()
        } catch let error as PreviewClearError {
            throw error
        } catch {
            throw PreviewClearError.routeTableUnavailable("netstat failed")
        }
        // A table without its header is not a route table read.
        guard tables.inet.contains("Destination"), tables.inet6.contains("Destination") else {
            throw PreviewClearError.routeTableUnavailable("the netstat output has no route table")
        }
        let found = PreviewOwnedRoutes.findings(inet: tables.inet, inet6: tables.inet6)
        if !found.isEmpty { throw PreviewClearError.ownedRoutePresent(found) }
    }

    private func refuseJournals() throws {
        let fixed: [(String, String)] = [
            (InstallJournalStore.relativePath, "A file transaction journal"),
            (ServiceJournalStore.relativePath, "A service transaction journal"),
            (StartJournalProbe.relativePath, "A start journal"),
        ]
        for (relative, name) in fixed {
            do {
                if try tree.entryExists(relative) { throw PreviewClearError.journalPresent(name) }
            } catch let error as PreviewClearError {
                throw error
            } catch {
                throw PreviewClearError.stateUnsafe("\(name.lowercased()) cannot be inspected")
            }
        }
    }
}
