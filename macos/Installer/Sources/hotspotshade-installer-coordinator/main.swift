import Foundation
import Darwin
import HotspotShadeInstallerCore

// System preview commands require a separate test-candidate build flag. The
// package preinstall still refuses and the manifest records approval false.
let previewUsage: String
#if HOTSPOTSHADE_LOCAL_PREVIEW && HOTSPOTSHADE_SYSTEM_PREVIEW_CANDIDATE
previewUsage = "The local system-preview test commands require root. They have not been verified on a live system."
#else
previewUsage = "The preview system commands are disabled in this build and require root if enabled after review."
#endif
let usage = """
usage:
  hotspotshade-installer-coordinator self-check
  hotspotshade-installer-coordinator preview-policy
  hotspotshade-installer-coordinator verify-preview --app PATH --payload PATH --manifest PATH
  hotspotshade-installer-coordinator preview-install --app PATH --payload PATH --manifest PATH
  hotspotshade-installer-coordinator preview-resume --app PATH --payload PATH --manifest PATH
  hotspotshade-installer-coordinator preview-recover-files
  hotspotshade-installer-coordinator preview-recover-service
  hotspotshade-installer-coordinator preview-status
  hotspotshade-installer-coordinator preview-uninstall
  hotspotshade-installer-coordinator sandbox-init --sandbox-root PATH
  hotspotshade-installer-coordinator verify --payload PATH --manifest PATH --team TEAM
  hotspotshade-installer-coordinator install --sandbox-root PATH --payload PATH --manifest PATH --team TEAM
  hotspotshade-installer-coordinator recover --sandbox-root PATH
  hotspotshade-installer-coordinator status --sandbox-root PATH

\(CoordinatorPolicy.refusal)
Every sandbox root must be a marked, private directory under the user's
temporary directory. Sandbox commands refuse root. \(previewUsage)
"""

struct UsageError: Error, CustomStringConvertible {
    let description: String
}

struct Arguments {
    let values: [String: String]

    init(_ raw: [String], allowed: Set<String>, required: Set<String>) throws {
        var parsed: [String: String] = [:]
        var index = 0
        while index < raw.count {
            let name = raw[index]
            guard name.hasPrefix("--"), name.count > 2 else {
                throw UsageError(description: "unexpected argument: \(name)")
            }
            let key = String(name.dropFirst(2))
            guard allowed.contains(key) else {
                throw UsageError(description: "unknown option: \(name)")
            }
            guard index + 1 < raw.count else {
                throw UsageError(description: "missing value for \(name)")
            }
            guard parsed[key] == nil else {
                throw UsageError(description: "duplicate option: \(name)")
            }
            parsed[key] = raw[index + 1]
            index += 2
        }
        for key in required where parsed[key] == nil {
            throw UsageError(description: "missing required option: --\(key)")
        }
        self.values = parsed
    }

    func value(_ key: String) -> String? { values[key] }
}

func refuse(_ message: String, code: Int32 = 1) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(code)
}

func readManifest(_ path: String) throws -> InstallerManifest {
    let descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
    guard descriptor >= 0 else { throw UsageError(description: "the manifest cannot be opened") }
    defer { close(descriptor) }
    var status = stat()
    guard fstat(descriptor, &status) == 0, status.st_mode & S_IFMT == S_IFREG,
          status.st_size > 0, status.st_size <= 1 << 20
    else { throw UsageError(description: "the manifest is not a bounded regular file") }
    var data = Data()
    var buffer = [UInt8](repeating: 0, count: 16384)
    while true {
        let count = buffer.withUnsafeMutableBytes { read(descriptor, $0.baseAddress, $0.count) }
        if count < 0 {
            if errno == EINTR { continue }
            throw UsageError(description: "the manifest cannot be read")
        }
        if count == 0 { break }
        guard data.count + count <= 1 << 20 else {
            throw UsageError(description: "the manifest is not a bounded regular file")
        }
        data.append(contentsOf: buffer[0..<count])
    }
    guard data.count == Int(status.st_size) else { throw UsageError(description: "the manifest changed") }
    return try JSONDecoder().decode(InstallerManifest.self, from: data)
}

func execute(_ command: String, _ raw: [String]) throws {
    switch command {
    case "self-check":
        guard raw.isEmpty else { throw UsageError(description: "self-check takes no options") }
        _ = try InstallerSelfIdentity.teamIdentifier()
        print("coordinator signature verified")

    case "preview-policy":
        guard raw.isEmpty else { throw UsageError(description: "preview-policy takes no options") }
        _ = try InstallerSelfIdentity.teamIdentifier()
        print(CoordinatorPolicy.localPreviewInstallationApproved
            ? "system-preview: enabled" : "system-preview: disabled")

    case "verify-preview":
        let arguments = try Arguments(
            raw, allowed: ["app", "payload", "manifest"], required: ["app", "payload", "manifest"]
        )
        let source = try PreviewIdentityBinding.source(
            appPath: arguments.value("app")!, payloadRoot: arguments.value("payload")!,
            manifest: readManifest(arguments.value("manifest")!)
        )
        let operations = try CoordinatorPayloadValidator.validate(
            source, validator: InstallerValidator(), expectedOwner: UInt32(geteuid())
        )
        print("preview verified: version \(source.manifest.version), \(operations.count) files")

    case "preview-install", "preview-resume":
        let arguments = try Arguments(
            raw, allowed: ["app", "payload", "manifest"], required: ["app", "payload", "manifest"]
        )
        let action: PreviewSystemInstaller.Action
        switch command {
        case "preview-install": action = .install
        case "preview-resume": action = .resume
        default: action = .resume
        }
        try PreviewSystemInstaller.run(
            action, appPath: arguments.value("app")!, payloadRoot: arguments.value("payload")!,
            manifest: readManifest(arguments.value("manifest")!)
        )
        print("preview operation completed")

    case "preview-recover-files":
        guard raw.isEmpty else { throw UsageError(description: "preview-recover-files takes no options") }
        switch try PreviewSystemInstaller.recoverFiles() {
        case .nothingToRecover: print("No file transaction needs recovery.")
        case .rolledBack: print("The file transaction was rolled back.")
        case .finishedCommit: print("The committed file transaction was completed.")
        }

    case "preview-recover-service":
        guard raw.isEmpty else { throw UsageError(description: "preview-recover-service takes no options") }
        switch try PreviewSystemInstaller.recoverService() {
        case .nothingToRecover: print("No service transaction needs recovery.")
        case .finishedInstall, .finishedCommit: print("The service transaction was completed.")
        case .finishedRollback: print("The service transaction was rolled back.")
        }

    case "preview-status":
        guard raw.isEmpty else { throw UsageError(description: "preview-status takes no options") }
        let status = try PreviewSystemInstaller.status()
        print("file journal: \(status.journalPhase?.rawValue ?? "none")")
        print("service journal: \(status.serviceJournalPresent ? "present" : "absent")")
        print("cleanup block: \(status.cleanupBlocked ? "present" : "absent")")
        print("launch intent: \(status.launchIntentPresent ? "present" : "absent")")
        print("start journal: \(status.startJournalPresent ? "present" : "absent")")
        print("backup orphans: \(status.backupOrphans.isEmpty ? "none" : "present")")

    case "preview-uninstall":
        guard raw.isEmpty else { throw UsageError(description: "preview-uninstall takes no options") }
        let report = try PreviewSystemInstaller.uninstall()
        if report.changedAnything {
            if report.removedLaunchdJob { print("removed the launch daemon job") }
            if report.removedAuthorizationRight { print("removed the start right") }
            for relative in report.removedFiles { print("removed \(relative)") }
            for relative in report.removedEmptyDirectories { print("removed empty \(relative)") }
        } else {
            print("No preview service, start right, or installed file is present.")
        }
        for relative in report.keptNonEmptyDirectories {
            print("kept non-empty \(relative)")
        }
        print("The installed app and the placed preview tree are not part of this removal.")
        print("The state directory, its lock files, /var/lib/hotspotshade, and /Library/PrivilegedHelperTools are kept.")

    case "sandbox-init":
        let arguments = try Arguments(
            raw,
            allowed: ["sandbox-root"],
            required: ["sandbox-root"]
        )
        let root = try CoordinatorSandboxPolicy.createMarker(arguments.value("sandbox-root")!)
        print("sandbox root marked: \(root)")

    case "verify":
        let arguments = try Arguments(
            raw,
            allowed: ["payload", "manifest", "team"],
            required: ["payload", "manifest", "team"]
        )
        let team = arguments.value("team")!
        let manifest = try readManifest(arguments.value("manifest")!)
        let operations = try CoordinatorPayloadValidator.validate(
            CoordinatorSource(
                payloadRoot: arguments.value("payload")!,
                manifest: manifest,
                expectedTeamIdentifier: team
            ),
            validator: InstallerValidator(),
            expectedOwner: UInt32(geteuid())
        )
        print("verify ok: version \(manifest.version), \(operations.count) files")

    case "install":
        let arguments = try Arguments(
            raw,
            allowed: ["sandbox-root", "payload", "manifest", "team"],
            required: ["sandbox-root", "payload", "manifest", "team"]
        )
        let manifest = try readManifest(arguments.value("manifest")!)
        let coordinator = try InstallCoordinator(sandboxRoot: arguments.value("sandbox-root")!)
        let outcome = try coordinator.install(
            source: CoordinatorSource(
                payloadRoot: arguments.value("payload")!,
                manifest: manifest,
                expectedTeamIdentifier: arguments.value("team")!
            )
        )
        print(
            "install ok: transaction \(outcome.transactionID), version \(outcome.version), "
                + "\(outcome.fileCount) files"
        )

    case "recover":
        let arguments = try Arguments(
            raw,
            allowed: ["sandbox-root"],
            required: ["sandbox-root"]
        )
        let coordinator = try InstallCoordinator(sandboxRoot: arguments.value("sandbox-root")!)
        switch try coordinator.recover() {
        case .nothingToRecover:
            print("recover: nothing to recover")
        case .rolledBack(let transactionID, let version):
            print("recover: rolled back transaction \(transactionID) for version \(version)")
        case .finishedCommit(let transactionID, let version):
            print("recover: finished committed transaction \(transactionID) for version \(version)")
        }

    case "status":
        let arguments = try Arguments(
            raw,
            allowed: ["sandbox-root"],
            required: ["sandbox-root"]
        )
        let coordinator = try InstallCoordinator(sandboxRoot: arguments.value("sandbox-root")!)
        let status = try coordinator.status()
        print("journal: \(status.journalPhase?.rawValue ?? "none")")
        print("service journal: \(status.serviceJournalPresent ? "present" : "absent")")
        print("cleanup block: \(status.cleanupBlocked ? "present" : "absent")")
        print("launch intent: \(status.launchIntentPresent ? "present" : "absent")")
        print("start journal: \(status.startJournalPresent ? "present" : "absent")")
        if let matches = status.startJournalLockMatchesHeldLock {
            print("start journal lock: \(matches ? "a held lock" : "an unknown lock inode")")
        }
        print("lock files: \(status.presentLockFileNames.isEmpty ? "none" : status.presentLockFileNames.joined(separator: ", "))")
        print("backup orphans: \(status.backupOrphans.isEmpty ? "none" : status.backupOrphans.joined(separator: ", "))")

    default:
        throw UsageError(description: "unknown command: \(command)")
    }
}

let arguments = Array(CommandLine.arguments.dropFirst())
if arguments.isEmpty || arguments == ["--help"] {
    print(usage)
    exit(0)
}
// self-check only reads the running process signature. It also needs to be
// usable as root when preparing the signed system-preview coordinator.
let rootAllowedCommands = [
    "self-check",
    "preview-install", "preview-resume", "preview-recover-files",
    "preview-recover-service", "preview-status", "preview-uninstall",
]
guard geteuid() != 0 || rootAllowedCommands.contains(arguments[0]) else {
    refuse("The install coordinator must not run as root.")
}
do {
    try execute(arguments[0], Array(arguments.dropFirst()))
} catch let error as UsageError {
    refuse(error.description + "\n\n" + usage, code: 2)
} catch let error as CoordinatorError {
    refuse("HotspotShade coordinator refused: \(error.description)")
} catch let error as CombinedInstallError {
    refuse("HotspotShade coordinator refused: \(error.description)")
} catch let error as ServiceTransactionError {
    refuse("HotspotShade coordinator refused: \(error.description)")
} catch let error as PreviewCleanupError {
    refuse("HotspotShade coordinator refused: \(error.description)")
} catch let error as InstallerError {
    refuse("HotspotShade coordinator refused: \(error.description)")
} catch is PreviewIdentityBinding.BindingError {
    refuse("HotspotShade coordinator refused: the coordinator, app, and preview manifest must use the same signing team.")
} catch let error as InstallerSelfIdentity.IdentityError {
    switch error {
    case .unavailable:
        refuse("HotspotShade coordinator refused: the coordinator's signing identity could not be read.")
    case .rejected:
        refuse("HotspotShade coordinator refused: the coordinator's signature does not meet the signing requirements. Rebuild the preview with the same signing identity as the app.")
    }
} catch {
    refuse("HotspotShade coordinator refused: the operation cannot complete.")
}
