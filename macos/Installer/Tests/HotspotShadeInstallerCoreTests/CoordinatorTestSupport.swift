import Foundation
import XCTest
import HotspotShadeKit
@testable import HotspotShadeInstallerCore

// A marked sandbox tree with the fixed install layout. The fixture never uses
// a system path and never runs as root. Old and new executables are fake Mach-O
// files whose tag selects the fake signing facts; only the padding differs, so
// the bytes and digests are distinct.
final class CoordinatorFixture {
    static let engineRelative = "Library/Application Support/HotspotShade/engine/hotspotshade"
    static let helperRelative = "Library/PrivilegedHelperTools/dev.hotspotshade.mac.helper"
    static let daemonRelative = "Library/LaunchDaemons/dev.hotspotshade.mac.helper.plist"
    static let rightRelative =
        "Library/Application Support/HotspotShade/install-support/dev.hotspotshade.tunnel.start.plist"
    static let stateRelative = "var/db/hotspotshade"
    static let journalRelative = stateRelative + "/" + InstallJournalStore.fileName
    static let backupRootRelative = stateRelative + "/" + InstallJournalStore.backupDirectoryName

    let workspace: Workspace
    let sandbox: String
    private(set) var oldEngine: Data?
    private(set) var oldHelper: Data?
    let newEngine: Data
    let newHelper: Data
    private(set) var staged: StagedInstaller!
    let launchDaemonData: Data
    let startRightData: Data

    init(oldPadding: Int? = nil, newPadding: Int = 128) throws {
        workspace = try Workspace()
        sandbox = workspace.path("sandbox")
        launchDaemonData = try Data(contentsOf: Repo.launchDaemon)
        startRightData = try Data(contentsOf: Repo.startRight)
        newHelper = fakeMachO(tag: "helper", padding: newPadding)
        newEngine = fakeMachO(tag: "engine", padding: newPadding)
        try FileManager.default.createDirectory(
            atPath: sandbox,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        for directory in [
            "Library",
            "Library/Application Support",
            "Library/PrivilegedHelperTools",
            "Library/LaunchDaemons",
            "var",
            "var/db",
        ] {
            try makeDirectory(directory, mode: 0o755)
        }
        try writeFile(
            sandbox + "/" + CoordinatorSandboxPolicy.markerName,
            Data(CoordinatorSandboxPolicy.markerContents.utf8),
            mode: 0o600
        )

        staged = try InstallerBuilder(validator: InstallerValidator(signatures: FakeSignatures.standard)).stage(
            inputs: try workspace.goodInputs(helper: newHelper, engine: newEngine),
            version: "2.0.0",
            outputDirectory: workspace.path("out")
        )
        if let oldPadding {
            let engine = fakeMachO(tag: "engine", padding: oldPadding)
            let helper = fakeMachO(tag: "helper", padding: oldPadding)
            oldEngine = engine
            oldHelper = helper
            try makeDirectory("Library/Application Support/HotspotShade", mode: 0o755)
            try makeDirectory("Library/Application Support/HotspotShade/engine", mode: 0o755)
            try makeDirectory("Library/Application Support/HotspotShade/install-support", mode: 0o755)
            try writeTarget(Self.engineRelative, engine, mode: 0o755)
            try writeTarget(Self.helperRelative, helper, mode: 0o755)
            try writeTarget(Self.daemonRelative, launchDaemonData, mode: 0o644)
            try writeTarget(Self.rightRelative, startRightData, mode: 0o644)
        } else {
            oldEngine = nil
            oldHelper = nil
        }
    }

    var source: CoordinatorSource {
        CoordinatorSource(
            payloadRoot: staged.payloadDirectory,
            manifest: staged.manifest,
            expectedTeamIdentifier: FakeSignatures.team
        )
    }

    func coordinator(
        faults: CoordinatorFaultInjecting = NoFaults(),
        journalFault: InstallJournalWriteFault? = nil,
        syncHooks: InstallTreeSyncHooks? = nil,
        journalTreeHooks: InstallTreeSyncHooks? = nil
    ) throws -> InstallCoordinator {
        let journalTree = try journalTreeHooks.map {
            try InstallTree(rootPath: sandbox, expectedOwner: UInt32(geteuid()), syncHooks: $0)
        }
        let factory: InstallCoordinator.JournalStoreFactory = { tree in
            if let journalTree {
                return InstallJournalStore(tree: journalTree)
            }
            guard let journalFault else { return InstallJournalStore(tree: tree) }
            return journalFault.store(tree: tree)
        }
        let treeFactory: InstallCoordinator.TreeFactory = { path, owner in
            guard let syncHooks else {
                return try InstallTree(rootPath: path, expectedOwner: owner)
            }
            return try InstallTree(
                rootPath: path,
                expectedOwner: owner,
                syncHooks: syncHooks
            )
        }
        return try InstallCoordinator(
            sandboxRoot: sandbox,
            validator: InstallerValidator(signatures: FakeSignatures.standard),
            faults: faults,
            journalStoreFactory: factory,
            treeFactory: treeFactory
        )
    }

    // MARK: filesystem helpers

    func makeDirectory(_ relative: String, mode: Int) throws {
        let path = sandbox + "/" + relative
        if !FileManager.default.fileExists(atPath: path) {
            try FileManager.default.createDirectory(
                atPath: path,
                withIntermediateDirectories: true
            )
        }
        try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: path)
    }

    func writeFile(_ path: String, _ data: Data, mode: Int) throws {
        try data.write(to: URL(fileURLWithPath: path))
        try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: path)
    }

    func writeTarget(_ relative: String, _ data: Data, mode: Int = 0o644) throws {
        let path = sandbox + "/" + relative
        try makeParent(of: path)
        try writeFile(path, data, mode: mode)
    }

    func writeState(_ name: String, _ data: Data, mode: Int = 0o600) throws {
        try makeDirectory(Self.stateRelative, mode: 0o700)
        try writeFile(sandbox + "/" + Self.stateRelative + "/" + name, data, mode: mode)
    }

    func makeStateDirectory() throws {
        try makeDirectory(Self.stateRelative, mode: 0o700)
    }

    func readTarget(_ relative: String) -> Data? {
        try? Data(contentsOf: URL(fileURLWithPath: sandbox + "/" + relative))
    }

    func targetExists(_ relative: String) -> Bool {
        FileManager.default.fileExists(atPath: sandbox + "/" + relative)
    }

    func targetMode(_ relative: String) throws -> Int {
        let attributes = try FileManager.default.attributesOfItem(atPath: sandbox + "/" + relative)
        return (attributes[.posixPermissions] as! NSNumber).intValue
    }

    func writeStateJournal(_ journal: InstallJournal) throws {
        try makeStateDirectory()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        try writeState(
            InstallJournalStore.fileName,
            try encoder.encode(journal),
            mode: 0o600
        )
    }

    func writeRawJournal(_ data: Data) throws {
        try writeState(InstallJournalStore.fileName, data, mode: 0o600)
    }

    func backupEntries() -> [String] {
        let path = sandbox + "/" + Self.backupRootRelative
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: path) else {
            return []
        }
        return names.sorted()
    }

    func backupFileNames(transactionID: String) -> [String] {
        let path = sandbox + "/" + Self.backupRootRelative + "/" + transactionID
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: path) else {
            return []
        }
        return names.sorted()
    }

    func readJournal() throws -> InstallJournal? {
        let path = sandbox + "/" + Self.journalRelative
        guard FileManager.default.fileExists(atPath: path) else { return nil }
        return try JSONDecoder().decode(
            InstallJournal.self,
            from: try Data(contentsOf: URL(fileURLWithPath: path))
        )
    }

    func temporaryNames(in relative: String) -> [String] {
        let path = sandbox + "/" + relative
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: path) else {
            return []
        }
        return names.filter { $0.contains(".hs-") }
    }

    // MARK: assertions

    func assertOldSet(file: StaticString = #filePath, line: UInt = #line) throws {
        guard let oldEngine, let oldHelper else {
            return XCTFail("the fixture has no old set", file: file, line: line)
        }
        XCTAssertEqual(readTarget(Self.engineRelative), oldEngine, file: file, line: line)
        XCTAssertEqual(readTarget(Self.helperRelative), oldHelper, file: file, line: line)
        XCTAssertEqual(readTarget(Self.daemonRelative), launchDaemonData, file: file, line: line)
        XCTAssertEqual(readTarget(Self.rightRelative), startRightData, file: file, line: line)
        XCTAssertEqual(try targetMode(Self.engineRelative), 0o755, file: file, line: line)
        XCTAssertEqual(try targetMode(Self.helperRelative), 0o755, file: file, line: line)
        XCTAssertEqual(try targetMode(Self.daemonRelative), 0o644, file: file, line: line)
        XCTAssertEqual(try targetMode(Self.rightRelative), 0o644, file: file, line: line)
    }

    func assertNewSet(file: StaticString = #filePath, line: UInt = #line) throws {
        XCTAssertEqual(readTarget(Self.engineRelative), newEngine, file: file, line: line)
        XCTAssertEqual(readTarget(Self.helperRelative), newHelper, file: file, line: line)
        XCTAssertEqual(readTarget(Self.daemonRelative), launchDaemonData, file: file, line: line)
        XCTAssertEqual(readTarget(Self.rightRelative), startRightData, file: file, line: line)
        XCTAssertEqual(try targetMode(Self.engineRelative), 0o755, file: file, line: line)
        XCTAssertEqual(try targetMode(Self.helperRelative), 0o755, file: file, line: line)
        XCTAssertEqual(try targetMode(Self.daemonRelative), 0o644, file: file, line: line)
        XCTAssertEqual(try targetMode(Self.rightRelative), 0o644, file: file, line: line)
    }

    func assertNoJournal(file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertFalse(targetExists(Self.journalRelative), "a journal remains", file: file, line: line)
    }

    func assertNoBackups(file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(backupEntries(), [], "backup entries remain", file: file, line: line)
    }

    func assertNoTemporaryFiles(file: StaticString = #filePath, line: UInt = #line) {
        for directory in [
            "Library/Application Support/HotspotShade/engine",
            "Library/Application Support/HotspotShade/install-support",
            "Library/PrivilegedHelperTools",
            "Library/LaunchDaemons",
            Self.stateRelative,
        ] {
            XCTAssertEqual(temporaryNames(in: directory), [], "temporary files remain in \(directory)",
                           file: file, line: line)
        }
    }

    // MARK: private

    private func makeParent(of path: String) throws {
        let parent = (path as NSString).deletingLastPathComponent
        if !FileManager.default.fileExists(atPath: parent) {
            try FileManager.default.createDirectory(atPath: parent, withIntermediateDirectories: true)
        }
    }
}

// A test action at one install step. The action changes the sandbox (for
// example, it removes a staged source file) so the next real operation fails
// through the production error path, not through a simulated crash.
final class CoordinatorActionAt: CoordinatorFaultInjecting, @unchecked Sendable {
    private let step: CoordinatorStep
    private let action: () throws -> Void

    init(_ step: CoordinatorStep, action: @escaping () throws -> Void) {
        self.step = step
        self.action = action
    }

    func check(_ candidate: CoordinatorStep) throws {
        if candidate == step { try action() }
    }
}

// A journal store whose writer stops at one phase. The pre-rename case throws
// before the tree sees the data, like a failed write or sync of the temporary
// file. The post-rename case calls the real atomic writer with a failing
// directory sync, so the production classification path runs and only the
// syscall result is simulated. A read-back is never used to classify either
// case.
final class InstallJournalWriteFault: @unchecked Sendable {
    enum Stage: Sendable {
        case preRename
        case postRename
    }

    let phase: InstallJournal.Phase
    let stage: Stage

    init(phase: InstallJournal.Phase, stage: Stage) {
        self.phase = phase
        self.stage = stage
    }

    func store(tree: InstallTree) -> InstallJournalStore {
        InstallJournalStore(tree: tree) { relative, data, mode, temporarySuffix, replaceExisting in
            let journal = try JSONDecoder().decode(InstallJournal.self, from: data)
            if journal.phase == self.phase {
                switch self.stage {
                case .preRename:
                    throw InstallTreeError.io(relative, EIO)
                case .postRename:
                    try tree.writeAtomic(
                        relative,
                        data: data,
                        mode: mode,
                        temporarySuffix: temporarySuffix,
                        replaceExisting: replaceExisting,
                        directorySync: { _ in
                            errno = EIO
                            return -1
                        }
                    )
                    return
                }
            }
            try tree.writeAtomic(
                relative,
                data: data,
                mode: mode,
                temporarySuffix: temporarySuffix,
                replaceExisting: replaceExisting
            )
        }
    }
}

// A deterministic failure at one directory-sync boundary. Production passes
// `fsync`; the test tree records which call ran and returns the injected error.
enum TreeSyncFault: Sendable {
    case copyAfterRename
    case moveGained
    case moveLost
    case restoreGained
    case restoreLost
    case removeAfterUnlink
}

func failingTreeHooks(_ fault: TreeSyncFault) -> InstallTreeSyncHooks {
    let fail: @Sendable (Int32) -> Int32 = { _ in
        errno = EIO
        return -1
    }
    var hooks = InstallTreeSyncHooks.production
    switch fault {
    case .copyAfterRename:
        hooks.copyDirectory = fail
    case .moveGained:
        hooks.moveGained = fail
    case .moveLost:
        hooks.moveLost = fail
    case .restoreGained:
        hooks.restoreGained = fail
    case .restoreLost:
        hooks.restoreLost = fail
    case .removeAfterUnlink:
        hooks.removeDirectory = fail
    }
    return hooks
}

func mutatedManifest(
    _ manifest: InstallerManifest,
    _ edit: (inout [InstallerManifest.File], inout [String: Any]) -> Void = { _, _ in }
) -> InstallerManifest {
    var files = manifest.files
    var fields: [String: Any] = [:]
    edit(&files, &fields)
    return InstallerManifest(
        schemaVersion: fields["schemaVersion"] as? Int ?? manifest.schemaVersion,
        packageIdentifier: fields["packageIdentifier"] as? String ?? manifest.packageIdentifier,
        version: fields["version"] as? String ?? manifest.version,
        installLocation: fields["installLocation"] as? String ?? manifest.installLocation,
        teamIdentifier: fields["teamIdentifier"] as? String ?? manifest.teamIdentifier,
        packageSigned: fields["packageSigned"] as? Bool ?? manifest.packageSigned,
        installationApproved: fields["installationApproved"] as? Bool ?? manifest.installationApproved,
        files: files,
        scripts: fields["scripts"] as? [InstallerManifest.File] ?? manifest.scripts,
        notes: manifest.notes
    )
}
