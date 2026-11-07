import Foundation
import Darwin
import XCTest
import HotspotShadeKit
@testable import HotspotShadeInstallerCore

enum ServiceTestFixtures {
    static let samplePrint = """
    system/dev.hotspotshade.mac.helper = {
    \tactive count = 0
    \tpath = /Library/LaunchDaemons/dev.hotspotshade.mac.helper.plist
    \ttype = LaunchDaemon
    \tstate = not running
    \tprogram = /Library/PrivilegedHelperTools/dev.hotspotshade.mac.helper
    \targuments = {
    \t\t/Library/PrivilegedHelperTools/dev.hotspotshade.mac.helper
    \t}
    }
    """

    static var readback: LaunchdJobReadback {
        LaunchdJobReadback(
            label: PrivilegedServiceLayout.launchdLabel,
            launchDaemonPath: PrivilegedServiceLayout.launchDaemonPath,
            helperPath: PrivilegedServiceLayout.helperPath,
            rawOutput: Data(samplePrint.utf8)
        )
    }

    static var loaded: LaunchdJobObservation { .loaded(readback) }

    static func rightData(comment: String) throws -> Data {
        try plistData([
            "allow-root": false,
            "authenticate-user": true,
            "class": "user",
            "comment": comment,
            "group": "admin",
            "shared": false,
            "timeout": 10,
        ])
    }

    static func previousRight() throws -> AuthorizationRightSnapshot {
        try AuthorizationRightPolicyParser.parse(rightData(comment: "previous install"))
    }

    static func previousRightWithAuthdMetadata() throws -> AuthorizationRightSnapshot {
        try AuthorizationRightPolicyParser.parse(
            withAuthdMetadata(rightData(comment: "previous install"))
        )
    }

    static func installedRightData() throws -> Data {
        try Data(contentsOf: Repo.startRight)
    }

    static func installedRight() throws -> AuthorizationRightSnapshot {
        try AuthorizationRightPolicyParser.parse(installedRightData())
    }

    // An ordinary upgrade may keep the same reviewed policy. authd still
    // returns its own metadata, so the stored bytes differ from the packaged
    // source even though the policy is identical.
    static func samePolicyRightWithAuthdMetadata() throws -> AuthorizationRightSnapshot {
        try AuthorizationRightPolicyParser.parse(
            withAuthdMetadata(installedRightData())
        )
    }

    static func withAuthdMetadata(_ data: Data) throws -> Data {
        guard let object = try PropertyListSerialization.propertyList(
            from: data,
            options: [],
            format: nil
        ) as? [String: Any] else {
            throw AuthorizationRightPolicyError.notPropertyList
        }
        var copy = object
        copy["created"] = 17
        copy["modified"] = 18
        copy["version"] = 1
        copy["session-owner"] = false
        copy["tries"] = 10000
        return try plistData(copy)
    }

    static func alternateRight() throws -> AuthorizationRightSnapshot {
        try AuthorizationRightPolicyParser.parse(rightData(comment: "a different safe comment"))
    }

    static func tree(_ fixture: CoordinatorFixture) throws -> InstallTree {
        try InstallTree(rootPath: fixture.sandbox, expectedOwner: UInt32(geteuid()))
    }
}

struct FakeServiceRuntime: PrivilegedServiceRuntime {
    let isLiveSystem = false
    let authorizationRights: AuthorizationRightStoring
    let launchd: LaunchdJobControlling
}

final class FakeAuthorizationRightStore: AuthorizationRightStoring, @unchecked Sendable {
    var observation: AuthorizationRightObservation = .absent
    var observeError: Error?
    var writeError: Error?
    var removeError: Error?
    var addMetadataOnWrite = false
    var nextWriteObservation: AuthorizationRightObservation?
    private(set) var writes: [Data] = []
    private(set) var removeCount = 0

    func observe() throws -> AuthorizationRightObservation {
        if let observeError { throw observeError }
        return observation
    }

    func write(_ definition: Data) throws {
        if let error = writeError {
            writeError = nil
            throw error
        }
        writes.append(definition)
        if let next = nextWriteObservation {
            nextWriteObservation = nil
            observation = next
            return
        }
        let stored = addMetadataOnWrite
            ? try ServiceTestFixtures.withAuthdMetadata(definition)
            : definition
        observation = .present(try AuthorizationRightPolicyParser.parse(stored))
    }

    func remove() throws {
        if let error = removeError {
            removeError = nil
            throw error
        }
        removeCount += 1
        observation = .absent
    }
}

final class FakeLaunchdJobController: LaunchdJobControlling, @unchecked Sendable {
    var observation: LaunchdJobObservation
    var bootoutError: Error?
    var bootstrapError: Error?
    var observationAfterFailedBootout: LaunchdJobObservation?
    var observationAfterFailedBootstrap: LaunchdJobObservation?
    var keepObservationAfterBootout = false
    var nextBootstrapObservation: LaunchdJobObservation?
    var observationQueue: [LaunchdJobObservation] = []
    private(set) var bootoutCount = 0
    private(set) var bootstrapCount = 0
    let readback: LaunchdJobReadback

    init(
        observation: LaunchdJobObservation = .absent,
        readback: LaunchdJobReadback = ServiceTestFixtures.readback
    ) {
        self.observation = observation
        self.readback = readback
    }

    func observe() throws -> LaunchdJobObservation {
        if !observationQueue.isEmpty {
            return observationQueue.removeFirst()
        }
        return observation
    }

    func bootout() throws {
        bootoutCount += 1
        if let error = bootoutError {
            bootoutError = nil
            if let after = observationAfterFailedBootout {
                observation = after
                observationAfterFailedBootout = nil
            }
            throw error
        }
        if !keepObservationAfterBootout {
            observation = .absent
        }
    }

    func bootstrap() throws {
        bootstrapCount += 1
        if let error = bootstrapError {
            bootstrapError = nil
            if let after = observationAfterFailedBootstrap {
                observation = after
                observationAfterFailedBootstrap = nil
            }
            throw error
        }
        observation = nextBootstrapObservation ?? .loaded(readback)
        nextBootstrapObservation = nil
    }
}

// Simulates the one writeAtomic failure that is not a clean pre-rename
// failure: the rename succeeded, so the new record is visible, but the
// directory sync failed. Production code reports this as `.writeUncertain`,
// and the store must turn it into an unknown outcome, not a failed write that
// can be safely rolled back.
final class PostRenameSyncFailureWriter: @unchecked Sendable {
    private let tree: InstallTree
    private let failPhase: ServiceJournal.Phase

    init(tree: InstallTree, failPhase: ServiceJournal.Phase) {
        self.tree = tree
        self.failPhase = failPhase
    }

    func write(
        _ relative: String,
        _ data: Data,
        _ mode: mode_t,
        _ temporarySuffix: String,
        _ replaceExisting: Bool
    ) throws {
        let journal = try JSONDecoder().decode(ServiceJournal.self, from: data)
        if journal.phase == failPhase {
            // The rename runs; only the following parent directory sync fails.
            // That is the production post-rename uncertainty, not a write that
            // is thrown away after a successful durable write.
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
        try tree.writeAtomic(
            relative,
            data: data,
            mode: mode,
            temporarySuffix: temporarySuffix,
            replaceExisting: replaceExisting
        )
    }
}

// Runs a test action at one transaction step. It lets a test change an
// installed input between two recovery observations without adding a
// production fault hook.
final class ServiceFaultAction: ServiceTransactionFaultInjecting, @unchecked Sendable {
    private let step: ServiceTransactionStep
    private let action: () throws -> Void

    init(_ step: ServiceTransactionStep, action: @escaping () throws -> Void) {
        self.step = step
        self.action = action
    }

    func check(_ candidate: ServiceTransactionStep) throws {
        if candidate == step { try action() }
    }
}

final class RecordingCommandRunner: PrivilegedCommandRunning, @unchecked Sendable {
    let isLiveSystem = false
    var commands: [PrivilegedServiceCommand] = []
    var results: [PrivilegedServiceCommand.Operation: PrivilegedCommandResult] = [:]
    var error: Error?

    func run(_ command: PrivilegedServiceCommand) throws -> PrivilegedCommandResult {
        commands.append(command)
        if let error { throw error }
        return results[command.operation] ?? PrivilegedCommandResult(
            exitCode: 0,
            standardOutput: Data()
        )
    }
}

struct FakeExistenceProbe: AuthorizationRightExistenceProbing {
    let answer: Bool?
    let error: Error?

    init(_ answer: Bool) {
        self.answer = answer
        self.error = nil
    }

    init(error: Error) {
        self.answer = nil
        self.error = error
    }

    func isPresent() throws -> Bool {
        if let error { throw error }
        return answer ?? false
    }
}

struct ServiceTestContext {
    let fixture: CoordinatorFixture
    let rightStore: FakeAuthorizationRightStore
    let launchd: FakeLaunchdJobController
    let runtime: FakeServiceRuntime
    let tree: InstallTree

    init(
        previousRight: AuthorizationRightObservation = .absent,
        previousJob: LaunchdJobObservation = .absent,
        jobReadback: LaunchdJobReadback = ServiceTestFixtures.readback
    ) throws {
        fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
        try fixture.makeStateDirectory()
        rightStore = FakeAuthorizationRightStore()
        rightStore.observation = previousRight
        launchd = FakeLaunchdJobController(observation: previousJob, readback: jobReadback)
        runtime = FakeServiceRuntime(
            authorizationRights: rightStore,
            launchd: launchd
        )
        tree = try ServiceTestFixtures.tree(fixture)
    }

    func transaction(
        stateTree: InstallTree? = nil,
        faults: ServiceTransactionFaultInjecting = NoServiceFaults(),
        journalStore: ServiceJournalStore? = nil
    ) throws -> PrivilegedServiceTransaction {
        try PrivilegedServiceTransaction(
            tree: tree,
            stateTree: stateTree,
            runtime: runtime,
            faults: faults,
            validator: InstallerValidator(signatures: FakeSignatures.standard),
            expectedTeamIdentifier: FakeSignatures.team,
            journalStore: journalStore
        )
    }

    func journalStore(failingAfter phase: ServiceJournal.Phase) -> ServiceJournalStore {
        let writer = PostRenameSyncFailureWriter(tree: tree, failPhase: phase)
        let atomicWriter: ServiceJournalStore.AtomicWriter = {
            relative, data, mode, temporarySuffix, replaceExisting in
            try writer.write(
                relative,
                data,
                mode,
                temporarySuffix,
                replaceExisting
            )
        }
        return ServiceJournalStore(tree: tree, atomicWriter: atomicWriter)
    }

    func journalExists() -> Bool {
        fixture.targetExists(
            PrivilegedServiceLayout.stateDirectoryRelative
                + "/" + ServiceJournalStore.fileName
        )
    }

    func journal() throws -> ServiceJournal? {
        try ServiceJournalStore(tree: tree).read()
    }

    func installedRightData() throws -> Data {
        try Data(
            contentsOf: URL(
                fileURLWithPath: fixture.sandbox + "/" + PrivilegedServiceLayout.rightSourceRelative
            )
        )
    }

    func installedRightPolicy() throws -> AuthorizationRightPolicy {
        try AuthorizationRightPolicyParser.parse(installedRightData()).policy
    }
}
