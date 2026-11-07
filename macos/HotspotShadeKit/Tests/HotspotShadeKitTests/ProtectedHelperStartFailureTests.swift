import XCTest
import Foundation
import Darwin
@testable import HotspotShadeKit

// A failed start before any grant, the root engine's fixed reason, and the
// descriptor placement that caused the 2026-11-06 live failure.

private final class ExitingEngine: RunningHelperEngine {
    let description = HelperEngineDescription(port: 5353, secret: "secret")
    var isRunning = true
    var exitObserved = false
    var startFailureReason: EngineStartFailureReason?
    var stopResult: EngineStopResult = .failed
    var authorizeFailure: Error?
    var authorizeCalls = 0
    var stopCalls = 0

    func authorizeStart() throws {
        authorizeCalls += 1
        if let authorizeFailure { throw authorizeFailure }
    }

    func stop() -> EngineStopResult {
        stopCalls += 1
        isRunning = false
        return stopResult
    }

    // The engine exits on its own and the helper reaps it.
    func exit(reason: EngineStartFailureReason?, observed: Bool = true) {
        isRunning = false
        exitObserved = observed
        startFailureReason = reason
    }
}

private final class ScriptedLauncher: HelperEngineLaunching {
    var engine = ExitingEngine()
    var failure: Error?
    var launches = 0

    func launch(holding exclusion: HelperStartExclusionHandoff?) throws -> RunningHelperEngine {
        launches += 1
        if let failure { throw failure }
        return engine
    }
}

private final class MemoryCleanupStore: HelperCleanupBlockStoring, @unchecked Sendable {
    var records: [String] = []
    func isBlocked() throws -> Bool { !records.isEmpty }
    func recordBlock(reason: String) throws { records.append(reason) }
}

private final class MemoryIntentStore: HelperLaunchIntentStoring, @unchecked Sendable {
    var present = false
    var clearFailure: Error?
    func isPresent() throws -> Bool { present }
    func create() throws {
        guard !present else { throw HelperLaunchIntentError.alreadyPresent }
        present = true
    }
    func clearAfterVerifiedCleanStop() throws {
        if let clearFailure { throw clearFailure }
        present = false
    }
}

private struct Fixture {
    let launcher = ScriptedLauncher()
    let cleanup = MemoryCleanupStore()
    let intent = MemoryIntentStore()
    let exclusion = TestStartExclusion()
    let record = InMemoryStartFailureRecord()

    func controller() -> HelperSessionController {
        HelperSessionController(
            launcher: launcher,
            cleanupStore: cleanup,
            intentStore: intent,
            exclusion: exclusion,
            failureRecord: record
        )
    }
}

final class ProtectedHelperStartFailureTests: XCTestCase {
    // MARK: - Session controller

    func testAnEngineThatExitsBeforeItIsReadyIsAFailedStartWithoutABlock() {
        let fixture = Fixture()
        fixture.launcher.failure = HelperEngineExitedBeforeGrant(reason: .credentialsDescriptorInvalid)
        let controller = fixture.controller()

        XCTAssertEqual(
            controller.start(connection: UUID()),
            .engineDidNotStart(.credentialsDescriptorInvalid)
        )
        XCTAssertTrue(fixture.cleanup.records.isEmpty, "a failed start sets no cleanup block")
        XCTAssertFalse(fixture.intent.present, "the launch intent is cleared")
        XCTAssertEqual(fixture.exclusion.lease.releaseCalls, 1)
        XCTAssertEqual(fixture.exclusion.lease.abandonCalls, 0)
        XCTAssertEqual(fixture.record.read(), .credentialsDescriptorInvalid)
        XCTAssertFalse(controller.requiresCleanup)

        // The next start is allowed.
        fixture.launcher.failure = nil
        guard case .started = controller.start(connection: UUID()) else {
            return XCTFail("a later start must be allowed")
        }
    }

    func testAFailedStartWhoseIntentCannotBeClearedStillBlocks() {
        let fixture = Fixture()
        fixture.launcher.failure = HelperEngineExitedBeforeGrant(reason: .tokenInvalid)
        fixture.intent.clearFailure = HelperLaunchIntentError.unsafe
        let controller = fixture.controller()
        XCTAssertEqual(controller.start(connection: UUID()), .cleanupBlocked)
        XCTAssertTrue(fixture.intent.present)
        XCTAssertTrue(controller.requiresCleanup)
    }

    func testAnUncleanLaunchThatTheHelperCannotExplainStillBlocks() {
        for error in [HelperTrustError.engineExitUnclean, .engineStopTimedOut] {
            let fixture = Fixture()
            fixture.launcher.failure = error
            let controller = fixture.controller()
            XCTAssertEqual(controller.start(connection: UUID()), .cleanupBlocked, "\(error)")
            XCTAssertEqual(fixture.cleanup.records, ["launch stop was not clean"], "\(error)")
            XCTAssertTrue(fixture.intent.present, "\(error)")
            XCTAssertNil(fixture.record.read())
        }
    }

    func testAReapedEngineExitBeforeAnyGrantIsAFailedStart() throws {
        let fixture = Fixture()
        let controller = fixture.controller()
        let connection = UUID()
        guard case .started(let session) = controller.start(connection: connection) else {
            return XCTFail("start")
        }
        fixture.launcher.engine.exit(reason: .credentialsImportFailed)

        let reaped = try XCTUnwrap(controller.reapExitedEngineReport())
        XCTAssertEqual(reaped.connection, connection)
        XCTAssertEqual(reaped.sessionID, session.sessionID)
        XCTAssertTrue(reaped.failedStart)
        XCTAssertEqual(reaped.reason, .credentialsImportFailed)
        XCTAssertTrue(fixture.cleanup.records.isEmpty)
        XCTAssertFalse(fixture.intent.present)
        XCTAssertEqual(fixture.exclusion.lease.releaseCalls, 1)
        XCTAssertFalse(controller.hasRetainedExclusion)
        XCTAssertFalse(controller.requiresCleanup)
        let snapshot = controller.snapshot()
        XCTAssertEqual(snapshot.lastSession, session.sessionID)
        XCTAssertEqual(snapshot.lastResult, .failedStart)
        XCTAssertEqual(snapshot.lastFailureReason, .credentialsImportFailed)
        XCTAssertEqual(fixture.record.read(), .credentialsImportFailed)
        guard case .started = controller.start(connection: UUID()) else {
            return XCTFail("a later start must be allowed")
        }
    }

    func testAnExitAfterAGrantWriteKeepsTheDurableBlock() throws {
        let fixture = Fixture()
        let controller = fixture.controller()
        let connection = UUID()
        guard case .started = controller.start(connection: connection) else { return XCTFail("start") }
        XCTAssertEqual(controller.authorizeStart(connection: connection), .authorized)
        fixture.launcher.engine.exit(reason: .credentialsImportFailed)

        let reaped = try XCTUnwrap(controller.reapExitedEngineReport())
        XCTAssertFalse(reaped.failedStart)
        XCTAssertEqual(fixture.cleanup.records, ["engine exited without a stop request"])
        XCTAssertTrue(fixture.intent.present)
        XCTAssertTrue(controller.requiresCleanup)
        XCTAssertEqual(controller.snapshot().lastResult, .engineExited)
    }

    func testAFailedGrantWriteStillCountsAsAGrantAttempt() throws {
        let fixture = Fixture()
        fixture.launcher.engine.authorizeFailure = HelperTrustError.grantFailed
        let controller = fixture.controller()
        let connection = UUID()
        guard case .started = controller.start(connection: connection) else { return XCTFail("start") }
        XCTAssertEqual(controller.authorizeStart(connection: connection), .grantFailed)
        fixture.launcher.engine.exit(reason: nil)

        let reaped = try XCTUnwrap(controller.reapExitedEngineReport())
        XCTAssertFalse(reaped.failedStart)
        XCTAssertFalse(fixture.cleanup.records.isEmpty)
        XCTAssertTrue(controller.requiresCleanup)
    }

    func testAnExitTheHelperCouldNotReadKeepsTheDurableBlock() throws {
        let fixture = Fixture()
        let controller = fixture.controller()
        guard case .started = controller.start(connection: UUID()) else { return XCTFail("start") }
        fixture.launcher.engine.exit(reason: .tokenInvalid, observed: false)

        let reaped = try XCTUnwrap(controller.reapExitedEngineReport())
        XCTAssertFalse(reaped.failedStart)
        XCTAssertEqual(fixture.cleanup.records, ["engine exited without a stop request"])
        XCTAssertTrue(controller.requiresCleanup)
    }

    func testAnUncleanStopBeforeAnyGrantIsAFailedStartButATimeoutBlocks() {
        // An unclean exit that the helper reaped while it stopped an engine
        // that never had a grant changed no route.
        let fixture = Fixture()
        let controller = fixture.controller()
        let connection = UUID()
        guard case .started = controller.start(connection: connection) else { return XCTFail("start") }
        fixture.launcher.engine.exitObserved = true
        fixture.launcher.engine.stopResult = .failed
        let report = controller.stopReportingOwnership(connection: connection, reason: .user)
        XCTAssertTrue(report.owned)
        XCTAssertTrue(fixture.cleanup.records.isEmpty)
        XCTAssertFalse(fixture.intent.present)
        XCTAssertEqual(controller.snapshot().lastResult, .failedStart)

        // A stop that did not end the engine is never proof.
        let second = Fixture()
        let blocked = second.controller()
        let owner = UUID()
        guard case .started = blocked.start(connection: owner) else { return XCTFail("start") }
        second.launcher.engine.stopResult = .timedOut
        _ = blocked.stopReportingOwnership(connection: owner, reason: .user)
        XCTAssertEqual(second.cleanup.records, ["engine stop timed out"])
        XCTAssertTrue(blocked.requiresCleanup)
    }

    // MARK: - App mapping

    func testTheAppSaysTheTunnelDidNotStartAndWhy() {
        let failure = EngineLaunchFailure.fromHelper(HelperEngineDidNotStart(reason: .credentialsHandoffInvalid))
        XCTAssertEqual(failure.kind, .engine)
        XCTAssertTrue(failure.message.hasPrefix("The tunnel did not start."), failure.message)
        XCTAssertTrue(failure.message.contains(EngineStartFailureReason.credentialsHandoffInvalid.sentence))
        XCTAssertFalse(failure.message.contains("did not stop cleanly"))
        XCTAssertFalse(failure.cleanupIsFinal)
        XCTAssertEqual(
            Strings.helperMessage(HelperEngineDidNotStart(reason: nil)),
            Strings.tunnelDidNotStart(nil)
        )
    }

    func testAFailedStartRecordConfirmsTheStop() {
        let session = UUID()
        let status = HelperStatus(
            running: false,
            cleanupBlocked: false,
            lastSession: session,
            lastResult: .failedStart,
            lastFailureReason: .tokenInvalid
        )
        XCTAssertEqual(
            TunnelStopResult.fromCleanupStatus(status, session: session, everStarted: true, previous: .disconnected),
            .stopped
        )
    }

    func testTheEngineExitedNoticeCarriesAFailedStart() {
        XCTAssertEqual(
            HelperInvalidation.engineExitedNotice(
                reason: "credentials_handoff_invalid",
                cleanupBlocked: false,
                failedStart: true
            ),
            .startFailed(.credentialsHandoffInvalid)
        )
        // A cleanup block always wins.
        XCTAssertEqual(
            HelperInvalidation.engineExitedNotice(reason: nil, cleanupBlocked: true, failedStart: true),
            .cleanupBlocked
        )
        XCTAssertEqual(
            HelperInvalidation.engineExitedNotice(reason: "free text", cleanupBlocked: false, failedStart: true),
            .startFailed(nil)
        )
    }

    func testEveryReasonSentenceIsPlainText() {
        for reason in EngineStartFailureReason.allCases {
            let text = Strings.tunnelDidNotStart(reason)
            XCTAssertFalse(text.contains("/"), text)
            XCTAssertFalse(text.localizedCaseInsensitiveContains("token"), text)
            XCTAssertFalse(text.contains("descriptor"), text)
        }
    }

    // MARK: - The engine's fixed reason line

    func testTheParserAcceptsOnlyAFixedEngineCode() {
        func parse(_ text: String) -> EngineStartFailureReason? {
            EngineStartFailureReason.parse(engineOutput: Array(text.utf8))
        }
        XCTAssertEqual(
            parse("error: The pairing handoff is not valid.\nhotspotshade-start-failure: credentials_handoff_invalid\n"),
            .credentialsHandoffInvalid
        )
        XCTAssertEqual(parse("hotspotshade-start-failure: token_invalid\r\n"), .tokenInvalid)
        XCTAssertEqual(parse("hotspotshade-start-failure: token_invalid"), .tokenInvalid, "no final newline")
        XCTAssertNil(parse("hotspotshade-start-failure: token_invalid secret=abc\n"))
        XCTAssertNil(parse("x hotspotshade-start-failure: token_invalid\n"))
        XCTAssertNil(parse("hotspotshade-start-failure: unknown_code\n"))
        XCTAssertNil(parse("hotspotshade-start-failure: no_port_in_time\n"), "a helper-side code is not an engine code")
        XCTAssertNil(parse("error: something else\n"))
        // The last fixed line wins.
        XCTAssertEqual(
            parse("hotspotshade-start-failure: token_invalid\nhotspotshade-start-failure: listener_failed\n"),
            .listenerFailed
        )
    }

    func testTheEngineCodesMatchTheRustStartupStages() throws {
        // rust/src/main.rs `StartupStage::reason` prints these codes, plus the
        // seal failure in `main`.
        let source = try String(
            contentsOf: URL(fileURLWithPath: #filePath)
                .deletingLastPathComponent().deletingLastPathComponent()
                .deletingLastPathComponent().deletingLastPathComponent()
                .deletingLastPathComponent()
                .appendingPathComponent("rust/src/main.rs"),
            encoding: .utf8
        )
        for reason in EngineStartFailureReason.engineCodes {
            XCTAssertTrue(source.contains("\"\(reason.rawValue)\""), reason.rawValue)
        }
    }

    func testTheCaptureKeepsOnlyTheLastBytesAndDrainsToEndOfFile() throws {
        var fds: [Int32] = [-1, -1]
        XCTAssertEqual(pipe(&fds), 0)
        let capture = RootEngineStderrCapture(readDescriptor: fds[0])
        // Far more than the bound, then the fixed line. A reader that stopped
        // at the bound would block this writer on a full pipe.
        let filler = [UInt8](repeating: UInt8(ascii: "x"), count: 200_000)
        XCTAssertTrue(HelperPipeWriter.writeAll(descriptor: fds[1], bytes: filler + Array("\nhotspotshade-start-failure: listener_failed\n".utf8)))
        close(fds[1])
        XCTAssertEqual(capture.reason(waitingUpTo: 5), .listenerFailed)
    }

    // MARK: - Descriptor placement

    func testSpawnMappingsRefuseASourceThatCouldBeATarget() {
        var actions: posix_spawn_file_actions_t?
        XCTAssertEqual(posix_spawn_file_actions_init(&actions), 0)
        defer { posix_spawn_file_actions_destroy(&actions) }
        // The old order: a credentials descriptor on 3 after `dup2(token, 3)`.
        XCTAssertFalse(RootEngineSpawnDescriptors.addMappings([(source: 20, target: 3), (source: 3, target: 6)], to: &actions))
        XCTAssertFalse(RootEngineSpawnDescriptors.addMappings([(source: 20, target: 3), (source: 21, target: 3)], to: &actions))
        XCTAssertFalse(RootEngineSpawnDescriptors.addMappings([(source: 20, target: 10)], to: &actions))
    }

    func testRelocatedDescriptorsReachTheirTargetsInARealChild() throws {
        // Four channels with one marker byte each, placed like the root engine
        // launch: token 3, parent 4, lock 5, pairing 6. A child shell reads one
        // byte from each and writes them to standard output.
        func markedPipe(_ marker: String) -> Int32 {
            var fds: [Int32] = [-1, -1]
            XCTAssertEqual(pipe(&fds), 0)
            XCTAssertTrue(HelperPipeWriter.writeAll(descriptor: fds[1], bytes: Array(marker.utf8)))
            close(fds[1])
            return fds[0]
        }
        let token = markedPipe("T")
        let parent = markedPipe("P")
        let lockPath = NSTemporaryDirectory() + "hs-spawn-\(UUID().uuidString)"
        XCTAssertTrue(FileManager.default.createFile(atPath: lockPath, contents: Data("L".utf8)))
        defer { unlink(lockPath) }
        let lock = open(lockPath, O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(lock, 0)
        var pair: [Int32] = [-1, -1]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair), 0)
        XCTAssertTrue(HelperPipeWriter.writeAll(descriptor: pair[0], bytes: Array("C".utf8)))
        var output: [Int32] = [-1, -1]
        XCTAssertEqual(pipe(&output), 0)

        let sources = [token, parent, lock, pair[1], output[1]]
        let relocated = sources.map { RootEngineSpawnDescriptors.relocate($0) }
        for value in relocated {
            XCTAssertGreaterThanOrEqual(try XCTUnwrap(value), RootEngineSpawnDescriptors.lowestSource)
        }
        defer {
            for value in relocated.compactMap({ $0 }) { close(value) }
            for value in sources + [pair[0], output[0]] { close(value) }
        }
        var actions: posix_spawn_file_actions_t?
        XCTAssertEqual(posix_spawn_file_actions_init(&actions), 0)
        defer { posix_spawn_file_actions_destroy(&actions) }
        XCTAssertTrue(RootEngineSpawnDescriptors.addMappings([
            (source: relocated[4]!, target: 1),
            (source: relocated[0]!, target: 3),
            (source: relocated[1]!, target: 4),
            (source: relocated[2]!, target: 5),
            (source: relocated[3]!, target: 6),
        ], to: &actions))
        var attributes: posix_spawnattr_t?
        XCTAssertEqual(posix_spawnattr_init(&attributes), 0)
        defer { posix_spawnattr_destroy(&attributes) }
        XCTAssertEqual(posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT)), 0)
        let script = "for fd in 3 4 5 6; do /bin/dd bs=1 count=1 <&$fd 2>/dev/null; done"
        let argv: [UnsafeMutablePointer<CChar>?] = ["/bin/sh", "-c", script].map { strdup($0) } + [nil]
        defer { for pointer in argv { free(pointer) } }
        var child: pid_t = 0
        XCTAssertEqual(posix_spawn(&child, "/bin/sh", &actions, &attributes, argv, nil), 0)
        close(output[1])
        output[1] = -1
        var collected = [UInt8]()
        var buffer = [UInt8](repeating: 0, count: 16)
        while true {
            let count = buffer.withUnsafeMutableBytes { read(output[0], $0.baseAddress, $0.count) }
            if count <= 0 { break }
            collected += buffer[0..<count]
        }
        var status: Int32 = 0
        XCTAssertEqual(waitpid(child, &status, 0), child)
        XCTAssertEqual(String(decoding: collected, as: UTF8.self), "TPLC")
    }

    // MARK: - Root-only record

    func testTheRecordHoldsOneFixedCodeInAPrivateFile() throws {
        let directory = NSTemporaryDirectory() + "hs-record-\(UUID().uuidString)"
        XCTAssertEqual(mkdir(directory, 0o700), 0)
        defer { try? FileManager.default.removeItem(atPath: directory) }
        let store = RootStartFailureStore(directoryPath: directory, fileName: "last-start-failure", expectedOwner: geteuid())
        XCTAssertNil(store.read())
        store.record(.credentialsHandoffInvalid)
        store.record(.credentialsDescriptorInvalid)
        XCTAssertEqual(store.read(), .credentialsDescriptorInvalid)
        let path = directory + "/last-start-failure"
        var status = stat()
        XCTAssertEqual(lstat(path, &status), 0)
        XCTAssertEqual(status.st_mode & 0o777, 0o600)
        XCTAssertEqual(try String(contentsOfFile: path, encoding: .utf8), "credentials_descriptor_invalid\n")
    }
}
