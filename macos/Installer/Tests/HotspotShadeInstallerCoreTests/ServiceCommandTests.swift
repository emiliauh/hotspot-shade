import Foundation
import Darwin
import XCTest
@testable import HotspotShadeInstallerCore

// These tests never start a child process. The supervisor is driven through an
// injected spawner that owns real pipes but no real process, and the fake
// child kernel proves the signal-before-reap ordering. The fixed tool policy is
// driven through injected metadata. No test calls launchctl, security
// authorizationdb, the installer, a route, a TUN device, or the network.
//
// The real PosixCommandSpawner is not started here. Its pure argv rule is tested
// directly; its OS-level spawn, process-group signal, and reap path need a live
// root test with the two actual tools before release.
final class ServiceCommandTests: XCTestCase {
    private func rightData() throws -> Data {
        try ServiceTestFixtures.rightData(comment: "stored definition")
    }

    private func trustedFacts(mode: UInt16 = 0o755) -> FixedToolFacts {
        FixedToolFacts(
            isRegularFile: true,
            isSymbolicLink: false,
            owner: 0,
            mode: mode,
            hasExtendedACL: false
        )
    }

    private func fastLimits(
        terminationGrace: TimeInterval = 0.05,
        killGrace: TimeInterval = 0.05,
        drainGrace: TimeInterval = 0.1,
        joinGrace: TimeInterval = 0.1
    ) -> CommandProcessLimits {
        CommandProcessLimits(
            terminationGrace: terminationGrace,
            killGrace: killGrace,
            drainGrace: drainGrace,
            joinGrace: joinGrace
        )
    }

    private func plan(
        path: String = "/usr/bin/false",
        arguments: [String] = [],
        input: Data? = nil,
        timeout: TimeInterval = 1,
        outputLimit: Int = 1024
    ) -> CommandExecutionPlan {
        CommandExecutionPlan(
            executablePath: path,
            arguments: arguments,
            standardInput: input,
            timeout: timeout,
            maximumOutputBytes: outputLimit
        )
    }

    func testFixedCommandShapesUseAbsoluteToolsAndFixedArguments() throws {
        let read = PrivilegedServiceCommand.authorizationRightRead()
        XCTAssertEqual(read.toolPath, "/usr/bin/security")
        XCTAssertEqual(
            read.arguments,
            ["authorizationdb", "read", "dev.hotspotshade.tunnel.start"]
        )
        XCTAssertNil(read.standardInput)

        let definition = try rightData()
        let write = try PrivilegedServiceCommand.authorizationRightWrite(definition)
        XCTAssertEqual(write.toolPath, "/usr/bin/security")
        XCTAssertEqual(
            write.arguments,
            ["authorizationdb", "write", "dev.hotspotshade.tunnel.start"]
        )
        XCTAssertEqual(write.standardInput, definition)

        let remove = PrivilegedServiceCommand.authorizationRightRemove()
        XCTAssertEqual(remove.toolPath, "/usr/bin/security")
        XCTAssertEqual(
            remove.arguments,
            ["authorizationdb", "remove", "dev.hotspotshade.tunnel.start"]
        )

        let print = PrivilegedServiceCommand.launchdPrint()
        XCTAssertEqual(print.toolPath, "/bin/launchctl")
        XCTAssertEqual(
            print.arguments,
            ["print", "system/dev.hotspotshade.mac.helper"]
        )

        let bootout = PrivilegedServiceCommand.launchdBootout()
        XCTAssertEqual(bootout.toolPath, "/bin/launchctl")
        XCTAssertEqual(
            bootout.arguments,
            ["bootout", "system/dev.hotspotshade.mac.helper"]
        )

        let bootstrap = PrivilegedServiceCommand.launchdBootstrap()
        XCTAssertEqual(bootstrap.toolPath, "/bin/launchctl")
        XCTAssertEqual(
            bootstrap.arguments,
            [
                "bootstrap",
                "system",
                "/Library/LaunchDaemons/dev.hotspotshade.mac.helper.plist",
            ]
        )
    }

    func testEveryFixedCommandPassesShapeValidation() throws {
        let commands = [
            PrivilegedServiceCommand.authorizationRightRead(),
            try PrivilegedServiceCommand.authorizationRightWrite(try rightData()),
            PrivilegedServiceCommand.authorizationRightRemove(),
            PrivilegedServiceCommand.launchdPrint(),
            PrivilegedServiceCommand.launchdBootout(),
            PrivilegedServiceCommand.launchdBootstrap(),
        ]
        for command in commands {
            XCTAssertNoThrow(try command.validateFixedShape())
        }
    }

    func testNoCommandUsesAShellOrACommandString() throws {
        let definition = try rightData()
        let commands = [
            PrivilegedServiceCommand.authorizationRightRead(),
            try PrivilegedServiceCommand.authorizationRightWrite(definition),
            PrivilegedServiceCommand.authorizationRightRemove(),
            PrivilegedServiceCommand.launchdPrint(),
            PrivilegedServiceCommand.launchdBootout(),
            PrivilegedServiceCommand.launchdBootstrap(),
        ]
        for command in commands {
            XCTAssertTrue(command.toolPath.hasPrefix("/"))
            XCTAssertNotEqual(command.toolPath, "/bin/sh")
            XCTAssertNotEqual(command.toolPath, "/bin/zsh")
            XCTAssertLessThanOrEqual(
                command.arguments.count,
                PrivilegedServiceLayout.maximumArgumentCount
            )
            for argument in command.arguments {
                XCTAssertNotEqual(argument, "-c")
                XCTAssertFalse(argument.contains("\n"))
                XCTAssertFalse(argument.contains("\0"))
            }
            XCTAssertLessThanOrEqual(
                command.maximumOutputBytes,
                PrivilegedServiceLayout.maximumCommandOutputBytes
            )
            XCTAssertLessThanOrEqual(
                command.timeout,
                PrivilegedServiceLayout.maximumTimeout
            )
        }
    }

    func testOversizedRightDefinitionIsRefused() {
        let oversized = Data(
            repeating: 0x41,
            count: PrivilegedServiceLayout.maximumRightBytes + 1
        )
        XCTAssertThrowsError(try PrivilegedServiceCommand.authorizationRightWrite(oversized)) {
            XCTAssertEqual($0 as? PrivilegedServiceCommandError, .definitionTooLarge)
        }
        XCTAssertThrowsError(try PrivilegedServiceCommand.authorizationRightWrite(Data())) {
            XCTAssertEqual($0 as? PrivilegedServiceCommandError, .definitionTooLarge)
        }
    }

    func testCommandShapeRefusesToolArgumentTimeoutAndOutputDrift() throws {
        let expectedReadArguments = [
            "authorizationdb", "read", "dev.hotspotshade.tunnel.start",
        ]
        let wrongTool = PrivilegedServiceCommand.testCommand(
            operation: .authorizationRightRead,
            toolPath: "/bin/launchctl",
            arguments: expectedReadArguments,
            timeout: PrivilegedServiceLayout.inspectionTimeout
        )
        XCTAssertThrowsError(try wrongTool.validateFixedShape()) {
            XCTAssertEqual($0 as? PrivilegedServiceCommandError, .invalidShape("tool"))
        }

        let wrongArguments = PrivilegedServiceCommand.testCommand(
            operation: .authorizationRightRead,
            toolPath: PrivilegedServiceLayout.securityToolPath,
            arguments: ["authorizationdb", "read", "dev.hotspotshade.tunnel.other"],
            timeout: PrivilegedServiceLayout.inspectionTimeout
        )
        XCTAssertThrowsError(try wrongArguments.validateFixedShape()) {
            XCTAssertEqual($0 as? PrivilegedServiceCommandError, .invalidShape("arguments"))
        }

        let wrongTimeout = PrivilegedServiceCommand.testCommand(
            operation: .authorizationRightRead,
            toolPath: PrivilegedServiceLayout.securityToolPath,
            arguments: expectedReadArguments,
            timeout: 1
        )
        XCTAssertThrowsError(try wrongTimeout.validateFixedShape()) {
            XCTAssertEqual($0 as? PrivilegedServiceCommandError, .invalidShape("timeout"))
        }

        let wrongOutput = PrivilegedServiceCommand.testCommand(
            operation: .authorizationRightRead,
            toolPath: PrivilegedServiceLayout.securityToolPath,
            arguments: expectedReadArguments,
            timeout: PrivilegedServiceLayout.inspectionTimeout,
            maximumOutputBytes: PrivilegedServiceLayout.maximumCommandOutputBytes + 1
        )
        XCTAssertThrowsError(try wrongOutput.validateFixedShape()) {
            XCTAssertEqual($0 as? PrivilegedServiceCommandError, .invalidShape("output limit"))
        }

        let unexpectedInput = PrivilegedServiceCommand.testCommand(
            operation: .authorizationRightRead,
            toolPath: PrivilegedServiceLayout.securityToolPath,
            arguments: expectedReadArguments,
            standardInput: Data("x".utf8),
            timeout: PrivilegedServiceLayout.inspectionTimeout
        )
        XCTAssertThrowsError(try unexpectedInput.validateFixedShape()) {
            XCTAssertEqual($0 as? PrivilegedServiceCommandError, .invalidShape("input"))
        }

        let writeArguments = [
            "authorizationdb", "write", "dev.hotspotshade.tunnel.start",
        ]
        let oversizedInput = PrivilegedServiceCommand.testCommand(
            operation: .authorizationRightWrite,
            toolPath: PrivilegedServiceLayout.securityToolPath,
            arguments: writeArguments,
            standardInput: Data(
                repeating: 0x41,
                count: PrivilegedServiceLayout.maximumStandardInputBytes + 1
            ),
            timeout: PrivilegedServiceLayout.mutationTimeout
        )
        XCTAssertThrowsError(try oversizedInput.validateFixedShape()) {
            XCTAssertEqual($0 as? PrivilegedServiceCommandError, .definitionTooLarge)
        }

        let missingInput = PrivilegedServiceCommand.testCommand(
            operation: .authorizationRightWrite,
            toolPath: PrivilegedServiceLayout.securityToolPath,
            arguments: writeArguments,
            timeout: PrivilegedServiceLayout.mutationTimeout
        )
        XCTAssertThrowsError(try missingInput.validateFixedShape()) {
            XCTAssertEqual($0 as? PrivilegedServiceCommandError, .invalidShape("input"))
        }
    }

    func testFixedToolPolicyAcceptsOnlyTrustedRootOwnedRegularFiles() throws {
        let reader = FakeFixedToolReader()
        reader.values[PrivilegedServiceLayout.securityToolPath] = trustedFacts()
        reader.values[PrivilegedServiceLayout.launchctlToolPath] = trustedFacts()
        let policy = FixedPrivilegedToolPolicy(reader: reader)

        XCTAssertNoThrow(try policy.verify(path: PrivilegedServiceLayout.securityToolPath))
        XCTAssertNoThrow(try policy.verify(path: PrivilegedServiceLayout.launchctlToolPath))

        let refusals: [(String, FixedToolFacts?, FixedToolTrustError)] = [
            ("/tmp/security", trustedFacts(), .notAllowlisted),
            (PrivilegedServiceLayout.securityToolPath, nil, .missing),
            (
                PrivilegedServiceLayout.securityToolPath,
                FixedToolFacts(
                    isRegularFile: false,
                    isSymbolicLink: false,
                    owner: 0,
                    mode: 0o755,
                    hasExtendedACL: false
                ),
                .notRegularFile
            ),
            (
                PrivilegedServiceLayout.securityToolPath,
                FixedToolFacts(
                    isRegularFile: false,
                    isSymbolicLink: true,
                    owner: 0,
                    mode: 0o755,
                    hasExtendedACL: false
                ),
                .notRegularFile
            ),
            (
                PrivilegedServiceLayout.securityToolPath,
                FixedToolFacts(
                    isRegularFile: true,
                    isSymbolicLink: false,
                    owner: 501,
                    mode: 0o755,
                    hasExtendedACL: false
                ),
                .notOwnedByRoot
            ),
            (
                PrivilegedServiceLayout.securityToolPath,
                trustedFacts(mode: 0o775),
                .writableByNonRoot
            ),
            (
                PrivilegedServiceLayout.securityToolPath,
                trustedFacts(mode: 0o757),
                .writableByNonRoot
            ),
            (
                PrivilegedServiceLayout.securityToolPath,
                trustedFacts(mode: 0o4755),
                .setIdentifier
            ),
            (
                PrivilegedServiceLayout.securityToolPath,
                trustedFacts(mode: 0o2755),
                .setIdentifier
            ),
            (
                PrivilegedServiceLayout.securityToolPath,
                trustedFacts(mode: 0o644),
                .notExecutable
            ),
            (
                PrivilegedServiceLayout.securityToolPath,
                FixedToolFacts(
                    isRegularFile: true,
                    isSymbolicLink: false,
                    owner: 0,
                    mode: 0o755,
                    hasExtendedACL: true
                ),
                .extendedACL
            ),
        ]

        for (path, facts, expected) in refusals {
            if let facts {
                reader.values[path] = facts
            } else {
                reader.values.removeValue(forKey: path)
            }
            XCTAssertThrowsError(try policy.verify(path: path), "\(path) \(facts as Any)") {
                XCTAssertEqual($0 as? FixedToolTrustError, expected)
            }
        }

        reader.errors[PrivilegedServiceLayout.securityToolPath] = .unreadable
        XCTAssertThrowsError(try policy.verify(path: PrivilegedServiceLayout.securityToolPath)) {
            XCTAssertEqual($0 as? FixedToolTrustError, .unreadable)
        }
    }

    func testLiveRunnerRefusesBeforeItCanSpawnWhileUnapproved() {
        let spawner = FakeCommandSpawner()
        let reader = FakeFixedToolReader()
        reader.values[PrivilegedServiceLayout.securityToolPath] = trustedFacts()
        let runner = SystemPrivilegedCommandRunner(
            trust: FixedPrivilegedToolPolicy(reader: reader),
            supervisor: CommandProcessSupervisor(spawner: spawner)
        )

        XCTAssertFalse(CoordinatorPolicy.liveInstallationApproved)
        XCTAssertThrowsError(
            try runner.run(.authorizationRightRead())
        ) {
            #if HOTSPOTSHADE_LOCAL_PREVIEW && HOTSPOTSHADE_SYSTEM_PREVIEW_CANDIDATE
            XCTAssertEqual($0 as? PrivilegedCommandError, .requiresRoot)
            #else
            XCTAssertEqual($0 as? PrivilegedCommandError, .notApproved)
            #endif
        }
        XCTAssertEqual(spawner.spawnCount, 0)
    }

    func testSpawnArgumentVectorStartsWithTheExecutablePath() {
        XCTAssertEqual(
            CommandArgumentVector.argv(executablePath: "/bin/sleep", arguments: ["3"]),
            ["/bin/sleep", "3"]
        )
        XCTAssertEqual(
            CommandArgumentVector.argv(executablePath: "/bin/cat", arguments: []),
            ["/bin/cat"]
        )
        XCTAssertEqual(
            CommandArgumentVector.argv(
                executablePath: "/usr/bin/security",
                arguments: ["authorizationdb", "read", "dev.hotspotshade.tunnel.start"]
            ),
            [
                "/usr/bin/security",
                "authorizationdb",
                "read",
                "dev.hotspotshade.tunnel.start",
            ]
        )
    }

    func testSupervisorReturnsExitStatusAndBoundedOutput() throws {
        let spawner = FakeCommandSpawner()
        spawner.behavior = .exit(7)
        spawner.initialOutput = Data("out".utf8)
        spawner.initialError = Data("err".utf8)
        let supervisor = CommandProcessSupervisor(
            spawner: spawner,
            limits: fastLimits()
        )

        let result = try supervisor.run(plan())
        XCTAssertEqual(result.exitCode, 7)
        XCTAssertEqual(result.standardOutput, Data("out".utf8))
        XCTAssertEqual(result.standardError, Data("err".utf8))
        XCTAssertEqual(spawner.spawnCount, 1)
        XCTAssertEqual(spawner.child?.recordedSignals.count, 0)
    }

    func testSupervisorWritesTheFixedInputAndReportsDelivery() throws {
        let spawner = FakeCommandSpawner()
        spawner.behavior = .exit(0)
        spawner.exitAfterPolls = 10
        let supervisor = CommandProcessSupervisor(
            spawner: spawner,
            limits: fastLimits()
        )
        let input = Data("fixed input".utf8)

        let result = try supervisor.run(plan(input: input))
        XCTAssertEqual(result.exitCode, 0)
        XCTAssertEqual(spawner.child?.readInput(), input)
    }

    func testSupervisorRefusesOversizedInputBeforeSpawn() {
        let spawner = FakeCommandSpawner()
        let supervisor = CommandProcessSupervisor(
            spawner: spawner,
            limits: fastLimits()
        )
        let oversized = Data(
            repeating: 0x41,
            count: PrivilegedServiceLayout.maximumStandardInputBytes + 1
        )
        XCTAssertThrowsError(try supervisor.run(plan(input: oversized))) {
            XCTAssertEqual($0 as? CommandPlanError, .inputTooLarge)
        }
        XCTAssertEqual(spawner.spawnCount, 0)
    }

    func testSupervisorRefusesPlanLimitsAndShapes() {
        let cases: [(CommandExecutionPlan, CommandPlanError)] = [
            (plan(path: "usr/bin/false"), .pathNotAbsolute),
            (
                plan(path: "/" + String(repeating: "a", count: 2000)),
                .pathTooLong
            ),
            (
                plan(arguments: (0..<9).map { "\($0)" }),
                .argumentCount
            ),
            (
                plan(arguments: [String(repeating: "a", count: 5000)]),
                .argumentBytes
            ),
            (plan(arguments: ["a\nb"]), .invalidArgument),
            (plan(outputLimit: 0), .outputLimit),
            (
                plan(outputLimit: PrivilegedServiceLayout.maximumCommandOutputBytes + 1),
                .outputLimit
            ),
            (plan(timeout: 0), .timeout),
            (plan(timeout: PrivilegedServiceLayout.maximumTimeout + 1), .timeout),
        ]
        for (candidate, expected) in cases {
            XCTAssertThrowsError(try CommandProcessSupervisor.validate(candidate)) {
                XCTAssertEqual($0 as? CommandPlanError, expected)
            }
        }
    }

    func testSupervisorStopsAtTheOutputLimitAndTerminatesTheChild() {
        let spawner = FakeCommandSpawner()
        spawner.behavior = .runUntilSignal(
            ignoreTerm: true,
            ignoreKill: false,
            exitCode: 0
        )
        spawner.initialOutput = Data(repeating: 0x41, count: 128)
        let supervisor = CommandProcessSupervisor(
            spawner: spawner,
            limits: fastLimits()
        )

        XCTAssertThrowsError(
            try supervisor.run(plan(timeout: 5, outputLimit: 64))
        ) {
            XCTAssertEqual($0 as? PrivilegedCommandError, .outputTooLarge)
        }
        XCTAssertEqual(spawner.child?.recordedSignals ?? [], [SIGTERM, SIGKILL])
    }

    func testSupervisorOutputLimitAppliesAcrossBothStreams() {
        let spawner = FakeCommandSpawner()
        spawner.behavior = .runUntilSignal(
            ignoreTerm: true,
            ignoreKill: false,
            exitCode: 0
        )
        spawner.initialOutput = Data(repeating: 0x41, count: 40)
        spawner.initialError = Data(repeating: 0x42, count: 40)
        let supervisor = CommandProcessSupervisor(
            spawner: spawner,
            limits: fastLimits()
        )

        XCTAssertThrowsError(
            try supervisor.run(plan(timeout: 5, outputLimit: 64))
        ) {
            XCTAssertEqual($0 as? PrivilegedCommandError, .outputTooLarge)
        }
    }

    func testSupervisorTimesOutAndReturnsEvenWhenPipesStayOpen() {
        let spawner = FakeCommandSpawner()
        spawner.behavior = .runUntilSignal(
            ignoreTerm: true,
            ignoreKill: true,
            exitCode: 0
        )
        spawner.closePipesOnExit = false
        let supervisor = CommandProcessSupervisor(
            spawner: spawner,
            limits: fastLimits(
                terminationGrace: 0.05,
                killGrace: 0.05,
                drainGrace: 0.05,
                joinGrace: 0.05
            )
        )

        let started = Date()
        XCTAssertThrowsError(try supervisor.run(plan(timeout: 0.05))) {
            XCTAssertEqual($0 as? PrivilegedCommandError, .timedOut)
        }
        XCTAssertLessThan(Date().timeIntervalSince(started), 2.0)
        XCTAssertEqual(spawner.child?.recordedSignals ?? [], [SIGTERM, SIGKILL])
    }

    func testSupervisorStopsAfterTermWhenTheChildExits() {
        let spawner = FakeCommandSpawner()
        spawner.behavior = .runUntilSignal(
            ignoreTerm: false,
            ignoreKill: false,
            exitCode: 0
        )
        spawner.closePipesOnExit = false
        let supervisor = CommandProcessSupervisor(
            spawner: spawner,
            limits: fastLimits()
        )

        XCTAssertThrowsError(try supervisor.run(plan(timeout: 0.05))) {
            XCTAssertEqual($0 as? PrivilegedCommandError, .timedOut)
        }
        XCTAssertEqual(spawner.child?.recordedSignals ?? [], [SIGTERM])
    }

    func testSupervisorFailsClosedWhenAPipeOutlivesTheChild() {
        let spawner = FakeCommandSpawner()
        spawner.behavior = .exit(0)
        spawner.closePipesOnExit = false
        let supervisor = CommandProcessSupervisor(
            spawner: spawner,
            limits: fastLimits(drainGrace: 0.1, joinGrace: 0.05)
        )

        let started = Date()
        XCTAssertThrowsError(try supervisor.run(plan(timeout: 1))) {
            XCTAssertEqual($0 as? PrivilegedCommandError, .outputIncomplete)
        }
        XCTAssertLessThan(Date().timeIntervalSince(started), 1.5)
        XCTAssertEqual(spawner.child?.recordedSignals.count, 0)
    }

    func testSupervisorRejectsAReaderThatFailsBeforeEOF() {
        let spawner = FakeCommandSpawner()
        spawner.invalidOutputDescriptor = true
        let supervisor = CommandProcessSupervisor(spawner: spawner, limits: fastLimits())

        XCTAssertThrowsError(try supervisor.run(plan())) {
            XCTAssertEqual($0 as? PrivilegedCommandError, .outputIncomplete)
        }
    }

    func testSupervisorReportsAnInputWriteFailureForAZeroExit() {
        let spawner = FakeCommandSpawner()
        spawner.behavior = .exit(0)
        spawner.closeInputBeforeReturn = true
        let supervisor = CommandProcessSupervisor(
            spawner: spawner,
            limits: fastLimits()
        )

        XCTAssertThrowsError(
            try supervisor.run(plan(input: Data("input".utf8)))
        ) {
            XCTAssertEqual($0 as? PrivilegedCommandError, .inputWriteFailed)
        }
    }

    func testSupervisorKeepsTheChildFailureWhenInputAlsoFailed() throws {
        let spawner = FakeCommandSpawner()
        spawner.behavior = .exit(1)
        spawner.closeInputBeforeReturn = true
        let supervisor = CommandProcessSupervisor(
            spawner: spawner,
            limits: fastLimits()
        )

        let result = try supervisor.run(plan(input: Data("input".utf8)))
        XCTAssertEqual(result.exitCode, 1)
    }

    func testPosixChildNeverSignalsAfterReap() {
        let kernel = FakeCommandChildKernel()
        kernel.waitResults = [
            (0, 0, 0),
            (4242, 7 << 8, 0),
        ]
        let child = PosixSpawnedCommand(
            processIdentifier: 4242,
            usesProcessGroup: true,
            standardInputDescriptor: -1,
            standardOutputDescriptor: -1,
            standardErrorDescriptor: -1,
            kernel: kernel
        )

        XCTAssertNil(child.pollExit())
        child.signal(SIGTERM)
        XCTAssertEqual(kernel.killCalls.count, 1)
        XCTAssertEqual(kernel.killCalls[0].signal, SIGTERM)
        XCTAssertTrue(kernel.killCalls[0].group)

        XCTAssertEqual(child.pollExit()?.exitCode, 7)
        child.signal(SIGKILL)
        XCTAssertEqual(kernel.killCalls.count, 1)
        XCTAssertEqual(kernel.waitCalls, 2)

        // A cached exit is returned without another waitpid call.
        XCTAssertEqual(child.pollExit()?.exitCode, 7)
        XCTAssertEqual(kernel.waitCalls, 2)
    }

    func testSystemToolReaderRefusesAMissingPath() {
        let missing = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString).path
        XCTAssertThrowsError(try SystemFixedToolFactReader().facts(atPath: missing)) {
            XCTAssertEqual($0 as? FixedToolTrustError, .missing)
        }
    }

    func testPosixChildDoesNotTreatOtherWaitErrorsAsReaped() {
        let kernel = FakeCommandChildKernel()
        kernel.waitResults = [(-1, 0, EINTR), (-1, 0, EIO), (-1, 0, ECHILD)]
        let child = PosixSpawnedCommand(
            processIdentifier: 4242,
            usesProcessGroup: false,
            standardInputDescriptor: -1,
            standardOutputDescriptor: -1,
            standardErrorDescriptor: -1,
            kernel: kernel
        )

        XCTAssertNil(child.pollExit())
        XCTAssertNil(child.pollExit())
        child.signal(SIGTERM)
        XCTAssertEqual(kernel.killCalls.count, 1)
        XCTAssertEqual(child.pollExit()?.exitCode, 127)
        child.signal(SIGKILL)
        XCTAssertEqual(kernel.killCalls.count, 1)
    }

    func testPosixChildFallsBackToPidOnlyWhenTheGroupIsNotConfirmed() {
        let kernel = FakeCommandChildKernel()
        let child = PosixSpawnedCommand(
            processIdentifier: 4242,
            usesProcessGroup: false,
            standardInputDescriptor: -1,
            standardOutputDescriptor: -1,
            standardErrorDescriptor: -1,
            kernel: kernel
        )

        child.signal(SIGTERM)
        XCTAssertEqual(kernel.killCalls.count, 1)
        XCTAssertFalse(kernel.killCalls[0].group)
    }

    func testPosixChildDecodesASignalTerminationAsFailure() {
        let kernel = FakeCommandChildKernel()
        kernel.waitResults = [(4242, SIGTERM, 0)]
        let child = PosixSpawnedCommand(
            processIdentifier: 4242,
            usesProcessGroup: true,
            standardInputDescriptor: -1,
            standardOutputDescriptor: -1,
            standardErrorDescriptor: -1,
            kernel: kernel
        )

        let exit = child.pollExit()
        XCTAssertEqual(exit?.termSignal, SIGTERM)
        XCTAssertEqual(exit?.exitCode, 128 + SIGTERM)
    }
}

// A fake tool metadata reader. It never touches the file system.
private final class FakeFixedToolReader: FixedToolFactReading, @unchecked Sendable {
    var values: [String: FixedToolFacts] = [:]
    var errors: [String: FixedToolTrustError] = [:]

    func facts(atPath path: String) throws -> FixedToolFacts {
        if let error = errors[path] { throw error }
        guard let value = values[path] else { throw FixedToolTrustError.missing }
        return value
    }
}

// One fake child with real pipes and no process. The tests can keep the write
// ends open to model a descendant that retains the output pipe.
private final class FakeSpawnedCommand: SpawnedCommand, @unchecked Sendable {
    enum Behavior {
        case exit(Int32)
        case runUntilSignal(ignoreTerm: Bool, ignoreKill: Bool, exitCode: Int32)
    }

    private let lock = NSLock()
    private let behavior: Behavior
    private let closePipesOnExit: Bool
    private var inputRead: Int32
    private var outputWrite: Int32
    private var errorWrite: Int32
    private var pollsBeforeExit: Int
    private var exit: CommandExit?
    private var signals: [Int32] = []
    private var inputReadClosed = false
    private var writeEndsClosed = false

    let standardInputDescriptor: Int32
    let standardOutputDescriptor: Int32
    let standardErrorDescriptor: Int32

    init(
        behavior: Behavior,
        closePipesOnExit: Bool,
        pollsBeforeExit: Int,
        invalidOutputDescriptor: Bool = false
    ) throws {
        self.behavior = behavior
        self.closePipesOnExit = closePipesOnExit
        self.pollsBeforeExit = pollsBeforeExit

        var input: [Int32] = [-1, -1]
        var output: [Int32] = [-1, -1]
        var error: [Int32] = [-1, -1]
        guard pipe(&input) == 0 else {
            throw PrivilegedCommandError.spawnFailed("fake input pipe")
        }
        guard pipe(&output) == 0 else {
            close(input[0])
            close(input[1])
            throw PrivilegedCommandError.spawnFailed("fake output pipe")
        }
        guard pipe(&error) == 0 else {
            close(input[0])
            close(input[1])
            close(output[0])
            close(output[1])
            throw PrivilegedCommandError.spawnFailed("fake error pipe")
        }

        self.inputRead = input[0]
        self.outputWrite = output[1]
        self.errorWrite = error[1]
        self.standardInputDescriptor = input[1]
        if invalidOutputDescriptor { close(output[0]) }
        self.standardOutputDescriptor = invalidOutputDescriptor ? -1 : output[0]
        self.standardErrorDescriptor = error[0]
    }

    deinit {
        closeIfOpen(inputRead)
        closeIfOpen(outputWrite)
        closeIfOpen(errorWrite)
    }

    var recordedSignals: [Int32] {
        lock.lock()
        defer { lock.unlock() }
        return signals
    }

    func pollExit() -> CommandExit? {
        lock.lock()
        defer { lock.unlock() }
        if let exit { return exit }
        switch behavior {
        case .exit(let code):
            guard pollsBeforeExit == 0 else {
                pollsBeforeExit -= 1
                return nil
            }
            let value = CommandExit(exitCode: code, termSignal: nil)
            exit = value
            if closePipesOnExit { closeWriteEndsLocked() }
            return value
        case .runUntilSignal:
            return nil
        }
    }

    func signal(_ signal: Int32) {
        lock.lock()
        defer { lock.unlock() }
        guard exit == nil else { return }
        signals.append(signal)
        guard case .runUntilSignal(let ignoreTerm, let ignoreKill, let code) = behavior else {
            return
        }
        let shouldExit = (signal == SIGTERM && !ignoreTerm)
            || (signal == SIGKILL && !ignoreKill)
        guard shouldExit else { return }
        exit = CommandExit(exitCode: code, termSignal: signal)
        if closePipesOnExit { closeWriteEndsLocked() }
    }

    func writeOutput(_ data: Data) {
        write(data, to: outputWrite)
    }

    func writeError(_ data: Data) {
        write(data, to: errorWrite)
    }

    func closeInputReadEnd() {
        lock.lock()
        defer { lock.unlock() }
        guard !inputReadClosed else { return }
        inputReadClosed = true
        closeIfOpen(inputRead)
        inputRead = -1
    }

    func readInput() -> Data {
        lock.lock()
        let descriptor = inputRead
        let alreadyClosed = inputReadClosed
        lock.unlock()
        guard !alreadyClosed, descriptor >= 0 else { return Data() }

        var result = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = buffer.withUnsafeMutableBytes { bytes in
                read(descriptor, bytes.baseAddress, bytes.count)
            }
            if count > 0 {
                result.append(contentsOf: buffer[0..<count])
                continue
            }
            break
        }
        return result
    }

    private func write(_ data: Data, to descriptor: Int32) {
        guard descriptor >= 0 else { return }
        _ = data.withUnsafeBytes { bytes in
            Darwin.write(descriptor, bytes.baseAddress, bytes.count)
        }
    }

    private func closeWriteEndsLocked() {
        guard !writeEndsClosed else { return }
        writeEndsClosed = true
        closeIfOpen(outputWrite)
        closeIfOpen(errorWrite)
        outputWrite = -1
        errorWrite = -1
    }

    private func closeIfOpen(_ descriptor: Int32) {
        guard descriptor >= 0 else { return }
        close(descriptor)
    }
}

private final class FakeCommandSpawner: CommandSpawning, @unchecked Sendable {
    var behavior: FakeSpawnedCommand.Behavior = .exit(0)
    var closePipesOnExit = true
    var closeInputBeforeReturn = false
    var invalidOutputDescriptor = false
    var exitAfterPolls = 2
    var initialOutput = Data()
    var initialError = Data()
    var spawnError: Error?
    private(set) var spawnCount = 0
    private(set) var child: FakeSpawnedCommand?

    func spawn(_ plan: CommandExecutionPlan) throws -> any SpawnedCommand {
        spawnCount += 1
        if let spawnError { throw spawnError }
        let child = try FakeSpawnedCommand(
            behavior: behavior,
            closePipesOnExit: closePipesOnExit,
            pollsBeforeExit: exitAfterPolls,
            invalidOutputDescriptor: invalidOutputDescriptor
        )
        self.child = child
        if !initialOutput.isEmpty { child.writeOutput(initialOutput) }
        if !initialError.isEmpty { child.writeError(initialError) }
        if closeInputBeforeReturn { child.closeInputReadEnd() }
        return child
    }
}

private final class FakeCommandChildKernel: CommandChildKernel, @unchecked Sendable {
    var waitResults: [(result: pid_t, status: Int32, code: Int32)] = []
    private(set) var waitCalls = 0
    private(set) var killCalls: [(signal: Int32, group: Bool)] = []

    func wait(pid: pid_t, options: Int32) -> (result: pid_t, status: Int32, code: Int32) {
        waitCalls += 1
        guard !waitResults.isEmpty else { return (0, 0, 0) }
        return waitResults.removeFirst()
    }

    func killGroup(_ pid: pid_t, _ signal: Int32) -> Int32 {
        killCalls.append((signal, true))
        return 0
    }

    func killProcess(_ pid: pid_t, _ signal: Int32) -> Int32 {
        killCalls.append((signal, false))
        return 0
    }
}
