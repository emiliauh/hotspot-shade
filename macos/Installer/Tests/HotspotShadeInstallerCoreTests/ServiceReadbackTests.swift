import Foundation
import Security
import XCTest
@testable import HotspotShadeInstallerCore

// The production command wrappers are driven through a fake runner. No test
// calls launchctl, security authorizationdb, or AuthorizationRightGet.
final class ServiceReadbackTests: XCTestCase {
    private func result(
        _ exitCode: Int32,
        output: Data = Data(),
        error: Data = Data()
    ) -> PrivilegedCommandResult {
        PrivilegedCommandResult(
            exitCode: exitCode,
            standardOutput: output,
            standardError: error
        )
    }

    func testLaunchdPrintReadbackAcceptsTheExactInstalledJob() throws {
        let runner = RecordingCommandRunner()
        runner.results[.launchdPrint] = result(
            0,
            output: Data(ServiceTestFixtures.samplePrint.utf8)
        )
        let controller = CommandLaunchdJobController(runner: runner)

        let observation = try controller.observe()
        XCTAssertEqual(observation, .loaded(ServiceTestFixtures.readback))
        XCTAssertEqual(runner.commands.map(\.operation), [.launchdPrint])
    }

    func testLaunchdPrintReadbackRefusesADifferentProgramOrPath() throws {
        let runner = RecordingCommandRunner()
        runner.results[.launchdPrint] = result(
            0,
            output: Data(
                """
                system/dev.hotspotshade.mac.helper = {
                \tpath = /tmp/another.plist
                \tprogram = /tmp/another-helper
                }
                """.utf8
            )
        )
        let controller = CommandLaunchdJobController(runner: runner)

        guard case .unexpected = try controller.observe() else {
            return XCTFail("a different job was accepted")
        }
    }

    func testLaunchdPrintAbsenceNeedsStatus113AndTheFixedDiagnostic() throws {
        let runner = RecordingCommandRunner()
        let controller = CommandLaunchdJobController(runner: runner)

        runner.results[.launchdPrint] = result(
            113,
            error: Data("Could not find service \"dev.hotspotshade.mac.helper\" in domain for system\n".utf8)
        )
        XCTAssertEqual(try controller.observe(), .absent)

        runner.results[.launchdPrint] = result(113)
        guard case .unknown = try controller.observe() else {
            return XCTFail("status 113 without the diagnostic was treated as absence")
        }

        runner.results[.launchdPrint] = result(
            1,
            error: Data("Could not find service\n".utf8)
        )
        guard case .unknown = try controller.observe() else {
            return XCTFail("a non-113 status was treated as absence")
        }
    }

    func testLaunchdPrintRunnerFailureIsUnknown() throws {
        let runner = RecordingCommandRunner()
        runner.error = PrivilegedCommandError.notApproved
        let controller = CommandLaunchdJobController(runner: runner)

        guard case .unknown = try controller.observe() else {
            return XCTFail("a runner failure was treated as a job state")
        }
    }

    func testAuthorizationReadbackUsesTheSafePolicyParser() throws {
        let runner = RecordingCommandRunner()
        let definition = try ServiceTestFixtures.rightData(comment: "stored definition")
        runner.results[.authorizationRightRead] = result(0, output: definition)
        let database = CommandAuthorizationRightDatabase(
            runner: runner,
            presence: FakeExistenceProbe(false)
        )

        guard case .present(let snapshot) = try database.observe() else {
            return XCTFail("the stored right was treated as absent")
        }
        XCTAssertEqual(snapshot, try AuthorizationRightPolicyParser.parse(definition))
        XCTAssertEqual(runner.commands.map(\.operation), [.authorizationRightRead])
    }

    func testAuthorizationReadbackRefusesAnInvalidDefinition() throws {
        let runner = RecordingCommandRunner()
        runner.results[.authorizationRightRead] = result(
            0,
            output: Data("not a property list".utf8)
        )
        let database = CommandAuthorizationRightDatabase(
            runner: runner,
            presence: FakeExistenceProbe(false)
        )

        XCTAssertThrowsError(try database.observe()) {
            guard let error = $0 as? AuthorizationRightDatabaseError,
                  case .readbackInvalid = error
            else {
                return XCTFail("\($0)")
            }
        }
    }

    func testAuthorizationReadFailureUsesTheExistenceProbe() throws {
        let runner = RecordingCommandRunner()
        runner.results[.authorizationRightRead] = result(1)

        let absent = CommandAuthorizationRightDatabase(
            runner: runner,
            presence: FakeExistenceProbe(false)
        )
        XCTAssertEqual(try absent.observe(), .absent)

        let present = CommandAuthorizationRightDatabase(
            runner: runner,
            presence: FakeExistenceProbe(true)
        )
        XCTAssertThrowsError(try present.observe()) {
            guard let error = $0 as? AuthorizationRightDatabaseError,
                  case .unreadable = error
            else {
                return XCTFail("\($0)")
            }
        }

        let failedProbe = CommandAuthorizationRightDatabase(
            runner: runner,
            presence: FakeExistenceProbe(
                error: AuthorizationRightDatabaseError.unreadable("injected")
            )
        )
        XCTAssertThrowsError(try failedProbe.observe()) {
            guard let error = $0 as? AuthorizationRightDatabaseError,
                  case .unreadable = error
            else {
                return XCTFail("\($0)")
            }
        }
    }

    func testAuthorizationObserverRunnerFailureIsUnreadable() throws {
        let runner = RecordingCommandRunner()
        runner.error = PrivilegedCommandError.notApproved
        let database = CommandAuthorizationRightDatabase(
            runner: runner,
            presence: FakeExistenceProbe(false)
        )

        XCTAssertThrowsError(try database.observe()) {
            guard let error = $0 as? AuthorizationRightDatabaseError,
                  case .unreadable = error
            else {
                return XCTFail("\($0)")
            }
        }
    }

    func testAuthorizationWriteAndRemoveUseFixedCommandsAndCheckTheStatus() throws {
        let runner = RecordingCommandRunner()
        let database = CommandAuthorizationRightDatabase(
            runner: runner,
            presence: FakeExistenceProbe(false)
        )
        let definition = try ServiceTestFixtures.rightData(comment: "stored definition")

        try database.write(definition)
        XCTAssertEqual(
            runner.commands.last,
            try PrivilegedServiceCommand.authorizationRightWrite(definition)
        )

        try database.remove()
        XCTAssertEqual(
            runner.commands.last,
            PrivilegedServiceCommand.authorizationRightRemove()
        )

        runner.results[.authorizationRightWrite] = result(1)
        XCTAssertThrowsError(try database.write(definition)) {
            guard let error = $0 as? AuthorizationRightDatabaseError,
                  case .commandFailed = error
            else {
                return XCTFail("\($0)")
            }
        }

        runner.results[.authorizationRightRemove] = result(1)
        XCTAssertThrowsError(try database.remove()) {
            guard let error = $0 as? AuthorizationRightDatabaseError,
                  case .commandFailed = error
            else {
                return XCTFail("\($0)")
            }
        }
    }

    func testAuthorizationAbsenceProbeMapsOnlyDeniedToAbsence() throws {
        let success = SecurityAuthorizationRightExistenceProbe { _ in errAuthorizationSuccess }
        XCTAssertTrue(try success.isPresent())

        let denied = SecurityAuthorizationRightExistenceProbe { _ in errAuthorizationDenied }
        XCTAssertFalse(try denied.isPresent())

        let failure = SecurityAuthorizationRightExistenceProbe { _ in OSStatus(-1) }
        XCTAssertThrowsError(try failure.isPresent()) {
            guard let error = $0 as? AuthorizationRightDatabaseError,
                  case .unreadable = error
            else {
                return XCTFail("\($0)")
            }
        }
    }
}
