import Foundation
import XCTest
import HotspotShadeKit
@testable import HotspotShadeInstallerCore

final class ValidationTests: XCTestCase {
    private func builder(_ signatures: FakeSignatures = .standard) -> InstallerBuilder {
        InstallerBuilder(validator: InstallerValidator(signatures: signatures))
    }

    private func stageError(
        _ workspace: Workspace,
        _ signatures: FakeSignatures = .standard,
        inputs: InstallerInputs? = nil
    ) throws -> InstallerError? {
        let inputs = try inputs ?? workspace.goodInputs()
        do {
            _ = try builder(signatures).stage(inputs: inputs, version: "1.0.0", outputDirectory: workspace.path("out"))
            return nil
        } catch let error as InstallerError {
            // A rejected input leaves no partial output behind.
            XCTAssertFalse(FileManager.default.fileExists(atPath: workspace.path("out")))
            return error
        }
    }

    func testGoodInputsStage() throws {
        let workspace = try Workspace()
        let staged = try builder().stage(
            inputs: try workspace.goodInputs(), version: "1.2.3", outputDirectory: workspace.path("out")
        )
        XCTAssertEqual(staged.manifest.teamIdentifier, FakeSignatures.team)
        XCTAssertFalse(staged.manifest.packageSigned)
        XCTAssertFalse(staged.manifest.installationApproved)
        XCTAssertEqual(staged.manifest.files.count, 4)
        XCTAssertEqual(staged.manifest.scripts.count, 2)
        // Supplied files are never moved or changed.
        XCTAssertTrue(FileManager.default.fileExists(atPath: workspace.path("in-helper")))
    }

    func testAdHocHelperIsRejected() throws {
        let workspace = try Workspace()
        let adHoc = HelperSigningInfo(identifier: HelperRequirement.helperIdentifier, teamIdentifier: nil,
                                      isAdHoc: true, hasHardenedRuntime: true)
        XCTAssertEqual(try stageError(workspace, FakeSignatures.standard.replacing("helper", with: adHoc)),
                       .signatureRejected(.helper))
    }

    func testWrongIdentifierIsRejected() throws {
        let workspace = try Workspace()
        let wrong = FakeSignatures.good("dev.other.engine")
        XCTAssertEqual(try stageError(workspace, FakeSignatures.standard.replacing("engine", with: wrong)),
                       .signatureRejected(.engine))
    }

    func testIdentifierSwapBetweenHelperAndEngineIsRejected() throws {
        // A binary signed for one role does not pass in the other.
        let workspace = try Workspace()
        let inputs = try workspace.goodInputs(helper: fakeMachO(tag: "engine"), engine: fakeMachO(tag: "helper"))
        XCTAssertNotNil(try stageError(workspace, inputs: inputs))
    }

    func testDifferentTeamIsRejected() throws {
        let workspace = try Workspace()
        let other = FakeSignatures.good(HelperRequirement.engineIdentifier, team: "ZZZZZ99999")
        XCTAssertEqual(try stageError(workspace, FakeSignatures.standard.replacing("engine", with: other)),
                       .signatureRejected(.engine))
    }

    func testTeamMismatchAfterStaticCheckIsRejected() throws {
        // A checker that accepts the requirement but reports another team.
        struct Lenient: HelperCodeSignatureChecking {
            let inner: FakeSignatures
            func signingInfo(atPath path: String) throws -> HelperSigningInfo {
                let info = try inner.signingInfo(atPath: path)
                return path.hasSuffix(".app") ? info
                    : HelperSigningInfo(identifier: info.identifier, teamIdentifier: "ZZZZZ99999",
                                        isAdHoc: false, hasHardenedRuntime: true)
            }
            func verifyStaticCode(atPath path: String, requirement: String) throws {}
            func verifyRunningCode(auditToken: [UInt8], processIdentifier: Int32, requirement: String) throws {}
        }
        let workspace = try Workspace()
        let validator = InstallerValidator(signatures: Lenient(inner: .standard))
        XCTAssertThrowsError(try InstallerBuilder(validator: validator).stage(
            inputs: try workspace.goodInputs(), version: "1.0.0", outputDirectory: workspace.path("out")
        )) { XCTAssertEqual($0 as? InstallerError, .teamMismatch(.helper)) }
    }

    func testMissingHardenedRuntimeIsRejected() throws {
        let workspace = try Workspace()
        let weak = HelperSigningInfo(identifier: HelperRequirement.helperIdentifier,
                                     teamIdentifier: FakeSignatures.team, isAdHoc: false, hasHardenedRuntime: false)
        XCTAssertEqual(try stageError(workspace, FakeSignatures.standard.replacing("helper", with: weak)),
                       .signatureRejected(.helper))
    }

    func testDebuggerEntitlementIsRejected() throws {
        let workspace = try Workspace()
        let debug = HelperSigningInfo(identifier: HelperRequirement.engineIdentifier,
                                      teamIdentifier: FakeSignatures.team, isAdHoc: false,
                                      hasHardenedRuntime: true, allowsDebugging: true)
        XCTAssertEqual(try stageError(workspace, FakeSignatures.standard.replacing("engine", with: debug)),
                       .signatureRejected(.engine))
    }

    func testWeakeningEntitlementsAreRejected() throws {
        let workspace = try Workspace()
        for info in [
            HelperSigningInfo(identifier: HelperRequirement.helperIdentifier, teamIdentifier: FakeSignatures.team,
                              isAdHoc: false, hasHardenedRuntime: true, disablesLibraryValidation: true),
            HelperSigningInfo(identifier: HelperRequirement.helperIdentifier, teamIdentifier: FakeSignatures.team,
                              isAdHoc: false, hasHardenedRuntime: true, allowsDyldEnvironmentVariables: true),
        ] {
            XCTAssertEqual(try stageError(workspace, FakeSignatures.standard.replacing("helper", with: info)),
                           .signatureRejected(.helper))
        }
    }

    func testScriptInPlaceOfExecutableIsRejected() throws {
        let workspace = try Workspace()
        let inputs = try workspace.goodInputs(helper: Data("#!/bin/sh\nexit 0\n".utf8))
        XCTAssertEqual(try stageError(workspace, inputs: inputs), .notMachO(.helper))
    }

    func testEmptyInputIsRejected() throws {
        let workspace = try Workspace()
        let inputs = try workspace.goodInputs(engine: Data())
        XCTAssertEqual(try stageError(workspace, inputs: inputs), .inputTooLarge(.engine))
    }

    func testSymlinkInputIsRejected() throws {
        let workspace = try Workspace()
        let good = try workspace.goodInputs()
        let link = workspace.path("link-helper")
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: good.helper)
        let inputs = InstallerInputs(helper: link, engine: good.engine, launchDaemon: good.launchDaemon,
                                     startRight: good.startRight, app: good.app)
        XCTAssertEqual(try stageError(workspace, inputs: inputs), .inputUnreadable(.helper))
    }

    func testDirectoryInputIsRejected() throws {
        let workspace = try Workspace()
        let good = try workspace.goodInputs()
        let inputs = InstallerInputs(helper: workspace.directory.path, engine: good.engine,
                                     launchDaemon: good.launchDaemon, startRight: good.startRight, app: good.app)
        XCTAssertNotNil(try stageError(workspace, inputs: inputs))
    }

    func testUnsignedAppIsRejected() throws {
        let workspace = try Workspace()
        let adHoc = HelperSigningInfo(identifier: HelperRequirement.appIdentifier, teamIdentifier: nil,
                                      isAdHoc: true, hasHardenedRuntime: true)
        XCTAssertEqual(try stageError(workspace, FakeSignatures.standard.replacing("app", with: adHoc)),
                       .appNotSigned)
    }

    func testAppWithWrongIdentifierIsRejected() throws {
        let workspace = try Workspace()
        XCTAssertEqual(
            try stageError(workspace, FakeSignatures.standard.replacing("app", with: FakeSignatures.good("dev.other.app"))),
            .appNotSigned
        )
    }

    func testAppThatIsNotABundleIsRejected() throws {
        let workspace = try Workspace()
        let good = try workspace.goodInputs()
        let inputs = InstallerInputs(helper: good.helper, engine: good.engine, launchDaemon: good.launchDaemon,
                                     startRight: good.startRight, app: workspace.path("in-helper"))
        XCTAssertEqual(try stageError(workspace, inputs: inputs), .appNotSigned)
    }

    func testRunningAsRootIsRefused() throws {
        let workspace = try Workspace()
        let root = InstallerBuilder(validator: InstallerValidator(signatures: FakeSignatures.standard),
                                    effectiveUserID: { 0 })
        XCTAssertThrowsError(try root.stage(inputs: try workspace.goodInputs(), version: "1.0.0",
                                            outputDirectory: workspace.path("out"))) {
            XCTAssertEqual($0 as? InstallerError, .runningAsRoot)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: workspace.path("out")))
    }

    func testVersionIsValidated() {
        for good in ["1", "1.0", "1.2.3", "2026.11.5"] { XCTAssertTrue(InstallerBuilder.isValidVersion(good), good) }
        for bad in ["", "1.2.3.4", "1..2", "a.b", "1.2.", "../1", "1.0 --root /", "12345", "-1"] {
            XCTAssertFalse(InstallerBuilder.isValidVersion(bad), bad)
        }
    }

    // MARK: launch daemon file

    private func daemon(_ edit: (inout [String: Any]) -> Void) throws -> Data {
        var object = try PropertyListSerialization.propertyList(
            from: Data(contentsOf: Repo.launchDaemon), options: [], format: nil) as! [String: Any]
        edit(&object)
        return try plistData(object)
    }

    func testRepositoryLaunchDaemonTemplateIsAccepted() throws {
        try InstallerValidator(signatures: FakeSignatures.standard)
            .validateLaunchDaemon(Data(contentsOf: Repo.launchDaemon))
    }

    func testLaunchDaemonRefusals() throws {
        let validator = InstallerValidator(signatures: FakeSignatures.standard)
        let cases: [(String, (inout [String: Any]) -> Void)] = [
            ("environment", { $0["EnvironmentVariables"] = ["A": "b"] }),
            ("stdout redirect", { $0["StandardOutPath"] = "/etc/passwd" }),
            ("watch path", { $0["WatchPaths"] = ["/tmp"] }),
            ("run at load", { $0["RunAtLoad"] = true }),
            ("keep alive", { $0["KeepAlive"] = true }),
            ("run at load number", { $0["RunAtLoad"] = 0 }),
            ("missing keep alive", { $0.removeValue(forKey: "KeepAlive") }),
            ("other program", { $0["ProgramArguments"] = ["/tmp/helper"] }),
            ("extra argument", { $0["ProgramArguments"] = [HelperRequirement.helperExecutablePath, "--x"] }),
            ("other label", { $0["Label"] = "dev.other" }),
            ("extra service", { $0["MachServices"] = [HelperRequirement.helperServiceName: true, "dev.x": true] }),
            ("disabled service", { $0["MachServices"] = [HelperRequirement.helperServiceName: false] }),
            ("non-root user", { $0["UserName"] = "nobody" }),
            ("process type", { $0["ProcessType"] = "Background" }),
            ("exit timeout", { $0["ExitTimeOut"] = 0 }),
            ("throttle", { $0["ThrottleInterval"] = 100_000 }),
        ]
        for (name, edit) in cases {
            XCTAssertThrowsError(try validator.validateLaunchDaemon(try daemon(edit)), name) {
                if case .plistUnsafe(.launchDaemon, _)? = $0 as? InstallerError {} else { XCTFail("\(name): \($0)") }
            }
        }
        XCTAssertThrowsError(try validator.validateLaunchDaemon(Data("not a plist".utf8))) {
            XCTAssertEqual($0 as? InstallerError, .plistInvalid(.launchDaemon))
        }
    }

    // MARK: start right

    func testRepositoryStartRightTemplateIsAccepted() throws {
        try InstallerValidator(signatures: FakeSignatures.standard).validateStartRight(Data(contentsOf: Repo.startRight))
    }

    func testStartRightRefusals() throws {
        let validator = InstallerValidator(signatures: FakeSignatures.standard)
        let base = try PropertyListSerialization.propertyList(
            from: Data(contentsOf: Repo.startRight), options: [], format: nil) as! [String: Any]
        let cases: [(String, (inout [String: Any]) -> Void)] = [
            ("allow root", { $0["allow-root"] = true }),
            ("shared", { $0["shared"] = true }),
            ("no prompt", { $0["authenticate-user"] = false }),
            ("class", { $0["class"] = "allow" }),
            ("rule", { $0["rule"] = "allow" }),
            ("group", { $0["group"] = "staff" }),
            ("zero timeout", { $0["timeout"] = 0 }),
            ("negative timeout", { $0["timeout"] = -1 }),
            ("timeout above the ceiling", { $0["timeout"] = 61 }),
            ("long timeout", { $0["timeout"] = 300 }),
            ("real timeout", { $0["timeout"] = 10.0 }),
            ("missing shared", { $0.removeValue(forKey: "shared") }),
            ("mechanisms", { $0["mechanisms"] = ["x:y"] }),
            ("authd metadata in source", { $0["version"] = 1 }),
        ]
        for (name, edit) in cases {
            var object = base
            edit(&object)
            XCTAssertThrowsError(try validator.validateStartRight(plistData(object)), name) {
                if case .plistUnsafe(.startRight, _)? = $0 as? InstallerError {} else { XCTFail("\(name): \($0)") }
            }
        }
    }

    func testStartRightAcceptsEveryPositiveTimeoutInTheReviewedWindow() throws {
        let validator = InstallerValidator(signatures: FakeSignatures.standard)
        let base = try PropertyListSerialization.propertyList(
            from: Data(contentsOf: Repo.startRight), options: [], format: nil) as! [String: Any]
        for timeout in [1, 10, 60] {
            var object = base
            object["timeout"] = timeout
            XCTAssertNoThrow(
                try validator.validateStartRight(plistData(object)),
                "A timeout of \(timeout) must be accepted."
            )
        }
    }

    func testKitMaliciousStartRightFixturesAreRefused() throws {
        let validator = InstallerValidator(signatures: FakeSignatures.standard)
        for name in ["start-right-malicious-entitled.plist", "start-right-malicious-rule.plist"] {
            let data = try Data(contentsOf: Repo.kitFixtures.appendingPathComponent(name))
            XCTAssertThrowsError(try validator.validateStartRight(data), name)
        }
    }

    // MARK: output policy

    func testOutputPolicy() throws {
        let workspace = try Workspace()
        for bad in ["relative/out", "/Library/hs-out", "/System/hs-out", "/usr/local/hs-out",
                    "/private/var/db/hs-out", "/var/db/hs-out", "/Applications/hs-out",
                    "/etc/hs-out", "/private/etc/hs-out", "/", workspace.path("missing-parent/out")] {
            XCTAssertThrowsError(try OutputPolicy.resolve(bad), bad)
        }
        // A symlink to a system directory is resolved before the check.
        let link = workspace.path("to-library")
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: "/Library")
        XCTAssertThrowsError(try OutputPolicy.resolve(link + "/hs-out"))
        // A path that climbs out is standardized first.
        XCTAssertThrowsError(try OutputPolicy.resolve(workspace.path("a/../../../../../Library/x")))
        // An existing directory is refused.
        try FileManager.default.createDirectory(atPath: workspace.path("taken"), withIntermediateDirectories: false)
        XCTAssertThrowsError(try OutputPolicy.resolve(workspace.path("taken")))
        XCTAssertNoThrow(try OutputPolicy.resolve(workspace.path("fresh")))
    }
}
