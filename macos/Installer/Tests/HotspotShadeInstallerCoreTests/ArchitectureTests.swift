import Foundation
import XCTest
import HotspotShadeKit
@testable import HotspotShadeInstallerCore

// The Security framework checks one slice of a universal file. The installer
// therefore accepts only one thin arm64 executable for the helper, the engine,
// and the app's main executable. These tests show that every other shape is
// refused before a signature check runs.
final class ArchitectureTests: XCTestCase {
    private let x86: UInt32 = 0x0100_0007
    private let arm64: UInt32 = 0x0100_000C

    private func classify(_ data: Data, in workspace: Workspace, name: String = "file") throws -> MachOPolicy.Verdict {
        MachOPolicy.classify(atPath: try workspace.write(name, data))
    }

    // MARK: policy on fake headers

    func testThinArm64ExecutableIsAccepted() throws {
        let workspace = try Workspace()
        XCTAssertEqual(try classify(fakeMachO(tag: "helper"), in: workspace), .thinArm64Executable)
    }

    func testRefusedShapes() throws {
        let workspace = try Workspace()
        let thin = fakeMachO(tag: "helper")
        let cases: [(String, Data, MachOPolicy.Verdict)] = [
            ("x86_64", fakeMachO(tag: "helper", cpuType: x86), .unsupported),
            ("arm64e", fakeMachO(tag: "helper", cpuSubtype: 2), .unsupported),
            ("32-bit arm", fakeMachO(tag: "helper", cpuType: 0x0000_000C), .unsupported),
            ("dylib", fakeMachO(tag: "helper", fileType: 6), .unsupported),
            ("bundle", fakeMachO(tag: "helper", fileType: 8), .unsupported),
            ("no signature command", fakeMachO(tag: "helper", withSignatureCommand: false), .unsupported),
            ("signature outside the file", fakeMachO(tag: "helper", signatureOffset: 1_000_000), .unsupported),
            ("fat arm64 and x86_64", fakeFat([(arm64, thin), (x86, fakeMachO(tag: "helper", cpuType: x86))]), .unsupported),
            ("fat arm64 only", fakeFat([(arm64, thin)]), .unsupported),
            ("fat x86_64 only", fakeFat([(x86, fakeMachO(tag: "helper", cpuType: x86))]), .unsupported),
            ("32-bit magic", Data([0xCE, 0xFA, 0xED, 0xFE]) + Data(repeating: 0, count: 64), .unsupported),
            ("big-endian magic", Data([0xFE, 0xED, 0xFA, 0xCF]) + Data(repeating: 0, count: 64), .unsupported),
            ("script", Data("#!/bin/sh\nexit 0\n".utf8), .notMachO),
            ("empty", Data(), .notMachO),
            ("three bytes", Data([0xCF, 0xFA, 0xED]), .notMachO),
        ]
        for (name, data, verdict) in cases {
            XCTAssertEqual(try classify(data, in: workspace, name: "f-" + name.replacingOccurrences(of: " ", with: "-")),
                           verdict, name)
        }
    }

    func testTruncatedAndMalformedLoadCommandsAreRefused() throws {
        let workspace = try Workspace()
        let good = fakeMachO(tag: "helper")
        // The header says one 16-byte command but the file ends inside it.
        XCTAssertEqual(try classify(good.prefix(40), in: workspace, name: "short"), .unsupported)
        // A header only.
        XCTAssertEqual(try classify(good.prefix(32), in: workspace, name: "header-only"), .unsupported)
        // A command size that is not a multiple of 8.
        var odd = good
        odd[36] = 12
        XCTAssertEqual(try classify(odd, in: workspace, name: "odd"), .unsupported)
        // The command count says two but the commands end after one.
        var counted = good
        counted[16] = 2
        XCTAssertEqual(try classify(counted, in: workspace, name: "counted"), .unsupported)
    }

    func testSymlinkAndDirectoryAreNotMachO() throws {
        let workspace = try Workspace()
        let real = try workspace.write("real", fakeMachO(tag: "helper"))
        let link = workspace.path("link")
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: real)
        XCTAssertEqual(MachOPolicy.classify(atPath: link), .notMachO)
        XCTAssertEqual(MachOPolicy.classify(atPath: workspace.directory.path), .notMachO)
        XCTAssertEqual(MachOPolicy.classify(atPath: workspace.path("missing")), .notMachO)
    }

    // MARK: policy on real compiler output

    func testRealThinArm64IsAcceptedAndRealUniversalIsRefused() throws {
        let workspace = try Workspace()
        let arm = try workspace.compileExecutable(architecture: "arm64", name: "real-arm64")
        let intel = try workspace.compileExecutable(architecture: "x86_64", name: "real-x86")
        let fat = try workspace.universalExecutable(of: arm, and: intel, name: "real-fat")
        XCTAssertEqual(MachOPolicy.classify(atPath: arm), .thinArm64Executable)
        XCTAssertEqual(MachOPolicy.classify(atPath: intel), .unsupported)
        XCTAssertEqual(MachOPolicy.classify(atPath: fat), .unsupported)
    }

    // MARK: the validator

    private func stageError(
        _ workspace: Workspace,
        inputs: InstallerInputs
    ) throws -> InstallerError? {
        let builder = InstallerBuilder(validator: InstallerValidator(signatures: FakeSignatures.standard))
        do {
            _ = try builder.stage(inputs: inputs, version: "1.0.0", outputDirectory: workspace.path("out"))
            return nil
        } catch let error as InstallerError {
            XCTAssertFalse(FileManager.default.fileExists(atPath: workspace.path("out")))
            return error
        }
    }

    func testMixedFatHelperAndEngineAreRefusedEvenWithGoodSignatureFacts() throws {
        // The fake checker says every tag is validly signed. The fat file must
        // be refused on its shape alone.
        let workspace = try Workspace()
        let mixed = fakeFat([
            (arm64, fakeMachO(tag: "helper")),
            (x86, fakeMachO(tag: "helper", cpuType: x86)),
        ])
        XCTAssertEqual(try stageError(workspace, inputs: try workspace.goodInputs(helper: mixed)),
                       .unsupportedArchitecture(.helper))
        let mixedEngine = fakeFat([
            (arm64, fakeMachO(tag: "engine")),
            (x86, fakeMachO(tag: "engine", cpuType: x86)),
        ])
        XCTAssertEqual(try stageError(workspace, inputs: try workspace.goodInputs(engine: mixedEngine)),
                       .unsupportedArchitecture(.engine))
    }

    func testNonArm64ThinHelperIsRefused() throws {
        let workspace = try Workspace()
        let intel = fakeMachO(tag: "helper", cpuType: x86)
        XCTAssertEqual(try stageError(workspace, inputs: try workspace.goodInputs(helper: intel)),
                       .unsupportedArchitecture(.helper))
    }

    func testAppMainExecutableMustBeThinArm64() throws {
        let thin = fakeMachO(tag: "appexec")
        let cases: [(String, Data)] = [
            ("fat", fakeFat([(arm64, thin), (x86, fakeMachO(tag: "appexec", cpuType: x86))])),
            ("x86_64", fakeMachO(tag: "appexec", cpuType: x86)),
            ("arm64e", fakeMachO(tag: "appexec", cpuSubtype: 2)),
        ]
        for (name, data) in cases {
            let workspace = try Workspace()
            var inputs = try workspace.goodInputs()
            inputs = InstallerInputs(helper: inputs.helper, engine: inputs.engine,
                                     launchDaemon: inputs.launchDaemon, startRight: inputs.startRight,
                                     app: try workspace.makeApp(name: "Other.app", executable: data))
            XCTAssertEqual(try stageError(workspace, inputs: inputs), .unsupportedArchitecture(.app), name)
        }
        let workspace = try Workspace()
        var inputs = try workspace.goodInputs()
        inputs = InstallerInputs(helper: inputs.helper, engine: inputs.engine,
                                 launchDaemon: inputs.launchDaemon, startRight: inputs.startRight,
                                 app: try workspace.makeApp(name: "Script.app", executable: Data("#!/bin/sh\n".utf8)))
        XCTAssertEqual(try stageError(workspace, inputs: inputs), .notMachO(.app))
    }

    func testAppExecutableNameMustBeOnePlainComponent() throws {
        for name in ["../../in-helper", "/bin/sh", "", ".", "a/b"] {
            let workspace = try Workspace()
            let app = try workspace.makeApp()
            try plistData(["CFBundleExecutable": name])
                .write(to: URL(fileURLWithPath: app + "/Contents/Info.plist"))
            let validator = InstallerValidator(signatures: FakeSignatures.standard)
            XCTAssertThrowsError(try validator.teamIdentifier(ofApp: app), name) {
                XCTAssertEqual($0 as? InstallerError, .appNotSigned, name)
            }
        }
    }

    func testAppWithMissingInfoPlistOrSymlinkedExecutableIsRefused() throws {
        let validator = InstallerValidator(signatures: FakeSignatures.standard)
        let workspace = try Workspace()
        let noInfo = try workspace.makeApp(name: "NoInfo.app")
        try FileManager.default.removeItem(atPath: noInfo + "/Contents/Info.plist")
        XCTAssertThrowsError(try validator.teamIdentifier(ofApp: noInfo)) {
            XCTAssertEqual($0 as? InstallerError, .appNotSigned)
        }
        let linked = try workspace.makeApp(name: "Linked.app")
        let target = try workspace.write("elsewhere", fakeMachO(tag: "appexec"))
        try FileManager.default.removeItem(atPath: linked + "/Contents/MacOS/HotspotShade")
        try FileManager.default.createSymbolicLink(atPath: linked + "/Contents/MacOS/HotspotShade",
                                                   withDestinationPath: target)
        XCTAssertThrowsError(try validator.teamIdentifier(ofApp: linked)) {
            XCTAssertEqual($0 as? InstallerError, .appNotSigned)
        }
    }

    func testGoodAppPassesTheArchitectureCheck() throws {
        let workspace = try Workspace()
        let app = try workspace.makeApp()
        XCTAssertEqual(try InstallerValidator(signatures: FakeSignatures.standard).teamIdentifier(ofApp: app),
                       FakeSignatures.team)
    }

    // MARK: real checker

    // A real universal file made from two real signed slices. The real checker
    // would verify one slice. The installer refuses the file before that.
    func testRealUniversalFileNeverReachesTheSignatureCheck() throws {
        guard FileManager.default.isExecutableFile(atPath: "/usr/bin/codesign") else { throw XCTSkip("no codesign") }
        let workspace = try Workspace()
        let arm = try workspace.compileExecutable(architecture: "arm64", name: "arm")
        let intel = try workspace.compileExecutable(architecture: "x86_64", name: "intel")
        let fat = try workspace.universalExecutable(of: arm, and: intel, name: "fat")
        XCTAssertThrowsError(try InstallerValidator().validateExecutable(
            atPath: fat, artifact: .helper, identifier: HelperRequirement.helperIdentifier,
            teamIdentifier: "ABCDE12345"
        )) { XCTAssertEqual($0 as? InstallerError, .unsupportedArchitecture(.helper)) }
    }

    func testRealThinArm64WithoutDeveloperIdIsRefusedBySignature() throws {
        let workspace = try Workspace()
        let arm = try workspace.compileExecutable(architecture: "arm64", name: "arm")
        XCTAssertThrowsError(try InstallerValidator().validateExecutable(
            atPath: arm, artifact: .engine, identifier: HelperRequirement.engineIdentifier,
            teamIdentifier: "ABCDE12345"
        )) { XCTAssertEqual($0 as? InstallerError, .signatureRejected(.engine)) }
    }
}
