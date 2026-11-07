import Foundation
import XCTest
import HotspotShadeKit
@testable import HotspotShadeInstallerCore

final class CoordinatorValidationTests: XCTestCase {
    private func validate(
        _ fixture: CoordinatorFixture,
        manifest: InstallerManifest? = nil,
        validator: InstallerValidator = InstallerValidator(signatures: FakeSignatures.standard)
    ) throws -> [CoordinatorOperation] {
        try CoordinatorPayloadValidator.validate(
            CoordinatorSource(
                payloadRoot: fixture.staged.payloadDirectory,
                manifest: manifest ?? fixture.staged.manifest,
                expectedTeamIdentifier: FakeSignatures.team
            ),
            validator: validator,
            expectedOwner: UInt32(geteuid())
        )
    }

    func testSandboxPolicyRefusesUnmarkedAndSystemRoots() throws {
        let fixture = try CoordinatorFixture()
        XCTAssertNoThrow(try CoordinatorSandboxPolicy.validate(fixture.sandbox))
        for path in ["/", "/Library", "/Applications", "/private/var/db"] {
            XCTAssertThrowsError(try CoordinatorSandboxPolicy.validate(path), path)
        }
        let unmarked = try Workspace()
        try FileManager.default.createDirectory(
            atPath: unmarked.path("root"),
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        XCTAssertThrowsError(try CoordinatorSandboxPolicy.validate(unmarked.path("root")))
        try unmarked.write(
            CoordinatorSandboxPolicy.markerName,
            Data("wrong\n".utf8),
            mode: 0o600
        )
        let root = unmarked.path("root")
        try Data("wrong\n".utf8).write(to: URL(fileURLWithPath: root + "/" + CoordinatorSandboxPolicy.markerName))
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: root + "/" + CoordinatorSandboxPolicy.markerName
        )
        XCTAssertThrowsError(try CoordinatorSandboxPolicy.validate(root))
        try Data(CoordinatorSandboxPolicy.markerContents.utf8)
            .write(to: URL(fileURLWithPath: root + "/" + CoordinatorSandboxPolicy.markerName))
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: root + "/" + CoordinatorSandboxPolicy.markerName
        )
        XCTAssertNoThrow(try CoordinatorSandboxPolicy.validate(root))
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: root)
        XCTAssertThrowsError(try CoordinatorSandboxPolicy.validate(root))
    }

    func testSandboxMarkerCreationIsLimitedToATemporaryRoot() throws {
        let workspace = try Workspace()
        let root = workspace.path("fresh")
        try FileManager.default.createDirectory(
            atPath: root,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let marked = try CoordinatorSandboxPolicy.createMarker(root)
        XCTAssertEqual(marked, try CoordinatorSandboxPolicy.validate(root))
        XCTAssertThrowsError(try CoordinatorSandboxPolicy.createMarker("/Library"))
        XCTAssertThrowsError(try CoordinatorSandboxPolicy.createMarker("/"))
    }

    func testStagedSetPassesThePayloadCheck() throws {
        let fixture = try CoordinatorFixture()
        let operations = try validate(fixture)
        XCTAssertEqual(operations.count, 4)
        XCTAssertEqual(operations.map(\.artifact), [
            InstallerArtifact.engine.rawValue,
            InstallerArtifact.helper.rawValue,
            InstallerArtifact.launchDaemon.rawValue,
            InstallerArtifact.startRight.rawValue,
        ])
        XCTAssertEqual(operations.map(\.mode), [0o755, 0o755, 0o644, 0o644])
    }

    func testApprovalAndPackageSignatureClaimsAreRefused() throws {
        let fixture = try CoordinatorFixture()
        let approved = mutatedManifest(fixture.staged.manifest) { _, fields in
            fields["installationApproved"] = true
        }
        XCTAssertThrowsError(try validate(fixture, manifest: approved)) {
            if case .manifestRefused? = $0 as? CoordinatorError {} else { XCTFail("\($0)") }
        }
        let signed = mutatedManifest(fixture.staged.manifest) { _, fields in
            fields["packageSigned"] = true
        }
        XCTAssertThrowsError(try validate(fixture, manifest: signed)) {
            if case .manifestRefused? = $0 as? CoordinatorError {} else { XCTFail("\($0)") }
        }
    }

    func testManifestRecordMismatchIsRefused() throws {
        let fixture = try CoordinatorFixture()
        var missing = fixture.staged.manifest.files
        missing.removeFirst()
        let missingManifest = mutatedManifest(fixture.staged.manifest) { files, _ in
            files = missing
        }
        XCTAssertThrowsError(try validate(fixture, manifest: missingManifest)) {
            if case .manifestInvalid? = $0 as? CoordinatorError {} else { XCTFail("\($0)") }
        }

        var changed = fixture.staged.manifest.files
        let first = changed[0]
        changed[0] = InstallerManifest.File(
            role: first.role,
            payloadPath: first.payloadPath,
            payloadMode: first.payloadMode,
            destination: first.destination,
            destinationMode: first.destinationMode,
            sha256: String(repeating: "0", count: 64),
            size: first.size
        )
        let changedManifest = mutatedManifest(fixture.staged.manifest) { files, _ in
            files = changed
        }
        XCTAssertThrowsError(try validate(fixture, manifest: changedManifest)) {
            XCTAssertEqual($0 as? CoordinatorError, .digestMismatch(first.payloadPath))
        }

        let wrongTeam = mutatedManifest(fixture.staged.manifest) { _, fields in
            fields["teamIdentifier"] = "ZZZZZ99999"
        }
        XCTAssertThrowsError(try validate(fixture, manifest: wrongTeam)) {
            if case .manifestInvalid? = $0 as? CoordinatorError {} else { XCTFail("\($0)") }
        }
    }

    func testExtraPayloadObjectIsRefused() throws {
        let fixture = try CoordinatorFixture()
        try Data("extra".utf8).write(
            to: URL(fileURLWithPath: fixture.staged.payloadDirectory + "/extra")
        )
        XCTAssertThrowsError(try validate(fixture)) {
            if case .payloadInvalid? = $0 as? CoordinatorError {} else { XCTFail("\($0)") }
        }
    }

    func testPayloadSymlinkIsRefused() throws {
        let fixture = try CoordinatorFixture()
        let engine = fixture.staged.payloadDirectory + "/engine/hotspotshade"
        let moved = fixture.staged.payloadDirectory + "/engine/hotspotshade-real"
        try FileManager.default.moveItem(atPath: engine, toPath: moved)
        try FileManager.default.createSymbolicLink(atPath: engine, withDestinationPath: moved)
        XCTAssertThrowsError(try validate(fixture)) {
            if case .payloadInvalid? = $0 as? CoordinatorError {} else { XCTFail("\($0)") }
        }
    }

    func testAdHocStagedHelperIsRefusedBeforeAnyChange() throws {
        let fixture = try CoordinatorFixture(oldPadding: 64, newPadding: 192)
        let adHoc = HelperSigningInfo(
            identifier: HelperRequirement.helperIdentifier,
            teamIdentifier: nil,
            isAdHoc: true,
            hasHardenedRuntime: true
        )
        let signatures = FakeSignatures.standard.replacing("helper", with: adHoc)
        XCTAssertThrowsError(
            try CoordinatorPayloadValidator.validate(
                fixture.source,
                validator: InstallerValidator(signatures: signatures),
                expectedOwner: UInt32(geteuid())
            )
        ) {
            if case .artifactRejected? = $0 as? CoordinatorError {} else { XCTFail("\($0)") }
        }
        let coordinator = try InstallCoordinator(
            sandboxRoot: fixture.sandbox,
            validator: InstallerValidator(signatures: signatures)
        )
        XCTAssertThrowsError(try coordinator.install(source: fixture.source)) {
            if case .artifactRejected? = $0 as? CoordinatorError {} else { XCTFail("\($0)") }
        }
        try fixture.assertOldSet()
        XCTAssertFalse(fixture.targetExists(CoordinatorFixture.journalRelative))
    }

    func testPayloadRootOwnershipAndModeAreChecked() throws {
        let fixture = try CoordinatorFixture()
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o777],
            ofItemAtPath: fixture.staged.payloadDirectory
        )
        XCTAssertThrowsError(try validate(fixture)) {
            if case .payloadInvalid? = $0 as? CoordinatorError {} else { XCTFail("\($0)") }
        }
    }
}
