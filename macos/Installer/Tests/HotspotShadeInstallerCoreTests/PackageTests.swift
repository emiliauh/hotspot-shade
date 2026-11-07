import Foundation
import XCTest
import HotspotShadeKit
@testable import HotspotShadeInstallerCore

final class PackageTests: XCTestCase {
    private func builder() -> InstallerBuilder {
        InstallerBuilder(validator: InstallerValidator(signatures: FakeSignatures.standard))
    }

    private func requireTools() throws {
        for tool in [InstallerTool.pkgbuild, .pkgutil, .lsbom]
        where !FileManager.default.isExecutableFile(atPath: tool.rawValue) {
            throw XCTSkip("\(tool.rawValue) is not available")
        }
    }

    func testBuildProducesUnsignedAuditedPackage() throws {
        try requireTools()
        let workspace = try Workspace()
        let built = try builder().build(inputs: try workspace.goodInputs(), version: "1.0.0",
                                        outputDirectory: workspace.path("out"))
        XCTAssertTrue(built.packagePath.hasSuffix("HotspotShade-1.0.0-unsigned.pkg"))
        XCTAssertTrue(FileManager.default.fileExists(atPath: built.packagePath))
        // The audit scratch directory is removed.
        XCTAssertFalse(FileManager.default.fileExists(atPath: workspace.path("out/audit")))
        // The manifest on disk matches the one returned.
        let stored = try JSONDecoder().decode(InstallerManifest.self,
                                              from: Data(contentsOf: URL(fileURLWithPath: built.staged.manifestPath)))
        XCTAssertEqual(stored, built.staged.manifest)
        XCTAssertFalse(stored.packageSigned)
        XCTAssertFalse(stored.installationApproved)
        XCTAssertEqual(stored.installLocation, InstallerLayout.installLocation)
        // pkgutil reports no signature. The build never signs.
        let result = Process()
        result.executableURL = URL(fileURLWithPath: "/usr/sbin/pkgutil")
        result.arguments = ["--check-signature", built.packagePath]
        let pipe = Pipe()
        result.standardOutput = pipe
        result.standardError = pipe
        try result.run()
        let text = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        result.waitUntilExit()
        XCTAssertTrue(text.contains("no signature"), text)
    }

    func testBuildTouchesNothingOutsideTheOutputDirectory() throws {
        try requireTools()
        let workspace = try Workspace()
        let inputs = try workspace.goodInputs()
        let before = try Set(FileManager.default.contentsOfDirectory(atPath: workspace.directory.path))
        _ = try builder().build(inputs: inputs, version: "1.0.0", outputDirectory: workspace.path("out"))
        let after = try Set(FileManager.default.contentsOfDirectory(atPath: workspace.directory.path))
        XCTAssertEqual(after.subtracting(before), ["out"])
    }

    func testPayloadNamesNoSystemDirectory() throws {
        try requireTools()
        // Neither the install location nor an entry may name a system
        // directory, because the package overwrites permissions on entries.
        let workspace = try Workspace()
        let built = try builder().build(inputs: try workspace.goodInputs(), version: "1.0.0",
                                        outputDirectory: workspace.path("out"))
        let bom = try SystemInstallerToolRunner().run(.pkgutil, arguments: ["--payload-files", built.packagePath])
        let lines = bom.split(separator: "\n").map(String.init)
        for line in lines {
            XCTAssertFalse(line.hasPrefix("./Library"), line)
            XCTAssertFalse(line.hasPrefix("./System"), line)
        }
        XCTAssertTrue(lines.contains("./engine/hotspotshade"))
    }

    func testAuditRejectsExtraPayloadFile() throws {
        try requireTools()
        let workspace = try Workspace()
        let staged = try builder().stage(inputs: try workspace.goodInputs(), version: "1.0.0",
                                         outputDirectory: workspace.path("out"))
        try Data("extra".utf8).write(to: URL(fileURLWithPath: staged.payloadDirectory + "/engine/extra"))
        let package = workspace.path("out/extra.pkg")
        let runner = SystemInstallerToolRunner()
        _ = try runner.run(.pkgbuild, arguments: [
            "--root", staged.payloadDirectory, "--identifier", InstallerLayout.packageIdentifier,
            "--version", "1.0.0", "--install-location", InstallerLayout.installLocation,
            "--scripts", staged.scriptsDirectory, "--ownership", "recommended", package,
        ])
        let audit = PackageAudit(validator: InstallerValidator(signatures: FakeSignatures.standard), tools: runner)
        XCTAssertThrowsError(try audit.audit(packagePath: package, manifest: staged.manifest,
                                             scratchDirectory: workspace.path("out/audit"))) {
            if case .packageAuditFailed? = $0 as? InstallerError {} else { XCTFail("\($0)") }
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: workspace.path("out/audit")))
    }

    func testAuditRejectsChangedFileContent() throws {
        try requireTools()
        let workspace = try Workspace()
        let staged = try builder().stage(inputs: try workspace.goodInputs(), version: "1.0.0",
                                         outputDirectory: workspace.path("out"))
        // The payload changes after staging. The package then holds bytes that
        // the manifest does not describe.
        let engine = staged.payloadDirectory + "/engine/hotspotshade"
        try fakeMachO(tag: "engine", padding: 999).write(to: URL(fileURLWithPath: engine))
        let package = workspace.path("out/changed.pkg")
        let runner = SystemInstallerToolRunner()
        _ = try runner.run(.pkgbuild, arguments: [
            "--root", staged.payloadDirectory, "--identifier", InstallerLayout.packageIdentifier,
            "--version", "1.0.0", "--install-location", InstallerLayout.installLocation,
            "--scripts", staged.scriptsDirectory, "--ownership", "recommended", package,
        ])
        let audit = PackageAudit(validator: InstallerValidator(signatures: FakeSignatures.standard), tools: runner)
        XCTAssertThrowsError(try audit.audit(packagePath: package, manifest: staged.manifest,
                                             scratchDirectory: workspace.path("out/audit"))) {
            if case .packageAuditFailed? = $0 as? InstallerError {} else { XCTFail("\($0)") }
        }
    }

    func testAuditRejectsAlteredScript() throws {
        try requireTools()
        let workspace = try Workspace()
        let staged = try builder().stage(inputs: try workspace.goodInputs(), version: "1.0.0",
                                         outputDirectory: workspace.path("out"))
        let script = staged.scriptsDirectory + "/postinstall"
        try Data((InstallerScripts.postinstall + "\n/bin/echo extra\n").utf8).write(to: URL(fileURLWithPath: script))
        let package = workspace.path("out/script.pkg")
        let runner = SystemInstallerToolRunner()
        _ = try runner.run(.pkgbuild, arguments: [
            "--root", staged.payloadDirectory, "--identifier", InstallerLayout.packageIdentifier,
            "--version", "1.0.0", "--install-location", InstallerLayout.installLocation,
            "--scripts", staged.scriptsDirectory, "--ownership", "recommended", package,
        ])
        let audit = PackageAudit(validator: InstallerValidator(signatures: FakeSignatures.standard), tools: runner)
        XCTAssertThrowsError(try audit.audit(packagePath: package, manifest: staged.manifest,
                                             scratchDirectory: workspace.path("out/audit"))) {
            if case .packageAuditFailed? = $0 as? InstallerError {} else { XCTFail("\($0)") }
        }
    }

    func testAuditRejectsWrongInstallLocationOrVersion() throws {
        try requireTools()
        let workspace = try Workspace()
        let staged = try builder().stage(inputs: try workspace.goodInputs(), version: "1.0.0",
                                         outputDirectory: workspace.path("out"))
        let package = workspace.path("out/loc.pkg")
        let runner = SystemInstallerToolRunner()
        _ = try runner.run(.pkgbuild, arguments: [
            "--root", staged.payloadDirectory, "--identifier", InstallerLayout.packageIdentifier,
            "--version", "1.0.0", "--install-location", "/Library/Elsewhere",
            "--scripts", staged.scriptsDirectory, "--ownership", "recommended", package,
        ])
        let audit = PackageAudit(validator: InstallerValidator(signatures: FakeSignatures.standard), tools: runner)
        XCTAssertThrowsError(try audit.audit(packagePath: package, manifest: staged.manifest,
                                             scratchDirectory: workspace.path("out/audit"))) {
            if case .packageAuditFailed? = $0 as? InstallerError {} else { XCTFail("\($0)") }
        }
    }

    func testSymbolicModes() {
        XCTAssertEqual(PackageAudit.symbolic(0o755, isDirectory: true), "drwxr-xr-x")
        XCTAssertEqual(PackageAudit.symbolic(0o755, isDirectory: false), "-rwxr-xr-x")
        XCTAssertEqual(PackageAudit.symbolic(0o644, isDirectory: false), "-rw-r--r--")
    }

    func testStagedFilesHaveFixedModesAndPrivateOutput() throws {
        let workspace = try Workspace()
        let staged = try builder().stage(inputs: try workspace.goodInputs(), version: "1.0.0",
                                         outputDirectory: workspace.path("out"))
        func mode(_ path: String) throws -> Int {
            (try FileManager.default.attributesOfItem(atPath: path)[.posixPermissions] as! NSNumber).intValue
        }
        XCTAssertEqual(try mode(staged.outputDirectory), 0o700)
        for entry in InstallerLayout.entries {
            XCTAssertEqual(try mode(staged.payloadDirectory + "/" + entry.payloadPath), Int(entry.payloadMode))
        }
        for dir in InstallerLayout.payloadDirectories {
            XCTAssertEqual(try mode(staged.payloadDirectory + "/" + dir), 0o755)
        }
        XCTAssertEqual(try mode(staged.scriptsDirectory + "/postinstall"), 0o755)
        // No staging leftovers.
        XCTAssertFalse(FileManager.default.fileExists(atPath: staged.outputDirectory + "/inputs"))
    }

    func testLayoutMatchesTheHelperContract() throws {
        XCTAssertEqual(InstallerLayout.helperDestination, "/Library/PrivilegedHelperTools/dev.hotspotshade.mac.helper")
        XCTAssertEqual(InstallerLayout.launchDaemonDestination, "/Library/LaunchDaemons/dev.hotspotshade.mac.helper.plist")
        XCTAssertEqual(InstallerLayout.engineDestination, "/Library/Application Support/HotspotShade/engine/hotspotshade")
        XCTAssertEqual(InstallerLayout.engineRoot, "/Library/Application Support/HotspotShade/engine")
        XCTAssertEqual(InstallerLayout.stateDirectory, "/var/db/hotspotshade")
        XCTAssertEqual(InstallerLayout.engineHome, "/var/lib/hotspotshade")
        XCTAssertEqual(InstallerLayout.startRightName, "dev.hotspotshade.tunnel.start")
        // Each payload path lands under the install location, and the engine
        // lands exactly where the root launcher looks for it.
        for entry in InstallerLayout.entries where entry.artifact == .engine || entry.artifact == .startRight {
            XCTAssertEqual(InstallerLayout.installLocation + "/" + entry.payloadPath, entry.destination)
        }
        // The helper installer default policy accepts exactly these paths.
        XCTAssertTrue(InstallerLayout.helperDestination.hasPrefix(InstallerLayout.helperInstallRoot + "/"))
        // The checked-in launch daemon file names the helper destination.
        let plist = try PropertyListSerialization.propertyList(
            from: Data(contentsOf: Repo.launchDaemon), options: [], format: nil) as! [String: Any]
        XCTAssertEqual(plist["ProgramArguments"] as? [String], [InstallerLayout.helperDestination])
        // The helper verifier accepts the daemon file at the installed path.
        try HelperLaunchDaemonPolicy.validate(
            plistData: Data(contentsOf: Repo.launchDaemon),
            helperPath: InstallerLayout.helperDestination,
            serviceName: HelperRequirement.helperServiceName
        )
        XCTAssertTrue(Set(InstallerLayout.entries.map(\.artifact)) == [.helper, .engine, .launchDaemon, .startRight])
    }
}
