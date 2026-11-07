import Foundation
import XCTest
import HotspotShadeKit
@testable import HotspotShadeInstallerCore

// Runs the real tool unless a closure replaces the call or reacts to it. The
// closures let a test break one step of the build and look at what is left.
struct InterceptingRunner: InstallerToolRunning {
    var replace: @Sendable (InstallerTool, [String]) throws -> String? = { _, _ in nil }
    var after: @Sendable (InstallerTool, [String]) throws -> Void = { _, _ in }

    func run(_ tool: InstallerTool, arguments: [String]) throws -> String {
        if let output = try replace(tool, arguments) { return output }
        let output = try SystemInstallerToolRunner().run(tool, arguments: arguments)
        try after(tool, arguments)
        return output
    }
}

final class PackageAuditTests: XCTestCase {
    private func requireTools() throws {
        for tool in [InstallerTool.pkgbuild, .pkgutil, .lsbom]
        where !FileManager.default.isExecutableFile(atPath: tool.rawValue) {
            throw XCTSkip("\(tool.rawValue) is not available")
        }
    }

    private var validator: InstallerValidator { InstallerValidator(signatures: FakeSignatures.standard) }

    private func stage(_ workspace: Workspace) throws -> StagedInstaller {
        try InstallerBuilder(validator: validator).stage(
            inputs: try workspace.goodInputs(), version: "1.0.0", outputDirectory: workspace.path("out"))
    }

    @discardableResult
    private func pkgbuild(_ staged: StagedInstaller, name: String, ownership: String = "recommended",
                          workspace: Workspace) throws -> String {
        let package = workspace.path("out/" + name)
        _ = try SystemInstallerToolRunner().run(.pkgbuild, arguments: [
            "--root", staged.payloadDirectory, "--identifier", InstallerLayout.packageIdentifier,
            "--version", "1.0.0", "--install-location", InstallerLayout.installLocation,
            "--scripts", staged.scriptsDirectory, "--ownership", ownership, package,
        ])
        return package
    }

    private func expectAuditFailure(
        _ package: String, _ staged: StagedInstaller, _ workspace: Workspace,
        tools: InstallerToolRunning = SystemInstallerToolRunner(),
        contains fragment: String? = nil, file: StaticString = #filePath, line: UInt = #line
    ) {
        let audit = PackageAudit(validator: validator, tools: tools)
        XCTAssertThrowsError(try audit.audit(packagePath: package, manifest: staged.manifest,
                                             scratchDirectory: workspace.path("out/audit")),
                             file: file, line: line) {
            guard case .packageAuditFailed(let why)? = $0 as? InstallerError else {
                return XCTFail("\($0)", file: file, line: line)
            }
            if let fragment { XCTAssertTrue(why.contains(fragment), why, file: file, line: line) }
        }
        // A failed audit removes its scratch directory.
        XCTAssertFalse(FileManager.default.fileExists(atPath: workspace.path("out/audit")), file: file, line: line)
    }

    // MARK: manifest approval

    func testAuditRefusesAManifestThatClaimsApproval() throws {
        let workspace = try Workspace()
        let staged = try stage(workspace)
        let approved = InstallerManifest(
            schemaVersion: staged.manifest.schemaVersion,
            packageIdentifier: staged.manifest.packageIdentifier,
            version: staged.manifest.version,
            installLocation: staged.manifest.installLocation,
            teamIdentifier: staged.manifest.teamIdentifier,
            packageSigned: staged.manifest.packageSigned,
            installationApproved: true,
            files: staged.manifest.files,
            scripts: staged.manifest.scripts,
            notes: staged.manifest.notes
        )
        XCTAssertThrowsError(try PackageAudit(validator: validator, tools: SystemInstallerToolRunner())
            .audit(packagePath: "/unused.pkg", manifest: approved,
                   scratchDirectory: workspace.path("audit"))) {
            guard case .packageAuditFailed(let why)? = $0 as? InstallerError else {
                return XCTFail("\($0)")
            }
            XCTAssertTrue(why.contains("installation approval"), why)
        }
    }

    // MARK: real packages with a broken payload

    func testAuditRejectsPackageOwnedByTheBuildUser() throws {
        try requireTools()
        let workspace = try Workspace()
        let staged = try stage(workspace)
        // `preserve` keeps the owner of the staged files, which is this user.
        let package = try pkgbuild(staged, name: "preserve.pkg", ownership: "preserve", workspace: workspace)
        expectAuditFailure(package, staged, workspace, contains: "root:wheel")
    }

    func testAuditRejectsWrongPayloadModes() throws {
        try requireTools()
        for (path, mode) in [("engine/hotspotshade", 0o775), ("engine/hotspotshade", 0o4755),
                             ("install-support/dev.hotspotshade.mac.helper", 0o755),
                             ("engine", 0o775), ("install-support", 0o700)] {
            let workspace = try Workspace()
            let staged = try stage(workspace)
            XCTAssertEqual(chmod(staged.payloadDirectory + "/" + path, mode_t(mode)), 0)
            let package = try pkgbuild(staged, name: "mode.pkg", workspace: workspace)
            expectAuditFailure(package, staged, workspace)
        }
    }

    func testAuditRejectsSymlinkInPayload() throws {
        try requireTools()
        let workspace = try Workspace()
        let staged = try stage(workspace)
        XCTAssertEqual(symlink("hotspotshade", staged.payloadDirectory + "/engine/link"), 0)
        let package = try pkgbuild(staged, name: "link.pkg", workspace: workspace)
        expectAuditFailure(package, staged, workspace)
        // A symlink in place of a payload file is also refused.
        let second = try Workspace()
        let other = try stage(second)
        let helper = other.payloadDirectory + "/install-support/dev.hotspotshade.mac.helper"
        XCTAssertEqual(unlink(helper), 0)
        XCTAssertEqual(symlink("/bin/sh", helper), 0)
        let linked = try pkgbuild(other, name: "swap.pkg", workspace: second)
        expectAuditFailure(linked, other, second)
    }

    func testAuditRejectsMissingPayloadFile() throws {
        try requireTools()
        let workspace = try Workspace()
        let staged = try stage(workspace)
        XCTAssertEqual(unlink(staged.payloadDirectory + "/install-support/dev.hotspotshade.tunnel.start.plist"), 0)
        let package = try pkgbuild(staged, name: "missing.pkg", workspace: workspace)
        expectAuditFailure(package, staged, workspace)
    }

    // MARK: bill of materials with a crafted listing

    private func expectedItems() -> [String: (mode: UInt16, isDirectory: Bool, sha256: String?)] {
        var expected: [String: (mode: UInt16, isDirectory: Bool, sha256: String?)] = [:]
        for directory in InstallerLayout.payloadDirectories { expected[directory] = (0o755, true, nil) }
        for entry in InstallerLayout.entries { expected[entry.payloadPath] = (entry.payloadMode, false, "x") }
        return expected
    }

    private func listing(
        edit: (inout [(symbolic: String, user: String, group: String, name: String)]) -> Void = { _ in }
    ) -> String {
        var rows: [(symbolic: String, user: String, group: String, name: String)] = [
            ("drwxr-xr-x", "root", "wheel", "."),
        ]
        for (path, item) in expectedItems().sorted(by: { $0.key < $1.key }) {
            rows.append((PackageAudit.symbolic(item.mode, isDirectory: item.isDirectory), "root", "wheel", "./" + path))
        }
        edit(&rows)
        return rows.map { "\($0.symbolic) \t\($0.user)\t\($0.group)\t\($0.symbolic.hasPrefix("d") ? "" : "7")\t\($0.name)" }
            .joined(separator: "\n") + "\n"
    }

    private func bomResult(_ text: String) -> Result<Void, Error> {
        let runner = InterceptingRunner(replace: { tool, _ in tool == .lsbom ? text : nil })
        let audit = PackageAudit(validator: validator, tools: runner)
        return Result { try audit.checkBillOfMaterials("/unused/Bom", expected: expectedItems()) }
    }

    private func assertBomRefused(_ text: String, _ name: String, file: StaticString = #filePath, line: UInt = #line) {
        if case .success = bomResult(text) { XCTFail("accepted: \(name)", file: file, line: line) }
    }

    func testBillOfMaterialsAcceptsTheExpectedListing() {
        if case .failure(let error) = bomResult(listing()) { XCTFail("\(error)") }
    }

    func testBillOfMaterialsRefusesOwnershipModeAndTypeChanges() {
        func change(_ index: Int, _ update: @escaping (inout (symbolic: String, user: String, group: String, name: String)) -> Void) -> String {
            listing { update(&$0[index]) }
        }
        assertBomRefused(change(0) { $0.user = "emi" }, "install location owner")
        assertBomRefused(change(0) { $0.symbolic = "drwxrwxr-x" }, "install location mode")
        for index in 1..<listing().split(separator: "\n").count {
            assertBomRefused(change(index) { $0.user = "staff" }, "user \(index)")
            assertBomRefused(change(index) { $0.group = "staff" }, "group \(index)")
            assertBomRefused(change(index) { $0.group = "admin" }, "admin group \(index)")
            assertBomRefused(change(index) { $0.symbolic = "-rwxrwxrwx" }, "mode \(index)")
            assertBomRefused(change(index) { $0.symbolic = "-rwsr-xr-x" }, "setuid \(index)")
            assertBomRefused(change(index) { $0.symbolic = "lrwxr-xr-x" }, "symlink \(index)")
        }
    }

    func testBillOfMaterialsRefusesExtraMissingAndMalformedRows() {
        assertBomRefused(listing { $0.append(("-rw-r--r--", "root", "wheel", "./engine/extra")) }, "extra file")
        assertBomRefused(listing { $0.append(("lrwxr-xr-x", "root", "wheel", "./engine/link")) }, "extra symlink")
        assertBomRefused(listing { $0.append(("drwxr-xr-x", "root", "wheel", "./../escape")) }, "escape")
        assertBomRefused(listing { $0.removeLast() }, "missing item")
        assertBomRefused(listing { $0.removeAll { $0.name == "." } }, "missing install location")
        assertBomRefused("garbage\n", "garbage")
        assertBomRefused("", "empty")
    }

    // MARK: PackageInfo

    private func packageInfo(
        attributes: [String: String?] = [:],
        children: String? = nil
    ) -> String {
        var values: [(String, String)] = [
            ("overwrite-permissions", "true"), ("relocatable", "false"),
            ("identifier", InstallerLayout.packageIdentifier), ("postinstall-action", "none"),
            ("version", "1.0.0"), ("format-version", "2"), ("generator-version", "InstallCmds-1 (1)"),
            ("install-location", InstallerLayout.installLocation), ("auth", "root"),
        ]
        for (key, value) in attributes {
            values.removeAll { $0.0 == key }
            if let value { values.append((key, value)) }
        }
        let list = values.map { "\($0.0)=\"\($0.1)\"" }.joined(separator: " ")
        let body = children ?? """
        <payload numberOfFiles="7" installKBytes="2"/>
        <bundle-version/><upgrade-bundle/><update-bundle/><atomic-update-bundle/><strict-identifier/><relocate/>
        <scripts><preinstall file="./preinstall" timeout="600"/><postinstall file="./postinstall" timeout="600"/></scripts>
        """
        return "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<pkg-info \(list)>\n\(body)\n</pkg-info>\n"
    }

    private func infoResult(_ text: String, itemCount: Int = 7) throws -> Result<Void, Error> {
        let workspace = try Workspace()
        let staged = try stage(workspace)
        let path = try workspace.write("PackageInfo", Data(text.utf8))
        let audit = PackageAudit(validator: validator, tools: SystemInstallerToolRunner())
        return Result { try audit.checkPackageInfo(path, manifest: staged.manifest, itemCount: itemCount) }
    }

    func testPackageInfoAcceptsTheExpectedShape() throws {
        if case .failure(let error) = try infoResult(packageInfo()) { XCTFail("\(error)") }
        // A real package from this machine matches the shape that the test writes.
        try requireTools()
        let workspace = try Workspace()
        let built = try InstallerBuilder(validator: validator).build(
            inputs: try workspace.goodInputs(), version: "1.0.0", outputDirectory: workspace.path("real"))
        XCTAssertTrue(FileManager.default.fileExists(atPath: built.packagePath))
    }

    func testPackageInfoRefusesEveryChange() throws {
        let scripts = "<scripts><preinstall file=\"./preinstall\" timeout=\"600\"/><postinstall file=\"./postinstall\" timeout=\"600\"/></scripts>"
        let payload = "<payload numberOfFiles=\"7\" installKBytes=\"2\"/>"
        let cases: [(String, String)] = [
            ("other identifier", packageInfo(attributes: ["identifier": "dev.other"])),
            ("other version", packageInfo(attributes: ["version": "2.0.0"])),
            ("other location", packageInfo(attributes: ["install-location": "/Library"])),
            ("no auth", packageInfo(attributes: ["auth": "none"])),
            ("relocatable", packageInfo(attributes: ["relocatable": "true"])),
            ("no overwrite permissions", packageInfo(attributes: ["overwrite-permissions": nil])),
            ("restart", packageInfo(attributes: ["postinstall-action": "restart"])),
            ("format", packageInfo(attributes: ["format-version": "3"])),
            ("extra attribute", packageInfo(attributes: ["deleteObsoleteLanguages": "true"])),
            ("count", packageInfo(children: "<payload numberOfFiles=\"8\" installKBytes=\"2\"/>\(scripts)")),
            ("no payload", packageInfo(children: scripts)),
            ("no scripts", packageInfo(children: payload)),
            ("only preinstall", packageInfo(children: payload + "<scripts><preinstall file=\"./preinstall\"/></scripts>")),
            ("extra script", packageInfo(children: payload + "<scripts><preinstall file=\"./preinstall\"/><postinstall file=\"./postinstall\"/><postupgrade file=\"./x\"/></scripts>")),
            ("swapped scripts", packageInfo(children: payload + "<scripts><postinstall file=\"./postinstall\"/><preinstall file=\"./preinstall\"/></scripts>")),
            ("other script file", packageInfo(children: payload + "<scripts><preinstall file=\"./other\"/><postinstall file=\"./postinstall\"/></scripts>")),
            ("script path", packageInfo(children: payload + "<scripts><preinstall file=\"/tmp/preinstall\"/><postinstall file=\"./postinstall\"/></scripts>")),
            ("two script lists", packageInfo(children: payload + scripts + scripts)),
            ("bundle list", packageInfo(children: payload + scripts + "<bundle id=\"com.apple.Safari\" path=\"./x.app\"/>")),
            ("filled upgrade bundle", packageInfo(children: payload + scripts + "<upgrade-bundle><bundle id=\"x\"/></upgrade-bundle>")),
            ("relocate with bundle", packageInfo(children: payload + scripts + "<relocate><bundle id=\"x\"/></relocate>")),
            ("strict identifier attribute", packageInfo(children: payload + scripts + "<strict-identifier a=\"b\"/>")),
            ("install check", packageInfo(children: payload + scripts + "<install-check script=\"x\"/>")),
            ("not a package info", "<other/>"),
            ("garbage", "not xml"),
        ]
        for (name, text) in cases {
            if case .success = try infoResult(text) { XCTFail("accepted: \(name)") }
        }
    }

    // MARK: failure cleanup and the package digest

    private func builder(_ runner: InstallerToolRunning) -> InstallerBuilder {
        InstallerBuilder(validator: validator, tools: runner)
    }

    private func expectBuildFailure(
        _ runner: InstallerToolRunning, contains fragment: String? = nil,
        file: StaticString = #filePath, line: UInt = #line
    ) throws {
        let workspace = try Workspace()
        XCTAssertThrowsError(try builder(runner).build(
            inputs: try workspace.goodInputs(), version: "1.0.0", outputDirectory: workspace.path("out")
        ), file: file, line: line) {
            if let fragment { XCTAssertTrue("\($0)".contains(fragment), "\($0)", file: file, line: line) }
        }
        // A failed build leaves nothing behind: no payload, package, or scratch.
        XCTAssertFalse(FileManager.default.fileExists(atPath: workspace.path("out")), file: file, line: line)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: workspace.directory.path)
            .filter { $0 == "out" }, [], file: file, line: line)
    }

    func testFailedPackageBuildRemovesTheOutputDirectory() throws {
        try expectBuildFailure(InterceptingRunner(replace: { tool, _ in
            if tool == .pkgbuild { throw InstallerError.packageBuildFailed }
            return nil
        }))
    }

    func testFailedExpandRemovesTheOutputDirectory() throws {
        try requireTools()
        try expectBuildFailure(InterceptingRunner(replace: { tool, _ in
            if tool == .pkgutil { throw InstallerError.packageBuildFailed }
            return nil
        }))
    }

    func testFailedAuditAfterARealBuildRemovesThePackageAndScratch() throws {
        try requireTools()
        // The real expand runs and leaves a scratch directory. The bill of
        // materials then reports another owner.
        try expectBuildFailure(InterceptingRunner(replace: { tool, _ in
            tool == .lsbom ? "drwxr-xr-x \tstaff\twheel\t\t.\n" : nil
        }), contains: "root:wheel")
    }

    func testPackageThatChangesDuringTheAuditIsRefused() throws {
        try requireTools()
        try expectBuildFailure(InterceptingRunner(after: { tool, arguments in
            guard tool == .pkgutil, arguments.first == "--expand-full" else { return }
            let handle = try FileHandle(forWritingTo: URL(fileURLWithPath: arguments[1]))
            try handle.seekToEnd()
            try handle.write(contentsOf: Data([0]))
            try handle.close()
        }), contains: "changed while it was audited")
    }

    func testBuildWritesThePackageDigest() throws {
        try requireTools()
        let workspace = try Workspace()
        let built = try builder(SystemInstallerToolRunner()).build(
            inputs: try workspace.goodInputs(), version: "1.0.0", outputDirectory: workspace.path("out"))
        XCTAssertEqual(built.packageSHA256.count, 64)
        let fileText = try String(contentsOfFile: built.digestPath, encoding: .utf8)
        XCTAssertEqual(fileText, "\(built.packageSHA256)  HotspotShade-1.0.0-unsigned.pkg\n")
        // The recorded digest is the digest of the package on disk, from a tool
        // that this package does not use.
        let result = try runShell("/usr/bin/shasum -a 256 \"$1\"", arguments: [built.packagePath])
        XCTAssertEqual(result.status, 0)
        XCTAssertTrue(result.output.hasPrefix(built.packageSHA256), result.output)
        // The sidecar is private to the build user.
        let mode = (try FileManager.default.attributesOfItem(atPath: built.digestPath)[.posixPermissions] as! NSNumber).intValue
        XCTAssertEqual(mode, 0o600)
    }

    func testLateStageFailureRemovesTheOutputDirectory() throws {
        // The helper and engine copy and pass. The plist check fails after the
        // copies exist, so a partial staging directory is on disk at that point.
        let workspace = try Workspace()
        let inputs = try workspace.goodInputs(launchDaemon: try plistData(["Label": "dev.other"]))
        XCTAssertThrowsError(try builder(SystemInstallerToolRunner()).stage(
            inputs: inputs, version: "1.0.0", outputDirectory: workspace.path("out")))
        XCTAssertFalse(FileManager.default.fileExists(atPath: workspace.path("out")))
    }
}
