import Foundation
import Darwin
import HotspotShadeKit

// Checks the built package, not the staging directory. It expands the package
// into a scratch directory and compares what a person would install against the
// manifest: the exact file set, the digests, the modes, the root:wheel
// ownership in the bill of materials, the scripts, and the signatures of the
// extracted executables. It installs nothing.
public struct PackageAudit: Sendable {
    private let validator: InstallerValidator
    private let tools: InstallerToolRunning

    public init(validator: InstallerValidator, tools: InstallerToolRunning) {
        self.validator = validator
        self.tools = tools
    }

    public func audit(packagePath: String, manifest: InstallerManifest, scratchDirectory: String) throws {
        // The current foundation must never be described as approved. A future
        // approval needs the exclusion design in README.md and a new policy.
        guard !manifest.installationApproved else {
            throw InstallerError.packageAuditFailed("the manifest claims installation approval")
        }
        // pkgutil creates the scratch directory and refuses an existing one.
        _ = try tools.run(.pkgutil, arguments: ["--expand-full", packagePath, scratchDirectory])
        defer { InstallerBuilder.removeOwnedOutput(scratchDirectory) }

        // The expected payload tree.
        var expected: [String: (mode: UInt16, isDirectory: Bool, sha256: String?)] = [:]
        for directory in InstallerLayout.payloadDirectories { expected[directory] = (0o755, true, nil) }
        for entry in InstallerLayout.entries {
            guard let recorded = manifest.files.first(where: { $0.role == entry.artifact.rawValue }),
                  recorded.payloadPath == entry.payloadPath,
                  recorded.payloadMode == String(entry.payloadMode, radix: 8)
            else { throw InstallerError.packageAuditFailed("the manifest does not match the layout") }
            expected[entry.payloadPath] = (entry.payloadMode, false, recorded.sha256)
        }
        // The payload count in PackageInfo includes the install location itself.
        try checkPackageInfo(scratchDirectory + "/PackageInfo", manifest: manifest, itemCount: expected.count + 1)

        let payloadRoot = scratchDirectory + "/Payload"
        let found = try walk(payloadRoot)
        guard Set(found.keys) == Set(expected.keys) else {
            throw InstallerError.packageAuditFailed("the payload holds a different set of files")
        }
        for (path, want) in expected {
            let item = found[path]!
            guard item.isDirectory == want.isDirectory, item.mode == want.mode else {
                throw InstallerError.packageAuditFailed("a payload item has the wrong type or mode")
            }
            if let digest = want.sha256 {
                let actual = try ArtifactIngest.sha256(ofFileAt: payloadRoot + "/" + path, artifact: .helper)
                guard actual.sha256 == digest else {
                    throw InstallerError.packageAuditFailed("a payload file differs from the manifest")
                }
            }
        }

        // Scripts: exactly the two generated scripts, byte for byte.
        let scriptsFound = try walk(scratchDirectory + "/Scripts")
        let wantedScripts = [
            InstallerScripts.preinstallName: InstallerScripts.preinstall,
            InstallerScripts.postinstallName: InstallerScripts.postinstall,
        ]
        guard Set(scriptsFound.keys) == Set(wantedScripts.keys) else {
            throw InstallerError.packageAuditFailed("the package holds a different set of scripts")
        }
        for (name, text) in wantedScripts {
            let data = try Data(contentsOf: URL(fileURLWithPath: scratchDirectory + "/Scripts/" + name))
            guard data == Data(text.utf8), scriptsFound[name]?.mode == 0o755,
                  manifest.scripts.contains(where: { $0.payloadPath == name })
            else {
                throw InstallerError.packageAuditFailed("a package script differs from the generated script")
            }
        }

        try checkBillOfMaterials(scratchDirectory + "/Bom", expected: expected)
        try Self.verifySignatures(validator: validator, root: payloadRoot, team: manifest.teamIdentifier)
    }

    // Verify the helper and the engine under a payload root.
    static func verifySignatures(validator: InstallerValidator, root: String, team: String) throws {
        for (artifact, identifier) in [
            (InstallerArtifact.helper, HelperRequirement.helperIdentifier),
            (InstallerArtifact.engine, HelperRequirement.engineIdentifier),
        ] {
            guard let entry = InstallerLayout.entries.first(where: { $0.artifact == artifact }) else { continue }
            try validator.validateExecutable(
                atPath: root + "/" + entry.payloadPath,
                artifact: artifact,
                identifier: identifier,
                teamIdentifier: team
            )
        }
    }

    private struct Item { let mode: UInt16; let isDirectory: Bool }

    // Relative path to type and mode. Anything that is not a plain file or
    // directory, including a symlink, fails the audit.
    private func walk(_ root: String) throws -> [String: Item] {
        var result: [String: Item] = [:]
        guard let enumerator = FileManager.default.enumerator(atPath: root) else {
            throw InstallerError.packageAuditFailed("the package payload cannot be read")
        }
        for case let relative as String in enumerator {
            var status = stat()
            guard lstat(root + "/" + relative, &status) == 0 else {
                throw InstallerError.packageAuditFailed("a payload item cannot be read")
            }
            let type = status.st_mode & S_IFMT
            guard type == S_IFREG || type == S_IFDIR else {
                throw InstallerError.packageAuditFailed("the payload holds a special file")
            }
            result[relative] = Item(mode: UInt16(status.st_mode & 0o7777), isDirectory: type == S_IFDIR)
        }
        return result
    }

    // The package metadata decides how Installer treats the package. Every
    // attribute and element must be one that this tool expects. A list of
    // bundles, a relocation, a restart action, or an extra script would change
    // what an install does without changing a file that the other checks read.
    func checkPackageInfo(_ path: String, manifest: InstallerManifest, itemCount: Int) throws {
        func fail(_ why: String) -> InstallerError { InstallerError.packageAuditFailed("PackageInfo: " + why) }
        guard let document = try? XMLDocument(contentsOf: URL(fileURLWithPath: path), options: []),
              let root = document.rootElement(), root.name == "pkg-info"
        else {
            throw InstallerError.packageAuditFailed("PackageInfo cannot be read")
        }
        func attributes(_ element: XMLElement) -> [String: String] {
            var result: [String: String] = [:]
            for node in element.attributes ?? [] {
                if let name = node.name { result[name] = node.stringValue ?? "" }
            }
            return result
        }
        let rootAttributes = attributes(root)
        let allowedAttributes: Set<String> = [
            "overwrite-permissions", "relocatable", "identifier", "postinstall-action", "version",
            "format-version", "generator-version", "install-location", "auth",
        ]
        guard Set(rootAttributes.keys).isSubset(of: allowedAttributes) else { throw fail("an unexpected attribute") }
        guard rootAttributes["identifier"] == InstallerLayout.packageIdentifier,
              rootAttributes["version"] == manifest.version,
              rootAttributes["install-location"] == InstallerLayout.installLocation,
              rootAttributes["auth"] == "root",
              rootAttributes["relocatable"] == "false",
              rootAttributes["overwrite-permissions"] == "true",
              rootAttributes["postinstall-action"] == "none",
              rootAttributes["format-version"] == "2"
        else {
            throw fail("a value differs from the manifest or the expected policy")
        }

        var payloadCount = 0
        var scriptsCount = 0
        let emptyElements: Set<String> = [
            "bundle-version", "upgrade-bundle", "update-bundle", "atomic-update-bundle",
            "strict-identifier", "relocate",
        ]
        var seenEmpty = Set<String>()
        for node in root.children ?? [] {
            guard let element = node as? XMLElement else {
                // Comments are harmless. Text must be whitespace.
                if node.kind == .text, (node.stringValue ?? "").trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    continue
                }
                if node.kind == .comment { continue }
                throw fail("unexpected text")
            }
            let name = element.name ?? ""
            let own = attributes(element)
            let children = (element.children ?? []).filter { $0.kind == .element }
            switch name {
            case "payload":
                payloadCount += 1
                guard Set(own.keys).isSubset(of: ["numberOfFiles", "installKBytes"]), children.isEmpty,
                      own["numberOfFiles"] == String(itemCount),
                      let kilobytes = own["installKBytes"], Int(kilobytes) != nil
                else {
                    throw fail("the payload count differs from the manifest")
                }
            case "scripts":
                scriptsCount += 1
                guard own.isEmpty, children.count == 2,
                      let first = children[0] as? XMLElement, let second = children[1] as? XMLElement,
                      first.name == InstallerScripts.preinstallName,
                      second.name == InstallerScripts.postinstallName
                else {
                    throw fail("the script list is not exactly preinstall and postinstall")
                }
                for (script, scriptName) in [(first, InstallerScripts.preinstallName),
                                             (second, InstallerScripts.postinstallName)] {
                    let scriptAttributes = attributes(script)
                    guard Set(scriptAttributes.keys).isSubset(of: ["file", "timeout"]),
                          scriptAttributes["file"] == "./" + scriptName,
                          (script.children ?? []).isEmpty,
                          scriptAttributes["timeout"].map({ Int($0) != nil }) ?? true
                    else {
                        throw fail("a script entry is not the expected file")
                    }
                }
            case _ where emptyElements.contains(name):
                // pkgbuild writes these empty. A filled one names bundles that
                // Installer would match, upgrade, or relocate.
                guard own.isEmpty, (element.children ?? []).isEmpty, seenEmpty.insert(name).inserted else {
                    throw fail("a bundle or relocation element is not empty")
                }
            default:
                throw fail("an unexpected element")
            }
        }
        guard payloadCount == 1, scriptsCount == 1 else { throw fail("a required element is missing") }
    }

    // The bill of materials is what Installer uses for ownership. Every entry
    // must be root:wheel. The install location itself appears as ".".
    func checkBillOfMaterials(
        _ path: String,
        expected: [String: (mode: UInt16, isDirectory: Bool, sha256: String?)]
    ) throws {
        let listing = try tools.run(.lsbom, arguments: ["-p", "MUGsf", path])
        var seen = Set<String>()
        for line in listing.split(separator: "\n") {
            let fields = line.split(separator: "\t", omittingEmptySubsequences: false)
                .map { $0.trimmingCharacters(in: .whitespaces) }
            guard fields.count >= 5 else {
                throw InstallerError.packageAuditFailed("the bill of materials is malformed")
            }
            let symbolic = fields[0], user = fields[1], group = fields[2]
            var name = fields[fields.count - 1]
            guard user == "root", group == "wheel" else {
                throw InstallerError.packageAuditFailed("a package item is not owned by root:wheel")
            }
            if name == "." {
                guard symbolic == Self.symbolic(0o755, isDirectory: true) else {
                    throw InstallerError.packageAuditFailed("the install location has the wrong mode")
                }
                seen.insert(".")
                continue
            }
            if name.hasPrefix("./") { name.removeFirst(2) }
            guard let want = expected[name], symbolic == Self.symbolic(want.mode, isDirectory: want.isDirectory) else {
                throw InstallerError.packageAuditFailed("the bill of materials holds an unexpected item")
            }
            seen.insert(name)
        }
        guard seen == Set(expected.keys).union(["."]) else {
            throw InstallerError.packageAuditFailed("the bill of materials is incomplete")
        }
    }

    static func symbolic(_ mode: UInt16, isDirectory: Bool) -> String {
        var text = isDirectory ? "d" : "-"
        for shift in [6, 3, 0] {
            let bits = (mode >> UInt16(shift)) & 0o7
            text += bits & 4 != 0 ? "r" : "-"
            text += bits & 2 != 0 ? "w" : "-"
            text += bits & 1 != 0 ? "x" : "-"
        }
        return text
    }
}
