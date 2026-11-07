import Foundation
import XCTest
import HotspotShadeKit
@testable import HotspotShadeInstallerCore

struct ShellResult {
    let status: Int32
    let output: String
}

// Runs one fragment of shell text with /bin/sh. The fragments in these tests
// are pure functions or the generated preinstall refusal, which touches no
// system path. No test runs a script against a system path, and no test runs as
// root.
func runShell(_ text: String, arguments: [String] = [], environment: [String: String] = [:]) throws -> ShellResult {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/sh")
    process.arguments = ["-c", text, "sh"] + arguments
    process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"].merging(environment) { _, new in new }
    let pipe = Pipe()
    process.standardOutput = pipe
    process.standardError = pipe
    try process.run()
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return ShellResult(status: process.terminationStatus, output: String(decoding: data, as: UTF8.self))
}

// The same `refuse` that the generated header defines, with a visible marker.
let shellPrelude = """
set -eu
LC_ALL=C
export LC_ALL
refuse() {
    /bin/echo "REFUSED: $1"
    exit 1
}

"""

// Replace one absolute tool path in generated script text with a hermetic stub
// path. The stub itself is written by the test and never touches a system path.
func stubbedShell(_ text: String, _ replacements: [String: String]) -> String {
    var result = text
    for (tool, stub) in replacements {
        result = result.replacingOccurrences(of: tool, with: stub)
    }
    return result
}

func writeShellStub(_ workspace: Workspace, name: String, body: String) throws -> String {
    try workspace.write(name, Data("#!/bin/sh\n\(body)\n".utf8), mode: 0o755)
}

final class ScriptTests: XCTestCase {
    private var scripts: [(String, String)] {
        [("preinstall", InstallerScripts.preinstall), ("postinstall", InstallerScripts.postinstall)]
    }

    // `sh -n` parses a script and runs none of it.
    func testScriptsParse() throws {
        let workspace = try Workspace()
        for (name, text) in scripts {
            let path = try workspace.write(name, Data(text.utf8), mode: 0o644)
            let result = try runShell("/bin/sh -n \"$1\"", arguments: [path])
            XCTAssertEqual(result.status, 0, "\(name): \(result.output)")
        }
    }

    func testScriptsHaveStrictHeader() {
        for (name, text) in scripts {
            XCTAssertTrue(text.hasPrefix("#!/bin/sh\n"), name)
            XCTAssertTrue(text.contains("\nset -eu\n"), name)
            XCTAssertTrue(text.contains("\nPATH=/usr/bin:/bin:/usr/sbin:/sbin\n"), name)
            XCTAssertTrue(text.contains("\nLC_ALL=C\n"), name)
            XCTAssertFalse(text.contains("\t"), name)
        }
    }

    // The stored right is checked as a parsed property list, not as the printed
    // lines of `plutil -p`. A regression to line parsing would make an empty key
    // or a key with a line break ambiguous.
    func testStoredRightKeyCheckIsStructured() {
        XCTAssertTrue(InstallerScripts.postinstall.contains("/usr/bin/xmllint --nonet --xpath"))
        XCTAssertTrue(InstallerScripts.postinstall.contains("preceding-sibling::key"))
        XCTAssertFalse(InstallerScripts.postinstall.contains("plutil -p"))
    }

    // The scripts never change a route, an interface, or a process, and never
    // reach the network. A word list is a coarse guard, not a proof.
    func testScriptsUseNoForbiddenCommand() {
        let forbidden = ["sudo", "eval ", "curl", "wget", "ifconfig", "route ", "networksetup", "scutil",
                         "kill", "pkill", "rm -r", "rm -f /", "rm -rf", "launchctl kickstart", "ln -s",
                         "python", "osascript", "defaults ", "nc ", "dscl", "spctl", "xattr", "codesign"]
        for (name, text) in scripts {
            for word in forbidden {
                XCTAssertFalse(text.contains(word), "\(name) contains \(word)")
            }
        }
    }

    func testScriptsNeverRemoveStateOrTheRight() {
        // The preinstall script removes nothing.
        XCTAssertFalse(InstallerScripts.preinstall.contains("rm "))
        XCTAssertFalse(InstallerScripts.preinstall.contains("authorizationdb"))
        // The postinstall script removes only its own temporary file.
        let removals = InstallerScripts.postinstall.split(separator: "\n").filter { $0.contains("/bin/rm") }
        XCTAssertEqual(removals.count, 1)
        XCTAssertTrue(removals[0].contains("rm -f \"$readback\""))
        XCTAssertFalse(InstallerScripts.postinstall.contains("authorizationdb remove"))
        for (name, text) in scripts {
            // The state files are named only in tests for presence.
            for line in text.split(separator: "\n") where line.contains(InstallerLayout.cleanupMarkerName)
                || line.contains(InstallerLayout.launchIntentName) {
                XCTAssertFalse(line.contains("/bin/rm") || line.contains(">"), "\(name): \(line)")
            }
        }
    }

    // Every program in a script is one absolute path from a short list.
    func testEveryProgramIsAKnownAbsolutePath() throws {
        let pattern = try NSRegularExpression(pattern: #"(?<![A-Za-z0-9_.\-])/(?:usr/)?s?bin/[A-Za-z0-9._\-]+"#)
        let known: [String: Set<String>] = [
            "preinstall": ["/bin/sh", "/bin/echo"],
            "postinstall": [
                "/usr/bin/stat", "/usr/bin/install", "/usr/bin/cmp", "/bin/mkdir", "/usr/sbin/chown", "/bin/chmod",
                "/usr/bin/security", "/usr/bin/mktemp", "/bin/rm", "/usr/bin/plutil", "/bin/launchctl",
                "/bin/sh", "/bin/echo", "/bin/ls", "/usr/bin/tr", "/usr/bin/xmllint",
            ],
        ]
        for (name, text) in scripts {
            let range = NSRange(text.startIndex..., in: text)
            let found = Set(pattern.matches(in: text, range: range).map {
                String(text[Range($0.range, in: text)!])
            })
            XCTAssertFalse(found.isEmpty, name)
            XCTAssertEqual(found.subtracting(known[name]!), [], name)
            // A program that a script names must be used in it.
            XCTAssertEqual(known[name]!.subtracting(found), [], name)
        }
    }

    func testPostinstallUsesOnlyFixedPathsAndOrdersItsChecks() {
        let text = InstallerScripts.postinstall
        for fixed in [
            InstallerLayout.helperDestination, InstallerLayout.launchDaemonDestination,
            InstallerLayout.engineDestination, InstallerLayout.stagedHelperPath,
            InstallerLayout.stagedLaunchDaemonPath, InstallerLayout.startRightDestination,
            InstallerLayout.startRightName, InstallerLayout.stateDirectory, InstallerLayout.engineHome,
            InstallerLayout.installLocation, InstallerLayout.engineRoot, InstallerLayout.supportRoot,
        ] {
            XCTAssertTrue(text.contains(fixed), fixed)
        }
        // No mode text is cut by position. The old check dropped the first
        // character, so it misread a four-digit mode such as 1755.
        XCTAssertFalse(text.contains("${mode#"))
        let bootstrap = text.range(of: "launchctl bootstrap")!.lowerBound
        func before(_ marker: String) {
            guard let range = text.range(of: marker) else { return XCTFail(marker) }
            XCTAssertLessThan(range.lowerBound, bootstrap, marker)
        }
        // The payload directory chain is checked before the first install.
        XCTAssertLessThan(text.range(of: "for dir in \"/Library\"")!.lowerBound,
                          text.range(of: "install -S")!.lowerBound)
        before("cmp -s")
        before("authorizationdb write")
        // The stored right is read back and checked before the helper is registered.
        before("check_right_file \"$readback\"")
        XCTAssertLessThan(text.range(of: "authorizationdb write")!.lowerBound,
                          text.range(of: "authorizationdb read")!.lowerBound)
        XCTAssertLessThan(text.range(of: "authorizationdb read")!.lowerBound,
                          text.range(of: "check_right_file \"$readback\"")!.lowerBound)
    }

    func testScriptsDoNotDependOnVersionTeamOrInputs() throws {
        // Two builds with a different version and a different team write the
        // same script bytes, and those bytes equal the generated constants.
        var other = FakeSignatures.standard
        for tag in ["app", "helper", "engine"] {
            let info = other.infos[tag]!
            other.infos[tag] = HelperSigningInfo(
                identifier: info.identifier, teamIdentifier: "ZZZZZ99999", isAdHoc: false, hasHardenedRuntime: true)
        }
        var written: [[String: Data]] = []
        for (signatures, version) in [(FakeSignatures.standard, "1.0.0"), (other, "9.8.7")] {
            let workspace = try Workspace()
            let staged = try InstallerBuilder(validator: InstallerValidator(signatures: signatures)).stage(
                inputs: try workspace.goodInputs(), version: version, outputDirectory: workspace.path("out"))
            var scripts: [String: Data] = [:]
            for name in ["preinstall", "postinstall"] {
                scripts[name] = try Data(contentsOf: URL(fileURLWithPath: staged.scriptsDirectory + "/" + name))
            }
            written.append(scripts)
        }
        XCTAssertEqual(written[0], written[1])
        XCTAssertEqual(written[0]["preinstall"], Data(InstallerScripts.preinstall.utf8))
        XCTAssertEqual(written[0]["postinstall"], Data(InstallerScripts.postinstall.utf8))
        XCTAssertFalse(InstallerScripts.postinstall.contains(FakeSignatures.team))
        XCTAssertFalse(InstallerScripts.postinstall.contains("ZZZZZ99999"))
    }

    // MARK: mode arithmetic

    private func modeStatus(_ text: String) throws -> Int32 {
        try runShell(shellPrelude + InstallerScripts.modeFunctions + "\nrefuse_unsafe_mode /x \"$1\"\n",
                     arguments: [text]).status
    }

    func testModeArithmeticAcceptsOnlyModesNobodyElseCanWrite() throws {
        // `stat -f %Lp` prints no leading zero and no fixed length.
        for safe in ["755", "644", "700", "750", "555", "0", "1755", "1000", "40"] {
            XCTAssertEqual(try modeStatus(safe), 0, safe)
        }
        for unsafe in ["775", "757", "777", "1777", "70", "7", "2", "20", "4755", "2755", "6755",
                       "abc", "", "8", "12345", "-1", "0x1", " 755"] {
            XCTAssertEqual(try modeStatus(unsafe), 1, "<\(unsafe)>")
        }
    }

    // MARK: access control lists

    func testAccessControlListIsRefused() throws {
        let workspace = try Workspace()
        let plain = try workspace.write("plain", Data("x".utf8))
        let withACL = try workspace.write("acl", Data("x".utf8))
        let chmod = try runShell("/bin/chmod +a 'everyone allow write' \"$1\"", arguments: [withACL])
        guard chmod.status == 0 else { throw XCTSkip("access control lists are not available here") }
        let aclDirectory = workspace.path("acl-dir")
        try FileManager.default.createDirectory(atPath: aclDirectory, withIntermediateDirectories: false)
        XCTAssertEqual(try runShell("/bin/chmod +a 'everyone allow add_file' \"$1\"", arguments: [aclDirectory]).status, 0)
        let check = shellPrelude + InstallerScripts.modeFunctions + "\nrefuse_if_acl \"$1\"\n"
        XCTAssertEqual(try runShell(check, arguments: [plain]).status, 0)
        XCTAssertEqual(try runShell(check, arguments: [workspace.directory.path]).status, 0)
        XCTAssertEqual(try runShell(check, arguments: [withACL]).status, 1)
        XCTAssertEqual(try runShell(check, arguments: [aclDirectory]).status, 1)
    }

    // A failed `ls` used to look like an empty second line after the pipeline,
    // so the check passed. The listing status is now checked on its own.
    func testAccessControlListCheckRefusesAFailedListing() throws {
        let workspace = try Workspace()
        let plain = try workspace.write("plain", Data("x".utf8))
        let failing = try writeShellStub(workspace, name: "ls-fail", body: "exit 70")
        let check = stubbedShell(
            shellPrelude + InstallerScripts.modeFunctions + "\nrefuse_if_acl \"$1\"\n",
            ["/bin/ls": failing]
        )
        let result = try runShell(check, arguments: [plain])
        XCTAssertEqual(result.status, 1, result.output)
        XCTAssertTrue(result.output.contains("could not be read for an access control list"), result.output)
    }

    // A newline in a name adds a line to `ls -lde`. The check refuses it rather
    // than risk reading part of a name as no access control list.
    func testAccessControlListCheckRefusesANameWithANewline() throws {
        let workspace = try Workspace()
        let path = try workspace.write("line\nbreak", Data("x".utf8))
        let check = shellPrelude + InstallerScripts.modeFunctions + "\nrefuse_if_acl \"$1\"\n"
        let result = try runShell(check, arguments: [path])
        XCTAssertEqual(result.status, 1, result.output)
        XCTAssertTrue(result.output.contains("has an access control list"), result.output)
    }

    // MARK: stored right allowlist

    private func rightBase() throws -> [String: Any] {
        try PropertyListSerialization.propertyList(
            from: Data(contentsOf: Repo.startRight), options: [], format: nil) as! [String: Any]
    }

    private func shellAcceptsRight(_ object: [String: Any], in workspace: Workspace, name: String) throws -> Bool {
        let path = try workspace.write("right-\(name).plist", try plistData(object))
        let result = try runShell(
            shellPrelude + InstallerScripts.rightFunctions + "\ncheck_right_file \"$1\"\n", arguments: [path])
        return result.status == 0
    }

    private func kitAcceptsRight(_ object: [String: Any]) throws -> Bool {
        let parsed = try PropertyListSerialization.propertyList(
            from: try plistData(object), options: [], format: nil) as! [String: Any]
        return HelperStartRightValidator.isSafe(parsed)
    }

    private func runRightFunction(
        _ body: String, file: String, replacements: [String: String] = [:]
    ) throws -> ShellResult {
        let text = stubbedShell(
            shellPrelude + InstallerScripts.rightFunctions + "\nright_file=\"$1\"\n" + body,
            replacements
        )
        return try runShell(text, arguments: [file])
    }

    private func shellAcceptsRightData(_ data: Data, in workspace: Workspace, name: String) throws -> Bool {
        let path = try workspace.write("right-\(name).plist", data)
        let result = try runShell(
            shellPrelude + InstallerScripts.rightFunctions + "\ncheck_right_file \"$1\"\n", arguments: [path])
        return result.status == 0
    }

    private func helperAcceptsRightData(_ data: Data) -> Bool {
        guard let object = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
              let dictionary = object as? [String: Any] else {
            return false
        }
        return HelperStartRightValidator.isSafe(dictionary)
    }

    // A minimal safe XML property list with knob values for the raw fixtures
    // that a dictionary round trip cannot express.
    private func rightXMLData(classValue: String = "<string>user</string>", extra: String = "") -> Data {
        Data("""
        <?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0">
        <dict>
        <key>class</key>\(classValue)
        <key>group</key><string>admin</string>
        <key>authenticate-user</key><true/>
        <key>shared</key><false/>
        <key>allow-root</key><false/>
        <key>timeout</key><integer>10</integer>
        \(extra)
        </dict>
        </plist>
        """.utf8)
    }

    func testStoredRightAllowlistMatchesTheHelperValidator() throws {
        let workspace = try Workspace()
        let base = try rightBase()
        let longText = String(repeating: "a", count: 1025)
        let cases: [(String, (inout [String: Any]) -> Void, Bool)] = [
            ("base", { _ in }, true),
            ("no comment", { $0.removeValue(forKey: "comment") }, true),
            ("authd metadata", {
                $0["created"] = 770_000_000.5
                $0["modified"] = 770_000_001.0
                $0["version"] = 1
                $0["identifier"] = "dev.example.app"
                $0["requirement"] = "identifier \"dev.example\"\nand anchor apple"
                $0["session-owner"] = false
                $0["tries"] = 3
            }, true),
            ("integer timestamps", { $0["created"] = 0; $0["modified"] = 5 }, true),
            ("tab in identifier", { $0["identifier"] = "a\tb" }, true),
            ("extra rule", { $0["rule"] = "allow" }, false),
            ("rule list", { $0["rule"] = ["allow"] }, false),
            ("mechanisms", { $0["mechanisms"] = ["builtin:authenticate"] }, false),
            ("k-of-n", { $0["k-of-n"] = 1 }, false),
            ("entitlement", { $0["entitlement"] = "com.apple.example" }, false),
            ("unknown key", { $0["extra"] = "x" }, false),
            ("empty key", { $0[""] = "x" }, false),
            ("newline key", { $0["a\nb"] = "x" }, false),
            ("newline class suffix key", { $0["class\nrule"] = "x" }, false),
            ("quoted rule key", { $0["  \"rule\""] = "x" }, false),
            ("class allow", { $0["class"] = "allow" }, false),
            ("class rule", { $0["class"] = "rule" }, false),
            ("group staff", { $0["group"] = "staff" }, false),
            ("authenticate off", { $0["authenticate-user"] = false }, false),
            ("authenticate string", { $0["authenticate-user"] = "true" }, false),
            ("authenticate integer", { $0["authenticate-user"] = 1 }, false),
            ("shared", { $0["shared"] = true }, false),
            ("shared missing", { $0.removeValue(forKey: "shared") }, false),
            ("allow root", { $0["allow-root"] = true }, false),
            ("allow root integer", { $0["allow-root"] = 0 }, false),
            ("timeout zero", { $0["timeout"] = 0 }, false),
            ("timeout negative", { $0["timeout"] = -1 }, false),
            ("timeout missing", { $0.removeValue(forKey: "timeout") }, false),
            ("timeout upper bound", { $0["timeout"] = 60 }, true),
            ("timeout above ceiling", { $0["timeout"] = 61 }, false),
            ("timeout 300", { $0["timeout"] = 300 }, false),
            ("timeout real", { $0["timeout"] = 10.0 }, false),
            ("timeout bool", { $0["timeout"] = false }, false),
            ("comment integer", { $0["comment"] = 5 }, false),
            ("comment array", { $0["comment"] = ["a"] }, false),
            ("created negative", { $0["created"] = -1 }, false),
            ("created string", { $0["created"] = "1" }, false),
            ("modified date", { $0["modified"] = Date(timeIntervalSince1970: 1_000_000) }, false),
            ("version negative", { $0["version"] = -1 }, false),
            ("version too large", { $0["version"] = 1_000_001 }, false),
            ("version real", { $0["version"] = 1.0 }, false),
            ("tries zero", { $0["tries"] = 0 }, false),
            ("tries too large", { $0["tries"] = 10_001 }, false),
            ("tries real", { $0["tries"] = 3.0 }, false),
            ("session owner true", { $0["session-owner"] = true }, false),
            ("session owner integer", { $0["session-owner"] = 0 }, false),
            ("identifier empty", { $0["identifier"] = "" }, false),
            ("identifier newline", { $0["identifier"] = "a\nb" }, false),
            ("identifier trailing newline", { $0["identifier"] = "ab\n" }, false),
            ("class trailing newline", { $0["class"] = "user\n" }, false),
            ("group trailing newline", { $0["group"] = "admin\n" }, false),
            ("requirement trailing newline", { $0["requirement"] = "ab\n" }, true),
            ("identifier control", { $0["identifier"] = "a\u{01}b" }, false),
            ("identifier non ASCII", { $0["identifier"] = "caf\u{e9}" }, false),
            ("identifier too long", { $0["identifier"] = longText }, false),
            ("requirement control", { $0["requirement"] = "a\u{01}b" }, false),
            ("requirement too long", { $0["requirement"] = String(repeating: "a", count: 4097) }, false),
        ]
        for (index, entry) in cases.enumerated() {
            var object = base
            entry.1(&object)
            let shell = try shellAcceptsRight(object, in: workspace, name: String(index))
            let kit = try kitAcceptsRight(object)
            XCTAssertEqual(shell, entry.2, "shell: \(entry.0)")
            XCTAssertEqual(kit, entry.2, "kit: \(entry.0)")
            // The shell check is never looser than the helper validator.
            if shell { XCTAssertTrue(kit, "shell accepted what the helper refuses: \(entry.0)") }
        }
    }

    func testStoredRightWithEmptyOrNewlineKeyIsRefusedByBothChecks() throws {
        let workspace = try Workspace()
        for (index, key) in ["", "a\nb", "x\n  \"rule\"", "class\nrule"].enumerated() {
            var object = try rightBase()
            object[key] = "x"
            XCTAssertFalse(try shellAcceptsRight(object, in: workspace, name: "hostile-\(index)"), key)
            XCTAssertFalse(try kitAcceptsRight(object), key)
            let path = try workspace.write("right-hostile-\(index).plist", try plistData(object))
            let result = try runShell(
                shellPrelude + InstallerScripts.rightFunctions + "\ncheck_right_file \"$1\"\n",
                arguments: [path])
            XCTAssertEqual(result.status, 1, key)
            XCTAssertTrue(result.output.contains("unknown, empty"), result.output)
        }
    }

    func testStoredRightThatIsNotAPropertyListIsRefused() throws {
        let workspace = try Workspace()
        let path = try workspace.write("garbage", Data("not a plist".utf8))
        let result = try runShell(
            shellPrelude + InstallerScripts.rightFunctions + "\ncheck_right_file \"$1\"\n", arguments: [path])
        XCTAssertEqual(result.status, 1, result.output)
        XCTAssertTrue(result.output.contains("REFUSED"))
    }

    func testStoredRightWithAFakeKeyLineInsideAValueIsAcceptedLikeTheHelper() throws {
        // A comment value with a line break is only a value. The old line
        // parser read the printed second line as a top-level key and refused
        // a definition that the helper accepts. The structured check sees the
        // parsed dictionary and accepts it too.
        let workspace = try Workspace()
        var object = try rightBase()
        object["comment"] = "line\n  \"rule\" => x"
        XCTAssertTrue(try shellAcceptsRight(object, in: workspace, name: "fake"))
        XCTAssertTrue(try kitAcceptsRight(object))
    }

    // `plutil -type` exits nonzero for an absent key. The old wrapper turned
    // every such failure into empty text, so a broken reader looked like an
    // absent optional field. Absence now needs both readers to agree, and any
    // other failure refuses.
    func testRightTypeDistinguishesAbsenceFromAnInspectionError() throws {
        let workspace = try Workspace()
        var withoutComment = try rightBase()
        withoutComment.removeValue(forKey: "comment")
        let absent = try workspace.write("right-absent-functional.plist", try plistData(withoutComment))
        let body = """
        right_type comment
        printf 'type=<%s>|' "$RIGHT_TYPE"
        right_optional_type comment string string
        """
        let absentResult = try runRightFunction(body, file: absent)
        XCTAssertEqual(absentResult.status, 0, absentResult.output)
        XCTAssertEqual(absentResult.output, "type=<>|")

        let present = try workspace.write("right-present-functional.plist", try plistData(try rightBase()))
        let failing = try writeShellStub(workspace, name: "plutil-type-fail", body: """
        case "$1" in
            -type) exit 70 ;;
            *) exec /usr/bin/plutil "$@" ;;
        esac
        """)
        let failure = try runRightFunction(body, file: present, replacements: ["/usr/bin/plutil": failing])
        XCTAssertEqual(failure.status, 1, failure.output)
        XCTAssertTrue(failure.output.contains("could not be read for comment"), failure.output)
    }

    // The sentinel used to append x even when plutil failed, so a failed
    // extraction became an empty value with a successful status.
    func testRightLoadRefusesAFailedExtractionInsteadOfReturningAnEmptyValue() throws {
        let workspace = try Workspace()
        let path = try workspace.write("right-extract-functional.plist", try plistData(try rightBase()))
        let failing = try writeShellStub(workspace, name: "plutil-extract-fail", body: """
        case "$1" in
            -type) exec /usr/bin/plutil "$@" ;;
            *) exit 70 ;;
        esac
        """)
        let body = """
        right_type class
        right_load class
        printf 'raw=<%s>|' "$RAW_VALUE"
        """
        let result = try runRightFunction(body, file: path, replacements: ["/usr/bin/plutil": failing])
        XCTAssertEqual(result.status, 1, result.output)
        XCTAssertTrue(result.output.contains("could not be read for class"), result.output)
    }

    // A trailing newline is part of the value. The sentinel and the single
    // newline removal must preserve it exactly, including an empty value and a
    // value that is only a newline.
    func testRightLoadPreservesTrailingNewlines() throws {
        let workspace = try Workspace()
        let body = """
        right_load comment
        printf '%s' "$RAW_VALUE"
        printf '|'
        """
        let cases: [(String, String, String)] = [
            ("plain", "line", "line|"),
            ("trailing", "line\n", "line\n|"),
            ("empty", "", "|"),
            ("only-newline", "\n", "\n|"),
        ]
        for (name, value, expected) in cases {
            var object = try rightBase()
            object["comment"] = value
            let path = try workspace.write("right-newline-\(name).plist", try plistData(object))
            let result = try runRightFunction(body, file: path)
            XCTAssertEqual(result.status, 0, "\(name): \(result.output)")
            XCTAssertEqual(result.output, expected, name)
        }
    }

    // The character filter is part of the validator. A missing or failed tr
    // used to leave only the sentinel, which passed as "no bad byte".
    func testRightTextRefusesAFailedCharacterFilter() throws {
        let workspace = try Workspace()
        var object = try rightBase()
        object["identifier"] = "dev.example"
        let path = try workspace.write("right-tr-functional.plist", try plistData(object))
        let failing = try writeShellStub(workspace, name: "tr-fail", body: "exit 70")
        let body = #"""
        right_text identifier 1024 "\011"
        """#
        let result = try runRightFunction(body, file: path, replacements: ["/usr/bin/tr": failing])
        XCTAssertEqual(result.status, 1, result.output)
        XCTAssertTrue(result.output.contains("could not be checked for identifier"), result.output)
    }

    // A parser mismatch must refuse. A reader that says a present key is
    // absent, or an absent key is present, must not turn an inspection error
    // into a missing optional field.
    func testRightTypeRefusesAReaderDisagreement() throws {
        let workspace = try Workspace()
        let present = try workspace.write("right-present-reader.plist", try plistData(try rightBase()))
        var withoutComment = try rightBase()
        withoutComment.removeValue(forKey: "comment")
        let absent = try workspace.write("right-absent-reader.plist", try plistData(withoutComment))
        let saysAbsent = try writeShellStub(workspace, name: "xmllint-absent", body: "printf false")
        let saysPresent = try writeShellStub(workspace, name: "xmllint-present", body: "printf true")
        let fails = try writeShellStub(workspace, name: "xmllint-fail", body: "exit 70")
        let body = "right_type comment\n"

        let absentMismatch = try runRightFunction(body, file: present, replacements: ["/usr/bin/xmllint": saysAbsent])
        XCTAssertEqual(absentMismatch.status, 1, absentMismatch.output)
        XCTAssertTrue(absentMismatch.output.contains("could not be inspected for comment"), absentMismatch.output)

        let presentMismatch = try runRightFunction(body, file: absent, replacements: ["/usr/bin/xmllint": saysPresent])
        XCTAssertEqual(presentMismatch.status, 1, presentMismatch.output)
        XCTAssertTrue(presentMismatch.output.contains("could not be read for comment"), presentMismatch.output)

        let readerFailure = try runRightFunction(body, file: present, replacements: ["/usr/bin/xmllint": fails])
        XCTAssertEqual(readerFailure.status, 1, readerFailure.output)
        XCTAssertTrue(readerFailure.output.contains("could not be inspected for comment"), readerFailure.output)
    }

    // The duplicate precheck reads the original file as XML. A binary plist
    // must still take the conversion path, not fail the precheck.
    func testStoredRightInBinaryPropertyListTakesTheSamePath() throws {
        let workspace = try Workspace()
        let data = try PropertyListSerialization.data(
            fromPropertyList: try rightBase(), format: .binary, options: 0)
        XCTAssertTrue(try shellAcceptsRightData(data, in: workspace, name: "binary"))
        XCTAssertTrue(helperAcceptsRightData(data))
    }

    // Raw XML is the only way to express duplicate keys and nested malformed
    // shapes. The shell check must refuse every one, and it must never accept a
    // file that the helper validator refuses.
    func testMalformedNestedXMLAndDuplicateKeysFailClosed() throws {
        let workspace = try Workspace()
        let fixtures: [(String, Data, Bool, Bool)] = [
            ("safe", rightXMLData(), true, true),
            // A duplicate known key is the same last value to both parsers, but
            // the shell refuses the ambiguity instead of choosing one.
            ("duplicate-safe", rightXMLData(
                classValue: "<string>user</string>\n<key>class</key><string>user</string>"), false, true),
            ("duplicate-unsafe", rightXMLData(
                classValue: "<string>user</string>\n<key>class</key><string>allow</string>"), false, false),
            ("nested-class", rightXMLData(
                classValue: "<dict><key>rule</key><string>allow</string></dict>"), false, false),
            ("nested-comment", rightXMLData(
                extra: "<key>comment</key><dict><key>rule</key><string>allow</string></dict>"), false, false),
            ("malformed-nested", rightXMLData(
                extra: "<key>comment</key><dict><key>x</key><string>y</string>"), false, false),
        ]
        for (index, fixture) in fixtures.enumerated() {
            let shell = try shellAcceptsRightData(fixture.1, in: workspace, name: "raw-\(index)")
            let helper = helperAcceptsRightData(fixture.1)
            XCTAssertEqual(shell, fixture.2, fixture.0)
            XCTAssertEqual(helper, fixture.3, fixture.0)
            if shell { XCTAssertTrue(helper, "shell accepted what the helper refuses: \(fixture.0)") }
        }
    }

}

// MARK: non-installable preinstall gate

// The foundation package has no exclusion held for the whole installation and
// shared by every start path. Its preinstall script must therefore refuse before
// it reads a process, a marker, or a launchd job, and before it can stop or
// change anything.
final class NonInstallableGateTests: XCTestCase {
    func testPreinstallRefusesBeforeAnyCheckOrChange() throws {
        let workspace = try Workspace()
        let script = try workspace.write("preinstall", Data(InstallerScripts.preinstall.utf8), mode: 0o755)
        let result = try runShell("/bin/sh \"$1\"", arguments: [script])
        XCTAssertEqual(result.status, 1, result.output)
        XCTAssertTrue(result.output.contains("not approved for installation"), result.output)
    }

    // A leading argument or an environment name cannot turn the gate into the
    // old upgrade flow.
    func testPreinstallRefusesWithArgumentsAndAnApprovalEnvironmentName() throws {
        let workspace = try Workspace()
        let script = try workspace.write("preinstall", Data(InstallerScripts.preinstall.utf8), mode: 0o755)
        let result = try runShell(
            "/bin/sh \"$1\" --approve",
            arguments: [script],
            environment: ["HOTSPOTSHADE_INSTALL_APPROVED": "1", "HOTSPOTSHADE_INSTALL": "1"]
        )
        XCTAssertEqual(result.status, 1, result.output)
        XCTAssertTrue(result.output.contains("not approved for installation"), result.output)
    }

    func testPreinstallHasNoProcessMarkerOrLaunchdPath() {
        let text = InstallerScripts.preinstall
        for word in ["pgrep", "launchctl", "bootout", "/bin/sleep", "cleanup-blocked", "engine-session",
                     "authorizationdb", "/bin/rm", "install -S", InstallerLayout.stateDirectory,
                     InstallerLayout.engineHome] {
            XCTAssertFalse(text.contains(word), "preinstall contains \(word)")
        }
        // The refusal is fixed text. No input, environment name, or state file
        // selects another branch.
        XCTAssertTrue(text.contains("refuse \"this package is a build-only foundation and is not approved for installation\""))
        XCTAssertFalse(text.contains("HOTSPOTSHADE_INSTALL"))
        XCTAssertFalse(text.contains("getenv"))
    }

    func testManifestAndNotesRecordTheRefusal() throws {
        let workspace = try Workspace()
        let staged = try InstallerBuilder(validator: InstallerValidator(signatures: FakeSignatures.standard)).stage(
            inputs: try workspace.goodInputs(), version: "1.0.0", outputDirectory: workspace.path("out"))
        XCTAssertFalse(staged.manifest.installationApproved)
        XCTAssertFalse(InstallerScripts.installationApproved)
        XCTAssertTrue(staged.manifest.notes.contains { $0.contains("NOT APPROVED FOR INSTALLATION") })
        XCTAssertTrue(staged.manifest.notes.contains { $0.contains("Do not install this package") })
    }
}

// The real Security framework checker, with no signing identity. It shows that
// the installer fails closed on what an unsigned or ad-hoc build produces. A
// real Developer ID signature is not tested here and stays unverified.
final class RealSignatureFailClosedTests: XCTestCase {
    private func run(_ tool: String, _ arguments: [String]) throws -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: tool)
        process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        return process.terminationStatus
    }

    func testAdHocSignedExecutableIsRejected() throws {
        guard FileManager.default.isExecutableFile(atPath: "/usr/bin/codesign") else { throw XCTSkip("no codesign") }
        let workspace = try Workspace()
        let path = try workspace.compileExecutable(architecture: "arm64", name: "helper")
        XCTAssertEqual(try run("/usr/bin/codesign", ["--remove-signature", path]), 0)
        XCTAssertEqual(try run("/usr/bin/codesign",
                               ["--force", "--sign", "-", "--options", "runtime",
                                "--identifier", HelperRequirement.helperIdentifier, path]), 0)
        // The file is thin arm64 and the signature is valid but ad-hoc. The
        // refusal comes from the signature, not from the architecture.
        XCTAssertEqual(MachOPolicy.classify(atPath: path), .thinArm64Executable)
        XCTAssertThrowsError(try InstallerValidator().validateExecutable(
            atPath: path, artifact: .helper, identifier: HelperRequirement.helperIdentifier,
            teamIdentifier: "ABCDE12345"
        )) { XCTAssertEqual($0 as? InstallerError, .signatureRejected(.helper)) }
    }

    func testUnsignedExecutableIsRejected() throws {
        guard FileManager.default.isExecutableFile(atPath: "/usr/bin/codesign") else { throw XCTSkip("no codesign") }
        let workspace = try Workspace()
        let path = try workspace.compileExecutable(architecture: "arm64", name: "engine")
        XCTAssertEqual(try run("/usr/bin/codesign", ["--remove-signature", path]), 0)
        // Without a signature the file has no code signature command, so the
        // architecture policy refuses it first.
        XCTAssertThrowsError(try InstallerValidator().validateExecutable(
            atPath: path, artifact: .engine, identifier: HelperRequirement.engineIdentifier,
            teamIdentifier: "ABCDE12345"
        )) {
            let error = $0 as? InstallerError
            XCTAssertTrue(error == .signatureRejected(.engine) || error == .unsupportedArchitecture(.engine), "\(String(describing: error))")
        }
    }

    func testAppleSignedAppIsNotAcceptedAsTheApp() throws {
        // A real, validly signed bundle from another team is not the app.
        let path = "/System/Applications/Calculator.app"
        guard FileManager.default.fileExists(atPath: path) else { throw XCTSkip("no Calculator.app") }
        XCTAssertThrowsError(try InstallerValidator().teamIdentifier(ofApp: path)) {
            XCTAssertEqual($0 as? InstallerError, .appNotSigned)
        }
    }

    func testRealCheckerEndToEndRefusesAnUnsignedBuild() throws {
        guard FileManager.default.isExecutableFile(atPath: "/usr/bin/codesign") else { throw XCTSkip("no codesign") }
        let workspace = try Workspace()
        let helper = try workspace.compileExecutable(architecture: "arm64", name: "in-helper")
        let engine = try workspace.compileExecutable(architecture: "arm64", name: "in-engine")
        let inputs = InstallerInputs(
            helper: helper, engine: engine,
            launchDaemon: try workspace.write("d.plist", Data(contentsOf: Repo.launchDaemon)),
            startRight: try workspace.write("r.plist", Data(contentsOf: Repo.startRight)),
            app: try workspace.makeApp()
        )
        XCTAssertThrowsError(try InstallerBuilder().stage(
            inputs: inputs, version: "1.0.0", outputDirectory: workspace.path("out")
        )) { XCTAssertEqual($0 as? InstallerError, .appNotSigned) }
        XCTAssertFalse(FileManager.default.fileExists(atPath: workspace.path("out")))
    }
}
