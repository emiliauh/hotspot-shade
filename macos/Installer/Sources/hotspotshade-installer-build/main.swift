import Foundation
import HotspotShadeInstallerCore

// hotspotshade-installer-build (stage | build) --helper PATH --engine PATH
//     --launch-daemon PATH --start-right PATH --app PATH --version X.Y.Z
//     --output DIR
//
// `stage` checks the inputs and writes the payload, scripts, and manifest.
// `build` also writes one unsigned, unapproved audit package and audits it.
// Neither installs, and the generated preinstall script always refuses.

func fail(_ message: String, code: Int32 = 1) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(code)
}

let usage = """
usage: hotspotshade-installer-build (stage|build) --helper PATH --engine PATH \
--launch-daemon PATH --start-right PATH --app PATH --version X.Y.Z --output DIR
"""

var arguments = Array(CommandLine.arguments.dropFirst())
guard let command = arguments.first, command == "stage" || command == "build" else { fail(usage, code: 2) }
arguments.removeFirst()

var values: [String: String] = [:]
let known = ["--helper", "--engine", "--launch-daemon", "--start-right", "--app", "--version", "--output"]
var index = 0
while index < arguments.count {
    let name = arguments[index]
    guard known.contains(name), index + 1 < arguments.count, values[name] == nil else { fail(usage, code: 2) }
    values[name] = arguments[index + 1]
    index += 2
}
guard known.allSatisfy({ values[$0] != nil }) else { fail(usage, code: 2) }

let inputs = InstallerInputs(
    helper: values["--helper"]!,
    engine: values["--engine"]!,
    launchDaemon: values["--launch-daemon"]!,
    startRight: values["--start-right"]!,
    app: values["--app"]!
)
let builder = InstallerBuilder()
do {
    if command == "stage" {
        let staged = try builder.stage(
            inputs: inputs,
            version: values["--version"]!,
            outputDirectory: values["--output"]!
        )
        print("Staged payload: \(staged.payloadDirectory)")
        print("Manifest: \(staged.manifestPath)")
    } else {
        let built = try builder.build(
            inputs: inputs,
            version: values["--version"]!,
            outputDirectory: values["--output"]!
        )
        print("Built unsigned package: \(built.packagePath)")
        print("Package SHA-256: \(built.packageSHA256) (written to \(built.digestPath))")
        print("Manifest: \(built.staged.manifestPath)")
    }
    print("NOT APPROVED FOR INSTALLATION: the generated preinstall script refuses before any check or change.")
    print("The package is unsigned and was not installed. Signing, notarization, and a live install are separate steps.")
} catch {
    fail("error: \(error)")
}
