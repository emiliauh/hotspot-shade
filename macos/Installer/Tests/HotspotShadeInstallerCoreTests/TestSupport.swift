import Foundation
import XCTest
import HotspotShadeKit
@testable import HotspotShadeInstallerCore

// A signature checker with no real identity. A fake Mach-O file starts with the
// 64-bit magic and then names a tag. The tag selects the signing facts. This
// shows how the installer reacts to each fact. It proves nothing about a real
// signature, which the tests below leave unverified.
struct FakeSignatures: HelperCodeSignatureChecking {
    var infos: [String: HelperSigningInfo]

    static let team = "ABCDE12345"

    static func good(_ identifier: String, team: String? = FakeSignatures.team) -> HelperSigningInfo {
        HelperSigningInfo(identifier: identifier, teamIdentifier: team, isAdHoc: false, hasHardenedRuntime: true)
    }

    static var standard: FakeSignatures {
        FakeSignatures(infos: [
            "app": good(HelperRequirement.appIdentifier),
            "helper": good(HelperRequirement.helperIdentifier),
            "engine": good(HelperRequirement.engineIdentifier),
        ])
    }

    func replacing(_ tag: String, with info: HelperSigningInfo) -> FakeSignatures {
        var copy = self
        copy.infos[tag] = info
        return copy
    }

    private func tag(atPath path: String) throws -> String {
        if path.hasSuffix(".app") { return "app" }
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        guard data.count > fakeMachOTagOffset else { throw HelperTrustError.signatureUnavailable }
        return String(decoding: data.dropFirst(fakeMachOTagOffset).prefix(while: { $0 != 0 }), as: UTF8.self)
    }

    func signingInfo(atPath path: String) throws -> HelperSigningInfo {
        guard let info = infos[try tag(atPath: path)] else { throw HelperTrustError.signatureUnavailable }
        return info
    }

    func verifyStaticCode(atPath path: String, requirement: String) throws {
        let info = try signingInfo(atPath: path)
        guard let team = info.teamIdentifier, !info.isAdHoc,
              requirement.contains("identifier \"\(info.identifier)\""),
              requirement.contains("= \"\(team)\"")
        else { throw HelperTrustError.signatureRejected }
    }

    func verifyRunningCode(auditToken: [UInt8], processIdentifier: Int32, requirement: String) throws {
        throw HelperTrustError.callerRejected
    }
}

let fakeMachOTagOffset = 48

private func le32Bytes(_ value: UInt32) -> [UInt8] {
    [UInt8(value & 0xFF), UInt8((value >> 8) & 0xFF), UInt8((value >> 16) & 0xFF), UInt8((value >> 24) & 0xFF)]
}

private func be32Bytes(_ value: UInt32) -> [UInt8] { le32Bytes(value).reversed() }

// A small thin Mach-O file: a 64-bit header, one LC_CODE_SIGNATURE command, and
// then the tag that selects the fake signing facts. The header is valid for the
// installer's architecture policy. It is not a runnable program. The knobs
// build the invalid shapes that the policy refuses.
func fakeMachO(
    tag: String,
    padding: Int = 64,
    cpuType: UInt32 = 0x0100_000C,
    cpuSubtype: UInt32 = 0,
    fileType: UInt32 = 2,
    withSignatureCommand: Bool = true,
    signatureOffset: UInt32? = nil
) -> Data {
    let body = Data(tag.utf8) + Data(repeating: 0, count: padding)
    var bytes: [UInt8] = [0xCF, 0xFA, 0xED, 0xFE]
    bytes += le32Bytes(cpuType)
    bytes += le32Bytes(cpuSubtype)
    bytes += le32Bytes(fileType)
    bytes += le32Bytes(withSignatureCommand ? 1 : 0)
    bytes += le32Bytes(withSignatureCommand ? 16 : 0)
    bytes += le32Bytes(0)
    bytes += le32Bytes(0)
    if withSignatureCommand {
        bytes += le32Bytes(0x1D)
        bytes += le32Bytes(16)
        bytes += le32Bytes(signatureOffset ?? UInt32(fakeMachOTagOffset))
        bytes += le32Bytes(UInt32(body.count))
    } else {
        // Keep the tag at the same offset.
        bytes += [UInt8](repeating: 0, count: 16)
    }
    return Data(bytes) + body
}

// A universal file with the given slices. Each slice is the bytes of a thin
// file. The file is a valid container, not a runnable program.
func fakeFat(_ slices: [(cpuType: UInt32, data: Data)]) -> Data {
    var header: [UInt8] = [0xCA, 0xFE, 0xBA, 0xBE] + be32Bytes(UInt32(slices.count))
    var offset = 4096
    var body = Data()
    for slice in slices {
        header += be32Bytes(slice.cpuType) + be32Bytes(0) + be32Bytes(UInt32(offset))
        header += be32Bytes(UInt32(slice.data.count)) + be32Bytes(12)
        body.append(slice.data)
        offset += slice.data.count
    }
    var data = Data(header)
    data.append(Data(repeating: 0, count: 4096 - data.count))
    data.append(body)
    return data
}

// Paths into the repository, for the real templates.
enum Repo {
    static let root: URL = {
        var url = URL(fileURLWithPath: #filePath)
        // <repo>/macos/Installer/Tests/<target>/TestSupport.swift
        for _ in 0..<5 { url.deleteLastPathComponent() }
        return url
    }()
    static var helperTemplates: URL { root.appendingPathComponent("macos/Helper") }
    static var launchDaemon: URL { helperTemplates.appendingPathComponent("dev.hotspotshade.mac.helper.plist") }
    static var startRight: URL { helperTemplates.appendingPathComponent("dev.hotspotshade.tunnel.start.plist") }
    static var kitFixtures: URL {
        root.appendingPathComponent("macos/HotspotShadeKit/Tests/HotspotShadeKitTests/Fixtures")
    }
}

final class Workspace {
    let directory: URL
    init() throws {
        let base = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("hs-installer-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: base, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        directory = base
    }
    deinit { try? FileManager.default.removeItem(at: directory) }

    func path(_ name: String) -> String { directory.appendingPathComponent(name).path }

    @discardableResult
    func write(_ name: String, _ data: Data, mode: Int = 0o644) throws -> String {
        let url = directory.appendingPathComponent(name)
        try data.write(to: url)
        try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: url.path)
        return url.path
    }

    // A bundle with an Info.plist and one thin arm64 main executable. The fake
    // checker reads no part of it except the `.app` suffix.
    @discardableResult
    func makeApp(name: String = "HotspotShade.app", executable: Data? = nil) throws -> String {
        let url = directory.appendingPathComponent(name)
        try FileManager.default.createDirectory(
            at: url.appendingPathComponent("Contents/MacOS"), withIntermediateDirectories: true)
        try plistData(["CFBundleExecutable": "HotspotShade"])
            .write(to: url.appendingPathComponent("Contents/Info.plist"))
        try (executable ?? fakeMachO(tag: "appexec"))
            .write(to: url.appendingPathComponent("Contents/MacOS/HotspotShade"))
        return url.path
    }

    // Real Mach-O files from the system C compiler, for the tests that use the
    // real Security checker. The tests skip when the compiler is missing.
    func compileExecutable(architecture: String, name: String) throws -> String {
        guard FileManager.default.isExecutableFile(atPath: "/usr/bin/clang") else { throw XCTSkip("no clang") }
        let source = try write("\(name).c", Data("int main(void) { return 0; }\n".utf8))
        let output = path(name)
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/clang")
        process.arguments = ["-arch", architecture, source, "-o", output]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do { try process.run() } catch { throw XCTSkip("clang did not start") }
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw XCTSkip("clang cannot build \(architecture)") }
        return output
    }

    func universalExecutable(of first: String, and second: String, name: String) throws -> String {
        guard FileManager.default.isExecutableFile(atPath: "/usr/bin/lipo") else { throw XCTSkip("no lipo") }
        let output = path(name)
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/lipo")
        process.arguments = ["-create", first, second, "-output", output]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw XCTSkip("lipo failed") }
        return output
    }

    func goodInputs(
        helper: Data? = nil,
        engine: Data? = nil,
        launchDaemon: Data? = nil,
        startRight: Data? = nil
    ) throws -> InstallerInputs {
        InstallerInputs(
            helper: try write("in-helper", helper ?? fakeMachO(tag: "helper"), mode: 0o755),
            engine: try write("in-engine", engine ?? fakeMachO(tag: "engine"), mode: 0o755),
            launchDaemon: try write("in-daemon.plist", try launchDaemon ?? Data(contentsOf: Repo.launchDaemon)),
            startRight: try write("in-right.plist", try startRight ?? Data(contentsOf: Repo.startRight)),
            app: try makeApp()
        )
    }
}

func plistData(_ object: [String: Any]) throws -> Data {
    try PropertyListSerialization.data(fromPropertyList: object, format: .xml, options: 0)
}
