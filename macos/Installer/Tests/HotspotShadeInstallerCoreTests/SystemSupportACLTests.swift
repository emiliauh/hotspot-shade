import Darwin
import Foundation
import XCTest
@testable import HotspotShadeInstallerCore

final class SystemSupportACLTests: XCTestCase {
    func testUnreadableDescriptorAndInvalidPathDoNotAppearClear() {
        XCTAssertTrue(SystemSupport.hasExtendedACL(-1))
        XCTAssertTrue(SystemSupport.hasExtendedACL(path: "/dev/null/not-a-child"))
        let missing = FileManager.default.temporaryDirectory
            .appendingPathComponent("hs-missing-acl-\(UUID().uuidString)")
        XCTAssertTrue(SystemSupport.hasExtendedACL(path: missing.path))
    }

    func testRegularTemporaryFileWithoutExtendedACLIsAccepted() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("hs-installer-acl-\(UUID().uuidString)")
        try Data("test".utf8).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW)
        XCTAssertGreaterThanOrEqual(descriptor, 0)
        guard descriptor >= 0 else { return }
        defer { close(descriptor) }
        XCTAssertFalse(SystemSupport.hasExtendedACL(descriptor))
        XCTAssertFalse(SystemSupport.hasExtendedACL(path: url.path))
    }

    func testSymbolicLinksAreNotTreatedAsClearPaths() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("hs-installer-link-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let target = directory.appendingPathComponent("target")
        let link = directory.appendingPathComponent("link")
        try Data("test".utf8).write(to: target)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
        XCTAssertTrue(SystemSupport.hasExtendedACL(path: link.path))
        try FileManager.default.removeItem(at: target)
        XCTAssertTrue(SystemSupport.hasExtendedACL(path: link.path))
    }

    func testExtendedACLIsRefusedForFileAndDirectory() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("hs-installer-acl-dir-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("file")
        try Data("test".utf8).write(to: file)
        for url in [file, directory] {
            let chmod = Process()
            chmod.executableURL = URL(fileURLWithPath: "/bin/chmod")
            chmod.arguments = ["+a", "everyone allow read", url.path]
            chmod.standardOutput = FileHandle.nullDevice
            chmod.standardError = FileHandle.nullDevice
            try chmod.run()
            chmod.waitUntilExit()
            guard chmod.terminationStatus == 0 else {
                throw XCTSkip("Extended ACLs are unavailable in the test directory")
            }
            let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW)
            XCTAssertGreaterThanOrEqual(descriptor, 0)
            guard descriptor >= 0 else { continue }
            XCTAssertTrue(SystemSupport.hasExtendedACL(descriptor))
            XCTAssertTrue(SystemSupport.hasExtendedACL(path: url.path))
            close(descriptor)
        }
    }
}
