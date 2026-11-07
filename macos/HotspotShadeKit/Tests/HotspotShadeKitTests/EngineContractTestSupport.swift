import Foundation
import XCTest
@testable import HotspotShadeKit

// The engine's --demo flag is a hidden CI test seam. The app never passes it,
// and BackendProcess has no way to pass it. These engine contract tests reach
// it through a small wrapper script that adds the flag, so they still run the
// real engine binary with the app's own launch arguments and descriptors.
final class TestDataEngineLaunch {
    let process: BackendProcess
    private let directory: URL

    init(engine path: String) throws {
        guard !path.contains("'") else { throw XCTSkip("The engine path cannot be quoted for the wrapper script.") }
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("hs-test-data-engine-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let wrapper = directory.appendingPathComponent("hotspotshade")
        try "#!/bin/sh\nexec '\(path)' \"$@\" --demo\n".write(to: wrapper, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: wrapper.path)
        process = BackendProcess(executable: wrapper)
    }

    deinit { try? FileManager.default.removeItem(at: directory) }

    // Read one endpoint without HTTPBackend, which refuses test data.
    func get(_ path: String) async throws -> (Int, Data) {
        let port = try XCTUnwrap(process.port)
        var request = URLRequest(url: URL(string: "http://127.0.0.1:\(port)\(path)")!)
        request.setValue("Bearer \(process.secret)", forHTTPHeaderField: "Authorization")
        request.setValue("127.0.0.1:\(port)", forHTTPHeaderField: "Host")
        let session = URLSession(configuration: HTTPBackend.configuration())
        let (data, response) = try await session.data(for: request)
        return ((response as? HTTPURLResponse)?.statusCode ?? 0, data)
    }
}
