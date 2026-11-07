import Darwin
import Foundation
import XCTest
@testable import HotspotShadeKit

final class UnprivilegedEngineIntegrationTests: XCTestCase {
    // Run only through the network-confined harness. This exercises the real
    // engine and bearer-protected loopback API, without requesting a tunnel.
    func testRealEngineReportsStatusAsAnOrdinaryUser() async throws {
        guard ProcessInfo.processInfo.environment["HS_TEST_CONFINED_REAL_ENGINE"] == "1",
              let path = ProcessInfo.processInfo.environment["HS_TEST_REAL_ENGINE"] else {
            throw XCTSkip("Use scripts/macos_unprivileged_engine_test.sh.")
        }
        XCTAssertNotEqual(geteuid(), 0)
        let process = BackendProcess(executable: URL(fileURLWithPath: path))
        try await process.start()
        XCTAssertGreaterThanOrEqual(process.handoffReadDescriptor, 0)
        do {
            let port = try XCTUnwrap(process.port)
            let backend = HTTPBackend(port: port, secret: process.secret)
            let status = try await backend.status(timeout: 3)
            XCTAssertEqual(status.demo, false)
            XCTAssertEqual(status.running, false)
            XCTAssertEqual(status.api, 1)
            // Turn on writes the pairing handoff through this route before it
            // asks the helper for the root engine. The real engine must route
            // it to its user-engine backend. `handoff_unsupported` means the
            // route answered with the trait default, and `handoff_unavailable`
            // means the engine lost the descriptor that BackendProcess passes.
            // The confined harness hides the pairing key, so an unpaired
            // engine refuses with its own code; a paired one writes the frame.
            do {
                try await backend.pairHandoff()
            } catch BackendError.response(let message) {
                XCTAssertNotEqual(message, "handoff_unsupported")
                XCTAssertNotEqual(message, "handoff_unavailable")
            }
            XCTAssertTrue(process.isRunning)
        } catch {
            await process.stop()
            throw error
        }
        await process.stop()
        XCTAssertFalse(process.isRunning)
    }
}
