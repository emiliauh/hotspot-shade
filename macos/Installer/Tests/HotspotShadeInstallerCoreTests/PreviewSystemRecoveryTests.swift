import XCTest
@testable import HotspotShadeInstallerCore

final class PreviewSystemRecoveryTests: XCTestCase {
    func testRecoveryEntryPointsStayDisabledWithoutPayloadInputs() {
        XCTAssertThrowsError(try PreviewSystemInstaller.recoverFiles()) {
            #if HOTSPOTSHADE_LOCAL_PREVIEW && HOTSPOTSHADE_SYSTEM_PREVIEW_CANDIDATE
            XCTAssertEqual($0 as? ServiceTransactionError, .requiresRoot)
            #else
            XCTAssertEqual($0 as? CoordinatorError, .notApproved)
            #endif
        }
        XCTAssertThrowsError(try PreviewSystemInstaller.recoverService()) {
            #if HOTSPOTSHADE_LOCAL_PREVIEW && HOTSPOTSHADE_SYSTEM_PREVIEW_CANDIDATE
            XCTAssertEqual($0 as? ServiceTransactionError, .requiresRoot)
            #else
            XCTAssertEqual($0 as? CoordinatorError, .notApproved)
            #endif
        }
        XCTAssertThrowsError(try PreviewSystemInstaller.status()) {
            #if HOTSPOTSHADE_LOCAL_PREVIEW && HOTSPOTSHADE_SYSTEM_PREVIEW_CANDIDATE
            XCTAssertEqual($0 as? ServiceTransactionError, .requiresRoot)
            #else
            XCTAssertEqual($0 as? CoordinatorError, .notApproved)
            #endif
        }
    }
}
