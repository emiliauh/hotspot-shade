import XCTest
import SwiftUI
import AppKit
@testable import HotspotShadeKit

// These tests measure the real views without a window. The offscreen image
// renderer does not draw text in the test process, so the tests do not compare
// pixels. The previews and the demo app check the drawing.
@MainActor final class W6LayoutTests: XCTestCase {
    // The refresh control must keep the same size while it shows the spinner.
    // A changing size moved the toolbar and clipped the spinner.
    func testRefreshToolbarButtonKeepsItsSize() {
        let idle = NSHostingView(rootView: RefreshToolbarButton(isRefreshing: false, help: UIStrings.refreshStatusHelp, action: {}))
        let busy = NSHostingView(rootView: RefreshToolbarButton(isRefreshing: true, help: UIStrings.refreshStatusHelp, action: {}))
        idle.layoutSubtreeIfNeeded()
        busy.layoutSubtreeIfNeeded()
        XCTAssertEqual(idle.fittingSize.width, busy.fittingSize.width, accuracy: 0.5)
        XCTAssertEqual(idle.fittingSize.height, busy.fittingSize.height, accuracy: 0.5)
        XCTAssertGreaterThan(idle.fittingSize.width, 0)
        XCTAssertGreaterThan(idle.fittingSize.height, 0)
    }
}
