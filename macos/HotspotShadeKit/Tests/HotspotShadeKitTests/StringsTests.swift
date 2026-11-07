import Foundation
import XCTest
@testable import HotspotShadeKit

final class StringsTests: XCTestCase {
    func testSigningGuidanceMatchesTheBuildPolicy() {
        #if HOTSPOTSHADE_LOCAL_PREVIEW
        XCTAssertTrue(Strings.helperNotSigned.contains("Apple Development"))
        #else
        XCTAssertTrue(Strings.helperNotSigned.contains("Developer ID"))
        #endif
    }

    func testCleanupBlockGuidanceDescribesDurableBlockAndAdministratorRecovery() {
        XCTAssertEqual(Strings.helperCleanup, "A previous tunnel did not stop cleanly, so HotspotShade stays off to protect this network. Restarting the target device does not clear it. First have an administrator confirm with netstat -rn that no HotspotShade route remains. Only after that check, run the preview coordinator command preview-clear-cleanup-block as root. It checks the routes again and clears the block only when nothing remains.")
        // The block names its clear command and puts the route check first.
        XCTAssertTrue(Strings.helperCleanup.contains("preview-clear-cleanup-block"))
        XCTAssertLessThan(
            Strings.helperCleanup.range(of: "netstat -rn")!.lowerBound,
            Strings.helperCleanup.range(of: "preview-clear-cleanup-block")!.lowerBound
        )
        for error in [HelperTrustError.cleanupBlocked, .engineStopTimedOut, .engineExited, .engineExitUnclean] {
            XCTAssertEqual(Strings.helperMessage(error), Strings.helperCleanup, "\(error)")
        }
        XCTAssertFalse(Strings.helperCleanup.contains("Restart the target device before"), Strings.helperCleanup)
        XCTAssertTrue(Strings.helperCleanup.contains("does not clear"), Strings.helperCleanup)
    }

    func testLostHelperConnectionIsReportedDistinctly() {
        XCTAssertEqual(Strings.helperLost, "Lost the connection to the protected helper. The tunnel may have stopped. Turn the tunnel on again.")
        for error in [HelperTrustError.notConnected, .helperTimeout, .helperUnavailable] {
            XCTAssertEqual(Strings.helperMessage(error), Strings.helperLost, "\(error)")
        }
        XCTAssertNotEqual(Strings.helperLost, Strings.helperStopped)
        XCTAssertNotEqual(Strings.helperLost, Strings.helperFailed)
    }

    // The status texts name the app, not its internal engine.
    func testStatusTextsUsePlainEnglish() {
        XCTAssertEqual(Strings.unknownSubtitle, "HotspotShade received a status that it does not understand.")
        XCTAssertEqual(Strings.staleStatus, "HotspotShade did not answer. This status may be out of date.")
        XCTAssertEqual(Strings.statusUnavailableSubtitle, "HotspotShade did not answer.")
        XCTAssertEqual(UIStrings.notificationsNotAsked, "macOS asks for notification permission the first time you turn the tunnel on.")
        XCTAssertEqual(UIStrings.adminAuthorization, "macOS asks for administrator authorization when you turn on the tunnel.")
        for text in [Strings.unknownSubtitle, Strings.staleStatus, Strings.statusUnavailableSubtitle, UIStrings.notificationsNotAsked] {
            XCTAssertFalse(text.localizedCaseInsensitiveContains("engine"), text)
        }
        XCTAssertTrue(UIStrings.allText.contains(UIStrings.adminAuthorization))
    }

    func testForgetStatesNeverClaimRemoteDeletion() {
        // Protocol v1 gives no proof that the source device removed the key. A
        // valid answer shows only that a peer replied. Both states stay
        // cautious, including the confirmed state.
        for text in [Strings.forgetConfirmed, Strings.forgetNotDelivered] {
            XCTAssertFalse(text.localizedCaseInsensitiveContains("removed this target device"), text)
            XCTAssertTrue(text.localizedCaseInsensitiveContains("could not confirm"), text)
            XCTAssertTrue(text.localizedCaseInsensitiveContains("may still trust"), text)
        }
        XCTAssertFalse(Strings.forgetConfirmed.localizedCaseInsensitiveContains("forgotten."), Strings.forgetConfirmed)
    }

    func testHelperMessagesUsePlainTextWithoutInstallDetails() {
        let messages = [
            Strings.helperNotInstalled,
            Strings.helperNotSigned,
            Strings.helperBusy,
            Strings.helperCleanup,
            Strings.helperStopped,
            Strings.helperLost,
            Strings.helperFailed,
            Strings.helperNotAuthorized,
            Strings.helperAuthorizationCancelled,
            Strings.helperAuthorizationBusy,
            Strings.helperRightNotConfigured,
            Strings.helperStartExclusionBusy,
            Strings.helperStartExclusionUnavailable,
            Strings.helperTunnelNotRunning,
            Strings.helperGrantFailed,
        ]
        for message in messages {
            XCTAssertFalse(message.contains("/"), message)
            XCTAssertFalse(message.localizedCaseInsensitiveContains("token"), message)
            XCTAssertFalse(message.localizedCaseInsensitiveContains("engine"), message)
            for word in ["laptop", "iphone", "hotspot proxy"] {
                XCTAssertFalse(message.localizedCaseInsensitiveContains(word), "\(word) in: \(message)")
            }
        }
    }

    func testStartExclusionFailuresUseFixedPlainMessages() {
        XCTAssertEqual(
            Strings.helperMessage(HelperTrustError.startExclusionBusy),
            Strings.helperStartExclusionBusy
        )
        XCTAssertEqual(
            Strings.helperMessage(HelperTrustError.startExclusionUnavailable),
            Strings.helperStartExclusionUnavailable
        )
        XCTAssertNotEqual(Strings.helperStartExclusionBusy, Strings.helperFailed)
        XCTAssertNotEqual(Strings.helperStartExclusionUnavailable, Strings.helperFailed)
        XCTAssertEqual(
            HelperTrustError.startExclusionBusy.errorDescription,
            Strings.helperStartExclusionBusy
        )
        XCTAssertEqual(
            HelperTrustError.startExclusionUnavailable.errorDescription,
            Strings.helperStartExclusionUnavailable
        )
        for message in [Strings.helperStartExclusionBusy, Strings.helperStartExclusionUnavailable] {
            for detail in ["lock", "journal", "path", "token", "engine", "/"] {
                XCTAssertFalse(
                    message.localizedCaseInsensitiveContains(detail),
                    "\(detail) in: \(message)"
                )
            }
        }
    }
}
