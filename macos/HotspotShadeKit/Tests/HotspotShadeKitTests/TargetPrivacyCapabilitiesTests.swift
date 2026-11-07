import XCTest
import Foundation
@testable import HotspotShadeKit

// These tests check the capability report and the Settings view. They open no
// socket, create no route, and need no root. They do not run a tunnel and they
// do not read a real engine.
final class TargetPrivacyCapabilitiesTests: XCTestCase {
    private let report = TargetPrivacyCapabilities.current

    // The Settings tab label is plain text and the mode schema is shared.
    func testModeNamesMatchTheSharedSchema() {
        XCTAssertEqual(TargetPrivacyCapabilities.tabTitle, "Privacy")
        XCTAssertEqual(TargetPrivacyMode.allCases.map { $0.rawValue }, ["off", "shape", "hide", "cover", "terminate"])
        XCTAssertEqual(report.modes.map { $0.mode.rawValue }, ["off", "shape", "hide", "cover", "terminate"])
        XCTAssertEqual(Set(report.modes.map { $0.mode }).count, report.modes.count)
    }

    // The page reads no tunnel state. No row may say that a mode is in force,
    // and no row may offer a control.
    func testNoRowReportsARunningModeOrOffersAControl() {
        XCTAssertEqual(report.defaultMode, .off)
        XCTAssertTrue(report.isReadOnly)
        XCTAssertFalse(report.hasUsableOptInMode)
        XCTAssertEqual(report.unusableOptInModes.count, 4)
        for row in report.modes {
            XCTAssertNotEqual(row.stateText, "In force")
            XCTAssertFalse(row.canTurnOn, "\(row.mode.rawValue) must not offer a control.")
        }
    }

    // Off is the default behavior for this build, not a running session and
    // not a privacy mode that hides names.
    func testOffIsTheDefaultBehaviorNotASessionState() throws {
        let row = try XCTUnwrap(report.row(.off))
        XCTAssertEqual(row.availability, .defaultBehavior)
        XCTAssertEqual(row.stateText, "Default")
        XCTAssertFalse(row.isOptIn)
        let detail = row.detail.lowercased()
        XCTAssertTrue(detail.contains("ttl"))
        XCTAssertTrue(detail.contains("does not hide destination names"))
        XCTAssertTrue(detail.contains("does not report whether a tunnel is running"))
    }

    // Shape is proposed, not implemented, and says so in plain text.
    func testShapeIsProposedAndUnavailable() throws {
        let row = try XCTUnwrap(report.row(.shape))
        XCTAssertEqual(row.availability, .unavailable)
        XCTAssertEqual(row.stateText, "Unavailable")
        XCTAssertFalse(row.canTurnOn)
        XCTAssertTrue(row.isOptIn)
        XCTAssertTrue(row.detail.hasPrefix("Proposed, not implemented in this build."))
        let detail = row.detail.lowercased()
        XCTAssertTrue(detail.contains("server name"))
        XCTAssertTrue(detail.contains("cannot pad the handshake"))
    }

    // Hide is unavailable under the current design. It must not imply that the engine can apply ECH
    // to TLS that another application owns.
    func testHideIsUnavailableUnderTheCurrentDesign() throws {
        let row = try XCTUnwrap(report.row(.hide))
        XCTAssertEqual(row.availability, .unavailable)
        XCTAssertEqual(row.stateText, "Unavailable")
        XCTAssertFalse(row.canTurnOn)
        XCTAssertTrue(row.isOptIn)
        let detail = row.detail.lowercased()
        XCTAssertTrue(detail.hasPrefix("unavailable under the current design"))
        XCTAssertTrue(detail.contains("another application owns"))
        XCTAssertTrue(detail.contains("cannot apply ech to relayed tls"))
        XCTAssertTrue(detail.contains("no switch"))
    }

    // Cover is deferred and unavailable. It needs an endpoint that the person
    // owns, and this build offers no switch.
    func testCoverIsDeferredButUnavailable() throws {
        let row = try XCTUnwrap(report.row(.cover))
        XCTAssertEqual(row.availability, .deferred)
        XCTAssertEqual(row.stateText, "Unavailable")
        XCTAssertFalse(row.canTurnOn)
        let detail = row.detail.lowercased()
        XCTAssertTrue(detail.contains("endpoint"))
        XCTAssertTrue(detail.contains("no external relay"))
        XCTAssertTrue(detail.contains("no switch"))
    }

    // TLS termination is out of scope, not waiting for later work.
    func testTerminationIsOutOfScope() throws {
        let row = try XCTUnwrap(report.row(.terminate))
        XCTAssertEqual(row.availability, .excluded)
        XCTAssertEqual(row.stateText, "Out of scope")
        XCTAssertFalse(row.canTurnOn)
        let detail = row.detail.lowercased()
        XCTAssertTrue(detail.contains("certificate authority"))
        XCTAssertTrue(detail.contains("decided not to build it"))
    }

    // The capability flags from the cross-platform contract stay explicit.
    func testCapabilityFactsAreExplicit() throws {
        XCTAssertEqual(report.facts.map { $0.fact.rawValue }, ["encryptedClientHello", "serverNameOverride", "backgroundTunnel"])
        let ech = try XCTUnwrap(report.facts.first { $0.fact == .encryptedClientHello })
        XCTAssertEqual(ech.valueText, "No")
        XCTAssertTrue(ech.detail.lowercased().contains("cannot add ech"))
        XCTAssertTrue(ech.detail.lowercased().contains("an application can use ech on its own"))
        let sni = try XCTUnwrap(report.facts.first { $0.fact == .serverNameOverride })
        XCTAssertEqual(sni.valueText, "No")
        XCTAssertTrue(sni.detail.lowercased().contains("relay cannot change the server name"))
        let lifetime = try XCTUnwrap(report.facts.first { $0.fact == .backgroundTunnel })
        XCTAssertEqual(lifetime.valueText, "Not verified")
        for fact in report.facts {
            XCTAssertFalse(fact.title.isEmpty)
            XCTAssertFalse(fact.valueText.isEmpty)
            XCTAssertFalse(fact.detail.isEmpty)
        }
    }

    // An application may use its own ECH or encrypted DNS. The report must
    // qualify that instead of saying that every name is visible, and it must
    // not claim the win for this app.
    func testApplicationEchAndEncryptedDnsAreQualified() {
        let limits = report.limits.joined(separator: " ").lowercased()
        XCTAssertTrue(limits.contains("an application can use its own encrypted client hello or encrypted dns"))
        XCTAssertTrue(limits.contains("not a mode of this app"))
        XCTAssertTrue(limits.contains("do not turn it on or verify it"))
        XCTAssertTrue(limits.contains("metadata"))
        XCTAssertTrue(limits.contains("may see the server name"))
    }

    // A network may inspect the traffic, but the report must not promise that
    // every carrier sees every value.
    func testVisibilityTextIsHedged() {
        let limits = report.limits.joined(separator: " ").lowercased()
        XCTAssertTrue(limits.contains("a network that inspects the plaintext handshake may see"))
        XCTAssertTrue(limits.contains("some networks do not inspect these values"))
        XCTAssertFalse(limits.contains("every carrier"))
    }

    // The page must say that no control exists and that it changes nothing.
    func testPageStatesThatNothingCanBeEnabled() {
        let intro = report.intro.lowercased()
        XCTAssertTrue(intro.contains("read-only"))
        XCTAssertTrue(intro.contains("does not read the tunnel state"))
        XCTAssertTrue(intro.contains("no row says that a mode is running"))
        let note = report.optInNote.lowercased()
        XCTAssertTrue(note.contains("opt-in"))
        XCTAssertTrue(note.contains("no switch"))
        XCTAssertTrue(note.contains("saves no privacy preference"))
        let footer = report.footer.lowercased()
        XCTAssertTrue(footer.contains("no setting on this page"))
        XCTAssertTrue(footer.contains("changes the tunnel"))
        XCTAssertTrue(footer.contains("stores no privacy mode"))
        XCTAssertTrue(footer.contains("does not say whether a tunnel is running"))
    }

    // The page keeps the honest scope and names the modes that stay out of
    // reach.
    func testLimitsKeepTheHonestScope() {
        let limits = report.limits.joined(separator: " ").lowercased()
        XCTAssertTrue(limits.contains("does not hide destination names"))
        XCTAssertTrue(limits.contains("tethering detection"))
        XCTAssertTrue(limits.contains("not a tls tunnel"))
        XCTAssertTrue(limits.contains("cover needs an endpoint"))
        XCTAssertTrue(limits.contains("out of scope"))
    }

    // No universal claim may appear in the visible text.
    func testReportAvoidsUniversalClaims() {
        let text = report.allText.joined(separator: " ").lowercased()
        for phrase in ["in force", "every carrier", "all traffic", "fully hidden", "cannot be seen"] {
            XCTAssertFalse(text.contains(phrase), "The report must not say \(phrase).")
        }
    }

    // Every row must carry a readable title, state, reason, and symbol. The
    // state is text, not color alone.
    func testEveryModeRowCarriesText() {
        for row in report.modes {
            XCTAssertFalse(row.title.isEmpty)
            XCTAssertFalse(row.stateText.isEmpty)
            XCTAssertGreaterThan(row.detail.count, 40)
            XCTAssertFalse(row.symbol.isEmpty)
        }
    }

    // No destination value, host name, or credential may reach this page.
    func testReportHoldsNoDestinationOrCredential() throws {
        let text = report.allText.joined(separator: " ").lowercased()
        for needle in ["http://", "https://", ".com", "@", "bearer", "token", "password", "secret", "identity"] {
            XCTAssertFalse(text.contains(needle), "The report must not hold \(needle).")
        }
        let ipv4 = try NSRegularExpression(pattern: "\\b\\d{1,3}(\\.\\d{1,3}){3}\\b")
        let range = NSRange(text.startIndex..., in: text)
        XCTAssertNil(ipv4.firstMatch(in: text, range: range))
    }

    // The report is stable. A view reads one value and cannot invent a mode.
    func testReportIsStable() {
        XCTAssertEqual(TargetPrivacyCapabilities.report(), report)
        XCTAssertEqual(TargetPrivacyCapabilities.report(), TargetPrivacyCapabilities.report())
    }
}

// The Settings tab shows the fixed report and starts on the current one.
@MainActor final class TargetPrivacySettingsViewTests: XCTestCase {
    func testViewDefaultsToTheCurrentReport() {
        XCTAssertEqual(TargetPrivacySettingsView().report, TargetPrivacyCapabilities.current)
    }

    func testViewUsesTheInjectedReport() {
        let custom = TargetPrivacyCapabilities.current
        XCTAssertEqual(TargetPrivacySettingsView(report: custom).report, custom)
    }

    // The view has no control to bind, so the injected report stays read-only.
    func testViewReportIsReadOnly() {
        XCTAssertTrue(TargetPrivacySettingsView().report.isReadOnly)
    }
}
