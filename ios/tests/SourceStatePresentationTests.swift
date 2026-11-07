import Foundation

/// Checks the presentation-level state for Start, Dashboard, Settings,
/// pairing, and diagnostics. It starts no listener and reads no device state.
@main
struct SourceStatePresentationTests {
    static func check(_ condition: Bool, _ message: String, line: Int = #line) {
        if !condition {
            print("FAIL line \(line): \(message)")
            exit(1)
        }
    }

    static func display(trusted: Int = 0, sessions: Int = 0, code: Bool = false,
                        ready: Bool = true, age: TimeInterval? = nil,
                        unavailable: Bool = false, notice: String? = nil) -> PairingDisplay {
        PairingDisplay.state(trustedCount: trusted, authenticatedSessions: sessions,
                             pairingCodePresent: code, listenerReady: ready,
                             lastTrafficAge: age, listenerUnavailable: unavailable,
                             notice: notice)
    }

    static func main() {
        let idle = display()

        // S1: Start uses the real hotspot observation. An unsupported link and
        // an unreadable list must not claim that the hotspot is off.
        check(HotspotStartMessage.message(for: .absent) == PlainMessage.noHotspot,
              "a missing hotspot keeps the turn-on line")
        check(HotspotStartMessage.message(for: .unsupported) == StopReason.hotspotUnsupported.message,
              "an unsupported link names the unsupported link")
        check(HotspotStartMessage.message(for: .unreadable) == PlainMessage.hotspotUnreadable,
              "an unreadable list names the read failure")
        check(!HotspotStartMessage.message(for: .unreadable).contains("172.20.10.1"),
              "the Start line holds no address")
        check(PlainMessage.hotspotUnreadable != PlainMessage.noHotspot,
              "an unreadable list is not a missing hotspot")

        // S4: a token problem that leaves the app with no usable token shows
        // Needs attention with the existing plain message. The token value is
        // never part of the text.
        let conflict = "Two saved tokens differ. The app cannot prove which one is current, so it kept both and uses neither. Pairing and the proxy stay off. Contact support before removing saved data."
        let tokenStatus = DashboardStatus.make(snapshotState: "Stopped", startFailure: nil,
                                               snapshotError: nil, tokenFailure: conflict,
                                               pairing: idle)
        check(tokenStatus.kind == .attention, "a token problem needs attention")
        check(tokenStatus.title == "Needs attention", "a token problem uses the attention title")
        check(tokenStatus.message == conflict, "a token problem shows the plain storage message")
        check(!tokenStatus.message.lowercased().contains("172.20.10.1"),
              "the token line holds no address")

        // A Start failure still wins, and a usable token keeps the normal off
        // state.
        let both = DashboardStatus.make(snapshotState: "Stopped",
                                        startFailure: PlainMessage.noHotspot,
                                        snapshotError: nil, tokenFailure: conflict,
                                        pairing: idle)
        check(both.message == PlainMessage.noHotspot, "a Start failure wins over a token problem")
        let healthyToken = DashboardStatus.make(snapshotState: "Stopped", startFailure: nil,
                                                snapshotError: nil, tokenFailure: nil,
                                                pairing: idle)
        check(healthyToken.kind == .off && healthyToken.title == "Off",
              "a usable token keeps the off state")

        // S5: the prompt needs a ready listener, an active app, and no answer.
        let promptID = UUID()
        check(PairingPromptPolicy.isVisible(sceneActive: true, listenerReady: true,
                                            promptID: promptID, answeredID: nil),
              "a ready listener shows the prompt")
        check(!PairingPromptPolicy.isVisible(sceneActive: true, listenerReady: false,
                                            promptID: promptID, answeredID: nil),
              "a code without a ready listener is stale")
        check(!PairingPromptPolicy.isVisible(sceneActive: false, listenerReady: true,
                                            promptID: promptID, answeredID: nil),
              "an inactive app shows no prompt")
        check(!PairingPromptPolicy.isVisible(sceneActive: true, listenerReady: true,
                                            promptID: promptID, answeredID: promptID),
              "an answered prompt does not return")
        check(!PairingPromptPolicy.isVisible(sceneActive: true, listenerReady: true,
                                            promptID: nil, answeredID: nil),
              "no prompt identifier means no prompt")
        check(display(code: true, ready: false).activity == .notPaired,
              "the display agrees that a stale code does not pair")

        // S6: a timeout, denial, or lockout line stays for 60 seconds. The text
        // holds no code, address, or device name.
        let now = Date(timeIntervalSinceReferenceDate: 1_000)
        let notice = PairingNotice(message: PairingNoticeText.expired, at: now)
        check(notice.isVisible(now: now), "a new notice is visible")
        check(notice.isVisible(now: now.addingTimeInterval(59)), "a notice is visible at 59 s")
        check(!notice.isVisible(now: now.addingTimeInterval(60)), "a notice expires at 60 s")
        check(PairingNoticeText.expired == "The pairing request expired. Start pairing again on the target device.",
              "the expired text is the plain line")
        check(PairingNoticeText.denied == "The pairing request was denied. Start pairing again on the target device.",
              "the denied text is the plain line")
        check(PairingNoticeText.lockedOut == "Pairing is paused for 30 seconds after repeated failures.",
              "the lockout text is the plain line")
        for text in [PairingNoticeText.expired, PairingNoticeText.denied, PairingNoticeText.lockedOut] {
            check(!text.contains("172.20.10.1"), "the pairing line holds no address")
            check(!text.lowercased().contains("token"), "the pairing line holds no token")
        }
        let withNotice = display(trusted: 1, notice: PairingNoticeText.expired)
        check(withNotice.notice == PairingNoticeText.expired, "the display carries the recent notice")

        // S3: an unavailable listener shows one plain line in both places. A
        // real session in use still wins, because that use is current.
        check(PairingDisplay.pairingUnavailableText ==
              "Pairing is not available. Another app may be using the pairing port. Close it and reopen HotspotShade.",
              "the unavailable line is plain")
        let unavailable = display(trusted: 2, unavailable: true)
        check(unavailable.activity == .unavailable, "an unavailable listener has its own state")
        check(unavailable.summary == PairingDisplay.pairingUnavailableText,
              "the Dashboard pairing line shows the bind failure")
        check(unavailable.settingsText == PairingDisplay.pairingUnavailableText,
              "the Settings row shows the bind failure")
        check(unavailable.settingsSymbol == "exclamationmark.triangle",
              "the Settings row uses the warning mark")
        let useWins = display(sessions: 1, age: 2, unavailable: true)
        check(useWins.activity == .inUse, "a current session wins over the unavailable line")

        // S7: the diagnostics report uses the same computed state as the
        // Dashboard and adds the plain attention line.
        let failedStatus = DashboardStatus.make(snapshotState: "Listening",
                                                startFailure: PlainMessage.hotspotUnreadable,
                                                snapshotError: "Something technical", pairing: idle)
        let failedSummary = DiagnosticsProxySummary.make(status: failedStatus)
        check(failedSummary.state == "Needs attention",
              "the diagnostics report shows the computed failure state")
        check(failedSummary.detail == PlainMessage.hotspotUnreadable,
              "the report includes the Start failure text")
        let offSummary = DiagnosticsProxySummary.make(status: DashboardStatus.make(
            snapshotState: "Stopped", startFailure: nil, snapshotError: nil, pairing: idle))
        check(offSummary.state == "Off" && offSummary.detail == nil,
              "a normal off state has no detail line")
        let paired = display(trusted: 1)
        let onSummary = DiagnosticsProxySummary.make(status: DashboardStatus.make(
            snapshotState: "Listening", startFailure: nil, snapshotError: nil, pairing: paired))
        check(onSummary.state == "On" && onSummary.detail == nil,
              "a normal on state has no detail line")
        for text in [failedSummary.state, failedSummary.detail ?? "",
                     offSummary.state, onSummary.state] {
            check(!text.contains("172.20.10.1"), "the diagnostics state holds no address")
            check(!text.lowercased().contains("token"), "the diagnostics state holds no token")
        }

        print("Source state presentation tests passed")
    }
}
