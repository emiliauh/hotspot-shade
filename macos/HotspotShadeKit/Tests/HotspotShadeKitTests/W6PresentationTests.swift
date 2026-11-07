import XCTest
@testable import HotspotShadeKit

@MainActor final class W6PresentationTests: XCTestCase {
    private func build(_ derive: DeriveInput, ping: String? = nil, connections: String? = nil, stop: String? = nil, checked: String? = nil, advice: [String] = [], denied: Bool = false, blocked: Bool = false, forgetting: Bool = false, canceling: Bool = false, cancelPending: Bool = false, startingPair: Bool = false) -> ScreenModel {
        ScreenPresentation.build(PresentationInput(derive: derive, pingLine: ping, connectionsLabel: connections, lastStopLine: stop, lastCheckedText: checked, linkAdvice: advice, notificationsDenied: denied, forgetBlocked: blocked, forgetInFlight: forgetting, pairingCancelInFlight: canceling, pairingStartInFlight: startingPair, pairingCancelRequested: cancelPending))
    }
    private func row(running: Bool = false, paired: Bool = false, phone: PhoneState = .unpaired, message: String? = nil, pairing: PairingPhase = .idle, operation: TunnelOperation? = nil, error: String? = nil, freshness: StatusFreshness = .fresh, token: String? = nil, trusted: Bool? = nil, forget: ForgetPhase = .none, warning: Bool = false, pairingFailure: String? = nil) -> DeriveInput {
        DeriveInput(running: running, paired: paired, phone: phone, phoneMessage: message, pairing: pairing, operation: operation, error: error, freshness: freshness, tokenRejected: token, trustedBySource: trusted, forget: forget, sourceDeviceWarning: warning, pairingFailure: pairingFailure)
    }

    // MARK: - One test per derive row

    func testRunningConnectedRow() {
        let model = build(row(running: true, paired: true, phone: .connected, message: "Connected."), ping: "Ping is on.")
        XCTAssertEqual(model.title, "On")
        XCTAssertEqual(model.subtitle, "Connected.")
        XCTAssertEqual(model.primaryAction, .turnOff)
        XCTAssertEqual(model.statusKind, .on)
        XCTAssertEqual(model.sourceDevice.lines, ["Paired", "Connected."])
        XCTAssertEqual(model.menuBar.icon, .on)
        XCTAssertEqual(model.menuBar.statusLine, "On")
        XCTAssertEqual(model.menuBar.actions.first { $0.kind == .turnOff }?.enabled, true)
        XCTAssertEqual(model.menuBar.actions.first { $0.kind == .turnOn }?.enabled, false)
        XCTAssertFalse(model.menuBar.actions.first { $0.kind == .turnOn }!.reason!.isEmpty)
    }
    func testRunningSourceWarningRow() {
        let model = build(row(running: true, paired: true, phone: .notResponding, warning: true))
        XCTAssertEqual(model.title, "On")
        XCTAssertEqual(model.primaryAction, .turnOff)
        XCTAssertEqual(model.statusKind, .on)
        XCTAssertTrue(model.attentionItems.contains("The source device stopped answering. New connections fail."))
    }
    func testRunningUnknownPinShowsEngineMessage() {
        let message = "The tunnel interface is unknown. Turn the tunnel off and on."
        let model = build(row(running: true, paired: true, phone: PhoneState(raw: "pin_unknown"), message: message))
        XCTAssertEqual(model.title, "On")
        XCTAssertEqual(model.primaryAction, .turnOff)
        XCTAssertEqual(model.sourceDevice.lines, ["Paired", message])
    }
    func testRunningNotTrustedRow() {
        let model = build(row(running: true, paired: true, phone: .notTrusted))
        XCTAssertEqual(model.title, "On")
        XCTAssertEqual(model.primaryAction, .turnOff)
        XCTAssertEqual(model.statusKind, .on)
        XCTAssertTrue(model.attentionItems.contains("The source device forgot this target device. The tunnel keeps running until you turn it off."))
    }
    func testUnpairedRow() {
        let model = build(row())
        XCTAssertEqual(model.title, "Not paired")
        XCTAssertEqual(model.subtitle, "Pair with your source device to use it.")
        XCTAssertEqual(model.primaryAction, .pair)
        XCTAssertEqual(model.statusKind, .off)
        XCTAssertEqual(model.sourceDevice.lines.first, "Not paired")
    }
    func testTrustedBySourceRow() {
        let model = build(row(trusted: true))
        XCTAssertEqual(model.title, "Not paired")
        XCTAssertEqual(model.subtitle, "The source device still knows this target device. Press Pair to continue.")
        XCTAssertEqual(model.primaryAction, .pair)
    }
    func testForgetPendingRow() {
        let model = build(row(forget: .pending))
        XCTAssertEqual(model.title, "Not paired")
        XCTAssertEqual(model.subtitle, "Forgetting...")
        XCTAssertEqual(model.primaryAction, .pair)
        XCTAssertEqual(model.statusKind, .off)
    }
    func testForgetConfirmedRow() {
        let model = build(row(forget: .confirmed))
        XCTAssertEqual(model.subtitle, "Could not confirm that the source device removed this pairing. This target device forgot the pairing, but the source device may still trust it.")
        XCTAssertEqual(model.primaryAction, .pair)
    }
    func testForgetNotDeliveredRow() {
        let model = build(row(forget: .notDelivered))
        XCTAssertEqual(model.subtitle, "Could not confirm that the source device removed this pairing. This target device forgot the pairing, but the source device may still trust it.")
        XCTAssertEqual(model.primaryAction, .pair)
    }
    func testNotTrustedPairedRow() {
        let model = build(row(paired: true, phone: .notTrusted))
        XCTAssertEqual(model.title, "Not trusted")
        XCTAssertEqual(model.subtitle, "The source device does not know this target device.")
        XCTAssertEqual(model.primaryAction, .pairAgain)
        XCTAssertEqual(model.secondaryAction, .forget)
        XCTAssertEqual(model.statusKind, .off)
    }
    func testNeedsSourceDeviceRows() {
        for phone in [PhoneState.notResponding, .notRunning, .noHotspot] {
            let model = build(row(paired: true, phone: phone))
            XCTAssertEqual(model.title, "Waiting for your source device", "\(phone)")
            XCTAssertNil(model.primaryAction, "\(phone)")
            XCTAssertEqual(model.statusKind, .off)
        }
    }
    func testProxyOffRow() {
        let model = build(row(paired: true, phone: .proxyOff))
        XCTAssertEqual(model.title, "Paired")
        XCTAssertEqual(model.subtitle, "Start the proxy on your source device.")
        XCTAssertNil(model.primaryAction)
        XCTAssertEqual(model.statusKind, .off)
    }
    func testReadyRow() {
        let model = build(row(paired: true, phone: .ready))
        XCTAssertEqual(model.title, "Ready")
        XCTAssertEqual(model.subtitle, "The source device is ready.")
        XCTAssertEqual(model.primaryAction, .turnOn)
        XCTAssertEqual(model.statusKind, .off)
        XCTAssertEqual(model.menuBar.actions.first { $0.kind == .turnOn }?.enabled, true)
    }
    func testConnectedWithoutRunningRow() {
        let model = build(row(paired: true, phone: .connected))
        XCTAssertEqual(model.title, "Ready")
        XCTAssertEqual(model.primaryAction, .turnOn)
    }
    func testUnknownRow() {
        let model = build(row(paired: true, phone: .unknown, message: "A new status."))
        XCTAssertEqual(model.title, "Status unavailable")
        XCTAssertEqual(model.subtitle, "A new status.")
        XCTAssertNil(model.primaryAction)
        XCTAssertEqual(model.statusKind, .attention)
    }
    func testErrorRow() {
        let model = build(row(error: "Problem"))
        XCTAssertEqual(model.title, "Needs attention")
        XCTAssertEqual(model.subtitle, "Problem")
        XCTAssertEqual(model.primaryAction, .retry)
        XCTAssertEqual(model.statusKind, .attention)
        XCTAssertNil(model.secondaryAction)
    }
    func testStartingRow() {
        let model = build(row(paired: true, phone: .ready, operation: .starting))
        XCTAssertEqual(model.title, "Starting the tunnel")
        XCTAssertEqual(model.subtitle, "This can take a minute.")
        XCTAssertNil(model.primaryAction)
        XCTAssertEqual(model.statusKind, .busy)
        XCTAssertEqual(model.menuBar.icon, .busy)
        XCTAssertFalse(model.menuBar.actions.first { $0.kind == .turnOn }!.enabled)
    }
    func testStoppingRow() {
        let model = build(row(running: true, paired: true, phone: .connected, operation: .stopping))
        XCTAssertEqual(model.title, "Turning off")
        XCTAssertNil(model.primaryAction)
        XCTAssertEqual(model.statusKind, .busy)
    }
    func testPairingRow() {
        let model = build(row(pairing: .starting))
        XCTAssertEqual(model.title, "Pairing")
        XCTAssertEqual(model.subtitle, "Connecting to your source device.")
        XCTAssertNil(model.primaryAction)
        XCTAssertEqual(model.statusKind, .pairing)
        XCTAssertEqual(model.menuBar.actions.first { $0.kind == .cancel }?.enabled, true)
    }
    func testPairingAgainAfterTrustFailureRow() {
        let model = build(row(paired: true, phone: .notTrusted, pairing: .starting))
        XCTAssertEqual(model.title, "Pairing")
        XCTAssertEqual(model.statusKind, .pairing)
    }
    // A paired phase from the last pairing is stale after a trust loss. The
    // menu must not disable Pair.
    func testStalePairedPhaseAfterTrustLossAllowsPair() {
        let model = build(row(paired: true, phone: .notTrusted, pairing: .paired))
        let pair = model.menuBar.actions.first { $0.kind == .pair }
        XCTAssertEqual(pair?.enabled, true)
        XCTAssertNil(pair?.reason)
    }
    // The same row after a forget: the target device has no pairing.
    func testStalePairedPhaseAfterForgetAllowsPair() {
        let model = build(row(paired: false, phone: .unpaired, pairing: .paired, forget: .confirmed))
        let pair = model.menuBar.actions.first { $0.kind == .pair }
        XCTAssertEqual(pair?.enabled, true)
        XCTAssertNil(pair?.reason)
    }
    // The failed pairing view goes away, so the calm Not paired screen shows
    // why the attempt stopped.
    func testPairingFailureRow() {
        let failure = "The pairing code does not match."
        let model = build(row(pairing: .failed, pairingFailure: failure))
        XCTAssertEqual(model.title, "Not paired")
        XCTAssertEqual(model.subtitle, failure)
        XCTAssertEqual(model.primaryAction, .pair)
        XCTAssertFalse(model.attentionItems.contains(failure))
    }
    // A failed re-pair from a paired, ready target keeps its Ready card but
    // the failure stays visible in the attention list.
    func testPairingFailureOnReadyRowGoesToAttention() {
        let failure = "The pairing code does not match."
        let model = build(row(paired: true, phone: .ready, pairing: .failed, pairingFailure: failure))
        XCTAssertEqual(model.title, "Ready")
        XCTAssertTrue(model.attentionItems.contains(failure))
        XCTAssertEqual(model.primaryAction, .turnOn)
    }
    func testTokenRejectedRow() {
        let text = "The source device changed its token. Open HotspotShade on your source device, then pair again."
        let model = build(row(paired: true, phone: .ready, token: text))
        XCTAssertEqual(model.title, "Pair again")
        XCTAssertEqual(model.subtitle, text)
        XCTAssertEqual(model.primaryAction, .pairAgain)
        XCTAssertEqual(model.statusKind, .attention)
    }
    func testStaleRowKeepsTheLastScreen() {
        let model = build(row(running: true, paired: true, phone: .connected, freshness: .stale))
        XCTAssertEqual(model.title, "On")
        XCTAssertEqual(model.primaryAction, .turnOff)
        XCTAssertEqual(model.secondaryAction, .checkNow)
        XCTAssertEqual(model.statusKind, .on)
        XCTAssertTrue(model.attentionItems.contains(Strings.staleStatus))
    }
    func testUnavailableRowDoesNotClaimOnOrOff() {
        let model = build(row(running: true, paired: true, phone: .connected, freshness: .unavailable), ping: "Ping is on.", connections: "The source device reports 2 active connections.")
        XCTAssertEqual(model.title, "Status unavailable")
        XCTAssertEqual(model.subtitle, Strings.statusUnavailableSubtitle)
        XCTAssertEqual(model.primaryAction, .checkNow)
        XCTAssertNil(model.secondaryAction)
        XCTAssertEqual(model.statusKind, .attention)
        XCTAssertEqual(model.menuBar.icon, .attention)
        XCTAssertEqual(model.connection.lines, [])
        XCTAssertEqual(model.sourceDevice.lines, [])
        XCTAssertEqual(model.menuBar.actions.first { $0.kind == .turnOn }?.reason, Strings.statusUnavailableSubtitle)
    }
    func testForgetBlockedRow() {
        let model = build(row(running: true, paired: true, phone: .connected), blocked: true)
        XCTAssertEqual(model.title, "On")
        XCTAssertEqual(model.primaryAction, .turnOff)
        XCTAssertEqual(model.secondaryAction, .turnOffAndForget)
        XCTAssertEqual(model.statusKind, .on)
        XCTAssertTrue(model.attentionItems.first == "Turn off the tunnel to forget this source device.")
    }
    // A refused Forget is live only while the tunnel still runs on a fresh
    // status. An old block must not offer a stop, and an off screen falls
    // through to the normal Forget action.
    func testForgetBlockedNeedsALiveRunningStatus() {
        let unavailable = build(row(running: true, paired: true, phone: .connected, freshness: .unavailable), blocked: true)
        XCTAssertNil(unavailable.secondaryAction)
        XCTAssertFalse(unavailable.attentionItems.contains(Strings.forgetBlocked))

        let stale = build(row(running: true, paired: true, phone: .connected, freshness: .stale), blocked: true)
        XCTAssertEqual(stale.secondaryAction, .checkNow)
        XCTAssertFalse(stale.attentionItems.contains(Strings.forgetBlocked))

        let off = build(row(paired: true, phone: .ready), blocked: true)
        XCTAssertEqual(off.secondaryAction, .forget)
        XCTAssertFalse(off.attentionItems.contains(Strings.forgetBlocked))
    }
    // A completed pairing keeps Pair disabled. The grayed row says why.
    func testPairReasonWhenTheTargetDeviceIsAlreadyPaired() {
        let model = build(row(paired: true, phone: .ready, pairing: .paired))
        let pair = model.menuBar.actions.first { $0.kind == .pair }
        XCTAssertEqual(pair?.enabled, false)
        XCTAssertEqual(pair?.reason, Strings.alreadyPaired)
    }
    // The unknown row uses the stale line as its subtitle. The attention list
    // must not repeat the same sentence.
    func testStaleAttentionDoesNotRepeatTheSubtitle() {
        let model = build(row(paired: true, phone: .unknown, message: Strings.staleStatus, freshness: .stale))
        XCTAssertEqual(model.subtitle, Strings.staleStatus)
        XCTAssertFalse(model.attentionItems.contains(Strings.staleStatus))
    }
    func testNotificationsDeniedRow() {
        let model = build(row(paired: true, phone: .ready), denied: true)
        XCTAssertTrue(model.attentionItems.contains("Notifications are off. You will not see a message when the tunnel turns off."))
    }
    func testLinkAdviceRow() {
        let slow = "This connection uses 2.4 GHz Wi-Fi, which is slower and less steady. On your source device, turn off Maximize Compatibility in the Personal Hotspot settings, or use a cable."
        let weak = "The Wi-Fi signal is weak. Move the target device closer to the source device."
        let model = build(row(running: true, paired: true, phone: .connected), advice: [slow, weak])
        XCTAssertEqual(model.attentionItems, [slow, weak])
    }

    // MARK: - Cards

    func testConnectionCardCarriesEveryField() {
        let model = build(row(running: true, paired: true, phone: .connected), ping: "Ping is on.", connections: "The source device reports 3 active connections.", stop: "Last stop: The hotspot turned off.", checked: "Checked just now")
        XCTAssertEqual(model.connection.ping, "Ping is on.")
        XCTAssertEqual(model.connection.activeConnections, "The source device reports 3 active connections.")
        XCTAssertEqual(model.connection.lastStop, "Last stop: The hotspot turned off.")
        XCTAssertEqual(model.connection.lastChecked, "Checked just now")
        XCTAssertEqual(model.connection.lines.count, 4)
    }
    func testSourceDeviceCardHoldsThePairLineAndMessage() {
        let model = build(row(paired: true, phone: .proxyOff, message: "Start the proxy."))
        XCTAssertEqual(model.sourceDevice.lines, ["Paired", "Start the proxy."])
    }

    // MARK: - Menu

    func testMenuHasEveryActionAndAReasonWhenDisabled() {
        let inputs: [DeriveInput] = [
            row(),
            row(paired: true, phone: .ready),
            row(running: true, paired: true, phone: .connected),
            row(pairing: .starting),
            row(paired: true, phone: .ready, operation: .starting),
            row(freshness: .unavailable),
        ]
        var busyInputs: [ScreenModel] = [
            build(row(pairing: .starting), forgetting: true),
            build(row(pairing: .starting), canceling: true),
            build(row(pairing: .starting), cancelPending: true),
            build(row(), startingPair: true),
        ]
        busyInputs.append(contentsOf: inputs.map { build($0) })
        for model in busyInputs {
            let menu = model.menuBar
            XCTAssertEqual(menu.actions.count, 7)
            XCTAssertEqual(Set(menu.actions.map(\.kind)), Set([.turnOn, .turnOff, .pair, .cancel, .open, .checkNow, .quit]))
            for action in menu.actions where !action.enabled {
                XCTAssertFalse((action.reason ?? "").isEmpty, "\(action.kind)")
            }
            XCTAssertEqual(menu.actions.first { $0.kind == .open }?.enabled, true)
            XCTAssertEqual(menu.actions.first { $0.kind == .checkNow }?.enabled, true)
            XCTAssertEqual(menu.actions.first { $0.kind == .quit }?.enabled, true)
        }
    }
    func testMenuDisablesPairWhileTheTunnelRuns() {
        let menu = build(row(running: true, paired: true, phone: .connected)).menuBar
        let pair = menu.actions.first { $0.kind == .pair }!
        XCTAssertFalse(pair.enabled)
        XCTAssertEqual(pair.reason, "Turn off the tunnel first.")
        XCTAssertFalse(menu.actions.first { $0.kind == .cancel }!.enabled)
        XCTAssertEqual(menu.actions.first { $0.kind == .cancel }!.reason, "Pairing is not running.")
    }
    func testMenuEnablesTurnOffOnlyWhileRunning() {
        XCTAssertEqual(build(row(running: true, paired: true, phone: .connected)).menuBar.actions.first { $0.kind == .turnOff }?.enabled, true)
        XCTAssertEqual(build(row(paired: true, phone: .ready)).menuBar.actions.first { $0.kind == .turnOff }?.enabled, false)
    }
    func testMenuEnablesPairWhenOffAndNotPairing() {
        XCTAssertEqual(build(row()).menuBar.actions.first { $0.kind == .pair }?.enabled, true)
        XCTAssertEqual(build(row(pairing: .confirming)).menuBar.actions.first { $0.kind == .pair }?.enabled, false)
    }
    // A Forget owns the engine. The main action and the secondary Forget must
    // not look usable, and the Pair menu row explains the wait.
    func testForgetBusyStateIsVisibleAndDisablesActions() {
        let model = build(row(paired: true, phone: .ready), forgetting: true)
        XCTAssertNil(model.primaryAction)
        XCTAssertNil(model.secondaryAction)
        XCTAssertEqual(model.subtitle, Strings.forgetPending)
        XCTAssertEqual(model.statusKind, .busy)
        let pair = model.menuBar.actions.first { $0.kind == .pair }
        XCTAssertEqual(pair?.enabled, false)
        XCTAssertEqual(pair?.reason, AppModelActionText.waitForAction)
    }
    // The Cancel row stays visible while the cancel request runs, but it is
    // disabled and explains the busy state. Pair waits for the engine.
    func testCancelBusyStateIsVisibleAndDisablesCancelAndPair() {
        let model = build(row(pairing: .starting), canceling: true)
        XCTAssertNil(model.primaryAction)
        XCTAssertEqual(model.subtitle, AppModelActionText.cancelingPairing)
        XCTAssertEqual(model.statusKind, .busy)
        let cancel = model.menuBar.actions.first { $0.kind == .cancel }
        XCTAssertEqual(cancel?.enabled, false)
        XCTAssertEqual(cancel?.reason, AppModelActionText.cancelingPairing)
        XCTAssertEqual(model.menuBar.actions.first { $0.kind == .pair }?.enabled, false)
    }
    // A Cancel press during the start request is recorded at once. The row
    // stays usable, so a lost request does not leave the engine busy without
    // a way to send the cancel again.
    func testCancelRequestedDuringStartStaysVisible() {
        let model = build(row(), cancelPending: true)
        let cancel = model.menuBar.actions.first { $0.kind == .cancel }
        XCTAssertNotNil(cancel)
        XCTAssertEqual(cancel?.enabled, true)
        XCTAssertNil(cancel?.reason)
        XCTAssertEqual(model.menuBar.actions.first { $0.kind == .pair }?.enabled, false)
    }

    // MARK: - Table

    func testEveryStateHasOneTitleOneSubtitleAndAtMostOnePrimaryAction() {
        let inputs: [DeriveInput] = [
            row(running: true, paired: true, phone: .connected),
            row(running: true, paired: true, phone: .notResponding, warning: true),
            row(running: true, paired: true, phone: .notTrusted),
            row(running: true, paired: true, phone: .ready),
            row(),
            row(paired: true, phone: .unpaired),
            row(paired: true, phone: .notTrusted),
            row(paired: true, phone: .proxyOff),
            row(paired: true, phone: .ready),
            row(paired: true, phone: .connected),
            row(paired: true, phone: .notResponding),
            row(paired: false, phone: .notResponding),
            row(paired: false, phone: .notRunning),
            row(paired: false, phone: .noHotspot),
            row(paired: true, phone: .unknown),
            row(phone: .unknown),
            row(pairing: .starting),
            row(pairing: .confirming),
            row(pairing: .failed),
            row(paired: true, phone: .notTrusted, pairing: .confirming),
            row(paired: true, phone: .ready, operation: .starting),
            row(running: true, paired: true, phone: .connected, operation: .stopping),
            row(error: "Problem"),
            row(error: "Problem", freshness: .stale),
            row(freshness: .stale),
            row(freshness: .unavailable),
            row(paired: true, phone: .ready, token: "Pair again text"),
            row(trusted: true),
            row(forget: .pending),
            row(forget: .confirmed),
            row(forget: .notDelivered),
            row(running: true, paired: true, phone: .connected),
        ]
        for input in inputs {
            let model = build(input)
            XCTAssertFalse(model.title.isEmpty)
            XCTAssertFalse(model.subtitle.isEmpty)
            let count = [model.primaryAction].compactMap { $0 }.count
            XCTAssertLessThanOrEqual(count, 1)
            XCTAssertFalse(model.menuBar.statusLine.isEmpty)
            XCTAssertEqual(model.menuBar.actions.count, 7)
        }
    }
    func testEveryPrimaryActionHasALabel() {
        for action in [ScreenModel.Action.pair, .pairAgain, .turnOn, .turnOff, .retry, .checkNow, .turnOffAndForget, .forget] {
            XCTAssertFalse(action.label.isEmpty)
        }
    }
}
