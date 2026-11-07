import XCTest
@testable import HotspotShadeKit

@MainActor final class W6M2UITests: XCTestCase {
    // MARK: - Menu content

    func testEveryScenarioHasAStableMenu() {
        for scenario in PreviewScenario.allCases {
            let model = PreviewData.model(scenario)
            let content = MenuBarContentBuilder.build(model)
            XCTAssertEqual(content.iconSymbol, MenuSymbols.icon(for: model.menuBar.icon), scenario.rawValue)
            XCTAssertEqual(content.stateWord, model.title, scenario.rawValue)
            XCTAssertEqual(content.header.title, model.title, scenario.rawValue)
            XCTAssertFalse(content.header.isEnabled, scenario.rawValue)
            XCTAssertFalse(content.detail.isEnabled, scenario.rawValue)
            XCTAssertEqual(content.header.symbol, content.iconSymbol, scenario.rawValue)

            let toggles = content.actions.filter { $0.kind == .turnOn || $0.kind == .turnOff }
            XCTAssertEqual(toggles.count, 1, scenario.rawValue)
            XCTAssertTrue(content.actions.contains { $0.kind == .pair }, scenario.rawValue)
            XCTAssertTrue(content.actions.contains { $0.kind == .cancel }, scenario.rawValue)
            XCTAssertTrue(content.actions.contains { $0.kind == .checkNow }, scenario.rawValue)
            XCTAssertEqual(content.actions.last?.kind, .checkNow, scenario.rawValue)
            XCTAssertEqual(content.open.kind, .open, scenario.rawValue)
            XCTAssertEqual(content.settings.kind, .settings, scenario.rawValue)
            XCTAssertEqual(content.quit.kind, .quit, scenario.rawValue)
            XCTAssertLessThanOrEqual(content.notices.count, MenuBarContentBuilder.maxNotices, scenario.rawValue)
        }
    }

    func testMenuIconFollowsTheModel() {
        let cases: [(PreviewScenario, ScreenModel.MenuBar.Icon, String)] = [
            (.unpaired, .off, "network.slash"),
            (.on, .on, "network"),
            (.unknown, .attention, "exclamationmark.triangle"),
            (.starting, .busy, "hourglass"),
        ]
        for (scenario, icon, symbol) in cases {
            XCTAssertEqual(PreviewData.model(scenario).menuBar.icon, icon, scenario.rawValue)
            XCTAssertEqual(MenuBarContentBuilder.build(PreviewData.model(scenario)).iconSymbol, symbol, scenario.rawValue)
        }
    }

    func testMenuShortcuts() {
        let on = MenuBarContentBuilder.build(PreviewData.model(.on))
        XCTAssertEqual(on.actions.first { $0.kind == .turnOff }?.shortcut, .commandReturn)
        XCTAssertEqual(on.actions.first { $0.kind == .checkNow }?.shortcut, .commandR)
        XCTAssertEqual(on.settings.shortcut, .commandComma)
        XCTAssertEqual(on.quit.shortcut, .commandQ)

        let ready = MenuBarContentBuilder.build(PreviewData.model(.ready))
        XCTAssertEqual(ready.actions.first { $0.kind == .turnOn }?.shortcut, .commandReturn)
        XCTAssertNil(ready.actions.first { $0.kind == .turnOff }?.shortcut)

        // A disabled toggle has no shortcut.
        let starting = MenuBarContentBuilder.build(PreviewData.model(.starting))
        let toggle = starting.actions.first { $0.kind == .turnOn || $0.kind == .turnOff }
        XCTAssertEqual(toggle?.isEnabled, false)
        XCTAssertNil(toggle?.shortcut)
    }

    func testEveryDisabledActionHasAReason() {
        for scenario in PreviewScenario.allCases {
            for quitting in [false, true] {
                let content = MenuBarContentBuilder.build(PreviewData.model(scenario), quitting: quitting)
                for item in content.allItems where item.kind.isAction && !item.isEnabled {
                    XCTAssertEqual(item.help?.isEmpty, false, "\(scenario.rawValue) \(item.kind) \(quitting)")
                }
            }
        }
        let starting = MenuBarContentBuilder.starting()
        for item in starting.allItems where item.kind.isAction && !item.isEnabled {
            XCTAssertEqual(item.help?.isEmpty, false, "\(item.kind)")
        }
    }

    func testQuittingMenuShowsTheStopWait() {
        let content = MenuBarContentBuilder.build(PreviewData.model(.on), quitting: true)
        XCTAssertEqual(content.quit.title, UIStrings.turningOff)
        XCTAssertFalse(content.quit.isEnabled)
        XCTAssertEqual(content.quit.help, UIStrings.turningOffNote)
        XCTAssertEqual(content.quit.shortcut, .commandQ)
        // The status still comes from the model.
        XCTAssertEqual(content.header.title, Strings.on)
    }

    func testNoticesTakeTheFirstThreeAttentionLines() {
        var input = PreviewData.input(.on)
        input.linkAdvice = ["First advice.", "Second advice.", "Third advice."]
        input.derive.freshness = .stale
        input.notificationsDenied = true
        let model = ScreenPresentation.build(input)
        let content = MenuBarContentBuilder.build(model)
        XCTAssertEqual(content.notices.count, 3)
        XCTAssertEqual(content.notices.map(\.title), Array(model.attentionItems.prefix(3)))
        XCTAssertTrue(content.notices.allSatisfy { !$0.isEnabled })
        XCTAssertTrue(content.notices.allSatisfy { $0.symbol?.isEmpty == false })
    }

    func testLastStopIsANotice() {
        var input = PreviewData.input(.ready)
        input.lastStopLine = "Last stop: The hotspot turned off."
        let model = ScreenPresentation.build(input)
        let content = MenuBarContentBuilder.build(model)
        XCTAssertEqual(content.notices.map(\.title), ["Last stop: The hotspot turned off."])
        XCTAssertEqual(content.notices.first?.symbol, "exclamationmark.triangle")
    }

    // MARK: - Formatting

    func testPairingCodeGrouping() {
        XCTAssertEqual(PairingCodeFormat.grouped("123456"), "123 456")
        XCTAssertEqual(PairingCodeFormat.grouped("12345"), "123 45")
        XCTAssertEqual(PairingCodeFormat.grouped("123"), "123")
        XCTAssertEqual(PairingCodeFormat.grouped("12"), "12")
        XCTAssertEqual(PairingCodeFormat.grouped(" 123 456 "), "123 456")
        XCTAssertEqual(PairingCodeFormat.grouped(""), "")
        XCTAssertEqual(PairingCodeFormat.grouped(nil), "")
        XCTAssertEqual(PairingCodeFormat.grouped("12-34-56"), "123 456")
    }

    func testFailureTableSortsCountAsANumber() {
        let rows = PreviewData.failureTableRows()
        XCTAssertEqual(rows.map(\.count), [9, 3, 2])
        let ascending = FailureTable.sorted(rows, by: .count, ascending: true)
        XCTAssertEqual(ascending.map(\.count), [2, 3, 9])
        let descending = FailureTable.sorted(rows, by: .count, ascending: false)
        XCTAssertEqual(descending.map(\.count), [9, 3, 2])

        let custom = [
            FailureTableRow(id: "a", count: 9, kind: "TCP", target: "a.example", reason: "Failed", summary: "", detail: ""),
            FailureTableRow(id: "b", count: 10, kind: "UDP", target: "b.example", reason: "Refused", summary: "", detail: ""),
            FailureTableRow(id: "c", count: 2, kind: "DNS", target: "c.example", reason: "Timed out", summary: "", detail: ""),
        ]
        XCTAssertEqual(FailureTable.sorted(custom, by: .count, ascending: true).map(\.count), [2, 9, 10])
        XCTAssertEqual(FailureTable.sorted(custom, by: .count, ascending: false).map(\.count), [10, 9, 2])
    }

    func testFailureTableSortsTextColumns() {
        let rows = [
            FailureTableRow(id: "a", count: 1, kind: "UDP", target: "z.example", stage: "Source connection", reason: "Refused", summary: "", detail: ""),
            FailureTableRow(id: "b", count: 1, kind: "DNS", target: "a.example", stage: "Destination request", reason: "No answer in time", summary: "", detail: ""),
            FailureTableRow(id: "c", count: 1, kind: "TCP", target: "m.example", stage: "Greeting", reason: "Blocked", summary: "", detail: ""),
        ]
        XCTAssertEqual(FailureTable.sorted(rows, by: .kind, ascending: true).map(\.kind), ["DNS", "TCP", "UDP"])
        XCTAssertEqual(FailureTable.sorted(rows, by: .target, ascending: true).map(\.target), ["a.example", "m.example", "z.example"])
        XCTAssertEqual(FailureTable.sorted(rows, by: .stage, ascending: true).map(\.stage), ["Destination request", "Greeting", "Source connection"])
        XCTAssertEqual(FailureTable.sorted(rows, by: .reason, ascending: true).map(\.reason), ["Blocked", "No answer in time", "Refused"])
        XCTAssertEqual(FailureTable.sorted(rows, by: .kind, ascending: false).map(\.kind), ["UDP", "TCP", "DNS"])
    }

    func testFailureRowsCarryTheTableColumns() {
        let rows = PreviewData.failureRows()
        XCTAssertEqual(rows.count, 3)
        XCTAssertEqual(rows.first?.count, 9)
        XCTAssertEqual(rows.first?.kind, "Web")
        XCTAssertEqual(rows.first?.target, "example.com")
        XCTAssertEqual(rows.first?.phase, "Destination request")
        XCTAssertEqual(rows.first?.reason, "No answer in time")
        XCTAssertEqual(FailureTable.rows(from: rows).map(\.id), rows.map(\.id))
        XCTAssertEqual(FailureTable.rows(from: rows).map(\.stage), rows.map(\.phase))
    }

    // MARK: - Accessibility

    func testAccessibilityLabels() {
        let status = AccessibilityText.status(kind: .on, title: Strings.on, subtitle: Strings.onSubtitle)
        XCTAssertTrue(status.contains(Strings.on))
        XCTAssertTrue(status.contains(Strings.onSubtitle))

        let detailed = AccessibilityText.status(kind: .on, title: Strings.on, subtitle: Strings.onSubtitle, checkedText: Strings.checkedJustNow)
        XCTAssertTrue(detailed.contains(Strings.checkedJustNow))

        let card = AccessibilityText.card(title: "Connection", lines: ["Ping is on.", "Last stop: none."])
        XCTAssertEqual(card, "Connection. Ping is on. Last stop: none.")

        let attention = AccessibilityText.attention(["One.", "Two."])
        XCTAssertTrue(attention.hasPrefix(UIStrings.needsAttention))
        XCTAssertTrue(attention.contains("One."))

        XCTAssertEqual(AccessibilityText.code("123 456"), "Pairing code 123 456")
        XCTAssertEqual(AccessibilityText.code(nil), UIStrings.pairingCodeLabel)
        XCTAssertEqual(AccessibilityText.menuStatus(title: "On", detail: "The tunnel is on."), "On. The tunnel is on.")
    }

    // The failure table has one plain text for each state. An unavailable
    // status never claims that the tunnel is off, and Refresh stays off.
    func testFailureTableUnavailableAndStaleText() {
        XCTAssertEqual(
            FailuresViewText.placeholder(state: .idle, tunnelRunning: false, unavailable: true, stale: false, recoveryBlocked: false, serviceStateUnknown: false),
            UIStrings.statusUnavailableLine
        )
        XCTAssertFalse(
            FailuresViewText.refreshEnabled(state: .idle, tunnelRunning: false, unavailable: true, recoveryBlocked: false)
        )
        XCTAssertEqual(
            FailuresViewText.placeholder(state: .idle, tunnelRunning: false, unavailable: false, stale: true, recoveryBlocked: false, serviceStateUnknown: false),
            Strings.staleStatus
        )
        XCTAssertEqual(
            FailuresViewText.placeholder(state: .idle, tunnelRunning: false, unavailable: false, stale: false, recoveryBlocked: false, serviceStateUnknown: false),
            Strings.failuresTunnelOff
        )
        XCTAssertEqual(
            FailuresViewText.placeholder(state: .empty, tunnelRunning: true, unavailable: false, stale: false, recoveryBlocked: false, serviceStateUnknown: false),
            Strings.noFailures
        )
        XCTAssertEqual(
            FailuresViewText.placeholder(state: .loading, tunnelRunning: true, unavailable: false, stale: false, recoveryBlocked: false, serviceStateUnknown: false),
            nil
        )
        XCTAssertTrue(
            FailuresViewText.refreshEnabled(state: .empty, tunnelRunning: true, unavailable: false, recoveryBlocked: false)
        )
    }

    // MARK: - Screen mapping

    func testEveryScreenMapsToTwoCards() {
        for scenario in PreviewScenario.allCases {
            let input = PreviewData.input(scenario)
            let model = PreviewData.model(scenario)
            let content = DashboardContent.build(model, linkAdvice: input.linkAdvice)
            XCTAssertEqual(content.sourceDevice.title, UIStrings.sourceDevice, scenario.rawValue)
            XCTAssertEqual(content.connection.title, UIStrings.connection, scenario.rawValue)
            XCTAssertFalse(content.sourceDevice.lines.isEmpty, scenario.rawValue)
            XCTAssertFalse(content.connection.lines.isEmpty, scenario.rawValue)
            XCTAssertEqual(content.attention, model.attentionItems, scenario.rawValue)
            XCTAssertEqual(content.title, model.title, scenario.rawValue)
            XCTAssertEqual(content.primaryAction, model.primaryAction, scenario.rawValue)
            XCTAssertEqual(content.statusKind, model.statusKind, scenario.rawValue)
        }
    }

    func testUnavailableScreenShowsTheUnavailableLine() {
        let content = DashboardContent.build(PreviewData.model(.unknown))
        XCTAssertEqual(content.sourceDevice.value, UIStrings.statusUnavailableLine)
        XCTAssertEqual(content.sourceDevice.details, [UIStrings.checkStatusAgain])
        XCTAssertEqual(content.connection.value, UIStrings.statusUnavailableLine)
        XCTAssertEqual(content.connection.details, [UIStrings.checkStatusAgain])
    }

    // The source card uses the same state as the header. It must not say
    // Paired while the header says Not trusted.
    func testSourceCardValueMatchesTheHeaderState() {
        let notTrusted = DashboardContent.build(PreviewData.model(.notTrusted))
        XCTAssertEqual(notTrusted.sourceDevice.value, Strings.notTrustedTitle)
        XCTAssertEqual(notTrusted.sourceDevice.value, notTrusted.title)
        XCTAssertEqual(notTrusted.sourceDevice.details, [UIStrings.pairToRestoreTrust])

        XCTAssertEqual(DashboardContent.build(PreviewData.model(.unpaired)).sourceDevice.value, Strings.notPaired)
        XCTAssertEqual(DashboardContent.build(PreviewData.model(.afterForget)).sourceDevice.value, Strings.notPaired)
        XCTAssertEqual(DashboardContent.build(PreviewData.model(.ready)).sourceDevice.value, Strings.paired)
        XCTAssertEqual(DashboardContent.build(PreviewData.model(.on)).sourceDevice.value, Strings.paired)
    }

    func testCardDetailsDoNotRepeatTheHeaderSubtitle() {
        for scenario in PreviewScenario.allCases {
            let model = PreviewData.model(scenario)
            let content = DashboardContent.build(model, linkAdvice: PreviewData.input(scenario).linkAdvice)
            for line in content.sourceDevice.details + content.connection.details {
                XCTAssertNotEqual(line, model.subtitle, scenario.rawValue)
            }
            if let checked = model.connection.lastChecked {
                XCTAssertFalse(content.connection.details.contains(checked), scenario.rawValue)
            }
        }
    }

    func testConnectionCardValueFollowsTheTunnelState() {
        XCTAssertEqual(DashboardContent.build(PreviewData.model(.on)).connection.value, UIStrings.tunnelOn)
        XCTAssertEqual(DashboardContent.build(PreviewData.model(.ready)).connection.value, UIStrings.tunnelOff)
        XCTAssertEqual(DashboardContent.build(PreviewData.model(.unpaired)).connection.value, UIStrings.tunnelOff)
        XCTAssertEqual(DashboardContent.build(PreviewData.model(.starting)).connection.value, UIStrings.connectionStarting)
        XCTAssertEqual(DashboardContent.build(PreviewData.model(.turningOff)).connection.value, Strings.stopping)
        XCTAssertEqual(DashboardContent.build(PreviewData.model(.unknown)).connection.value, UIStrings.statusUnavailableLine)
    }

    func testConnectionCardShowsRealFacts() {
        let on = DashboardContent.build(PreviewData.model(.on))
        XCTAssertTrue(on.connection.details.contains(Strings.pingOn))
        XCTAssertTrue(on.connection.details.contains(Strings.connections(3)))

        let stop = DashboardContent.build(PreviewData.model(.onStale))
        XCTAssertTrue(stop.connection.details.contains("Last stop: The hotspot turned off."))

        let ready = DashboardContent.build(PreviewData.model(.ready))
        XCTAssertEqual(ready.connection.details, [UIStrings.noConnectionYet])
    }

    func testStatusDotPromotesNotTrustedToAttention() {
        XCTAssertEqual(StatusAppearance.kind(title: Strings.notTrustedTitle, kind: .off), .attention)
        XCTAssertEqual(StatusAppearance.kind(title: Strings.on, kind: .on), .on)
        XCTAssertEqual(StatusAppearance.kind(title: Strings.ready, kind: .off), .off)
        XCTAssertEqual(StatusAppearance.kind(for: PreviewData.model(.notTrusted)), .attention)
        XCTAssertEqual(StatusAppearance.kind(for: PreviewData.model(.on)), .on)
    }

    func testSettingsPairingStateFollowsTheScreen() {
        XCTAssertEqual(SettingsPairingText.state(.notTrusted, paired: true, unavailable: false), Strings.notTrustedTitle)
        XCTAssertEqual(SettingsPairingText.state(.unpaired, paired: false, unavailable: false), Strings.notPaired)
        XCTAssertEqual(SettingsPairingText.state(.on, paired: true, unavailable: false), Strings.paired)
        XCTAssertEqual(SettingsPairingText.state(.ready, paired: true, unavailable: false), Strings.paired)
        XCTAssertEqual(SettingsPairingText.state(.ready, paired: true, unavailable: true), UIStrings.statusUnavailableLine)
        XCTAssertEqual(SettingsPairingText.symbol(.notTrusted, paired: true, unavailable: false), "exclamationmark.triangle")
    }

    func testConnectionCardAddsLinkAdvice() {
        let input = PreviewData.input(.onLinkAdvice)
        let content = DashboardContent.build(PreviewData.model(.onLinkAdvice), linkAdvice: input.linkAdvice)
        XCTAssertTrue(content.connection.lines.contains(Strings.slowWiFi))
        XCTAssertTrue(content.connection.lines.contains(Strings.weakWiFi))
        XCTAssertTrue(content.attention.contains(Strings.slowWiFi))
    }

    func testPrimaryActionMapping() {
        XCTAssertEqual(DashboardContent.primaryAction(for: .pair), .pair)
        XCTAssertEqual(DashboardContent.primaryAction(for: .pairAgain), .pairAgain)
        XCTAssertEqual(DashboardContent.primaryAction(for: .turnOn), .turnOn)
        XCTAssertEqual(DashboardContent.primaryAction(for: .turnOff), .turnOff)
        XCTAssertEqual(DashboardContent.primaryAction(for: .retry), .retry)
        XCTAssertEqual(DashboardContent.primaryAction(for: .checkNow), .checkNow)
        XCTAssertNil(DashboardContent.primaryAction(for: .forget))
        XCTAssertNil(DashboardContent.primaryAction(for: .turnOffAndForget))
    }

    func testAttentionActions() {
        XCTAssertEqual(DashboardContent.attentionAction(for: Strings.forgetBlocked), .turnOffAndForget)
        XCTAssertEqual(DashboardContent.attentionAction(for: Strings.staleStatus), .checkNow)
        XCTAssertEqual(DashboardContent.attentionAction(for: Strings.notificationsDenied), .openNotificationSettings)
        XCTAssertEqual(DashboardContent.attentionAction(for: Strings.notTrustedWhileRunning), .turnOff)
        XCTAssertNil(DashboardContent.attentionAction(for: Strings.slowWiFi))
        XCTAssertNil(DashboardContent.attentionAction(for: "A new line."))
    }

    func testAttentionActionLabels() {
        XCTAssertEqual(AttentionAction.checkNow.label, Strings.checkNow)
        XCTAssertEqual(AttentionAction.turnOff.label, Strings.turnOff)
        XCTAssertEqual(AttentionAction.turnOffAndForget.label, Strings.turnOffAndForget)
        XCTAssertEqual(AttentionAction.openNotificationSettings.label, UIStrings.openSystemSettings)
    }

    // MARK: - Words

    func testNewTextHasNoBannedWords() {
        var texts = UIStrings.allText
        for scenario in PreviewScenario.allCases {
            let content = MenuBarContentBuilder.build(PreviewData.model(scenario))
            texts.append(contentsOf: content.actions.map(\.title))
            texts.append(contentsOf: [content.header.title, content.open.title, content.settings.title, content.quit.title])
        }
        let banned = ["hotspot proxy", "laptop", "iphone", "engine"]
        for text in texts {
            for word in banned {
                XCTAssertFalse(text.lowercased().contains(word), "\(word) in: \(text)")
            }
        }
    }

    func testStatusAndCardTextUsesSourceAndTargetWords() {
        XCTAssertTrue(Strings.sourceStoppedTitle.lowercased().contains("source device"))
        XCTAssertTrue(UIStrings.pairingStepOpen.lowercased().contains("source device"))
        XCTAssertFalse(UIStrings.allText.contains { $0.lowercased().contains("target device app") })
    }

    // MARK: - Quit and window life

    func testClosingTheWindowDoesNotStopTheTunnel() async {
        let fake = FakeBackend()
        fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "connected"))
        let model = AppModel(backend: fake, pingSetting: PreviewPingSetting())
        await model.refresh()
        XCTAssertEqual(model.screen, .on)

        model.setWindowVisible(false)
        XCTAssertEqual(model.statusPollInterval, 5)
        XCTAssertFalse(fake.calls.contains("stopTunnel"))
        XCTAssertEqual(model.screen, .on)

        model.setWindowVisible(true)
        XCTAssertEqual(model.statusPollInterval, 1)
        XCTAssertFalse(fake.calls.contains("stopTunnel"))
        model.stopPolling()
    }

    func testQuitUsesTheGracefulStopAndWaits() async {
        let fake = TimeoutRecordingBackend()
        fake.fake.currentStatus = Status(running: true, paired: true, phone: Phone(state: "connected"))
        fake.fake.stopClearsRunning = true
        let model = AppModel(backend: fake, pingSetting: PreviewPingSetting())
        await model.refresh()
        XCTAssertEqual(model.screen, .on)

        await model.stopForQuit()
        XCTAssertEqual(fake.stopTimeouts, [45])
        XCTAssertTrue(fake.fake.calls.contains("stopTunnel"))
        XCTAssertEqual(model.screen, .stopping)
    }

    func testQuitSendsStopWhenTheStatusReadFails() async {
        let fake = TimeoutRecordingBackend()
        fake.fake.statusFailure = BackendError.timeout
        let model = AppModel(backend: fake, pingSetting: PreviewPingSetting())
        await model.stopForQuit()
        XCTAssertEqual(fake.stopTimeouts, [45])
        XCTAssertTrue(fake.fake.calls.contains("stopTunnel"))
    }
}

// A backend that records the stop timeout. The app must use the 45 second
// wait on the quit path.
final class TimeoutRecordingBackend: BackendClient {
    let fake = FakeBackend()
    var stopTimeouts: [TimeInterval] = []

    func status(timeout: TimeInterval) async throws -> Status { try await fake.status(timeout: timeout) }
    func logs(since: Int) async throws -> [LogLine] { try await fake.logs(since: since) }
    func pairState() async throws -> PairState { try await fake.pairState() }
    func startPairing() async throws { try await fake.startPairing() }
    func cancelPairing() async throws { try await fake.cancelPairing() }
    func forget() async throws -> ForgetState { try await fake.forget() }
    func startTunnel(experimentalICMP: Bool) async throws { try await fake.startTunnel(experimentalICMP: experimentalICMP) }
    func stopTunnel(timeout: TimeInterval) async throws {
        stopTimeouts.append(timeout)
        try await fake.stopTunnel(timeout: timeout)
    }
    func failures() async throws -> Failures { try await fake.failures() }
    func probe() async throws -> Phone { try await fake.probe() }
    func diagnostics() async throws -> Diagnostics { try await fake.diagnostics() }
}
