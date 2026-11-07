import SwiftUI

// Show one view in the light theme and in the dark theme.
struct PreviewBoth<Content: View>: View {
    private let make: () -> Content
    init(@ViewBuilder content: @escaping () -> Content) {
        self.make = content
    }
    var body: some View {
        VStack(spacing: 1) {
            make()
                .environment(\.colorScheme, .light)
                .background(Color(nsColor: .windowBackgroundColor))
            make()
                .environment(\.colorScheme, .dark)
                .background(Color(nsColor: .windowBackgroundColor))
        }
    }
}

// One dashboard state with no engine.
struct DashboardPreview: View {
    let scenario: PreviewScenario
    var isRefreshing = false
    var body: some View {
        let input = PreviewData.input(scenario)
        DashboardView(
            model: PreviewData.model(scenario),
            linkAdvice: input.linkAdvice,
            isPairing: scenario == .pairingStart || scenario == .pairingCode,
            pairingCode: PreviewData.pairingCode(scenario),
            isRefreshing: isRefreshing,
            onAction: { _ in }
        )
        .frame(width: 780, height: 620)
    }
}

// One menu bar menu as a list. Disabled flags and help text stay visible.
struct MenuBarContentPreview: View {
    let scenario: PreviewScenario
    var body: some View {
        let content = MenuBarContentBuilder.build(PreviewData.model(scenario))
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Image(systemName: content.iconSymbol)
                Text(content.header.title).font(.headline)
                Spacer()
                Text("disabled").font(.caption2).foregroundStyle(.secondary)
            }
            Text(content.detail.title).font(.caption).foregroundStyle(.secondary)
            Divider()
            ForEach(content.actions) { row($0) }
            if !content.notices.isEmpty {
                Divider()
                Text(UIStrings.notices).font(.caption).foregroundStyle(.secondary)
                ForEach(content.notices) { row($0) }
            }
            Divider()
            row(content.open)
            row(content.copyDiagnostics)
            row(content.settings)
            Divider()
            row(content.quit)
        }
        .padding(16)
        .frame(width: 340, alignment: .leading)
    }

    private func row(_ item: MenuBarItem) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            if let symbol = item.symbol {
                Image(systemName: symbol).frame(width: 16)
            } else {
                Spacer().frame(width: 16)
            }
            Text(item.title)
                .foregroundStyle(item.isEnabled ? .primary : .secondary)
            Spacer()
            if let shortcut = item.shortcut {
                Text(shortcut.label).font(.caption2).foregroundStyle(.secondary)
            }
        }
        .help(item.help ?? "")
        .accessibilityElement(children: .combine)
    }
}

// MARK: - Dashboard previews

#Preview("Dashboard: unpaired") { PreviewBoth { DashboardPreview(scenario: .unpaired) } }
#Preview("Dashboard: pairing start") { PreviewBoth { DashboardPreview(scenario: .pairingStart) } }
#Preview("Dashboard: pairing code") { PreviewBoth { DashboardPreview(scenario: .pairingCode) } }
#Preview("Dashboard: not trusted") { PreviewBoth { DashboardPreview(scenario: .notTrusted) } }
#Preview("Dashboard: proxy off") { PreviewBoth { DashboardPreview(scenario: .proxyOff) } }
#Preview("Dashboard: waiting") { PreviewBoth { DashboardPreview(scenario: .waiting) } }
#Preview("Dashboard: ready") { PreviewBoth { DashboardPreview(scenario: .ready) } }
#Preview("Dashboard: starting") { PreviewBoth { DashboardPreview(scenario: .starting) } }
#Preview("Dashboard: on") { PreviewBoth { DashboardPreview(scenario: .on) } }
#Preview("Dashboard: on, source device stopped") { PreviewBoth { DashboardPreview(scenario: .onSourceStopped) } }
#Preview("Dashboard: on, not trusted") { PreviewBoth { DashboardPreview(scenario: .onNotTrusted) } }
#Preview("Dashboard: on, link advice") { PreviewBoth { DashboardPreview(scenario: .onLinkAdvice) } }
#Preview("Dashboard: on, stale status") { PreviewBoth { DashboardPreview(scenario: .onStale) } }
#Preview("Dashboard: on, notifications off") { PreviewBoth { DashboardPreview(scenario: .onNotificationsOff) } }
#Preview("Dashboard: turning off") { PreviewBoth { DashboardPreview(scenario: .turningOff) } }
#Preview("Dashboard: error") { PreviewBoth { DashboardPreview(scenario: .error) } }
#Preview("Dashboard: unknown") { PreviewBoth { DashboardPreview(scenario: .unknown) } }
#Preview("Dashboard: stale status") { PreviewBoth { DashboardPreview(scenario: .staleEngine) } }
#Preview("Dashboard: after forget") { PreviewBoth { DashboardPreview(scenario: .afterForget) } }
#Preview("Dashboard: refreshing") { PreviewBoth { DashboardPreview(scenario: .on, isRefreshing: true) } }

// The card row at the content width of a 780 and a 900 point window.
#Preview("Card row: 780") {
    PreviewBoth {
        DashboardCardRow(content: DashboardContent.build(PreviewData.model(.on)))
            .frame(width: 542)
            .padding(24)
    }
}
#Preview("Card row: 900") {
    PreviewBoth {
        DashboardCardRow(content: DashboardContent.build(PreviewData.model(.on)))
            .frame(width: 662)
            .padding(24)
    }
}

// The refresh control in the idle state and in the busy state. The two
// controls must have the same size.
#Preview("Toolbar: refresh") {
    PreviewBoth {
        HStack(spacing: HSMetrics.space16) {
            RefreshToolbarButton(isRefreshing: false, help: UIStrings.refreshStatusHelp, action: {})
            RefreshToolbarButton(isRefreshing: true, help: UIStrings.refreshStatusHelp, action: {})
        }
        .padding(HSMetrics.space24)
    }
}

// MARK: - Menu bar previews

#Preview("Menu: off") { PreviewBoth { MenuBarContentPreview(scenario: .unpaired) } }
#Preview("Menu: on") { PreviewBoth { MenuBarContentPreview(scenario: .on) } }
#Preview("Menu: needs attention") { PreviewBoth { MenuBarContentPreview(scenario: .unknown) } }
#Preview("Menu: busy") { PreviewBoth { MenuBarContentPreview(scenario: .starting) } }
#Preview("Menu: pairing") { PreviewBoth { MenuBarContentPreview(scenario: .pairingCode) } }

// MARK: - Settings previews

#Preview("Settings: general") {
    PreviewBoth { SettingsView(model: PreviewData.appModel(), initialTab: .general) }
}
#Preview("Settings: pairing") {
    PreviewBoth { SettingsView(model: PreviewData.appModel(paired: true), initialTab: .pairing) }
}
#Preview("Settings: pairing, not trusted") {
    PreviewBoth { SettingsView(model: PreviewData.appModel(paired: true, phoneState: "not_trusted"), initialTab: .pairing) }
}
#Preview("Settings: advanced") {
    PreviewBoth { SettingsView(model: PreviewData.appModel(), initialTab: .advanced) }
}

// MARK: - Activity previews

#Preview("Activity: empty") {
    PreviewBoth {
        ActivityView(lines: [])
            .frame(width: 700, height: 420)
    }
}
#Preview("Activity: loaded") {
    PreviewBoth {
        ActivityView(lines: ActivityPreviewData.lines)
            .frame(width: 700, height: 420)
    }
}
#Preview("Activity: unavailable") {
    PreviewBoth {
        ActivityView(lines: [], unavailable: true)
            .frame(width: 700, height: 420)
    }
}
#Preview("Activity: loading") {
    PreviewBoth {
        ActivityView(lines: [], isLoading: true)
            .frame(width: 700, height: 420)
    }
}
#Preview("Activity: loaded, refreshing") {
    PreviewBoth {
        ActivityView(lines: ActivityPreviewData.lines, isLoading: true)
            .frame(width: 700, height: 420)
    }
}

enum ActivityPreviewData {
    static let lines = [
        LogLine(seq: 1, level: "info", msg: "The tunnel started.", ts: 1_762_000_000),
        LogLine(seq: 2, level: "info", msg: "The source device is ready.", ts: 1_762_000_002),
        LogLine(seq: 3, level: "warn", msg: "The hotspot turned off.", ts: 1_762_000_030),
    ]
}

// MARK: - Failures previews

#Preview("Failures: empty") {
    PreviewBoth {
        FailuresTableView(rows: [], state: .empty)
            .frame(width: 640, height: 360)
    }
}
#Preview("Failures: loaded") {
    PreviewBoth {
        FailuresTableView(rows: PreviewData.failureRows(), state: .loaded)
            .frame(width: 640, height: 360)
    }
}
#Preview("Failures: unavailable") {
    PreviewBoth {
        FailuresTableView(rows: [], state: .unavailable)
            .frame(width: 640, height: 360)
    }
}

// MARK: - Engine start

#Preview("Engine start: loading") {
    PreviewBoth {
        EngineStartView()
            .frame(width: 560, height: 400)
    }
}
#Preview("Engine start: error") {
    PreviewBoth {
        EngineStartView(error: Strings.engineMissing)
            .frame(width: 560, height: 400)
    }
}

// MARK: - Main window

#Preview("Main window") {
    MainWindowView(model: PreviewData.appModel(paired: true, running: true))
        .frame(width: 900, height: 640)
}
