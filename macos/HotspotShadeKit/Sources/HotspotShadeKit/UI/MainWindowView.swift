import SwiftUI
import AppKit

// The section pages in the sidebar.
public enum MainSection: Hashable {
    case dashboard
    case activity
}

// The one main window. The sidebar has Dashboard, Activity, and Settings at
// the bottom. Closing the window keeps the app and the menu bar item alive.
public struct MainWindowView: View {
    @ObservedObject public var model: AppModel
    @State private var selection: MainSection? = .dashboard
    @State private var refreshingDashboard = false
    @State private var refreshingActivity = false
    @Environment(\.openSettings) private var openSettings

    public init(model: AppModel) {
        self.model = model
    }

    public var body: some View {
        NavigationSplitView {
            sidebar
        } detail: {
            detail
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .navigationTitle(Strings.app)
        }
        .frame(minWidth: HSMetrics.minimumWidth, minHeight: HSMetrics.minimumHeight)
    }

    private var sidebar: some View {
        List(selection: $selection) {
            HStack(alignment: .center, spacing: HSMetrics.space8) {
                Label(UIStrings.dashboard, systemImage: HSSymbol.dashboard)
                Spacer(minLength: HSMetrics.space4)
                StatusDot(kind: StatusAppearance.kind(for: model.screenModel))
            }
            .tag(MainSection.dashboard)
            .accessibilityElement(children: .combine)
            .accessibilityLabel("\(UIStrings.dashboard). \(model.dashboard.title)")

            Label(UIStrings.activity, systemImage: HSSymbol.activity)
                .tag(MainSection.activity)
        }
        .navigationSplitViewColumnWidth(min: 170, ideal: 190, max: 230)
        .safeAreaInset(edge: .bottom) {
            VStack(spacing: 0) {
                Divider()
                Button {
                    NSApp.activate(ignoringOtherApps: true)
                    openSettings()
                } label: {
                    Label(UIStrings.settingsMenu.replacingOccurrences(of: "...", with: ""), systemImage: HSSymbol.settings)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(HSMetrics.space12)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel(Strings.settings)
                .help("Open Settings. Command ,")
            }
        }
    }

    @ViewBuilder private var detail: some View {
        switch selection ?? .dashboard {
        case .dashboard:
            DashboardView(
                model: model.screenModel,
                linkAdvice: model.linkAdvice,
                isPairing: model.isPairing,
                pairingCode: model.pairing.code,
                isRefreshing: refreshingDashboard,
                onAction: perform,
                onRefresh: refreshDashboard,
                onCopyCode: copy,
                onCancelPairing: { Task { await model.cancelPairing() } },
                onOpenNotificationSettings: { model.openNotificationSettings() }
            )
        case .activity:
            ActivityView(
                lines: model.logLines,
                unavailable: model.statusUnavailable,
                error: model.logsError,
                isLoading: refreshingActivity,
                onRefresh: refreshActivity
            )
            .onAppear { loadActivityIfNeeded() }
        }
    }

    private func perform(_ action: ScreenModel.Action) {
        switch action {
        case .pair, .pairAgain:
            Task { await model.beginPairing() }
        case .turnOn:
            Task { await model.turnOn() }
        case .turnOff:
            Task { await model.turnOff() }
        case .retry:
            Task { await model.perform(.retry) }
        case .checkNow:
            Task { await model.checkNow() }
        case .forget:
            Task { await model.forget() }
        case .turnOffAndForget:
            Task { await model.turnOffAndForget() }
        }
    }

    private func refreshDashboard() {
        guard !refreshingDashboard else { return }
        refreshingDashboard = true
        Task {
            await model.checkNow()
            refreshingDashboard = false
        }
    }

    private func loadActivityIfNeeded() {
        guard model.logLines.isEmpty, !refreshingActivity else { return }
        refreshActivity()
    }

    private func refreshActivity() {
        guard !refreshingActivity else { return }
        refreshingActivity = true
        Task {
            await model.loadLogs()
            refreshingActivity = false
        }
    }

    private func copy(_ text: String) {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(text, forType: .string)
    }
}
