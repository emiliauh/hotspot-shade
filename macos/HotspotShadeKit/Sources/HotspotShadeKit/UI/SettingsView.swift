import SwiftUI

// The Settings tabs.
public enum SettingsTab: Hashable {
    case general
    case pairing
    case privacy
    case advanced
}

// The Settings window. General holds the two settings and the notification
// state. Pairing holds Forget and Pair. Privacy reports the destination
// privacy capability state and offers no control. Advanced holds failures and
// details.
public struct SettingsView: View {
    @ObservedObject public var model: AppModel
    public var letPingWork: Bool
    public var initialTab: SettingsTab
    private let onSetLetPingWork: (Bool) -> Void
    @State private var tab: SettingsTab
    @State private var login: Bool
    @State private var loginAvailable: Bool

    public init(model: AppModel, letPingWork: Bool = true, initialTab: SettingsTab = .general, onSetLetPingWork: @escaping (Bool) -> Void = { _ in }) {
        self.model = model
        self.letPingWork = letPingWork
        self.initialTab = initialTab
        self.onSetLetPingWork = onSetLetPingWork
        _tab = State(initialValue: initialTab)
        _login = State(initialValue: LaunchAtLogin.isEnabled)
        _loginAvailable = State(initialValue: LaunchAtLogin.isAvailable)
    }

    public var body: some View {
        TabView(selection: $tab) {
            general
                .tabItem { Label(UIStrings.general, systemImage: HSSymbol.settings) }
                .tag(SettingsTab.general)
            pairing
                .tabItem { Label(UIStrings.pairingTab, systemImage: HSSymbol.pairing) }
                .tag(SettingsTab.pairing)
            privacy
                .tabItem { Label(TargetPrivacyCapabilities.tabTitle, systemImage: "eye.slash") }
                .tag(SettingsTab.privacy)
            advanced
                .tabItem { Label(UIStrings.advanced, systemImage: "wrench.and.screwdriver") }
                .tag(SettingsTab.advanced)
        }
        .frame(width: 560, height: 480)
        .task { await model.refreshNotificationAuthorization() }
    }

    // MARK: - General

    private var general: some View {
        Form {
            Section {
                Toggle(Strings.login, isOn: loginBinding)
                    .disabled(!loginAvailable)
                if !loginAvailable {
                    Text(Strings.loginUnavailable)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Toggle(Strings.letPingWork, isOn: Binding(get: { letPingWork }, set: { onSetLetPingWork($0) }))
                Text(Strings.letPingWorkHint)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Section(UIStrings.notifications) {
                Text(notificationText)
                    .fixedSize(horizontal: false, vertical: true)
                if model.canOpenNotificationSettings {
                    Button(UIStrings.openSystemSettings) { model.openNotificationSettings() }
                }
            }
        }
        .formStyle(.grouped)
    }

    private var notificationText: String {
        switch model.notificationAuthorization {
        case .authorized: return UIStrings.notificationsOn
        case .denied: return Strings.notificationsDenied
        case .notDetermined: return UIStrings.notificationsNotAsked
        }
    }

    private var loginBinding: Binding<Bool> {
        Binding(get: { login }, set: { value in
            LaunchAtLogin.set(value)
            login = LaunchAtLogin.isEnabled
            loginAvailable = LaunchAtLogin.isAvailable
        })
    }

    // MARK: - Pairing

    private var pairing: some View {
        Form {
            Section {
                HStack(alignment: .firstTextBaseline, spacing: HSMetrics.space8) {
                    Image(systemName: pairedSymbol)
                        .foregroundStyle(pairedColor)
                        .accessibilityHidden(true)
                    Text(pairingStateText)
                        .font(.headline)
                }
                if !model.statusUnavailable, !model.recoveryBlocked {
                    Text(model.dashboard.subtitle)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                // The recovery text replaces the saved pairing claim. It is
                // the same fixed text as the dashboard.
                if model.recoveryBlocked {
                    Text(model.cleanupBlocked ? Strings.cleanupBlockedBody : Strings.serviceStateUnknownBody)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Section {
                Button(Strings.pair) { Task { await model.beginPairing() } }
                    .disabled(!pairEnabled)
                if let reason = pairReason {
                    Text(reason)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                if model.isPairing {
                    HStack(spacing: HSMetrics.space8) {
                        ProgressView()
                            .controlSize(.small)
                            .accessibilityHidden(true)
                        Text(Strings.pairingSubtitle)
                    }
                    Button(Strings.cancel) { Task { await model.cancelPairing() } }
                }
            }
            if model.status.paired == true, !model.serviceStateUnknown {
                Section(Strings.forget) {
                    Text(UIStrings.forgetHint)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    if model.recoveryBlocked {
                        // Neither Forget nor Turn off and forget is safe while
                        // the engine cannot describe the tunnel.
                        Text(model.cleanupBlocked ? Strings.cleanupBlockedBody : Strings.serviceStateUnknownBody)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    } else if let pending = model.pendingCleanupMessage {
                        // A helper stop that is not confirmed is not cleanup
                        // proof, even when the last status said running false.
                        Text(Strings.sanitized(pending) ?? pending)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    } else if model.statusUnavailable {
                        // An unavailable status cannot prove the tunnel is off,
                        // so neither Forget action is safe.
                        Text(Strings.statusUnavailableSubtitle)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    } else if model.status.running == true {
                        Text(Strings.forgetBlocked)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                        Button(Strings.turnOffAndForget, role: .destructive) { Task { await model.turnOffAndForget() } }
                            .tint(.red)
                            .disabled(model.statusUnavailable || model.recoveryBlocked || model.hasPendingCleanup)
                    } else {
                        Button(Strings.forget, role: .destructive) { Task { await model.forget() } }
                            .tint(.red)
                            .disabled(model.statusUnavailable || model.recoveryBlocked || model.hasPendingCleanup)
                    }
                    if let message = model.forgetMessage {
                        Text(message)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
        }
        .formStyle(.grouped)
    }

    private var paired: Bool { model.status.paired == true }

    private var showsNotTrusted: Bool { model.screen == .notTrusted }

    private var pairedSymbol: String {
        SettingsPairingText.symbol(model.screen, paired: paired, unavailable: model.statusUnavailable, indeterminate: model.serviceStateUnknown)
    }

    private var pairedColor: Color {
        if model.statusUnavailable || model.recoveryBlocked { return .secondary }
        if showsNotTrusted { return .orange }
        return paired ? .green : .secondary
    }

    private var pairingStateText: String {
        SettingsPairingText.state(model.screen, paired: paired, unavailable: model.statusUnavailable, indeterminate: model.serviceStateUnknown)
    }

    private var pairAction: ScreenModel.MenuBarAction? {
        model.screenModel.menuBar.actions.first { $0.kind == .pair }
    }
    private var pairEnabled: Bool { pairAction?.enabled == true && !model.isPairing }
    private var pairReason: String? {
        if model.isPairing { return nil }
        return pairAction?.reason
    }

    // MARK: - Privacy

    // The capability report is fixed text. It has no switch, because the
    // engine implements none of the opt-in modes in this build.
    private var privacy: some View {
        TargetPrivacySettingsView(report: TargetPrivacyCapabilities.current)
    }

    // MARK: - Advanced

    private var advanced: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: HSMetrics.space24) {
                VStack(alignment: .leading, spacing: HSMetrics.space12) {
                    Text(Strings.recentFailures)
                        .font(.headline)
                    FailuresTableView(
                        rows: model.failureRows,
                        state: model.failuresState,
                        reportCopied: model.reportCopied,
                        tunnelRunning: model.failuresAvailable,
                        recoveryBlocked: model.recoveryBlocked,
                        serviceStateUnknown: model.serviceStateUnknown,
                        unavailable: model.statusUnavailable,
                        stale: model.statusIsStale,
                        onRefresh: { Task { await model.loadFailures() } },
                        onCopyReport: { model.copyReport() }
                    )
                }
                Divider()
                VStack(alignment: .leading, spacing: HSMetrics.space8) {
                    Text(UIStrings.link)
                        .font(.headline)
                    if model.linkAdvice.isEmpty {
                        Text(UIStrings.noLinkAdvice).foregroundStyle(.secondary)
                    } else {
                        ForEach(Array(model.linkAdvice.enumerated()), id: \.offset) { _, line in
                            Text(line)
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }
                Divider()
                VStack(alignment: .leading, spacing: HSMetrics.space12) {
                    Text(UIStrings.appDetails)
                        .font(.headline)
                    LabeledContent(UIStrings.appVersion, value: AppModel.bundleVersion())
                    LabeledContent(UIStrings.macOSVersion, value: ProcessInfo.processInfo.operatingSystemVersionString)
                    LabeledContent(UIStrings.status, value: model.dashboard.title)
                    if model.recoveryBlocked {
                        LabeledContent(UIStrings.serviceState, value: model.cleanupBlocked ? UIStrings.serviceStateCleanupBlocked : UIStrings.serviceStateUnknown)
                    }
                    HStack(spacing: HSMetrics.space12) {
                        Button(UIStrings.copyDiagnostics) { Task { await model.copyDiagnostics() } }
                        if model.diagnosticsCopied {
                            Text(UIStrings.copied)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
            .padding(HSMetrics.space24)
        }
        .onAppear { Task { await model.loadFailures() } }
    }
}

// The main window and the Settings window show this before the app has a
// model. It never claims that the tunnel is on.
public struct EngineStartView: View {
    public var error: String?
    private let onRetry: () -> Void
    public init(error: String? = nil, onRetry: @escaping () -> Void = {}) {
        self.error = error
        self.onRetry = onRetry
    }
    public var body: some View {
        VStack(spacing: HSMetrics.space16) {
            if let error {
                VStack(spacing: HSMetrics.space16) {
                    Image(systemName: "exclamationmark.triangle")
                        .font(.largeTitle)
                        .foregroundStyle(.secondary)
                        .accessibilityHidden(true)
                    Text(Strings.attention)
                        .font(.title2.bold())
                    Text(Strings.sanitized(error) ?? error)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
                .accessibilityElement(children: .combine)
                Button(Strings.tryAgain, action: onRetry)
                    .buttonStyle(.borderedProminent)
            } else {
                VStack(spacing: HSMetrics.space16) {
                    ProgressView()
                        .accessibilityHidden(true)
                    Text(UIStrings.startingApp)
                        .font(.headline)
                    Text(Strings.takesAMinute)
                        .foregroundStyle(.secondary)
                }
                .accessibilityElement(children: .combine)
            }
        }
        .padding(HSMetrics.space48)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
