import SwiftUI
import AppKit
import HotspotShadeKit

// The app owns the engine and the model. The package views draw the state.
@MainActor final class Coordinator: ObservableObject {
    @Published var model: AppModel?
    @Published var error: String?
    // --demo or HS_DEMO=1 starts the engine in demo mode.
    @Published var demo = LaunchOptions().demo || UserDefaults.standard.bool(forKey: "demo")
    @Published var port: UInt16?
    @Published var letPingWork: Bool
    // True from the Quit command until the app exits. The menu shows the wait.
    @Published var quitting = false
    private let pingSetting: UserDefaultsPingSetting
    private var engine: BackendProcess?
    private var monitor: Task<Void, Never>?
    private var starting = false
    private var stopping = false
    private var observers: [NSObjectProtocol] = []

    init() {
        let setting = UserDefaultsPingSetting()
        pingSetting = setting
        letPingWork = setting.letPingWork
        // The notification policy stays quiet for events 2 to 4 while the app
        // is frontmost. Track the application focus here.
        observe(NSApplication.didBecomeActiveNotification) { [weak self] _ in
            Task { @MainActor in self?.model?.setFrontmost(true) }
        }
        observe(NSApplication.didResignActiveNotification) { [weak self] _ in
            Task { @MainActor in self?.model?.setFrontmost(false) }
        }
        // The status poll is slower while the main window is not visible.
        for name in [NSWindow.didMiniaturizeNotification, NSWindow.willCloseNotification] {
            observe(name) { [weak self] note in
                Task { @MainActor in
                    guard let window = note.object as? NSWindow, window.title == Strings.app else { return }
                    self?.model?.setWindowVisible(false)
                }
            }
        }
        observe(NSWindow.didDeminiaturizeNotification) { [weak self] note in
            Task { @MainActor in
                guard let window = note.object as? NSWindow, window.title == Strings.app else { return }
                self?.model?.setWindowVisible(true)
            }
        }
    }

    deinit {
        for observer in observers { NotificationCenter.default.removeObserver(observer) }
    }

    private func observe(_ name: Notification.Name, _ handler: @escaping @Sendable (Notification) -> Void) {
        observers.append(NotificationCenter.default.addObserver(forName: name, object: nil, queue: .main, using: handler))
    }

    // Build one model with the product stores and providers. Tests use the
    // package with fakes instead.
    private func makeModel(port: UInt16, secret: String) -> AppModel {
        #if canImport(CoreWLAN)
        let link: LinkInfoProvider = CoreWLANLinkInfoProvider()
        #else
        let link: LinkInfoProvider = NoLinkInfoProvider()
        #endif
        #if canImport(UserNotifications)
        let sink: NotificationSink = UserNotificationSink()
        #else
        let sink: NotificationSink = NoNotificationSink()
        #endif
        let model = AppModel(backend: HTTPBackend(port: port, secret: secret), pingSetting: pingSetting, pasteboard: SystemPasteboard(), forgetIntent: UserDefaultsForgetIntent(), notificationSink: sink, settingsOpener: WorkspaceSettingsOpener(), linkProvider: link)
        model.setFrontmost(NSApp.isActive)
        Task { await model.refreshNotificationAuthorization() }
        return model
    }

    func start() {
        Task { await startEngine() }
    }

    // Store the next value. A running tunnel keeps its own setting.
    func setLetPingWork(_ enabled: Bool) {
        letPingWork = enabled
        if let model { model.setLetPingWork(enabled) } else { pingSetting.letPingWork = enabled }
    }

    // The retry button calls this after a failed engine start.
    func retry() {
        guard model == nil else { return }
        error = nil
        Task { await startEngine() }
    }

    func windowBecameVisible() {
        model?.setWindowVisible(true)
    }

    func windowBecameHidden() {
        model?.setWindowVisible(false)
    }

    func sceneChanged(_ phase: ScenePhase) {
        switch phase {
        case .active:
            model?.setFrontmost(NSApp.isActive)
        case .inactive, .background:
            model?.setFrontmost(false)
        @unknown default:
            break
        }
    }

    // The menu and the commands call this for the model actions.
    func perform(_ kind: ScreenModel.MenuBarAction.Kind) {
        guard let model else { return }
        switch kind {
        case .turnOn, .turnOff:
            Task { await model.toggle() }
        case .pair:
            Task { await model.beginPairing() }
        case .cancel:
            Task { await model.cancelPairing() }
        case .checkNow:
            Task { await model.checkNow() }
        case .open, .quit:
            break
        }
    }

    func copyDiagnostics() {
        guard let model else { return }
        Task { await model.copyDiagnostics() }
    }

    // Quit uses the same graceful flow as the app menu. The delegate stops the
    // tunnel first, then the app exits.
    func quit() {
        guard !quitting else { return }
        quitting = true
        NSApp.terminate(nil)
    }

    private func startEngine() async {
        guard engine == nil, !starting, !stopping else { return }
        starting = true
        defer { starting = false }
        error = nil
        guard let executable = Bundle.main.resourceURL?.appendingPathComponent("bin/hotspotshade") else { error = Strings.engineMissing; return }
        let process = BackendProcess(executable: executable, demo: demo)
        do {
            try await process.start()
            guard let port = process.port else { throw BackendError.timeout }
            // The app may quit while the engine starts. Do not leave it behind.
            guard !stopping else { await process.stop(); return }
            engine = process; self.port = port; self.error = nil
            let model = makeModel(port: port, secret: process.secret)
            self.model = model; model.startPolling(); monitorEngine()
        } catch {
            await process.stop()
            engine = nil; self.model = nil; self.error = error.localizedDescription
        }
    }

    private func monitorEngine() {
        monitor?.cancel()
        monitor = Task { [weak self] in
            var healthySince = Date()
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                guard !Task.isCancelled, let self, let engine = self.engine else { return }
                if !engine.isRunning {
                    self.model?.stopPolling()
                    do {
                        try await engine.restartOnce()
                        guard let port = engine.port else { throw BackendError.timeout }
                        self.port = port
                        let model = self.makeModel(port: port, secret: engine.secret)
                        self.model = model; model.startPolling(); self.error = nil; healthySince = Date()
                    } catch {
                        // Make the error panel able to start a new engine.
                        self.model = nil
                        await engine.stop()
                        self.engine = nil
                        self.error = error.localizedDescription
                        return
                    }
                } else if Date().timeIntervalSince(healthySince) >= 60 {
                    // One healthy minute gives the engine a new restart budget.
                    engine.markHealthy(); healthySince = Date()
                }
            }
        }
    }

    func stop() async {
        stopping = true
        monitor?.cancel(); monitor = nil
        await model?.stopForQuit()
        await engine?.stop()
        engine = nil
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    var coordinator: Coordinator?
    var openMain: (() -> Void)?
    private var terminating = false

    // Closing the main window keeps the app and the menu bar item running.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    // The Dock icon brings the one main window to the front.
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        NSApp.activate(ignoringOtherApps: true)
        if let openMain {
            openMain()
        } else if let window = NSApp.windows.first(where: { $0.title == Strings.app }) {
            window.makeKeyAndOrderFront(nil)
        }
        return true
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard !terminating else { return .terminateLater }
        terminating = true
        Task { @MainActor in
            await coordinator?.stop()
            sender.reply(toApplicationShouldTerminate: true)
        }
        return .terminateLater
    }
}

@main struct HotspotShadeApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var coordinator = Coordinator()
    @Environment(\.openWindow) private var openWindow
    @Environment(\.openSettings) private var openSettings
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        Window(Strings.app, id: "main") {
            windowContent
                .frame(minWidth: HSMetrics.minimumWidth, minHeight: HSMetrics.minimumHeight)
                .onAppear {
                    delegate.coordinator = coordinator
                    delegate.openMain = { openMainWindow() }
                    coordinator.windowBecameVisible()
                    coordinator.start()
                }
                .onDisappear { coordinator.windowBecameHidden() }
                .onChange(of: scenePhase) { _, phase in coordinator.sceneChanged(phase) }
        }
        .defaultSize(width: HSMetrics.defaultWidth, height: HSMetrics.defaultHeight)
        .windowResizability(.contentMinSize)
        .commands { AppCommands(coordinator: coordinator) }

        Settings {
            settingsContent
                .frame(width: 560, height: 480)
        }

        MenuBarExtra {
            menuContent
        } label: {
            MenuBarStatusIcon(symbol: menu.iconSymbol, stateWord: menu.stateWord)
        }
        .menuBarExtraStyle(.menu)
    }

    @ViewBuilder private var windowContent: some View {
        if let model = coordinator.model {
            MainWindowView(model: model, demo: coordinator.demo)
        } else {
            EngineStartView(error: coordinator.error, onRetry: { coordinator.retry() })
        }
    }

    @ViewBuilder private var settingsContent: some View {
        if let model = coordinator.model {
            SettingsView(model: model, letPingWork: coordinator.letPingWork, onSetLetPingWork: { coordinator.setLetPingWork($0) })
        } else {
            EngineStartView(error: coordinator.error, onRetry: { coordinator.retry() })
        }
    }

    private var menu: MenuBarContent {
        if let model = coordinator.model {
            return MenuBarContentBuilder.build(model.screenModel, quitting: coordinator.quitting)
        }
        return MenuBarContentBuilder.starting(quitting: coordinator.quitting)
    }

    @ViewBuilder private var menuContent: some View {
        if coordinator.model != nil {
            MenuBarMenu(
                content: menu,
                onAction: { coordinator.perform($0) },
                onOpen: { openMainWindow() },
                onCopyDiagnostics: { coordinator.copyDiagnostics() },
                onSettings: { openSettingsWindow() },
                onQuit: { coordinator.quit() }
            )
        } else {
            MenuBarMenu(
                content: menu,
                onAction: { coordinator.perform($0) },
                onOpen: { openMainWindow() },
                onCopyDiagnostics: {},
                onSettings: { openSettingsWindow() },
                onQuit: { coordinator.quit() }
            )
        }
    }

    private func openMainWindow() {
        NSApp.activate(ignoringOtherApps: true)
        openWindow(id: "main")
    }

    private func openSettingsWindow() {
        NSApp.activate(ignoringOtherApps: true)
        openSettings()
    }
}

// The window commands. New Window is removed. Refresh and the tunnel toggle
// stay in the main menu bar.
struct AppCommands: Commands {
    @ObservedObject var coordinator: Coordinator

    var body: some Commands {
        CommandGroup(replacing: .newItem) {}
        CommandMenu("Tunnel") {
            Button(Strings.refresh) {
                Task { await coordinator.model?.checkNow() }
            }
            .keyboardShortcut("r", modifiers: .command)
            .disabled(coordinator.model == nil)

            if let toggle = toggleItem {
                Button(toggle.title) {
                    Task { await coordinator.model?.toggle() }
                }
                .keyboardShortcut(.return, modifiers: .command)
                .disabled(!toggle.isEnabled)
            }
        }
    }

    private var toggleItem: MenuBarItem? {
        guard let model = coordinator.model else { return nil }
        return MenuBarContentBuilder.build(model.screenModel).actions.first { $0.kind == .turnOn || $0.kind == .turnOff }
    }
}

// Write the plain-text report to the system pasteboard.
struct SystemPasteboard: PasteboardWriting {
    func write(_ text: String) {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(text, forType: .string)
    }
}
