import SwiftUI
import AppKit
import HotspotShadeKit

// A handoff descriptor that changes when the user engine restarts. The
// elevated session outlives the user engine, so its closure reads the current
// value instead of capturing one process.
private final class HandoffDescriptorBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Int32 = -1
    func set(_ next: Int32) {
        lock.lock(); value = next; lock.unlock()
    }
    var current: Int32 {
        lock.lock(); defer { lock.unlock() }
        return value
    }
}

// The app owns the user engine and the model. The package views draw the
// state. A root engine exists only while a tunnel runs.
@MainActor final class Coordinator: ObservableObject {
    @Published var model: AppModel?
    @Published private(set) var launchState: EngineLaunchState = .waiting
    @Published var port: UInt16?
    @Published var letPingWork: Bool
    // True from the Quit command until the app exits. The menu shows the wait.
    @Published var quitting = false
    // The launch screen shows this after Copy diagnostics works without a model.
    @Published private(set) var diagnosticsCopied = false
    private let pingSetting: UserDefaultsPingSetting
    private let pasteboard = SystemPasteboard()
    private var engine: BackendProcess?
    private var monitor: Task<Void, Never>?
    private var launchTask: Task<Void, Never>?
    private var launchCancellation: EngineLaunchCancellation?
    private var stopping = false
    private var lifetime = EngineLifetimeFence()
    private var stateBeforeQuit: EngineLaunchState?
    // A monitor restart and a quit both stop the same user engine. One gate
    // makes the stop wait for the restart instead of racing the process.
    private let stopRestartGate = SerialOperationGate()
    // A tunnel authorization that starts after a quit must not prompt.
    // The app-wide gate closes at the start of a quit. Every model action and
    // the tunnel session read the same object.
    private let actionGate = AppActionGate()
    // The one elevated session for this app. It outlives a model rebuild, a
    // lost user engine, and a quit that the person cancels. Its cleanup state
    // is shared with every routing backend built for it.
    private var tunnelSession: RealTunnelSession?
    private let handoff = HandoffDescriptorBox()
    private var cleanupRetryInFlight = false
    private var observers: [NSObjectProtocol] = []

    init() {
        let setting = UserDefaultsPingSetting()
        pingSetting = setting
        letPingWork = setting.letPingWork
        // The app starts the engine with the window. It runs the bundled
        // engine as the signed-in user, so the full interface and the
        // pairing work without an administrator prompt. The root engine starts
        // only when a person turns the tunnel on.
        if EngineLaunchPolicy.startsAutomatically() {
            launchState = .starting
        }
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
        launchCancellation?.cancel()
        launchTask?.cancel()
        monitor?.cancel()
        for observer in observers { NotificationCenter.default.removeObserver(observer) }
    }

    private func observe(_ name: Notification.Name, _ handler: @escaping @Sendable (Notification) -> Void) {
        observers.append(NotificationCenter.default.addObserver(forName: name, object: nil, queue: .main, using: handler))
    }

    // Build one model with the product stores and providers. The user engine
    // answers every request until a person turns the tunnel on. A routing
    // backend swaps to the elevated engine only for the live tunnel.
    private func makeModel(process: BackendProcess) -> AppModel {
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
        guard let port = process.port else {
            fatalError("The model is built only after the engine reports its port.")
        }
        let user = HTTPBackend(port: port, secret: process.secret)
        let session: RealTunnelSession
        if let existing = tunnelSession {
            existing.updateUser(user)
            session = existing
        } else {
            let handoffBox = handoff
            let gate = actionGate
            session = RealTunnelSession(
                user: user,
                handoffDescriptor: { handoffBox.current },
                isQuitting: { gate.isQuitting },
                actionGate: gate
            )
            tunnelSession = session
        }
        // The router owns the authorization step, so it can refuse a start
        // after an unconfirmed stop before any prompt, handoff, or root
        // engine start. It shares the session's cleanup state, so a rebuilt
        // model cannot forget a pending stop or a live elevated engine.
        // The session builds the router, so the hermetic tests exercise
        // the same wiring that the app uses.
        let backend: BackendClient = session.makeRouter(user: user)
        let gate = actionGate
        let model = AppModel(backend: backend, isQuitting: { gate.isQuitting }, actionGate: gate, pingSetting: pingSetting, pasteboard: SystemPasteboard(), forgetIntent: UserDefaultsForgetIntent(), notificationSink: sink, settingsOpener: WorkspaceSettingsOpener(), linkProvider: link)
        model.setFrontmost(NSApp.isActive)
        Task { await model.refreshNotificationAuthorization() }
        return model
    }

    // The engine starts when the window appears. The app runs its engine as
    // the signed-in user, so the interface, pairing, and status need no
    // administrator prompt.
    func startIfNeeded() {
        guard EngineLaunchPolicy.startsAutomatically() else { return }
        start()
    }

    // The Start HotspotShade and Try again buttons call this. The admin prompt
    // is a separate request when the person turns the tunnel on.
    func start() {
        guard launchTask == nil, engine == nil, !stopping, !quitting, !cleanupRetryInFlight, !actionGate.isQuitting else { return }
        let token = lifetime.beginStart()
        let cancellation = EngineLaunchCancellation()
        launchCancellation = cancellation
        launchState = .starting
        diagnosticsCopied = false
        launchTask = Task { [weak self] in
            guard let self else { return }
            await self.startUserEngine(token: token, cancellation: cancellation)
            if self.launchCancellation === cancellation {
                self.launchCancellation = nil
            }
            self.launchTask = nil
        }
    }

    // Store the next value. A running tunnel keeps its own setting.
    func setLetPingWork(_ enabled: Bool) {
        letPingWork = enabled
        if let model { model.setLetPingWork(enabled) } else { pingSetting.letPingWork = enabled }
    }

    // The retry button calls this after a failed engine start or an
    // unconfirmed cleanup. A pending helper stop is retried before any new
    // engine start, because the idle user engine cannot prove it away.
    func retry() {
        guard model == nil, !quitting, !stopping, !cleanupRetryInFlight, !actionGate.isQuitting else { return }
        // A final cleanup answer has no useful retry. The launch screen shows no
        // action for it, and a programmatic call must not loop either.
        if launchState.failure?.cleanupIsFinal == true { return }
        if let pending = tunnelSession?.cleanup.pending, pending.isTerminal { return }
        let needsCleanupRetry = tunnelSession?.hasPendingCleanup == true
            || (tunnelSession?.hasElevatedSession == true && launchState.failure?.kind == .cleanup)
        if needsCleanupRetry {
            Task { await retryCleanup() }
            return
        }
        start()
    }

    // Ask the helper again for an unconfirmed stop. This works even when no
    // elevated process handle remains, because the session reconnects and reads
    // the helper's session record. Only a confirmed result starts the user
    // engine again.
    private func retryCleanup() async {
        guard !cleanupRetryInFlight, !quitting, !stopping, !actionGate.isQuitting else { return }
        guard let session = tunnelSession else { start(); return }
        cleanupRetryInFlight = true
        // A quit and a Stay can both land while the helper answers. Stay moves
        // the lifetime generation and restores its own screen, so this late
        // answer must not replace that screen or start a second engine.
        let token = lifetime.current
        let previous = launchState
        launchState = .stopping
        diagnosticsCopied = false
        let outcome = await session.stopElevated()
        cleanupRetryInFlight = false
        // A quit can begin while the helper confirmation is in flight. The
        // session kept the result; do not change the launch screen underneath
        // the quit.
        guard !quitting, !stopping, lifetime.permits(token, stopping: stopping) else { return }
        if outcome.isUncertain {
            // The current app-owned mark decides the text and the action. A
            // newer final mark wins over this one answer, and a durable block
            // keeps its own recovery text instead of the route text.
            let current = session.cleanup.pending
            let message = current?.message ?? outcome.message ?? EngineLaunchText.stopUnverified
            let kind = current?.kind ?? outcome.cleanupKind ?? .retryable
            launchState = .lost(EngineLaunchFailure.fromCleanupRetry(message: message, kind: kind))
            return
        }
        // The helper confirmed that no elevated engine remains. Start the user
        // engine again for a cleanup retry, or restore a different failure.
        if previous == .running || previous == .waiting || previous.failure?.kind == .cleanup {
            start()
        } else {
            launchState = previous
        }
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
        guard let model, !stopping, !quitting else { return }
        switch kind {
        case .turnOn, .turnOff:
            // The command carries a direction. Check it at entry so a stale
            // screen can never turn "Turn off" into a start, or "Turn on" into
            // a stop, while an asynchronous toggle is pending. Send the
            // direction itself: only a start asks for administrator
            // authorization.
            guard let direction = EngineToggleDirection(kind),
                  model.screenModel.permits(direction) else { return }
            // Take the gate token at the press. A quit that begins before the
            // task runs, followed by Stay, must not let this press through.
            let gate = actionGate
            let token = gate.current()
            Task {
                // Check again on the main actor immediately before the action.
                // A queued opposite action cannot invert this command.
                guard gate.permits(token), model.screenModel.permits(direction) else { return }
                switch direction {
                case .turnOn: await model.turnOn()
                case .turnOff: await model.turnOff()
                }
            }
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

    // Copy the full report when the engine has a model. Before that, copy the
    // launch report so a failed helper start still has evidence to share.
    func copyDiagnostics() {
        if let model {
            Task {
                await model.copyDiagnostics()
                diagnosticsCopied = true
            }
            return
        }
        let text = EngineLaunchDiagnostics.text(
            state: launchState,
            appVersion: AppModel.bundleVersion(),
            macOSVersion: ProcessInfo.processInfo.operatingSystemVersionString
        )
        pasteboard.write(text)
        diagnosticsCopied = true
    }

    // Command Q and the menu both set the wait state before the delegate runs.
    // The menu shows "Turning off..." for either path.
    func beginQuit() {
        guard !quitting else { return }
        // Close every app action first. A dashboard call that is queued or
        // already running must observe this before the quit path touches the
        // tunnel.
        actionGate.beginQuit()
        quitting = true
        // Fence every monitor and start from before this quit. A late result
        // must not change the screen after the quit path owns the engine.
        lifetime.beginQuit()
        // A tunnel start that is asking for authorization or preparing a root
        // engine must not publish its result after this quit. The generation
        // stays cancelled even if the person later chooses Stay.
        tunnelSession?.abortPendingStarts()
        launchCancellation?.cancel()
    }

    // Quit uses the same graceful flow as the app menu. The delegate stops the
    // tunnel first, then the app exits.
    func quit() {
        beginQuit()
        NSApp.terminate(nil)
    }

    // The quit alert chose Stay. Restore the earlier cleanup guidance when the
    // app had one. A late Stay reply from an older quit generation is ignored.
    // The elevated session and its pending cleanup are retained by the
    // coordinator, so a rebuilt model cannot clear them.
    func cancelQuit(_ preparation: QuitPreparation) {
        guard preparation.generation == lifetime.quitGeneration else { return }
        quitting = false
        stopping = false
        lifetime.cancelQuit()
        actionGate.cancelQuit()
        let pending = tunnelSession?.cleanup.pending
        let restored = EngineLaunchState.afterCancelledQuit(
            previous: stateBeforeQuit,
            outcome: preparation.outcome,
            pendingCleanup: pending
        )
        launchState = restored
        stateBeforeQuit = nil
        // The quit stopped the user engine. If the person stays and no
        // cleanup is pending, start the user engine again. A pending stop keeps
        // the launch screen with its Retry cleanup action and starts nothing.
        // A quit that raced a tunnel action or a cleanup retry can leave the
        // model and the user engine alive. The quit stopped the poll and the
        // monitor, so resume both: a later user engine death must still stop
        // the tunnel and show the lost screen.
        switch QuitStayPlan.after(
            engineAlive: engine != nil,
            modelAlive: model != nil,
            pendingCleanup: pending,
            restored: restored
        ) {
        case .startUserEngine:
            start()
        case .resume(let resumeMonitor):
            model?.startPolling()
            if resumeMonitor { monitorEngine(token: lifetime.current) }
        case .none:
            break
        }
    }

    // The app runs the bundled engine as the signed-in user. It keeps
    // the pairing and the full interface here; a root engine starts only for a
    // tunnel. The engine creates no route and no tunnel device.
    private func startUserEngine(token: EngineLifetimeFence.Token, cancellation: EngineLaunchCancellation) async {
        guard let executable = Bundle.main.resourceURL?.appendingPathComponent("bin/hotspotshade") else {
            fail(EngineLaunchFailure.fromUserEngine(BackendError.missingEngine))
            return
        }
        let process = BackendProcess(executable: executable)
        do {
            try await process.start()
            guard let port = process.port else { throw BackendError.timeout }
            // The app has no test-data mode. An engine that answers with test
            // data is a launch failure with a plain engine error.
            try await UserEngineCheck.verify(HTTPBackend(port: port, secret: process.secret))
            // The app may quit while the engine starts. Do not leave it behind
            // and do not publish a result from a quit that already began.
            guard !cancellation.isCancelled, !stopping, !quitting, lifetime.permits(token, stopping: stopping) else {
                await process.stop()
                return
            }
            engine = process; self.port = port; launchState = .running
            handoff.set(process.handoffReadDescriptor)
            let model = makeModel(process: process)
            self.model = model; model.startPolling(); monitorEngine(token: token)
        } catch {
            await process.stop()
            if cancellation.isCancelled || stopping || quitting || !lifetime.permits(token, stopping: stopping) {
                return
            }
            fail(EngineLaunchFailure.fromUserEngine(error))
        }
    }

    private func fail(_ failure: EngineLaunchFailure) {
        // A quit may already be waiting for this start attempt to return. Do
        // not replace the stopping screen with an error that the app will not
        // show.
        guard !stopping, !quitting else { return }
        engine = nil
        model = nil
        port = nil
        launchState = .failed(failure)
    }

    private enum RestartResult {
        case restarted
        case failed
        case stale
    }

    private func monitorEngine(token: EngineLifetimeFence.Token) {
        monitor?.cancel()
        monitor = Task { [weak self] in
            var healthySince = Date()
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                // Fence the loop after every await. A quit or a new start
                // invalidates this token and owns the engine from then on.
                guard !Task.isCancelled,
                      let self,
                      self.lifetime.permits(token, stopping: self.stopping),
                      let engine = self.engine else { return }
                if !engine.isRunning {
                    self.model?.stopPolling()
                    // A dead user engine while a root tunnel runs must not be
                    // restarted. A new user engine would not own the live
                    // routes, and the paired view would disagree with the
                    // tunnel. Stop the elevated tunnel first, then report the
                    // loss. A user engine with no tunnel may restart once.
                    if self.model?.hasUnresolvedTunnelLifecycle == true {
                        // An uncertain cleanup is stronger evidence than the
                        // user engine loss. Carry that result into the lost
                        // screen; a stopped status is not cleanup proof.
                        let stopOutcome = await self.model?.quitStopOutcome() ?? .notRunning
                        guard self.lifetime.permits(token, stopping: self.stopping),
                              self.engine != nil else { return }
                        self.engine = nil
                        self.model = nil
                        self.port = nil
                        self.launchState = .lost(
                            EngineLaunchFailure.fromUserEngineLoss(
                                cleanup: stopOutcome.message,
                                kind: self.tunnelSession?.cleanup.pending?.kind
                            )
                        )
                        return
                    }
                    switch await self.restartUserEngine(engine, token: token) {
                    case .restarted:
                        healthySince = Date()
                    case .failed, .stale:
                        return
                    }
                } else if Date().timeIntervalSince(healthySince) >= 60 {
                    // One healthy minute gives the engine a new restart budget.
                    engine.markHealthy(); healthySince = Date()
                }
            }
        }
    }

    // The stop/restart gate is shared with prepareToQuit. A quit that begins
    // while a restart is in flight waits for the restart to finish, then stops
    // the same process. A restart that wakes after the quit sees a stale token
    // and starts nothing.
    private func restartUserEngine(_ engine: BackendProcess, token: EngineLifetimeFence.Token) async -> RestartResult {
        await stopRestartGate.acquire()
        let result = await restartUserEngineHoldingGate(engine, token: token)
        await stopRestartGate.release()
        return result
    }

    private func restartUserEngineHoldingGate(_ engine: BackendProcess, token: EngineLifetimeFence.Token) async -> RestartResult {
        guard lifetime.permits(token, stopping: stopping), !quitting else { return .stale }
        do {
            try await engine.restartOnce()
            guard let port = engine.port else { throw BackendError.timeout }
            try await UserEngineCheck.verify(HTTPBackend(port: port, secret: engine.secret))
            guard lifetime.permits(token, stopping: stopping), !quitting else {
                await engine.stop()
                return .stale
            }
            self.port = port
            handoff.set(engine.handoffReadDescriptor)
            let model = makeModel(process: engine)
            self.model = model; model.startPolling()
            launchState = .running
            return .restarted
        } catch {
            // Make the error panel able to start a new engine.
            let failure = EngineLaunchFailure.fromUserEngine(error)
            guard lifetime.permits(token, stopping: stopping), !quitting else {
                await engine.stop()
                return .stale
            }
            self.model = nil
            await engine.stop()
            guard lifetime.permits(token, stopping: stopping), !quitting else { return .stale }
            self.engine = nil
            self.port = nil
            launchState = .failed(failure)
            return .failed
        }
    }

    // Stop the tunnel and the engine for quit. The tunnel stop is attempted
    // through the engine API first, so a clean route removal is observed. The
    // engine process stop follows with the helper's real result. An unknown
    // result is returned as uncertain and is never reported as a clean stop.
    func prepareToQuit() async -> QuitPreparation {
        beginQuit()
        stopping = true
        monitor?.cancel(); monitor = nil
        launchCancellation?.cancel()
        let previous = launchState
        if previous != .stopping {
            stateBeforeQuit = previous
        }
        // A cleanup retry can be connecting to the helper. Let it finish before
        // the quit decides whether cleanup is confirmed. A retry that never
        // answers is an uncertain quit, not a clean one.
        if cleanupRetryInFlight {
            let deadline = Date().addingTimeInterval(5)
            while cleanupRetryInFlight, Date() < deadline {
                try? await Task.sleep(nanoseconds: 50_000_000)
            }
            if cleanupRetryInFlight {
                let message = "A cleanup retry was still running when the quit began."
                tunnelSession?.cleanup.recordPendingStop(message)
                return QuitPreparation(outcome: .uncertain(message), generation: lifetime.quitGeneration)
            }
        }
        // A tunnel start that is still asking for authorization or preparing
        // a root engine must settle before quit reports a clean stop. Wait a
        // bounded time. A system prompt can stay open indefinitely, so a
        // timeout is an uncertain quit, never a clean one.
        // The start flag lives in the shared cleanup state, so a start that an
        // earlier model began still counts after a rebuild or a loss.
        let sharedStart = tunnelSession?.cleanup.hasStartInFlight == true
        if model?.tunnelActionIsInFlight == true || sharedStart {
            let settled: Bool
            if let model {
                settled = await model.waitForTunnelActionToSettle(within: 5)
            } else {
                settled = await tunnelSession?.cleanup.waitForStartToSettle(within: 5) ?? true
            }
            if !settled {
                let message = EngineLaunchText.stopUnverified
                tunnelSession?.cleanup.recordPendingStop(message)
                model?.stopPolling()
                return QuitPreparation(outcome: .uncertain(message), generation: lifetime.quitGeneration)
            }
        }
        let wasLaunching = launchTask != nil && engine == nil
        let hadEngine = engine != nil
        if hadEngine || wasLaunching { launchState = .stopping }
        diagnosticsCopied = false
        model?.stopPolling()
        // Do not wait for an administrator prompt. The cancellation token stops
        // a start that has not claimed the prompt yet. Process exit closes the
        // helper connection, which also stops a late engine.
        if wasLaunching {
            // Give the cancelled user-engine launch a bounded chance to stop
            // its own process. A launch that is still running after that is an
            // uncertain quit, not a clean one.
            for _ in 0..<100 {
                if launchTask == nil { break }
                try? await Task.sleep(nanoseconds: 50_000_000)
            }
            if launchTask != nil {
                return QuitPreparation(
                    outcome: .uncertain("The app engine was still starting when the quit began."),
                    generation: lifetime.quitGeneration
                )
            }
            return QuitPreparation(outcome: .startPending, generation: lifetime.quitGeneration)
        }
        // Wait for a monitor restart to finish before stopping the same
        // process. A queued restart sees the generation change and starts
        // nothing after this quit.
        await stopRestartGate.acquire()
        let tunnel = await stopTunnelForQuit(previous: previous)
        // The app-owned cleanup state is the final word. A model that went away
        // must not turn a still-pending helper stop into a clean quit.
        let pendingCleanup = tunnelSession?.cleanup.pendingMessage
        let tunnelOutcome = tunnel.isUncertain
            ? tunnel
            : (pendingCleanup.map { EngineStopOutcome.uncertain($0) } ?? tunnel)
        let user = engine
        let wasRunning = user?.isRunning == true
        await user?.stop()
        let process: EngineStopOutcome
        if let user, wasRunning && user.isRunning {
            process = .uncertain("The engine did not stop.")
        } else {
            process = wasRunning ? .stopped : .notRunning
        }
        engine = nil
        model = nil
        port = nil
        await stopRestartGate.release()
        return QuitPreparation(
            outcome: EngineStopOutcome.combine(tunnel: tunnelOutcome, engine: process),
            generation: lifetime.quitGeneration
        )
    }

    // The model's backend routes the stop to the elevated engine while a
    // tunnel runs and to the user engine otherwise. The elevated helper stop
    // reports its own result through the same path.
    private func stopTunnelForQuit(previous: EngineLaunchState) async -> EngineStopOutcome {
        guard let model else {
            if let failure = previous.failure, failure.kind == .cleanup {
                return .uncertain(failure.message)
            }
            var wasLost = false
            if case .lost = previous { wasLost = true }
            return wasLost ? .uncertain(Strings.helperLost) : .notRunning
        }
        return await model.quitStopOutcome()
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
        // Command Q does not call Coordinator.quit(). Set the same wait state
        // here so the menu never offers Quit while the stop is running.
        coordinator?.beginQuit()
        Task { @MainActor in
            let preparation = await coordinator?.prepareToQuit()
                ?? QuitPreparation(outcome: .notRunning, generation: 0)
            if preparation.outcome.isUncertain {
                let alert = NSAlert()
                alert.alertStyle = .warning
                alert.messageText = "HotspotShade could not confirm that the tunnel stopped."
                alert.informativeText = "\(preparation.outcome.message ?? "The engine did not report a clean stop.")\n\nCheck the tunnel before you use the network again. Quitting now closes the app without reporting a clean stop."
                alert.addButton(withTitle: "Stay")
                alert.addButton(withTitle: "Quit Anyway")
                NSApp.activate(ignoringOtherApps: true)
                if alert.runModal() == .alertFirstButtonReturn {
                    terminating = false
                    coordinator?.cancelQuit(preparation)
                    sender.reply(toApplicationShouldTerminate: false)
                    return
                }
            }
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
                    coordinator.startIfNeeded()
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
        // A quit keeps the stopping screen in front of the dashboard. The app
        // does not claim a clean stop while the stop is still running.
        if coordinator.launchState == .stopping {
            launchContent
        } else if let model = coordinator.model {
            MainWindowView(model: model)
        } else {
            launchContent
        }
    }

    @ViewBuilder private var settingsContent: some View {
        if coordinator.launchState == .stopping {
            launchContent
        } else if let model = coordinator.model {
            SettingsView(model: model, letPingWork: coordinator.letPingWork, onSetLetPingWork: { coordinator.setLetPingWork($0) })
        } else {
            launchContent
        }
    }

    private var launchContent: some View {
        EngineLaunchView(
            state: coordinator.launchState,
            diagnosticsCopied: coordinator.diagnosticsCopied,
            onStart: { coordinator.start() },
            onRetry: { coordinator.retry() },
            onCopyDiagnostics: { coordinator.copyDiagnostics() }
        )
    }

    private var menu: MenuBarContent {
        if coordinator.launchState == .stopping {
            return EngineLaunchMenu.content(state: .stopping, quitting: coordinator.quitting)
        }
        if let model = coordinator.model {
            return MenuBarContentBuilder.build(model.screenModel, quitting: coordinator.quitting)
        }
        return EngineLaunchMenu.content(state: coordinator.launchState, quitting: coordinator.quitting)
    }

    private var menuContent: some View {
        MenuBarMenu(
            content: menu,
            onAction: { coordinator.perform($0) },
            onOpen: { openMainWindow() },
            onCopyDiagnostics: { coordinator.copyDiagnostics() },
            onSettings: { openSettingsWindow() },
            onQuit: { coordinator.quit() }
        )
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
                    switch toggle.kind {
                    case .turnOn: coordinator.perform(.turnOn)
                    case .turnOff: coordinator.perform(.turnOff)
                    default: break
                    }
                }
                .keyboardShortcut(.return, modifiers: .command)
                .disabled(!toggle.isEnabled)
                // The Tunnel menu Turn on item explains the administrator
                // prompt. A disabled item keeps its own reason.
                .help(toggle.help ?? (toggle.kind == .turnOn ? UIStrings.adminAuthorization : ""))
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
