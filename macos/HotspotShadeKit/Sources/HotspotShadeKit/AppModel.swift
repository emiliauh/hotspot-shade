import Foundation
import Combine

// The visible screen. It identifies the state for colors and tests. The text
// and the action come from the derive table, not from this enum.
public enum Screen: Equatable {
    case unpaired
    case notTrusted
    case pairing
    case needsSourceDevice
    case proxyOff
    case ready
    case starting
    case on
    case stopping
    case unknown
    case needsAttention(String)
}

// The one primary action on the main card.
public enum PrimaryAction: Equatable {
    case pair, pairAgain, turnOn, turnOff, retry, checkNow
    public var label: String {
        switch self {
        case .pair: return Strings.pair
        case .pairAgain: return Strings.pairAgain
        case .turnOn: return Strings.turnOn
        case .turnOff: return Strings.turnOff
        case .retry: return Strings.tryAgain
        case .checkNow: return Strings.checkNow
        }
    }
}

public struct DashboardState: Equatable {
    public var screen: Screen
    public var title: String
    public var subtitle: String
    public var action: PrimaryAction?
    public var pairedLine: String
    public init(screen: Screen, title: String, subtitle: String, action: PrimaryAction?, pairedLine: String) {
        self.screen = screen; self.title = title; self.subtitle = subtitle; self.action = action; self.pairedLine = pairedLine
    }
}

public enum PairingPhase: Equatable { case idle, starting, confirming, paired, failed }
// How much of this engine launch has passed since the last automatic pairing
// attempt. The table uses it to allow one start and the 10 s retry.
public enum LaunchPhase: Equatable { case notAttempted, waiting, due }
public enum TunnelOperation: Equatable { case starting, stopping }
// The action for the Try again button. A start failure must retry the start,
// not only read the status.
enum RetryTarget: Equatable { case refresh, start, stop, pair }
// How much this app can trust the last status answer. A stale status keeps the
// last screen. An unavailable status never claims that the tunnel is on or off.
public enum StatusFreshness: Equatable { case fresh, stale, unavailable }

// The state of the failure list in Settings. The person opens the section or
// presses Refresh, so the list never polls.
public enum FailuresState: Equatable { case idle, loading, loaded, empty, unavailable, error(String) }

// The result of one Forget request. The app shows a calm Not paired screen for
// every case. A blocked request is not an error: the person must turn the
// tunnel off first.
public enum ForgetResult: Equatable {
    // The local pairing is gone. The phase is the engine forget state.
    case done(ForgetPhase)
    // The tunnel still runs, so the engine was not asked to forget.
    case blockedByTunnel
    // The request failed. The text is plain.
    case failed(String)
    public var blockedByTunnel: Bool { if case .blockedByTunnel = self { return true }; return false }
    public var message: String? {
        switch self {
        case .done(let phase): return ForgetMessages.text(for: phase)
        case .blockedByTunnel: return Strings.forgetBlocked
        case .failed(let text): return Strings.sanitized(text)
        }
    }
}

// The three plain texts for the engine forget state.
public enum ForgetMessages {
    public static func text(for phase: ForgetPhase) -> String? {
        switch phase {
        case .pending: return Strings.forgetPending
        case .confirmed: return Strings.forgetConfirmed
        case .notDelivered: return Strings.forgetNotDelivered
        case .none, .unknown: return nil
        }
    }
}

// Every input to the visible state. The table is pure, so every row is a test.
public struct DeriveInput: Equatable {
    public var running: Bool
    public var paired: Bool
    public var phone: PhoneState
    public var phoneMessage: String?
    public var pairing: PairingPhase
    public var suppressAutoPair: Bool
    public var launch: LaunchPhase
    public var operation: TunnelOperation?
    public var error: String?
    // New inputs. Every one has a safe default for the first rows.
    public var freshness: StatusFreshness
    public var tokenRejected: String?
    public var trustedBySource: Bool?
    public var forget: ForgetPhase
    public var forgotIntent: Bool
    public var sourceDeviceWarning: Bool
    public init(running: Bool = false, paired: Bool = false, phone: PhoneState = .unknown, phoneMessage: String? = nil, pairing: PairingPhase = .idle, suppressAutoPair: Bool = false, launch: LaunchPhase = .notAttempted, operation: TunnelOperation? = nil, error: String? = nil, freshness: StatusFreshness = .fresh, tokenRejected: String? = nil, trustedBySource: Bool? = nil, forget: ForgetPhase = .none, forgotIntent: Bool = false, sourceDeviceWarning: Bool = false) {
        self.running = running; self.paired = paired; self.phone = phone; self.phoneMessage = phoneMessage
        self.pairing = pairing; self.suppressAutoPair = suppressAutoPair; self.launch = launch
        self.operation = operation; self.error = error
        self.freshness = freshness; self.tokenRejected = tokenRejected
        self.trustedBySource = trustedBySource; self.forget = forget
        self.forgotIntent = forgotIntent; self.sourceDeviceWarning = sourceDeviceWarning
    }
}

public struct DeriveResult: Equatable {
    public var dashboard: DashboardState
    public var startsAutoPair: Bool
    public init(dashboard: DashboardState, startsAutoPair: Bool) { self.dashboard = dashboard; self.startsAutoPair = startsAutoPair }
}

@MainActor public final class AppModel: ObservableObject {
    // The engine probes the source device every 2 seconds while a phone tunnel
    // runs. A result older than this is not proof of a failure.
    private static let sourceProbeFresh: TimeInterval = 10
    @Published public private(set) var dashboard: DashboardState
    @Published public private(set) var screen: Screen
    @Published public private(set) var status = Status()
    @Published public private(set) var pairing = PairState()
    @Published public private(set) var isPairing = false
    @Published public private(set) var sourceDeviceWarning = false
    @Published public private(set) var logLines: [LogLine] = []
    @Published public private(set) var failuresState: FailuresState = .idle
    @Published public private(set) var failureRows: [FailureRow] = []
    @Published public private(set) var reportCopied = false
    // The engine did not answer for 3 s. Keep the last screen.
    @Published public private(set) var statusIsStale = false
    // The engine did not answer for 10 s. Never claim On or Off.
    @Published public private(set) var statusUnavailable = false
    // The last Forget request. The app keeps a calm screen for every case.
    @Published public private(set) var forgetResult: ForgetResult?
    // The engine forget state. It is "none" before the first request.
    @Published public private(set) var forgetProgress: ForgetPhase = .none
    @Published public private(set) var linkInfo: WiFiLinkInfo?
    @Published public private(set) var notificationAuthorization: NotificationAuthorization = .notDetermined
    @Published public private(set) var diagnosticsCopied = false
    // The window visibility decides the status poll interval: 1 s or 5 s.
    @Published public private(set) var windowVisible = true
    // The app sets this when its window loses focus. Notifications stay quiet
    // for events 2 to 4 while it is true.
    @Published public private(set) var isFrontmost = true
    public private(set) var failureReport = ""
    // The last diagnostics text. Tests compare it. The app can show it.
    public private(set) var lastDiagnosticsText = ""
    private let backend: BackendClient
    private let now: () -> Date
    private let pingSetting: PingSettingStore
    private let pasteboard: PasteboardWriting
    private let forgetIntentStore: ForgetIntentStore
    private let notificationSink: NotificationSink
    private let settingsOpener: SettingsOpening
    private let linkProvider: LinkInfoProvider
    private let macOSVersion: String
    private let appVersion: String
    private var lastAutoPair: Date?
    // Cancel stops automatic pairing for the rest of this launch. A forget
    // intent is stronger: it survives a relaunch until an explicit Pair.
    private var suppressAutoPair = false
    private var polling: Task<Void, Never>?
    private var pairPolling: Task<Void, Never>?
    // The notification permission request runs without the tunnel action. A
    // system prompt that never answers must not hold the start or the stop.
    private var notificationPermissionTask: Task<Void, Never>?
    private var notificationPermissionInFlight = false
    private var retryTarget: RetryTarget = .refresh
    private var pairingGeneration = 0
    private var operation: TunnelOperation?
    private var failure: String?
    private var tokenRejected: String?
    private var unreachableSince: Date?
    private var busy = false
    private var statusFailureSince: Date?
    private var lastLinkCheck: Date?
    private var notificationPolicy = NotificationPolicy()
    private var requestedNotificationPermission = false
    private var notificationsPrimed = false
    private var lastStopKey: String?
    private var forgetInFlight = false
    // An explicit Pair resets the old forget text. Ignore an old engine
    // forget state until the engine reports "none" again.
    private var ignoreForgetState = false

    public init(backend: BackendClient, now: @escaping () -> Date = Date.init, pingSetting: PingSettingStore = UserDefaultsPingSetting(), pasteboard: PasteboardWriting = NoPasteboard(), forgetIntent: ForgetIntentStore = MemoryForgetIntent(), notificationSink: NotificationSink = NoNotificationSink(), settingsOpener: SettingsOpening = NoSettingsOpener(), linkProvider: LinkInfoProvider = NoLinkInfoProvider(), macOSVersion: String = ProcessInfo.processInfo.operatingSystemVersionString, appVersion: String = AppModel.bundleVersion()) {
        let initial = DashboardState(screen: .needsSourceDevice, title: Strings.waiting, subtitle: Strings.openSourceDeviceApp, action: nil, pairedLine: Strings.notPaired)
        dashboard = initial
        screen = initial.screen
        self.backend = backend
        self.now = now
        self.pingSetting = pingSetting
        self.pasteboard = pasteboard
        self.forgetIntentStore = forgetIntent
        self.notificationSink = notificationSink
        self.settingsOpener = settingsOpener
        self.linkProvider = linkProvider
        self.macOSVersion = macOSVersion
        self.appVersion = appVersion
        self.notificationPolicy = NotificationPolicy(now: now)
    }
    deinit { polling?.cancel(); pairPolling?.cancel(); notificationPermissionTask?.cancel() }

    // The app version and build from the bundle. Tests inject a fixed value.
    public nonisolated static func bundleVersion(bundle: Bundle = .main) -> String {
        let version = bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "unknown"
        let build = bundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String
        return build.map { "\(version) (\($0))" } ?? version
    }

    // MARK: - Polling

    public func startPolling() {
        guard polling == nil else { return }
        polling = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                await self.refresh()
                let interval = UInt64(self.statusPollInterval * 1_000_000_000)
                try? await Task.sleep(nanoseconds: interval)
            }
        }
    }
    public func stopPolling() { polling?.cancel(); polling = nil; pairPolling?.cancel(); pairPolling = nil; pairingGeneration += 1 }

    // The window calls this when its visibility changes. A visible window polls
    // every second and refreshes at once. A hidden window polls every 5 s.
    public func setWindowVisible(_ visible: Bool) {
        guard windowVisible != visible else { return }
        windowVisible = visible
        refreshLinkIfNeeded(force: true)
        if polling != nil {
            polling?.cancel(); polling = nil
            startPolling()
        } else if visible {
            // A view can set visibility before it starts polling. Refresh at
            // once in that case too.
            Task { await self.refresh() }
        }
    }
    public func setFrontmost(_ frontmost: Bool) { isFrontmost = frontmost }
    public var statusPollInterval: TimeInterval { windowVisible ? 1 : 5 }

    // MARK: - Refresh

    public func refresh() async {
        // The failure window starts when the request starts. A 3 s timeout is
        // then stale at once, as if the engine had not answered for 3 s.
        let attempt = now()
        do {
            status = try await backend.status(timeout: 3)
            statusFailureSince = nil
            // Keep an action error until the next attempt. A successful status
            // read cannot prove that a failed start succeeded. Clearing it here
            // hid every start error within one poll.
            updateSourceDeviceWarning()
            adoptForgetState()
            refreshLinkIfNeeded()
            await evaluateNotifications()
            updateFreshness()
            let result = deriveNow()
            apply(result.dashboard)
            guard result.startsAutoPair else { return }
            lastAutoPair = now()
            await startPairing()
        } catch {
            if Task.isCancelled { return }
            // Keep the last screen. The freshness window decides when the
            // status is stale and when it is unavailable.
            if statusFailureSince == nil { statusFailureSince = attempt }
            // Do not clear an operation error. A status failure only changes
            // the freshness of the last screen.
            updateFreshness()
            apply(deriveNow().dashboard)
            await evaluateNotifications()
        }
    }

    private func updateFreshness() {
        let freshness = statusFreshness
        statusIsStale = freshness != .fresh
        statusUnavailable = freshness == .unavailable
    }
    public var statusFreshness: StatusFreshness {
        guard let since = statusFailureSince else { return .fresh }
        let age = now().timeIntervalSince(since)
        if age >= 10 { return .unavailable }
        if age >= 3 { return .stale }
        return .fresh
    }
    // The exact text for a stale status. Nil when the status is fresh.
    public var staleStatusText: String? { statusFreshness == .fresh ? nil : Strings.staleStatus }
    // The text when statusIsStale is true. The same text as staleStatusText.
    public var statusStaleText: String? { statusIsStale ? Strings.staleStatus : nil }

    private func adoptForgetState() {
        guard let phase = status.forget?.phase else { return }
        if phase == .none {
            ignoreForgetState = false
            forgetProgress = .none
            return
        }
        guard !ignoreForgetState else { return }
        forgetProgress = phase
        // Keep a completed Forget result in step with the engine. The current
        // engine reports the final state in the status, not in the response.
        if case .some(.done) = forgetResult { forgetResult = .done(phase) }
    }

    // MARK: - Derive table

    // The only place that reads the visible state. It is pure and it has one
    // row for every combination that the app can see.
    public nonisolated static func derive(_ input: DeriveInput) -> DeriveResult {
        let startsAutoPair = !input.running
            && !input.paired
            && input.phone == .unpaired
            && !input.suppressAutoPair
            && !input.forgotIntent
            && input.operation == nil
            && (input.error ?? "").isEmpty
            && (input.pairing == .idle || input.pairing == .failed)
            && input.launch != .waiting
            && input.freshness == .fresh
            && input.tokenRejected == nil
        return DeriveResult(dashboard: dashboard(input), startsAutoPair: startsAutoPair)
    }

    private nonisolated static func dashboard(_ input: DeriveInput) -> DashboardState {
        let pairedLine = input.paired ? Strings.paired : Strings.notPaired
        func state(_ screen: Screen, _ title: String, _ subtitle: String, _ action: PrimaryAction?) -> DashboardState {
            DashboardState(screen: screen, title: title, subtitle: subtitle, action: action, pairedLine: pairedLine)
        }
        switch input.operation {
        case .starting: return state(.starting, Strings.startingTunnel, Strings.takesAMinute, nil)
        case .stopping: return state(.stopping, Strings.stopping, Strings.takesAMinute, nil)
        case .none: break
        }
        // The engine rejected the saved token at start. Pair again.
        if let token = input.tokenRejected, !token.isEmpty {
            return state(.needsAttention(token), Strings.pairAgain, Strings.sanitized(token) ?? token, .pairAgain)
        }
        // After 10 s without an answer the app does not claim On or Off.
        if input.freshness == .unavailable {
            return state(.unknown, Strings.unknownTitle, Strings.statusUnavailableSubtitle, .checkNow)
        }
        if let error = input.error, !error.isEmpty {
            return state(.needsAttention(error), Strings.attention, Strings.sanitized(error) ?? error, .retry)
        }
        if input.running {
            // The tunnel stays On even when the source device stopped
            // answering or forgot this target device. The attention list says
            // what happened.
            return state(.on, Strings.on, Strings.sanitized(input.phoneMessage) ?? Strings.onSubtitle, .turnOff)
        }
        if input.pairing == .starting || input.pairing == .confirming {
            return state(.pairing, Strings.pairing, Strings.pairingSubtitle, nil)
        }
        switch input.phone {
        case .unpaired:
            if input.paired { return state(.needsSourceDevice, Strings.waiting, Strings.openSourceDeviceApp, nil) }
            return unpairedState(input, state)
        case .notTrusted:
            if input.paired { return state(.notTrusted, Strings.notTrustedTitle, Strings.notTrustedSubtitle, .pairAgain) }
            return unpairedState(input, state)
        case .proxyOff:
            if input.paired { return state(.proxyOff, Strings.paired, Strings.proxyOffSubtitle, nil) }
            return unpairedState(input, state)
        case .ready:
            if input.paired { return state(.ready, Strings.ready, Strings.sanitized(input.phoneMessage) ?? Strings.readySubtitle, .turnOn) }
            return unpairedState(input, state)
        case .connected:
            // A tunnel that reports connected must also report running. If it
            // does not, keep the tunnel off in the window.
            if input.paired { return state(.ready, Strings.ready, Strings.readySubtitle, .turnOn) }
            return unpairedState(input, state)
        case .noHotspot:
            return state(.needsSourceDevice, Strings.waiting, Strings.sanitized(input.phoneMessage) ?? Strings.noHotspotSubtitle, nil)
        case .notRunning:
            return state(.needsSourceDevice, Strings.waiting, Strings.sanitized(input.phoneMessage) ?? Strings.notRunningSubtitle, nil)
        case .notResponding:
            return state(.needsSourceDevice, Strings.waiting, Strings.notRespondingSubtitle, nil)
        case .unknown:
            return state(.unknown, Strings.unknownTitle, Strings.sanitized(input.phoneMessage) ?? Strings.unknownSubtitle, nil)
        }
    }

    // The calm Not paired screen. It has one Pair action and no animation.
    // A forget message wins over the pair hint. The source device hint shows
    // only when the source device still knows this target device.
    private nonisolated static func unpairedState(_ input: DeriveInput, _ state: (Screen, String, String, PrimaryAction?) -> DashboardState) -> DashboardState {
        if let message = ForgetMessages.text(for: input.forget) {
            return state(.unpaired, Strings.notPaired, message, .pair)
        }
        if input.trustedBySource == true {
            return state(.unpaired, Strings.notPaired, Strings.trustedBySource, .pair)
        }
        return state(.unpaired, Strings.notPaired, Strings.unpairedSubtitle, .pair)
    }

    private func pairingPhase() -> PairingPhase {
        if pairing.state == "failed" { return .failed }
        if isPairing { return pairing.state == "confirm" ? .confirming : .starting }
        if pairing.state == "paired" { return .paired }
        return .idle
    }
    private func launchPhase() -> LaunchPhase {
        guard let last = lastAutoPair else { return .notAttempted }
        return now().timeIntervalSince(last) >= 10 ? .due : .waiting
    }
    private func currentInput() -> DeriveInput {
        DeriveInput(running: status.running == true, paired: status.paired == true, phone: PhoneState(raw: status.phone?.state), phoneMessage: status.phone?.message, pairing: pairingPhase(), suppressAutoPair: suppressAutoPair, launch: launchPhase(), operation: operation, error: failure, freshness: statusFreshness, tokenRejected: tokenRejected, trustedBySource: status.phone?.trustedBySource, forget: forgetProgress, forgotIntent: forgetIntentStore.forgotIntent, sourceDeviceWarning: sourceDeviceWarning)
    }
    private func deriveNow() -> DeriveResult { Self.derive(currentInput()) }
    private func apply(_ state: DashboardState) { dashboard = state; screen = state.screen }
    private func rederive() { updateFreshness(); apply(deriveNow().dashboard) }

    // A warning needs a continuous 10 s failure while the tunnel runs. One
    // probe miss must not flash it. An old probe result is not proof of a
    // failure, so it clears the warning instead of starting one.
    private func updateSourceDeviceWarning() {
        guard status.running == true else { unreachableSince = nil; sourceDeviceWarning = false; return }
        if sourceProbeIsStale() {
            unreachableSince = nil
            sourceDeviceWarning = false
            return
        }
        switch PhoneState(raw: status.phone?.state) {
        case .notResponding, .notRunning, .noHotspot:
            if unreachableSince == nil { unreachableSince = now() }
            if let since = unreachableSince, !sourceDeviceWarning, now().timeIntervalSince(since) >= 10 { sourceDeviceWarning = true }
        default:
            // Any other state means that the source device answered. The
            // warning clears before the next failure can start a new window.
            unreachableSince = nil
            sourceDeviceWarning = false
        }
    }

    // True when the engine sent a probe time that is older than the engine's
    // freshness window. A missing time is an older engine, not a stale result.
    private func sourceProbeIsStale() -> Bool {
        guard let checked = status.phone?.checkedAt else { return false }
        return now().timeIntervalSince1970 - checked > Self.sourceProbeFresh
    }

    // MARK: - Status values for the views

    // Show a count only while the tunnel runs. The engine sends the count.
    public var connectionsLabel: String? {
        guard statusFreshness != .unavailable, status.running == true, let count = status.phone?.connections else { return nil }
        return Strings.connections(count)
    }
    // The one plain line about ping. It needs a running tunnel and a value
    // from the engine. A missing value shows no line.
    public nonisolated static func pingLine(running: Bool, icmpEnabled: Bool?) -> String? {
        guard running, let icmpEnabled else { return nil }
        return icmpEnabled ? Strings.pingOn : Strings.pingOff
    }
    public var pingLine: String? {
        guard statusFreshness != .unavailable else { return nil }
        return Self.pingLine(running: status.running == true, icmpEnabled: status.icmp_enabled)
    }
    // The age of the last probe. The text uses the injected clock.
    public var lastCheckedText: String? {
        guard let checked = status.phone?.checkedAt, checked.isFinite else { return nil }
        let elapsed = now().timeIntervalSince1970 - checked
        guard elapsed.isFinite else { return nil }
        let age = max(0, elapsed)
        if age < 10 { return Strings.checkedJustNow }
        if age < 60 { return Strings.checkedSeconds(Int(age)) }
        guard let minutes = Int(exactly: (age / 60).rounded(.down)) else { return nil }
        return Strings.checkedMinutes(minutes)
    }
    public var lastStopLine: String? {
        // The engine always sends the object. A null reason means no stop.
        guard let stop = status.last_stop, let reason = stop.reason, !reason.isEmpty else { return nil }
        let phrase: String
        switch stop.kind {
        case .user: phrase = "You turned the tunnel off."
        case .hotspotLost: phrase = "The hotspot turned off."
        case .sourceDeviceGone: phrase = "The source device stopped answering."
        case .error: phrase = Strings.sanitized(status.last_stop_message) ?? "The tunnel stopped with an error."
        case .unknown: phrase = "The reason is unknown."
        }
        return atText(phrase, at: stop.at)
    }
    // Add the time of the stop. A missing value keeps the plain sentence.
    private func atText(_ phrase: String, at timestamp: Double?) -> String {
        let base = "Last stop: \(phrase)"
        guard let timestamp else { return base }
        let time = Date(timeIntervalSince1970: timestamp).formatted(date: .omitted, time: .shortened)
        return "\(base) \(time)."
    }
    public var linkAdvice: [String] {
        LinkAdvice.advice(running: status.running == true, statusIface: status.iface, link: linkInfo)
    }
    // True when macOS denied notification permission. A view shows
    // notificationsSettingsText and a button that calls openNotificationSettings().
    public var notificationsDenied: Bool { notificationAuthorization == .denied }
    // The one plain Settings line for a denied permission. Nil otherwise.
    public var notificationsSettingsText: String? { notificationsDenied ? Strings.notificationsDenied : nil }
    // True when a Settings button must offer to open System Settings.
    public var canOpenNotificationSettings: Bool { notificationsDenied }
    public var forgetIsBlocked: Bool { forgetResult?.blockedByTunnel == true }
    // The typed "the tunnel still runs" result. The view offers
    // "Turn off and forget" and calls turnOffAndForget().
    public var forgetBlockedByTunnel: Bool { forgetIsBlocked }
    public var forgetMessage: String? { ForgetMessages.text(for: forgetProgress) ?? forgetResult?.message }
    public var activityLine: String { Strings.sanitized(status.phone?.message) ?? Strings.notConnected }

    // The one model that a view draws.
    public var screenModel: ScreenModel {
        ScreenPresentation.build(PresentationInput(derive: currentInput(), pingLine: pingLine, connectionsLabel: connectionsLabel, lastStopLine: lastStopLine, lastCheckedText: lastCheckedText, linkAdvice: linkAdvice, notificationsDenied: notificationsDenied, forgetBlocked: forgetIsBlocked))
    }

    // MARK: - Link quality

    // Read the Wi-Fi link at most once every 10 s while the window is visible.
    public func refreshLinkIfNeeded(force: Bool = false) {
        guard windowVisible else { return }
        if !force, let last = lastLinkCheck, now().timeIntervalSince(last) < 10 { return }
        lastLinkCheck = now()
        linkInfo = linkProvider.currentLink()
    }

    // MARK: - Actions

    public func perform(_ action: PrimaryAction) async {
        switch action {
        case .pair, .pairAgain: await beginPairing()
        case .turnOn, .turnOff: await toggle()
        case .retry: await retryLastAction()
        case .checkNow: await checkNow()
        }
    }

    // Try again repeats the action that failed. A start error must not become
    // a status refresh that leaves the tunnel off.
    private func retryLastAction() async {
        failure = nil
        switch retryTarget {
        case .start, .stop: await toggle()
        case .pair: await beginPairing()
        case .refresh: await refresh()
        }
    }

    // The Pair action calls this. An explicit press clears the Cancel guard
    // and the stored forget intent, so automatic pairing can start again.
    public func beginPairing() async {
        retryTarget = .pair
        suppressAutoPair = false
        forgetIntentStore.forgotIntent = false
        tokenRejected = nil
        forgetResult = nil
        forgetProgress = .none
        ignoreForgetState = true
        await startPairing()
    }
    private func startPairing() async {
        guard !busy && !isPairing else { return }
        retryTarget = .pair
        busy = true; isPairing = true; pairing = PairState(); failure = nil
        pairPolling?.cancel(); pairPolling = nil
        pairingGeneration += 1
        let generation = pairingGeneration
        defer { busy = false }
        rederive()
        do {
            try await backend.startPairing()
            guard generation == pairingGeneration else { return }
            pairPolling = Task { [weak self] in
                while !Task.isCancelled {
                    await self?.refreshPairing(generation: generation)
                    try? await Task.sleep(nanoseconds: 700_000_000)
                }
            }
        } catch {
            guard generation == pairingGeneration else { return }
            isPairing = false
            pairing = PairState(state: "failed", error: error.localizedDescription)
            failure = error.localizedDescription
            rederive()
        }
    }
    // A test or a view can refresh the pairing state on its own.
    public func refreshPairing() async { await refreshPairing(generation: nil) }
    private func refreshPairing(generation: Int?) async {
        do {
            let value = try await backend.pairState()
            if let generation, generation != pairingGeneration { return }
            pairing = value
            if pairing.state == "paired" {
                retryTarget = .refresh
                isPairing = false; pairPolling?.cancel(); pairPolling = nil; pairingGeneration += 1
                // Probe at once, so the screen shows the new state without a
                // wait for the next poll.
                await probeNow()
                await refresh()
            } else if pairing.state == "failed" {
                isPairing = false; pairPolling?.cancel(); pairPolling = nil; pairingGeneration += 1
                rederive()
                await evaluateNotifications()
            } else {
                rederive()
                await evaluateNotifications()
            }
        } catch {
            if let generation, generation != pairingGeneration { return }
            isPairing = false; pairPolling?.cancel(); pairPolling = nil; pairingGeneration += 1
            pairing = PairState(state: "failed", error: error.localizedDescription)
            rederive()
        }
    }
    public func cancelPairing() async {
        retryTarget = .refresh
        suppressAutoPair = true
        guard !busy else { return }
        busy = true; defer { busy = false }
        pairingGeneration += 1
        pairPolling?.cancel(); pairPolling = nil; isPairing = false
        do { try await backend.cancelPairing(); await refresh() } catch { failure = error.localizedDescription; rederive() }
    }

    // Forget the source device. If the tunnel runs, do not ask the engine:
    // return the typed blocked result. The person can then use
    // turnOffAndForget().
    @discardableResult
    public func forget() async -> ForgetResult {
        if forgetInFlight { return forgetResult ?? .blockedByTunnel }
        forgetInFlight = true
        defer { forgetInFlight = false }
        // A new action replaces the old start or stop error.
        failure = nil
        forgetResult = nil
        // A Forget during pairing cancels pairing first, so no late pair result
        // can change the final state.
        if isPairing { await cancelPairing() }
        pairingGeneration += 1
        pairPolling?.cancel(); pairPolling = nil; isPairing = false
        // The person chose to forget. Persist the intent before the request,
        // so a blocked request cannot start automatic pairing later.
        forgetIntentStore.forgotIntent = true
        ignoreForgetState = false
        // A known running tunnel stops here. This path makes no engine call.
        var running = status.running == true
        if !running, let live = try? await backend.status(timeout: 2) {
            status = live
            statusFailureSince = nil
            running = live.running == true
        }
        if running {
            let result = ForgetResult.blockedByTunnel
            forgetResult = result
            rederive()
            return result
        }
        tokenRejected = nil
        do {
            let state = try await backend.forget()
            forgetProgress = state.phase
            let result = ForgetResult.done(state.phase)
            forgetResult = result
            // Probe at once, then read the full status.
            await probeNow()
            await refresh()
            return result
        } catch BackendError.forgetBlockedByTunnel {
            let result = ForgetResult.blockedByTunnel
            forgetResult = result
            rederive()
            return result
        } catch {
            let result = ForgetResult.failed(error.localizedDescription)
            forgetResult = result
            rederive()
            return result
        }
    }

    // Stop the tunnel, wait for the engine to report stopped, then forget.
    @discardableResult
    public func turnOffAndForget() async -> ForgetResult {
        if status.running == true || statusFreshness != .fresh {
            operation = .stopping; rederive()
            try? await backend.stopTunnel(timeout: 45)
            for _ in 0..<100 {
                if let live = try? await backend.status(timeout: 2), live.running != true { status = live; break }
                try? await Task.sleep(nanoseconds: 150_000_000)
            }
            operation = nil; rederive()
        }
        return await forget()
    }

    // Run one probe now, then refresh the status. A missing probe endpoint is
    // not an error. The last status stays in place.
    public func checkNow() async {
        failure = nil
        retryTarget = .refresh
        await probeNow()
        await refresh()
        refreshLinkIfNeeded(force: true)
    }
    private func probeNow() async {
        guard let phone = try? await backend.probe() else { return }
        status.phone = phone
        rederive()
    }

    public func toggle() async {
        guard !busy else { return }
        busy = true; defer { busy = false }
        failure = nil
        let turningOff = status.running == true
        retryTarget = turningOff ? .stop : .start
        // Show the operation before any await. A system permission request
        // must never leave the button looking as if the press did nothing.
        operation = turningOff ? .stopping : .starting
        rederive()
        do {
            if turningOff {
                try await backend.stopTunnel()
            } else {
                try await backend.startTunnel(experimentalICMP: pingSetting.letPingWork)
                tokenRejected = nil
                // Ask after the start. A permission alert must not compete
                // with the administrator prompt, and it must not hold the
                // start when the system never answers.
                requestNotificationPermissionInBackground()
            }
            retryTarget = .refresh
            operation = nil; await refresh()
        } catch BackendError.phoneTokenRejected(let message) {
            operation = nil
            tokenRejected = message.isEmpty ? Strings.phoneTokenRejected : message
            failure = nil
            rederive()
        } catch {
            operation = nil; failure = error.localizedDescription; rederive()
        }
    }
    // Read the live status before the quit decision. A failed read means the
    // tunnel may be on, so send stop in that case.
    public func stopForQuit() async {
        stopPolling(); operation = .stopping; rederive()
        var running = true
        do { running = try await backend.status(timeout: 2).running == true } catch { running = true }
        if running { try? await backend.stopTunnel(timeout: 45) }
    }
    public func loadLogs() async { retryTarget = .refresh; do { logLines = try await backend.logs(since: 0) } catch { failure = error.localizedDescription; rederive() } }

    // Store the next value. A running tunnel keeps the setting that it started
    // with. Only the next start uses the new value.
    public func setLetPingWork(_ enabled: Bool) { pingSetting.letPingWork = enabled }

    // MARK: - Notifications

    public func requestNotificationPermissionIfNeeded() async {
        let current = await notificationSink.authorizationStatus()
        notificationAuthorization = current
        guard !notificationPermissionInFlight,
              NotificationPolicy.shouldAskForPermission(status: current, asked: requestedNotificationPermission) else { return }
        requestedNotificationPermission = true
        notificationAuthorization = await notificationSink.requestAuthorization()
    }

    // Ask once, without holding the tunnel action. macOS can present the
    // permission alert while the app is not active, and its answer may never
    // arrive. The start and stop must not wait for it.
    private func requestNotificationPermissionInBackground() {
        guard !requestedNotificationPermission, !notificationPermissionInFlight else { return }
        notificationPermissionInFlight = true
        let sink = notificationSink
        notificationPermissionTask = Task { [weak self] in
            let current = await sink.authorizationStatus()
            guard let self, !Task.isCancelled else { return }
            self.notificationAuthorization = current
            guard NotificationPolicy.shouldAskForPermission(status: current, asked: self.requestedNotificationPermission) else {
                self.notificationPermissionInFlight = false
                return
            }
            self.requestedNotificationPermission = true
            let granted = await sink.requestAuthorization()
            guard !Task.isCancelled else { return }
            self.notificationAuthorization = granted
            self.notificationPermissionInFlight = false
        }
    }
    public func refreshNotificationAuthorization() async {
        notificationAuthorization = await notificationSink.authorizationStatus()
    }
    public func openNotificationSettings() { settingsOpener.openNotificationSettings() }

    private func evaluateNotifications() async {
        let key = "\(status.last_stop?.stableKey ?? "")|\(status.last_stop_message ?? "")"
        var newStop: LastStop?
        if !notificationsPrimed {
            notificationsPrimed = true
            lastStopKey = key
        } else if key != lastStopKey {
            lastStopKey = key
            newStop = status.last_stop
        }
        let attention = isPairing && (pairing.state == "confirm" || pairing.state == "failed")
        let input = NotificationInput(authorization: notificationAuthorization, isFrontmost: isFrontmost, running: status.running == true, phone: PhoneState(raw: status.phone?.state), sourceDeviceWarning: sourceDeviceWarning, pairingNeedsAttention: attention, lastStop: newStop, lastStopMessage: status.last_stop_message, error: failure ?? status.error)
        let output = notificationPolicy.evaluate(input)
        // Clear first. A new message in the same answer must stay delivered.
        if output.clearDelivered { await notificationSink.clearDelivered() }
        for message in output.messages { await notificationSink.post(message) }
    }

    // MARK: - Diagnostics

    // Copy one plain-text report. A missing endpoint adds an "unavailable"
    // line and never blocks the copy.
    public func copyDiagnostics() async {
        let diagnostics = try? await backend.diagnostics()
        let failures = try? await backend.failures()
        let lastStop = status.last_stop.flatMap { $0.reason == nil ? nil : $0 }
        let context = DiagnosticsContext(macOSVersion: macOSVersion, appVersion: appVersion, link: linkInfo, interfaceName: status.iface, icmpEnabled: status.icmp_enabled, lastStop: lastStop, lastStopMessage: status.last_stop_message, notificationAuthorization: notificationAuthorization, now: now())
        lastDiagnosticsText = DiagnosticsReport.text(diagnostics: diagnostics, failures: failures, context: context)
        pasteboard.write(lastDiagnosticsText)
        diagnosticsCopied = true
    }

    // MARK: - Failure list

    // Read the failure list once. The Settings panel calls this when the
    // person opens the section or presses Refresh. Without a running tunnel
    // the endpoint has no data, so the app does not ask for it.
    public func loadFailures() async {
        guard status.running == true else { failuresState = .idle; return }
        failuresState = .loading
        reportCopied = false
        do {
            let report = try await backend.failures()
            failureRows = FailureFormat.rows(report)
            failureReport = FailureFormat.report(report)
            failuresState = failureRows.isEmpty ? .empty : .loaded
        } catch BackendError.unavailable {
            clearFailures(); failuresState = .unavailable
        } catch {
            clearFailures(); failuresState = .error(error.localizedDescription)
        }
    }
    // Put the last report on the pasteboard. The text holds no credentials.
    public func copyReport() {
        guard !failureReport.isEmpty else { return }
        pasteboard.write(failureReport)
        reportCopied = true
    }
    private func clearFailures() { failureRows = []; failureReport = "" }
}
