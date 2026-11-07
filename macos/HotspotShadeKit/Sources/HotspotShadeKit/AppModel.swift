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

// Fixed lines for an action that cannot start while another action holds the
// engine. They are not error screens.
enum AppModelActionText {
    static let waitForAction = "Wait for the current action to finish."
    static let forgetAlreadyRunning = "A forget is already running."
    static let cancelingPairing = "Canceling pairing."
    static let quitting = "HotspotShade is quitting."
}

// The three plain texts for the engine forget state.
public enum ForgetMessages {
    // Protocol v1 answers FORGET with a plaintext RESULT frame and no sealed
    // part. Any peer can send that frame, so even the engine's "confirmed"
    // phase is only a valid answer, not proof that the source device removed
    // the key. Both final phases keep the cautious text from Strings. Do not
    // turn the phase name into a stronger claim.
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
    // The last pairing failure. It stays visible after isPairing turns false,
    // so a failed code check does not look like a fresh start.
    public var pairingFailure: String?
    // How far the engine's running flag can be trusted. An older engine sends
    // no state, so the default keeps the old behavior.
    public var engineHealth: EngineHealth
    // A helper stop that the app has not confirmed. The screen must not show a
    // clean On or Off while this is set, and a new start must stay disabled.
    public var cleanupPending: String?
    // Why the cleanup mark cannot be cleared yet. A terminal mark has no useful
    // retry, so the screen must not offer one.
    public var cleanupPendingKind: TunnelCleanupKind?
    // The last status read returned engine test data. The unavailable screen
    // names that engine error instead of a missing answer.
    public var testDataEngine: Bool
    public init(running: Bool = false, paired: Bool = false, phone: PhoneState = .unknown, phoneMessage: String? = nil, pairing: PairingPhase = .idle, suppressAutoPair: Bool = false, launch: LaunchPhase = .notAttempted, operation: TunnelOperation? = nil, error: String? = nil, freshness: StatusFreshness = .fresh, tokenRejected: String? = nil, trustedBySource: Bool? = nil, forget: ForgetPhase = .none, forgotIntent: Bool = false, sourceDeviceWarning: Bool = false, pairingFailure: String? = nil, engineHealth: EngineHealth = .normal, cleanupPending: String? = nil, cleanupPendingKind: TunnelCleanupKind? = nil, testDataEngine: Bool = false) {
        self.running = running; self.paired = paired; self.phone = phone; self.phoneMessage = phoneMessage
        self.pairing = pairing; self.suppressAutoPair = suppressAutoPair; self.launch = launch
        self.operation = operation; self.error = error
        self.freshness = freshness; self.tokenRejected = tokenRejected
        self.trustedBySource = trustedBySource; self.forget = forget
        self.forgotIntent = forgotIntent; self.sourceDeviceWarning = sourceDeviceWarning
        self.pairingFailure = pairingFailure; self.engineHealth = engineHealth
        self.cleanupPending = cleanupPending
        self.cleanupPendingKind = cleanupPendingKind
        self.testDataEngine = testDataEngine
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
    // A status with no answer for this long is unavailable, not stale.
    nonisolated static let statusUnavailableAfter: TimeInterval = 10
    // True after a status read returned engine test data, until a real status
    // arrives.
    private var lastStatusWasTestData = false
    @Published public private(set) var dashboard: DashboardState
    @Published public private(set) var screen: Screen
    @Published public private(set) var status = Status()
    @Published public private(set) var pairing = PairState()
    @Published public private(set) var isPairing = false
    @Published public private(set) var sourceDeviceWarning = false
    @Published public private(set) var logLines: [LogLine] = []
    // The plain text for a failed activity read. Cleared by the next success.
    @Published public private(set) var logsError: String?
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
    // The app-wide gate that a quit closes. The Coordinator and the tunnel
    // session share it, and every dashboard action checks it at entry and
    // after an await. A direct view call cannot slip past the quit.
    private let isQuitting: @Sendable () -> Bool
    // The same gate as an object. A tunnel action takes its generation at the
    // press and checks that generation after every await. A quit closes the
    // gate and Stay opens a new generation, so an action that began before
    // the quit stays cancelled after Stay instead of resuming with a fresh
    // isQuitting answer. The token also reaches the tunnel session through a
    // task-local value, so a late start cannot ask for authorization.
    private let actionGate: AppActionGate?
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
    private var statusReadGeneration: UInt64 = 0
    private enum StatusReadError: Error { case superseded }
    private var operation: TunnelOperation?
    private var failure: String?
    @Published public private(set) var pairingFailure: String?
    private var tokenRejected: String?
    private var unreachableSince: Date?
    // One state-changing action at a time. A tunnel start or stop and a
    // pairing start must not interleave at an await point, and a forget must
    // not slip between them. The pairing and forget flags are visible, so a
    // view can disable an action that is already running.
    private var tunnelActionInFlight = false
    @Published public private(set) var pairingStartInFlight = false
    // A Cancel press during the pairing start request is not dropped. The
    // start path sends the engine cancel when the request returns. A failed
    // best-effort cancel leaves this true, so the Cancel action stays.
    @Published public private(set) var pairingCancelRequested = false
    // A cancel request is in flight. A new pair must wait for the engine to
    // settle, because the engine refuses a start while an old cancel runs.
    @Published public private(set) var pairingCancelInFlight = false
    private var pairingFailureNeedsNotification = false
    // True while the current attempt is the one automatic retry. A second
    // automatic failure must not loop and hide the text from the person.
    private var pairingAttemptIsAutomaticRetry = false
    private var statusFailureSince: Date?
    private var lastLinkCheck: Date?
    private var notificationPolicy = NotificationPolicy()
    private var requestedNotificationPermission = false
    private var notificationsPrimed = false
    private var lastStopKey: String?
    @Published public private(set) var forgetInFlight = false
    // An explicit Pair resets the old forget text. Ignore an old engine
    // forget state until the engine reports "none" again.
    private var ignoreForgetState = false

    public init(backend: BackendClient, now: @escaping () -> Date = Date.init, isQuitting: @escaping @Sendable () -> Bool = { false }, actionGate: AppActionGate? = nil, pingSetting: PingSettingStore = UserDefaultsPingSetting(), pasteboard: PasteboardWriting = NoPasteboard(), forgetIntent: ForgetIntentStore = MemoryForgetIntent(), notificationSink: NotificationSink = NoNotificationSink(), settingsOpener: SettingsOpening = NoSettingsOpener(), linkProvider: LinkInfoProvider = NoLinkInfoProvider(), macOSVersion: String = ProcessInfo.processInfo.operatingSystemVersionString, appVersion: String = AppModel.bundleVersion()) {
        let initial = DashboardState(screen: .needsSourceDevice, title: Strings.waiting, subtitle: Strings.openSourceDeviceApp, action: nil, pairedLine: Strings.notPaired)
        dashboard = initial
        screen = initial.screen
        self.backend = backend
        self.now = now
        self.isQuitting = isQuitting
        self.actionGate = actionGate
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

    // A slower earlier read must not replace a later observation. An
    // uncertain response is retained even if superseded, since it cannot
    // safely authorize an action based on a competing normal response.
    private func readCurrentStatus(timeout: TimeInterval) async throws -> Status {
        statusReadGeneration &+= 1
        let generation = statusReadGeneration
        let live: Status
        do {
            live = try await backend.status(timeout: timeout)
            // Test data is an engine error, not a status. Its values never
            // replace the last real status and never reach the screen.
            if live.demo == true { throw BackendError.testDataEngine }
        } catch {
            if generation != statusReadGeneration { throw StatusReadError.superseded }
            throw error
        }
        guard generation == statusReadGeneration || !live.engineHealth.isNormal else {
            throw StatusReadError.superseded
        }
        status = live
        statusFailureSince = nil
        lastStatusWasTestData = false
        if !live.engineHealth.isNormal { statusReadGeneration &+= 1 }
        return live
    }

    // One competing poll may supersede an action read. Retry once, without
    // turning persistent overlap or an uncertain response into a clean state.
    private func readStatusForAction() async throws -> Status {
        do { return try await readCurrentStatus(timeout: 2) }
        catch StatusReadError.superseded {
            // A competing recovery observation must not be cleared by this
            // action's retry. Require a separate later refresh instead.
            if !status.engineHealth.isNormal { return status }
            return try await readCurrentStatus(timeout: 2)
        }
    }

    public func refresh() async {
        // A poll that resumes after a quit must not replace the quit screen or
        // start automatic pairing.
        guard !isQuitting() else { return }
        // The failure window starts when the request starts. A 3 s timeout is
        // then stale at once, as if the engine had not answered for 3 s.
        let attempt = now()
        do {
            _ = try await readCurrentStatus(timeout: 3)
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
            let isRetry = lastAutoPair != nil
            lastAutoPair = now()
            await startPairing(automatic: true, isRetry: isRetry)
        } catch StatusReadError.superseded {
            return
        } catch {
            if Task.isCancelled { return }
            // Keep the last screen. The freshness window decides when the
            // status is stale and when it is unavailable.
            if statusFailureSince == nil { statusFailureSince = attempt }
            // An engine that answers with test data will not recover on the
            // next poll. Show the unavailable state at once, so no action
            // runs on the last real status.
            if case BackendError.testDataEngine = error { lastStatusWasTestData = true } else { lastStatusWasTestData = false }
            if lastStatusWasTestData, let since = statusFailureSince {
                statusFailureSince = min(since, attempt.addingTimeInterval(-Self.statusUnavailableAfter))
            }
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
        if age >= Self.statusUnavailableAfter { return .unavailable }
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
        // Normalize a stale paired phase first. Every row below sees the live
        // phase, so a forget or a trust loss cannot leave Pair disabled.
        var input = input
        input.pairing = livePairing(input)
        let startsAutoPair = input.engineHealth.isNormal
            && input.cleanupPending == nil
            && !input.running
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

    // A paired phase describes the last pairing request. It is live only
    // while this target device still holds the pairing and the source device
    // still trusts it. After a forget or a trust loss the phase is stale and
    // must not disable the next Pair.
    nonisolated static func livePairing(_ input: DeriveInput) -> PairingPhase {
        guard input.pairing == .paired else { return input.pairing }
        if input.paired != true { return .idle }
        if input.phone == .notTrusted { return .idle }
        if input.trustedBySource == false { return .idle }
        if let token = input.tokenRejected, !token.isEmpty { return .idle }
        return .paired
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
        // After 10 s without an answer the app does not claim On or Off.
        if input.freshness == .unavailable {
            return state(.unknown, Strings.unknownTitle, input.testDataEngine ? EngineLaunchText.testDataEngine : Strings.statusUnavailableSubtitle, .checkNow)
        }
        // An interrupted engine operation makes the running flag a guard, not
        // a measurement. Never show On, Off, or a start action from here.
        switch input.engineHealth {
        case .stateUnknown:
            return state(.unknown, Strings.serviceStateUnknownTitle, Strings.serviceStateUnknownBody, .checkNow)
        case .cleanupBlocked:
            return state(.needsAttention(Strings.cleanupBlockedTitle), Strings.cleanupBlockedTitle, Strings.cleanupBlockedBody, .checkNow)
        case .normal:
            break
        }
        // A pending helper stop is not a clean On or Off, even when the last
        // status said running false. A retryable mark can be retried with a
        // stop. A terminal mark already has the helper's final answer, so the
        // screen offers no action and never presents an endless retry.
        if let pending = input.cleanupPending, !pending.isEmpty {
            let message = Strings.sanitized(pending) ?? pending
            let kind = input.cleanupPendingKind ?? .retryable
            let action: PrimaryAction?
            var subtitle = message
            switch kind {
            case .retryable:
                action = input.running ? .turnOff : .retry
            case .routesUnverified, .durableBlock:
                // A final mark has no action. Without one, the screen must
                // still say what the person does next. The durable block text
                // already carries its recovery, so it is not repeated.
                action = nil
                let recovery = EngineLaunchText.recovery(for: kind)
                if !message.contains(recovery) {
                    subtitle = "\(message) \(recovery)"
                }
            }
            return state(.needsAttention(message), Strings.cleanupBlockedTitle, subtitle, action)
        }
        // A recovery state takes precedence over an earlier token rejection.
        if let token = input.tokenRejected, !token.isEmpty {
            return state(.needsAttention(token), Strings.pairAgain, Strings.sanitized(token) ?? token, .pairAgain)
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
    // A forget message wins over the pair hint. A pairing failure comes next,
    // so the person sees why the last attempt stopped. The source device hint
    // shows only when the source device still knows this target device.
    private nonisolated static func unpairedState(_ input: DeriveInput, _ state: (Screen, String, String, PrimaryAction?) -> DashboardState) -> DashboardState {
        if let message = ForgetMessages.text(for: input.forget) {
            return state(.unpaired, Strings.notPaired, message, .pair)
        }
        if let failure = Strings.sanitized(input.pairingFailure), !failure.isEmpty {
            return state(.unpaired, Strings.notPaired, failure, .pair)
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
        let pending = pendingCleanup
        return DeriveInput(running: status.running == true, paired: status.paired == true, phone: PhoneState(raw: status.phone?.state), phoneMessage: status.phone?.message, pairing: pairingPhase(), suppressAutoPair: suppressAutoPair, launch: launchPhase(), operation: operation, error: failure, freshness: statusFreshness, tokenRejected: tokenRejected, trustedBySource: status.phone?.trustedBySource, forget: forgetProgress, forgotIntent: forgetIntentStore.forgotIntent, sourceDeviceWarning: sourceDeviceWarning, pairingFailure: pairingFailure, engineHealth: status.engineHealth, cleanupPending: pending?.message, cleanupPendingKind: pending?.kind, testDataEngine: lastStatusWasTestData)
    }
    private func deriveNow() -> DeriveResult { Self.derive(currentInput()) }
    private func apply(_ state: DashboardState) { dashboard = state; screen = state.screen }
    private func rederive() { updateFreshness(); apply(deriveNow().dashboard) }

    // A warning needs a continuous 10 s failure while the tunnel runs. One
    // probe miss must not flash it. An old probe result is not proof of a
    // failure, so it clears the warning instead of starting one.
    private func updateSourceDeviceWarning() {
        // An interrupted engine status cannot prove a source device failure.
        // A warning here would blame the source device for the target
        // device's state.
        guard status.engineHealth.isNormal, status.running == true else { unreachableSince = nil; sourceDeviceWarning = false; return }
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

    // True when the backend cannot prove that no tunnel lifecycle remains. An
    // elevated engine or an unconfirmed stop must be stopped before the app
    // restarts a lost user engine, even when the last status said running
    // false. The running flag alone is not cleanup proof.
    public var hasUnresolvedTunnelLifecycle: Bool {
        if let router = backend as? TunnelRoutingBackend {
            return router.activeBackendIsElevated || router.hasPendingStop || router.hasStartInFlight
        }
        return status.running == true
    }

    // The mark for an unconfirmed helper stop, or nil when cleanup is proven.
    // A running false status never clears it. A retained elevated session with
    // no reachable backend is also not a clean Off; that mark is retryable
    // because a helper retry can still reach the exact session.
    public var pendingCleanup: TunnelCleanupPending? {
        guard let router = backend as? TunnelRoutingBackend else { return nil }
        if let pending = router.pendingCleanup { return pending }
        guard router.hasUnreachableElevatedSession else { return nil }
        return TunnelCleanupPending(token: 0, message: EngineLaunchText.elevatedSessionOpen, kind: .retryable)
    }

    public var pendingCleanupMessage: String? { pendingCleanup?.message }
    public var pendingCleanupKind: TunnelCleanupKind? { pendingCleanup?.kind }

    // True when the engine cannot prove whether the tunnel is on or off. A
    // view must not show On or Off, and every control that changes the tunnel
    // or the pairing stays disabled.
    public var serviceStateUnknown: Bool { status.engineHealth == .stateUnknown }
    // True when the tunnel is off but cleanup did not finish. A new start must
    // stay disabled.
    public var cleanupBlocked: Bool { status.engineHealth == .cleanupBlocked }
    // True when the engine could not answer for 10 s. The README says Turn on,
    // Turn off, Pair, and Forget are disabled in this state. Check now stays
    // available, and a pairing cancel stays available so a stuck request can
    // still be released.
    private var actionsBlockedByUnavailableStatus: Bool { statusFreshness == .unavailable }

    // A quit or stop waits for this before it asks the helper to stop. A
    // tunnel start that is still asking for authorization must either settle
    // first or be reported as uncertain, never overtaken by a clean claim.
    // A start that an earlier model began is in the shared cleanup state, so a
    // model rebuilt during that start still reports it.
    public var tunnelActionIsInFlight: Bool { tunnelActionInFlight || sharedStartInFlight }

    private var sharedStartInFlight: Bool { (backend as? TunnelRoutingBackend)?.hasStartInFlight == true }

    // Wait a bounded time for a tunnel start or stop to settle. A system
    // authorization prompt may never answer, so the caller must be able to
    // fall back to an uncertain result instead of blocking quit forever.
    public func waitForTunnelActionToSettle(within seconds: TimeInterval) async -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while tunnelActionIsInFlight {
            if Date() >= deadline { return false }
            try? await Task.sleep(nanoseconds: 40_000_000)
        }
        return true
    }

    // True for both recovery states.
    public var recoveryBlocked: Bool { !status.engineHealth.isNormal }
    // The failure list needs a normal running tunnel. An unknown status has no
    // readable record, and an empty list must not look healthy.
    public var failuresAvailable: Bool {
        status.running == true && status.engineHealth.isNormal && statusFreshness != .unavailable && !hasPendingCleanup
    }

    public var hasPendingCleanup: Bool { (backend as? TunnelRoutingBackend)?.hasPendingStop == true }

    // Show a count only while the tunnel runs. The engine sends the count.
    public var connectionsLabel: String? {
        guard status.engineHealth.isNormal, statusFreshness != .unavailable, status.running == true, let count = status.phone?.connections else { return nil }
        return Strings.connections(count)
    }
    // The one plain line about ping. It needs a running tunnel and a value
    // from the engine. A missing value shows no line.
    public nonisolated static func pingLine(running: Bool, icmpEnabled: Bool?) -> String? {
        guard running, let icmpEnabled else { return nil }
        return icmpEnabled ? Strings.pingOn : Strings.pingOff
    }
    public var pingLine: String? {
        guard status.engineHealth.isNormal, statusFreshness != .unavailable else { return nil }
        return Self.pingLine(running: status.running == true, icmpEnabled: status.icmp_enabled)
    }
    // The age of the last probe. The text uses the injected clock.
    public var lastCheckedText: String? {
        guard status.engineHealth.isNormal, let checked = status.phone?.checkedAt, checked.isFinite else { return nil }
        let elapsed = now().timeIntervalSince1970 - checked
        guard elapsed.isFinite else { return nil }
        let age = max(0, elapsed)
        if age < 10 { return Strings.checkedJustNow }
        if age < 60 { return Strings.checkedSeconds(Int(age)) }
        guard let minutes = Int(exactly: (age / 60).rounded(.down)) else { return nil }
        return Strings.checkedMinutes(minutes)
    }
    public var lastStopLine: String? {
        // An unknown status has no trustworthy stop record.
        guard status.engineHealth != .stateUnknown else { return nil }
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
        guard status.engineHealth.isNormal else { return [] }
        return LinkAdvice.advice(running: status.running == true, statusIface: status.iface, link: linkInfo)
    }
    // True when macOS denied notification permission. A view shows
    // notificationsSettingsText and a button that calls openNotificationSettings().
    public var notificationsDenied: Bool { notificationAuthorization == .denied }
    // The one plain Settings line for a denied permission. Nil otherwise.
    public var notificationsSettingsText: String? { notificationsDenied ? Strings.notificationsDenied : nil }
    // True when a Settings button must offer to open System Settings.
    public var canOpenNotificationSettings: Bool { notificationsDenied }
    public var forgetIsBlocked: Bool { forgetResult?.blockedByTunnel == true }
    // True while a Forget request owns the engine. The view disables the
    // button and shows the same text that the presentation uses.
    public var forgetIsBusy: Bool { forgetInFlight }
    // True while the engine cancel request runs. A new Pair waits for it.
    public var pairingCancelIsBusy: Bool { pairingCancelInFlight }
    public var pairingStartIsBusy: Bool { pairingStartInFlight }
    public var pairingCancelIsPending: Bool { pairingCancelRequested }
    // The typed "the tunnel still runs" result. The view offers
    // "Turn off and forget" and calls turnOffAndForget().
    public var forgetBlockedByTunnel: Bool { forgetIsBlocked }
    public var forgetMessage: String? { ForgetMessages.text(for: forgetProgress) ?? forgetResult?.message }
    public var activityLine: String { Strings.sanitized(status.phone?.message) ?? Strings.notConnected }

    // The one model that a view draws.
    public var screenModel: ScreenModel {
        ScreenPresentation.build(PresentationInput(derive: currentInput(), pingLine: pingLine, connectionsLabel: connectionsLabel, lastStopLine: lastStopLine, lastCheckedText: lastCheckedText, linkAdvice: linkAdvice, notificationsDenied: notificationsDenied, forgetBlocked: forgetIsBlocked, forgetInFlight: forgetInFlight, pairingCancelInFlight: pairingCancelInFlight, pairingStartInFlight: pairingStartInFlight, pairingCancelRequested: pairingCancelRequested, retryStartsTunnel: retryTarget == .start))
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
        guard !isQuitting() else { return }
        switch action {
        case .pair, .pairAgain: await beginPairing()
        // The visible action names the direction. Never read the last status
        // here: a stale answer would turn an explicit Turn on into a stop.
        case .turnOn: await turnOn()
        case .turnOff: await turnOff()
        case .retry: await retryLastAction()
        case .checkNow: await checkNow()
        }
    }

    // Try again repeats the action that failed. It must repeat the direction
    // that the person asked for. A lost start answer can leave the tunnel on,
    // so reading the current status here would turn Try again into a stop.
    private func retryLastAction() async {
        guard !isQuitting() else { return }
        // A pending helper stop is retried with a stop only while the helper
        // can still produce new evidence. A terminal mark repeats its exact
        // answer and offers no action, so a direct call must not loop.
        if let pending = pendingCleanup {
            if pending.kind == .retryable {
                await setTunnel(on: false)
            } else {
                await refresh()
            }
            return
        }
        switch retryTarget {
        case .start: await setTunnel(on: true)
        case .stop: await setTunnel(on: false)
        case .pair: await beginPairing()
        case .refresh:
            failure = nil
            await refresh()
        }
    }

    // The Pair action calls this. An explicit press clears the Cancel guard
    // and the stored forget intent, so automatic pairing can start again.
    public func beginPairing() async {
        guard !isQuitting() else { return }
        // Do not clear the forget intent or a Cancel guard while another
        // action owns the engine. A recovery block, an unavailable status, or
        // an unconfirmed stop must clear first.
        guard status.engineHealth.isNormal else { return }
        guard !actionsBlockedByUnavailableStatus else { return }
        guard !hasPendingCleanup else { return }
        guard !pairingStartInFlight, !pairingCancelInFlight, !pairingCancelRequested, !isPairing, !tunnelActionIsInFlight, !forgetInFlight else { return }
        retryTarget = .pair
        suppressAutoPair = false
        forgetIntentStore.forgotIntent = false
        tokenRejected = nil
        forgetResult = nil
        forgetProgress = .none
        ignoreForgetState = true
        await startPairing(automatic: false)
    }
    // An automatic retry keeps the last pairing failure visible. An explicit
    // Pair press clears it. The engine may also be free after a lost reply, so
    // the start path sends a best-effort cancel before it reports the error.
    private func startPairing(automatic: Bool = false, isRetry: Bool = false) async {
        guard !isQuitting() else { return }
        guard status.engineHealth.isNormal else { return }
        guard !actionsBlockedByUnavailableStatus else { return }
        guard !hasPendingCleanup else { return }
        guard !pairingStartInFlight, !pairingCancelInFlight, !pairingCancelRequested, !isPairing, !tunnelActionIsInFlight, !forgetInFlight else { return }
        retryTarget = .pair
        pairingStartInFlight = true
        pairingAttemptIsAutomaticRetry = automatic && isRetry
        isPairing = true
        pairing = PairState()
        if !automatic {
            pairingFailure = nil
            pairingFailureNeedsNotification = false
            failure = nil
        }
        pairingCancelRequested = false
        pairPolling?.cancel(); pairPolling = nil
        pairingGeneration += 1
        let generation = pairingGeneration
        defer { pairingStartInFlight = false }
        rederive()
        do {
            try await backend.startPairing()
            // A quit can begin while the start request is in flight. Do not
            // publish a pairing poll or a new screen after the quit owns the
            // engine.
            if isQuitting() {
                isPairing = false
                pairing = PairState()
                return
            }
            // A Cancel press while this request was in flight is handled
            // here, so the press is never dropped and no pairing runs unseen.
            if pairingCancelRequested {
                await sendPairingCancel()
                return
            }
            guard generation == pairingGeneration else { return }
            pairPolling = Task { [weak self] in
                while !Task.isCancelled {
                    await self?.refreshPairing(generation: generation)
                    try? await Task.sleep(nanoseconds: 700_000_000)
                }
            }
        } catch {
            guard !isQuitting() else { return }
            // The request may have reached the engine even though its answer
            // was lost. Send the cancel in that case too.
            if pairingCancelRequested {
                await sendPairingCancel()
                return
            }
            guard generation == pairingGeneration else { return }
            isPairing = false
            let text = error.localizedDescription
            pairing = PairState(state: "failed", error: text)
            // The engine could not start the attempt. This is an action error
            // with a Try again action, not a fresh pairing failure.
            failure = text
            if pairingAttemptIsAutomaticRetry { suppressAutoPair = true }
            // A lost reply or a busy engine can leave a pairing running. The
            // cancel is best effort and never replaces the start error.
            await bestEffortPairingCancel()
            rederive()
        }
    }
    // A test or a view can refresh the pairing state on its own. Capture the
    // generation so a Cancel or a new pair makes the answer stale.
    public func refreshPairing() async { await refreshPairing(generation: pairingGeneration) }
    private func refreshPairing(generation: Int?) async {
        guard !isQuitting() else { return }
        do {
            let value = try await backend.pairState()
            if let generation, generation != pairingGeneration { return }
            if isQuitting() { return }
            pairing = value
            if pairing.state == "paired" {
                retryTarget = .refresh
                pairingFailure = nil
                pairingFailureNeedsNotification = false
                pairingAttemptIsAutomaticRetry = false
                isPairing = false; pairPolling?.cancel(); pairPolling = nil; pairingGeneration += 1
                // Probe at once, so the screen shows the new state without a
                // wait for the next poll.
                await probeNow()
                await refresh()
            } else if pairing.state == "failed" {
                isPairing = false; pairPolling?.cancel(); pairPolling = nil; pairingGeneration += 1
                // Keep the failure on the screen after the pairing view goes
                // away. Notify once for a new failure, not on every poll.
                let text = Strings.sanitized(pairing.error) ?? Strings.pairingNeedsAttention
                if pairingFailure != text {
                    pairingFailure = text
                    pairingFailureNeedsNotification = true
                }
                // One automatic start and one retry. A second automatic
                // failure must not start another attempt that hides the text.
                if pairingAttemptIsAutomaticRetry { suppressAutoPair = true }
                rederive()
                await evaluateNotifications()
            } else {
                rederive()
                await evaluateNotifications()
            }
        } catch {
            if let generation, generation != pairingGeneration { return }
            isPairing = false; pairPolling?.cancel(); pairPolling = nil; pairingGeneration += 1
            let text = error.localizedDescription
            pairing = PairState(state: "failed", error: text)
            // The error stays visible after the pairing view goes away. A lost
            // reply is not a code mismatch, so it must not send the "Check the
            // code" notification. The engine may still be pairing, so release
            // it with one best-effort cancel.
            if pairingFailure != text { pairingFailure = text }
            if pairingAttemptIsAutomaticRetry { suppressAutoPair = true }
            await bestEffortPairingCancel()
            rederive()
            await evaluateNotifications()
        }
    }
    public func cancelPairing() async {
        guard !isQuitting() else { return }
        retryTarget = .refresh
        suppressAutoPair = true
        pairingGeneration += 1
        pairPolling?.cancel(); pairPolling = nil
        isPairing = false
        pairing = PairState()
        pairingFailure = nil
        pairingFailureNeedsNotification = false
        pairingAttemptIsAutomaticRetry = false
        if pairingStartInFlight {
            // The start request owns the engine call. Its completion sends the
            // cancel, so this press is not lost and the pairing cannot run on
            // without a view.
            pairingCancelRequested = true
            rederive()
            return
        }
        if pairingCancelInFlight {
            // One cancel is enough. A new pair waits for it to settle.
            rederive()
            return
        }
        await sendPairingCancel()
    }
    // Send one cancel to the engine and read the settled state. The caller
    // owns the engine action, or the start path is finishing its own request.
    private func sendPairingCancel() async {
        pairingCancelRequested = false
        pairingCancelInFlight = true
        rederive()
        defer { pairingCancelInFlight = false; rederive() }
        do {
            try await backend.cancelPairing()
        } catch {
            // Keep the Cancel action available for another try. The engine may
            // still own a pairing even though the cancel reply was lost.
            pairingCancelRequested = true
            failure = error.localizedDescription
            rederive()
            return
        }
        // A forget or a tunnel action owns the final status read. Do not
        // overwrite its result with this cancel's older answer.
        if !forgetInFlight && !tunnelActionInFlight {
            await refresh()
        }
    }
    // The engine can keep a pairing after a lost start or poll reply. This
    // cancel is best effort: the original error stays, and a failed cancel
    // leaves the Cancel action so the person can try again.
    private func bestEffortPairingCancel() async {
        guard !pairingCancelInFlight else { return }
        pairingCancelInFlight = true
        rederive()
        defer { pairingCancelInFlight = false; rederive() }
        do {
            try await backend.cancelPairing()
        } catch {
            pairingCancelRequested = true
        }
    }

    // Forget the source device. If the tunnel runs, do not ask the engine:
    // return the typed blocked result. The person can then use
    // turnOffAndForget().
    @discardableResult
    public func forget() async -> ForgetResult {
        guard !isQuitting() else { return refuseForget(AppModelActionText.quitting) }
        if forgetInFlight { return refuseForget(AppModelActionText.forgetAlreadyRunning) }
        // A recovery block leaves the tunnel and its trust state unproven.
        // A forget must not run in that window. An unavailable status cannot
        // prove that the tunnel is off either.
        guard status.engineHealth.isNormal else { return refuseForget(recoveryActionText) }
        guard !actionsBlockedByUnavailableStatus else { return refuseForget(Strings.statusUnavailableSubtitle) }
        if let pending = pendingCleanupMessage {
            return refuseForget(Strings.sanitized(pending) ?? pending)
        }
        // Never slip a forget between a start, a stop, and the status read
        // that decides whether the engine may be asked. A cancel in flight is
        // safe: the forget request takes the engine after this check.
        guard !tunnelActionIsInFlight, !pairingStartInFlight, !pairingCancelInFlight, !pairingCancelRequested else {
            return refuseForget(AppModelActionText.waitForAction)
        }
        forgetInFlight = true
        rederive()
        defer { forgetInFlight = false; rederive() }
        return await runForget()
    }

    // The fixed text for an action that a recovery block refuses.
    private var recoveryActionText: String {
        status.engineHealth == .cleanupBlocked ? Strings.cleanupBlockedBody : Strings.serviceStateUnknownBody
    }

    // A refused Forget still has to be visible under the Forget button. The
    // Settings view ignores the return value, so store the line here.
    private func refuseForget(_ text: String) -> ForgetResult {
        let result = ForgetResult.failed(text)
        forgetResult = result
        rederive()
        return result
    }

    // Stop the tunnel, wait for the engine to report stopped, then forget.
    @discardableResult
    public func turnOffAndForget() async -> ForgetResult {
        guard !isQuitting() else { return refuseForget(AppModelActionText.quitting) }
        if forgetInFlight { return refuseForget(AppModelActionText.forgetAlreadyRunning) }
        // The stop path cannot settle an unproven service state. A person
        // must inspect the target device first. An unavailable status cannot
        // prove that the tunnel is off, so it cannot authorize a trust change.
        guard status.engineHealth.isNormal else { return refuseForget(recoveryActionText) }
        guard !actionsBlockedByUnavailableStatus else { return refuseForget(Strings.statusUnavailableSubtitle) }
        guard !tunnelActionIsInFlight, !pairingStartInFlight, !pairingCancelInFlight, !pairingCancelRequested else {
            return refuseForget(AppModelActionText.waitForAction)
        }
        forgetInFlight = true
        tunnelActionInFlight = true
        rederive()
        defer { tunnelActionInFlight = false; forgetInFlight = false; rederive() }
        if status.running == true || statusFreshness != .fresh || hasUnresolvedTunnelLifecycle {
            operation = .stopping; rederive()
            // A stop failure is a trust change blocker, not a detail to drop.
            // Forget must not run after the stop answer was lost or refused.
            do {
                try await backend.stopTunnel(timeout: 45)
            } catch {
                operation = nil; rederive()
                return refuseForget(stopFailureText(error))
            }
            var stopped = false
            var recovery: String?
            for _ in 0..<100 {
                if let live = try? await readCurrentStatus(timeout: 2) {
                    if !live.engineHealth.isNormal {
                        recovery = live.engineHealth == .cleanupBlocked
                            ? Strings.cleanupBlockedBody
                            : Strings.serviceStateUnknownBody
                        break
                    }
                    if live.running == false { stopped = true; break }
                }
                try? await Task.sleep(nanoseconds: 150_000_000)
            }
            operation = nil; rederive()
            if let recovery { return refuseForget(recovery) }
            guard stopped else { return refuseForget(EngineLaunchText.stopUnverified) }
            guard !isQuitting() else { return refuseForget(AppModelActionText.quitting) }
        }
        return await runForget()
    }

    // The plain line for a failed stop on the forget path. The text never
    // claims that the tunnel stopped.
    private func stopFailureText(_ error: Error) -> String {
        Strings.sanitized(error.localizedDescription) ?? EngineLaunchText.stopUnverified
    }

    // The one Forget implementation. The caller holds forgetInFlight, so a
    // second forget, a start, or a stop cannot interleave with it.
    @discardableResult
    private func runForget() async -> ForgetResult {
        guard !isQuitting() else { return refuseForget(AppModelActionText.quitting) }
        // Recheck after any await in the caller. A status that became
        // uncertain cannot authorize a trust change, even if running is false.
        guard status.engineHealth.isNormal else { return refuseForget(recoveryActionText) }
        guard !actionsBlockedByUnavailableStatus else { return refuseForget(Strings.statusUnavailableSubtitle) }
        if let pending = pendingCleanupMessage {
            return refuseForget(Strings.sanitized(pending) ?? pending)
        }
        if status.running != true {
            guard (try? await readStatusForAction()) != nil else {
                return refuseForget(Strings.statusUnavailableSubtitle)
            }
        }
        guard status.engineHealth.isNormal else { return refuseForget(recoveryActionText) }
        guard !actionsBlockedByUnavailableStatus else { return refuseForget(Strings.statusUnavailableSubtitle) }
        guard !pairingCancelInFlight, !pairingCancelRequested else {
            return refuseForget(AppModelActionText.waitForAction)
        }
        retryTarget = .refresh
        // A new action replaces the old start or stop error.
        failure = nil
        forgetResult = nil
        // A Forget during pairing cancels pairing first, so no late pair result
        // can change the final state.
        if isPairing {
            guard await cancelPairingForForget() else {
                return refuseForget(AppModelActionText.cancelingPairing)
            }
            guard (try? await readStatusForAction()) != nil else {
                return refuseForget(Strings.statusUnavailableSubtitle)
            }
        }
        guard status.engineHealth.isNormal else { return refuseForget(recoveryActionText) }
        guard !actionsBlockedByUnavailableStatus else { return refuseForget(Strings.statusUnavailableSubtitle) }
        guard !pairingCancelInFlight, !pairingCancelRequested else {
            return refuseForget(AppModelActionText.waitForAction)
        }
        pairingGeneration += 1
        pairPolling?.cancel(); pairPolling = nil
        isPairing = false
        pairing = PairState()
        pairingFailure = nil
        pairingFailureNeedsNotification = false
        suppressAutoPair = true
        // The person chose to forget. Persist the intent before the request,
        // so a blocked request cannot start automatic pairing later.
        forgetIntentStore.forgotIntent = true
        ignoreForgetState = false
        if status.running == true {
            let result = ForgetResult.blockedByTunnel
            forgetResult = result
            rederive()
            return result
        }
        guard status.running == false else { return refuseForget(Strings.statusUnavailableSubtitle) }
        guard !isQuitting() else { return refuseForget(AppModelActionText.quitting) }
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

    // A lost cancellation reply leaves pairing unproven. Keep the cancel
    // fence and refuse Forget until a later cancellation succeeds.
    private func cancelPairingForForget() async -> Bool {
        pairingGeneration += 1
        pairPolling?.cancel(); pairPolling = nil
        isPairing = false
        pairingCancelRequested = false
        pairingCancelInFlight = true
        defer { pairingCancelInFlight = false }
        pairingAttemptIsAutomaticRetry = false
        pairing = PairState()
        pairingFailure = nil
        pairingFailureNeedsNotification = false
        do {
            try await backend.cancelPairing()
            return true
        } catch {
            pairingCancelRequested = true
            failure = error.localizedDescription
            return false
        }
    }

    // Probe and read the status. This is a refresh, not a retry: a failed
    // start or stop keeps its text and its Try again target.
    public func checkNow() async {
        guard !isQuitting() else { return }
        await probeNow()
        await refresh()
        refreshLinkIfNeeded(force: true)
    }
    private func probeNow() async {
        guard let phone = try? await backend.probe() else { return }
        status.phone = phone
        rederive()
    }

    // An explicit action always sends its own direction. A stale status must
    // not invert a press that the window or menu already labeled.
    public func turnOn() async { await setTunnel(on: true) }
    public func turnOff() async { await setTunnel(on: false) }

    // A fresh press reads the current status to pick the direction. Try again
    // does not use this path, because a lost answer can make the status
    // describe the state that the failed action already reached.
    public func toggle() async {
        guard !actionsBlockedByUnavailableStatus else { return }
        await setTunnel(on: status.running != true)
    }

    // Take the gate generation at the press. Nil means the gate is closed.
    private func openActionToken() -> AppActionGate.Token?? {
        guard !isQuitting() else { return nil }
        guard let actionGate else { return .some(nil) }
        let token = actionGate.current()
        guard actionGate.permits(token) else { return nil }
        return .some(token)
    }

    // True while the press that took this token may still act. A quit closes
    // the gate; a Stay after it moves the generation, so the old press stays
    // cancelled.
    private func actionPermitted(_ token: AppActionGate.Token?) -> Bool {
        guard !isQuitting() else { return false }
        guard let token, let actionGate else { return true }
        return actionGate.permits(token)
    }

    private func setTunnel(on targetOn: Bool) async {
        // The app gate closes before the quit path touches the tunnel. A
        // dashboard button that is already queued, or a direct model call,
        // must not start or stop after that point.
        guard let opened = openActionToken() else { return }
        let actionToken = opened
        // The engine refuses a start after an interrupted operation, and an
        // unknown state cannot prove a safe stop either. The menu and the
        // buttons are disabled already; this guard keeps a programmatic call
        // from bypassing them. An unavailable status cannot prove either
        // direction.
        guard status.engineHealth.isNormal else { return }
        guard !actionsBlockedByUnavailableStatus else { return }
        if let pending = pendingCleanup {
            switch (targetOn, pending.kind) {
            case (true, _):
                // A start cannot run while the previous stop is unconfirmed.
                // Show the same message and leave only a retryable explicit
                // stop available. A final mark has no stop to retry.
                failure = Strings.sanitized(pending.message) ?? pending.message
                retryTarget = pending.kind == .retryable ? .stop : .refresh
                rederive()
                return
            case (false, .retryable):
                break
            case (false, .routesUnverified), (false, .durableBlock):
                // The helper already gave its final answer. Another stop
                // cannot add route evidence, so a direct call must not loop.
                failure = Strings.sanitized(pending.message) ?? pending.message
                retryTarget = .refresh
                rederive()
                return
            }
        }
        guard !tunnelActionInFlight, !forgetInFlight, !pairingStartInFlight, !pairingCancelInFlight, !pairingCancelRequested, !isPairing else { return }
        tunnelActionInFlight = true; defer { tunnelActionInFlight = false }
        failure = nil
        retryTarget = targetOn ? .start : .stop
        // Show the operation before any await. A system permission request
        // must never leave the button looking as if the press did nothing.
        operation = targetOn ? .starting : .stopping
        rederive()
        do {
            let backend = self.backend
            let letPingWork = pingSetting.letPingWork
            if targetOn {
                // The routing backend asks for administrator authorization
                // only for the operation that changes routes, and only after
                // it proves that no earlier stop is unconfirmed. The engine
                // and the full interface are already running without one.
                // The press token travels with the call, so the tunnel
                // session refuses this start if a quit began after the press.
                try await AppActionGate.$actionToken.withValue(actionToken) {
                    try await backend.startTunnel(experimentalICMP: letPingWork)
                }
                guard actionPermitted(actionToken) else { operation = nil; return }
                tokenRejected = nil
                // Ask after the start. A permission alert must not compete
                // with the administrator prompt, and it must not hold the
                // start when the system never answers.
                requestNotificationPermissionInBackground()
            } else {
                try await backend.stopTunnel()
            }
            // A quit can begin while the engine call is in flight. Do not
            // refresh or replace the quit screen with an action result. A
            // Stay after that quit does not make this old press current.
            guard actionPermitted(actionToken) else { operation = nil; return }
            retryTarget = .refresh
            operation = nil; await refresh()
        } catch BackendError.phoneTokenRejected(let message) {
            operation = nil
            guard actionPermitted(actionToken) else { return }
            tokenRejected = message.isEmpty ? Strings.phoneTokenRejected : message
            failure = nil
            rederive()
        } catch {
            guard actionPermitted(actionToken) else { operation = nil; return }
            // An explicit uncertain stop is never cleared by a stopped status.
            // The status cannot prove that route cleanup finished.
            if Self.isUncertainStop(error) {
                operation = nil
                failure = error.localizedDescription
                retryTarget = targetOn ? .start : .stop
                rederive()
                return
            }
            // A lost answer can leave the engine in the target state. Read the
            // live status once. If it already matches the direction that the
            // person asked for, this is not a failure, and Try again keeps
            // that direction instead of inverting it.
            let reached = await tunnelReached(on: targetOn)
            operation = nil
            guard actionPermitted(actionToken) else { return }
            if reached {
                if targetOn { tokenRejected = nil }
                failure = nil
                retryTarget = .refresh
                await refresh()
            } else {
                failure = error.localizedDescription
                retryTarget = targetOn ? .start : .stop
                rederive()
            }
        }
    }

    // A typed cleanup refusal from the router or the authorizer. A running
    // false status is not evidence that this stop finished.
    nonisolated static func isUncertainStop(_ error: Error) -> Bool {
        if let routing = error as? TunnelRoutingError, case .cleanupUncertain = routing {
            return true
        }
        if let authorization = error as? TunnelAuthorizationFailure {
            return authorization.isUncertainStop
        }
        return false
    }

    // True when a fresh status read shows the state that the action asked
    // for. The read also becomes the visible status.
    private func tunnelReached(on: Bool) async -> Bool {
        guard let live = try? await readCurrentStatus(timeout: 2) else { return false }
        guard live.engineHealth.isNormal else {
            return false
        }
        guard let running = live.running, running == on else { return false }
        updateSourceDeviceWarning()
        updateFreshness()
        return true
    }
    // The quit path needs the result, not only the request. The routing
    // backend stops the elevated engine and its helper session first, then
    // reports the user engine's stopped state. A failed or uncertain stop is
    // returned as uncertain and is never presented as a clean stop.
    public func quitStopOutcome() async -> EngineStopOutcome {
        stopPolling()
        operation = .stopping
        rederive()
        let outcome = await TunnelQuitCheck.stop(backend)
        operation = nil
        rederive()
        return outcome
    }

    // Read the live status before the quit decision. A failed read means the
    // tunnel may be on, so send stop in that case.
    public func stopForQuit() async {
        stopPolling(); operation = .stopping; rederive()
        var running = true
        do {
            let live = try await readCurrentStatus(timeout: 2)
            guard live.engineHealth.isNormal else { operation = nil; rederive(); return }
            running = live.running != false
        } catch StatusReadError.superseded { operation = nil; rederive(); return }
        catch { running = true }
        if running { try? await backend.stopTunnel(timeout: 45) }
    }
    public func loadLogs() async {
        guard !isQuitting() else { return }
        retryTarget = .refresh
        do {
            logLines = try await backend.logs(since: 0)
            logsError = nil
        } catch {
            // A failed read stays in the Activity screen. It is not a tunnel
            // or pairing failure, so the dashboard keeps its own state.
            logsError = Strings.sanitized(error.localizedDescription) ?? error.localizedDescription
        }
    }

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
        // Do not consume a stop record until a later status can confirm it.
        guard status.engineHealth != .stateUnknown else { return }
        let key = "\(status.last_stop?.stableKey ?? "")|\(status.last_stop_message ?? "")"
        var newStop: LastStop?
        if !notificationsPrimed {
            notificationsPrimed = true
            lastStopKey = key
        } else if key != lastStopKey {
            lastStopKey = key
            newStop = status.last_stop
        }
        // A code prompt needs the person. A pairing failure keeps needing
        // attention after isPairing turns false, so it is a one-shot flag
        // rather than a condition that fires on every poll.
        let attention = (isPairing && pairing.state == "confirm") || pairingFailureNeedsNotification
        // A failed Pair or pairing cancel request is not a tunnel failure.
        // Passing it as the tunnel error sent a misleading "The engine did not
        // respond" or "A pairing is already running" notification.
        let actionError = (retryTarget == .pair || pairingCancelRequested) ? nil : failure
        let input = NotificationInput(authorization: notificationAuthorization, isFrontmost: isFrontmost, running: status.running == true, phone: PhoneState(raw: status.phone?.state), sourceDeviceWarning: sourceDeviceWarning, pairingNeedsAttention: attention, lastStop: newStop, lastStopMessage: status.last_stop_message, error: actionError ?? status.error, serviceStateUnknown: status.engineHealth == .stateUnknown)
        let output = notificationPolicy.evaluate(input)
        // Clear first. A new message in the same answer must stay delivered.
        if output.clearDelivered { await notificationSink.clearDelivered() }
        for message in output.messages { await notificationSink.post(message) }
        // The failure needs only one message. Drop the pending flag after it
        // is shown, when the app is frontmost, or when no message can show.
        if output.messages.contains(where: { $0.kind == .pairingAttention }) || isFrontmost || notificationAuthorization != .authorized {
            pairingFailureNeedsNotification = false
        }
    }

    // MARK: - Diagnostics

    // Copy one plain-text report. A missing endpoint adds an "unavailable"
    // line and never blocks the copy.
    public func copyDiagnostics() async {
        let diagnostics = try? await backend.diagnostics()
        let failures = status.engineHealth.isNormal ? try? await backend.failures() : nil
        let lastStop = status.engineHealth == .stateUnknown ? nil : status.last_stop.flatMap { $0.reason == nil ? nil : $0 }
        // An unknown status cannot support an interface, a ping state, or a
        // stop record. The report names the recovery state instead.
        let healthy = status.engineHealth.isNormal
        let context = DiagnosticsContext(macOSVersion: macOSVersion, appVersion: appVersion, link: linkInfo, interfaceName: healthy ? status.iface : nil, icmpEnabled: healthy ? status.icmp_enabled : nil, lastStop: lastStop, lastStopMessage: status.engineHealth == .stateUnknown ? nil : status.last_stop_message, notificationAuthorization: notificationAuthorization, serviceState: status.engineHealth == .stateUnknown ? .unknown : status.serviceState, cleanupBlocked: status.cleanup_blocked == true, pendingCleanup: pendingCleanupMessage, now: now())
        lastDiagnosticsText = DiagnosticsReport.text(diagnostics: diagnostics, failures: failures, context: context)
        pasteboard.write(lastDiagnosticsText)
        diagnosticsCopied = true
    }

    // MARK: - Failure list

    // Read the failure list once. The Settings panel calls this when the
    // person opens the section or presses Refresh. Without a running tunnel
    // the endpoint has no data, so the app does not ask for it.
    public func loadFailures() async {
        guard !isQuitting() else { return }
        // An unknown status has no readable failure record. A start-recovery
        // block must not turn its empty answer into "No failed connections".
        guard failuresAvailable else { failuresState = .idle; return }
        failuresState = .loading
        reportCopied = false
        do {
            let report = try await backend.failures()
            if report.demo == true { throw BackendError.testDataEngine }
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
