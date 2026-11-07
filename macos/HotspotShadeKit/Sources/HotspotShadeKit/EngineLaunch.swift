import Foundation

// The app owns one engine process. This state covers the time before that
// engine has a model. It keeps a failed engine or a lost connection from
// looking like a launch that is still starting.
public enum EngineLaunchState: Equatable {
    // The app waits here. Launching the app must not ask for administrator
    // authorization until a person asks to start the engine.
    case waiting
    case starting
    case running
    // The quit path stops the tunnel and the engine. No new action is offered.
    case stopping
    // The engine never became usable. The failure says what to do next.
    case failed(EngineLaunchFailure)
    // The app stopped or lost the engine after it had run. The app never
    // restarts it automatically. The failure says what to check.
    case lost(EngineLaunchFailure)

    public var failure: EngineLaunchFailure? {
        switch self {
        case .failed(let failure), .lost(let failure): return failure
        default: return nil
        }
    }
}

public enum EngineLaunchPolicy {
    // The app starts the bundled engine with the window. It starts the
    // engine as the signed-in user. That engine serves the Dashboard,
    // pairing, status, Settings, diagnostics, and failures without an
    // administrator prompt. The protected helper starts a root engine only
    // when a person turns the tunnel on. This policy decides when the user
    // engine starts, not when the tunnel starts.
    public static func startsAutomatically() -> Bool { true }
}

// One status read right after the user engine reports its port. An engine
// that answers with its built-in test data is a wrong build or a wrong launch.
// The app has no mode for that data, so the launch fails with a plain engine
// error. Any other read failure is left to the status poll, which already
// shows a stale or unavailable status.
public enum UserEngineCheck {
    public static func verify(_ backend: BackendClient, timeout: TimeInterval = 3) async throws {
        let status: Status
        do { status = try await backend.status(timeout: timeout) }
        catch BackendError.testDataEngine { throw BackendError.testDataEngine }
        catch { return }
        if status.demo == true { throw BackendError.testDataEngine }
    }
}

// The administrator authorization for one tunnel start. The app asks for it
// only when a person turns the tunnel on. A hermetic test and an unprivileged
// engine use the no-op value.
public protocol TunnelStartAuthorizing: Sendable {
    func authorizeTunnelStart() async throws
}

public struct NoTunnelStartAuthorization: TunnelStartAuthorizing {
    public init() {}
    public func authorizeTunnelStart() async throws {}
}

// A plain authorization failure for the dashboard. It carries the same
// sentence as the helper failure table and no path, token, or signing detail.
// A failure that stopped an engine without confirming cleanup is typed. The
// routing backend latches that case so a later start, pairing request, forget,
// or quit cannot treat a stopped status as proof.
public struct TunnelAuthorizationFailure: LocalizedError, Equatable, Sendable {
    public enum Cleanup: Equatable, Sendable {
        case none
        case uncertainStop
    }

    public let message: String
    public let cleanup: Cleanup

    public init(message: String, cleanup: Cleanup = .none) {
        self.message = message
        self.cleanup = cleanup
    }

    public var isUncertainStop: Bool { cleanup == .uncertainStop }
    public var errorDescription: String? { message }
}

// A menu command carries a direction. The Coordinator checks that direction
// before it schedules a toggle, so a stale screen can never turn a "Turn off"
// command into a start. The request is not a blind toggle.
public enum EngineToggleDirection: Equatable, Sendable {
    case turnOn
    case turnOff

    public init?(_ kind: ScreenModel.MenuBarAction.Kind) {
        switch kind {
        case .turnOn: self = .turnOn
        case .turnOff: self = .turnOff
        default: return nil
        }
    }

    var menuKind: ScreenModel.MenuBarAction.Kind {
        switch self {
        case .turnOn: return .turnOn
        case .turnOff: return .turnOff
        }
    }

    var primaryAction: ScreenModel.Action {
        switch self {
        case .turnOn: return .turnOn
        case .turnOff: return .turnOff
        }
    }
}

public extension ScreenModel {
    // True when the visible screen offers this direction. The Coordinator
    // checks this at entry, before it starts an asynchronous toggle. A command
    // that does not match the current screen direction is dropped instead of
    // inverting the tunnel.
    func permits(_ direction: EngineToggleDirection) -> Bool {
        if primaryAction == direction.primaryAction { return true }
        return menuBar.actions.contains { $0.kind == direction.menuKind && $0.enabled }
    }
}

// One launch's cancellation token. The Coordinator passes it to a protected
// start so a queued start cannot ask for administrator authorization after a
// quit begins. The token is safe to use from the detached start task.
public final class EngineLaunchCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false
    private let condition: (@Sendable () -> Bool)?

    public init() { condition = nil }

    // A token that is also cancelled whenever the condition says so. The
    // tunnel session builds one from its own start fence and the press token,
    // so a stop or a quit that lands after the session last checked still
    // reaches the helper start, even after Stay.
    public init(cancelledWhen condition: @escaping @Sendable () -> Bool) {
        self.condition = condition
    }

    public func cancel() {
        lock.lock()
        cancelled = true
        lock.unlock()
    }

    public var isCancelled: Bool {
        lock.lock()
        let value = cancelled
        lock.unlock()
        return value || condition?() == true
    }
}

// The fencing rules for one engine launch or monitor loop. A start, a quit, or
// a cancelled quit advances a generation. An operation that resumes after an
// await must present its token again before it changes state.
public struct EngineLifetimeFence: Equatable, Sendable {
    public struct Token: Equatable, Sendable {
        public let generation: Int
        public let quitGeneration: Int
        public init(generation: Int, quitGeneration: Int) {
            self.generation = generation
            self.quitGeneration = quitGeneration
        }
    }

    public private(set) var generation = 0
    public private(set) var quitGeneration = 0

    public init() {}

    public var current: Token {
        Token(generation: generation, quitGeneration: quitGeneration)
    }

    @discardableResult
    public mutating func beginStart() -> Token {
        generation += 1
        return current
    }

    @discardableResult
    public mutating func beginQuit() -> Token {
        quitGeneration += 1
        generation += 1
        return current
    }

    // Stay keeps the app open. The quit that produced the alert is over, so a
    // monitor or start from that quit must not apply its result.
    @discardableResult
    public mutating func cancelQuit() -> Token {
        generation += 1
        return current
    }

    public func permits(_ token: Token, stopping: Bool) -> Bool {
        !stopping && token == current
    }
}

// Run one stop or restart at a time. A monitor restart holds the gate while it
// stops and starts the user engine. A quit waits for that restart before it
// stops the same process. A queued restart that wakes after a quit checks its
// lifetime token and returns without starting anything.
public actor SerialOperationGate {
    private var busy = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    public init() {}

    public func acquire() async {
        if !busy {
            busy = true
            return
        }
        await withCheckedContinuation { continuation in
            waiters.append(continuation)
        }
    }

    public func release() {
        if waiters.isEmpty {
            busy = false
            return
        }
        // The next waiter inherits the held slot. busy stays true so a third
        // caller cannot slip in between the resume and the waiter's return.
        waiters.removeFirst().resume()
    }
}

// The result of a quit attempt. The generation fences a late Stay reply from
// an older alert. The launch state is restored from the same snapshot when a
// person chooses Stay.
public struct QuitPreparation: Equatable {
    public var outcome: EngineStopOutcome
    public var generation: Int

    public init(outcome: EngineStopOutcome, generation: Int) {
        self.outcome = outcome
        self.generation = generation
    }
}

// What the app restarts after the person chooses Stay. The quit cancelled the
// user engine monitor and the status poll before it decided anything. A quit
// that returned early, because a tunnel start or a cleanup retry did not settle
// in time, leaves the user engine and the model alive. Stay must then resume
// both the poll and the monitor; without the monitor, a later user engine death
// shows no lost screen and does not stop the tunnel.
public enum QuitStayPlan: Equatable, Sendable {
    // The quit stopped the user engine and no cleanup is pending.
    case startUserEngine
    // The model survived the quit. Resume its poll, and the user engine
    // monitor when the engine survived too.
    case resume(monitorEngine: Bool)
    // Nothing to restart. A pending stop keeps the launch screen and its
    // Retry cleanup action.
    case none

    public static func after(
        engineAlive: Bool,
        modelAlive: Bool,
        pendingCleanup: TunnelCleanupPending?,
        restored: EngineLaunchState
    ) -> QuitStayPlan {
        if !engineAlive, !modelAlive, pendingCleanup == nil,
           restored == .running || restored == .waiting {
            return .startUserEngine
        }
        if modelAlive {
            return .resume(monitorEngine: engineAlive)
        }
        return .none
    }
}

// One plain launch or loss failure. The message is safe to show. The
// diagnostic code holds no path, token, or identity key.
public struct EngineLaunchFailure: Equatable {
    public enum Kind: Equatable {
        case helper
        case authorization
        case cleanup
        case engine
    }

    public var kind: Kind
    public var message: String
    public var recovery: String
    public var diagnosticCode: String
    // True when the helper or the app already reached its final answer for
    // this cleanup. A retry cannot produce new evidence, so the launch screen
    // offers no action and keeps only the recovery text and diagnostics.
    public var cleanupIsFinal: Bool

    public init(kind: Kind, message: String, recovery: String, diagnosticCode: String, cleanupIsFinal: Bool = false) {
        self.kind = kind
        self.message = message
        self.recovery = recovery
        self.diagnosticCode = diagnosticCode
        self.cleanupIsFinal = cleanupIsFinal
    }

    // The user engine runs as the signed-in user. Its failures never mention
    // the protected helper.
    public static func fromUserEngine(_ error: Error) -> EngineLaunchFailure {
        if let backend = error as? BackendError {
            switch backend {
            case .missingEngine:
                return EngineLaunchFailure(kind: .engine, message: Strings.engineMissing, recovery: EngineLaunchText.engineRecovery, diagnosticCode: "engine_missing")
            case .timeout:
                return EngineLaunchFailure(kind: .engine, message: EngineLaunchText.engineTimeout, recovery: EngineLaunchText.engineRecovery, diagnosticCode: "engine_timeout")
            case .exited:
                return EngineLaunchFailure(kind: .engine, message: EngineLaunchText.engineExited, recovery: EngineLaunchText.engineRecovery, diagnosticCode: "engine_exited")
            case .testDataEngine:
                return EngineLaunchFailure(kind: .engine, message: EngineLaunchText.testDataEngine, recovery: EngineLaunchText.testDataEngineRecovery, diagnosticCode: "engine_test_data")
            default:
                break
            }
        }
        return EngineLaunchFailure(kind: .engine, message: Strings.sanitized(error.localizedDescription) ?? Strings.helperFailed, recovery: EngineLaunchText.engineRecovery, diagnosticCode: "engine_error")
    }

    // A real start failure. The helper decides whether a start is allowed. This
    // mapping only chooses the plain sentence, the recovery step, and the
    // diagnostic code.
    public static func fromHelper(_ error: Error) -> EngineLaunchFailure {
        // The engine stopped before any administrator authorization, so the
        // tunnel did not start and no route changed. This is not a cleanup.
        if let failure = error as? HelperEngineDidNotStart {
            return EngineLaunchFailure(
                kind: .engine,
                message: Strings.tunnelDidNotStart(failure.reason),
                recovery: EngineLaunchText.engineRecovery,
                diagnosticCode: "engine_did_not_start"
            )
        }
        if let backend = error as? BackendError {
            switch backend {
            case .timeout:
                return EngineLaunchFailure(kind: .engine, message: EngineLaunchText.engineTimeout, recovery: EngineLaunchText.engineRecovery, diagnosticCode: "engine_timeout")
            case .exited:
                return EngineLaunchFailure(kind: .engine, message: EngineLaunchText.engineExited, recovery: EngineLaunchText.engineRecovery, diagnosticCode: "engine_exited")
            default:
                break
            }
        }
        guard let error = error as? HelperTrustError else {
            return EngineLaunchFailure(kind: .helper, message: Strings.helperFailed, recovery: EngineLaunchText.helperRecovery, diagnosticCode: "helper_error")
        }
        switch error {
        case .cancelled:
            return EngineLaunchFailure(kind: .authorization, message: Strings.helperAuthorizationCancelled, recovery: EngineLaunchText.authorizationRecovery, diagnosticCode: "authorization_cancelled")
        case .notAuthorized:
            return EngineLaunchFailure(kind: .authorization, message: Strings.helperNotAuthorized, recovery: EngineLaunchText.authorizationRecovery, diagnosticCode: "not_authorized")
        case .authorizationBusy:
            return EngineLaunchFailure(kind: .authorization, message: Strings.helperAuthorizationBusy, recovery: EngineLaunchText.authorizationBusyRecovery, diagnosticCode: "authorization_busy")
        case .cleanupBlocked:
            return cleanupFailure(code: "cleanup_blocked", isFinal: true)
        case .engineStopTimedOut:
            return cleanupFailure(code: "cleanup_timeout")
        case .engineExitUnclean:
            return cleanupFailure(code: "cleanup_unclean")
        case .engineExited:
            return cleanupFailure(code: "cleanup_engine_exited")
        case .stopNotConfirmed:
            return cleanupFailure(code: "cleanup_unconfirmed")
        case .missingSigningIdentity, .invalidSigningPolicy, .signatureUnavailable,
             .signatureRejected, .callerRejected:
            return EngineLaunchFailure(kind: .helper, message: Strings.helperNotSigned, recovery: EngineLaunchText.signingRecovery, diagnosticCode: "helper_signature")
        case .notInstalledPath, .pathIsNotCanonical, .executableNotRegularFile,
             .executableNotOwnedByRoot, .executableWritable, .unsafeParentDirectory,
             .unsafeInstallRoot, .launchDaemonPlistMissing, .launchDaemonPlistUnsafe,
             .launchDaemonPlistMismatch, .bundleOutsideApplications, .helperOutsideBundle,
             .bundleNotOwnedByRoot, .bundleWritable, .signedAppMissing, .requiresRoot,
             .aclUnavailable:
            return EngineLaunchFailure(kind: .helper, message: Strings.helperNotInstalled, recovery: EngineLaunchText.installRecovery, diagnosticCode: "helper_install")
        case .helperBusy:
            return EngineLaunchFailure(kind: .helper, message: Strings.helperBusy, recovery: EngineLaunchText.busyRecovery, diagnosticCode: "helper_busy")
        case .startRightNotConfigured:
            return EngineLaunchFailure(kind: .helper, message: Strings.helperRightNotConfigured, recovery: EngineLaunchText.installRecovery, diagnosticCode: "start_right_missing")
        case .startExclusionBusy:
            return EngineLaunchFailure(kind: .helper, message: Strings.helperStartExclusionBusy, recovery: EngineLaunchText.startExclusionBusyRecovery, diagnosticCode: "start_exclusion_busy")
        case .startExclusionUnavailable:
            return EngineLaunchFailure(kind: .helper, message: Strings.helperStartExclusionUnavailable, recovery: EngineLaunchText.startExclusionUnavailableRecovery, diagnosticCode: "start_exclusion_unavailable")
        case .notConnected, .helperTimeout, .helperUnavailable:
            return EngineLaunchFailure(kind: .helper, message: Strings.helperLost, recovery: EngineLaunchText.helperRecovery, diagnosticCode: "helper_lost")
        case .handshakeRequired:
            return EngineLaunchFailure(kind: .helper, message: Strings.helperStopped, recovery: EngineLaunchText.helperRecovery, diagnosticCode: "helper_unavailable")
        case .tunnelNotRunning:
            return EngineLaunchFailure(kind: .engine, message: Strings.helperTunnelNotRunning, recovery: EngineLaunchText.engineRecovery, diagnosticCode: "tunnel_not_running")
        case .authorizationTimedOut:
            return EngineLaunchFailure(kind: .authorization, message: Strings.helperAuthorizationTimedOut, recovery: EngineLaunchText.authorizationTimeoutRecovery, diagnosticCode: "authorization_timeout")
        case .grantFailed:
            return EngineLaunchFailure(kind: .authorization, message: Strings.helperGrantFailed, recovery: EngineLaunchText.engineRecovery, diagnosticCode: "authorization_failed")
        case .engineStartFailed:
            return EngineLaunchFailure(kind: .engine, message: EngineLaunchText.engineStartFailed, recovery: EngineLaunchText.engineRecovery, diagnosticCode: "engine_start")
        default:
            return EngineLaunchFailure(kind: .helper, message: Strings.helperFailed, recovery: EngineLaunchText.helperRecovery, diagnosticCode: "helper_error")
        }
    }

    // The helper connection ended after a start. A lost connection is a stop,
    // never a restart. Do not call this a clean stop.
    public static func fromLost(_ error: Error?) -> EngineLaunchFailure {
        guard let error else {
            return EngineLaunchFailure(kind: .helper, message: Strings.helperLost, recovery: EngineLaunchText.helperRecovery, diagnosticCode: "helper_lost")
        }
        guard let helper = error as? HelperTrustError else {
            return EngineLaunchFailure(kind: .helper, message: Strings.helperLost, recovery: EngineLaunchText.helperRecovery, diagnosticCode: "helper_lost")
        }
        switch helper {
        case .cleanupBlocked:
            return cleanupFailure(code: "cleanup_blocked", isFinal: true)
        case .engineStopTimedOut:
            return cleanupFailure(code: "cleanup_timeout")
        case .engineExitUnclean:
            return cleanupFailure(code: "cleanup_unclean")
        case .engineExited:
            return cleanupFailure(code: "cleanup_engine_exited")
        case .stopNotConfirmed:
            return cleanupFailure(code: "cleanup_unconfirmed")
        case .notConnected, .helperTimeout, .helperUnavailable, .handshakeRequired:
            return EngineLaunchFailure(kind: .helper, message: Strings.helperLost, recovery: EngineLaunchText.helperRecovery, diagnosticCode: "helper_lost")
        case .engineStartFailed:
            return EngineLaunchFailure(kind: .engine, message: EngineLaunchText.engineStartFailed, recovery: EngineLaunchText.engineRecovery, diagnosticCode: "engine_start")
        default:
            return fromHelper(helper)
        }
    }

    // A lost user engine after a running tunnel. If the tunnel stop did not
    // confirm cleanup, that result wins over the plain engine loss. A status
    // that says running false is not cleanup proof, so the message comes from
    // the stop outcome, not from the lost engine.
    // The pending kind chooses the recovery text and whether Retry cleanup is
    // offered. A missing kind is retryable: the lost engine's stop result is
    // not a final helper answer.
    public static func fromUserEngineLoss(cleanup message: String?, kind: TunnelCleanupKind?) -> EngineLaunchFailure {
        guard let message, !message.isEmpty else {
            // The helper confirmed the tunnel stop (or the tunnel was never
            // running). The dead user engine is a separate loss. Do not use the
            // start failure text and never let it replace the confirmed stop
            // with an unproven cleanup claim.
            return EngineLaunchFailure(
                kind: .engine,
                message: EngineLaunchText.engineStopped,
                recovery: EngineLaunchText.engineRecovery,
                diagnosticCode: "engine_exited"
            )
        }
        let markKind = kind ?? .retryable
        return EngineLaunchFailure(
            kind: .cleanup,
            message: Strings.sanitized(message) ?? Strings.helperCleanup,
            recovery: EngineLaunchText.recovery(for: markKind),
            diagnosticCode: "engine_lost_cleanup",
            cleanupIsFinal: markKind != .retryable
        )
    }

    // A failed Retry cleanup. The kind of the current mark, not of this one
    // answer, decides the text: a newer final mark wins over a retryable reply.
    public static func fromCleanupRetry(message: String, kind: TunnelCleanupKind) -> EngineLaunchFailure {
        EngineLaunchFailure(
            kind: .cleanup,
            message: Strings.sanitized(message) ?? message,
            recovery: EngineLaunchText.recovery(for: kind),
            diagnosticCode: kind == .durableBlock ? "cleanup_retry_blocked" : "cleanup_retry",
            cleanupIsFinal: kind != .retryable
        )
    }

    // A cleanup block, a stop timeout, an unclean exit, and an unprompted
    // engine exit all mean the same thing to a person: the app cannot prove
    // that the routes were removed. The durable block does not clear on a
    // target device restart, so the recovery text must not suggest one.
    //
    // The durable helper block is final. Every later start is refused until a
    // person completes the documented recovery, so Retry cleanup would loop
    // without new evidence. A timeout or an unclean exit can still change on a
    // later helper read, so only the block bit is set here.
    private static func cleanupFailure(code: String, isFinal: Bool = false) -> EngineLaunchFailure {
        EngineLaunchFailure(
            kind: .cleanup,
            message: Strings.helperCleanup,
            recovery: EngineLaunchText.cleanupRecovery,
            diagnosticCode: code,
            cleanupIsFinal: isFinal
        )
    }
}

// The words for the launch screen and the menu. These stay in one place so a
// failed start never shows an unrelated tunnel state.
public enum EngineLaunchText {
    public static let startAction = "Start HotspotShade"
    public static let retryCleanupAction = "Retry cleanup"
    public static let waitingTitle = "HotspotShade is ready"
    public static let waitingMessage = "HotspotShade runs its engine as your account. macOS asks for administrator authorization only when you turn on the tunnel."
    public static let startingTitle = "Starting HotspotShade"
    public static let startingHelperMessage = "The engine is starting as your account. No administrator authorization is needed for this step."
    public static let stoppingTitle = "Turning off the tunnel"
    public static let stoppingMessage = "Wait for HotspotShade to stop the tunnel, then quit."
    public static let failedTitle = "HotspotShade did not start"
    public static let lostTitle = "HotspotShade needs attention"
    public static let runningTitle = "HotspotShade is running"
    public static let runningMessage = "The engine is ready."
    public static let engineTimeout = "The engine did not answer in time."
    public static let engineExited = "The engine stopped while it was starting."
    // The bundled engine answered with its test data. That is a wrong engine
    // build or launch, never a mode of this app.
    public static let testDataEngine = "The engine answered with test data instead of real status."
    public static let testDataEngineRecovery = "Reinstall HotspotShade. If this keeps happening, copy diagnostics and report it."
    public static let engineStartFailed = "The protected helper did not start the engine."
    public static let engineStopped = "The engine stopped. Turn the tunnel on again."
    public static let stopTimedOut = "The protected helper did not confirm that the engine stopped in time."
    public static let stopUnclean = "The engine stopped without a clean helper stop, so HotspotShade cannot confirm that its routes were removed."
    public static let stopUnverified = "The protected helper did not report a clean engine stop, so HotspotShade cannot confirm that the tunnel stopped."
    // The helper stopped the engine at the authorization deadline, but this
    // stop answer did not confirm it yet. The helper record is retried.
    public static let stopAuthorizationTimedOut = "The administrator authorization was not completed in time, so the protected helper stopped the tunnel before it started. HotspotShade could not confirm that stop yet."
    public static let elevatedSessionOpen = "A previous elevated tunnel session is still open. Turn the tunnel off before you start again."
    // The helper confirmed that no elevated engine remains, but the app never
    // saw that engine's own route cleanup. A later stop cannot recover the
    // observation, so the text tells the person what to check instead of
    // offering a retry that would always return this answer.
    public static let routeCleanupUnverified = "The tunnel engine stopped, but HotspotShade did not see its route cleanup."
    public static let routeCleanupRecovery = "Stop testing and have an administrator check for leftover routes. Restarting the app forgets this warning, so check before you start it again."
    public static let authorizationRecovery = "Choose an administrator account and allow access when macOS asks, then try again."
    public static let authorizationBusyRecovery = "Finish the open administrator prompt, then try again."
    // The helper stops a tunnel engine whose administrator authorization was
    // not completed within its deadline.
    public static let authorizationTimeoutRecovery = "Turn the tunnel on again and answer the administrator prompt within 2 minutes."
    // The cleanup marker survives a helper restart and a target device restart.
    // Recovery needs an administrator who checks for leftover routes and
    // follows the helper recovery steps. Do not tell a person to reboot in the
    // hope that the block clears.
    public static let cleanupRecovery = "Stop testing. Have an administrator run netstat -rn and confirm that no HotspotShade route remains: no 0/1 or 128.0/1 route through a utun and no 2000::/3 route. Only then run sudo hotspotshade-installer-coordinator preview-clear-cleanup-block from the preview coordinator folder. Restarting the target device does not clear it."
    // A retryable mark is not a cleanup block. The helper may still confirm
    // the exact session, so the text names the retry and the check to make
    // until then, and does not mention a block that the helper never set.
    public static let quitRecovery = "Choose Retry cleanup to ask the protected helper again. Until it confirms the stop, check for leftover routes before you use the network."

    // The one recovery sentence for each cleanup mark. A durable block keeps
    // its no-clear text, because the helper refuses every start after a relaunch
    // too. A route-unverified mark lives only in app memory, so its text says
    // that a relaunch forgets it. A retryable mark names the retry.
    public static func recovery(for kind: TunnelCleanupKind) -> String {
        switch kind {
        case .retryable: return quitRecovery
        case .routesUnverified: return routeCleanupRecovery
        case .durableBlock: return cleanupRecovery
        }
    }
    public static let helperRecovery = "Try again. If this keeps happening, copy diagnostics and restart the target device."
    public static let installRecovery = HelperRequirement.isLocalPreview
        ? "Follow the local preview setup instructions, then try again."
        : "Install the signed helper package, then try again."
    public static let signingRecovery = HelperRequirement.isLocalPreview
        ? "Use an Apple Development preview build that matches the installed helper, then try again."
        : "Use a Developer ID build that matches the installed helper, then try again."
    public static let busyRecovery = "Close the other HotspotShade window, then try again."
    public static let startExclusionBusyRecovery = "Wait for the install or upgrade to finish, then try again."
    public static let startExclusionUnavailableRecovery = "Try again later. If this keeps happening, copy diagnostics and reinstall HotspotShade."
    public static let engineRecovery = "Try again. If this keeps happening, copy diagnostics and restart HotspotShade."
}

// One action on the launch screen. A final cleanup failure has no action; the
// screen keeps the recovery text, the copy button, and the quit command.
public enum EngineLaunchAction: Equatable {
    case start
    case retry
    case retryCleanup

    public var title: String {
        switch self {
        case .start: return EngineLaunchText.startAction
        case .retry: return Strings.tryAgain
        case .retryCleanup: return EngineLaunchText.retryCleanupAction
        }
    }
}

// The one presentation of a launch state. The view draws this and the tests
// compare it without a window.
public struct EngineLaunchPresentation: Equatable {
    public var title: String
    public var message: String
    public var recovery: String?
    public var action: EngineLaunchAction?
    public var showsProgress: Bool
    public var isAttention: Bool
    public var showsCopyDiagnostics: Bool

    public init(title: String, message: String, recovery: String?, action: EngineLaunchAction?, showsProgress: Bool, isAttention: Bool, showsCopyDiagnostics: Bool) {
        self.title = title
        self.message = message
        self.recovery = recovery
        self.action = action
        self.showsProgress = showsProgress
        self.isAttention = isAttention
        self.showsCopyDiagnostics = showsCopyDiagnostics
    }

    public var actionTitle: String? { action?.title }
}

public extension EngineLaunchState {
    func presentation() -> EngineLaunchPresentation {
        switch self {
        case .waiting:
            return EngineLaunchPresentation(title: EngineLaunchText.waitingTitle, message: EngineLaunchText.waitingMessage, recovery: nil, action: .start, showsProgress: false, isAttention: false, showsCopyDiagnostics: true)
        case .starting:
            return EngineLaunchPresentation(title: EngineLaunchText.startingTitle, message: EngineLaunchText.startingHelperMessage, recovery: nil, action: nil, showsProgress: true, isAttention: false, showsCopyDiagnostics: true)
        case .running:
            return EngineLaunchPresentation(title: EngineLaunchText.runningTitle, message: EngineLaunchText.runningMessage, recovery: nil, action: nil, showsProgress: false, isAttention: false, showsCopyDiagnostics: true)
        case .stopping:
            return EngineLaunchPresentation(title: EngineLaunchText.stoppingTitle, message: EngineLaunchText.stoppingMessage, recovery: nil, action: nil, showsProgress: true, isAttention: false, showsCopyDiagnostics: false)
        case .failed(let failure):
            return EngineLaunchPresentation(title: EngineLaunchText.failedTitle, message: failure.message, recovery: failure.recovery, action: .retry, showsProgress: false, isAttention: true, showsCopyDiagnostics: true)
        case .lost(let failure):
            return EngineLaunchPresentation(
                title: EngineLaunchText.lostTitle,
                message: failure.message,
                recovery: failure.recovery,
                action: launchAction(for: failure),
                showsProgress: false,
                isAttention: true,
                showsCopyDiagnostics: true
            )
        }
    }

    // A final cleanup mark is not a Retry cleanup target. The helper already
    // gave its final answer, and the app-owned route mark has no recoverable
    // observation. The person checks the network and quits, and the screen
    // never pretends that one more press can clear it.
    private func launchAction(for failure: EngineLaunchFailure) -> EngineLaunchAction? {
        guard failure.kind == .cleanup else { return .retry }
        return failure.cleanupIsFinal ? nil : .retryCleanup
    }
}

// The menu content before an AppModel exists. A failed launch must not show
// "HotspotShade is starting" forever.
public enum EngineLaunchMenu {
    public static func content(state: EngineLaunchState, quitting: Bool) -> MenuBarContent {
        let presentation = state.presentation()
        let icon = symbol(for: state)
        let header = MenuBarItem(id: "status", kind: .statusHeader, title: presentation.title, symbol: icon, isEnabled: false)
        let detail = MenuBarItem(id: "detail", kind: .statusDetail, title: detail(for: state), isEnabled: false)
        var notices: [MenuBarItem] = []
        if let recovery = presentation.recovery {
            notices.append(MenuBarItem(id: "notice-0", kind: .notice, title: recovery, symbol: "exclamationmark.triangle", isEnabled: false))
        }
        let open = MenuBarItem(id: "open", kind: .open, title: Strings.openApp, symbol: "macwindow")
        let copy = MenuBarItem(id: "copyDiagnostics", kind: .copyDiagnostics, title: UIStrings.copyDiagnostics, symbol: "doc.on.doc", isEnabled: presentation.showsCopyDiagnostics && !quitting)
        let settings = MenuBarItem(id: "settings", kind: .settings, title: UIStrings.settingsMenu, symbol: "gearshape", shortcut: .commandComma)
        let quit = MenuBarItem(id: "quit", kind: .quit, title: quitting ? UIStrings.turningOff : Strings.quit, symbol: "power", shortcut: .commandQ, isEnabled: !quitting, help: quitting ? UIStrings.turningOffNote : nil)
        return MenuBarContent(iconSymbol: icon, stateWord: stateWord(for: state), header: header, detail: detail, actions: [], notices: notices, open: open, copyDiagnostics: copy, settings: settings, quit: quit)
    }

    private static func detail(for state: EngineLaunchState) -> String {
        switch state {
        case .waiting: return "Open HotspotShade to start its engine."
        case .starting: return "The engine is starting as your account."
        case .running: return EngineLaunchText.runningMessage
        case .stopping: return "Wait for the tunnel to stop."
        case .failed(let failure), .lost(let failure): return failure.message
        }
    }

    private static func stateWord(for state: EngineLaunchState) -> String {
        switch state {
        case .waiting: return "Ready"
        case .starting: return "Starting"
        case .running: return "On"
        case .stopping: return "Turning off"
        case .failed, .lost: return "Needs attention"
        }
    }

    private static func symbol(for state: EngineLaunchState) -> String {
        switch state {
        case .waiting: return "network.slash"
        case .starting, .stopping: return "hourglass"
        case .running: return "network"
        case .failed, .lost: return "exclamationmark.triangle"
        }
    }
}

// Copy diagnostics without an engine. The report stays local and holds no
// token, host, or identity key.
public enum EngineLaunchDiagnostics {
    public static func text(state: EngineLaunchState, appVersion: String, macOSVersion: String, now: Date = Date()) -> String {
        var lines: [String] = []
        lines.append("HotspotShade start diagnostics")
        lines.append("Time: \(timeWord(now))")
        lines.append("macOS: \(macOSVersion)")
        lines.append("App: \(appVersion)")
        lines.append("Engine owner: your account")
        lines.append("Engine: \(stateWord(state))")
        if let failure = state.failure {
            lines.append("Reason: \(failure.diagnosticCode)")
            lines.append("Message: \(failure.message)")
            lines.append("Recovery: \(failure.recovery)")
        }
        if case .lost(let failure) = state, failure.kind == .helper {
            lines.append("Note: The protected helper connection ended. The app did not restart it.")
        }
        if case .waiting = state {
            lines.append("Note: No engine start was attempted. No administrator authorization was requested.")
        }
        return lines.joined(separator: "\n")
    }

    private static func stateWord(_ state: EngineLaunchState) -> String {
        switch state {
        case .waiting: return "not started"
        case .starting: return "starting"
        case .running: return "running"
        case .stopping: return "stopping"
        case .failed: return "failed"
        case .lost: return "unavailable"
        }
    }

    private static func timeWord(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.string(from: date)
    }
}

// What happened when the app asked the engine and the helper to stop. The quit
// path never claims a clean stop when it could not observe one.
// The API stop reply alone does not prove the later service state. This check
// is shared by the app's quit coordinator and its hermetic tests.
public enum TunnelQuitCheck {
    public static func stop(_ backend: BackendClient) async -> EngineStopOutcome {
        // An elevated session has its own helper process and grant directory.
        // Stop it even when the elevated status already says the tunnel is off,
        // because a previous helper stop may have been uncertain. A pending
        // stop with no selected elevated backend still needs the helper stop.
        if let router = backend as? TunnelRoutingBackend,
           router.activeBackendIsElevated || router.hasPendingStop {
            let message = await router.stopForQuit()
            return message.map { EngineStopOutcome.uncertain($0) } ?? .stopped
        }
        if let live = try? await backend.status(timeout: 2) {
            if !live.engineHealth.isNormal {
                return .uncertain(live.engineHealth == .cleanupBlocked ? Strings.cleanupBlockedBody : Strings.serviceStateUnknownBody)
            }
            if live.running == false { return .notRunning }
        }
        var stopError: String?
        do {
            try await backend.stopTunnel(timeout: 45)
        } catch {
            stopError = Strings.sanitized(error.localizedDescription)
        }
        guard let live = try? await backend.status(timeout: 2) else {
            return .uncertain(stopError ?? "The engine did not confirm the tunnel stop.")
        }
        guard live.engineHealth.isNormal else {
            return .uncertain(live.engineHealth == .cleanupBlocked ? Strings.cleanupBlockedBody : Strings.serviceStateUnknownBody)
        }
        guard live.running == false else {
            return .uncertain(stopError ?? "The engine did not confirm the tunnel stop.")
        }
        return stopError == nil ? .stopped : .notRunning
    }
}

public enum EngineStopOutcome: Equatable {
    case notRunning
    // An engine launch was still in progress. The app did not wait for an
    // administrator prompt. Process exit closes the helper connection, which
    // stops a late engine.
    case startPending
    // A stop request was sent but no later result was observed. The current
    // helper API returns the result, so only a legacy path can produce this.
    case stopRequested
    case stopped
    case uncertain(String)

    public var isUncertain: Bool {
        if case .uncertain = self { return true }
        return false
    }

    public var message: String? {
        if case .uncertain(let text) = self { return text }
        return nil
    }

    // Interpret one helper stop reply. A reply that this connection did not
    // own proves nothing about the caller's earlier engine. It can confirm an
    // idle helper only when the helper names the exact session that stopped and
    // records a clean result for it. That is the difference between a real
    // confirmation and a second connection's empty acknowledgement.
    //
    // This wrapper keeps the earlier outcome type for its existing callers.
    // The lifecycle uses TunnelStopResult.fromHelperStop below, which also
    // reports whether a retry can still change the answer.
    public static func fromHelperStop(
        reply: HelperStopReply?,
        previous: ProtectedHelperClientState,
        session: UUID?,
        everStarted: Bool
    ) -> EngineStopOutcome {
        TunnelStopResult.fromHelperStop(
            reply: reply,
            previous: previous,
            session: session,
            everStarted: everStarted
        ).outcome
    }

    // Interpret a status read used to confirm cleanup without a process handle.
    // A live or stopping session, a mismatched session id, an unprompted exit,
    // or a cleanup block keeps the uncertainty.
    public static func fromCleanupStatus(
        _ status: HelperStatus,
        session: UUID?,
        everStarted: Bool,
        previous: ProtectedHelperClientState
    ) -> EngineStopOutcome {
        TunnelStopResult.fromCleanupStatus(
            status,
            session: session,
            everStarted: everStarted,
            previous: previous
        ).outcome
    }

    private static func outcome(for result: HelperSessionStopResult) -> EngineStopOutcome {
        switch result {
        case .stopped: return .stopped
        case .timedOut: return .uncertain(EngineLaunchText.stopTimedOut)
        case .failed: return .uncertain(EngineLaunchText.stopUnclean)
        case .engineExited: return .uncertain(EngineLaunchText.stopUnclean)
        // The engine exited before any grant, so it changed no route.
        case .failedStart: return .stopped
        case .none: return .uncertain(EngineLaunchText.stopUnverified)
        }
    }

    private static func protectedStopMessage(_ error: HelperTrustError) -> String {
        TunnelStopResult.protectedStopMessage(error)
    }

    // Merge the tunnel stop and the engine process stop. A confirmed tunnel
    // stop wins over an engine process that the app could not observe. The user
    // engine never owns routes, so its dead process must not turn a confirmed
    // helper stop into an unproven cleanup. An uncertain tunnel stop always
    // wins.
    public static func combine(tunnel: EngineStopOutcome, engine: EngineStopOutcome) -> EngineStopOutcome {
        if tunnel == .stopped { return .stopped }
        if tunnel.isUncertain { return tunnel }
        if engine.isUncertain { return engine }
        if engine == .stopped { return .stopped }
        if tunnel == .startPending || engine == .startPending { return .startPending }
        if tunnel == .stopRequested || engine == .stopRequested { return .stopRequested }
        return .notRunning
    }
}

// The outcome of asking the protected helper to stop. Only a confirmed stop may
// clear an elevated session. An uncertain stop stays latched until a later
// helper stop explicitly confirms, and never clears from a status that says
// running false.
//
// The two terminal cases are distinct from a retryable uncertainty. The helper
// already gave its final answer for them, so another stop call cannot produce
// new route evidence and the UI must not present an endless retry.
public enum TunnelStopResult: Equatable, Sendable {
    case notRunning
    case stopped
    // A helper session or launch may still exist, a stop is still in flight, or
    // the connection was lost. A later stop may confirm.
    case uncertain(String)
    // The helper proved that no engine remains, but route removal was not
    // observed. No later helper call can recover that observation.
    case routesUnverified(String)
    // The helper reported its durable cleanup block. Every start is refused
    // until a person completes the documented recovery.
    case durableBlock(String)

    public var message: String? {
        switch self {
        case .notRunning, .stopped: return nil
        case .uncertain(let text), .routesUnverified(let text), .durableBlock(let text):
            return text
        }
    }

    public var isUncertain: Bool {
        switch self {
        case .notRunning, .stopped: return false
        case .uncertain, .routesUnverified, .durableBlock: return true
        }
    }

    public var cleanupKind: TunnelCleanupKind? {
        switch self {
        case .notRunning, .stopped: return nil
        case .uncertain: return .retryable
        case .routesUnverified: return .routesUnverified
        case .durableBlock: return .durableBlock
        }
    }

    // The engine process API keeps its historic outcome type for the existing
    // callers and tests. The tunnel lifecycle uses the richer value above.
    public var outcome: EngineStopOutcome {
        switch self {
        case .notRunning: return .notRunning
        case .stopped: return .stopped
        case .uncertain(let text), .routesUnverified(let text), .durableBlock(let text):
            return .uncertain(text)
        }
    }
}

// Read one helper answer into the lifecycle type. A session identity is proof
// only when it matches the exact retained id. An idle helper with some other
// clean session record is not proof of this engine's cleanup.
public extension TunnelStopResult {
    static func fromHelperStop(
        reply: HelperStopReply?,
        previous: ProtectedHelperClientState,
        session: UUID?,
        everStarted: Bool,
        requireExistingSession: Bool = false
    ) -> TunnelStopResult {
        guard let reply else {
            if case .unavailable(.cleanupBlocked) = previous {
                return .durableBlock(Strings.helperCleanup)
            }
            return .uncertain(stopMessage(for: previous))
        }
        let status = reply.status
        if status.cleanupBlocked { return .durableBlock(Strings.helperCleanup) }
        if status.running || status.stopping || status.starting {
            // A live engine, an in-flight launch, or an in-flight stop is never
            // a clean stop, even when this connection owned nothing.
            return .uncertain(EngineLaunchText.stopUnverified)
        }
        if reply.owned { return .stopped }
        if let session {
            guard status.lastSession == session else {
                // The exact retained session has no completed record. An idle
                // helper cannot prove that its routes were removed.
                return .routesUnverified(EngineLaunchText.stopUnverified)
            }
            return result(for: status.lastResult)
        }
        // No session id was retained. Only an object that never asked for an
        // engine may call this a non-running state. Once it asked, a clean
        // record for any other session is not this engine's cleanup.
        if !everStarted && !requireExistingSession { return .notRunning }
        return .routesUnverified(EngineLaunchText.stopUnverified)
    }

    static func fromCleanupStatus(
        _ status: HelperStatus,
        session: UUID?,
        everStarted: Bool,
        previous: ProtectedHelperClientState,
        requireExistingSession: Bool = false
    ) -> TunnelStopResult {
        if status.cleanupBlocked { return .durableBlock(Strings.helperCleanup) }
        if status.running || status.stopping || status.starting {
            return .uncertain(EngineLaunchText.stopUnverified)
        }
        if let session {
            guard status.lastSession == session else {
                return .routesUnverified(EngineLaunchText.stopUnverified)
            }
            return result(for: status.lastResult)
        }
        // No exact identity is retained. An unrelated completed session never
        // proves that this engine stopped, and an idle snapshot after a lost
        // start reply does not either.
        if everStarted || requireExistingSession {
            return .routesUnverified(EngineLaunchText.stopUnverified)
        }
        if case .unavailable(let error) = previous {
            return .uncertain(protectedStopMessage(error))
        }
        return .notRunning
    }

    private static func result(for result: HelperSessionStopResult) -> TunnelStopResult {
        switch result {
        case .stopped: return .stopped
        case .timedOut: return .routesUnverified(EngineLaunchText.stopTimedOut)
        case .failed: return .routesUnverified(EngineLaunchText.stopUnclean)
        case .engineExited: return .routesUnverified(EngineLaunchText.stopUnclean)
        // The engine exited before any grant, so it changed no route.
        case .failedStart: return .stopped
        case .none: return .uncertain(EngineLaunchText.stopUnverified)
        }
    }

    private static func stopMessage(for previous: ProtectedHelperClientState) -> String {
        if case .unavailable(let error) = previous {
            return protectedStopMessage(error)
        }
        return EngineLaunchText.stopUnverified
    }

    fileprivate static func protectedStopMessage(_ error: HelperTrustError) -> String {
        switch error {
        case .cleanupBlocked:
            return Strings.helperCleanup
        case .engineStopTimedOut, .helperTimeout, .stopNotConfirmed:
            return EngineLaunchText.stopTimedOut
        case .authorizationTimedOut:
            return EngineLaunchText.stopAuthorizationTimedOut
        case .engineExitUnclean, .engineExited:
            return EngineLaunchText.stopUnclean
        case .notConnected, .helperUnavailable, .responseRejected:
            return Strings.helperLost
        default:
            return EngineLaunchText.stopUnverified
        }
    }
}

public extension TunnelCleanupPending {
    // The defined answer for this mark. A retry of a terminal mark repeats this
    // value and never becomes a clean stop.
    var stopResult: TunnelStopResult {
        switch kind {
        case .retryable: return .uncertain(message)
        case .routesUnverified: return .routesUnverified(message)
        case .durableBlock: return .durableBlock(message)
        }
    }
}

public extension EngineLaunchState {
    // Restore the screen after Stay. Any earlier failure keeps its own message
    // and recovery, so a cleanup block, a cleanup timeout, or a lost helper is
    // not replaced with a weaker generic sentence. A generic quit failure must
    // not hide the guidance that the person already had.
    //
    // A pending helper stop is stronger than any clean-looking previous state.
    // The quit may have looked confirmed, but the app-owned cleanup state still
    // cannot prove that the root engine stopped.
    static func afterCancelledQuit(
        previous: EngineLaunchState?,
        outcome: EngineStopOutcome,
        pendingCleanup: TunnelCleanupPending? = nil
    ) -> EngineLaunchState {
        if let pendingCleanup {
            let message = Strings.sanitized(pendingCleanup.message) ?? pendingCleanup.message
            switch pendingCleanup.kind {
            case .durableBlock:
                return .lost(
                    EngineLaunchFailure(
                        kind: .cleanup,
                        message: message,
                        recovery: EngineLaunchText.cleanupRecovery,
                        diagnosticCode: "quit_cleanup_blocked",
                        cleanupIsFinal: true
                    )
                )
            case .routesUnverified:
                return .lost(
                    EngineLaunchFailure(
                        kind: .cleanup,
                        message: message,
                        recovery: EngineLaunchText.routeCleanupRecovery,
                        diagnosticCode: "quit_routes_unverified",
                        cleanupIsFinal: true
                    )
                )
            case .retryable:
                return .lost(
                    EngineLaunchFailure(
                        kind: .cleanup,
                        message: message,
                        recovery: EngineLaunchText.quitRecovery,
                        diagnosticCode: "quit_unverified"
                    )
                )
            }
        }
        if let previous, previous.failure != nil {
            return previous
        }
        // A cancelled user-engine launch has no engine and no root tunnel. Show
        // the explicit start screen instead of a permanent "starting" screen.
        if previous == .starting, outcome == .startPending {
            return .waiting
        }
        guard let message = outcome.message else {
            if let previous, previous != .stopping { return previous }
            return .waiting
        }
        let failure: EngineLaunchFailure
        if message == Strings.helperCleanup {
            failure = EngineLaunchFailure(
                kind: .cleanup,
                message: Strings.helperCleanup,
                recovery: EngineLaunchText.cleanupRecovery,
                diagnosticCode: "quit_unverified",
                cleanupIsFinal: true
            )
        } else {
            failure = EngineLaunchFailure(
                kind: .cleanup,
                message: message,
                recovery: EngineLaunchText.quitRecovery,
                diagnosticCode: "quit_unverified"
            )
        }
        return .lost(failure)
    }
}
