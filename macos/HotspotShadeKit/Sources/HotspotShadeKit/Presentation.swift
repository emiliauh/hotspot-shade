import Foundation

// The visible state that a view draws. This type is pure. A view never reads
// the engine types directly.
public struct ScreenModel: Equatable {
    // The color family of the status mark.
    public enum StatusKind: String, Equatable {
        // The tunnel is off, or no action is possible.
        case off
        // The tunnel runs.
        case on
        // Something needs the person.
        case attention
        // Pairing waits for the person.
        case pairing
        // A tunnel start or stop runs.
        case busy
    }

    // One action on the main card or a menu.
    public enum Action: String, Equatable {
        // Pair with the source device. Clears the stored forget intent.
        case pair
        // Pair again after the source device rejected the old credentials.
        case pairAgain
        // Turn the tunnel on.
        case turnOn
        // Turn the tunnel off.
        case turnOff
        // Try the failed request again.
        case retry
        // Probe the source device and refresh the status now.
        case checkNow
        // Stop the tunnel, wait for stopped, then forget. Uses the model
        // method turnOffAndForget().
        case turnOffAndForget
        // Forget the source device.
        case forget
        public var label: String {
            switch self {
            case .pair: return Strings.pair
            case .pairAgain: return Strings.pairAgain
            case .turnOn: return Strings.turnOn
            case .turnOff: return Strings.turnOff
            case .retry: return Strings.tryAgain
            case .checkNow: return Strings.checkNow
            case .turnOffAndForget: return Strings.turnOffAndForget
            case .forget: return Strings.forget
            }
        }
    }

    // The source device card. Each line is plain text that the view shows
    // without changes.
    public struct DeviceCard: Equatable {
        public var lines: [String]
        public init(lines: [String] = []) { self.lines = lines }
    }

    // The connection card. The named fields are the same values that the lines
    // hold, so a view can place them on its own. A nil value means that the
    // engine has no data and the view shows nothing for that field.
    public struct ConnectionCard: Equatable {
        public var lines: [String]
        public var ping: String?
        public var activeConnections: String?
        public var lastStop: String?
        public var lastChecked: String?
        public init(lines: [String] = [], ping: String? = nil, activeConnections: String? = nil, lastStop: String? = nil, lastChecked: String? = nil) {
            self.lines = lines; self.ping = ping; self.activeConnections = activeConnections
            self.lastStop = lastStop; self.lastChecked = lastChecked
        }
    }

    // One item in the menu. Every action is always present, with an enabled
    // flag. A disabled action has a plain reason.
    public struct MenuBarAction: Equatable {
        public enum Kind: String, Equatable {
            case turnOn, turnOff, pair, cancel, open, checkNow, quit
        }
        // The action that the menu item runs.
        public var kind: Kind
        // False when the action is not safe now. The view must show it grayed.
        public var enabled: Bool
        // The plain reason for a disabled action. It is nil when enabled.
        public var reason: String?
        public init(kind: Kind, enabled: Bool, reason: String? = nil) {
            self.kind = kind; self.enabled = enabled; self.reason = reason
        }
        public var label: String {
            switch kind {
            case .turnOn: return Strings.turnOn
            case .turnOff: return Strings.turnOff
            case .pair: return Strings.pair
            case .cancel: return Strings.cancel
            case .open: return Strings.openApp
            case .checkNow: return Strings.checkNow
            case .quit: return Strings.quit
            }
        }
    }

    // The menu bar status item.
    public struct MenuBar: Equatable {
        public enum Icon: String, Equatable { case off, on, attention, busy }
        // The icon family for the menu bar item.
        public var icon: Icon
        // One short line for the menu bar menu header.
        public var statusLine: String
        // Every action, in a stable order.
        public var actions: [MenuBarAction]
        public init(icon: Icon, statusLine: String, actions: [MenuBarAction]) {
            self.icon = icon; self.statusLine = statusLine; self.actions = actions
        }
    }

    // The main heading on the screen.
    public var title: String
    // The sentence under the heading. It is never empty.
    public var subtitle: String
    // The one action on the main card. It is nil when no action is safe.
    public var primaryAction: Action?
    // A second, optional action, for example "Turn off and forget".
    public var secondaryAction: Action?
    // The color family of the status mark.
    public var statusKind: StatusKind
    // The source device card. It is empty when the status is unavailable.
    public var sourceDevice: DeviceCard
    // The connection card. It is empty when the status is unavailable.
    public var connection: ConnectionCard
    // Plain lines that need attention. The view may show them as a list.
    public var attentionItems: [String]
    public var menuBar: MenuBar
    // True when Try again would start the tunnel, so the view can explain the
    // administrator authorization before the retry runs.
    public var retryStartsTunnel: Bool
    public init(title: String, subtitle: String, primaryAction: Action?, secondaryAction: Action? = nil, statusKind: StatusKind, sourceDevice: DeviceCard = DeviceCard(), connection: ConnectionCard = ConnectionCard(), attentionItems: [String] = [], menuBar: MenuBar, retryStartsTunnel: Bool = false) {
        self.title = title; self.subtitle = subtitle; self.primaryAction = primaryAction
        self.secondaryAction = secondaryAction; self.statusKind = statusKind
        self.sourceDevice = sourceDevice; self.connection = connection
        self.attentionItems = attentionItems; self.menuBar = menuBar
        self.retryStartsTunnel = retryStartsTunnel
    }
}

// Every input that builds one ScreenModel. The table is pure, so every row is
// a test without a backend.
public struct PresentationInput: Equatable {
    // The pure derive inputs: tunnel, pairing, trust, forget, freshness.
    public var derive: DeriveInput
    // "Ping is on." or "Ping is off.". Nil when the engine has no value.
    public var pingLine: String?
    // The active connection count line. Nil when the engine has no value.
    public var connectionsLabel: String?
    // "Last stop: ...". Nil when there is no stop.
    public var lastStopLine: String?
    // "Checked just now", "Checked N seconds ago", or "Checked N minutes ago".
    public var lastCheckedText: String?
    // The plain Wi-Fi advice lines.
    public var linkAdvice: [String]
    // True when macOS denied notification permission.
    public var notificationsDenied: Bool
    // True when a Forget request was refused because the tunnel runs.
    public var forgetBlocked: Bool
    // True while a state-changing action owns the engine. The actions are
    // disabled and the main card shows the matching busy line.
    public var forgetInFlight: Bool
    public var pairingCancelInFlight: Bool
    public var pairingStartInFlight: Bool
    public var pairingCancelRequested: Bool
    // True when Try again would start the tunnel. The dashboard then explains
    // the administrator authorization before the retry runs.
    public var retryStartsTunnel: Bool
    public init(derive: DeriveInput = DeriveInput(), pingLine: String? = nil, connectionsLabel: String? = nil, lastStopLine: String? = nil, lastCheckedText: String? = nil, linkAdvice: [String] = [], notificationsDenied: Bool = false, forgetBlocked: Bool = false, forgetInFlight: Bool = false, pairingCancelInFlight: Bool = false, pairingStartInFlight: Bool = false, pairingCancelRequested: Bool = false, retryStartsTunnel: Bool = false) {
        self.derive = derive; self.pingLine = pingLine; self.connectionsLabel = connectionsLabel
        self.lastStopLine = lastStopLine; self.lastCheckedText = lastCheckedText
        self.linkAdvice = linkAdvice; self.notificationsDenied = notificationsDenied
        self.forgetBlocked = forgetBlocked
        self.forgetInFlight = forgetInFlight; self.pairingCancelInFlight = pairingCancelInFlight
        self.pairingStartInFlight = pairingStartInFlight; self.pairingCancelRequested = pairingCancelRequested
        self.retryStartsTunnel = retryStartsTunnel
    }
}

public enum ScreenPresentation {
    // Build the visible model from one input. The derive table holds the main
    // title, subtitle, and one primary action. This function adds the cards,
    // the attention list, and the menu.
    public static func build(_ input: PresentationInput) -> ScreenModel {
        // The main card normalizes a stale paired phase. Mirror that here so
        // the cards, the secondary action, and the menu agree with it.
        var input = input
        input.derive.pairing = AppModel.livePairing(input.derive)
        let derived = AppModel.derive(input.derive).dashboard
        let kind = statusKind(input)
        let title = derived.title
        let busy = actionBusy(input)
        var subtitle = derived.subtitle
        if input.forgetInFlight && input.derive.operation == nil {
            subtitle = Strings.forgetPending
        } else if (input.pairingCancelInFlight || input.pairingCancelRequested) && input.derive.operation == nil {
            subtitle = AppModelActionText.cancelingPairing
        }
        let primary = busy ? nil : action(derived.action)
        // A blocked Forget is live only while the status is fresh and the
        // tunnel still runs. An old or stale block must not offer a stop.
        let forgetBlocked = input.forgetBlocked && input.derive.running && input.derive.freshness == .fresh
        var attention = attentionItems(input, subtitle: subtitle)
        if forgetBlocked {
            attention.insert(Strings.forgetBlocked, at: 0)
        }
        let secondary: ScreenModel.Action?
        if busy || !input.derive.engineHealth.isNormal {
            secondary = nil
        } else if forgetBlocked {
            secondary = .turnOffAndForget
        } else if input.derive.freshness == .stale {
            secondary = .checkNow
        } else if input.derive.freshness == .unavailable || input.derive.cleanupPending != nil {
            // The README says Forget is disabled when the status is
            // unavailable. A pending helper stop is not cleanup proof either.
            secondary = nil
        } else if input.derive.paired && !input.derive.running && input.derive.operation == nil && input.derive.pairing == .idle {
            secondary = .forget
        } else {
            secondary = nil
        }
        // When the engine has not answered for 10 s, or cannot prove whether
        // the tunnel is on, the cards must not show the old status as current.
        let unavailable = input.derive.freshness == .unavailable
        let indeterminate = input.derive.engineHealth == .stateUnknown
        return ScreenModel(
            title: title,
            subtitle: subtitle,
            primaryAction: primary,
            secondaryAction: secondary,
            statusKind: kind,
            sourceDevice: (unavailable || indeterminate) ? ScreenModel.DeviceCard() : ScreenModel.DeviceCard(lines: sourceDeviceLines(input)),
            connection: (unavailable || indeterminate) ? ScreenModel.ConnectionCard() : connectionCard(input),
            attentionItems: attention,
            menuBar: menuBar(input, kind: kind, title: title),
            retryStartsTunnel: input.retryStartsTunnel
        )
    }

    // MARK: - Status

    private static func actionBusy(_ input: PresentationInput) -> Bool {
        input.forgetInFlight || input.pairingCancelInFlight || input.pairingStartInFlight || input.pairingCancelRequested
    }

    private static func statusKind(_ input: PresentationInput) -> ScreenModel.StatusKind {
        let derive = input.derive
        if derive.freshness == .unavailable { return .attention }
        if derive.cleanupPending != nil { return .attention }
        if let token = derive.tokenRejected, !token.isEmpty { return .attention }
        // An interrupted operation never shows the On color, even when the
        // engine's guard flag says running.
        if !derive.engineHealth.isNormal { return .attention }
        if input.forgetInFlight || input.pairingCancelInFlight || input.pairingCancelRequested { return .busy }
        if derive.operation != nil { return .busy }
        if derive.pairing == .starting || derive.pairing == .confirming { return .pairing }
        if derive.running { return .on }
        if derive.phone == .unknown { return .attention }
        if let error = derive.error, !error.isEmpty { return .attention }
        return .off
    }

    private static func action(_ action: PrimaryAction?) -> ScreenModel.Action? {
        switch action {
        case .pair?: return .pair
        case .pairAgain?: return .pairAgain
        case .turnOn?: return .turnOn
        case .turnOff?: return .turnOff
        case .retry?: return .retry
        case .checkNow?: return .checkNow
        case nil: return nil
        }
    }

    // MARK: - Cards

    private static func sourceDeviceLines(_ input: PresentationInput) -> [String] {
        var lines = [input.derive.paired ? Strings.paired : Strings.notPaired]
        if let message = Strings.sanitized(input.derive.phoneMessage), !message.isEmpty {
            lines.append(message)
        } else if input.derive.running {
            lines.append(Strings.onSubtitle)
        } else if input.derive.phone == .notRunning || input.derive.phone == .noHotspot {
            lines.append(Strings.openSourceDeviceApp)
        }
        return lines
    }

    private static func connectionCard(_ input: PresentationInput) -> ScreenModel.ConnectionCard {
        // A recovery block or a pending stop cannot support the ping state,
        // the connection count, or the probe time. A known stop record stays
        // visible for the cleanup-blocked case.
        let healthy = input.derive.engineHealth.isNormal && input.derive.cleanupPending == nil
        let ping = healthy ? input.pingLine : nil
        let connections = healthy ? input.connectionsLabel : nil
        let checked = healthy ? input.lastCheckedText : nil
        var lines: [String] = []
        if let ping { lines.append(ping) }
        if let connections { lines.append(connections) }
        if let stop = input.lastStopLine { lines.append(stop) }
        if let checked { lines.append(checked) }
        return ScreenModel.ConnectionCard(lines: lines, ping: ping, activeConnections: connections, lastStop: input.lastStopLine, lastChecked: checked)
    }

    // MARK: - Attention

    private static func attentionItems(_ input: PresentationInput, subtitle: String) -> [String] {
        var items: [String] = []
        let derive = input.derive
        // An interrupted operation is not a source device failure.
        if derive.sourceDeviceWarning && derive.engineHealth.isNormal { items.append(Strings.sourceStoppedTitle) }
        if derive.running && derive.phone == .notTrusted && derive.engineHealth.isNormal { items.append(Strings.notTrustedWhileRunning) }
        switch derive.engineHealth {
        case .stateUnknown: items.append(Strings.serviceStateUnknownHint)
        case .cleanupBlocked: items.append(Strings.cleanupBlockedHint)
        case .normal: break
        }
        if let pending = Strings.sanitized(derive.cleanupPending), !pending.isEmpty, pending != subtitle {
            items.append(pending)
        }
        // A pairing failure is the main subtitle on the calm Not paired
        // screen. Every other screen shows it here, so a failed re-pair does
        // not disappear behind a Ready or Not trusted card.
        if let failure = Strings.sanitized(derive.pairingFailure), !failure.isEmpty, failure != subtitle {
            items.append(failure)
        }
        items.append(contentsOf: input.linkAdvice)
        // The subtitle already carries the stale line in the unknown row.
        // Repeating it in the list would say the same thing twice.
        if derive.freshness != .fresh && Strings.staleStatus != subtitle { items.append(Strings.staleStatus) }
        if input.notificationsDenied { items.append(Strings.notificationsDenied) }
        // Remove duplicates but keep the order.
        var seen = Set<String>()
        return items.filter { seen.insert($0).inserted }
    }

    // MARK: - Menu bar

    private static func menuBar(_ input: PresentationInput, kind: ScreenModel.StatusKind, title: String) -> ScreenModel.MenuBar {
        let derive = input.derive
        let pairingActive = derive.pairing == .starting || derive.pairing == .confirming
        let busy = derive.operation != nil || pairingActive || actionBusy(input)
        let unavailable = derive.freshness == .unavailable
        let healthy = derive.engineHealth.isNormal
        let ready = healthy && derive.paired && derive.phone == .ready && !derive.running && !busy && !unavailable && derive.tokenRejected == nil && derive.cleanupPending == nil
        // A requested cancel that has not reached the engine stays available,
        // so a failed best-effort cancel does not strand the engine.
        let cancelEnabled = (pairingActive || input.pairingCancelRequested) && !input.pairingCancelInFlight && !input.forgetInFlight
        let cancelReason: String?
        if input.forgetInFlight {
            cancelReason = AppModelActionText.waitForAction
        } else if input.pairingCancelInFlight || input.pairingCancelRequested {
            cancelReason = AppModelActionText.cancelingPairing
        } else if !pairingActive {
            cancelReason = "Pairing is not running."
        } else {
            cancelReason = nil
        }
        let turnOffEnabled = healthy && derive.running && !busy && !unavailable
        let actions: [ScreenModel.MenuBarAction] = [
            .init(kind: .turnOn, enabled: ready, reason: ready ? nil : turnOnReason(derive, busy: busy, unavailable: unavailable)),
            .init(kind: .turnOff, enabled: turnOffEnabled, reason: turnOffEnabled ? nil : turnOffReason(derive, busy: busy, unavailable: unavailable)),
            .init(kind: .pair, enabled: pairEnabled(input), reason: pairReason(input, busy: busy)),
            .init(kind: .cancel, enabled: cancelEnabled, reason: cancelEnabled ? nil : cancelReason),
            .init(kind: .open, enabled: true, reason: nil),
            .init(kind: .checkNow, enabled: true, reason: nil),
            .init(kind: .quit, enabled: true, reason: nil),
        ]
        let icon: ScreenModel.MenuBar.Icon
        switch kind {
        case .on: icon = .on
        case .attention: icon = .attention
        case .busy, .pairing: icon = .busy
        case .off: icon = .off
        }
        return ScreenModel.MenuBar(icon: icon, statusLine: unavailable ? Strings.unknownTitle : title, actions: actions)
    }

    private static func pairEnabled(_ input: PresentationInput) -> Bool {
        let derive = input.derive
        guard derive.engineHealth.isNormal, derive.freshness != .unavailable, derive.cleanupPending == nil, !derive.running, derive.operation == nil, !actionBusy(input) else { return false }
        return derive.pairing == .idle || derive.pairing == .failed
    }
    private static func pairReason(_ input: PresentationInput, busy: Bool) -> String? {
        let derive = input.derive
        if !derive.engineHealth.isNormal { return recoveryReason(derive.engineHealth) }
        if derive.freshness == .unavailable { return Strings.statusUnavailableSubtitle }
        if let pending = derive.cleanupPending { return Strings.sanitized(pending) ?? pending }
        if derive.running { return "Turn off the tunnel first." }
        if derive.operation != nil || actionBusy(input) { return AppModelActionText.waitForAction }
        if busy || derive.pairing == .starting || derive.pairing == .confirming { return "Pairing is already running." }
        // Pair stays disabled after a completed pairing. Explain that state
        // instead of leaving a grayed row with no reason.
        if derive.paired && !pairEnabled(input) { return Strings.alreadyPaired }
        return nil
    }
    private static func turnOffReason(_ derive: DeriveInput, busy: Bool, unavailable: Bool) -> String {
        if !derive.engineHealth.isNormal { return recoveryReason(derive.engineHealth) }
        if unavailable { return Strings.statusUnavailableSubtitle }
        if busy || derive.operation != nil { return AppModelActionText.waitForAction }
        if !derive.running { return "The tunnel is not on." }
        return AppModelActionText.waitForAction
    }
    private static func turnOnReason(_ derive: DeriveInput, busy: Bool, unavailable: Bool) -> String {
        if !derive.engineHealth.isNormal { return recoveryReason(derive.engineHealth) }
        if unavailable { return Strings.statusUnavailableSubtitle }
        if let pending = derive.cleanupPending { return Strings.sanitized(pending) ?? pending }
        if busy { return AppModelActionText.waitForAction }
        if derive.tokenRejected != nil { return Strings.pairAgain }
        if !derive.paired { return Strings.unpairedSubtitle }
        if derive.running { return "The tunnel is already on." }
        return "The source device is not ready."
    }
    // The fixed recovery text for a disabled action. It never claims that the
    // tunnel is off.
    private static func recoveryReason(_ health: EngineHealth) -> String {
        switch health {
        case .stateUnknown: return Strings.serviceStateUnknownBody
        case .cleanupBlocked: return Strings.cleanupBlockedBody
        case .normal: return ""
        }
    }
}
