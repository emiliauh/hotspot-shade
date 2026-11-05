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
    public init(title: String, subtitle: String, primaryAction: Action?, secondaryAction: Action? = nil, statusKind: StatusKind, sourceDevice: DeviceCard = DeviceCard(), connection: ConnectionCard = ConnectionCard(), attentionItems: [String] = [], menuBar: MenuBar) {
        self.title = title; self.subtitle = subtitle; self.primaryAction = primaryAction
        self.secondaryAction = secondaryAction; self.statusKind = statusKind
        self.sourceDevice = sourceDevice; self.connection = connection
        self.attentionItems = attentionItems; self.menuBar = menuBar
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
    public init(derive: DeriveInput = DeriveInput(), pingLine: String? = nil, connectionsLabel: String? = nil, lastStopLine: String? = nil, lastCheckedText: String? = nil, linkAdvice: [String] = [], notificationsDenied: Bool = false, forgetBlocked: Bool = false) {
        self.derive = derive; self.pingLine = pingLine; self.connectionsLabel = connectionsLabel
        self.lastStopLine = lastStopLine; self.lastCheckedText = lastCheckedText
        self.linkAdvice = linkAdvice; self.notificationsDenied = notificationsDenied
        self.forgetBlocked = forgetBlocked
    }
}

public enum ScreenPresentation {
    // Build the visible model from one input. The derive table holds the main
    // title, subtitle, and one primary action. This function adds the cards,
    // the attention list, and the menu.
    public static func build(_ input: PresentationInput) -> ScreenModel {
        let derived = AppModel.derive(input.derive).dashboard
        let kind = statusKind(input)
        let title = derived.title
        let subtitle = derived.subtitle
        let primary = action(derived.action)
        var attention = attentionItems(input)
        if input.forgetBlocked {
            attention.insert(Strings.forgetBlocked, at: 0)
        }
        let secondary: ScreenModel.Action?
        if input.forgetBlocked {
            secondary = .turnOffAndForget
        } else if input.derive.freshness == .stale {
            secondary = .checkNow
        } else if input.derive.paired && !input.derive.running && input.derive.operation == nil && input.derive.pairing == .idle {
            secondary = .forget
        } else {
            secondary = nil
        }
        // When the engine has not answered for 10 s, the cards must not show
        // the old status as if it were current.
        let unavailable = input.derive.freshness == .unavailable
        return ScreenModel(
            title: title,
            subtitle: subtitle,
            primaryAction: primary,
            secondaryAction: secondary,
            statusKind: kind,
            sourceDevice: unavailable ? ScreenModel.DeviceCard() : ScreenModel.DeviceCard(lines: sourceDeviceLines(input)),
            connection: unavailable ? ScreenModel.ConnectionCard() : connectionCard(input),
            attentionItems: attention,
            menuBar: menuBar(input, kind: kind, title: title)
        )
    }

    // MARK: - Status

    private static func statusKind(_ input: PresentationInput) -> ScreenModel.StatusKind {
        let derive = input.derive
        if derive.freshness == .unavailable { return .attention }
        if let token = derive.tokenRejected, !token.isEmpty { return .attention }
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
        var lines: [String] = []
        if let ping = input.pingLine { lines.append(ping) }
        if let connections = input.connectionsLabel { lines.append(connections) }
        if let stop = input.lastStopLine { lines.append(stop) }
        if let checked = input.lastCheckedText { lines.append(checked) }
        return ScreenModel.ConnectionCard(lines: lines, ping: input.pingLine, activeConnections: input.connectionsLabel, lastStop: input.lastStopLine, lastChecked: input.lastCheckedText)
    }

    // MARK: - Attention

    private static func attentionItems(_ input: PresentationInput) -> [String] {
        var items: [String] = []
        let derive = input.derive
        if derive.sourceDeviceWarning { items.append(Strings.sourceStoppedTitle) }
        if derive.running && derive.phone == .notTrusted { items.append(Strings.notTrustedWhileRunning) }
        items.append(contentsOf: input.linkAdvice)
        if derive.freshness != .fresh { items.append(Strings.staleStatus) }
        if input.notificationsDenied { items.append(Strings.notificationsDenied) }
        // Remove duplicates but keep the order.
        var seen = Set<String>()
        return items.filter { seen.insert($0).inserted }
    }

    // MARK: - Menu bar

    private static func menuBar(_ input: PresentationInput, kind: ScreenModel.StatusKind, title: String) -> ScreenModel.MenuBar {
        let derive = input.derive
        let busy = derive.operation != nil || derive.pairing == .starting || derive.pairing == .confirming
        let unavailable = derive.freshness == .unavailable
        let ready = derive.paired && derive.phone == .ready && !derive.running && !busy && !unavailable && derive.tokenRejected == nil
        let actions: [ScreenModel.MenuBarAction] = [
            .init(kind: .turnOn, enabled: ready, reason: ready ? nil : turnOnReason(derive, busy: busy, unavailable: unavailable)),
            .init(kind: .turnOff, enabled: derive.running && !busy, reason: !derive.running ? "The tunnel is not on." : (busy ? "Wait for the current action to finish." : nil)),
            .init(kind: .pair, enabled: pairEnabled(derive), reason: pairReason(derive, busy: busy)),
            .init(kind: .cancel, enabled: derive.pairing == .starting || derive.pairing == .confirming, reason: (derive.pairing == .starting || derive.pairing == .confirming) ? nil : "Pairing is not running."),
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

    private static func pairEnabled(_ derive: DeriveInput) -> Bool {
        guard !derive.running, derive.operation == nil else { return false }
        return derive.pairing == .idle || derive.pairing == .failed
    }
    private static func pairReason(_ derive: DeriveInput, busy: Bool) -> String? {
        if derive.running { return "Turn off the tunnel first." }
        if derive.operation != nil { return "Wait for the current action to finish." }
        if busy || derive.pairing == .starting || derive.pairing == .confirming { return "Pairing is already running." }
        return nil
    }
    private static func turnOnReason(_ derive: DeriveInput, busy: Bool, unavailable: Bool) -> String {
        if unavailable { return Strings.statusUnavailableSubtitle }
        if busy { return "Wait for the current action to finish." }
        if derive.tokenRejected != nil { return Strings.pairAgain }
        if !derive.paired { return Strings.unpairedSubtitle }
        if derive.running { return "The tunnel is already on." }
        return "The source device is not ready."
    }
}
