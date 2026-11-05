import Foundation

// The action that an attention line can offer. The line itself stays plain.
// A nil action means that the person can only read the line.
public enum AttentionAction: Equatable {
    case checkNow
    case turnOff
    case turnOffAndForget
    case openNotificationSettings

    public var label: String {
        switch self {
        case .checkNow: return Strings.checkNow
        case .turnOff: return Strings.turnOff
        case .turnOffAndForget: return Strings.turnOffAndForget
        case .openNotificationSettings: return UIStrings.openSystemSettings
        }
    }
}

// The visible status kind for the dot. The presentation model keeps Not
// trusted in the off family. The window shows it as attention, because the
// person must act.
public enum StatusAppearance {
    public static func kind(title: String, kind: ScreenModel.StatusKind) -> ScreenModel.StatusKind {
        if kind == .off && title == Strings.notTrustedTitle { return .attention }
        return kind
    }

    public static func kind(for model: ScreenModel) -> ScreenModel.StatusKind {
        kind(title: model.title, kind: model.statusKind)
    }
}

// The content of the dashboard cards. It is pure, so the screen-to-card
// mapping is a test without a window. Each card has one value line and zero
// or more detail lines.
public struct DashboardContent: Equatable {
    public struct Card: Equatable {
        public var title: String
        public var symbol: String
        public var value: String
        public var details: [String]
        // The plain lines for the accessibility label and the old tests.
        public var lines: [String] { [value] + details }
        public init(title: String, symbol: String, value: String, details: [String]) {
            self.title = title; self.symbol = symbol; self.value = value; self.details = details
        }
    }
    public var statusKind: ScreenModel.StatusKind
    public var title: String
    public var subtitle: String
    public var checkedText: String?
    public var primaryAction: ScreenModel.Action?
    public var secondaryAction: ScreenModel.Action?
    public var sourceDevice: Card
    public var connection: Card
    public var attention: [String]
    public var demo: Bool

    public init(statusKind: ScreenModel.StatusKind, title: String, subtitle: String, checkedText: String?, primaryAction: ScreenModel.Action?, secondaryAction: ScreenModel.Action?, sourceDevice: Card, connection: Card, attention: [String], demo: Bool) {
        self.statusKind = statusKind; self.title = title; self.subtitle = subtitle
        self.checkedText = checkedText; self.primaryAction = primaryAction
        self.secondaryAction = secondaryAction; self.sourceDevice = sourceDevice
        self.connection = connection; self.attention = attention; self.demo = demo
    }

    // Build the card content. The value line and the detail lines never repeat
    // the header subtitle. The checked time stays in the header.
    public static func build(_ model: ScreenModel, linkAdvice: [String] = [], demo: Bool = false) -> DashboardContent {
        let unavailable = model.sourceDevice.lines.isEmpty && model.connection.lines.isEmpty
        let value = sourceValue(model, unavailable: unavailable)
        let sourceDetails = sourceDetails(model, unavailable: unavailable)
        var connectionDetails = connectionDetails(model, linkAdvice: linkAdvice)
        if connectionDetails.isEmpty { connectionDetails = [UIStrings.noConnectionYet] }
        return DashboardContent(
            statusKind: model.statusKind,
            title: model.title,
            subtitle: model.subtitle,
            checkedText: model.connection.lastChecked,
            primaryAction: model.primaryAction,
            secondaryAction: model.secondaryAction,
            sourceDevice: Card(title: UIStrings.sourceDevice, symbol: "antenna.radiowaves.left.and.right", value: value, details: sourceDetails),
            connection: Card(title: UIStrings.connection, symbol: "network", value: connectionValue(model, unavailable: unavailable), details: connectionDetails),
            attention: model.attentionItems,
            demo: demo
        )
    }

    // The model action for the big button. A Forget action is not a main
    // action, so it has no primary mapping.
    public static func primaryAction(for action: ScreenModel.Action) -> PrimaryAction? {
        switch action {
        case .pair: return .pair
        case .pairAgain: return .pairAgain
        case .turnOn: return .turnOn
        case .turnOff: return .turnOff
        case .retry: return .retry
        case .checkNow: return .checkNow
        case .forget, .turnOffAndForget: return nil
        }
    }

    // The action for one attention line. Unknown text offers no action.
    public static func attentionAction(for item: String) -> AttentionAction? {
        switch item {
        case Strings.forgetBlocked: return .turnOffAndForget
        case Strings.staleStatus: return .checkNow
        case Strings.notificationsDenied: return .openNotificationSettings
        case Strings.notTrustedWhileRunning: return .turnOff
        default: return nil
        }
    }

    // MARK: - Source device

    private static func sourceValue(_ model: ScreenModel, unavailable: Bool) -> String {
        if unavailable { return UIStrings.statusUnavailableLine }
        if model.title == Strings.notTrustedTitle { return Strings.notTrustedTitle }
        if model.sourceDevice.lines.first == Strings.paired { return Strings.paired }
        return Strings.notPaired
    }

    private static func sourceDetails(_ model: ScreenModel, unavailable: Bool) -> [String] {
        if unavailable { return [UIStrings.checkStatusAgain] }
        if model.title == Strings.notTrustedTitle { return [UIStrings.pairToRestoreTrust] }
        guard model.sourceDevice.lines.first == Strings.paired else {
            if model.subtitle == Strings.trustedBySource { return [UIStrings.pressPairToContinue] }
            return [UIStrings.pairWhenReady]
        }
        switch model.title {
        case Strings.pairing: return [UIStrings.lookingForSourceDevice]
        case Strings.waiting: return [UIStrings.checksEverySecond]
        case Strings.on: return [UIStrings.tunnelUsesSourceDevice]
        case Strings.attention: return [UIStrings.readTheMessageAbove]
        case Strings.unknownTitle: return [UIStrings.checkStatusAgain]
        default: return [UIStrings.pairingIsSaved]
        }
    }

    // MARK: - Connection

    private static func connectionValue(_ model: ScreenModel, unavailable: Bool) -> String {
        if unavailable { return UIStrings.statusUnavailableLine }
        switch model.title {
        case Strings.startingTunnel: return UIStrings.connectionStarting
        case Strings.stopping: return Strings.stopping
        case Strings.on: return UIStrings.tunnelOn
        default: return UIStrings.tunnelOff
        }
    }

    private static func connectionDetails(_ model: ScreenModel, linkAdvice: [String]) -> [String] {
        var details: [String] = []
        if let ping = model.connection.ping { details.append(ping) }
        if let connections = model.connection.activeConnections { details.append(connections) }
        if let stop = model.connection.lastStop { details.append(stop) }
        for line in linkAdvice where !details.contains(line) { details.append(line) }
        return details
    }
}
