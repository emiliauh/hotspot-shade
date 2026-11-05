import Foundation

// A keyboard shortcut for a menu item. The view maps it to a SwiftUI
// KeyboardShortcut. The type stays pure, so the tests can read it.
public enum MenuShortcut: String, Equatable, CaseIterable {
    case commandReturn
    case commandR
    case commandComma
    case commandQ

    // The menu preview shows these words.
    public var label: String {
        switch self {
        case .commandReturn: return "Command Return"
        case .commandR: return "Command R"
        case .commandComma: return "Command ,"
        case .commandQ: return "Command Q"
        }
    }
}

// One row in the menu bar menu.
public struct MenuBarItem: Identifiable, Equatable {
    public enum Kind: Equatable {
        case statusHeader
        case statusDetail
        case turnOn
        case turnOff
        case pair
        case cancel
        case checkNow
        case notice
        case open
        case copyDiagnostics
        case settings
        case quit

        // True for the rows that a person can select.
        public var isAction: Bool {
            switch self {
            case .turnOn, .turnOff, .pair, .cancel, .checkNow, .open, .copyDiagnostics, .settings, .quit:
                return true
            case .statusHeader, .statusDetail, .notice:
                return false
            }
        }
    }
    public var id: String
    public var kind: Kind
    public var title: String
    public var symbol: String?
    public var shortcut: MenuShortcut?
    public var isEnabled: Bool
    // The plain reason for a disabled action. It is the help text.
    public var help: String?
    public init(id: String, kind: Kind, title: String, symbol: String? = nil, shortcut: MenuShortcut? = nil, isEnabled: Bool = true, help: String? = nil) {
        self.id = id; self.kind = kind; self.title = title; self.symbol = symbol
        self.shortcut = shortcut; self.isEnabled = isEnabled; self.help = help
    }
}

// The symbols for the menu bar item and the menu rows.
public enum MenuSymbols {
    public static func icon(for icon: ScreenModel.MenuBar.Icon) -> String {
        switch icon {
        case .off: return "network.slash"
        case .on: return "network"
        case .attention: return "exclamationmark.triangle"
        case .busy: return "hourglass"
        }
    }

    // A symbol for one plain attention line.
    public static func notice(for text: String) -> String {
        switch text {
        case Strings.sourceStoppedTitle: return "antenna.radiowaves.left.and.right.slash"
        case Strings.notTrustedWhileRunning: return "person.crop.circle.badge.xmark"
        case Strings.slowWiFi, Strings.weakWiFi: return "wifi.exclamationmark"
        case Strings.staleStatus: return "clock.badge.exclamationmark"
        case Strings.notificationsDenied: return "bell.slash"
        case Strings.forgetBlocked: return "lock"
        default: return "exclamationmark.triangle"
        }
    }
}

// The menu bar menu. The builder is pure. The view draws the sections in
// this order.
public struct MenuBarContent: Equatable {
    public var iconSymbol: String
    public var stateWord: String
    public var header: MenuBarItem
    public var detail: MenuBarItem
    public var actions: [MenuBarItem]
    public var notices: [MenuBarItem]
    public var open: MenuBarItem
    public var copyDiagnostics: MenuBarItem
    public var settings: MenuBarItem
    public var quit: MenuBarItem

    public init(iconSymbol: String, stateWord: String, header: MenuBarItem, detail: MenuBarItem, actions: [MenuBarItem], notices: [MenuBarItem], open: MenuBarItem, copyDiagnostics: MenuBarItem, settings: MenuBarItem, quit: MenuBarItem) {
        self.iconSymbol = iconSymbol; self.stateWord = stateWord; self.header = header
        self.detail = detail; self.actions = actions; self.notices = notices
        self.open = open; self.copyDiagnostics = copyDiagnostics
        self.settings = settings; self.quit = quit
    }

    // Every row in draw order.
    public var allItems: [MenuBarItem] {
        [header, detail] + actions + notices + [open, copyDiagnostics, settings, quit]
    }
}

public enum MenuBarContentBuilder {
    public static let maxNotices = 3

    // Build the menu for a screen model. A quitting menu shows the wait for
    // the tunnel stop.
    public static func build(_ model: ScreenModel, quitting: Bool = false) -> MenuBarContent {
        let icon = MenuSymbols.icon(for: model.menuBar.icon)
        let header = MenuBarItem(id: "status", kind: .statusHeader, title: model.title, symbol: icon, isEnabled: false)
        let detailText = model.subtitle.isEmpty ? (model.connection.lastChecked ?? "") : model.subtitle
        let detail = MenuBarItem(id: "detail", kind: .statusDetail, title: detailText, isEnabled: false)

        let turnOn = action(.turnOn, in: model)
        let turnOff = action(.turnOff, in: model)
        let looksOn = model.statusKind == .on || model.title == Strings.stopping
        let toggle = looksOn ? turnOff : turnOn
        var actions: [MenuBarItem] = []
        if let toggle {
            actions.append(item(for: toggle, id: toggle.kind.rawValue, shortcut: toggle.enabled ? .commandReturn : nil))
        }
        if let pair = action(.pair, in: model) { actions.append(item(for: pair, id: pair.kind.rawValue, shortcut: nil)) }
        if let cancel = action(.cancel, in: model) { actions.append(item(for: cancel, id: cancel.kind.rawValue, shortcut: nil)) }
        if let check = action(.checkNow, in: model) { actions.append(item(for: check, id: check.kind.rawValue, shortcut: check.enabled ? .commandR : nil)) }

        var noticeTexts: [String] = []
        var seen = Set<String>()
        for text in model.attentionItems where seen.insert(text).inserted {
            noticeTexts.append(text)
        }
        if let stop = model.connection.lastStop, seen.insert(stop).inserted {
            noticeTexts.append(stop)
        }
        if noticeTexts.count > maxNotices { noticeTexts = Array(noticeTexts.prefix(maxNotices)) }
        let notices = noticeTexts.enumerated().map { index, text in notice(text, index: index) }

        let open = MenuBarItem(id: "open", kind: .open, title: Strings.openApp, symbol: "macwindow")
        let copy = MenuBarItem(id: "copyDiagnostics", kind: .copyDiagnostics, title: UIStrings.copyDiagnostics, symbol: "doc.on.doc")
        let settings = MenuBarItem(id: "settings", kind: .settings, title: UIStrings.settingsMenu, symbol: "gearshape", shortcut: .commandComma)
        let quit = MenuBarItem(id: "quit", kind: .quit, title: quitting ? UIStrings.turningOff : Strings.quit, symbol: "power", shortcut: .commandQ, isEnabled: !quitting, help: quitting ? UIStrings.turningOffNote : nil)

        return MenuBarContent(iconSymbol: icon, stateWord: model.title, header: header, detail: detail, actions: actions, notices: notices, open: open, copyDiagnostics: copy, settings: settings, quit: quit)
    }

    // The menu before the app has a model. It shows the startup state.
    public static func starting(quitting: Bool = false) -> MenuBarContent {
        let icon = MenuSymbols.icon(for: .busy)
        let header = MenuBarItem(id: "status", kind: .statusHeader, title: UIStrings.menuStarting, symbol: icon, isEnabled: false)
        let detail = MenuBarItem(id: "detail", kind: .statusDetail, title: UIStrings.menuStartingDetail, isEnabled: false)
        let open = MenuBarItem(id: "open", kind: .open, title: Strings.openApp, symbol: "macwindow")
        let copy = MenuBarItem(id: "copyDiagnostics", kind: .copyDiagnostics, title: UIStrings.copyDiagnostics, symbol: "doc.on.doc", isEnabled: false, help: UIStrings.menuStartingDetail)
        let settings = MenuBarItem(id: "settings", kind: .settings, title: UIStrings.settingsMenu, symbol: "gearshape", shortcut: .commandComma)
        let quit = MenuBarItem(id: "quit", kind: .quit, title: quitting ? UIStrings.turningOff : Strings.quit, symbol: "power", shortcut: .commandQ, isEnabled: !quitting, help: quitting ? UIStrings.turningOffNote : nil)
        return MenuBarContent(iconSymbol: icon, stateWord: UIStrings.menuStarting, header: header, detail: detail, actions: [], notices: [], open: open, copyDiagnostics: copy, settings: settings, quit: quit)
    }

    private static func action(_ kind: ScreenModel.MenuBarAction.Kind, in model: ScreenModel) -> ScreenModel.MenuBarAction? {
        model.menuBar.actions.first { $0.kind == kind }
    }

    private static func item(for action: ScreenModel.MenuBarAction, id: String, shortcut: MenuShortcut?) -> MenuBarItem {
        MenuBarItem(id: id, kind: kind(action.kind), title: action.label, symbol: nil, shortcut: shortcut, isEnabled: action.enabled, help: action.enabled ? nil : action.reason)
    }

    private static func kind(_ kind: ScreenModel.MenuBarAction.Kind) -> MenuBarItem.Kind {
        switch kind {
        case .turnOn: return .turnOn
        case .turnOff: return .turnOff
        case .pair: return .pair
        case .cancel: return .cancel
        case .open: return .open
        case .checkNow: return .checkNow
        case .quit: return .quit
        }
    }

    private static func notice(_ text: String, index: Int) -> MenuBarItem {
        MenuBarItem(id: "notice-\(index)", kind: .notice, title: text, symbol: MenuSymbols.notice(for: text), isEnabled: false)
    }
}
