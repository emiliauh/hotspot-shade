import SwiftUI

// The menu bar menu. It is a native menu, not a window. The order is: the
// status, the actions, the notices, the window and settings rows, then Quit.
public struct MenuBarMenu: View {
    public var content: MenuBarContent
    private let onAction: (ScreenModel.MenuBarAction.Kind) -> Void
    private let onOpen: () -> Void
    private let onCopyDiagnostics: () -> Void
    private let onSettings: () -> Void
    private let onQuit: () -> Void

    public init(content: MenuBarContent, onAction: @escaping (ScreenModel.MenuBarAction.Kind) -> Void = { _ in }, onOpen: @escaping () -> Void = {}, onCopyDiagnostics: @escaping () -> Void = {}, onSettings: @escaping () -> Void = {}, onQuit: @escaping () -> Void = {}) {
        self.content = content
        self.onAction = onAction
        self.onOpen = onOpen
        self.onCopyDiagnostics = onCopyDiagnostics
        self.onSettings = onSettings
        self.onQuit = onQuit
    }

    public var body: some View {
        statusRow(content.header)
        Text(content.detail.title)
            .disabled(true)
        Divider()
        ForEach(content.actions) { item in
            actionRow(item)
        }
        if !content.notices.isEmpty {
            Divider()
            Section(UIStrings.notices) {
                ForEach(content.notices) { item in
                    staticRow(item)
                }
            }
        }
        Divider()
        actionRow(content.open)
        actionRow(content.copyDiagnostics)
        actionRow(content.settings)
        Divider()
        actionRow(content.quit)
    }

    private func statusRow(_ item: MenuBarItem) -> some View {
        Button(action: {}) {
            Label(item.title, systemImage: item.symbol ?? content.iconSymbol)
        }
        .disabled(true)
        .accessibilityLabel(AccessibilityText.menuStatus(title: item.title, detail: content.detail.title))
    }

    private func staticRow(_ item: MenuBarItem) -> some View {
        Button(action: {}) {
            if let symbol = item.symbol {
                Label(item.title, systemImage: symbol)
            } else {
                Text(item.title)
            }
        }
        .disabled(true)
        .help(item.help ?? "")
    }

    @ViewBuilder private func actionRow(_ item: MenuBarItem) -> some View {
        if let shortcut = item.shortcut {
            button(item)
                .keyboardShortcut(key(shortcut), modifiers: modifiers(shortcut))
        } else {
            button(item)
        }
    }

    private func button(_ item: MenuBarItem) -> some View {
        Button {
            activate(item.kind)
        } label: {
            if let symbol = item.symbol {
                Label(item.title, systemImage: symbol)
            } else {
                Text(item.title)
            }
        }
        .disabled(!item.isEnabled)
        .help(item.help ?? "")
    }

    private func activate(_ kind: MenuBarItem.Kind) {
        switch kind {
        case .turnOn: onAction(.turnOn)
        case .turnOff: onAction(.turnOff)
        case .pair: onAction(.pair)
        case .cancel: onAction(.cancel)
        case .checkNow: onAction(.checkNow)
        case .open: onOpen()
        case .copyDiagnostics: onCopyDiagnostics()
        case .settings: onSettings()
        case .quit: onQuit()
        case .statusHeader, .statusDetail, .notice: break
        }
    }

    private func key(_ shortcut: MenuShortcut) -> KeyEquivalent {
        switch shortcut {
        case .commandReturn: return .return
        case .commandR: return "r"
        case .commandComma: return ","
        case .commandQ: return "q"
        }
    }

    private func modifiers(_ shortcut: MenuShortcut) -> EventModifiers {
        switch shortcut {
        case .commandReturn, .commandR, .commandComma, .commandQ:
            return .command
        }
    }
}

// The menu bar icon. One symbol follows the model icon. A template symbol
// fits a light, dark, or tinted menu bar.
public struct MenuBarStatusIcon: View {
    public var symbol: String
    public var stateWord: String
    public init(symbol: String, stateWord: String) {
        self.symbol = symbol
        self.stateWord = stateWord
    }
    public var body: some View {
        Image(systemName: symbol)
            .symbolRenderingMode(.monochrome)
            .accessibilityLabel("\(Strings.app). \(stateWord)")
    }
}
