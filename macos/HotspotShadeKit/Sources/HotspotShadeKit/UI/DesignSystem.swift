import SwiftUI
import AppKit

// The spacing, radii, and motion values for the target app. Use these values
// and no other margin.
public enum HSMetrics {
    public static let space4: CGFloat = 4
    public static let space8: CGFloat = 8
    public static let space12: CGFloat = 12
    public static let space16: CGFloat = 16
    public static let space24: CGFloat = 24
    public static let space32: CGFloat = 32
    public static let space48: CGFloat = 48

    public static let cardRadius: CGFloat = 16
    public static let controlRadius: CGFloat = 8
    public static let markRadius: CGFloat = 6

    public static let animation: TimeInterval = 0.15
    public static let toolbarIconSize: CGFloat = 16
    public static let contentWidth: CGFloat = 720
    public static let minimumWidth: CGFloat = 780
    public static let minimumHeight: CGFloat = 560
    public static let defaultWidth: CGFloat = 900
    public static let defaultHeight: CGFloat = 640
}

// The color of a status mark.
public enum StatusColor {
    public static func color(for kind: ScreenModel.StatusKind) -> Color {
        switch kind {
        case .off: return .secondary
        case .on: return .green
        case .attention: return .orange
        case .pairing: return .accentColor
        case .busy: return .blue
        }
    }
}

// A small mark for the status. The state text is always next to it, so the
// mark is hidden from assistive technology.
public struct StatusDot: View {
    public var kind: ScreenModel.StatusKind
    public var size: CGFloat
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    public init(kind: ScreenModel.StatusKind, size: CGFloat = 12) {
        self.kind = kind
        self.size = size
    }
    public var body: some View {
        Circle()
            .fill(StatusColor.color(for: kind))
            .frame(width: size, height: size)
            .animation(reduceMotion ? nil : .easeInOut(duration: HSMetrics.animation), value: kind)
            .accessibilityHidden(true)
    }
}

// One card. The card combines its content into one accessibility element.
public struct Card<Content: View>: View {
    public var title: String
    public var systemImage: String
    public var accessibilityLabel: String?
    public var combinesChildren: Bool
    public var fillsHeight: Bool
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    private let content: () -> Content
    public init(title: String, systemImage: String, accessibilityLabel: String? = nil, combinesChildren: Bool = true, fillsHeight: Bool = false, @ViewBuilder content: @escaping () -> Content) {
        self.title = title
        self.systemImage = systemImage
        self.accessibilityLabel = accessibilityLabel
        self.combinesChildren = combinesChildren
        self.fillsHeight = fillsHeight
        self.content = content
    }
    public var body: some View {
        VStack(alignment: .leading, spacing: HSMetrics.space12) {
            Label(title, systemImage: systemImage)
                .font(.headline)
                .accessibilityHidden(true)
            content()
        }
        .frame(maxWidth: .infinity, maxHeight: fillsHeight ? .infinity : nil, alignment: .topLeading)
        .padding(HSMetrics.space24)
        .hsGlassSurface(cornerRadius: HSMetrics.cardRadius, reduceTransparency: reduceTransparency)
        .accessibilityElement(children: combinesChildren ? .combine : .contain)
        .accessibilityLabel(accessibilityLabel ?? title)
    }
}

// The one main button. macOS 26 uses glass. Earlier systems use a prominent
// bordered button.
public struct PrimaryActionButton: View {
    public var title: String
    private let action: () -> Void
    public init(_ title: String, action: @escaping () -> Void) {
        self.title = title
        self.action = action
    }
    public var body: some View {
        #if compiler(>=6.2)
        if #available(macOS 26.0, *) {
            base.buttonStyle(.glassProminent)
        } else {
            base.buttonStyle(.borderedProminent)
        }
        #else
        base.buttonStyle(.borderedProminent)
        #endif
    }
    private var base: some View {
        Button(title, action: action)
            .controlSize(.large)
            .tint(.accentColor)
    }
}

// A second action. It never uses the accent color of the main button.
public struct SecondaryActionButton: View {
    public var title: String
    public var isDestructive: Bool
    private let action: () -> Void
    public init(_ title: String, isDestructive: Bool = false, action: @escaping () -> Void) {
        self.title = title
        self.isDestructive = isDestructive
        self.action = action
    }
    public var body: some View {
        Button(role: isDestructive ? .destructive : nil, action: action) { Text(title) }
            .buttonStyle(.bordered)
            .controlSize(.large)
            .tint(isDestructive ? .red : nil)
    }
}

// The toolbar refresh action. The spinner replaces the symbol inside the
// button. The button keeps its size, so the toolbar does not move. The spinner
// stays inside the glass shape of the button.
public struct RefreshToolbarButton: View {
    public var isRefreshing: Bool
    public var help: String
    private let action: () -> Void
    public init(isRefreshing: Bool, help: String, action: @escaping () -> Void) {
        self.isRefreshing = isRefreshing
        self.help = help
        self.action = action
    }
    public var body: some View {
        Button(action: action) {
            Label {
                Text(Strings.refresh)
            } icon: {
                ZStack {
                    Image(systemName: HSSymbol.refresh)
                        .opacity(isRefreshing ? 0 : 1)
                    if isRefreshing {
                        ProgressView()
                            .controlSize(.small)
                    }
                }
                .frame(width: HSMetrics.toolbarIconSize, height: HSMetrics.toolbarIconSize)
                .accessibilityHidden(true)
            }
        }
        .help(help)
        .accessibilityLabel(Strings.refresh)
        .accessibilityValue(isRefreshing ? UIStrings.refreshing : "")
    }
}

// One line in the attention card. The action is optional.
public struct AttentionRow: View {
    public var text: String
    public var actionLabel: String?
    private let action: (() -> Void)?
    public init(text: String, actionLabel: String? = nil, action: (() -> Void)? = nil) {
        self.text = text
        self.actionLabel = actionLabel
        self.action = action
    }
    public var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: HSMetrics.space12) {
            Image(systemName: "exclamationmark.triangle")
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text(text)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
            if let actionLabel, let action {
                Button(actionLabel, action: action)
                    .buttonStyle(.link)
            }
        }
    }
}

// The symbols for the app. The status text always sits next to the symbol.
public enum HSSymbol {
    public static let sourceDevice = "antenna.radiowaves.left.and.right"
    public static let connection = "network"
    public static let attention = "exclamationmark.triangle"
    public static let activity = "clock.arrow.circlepath"
    public static let dashboard = "gauge"
    public static let settings = "gearshape"
    public static let pairing = "link"
    public static let refresh = "arrow.clockwise"

    public static func attentionAction(_ action: AttentionAction) -> String {
        switch action {
        case .checkNow: return "arrow.clockwise"
        case .turnOff: return "stop.circle"
        case .turnOffAndForget: return "trash"
        case .openNotificationSettings: return "bell"
        }
    }
}
