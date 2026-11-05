import SwiftUI

// The dashboard. It draws one status header, one main action, two cards, and
// the attention list. The pairing view replaces the cards while pairing runs.
public struct DashboardView: View {
    public var model: ScreenModel
    public var linkAdvice: [String]
    public var isPairing: Bool
    public var pairingCode: String?
    public var demo: Bool
    public var isRefreshing: Bool
    private let onAction: (ScreenModel.Action) -> Void
    private let onRefresh: () -> Void
    private let onCopyCode: (String) -> Void
    private let onCancelPairing: () -> Void
    private let onOpenNotificationSettings: () -> Void
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    public init(model: ScreenModel, linkAdvice: [String] = [], isPairing: Bool = false, pairingCode: String? = nil, demo: Bool = false, isRefreshing: Bool = false, onAction: @escaping (ScreenModel.Action) -> Void, onRefresh: @escaping () -> Void = {}, onCopyCode: @escaping (String) -> Void = { _ in }, onCancelPairing: @escaping () -> Void = {}, onOpenNotificationSettings: @escaping () -> Void = {}) {
        self.model = model
        self.linkAdvice = linkAdvice
        self.isPairing = isPairing
        self.pairingCode = pairingCode
        self.demo = demo
        self.isRefreshing = isRefreshing
        self.onAction = onAction
        self.onRefresh = onRefresh
        self.onCopyCode = onCopyCode
        self.onCancelPairing = onCancelPairing
        self.onOpenNotificationSettings = onOpenNotificationSettings
    }

    public var body: some View {
        ScrollView {
            if isPairing {
                PairingView(code: pairingCode, onCopyCode: onCopyCode, onCancel: onCancelPairing)
                    .padding(HSMetrics.space24)
                    .frame(maxWidth: .infinity)
            } else {
                content
                    .padding(HSMetrics.space24)
                    .frame(maxWidth: HSMetrics.contentWidth)
                    .frame(maxWidth: .infinity)
            }
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                RefreshToolbarButton(isRefreshing: isRefreshing, help: UIStrings.refreshStatusHelp, action: onRefresh)
            }
        }
    }

    private var content: some View {
        let content = DashboardContent.build(model, linkAdvice: linkAdvice, demo: demo)
        return VStack(alignment: .leading, spacing: HSMetrics.space16) {
            header(content)
            GlassCardGroup(spacing: HSMetrics.space16) {
                DashboardCardRow(content: content)
            }
            if !content.attention.isEmpty {
                attentionCard(content.attention)
            }
        }
    }

    private func header(_ content: DashboardContent) -> some View {
        VStack(alignment: .leading, spacing: HSMetrics.space16) {
            VStack(alignment: .leading, spacing: HSMetrics.space8) {
                HStack(alignment: .firstTextBaseline, spacing: HSMetrics.space12) {
                    StatusDot(kind: StatusAppearance.kind(title: content.title, kind: content.statusKind), size: 14)
                    Text(content.title)
                        .font(.largeTitle.bold())
                        .fixedSize(horizontal: false, vertical: true)
                }
                Text(content.subtitle)
                    .font(.title3)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if let checked = content.checkedText {
                    Text(checked)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                if content.demo {
                    Text(Strings.simulated)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel(AccessibilityText.status(kind: StatusAppearance.kind(title: content.title, kind: content.statusKind), title: content.title, subtitle: content.subtitle))

            HStack(spacing: HSMetrics.space12) {
                if let action = content.primaryAction {
                    PrimaryActionButton(action.label) { onAction(action) }
                }
                if let action = content.secondaryAction {
                    SecondaryActionButton(action.label, isDestructive: action == .forget || action == .turnOffAndForget) {
                        onAction(action)
                    }
                }
            }
            if content.title == Strings.notPaired && content.primaryAction == .pair && content.attention.isEmpty {
                Text(UIStrings.pairWhenReady)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(HSMetrics.space24)
        .hsGlassSurface(cornerRadius: HSMetrics.cardRadius, reduceTransparency: reduceTransparency)
    }

    private func attentionCard(_ items: [String]) -> some View {
        Card(title: UIStrings.needsAttention, systemImage: HSSymbol.attention, accessibilityLabel: AccessibilityText.attention(items), combinesChildren: false) {
            VStack(alignment: .leading, spacing: HSMetrics.space12) {
                ForEach(Array(items.enumerated()), id: \.offset) { _, item in
                    let action = DashboardContent.attentionAction(for: item)
                    AttentionRow(text: item, actionLabel: action?.label, action: action.map { value in
                        { perform(value) }
                    })
                }
            }
        }
    }

    private func perform(_ action: AttentionAction) {
        switch action {
        case .checkNow: onAction(.checkNow)
        case .turnOff: onAction(.turnOff)
        case .turnOffAndForget: onAction(.turnOffAndForget)
        case .openNotificationSettings: onOpenNotificationSettings()
        }
    }
}

// The two cards in one row. Both cards get the same height and the same top
// edge. Each card has the same inner layout: title, one value line, then the
// detail lines.
public struct DashboardCardRow: View {
    public var content: DashboardContent
    public init(content: DashboardContent) { self.content = content }

    public var body: some View {
        HStack(alignment: .top, spacing: HSMetrics.space16) {
            card(content.sourceDevice)
            card(content.connection)
        }
        .frame(maxWidth: .infinity, alignment: .top)
    }

    private func card(_ card: DashboardContent.Card) -> some View {
        Card(title: card.title, systemImage: card.symbol, accessibilityLabel: AccessibilityText.card(title: card.title, lines: card.lines), fillsHeight: true) {
            VStack(alignment: .leading, spacing: HSMetrics.space8) {
                Text(card.value)
                    .font(.title3.weight(.semibold))
                    .fixedSize(horizontal: false, vertical: true)
                ForEach(Array(card.details.enumerated()), id: \.offset) { _, line in
                    Text(line)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}
