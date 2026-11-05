import SwiftUI

// The pairing view inside the dashboard. It shows one large code and three
// short steps. It never shows a fake percentage.
public struct PairingView: View {
    public var code: String?
    private let onCopyCode: (String) -> Void
    private let onCancel: () -> Void
    @State private var copied = false
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    public init(code: String?, onCopyCode: @escaping (String) -> Void, onCancel: @escaping () -> Void) {
        self.code = code
        self.onCopyCode = onCopyCode
        self.onCancel = onCancel
    }

    private var groupedCode: String { PairingCodeFormat.grouped(code) }

    public var body: some View {
        VStack(alignment: .leading, spacing: HSMetrics.space24) {
            VStack(alignment: .leading, spacing: HSMetrics.space8) {
                Text(Strings.pairingTitle)
                    .font(.title2.bold())
                Text(UIStrings.checkBothScreens)
                    .font(.title3)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            VStack(alignment: .leading, spacing: HSMetrics.space12) {
                if groupedCode.isEmpty {
                    HStack(spacing: HSMetrics.space8) {
                        ProgressView()
                            .controlSize(.small)
                            .accessibilityHidden(true)
                        Text(UIStrings.waitingForCode)
                            .foregroundStyle(.secondary)
                    }
                } else {
                    Text(groupedCode)
                        .font(.system(size: 40, weight: .semibold, design: .rounded))
                        .monospacedDigit()
                        .textSelection(.enabled)
                        .accessibilityLabel(AccessibilityText.code(groupedCode))
                }
                HStack(spacing: HSMetrics.space8) {
                    Image(systemName: "hand.tap")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .accessibilityHidden(true)
                    Text(Strings.allow)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(HSMetrics.space16)
            .background(.quaternary, in: RoundedRectangle(cornerRadius: HSMetrics.controlRadius, style: .continuous))

            VStack(alignment: .leading, spacing: HSMetrics.space8) {
                step("1", UIStrings.pairingStepOpen)
                step("2", UIStrings.pairingStepCompare)
                step("3", UIStrings.pairingStepAllow)
            }

            HStack(spacing: HSMetrics.space12) {
                Button(UIStrings.copyCode) {
                    guard !groupedCode.isEmpty else { return }
                    onCopyCode(groupedCode)
                    copied = true
                }
                .disabled(groupedCode.isEmpty)
                Button(Strings.cancel, action: onCancel)
                    .keyboardShortcut(.cancelAction)
                if copied {
                    Text(UIStrings.codeCopied)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(HSMetrics.space24)
        .hsGlassSurface(cornerRadius: HSMetrics.cardRadius, reduceTransparency: reduceTransparency)
        .frame(maxWidth: HSMetrics.contentWidth)
    }

    private func step(_ number: String, _ text: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: HSMetrics.space8) {
            Text(number)
                .font(.subheadline.weight(.semibold).monospacedDigit())
                .foregroundStyle(.secondary)
                .frame(minWidth: 16, alignment: .trailing)
                .accessibilityHidden(true)
            Text(text)
                .fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Step \(number). \(text)")
    }
}
