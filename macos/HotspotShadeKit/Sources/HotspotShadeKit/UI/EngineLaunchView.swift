import SwiftUI

// The main window and the Settings window show this before the app has a
// model. It never claims that the tunnel is on, and it never claims a clean
// stop after an uncertain one.
public struct EngineLaunchView: View {
    public var state: EngineLaunchState
    public var diagnosticsCopied: Bool
    private let onStart: () -> Void
    private let onRetry: () -> Void
    private let onCopyDiagnostics: () -> Void

    public init(
        state: EngineLaunchState,
        diagnosticsCopied: Bool = false,
        onStart: @escaping () -> Void = {},
        onRetry: @escaping () -> Void = {},
        onCopyDiagnostics: @escaping () -> Void = {}
    ) {
        self.state = state
        self.diagnosticsCopied = diagnosticsCopied
        self.onStart = onStart
        self.onRetry = onRetry
        self.onCopyDiagnostics = onCopyDiagnostics
    }

    public var body: some View {
        let presentation = state.presentation()
        VStack(spacing: HSMetrics.space16) {
            VStack(spacing: HSMetrics.space16) {
                Image(systemName: symbol)
                    .font(.largeTitle)
                    .foregroundStyle(presentation.isAttention ? .orange : .secondary)
                    .accessibilityHidden(true)
                Text(presentation.title)
                    .font(.title2.bold())
                Text(presentation.message)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                if let recovery = presentation.recovery {
                    Text(recovery)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
            }
            .accessibilityElement(children: .combine)

            if presentation.showsProgress {
                ProgressView()
                    .accessibilityLabel(presentation.title)
            }

            if let actionTitle = presentation.actionTitle {
                PrimaryActionButton(actionTitle, action: action)
            }

            if presentation.showsCopyDiagnostics {
                VStack(spacing: HSMetrics.space8) {
                    SecondaryActionButton(UIStrings.copyDiagnostics, action: onCopyDiagnostics)
                    if diagnosticsCopied {
                        Text(UIStrings.copied)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }

        }
        .padding(HSMetrics.space48)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var symbol: String {
        switch state {
        case .waiting: return "network.slash"
        case .starting, .stopping: return "hourglass"
        case .running: return "network"
        case .failed, .lost: return "exclamationmark.triangle"
        }
    }

    private func action() {
        switch state {
        case .waiting:
            onStart()
        case .failed, .lost:
            onRetry()
        case .starting, .running, .stopping:
            break
        }
    }
}
