import SwiftUI

// The recent failures table. It is native and sortable. The Count column sorts
// as a number. Every state has plain text.
public struct FailuresTableView: View {
    public var rows: [FailureRow]
    public var state: FailuresState
    public var reportCopied: Bool
    public var tunnelRunning: Bool
    private let onRefresh: () -> Void
    private let onCopyReport: () -> Void
    @State private var sortOrder: [KeyPathComparator<FailureTableRow>] = [KeyPathComparator(\.count, order: .reverse)]

    public init(rows: [FailureRow], state: FailuresState, reportCopied: Bool = false, tunnelRunning: Bool = true, onRefresh: @escaping () -> Void = {}, onCopyReport: @escaping () -> Void = {}) {
        self.rows = rows
        self.state = state
        self.reportCopied = reportCopied
        self.tunnelRunning = tunnelRunning
        self.onRefresh = onRefresh
        self.onCopyReport = onCopyReport
    }

    private var tableRows: [FailureTableRow] { FailureTable.rows(from: rows) }

    public var body: some View {
        VStack(alignment: .leading, spacing: HSMetrics.space12) {
            content
            HStack(spacing: HSMetrics.space12) {
                Button(Strings.refresh, action: onRefresh)
                    .disabled(!tunnelRunning || state == .loading)
                if state == .loaded {
                    Button(Strings.copyReport, action: onCopyReport)
                }
                if reportCopied {
                    Text(Strings.reportCopied)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Text(Strings.failuresHint)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    @ViewBuilder private var content: some View {
        if !tunnelRunning {
            stateText(Strings.failuresTunnelOff)
        } else {
            switch state {
            case .idle:
                stateText(Strings.failuresNotLoaded)
            case .loading:
                HStack(spacing: HSMetrics.space8) {
                    ProgressView()
                        .controlSize(.small)
                        .accessibilityHidden(true)
                    Text(Strings.loadingFailures).foregroundStyle(.secondary)
                }
            case .empty:
                stateText(Strings.noFailures)
            case .unavailable:
                stateText(UIStrings.failuresUnavailable)
            case .error(let message):
                stateText(Strings.sanitized(message) ?? message)
            case .loaded:
                table
            }
        }
    }

    private func stateText(_ text: String) -> some View {
        Text(text)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.vertical, HSMetrics.space8)
    }

    private var table: some View {
        Table(tableRows, sortOrder: $sortOrder) {
            TableColumn(UIStrings.countColumn, value: \.count) { row in
                Text(String(row.count)).monospacedDigit()
            }
            .width(min: 60, ideal: 70)
            TableColumn(UIStrings.kindColumn, value: \.kind) { row in
                Text(row.kind)
            }
            .width(min: 60, ideal: 70)
            TableColumn(UIStrings.targetColumn, value: \.target) { row in
                Text(row.target)
                    .help(row.detail)
            }
            .width(min: 140, ideal: 220)
            TableColumn(UIStrings.stageColumn, value: \.stage) { row in
                Text(row.stage)
            }
            .width(min: 90, ideal: 130)
            TableColumn(UIStrings.reasonColumn, value: \.reason) { row in
                Text(row.reason)
            }
            .width(min: 110, ideal: 140)
        }
        .frame(minHeight: 180, idealHeight: 220)
        .accessibilityLabel(Strings.recentFailures)
    }
}
