import SwiftUI

// The recent failures table. It is native and sortable. The Count column sorts
// as a number. Every state has plain text.
public struct FailuresTableView: View {
    public var rows: [FailureRow]
    public var state: FailuresState
    public var reportCopied: Bool
    public var tunnelRunning: Bool
    // True after an interrupted operation. The engine cannot list failures,
    // and an empty table must not look like a healthy record.
    public var recoveryBlocked: Bool
    public var serviceStateUnknown: Bool
    // True when the engine did not answer. The table must not claim that the
    // tunnel is off, and Refresh is disabled.
    public var unavailable: Bool
    // True when the last status is old. An empty list must not claim Off.
    public var stale: Bool
    private let onRefresh: () -> Void
    private let onCopyReport: () -> Void
    @State private var sortOrder: [KeyPathComparator<FailureTableRow>] = [KeyPathComparator(\.count, order: .reverse)]

    public init(rows: [FailureRow], state: FailuresState, reportCopied: Bool = false, tunnelRunning: Bool = true, recoveryBlocked: Bool = false, serviceStateUnknown: Bool = false, unavailable: Bool = false, stale: Bool = false, onRefresh: @escaping () -> Void = {}, onCopyReport: @escaping () -> Void = {}) {
        self.rows = rows
        self.state = state
        self.reportCopied = reportCopied
        self.tunnelRunning = tunnelRunning
        self.recoveryBlocked = recoveryBlocked
        self.serviceStateUnknown = serviceStateUnknown
        self.unavailable = unavailable
        self.stale = stale
        self.onRefresh = onRefresh
        self.onCopyReport = onCopyReport
    }

    private var tableRows: [FailureTableRow] { FailureTable.rows(from: rows) }

    public var body: some View {
        VStack(alignment: .leading, spacing: HSMetrics.space12) {
            content
            HStack(spacing: HSMetrics.space12) {
                Button(Strings.refresh, action: onRefresh)
                    .disabled(!FailuresViewText.refreshEnabled(state: state, tunnelRunning: tunnelRunning, unavailable: unavailable, recoveryBlocked: recoveryBlocked))
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
        if let text = FailuresViewText.placeholder(state: state, tunnelRunning: tunnelRunning, unavailable: unavailable, stale: stale, recoveryBlocked: recoveryBlocked, serviceStateUnknown: serviceStateUnknown) {
            stateText(text)
        } else if state == .loading {
            HStack(spacing: HSMetrics.space8) {
                ProgressView()
                    .controlSize(.small)
                    .accessibilityHidden(true)
                Text(Strings.loadingFailures).foregroundStyle(.secondary)
            }
        } else {
            table
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

// The plain text and the Refresh state for the failure table. It is pure, so
// every unavailable and recovery case is a test without a window.
public enum FailuresViewText {
    public static func placeholder(state: FailuresState, tunnelRunning: Bool, unavailable: Bool, stale: Bool, recoveryBlocked: Bool, serviceStateUnknown: Bool) -> String? {
        if recoveryBlocked {
            return serviceStateUnknown ? Strings.serviceStateUnknownBody : Strings.cleanupBlockedBody
        }
        if unavailable {
            return UIStrings.statusUnavailableLine
        }
        if !tunnelRunning {
            return stale ? Strings.staleStatus : Strings.failuresTunnelOff
        }
        switch state {
        case .idle: return Strings.failuresNotLoaded
        case .empty: return Strings.noFailures
        case .unavailable: return UIStrings.failuresUnavailable
        case .error(let message): return Strings.sanitized(message) ?? message
        case .loading, .loaded: return nil
        }
    }

    public static func refreshEnabled(state: FailuresState, tunnelRunning: Bool, unavailable: Bool, recoveryBlocked: Bool) -> Bool {
        tunnelRunning && !unavailable && !recoveryBlocked && state != .loading
    }
}
