import SwiftUI

// The activity view. It shows the engine log lines with a time. The Details
// toggle adds the level and the sequence number.
public struct ActivityView: View {
    public var lines: [LogLine]
    public var unavailable: Bool
    public var error: String?
    public var isLoading: Bool
    private let onRefresh: () -> Void
    @State private var showDetails = false

    public init(lines: [LogLine], unavailable: Bool = false, error: String? = nil, isLoading: Bool = false, onRefresh: @escaping () -> Void = {}) {
        self.lines = lines
        self.unavailable = unavailable
        self.error = error
        self.isLoading = isLoading
        self.onRefresh = onRefresh
    }

    private var messages: [(index: Int, time: String, message: String, level: String, sequence: String)] {
        lines.enumerated().compactMap { index, line in
            guard let raw = line.msg, let message = Strings.sanitized(raw), !message.isEmpty else { return nil }
            let time = line.ts.map { Date(timeIntervalSince1970: $0).formatted(date: .omitted, time: .standard) } ?? ""
            return (index, time, message, line.level ?? "", line.seq.map(String.init) ?? "")
        }
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text(UIStrings.activity)
                    .font(.largeTitle.bold())
                Spacer()
            }
            .frame(maxWidth: HSMetrics.contentWidth)
            .frame(maxWidth: .infinity)
            .padding(.horizontal, HSMetrics.space24)
            .padding(.top, HSMetrics.space24)
            .padding(.bottom, HSMetrics.space12)
            content
                .frame(maxWidth: HSMetrics.contentWidth, maxHeight: .infinity, alignment: .topLeading)
                .frame(maxWidth: .infinity, alignment: .center)
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Toggle(UIStrings.details, isOn: $showDetails)
                    .toggleStyle(.button)
                    .accessibilityLabel(UIStrings.details)
                    .help(UIStrings.detailsHelp)
            }
            ToolbarItem(placement: .primaryAction) {
                RefreshToolbarButton(isRefreshing: isLoading, help: UIStrings.refreshActivityHelp, action: onRefresh)
            }
        }
    }

    @ViewBuilder private var content: some View {
        if unavailable {
            stateView(symbol: "clock.badge.exclamationmark", title: UIStrings.activityUnavailable, detail: UIStrings.statusUnavailableLine, showRefresh: true)
        } else if let error {
            // A failed read is a real error. It must not look like the calm
            // empty state, and Retry stays on the screen.
            stateView(symbol: "exclamationmark.triangle", title: UIStrings.activityError, detail: Strings.sanitized(error) ?? error, showRefresh: true)
        } else if messages.isEmpty {
            if isLoading {
                VStack(spacing: HSMetrics.space8) {
                    ProgressView()
                        .controlSize(.small)
                        .accessibilityHidden(true)
                    Text(UIStrings.loadingActivity).foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                stateView(symbol: "clock", title: UIStrings.activityEmpty, detail: UIStrings.activityDetailsNote, showRefresh: true)
            }
        } else {
            list
        }
    }

    private var list: some View {
        List {
            if showDetails {
                Text(UIStrings.activityDetailsNote)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .listRowSeparator(.hidden)
            }
            ForEach(messages, id: \.index) { entry in
                HStack(alignment: .firstTextBaseline, spacing: HSMetrics.space12) {
                    Text(entry.time)
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                        .frame(minWidth: 72, alignment: .leading)
                    VStack(alignment: .leading, spacing: HSMetrics.space4) {
                        if showDetails {
                            Text(details(entry))
                                .font(.caption2.monospaced())
                                .foregroundStyle(.secondary)
                        }
                        Text(entry.message)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .accessibilityElement(children: .combine)
                .accessibilityLabel(accessibility(entry))
            }
        }
        .listStyle(.inset)
    }

    private func details(_ entry: (index: Int, time: String, message: String, level: String, sequence: String)) -> String {
        var parts: [String] = []
        if !entry.level.isEmpty { parts.append(entry.level) }
        if !entry.sequence.isEmpty { parts.append("seq \(entry.sequence)") }
        return parts.joined(separator: ", ")
    }

    private func accessibility(_ entry: (index: Int, time: String, message: String, level: String, sequence: String)) -> String {
        var parts: [String] = []
        if !entry.time.isEmpty { parts.append(entry.time) }
        parts.append(entry.message)
        if showDetails, !entry.level.isEmpty { parts.append(entry.level) }
        return parts.joined(separator: ". ")
    }

    private func stateView(symbol: String, title: String, detail: String, showRefresh: Bool) -> some View {
        VStack(spacing: HSMetrics.space12) {
            Image(systemName: symbol)
                .font(.largeTitle)
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text(title)
                .font(.headline)
            Text(detail)
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            if showRefresh {
                Button(Strings.refresh, action: onRefresh)
            }
        }
        .padding(HSMetrics.space24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
