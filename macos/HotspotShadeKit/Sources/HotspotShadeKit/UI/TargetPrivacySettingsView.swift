import SwiftUI

// The Privacy tab in Settings. It reports what this build can and cannot do
// for destination names, and it offers no control. A control would claim a
// service that the engine does not provide.
//
// The page is read-only. It does not read the tunnel state, so no row says
// that a mode is running and no mark looks like an active indicator. Every row
// names its state in text, so the meaning does not depend on color. The view
// reads only the fixed report and never the network or the engine.
public struct TargetPrivacySettingsView: View {
    public var report: TargetPrivacyReport

    public init(report: TargetPrivacyReport = TargetPrivacyCapabilities.current) {
        self.report = report
    }

    public var body: some View {
        Form {
            Section {
                Text(report.intro)
                    .fixedSize(horizontal: false, vertical: true)
                Text(report.optInNote)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Section("Modes in this build") {
                VStack(alignment: .leading, spacing: HSMetrics.space16) {
                    ForEach(report.modes) { row in
                        modeRow(row)
                    }
                }
                .padding(.vertical, HSMetrics.space4)
            }
            Section("Capabilities in this build") {
                VStack(alignment: .leading, spacing: HSMetrics.space16) {
                    ForEach(report.facts) { row in
                        factRow(row)
                    }
                }
                .padding(.vertical, HSMetrics.space4)
            }
            Section("What stays visible") {
                VStack(alignment: .leading, spacing: HSMetrics.space8) {
                    ForEach(report.limits, id: \.self) { line in
                        Text(line)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            Section {
                Text(report.footer)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .formStyle(.grouped)
    }

    private func modeRow(_ row: TargetPrivacyModeRow) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: HSMetrics.space12) {
            Image(systemName: row.symbol)
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: HSMetrics.space4) {
                HStack(alignment: .firstTextBaseline, spacing: HSMetrics.space8) {
                    Text(row.title)
                    Spacer(minLength: HSMetrics.space8)
                    Text(row.stateText)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Text(row.detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(row.title). \(row.stateText). \(row.detail)")
    }

    private func factRow(_ row: TargetPrivacyFactRow) -> some View {
        VStack(alignment: .leading, spacing: HSMetrics.space4) {
            HStack(alignment: .firstTextBaseline, spacing: HSMetrics.space8) {
                Text(row.title)
                Spacer(minLength: HSMetrics.space8)
                Text(row.valueText)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            Text(row.detail)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(row.title). \(row.valueText). \(row.detail)")
    }
}
