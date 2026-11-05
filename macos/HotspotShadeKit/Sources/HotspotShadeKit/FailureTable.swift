import Foundation

// The columns of the recent failures table.
public enum FailureColumn: String, CaseIterable, Equatable {
    case count
    case kind
    case target
    case stage
    case reason

    public var title: String {
        switch self {
        case .count: return UIStrings.countColumn
        case .kind: return UIStrings.kindColumn
        case .target: return UIStrings.targetColumn
        case .stage: return UIStrings.stageColumn
        case .reason: return UIStrings.reasonColumn
        }
    }
}

// One row of the recent failures table. The table shows these fields as
// separate columns, so a person can sort each one.
public struct FailureTableRow: Identifiable, Equatable {
    public var id: String
    public var count: Int
    public var kind: String
    public var target: String
    public var stage: String
    public var reason: String
    // The plain sentence for the row, used as a tooltip and by a reader.
    public var summary: String
    public var detail: String
    public init(id: String, count: Int, kind: String, target: String, stage: String = "", reason: String, summary: String, detail: String) {
        self.id = id; self.count = count; self.kind = kind; self.target = target
        self.stage = stage; self.reason = reason; self.summary = summary; self.detail = detail
    }
}

// Pure conversion and sorting. The table uses the same rule as the tests.
public enum FailureTable {
    public static func rows(from rows: [FailureRow]) -> [FailureTableRow] {
        rows.map {
            FailureTableRow(id: $0.id, count: $0.count, kind: $0.kind, target: $0.target, stage: $0.phase, reason: $0.reason, summary: $0.summary, detail: $0.detail)
        }
    }

    // Sort one column. A count is a number, so 9 comes before 10 in ascending
    // order. Equal values keep a stable order by identifier.
    public static func sorted(_ rows: [FailureTableRow], by column: FailureColumn, ascending: Bool) -> [FailureTableRow] {
        rows.sorted { left, right in
            let order: ComparisonResult
            switch column {
            case .count:
                order = left.count == right.count ? .orderedSame : (left.count < right.count ? .orderedAscending : .orderedDescending)
            case .kind:
                order = word(left.kind, right.kind)
            case .target:
                order = word(left.target, right.target)
            case .stage:
                order = word(left.stage, right.stage)
            case .reason:
                order = word(left.reason, right.reason)
            }
            if order == .orderedSame { return left.id < right.id }
            return ascending ? order == .orderedAscending : order == .orderedDescending
        }
    }

    public static func value(_ row: FailureTableRow, column: FailureColumn) -> String {
        switch column {
        case .count: return String(row.count)
        case .kind: return row.kind
        case .target: return row.target
        case .stage: return row.stage
        case .reason: return row.reason
        }
    }

    private static func word(_ left: String, _ right: String) -> ComparisonResult {
        let a = left.lowercased(), b = right.lowercased()
        if a == b { return .orderedSame }
        return a < b ? .orderedAscending : .orderedDescending
    }
}
