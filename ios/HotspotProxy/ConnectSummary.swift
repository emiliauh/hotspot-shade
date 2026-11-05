import Foundation

/// Plain words for the connection counters. This file uses Foundation only.
/// The line holds counts and kind words. It holds no address, port, or host.
enum ConnectSummary {
    /// The fixed order for a tie. It follows the order in `ConnectConclusion.Kind`.
    static let kindOrder: [ConnectConclusion.Kind] = [.web, .otherTCP, .udp, .dnsLookup]

    /// The "Did not work" line for the failed counts by kind. Return nil when
    /// every count is zero. Sort by count, then by `kindOrder`.
    /// Example: "Did not work: 96 web, 24 DNS lookups, 15 other connections."
    static func didNotWorkKinds(_ counts: [ConnectConclusion.Kind: Int]) -> String? {
        let order = Dictionary(uniqueKeysWithValues: kindOrder.enumerated().map { ($1, $0) })
        let parts: [(kind: ConnectConclusion.Kind, count: Int, text: String)] =
            kindOrder.compactMap { kind in
                let count = max(0, counts[kind] ?? 0)
                guard count > 0 else { return nil }
                return (kind, count, "\(count) \(kindWord(kind, count: count))")
            }
        guard !parts.isEmpty else { return nil }
        let sorted = parts.sorted { left, right in
            if left.count != right.count { return left.count > right.count }
            return (order[left.kind] ?? 0) < (order[right.kind] ?? 0)
        }
        return "Did not work: " + sorted.map(\.text).joined(separator: ", ") + "."
    }

    /// The kind words. A count of one uses the singular.
    private static func kindWord(_ kind: ConnectConclusion.Kind, count: Int) -> String {
        switch kind {
        case .web: return "web"
        case .otherTCP: return count == 1 ? "other connection" : "other connections"
        case .udp: return "UDP"
        case .dnsLookup: return count == 1 ? "DNS lookup" : "DNS lookups"
        }
    }
}
