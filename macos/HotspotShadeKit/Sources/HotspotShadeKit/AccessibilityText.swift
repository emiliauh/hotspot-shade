import Foundation

// Plain labels for assistive technology. The views use one label for each
// group, so a screen reader does not read a card piece by piece.
public enum AccessibilityText {
    public static func status(kind: ScreenModel.StatusKind, title: String, subtitle: String, checkedText: String? = nil) -> String {
        let state = word(kind)
        var parts = [state, title]
        if !subtitle.isEmpty { parts.append(subtitle) }
        // A screen reader must hear when the status was read, not only see the
        // small print.
        if let checkedText, !checkedText.isEmpty { parts.append(checkedText) }
        return parts.joined(separator: ". ")
    }

    public static func card(title: String, lines: [String]) -> String {
        let body = lines.filter { !$0.isEmpty }.joined(separator: " ")
        if body.isEmpty { return title }
        return "\(title). \(body)"
    }

    public static func attention(_ items: [String]) -> String {
        guard !items.isEmpty else { return UIStrings.needsAttention }
        return "\(UIStrings.needsAttention). \(items.joined(separator: " "))"
    }

    public static func menuStatus(title: String, detail: String) -> String {
        detail.isEmpty ? title : "\(title). \(detail)"
    }

    public static func code(_ code: String?) -> String {
        guard let code, !code.isEmpty else { return UIStrings.pairingCodeLabel }
        return "\(UIStrings.pairingCodeLabel) \(code)"
    }

    private static func word(_ kind: ScreenModel.StatusKind) -> String {
        switch kind {
        case .off: return "Status"
        case .on: return "The tunnel is on"
        case .attention: return "Needs attention"
        case .pairing: return "Pairing"
        case .busy: return "The app is busy"
        }
    }
}
