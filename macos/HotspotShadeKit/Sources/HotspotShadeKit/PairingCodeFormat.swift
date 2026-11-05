import Foundation

// Show a pairing code in groups of three. The engine sends digits. A code
// with other characters keeps only the digits.
public enum PairingCodeFormat {
    public static func grouped(_ code: String?) -> String {
        let digits = (code ?? "").filter { $0.isNumber }
        guard !digits.isEmpty else { return "" }
        var groups: [String] = []
        var start = digits.startIndex
        while start < digits.endIndex {
            let end = digits.index(start, offsetBy: 3, limitedBy: digits.endIndex) ?? digits.endIndex
            groups.append(String(digits[start..<end]))
            start = end
        }
        return groups.joined(separator: " ")
    }
}
