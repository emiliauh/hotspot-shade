import Foundation
import CryptoKit

@main
struct TrustedTargetListTests {
    static func check(_ condition: Bool, _ message: String, line: Int = #line) {
        if !condition {
            print("FAIL line \(line): \(message)")
            exit(1)
        }
    }

    static func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }

    static func freshDefaults() -> (UserDefaults, String) {
        let suite = "TrustedTargetListTests." + UUID().uuidString
        let defaults = UserDefaults(suiteName: suite)!
        defaults.removePersistentDomain(forName: suite)
        return (defaults, suite)
    }

    static func main() {
        let keyA = Data((0..<32).map { UInt8($0) })
        let keyB = Data((0..<32).map { UInt8(255 - $0) })

        // Digest label: "Target device " and the first four digest bytes in
        // lowercase hex. Fixed vectors match the Android label.
        let digestA = Array(SHA256.hash(data: keyA))
        check(TrustFingerprint.label(for: keyA) == "Target device " + hex(Data(digestA.prefix(4))),
              "label uses the first four digest bytes")
        check(TrustFingerprint.label(for: Data()) == "Target device e3b0c442",
              "empty key digest vector: \(TrustFingerprint.label(for: Data()))")
        check(TrustFingerprint.label(for: Data("abc".utf8)) == "Target device ba7816bf",
              "abc digest vector: \(TrustFingerprint.label(for: Data("abc".utf8)))")
        check(TrustFingerprint.label(for: keyA) == TrustFingerprint.label(for: keyA), "label is stable")
        check(TrustFingerprint.label(for: keyA) != TrustFingerprint.label(for: keyB), "keys differ")
        let label = TrustFingerprint.label(for: keyA)
        check(label.count == "Target device ".count + 8, "label has eight hex digits")
        check(!label.contains(Data(keyA).base64EncodedString()), "label shows no key")
        check(TrustedTarget(key: keyA).forgetAccessibilityLabel == "Forget " + label, "accessibility label")

        // List order and duplicates.
        let list = TrustedTarget.list([keyA, keyB, keyA])
        check(list.map(\.key) == [keyA, keyB], "stored order, no duplicate")
        check(list.map(\.id) == [keyA, keyB], "the id is the full key")
        check(TrustedTarget.list([]).isEmpty, "empty list")

        // Memory store: per-key removal and forget all.
        let memory = MemoryTrustStore()
        memory.add(keyA); memory.add(keyB); memory.add(keyA)
        check(memory.keys == [keyA, keyB] && memory.count == 2, "memory keys, no duplicate")
        memory.remove(keyA)
        check(memory.keys == [keyB] && !memory.contains(keyA) && memory.contains(keyB),
              "remove one key leaves the other")
        memory.remove(keyA)
        check(memory.keys == [keyB], "remove of an absent key changes nothing")
        memory.removeAll()
        check(memory.keys.isEmpty && memory.count == 0, "memory forget all")

        // Compatibility with the stored format. A list written by an older
        // build is a string array of base64 public keys under "pairedLaptops".
        let (defaults, suite) = freshDefaults()
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set([keyA.base64EncodedString(), keyB.base64EncodedString()], forKey: "pairedLaptops")
        let store = UserDefaultsTrustStore(defaults: defaults)
        check(store.count == 2, "old list counts")
        check(store.contains(keyA) && store.contains(keyB), "old entries stay trusted")
        check(store.keys == [keyA, keyB], "old list reads in stored order")
        check(TrustedTarget.list(store.keys).map(\.label)
                == [TrustFingerprint.label(for: keyA), TrustFingerprint.label(for: keyB)],
              "old entries get digest labels")

        // Per-key removal writes the same format and leaves the other entry.
        store.remove(keyA)
        check(defaults.stringArray(forKey: "pairedLaptops") == [keyB.base64EncodedString()],
              "stored format after one forget: \(String(describing: defaults.stringArray(forKey: "pairedLaptops")))")
        check(!store.contains(keyA) && store.contains(keyB), "the forgotten key is no longer trusted")
        check(store.keys == [keyB] && store.count == 1, "one key remains")
        store.remove(keyA)
        check(store.count == 1, "removing an absent key keeps the list")

        // A new key is appended in the same format.
        store.add(keyA)
        check(defaults.stringArray(forKey: "pairedLaptops") == [keyB.base64EncodedString(), keyA.base64EncodedString()],
              "an add appends base64")
        store.add(keyA)
        check(store.count == 2, "a duplicate add keeps one entry")

        // A new store object on the same defaults sees the same trust.
        check(UserDefaultsTrustStore(defaults: defaults).keys == [keyB, keyA], "trust survives a new store object")

        // An entry that is not valid base64 never matches a key. It is not
        // listed and it still counts, and Forget all clears it.
        defaults.set([keyA.base64EncodedString(), "not base64 !!"], forKey: "pairedLaptops")
        check(store.keys == [keyA], "an unreadable entry is not listed")
        check(store.count == 2, "an unreadable entry still counts")
        store.remove(keyA)
        check(defaults.stringArray(forKey: "pairedLaptops") == ["not base64 !!"],
              "removing one key keeps an unreadable entry")

        // Forget all removes every entry and leaves no key.
        store.add(keyA); store.add(keyB)
        store.removeAll()
        check(defaults.object(forKey: "pairedLaptops") == nil, "forget all clears the stored list")
        check(store.keys.isEmpty && store.count == 0 && !store.contains(keyA) && !store.contains(keyB),
              "nothing is trusted after forget all")

        // The wrapper lists the same keys and reports a per-row forget once.
        let observable = ObservableTrustStore(MemoryTrustStore())
        var changes: [TrustChange] = []
        observable.setChangeHandler { changes.append($0) }
        observable.add(keyA); observable.add(keyB)
        check(observable.keys == [keyA, keyB], "wrapper lists keys")
        observable.remove(keyA)
        check(observable.keys == [keyB] && changes == [.added, .added, .removed], "a per-row forget is one removal: \(changes)")
        observable.removeAll()
        check(observable.keys.isEmpty && changes.last == .forgottenAll, "forget all through the wrapper")

        // A forgotten key is untrusted. PairingTests covers the prompt for it
        // (unknownAllowThenKnown, knownForgottenBeforeReveal).
        let forgotten = MemoryTrustStore()
        forgotten.add(keyA)
        forgotten.remove(keyA)
        check(!forgotten.contains(keyA), "a forgotten key is untrusted, so the pairing responder prompts")

        // Confirmation text. It names the label and says the token stays.
        check(ConfirmationText.forgetTargetTitle == "Forget this target device?", "title")
        let message = ConfirmationText.forgetTargetMessage(label: label)
        check(message.contains(label) && message.contains("does not revoke"), "message: \(message)")
        check(!message.contains("\u{2014}") && !message.lowercased().contains("laptop"), "style")

        print("Trusted target list tests passed")
    }
}
