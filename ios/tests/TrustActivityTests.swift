import Foundation

@main
struct TrustActivityTests {
    static func check(_ condition: Bool, _ message: String, line: Int = #line) {
        if !condition {
            print("FAIL line \(line): \(message)")
            exit(1)
        }
    }

    static func main() {
        // The exact activity lines. They name no device, address, or code.
        check(TrustChange.added.activity == "A target device was added.", "added line")
        check(TrustChange.removed.activity == "A target device was removed.", "removed line")
        check(TrustChange.forgottenAll.activity == "Paired target devices forgotten.", "forget all line")
        for change in [TrustChange.added, .removed, .forgottenAll] {
            let line = change.activity
            check(!line.contains(where: \.isNumber), "no number: \(line)")
            check(!line.lowercased().contains("laptop") && !line.lowercased().contains("computer"),
                  "no old device name: \(line)")
            check(!line.lowercased().contains(":"), "no address: \(line)")
        }

        // A count increase is a new pairing, also above one.
        check(TrustChange.change(previous: 0, current: 1) == .added, "first pairing")
        check(TrustChange.change(previous: 1, current: 2) == .added, "another pairing")
        check(TrustChange.change(previous: 2, current: 5) == .added, "one line for an increase")

        // A count decrease is a remote FORGET.
        check(TrustChange.change(previous: 1, current: 0) == .removed, "the last device leaves")
        check(TrustChange.change(previous: 3, current: 2) == .removed, "one of several leaves")

        // No count change gives no line.
        check(TrustChange.change(previous: 0, current: 0) == nil, "no change")
        check(TrustChange.change(previous: 2, current: 2) == nil, "no change with devices")

        // Forget all wins over the count.
        check(TrustChange.change(previous: 2, current: 0, forgottenAll: true) == .forgottenAll,
              "forget all")
        check(TrustChange.change(previous: 2, current: 2, forgottenAll: true) == .forgottenAll,
              "forget all with no count change")
        check(TrustChange.change(previous: 1, current: 0, forgottenAll: false) == .removed,
              "the flag alone selects forget all")

        // The wrapper reports each change, including a remote FORGET.
        let base = MemoryTrustStore()
        let store = ObservableTrustStore(base)
        var changes: [TrustChange] = []
        store.setChangeHandler { changes.append($0) }
        let keyA = Data([1, 2, 3])
        let keyB = Data([4, 5, 6])
        check(store.count == 0 && !store.contains(keyA), "the wrapper starts empty")
        store.add(keyA)
        check(store.count == 1 && store.contains(keyA), "the wrapper keeps the key")
        check(changes == [.added], "add notifies: \(changes)")
        store.add(keyA)
        check(changes == [.added], "a duplicate add notifies once: \(changes)")
        store.add(keyB)
        check(changes == [.added, .added], "a second add notifies")
        store.remove(keyA)
        check(store.count == 1 && changes == [.added, .added, .removed],
              "a remove notifies once: \(changes)")
        store.remove(keyA)
        check(changes.count == 3, "a remove of an absent key does not notify")
        store.removeAll()
        check(store.count == 0 && changes.last == .forgottenAll, "forget all notifies")
        store.removeAll()
        check(changes.count == 4, "an empty forget all does not notify")
        store.setChangeHandler(nil)
        store.add(keyA)
        check(store.count == 1, "the wrapper works with no handler")

        print("Trust activity tests passed")
    }
}
