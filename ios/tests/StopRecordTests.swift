import Foundation

@main
struct StopRecordTests {
    static func check(_ condition: Bool, _ message: String, line: Int = #line) {
        if !condition {
            print("FAIL line \(line): \(message)")
            exit(1)
        }
    }

    static func main() {
        let first = Date(timeIntervalSince1970: 1_700_000_000)
        let second = Date(timeIntervalSince1970: 1_700_003_600)

        // The one plain Dashboard line.
        let hotspot = StopRecord(reason: .hotspotLost, date: first)
        check(hotspot.line(timeText: "14:32") == "Last stop: The hotspot address was lost. 14:32.",
              "hotspot line: \(hotspot.line(timeText: "14:32"))")
        // The default uses the user's time style.
        let userTime = first.formatted(date: .omitted, time: .shortened)
        check(hotspot.line() == hotspot.line(timeText: userTime), "the default time style")

        // Every short reason is plain and names no old device or product.
        let oldProduct = ["hotspot", "proxy"].joined(separator: " ")
        for reason in StopReason.allCases {
            let text = reason.shortMessage
            check(!text.contains(where: \.isNumber), "no number in the short reason: \(text)")
            check(!text.lowercased().contains("laptop") && !text.lowercased().contains("computer"),
                  "no old device name: \(text)")
            check(!text.lowercased().contains(oldProduct), "no old product name: \(text)")
            let line = StopRecord(reason: reason, date: first).line(timeText: "09:05")
            check(line.hasPrefix("Last stop: "), "the line starts with the label: \(line)")
        }
        check(StopRecord(reason: .user, date: first).line(timeText: "09:05") == "Last stop: You stopped it. 09:05.", "user line")
        check(StopRecord(reason: .failed, date: first).line(timeText: "09:05")
                == "Last stop: The proxy stopped because of an error. 09:05.", "failed line")
        check(StopRecord(reason: .locationLost, date: first).line(timeText: "09:05")
                == "Last stop: Location turned off. 09:05.", "location line")

        // The injected clock and the in-memory store.
        let store = MemoryStopRecordStore()
        let log = StopLog(store: store, now: { first })
        check(log.current() == nil, "no record at the first launch")
        let saved = log.record(.user)
        check(saved == StopRecord(reason: .user, date: first), "the record holds the injected time")
        check(log.current() == saved, "the record loads again")
        check(first.formatted(date: .omitted, time: .shortened).isEmpty == false, "the time text is not empty")

        // A later stop replaces the earlier one.
        let later = StopLog(store: store, now: { second })
        let replaced = later.record(.hotspotLost)
        check(replaced.date == second, "the new time")
        check(later.current()?.reason == .hotspotLost, "the new reason")
        check(store.load() == replaced, "the store holds one record only")

        // A new start clears the line.
        later.clear()
        check(later.current() == nil, "clear removes the record")

        // The UserDefaults store survives across two store objects.
        let suite = UserDefaults(suiteName: "hs-stop-record-test")!
        suite.removePersistentDomain(forName: "hs-stop-record-test")
        let defaultsStore = UserDefaultsStopRecordStore(defaults: suite)
        check(defaultsStore.load() == nil, "the defaults store starts empty")
        defaultsStore.save(StopRecord(reason: .failed, date: second))
        let reloaded = UserDefaultsStopRecordStore(defaults: suite).load()
        check(reloaded?.reason == .failed, "the reason survives")
        check(reloaded?.date.timeIntervalSince1970 == second.timeIntervalSince1970, "the date survives")
        defaultsStore.clear()
        check(defaultsStore.load() == nil, "the defaults store clears")
        suite.removePersistentDomain(forName: "hs-stop-record-test")

        print("Stop record tests passed")
    }
}
