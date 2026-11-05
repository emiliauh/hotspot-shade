import Foundation

@main
struct LocationHealthTests {
    static func check(_ condition: Bool, _ message: String, line: Int = #line) {
        if !condition {
            print("FAIL line \(line): \(message)")
            exit(1)
        }
    }

    static func main() {
        let now = Date(timeIntervalSince1970: 100_000)

        check(LocationHealth.recentSeconds == 60, "recent window")
        check(LocationHealth.stoppedSeconds == 300, "stopped window")
        check(LocationHealth.keepingAwake == "The app stays awake while the proxy runs.", "keeping awake text")
        check(LocationHealth.updatesStopped == "Location updates stopped. Open HotspotShade to restart.",
              "stopped text")
        check(LocationHealth.noFix == "No location yet.", "no fix text")
        check(LocationHealth.permissionOff == "Location is off, so iOS can pause the app. Open Settings to turn it on.",
              "permission text")

        // The three fix states.
        check(LocationHealth.fix(lastFix: nil, now: now) == .none, "no fix")
        check(LocationHealth.fix(lastFix: now, now: now) == .recent, "now is recent")
        check(LocationHealth.fix(lastFix: now.addingTimeInterval(-59.9), now: now) == .recent, "59.9 s")
        check(LocationHealth.fix(lastFix: now.addingTimeInterval(-60), now: now) == .stopped, "60 s is stopped")
        check(LocationHealth.fix(lastFix: now.addingTimeInterval(-300), now: now) == .stopped, "300 s is stopped")
        check(LocationHealth.fix(lastFix: now.addingTimeInterval(-300.1), now: now) == .none, "over 300 s is none")
        check(LocationHealth.fix(lastFix: now.addingTimeInterval(5), now: now) == .recent, "a future fix is recent")

        // The state mapping for the card.
        func message(access: LocationAccess, lastFix: Date?, hadFix: Bool = false,
                     keepAwake: Bool = true, running: Bool = true, cap: Bool = false) -> String {
            LocationHealth.message(access: access, lastFix: lastFix, hadFix: hadFix, now: now,
                                   keepAwake: keepAwake, running: running, capReached: cap)
        }

        check(message(access: .granted, lastFix: nil) == LocationHealth.noFix, "granted, no fix yet")
        check(message(access: .granted, lastFix: now.addingTimeInterval(-30)) == LocationHealth.keepingAwake,
              "recent fix")
        check(message(access: .granted, lastFix: now.addingTimeInterval(-90)) == LocationHealth.updatesStopped,
              "stopped updates")
        check(message(access: .granted, lastFix: now.addingTimeInterval(-301)) == LocationHealth.noFix,
              "very old fix")
        check(message(access: .granted, lastFix: now, running: false) == LocationHealth.startsWithProxy,
              "not running")
        check(message(access: .granted, lastFix: now, keepAwake: false) == LocationHealth.keepAwakeOff,
              "keep awake off")
        check(message(access: .denied, lastFix: nil) == LocationHealth.permissionOff, "denied")
        check(message(access: .restricted, lastFix: nil) == LocationHealth.permissionOff, "restricted")
        check(message(access: .servicesOff, lastFix: nil) == LocationHealth.permissionOff, "services off")
        check(message(access: .notDetermined, lastFix: nil) == LocationHealth.waitingForPermission,
              "a first prompt is not a settings problem")
        check(message(access: .notDetermined, lastFix: nil, hadFix: true) == LocationHealth.permissionOff,
              "an expired Allow Once needs Settings after a relaunch")
        check(message(access: .notDetermined, lastFix: now.addingTimeInterval(-10), hadFix: true)
                == LocationHealth.permissionOff, "an expired Allow Once needs Settings")
        check(message(access: .granted, lastFix: now, cap: true) == LocationHealth.tooManyRestarts,
              "the retry cap is shown")

        // The permission mapping for the Settings button.
        check(LocationAccess.denied.needsSettings(hadFix: false), "denied needs settings")
        check(LocationAccess.restricted.needsSettings(hadFix: false), "restricted needs settings")
        check(LocationAccess.servicesOff.needsSettings(hadFix: false), "services off needs settings")
        check(!LocationAccess.notDetermined.needsSettings(hadFix: false), "a first prompt needs no settings")
        check(LocationAccess.notDetermined.needsSettings(hadFix: true), "an expired permission needs settings")
        check(!LocationAccess.granted.needsSettings(hadFix: true), "granted needs no settings")

        // The retry cap: 5 restarts in 10 minutes, then no more.
        var budget = LocationRetryBudget()
        check(LocationRetryBudget.maximumRestarts == 5, "five restarts")
        check(LocationRetryBudget.windowSeconds == 600, "ten minute window")
        for i in 0..<5 {
            check(budget.allowRestart(now: Double(i)), "restart \(i) is allowed")
        }
        check(budget.exhausted, "the budget is spent")
        check(!budget.allowRestart(now: 5), "the sixth restart is denied")
        check(!budget.allowRestart(now: 599), "still denied inside the window")
        // The first restart falls out of the window at 600.
        check(budget.allowRestart(now: 600), "one old restart expires")
        check(!budget.allowRestart(now: 600.5), "the budget is spent again")
        budget.reset()
        check(budget.restarts.isEmpty && !budget.exhausted, "reset clears the budget")
        check(budget.allowRestart(now: 700), "a restart after the reset")

        print("Location health tests passed")
    }
}
