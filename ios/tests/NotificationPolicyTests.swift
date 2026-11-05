import Foundation

@main
struct NotificationPolicyTests {
    static func check(_ condition: Bool, _ message: String, line: Int = #line) {
        if !condition {
            print("FAIL line \(line): \(message)")
            exit(1)
        }
    }

    static func main() {
        // Ask once, and only while the person has not answered the prompt.
        check(NotificationPermission.shouldRequest(.notDetermined), "ask while not determined")
        check(!NotificationPermission.shouldRequest(.denied), "never ask after a denial")
        check(!NotificationPermission.shouldRequest(.allowed), "never ask after an approval")

        // The note and the Settings button show only after a denial.
        check(NotificationPermission.needsSettings(.denied), "denied needs settings")
        check(!NotificationPermission.needsSettings(.notDetermined), "a prompt needs no settings")
        check(!NotificationPermission.needsSettings(.allowed), "allowed needs no settings")

        // The exact texts.
        check(NotificationPermission.deniedNote
                == "Notifications are off. You will not see a message when the proxy stops.",
              "denied note: \(NotificationPermission.deniedNote)")
        check(NotificationPermission.stopTitle == "HotspotShade stopped",
              "stop title: \(NotificationPermission.stopTitle)")
        check(!NotificationPermission.deniedNote.contains(where: \.isNumber), "the note has no number")
        let oldProduct = ["hotspot", "proxy"].joined(separator: " ")
        check(!NotificationPermission.deniedNote.lowercased().contains(oldProduct), "the note has the new name")
        check(!NotificationPermission.stopTitle.lowercased().contains(oldProduct), "the title has the new name")

        print("Notification policy tests passed")
    }
}
