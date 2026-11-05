import Foundation

@main
struct ActivityStateTests {
    static func main() {
        precondition(StopReason.user.message == "You stopped the proxy.")
        precondition(StopReason.hotspotLost.message == "The app lost the hotspot address, so the proxy stopped. Check Personal Hotspot, then tap Start.")
        precondition(StopReason.failed.message == "The proxy stopped because of an error.")
        precondition(StopReason.locationLost.message == "Location is off, so iOS can pause the app. Open Settings to turn it on.")
        precondition(StopReason.user.rawValue == "user" && StopReason.hotspotLost.rawValue == "hotspotLost")
        precondition(StopReason.failed.rawValue == "failed" && StopReason.locationLost.rawValue == "locationLost")
        precondition(StopReason.appClosed.rawValue == "appClosed" &&
                     StopReason.appClosed.message == "The app was closed by iOS.")
        precondition(PlainMessage.invalidPort == "The proxy port is not valid. Change it in Settings, Advanced.")
        precondition(PlainMessage.noHotspot == "Turn on Personal Hotspot. Connect the target device, then tap Start.")
        precondition(PlainMessage.portInUse == "Something else on this source device uses the proxy port. Change it in Settings, Advanced.")
        precondition(PlainMessage.startFailed == "The proxy could not start. Try again.")
        precondition(PlainMessage.started == "Proxy started.")
        precondition(PlainMessage.paired == "A target device was added.")
        precondition(PlainMessage.targetRemoved == "A target device was removed.")
        precondition(PlainMessage.forgotten == "Paired target devices forgotten.")
        precondition(ConfirmationText.forgetAllTitle == "Forget all target devices?")
        precondition(ConfirmationText.forgetAllMessage
                      == "Each target device keeps its copy until it contacts this source device again.")
        precondition(ConfirmationText.rotateTokenNote
                      == "Target devices that are already paired keep the old token. Pair them again after you rotate the token.")
        // A plain message holds no port, address, or code, and no old device name.
        let plain = [StopReason.user.message, StopReason.hotspotLost.message, StopReason.failed.message,
                     StopReason.locationLost.message, StopReason.appClosed.message,
                     PlainMessage.invalidPort, PlainMessage.noHotspot, PlainMessage.portInUse,
                     PlainMessage.startFailed, PlainMessage.started, PlainMessage.paired,
                     PlainMessage.targetRemoved, PlainMessage.forgotten,
                     ConfirmationText.forgetAllTitle, ConfirmationText.forgetAllMessage,
                     ConfirmationText.rotateTokenNote]
        for message in plain {
            precondition(!message.contains(where: \.isNumber), "a plain message has no number: \(message)")
            precondition(!message.lowercased().contains("laptop") && !message.lowercased().contains("computer"),
                         "a plain message names no old device: \(message)")
        }
        precondition(DisplayState.label("Listening") == "On")
        precondition(DisplayState.label("Starting") == "Starting")
        precondition(DisplayState.label("Stopped") == "Off")
        precondition(DisplayState.label("Failed") == "Needs attention")
        let now = Date(timeIntervalSince1970: 1000)
        precondition(WakeGap.message(lastTick: nil, now: now) == nil)
        precondition(WakeGap.message(lastTick: now.addingTimeInterval(-60), now: now) == nil)
        precondition(WakeGap.message(lastTick: now.addingTimeInterval(-61), now: now) == "iOS paused the app for 1 minute")
        precondition(WakeGap.message(lastTick: now.addingTimeInterval(-180), now: now) == "iOS paused the app for 3 minutes")
        // The token shows for 30 seconds after the user asks for it.
        precondition(TokenReveal.seconds == 30)
        let reveal = TokenReveal.deadline(now: now)
        precondition(TokenReveal.isVisible(until: nil, now: now) == false, "the token is hidden by default")
        precondition(TokenReveal.isVisible(until: reveal, now: now))
        precondition(TokenReveal.isVisible(until: reveal, now: now.addingTimeInterval(29.9)))
        precondition(!TokenReveal.isVisible(until: reveal, now: now.addingTimeInterval(30)))
        precondition(!TokenReveal.isVisible(until: reveal, now: now.addingTimeInterval(31)))
        // The proxy port: valid range, reserved port, parsing, random choice, saving.
        precondition(ProxyPort.automaticRange == 20000...59999)
        precondition(ProxyPort.reserved == [18090], "the pairing port is reserved")
        precondition(!ProxyPort.automaticRange.contains(18090), "the pairing port is never automatic")
        precondition(ProxyPort.isValid(20000) && ProxyPort.isValid(1024) && ProxyPort.isValid(65535))
        precondition(!ProxyPort.isValid(1023) && !ProxyPort.isValid(0) && !ProxyPort.isValid(18090))
        precondition(ProxyPort.parse(" 20123 ") == 20123)
        precondition(ProxyPort.parse("1024") == 1024 && ProxyPort.parse("65535") == 65535)
        precondition(ProxyPort.parse("18090") == nil && ProxyPort.parse("80") == nil && ProxyPort.parse("abc") == nil)
        precondition(ProxyPort.parse("70000") == nil && ProxyPort.parse("") == nil && ProxyPort.parse("-1") == nil)
        precondition(ProxyPort.sanitizedText("20a123") == "20123")
        precondition(ProxyPort.sanitizedText("20000-59999") == "20000")
        precondition(ProxyPort.sanitizedText("123456") == "12345" && ProxyPort.sanitizedText("  ") == "")
        var generator = SystemRandomNumberGenerator()
        for _ in 0..<2000 {
            let value = ProxyPort.random(using: &generator)
            precondition(ProxyPort.automaticRange.contains(value) && ProxyPort.isValid(value))
        }
        let suite = UserDefaults(suiteName: "hs-proxy-port-test")!
        suite.removePersistentDomain(forName: "hs-proxy-port-test")
        let first = ProxyPort.storedOrNew(defaults: suite)
        precondition(ProxyPort.automaticRange.contains(first), "the first port is automatic")
        precondition(ProxyPort.storedOrNew(defaults: suite) == first, "the port stays the same after the first run")
        suite.set("30000", forKey: ProxyPort.storageKey)
        precondition(ProxyPort.storedOrNew(defaults: suite) == 30000, "a custom port is kept")
        suite.set("18090", forKey: ProxyPort.storageKey)
        let second = ProxyPort.storedOrNew(defaults: suite)
        precondition(second != 18090 && ProxyPort.isValid(second), "a reserved saved port is replaced")
        suite.set("abc", forKey: ProxyPort.storageKey)
        precondition(ProxyPort.isValid(ProxyPort.storedOrNew(defaults: suite)), "an invalid saved port is replaced")
        suite.removePersistentDomain(forName: "hs-proxy-port-test")
        print("Activity state tests passed")
    }
}
