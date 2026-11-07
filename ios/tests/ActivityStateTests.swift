import Foundation

@main
struct ActivityStateTests {
    static func main() {
        precondition(StopReason.user.message == "You stopped the proxy.")
        precondition(StopReason.hotspotLost.message == "The app lost the hotspot address, so the proxy stopped. Check Personal Hotspot, then tap Start.")
        precondition(StopReason.hotspotChanged.message == "The hotspot link changed, so the proxy stopped. Check Personal Hotspot, then tap Start.")
        precondition(StopReason.hotspotUnsupported.message == "The hotspot address is on an unsupported link, so the proxy stopped. Check Personal Hotspot, then tap Start.")
        precondition(StopReason.failed.message == "The proxy stopped because of an error.")
        precondition(StopReason.locationLost.message == "Location is off, so iOS can pause the app. Open Settings to turn it on.")
        precondition(StopReason.user.rawValue == "user" && StopReason.hotspotLost.rawValue == "hotspotLost")
        precondition(StopReason.hotspotChanged.rawValue == "hotspotChanged" &&
                     StopReason.hotspotUnsupported.rawValue == "hotspotUnsupported")
        precondition(StopReason.hotspotChanged.shortMessage == "The hotspot link changed.")
        precondition(StopReason.hotspotUnsupported.shortMessage == "The hotspot link is not supported.")
        precondition(StopReason.failed.rawValue == "failed" && StopReason.locationLost.rawValue == "locationLost")
        precondition(StopReason.appClosed.rawValue == "appClosed" &&
                     StopReason.appClosed.message == "The app was closed by iOS.")
        precondition(PlainMessage.invalidPort == "The proxy port is not valid. Change it in Settings, Advanced.")
        precondition(PlainMessage.noHotspot == "Turn on Personal Hotspot. Connect the target device, then tap Start.")
        precondition(PlainMessage.portInUse == "Something else on this source device uses the proxy port. Change it in Settings, Advanced.")
        precondition(PlainMessage.startFailed == "The proxy could not start. Try again.")
        precondition(PlainMessage.tokenUnavailable == "The proxy token is not available. Unlock the device and try again.")
        precondition(PlainMessage.tokenRotationReloaded == "The app could not confirm the token change. It reloaded the stored token.")
        precondition(PlainMessage.tokenRotated == "The source token changed. Paired target devices must pair again for the new token. A trusted target can pair again without a prompt.")
        precondition(PlainMessage.tokenRotationRecovered == "The app finished an interrupted token rotation. Target devices with the old token must pair again for the new token.")
        precondition(PlainMessage.tokenRotationAborted == "The app cleared an interrupted token rotation. The saved token did not change.")
        precondition(PlainMessage.tokenReplaced == "The saved source token was replaced. Target devices that were previously paired must pair again.")
        precondition(PlainMessage.tokenRestored == "The saved source token was restored. If it is older than a rotation, devices with the old token can connect again, and devices using the newer token lose access. Check access on each target device.")
        precondition(PlainMessage.tokenRecreated == "The app created a new source token. Target devices that were paired must pair again.")
        precondition(!PlainMessage.tokenRestored.lowercased().contains("keep access"),
                     "a restore does not promise unchanged access")
        precondition(!PlainMessage.tokenRestored.lowercased().contains("does not revoke"),
                     "a restore does not claim that it revokes nothing")
        precondition(PlainMessage.tokenRestored.lowercased().contains("older than a rotation"),
                     "a restore names the older-copy risk")
        precondition(PlainMessage.started == "Proxy started.")
        precondition(PlainMessage.paired == "A target device was added.")
        precondition(PlainMessage.targetRemoved == "A target device was removed.")
        precondition(PlainMessage.forgotten == "Paired target devices forgotten.")
        precondition(ConfirmationText.forgetAllTitle == "Forget all target devices?")
        precondition(ConfirmationText.forgetAllMessage
                      == "Target devices can still connect with their saved token. Forgetting them does not revoke that token. A forgotten target device must be approved to pair again.")
        precondition(ConfirmationText.rotateTokenTitle == "Rotate the source token?")
        precondition(ConfirmationText.rotateTokenMessage
                      == "This creates a new source token. Paired target devices must pair again. A target device that is still trusted can pair again without a prompt. A restore can bring back older credentials.")
        precondition(ConfirmationText.rotateTokenNote
                      == "Target devices that are already paired keep the old token. Pair them again after you rotate the token.")
        precondition(ConfirmationText.replaceInvalidTokenTitle == "Replace the saved source token?")
        precondition(ConfirmationText.replaceInvalidTokenMessage
                      == "This replaces the saved source token and deletes the damaged copy. Target devices that were previously paired must pair again. This cannot be undone.")
        precondition(ConfirmationText.replaceInvalidTokenNote
                      == "This is available only when no valid saved token remains. Stop the proxy before you replace the token.")
        precondition(ConfirmationText.restoreLegacyTokenTitle == "Restore the saved source token?")
        precondition(ConfirmationText.restoreLegacyTokenMessage
                      == "This deletes the damaged keychain item and writes the earlier saved token back. If it is older than a rotation, target devices that still hold the old token can connect again, and devices using the newer token lose access. This can undo a rotation used to revoke access. Continue only if you accept this risk.")
        precondition(ConfirmationText.restoreLegacyTokenNote
                      == "This is available only when the keychain item is damaged and the earlier saved token is still valid. The app cannot tell whether that copy is current; it may be older than a rotation whose cleanup failed. Stop the proxy before restoring, then check access on each target device.")
        precondition(!ConfirmationText.restoreLegacyTokenMessage.lowercased().contains("keep access"),
                     "a restore message does not promise unchanged access")
        precondition(!ConfirmationText.restoreLegacyTokenMessage.lowercased().contains("does not revoke"),
                     "a restore message does not claim that it revokes nothing")
        precondition(ConfirmationText.restoreLegacyTokenMessage.lowercased().contains("older than a rotation"),
                     "a restore message names the older-copy risk")
        precondition(ConfirmationText.restoreLegacyTokenMessage.lowercased().contains("accept this risk"),
                     "a restore message asks for an informed action")
        precondition(ConfirmationText.replaceInvalidTokenMessage.lowercased().contains("must pair again"),
                     "a replacement says paired devices must pair again")
        // A plain message holds no port, address, or code, and no old device name.
        let plain = [StopReason.user.message, StopReason.hotspotLost.message,
                     StopReason.hotspotChanged.message, StopReason.hotspotUnsupported.message,
                     StopReason.failed.message,
                     StopReason.locationLost.message, StopReason.appClosed.message,
                     PlainMessage.invalidPort, PlainMessage.noHotspot, PlainMessage.portInUse,
                     PlainMessage.startFailed, PlainMessage.tokenUnavailable, PlainMessage.tokenRotationReloaded, PlainMessage.tokenRotated, PlainMessage.tokenRotationRecovered, PlainMessage.tokenRotationAborted, PlainMessage.tokenReplaced, PlainMessage.tokenRestored, PlainMessage.tokenRecreated, PlainMessage.started, PlainMessage.paired,
                     PlainMessage.targetRemoved, PlainMessage.forgotten,
                     ConfirmationText.forgetAllTitle, ConfirmationText.forgetAllMessage,
                     ConfirmationText.rotateTokenTitle, ConfirmationText.rotateTokenMessage,
                     ConfirmationText.rotateTokenNote,
                     ConfirmationText.replaceInvalidTokenTitle,
                     ConfirmationText.replaceInvalidTokenMessage,
                     ConfirmationText.replaceInvalidTokenNote,
                     ConfirmationText.restoreLegacyTokenTitle,
                     ConfirmationText.restoreLegacyTokenMessage,
                     ConfirmationText.restoreLegacyTokenNote]
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
        var clipboard = TokenPasteboardOwnership()
        precondition(TokenPasteboardOwnership.expirationSeconds == 120)
        precondition(!clipboard.takeIfUnchanged(currentChangeCount: 1))
        clipboard.record(before: 3, after: 4)
        precondition(clipboard.takeIfUnchanged(currentChangeCount: 4))
        precondition(!clipboard.takeIfUnchanged(currentChangeCount: 4), "a copy is cleared only once")
        clipboard.record(before: 4, after: 5)
        precondition(!clipboard.takeIfUnchanged(currentChangeCount: 6), "another copy stays untouched")
        precondition(!clipboard.takeIfUnchanged(currentChangeCount: 5), "a mismatch clears the record")
        clipboard.record(before: 5, after: 7)
        precondition(!clipboard.takeIfUnchanged(currentChangeCount: 7), "an interleaved write is not claimed")
        clipboard.record(before: 6, after: 7)
        clipboard.forget()
        precondition(!clipboard.takeIfUnchanged(currentChangeCount: 7), "a diagnostics copy stays untouched")
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
