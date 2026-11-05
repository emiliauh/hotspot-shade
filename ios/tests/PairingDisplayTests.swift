import Foundation

@main
struct PairingDisplayTests {
    static func check(_ condition: Bool, _ message: String, line: Int = #line) {
        if !condition {
            print("FAIL line \(line): \(message)")
            exit(1)
        }
    }

    static func display(trusted: Int = 0, sessions: Int = 0, code: Bool = false,
                        ready: Bool = true, age: TimeInterval? = nil) -> PairingDisplay {
        PairingDisplay.state(trustedCount: trusted, authenticatedSessions: sessions,
                             pairingCodePresent: code, listenerReady: ready,
                             lastTrafficAge: age)
    }

    static func main() {
        // The exact texts.
        check(PairingDisplay.recentTrafficSeconds == 60, "the traffic window is 60 s")
        check(PairingDisplay.notPairedText == "Not paired. Open HotspotShade on your target device to pair.",
              "not paired text")
        check(PairingDisplay.pairingText == "Pairing in progress. Check the code on your target device.",
              "pairing text")
        check(PairingDisplay.inUseText == "A target device is using the proxy now.", "in use text")
        check(PairingDisplay.connectedTitle == "Target device connected", "connected title")
        check(PairingDisplay.waitingTitle == "Waiting for your target device.", "waiting title")
        check(PairingDisplay.noTargetDevicesText == "No target devices are paired.", "empty settings text")

        // State one: nothing is paired.
        let idle = display()
        check(idle.activity == .notPaired, "idle state")
        check(idle.summary == PairingDisplay.notPairedText, "idle summary")
        check(idle.usageTitle == PairingDisplay.waitingTitle, "idle usage title")
        check(idle.pairedLine == nil && idle.detail == nil, "idle has no paired line")
        check(idle.settingsText == PairingDisplay.noTargetDevicesText, "idle settings text")

        // State two: a pairing code waits for the person.
        let pairing = display(code: true)
        check(pairing.activity == .pairing, "pairing state")
        check(pairing.summary == PairingDisplay.pairingText, "pairing summary")
        check(pairing.usageTitle == PairingDisplay.waitingTitle, "pairing usage title")
        check(pairing.detail == nil, "pairing has no paired line")
        check(pairing.settingsText == PairingDisplay.pairingText,
              "Settings shows the pairing state, not the empty state: \(pairing.settingsText)")
        check(pairing.settingsSymbol == "link", "pairing Settings symbol")

        // A code without a ready listener is stale. It does not claim a pairing.
        check(display(code: true, ready: false).activity == .notPaired, "stale code is ignored")
        check(display(trusted: 2, code: true, ready: false).activity == .paired, "stale code with trust is paired")

        // State three: one or more target devices are paired.
        let one = display(trusted: 1)
        check(one.activity == .paired, "paired state")
        check(one.summary == "Paired with 1 target device.", "one paired text: \(one.summary)")
        check(one.pairedLine == "Paired with 1 target device.", "one paired line")
        check(one.detail == nil, "summary already holds the paired line")
        check(one.usageTitle == PairingDisplay.waitingTitle, "a paired device is not connected")
        check(one.settingsText == "Paired with 1 target device.", "one settings text")
        check(one.settingsSymbol == "checkmark.seal", "paired Settings symbol")
        let many = display(trusted: 4)
        check(many.summary == "Paired with 4 target devices.", "many paired text")
        check(many.settingsText == "Paired with 4 target devices.", "many settings text")

        // A pairing prompt wins in Settings too, so Settings and Dashboard
        // never show two different states.
        check(display(trusted: 2, code: true).settingsText == PairingDisplay.pairingText,
              "Settings keeps the pairing state with a stored trust")
        check(display(trusted: 2, code: true, ready: false).settingsText == "Paired with 2 target devices.",
              "a stale code does not hide the paired state")
        check(idle.settingsSymbol == "link.badge.plus", "empty Settings symbol")

        // State four: an authenticated session has recent traffic.
        let using = display(trusted: 1, sessions: 1, age: 3)
        check(using.activity == .inUse, "in use state")
        check(using.summary == PairingDisplay.inUseText, "in use summary")
        check(using.usageTitle == PairingDisplay.connectedTitle, "in use usage title")
        check(using.detail == "Paired with 1 target device.", "the paired line stays below")
        check(using.pairedLine == "Paired with 1 target device.", "in use paired line")
        check(using.settingsText == "Paired with 1 target device.", "in-use settings text")
        check(using.settingsSymbol == "checkmark.seal", "in-use Settings symbol")

        // A manual client can use the token without a stored pairing. It is in
        // use, but Settings must not claim that a target device is paired.
        let unpairedUse = display(trusted: 0, sessions: 1, age: 2)
        check(unpairedUse.activity == .inUse, "unpaired client is in use")
        check(unpairedUse.settingsText == PairingDisplay.noTargetDevicesText,
              "an unpaired client does not claim a pairing")
        check(unpairedUse.settingsSymbol == "network", "an unpaired client uses the network mark")
        check(unpairedUse.pairedLine == nil, "an unpaired client has no paired line")

        // The window is 60 seconds, inclusive.
        check(display(sessions: 1, age: 0).activity == .inUse, "age zero")
        check(display(sessions: 1, age: 60).activity == .inUse, "age 60")
        check(display(sessions: 1, age: 60.001).activity == .notPaired, "age past 60 is not in use")
        check(display(trusted: 3, sessions: 1, age: 61).activity == .paired, "age past 60 with trust is paired")
        check(display(trusted: 3, sessions: 1, age: 61).summary == "Paired with 3 target devices.",
              "the paired line returns")
        check(display(sessions: 1, age: nil).activity == .notPaired, "no traffic yet is not in use")
        check(display(trusted: 2, sessions: 1, age: nil).activity == .paired, "no traffic yet with trust")
        check(display(trusted: 1, sessions: 0, age: 2).activity == .paired, "no open session is not in use")
        check(display(sessions: 2, age: -5).activity == .inUse, "a future time still counts as recent")

        // An active session wins over a pending code.
        check(display(trusted: 1, sessions: 1, code: true, age: 1).activity == .inUse,
              "in use wins over a pairing prompt")

        // A silent pair for a known target device: the trusted count does not
        // change, but the target device uses the proxy.
        let beforeSilent = display(trusted: 1)
        let afterSilent = display(trusted: 1, sessions: 1, age: 2)
        check(beforeSilent.trustedCount == afterSilent.trustedCount, "the trusted count stays the same")
        check(beforeSilent.activity == .paired && afterSilent.activity == .inUse, "the silent pair reaches in use")
        check(afterSilent.pairedLine == "Paired with 1 target device.", "no duplicate trust entry")

        // The Dashboard header follows the same state. It never says "On"
        // while the snapshot is stopped.
        let off = DashboardStatus.make(snapshotState: "Stopped", startFailure: nil,
                                       snapshotError: nil, pairing: idle)
        check(off.kind == .off, "off kind")
        check(off.title == "Off", "off title")
        check(off.message == DashboardStatus.offMessage, "off message")

        let starting = DashboardStatus.make(snapshotState: "Starting", startFailure: nil,
                                            snapshotError: nil, pairing: idle)
        check(starting.kind == .starting, "starting kind")
        check(starting.title == "Starting", "starting title")
        check(starting.message == PairingDisplay.notPairedText, "starting message")

        let on = DashboardStatus.make(snapshotState: "Listening", startFailure: nil,
                                      snapshotError: nil, pairing: one)
        check(on.kind == .on, "on kind")
        check(on.title == "On", "on title")
        check(on.message == one.summary, "on message")

        // A running proxy shows the current use. An old error does not replace
        // the state that the person sees now.
        let onWithOldError = DashboardStatus.make(snapshotState: "Listening", startFailure: nil,
                                                  snapshotError: "Something technical", pairing: one)
        check(onWithOldError.message == one.summary, "a running proxy shows the current use")

        // The header and the usage card share one display, so they cannot
        // show two different pairing states.
        let shared = DashboardDisplay(status: on, pairing: one)
        check(shared.status.message == shared.pairing.summary,
              "the two Dashboard cards share one state")

        let pairingStatus = DashboardStatus.make(snapshotState: "Listening", startFailure: nil,
                                                 snapshotError: nil, pairing: pairing)
        check(pairingStatus.kind == .pairing, "pairing kind")
        check(pairingStatus.title == "On", "pairing keeps the proxy title")
        check(pairingStatus.message == PairingDisplay.pairingText, "pairing message")

        let startingPairing = DashboardStatus.make(snapshotState: "Starting", startFailure: nil,
                                                   snapshotError: nil, pairing: pairing)
        check(startingPairing.kind == .pairing, "pairing during start kind")
        check(startingPairing.title == "Starting", "pairing during start title")
        check(startingPairing.message == PairingDisplay.pairingText, "pairing during start message")

        let inUse = DashboardStatus.make(snapshotState: "Listening", startFailure: nil,
                                         snapshotError: nil, pairing: using)
        check(inUse.kind == .on, "in use kind")
        check(inUse.message == PairingDisplay.inUseText, "in use message")

        // A failed state without a message still says what happened.
        let failed = DashboardStatus.make(snapshotState: "Failed", startFailure: nil,
                                          snapshotError: nil, pairing: idle)
        check(failed.kind == .attention, "failed kind")
        check(failed.title == "Needs attention", "failed title")
        check(failed.message == PlainMessage.startFailed, "a failed state always has a reason")

        let failedPort = DashboardStatus.make(snapshotState: "Failed", startFailure: nil,
                                              snapshotError: "The address is in use", pairing: idle)
        check(failedPort.message == PlainMessage.portInUse, "a port conflict uses the plain line")

        let failedPlain = DashboardStatus.make(snapshotState: "Failed", startFailure: nil,
                                               snapshotError: PlainMessage.noHotspot, pairing: idle)
        check(failedPlain.message == PlainMessage.noHotspot, "a known plain line stays")

        // A Start failure wins over an old snapshot error and over the state.
        let startFailure = DashboardStatus.make(snapshotState: "Listening",
                                                startFailure: PlainMessage.noHotspot,
                                                snapshotError: "Something technical", pairing: idle)
        check(startFailure.kind == .attention, "start failure kind")
        check(startFailure.title == "Needs attention", "start failure title")
        check(startFailure.message == PlainMessage.noHotspot, "start failure message")

        // A stop message stays visible while the proxy is off.
        let stopped = DashboardStatus.make(snapshotState: "Stopped", startFailure: nil,
                                           snapshotError: StopReason.user.message, pairing: idle)
        check(stopped.kind == .off, "stopped kind")
        check(stopped.title == "Off", "stopped title")
        check(stopped.message == StopReason.user.message, "stopped message")

        // An unknown state is off, never on.
        let unknown = DashboardStatus.make(snapshotState: "Unknown", startFailure: nil,
                                           snapshotError: nil, pairing: idle)
        check(unknown.kind == .off && unknown.title == "Off", "an unknown state is off")
        check(unknown.message == DashboardStatus.offMessage, "an unknown state keeps the instruction")

        // The error mapping holds no technical text.
        check(DashboardStatus.plainError(nil) == nil, "no error gives no line")
        check(DashboardStatus.plainError("Something technical") == PlainMessage.startFailed,
              "an unknown error gives the general line")
        check(DashboardStatus.plainError(PlainMessage.invalidPort) == PlainMessage.invalidPort,
              "a known plain line passes through")

        // No card text may claim a pairing is ready, or name an old device.
        let oldProduct = ["hotspot", "proxy"].joined(separator: " ")
        let texts = [idle.summary, pairing.summary, one.summary, using.summary,
                     idle.usageTitle, using.usageTitle, using.detail ?? "",
                     idle.settingsText, pairing.settingsText, one.settingsText,
                     using.settingsText, many.settingsText,
                     off.title, off.message, on.title, on.message,
                     pairingStatus.title, pairingStatus.message]
        for text in texts {
            let lower = text.lowercased()
            check(!lower.contains("ready to pair"), "no ready-to-pair text: \(text)")
            check(!lower.contains("laptop") && !lower.contains("computer") && !lower.contains("iphone"),
                  "no old device name: \(text)")
            check(!lower.contains(oldProduct), "no old product name: \(text)")
        }
        // The four state texts are distinct, so a card cannot show two at once.
        let states = [PairingDisplay.notPairedText, PairingDisplay.pairingText,
                      one.summary, PairingDisplay.inUseText]
        check(Set(states).count == 4, "four distinct state texts")

        print("Pairing display tests passed")
    }
}
