import Foundation

// Every text that a person can read in the target app. Keep the sentences
// short. Use "source device" and "target device".
public enum Strings {
    public static let app = "HotspotShade"
    public static let turnOn = "Turn on", turnOff = "Turn off", notConnected = "Not connected"
    public static let waiting = "Waiting for your source device", on = "On", stopping = "Turning off", attention = "Needs attention"
    public static let startingEngine = "Starting the engine", startingTunnel = "Starting the tunnel", ready = "Ready"
    public static let paired = "Paired", notPaired = "Not paired"
    public static let notTrustedTitle = "Not trusted"
    public static let pair = "Pair with source device", pairAgain = "Pair again"
    public static let unpairedSubtitle = "Pair with your source device to use it."
    public static let notTrustedSubtitle = "The source device does not know this target device."
    public static let pairing = "Pairing", pairingSubtitle = "Connecting to your source device."
    public static let proxyOffSubtitle = "Start the proxy on your source device."
    public static let readySubtitle = "The source device is ready.", onSubtitle = "The tunnel is on."
    public static let takesAMinute = "This can take a minute."
    public static let notRespondingSubtitle = "Open HotspotShade on your source device and keep it open."
    public static let openSourceDeviceApp = "Open HotspotShade on your source device."
    public static let noHotspotSubtitle = "Connect this target device to the source device hotspot."
    public static let notRunningSubtitle = "Open HotspotShade on your source device."
    public static let unknownTitle = "Status unavailable"
    public static let unknownSubtitle = "The engine sent a status that this app does not know."
    public static let sourceStoppedTitle = "The source device stopped answering. New connections fail."
    public static let sourceStoppedHint = "Open HotspotShade on your source device."
    public static let simulated = "Demo mode. Data is simulated.", restartDemo = "Restart the app to change demo mode.", close = "Close", pairingCode = "Pairing code"
    public static let pairingTitle = "Pair your source device", compareCode = "Check that both screens show the same code.", allow = "Tap Allow on the source device.", cancel = "Cancel", happening = "What is happening", settings = "Settings", login = "Launch at login", forget = "Forget this source device", advanced = "Advanced", logs = "Open logs", raw = "Raw state", browser = "Open web page", demo = "Demo mode", noLogs = "No activity yet.", engineMissing = "The engine is missing.", loginUnavailable = "Launch at login requires a signed app."
    public static let tryAgain = "Try again", stoppingNote = "This can take a minute."
    public static let letPingWork = "Let ping work"
    public static let letPingWorkHint = "Uses an experimental echo relay on the source device. Applies the next time you turn the tunnel on."
    public static let pingOn = "Ping is on.", pingOff = "Ping is off."
    public static let recentFailures = "Recent failures"
    public static let refresh = "Refresh", copyReport = "Copy report"
    public static let loadingFailures = "Loading failures..."
    public static let failuresNotLoaded = "Press Refresh to read failures."
    public static let noFailures = "No failed connections yet."
    public static let failuresUnavailable = "This engine cannot list failures."
    public static let failuresTunnelOff = "Turn the tunnel on to see failures."
    public static let failuresHint = "The data stays on this target device."
    public static let reportCopied = "The report is copied."

    // Forget and pairing.
    public static let forgetBlocked = "Turn off the tunnel to forget this source device."
    public static let turnOffAndForget = "Turn off and forget"
    public static let forgetPending = "Forgetting..."
    public static let forgetConfirmed = "Forgotten. The source device removed this target device."
    public static let forgetNotDelivered = "The source device did not answer. This target device forgot the pairing, but the source device may still trust it."
    public static let trustedBySource = "The source device still knows this target device. Press Pair to continue."
    public static let notTrustedWhileRunning = "The source device forgot this target device. The tunnel keeps running until you turn it off."
    public static let phoneTokenRejected = "The source device changed its token. Open HotspotShade on your source device, then pair again."

    // Engine health and checks.
    public static let staleStatus = "The engine did not answer. This status may be out of date."
    public static let statusUnavailableSubtitle = "The engine did not answer."
    public static let checkNow = "Check now", openApp = "Open HotspotShade", quit = "Quit HotspotShade"
    public static let checkedJustNow = "Checked just now"
    public static func checkedSeconds(_ count: Int) -> String { "Checked \(count) second\(count == 1 ? "" : "s") ago" }
    public static func checkedMinutes(_ count: Int) -> String { "Checked \(count) minute\(count == 1 ? "" : "s") ago" }

    // Notifications.
    public static let notificationsDenied = "Notifications are off. You will not see a message when the tunnel turns off."
    public static let autoStoppedHotspot = "The hotspot turned off, so HotspotShade turned the tunnel off."
    public static let autoStoppedSource = "The source device stopped answering, so HotspotShade turned the tunnel off."
    public static let pairingNeedsAttention = "Check the code on your source device."
    public static let notificationTitle = app

    // Link quality.
    public static let slowWiFi = "This connection uses 2.4 GHz Wi-Fi, which is slower and less steady. On your source device, turn off Maximize Compatibility in the Personal Hotspot settings, or use a cable."
    public static let weakWiFi = "The Wi-Fi signal is weak. Move the target device closer to the source device."

    public static let diagnosticsCopied = "The diagnostics report is copied."

    // The engine can come from an older build. Hide the old product name in
    // every message that this app shows.
    public static func sanitized(_ message: String?) -> String? {
        guard let message, !message.isEmpty else { return nil }
        return message.replacingOccurrences(of: "Hotspot Proxy", with: app, options: [.caseInsensitive])
    }

    // Show a count only when the engine reports one.
    public static func connections(_ count: Int) -> String {
        "The source device reports \(count) active connection\(count == 1 ? "" : "s")."
    }
}
