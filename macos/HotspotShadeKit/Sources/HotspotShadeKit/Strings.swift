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
    public static let unknownSubtitle = "HotspotShade received a status that it does not understand."

    // An interrupted engine operation. The running flag is a conservative
    // guard, not evidence that a tunnel is on. These texts never claim On,
    // Off, or a source device failure.
    public static let serviceStateUnknownTitle = "Status unknown"
    public static let serviceStateUnknownBody = "The service state is unavailable after an interrupted operation. Inspect routes, devices, and the start record before restarting."
    public static let serviceStateUnknownHint = "HotspotShade cannot tell whether the tunnel is on. Turn on and Turn off stay disabled until the target device is checked."
    // The engine proved that the tunnel is off, but cleanup did not finish.
    public static let cleanupBlockedTitle = "Tunnel cleanup did not finish"
    public static let cleanupBlockedBody = "The tunnel is off, but cleanup did not finish. Inspect routes, devices, and the start record before restarting."
    public static let cleanupBlockedHint = "Turn on stays disabled until the target device is checked."
    public static let sourceStoppedTitle = "The source device stopped answering. New connections fail."
    public static let sourceStoppedHint = "Open HotspotShade on your source device."
    public static let close = "Close", pairingCode = "Pairing code"
    public static let pairingTitle = "Pair your source device", compareCode = "Check that both screens show the same code.", allow = "Tap Allow on the source device.", cancel = "Cancel", happening = "What is happening", settings = "Settings", login = "Launch at login", forget = "Forget this source device", advanced = "Advanced", logs = "Open logs", raw = "Raw state", browser = "Open web page", noLogs = "No activity yet.", engineMissing = "The engine is missing.", loginUnavailable = "Launch at login requires a signed app."
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
    public static let alreadyPaired = "This target device is already paired."
    public static let forgetPending = "Forgetting..."
    // Protocol v1 cannot prove that the source device removed the key. A valid
    // answer shows only that a peer replied. Neither state claims remote
    // deletion, and neither invites the person to assume the key is gone.
    public static let forgetConfirmed = "Could not confirm that the source device removed this pairing. This target device forgot the pairing, but the source device may still trust it."
    public static let forgetNotDelivered = "Could not confirm that the source device removed this pairing. This target device forgot the pairing, but the source device may still trust it."
    public static let trustedBySource = "The source device still knows this target device. Press Pair to continue."
    public static let notTrustedWhileRunning = "The source device forgot this target device. The tunnel keeps running until you turn it off."
    public static let phoneTokenRejected = "The source device changed its token. Open HotspotShade on your source device, then pair again."

    // Engine health and checks.
    public static let staleStatus = "HotspotShade did not answer. This status may be out of date."
    public static let statusUnavailableSubtitle = "HotspotShade did not answer."
    public static let checkNow = "Check now", openApp = "Open HotspotShade", quit = "Quit HotspotShade"
    public static let checkedJustNow = "Checked just now"
    public static func checkedSeconds(_ count: Int) -> String { "Checked \(count) second\(count == 1 ? "" : "s") ago" }
    public static func checkedMinutes(_ count: Int) -> String { "Checked \(count) minute\(count == 1 ? "" : "s") ago" }

    // Notifications.
    public static let notificationsDenied = "Notifications are off. You will not see a message when the tunnel turns off."
    public static let autoStoppedHotspot = "The hotspot turned off, so HotspotShade turned the tunnel off."
    public static let autoStoppedSource = "The source device stopped answering, so HotspotShade turned the tunnel off."
    public static let pairingNeedsAttention = "Check the code on your source device."
    // A stop error with no engine message. The app never sends the bare
    // "Needs attention" heading as a notification body.
    public static let tunnelErrorBody = "The tunnel stopped with an error. Open HotspotShade to see the details."
    public static let notificationTitle = app

    // Link quality.
    public static let slowWiFi = "This connection uses 2.4 GHz Wi-Fi, which is slower and less steady. On your source device, turn off Maximize Compatibility in the Personal Hotspot settings, or use a cable."
    public static let weakWiFi = "The Wi-Fi signal is weak. Move the target device closer to the source device."

    public static let diagnosticsCopied = "The diagnostics report is copied."

    // Protected helper availability. A tunnel start never elevates the
    // bundled engine. These messages explain the real blocker without asking a
    // person to weaken the check.
    public static let helperNotInstalled = HelperRequirement.isLocalPreview
        ? "The protected helper is not installed. Follow the local preview setup instructions, then try again."
        : "The protected helper is not installed. Install the signed HotspotShade helper package, then try again."
    public static let helperNotSigned = HelperRequirement.isLocalPreview
        ? "The protected helper is not signed for this app. Use matching Apple Development preview builds."
        : "The protected helper is not signed for this app. Use a Developer ID build of HotspotShade."
    public static let helperBusy = "Another HotspotShade window is using the tunnel."
    // The block is a root-owned marker that survives a reboot. A restart does
    // not clear it, so the text must not suggest one.
    public static let helperCleanup = "A previous tunnel did not stop cleanly, so HotspotShade stays off to protect this network. Restarting the target device does not clear it. First have an administrator confirm with netstat -rn that no HotspotShade route remains. Only after that check, run the preview coordinator command preview-clear-cleanup-block as root. It checks the routes again and clears the block only when nothing remains."
    // The tunnel never started: the engine stopped before any administrator
    // authorization, so it changed no route. This is not a cleanup block.
    public static func tunnelDidNotStart(_ reason: EngineStartFailureReason?) -> String {
        "The tunnel did not start. " + (reason ?? .exitedWithoutReason).sentence + " No route was changed."
    }
    public static let helperStopped = "The protected helper stopped. Turn the tunnel on again."
    // A lost XPC connection and a start timeout are connection failures, not a
    // missing helper and not a clean stop. Name the failure so the person
    // knows to retry the start.
    public static let helperLost = "Lost the connection to the protected helper. The tunnel may have stopped. Turn the tunnel on again."
    public static let helperFailed = "The protected helper could not start the tunnel."
    public static let helperNotAuthorized = "HotspotShade did not get administrator authorization, so the tunnel did not start."
    public static let helperAuthorizationCancelled = "The administrator authorization was cancelled, so the tunnel did not start."
    // The helper stops an engine whose administrator authorization was not
    // completed within its deadline. That is a stop, not a lost helper and not
    // a route problem.
    public static let helperAuthorizationTimedOut = "The administrator authorization was not completed in time, so the tunnel did not start. Turn the tunnel on again."
    public static let helperAuthorizationBusy = "Another authorization prompt is already open. Finish it, then try again."
    public static let helperRightNotConfigured = "The helper administrator right is not configured. Reinstall HotspotShade or repair the helper install."
    // A start can be refused while an install or upgrade holds the shared
    // transition lock, or when that state cannot be checked. Neither sentence
    // names a path, a lock, or a journal.
    public static let helperStartExclusionBusy = "An install or upgrade is using the tunnel. Try again when it finishes."
    public static let helperStartExclusionUnavailable = "HotspotShade cannot check whether an install or upgrade is in progress. Try again later."
    // The administrator authorization is checked at the tunnel start, not at
    // app launch. These lines cover the two failures at that point.
    public static let helperTunnelNotRunning = "HotspotShade is not running, so the tunnel did not start. Restart HotspotShade and try again."
    public static let helperGrantFailed = "The protected helper could not authorize the tunnel start. Try again."

    // Map one helper failure to a plain sentence. The text never includes a
    // path, a token, or a signing detail.
    public static func helperMessage(_ error: Error) -> String {
        if let failure = error as? HelperEngineDidNotStart {
            return tunnelDidNotStart(failure.reason)
        }
        guard let error = error as? HelperTrustError else { return helperFailed }
        switch error {
        case .missingSigningIdentity, .invalidSigningPolicy, .signatureUnavailable,
             .signatureRejected, .callerRejected:
            return helperNotSigned
        case .notInstalledPath, .pathIsNotCanonical, .executableNotRegularFile,
             .executableNotOwnedByRoot, .executableWritable, .unsafeParentDirectory,
             .unsafeInstallRoot, .launchDaemonPlistMissing, .launchDaemonPlistUnsafe,
             .launchDaemonPlistMismatch, .bundleOutsideApplications, .helperOutsideBundle,
             .bundleNotOwnedByRoot, .bundleWritable, .signedAppMissing, .requiresRoot,
             .aclUnavailable:
            return helperNotInstalled
        case .helperBusy:
            return helperBusy
        case .cleanupBlocked, .engineStopTimedOut, .engineExited, .engineExitUnclean:
            return helperCleanup
        case .notConnected, .helperTimeout, .helperUnavailable:
            return helperLost
        case .cancelled:
            return helperAuthorizationCancelled
        case .authorizationTimedOut:
            return helperAuthorizationTimedOut
        case .notAuthorized:
            return helperNotAuthorized
        case .authorizationBusy:
            return helperAuthorizationBusy
        case .startRightNotConfigured:
            return helperRightNotConfigured
        case .startExclusionBusy:
            return helperStartExclusionBusy
        case .startExclusionUnavailable:
            return helperStartExclusionUnavailable
        case .tunnelNotRunning:
            return helperTunnelNotRunning
        case .grantFailed:
            return helperGrantFailed
        case .handshakeRequired:
            return helperStopped
        default:
            return helperFailed
        }
    }

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
