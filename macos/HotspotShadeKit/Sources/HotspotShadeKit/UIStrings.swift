import Foundation

// Text that only the windows use. The model texts stay in Strings. Use short
// sentences. Use "source device" and "target device".
// The pairing state line in Settings. It follows the screen, not only the
// saved credentials.
public enum SettingsPairingText {
    public static func state(_ screen: Screen, paired: Bool, unavailable: Bool, indeterminate: Bool = false) -> String {
        // An unknown service state cannot support "Paired" or "Not paired".
        if indeterminate { return Strings.serviceStateUnknownTitle }
        if unavailable { return UIStrings.statusUnavailableLine }
        if screen == .notTrusted { return Strings.notTrustedTitle }
        if screen == .unpaired { return Strings.notPaired }
        return paired ? Strings.paired : Strings.notPaired
    }

    public static func symbol(_ screen: Screen, paired: Bool, unavailable: Bool, indeterminate: Bool = false) -> String {
        if indeterminate || unavailable { return "questionmark.circle" }
        if screen == .notTrusted { return "exclamationmark.triangle" }
        return paired ? "checkmark.seal" : "link.badge.plus"
    }
}

public enum UIStrings {
    // Window sections.
    public static let dashboard = "Dashboard"
    public static let activity = "Activity"
    public static let general = "General"
    public static let pairingTab = "Pairing"
    public static let advanced = Strings.advanced

    // Cards.
    public static let sourceDevice = "Source device"
    public static let connection = "Connection"
    public static let needsAttention = Strings.attention
    public static let noConnectionDetails = "No connection details yet."
    public static let noConnectionYet = "No connection yet."
    public static let statusUnavailableLine = "The status is unavailable."
    // The engine cannot prove whether the tunnel is on. The cards must not
    // show Tunnel off or a source device state as if either were measured.
    public static let unknownValue = "Unknown"
    public static let unknownCardHint = "Inspect routes, devices, and the start record before restarting."
    public static let startingApp = "Starting HotspotShade"
    public static let failuresUnavailable = "This app cannot list failures."

    // Card values and details.
    public static let tunnelOn = "Tunnel on"
    public static let tunnelOff = "Tunnel off"
    public static let connectionStarting = "Starting"
    public static let pairToRestoreTrust = "Pair again to restore trust."
    public static let pressPairToContinue = "Press Pair to continue."
    public static let pairingIsSaved = "The pairing is saved."
    public static let lookingForSourceDevice = "The app is looking for the source device."
    public static let checksEverySecond = "The app checks for the source device every second."
    public static let tunnelUsesSourceDevice = "The tunnel uses this source device."
    public static let readTheMessageAbove = "Read the message above."
    public static let checkStatusAgain = "Check the status again."

    // Pairing.
    public static let checkBothScreens = "Check both screens."
    public static let pairWhenReady = "Pair when you are ready."
    public static let waitingForCode = "Waiting for the code."
    public static let pairingStepOpen = "Open HotspotShade on your source device."
    public static let pairingStepCompare = "Check that both screens show the same code."
    public static let pairingStepAllow = "Tap Allow on the source device."
    public static let copyCode = "Copy code"
    public static let codeCopied = "The code is copied."
    public static let pairingCodeLabel = Strings.pairingCode

    // Activity.
    public static let details = "Details"
    public static let detailsHelp = "Show or hide the level and the sequence number."
    public static let refreshActivityHelp = "Refresh the activity."
    public static let refreshing = "Refreshing"
    public static let refreshStatusHelp = "Refresh the status. Command R."
    public static let activityEmpty = Strings.noLogs
    public static let activityUnavailable = "The app cannot read activity now."
    public static let activityError = "HotspotShade could not read activity."
    public static let activityDetailsNote = "Details add the level and the sequence number."

    // Settings.
    public static let notifications = "Notifications"
    public static let notificationsOn = "Notifications are on."
    public static let notificationsNotAsked = "macOS asks for notification permission the first time you turn the tunnel on."
    public static let openSystemSettings = "Open System Settings"
    public static let forgetHint = "Forget removes this pairing from this target device."
    public static let link = "Wi-Fi"
    public static let noLinkAdvice = "No Wi-Fi advice right now."
    public static let loadingActivity = "Loading activity..."
    public static let appDetails = "App details"
    public static let appVersion = "App version"
    public static let macOSVersion = "macOS"
    public static let status = "Status"
    public static let serviceState = "Service state"
    public static let serviceStateUnknown = "unknown"
    public static let serviceStateCleanupBlocked = "cleanup blocked"
    public static let copied = Strings.diagnosticsCopied
    public static let copyDiagnostics = "Copy diagnostics"

    // Failures table.
    public static let countColumn = "Count"
    public static let kindColumn = "Kind"
    public static let targetColumn = "Target"
    public static let stageColumn = "Stage"
    public static let reasonColumn = "Reason"
    public static let failureDetails = "Details"

    // Menu bar.
    public static let notices = "Notices"
    public static let settingsMenu = "Settings..."
    public static let turningOff = "Turning off..."
    public static let turningOffNote = "The app turns the tunnel off before it quits."
    public static let menuStarting = "HotspotShade is starting"
    public static let menuStartingDetail = "The window shows more when the app is ready."
    public static let checking = "Checking..."

    // The administrator authorization is a system prompt at the tunnel start,
    // not at app launch. The dashboard and the Turn on menus say so.
    public static let adminAuthorization = "macOS asks for administrator authorization when you turn on the tunnel."

    // The texts that the tests check for product words. Add a text here when
    // a window shows new text.
    public static let allText: [String] = [
        dashboard, activity, general, pairingTab, advanced,
        sourceDevice, connection, needsAttention, noConnectionDetails, noConnectionYet, statusUnavailableLine,
        unknownValue, unknownCardHint,
        startingApp, failuresUnavailable,
        tunnelOn, tunnelOff, connectionStarting, pairToRestoreTrust, pressPairToContinue,
        pairingIsSaved, lookingForSourceDevice, checksEverySecond, tunnelUsesSourceDevice,
        readTheMessageAbove, checkStatusAgain,
        checkBothScreens, pairWhenReady, waitingForCode, pairingStepOpen, pairingStepCompare,
        pairingStepAllow, copyCode, codeCopied, pairingCodeLabel,
        details, detailsHelp, refreshActivityHelp, refreshing, refreshStatusHelp,
        activityEmpty, activityUnavailable, activityError, activityDetailsNote,
        notifications, notificationsOn, notificationsNotAsked, openSystemSettings, forgetHint,
        link, noLinkAdvice, loadingActivity, appDetails, appVersion, macOSVersion, status, serviceState, serviceStateUnknown, serviceStateCleanupBlocked, copied,
        copyDiagnostics, countColumn, kindColumn, targetColumn, stageColumn, reasonColumn, failureDetails,
        notices, settingsMenu, turningOff, turningOffNote, menuStarting, menuStartingDetail, checking,
        adminAuthorization,
        Strings.pair, Strings.pairAgain, Strings.turnOn, Strings.turnOff, Strings.checkNow,
        Strings.openApp, Strings.quit, Strings.settings, Strings.refresh, Strings.copyReport,
        Strings.recentFailures, Strings.pairingTitle, Strings.compareCode, Strings.allow,
        Strings.cancel, Strings.letPingWork, Strings.login, Strings.forget,
        Strings.turnOffAndForget, Strings.forgetBlocked, Strings.alreadyPaired,
        Strings.tunnelErrorBody,
    ]
}
