import Foundation

/// The pairing and use status for the Dashboard and Settings. Every text comes
/// from one state, so the two Dashboard cards never disagree. This file uses
/// Foundation only. It holds no code, address, port, or token.
struct PairingDisplay: Equatable {
    /// An authenticated session had traffic in this many seconds.
    static let recentTrafficSeconds: TimeInterval = 60

    /// The one state for both cards.
    enum Activity: Equatable {
        /// No target device is paired.
        case notPaired
        /// A target device is pairing and the person must check the code.
        case pairing
        /// At least one target device is paired. None uses the proxy now.
        case paired
        /// An authenticated session had traffic in the last 60 seconds.
        case inUse
        /// The pairing listener could not bind. No target device can pair now.
        case unavailable
    }

    let activity: Activity
    /// The number of trusted target devices.
    let trustedCount: Int
    /// A short line for a pairing event that just ended, for example an
    /// expired request. Nil means no recent event. It holds no code or device.
    var notice: String? = nil

    static let notPairedText = "Not paired. Open HotspotShade on your target device to pair."
    static let pairingText = "Pairing in progress. Check the code on your target device."
    static let inUseText = "A target device is using the proxy now."
    static let connectedTitle = "Target device connected"
    static let waitingTitle = "Waiting for your target device."
    static let noTargetDevicesText = "No target devices are paired."
    /// The pairing listener could not bind or become ready. Another app can
    /// hold the pairing port, so the line names that local cause only.
    static let pairingUnavailableText = "Pairing is not available. Another app may be using the pairing port. Close it and reopen HotspotShade."

    /// Build the one state from the snapshot values. Count authenticated
    /// sessions only, and only while one had traffic in the last 60 seconds.
    /// A pairing code without a ready listener is stale, so it does not count.
    /// An unavailable listener shows the bind failure unless a session is in
    /// use now, because that use is still real.
    static func state(trustedCount: Int, authenticatedSessions: Int, pairingCodePresent: Bool,
                      listenerReady: Bool, lastTrafficAge: TimeInterval?,
                      listenerUnavailable: Bool = false, notice: String? = nil) -> PairingDisplay {
        let trusted = max(0, trustedCount)
        if authenticatedSessions > 0, let age = lastTrafficAge, age <= recentTrafficSeconds {
            return PairingDisplay(activity: .inUse, trustedCount: trusted, notice: notice)
        }
        if listenerUnavailable {
            return PairingDisplay(activity: .unavailable, trustedCount: trusted, notice: notice)
        }
        if pairingCodePresent && listenerReady {
            return PairingDisplay(activity: .pairing, trustedCount: trusted, notice: notice)
        }
        if trusted > 0 {
            return PairingDisplay(activity: .paired, trustedCount: trusted, notice: notice)
        }
        return PairingDisplay(activity: .notPaired, trustedCount: trusted, notice: notice)
    }

    /// The status card line.
    var summary: String {
        switch activity {
        case .notPaired: return Self.notPairedText
        case .pairing: return Self.pairingText
        case .paired: return pairedText
        case .inUse: return Self.inUseText
        case .unavailable: return Self.pairingUnavailableText
        }
    }

    /// The usage card title. It says connected only while a session has recent
    /// traffic.
    var usageTitle: String { activity == .inUse ? Self.connectedTitle : Self.waitingTitle }

    /// "Paired with 1 target device." or "Paired with N target devices."
    var pairedText: String {
        trustedCount == 1 ? "Paired with 1 target device." : "Paired with \(trustedCount) target devices."
    }

    /// The paired line. It is nil when no target device is paired.
    var pairedLine: String? { trustedCount > 0 ? pairedText : nil }

    /// The Settings line. It shows the pairing prompt while a code waits.
    /// Otherwise it shows the paired count, or the empty state.
    var settingsText: String {
        switch activity {
        case .pairing: return Self.pairingText
        case .notPaired: return Self.noTargetDevicesText
        case .paired, .inUse: return pairedLine ?? Self.noTargetDevicesText
        case .unavailable: return Self.pairingUnavailableText
        }
    }

    /// The Settings symbol. A paired target device uses a seal. A first
    /// pairing uses a link. An unpaired client that uses the token shows the
    /// network mark. An unavailable listener uses the warning mark.
    var settingsSymbol: String {
        switch activity {
        case .notPaired: return "link.badge.plus"
        case .pairing: return "link"
        case .paired: return "checkmark.seal"
        case .inUse: return trustedCount > 0 ? "checkmark.seal" : "network"
        case .unavailable: return "exclamationmark.triangle"
        }
    }

    /// The extra line for the usage card. It is nil when the summary already
    /// holds the paired line.
    var detail: String? {
        guard let line = pairedLine, line != summary else { return nil }
        return line
    }
}

// MARK: Pairing event line

/// The plain lines for a pairing event that just ended. The status line shows
/// one for 60 seconds or until the next pairing event. The lines hold no code,
/// address, or device name.
enum PairingNoticeText {
    static let denied = "The pairing request was denied. Start pairing again on the target device."
    static let expired = "The pairing request expired. Start pairing again on the target device."
    static let lockedOut = "Pairing is paused for 30 seconds after repeated failures."
}

/// One recent pairing event. The app hides it after `visibleSeconds`, so an
/// old result does not look like the current state.
struct PairingNotice: Equatable {
    static let visibleSeconds: TimeInterval = 60

    let message: String
    let at: Date

    /// True while the line is recent. A time before the event still counts, so
    /// a clock adjustment does not flash the old line.
    func isVisible(now: Date) -> Bool {
        now.timeIntervalSince(at) < Self.visibleSeconds
    }
}

/// The one rule for showing the pairing prompt. The listener must be ready,
/// because a code without a ready listener is stale.
enum PairingPromptPolicy {
    static func isVisible(sceneActive: Bool, listenerReady: Bool,
                          promptID: UUID?, answeredID: UUID?) -> Bool {
        guard sceneActive, listenerReady, let promptID else { return false }
        return promptID != answeredID
    }
}

/// The diagnostics state and detail, built from the same status that the
/// Dashboard shows. The detail appears only when the app needs attention. It
/// holds no token and no address.
struct DiagnosticsProxySummary: Equatable {
    let state: String
    let detail: String?

    static func make(status: DashboardStatus) -> DiagnosticsProxySummary {
        DiagnosticsProxySummary(state: status.title,
                                detail: status.kind == .attention ? status.message : nil)
    }
}

/// The plain text for the main listener's recoverable ends. The Dashboard
/// shows it in place of the general start failure. It holds no address, port,
/// or code.
enum ListenerDisplayText {
    static let cancelled = "The proxy listener stopped unexpectedly. Start the proxy again."
    static let waiting = "The proxy listener is waiting for the hotspot."
    static let waitExpired = "The proxy listener stayed waiting for the hotspot. Start the proxy again."
}

/// The one status for the Dashboard header. It uses the same state text as
/// Settings. It never claims that the proxy is on when the snapshot is not
/// running. This file uses Foundation only.
struct DashboardStatus: Equatable {
    /// The status mark and the tone of the header.
    enum Kind: Equatable {
        case off
        case starting
        case on
        case pairing
        case attention
    }

    let kind: Kind
    let title: String
    let message: String

    static let offMessage = "Start the proxy when your target device is connected to your hotspot."

    /// Build the header from the snapshot and the one pairing display. A Start
    /// failure wins over a token storage problem, and both win over the
    /// snapshot error. A failed state without a message shows the general
    /// failure text.
    static func make(snapshotState: String, startFailure: String?, snapshotError: String?,
                     tokenFailure: String? = nil, pairing: PairingDisplay) -> DashboardStatus {
        let attention = startFailure ?? tokenFailure
        let displayState = attention != nil ? "Failed" : snapshotState
        let title = DisplayState.label(displayState)
        let kind: Kind
        switch displayState {
        case "Failed":
            kind = .attention
        case "Starting":
            kind = pairing.activity == .pairing ? .pairing : .starting
        case "Listening":
            kind = pairing.activity == .pairing ? .pairing : .on
        default:
            kind = .off
        }
        let message: String
        if let failure = startFailure {
            message = failure
        } else if let failure = tokenFailure {
            message = failure
        } else if displayState == "Failed" {
            message = plainError(snapshotError) ?? PlainMessage.startFailed
        } else if displayState == "Starting" && snapshotError == ListenerDisplayText.waiting {
            message = ListenerDisplayText.waiting
        } else if displayState == "Listening" || displayState == "Starting" {
            // A running or starting proxy otherwise shows the current use.
            message = pairing.summary
        } else if let error = plainError(snapshotError) {
            message = error
        } else {
            message = offMessage
        }
        return DashboardStatus(kind: kind, title: title, message: message)
    }

    /// Turn a technical error into plain words. A known plain message stays as
    /// it is. The Dashboard shows no port or address.
    static func plainError(_ error: String?) -> String? {
        guard let error = error else { return nil }
        let plain = [
            StopReason.user.message,
            StopReason.hotspotLost.message,
            StopReason.hotspotChanged.message,
            StopReason.hotspotUnsupported.message,
            StopReason.failed.message,
            StopReason.locationLost.message,
            PlainMessage.invalidPort,
            PlainMessage.noHotspot,
            PlainMessage.hotspotUnreadable,
            ListenerDisplayText.cancelled,
            ListenerDisplayText.waiting,
            ListenerDisplayText.waitExpired
        ]
        if plain.contains(error) { return error }
        if error.contains("in use") { return PlainMessage.portInUse }
        return PlainMessage.startFailed
    }
}

/// The Dashboard header and usage state. Build both from one pairing display,
/// so the two Dashboard cards cannot show different states.
struct DashboardDisplay: Equatable {
    let status: DashboardStatus
    let pairing: PairingDisplay
}
