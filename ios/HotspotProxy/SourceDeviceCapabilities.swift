import Foundation

/// The destination-privacy capabilities of the iOS source device app. One row
/// says what this build does now. Another row says what it cannot do and why.
/// A row that is not on has no control, so the screen never suggests that an
/// inactive mechanism works. A row about destination metadata states a limit.
/// It never claims that every destination name is visible, because an
/// application can conceal its own name.
///
/// This file uses Foundation only. The text holds no address, host name,
/// port, token, key, or certificate. The tests inject nothing.
struct SourceCapability: Equatable, Identifiable {
    /// The truth for one mechanism in this build.
    enum State: Equatable {
        /// The mechanism runs now.
        case on
        /// The mechanism does not run and does not apply to this design.
        case notAvailable
        /// The mechanism belongs to later work and is not wired in yet.
        case notIntegrated
        /// iOS can suspend the app, so a sustained relay is not guaranteed.
        case notGuaranteed
        /// The metadata may stay visible to the network. This is a named
        /// limit, not a protection.
        case mayStayVisible
        /// The app does not use the mechanism at all.
        case notUsed

        /// The plain state word. It is never only a color or a symbol.
        var label: String {
            switch self {
            case .on: return "On"
            case .notAvailable: return "Not available"
            case .notIntegrated: return "Not available in this build"
            case .notGuaranteed: return "Not guaranteed"
            case .mayStayVisible: return "May be visible"
            case .notUsed: return "Not used"
            }
        }

        /// True only for a mechanism that runs now. A later screen may use
        /// this to enable a control. No state here is a promise.
        var isOn: Bool { self == .on }
    }

    /// A stable identifier for tests and diagnostics. It holds no user value.
    let id: String
    let title: String
    let state: State
    /// The plain reason. It repeats no state word and claims no future work.
    let detail: String
    /// The SF Symbol for the Settings row. The text carries the state too.
    let symbol: String
}

/// The capabilities of the source device app in this build. The rows are the
/// one source for Settings and for the diagnostics report, so the two cannot
/// disagree.
struct SourceDeviceCapabilities: Equatable {
    /// The stable row identifiers.
    enum Row {
        static let byteRelay = "byte-relay"
        static let destinationNames = "destination-names"
        static let ech = "ech"
        static let serverNameOverride = "server-name-override"
        static let handshakeShaping = "handshake-shaping"
        static let relayLifetime = "relay-lifetime"
        static let tlsTermination = "tls-termination"
    }

    /// The rows in the order that Settings shows them.
    var rows: [SourceCapability]

    /// The Settings footer. It says that no row here has a control.
    static let settingsNote = "No setting on this screen turns a mechanism on. "
        + "These rows report what this build can and cannot do."

    /// The capability set of this iOS source device app. Every value restates
    /// the platform limit in docs/SNI_HIDING_PLAN.md section 2.
    static let iosSource = SourceDeviceCapabilities(rows: [
        SourceCapability(
            id: Row.byteRelay,
            title: "Byte relay",
            state: .on,
            detail: "The app opens the destination connection and copies bytes in both directions. "
                + "It forwards TLS bytes unchanged.",
            symbol: "arrow.left.arrow.right"),
        SourceCapability(
            id: Row.destinationNames,
            title: "Destination names",
            state: .mayStayVisible,
            detail: "The relay itself adds no concealment. "
                + "The carrier can still see the destination address and the traffic shape, "
                + "and it may see the destination name of a TLS connection. "
                + "An application that uses Encrypted Client Hello keeps its own name hidden.",
            symbol: "eye"),
        SourceCapability(
            id: Row.ech,
            title: "Encrypted Client Hello (ECH)",
            state: .notAvailable,
            detail: "The relay opens no TLS session of its own, so it cannot add "
                + "Encrypted Client Hello to a flow. "
                + "An application that supports ECH can still use it on its own.",
            symbol: "lock.slash"),
        SourceCapability(
            id: Row.serverNameOverride,
            title: "Server name override",
            state: .notAvailable,
            detail: "The relay never parses or rewrites TLS, so the app cannot change the server name.",
            symbol: "textformat"),
        SourceCapability(
            id: Row.handshakeShaping,
            title: "Handshake shaping",
            state: .notIntegrated,
            detail: "The relay does not re-frame the TLS handshake in this build. "
                + "There is no control for it.",
            symbol: "waveform.path"),
        SourceCapability(
            id: Row.relayLifetime,
            title: "Relay lifetime",
            state: .notGuaranteed,
            detail: "iOS can suspend the app while it is in the background. "
                + "The app offers a keep-awake option that uses location updates, "
                + "and it has no Network Extension, so a sustained relay in the background "
                + "is not guaranteed. Keep the app open while it relays.",
            symbol: "clock"),
        SourceCapability(
            id: Row.tlsTermination,
            title: "TLS termination",
            state: .notUsed,
            detail: "The app does not end TLS, present a certificate, or read the destination name. "
                + "No certificate is installed on your target device.",
            symbol: "xmark.shield")
    ])

    /// One row by its stable identifier.
    func row(_ id: String) -> SourceCapability? {
        rows.first { $0.id == id }
    }

    /// True only when that mechanism runs now. A missing row is false.
    func isOn(_ id: String) -> Bool {
        row(id)?.state.isOn ?? false
    }

    /// The capability flags. Each one is false in this build. The names follow
    /// the cross-platform contract in the plan.
    var echEnabled: Bool { isOn(Row.ech) }
    var serverNameOverrideEnabled: Bool { isOn(Row.serverNameOverride) }
    /// A relay whose lifetime is not guaranteed is not a background relay.
    var backgroundRelayEnabled: Bool { row(Row.relayLifetime)?.state == .on }
    var handshakeShapingEnabled: Bool { isOn(Row.handshakeShaping) }
    var tlsTerminationEnabled: Bool { isOn(Row.tlsTermination) }

    /// The flags in one report line.
    var flagsLine: String {
        "Capability flags: ECH \(yesNo(echEnabled)). "
            + "Server name override \(yesNo(serverNameOverrideEnabled)). "
            + "Background relay \(yesNo(backgroundRelayEnabled)). "
            + "Handshake shaping \(yesNo(handshakeShapingEnabled)). "
            + "TLS termination \(yesNo(tlsTerminationEnabled))."
    }

    /// One line per mechanism for the diagnostics report. A line repeats the
    /// Settings state word and its reason. It holds no destination value.
    var diagnosticsLines: [String] {
        rows.map { "Source capability - \($0.title): \($0.state.label). \($0.detail)" }
            + [flagsLine]
    }

    private func yesNo(_ value: Bool) -> String { value ? "yes" : "no" }
}
