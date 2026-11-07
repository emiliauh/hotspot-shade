// The destination-privacy modes from docs/SNI_HIDING_PLAN.md section 3. The
// raw values are the shared schema names. Every app and the engine use the
// same five names, so a report cannot drift from another platform.
//
// This file is data and text only. It holds no address, host name, port,
// token, key, or certificate, and it reads no engine or session state. The
// engine reports no privacy field today, so the report states what this build
// can do and never what the service is doing at this moment.
public enum TargetPrivacyMode: String, CaseIterable, Identifiable, Equatable {
    case off
    case shape
    case hide
    case cover
    case terminate

    public var id: String { rawValue }

    // The user-facing name. It matches the plan's mode names.
    public var title: String {
        switch self {
        case .off: return "Off"
        case .shape: return "Shape the TLS handshake"
        case .hide: return "Hide the destination name"
        case .cover: return "Cover with an endpoint you own"
        case .terminate: return "Terminate TLS on this device"
        }
    }

    // Every mode except Off is a choice that a person must make. Off is the
    // behavior that this build applies, not an opt-in.
    public var isOptIn: Bool { self != .off }
}

// What one mode can do in this build. The values name a build capability, not
// a session state. This page reads no tunnel state, so no value means that a
// mode runs right now.
public enum TargetPrivacyAvailability: String, Equatable {
    // The behavior that this build applies when a tunnel runs. It is not a
    // mode that a person turns on. The page does not report whether a tunnel
    // is running.
    case defaultBehavior
    // Proposed, but the engine does not implement the mode in this build.
    case unavailable
    // The schema is reserved, but the mode needs an endpoint the person owns.
    case deferred
    // The project decided not to build the mode.
    case excluded

    // The plain state word. A person must not depend on a color or a symbol.
    // A deferred mode also reads "Unavailable", because the service does not
    // implement it.
    public var label: String {
        switch self {
        case .defaultBehavior: return "Default"
        case .unavailable: return "Unavailable"
        case .deferred: return "Unavailable"
        case .excluded: return "Out of scope"
        }
    }

    // No mode has a backend in this build, so no row offers a control. A
    // future backend must change this value only with a real service field.
    public var isUsable: Bool { false }
}

// One mode row in the capability report.
public struct TargetPrivacyModeRow: Identifiable, Equatable {
    public let mode: TargetPrivacyMode
    public let availability: TargetPrivacyAvailability
    // The plain reason. It repeats no state word, so the row reads as one fact.
    public let detail: String

    public init(mode: TargetPrivacyMode, availability: TargetPrivacyAvailability, detail: String) {
        self.mode = mode
        self.availability = availability
        self.detail = detail
    }

    public var id: String { mode.rawValue }
    public var title: String { mode.title }
    public var stateText: String { availability.label }
    // False for every row in this build. No value allows a control.
    public var canTurnOn: Bool { availability.isUsable }
    public var isOptIn: Bool { mode.isOptIn }

    // The row symbol. The state text always sits next to it. The default row
    // uses a hollow mark, so the symbol does not read as an active indicator.
    public var symbol: String {
        switch mode {
        case .off: return "circle"
        case .shape: return "waveform.path"
        case .hide: return "lock.slash"
        case .cover: return "arrow.triangle.branch"
        case .terminate: return "xmark.shield"
        }
    }
}

// One capability fact from the cross-platform contract in the plan. The value
// is a short answer. The detail says what the build can and cannot do.
public enum TargetPrivacyFact: String, CaseIterable, Identifiable, Equatable {
    case encryptedClientHello
    case serverNameOverride
    case backgroundTunnel

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .encryptedClientHello: return "Encrypted Client Hello (ECH)"
        case .serverNameOverride: return "Server name override"
        case .backgroundTunnel: return "Tunnel lifetime"
        }
    }
}

public struct TargetPrivacyFactRow: Identifiable, Equatable {
    public let fact: TargetPrivacyFact
    public let valueText: String
    public let detail: String

    public init(fact: TargetPrivacyFact, valueText: String, detail: String) {
        self.fact = fact
        self.valueText = valueText
        self.detail = detail
    }

    public var id: String { fact.rawValue }
    public var title: String { fact.title }
}

// The report that the Settings window shows. It is built once from fixed text,
// so a view cannot set a mode or invent a running state. A later engine field
// can replace the rows, but only with real service data.
public struct TargetPrivacyReport: Equatable {
    public let defaultMode: TargetPrivacyMode
    public let modes: [TargetPrivacyModeRow]
    public let facts: [TargetPrivacyFactRow]
    public let intro: String
    public let optInNote: String
    public let limits: [String]
    public let footer: String

    public init(defaultMode: TargetPrivacyMode, modes: [TargetPrivacyModeRow], facts: [TargetPrivacyFactRow], intro: String, optInNote: String, limits: [String], footer: String) {
        self.defaultMode = defaultMode
        self.modes = modes
        self.facts = facts
        self.intro = intro
        self.optInNote = optInNote
        self.limits = limits
        self.footer = footer
    }

    // One row by its mode. A missing row is nil, never a default.
    public func row(_ mode: TargetPrivacyMode) -> TargetPrivacyModeRow? {
        modes.first { $0.mode == mode }
    }

    // The opt-in modes that a person cannot use now. Every opt-in mode is
    // here in this build.
    public var unusableOptInModes: [TargetPrivacyModeRow] {
        modes.filter { $0.isOptIn && !$0.canTurnOn }
    }

    // False in this build. A view must not show a switch when this is false.
    public var hasUsableOptInMode: Bool {
        modes.contains { $0.isOptIn && $0.canTurnOn }
    }

    // True when no row offers a control. The page is a report, not a setting.
    public var isReadOnly: Bool {
        !modes.contains { $0.canTurnOn }
    }

    // Every visible string. Tests use it to check the product words and to
    // check that no destination or credential text reached the page.
    public var allText: [String] {
        [intro, optInNote, footer]
            + modes.flatMap { [$0.title, $0.stateText, $0.detail] }
            + facts.flatMap { [$0.title, $0.valueText, $0.detail] }
            + limits
    }
}

// The capability report for the macOS target app in this build.
//
// The report does not read the engine status. The current engine has no
// destination-privacy field, and a missing field is not proof that a mode ran.
// Off is the built-in behavior, and it applies only while a tunnel runs. This
// page does not claim that the tunnel is running now.
public enum TargetPrivacyCapabilities {
    // The Settings tab label. It is plain text, so the state report and the
    // tab cannot disagree about what the page covers.
    public static let tabTitle = "Privacy"

    public static let current = TargetPrivacyReport(
        defaultMode: .off,
        modes: [
            TargetPrivacyModeRow(
                mode: .off,
                availability: .defaultBehavior,
                detail: "This build normalizes the TTL and sends each inner flow through a normal outer socket when a tunnel runs. It changes no payload byte and does not hide destination names. This page does not report whether a tunnel is running."),
            TargetPrivacyModeRow(
                mode: .shape,
                availability: .unavailable,
                detail: "Proposed, not implemented in this build. It would re-cut the first TLS records on the relay socket and change no byte of the handshake. It would not hide the server name, the destination address, the TLS fingerprint, or the flow size, and it cannot pad the handshake."),
            TargetPrivacyModeRow(
                mode: .hide,
                availability: .unavailable,
                detail: "Unavailable under the current design. A relay cannot add encrypted Client Hello to a handshake that another application owns. The engine copies application bytes, so it cannot apply ECH to relayed TLS. No switch is offered."),
            TargetPrivacyModeRow(
                mode: .cover,
                availability: .deferred,
                detail: "It would need one TLS endpoint that you own. The project keeps no external relay or VPS, so the schema is reserved and this build offers no switch. Naming another service's site stays out of scope."),
            TargetPrivacyModeRow(
                mode: .terminate,
                availability: .excluded,
                detail: "It would need a certificate authority trusted on this target device, break certificate pinning, and add a second TLS session. The project decided not to build it."),
        ],
        facts: [
            TargetPrivacyFactRow(
                fact: .encryptedClientHello,
                valueText: "No",
                detail: "This app has no TLS client that uses encrypted Client Hello, so it cannot add ECH to a flow. An application can use ECH on its own. That is outside this app, and these settings do not turn it on or verify it."),
            TargetPrivacyFactRow(
                fact: .serverNameOverride,
                valueText: "No",
                detail: "The engine has no TLS client in this build. A relay cannot change the server name, because the destination checks the whole handshake transcript."),
            TargetPrivacyFactRow(
                fact: .backgroundTunnel,
                valueText: "Not verified",
                detail: "The engine is designed to run under the protected helper, so closing this window does not stop it. A signed helper install and a live helper launch are not verified in this build."),
        ],
        intro: "This page is a read-only report of what this build can do. It does not read the tunnel state, so no row says that a mode is running. This app has no destination-privacy mode. When a tunnel runs it normalizes the TTL and sends each inner flow through a normal outer socket, and it does not hide destination names.",
        optInNote: "Every mode other than Off is opt-in, and this build implements none of them. There is no switch, because a switch would claim a service that the engine does not provide. The app saves no privacy preference and sends no privacy field to the engine.",
        limits: [
            "This app does not hide destination names. For an application that uses TLS without ECH, a network that inspects the plaintext handshake may see the server name. A network may also see the destination address and network, DNS names, the TLS fingerprint when TLS is used, and the flow size and timing. Some networks do not inspect these values, but this app does not rely on that.",
            "An application can use its own encrypted Client Hello or encrypted DNS. That is the application's choice, not a mode of this app, and these settings do not turn it on or verify it. Metadata such as the destination address, the flow size, and the timing can stay visible even then.",
            "Hide, if it is ever built, would cover only flows carried by a product-owned TLS client, and only destinations that publish an ECH config. Most destinations do not. It would not hide the destination address, the TLS fingerprint, or the flow size.",
            "The current build does not hide operating-system or TCP fingerprints, traffic volume, or timing. These can contribute to tethering detection. The proposed privacy modes have not been shown to defeat it.",
            "The source device relay is not a TLS tunnel, so it adds no second TLS handshake. That is a property of the current design, not of a mode.",
            "Cover needs an endpoint that you own. TLS termination with a local certificate authority is out of scope. This build offers neither.",
        ],
        footer: "No setting on this page turns a mode on or changes the tunnel. The app stores no privacy mode. This page is a report only, and it does not say whether a tunnel is running.")

    // The one report. A view calls this instead of holding its own state.
    public static func report() -> TargetPrivacyReport { current }
}
