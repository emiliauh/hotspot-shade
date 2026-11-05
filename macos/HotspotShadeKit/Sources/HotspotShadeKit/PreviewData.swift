import Foundation

// One visible state that the previews show. The list covers every state of
// the target app.
public enum PreviewScenario: String, CaseIterable, Equatable {
    case unpaired
    case pairingStart
    case pairingCode
    case notTrusted
    case proxyOff
    case waiting
    case ready
    case starting
    case on
    case onSourceStopped
    case onNotTrusted
    case onLinkAdvice
    case onStale
    case onNotificationsOff
    case turningOff
    case error
    case unknown
    case staleEngine
    case afterForget

    public var previewTitle: String {
        switch self {
        case .unpaired: return "Unpaired"
        case .pairingStart: return "Pairing start"
        case .pairingCode: return "Pairing code"
        case .notTrusted: return "Not trusted"
        case .proxyOff: return "Proxy off"
        case .waiting: return "Waiting for source device"
        case .ready: return "Ready"
        case .starting: return "Starting"
        case .on: return "On"
        case .onSourceStopped: return "On, source device stopped"
        case .onNotTrusted: return "On, not trusted"
        case .onLinkAdvice: return "On, link advice"
        case .onStale: return "On, stale status"
        case .onNotificationsOff: return "On, notifications off"
        case .turningOff: return "Turning off"
        case .error: return "Error"
        case .unknown: return "Unknown"
        case .staleEngine: return "Stale status"
        case .afterForget: return "After forget"
        }
    }
}

// Fake data for the previews and for tests. It needs no engine.
public enum PreviewData {
    public static func model(_ scenario: PreviewScenario) -> ScreenModel {
        ScreenPresentation.build(input(scenario))
    }

    // The screen model inputs for a scenario.
    public static func input(_ scenario: PreviewScenario) -> PresentationInput {
        let ready = DeriveInput(paired: true, phone: .ready)
        switch scenario {
        case .unpaired:
            return PresentationInput(derive: DeriveInput(phone: .unpaired), lastCheckedText: Strings.checkedSeconds(3))
        case .pairingStart:
            return PresentationInput(derive: DeriveInput(phone: .unpaired, pairing: .starting))
        case .pairingCode:
            return PresentationInput(derive: DeriveInput(phone: .unpaired, pairing: .confirming))
        case .notTrusted:
            return PresentationInput(derive: DeriveInput(paired: true, phone: .notTrusted), lastCheckedText: Strings.checkedSeconds(4))
        case .proxyOff:
            return PresentationInput(derive: ready.copy(phone: .proxyOff), lastCheckedText: Strings.checkedSeconds(5))
        case .waiting:
            return PresentationInput(derive: ready.copy(phone: .notRunning), lastCheckedText: Strings.checkedSeconds(6))
        case .ready:
            return PresentationInput(derive: ready, lastCheckedText: Strings.checkedSeconds(2))
        case .starting:
            return PresentationInput(derive: ready.copy(operation: .starting), lastCheckedText: Strings.checkedSeconds(1))
        case .on:
            return onInput(phone: .ready)
        case .onSourceStopped:
            return onInput(phone: .notResponding, warning: true)
        case .onNotTrusted:
            return onInput(phone: .notTrusted)
        case .onLinkAdvice:
            var input = onInput(phone: .ready)
            input.linkAdvice = [Strings.slowWiFi, Strings.weakWiFi]
            return input
        case .onStale:
            var input = onInput(phone: .ready)
            input.derive.freshness = .stale
            input.lastStopLine = "Last stop: The hotspot turned off."
            return input
        case .onNotificationsOff:
            var input = onInput(phone: .ready)
            input.notificationsDenied = true
            return input
        case .turningOff:
            var input = onInput(phone: .ready)
            input.derive.operation = .stopping
            return input
        case .error:
            return PresentationInput(derive: DeriveInput(paired: true, phone: .ready, error: "The source device could not be reached."), lastCheckedText: Strings.checkedSeconds(8))
        case .unknown:
            return PresentationInput(derive: DeriveInput(freshness: .unavailable), lastCheckedText: Strings.checkedSeconds(12))
        case .staleEngine:
            return PresentationInput(derive: ready.copy(freshness: .stale), lastCheckedText: Strings.checkedSeconds(7))
        case .afterForget:
            return PresentationInput(derive: DeriveInput(phone: .unpaired, forget: .confirmed, forgotIntent: true), lastCheckedText: Strings.checkedSeconds(3))
        }
    }

    private static func onInput(phone: PhoneState, warning: Bool = false) -> PresentationInput {
        PresentationInput(
            derive: DeriveInput(running: true, paired: true, phone: phone, sourceDeviceWarning: warning),
            pingLine: Strings.pingOn,
            connectionsLabel: Strings.connections(3),
            lastCheckedText: Strings.checkedSeconds(2)
        )
    }

    // The pairing code for the pairing previews.
    public static func pairingCode(_ scenario: PreviewScenario) -> String? {
        scenario == .pairingCode ? "482931" : nil
    }

    public static func failures() -> Failures {
        Failures(
            since: 1_762_000_000,
            total: 14,
            dropped: 1,
            demo: false,
            groups: [
                FailureGroup(proto: "tcp", family: "ipv4", port: 443, reason: "timed_out", phase: "request", count: 9, name: "example.com", exampleIp: "192.0.2.10"),
                FailureGroup(proto: "udp", family: "ipv4", port: 53, reason: "unreachable", phase: "connect", count: 3, name: "dns.example", exampleIp: "192.0.2.53"),
                FailureGroup(proto: "tcp", family: "ipv6", port: 80, reason: "refused", phase: "greeting", count: 2, name: nil, exampleIp: "2001:db8::20"),
            ]
        )
    }

    public static func failureRows() -> [FailureRow] { FailureFormat.rows(failures()) }
    public static func failureTableRows() -> [FailureTableRow] { FailureTable.rows(from: failureRows()) }

    // One model for the Settings previews. It uses the fake engine client, so
    // it never starts an engine. The refresh fills the visible state.
    @MainActor public static func appModel(paired: Bool = false, running: Bool = false, phoneState: String = "ready") -> AppModel {
        let backend = FakeBackend()
        var status = Status(running: running, paired: paired, phone: Phone(state: phoneState), icmpEnabled: true)
        status.demo = false
        backend.currentStatus = status
        let model = AppModel(backend: backend, pingSetting: PreviewPingSetting(), macOSVersion: "14.5", appVersion: "1.0 (1)")
        Task { await model.refresh() }
        return model
    }
}

// A fixed ping setting for the previews.
public final class PreviewPingSetting: PingSettingStore {
    public var letPingWork: Bool
    public init(_ letPingWork: Bool = true) { self.letPingWork = letPingWork }
}

private extension DeriveInput {
    // A copy with one field changed. The preview rows stay short.
    func copy(phone: PhoneState? = nil, operation: TunnelOperation? = nil, freshness: StatusFreshness? = nil) -> DeriveInput {
        var value = self
        if let phone { value.phone = phone }
        if let operation { value.operation = operation }
        if let freshness { value.freshness = freshness }
        return value
    }
}
