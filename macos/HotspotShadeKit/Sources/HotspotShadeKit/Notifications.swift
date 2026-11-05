import Foundation

#if canImport(UserNotifications)
import UserNotifications
#endif

#if canImport(AppKit)
import AppKit
#endif

// The notification permission that the app can see.
public enum NotificationAuthorization: String, Equatable {
    case notDetermined, authorized, denied
}

// One message for the user. The title is always the product name.
public struct NotificationMessage: Equatable {
    public enum Kind: String, CaseIterable, Equatable {
        // The engine turned the tunnel off by itself.
        case autoStopped
        // The source device stopped answering while the tunnel runs.
        case sourceStopped
        // Pairing waits for the person.
        case pairingAttention
        // The tunnel ended with an error.
        case tunnelError
    }
    public var kind: Kind
    public var title: String
    public var body: String
    public init(kind: Kind, title: String = Strings.notificationTitle, body: String) {
        self.kind = kind; self.title = title; self.body = body
    }
}

// The real app uses UserNotifications. Tests use a recording sink.
public protocol NotificationSink: AnyObject {
    func authorizationStatus() async -> NotificationAuthorization
    func requestAuthorization() async -> NotificationAuthorization
    func post(_ message: NotificationMessage) async
    func clearDelivered() async
}

// The default sink does nothing. The app injects UserNotificationSink.
public final class NoNotificationSink: NotificationSink {
    public init() {}
    public func authorizationStatus() async -> NotificationAuthorization { .notDetermined }
    public func requestAuthorization() async -> NotificationAuthorization { .notDetermined }
    public func post(_ message: NotificationMessage) async {}
    public func clearDelivered() async {}
}

// Open the notification section of System Settings. Tests inject a recorder.
public protocol SettingsOpening {
    func openNotificationSettings()
}
public struct NoSettingsOpener: SettingsOpening {
    public init() {}
    public func openNotificationSettings() {}
}
#if canImport(AppKit)
public struct WorkspaceSettingsOpener: SettingsOpening {
    public init() {}
    public func openNotificationSettings() {
        guard let url = URL(string: "x-apple.systempreferences:com.apple.Notifications-Settings.extension") else { return }
        NSWorkspace.shared.open(url)
    }
}
#endif

// Everything that the policy needs to make one decision. The values come from
// the model. The policy never reads the clock or the network itself.
public struct NotificationInput: Equatable {
    public var authorization: NotificationAuthorization
    public var isFrontmost: Bool
    public var running: Bool
    public var phone: PhoneState
    // True after the source device failed to answer for 10 seconds.
    public var sourceDeviceWarning: Bool
    // True when pairing shows a code or failed and needs the person.
    public var pairingNeedsAttention: Bool
    // The last stop from the engine. The model sends it only when it changes.
    public var lastStop: LastStop?
    public var lastStopMessage: String?
    // A tunnel error from the model. Used when the engine sends no last stop.
    public var error: String?
    public init(authorization: NotificationAuthorization = .authorized, isFrontmost: Bool = false, running: Bool = false, phone: PhoneState = .unknown, sourceDeviceWarning: Bool = false, pairingNeedsAttention: Bool = false, lastStop: LastStop? = nil, lastStopMessage: String? = nil, error: String? = nil) {
        self.authorization = authorization; self.isFrontmost = isFrontmost; self.running = running; self.phone = phone
        self.sourceDeviceWarning = sourceDeviceWarning; self.pairingNeedsAttention = pairingNeedsAttention
        self.lastStop = lastStop; self.lastStopMessage = lastStopMessage; self.error = error
    }
}

public struct NotificationOutput: Equatable {
    public var messages: [NotificationMessage]
    // True when the delivered warning must be removed because the state is
    // healthy again.
    public var clearDelivered: Bool
    public init(messages: [NotificationMessage] = [], clearDelivered: Bool = false) {
        self.messages = messages; self.clearDelivered = clearDelivered
    }
}

// A pure policy. It debounces each event type for 60 seconds, never notifies
// for a user stop, and never sends a message while the app is frontmost except
// for the automatic stop message.
public struct NotificationPolicy {
    public static let debounce: TimeInterval = 60
    private let now: () -> Date
    private var lastFired: [NotificationMessage.Kind: Date] = [:]
    private var seenLastStop: String?
    // A start or stop error can stay on the screen until the next attempt.
    // Tell the person once, not on every status poll.
    private var seenError: String?
    private var wasUnhealthy = false

    public init(now: @escaping () -> Date = Date.init) { self.now = now }

    // Ask for permission only at the first Start, and only when macOS has not
    // asked yet.
    public static func shouldAskForPermission(status: NotificationAuthorization, asked: Bool) -> Bool {
        !asked && status == .notDetermined
    }

    public mutating func evaluate(_ input: NotificationInput) -> NotificationOutput {
        let date = now()
        var messages: [NotificationMessage] = []
        var clear = false

        // A healthy state removes the delivered warning.
        let unhealthy = input.running && (input.sourceDeviceWarning || [.notResponding, .notRunning, .noHotspot].contains(input.phone))
        if wasUnhealthy && !unhealthy { clear = true }
        wasUnhealthy = unhealthy

        guard input.authorization == .authorized else {
            return NotificationOutput(messages: [], clearDelivered: clear)
        }

        // 1 and 4. A new last stop. A user stop never sends a message.
        if let stop = input.lastStop {
            let key = "\(stop.stableKey)|\(input.lastStopMessage ?? "")"
            if key != seenLastStop {
                seenLastStop = key
                switch stop.kind {
                case .user:
                    break
                case .hotspotLost, .sourceDeviceGone:
                    if canFire(.autoStopped, at: date) {
                        let body = sanitizedMessage(input.lastStopMessage)
                            ?? (stop.kind == .hotspotLost ? Strings.autoStoppedHotspot : Strings.autoStoppedSource)
                        messages.append(NotificationMessage(kind: .autoStopped, body: body))
                        markFired(.autoStopped, at: date)
                    }
                case .error:
                    if !input.isFrontmost, canFire(.tunnelError, at: date) {
                        let body = sanitizedMessage(input.lastStopMessage) ?? input.error.flatMap(sanitizedMessage) ?? Strings.attention
                        messages.append(NotificationMessage(kind: .tunnelError, body: body))
                        markFired(.tunnelError, at: date)
                    }
                case .unknown:
                    break
                }
            }
        } else if let error = input.error.flatMap(sanitizedMessage), error != seenError, !input.running, !input.isFrontmost, canFire(.tunnelError, at: date) {
            // 4. An error without a last stop from an older engine.
            messages.append(NotificationMessage(kind: .tunnelError, body: error))
            markFired(.tunnelError, at: date)
        }
        seenError = input.error.flatMap(sanitizedMessage)

        // 2. The source device stopped answering while the tunnel runs.
        if input.running, input.sourceDeviceWarning, !input.isFrontmost, canFire(.sourceStopped, at: date) {
            messages.append(NotificationMessage(kind: .sourceStopped, body: Strings.sourceStoppedTitle))
            markFired(.sourceStopped, at: date)
        }

        // 3. Pairing waits for the person.
        if input.pairingNeedsAttention, !input.isFrontmost, canFire(.pairingAttention, at: date) {
            messages.append(NotificationMessage(kind: .pairingAttention, body: Strings.pairingNeedsAttention))
            markFired(.pairingAttention, at: date)
        }

        return NotificationOutput(messages: messages, clearDelivered: clear)
    }

    private func canFire(_ kind: NotificationMessage.Kind, at date: Date) -> Bool {
        guard let last = lastFired[kind] else { return true }
        return date.timeIntervalSince(last) >= Self.debounce
    }
    private mutating func markFired(_ kind: NotificationMessage.Kind, at date: Date) { lastFired[kind] = date }
    private func sanitizedMessage(_ text: String?) -> String? {
        guard let value = Strings.sanitized(text), !value.isEmpty else { return nil }
        return value
    }
}

#if canImport(UserNotifications)
// The system sink. This type does not ask for permission in an initializer.
public final class UserNotificationSink: NotificationSink {
    private let center: UNUserNotificationCenter
    public init(center: UNUserNotificationCenter = UNUserNotificationCenter.current()) { self.center = center }

    public func authorizationStatus() async -> NotificationAuthorization {
        await withCheckedContinuation { continuation in
            center.getNotificationSettings { settings in
                continuation.resume(returning: Self.map(settings.authorizationStatus))
            }
        }
    }

    public func requestAuthorization() async -> NotificationAuthorization {
        await withCheckedContinuation { continuation in
            center.requestAuthorization(options: [.alert, .sound]) { granted, _ in
                continuation.resume(returning: granted ? .authorized : .denied)
            }
        }
    }

    public func post(_ message: NotificationMessage) async {
        let content = UNMutableNotificationContent()
        content.title = message.title
        content.body = message.body
        content.sound = .default
        let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            center.add(request) { _ in continuation.resume() }
        }
    }

    public func clearDelivered() async {
        center.removeAllDeliveredNotifications()
    }

    private static func map(_ status: UNAuthorizationStatus) -> NotificationAuthorization {
        switch status {
        case .notDetermined: return .notDetermined
        case .denied: return .denied
        case .authorized, .provisional, .ephemeral: return .authorized
        @unknown default: return .denied
        }
    }
}
#endif
