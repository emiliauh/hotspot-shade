import Foundation

/// Why the proxy stopped. The raw value is saved, so it survives a relaunch.
enum StopReason: String, CaseIterable {
    case user, hotspotLost, failed, locationLost, appClosed
    var message: String {
        switch self {
        case .user: return "You stopped the proxy."
        case .hotspotLost: return "The app lost the hotspot address, so the proxy stopped. Check Personal Hotspot, then tap Start."
        case .failed: return "The proxy stopped because of an error."
        case .locationLost: return LocationHealth.permissionOff
        case .appClosed: return "The app was closed by iOS."
        }
    }

    /// A short phrase for the last-stop line. It holds no number and no address.
    var shortMessage: String {
        switch self {
        case .user: return "You stopped it."
        case .hotspotLost: return "The hotspot address was lost."
        case .failed: return "The proxy stopped because of an error."
        case .locationLost: return "Location turned off."
        case .appClosed: return "The app was closed by iOS."
        }
    }

    /// The body of the stop notification. It holds no number and no address.
    var notificationBody: String { shortMessage }
}

/// Plain Dashboard messages and activity entries. They hold no address, port, code, or token.
enum PlainMessage {
    static let invalidPort = "The proxy port is not valid. Change it in Settings, Advanced."
    static let noHotspot = "Turn on Personal Hotspot. Connect the target device, then tap Start."
    static let portInUse = "Something else on this source device uses the proxy port. Change it in Settings, Advanced."
    static let startFailed = "The proxy could not start. Try again."
    static let started = "Proxy started."
    /// A new target device paired. The line names no device.
    static let paired = "A target device was added."
    /// A paired target device asked this source device to forget it.
    static let targetRemoved = "A target device was removed."
    static let forgotten = "Paired target devices forgotten."
}

/// The confirmation and note texts for the Settings actions that change trust
/// or credentials. Each text says what stays on the other side.
enum ConfirmationText {
    static let forgetAllTitle = "Forget all target devices?"
    static let forgetAllMessage = "Each target device keeps its copy until it contacts this source device again."
    static let rotateTokenNote = "Target devices that are already paired keep the old token. Pair them again after you rotate the token."
}

enum DisplayState {
    static func label(_ state: String) -> String {
        switch state {
        case "Listening": return "On"
        case "Starting": return "Starting"
        case "Failed": return "Needs attention"
        default: return "Off"
        }
    }
}

enum WakeGap {
    static func message(lastTick: Date?, now: Date) -> String? {
        guard let lastTick = lastTick, now.timeIntervalSince(lastTick) > 60 else { return nil }
        let minutes = max(1, Int(now.timeIntervalSince(lastTick) / 60))
        return "iOS paused the app for \(minutes) \(minutes == 1 ? "minute" : "minutes")"
    }
}

/// The token stays hidden until the user asks for it. It hides again after a
/// short time, so another person cannot read it from the screen.
enum TokenReveal {
    static let seconds: TimeInterval = 30

    /// The time when the token hides again.
    static func deadline(now: Date) -> Date { now.addingTimeInterval(seconds) }

    /// Return true while the token can be visible.
    static func isVisible(until: Date?, now: Date) -> Bool {
        guard let until = until else { return false }
        return now < until
    }
}

/// The proxy port. The phone picks a random port by itself and tells the target
/// device through the pairing channel. The user can choose a port instead.
enum ProxyPort {
    /// The pairing channel uses this port. The proxy must not use it.
    /// Keep this value equal to `PairingProtocol.port`. The logic test does not compile Pairing.swift.
    static let reserved: Set<UInt16> = [18090]
    /// The range for an automatic choice. It stays clear of well-known ports.
    static let automaticRange: ClosedRange<UInt16> = 20000...59999
    static let storageKey = "proxyPort"

    /// A port is valid when it is not privileged and not reserved.
    static func isValid(_ value: UInt16) -> Bool {
        value >= 1024 && !reserved.contains(value)
    }

    /// Parse the text of a custom port. Return nil for anything that is not valid.
    static func parse(_ text: String) -> UInt16? {
        guard let value = UInt16(text.trimmingCharacters(in: .whitespaces)), isValid(value) else { return nil }
        return value
    }

    /// Keep digits only and limit the text to five characters while the user types.
    static func sanitizedText(_ text: String) -> String {
        String(text.filter(\.isNumber).prefix(5))
    }

    static func random<G: RandomNumberGenerator>(using generator: inout G) -> UInt16 {
        while true {
            let value = UInt16.random(in: automaticRange, using: &generator)
            if isValid(value) { return value }
        }
    }

    static func random() -> UInt16 {
        var generator = SystemRandomNumberGenerator()
        return random(using: &generator)
    }

    /// Return the saved port. Choose and save a random port on the first run.
    static func storedOrNew(defaults: UserDefaults = .standard) -> UInt16 {
        if let text = defaults.string(forKey: storageKey), let value = parse(text) { return value }
        let value = random()
        defaults.set(String(value), forKey: storageKey)
        return value
    }
}

// MARK: Last stop

/// The last time the proxy stopped. It stays across launches, so the person can
/// read why the proxy is off after the app was closed.
struct StopRecord: Equatable {
    let reason: StopReason
    let date: Date

    /// The Dashboard line. Pass the time text to keep this free of the locale.
    func line(timeText: String) -> String { "Last stop: \(reason.shortMessage) \(timeText)." }

    /// The Dashboard line with the user's time style.
    func line() -> String { line(timeText: date.formatted(date: .omitted, time: .shortened)) }
}

/// Save and load the last stop. Tests use the in-memory store.
protocol StopRecordStore: AnyObject {
    func save(_ record: StopRecord)
    func load() -> StopRecord?
    func clear()
}

final class MemoryStopRecordStore: StopRecordStore {
    private var record: StopRecord?
    init(_ record: StopRecord? = nil) { self.record = record }
    func save(_ record: StopRecord) { self.record = record }
    func load() -> StopRecord? { record }
    func clear() { record = nil }
}

/// Store the reason and the date in UserDefaults. The two keys hold no secret.
final class UserDefaultsStopRecordStore: StopRecordStore {
    static let reasonKey = "lastStopReason"
    static let dateKey = "lastStopDate"
    private let defaults: UserDefaults

    init(defaults: UserDefaults = .standard) { self.defaults = defaults }

    func save(_ record: StopRecord) {
        defaults.set(record.reason.rawValue, forKey: Self.reasonKey)
        defaults.set(record.date, forKey: Self.dateKey)
    }

    func load() -> StopRecord? {
        guard let raw = defaults.string(forKey: Self.reasonKey),
              let reason = StopReason(rawValue: raw),
              let date = defaults.object(forKey: Self.dateKey) as? Date else { return nil }
        return StopRecord(reason: reason, date: date)
    }

    func clear() {
        defaults.removeObject(forKey: Self.reasonKey)
        defaults.removeObject(forKey: Self.dateKey)
    }
}

/// Record a stop with the clock injected for tests.
struct StopLog {
    let store: StopRecordStore
    let now: () -> Date

    init(store: StopRecordStore, now: @escaping () -> Date = { Date() }) {
        self.store = store
        self.now = now
    }

    @discardableResult
    func record(_ reason: StopReason) -> StopRecord {
        let record = StopRecord(reason: reason, date: now())
        store.save(record)
        return record
    }

    func current() -> StopRecord? { store.load() }
    func clear() { store.clear() }
}

// MARK: Keep-alive

/// The Location permission as the app sees it. It holds no CoreLocation type,
/// so the logic test can compile this file without a device.
enum LocationAccess: Equatable {
    case notDetermined, denied, restricted, granted, servicesOff

    /// The person must change a setting when the permission cannot work.
    /// A first-run prompt is not a settings problem. A permission that expired
    /// after a fix (Allow Once) is one.
    func needsSettings(hadFix: Bool) -> Bool {
        switch self {
        case .denied, .restricted, .servicesOff: return true
        case .notDetermined: return hadFix
        case .granted: return false
        }
    }
}

/// The truth about the keep-alive. It depends on the last location fix only.
enum LocationHealth {
    /// A fix younger than this means the updates flow.
    static let recentSeconds: TimeInterval = 60
    /// A fix older than this is so old that it says nothing about the app now.
    static let stoppedSeconds: TimeInterval = 300

    static let keepingAwake = "The app stays awake while the proxy runs."
    static let updatesStopped = "Location updates stopped. Open HotspotShade to restart."
    static let noFix = "No location yet."
    static let permissionOff = "Location is off, so iOS can pause the app. Open Settings to turn it on."
    static let waitingForPermission = "Allow Location when iOS asks, so the app can stay awake."
    static let keepAwakeOff = "Keep running in the background is off. Turn it on in Settings."
    static let startsWithProxy = "Starts when the proxy starts."
    static let tooManyRestarts = "Location updates keep stopping. Open HotspotShade to restart."

    enum Fix: Equatable { case recent, stopped, none }

    /// Map the age of the last fix to one of three states.
    static func fix(lastFix: Date?, now: Date) -> Fix {
        guard let lastFix = lastFix else { return .none }
        let age = now.timeIntervalSince(lastFix)
        if age < recentSeconds { return .recent }
        if age <= stoppedSeconds { return .stopped }
        return .none
    }

    /// The plain line for the keep-awake card. It must tell the truth: the app
    /// stays awake only while the location updates flow. `hadFix` is true when
    /// the app ever received a fix, also in an earlier run.
    static func message(access: LocationAccess, lastFix: Date?, hadFix: Bool, now: Date,
                        keepAwake: Bool, running: Bool, capReached: Bool) -> String {
        guard keepAwake else { return keepAwakeOff }
        if access.needsSettings(hadFix: hadFix) { return permissionOff }
        if access == .notDetermined { return waitingForPermission }
        guard running else { return startsWithProxy }
        if capReached { return tooManyRestarts }
        switch fix(lastFix: lastFix, now: now) {
        case .recent: return keepingAwake
        case .stopped: return updatesStopped
        case .none: return noFix
        }
    }
}

/// Limit the restarts of the location updates. It stops a tight loop when the
/// location service keeps failing. At most 5 restarts in 10 minutes.
struct LocationRetryBudget: Equatable {
    static let maximumRestarts = 5
    static let windowSeconds: TimeInterval = 600
    private(set) var restarts: [TimeInterval] = []

    /// Return true and record a restart when the budget allows one.
    mutating func allowRestart(now: TimeInterval) -> Bool {
        restarts.removeAll { now - $0 >= Self.windowSeconds }
        guard restarts.count < Self.maximumRestarts else { return false }
        restarts.append(now)
        return true
    }

    var exhausted: Bool { restarts.count >= Self.maximumRestarts }

    mutating func reset() { restarts.removeAll() }
}

// MARK: Notifications

/// The notification permission decision. The app asks once, and only while the
/// status is not determined. A denied status shows a note in Settings.
enum NotificationPermission {
    enum Status: Equatable { case notDetermined, denied, allowed }

    static let stopTitle = "HotspotShade stopped"
    static let deniedNote = "Notifications are off. You will not see a message when the proxy stops."

    /// Ask only while the person has not answered the system prompt.
    static func shouldRequest(_ status: Status) -> Bool { status == .notDetermined }

    /// Show the note and the Settings button only when the person denied it.
    static func needsSettings(_ status: Status) -> Bool { status == .denied }
}
