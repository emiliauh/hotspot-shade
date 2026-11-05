import SwiftUI
import UIKit
import Security
import Darwin
import CoreLocation
import UserNotifications

@main
struct HotspotProxyApp: App {
    var body: some Scene {
        WindowGroup { ContentView() }
    }
}

/// One plain line in Recent activity. The time is formatted when the sheet
/// shows the line, so the text follows the current locale.
struct ActivityEntry: Identifiable, Equatable {
    let id = UUID()
    let time: Date
    let message: String

    var timeText: String { time.formatted(date: .omitted, time: .shortened) }
}

/// The copy action that shows a short confirmation.
enum CopyTarget: Equatable {
    case token
    case diagnostics
}

final class ProxyModel: NSObject, ObservableObject, CLLocationManagerDelegate {
    @Published var snapshot = ProxyServer.Snapshot()
    /// The proxy port. The phone picks it and tells the target device when they pair.
    @Published var port = String(ProxyPort.storedOrNew())
    @Published var portIsCustom = UserDefaults.standard.bool(forKey: "proxyPortCustom")
    @Published var token: String
    @Published var addresses = "Unavailable"
    /// Keep-alive is on by default. The choice is saved.
    @Published var backgroundLocation = UserDefaults.standard.object(forKey: "keepAwake") as? Bool ?? true
    @Published var pairedLaptops = 0
    /// The prompt that the user already answered. The alert does not show it again.
    @Published var answeredPairingID: UUID?
    @Published var activity: [ActivityEntry] = []
    @Published var offerRestart = UserDefaults.standard.bool(forKey: "wasListening")
    /// The last copy action. The confirmation hides after a short time.
    @Published private(set) var copied: CopyTarget?
    /// The last Start failure. A later snapshot update does not clear it.
    @Published private(set) var startFailure: String?
    /// True while the user can see the token. It hides again after 30 seconds.
    @Published private(set) var tokenVisible = false
    /// The time used to age the display. A timer refreshes it while the proxy runs.
    @Published private(set) var displayNow = Date()
    /// The Location access as the app sees it.
    @Published private(set) var locationAccess: LocationAccess = .notDetermined
    /// The time of the last location fix. It is nil before the first fix.
    @Published private(set) var lastFix: Date?
    /// True when the location restarts hit the cap.
    @Published private(set) var locationCapReached = false
    /// One plain line with the last stop. It stays across launches.
    @Published private(set) var lastStopLine: String?
    /// The notification permission. The app asks once and never again.
    @Published private(set) var notificationStatus: NotificationPermission.Status = .notDetermined
    private var tokenRevealUntil: Date?
    private var tokenRevealTimer: Timer?
    private var copyTimer: Timer?
    private var wakeTimer: Timer?
    /// The last awake time. It stays in memory and is saved at most once a minute.
    private var wakeTick = Date()
    private var lastWakePersist = Date.distantPast
    private var notifiedCode: String?
    private let locationManager = CLLocationManager()
    private var locationRunning = false
    private var locationServicesEnabled = true
    private var locationRetry = LocationRetryBudget()
    private var locationRestartTimer: Timer?
    /// True after a fix in this run. It tells a lost permission from a first prompt.
    private var hadLocationThisRun = false
    /// True after any fix, also across launches. It detects an Allow Once permission.
    private var hadFixEver = UserDefaults.standard.bool(forKey: "hadLocationFix")
    private var proxyRequested = false
    private var sceneIsActive = true
    private var notificationRequestStarted = false
    private var hotspotAddress: String?
    private var hotspotTimer: DispatchSourceTimer?
    private var lossDetector: HotspotLossDetector?
    private let trust: ObservableTrustStore
    private let server: ProxyServer
    private let stopLog: StopLog
    private let tokenKey = "proxyToken"
    private let notificationAskedKey = "notificationAsked"
    /// The last trust revision that the app recorded as activity.
    private var trustRevision = 0

    override init() {
        // The trust list holds target device public keys only. The wrapper
        // reports every change, including a remote FORGET.
        let store = ObservableTrustStore(UserDefaultsTrustStore())
        trust = store
        server = ProxyServer(trust: store)
        stopLog = StopLog(store: UserDefaultsStopRecordStore())
        if let stored = UserDefaults.standard.string(forKey: "proxyToken"), !stored.isEmpty {
            token = stored
        } else {
            let newToken = Self.newToken()
            token = newToken
            UserDefaults.standard.set(newToken, forKey: "proxyToken")
        }
        super.init()
        locationManager.delegate = self
        locationManager.desiredAccuracy = kCLLocationAccuracyNearestTenMeters
        locationManager.distanceFilter = kCLDistanceFilterNone
        locationManager.activityType = .other
        locationManager.pausesLocationUpdatesAutomatically = false
        locationManager.showsBackgroundLocationIndicator = true
        server.onChange = { [weak self] snapshot in
            guard let self = self else { return }
            let previous = self.snapshot.state
            let previousPairingFailures = self.snapshot.pairingFailureCount
            let previousCapacityWarning = self.snapshot.capacityWarning
            self.snapshot = snapshot
            self.displayNow = Date()
            if snapshot.state == "Starting" || snapshot.state == "Listening",
               let warning = snapshot.capacityWarning, warning != previousCapacityWarning {
                self.recordActivity(warning)
            }
            if snapshot.state == "Listening" || snapshot.state == "Starting" { self.startFailure = nil }
            if snapshot.pairingFailureCount > previousPairingFailures { self.recordActivity(PairingListenerPolicy.failureMessage) }
            if snapshot.state == "Listening" {
                if previous != "Listening" { self.recordActivity(PlainMessage.started) }
                UserDefaults.standard.set(true, forKey: "wasListening")
                self.offerRestart = false
                self.startWakeTimer()
            } else if previous == "Listening" || snapshot.state == "Failed" {
                UserDefaults.standard.set(false, forKey: "wasListening")
                self.wakeTimer?.invalidate()
                self.wakeTimer = nil
                if snapshot.state == "Failed" {
                    self.proxyRequested = false
                    self.stopHotspotWatch()
                    self.stopLocation()
                    if previous != "Failed" {
                        self.recordActivity(StopReason.failed.message)
                        self.recordStop(.failed)
                        self.notifyStopped(.failed)
                    }
                }
            }
            if let code = snapshot.pairingCode, !self.sceneIsActive, self.notifiedCode != code {
                self.notifiedCode = code
                self.notifyPairing()
            }
            if snapshot.pairingCode == nil { self.notifiedCode = nil }
            // The snapshot carries the trusted count on every change, so a
            // remote FORGET updates the Dashboard and Settings at once.
            self.pairedLaptops = snapshot.trustedCount
            if snapshot.trustRevision != self.trustRevision {
                self.trustRevision = snapshot.trustRevision
                if let change = snapshot.lastTrustChange { self.recordActivity(change.activity) }
            }
            if snapshot.pairingPromptID == nil { self.answeredPairingID = nil }
            UIApplication.shared.isIdleTimerDisabled = snapshot.state == "Starting" || snapshot.state == "Listening"
            self.updateLocation()
        }
        pairedLaptops = trust.count
        // A run that did not stop by itself was closed by iOS. Record it once.
        if UserDefaults.standard.bool(forKey: "wasListening") {
            stopLog.record(.appClosed)
            UserDefaults.standard.set(false, forKey: "wasListening")
        }
        lastStopLine = stopLog.current().map { $0.line() }
        syncPairingCredentials()
        refreshAddresses()
        refreshLocationServices()
        updateLocation()
        refreshNotificationSettings()
        // Show the startup capacity before the first Start.
        server.publishCurrentState()
    }

    private static func newToken() -> String {
        var bytes = [UInt8](repeating: 0, count: 16)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            fatalError("Cannot generate a secure proxy token.")
        }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    private func syncPairingCredentials() {
        let saved = UserDefaults.standard.string(forKey: ProxyPort.storageKey).flatMap(ProxyPort.parse) ?? ProxyPort.storedOrNew()
        server.configurePairing(port: saved, token: token)
    }

    /// Choose the port automatically or let the user set it. Not while the proxy runs.
    func setPortAutomatic(_ automatic: Bool) {
        guard snapshot.state != "Listening", snapshot.state != "Starting" else { return }
        portIsCustom = !automatic
        UserDefaults.standard.set(portIsCustom, forKey: "proxyPortCustom")
        if automatic {
            UserDefaults.standard.removeObject(forKey: ProxyPort.storageKey)
            port = String(ProxyPort.storedOrNew())
        }
        syncPairingCredentials()
    }

    /// Save a custom port when the text is valid. The text can be incomplete while typing.
    func setCustomPort(_ text: String) {
        guard snapshot.state != "Listening", snapshot.state != "Starting" else { return }
        let digits = ProxyPort.sanitizedText(text)
        port = digits
        if let value = ProxyPort.parse(digits) { UserDefaults.standard.set(String(value), forKey: ProxyPort.storageKey); syncPairingCredentials() }
    }

    func rotateToken() {
        guard snapshot.state != "Listening", snapshot.state != "Starting" else { return }
        token = Self.newToken()
        UserDefaults.standard.set(token, forKey: tokenKey)
        syncPairingCredentials()
        hideToken()
    }

    /// Show or hide the token. The token hides by itself after 30 seconds.
    func toggleTokenReveal() {
        if tokenVisible {
            hideToken()
        } else {
            tokenRevealUntil = TokenReveal.deadline(now: Date())
            tokenVisible = true
            tokenRevealTimer?.invalidate()
            tokenRevealTimer = Timer.scheduledTimer(withTimeInterval: TokenReveal.seconds, repeats: false) { [weak self] _ in
                self?.refreshTokenVisibility()
            }
        }
    }

    private func refreshTokenVisibility() {
        guard TokenReveal.isVisible(until: tokenRevealUntil, now: Date()) else {
            hideToken()
            return
        }
        tokenVisible = true
    }

    private func hideToken() {
        tokenRevealTimer?.invalidate()
        tokenRevealTimer = nil
        tokenRevealUntil = nil
        tokenVisible = false
    }

    func start() {
        // The user tries again. An old start failure no longer applies.
        startFailure = nil
        // Ask for location permission on the first Start. Keep-alive needs it.
        requestLocationPermissionIfNeeded()
        // Ask for notification permission at the first Start only.
        requestNotificationPermissionIfNeeded()
        guard let value = ProxyPort.parse(port) else {
            failStart(PlainMessage.invalidPort)
            return
        }
        refreshAddresses()
        guard let address = hotspotAddress else {
            failStart(PlainMessage.noHotspot)
            return
        }
        // The user starts again. The last stop no longer applies.
        stopLog.clear()
        lastStopLine = nil
        hadLocationThisRun = false
        locationCapReached = false
        proxyRequested = true
        updateLocation()
        server.start(port: value, token: token, hotspotAddress: address)
        startHotspotWatch(boundAddress: address)
    }

    /// One exit for a Start that cannot run. The message is plain and holds no port or address.
    /// It stays in `startFailure` because a later snapshot replaces `snapshot.error`.
    private func failStart(_ message: String) {
        proxyRequested = false
        startFailure = message
        wakeTimer?.invalidate()
        wakeTimer = nil
        stopHotspotWatch()
        snapshot.state = "Failed"
        snapshot.error = message
        UserDefaults.standard.set(false, forKey: "wasListening")
        offerRestart = false
        UIApplication.shared.isIdleTimerDisabled = false
        updateLocation()
        recordActivity(message)
    }

    /// Show the pairing prompt only while the app is active and the user has not answered.
    var pairingPrompt: PairingPrompt? {
        guard sceneIsActive, let code = snapshot.pairingCode, let id = snapshot.pairingPromptID,
              id != answeredPairingID else { return nil }
        return PairingPrompt(id: id, code: code)
    }

    func decidePairing(prompt: PairingPrompt, allow: Bool) {
        answeredPairingID = prompt.id
        server.decidePairing(promptID: prompt.id, allow: allow)
    }

    /// Forget every paired target device. The trust wrapper publishes the
    /// change, and the app records the plain activity line once.
    func forgetPairedLaptops() {
        trust.removeAll()
    }

    // MARK: Diagnostics

    /// The diagnostics text for the pasteboard. It holds counts, states, and
    /// versions. It holds no address, host, port, token, code, or website.
    func diagnosticsText() -> String {
        var report = snapshot.diagnostics
        report.proxyState = DisplayState.label(snapshot.state)
        report.lowPowerMode = ProcessInfo.processInfo.isLowPowerModeEnabled
        report.thermal = Self.thermalLevel(ProcessInfo.processInfo.thermalState)
        report.locationHealth = keepAwakeMessage
        report.appVersion = Self.appVersion
        report.systemVersion = UIDevice.current.systemVersion
        // The copy can happen after the snapshot. Recompute the bucket ages,
        // so the report does not show the age at the last publish.
        report.refreshEstablishedRows(now: ProcessInfo.processInfo.systemUptime)
        var text = report.text()
        #if DEBUG
        if let note = HotspotInterface.testOverrideNote() { text += "\n" + note }
        #endif
        return text
    }

    func copyDiagnostics() {
        UIPasteboard.general.string = diagnosticsText()
        showCopied(.diagnostics, announcement: "The diagnostics report is copied.")
    }

    /// Copy the token only when the person can see it. The confirmation holds
    /// no token.
    func copyToken() {
        guard tokenVisible else { return }
        UIPasteboard.general.string = token
        showCopied(.token, announcement: "The token is copied.")
    }

    /// Show the confirmation for two seconds. VoiceOver hears the result at
    /// once, so the person does not have to find the new line.
    private func showCopied(_ target: CopyTarget, announcement: String) {
        copied = target
        copyTimer?.invalidate()
        copyTimer = Timer.scheduledTimer(withTimeInterval: 2, repeats: false) { [weak self] _ in
            self?.copied = nil
        }
        UIAccessibility.post(notification: .announcement, argument: announcement)
    }

    /// Clear a copy confirmation when the app leaves the foreground. A
    /// suspended app can show an old confirmation after it returns.
    private func clearCopied() {
        copyTimer?.invalidate()
        copyTimer = nil
        copied = nil
    }

    private static func thermalLevel(_ state: ProcessInfo.ThermalState) -> ThermalLevel {
        switch state {
        case .nominal: return .nominal
        case .fair: return .fair
        case .serious: return .serious
        case .critical: return .critical
        @unknown default: return .nominal
        }
    }

    /// The app version and build, for the diagnostics header.
    private static var appVersion: String { AppVersion.text }

    func stop() {
        proxyRequested = false
        recordActivity(StopReason.user.message)
        recordStop(.user)
        stopLocation()
        updateLocation()
        stopHotspotWatch()
        server.stop()
    }

    func setBackgroundLocation(_ enabled: Bool) {
        backgroundLocation = enabled
        UserDefaults.standard.set(enabled, forKey: "keepAwake")
        requestLocationPermissionIfNeeded()
        updateLocation()
    }

    /// Ask for the Location permission once. Keep-alive needs it.
    private func requestLocationPermissionIfNeeded() {
        guard backgroundLocation, locationManager.authorizationStatus == .notDetermined else { return }
        locationManager.requestWhenInUseAuthorization()
    }

    func sceneChanged(_ phase: ScenePhase) {
        // A suspended interval cannot prove that the address stayed absent.
        lossDetector?.reset()
        sceneIsActive = phase == .active
        displayNow = Date()
        // Do not keep the token on screen while the app is not active.
        if !sceneIsActive {
            hideToken()
            clearCopied()
        }
        server.setSceneActive(sceneIsActive)
        if !sceneIsActive, let code = snapshot.pairingCode, notifiedCode != code {
            notifiedCode = code
            notifyPairing()
        }
        if sceneIsActive {
            checkHotspot()
            refreshNotificationSettings()
            refreshLocationServices()
            if proxyRequested, let last = UserDefaults.standard.object(forKey: "wakeTick") as? Date,
               let message = WakeGap.message(lastTick: last, now: Date()) { recordActivity(message) }
        }
        // Save the awake time when the scene changes. It shows a pause while the proxy ran.
        if proxyRequested {
            wakeTick = Date()
            persistWakeTick(force: true)
        }
        updateLocation()
    }

    // MARK: Pairing and use display

    /// The one display state for the Dashboard and Settings. Both cards read it.
    var pairingDisplay: PairingDisplay {
        let age = snapshot.lastAuthenticatedTraffic.map { Date().timeIntervalSince($0) }
        return PairingDisplay.state(trustedCount: pairedLaptops,
                                    authenticatedSessions: snapshot.authenticatedSessions,
                                    pairingCodePresent: snapshot.pairingCode != nil,
                                    listenerReady: snapshot.pairingReady,
                                    lastTrafficAge: age)
    }

    /// The one Dashboard state. The header and the usage card share one
    /// pairing display, so they cannot show different states.
    var dashboardDisplay: DashboardDisplay {
        let pairing = pairingDisplay
        return DashboardDisplay(status: DashboardStatus.make(snapshotState: snapshot.state,
                                                             startFailure: startFailure,
                                                             snapshotError: snapshot.error,
                                                             pairing: pairing),
                                pairing: pairing)
    }

    /// The connection lines in their fixed order. The first line is the summary.
    var connectionLines: [String] {
        [snapshot.connections, snapshot.connectionCancellations,
         snapshot.connectionKinds, snapshot.connectionReasons].compactMap { $0 }
    }

    // MARK: Location

    func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        refreshLocationServices()
        updateLocation()
    }

    func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        // Discard the location data. The app does not use it.
        guard !locations.isEmpty else { return }
        lastFix = Date()
        locationCapReached = false
        displayNow = Date()
        if !hadFixEver {
            hadFixEver = true
            UserDefaults.standard.set(true, forKey: "hadLocationFix")
        }
        if proxyRequested && locationRunning { hadLocationThisRun = true }
    }

    func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {
        if (error as? CLError)?.code == .denied {
            stopLocation()
            refreshLocationServices()
            updateLocation()
        } else {
            // Keep the background mode, so the restart can run in the background.
            stopLocation(keepBackgroundMode: true)
            scheduleLocationRestart()
        }
    }

    /// iOS paused the updates to save power. Ask for them again.
    func locationManagerDidPauseLocationUpdates(_ manager: CLLocationManager) {
        stopLocation(keepBackgroundMode: true)
        scheduleLocationRestart()
    }

    /// Restart the updates after a failure. At most 5 restarts in 10 minutes.
    private func scheduleLocationRestart() {
        guard backgroundLocation, proxyRequested, snapshot.state != "Failed" else { return }
        guard locationRetry.allowRestart(now: Date().timeIntervalSinceReferenceDate) else {
            locationCapReached = true
            return
        }
        locationRestartTimer?.invalidate()
        locationRestartTimer = Timer.scheduledTimer(withTimeInterval: 2, repeats: false) { [weak self] _ in
            guard let self = self else { return }
            self.locationRestartTimer = nil
            self.updateLocation()
        }
    }

    private func stopLocation(keepBackgroundMode: Bool = false) {
        locationRestartTimer?.invalidate()
        locationRestartTimer = nil
        locationManager.stopUpdatingLocation()
        if !keepBackgroundMode { locationManager.allowsBackgroundLocationUpdates = false }
        locationRunning = false
    }

    private var currentLocationAccess: LocationAccess {
        guard locationServicesEnabled else { return .servicesOff }
        switch locationManager.authorizationStatus {
        case .notDetermined: return .notDetermined
        case .denied: return .denied
        case .restricted: return .restricted
        case .authorizedWhenInUse, .authorizedAlways: return .granted
        @unknown default: return .denied
        }
    }

    /// Read the Location Services switch off the main thread. The call can block.
    private func refreshLocationServices() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let enabled = CLLocationManager.locationServicesEnabled()
            DispatchQueue.main.async {
                guard let self = self, self.locationServicesEnabled != enabled else { return }
                self.locationServicesEnabled = enabled
                self.updateLocation()
            }
        }
    }

    private func updateLocation() {
        locationAccess = currentLocationAccess
        guard backgroundLocation else {
            stopLocation()
            return
        }
        if locationAccess.needsSettings(hadFix: hadFixEver) {
            stopLocation()
            // A permission that was granted and then lost stops the proxy. iOS
            // can pause the app, so the proxy would die without a message.
            if proxyRequested, hadLocationThisRun, snapshot.state == "Listening" || snapshot.state == "Starting" {
                stopForLocationLost()
            }
            return
        }
        guard locationAccess == .granted else {
            stopLocation()
            return
        }
        guard proxyRequested && snapshot.state != "Failed" else {
            stopLocation()
            return
        }
        // Apple requires the background mode to be set from the foreground.
        // Start the updates from the foreground too, or restart them if the
        // background mode is already on.
        if !locationRunning {
            if sceneIsActive {
                locationManager.allowsBackgroundLocationUpdates = true
            } else if !locationManager.allowsBackgroundLocationUpdates {
                return
            }
            locationManager.startUpdatingLocation()
            locationRunning = true
        }
    }

    private var proxyRunning: Bool { snapshot.state == "Listening" || snapshot.state == "Starting" }

    var keepAwakeMessage: String {
        LocationHealth.message(access: locationAccess, lastFix: lastFix, hadFix: hadFixEver,
                               now: displayNow, keepAwake: backgroundLocation, running: proxyRunning,
                               capReached: locationCapReached)
    }

    /// True when the person must turn Location on in Settings.
    var locationNeedsSettings: Bool { backgroundLocation && locationAccess.needsSettings(hadFix: hadFixEver) }

    func openLocationSettings() { openSettings() }
    func openNotificationSettings() { openSettings() }

    private func openSettings() {
        guard let url = URL(string: UIApplication.openSettingsURLString) else { return }
        UIApplication.shared.open(url)
    }

    // MARK: Notifications

    /// Ask for notification permission at the first Start, only while the
    /// status is not determined. Never ask again after the person answered.
    private func requestNotificationPermissionIfNeeded() {
        guard !notificationRequestStarted, !UserDefaults.standard.bool(forKey: notificationAskedKey) else { return }
        notificationRequestStarted = true
        let center = UNUserNotificationCenter.current()
        center.getNotificationSettings { [weak self] settings in
            DispatchQueue.main.async {
                guard let self = self else { return }
                let status = Self.notificationStatus(settings.authorizationStatus)
                self.notificationStatus = status
                guard NotificationPermission.shouldRequest(status) else { return }
                UserDefaults.standard.set(true, forKey: self.notificationAskedKey)
                center.requestAuthorization(options: [.alert, .sound]) { granted, _ in
                    DispatchQueue.main.async { self.notificationStatus = granted ? .allowed : .denied }
                }
            }
        }
    }

    /// Read the status again. The person can change it in Settings.
    private func refreshNotificationSettings() {
        UNUserNotificationCenter.current().getNotificationSettings { [weak self] settings in
            DispatchQueue.main.async {
                self?.notificationStatus = Self.notificationStatus(settings.authorizationStatus)
            }
        }
    }

    private static func notificationStatus(_ authorization: UNAuthorizationStatus) -> NotificationPermission.Status {
        switch authorization {
        case .denied: return .denied
        case .notDetermined: return .notDetermined
        default: return .allowed
        }
    }

    /// True when notifications are denied, so the person must change a setting.
    var notificationsDenied: Bool { NotificationPermission.needsSettings(notificationStatus) }

    private func notifyStopped(_ reason: StopReason) {
        // A message in the app is enough while the person looks at it.
        guard !sceneIsActive else { return }
        let content = UNMutableNotificationContent()
        content.title = NotificationPermission.stopTitle
        content.body = reason.notificationBody
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: "stopped", content: content, trigger: nil))
    }

    private func notifyPairing() {
        let content = UNMutableNotificationContent()
        content.title = "Pair a target device?"
        content.body = "Open HotspotShade to review."
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: "pairing", content: content, trigger: nil))
    }

    func refreshAddresses() {
        switch HotspotInterface.observe() {
        case .present(let address):
            hotspotAddress = address
            addresses = address
        case .absent:
            hotspotAddress = nil
            addresses = "Hotspot IPv4 address not found."
        case .unreadable:
            hotspotAddress = nil
            addresses = "Cannot read network interfaces."
        }
    }

    // MARK: Stop record

    private func recordStop(_ reason: StopReason) {
        let record = stopLog.record(reason)
        lastStopLine = record.line()
    }

    // MARK: Hotspot watch
    // While the proxy runs, look at the hotspot interface once a second. Stop the
    // proxy when the hotspot address stays missing. The interface check does
    // not report the state of the Personal Hotspot switch.

    private func startHotspotWatch(boundAddress: String) {
        stopHotspotWatch()
        lossDetector = HotspotLossDetector(boundAddress: boundAddress)
        let timer = DispatchSource.makeTimerSource(queue: .main)
        timer.schedule(deadline: .now() + 1, repeating: 1)
        timer.setEventHandler { [weak self] in self?.checkHotspot() }
        hotspotTimer = timer
        timer.resume()
    }

    private func stopHotspotWatch() {
        hotspotTimer?.cancel()
        hotspotTimer = nil
        lossDetector = nil
    }

    func checkHotspot() {
        guard proxyRequested, var detector = lossDetector else { return }
        // The proxy already stopped or failed to start. Nothing to watch.
        if snapshot.state == "Failed" || snapshot.state == "Stopped" {
            stopHotspotWatch()
            return
        }
        let lost = detector.observe(HotspotInterface.observe())
        lossDetector = detector
        if lost { stopForLostHotspot() }
    }

    private func stopForLostHotspot() {
        proxyRequested = false
        stopLocation()
        stopHotspotWatch()
        recordActivity(StopReason.hotspotLost.message)
        recordStop(.hotspotLost)
        notifyStopped(.hotspotLost)
        server.stop(reason: StopReason.hotspotLost.message)
    }

    private func stopForLocationLost() {
        proxyRequested = false
        stopLocation()
        stopHotspotWatch()
        recordActivity(StopReason.locationLost.message)
        recordStop(.locationLost)
        notifyStopped(.locationLost)
        server.stop(reason: StopReason.locationLost.message)
    }

    func recordActivity(_ message: String) {
        activity.append(ActivityEntry(time: Date(), message: message))
        if activity.count > 50 { activity.removeFirst() }
    }

    private func startWakeTimer() {
        guard wakeTimer == nil else { return }
        wakeTick = Date()
        persistWakeTick(force: true)
        displayNow = Date()
        wakeTimer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            guard let self = self else { return }
            self.wakeTick = Date()
            self.displayNow = Date()
            self.persistWakeTick(force: false)
        }
    }

    /// Save the awake time at most once a minute. A scene change saves it at once.
    private func persistWakeTick(force: Bool) {
        guard force || wakeTick.timeIntervalSince(lastWakePersist) >= 60 else { return }
        lastWakePersist = wakeTick
        UserDefaults.standard.set(wakeTick, forKey: "wakeTick")
    }
}

struct ContentView: View {
    @StateObject private var model = ProxyModel()
    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    @State private var showActivity = false
    @State private var showDetails = false
    @State private var showForgetAll = false
    @FocusState private var portFieldFocused: Bool
    private var running: Bool { model.snapshot.state == "Listening" || model.snapshot.state == "Starting" }
    /// A Start failure stays visible until the user tries again or the proxy starts.
    private var state: String { model.startFailure != nil ? "Failed" : model.snapshot.state }

    var body: some View {
        TabView {
            NavigationStack {
                DashboardContent(
                    display: model.dashboardDisplay,
                    running: running,
                    offerRestart: model.offerRestart,
                    capacityWarning: model.snapshot.capacityWarning,
                    connectionLines: model.connectionLines,
                    keepAwakeMessage: model.keepAwakeMessage,
                    locationNeedsSettings: model.locationNeedsSettings,
                    lastStop: model.lastStopLine,
                    onStartStop: {
                        if running { model.stop() } else { model.start() }
                    },
                    onOpenSettings: { model.openLocationSettings() }
                )
                .navigationTitle("Dashboard")
                .toolbar { activityButton }
            }
            .tabItem { Label("Dashboard", systemImage: "house") }

            NavigationStack {
                settings
                    .navigationTitle("Settings")
                    .toolbar { activityButton }
            }
            .tabItem { Label("Settings", systemImage: "gearshape") }
        }
        .sheet(isPresented: $showActivity) {
            ActivitySheet(entries: model.activity,
                          details: model.snapshot.logs,
                          showDetails: $showDetails)
                .presentationDetents([.medium, .large])
                .presentationDragIndicator(.visible)
        }
        .alert("Allow this target device?", isPresented: Binding(get: { model.pairingPrompt != nil }, set: { _ in }), presenting: model.pairingPrompt) { prompt in
            Button("Deny", role: .cancel) { model.decidePairing(prompt: prompt, allow: false) }
            Button("Allow") { model.decidePairing(prompt: prompt, allow: true) }
        } message: { prompt in
            Text("Check that the target device shows \(prompt.code). Tap Allow only if it matches.")
        }
        .onChange(of: scenePhase) { _, phase in model.sceneChanged(phase) }
    }

    private var activityButton: some ToolbarContent {
        ToolbarItem(placement: .topBarTrailing) {
            Button {
                showDetails = false
                showActivity = true
            } label: {
                Image(systemName: "clock.arrow.circlepath")
            }
            .accessibilityLabel("Recent activity")
            .accessibilityHint("Shows recent events and technical details.")
        }
    }

    private var portField: some View {
        TextField("Port", text: Binding(get: { model.port }, set: { model.setCustomPort($0) }))
            .keyboardType(.numberPad)
            .multilineTextAlignment(dynamicTypeSize >= .accessibility1 ? .leading : .trailing)
            .disabled(running)
            .focused($portFieldFocused)
            .accessibilityLabel("Proxy port")
    }

    private var settings: some View {
        Form {
            Section {
                Toggle("Keep running in the background", isOn: Binding(get: { model.backgroundLocation }, set: { model.setBackgroundLocation($0) }))
                Text("This uses Location to stop iOS from pausing the app. The app does not save your location. Battery use is higher.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if model.locationNeedsSettings {
                    Button("Open Settings") { model.openLocationSettings() }
                        .accessibilityHint("Opens the Settings app.")
                }
            }
            Section("Notifications") {
                SettingsStatusRow(symbol: notificationSymbol,
                                  tint: model.notificationsDenied ? .orange : .secondary,
                                  text: notificationStatusText)
                if model.notificationsDenied {
                    Button("Open Settings") { model.openNotificationSettings() }
                        .accessibilityHint("Opens the Settings app.")
                }
            }
            Section("Paired target devices") {
                SettingsPairingRow(pairing: model.pairingDisplay)
                if model.pairedLaptops > 0 {
                    Button("Forget paired target devices", role: .destructive) { showForgetAll = true }
                        .accessibilityHint("Asks for confirmation.")
                }
            }
            Section {
                DisclosureGroup("Advanced") {
                    Toggle("Choose the port automatically", isOn: Binding(get: { !model.portIsCustom }, set: { model.setPortAutomatic($0) }))
                        .disabled(running)
                    if model.portIsCustom {
                        if dynamicTypeSize >= .accessibility1 {
                            VStack(alignment: .leading, spacing: SourceMetrics.space8) {
                                Text("Proxy port")
                                portField
                            }
                        } else {
                            HStack {
                                Text("Proxy port")
                                Spacer()
                                portField
                            }
                        }
                        Text("Enter a port from 1024 to 65535. Port 18090 is reserved.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    } else {
                        LabeledContent("Proxy port", value: model.port)
                    }
                    Text("Your target device learns the port when it pairs, and again when it changes. You do not need to type it there.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    VStack(alignment: .leading, spacing: SourceMetrics.space4) {
                        Text("Hotspot address")
                        Text(model.addresses)
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .accessibilityElement(children: .ignore)
                    .accessibilityLabel("Hotspot address")
                    .accessibilityValue(model.addresses)
                    Button("Refresh address") { model.refreshAddresses() }
                        .accessibilityHint("Reads the hotspot address again.")
                    LabeledContent("Token") {
                        Button(model.tokenVisible ? "Hide token" : "Show token") { model.toggleTokenReveal() }
                    }
                    if model.tokenVisible {
                        Text(model.token)
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                            .privacySensitive()
                            .fixedSize(horizontal: false, vertical: true)
                            .accessibilityLabel("Proxy token")
                            .accessibilityValue(model.token)
                        Button("Copy token") { model.copyToken() }
                        if model.copied == .token {
                            Text("The token is copied.")
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                        }
                    } else {
                        Text("The token is hidden. Tap Show token to see it. It hides again after 30 seconds.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Button("Rotate token") { model.rotateToken() }.disabled(running)
                    Text(ConfirmationText.rotateTokenNote)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    VStack(alignment: .leading, spacing: SourceMetrics.space4) {
                        Text("State")
                        Text(DisplayState.label(state))
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .accessibilityElement(children: .ignore)
                    .accessibilityLabel("State")
                    .accessibilityValue(DisplayState.label(state))
                    if let warning = model.snapshot.capacityWarning {
                        Text(warning)
                            .font(.footnote)
                            .foregroundStyle(.orange)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    LabeledContent("Version", value: AppVersion.text)
                    Button("Copy diagnostics") { model.copyDiagnostics() }
                    if model.copied == .diagnostics {
                        Text("The diagnostics report is copied.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    Text("The report holds counts and versions. It holds no address, port, token, or website.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .confirmationDialog(ConfirmationText.forgetAllTitle, isPresented: $showForgetAll, titleVisibility: .visible) {
            Button("Forget All", role: .destructive) { model.forgetPairedLaptops() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(ConfirmationText.forgetAllMessage)
        }
        .scrollDismissesKeyboard(.interactively)
        .toolbar {
            ToolbarItemGroup(placement: .keyboard) {
                Spacer()
                Button("Done") { portFieldFocused = false }
            }
        }
    }

    private var notificationStatusText: String {
        switch model.notificationStatus {
        case .allowed:
            return "Notifications are on. The app can send a message when the proxy stops."
        case .denied:
            return NotificationPermission.deniedNote
        case .notDetermined:
            return "The app asks for notifications the first time you start the proxy."
        }
    }

    private var notificationSymbol: String {
        switch model.notificationStatus {
        case .allowed: return "bell"
        case .denied: return "bell.slash"
        case .notDetermined: return "bell.badge"
        }
    }
}

// MARK: - Design values

/// The spacing, radius, and width for the source device app. Use these values
/// and no other margin.
private enum SourceMetrics {
    static let space4: CGFloat = 4
    static let space8: CGFloat = 8
    static let space12: CGFloat = 12
    static let space16: CGFloat = 16
    static let space24: CGFloat = 24
    /// Keep this value equal to the radius in GlassCompat.swift.
    static let cardRadius: CGFloat = 24
    static let contentWidth: CGFloat = 640
}

/// The status mark colors. The text next to the mark carries the same state,
/// so the color is never the only signal.
private enum SourceStatusColor {
    static func color(for kind: DashboardStatus.Kind) -> Color {
        switch kind {
        case .off: return .secondary
        case .starting: return .blue
        case .on: return .green
        case .pairing: return .accentColor
        case .attention: return .orange
        }
    }
}

/// One card surface. Reduce Transparency uses an opaque surface. The normal
/// path uses the card helper in GlassCompat.swift.
private struct SourceCardModifier: ViewModifier {
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    func body(content: Content) -> some View {
        content
            .padding(SourceMetrics.space24)
            .frame(maxWidth: .infinity, alignment: .leading)
            .modifier(SourceCardSurface(reduceTransparency: reduceTransparency))
    }
}

private struct SourceCardSurface: ViewModifier {
    var reduceTransparency: Bool

    @ViewBuilder
    func body(content: Content) -> some View {
        if reduceTransparency {
            content
                .background(Color(uiColor: .secondarySystemGroupedBackground),
                            in: RoundedRectangle(cornerRadius: SourceMetrics.cardRadius, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: SourceMetrics.cardRadius, style: .continuous)
                    .strokeBorder(Color(uiColor: .separator), lineWidth: 1))
        } else {
            content.cardGlass()
        }
    }
}

private extension View {
    func sourceCard() -> some View { modifier(SourceCardModifier()) }
}

/// The one main action. iOS 26 uses the Liquid Glass style. Earlier systems
/// use a prominent bordered button.
private struct PrimaryActionButton: View {
    var title: String
    var accessibilityLabel: String
    var accessibilityHint: String
    var action: () -> Void

    var body: some View {
        #if compiler(>=6.2)
        if #available(iOS 26.0, *) {
            base.buttonStyle(.glassProminent)
        } else {
            base.buttonStyle(.borderedProminent)
        }
        #else
        base.buttonStyle(.borderedProminent)
        #endif
    }

    private var base: some View {
        Button(action: action) {
            Text(title).frame(maxWidth: .infinity)
        }
        .controlSize(.large)
        .accessibilityLabel(accessibilityLabel)
        .accessibilityHint(accessibilityHint)
    }
}

/// One status line in Settings. The symbol is decorative, because the text
/// carries the same state.
private struct SettingsStatusRow: View {
    var symbol: String
    var tint: Color
    var text: String

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: SourceMetrics.space8) {
            Image(systemName: symbol)
                .foregroundStyle(tint)
                .accessibilityHidden(true)
            Text(text)
                .frame(maxWidth: .infinity, alignment: .leading)
                .fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .combine)
    }
}

/// The Settings pairing row. The text, the symbol, and the tint come from one
/// pairing display.
private struct SettingsPairingRow: View {
    var pairing: PairingDisplay

    var body: some View {
        SettingsStatusRow(symbol: pairing.settingsSymbol,
                          tint: tint,
                          text: pairing.settingsText)
    }

    private var tint: Color {
        switch pairing.activity {
        case .notPaired: return .secondary
        case .pairing: return .accentColor
        case .paired, .inUse: return .green
        }
    }
}

// MARK: - Dashboard

/// The Dashboard content. It takes plain values, so a preview can show every
/// state without a proxy, a listener, or a location manager.
private struct DashboardContent: View {
    var display: DashboardDisplay
    var running: Bool
    var offerRestart: Bool
    var capacityWarning: String?
    var connectionLines: [String]
    var keepAwakeMessage: String
    var locationNeedsSettings: Bool
    var lastStop: String?
    var onStartStop: () -> Void
    var onOpenSettings: () -> Void

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: SourceMetrics.space16) {
                statusCard
                usageCard
                keepAwakeCard
                if let lastStop = lastStop {
                    lastStopCard(lastStop)
                }
            }
            .frame(maxWidth: SourceMetrics.contentWidth)
            .frame(maxWidth: .infinity)
            .padding(SourceMetrics.space16)
        }
        .background(Color(uiColor: .systemGroupedBackground))
    }

    private var statusCard: some View {
        VStack(alignment: .leading, spacing: SourceMetrics.space12) {
            VStack(alignment: .leading, spacing: SourceMetrics.space8) {
                HStack(alignment: .firstTextBaseline, spacing: SourceMetrics.space12) {
                    Image(systemName: "circle.fill")
                        .font(.system(size: 11))
                        .foregroundStyle(SourceStatusColor.color(for: display.status.kind))
                        .accessibilityHidden(true)
                    Text(display.status.title)
                        .font(.title.bold())
                        .fixedSize(horizontal: false, vertical: true)
                }
                Text(display.status.message)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("Proxy status")
            .accessibilityValue("\(display.status.title). \(display.status.message)")

            if let warning = capacityWarning {
                HStack(alignment: .firstTextBaseline, spacing: SourceMetrics.space8) {
                    Image(systemName: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                        .accessibilityHidden(true)
                    Text(warning)
                        .font(.subheadline)
                        .foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .accessibilityElement(children: .combine)
            }

            PrimaryActionButton(
                title: running ? "Stop" : (offerRestart ? "Start again" : "Start"),
                accessibilityLabel: running ? "Stop proxy" : "Start proxy",
                accessibilityHint: running ? "Stops the proxy." : "Starts the proxy for your target device.",
                action: onStartStop
            )
        }
        .sourceCard()
    }

    private var usageCard: some View {
        VStack(alignment: .leading, spacing: SourceMetrics.space8) {
            Label(display.pairing.usageTitle, systemImage: "network")
                .font(.headline)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityAddTraits(.isHeader)
            Text(display.pairing.summary)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if let detail = display.pairing.detail {
                Text(detail)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if !connectionLines.isEmpty {
                VStack(alignment: .leading, spacing: SourceMetrics.space4) {
                    ForEach(Array(connectionLines.enumerated()), id: \.offset) { index, line in
                        Text(line)
                            .font(.subheadline)
                            .foregroundStyle(index == 0 ? Color.primary : Color.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .padding(.top, SourceMetrics.space4)
                .accessibilityElement(children: .ignore)
                .accessibilityLabel("Connection attempts")
                .accessibilityValue(connectionLines.joined(separator: " "))
            }
        }
        .sourceCard()
    }

    private var keepAwakeCard: some View {
        VStack(alignment: .leading, spacing: SourceMetrics.space8) {
            Label("Keeping awake", systemImage: "moon.zzz")
                .font(.headline)
                .accessibilityAddTraits(.isHeader)
            Text(keepAwakeMessage)
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if locationNeedsSettings {
                Button("Open Settings", action: onOpenSettings)
                    .buttonStyle(.bordered)
                    .accessibilityHint("Opens the Settings app.")
            }
        }
        .sourceCard()
    }

    private func lastStopCard(_ line: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: SourceMetrics.space12) {
            Image(systemName: "clock")
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text(line)
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .sourceCard()
        .accessibilityElement(children: .combine)
    }
}

// MARK: - Activity

/// The Recent activity sheet. The plain list shows events. Details shows the
/// technical lines. The sheet has a Done button for VoiceOver and for iPad.
private struct ActivitySheet: View {
    var entries: [ActivityEntry]
    var details: [String]
    @Binding var showDetails: Bool
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            List {
                Picker("Activity view", selection: $showDetails) {
                    Text("Activity").tag(false)
                    Text("Details").tag(true)
                }
                .pickerStyle(.segmented)
                .listRowBackground(Color.clear)
                .accessibilityLabel("Activity view")

                if showDetails {
                    Text("Details can include addresses and websites. They stay on this source device and are not saved.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    if details.isEmpty {
                        emptyRow(title: "No details yet.",
                                 symbol: "doc.text.magnifyingglass",
                                 detail: "Technical lines appear here while the app runs.")
                    } else {
                        ForEach(Array(details.reversed().enumerated()), id: \.offset) { _, line in
                            Text(line)
                                .font(.footnote)
                                .textSelection(.enabled)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                } else if entries.isEmpty {
                    emptyRow(title: "No activity yet.",
                             symbol: "clock",
                             detail: "Events appear here while the app runs.")
                } else {
                    ForEach(Array(entries.reversed())) { entry in
                        ActivityRow(entry: entry)
                    }
                }
            }
            .listStyle(.insetGrouped)
            .navigationTitle("Recent activity")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }

    private func emptyRow(title: String, symbol: String, detail: String) -> some View {
        VStack(spacing: SourceMetrics.space8) {
            Image(systemName: symbol)
                .font(.largeTitle)
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text(title)
                .font(.headline)
            Text(detail)
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, SourceMetrics.space24)
        .listRowBackground(Color.clear)
        .listRowSeparator(.hidden)
        .accessibilityElement(children: .combine)
    }
}

/// One plain activity line. At accessibility sizes the time sits above the
/// message, so the message keeps the full width.
private struct ActivityRow: View {
    var entry: ActivityEntry
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize

    var body: some View {
        Group {
            if dynamicTypeSize.isAccessibilitySize {
                VStack(alignment: .leading, spacing: SourceMetrics.space4) {
                    time
                    message
                }
            } else {
                HStack(alignment: .firstTextBaseline, spacing: SourceMetrics.space12) {
                    time.frame(minWidth: 56, alignment: .leading)
                    message
                }
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(entry.timeText). \(entry.message)")
    }

    private var time: some View {
        Text(entry.timeText)
            .font(.caption.monospacedDigit())
            .foregroundStyle(.secondary)
    }

    private var message: some View {
        Text(entry.message)
            .font(.subheadline)
            .frame(maxWidth: .infinity, alignment: .leading)
            .fixedSize(horizontal: false, vertical: true)
    }
}


/// The version text for the Settings row and the diagnostics header.
enum AppVersion {
    static var text: String {
        let info = Bundle.main.infoDictionary
        let short = info?["CFBundleShortVersionString"] as? String ?? "Unknown"
        guard let build = info?["CFBundleVersion"] as? String, !build.isEmpty else { return short }
        return "\(short) (\(build))"
    }
}

#if DEBUG
// The previews use plain values. They start no listener and ask for no
// permission. Check the light theme, the dark theme, large text, and Reduce
// Transparency.

/// A Dashboard with plain values. It starts no proxy.
private struct DashboardPreview: View {
    var display: DashboardDisplay
    var running: Bool
    var offerRestart = false
    var capacityWarning: String? = nil
    var connectionLines = ["No connections yet."]
    var keepAwakeMessage: String? = nil
    var locationNeedsSettings = false
    var lastStop: String? = nil

    var body: some View {
        NavigationStack {
            DashboardContent(
                display: display,
                running: running,
                offerRestart: offerRestart,
                capacityWarning: capacityWarning,
                connectionLines: connectionLines,
                keepAwakeMessage: keepAwakeMessage ?? (running ? LocationHealth.keepingAwake : LocationHealth.startsWithProxy),
                locationNeedsSettings: locationNeedsSettings,
                lastStop: lastStop,
                onStartStop: {},
                onOpenSettings: {}
            )
            .navigationTitle("Dashboard")
        }
    }
}

private enum PreviewDisplay {
    static let idle = PairingDisplay.state(trustedCount: 0, authenticatedSessions: 0,
                                           pairingCodePresent: false, listenerReady: true,
                                           lastTrafficAge: nil)
    static let paired = PairingDisplay.state(trustedCount: 1, authenticatedSessions: 0,
                                             pairingCodePresent: false, listenerReady: true,
                                             lastTrafficAge: nil)
    static let pairing = PairingDisplay.state(trustedCount: 0, authenticatedSessions: 0,
                                              pairingCodePresent: true, listenerReady: true,
                                              lastTrafficAge: nil)
    static let inUse = PairingDisplay.state(trustedCount: 1, authenticatedSessions: 1,
                                            pairingCodePresent: false, listenerReady: true,
                                            lastTrafficAge: 5)
    static let connectionLines = [
        "12 attempts. 9 worked. 3 did not.",
        "2 were cancelled by the target device.",
        "Did not work: 2 web, 1 DNS lookup."
    ]
    static let lastStop = "Last stop: You stopped it. 14:32."

    static func display(_ state: String, _ pairing: PairingDisplay,
                        error: String? = nil) -> DashboardDisplay {
        DashboardDisplay(status: DashboardStatus.make(snapshotState: state,
                                                      startFailure: nil,
                                                      snapshotError: error,
                                                      pairing: pairing),
                         pairing: pairing)
    }
}

private struct ActivityPreview: View {
    var entries: [ActivityEntry]
    var details: [String]
    @State private var showDetails: Bool

    init(entries: [ActivityEntry] = [], details: [String] = [], showDetails: Bool = false) {
        self.entries = entries
        self.details = details
        _showDetails = State(initialValue: showDetails)
    }

    var body: some View {
        ActivitySheet(entries: entries, details: details, showDetails: $showDetails)
    }
}

private enum PreviewActivity {
    static let entries = [
        ActivityEntry(time: Date(timeIntervalSince1970: 1_762_000_000), message: "Proxy started."),
        ActivityEntry(time: Date(timeIntervalSince1970: 1_762_000_090), message: "A target device was added."),
        ActivityEntry(time: Date(timeIntervalSince1970: 1_762_000_130), message: PlainMessage.forgotten)
    ]
    static let details = [
        "A web connection did not become ready in time.",
        "A name lookup did not finish.",
        "A UDP flow was cancelled by the target device."
    ]
}

#Preview("Dashboard: off, light") {
    DashboardPreview(display: PreviewDisplay.display("Stopped", PreviewDisplay.idle),
                     running: false,
                     lastStop: PreviewDisplay.lastStop)
        .preferredColorScheme(.light)
}

#Preview("Dashboard: off, dark") {
    DashboardPreview(display: PreviewDisplay.display("Stopped", PreviewDisplay.idle),
                     running: false,
                     offerRestart: true,
                     lastStop: PreviewDisplay.lastStop)
        .preferredColorScheme(.dark)
}

#Preview("Dashboard: on") {
    DashboardPreview(display: PreviewDisplay.display("Listening", PreviewDisplay.paired),
                     running: true,
                     connectionLines: PreviewDisplay.connectionLines)
        .preferredColorScheme(.light)
}

#Preview("Dashboard: pairing") {
    DashboardPreview(display: PreviewDisplay.display("Listening", PreviewDisplay.pairing),
                     running: true)
        .preferredColorScheme(.light)
}

#Preview("Dashboard: in use, dark") {
    DashboardPreview(display: PreviewDisplay.display("Listening", PreviewDisplay.inUse),
                     running: true,
                     connectionLines: PreviewDisplay.connectionLines)
        .preferredColorScheme(.dark)
}

#Preview("Dashboard: needs attention") {
    DashboardPreview(display: PreviewDisplay.display("Failed", PreviewDisplay.idle,
                                                    error: "The address is in use"),
                     running: false,
                     keepAwakeMessage: LocationHealth.permissionOff,
                     locationNeedsSettings: true)
        .preferredColorScheme(.light)
}

#Preview("Dashboard: large text, dark") {
    DashboardPreview(display: PreviewDisplay.display("Listening", PreviewDisplay.inUse),
                     running: true,
                     connectionLines: PreviewDisplay.connectionLines)
        .environment(\.dynamicTypeSize, .accessibility3)
        .preferredColorScheme(.dark)
}

#Preview("Settings rows: light") {
    Form {
        Section("Notifications") {
            SettingsStatusRow(symbol: "bell", tint: .secondary,
                              text: "Notifications are on. The app can send a message when the proxy stops.")
        }
        Section("Paired target devices") {
            SettingsPairingRow(pairing: PreviewDisplay.paired)
            SettingsPairingRow(pairing: PreviewDisplay.pairing)
        }
    }
    .preferredColorScheme(.light)
}

#Preview("Settings rows: dark, large text") {
    Form {
        Section("Notifications") {
            SettingsStatusRow(symbol: "bell.slash", tint: .orange,
                              text: NotificationPermission.deniedNote)
        }
        Section("Paired target devices") {
            SettingsPairingRow(pairing: PreviewDisplay.idle)
        }
    }
    .environment(\.dynamicTypeSize, .accessibility3)
    .preferredColorScheme(.dark)
}

#Preview("Activity: empty") {
    ActivityPreview()
        .preferredColorScheme(.light)
}

#Preview("Activity: entries") {
    ActivityPreview(entries: PreviewActivity.entries)
        .preferredColorScheme(.light)
}

#Preview("Activity: entries, large text") {
    ActivityPreview(entries: PreviewActivity.entries)
        .environment(\.dynamicTypeSize, .accessibility3)
        .preferredColorScheme(.dark)
}

#Preview("Activity: details") {
    ActivityPreview(details: PreviewActivity.details, showDetails: true)
        .preferredColorScheme(.dark)
}
#endif
