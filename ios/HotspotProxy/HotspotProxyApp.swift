import SwiftUI
import UIKit
import Darwin
import CoreLocation
import UserNotifications
import UniformTypeIdentifiers

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
    case connection
    case diagnostics
}

final class ProxyModel: NSObject, ObservableObject, CLLocationManagerDelegate {
    @Published var snapshot = ProxyServer.Snapshot()
    /// The proxy port. The phone picks it and tells the target device when they pair.
    @Published var port = String(ProxyPort.storedOrNew())
    @Published var portIsCustom = UserDefaults.standard.bool(forKey: "proxyPortCustom")
    @Published private(set) var token = ""
    /// The last token storage failure. It holds no token. A missing token
    /// blocks a proxy start until a later load succeeds. Token rotation is
    /// disabled pending review, so it cannot repair this state.
    @Published private(set) var tokenStorageFailure: String?
    /// True when the keychain holds a token the app can use. Rotation needs
    /// this. A new token must not replace an item the app could not read.
    @Published private(set) var tokenStorageReady = false
    /// A conflict keeps both copies and suspends pairing.
    @Published private(set) var tokenConflict = false
    /// Recovery is unavailable while storage cannot conditionally change items.
    @Published private(set) var tokenRecovery: TokenRecoveryKind = .none
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
    private var tokenPasteboardOwnership = TokenPasteboardOwnership()
    private var copyTimer: Timer?
    private var wakeTimer: Timer?
    /// Refresh the display when a pairing result line reaches 60 seconds.
    private var pairingNoticeTimer: Timer?
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
    /// The server failure revision that was visible when the current start was
    /// requested. A queued snapshot at or below it is from an older run.
    private var startFailureRevision = 0
    private var sceneIsActive = true
    private var notificationRequestStarted = false
    private var hotspotIdentity: HotspotInterface.Identity?
    /// The plain state of the last hotspot observation. Start uses it when no
    /// supported identity is available, so an unsupported or unreadable link
    /// does not show the "turn on the hotspot" text.
    private(set) var hotspotState: HotspotStartMessage.Observation = .absent
    private var hotspotTimer: DispatchSourceTimer?
    private var lossDetector: HotspotLossDetector?
    private let trust: ObservableTrustStore
    private let server: ProxyServer
    private let stopLog: StopLog
    /// The token state machine. The `@Published` token fields above mirror it
    /// through `tokenStateDidChange`.
    private let tokens: TokenLifecycle
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
        tokens = TokenLifecycle(store: SecureTokenStore(), pairing: server)
        super.init()
        tokens.attach(host: self)
        locationManager.delegate = self
        locationManager.desiredAccuracy = kCLLocationAccuracyNearestTenMeters
        locationManager.distanceFilter = kCLDistanceFilterNone
        locationManager.activityType = .other
        locationManager.pausesLocationUpdatesAutomatically = false
        locationManager.showsBackgroundLocationIndicator = true
        server.onChange = { [weak self] incomingSnapshot in
            guard let self = self else { return }
            let previous = self.snapshot.state
            let previousPairingFailures = self.snapshot.pairingFailureCount
            let previousPairingReady = self.snapshot.pairingReady
            let previousCapacityWarning = self.snapshot.capacityWarning
            var snapshot = incomingSnapshot
            // A start queues a pairing update before the server runs the start.
            // That update can publish the previous run's Stopped or Failed
            // state. Keep the requested start visible so the hotspot watch and
            // location do not stop before the server reports Starting. A newer
            // failure is not stale and ends the request below.
            if self.proxyRequested
                && ProxyStartPolicy.isStaleForPendingStart(
                    state: snapshot.state,
                    snapshotFailureRevision: snapshot.failureRevision,
                    requestFailureRevision: self.startFailureRevision) {
                snapshot.state = "Starting"
            }
            self.snapshot = snapshot
            self.displayNow = Date()
            // The pairing listener reads the live link. When it becomes ready,
            // use that observation to refresh the Manual connection address
            // without a new poll. The hotspot watch keeps it current while the
            // proxy runs.
            if snapshot.pairingReady && !previousPairingReady { self.refreshAddresses() }
            self.schedulePairingNoticeExpiry(snapshot.pairingNotice)
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
        tokens.launch()
        // The keychain item is readable after the first unlock. A launch before
        // the first unlock fails closed, and this notification is the one safe
        // signal to try the read again.
        NotificationCenter.default.addObserver(self,
                                               selector: #selector(protectedDataBecameAvailable),
                                               name: UIApplication.protectedDataDidBecomeAvailableNotification,
                                               object: nil)
        refreshAddresses()
        refreshLocationServices()
        updateLocation()
        refreshNotificationSettings()
        // Show the startup capacity before the first Start.
        server.publishCurrentState()
    }

    /// True while the proxy runs or a start is pending. Rotation is refused in
    /// both cases, so the running proxy and the pairing channel keep one token.
    var proxyActive: Bool {
        TokenRotationPolicy.proxyActive(proxyRequested: proxyRequested, state: snapshot.state)
    }

    /// The non-secret values that another device needs to use the proxy
    /// directly. Pairing is optional. The source token is not part of this
    /// value and stays in Settings behind the timed reveal.
    var manualConnection: ManualConnection {
        ManualConnection(address: hotspotIdentity?.address,
                         port: ProxyPort.parse(port),
                         running: snapshot.state == "Listening",
                         starting: snapshot.state == "Starting")
    }

    /// Rotation needs a usable token and a readable store, and it is gated on
    /// an independent review. The button and the action read the same rule,
    /// which lives in `TokenLifecycle`.
    var canRotateToken: Bool { tokens.canRotate }

    /// False in this build. The UI must say that rotation is unavailable
    /// pending review rather than blame the current token state.
    var rotationReviewApproved: Bool { tokens.rotationReviewApproved }

    /// True when no valid saved token remains, so recovery must create a new
    /// credential. Settings asks for a replacement. The control stays visible
    /// while the proxy runs, and `canReplaceInvalidToken` decides if it is
    /// enabled.
    var tokenNeedsReplacement: Bool { tokens.needsReplacement }

    /// True when the Keychain item is invalid but the old copy is still a valid
    /// token. Settings offers a restore. That copy may predate a rotation, so
    /// the action can also take access away from a newer token.
    var tokenNeedsRestore: Bool { tokens.needsRestore }

    /// True when the person may replace the invalid token now.
    var canReplaceInvalidToken: Bool { tokens.canReplaceInvalid }

    /// True when the person may restore the valid old token now.
    var canRestoreLegacyToken: Bool { tokens.canRestoreLegacy }

    /// Offer pairing with the saved port and the current token, or take the
    /// listener down when no usable token exists.
    private func syncPairingCredentials() { tokens.syncPairing() }

    /// Choose the port automatically or let the user set it. Not while the proxy runs.
    func setPortAutomatic(_ automatic: Bool) {
        guard !proxyActive else { return }
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
        guard !proxyActive else { return }
        let digits = ProxyPort.sanitizedText(text)
        port = digits
        if let value = ProxyPort.parse(digits) { UserDefaults.standard.set(String(value), forKey: ProxyPort.storageKey); syncPairingCredentials() }
    }

    /// `TokenLifecycle` owns every store call and every pairing start or stop.
    /// These actions only add the screen's own follow-up: the token hides after
    /// any change.
    func rotateToken() {
        // Refused while the proxy runs or a start is pending. The guard is the
        // same rule as the button.
        guard canRotateToken else { return }
        tokens.rotate()
        hideToken()
    }

    /// Replace the invalid saved token after an explicit confirmation.
    func replaceInvalidToken() {
        guard canReplaceInvalidToken else { return }
        tokens.replaceInvalid()
        hideToken()
    }

    /// Restore the valid old token into the Keychain after an explicit
    /// confirmation. The old copy may predate a rotation, so the confirmation
    /// names that risk.
    func restoreLegacyToken() {
        guard canRestoreLegacyToken else { return }
        tokens.restoreLegacy()
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

    /// Avoid reading the pasteboard, which can trigger an iOS paste prompt.
    private func clearOwnedTokenPasteboard() {
        let pasteboard = UIPasteboard.general
        if tokenPasteboardOwnership.takeIfUnchanged(currentChangeCount: pasteboard.changeCount) {
            pasteboard.items = []
        }
    }

    func start() {
        // The user tries again. An old start failure no longer applies.
        startFailure = nil
        // A keychain that was locked at launch may work now. Do not create a
        // new token when a stored one is readable.
        if token.isEmpty { tokens.retryLoadIfNeeded() }
        // Reserve the token lifecycle boundary across the token copy and the
        // point where the start request becomes visible. A rotation cannot slip
        // between them.
        guard let token = tokens.beginStart() else {
            failStart(tokenStorageFailure ?? PlainMessage.tokenUnavailable)
            return
        }
        defer { tokens.endStart() }
        syncPairingCredentials()
        // Ask for location permission on the first Start. Keep-alive needs it.
        requestLocationPermissionIfNeeded()
        // Ask for notification permission at the first Start only.
        requestNotificationPermissionIfNeeded()
        guard let value = ProxyPort.parse(port) else {
            failStart(PlainMessage.invalidPort)
            return
        }
        refreshAddresses()
        guard let identity = hotspotIdentity else {
            failStart(HotspotStartMessage.message(for: hotspotState))
            return
        }
        // The user starts again. The last stop no longer applies.
        stopLog.clear()
        lastStopLine = nil
        hadLocationThisRun = false
        locationCapReached = false
        startFailureRevision = snapshot.failureRevision
        proxyRequested = true
        // The previous run may have left a Failed state. Show the request at
        // once so the hotspot watch and location start, and the server replaces
        // this with its own Starting snapshot.
        snapshot.state = "Starting"
        updateLocation()
        server.start(port: value, token: token, hotspotAddress: identity.address)
        startHotspotWatch(boundIdentity: identity)
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

    /// Show the pairing prompt only while the app is active, the listener is
    /// ready, and the user has not answered. The listener rule matches
    /// `PairingDisplay.state`: a code without a ready listener is stale.
    var pairingPrompt: PairingPrompt? {
        guard let code = snapshot.pairingCode,
              let id = snapshot.pairingPromptID,
              PairingPromptPolicy.isVisible(sceneActive: sceneIsActive,
                                            listenerReady: snapshot.pairingReady,
                                            promptID: id,
                                            answeredID: answeredPairingID) else { return nil }
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
        // Use the same computed state that the Dashboard shows, so a Start
        // failure is not reported as the old snapshot state. The detail is the
        // plain attention line. Neither holds a token or an address.
        let summary = DiagnosticsProxySummary.make(status: dashboardDisplay.status)
        report.proxyState = summary.state
        report.proxyDetail = summary.detail ?? ""
        // The source device limit is the same in every run. The report carries
        // it so a copied report cannot claim ECH or a server name override.
        report.capabilityLines = SourceDeviceCapabilities.iosSource.diagnosticsLines
        report.lowPowerMode = ProcessInfo.processInfo.isLowPowerModeEnabled
        report.thermal = Self.thermalLevel(ProcessInfo.processInfo.thermalState)
        report.locationHealth = keepAwakeMessage
        report.appVersion = Self.appVersion
        report.systemVersion = UIDevice.current.systemVersion
        // The copy can happen after the snapshot. Recompute the bucket ages,
        // so the report does not show the age at the last publish.
        report.refreshEstablishedRows(now: ProcessInfo.processInfo.systemUptime)
        var text = report.text()
        // The token storage lines carry counts and a status code only. They
        // never carry a token, a key, or a keychain value.
        text += "\n" + tokens.diagnostics.text()
        #if DEBUG
        if let note = HotspotInterface.testOverrideNote() { text += "\n" + note }
        #endif
        return text
    }

    func copyDiagnostics() {
        UIPasteboard.general.string = diagnosticsText()
        tokenPasteboardOwnership.forget()
        showCopied(.diagnostics, announcement: "The diagnostics report is copied.")
    }

    /// Copy the address, port, and user name for another SOCKS5 client. The
    /// text holds no token. Writing it replaces any token copy, so the app
    /// stops tracking the old pasteboard item.
    func copyManualConnection() {
        guard let text = manualConnection.copyText else { return }
        let pasteboard = UIPasteboard.general
        pasteboard.setItems(
            [[UTType.utf8PlainText.identifier: text]],
            options: [.localOnly: true,
                      .expirationDate: Date().addingTimeInterval(TokenPasteboardOwnership.expirationSeconds)]
        )
        tokenPasteboardOwnership.forget()
        showCopied(.connection, announcement: "The connection details are copied.")
    }

    /// Copy the token only when the person can see it. The confirmation holds
    /// no token.
    func copyToken() {
        guard tokenVisible, !token.isEmpty else { return }
        let pasteboard = UIPasteboard.general
        let before = pasteboard.changeCount
        pasteboard.setItems(
            [[UTType.utf8PlainText.identifier: token]],
            options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(TokenPasteboardOwnership.expirationSeconds)]
        )
        tokenPasteboardOwnership.record(before: before, after: pasteboard.changeCount)
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

    /// The protected data is readable now. Retry a token load that failed
    /// before the first unlock. The retry never replaces a stored token.
    @objc private func protectedDataBecameAvailable() {
        DispatchQueue.main.async { [weak self] in
            self?.tokens.retryLoadIfNeeded()
        }
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
            // A keychain that was locked at launch may work now.
            tokens.retryLoadIfNeeded()
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
        let notice = snapshot.pairingNotice.flatMap {
            $0.isVisible(now: displayNow) ? $0.message : nil
        }
        return PairingDisplay.state(trustedCount: pairedLaptops,
                                    authenticatedSessions: snapshot.authenticatedSessions,
                                    pairingCodePresent: snapshot.pairingCode != nil,
                                    listenerReady: snapshot.pairingReady,
                                    lastTrafficAge: age,
                                    listenerUnavailable: snapshot.pairingUnavailable,
                                    notice: notice)
    }

    /// A token problem that leaves the app with no usable token. The Dashboard
    /// shows it as Needs attention. It holds no token.
    var tokenAttention: String? { token.isEmpty ? tokenStorageFailure : nil }

    /// The one Dashboard state. The header and the usage card share one
    /// pairing display, so they cannot show different states.
    var dashboardDisplay: DashboardDisplay {
        let pairing = pairingDisplay
        return DashboardDisplay(status: DashboardStatus.make(snapshotState: snapshot.state,
                                                             startFailure: startFailure,
                                                             snapshotError: snapshot.error,
                                                             tokenFailure: tokenAttention,
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
        applyHotspotObservation(HotspotInterface.observeLink())
    }

    /// Apply one observation to the Manual connection state. The interface
    /// name is kept with the address. A failed read is not a missing hotspot.
    private func applyHotspotObservation(_ observation: HotspotInterface.LinkObservation) {
        switch observation {
        case .present(let identity):
            hotspotIdentity = identity
            hotspotState = .present
            setAddresses(identity.address)
        case .unsupported:
            // The hotspot address is on a link this build cannot use. Do not
            // keep it as a start target.
            hotspotIdentity = nil
            hotspotState = .unsupported
            setAddresses("The hotspot address is on an unsupported link.")
        case .absent:
            hotspotIdentity = nil
            hotspotState = .absent
            setAddresses("Hotspot IPv4 address not found.")
        case .unreadable:
            hotspotIdentity = nil
            hotspotState = .unreadable
            setAddresses("Cannot read network interfaces.")
        }
    }

    private func setAddresses(_ text: String) {
        if addresses != text { addresses = text }
    }

    // MARK: Stop record

    private func recordStop(_ reason: StopReason) {
        let record = stopLog.record(reason)
        lastStopLine = record.line()
    }

    // MARK: Hotspot watch
    // While the proxy runs, look at the hotspot interface once a second. Stop the
    // proxy when the hotspot address stays missing, or when a complete read
    // names a different interface at the same address or an unsupported link.
    // The interface check does not report the state of the Personal Hotspot
    // switch, and a matching interface name does not prove that the hotspot is
    // still on.

    private func startHotspotWatch(boundIdentity: HotspotInterface.Identity) {
        stopHotspotWatch()
        lossDetector = HotspotLossDetector(boundIdentity: boundIdentity)
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
        // A snapshot from before the requested start can still say Stopped or
        // Failed. Keep watching until the server reaches Starting or reports a
        // failure newer than the request.
        if ProxyStartPolicy.isStaleForPendingStart(
            state: snapshot.state,
            snapshotFailureRevision: snapshot.failureRevision,
            requestFailureRevision: startFailureRevision) {
            return
        }
        // The proxy already stopped or failed to start. Nothing to watch.
        if snapshot.state == "Failed" || snapshot.state == "Stopped" {
            stopHotspotWatch()
            return
        }
        let observation = HotspotInterface.observeLink()
        let decision = detector.observe(observation)
        lossDetector = detector
        switch decision {
        case .keepRunning:
            // Keep the Manual connection address current from the same
            // observation. An unreadable read proves no change, so leave it.
            if observation != .unreadable { applyHotspotObservation(observation) }
        case .lost:
            applyHotspotObservation(.absent)
            stopForLostHotspot(.hotspotLost)
        case .identityChanged:
            applyHotspotObservation(observation)
            stopForLostHotspot(.hotspotChanged)
        case .unsupportedLink:
            applyHotspotObservation(observation)
            stopForLostHotspot(.hotspotUnsupported)
        }
    }

    private func stopForLostHotspot(_ reason: StopReason) {
        proxyRequested = false
        stopLocation()
        stopHotspotWatch()
        recordActivity(reason.message)
        recordStop(reason)
        notifyStopped(reason)
        server.stop(reason: reason.message)
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

    /// Refresh the display when the pairing result line is 60 seconds old, so
    /// it disappears even when the proxy is stopped and no other timer runs.
    private func schedulePairingNoticeExpiry(_ notice: PairingNotice?) {
        pairingNoticeTimer?.invalidate()
        pairingNoticeTimer = nil
        guard let notice, notice.isVisible(now: Date()) else { return }
        let remaining = notice.at.addingTimeInterval(PairingNotice.visibleSeconds).timeIntervalSinceNow
        guard remaining > 0 else { return }
        pairingNoticeTimer = Timer.scheduledTimer(withTimeInterval: remaining, repeats: false) { [weak self] _ in
            self?.pairingNoticeTimer = nil
            self?.displayNow = Date()
        }
    }

    /// Save the awake time at most once a minute. A scene change saves it at once.
    private func persistWakeTick(force: Bool) {
        guard force || wakeTick.timeIntervalSince(lastWakePersist) >= 60 else { return }
        lastWakePersist = wakeTick
        UserDefaults.standard.set(wakeTick, forKey: "wakeTick")
    }
}

/// The real pairing listener is the production sink of the token lifecycle.
/// `ProxyServer` keeps its own guards, so it never runs without a token.
extension ProxyServer: PairingCredentialSink {}

/// The production host of the token lifecycle. It supplies the proxy state and
/// the saved port, records activity, and copies the lifecycle state into the
/// published fields that the views read.
extension ProxyModel: TokenLifecycleHost {
    var tokenProxyRequested: Bool { proxyRequested }
    var tokenProxyState: String { snapshot.state }

    var tokenPairingPort: UInt16 {
        UserDefaults.standard.string(forKey: ProxyPort.storageKey).flatMap(ProxyPort.parse)
            ?? ProxyPort.storedOrNew()
    }

    func tokenActivity(_ message: String) { recordActivity(message) }

    func tokenStateDidChange() {
        if token != tokens.token {
            clearOwnedTokenPasteboard()
            hideToken()
        }
        token = tokens.token
        tokenStorageFailure = tokens.storageFailure
        tokenStorageReady = tokens.storageReady
        tokenConflict = tokens.conflict
        tokenRecovery = tokens.recovery
    }
}

struct ContentView: View {
    @StateObject private var model = ProxyModel()
    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    @State private var showActivity = false
    @State private var showDetails = false
    @State private var showForgetAll = false
    @State private var showRotateToken = false
    @State private var showReplaceInvalidToken = false
    @State private var showRestoreLegacyToken = false
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
            .disabled(model.proxyActive)
            .focused($portFieldFocused)
            .accessibilityLabel("Proxy port")
    }

    private var settings: some View {
        Form {
            Section {
                Toggle("Help keep running in the background", isOn: Binding(get: { model.backgroundLocation }, set: { model.setBackgroundLocation($0) }))
                Text("This uses Location to help keep the app active, but iOS can still pause it. The app does not save your location. Battery use is higher.")
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
                if let notice = model.pairingDisplay.notice {
                    SettingsStatusRow(symbol: "clock.arrow.circlepath",
                                      tint: .secondary,
                                      text: notice)
                }
                if model.pairedLaptops > 0 {
                    Button("Forget paired target devices", role: .destructive) { showForgetAll = true }
                        .accessibilityHint("Asks for confirmation.")
                }
            }
            Section("Manual connection") {
                Text("Another device can use these values in a SOCKS5 client. You do not need to pair it.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                LabeledContent("SOCKS5 username", value: ManualConnection.username)
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
                LabeledContent("SOCKS5 port", value: model.manualConnection.portText)
                Text(model.manualConnection.stateText)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Button("Copy connection details") { model.copyManualConnection() }
                    .disabled(!model.manualConnection.isUsable)
                    .accessibilityHint("Copies the address, port, and user name. It does not copy the token.")
                if model.copied == .connection {
                    Text("The connection details are copied.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                Text("The SOCKS5 password is the source token. Show it in Advanced. Use remote DNS, for example a socks5h proxy URL, so names resolve on this source device.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Section("Destination privacy") {
                ForEach(SourceDeviceCapabilities.iosSource.rows) { capability in
                    SettingsCapabilityRow(capability: capability)
                }
                Text(SourceDeviceCapabilities.settingsNote)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Section {
                DisclosureGroup("Advanced") {
                    Toggle("Choose the port automatically", isOn: Binding(get: { !model.portIsCustom }, set: { model.setPortAutomatic($0) }))
                        .disabled(model.proxyActive)
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
                    }
                    Text("Your target device learns the port when it pairs, and again when it changes. You do not need to type it there. The Manual connection section shows the current port for another client.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    LabeledContent("Token") {
                        Button(model.tokenVisible ? "Hide token" : "Show token") { model.toggleTokenReveal() }
                            .disabled(model.token.isEmpty)
                    }
                    if model.tokenVisible && !model.token.isEmpty {
                        Text(model.token)
                            .font(.system(.body, design: .monospaced))
                            .privacySensitive()
                            .fixedSize(horizontal: false, vertical: true)
                            .accessibilityLabel("Proxy token")
                            .accessibilityValue(model.token)
                        Button("Copy token") { model.copyToken() }
                        Text("The copy stays on this device for up to two minutes, including after you hide the token or leave the app. Other apps on this device may read it.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                        if model.copied == .token {
                            Text("The token is copied.")
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                        }
                    } else if !model.token.isEmpty {
                        Text("The token is hidden. Tap Show token to see it. It hides again after 30 seconds.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    if let failure = model.tokenStorageFailure {
                        Text(failure)
                            .font(.footnote)
                            .foregroundStyle(.orange)
                            .fixedSize(horizontal: false, vertical: true)
                            .accessibilityLabel("Token storage problem")
                            .accessibilityValue(failure)
                    }
                    if model.tokenNeedsRestore {
                        Button("Restore saved token...") {
                            showRestoreLegacyToken = true
                        }
                        .disabled(!model.canRestoreLegacyToken)
                        if model.proxyActive {
                            Text("Stop the proxy before you restore the token.")
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        Text(ConfirmationText.restoreLegacyTokenNote)
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    } else if model.tokenNeedsReplacement {
                        Button("Replace invalid token...", role: .destructive) {
                            showReplaceInvalidToken = true
                        }
                        .disabled(!model.canReplaceInvalidToken)
                        if model.proxyActive {
                            Text("Stop the proxy before you replace the token.")
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        Text(ConfirmationText.replaceInvalidTokenNote)
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Button("Rotate token") { showRotateToken = true }
                        .disabled(!model.canRotateToken)
                    Text(model.canRotateToken
                         ? ConfirmationText.rotateTokenNote
                         : (model.rotationReviewApproved
                            ? "Token rotation needs a readable saved token, no saved-token conflict, and a stopped proxy."
                            : "Token rotation is unavailable pending review. It stays disabled until the staged rotation protocol is reviewed. Do not treat it as a revocation path in this build."))
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
        .onAppear { model.refreshAddresses() }
        .confirmationDialog(ConfirmationText.forgetAllTitle, isPresented: $showForgetAll, titleVisibility: .visible) {
            Button("Forget All", role: .destructive) { model.forgetPairedLaptops() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(ConfirmationText.forgetAllMessage)
        }
        .confirmationDialog(ConfirmationText.rotateTokenTitle, isPresented: $showRotateToken, titleVisibility: .visible) {
            Button("Rotate Token", role: .destructive) { model.rotateToken() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(ConfirmationText.rotateTokenMessage)
        }
        .confirmationDialog(ConfirmationText.replaceInvalidTokenTitle, isPresented: $showReplaceInvalidToken, titleVisibility: .visible) {
            Button("Replace Token", role: .destructive) { model.replaceInvalidToken() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(ConfirmationText.replaceInvalidTokenMessage)
        }
        .confirmationDialog(ConfirmationText.restoreLegacyTokenTitle, isPresented: $showRestoreLegacyToken, titleVisibility: .visible) {
            Button("Restore Token", role: .destructive) { model.restoreLegacyToken() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(ConfirmationText.restoreLegacyTokenMessage)
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
        case .unavailable: return .orange
        }
    }
}

/// One destination-privacy row in Settings. It is a report, not a control:
/// nothing here can be turned on in this build. The state word carries the
/// meaning, so the symbol and the color are never the only signal.
private struct SettingsCapabilityRow: View {
    var capability: SourceCapability

    var body: some View {
        HStack(alignment: .top, spacing: SourceMetrics.space8) {
            Image(systemName: capability.symbol)
                .foregroundStyle(tint)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: SourceMetrics.space4) {
                Text(capability.title)
                Text(capability.state.label)
                    .font(.footnote)
                    .foregroundStyle(tint)
                Text(capability.detail)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .accessibilityElement(children: .combine)
    }

    private var tint: Color { capability.state.isOn ? .green : .secondary }
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
            if let notice = display.pairing.notice {
                HStack(alignment: .firstTextBaseline, spacing: SourceMetrics.space8) {
                    Image(systemName: "clock.arrow.circlepath")
                        .foregroundStyle(.secondary)
                        .accessibilityHidden(true)
                    Text(notice)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .accessibilityElement(children: .combine)
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
