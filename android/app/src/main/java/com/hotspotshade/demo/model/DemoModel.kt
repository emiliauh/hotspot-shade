package com.hotspotshade.demo.model

import java.util.Locale
import kotlin.math.max
import kotlin.random.Random

/** The three proxy states of the real source device app, plus the failure state. */
enum class ProxyState { OFF, STARTING, ON, FAILED }

/** The one pairing state that the Dashboard and Settings share. */
enum class PairingActivity { NOT_PAIRED, PAIRING, PAIRED, IN_USE }

/** The status mark and tone of the Dashboard header. */
enum class StatusKind { OFF, STARTING, ON, PAIRING, ATTENTION }

/** The Settings pairing row symbol. */
enum class PairingGlyph { LINK_PLUS, LINK, SEAL, NETWORK }

enum class StopReason(val shortMessage: String, val message: String) {
    USER(
        shortMessage = "You stopped it.",
        message = "You stopped the proxy.",
    ),
    HOTSPOT_LOST(
        shortMessage = "The hotspot turned off.",
        message = "The hotspot turned off, so the proxy stopped. Connect the target device, then tap Start.",
    ),
    FAILED(
        shortMessage = "The proxy stopped because of an error.",
        message = "The proxy stopped because of an error.",
    ),
    APP_CLOSED(
        shortMessage = "The app was closed by iOS.",
        message = "The app was closed by iOS.",
    ),
}

enum class NotificationStatus { NOT_DETERMINED, DENIED, ALLOWED }

enum class ThemeChoice { SYSTEM, LIGHT, DARK }

enum class CopyTarget { TOKEN, DIAGNOSTICS }

data class ActivityEntry(
    val id: Long,
    val timeMillis: Long,
    val message: String,
)

/**
 * One immutable demo state. The state holds simulated values only.
 * It holds no address, socket, credential, or real traffic data.
 */
data class DemoState(
    val proxy: ProxyState = ProxyState.OFF,
    val trustedCount: Int = 0,
    val authenticatedSessions: Int = 0,
    val lastTrafficAgeSeconds: Int? = null,
    val pairingCode: String? = null,
    val pairingInProgress: Boolean = false,
    val listenerReady: Boolean = true,
    val startFailure: String? = null,
    val lastStop: StopReason? = null,
    val lastStopAtMillis: Long? = null,
    val offerRestart: Boolean = false,
    val activity: List<ActivityEntry> = emptyList(),
    val details: List<String> = emptyList(),
    val keepAwake: Boolean = true,
    val simulatedLocationOff: Boolean = false,
    val notifications: NotificationStatus = NotificationStatus.NOT_DETERMINED,
    val portAutomatic: Boolean = true,
    val port: String = DemoEngine.DEFAULT_PORT,
    val token: String = DemoEngine.DEFAULT_TOKEN,
    val tokenVisible: Boolean = false,
    val tokenRevealUntilMillis: Long? = null,
    val copied: CopyTarget? = null,
    val theme: ThemeChoice = ThemeChoice.SYSTEM,
    val reduceMotion: Boolean = false,
    val addressChecks: Int = 0,
    val nextActivityId: Long = 1,
    val previewMode: Boolean = false,
) {
    val running: Boolean get() = proxy == ProxyState.STARTING || proxy == ProxyState.ON

    val pairingActivity: PairingActivity
        get() {
            val age = lastTrafficAgeSeconds
            if (authenticatedSessions > 0 && age != null && age <= RECENT_TRAFFIC_SECONDS) {
                return PairingActivity.IN_USE
            }
            if ((pairingCode != null || pairingInProgress) && listenerReady) {
                return PairingActivity.PAIRING
            }
            if (trustedCount > 0) return PairingActivity.PAIRED
            return PairingActivity.NOT_PAIRED
        }

    val statusTitle: String
        get() = when {
            startFailure != null || proxy == ProxyState.FAILED -> "Needs attention"
            proxy == ProxyState.STARTING -> "Starting"
            proxy == ProxyState.ON -> "On"
            else -> "Off"
        }

    val statusKind: StatusKind
        get() = when {
            startFailure != null || proxy == ProxyState.FAILED -> StatusKind.ATTENTION
            pairingActivity == PairingActivity.PAIRING -> StatusKind.PAIRING
            proxy == ProxyState.STARTING -> StatusKind.STARTING
            proxy == ProxyState.ON -> StatusKind.ON
            else -> StatusKind.OFF
        }

    val statusMessage: String
        get() = when {
            startFailure != null -> startFailure
            proxy == ProxyState.FAILED -> START_FAILED
            running -> usageSummary
            else -> OFF_MESSAGE
        }

    val usageTitle: String
        get() = if (pairingActivity == PairingActivity.IN_USE) CONNECTED_TITLE else WAITING_TITLE

    val usageSummary: String
        get() = when (pairingActivity) {
            PairingActivity.NOT_PAIRED -> NOT_PAIRED_TEXT
            PairingActivity.PAIRING -> PAIRING_TEXT
            PairingActivity.PAIRED -> pairedText
            PairingActivity.IN_USE -> IN_USE_TEXT
        }

    val pairedText: String
        get() = if (trustedCount == 1) {
            "Paired with 1 target device."
        } else {
            "Paired with $trustedCount target devices."
        }

    val usageDetail: String?
        get() = pairedText.takeIf {
            trustedCount > 0 && it != usageSummary
        }

    val settingsPairingText: String
        get() = when (pairingActivity) {
            PairingActivity.PAIRING -> PAIRING_TEXT
            PairingActivity.NOT_PAIRED -> NO_TARGET_DEVICES_TEXT
            PairingActivity.PAIRED, PairingActivity.IN_USE -> pairedText.takeIf {
                trustedCount > 0
            } ?: NO_TARGET_DEVICES_TEXT
        }

    val settingsPairingGlyph: PairingGlyph
        get() = when (pairingActivity) {
            PairingActivity.NOT_PAIRED -> PairingGlyph.LINK_PLUS
            PairingActivity.PAIRING -> PairingGlyph.LINK
            PairingActivity.PAIRED -> PairingGlyph.SEAL
            PairingActivity.IN_USE -> if (trustedCount > 0) PairingGlyph.SEAL else PairingGlyph.NETWORK
        }

    val connectionLines: List<String>
        get() = if (running) DemoEngine.SAMPLE_CONNECTION_LINES else emptyList()

    val keepAwakeMessage: String
        get() = when {
            !keepAwake -> KEEP_AWAKE_OFF
            simulatedLocationOff -> PERMISSION_OFF
            !running -> STARTS_WITH_PROXY
            else -> KEEPING_AWAKE_DEMO
        }

    val notificationStatusText: String
        get() = when (notifications) {
            NotificationStatus.ALLOWED ->
                "Simulated: notifications are on. The real app can send a message when the proxy stops."
            NotificationStatus.DENIED ->
                "Simulated: notifications are off. You will not see a message when the proxy stops."
            NotificationStatus.NOT_DETERMINED ->
                "Simulated: the app asks for notifications the first time you start the proxy."
        }

    fun tokenSecondsRemainingAt(nowMillis: Long): Int {
        val until = tokenRevealUntilMillis ?: return 0
        val remaining = until - nowMillis
        return max(0, ((remaining + 999) / 1000).toInt())
    }

    companion object {
        const val RECENT_TRAFFIC_SECONDS = 60
        const val OFF_MESSAGE = "Start the proxy when your target device is connected to your hotspot."
        const val START_FAILED = "The proxy could not start. Try again."
        const val NOT_PAIRED_TEXT = "Not paired. Open HotspotShade on your target device to pair."
        const val PAIRING_TEXT = "Pairing in progress. Check the code on your target device."
        const val IN_USE_TEXT = "A target device is using the proxy now."
        const val CONNECTED_TITLE = "Target device connected"
        const val WAITING_TITLE = "Waiting for your target device."
        const val NO_TARGET_DEVICES_TEXT = "No target devices are paired."
        const val KEEP_AWAKE_OFF = "Keep running in the background is off. Turn it on in Settings."
        const val PERMISSION_OFF =
            "Simulated: Location is off, so Android can pause the app. Turn it on in Settings."
        const val STARTS_WITH_PROXY = "Starts when the proxy starts."
        const val KEEPING_AWAKE_DEMO =
            "Simulated: the demo stays awake while it is on screen. The real app would use a foreground service."
    }
}

/** The pure demo logic. It performs no I/O and it contacts no device. */
object DemoEngine {
    const val DEFAULT_PORT = "49152"
    const val DEFAULT_TOKEN = "demo-6f2a91c4"
    const val MAX_ACTIVITY = 50
    const val RESERVED_PORT = 18090
    const val TOKEN_REVEAL_SECONDS = 30

    const val INVALID_PORT =
        "The proxy port is not valid. Change it in Settings, Advanced."

    const val ROTATE_TOKEN_NOTE =
        "Target devices that are already paired would keep the old token. In this demo, the token is not used."

    val SAMPLE_CONNECTION_LINES = listOf(
        "Simulated sample: 14 attempts. 9 worked. 3 did not.",
        "2 were cancelled by the target device.",
        "Did not work: 2 web, 1 DNS lookup.",
    )

    val SAMPLE_ACTIVITY = listOf(
        "Proxy started.",
        "A target device was added.",
        "You stopped the proxy.",
        "The hotspot turned off, so the proxy stopped. Connect the target device, then tap Start.",
        "A target device was removed.",
        "Simulated sample event.",
    )

    val SAMPLE_DETAILS = listOf(
        "Simulated detail: a web connection did not become ready in time.",
        "Simulated detail: a name lookup did not finish.",
        "Simulated detail: a UDP flow was cancelled by the target device.",
    )

    /** Keep digits only and limit the text to five characters while a person types. */
    fun sanitizePort(text: String): String = text.filter(Char::isDigit).take(5)

    fun isValidPort(text: String): Boolean {
        val value = text.toIntOrNull() ?: return false
        return value in 1024..65535 && value != RESERVED_PORT
    }

    fun formatPairingCode(code: String): String {
        if (code.length != 6) return code
        return "${code.take(3)} ${code.drop(3)}"
    }

    /** Spoken form for TalkBack. Each digit is separate. */
    fun spokenPairingCode(code: String): String = code.toCharArray().joinToString(" ")

    fun newDemoToken(): String {
        val hex = "0123456789abcdef"
        return "demo-" + buildString {
            repeat(10) { append(hex[Random.nextInt(hex.length)]) }
        }
    }

    fun addActivity(state: DemoState, message: String, nowMillis: Long): DemoState {
        val entry = ActivityEntry(
            id = state.nextActivityId,
            timeMillis = nowMillis,
            message = message,
        )
        val next = (state.activity + entry).takeLast(MAX_ACTIVITY)
        return state.copy(activity = next, nextActivityId = state.nextActivityId + 1)
    }

    fun addDetail(state: DemoState, detail: String): DemoState =
        state.copy(details = (state.details + detail).takeLast(MAX_ACTIVITY))

    fun requestStart(state: DemoState): DemoState = state.copy(
        proxy = ProxyState.STARTING,
        startFailure = null,
        lastStop = null,
        lastStopAtMillis = null,
        offerRestart = false,
        tokenVisible = false,
        tokenRevealUntilMillis = null,
        authenticatedSessions = 0,
        lastTrafficAgeSeconds = null,
        pairingCode = null,
        pairingInProgress = false,
    )

    fun finishStart(state: DemoState, nowMillis: Long): DemoState {
        if (state.proxy != ProxyState.STARTING) return state
        val started = state.copy(proxy = ProxyState.ON, startFailure = null)
        return addActivity(started, "Proxy started.", nowMillis)
    }

    fun stop(
        state: DemoState,
        nowMillis: Long,
        reason: StopReason = StopReason.USER,
    ): DemoState {
        if (!state.running) return state
        val stopped = state.copy(
            proxy = ProxyState.OFF,
            startFailure = null,
            authenticatedSessions = 0,
            lastTrafficAgeSeconds = null,
            pairingCode = null,
            pairingInProgress = false,
            lastStop = reason,
            lastStopAtMillis = nowMillis,
            offerRestart = reason == StopReason.APP_CLOSED,
            tokenVisible = false,
            tokenRevealUntilMillis = null,
        )
        return addActivity(stopped, reason.message, nowMillis)
    }

    fun failStart(state: DemoState, message: String, nowMillis: Long): DemoState {
        val failed = state.copy(
            proxy = ProxyState.FAILED,
            startFailure = message,
            authenticatedSessions = 0,
            lastTrafficAgeSeconds = null,
            pairingCode = null,
            pairingInProgress = false,
            lastStop = StopReason.FAILED,
            lastStopAtMillis = nowMillis,
            offerRestart = false,
            tokenVisible = false,
            tokenRevealUntilMillis = null,
        )
        return addActivity(failed, message, nowMillis)
    }

    /** Set a proxy state from the preview controls. This adds no activity entry. */
    fun setProxyScenario(state: DemoState, target: ProxyState, nowMillis: Long): DemoState =
        when (target) {
            ProxyState.OFF -> state.copy(
                proxy = ProxyState.OFF,
                startFailure = null,
                authenticatedSessions = 0,
                lastTrafficAgeSeconds = null,
                pairingCode = null,
                pairingInProgress = false,
            )

            ProxyState.STARTING -> state.copy(
                proxy = ProxyState.STARTING,
                startFailure = null,
                lastStop = null,
                lastStopAtMillis = null,
                offerRestart = false,
                authenticatedSessions = 0,
                lastTrafficAgeSeconds = null,
                pairingCode = null,
                pairingInProgress = false,
            )

            ProxyState.ON -> state.copy(
                proxy = ProxyState.ON,
                startFailure = null,
                lastStop = null,
                lastStopAtMillis = null,
                offerRestart = false,
                pairingCode = null,
                pairingInProgress = false,
            )

            ProxyState.FAILED -> state.copy(
                proxy = ProxyState.FAILED,
                startFailure = DemoState.START_FAILED,
                lastStop = StopReason.FAILED,
                lastStopAtMillis = nowMillis,
                offerRestart = false,
                authenticatedSessions = 0,
                lastTrafficAgeSeconds = null,
                pairingCode = null,
                pairingInProgress = false,
            )
        }

    fun requestPairing(state: DemoState, code: String): DemoState = state.copy(
        proxy = ProxyState.ON,
        startFailure = null,
        listenerReady = true,
        pairingCode = code,
        pairingInProgress = true,
        authenticatedSessions = 0,
        lastTrafficAgeSeconds = null,
    )

    fun allowPairing(state: DemoState, nowMillis: Long): DemoState {
        if (state.pairingCode == null && !state.pairingInProgress) return state
        val paired = state.copy(
            trustedCount = max(1, state.trustedCount),
            pairingCode = null,
            pairingInProgress = false,
            authenticatedSessions = 1,
            lastTrafficAgeSeconds = 0,
            listenerReady = true,
        )
        return addActivity(paired, "A target device was added.", nowMillis)
    }

    fun denyPairing(state: DemoState, nowMillis: Long): DemoState {
        if (state.pairingCode == null && !state.pairingInProgress) return state
        val denied = state.copy(pairingCode = null, pairingInProgress = false)
        return addActivity(denied, "A pairing request was denied.", nowMillis)
    }

    fun setPairingScenario(
        state: DemoState,
        activity: PairingActivity,
    ): DemoState = when (activity) {
        PairingActivity.NOT_PAIRED -> state.copy(
            trustedCount = 0,
            authenticatedSessions = 0,
            lastTrafficAgeSeconds = null,
            pairingCode = null,
            pairingInProgress = false,
        )

        PairingActivity.PAIRING -> state.copy(
            proxy = ProxyState.ON,
            startFailure = null,
            listenerReady = true,
            pairingCode = null,
            pairingInProgress = true,
            authenticatedSessions = 0,
            lastTrafficAgeSeconds = null,
        )

        PairingActivity.PAIRED -> state.copy(
            proxy = ProxyState.ON,
            trustedCount = max(1, state.trustedCount),
            authenticatedSessions = 0,
            lastTrafficAgeSeconds = null,
            pairingCode = null,
            pairingInProgress = false,
        )

        PairingActivity.IN_USE -> state.copy(
            proxy = ProxyState.ON,
            trustedCount = max(1, state.trustedCount),
            authenticatedSessions = 1,
            lastTrafficAgeSeconds = 0,
            pairingCode = null,
            pairingInProgress = false,
        )
    }

    fun forgetAll(state: DemoState, nowMillis: Long): DemoState {
        val cleared = state.copy(
            trustedCount = 0,
            authenticatedSessions = 0,
            lastTrafficAgeSeconds = null,
            pairingCode = null,
            pairingInProgress = false,
        )
        return if (state.trustedCount > 0 || state.pairingCode != null || state.pairingInProgress) {
            addActivity(cleared, "Paired target devices forgotten.", nowMillis)
        } else {
            cleared
        }
    }

    fun setNotifications(state: DemoState, status: NotificationStatus): DemoState =
        state.copy(notifications = status)

    fun setKeepAwake(state: DemoState, enabled: Boolean): DemoState =
        state.copy(keepAwake = enabled)

    fun setSimulatedLocationOff(state: DemoState, off: Boolean): DemoState =
        state.copy(simulatedLocationOff = off)

    fun setPortAutomatic(state: DemoState, automatic: Boolean): DemoState =
        state.copy(
            portAutomatic = automatic,
            port = if (automatic) DEFAULT_PORT else state.port,
        )

    fun setPortText(state: DemoState, text: String): DemoState =
        state.copy(
            portAutomatic = false,
            port = sanitizePort(text),
        )

    fun revealToken(state: DemoState, nowMillis: Long): DemoState = state.copy(
        tokenVisible = true,
        tokenRevealUntilMillis = nowMillis + TOKEN_REVEAL_SECONDS * 1000L,
    )

    fun hideToken(state: DemoState): DemoState =
        state.copy(tokenVisible = false, tokenRevealUntilMillis = null)

    fun expireToken(state: DemoState, nowMillis: Long): DemoState {
        val until = state.tokenRevealUntilMillis ?: return state
        return if (nowMillis >= until) hideToken(state) else state
    }

    fun rotateToken(state: DemoState): DemoState =
        hideToken(state).copy(token = newDemoToken())

    fun markCopied(state: DemoState, target: CopyTarget): DemoState =
        state.copy(copied = target)

    fun clearCopied(state: DemoState): DemoState =
        if (state.copied == null) state else state.copy(copied = null)

    fun addSampleEvent(state: DemoState, nowMillis: Long): DemoState {
        val message = SAMPLE_ACTIVITY[state.activity.size % SAMPLE_ACTIVITY.size]
        return addActivity(state, message, nowMillis)
    }

    fun addSampleDetail(state: DemoState): DemoState {
        val detail = SAMPLE_DETAILS[state.details.size % SAMPLE_DETAILS.size]
        return addDetail(state, detail)
    }

    fun clearActivity(state: DemoState): DemoState =
        state.copy(activity = emptyList(), details = emptyList())

    fun checkAddress(state: DemoState): DemoState =
        state.copy(addressChecks = state.addressChecks + 1)

    fun setLastStop(state: DemoState, reason: StopReason?, nowMillis: Long): DemoState =
        if (reason == null) {
            state.copy(lastStop = null, lastStopAtMillis = null, offerRestart = false)
        } else {
            state.copy(
                proxy = ProxyState.OFF,
                startFailure = null,
                authenticatedSessions = 0,
                lastTrafficAgeSeconds = null,
                pairingCode = null,
                pairingInProgress = false,
                lastStop = reason,
                lastStopAtMillis = nowMillis,
                offerRestart = reason == StopReason.APP_CLOSED,
                tokenVisible = false,
                tokenRevealUntilMillis = null,
            )
        }

    fun reset(state: DemoState): DemoState = DemoState(
        theme = state.theme,
        reduceMotion = state.reduceMotion,
    )

    /** Turn the simulated preview on or off. The real proxy is not affected. */
    fun setPreviewMode(state: DemoState, enabled: Boolean): DemoState =
        state.copy(previewMode = enabled)

    fun diagnosticsReport(state: DemoState): String = buildString {
        appendLine("HotspotShade Android demo")
        appendLine("Version: 0.1.0-demo")
        appendLine("State: ${state.statusTitle}")
        appendLine("Paired target devices: ${state.trustedCount}")
        appendLine("Connection attempts: simulated")
        appendLine("This report holds preview values only.")
    }

    fun formatTime(timeMillis: Long, locale: Locale = Locale.getDefault()): String {
        val zone = java.time.ZoneId.systemDefault()
        val time = java.time.Instant.ofEpochMilli(timeMillis).atZone(zone)
        return time.format(java.time.format.DateTimeFormatter.ofLocalizedTime(java.time.format.FormatStyle.SHORT).withLocale(locale))
    }
}
