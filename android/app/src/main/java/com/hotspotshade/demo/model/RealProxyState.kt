package com.hotspotshade.demo.model

/**
 * The real source proxy phase, for the app UI.
 *
 * [WAITING_FOR_HOTSPOT] is a terminal state: the run ended because the hotspot
 * was not found. The person turns on the hotspot and taps Start again. The app
 * does not restart by itself.
 */
enum class RealProxyPhase {
    OFF,
    STARTING,
    WAITING_FOR_HOTSPOT,
    WAITING_FOR_CELLULAR,
    RUNNING,
    STOPPED,
}

/** The plain stop reason of the real source proxy. */
enum class RealStopReason {
    NONE,
    USER,
    NETWORK_LOST,
    CAPABILITIES_LOST,
    NETWORK_UNAVAILABLE,
    HOTSPOT_NOT_FOUND,
    HOTSPOT_LOST,
    BIND_FAILED,
    START_FAILED,
    TOKEN_MISSING,
    ;
    /** A short line for the last stop card. */
    val shortMessage: String
        get() = when (this) {
            NONE -> "The proxy stopped."
            USER -> "You stopped it."
            NETWORK_LOST -> "The cellular network is gone."
            CAPABILITIES_LOST -> "The cellular network changed."
            NETWORK_UNAVAILABLE -> "No cellular network is available."
            HOTSPOT_NOT_FOUND -> "The hotspot was not found."
            HOTSPOT_LOST -> "The hotspot is gone."
            BIND_FAILED -> "The proxy could not listen on the hotspot address."
            START_FAILED -> "The proxy could not start."
            TOKEN_MISSING -> "No source token is stored."
        }

    /** A full sentence for the status card. */
    val message: String
        get() = when (this) {
            NONE -> "The proxy stopped."
            USER -> "You stopped the proxy."
            NETWORK_LOST -> "The cellular network is gone. The proxy stopped."
            CAPABILITIES_LOST -> "The cellular network changed. The proxy stopped."
            NETWORK_UNAVAILABLE -> "No cellular network is available. The proxy stopped."
            HOTSPOT_NOT_FOUND -> "Turn on the hotspot, then tap Start again."
            HOTSPOT_LOST -> "The hotspot is gone. The proxy stopped."
            BIND_FAILED ->
                "The proxy could not listen on the hotspot address. Tap Start to try again."
            START_FAILED -> "The proxy could not start. Tap Start to try again."
            TOKEN_MISSING -> "Pair first. No source token is stored."
        }
}

/**
 * One real source proxy state for the app UI.
 *
 * The state holds counts and plain text. It holds no token, address, or host.
 */
data class RealProxyState(
    val phase: RealProxyPhase = RealProxyPhase.OFF,
    val stopReason: RealStopReason = RealStopReason.NONE,
    val port: Int = 0,
    val connections: Int = 0,
    val totalConnections: Long = 0,
    val stoppedAtMillis: Long? = null,
) {
    /** True while a start waits for the network or the proxy serves flows. */
    val active: Boolean
        get() = phase == RealProxyPhase.STARTING ||
            phase == RealProxyPhase.WAITING_FOR_CELLULAR ||
            phase == RealProxyPhase.RUNNING

    /** True only while the proxy serves flows. */
    val running: Boolean get() = phase == RealProxyPhase.RUNNING

    /** The Dashboard title. */
    val statusTitle: String
        get() = when (phase) {
            RealProxyPhase.OFF -> "Off"
            RealProxyPhase.STARTING -> "Starting"
            RealProxyPhase.WAITING_FOR_HOTSPOT -> "Waiting for the hotspot"
            RealProxyPhase.WAITING_FOR_CELLULAR -> "Waiting for the cellular network"
            RealProxyPhase.RUNNING -> "On"
            RealProxyPhase.STOPPED -> when (stopReason) {
                RealStopReason.TOKEN_MISSING -> "Pair first"
                RealStopReason.USER, RealStopReason.NONE -> "Off"
                else -> "Needs attention"
            }
        }

    /** The Dashboard message. */
    val statusMessage: String
        get() = when (phase) {
            RealProxyPhase.OFF ->
                "Start the proxy when your target device is connected to your hotspot."
            RealProxyPhase.STARTING -> "Starting the source proxy."
            RealProxyPhase.WAITING_FOR_HOTSPOT -> "Turn on the hotspot, then tap Start again."
            RealProxyPhase.WAITING_FOR_CELLULAR ->
                "The hotspot is ready. Waiting for the cellular network."
            RealProxyPhase.RUNNING -> "Target devices can connect through the hotspot."
            RealProxyPhase.STOPPED -> stopReason.message
        }

    /** The status mark and tone. */
    val statusKind: StatusKind
        get() = when (phase) {
            RealProxyPhase.OFF -> StatusKind.OFF
            RealProxyPhase.STARTING,
            RealProxyPhase.WAITING_FOR_CELLULAR,
            -> StatusKind.STARTING
            RealProxyPhase.WAITING_FOR_HOTSPOT -> StatusKind.ATTENTION
            RealProxyPhase.RUNNING -> StatusKind.ON
            RealProxyPhase.STOPPED -> when (stopReason) {
                RealStopReason.USER, RealStopReason.NONE -> StatusKind.OFF
                else -> StatusKind.ATTENTION
            }
        }

    /** The primary button label. */
    val actionTitle: String get() = if (active) "Stop" else "Start"

    /** The usage card title. */
    val usageTitle: String
        get() = if (running && connections > 0) {
            "Target device connected"
        } else {
            "Waiting for your target device."
        }

    /** The usage card summary for one trusted target count. */
    fun usageSummary(trustedTargets: Int): String = when {
        running && connections > 0 -> "A target device is using the proxy now."
        trustedTargets <= 0 ->
            "Not paired. Open HotspotShade on your target device to pair."
        running -> "${pairedText(trustedTargets)} The proxy is ready."
        else -> pairedText(trustedTargets)
    }

    /** The real connection lines, or an empty list when the proxy is off. */
    val connectionLines: List<String>
        get() = if (running) {
            listOf(
                "Open connections: $connections.",
                "Connections since start: $totalConnections.",
            )
        } else {
            emptyList()
        }

    /** The Advanced port value. */
    val portText: String get() = if (port > 0) "$port" else "Chosen when the proxy starts."

    /** The last stop line, or null when no run has stopped. */
    val lastStopText: String?
        get() = if (phase == RealProxyPhase.STOPPED && stopReason != RealStopReason.NONE) {
            "Last stop: ${stopReason.shortMessage}"
        } else {
            null
        }

    /** The diagnostics report. It holds counts and states only. */
    fun diagnosticsReport(listener: String): String = buildString {
        appendLine("HotspotShade for Android")
        appendLine("Version: 0.1.0-demo")
        appendLine("State: $statusTitle")
        appendLine("Stop reason: ${stopReason.name.lowercase()}")
        appendLine("Open connections: $connections")
        appendLine("Connections since start: $totalConnections")
        appendLine("Proxy port: $portText")
        appendLine("Pairing listener: $listener")
        appendLine("This report holds counts and states only.")
        appendLine("It holds no address, host, token, key, or website.")
    }

    companion object {
        fun pairedText(count: Int): String = if (count == 1) {
            "Paired with 1 target device."
        } else {
            "Paired with $count target devices."
        }
    }
}
