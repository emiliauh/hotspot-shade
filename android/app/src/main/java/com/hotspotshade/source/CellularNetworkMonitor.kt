package com.hotspotshade.source

import java.io.Closeable
import java.io.IOException

/**
 * Select one eligible cellular network for the source service. The platform
 * adapter uses ConnectivityManager. A JVM test uses a fake. The selection
 * reports the selected network and its loss through a listener.
 */
internal interface CellularNetworkSelection {
    /** Start selection. Use one listener for this selection. */
    fun start(listener: Listener)

    /** Stop selection and release the platform request. This call is idempotent. */
    fun stop()

    interface Listener {
        /** The selection found a cellular network that can carry traffic. */
        fun onAvailable(binding: CellularBinding)

        /** The selected network is gone. */
        fun onLost()

        /** The selected network lost a required capability. */
        fun onCapabilitiesLost()

        /** The platform did not select an eligible network. */
        fun onUnavailable()
    }
}

/**
 * Own the cellular session for one selected network.
 *
 * The monitor opens one session for one eligible network. It closes that
 * session when the network is lost, when a required capability is lost, or
 * when the service closes the monitor. It never opens a second session. The
 * service must create a new monitor for a new start that the user requests.
 *
 * Callbacks can arrive on a connectivity thread. The monitor is safe to call
 * from more than one thread. A socket close failure does not throw from
 * [close]. Read [closeFailure] and call [close] again to retry the close.
 */
internal class CellularNetworkMonitor(
    private val selection: CellularNetworkSelection,
    private val openSession: (CellularBinding) -> CellularSession = { binding ->
        CellularSession(CellularSockets(binding))
    },
) : Closeable {
    enum class State { IDLE, SELECTING, OPEN, STOPPED }

    enum class StopReason { NONE, SERVICE_STOP, NETWORK_LOST, CAPABILITIES_LOST, UNAVAILABLE }

    private val lock = Any()
    private var phase = State.IDLE
    private var reason = StopReason.NONE
    private var session: CellularSession? = null
    private var closeFailureValue: IOException? = null

    val state: State
        get() = synchronized(lock) { phase }

    val stopReason: StopReason
        get() = synchronized(lock) { reason }

    /** The last socket close failure, or null after a complete close. */
    val closeFailure: IOException?
        get() = synchronized(lock) { closeFailureValue }

    /** Start one selection. Call this method one time. */
    fun start() {
        synchronized(lock) {
            check(phase == State.IDLE) { "The cellular network monitor can start only once." }
            phase = State.SELECTING
            // Keep the lock. A concurrent close cannot release the request before it registers.
            selection.start(listener)
        }
    }

    override fun close() = finish(StopReason.SERVICE_STOP)

    private val listener = object : CellularNetworkSelection.Listener {
        override fun onAvailable(binding: CellularBinding) {
            try {
                synchronized(lock) {
                    if (phase != State.SELECTING) return
                    session = openSession(binding)
                    phase = State.OPEN
                }
            } catch (_: Exception) {
                finish(StopReason.UNAVAILABLE)
            }
        }

        override fun onLost() = finish(StopReason.NETWORK_LOST)

        override fun onCapabilitiesLost() = finish(StopReason.CAPABILITIES_LOST)

        override fun onUnavailable() = finish(StopReason.UNAVAILABLE)
    }

    private fun finish(reason: StopReason) {
        var stopSelection = false
        val pending = synchronized(lock) {
            if (phase != State.STOPPED) {
                phase = State.STOPPED
                this.reason = reason
                stopSelection = true
            }
            // Keep a session that failed to close. A second close can retry it.
            session
        }
        if (pending == null) {
            if (stopSelection) selection.stop()
            return
        }
        try {
            pending.close()
            synchronized(lock) {
                if (session === pending) session = null
                closeFailureValue = null
            }
        } catch (failure: IOException) {
            synchronized(lock) { closeFailureValue = failure }
        } finally {
            if (stopSelection) selection.stop()
        }
    }
}
