package com.hotspotshade.source

import java.io.Closeable
import java.io.IOException
import java.net.InetAddress

/** The state of one source proxy run. */
internal enum class SourceProxyState {
    IDLE,
    WAITING_FOR_NETWORK,
    RUNNING,
    STOPPED,
}

/** Why a source proxy run ended. NONE holds until it ends. */
internal enum class SourceProxyStopReason {
    NONE,
    USER_STOP,
    NETWORK_LOST,
    CAPABILITIES_LOST,
    NETWORK_UNAVAILABLE,
    HOTSPOT_NOT_FOUND,
    HOTSPOT_LOST,
    BIND_FAILED,
    START_FAILED,
    TOKEN_MISSING,
}

/** One state report. It holds no token, address, or host. */
internal data class SourceProxySnapshot(
    val state: SourceProxyState,
    val reason: SourceProxyStopReason,
    val port: Int,
)

/** One source listener. The controller closes it on every exit path. */
internal interface SourceServerHandle : Closeable {
    /** The bound TCP port, or 0 before a successful start. */
    val localPort: Int

    /** The open relay count. It holds no address or host. */
    val activeConnections: Int

    /** The relay count since the start. It holds no address or host. */
    val totalConnections: Long

    /** Bind the listener. */
    fun start()
}

/** The service receives each state change. A callback can arrive on a network thread. */
internal fun interface SourceProxyListener {
    fun onStateChanged(snapshot: SourceProxySnapshot)
}

/**
 * Run one source proxy: wait for the cellular network, bind the hotspot
 * address, and stop on every loss.
 *
 * The controller never restarts itself. A stopped controller cannot start
 * again. The service creates a new controller only for a new start that the
 * user requests.
 *
 * The listener receives the terminal state one time. A callback can arrive on
 * a connectivity thread. The listener must not block.
 */
internal class SourceProxyController(
    private val tokenStore: TokenStore,
    private val hotspotFinder: HotspotAddressFinder,
    private val selectionFactory: () -> CellularNetworkSelection,
    private val resolverFactory: (CellularBinding) -> SourceHostResolver,
    private val echoFactory: (CellularBinding) -> SourceEchoSender,
    private val serverFactory: (
        CellularSession,
        SourceHostResolver,
        SourceEchoSender,
        InetAddress,
        String
    ) -> SourceServerHandle,
    private val watchFactory: (InetAddress) -> HotspotWatch,
    private val listener: SourceProxyListener,
) {
    private val lock = Any()
    private var phase = SourceProxyState.IDLE
    private var reason = SourceProxyStopReason.NONE
    private var token: String? = null
    private var monitor: CellularNetworkMonitor? = null
    private var server: SourceServerHandle? = null
    private var watch: HotspotWatch? = null
    private var port = 0
    private var closeFailureValue: IOException? = null

    /** The current state. */
    val state: SourceProxyState
        get() = synchronized(lock) { phase }

    /** The reason of the terminal state, or NONE. */
    val stopReason: SourceProxyStopReason
        get() = synchronized(lock) { reason }

    /** The bound port, or 0 when the proxy is not running. */
    val localPort: Int
        get() = synchronized(lock) { port }

    /** The open relay count, or 0 when the proxy is not running. */
    val connectionCount: Int
        get() = synchronized(lock) { server?.activeConnections ?: 0 }

    /** The relay count since the start, or 0 when the proxy is not running. */
    val totalConnections: Long
        get() = synchronized(lock) { server?.totalConnections ?: 0L }

    /** True while the run waits for a network or serves flows. */
    val isActive: Boolean
        get() = synchronized(lock) {
            phase == SourceProxyState.WAITING_FOR_NETWORK || phase == SourceProxyState.RUNNING
        }

    /** The last cellular socket close failure, or null after a complete close. */
    val closeFailure: IOException?
        get() = synchronized(lock) { closeFailureValue }

    /**
     * Start one run. Return false when this controller cannot start.
     *
     * A second call returns false. The method reports a terminal snapshot
     * when the token is missing or the hotspot is not present.
     */
    fun start(): Boolean {
        var initial: SourceProxySnapshot? = null
        var startMonitor = false
        synchronized(lock) {
            if (phase != SourceProxyState.IDLE) return false
            val hotspot = try {
                hotspotFinder.findHotspotAddress()
            } catch (_: Exception) {
                null
            }
            if (hotspot == null) {
                phase = SourceProxyState.STOPPED
                reason = SourceProxyStopReason.HOTSPOT_NOT_FOUND
                initial = snapshotLocked()
            } else {
                val stored = try {
                    tokenStore.load()
                } catch (_: Exception) {
                    null
                }
                if (stored.isNullOrEmpty()) {
                    phase = SourceProxyState.STOPPED
                    reason = SourceProxyStopReason.TOKEN_MISSING
                    initial = snapshotLocked()
                } else {
                    token = stored
                    phase = SourceProxyState.WAITING_FOR_NETWORK
                    initial = snapshotLocked()
                    try {
                        val selection = ObservingSelection(selectionFactory()) { event ->
                            onNetworkStopped(event)
                        }
                        monitor = CellularNetworkMonitor(selection, ::openSession)
                        startMonitor = true
                    } catch (_: Exception) {
                        token = null
                        phase = SourceProxyState.STOPPED
                        reason = SourceProxyStopReason.START_FAILED
                        initial = snapshotLocked()
                    }
                }
            }
        }
        val report = initial ?: return false
        listener.onStateChanged(report)
        if (!startMonitor) return false
        return try {
            monitor?.start()
            synchronized(lock) {
                phase == SourceProxyState.WAITING_FOR_NETWORK || phase == SourceProxyState.RUNNING
            }
        } catch (_: Exception) {
            finish(SourceProxyStopReason.START_FAILED)
            false
        }
    }

    /** Stop the run and close every owned resource. This call is idempotent. */
    fun stop() = finish(SourceProxyStopReason.USER_STOP)

    private fun openSession(binding: CellularBinding): CellularSession {
        val session = CellularSession(CellularSockets(binding))
        try {
            val hotspot = hotspotFinder.findHotspotAddress()
            if (hotspot == null) {
                finish(SourceProxyStopReason.HOTSPOT_NOT_FOUND)
                throw IOException("Hotspot not found.")
            }
            val tokenValue = synchronized(lock) { token }
            if (tokenValue == null) {
                finish(SourceProxyStopReason.TOKEN_MISSING)
                throw IOException("The source token is not available.")
            }
            val resolver = try {
                resolverFactory(binding)
            } catch (_: Exception) {
                finish(SourceProxyStopReason.START_FAILED)
                throw IOException("The resolver could not start.")
            }
            val echo = try {
                echoFactory(binding)
            } catch (_: Exception) {
                finish(SourceProxyStopReason.START_FAILED)
                throw IOException("The echo path could not start.")
            }
            val newServer = try {
                serverFactory(session, resolver, echo, hotspot, tokenValue)
            } catch (_: Exception) {
                finish(SourceProxyStopReason.START_FAILED)
                throw IOException("The server could not start.")
            }
            try {
                newServer.start()
            } catch (_: Exception) {
                closeQuietly(newServer)
                finish(SourceProxyStopReason.BIND_FAILED)
                throw IOException("The listener could not bind.")
            }
            val newWatch = try {
                watchFactory(hotspot)
            } catch (_: Exception) {
                closeQuietly(newServer)
                finish(SourceProxyStopReason.START_FAILED)
                throw IOException("The hotspot watch could not start.")
            }
            try {
                newWatch.start { onHotspotLost() }
            } catch (_: Exception) {
                newWatch.stop()
                closeQuietly(newServer)
                finish(SourceProxyStopReason.START_FAILED)
                throw IOException("The hotspot watch could not start.")
            }
            val running: SourceProxySnapshot
            synchronized(lock) {
                if (phase != SourceProxyState.WAITING_FOR_NETWORK) {
                    // A stop raced with the setup. Close the new resources.
                    newWatch.stop()
                    closeQuietly(newServer)
                    throw IOException("The proxy stopped during setup.")
                }
                server = newServer
                watch = newWatch
                port = newServer.localPort
                token = null
                phase = SourceProxyState.RUNNING
                running = snapshotLocked()
            }
            listener.onStateChanged(running)
            return session
        } catch (failure: Exception) {
            closeQuietly(session)
            throw failure
        }
    }

    private fun onHotspotLost() {
        finish(SourceProxyStopReason.HOTSPOT_LOST)
    }

    private fun onNetworkStopped(event: SourceProxyStopReason) {
        finish(event)
    }

    private fun finish(newReason: SourceProxyStopReason) {
        var stopServer: SourceServerHandle? = null
        var stopWatch: HotspotWatch? = null
        var stopMonitor: CellularNetworkMonitor? = null
        var stoppedSnapshot: SourceProxySnapshot? = null
        var transitioned = false
        synchronized(lock) {
            if (phase == SourceProxyState.IDLE ||
                phase == SourceProxyState.WAITING_FOR_NETWORK ||
                phase == SourceProxyState.RUNNING
            ) {
                phase = SourceProxyState.STOPPED
                reason = newReason
                transitioned = true
                token = null
                port = 0
                stopServer = server
                server = null
                stopWatch = watch
                watch = null
                stoppedSnapshot = snapshotLocked()
            }
            // Retry a monitor close after a reported failure. Do not notify again.
            stopMonitor = monitor
            monitor = null
        }
        if (!transitioned && stopMonitor == null) return
        try {
            stopWatch?.stop()
        } catch (_: Exception) {
            // The watch is already ending.
        }
        try {
            stopServer?.close()
        } catch (_: Exception) {
            // The server is already ending.
        }
        var failure: IOException? = null
        try {
            stopMonitor?.close()
        } catch (closeFailure: IOException) {
            failure = closeFailure
        } catch (_: Exception) {
            failure = IOException("The cellular session did not close.")
        }
        synchronized(lock) {
            closeFailureValue = failure
            if (failure != null) monitor = stopMonitor
        }
        if (transitioned && stoppedSnapshot != null) {
            listener.onStateChanged(stoppedSnapshot)
        }
    }

    private fun snapshotLocked() = SourceProxySnapshot(phase, reason, port)

    private fun closeQuietly(closeable: Closeable?) {
        if (closeable == null) return
        try {
            closeable.close()
        } catch (_: Exception) {
            // The resource is already ending.
        }
    }

    /**
     * Forward network events to the monitor and to the controller.
     *
     * The monitor must see each event first. It closes the cellular session
     * before the controller stops the server.
     */
    private class ObservingSelection(
        private val delegate: CellularNetworkSelection,
        private val onStopped: (SourceProxyStopReason) -> Unit,
    ) : CellularNetworkSelection {
        private val lock = Any()
        private var listener: CellularNetworkSelection.Listener? = null
        private var stopped = false
        private var reported = false

        override fun start(listener: CellularNetworkSelection.Listener) {
            synchronized(lock) { this.listener = listener }
            delegate.start(forwarder)
        }

        override fun stop() {
            val first = synchronized(lock) {
                if (stopped) {
                    false
                } else {
                    stopped = true
                    true
                }
            }
            if (first) delegate.stop()
        }

        private val forwarder = object : CellularNetworkSelection.Listener {
            override fun onAvailable(binding: CellularBinding) {
                listener?.onAvailable(binding)
            }

            override fun onLost() {
                listener?.onLost()
                report(SourceProxyStopReason.NETWORK_LOST)
            }

            override fun onCapabilitiesLost() {
                listener?.onCapabilitiesLost()
                report(SourceProxyStopReason.CAPABILITIES_LOST)
            }

            override fun onUnavailable() {
                listener?.onUnavailable()
                report(SourceProxyStopReason.NETWORK_UNAVAILABLE)
            }

            private fun report(event: SourceProxyStopReason) {
                val fire = synchronized(lock) {
                    if (reported) {
                        false
                    } else {
                        reported = true
                        true
                    }
                }
                if (fire) onStopped(event)
            }
        }
    }
}
