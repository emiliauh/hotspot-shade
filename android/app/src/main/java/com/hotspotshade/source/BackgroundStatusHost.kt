package com.hotspotshade.source

import android.app.ActivityManager
import android.content.Context
import android.os.SystemClock
import com.hotspotshade.source.pairing.PairingCredentials
import com.hotspotshade.source.pairing.PairingIdentity
import com.hotspotshade.source.pairing.PairingListener
import com.hotspotshade.source.pairing.PairingPrompt
import com.hotspotshade.source.pairing.PairingProtocol
import com.hotspotshade.source.pairing.PairingResponder
import com.hotspotshade.source.pairing.PairingResponderMode
import com.hotspotshade.source.pairing.PairingServer
import com.hotspotshade.source.pairing.PairingTrustStore
import com.hotspotshade.source.pairing.ProxyStatus
import com.hotspotshade.source.pairing.SecureRandomPairingIdentity
import java.net.Inet4Address
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * Keep the authenticated status channel on TCP 18090 while the source proxy
 * runs in its foreground service and the activity is not visible.
 *
 * The activity owns the full pairing listener while it is visible. This host
 * takes over the same hotspot address and port only after the process leaves
 * the foreground and the controller reports a live bind. It stops the moment
 * either condition changes, so the pairing listener can bind again when the
 * person opens the app.
 *
 * The host is not a second control path. It uses the same [PairingResponder],
 * trust store, token, socket limits, and status format as the visible
 * listener, but the responder runs in [PairingResponderMode.STATUS_ONLY].
 * Only an authenticated status request from a target key that the app already
 * trusts can succeed. Pairing, re-pairing, and Forget are rejected before a
 * credential callback, prompt, or trust mutation. The prompt callback is a
 * second fail-closed layer: it denies at once without displaying, posting, or
 * logging a prompt.
 *
 * The listener binds only the controller's live hotspot address. It never
 * probes for a port and never binds the any-local address. It never writes a
 * route, a device, or a token. A listener belongs to one controller run and
 * one token epoch: a failed load, a changed run, a changed hotspot address, a
 * changed port, and a changed token all close it. A bind failure is retried on
 * the next tick while the run stays eligible.
 *
 * Transport v1 has one discovery and status port and no separate health
 * message. The target maps a refused connection to `not_running` and stops a
 * running tunnel after 90 seconds of continuous silence. A listener that only
 * accepts a socket, or that sends a plaintext answer, cannot reset that timer:
 * only an authenticated status answer can. This host therefore answers with
 * the real status exchange and keeps no plaintext fallback.
 */
internal class BackgroundStatusHost(
    private val binding: () -> SourceProxyBinding,
    private val visible: () -> Boolean,
    private val loadToken: () -> String?,
    private val trust: PairingTrustStore,
    private val identity: PairingIdentity,
    private val clock: () -> Long,
    /**
     * The process token epoch. One listener belongs to one epoch. A rotation
     * or reload moves the epoch, so the next tick closes the listener and
     * loads the store again instead of serving the old token.
     */
    private val tokenEpoch: () -> Long = { SourceTokenGuard.shared.epoch() },
    private val listenerFactory: (
        responder: PairingResponder,
        address: Inet4Address,
        port: Int,
        onPromptChanged: (PairingPrompt?) -> Unit,
    ) -> PairingListener,
    private val schedulerFactory: () -> ScheduledExecutorService = {
        Executors.newSingleThreadScheduledExecutor { runnable ->
            Thread(runnable, "background-status").apply { isDaemon = true }
        }
    },
    private val pollMillis: Long = POLL_MILLIS,
) {
    private val lock = Any()
    private var running = false
    private var generation = 0L
    private var scheduler: ScheduledExecutorService? = null
    private var listener: PairingListener? = null
    private var listenerAddress: Inet4Address? = null
    private var listenerPort: Int? = null
    private var listenerRunId: Long? = null
    private var listenerTokenEpoch: Long? = null

    /** Start the background check. A second call has no effect. */
    fun start() {
        val started = synchronized(lock) {
            if (running) return
            running = true
            generation += 1
            generation
        }
        hosts.add(this)
        if (pollMillis <= 0L) {
            runTickSafely(started)
            return
        }
        var executor: ScheduledExecutorService? = null
        try {
            // A factory failure rolls back like a failed schedule, so a later
            // start is not blocked by a host that never ran.
            val created = schedulerFactory()
            executor = created
            synchronized(lock) {
                if (!running || generation != started) {
                    created.shutdownNow()
                    return
                }
                scheduler = created
            }
            created.scheduleWithFixedDelay(
                { runTickSafely(started) },
                0L,
                pollMillis,
                TimeUnit.MILLISECONDS,
            )
        } catch (_: Exception) {
            synchronized(lock) {
                if (generation == started) {
                    running = false
                    generation += 1
                    scheduler = null
                }
            }
            hosts.remove(this)
            executor?.shutdownNow()
            closeListener()
        }
    }

    /**
     * Stop the background check and close the listener. This call is
     * idempotent and never starts a replacement listener.
     */
    fun stop() {
        hosts.remove(this)
        val active = synchronized(lock) {
            running = false
            generation += 1
            scheduler?.shutdownNow()
            scheduler = null
            listener.also {
                listener = null
                listenerAddress = null
                listenerPort = null
                listenerRunId = null
                listenerTokenEpoch = null
            }
        }
        active?.let(::closeQuietly)
    }

    /** Run one check now. A test uses this with a zero poll interval. */
    internal fun tickNow() {
        val current = synchronized(lock) {
            if (!running) return
            generation
        }
        runTickSafely(current)
    }

    private fun runTickSafely(expected: Long) {
        if (!isCurrent(expected)) return
        try {
            runTick(expected)
        } catch (_: Exception) {
            // A failed observation closes the listener. Do not keep a stale
            // answer on the pairing port after the run or token is unknown.
            closeListener(expected)
        }
    }

    private fun runTick(expected: Long) {
        if (!isCurrent(expected)) return
        val visibleNow = try {
            visible()
        } catch (_: Exception) {
            // An unknown visibility state keeps the visible listener's port.
            true
        }
        if (!isCurrent(expected)) return
        if (visibleNow) {
            closeListener(expected)
            return
        }
        val snapshot = try {
            binding()
        } catch (_: Exception) {
            closeListener(expected)
            return
        }
        if (!isCurrent(expected)) return
        val address = snapshot.address as? Inet4Address
        if (!eligible(snapshot) || address == null ||
            address.isAnyLocalAddress || address.isMulticastAddress
        ) {
            closeListener(expected)
            return
        }
        val epoch = currentEpoch()
        if (epoch == null) {
            closeListener(expected)
            return
        }
        val current = synchronized(lock) {
            listener != null &&
                listenerAddress == address &&
                listenerPort == snapshot.port &&
                listenerRunId == snapshot.runId &&
                listenerTokenEpoch == epoch &&
                listener?.isRunning() == true
        }
        if (current) return
        closeListener(expected)
        if (!isCurrent(expected)) return
        // The token is loaded only when a listener is created. The proxy run
        // refuses a rotation, so a live listener does not need a Keystore read
        // on every poll. A stop, a changed run or address, a changed token
        // epoch, a failed listener, and a return to the foreground all cause a
        // fresh load on the next bind.
        val token = try {
            loadToken()
        } catch (_: Exception) {
            null
        }
        if (!isCurrent(expected)) return
        if (token == null || !isUsableSourceToken(token)) return
        // The store load and the epoch must describe one token. A rotation or
        // reload that won the race would leave the loaded value stale.
        if (currentEpoch() != epoch) return
        val created = open(address, snapshot.port, token, snapshot.runId, epoch, expected) ?: return
        val keep = synchronized(lock) {
            if (!running || generation != expected || listener != null) {
                false
            } else {
                listener = created
                listenerAddress = address
                listenerPort = snapshot.port
                listenerRunId = snapshot.runId
                listenerTokenEpoch = epoch
                true
            }
        }
        if (!keep) closeQuietly(created)
    }

    private fun isCurrent(expected: Long): Boolean = synchronized(lock) {
        running && generation == expected
    }

    /** Read the token epoch, or null when the source cannot report it. */
    private fun currentEpoch(): Long? = try {
        tokenEpoch()
    } catch (_: Exception) {
        null
    }

    /**
     * Build one listener for one run, token, and token epoch.
     *
     * The listener answers status from the live controller binding. Every
     * credential and status build rechecks that the run identity, the address,
     * the port, and the token epoch still belong to this listener. A stopped,
     * restarted, or rotated run therefore gets REJECTED instead of an answer
     * built from the old run or the old token.
     *
     * The responder is in [PairingResponderMode.STATUS_ONLY]. It rejects
     * pairing, re-pairing, and Forget before a credential callback, prompt, or
     * trust mutation. The prompt callback is a second fail-closed layer: it
     * denies at once and never displays, posts, or logs a prompt.
     */
    private fun open(
        address: Inet4Address,
        port: Int,
        token: String,
        runId: Long,
        epoch: Long,
        hostGeneration: Long,
    ): PairingListener? {
        val credentialsForListener: () -> PairingCredentials? = {
            val live = try {
                binding()
            } catch (_: Exception) {
                null
            }
            val usable = isCurrent(hostGeneration) && live != null && eligible(live) &&
                live.address == address &&
                live.port == port &&
                live.runId == runId &&
                currentEpoch() == epoch
            if (!usable) {
                null
            } else {
                PairingCredentials.create(address, port, token)
            }
        }
        val statusFor: (PairingCredentials) -> ProxyStatus? = { credentials ->
            val live = try {
                binding()
            } catch (_: Exception) {
                null
            }
            if (!isCurrent(hostGeneration) || live == null || !eligible(live) ||
                live.address != credentials.host ||
                live.port != credentials.port ||
                live.runId != runId ||
                currentEpoch() != epoch
            ) {
                null
            } else {
                ProxyStatus(
                    proxyRunning = true,
                    foreground = try { visible() } catch (_: Exception) { false },
                    connections = live.connections.coerceIn(0, 65535),
                    port = credentials.port,
                    host = credentials.host,
                    sequence = 0,
                )
            }
        }
        val responder = PairingResponder(
            trust = trust,
            credentials = credentialsForListener,
            statusFor = statusFor,
            identity = identity,
            clock = clock,
            // Status-only mode never seals credentials. Return false anyway,
            // so a future path that bypasses the mode fails closed and never
            // writes a token from the background listener.
            commitToken = { false },
            mode = PairingResponderMode.STATUS_ONLY,
        )
        val holder = AtomicReference<PairingListener?>()
        val created = try {
            listenerFactory(responder, address, PairingProtocol.PAIRING_PORT) { prompt ->
                if (prompt != null) {
                    try {
                        holder.get()?.deny(prompt)
                    } catch (_: Exception) {
                        // A host failure must not keep a background prompt.
                    }
                }
            }
        } catch (_: Exception) {
            null
        } ?: return null
        holder.set(created)
        try {
            created.start()
            // Status-only mode should never create a prompt. Mark the listener
            // inactive and let the callback deny anything that unexpectedly
            // appears, so no background prompt can wait for a decision.
            created.deactivate()
        } catch (_: Exception) {
            closeQuietly(created)
            return null
        }
        return created
    }

    private fun eligible(binding: SourceProxyBinding): Boolean {
        if (!binding.active) return false
        if (binding.state != SourceProxyState.RUNNING &&
            binding.state != SourceProxyState.WAITING_FOR_NETWORK
        ) {
            return false
        }
        val address = binding.address as? Inet4Address ?: return false
        if (address.isAnyLocalAddress || address.isMulticastAddress) return false
        return binding.port in 1024..65535 && binding.port != PairingProtocol.PAIRING_PORT
    }

    private fun closeListener(expected: Long? = null) {
        val active = synchronized(lock) {
            if (expected != null && (!running || generation != expected)) return
            listener.also {
                listener = null
                listenerAddress = null
                listenerPort = null
                listenerRunId = null
                listenerTokenEpoch = null
            }
        }
        active?.let(::closeQuietly)
    }

    private fun closeQuietly(value: PairingListener) {
        try {
            value.close()
        } catch (_: Exception) {
            // The listener is already closing.
        }
    }

    internal companion object {
        private const val POLL_MILLIS = 500L

        // The activity tells the host directly that it now owns port 18090.
        // The process importance check lags the activity start by a tick, and a
        // visible listener that loses that race shows a failed bind.
        @Volatile
        private var activityHoldsPort = false
        private val hosts = java.util.concurrent.CopyOnWriteArraySet<BackgroundStatusHost>()

        /** The activity is starting. Mark the port as its own. Does not block. */
        fun activityStarted() {
            activityHoldsPort = true
        }

        /** Close every live host listener now. The caller runs off the main thread. */
        fun releasePortNow() {
            hosts.forEach { it.closeListener() }
        }

        /** The activity stopped. The host may take the port again. */
        fun activityStopped() {
            activityHoldsPort = false
        }

        /**
         * Build the production host.
         *
         * The service owns the host lifetime. The activity keeps its own
         * visible listener and does not call this class.
         */
        fun create(context: Context): BackgroundStatusHost {
            val app = context.applicationContext
            val tokenStore = SourceProxyRuntime.tokenStore(app)
            val trust = FilePairingTrustStore(
                java.io.File(app.noBackupFilesDir, "pairing-trust"),
                SourceProxyRuntime.preferences(app),
            )
            return BackgroundStatusHost(
                binding = { SourceProxyRuntime.binding() },
                visible = { activityHoldsPort || processVisible(app) },
                loadToken = { tokenStore.load() },
                trust = trust,
                identity = SecureRandomPairingIdentity(),
                clock = { SystemClock.elapsedRealtime() },
                listenerFactory = { responder, address, port, onPrompt ->
                    PairingServer(
                        responder = responder,
                        bindAddress = address,
                        port = port,
                        onPromptChanged = onPrompt,
                        onPairingSucceeded = {},
                        onTokenCommitFailed = {},
                    )
                },
            )
        }

        /**
         * True while this app process has a visible activity.
         *
         * The importance value avoids a dependency on the activity class, so
         * the service can start the host without touching the UI lifecycle.
         * A foreground service alone reports [ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND_SERVICE],
         * which is not visible. An unknown or failed read reports visible, so
         * the host never takes the port from a listener that may still be
         * showing a prompt.
         */
        private fun processVisible(context: Context): Boolean = try {
            val manager = context.getSystemService(ActivityManager::class.java)
            if (manager == null) {
                true
            } else {
                val info = ActivityManager.RunningAppProcessInfo()
                ActivityManager.getMyMemoryState(info)
                if (info.importance <= 0) {
                    true
                } else {
                    info.importance <=
                        ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND ||
                        info.importance ==
                        ActivityManager.RunningAppProcessInfo.IMPORTANCE_VISIBLE
                }
            }
        } catch (_: Exception) {
            true
        }
    }
}
