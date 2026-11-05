package com.hotspotshade.source

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.SystemClock
import androidx.core.content.ContextCompat
import com.hotspotshade.source.pairing.PairingCredentials
import com.hotspotshade.source.pairing.PairingIdentity
import com.hotspotshade.source.pairing.PairingPrompt
import com.hotspotshade.source.pairing.PairingProtocol
import com.hotspotshade.source.pairing.PairingResponder
import com.hotspotshade.source.pairing.PairingServer
import com.hotspotshade.source.pairing.PairingTrustStore
import com.hotspotshade.source.pairing.ProxyStatus
import com.hotspotshade.source.pairing.SecureRandomPairingIdentity
import java.security.SecureRandom
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit

/** The state of the real pairing listener. */
internal enum class PairingListenerState {
    STOPPED,
    NO_HOTSPOT,
    LISTENING,
    FAILED,
}

/**
 * Run the real pairing listener while the app is open.
 *
 * The coordinator finds the hotspot address, creates a responder with the
 * current proxy credentials, and binds TCP port 18090 on that address only. A
 * hotspot change closes the old listener and binds the new address. A stop
 * closes the listener and every connection.
 *
 * The token is stored in memory until a pairing succeeds. A successful pairing
 * saves it with [TokenWriter], so the source proxy start finds a token instead
 * of `TOKEN_MISSING`.
 */
internal class PairingCoordinator(
    private val finder: HotspotAddressFinder,
    private val tokenStore: TokenStore,
    private val tokenWriter: TokenWriter,
    private val trust: PairingTrustStore,
    private val ports: ProxyPortPolicy,
    private val onPrompt: (PairingPrompt?) -> Unit,
    private val onState: (PairingListenerState, Int) -> Unit,
    private val clock: () -> Long = { SystemClock.elapsedRealtime() },
    private val identity: PairingIdentity = SecureRandomPairingIdentity(),
    private val random: SecureRandom = SecureRandom(),
    private val pairingPort: Int = com.hotspotshade.source.pairing.PairingProtocol.PAIRING_PORT,
    private val schedulerFactory: () -> ScheduledExecutorService = {
        Executors.newSingleThreadScheduledExecutor { runnable ->
            Thread(runnable, "pairing-coordinator").apply { isDaemon = true }
        }
    },
) {
    /** The bound pairing port, or 0 when the listener is off. */
    val localPort: Int
        get() = synchronized(lock) { server?.localPort ?: 0 }
    private val lock = Any()
    private var scheduler: ScheduledExecutorService? = null
    private var server: PairingServer? = null
    private var address: java.net.InetAddress? = null
    private var token: String? = null
    private var running = false
    private var state = PairingListenerState.STOPPED

    /** Start the listener and the periodic hotspot check. */
    fun start() {
        synchronized(lock) {
            if (running) return
            running = true
            token = loadToken()
        }
        val executor = schedulerFactory()
        synchronized(lock) { scheduler = executor }
        executor.scheduleWithFixedDelay(
            { refresh() },
            0L,
            REFRESH_MILLIS,
            TimeUnit.MILLISECONDS,
        )
    }

    /** Stop the listener and every connection. This call is idempotent. */
    fun stop() {
        val executor: ScheduledExecutorService?
        val active: PairingServer?
        synchronized(lock) {
            if (!running) return
            running = false
            executor = scheduler
            scheduler = null
            active = server
            server = null
            address = null
            token = null
        }
        executor?.shutdownNow()
        active?.close()
        publish(PairingListenerState.STOPPED)
    }

    /** Approve the prompt that the person saw. */
    fun allow(prompt: PairingPrompt) {
        synchronized(lock) { server }?.allow(prompt)
        publishCurrentState()
    }

    /** Deny the prompt that the person saw. */
    fun deny(prompt: PairingPrompt) {
        synchronized(lock) { server }?.deny(prompt)
        publishCurrentState()
    }

    /** Mark the app as visible. */
    fun activate() {
        synchronized(lock) { server }?.activate()
    }

    /** Mark the app as hidden. A live prompt gets a bounded extension. */
    fun deactivate() {
        synchronized(lock) { server }?.deactivate()
    }

    /**
     * Load the stored token again and rebind the listener.
     *
     * The app calls this method after a token rotation. The listener keeps the
     * hotspot address and binds a new server with the new token.
     */
    fun reloadToken() {
        var close: PairingServer? = null
        val restart = synchronized(lock) {
            token = loadToken()
            close = server
            server = null
            running
        }
        close?.close()
        if (restart) refresh()
    }

    /** Publish the trusted target count after a forget action. */
    fun trustChanged() {
        publishCurrentState()
    }

    private fun refresh() {
        val hotspot = try {
            finder.findHotspotAddress()
        } catch (_: Exception) {
            null
        }
        var close: PairingServer? = null
        var createFor: java.net.InetAddress? = null
        var publish: PairingListenerState = PairingListenerState.STOPPED
        synchronized(lock) {
            if (!running) return
            if (hotspot == null) {
                close = server
                server = null
                address = null
                state = PairingListenerState.NO_HOTSPOT
                publish = state
            } else if (server != null && address == hotspot) {
                publish = state
            } else {
                close = server
                server = null
                address = hotspot
                createFor = hotspot
            }
        }
        close?.close()
        if (createFor != null) create(createFor)
        if (publish != PairingListenerState.STOPPED) publish(publish)
    }

    private fun create(hotspot: java.net.InetAddress) {
        val currentToken: String
        synchronized(lock) {
            if (!running || address != hotspot) return
            currentToken = token ?: loadToken().also { token = it }
        }
        val proxyPort = try {
            ports.current(hotspot)
        } catch (_: Exception) {
            0
        }
        val credentials = PairingCredentials.create(hotspot, proxyPort, currentToken)
        if (credentials == null) {
            publish(PairingListenerState.FAILED)
            return
        }
        val responder = PairingResponder(
            trust = trust,
            credentials = { credentials },
            status = { currentStatus(hotspot, credentials) },
            identity = identity,
            clock = clock,
        )
        val newServer = PairingServer(
            responder = responder,
            bindAddress = hotspot,
            port = pairingPort,
            onPromptChanged = onPrompt,
            onPairingSucceeded = { saveToken() },
        )
        responder.activate()
        try {
            newServer.start()
        } catch (_: Exception) {
            try {
                newServer.close()
            } catch (_: Exception) {
                // The listener did not start.
            }
            publish(PairingListenerState.FAILED)
            return
        }
        synchronized(lock) {
            if (!running || address != hotspot) {
                // A stop or a hotspot change raced with the bind. Do not leave
                // the listener running.
                newServer.close()
                return
            }
            server = newServer
            state = PairingListenerState.LISTENING
        }
        publish(PairingListenerState.LISTENING)
    }

    private fun currentStatus(
        hotspot: java.net.InetAddress,
        credentials: PairingCredentials,
    ): ProxyStatus {
        val observation = SourceProxyRuntime.observation()
        val running = observation.state == SourceProxyState.RUNNING
        val bound = observation.port
        return ProxyStatus(
            proxyRunning = running,
            foreground = true,
            connections = if (running) observation.connections else 0,
            port = if (running && bound > 0) bound else credentials.port,
            host = hotspot as? java.net.Inet4Address ?: credentials.host,
            sequence = 0,
        )
    }

    private fun saveToken() {
        val value = synchronized(lock) { token } ?: return
        try {
            tokenWriter.save(value)
        } catch (_: Exception) {
            // The pairing result already left the device. The next start
            // reports TOKEN_MISSING, and the person can pair again.
        }
        publishCurrentState()
    }

    private fun loadToken(): String {
        val stored = try {
            tokenStore.load()
        } catch (_: Exception) {
            null
        }
        if (stored != null && isUsableToken(stored)) return stored
        return newToken()
    }

    private fun newToken(): String {
        val bytes = ByteArray(32)
        random.nextBytes(bytes)
        return PairingProtocol.hex(bytes)
    }

    private fun isUsableToken(token: String): Boolean =
        token.isNotEmpty() && token.length <= 255 && token.all { it.code in 0x21..0x7E }

    private fun publishCurrentState() {
        val current = synchronized(lock) { state }
        publish(current)
    }

    private fun publish(value: PairingListenerState) {
        synchronized(lock) { state = value }
        onState(value, trust.count)
    }

    private companion object {
        const val REFRESH_MILLIS = 3_000L
    }
}

/** Build the production pairing coordinator. Return null without network permission. */
internal object PairingRuntime {
    fun coordinator(
        context: Context,
        onPrompt: (PairingPrompt?) -> Unit,
        onState: (PairingListenerState, Int) -> Unit,
    ): PairingCoordinator? {
        if (ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.ACCESS_NETWORK_STATE,
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            return null
        }
        val preferences = SourceProxyRuntime.preferences(context)
        val store = SourceProxyRuntime.tokenStore(context)
        @Suppress("MissingPermission")
        val finder = SourceProxyRuntime.hotspotFinder(context)
        return PairingCoordinator(
            finder = finder,
            tokenStore = store,
            tokenWriter = store,
            trust = SharedPreferencesPairingTrustStore(preferences),
            ports = ProxyPortPolicy(SharedPreferencesProxyPortStore(preferences)),
            onPrompt = onPrompt,
            onState = onState,
        )
    }

    /** Build the admin actions for the real trust list and the source token. */
    fun admin(context: Context): PairingAdmin = PairingAdmin(
        trust = SharedPreferencesPairingTrustStore(SourceProxyRuntime.preferences(context)),
        tokenStore = SourceProxyRuntime.tokenStore(context),
    )
}
