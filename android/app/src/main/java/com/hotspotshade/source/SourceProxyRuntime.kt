package com.hotspotshade.source

import android.Manifest
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import androidx.annotation.RequiresPermission
import java.io.File
import java.io.IOException
import java.net.InetAddress

/** The dependencies of one source proxy run. A test supplies fakes. */
internal class SourceProxyEnvironment(
    val tokenStore: TokenStore,
    val hotspotFinder: HotspotAddressFinder,
    val selectionFactory: () -> CellularNetworkSelection,
    val resolverFactory: (CellularBinding) -> SourceHostResolver,
    val echoFactory: (CellularBinding) -> SourceEchoSender,
    val serverFactory: (
        CellularSession,
        SourceHostResolver,
        SourceEchoSender,
        InetAddress,
        String
    ) -> SourceServerHandle,
    val watchFactory: (InetAddress) -> HotspotWatch,
)

/** One state report for the app UI. It holds no token, address, or host. */
internal data class SourceProxyObservation(
    val state: SourceProxyState,
    val reason: SourceProxyStopReason,
    val port: Int,
    val connections: Int,
    val totalConnections: Long,
    val stoppedAtMillis: Long?,
)

/**
 * Build the production environment and hold the test-only override.
 *
 * The override is internal and needs code in this app process. It carries no
 * secret. The service uses it only when an instrumented test installs it.
 *
 * The service reports each state change here. The app reads [observation] to
 * show the real state. The report holds counts only. It never holds the token,
 * a local address, or a host name.
 */
internal object SourceProxyRuntime {
    private const val TOKEN_FILE_NAME = "source-token.bin"
    private const val PREFERENCES_NAME = "hotspotshade-source"

    @Volatile
    private var testEnvironment: SourceProxyEnvironment? = null

    private val lock = Any()
    private var lastStateValue: SourceProxyState = SourceProxyState.IDLE
    private var lastStopReasonValue: SourceProxyStopReason = SourceProxyStopReason.NONE
    private var lastPortValue: Int = 0
    private var stoppedAtValue: Long? = null
    private var activeController: SourceProxyController? = null

    /** The last reported state. */
    val lastState: SourceProxyState
        get() = synchronized(lock) { lastStateValue }

    /** The last reported stop reason. */
    val lastStopReason: SourceProxyStopReason
        get() = synchronized(lock) { lastStopReasonValue }

    /** The last reported bound port. */
    val lastPort: Int
        get() = synchronized(lock) { lastPortValue }

    /** Return the current report for the app UI. */
    fun observation(): SourceProxyObservation = synchronized(lock) {
        SourceProxyObservation(
            state = lastStateValue,
            reason = lastStopReasonValue,
            port = lastPortValue,
            connections = activeController?.connectionCount ?: 0,
            totalConnections = activeController?.totalConnections ?: 0L,
            stoppedAtMillis = stoppedAtValue,
        )
    }

    /** Attach the controller that serves the current run, or null after it ends. */
    fun attach(controller: SourceProxyController?) {
        synchronized(lock) { activeController = controller }
    }

    /**
     * Clear the previous run report before a new start request.
     *
     * The app calls this method only when no run is active. It keeps the
     * attached controller, so a second start request cannot hide a live run.
     */
    fun requestStart() {
        synchronized(lock) {
            lastStateValue = SourceProxyState.IDLE
            lastStopReasonValue = SourceProxyStopReason.NONE
            lastPortValue = 0
            stoppedAtValue = null
        }
    }

    /** Return the source token store for this app. */
    fun tokenStore(context: Context): AndroidKeystoreTokenStore =
        AndroidKeystoreTokenStore(File(context.filesDir, TOKEN_FILE_NAME))

    /** Return the shared preferences that hold non-secret pairing data. */
    fun preferences(context: Context): android.content.SharedPreferences =
        context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)

    /** Return the production hotspot finder. */
    @RequiresPermission(Manifest.permission.ACCESS_NETWORK_STATE)
    fun hotspotFinder(context: Context): HotspotAddressFinder {
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
            ?: throw IllegalStateException("The connectivity service is not available.")
        val excluded = ExcludedInterfaceNames(connectivity)
        return NetworkInterfaceHotspotAddressFinder(PlatformInterfaceSource()) {
            excluded.read()
        }
    }

    /** Install an environment for an instrumented test. */
    fun installTestEnvironment(environment: SourceProxyEnvironment) {
        testEnvironment = environment
        resetObservation()
    }

    /** Remove the test environment. */
    fun clearTestEnvironment() {
        testEnvironment = null
        resetObservation()
    }

    /** Clear the test observation. */
    fun resetObservation() {
        synchronized(lock) {
            lastStateValue = SourceProxyState.IDLE
            lastStopReasonValue = SourceProxyStopReason.NONE
            lastPortValue = 0
            stoppedAtValue = null
            activeController = null
        }
    }

    /** Record one state report. It holds no token or address. */
    fun record(snapshot: SourceProxySnapshot) {
        synchronized(lock) {
            lastStateValue = snapshot.state
            lastStopReasonValue = snapshot.reason
            lastPortValue = snapshot.port
            if (snapshot.state == SourceProxyState.STOPPED) {
                stoppedAtValue = System.currentTimeMillis()
            }
        }
    }

    /** Return the test environment, or the production environment. */
    @RequiresPermission(Manifest.permission.ACCESS_NETWORK_STATE)
    fun environment(context: Context): SourceProxyEnvironment =
        testEnvironment ?: production(context.applicationContext)

    /** Create the source listener. It binds an ephemeral port. */
    fun serverFactory(): (
        CellularSession,
        SourceHostResolver,
        SourceEchoSender,
        InetAddress,
        String
    ) -> SourceServerHandle = { session, resolver, echo, address, token ->
        SocksServerHandle(session, resolver, echo, address, token, null)
    }

    /** Create the source listener with the saved proxy port. */
    fun serverFactory(ports: ProxyPortPolicy): (
        CellularSession,
        SourceHostResolver,
        SourceEchoSender,
        InetAddress,
        String
    ) -> SourceServerHandle = { session, resolver, echo, address, token ->
        SocksServerHandle(session, resolver, echo, address, token, ports)
    }

    @RequiresPermission(Manifest.permission.ACCESS_NETWORK_STATE)
    private fun production(context: Context): SourceProxyEnvironment {
        val finder = hotspotFinder(context)
        val ports = ProxyPortPolicy(SharedPreferencesProxyPortStore(preferences(context)))
        return SourceProxyEnvironment(
            tokenStore = tokenStore(context),
            hotspotFinder = finder,
            selectionFactory = {
                val connectivity = context.getSystemService(ConnectivityManager::class.java)
                    ?: throw IllegalStateException("The connectivity service is not available.")
                AndroidSourceCellularSelection(connectivity)
            },
            resolverFactory = { binding ->
                val selected = binding as? SelectedCellularNetworkBinding
                    ?: throw IOException("The selected cellular network is not available.")
                NetworkResolver(selected.network)
            },
            echoFactory = { binding ->
                val selected = binding as? SelectedCellularNetworkBinding
                    ?: throw IOException("The selected cellular network is not available.")
                AndroidNetworkEcho(selected.network)
            },
            serverFactory = serverFactory(ports),
            watchFactory = { address -> PeriodicHotspotWatch(finder, address) },
        )
    }
}

private class ExcludedInterfaceNames(private val connectivity: ConnectivityManager) {
    /** Return the interface names of the cellular, Wi-Fi client, and VPN networks. */
    @RequiresPermission(Manifest.permission.ACCESS_NETWORK_STATE)
    fun read(): Set<String> {
        val names = mutableSetOf<String>()
        val networks = try {
            connectivity.allNetworks
        } catch (_: Exception) {
            return names
        }
        for (network in networks) {
            val capabilities = try {
                connectivity.getNetworkCapabilities(network)
            } catch (_: Exception) {
                null
            } ?: continue
            if (!capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) &&
                !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) &&
                !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
            ) {
                continue
            }
            val name = try {
                connectivity.getLinkProperties(network)?.interfaceName
            } catch (_: Exception) {
                null
            } ?: continue
            names += name
        }
        return names
    }
}

private class SocksServerHandle(
    session: CellularSession,
    resolver: SourceHostResolver,
    echo: SourceEchoSender,
    address: InetAddress,
    token: String,
    private val ports: ProxyPortPolicy?,
) : SourceServerHandle {
    private val limits = SourceSocksCapacity.limitsForFileLimit(
        SourceSocksCapacity.readSoftFileLimit()
            ?: throw IOException("The app cannot read the open-file limit. Restart the app."),
    )

    init {
        if (limits.total <= 0) {
            throw IOException("The open-file limit is too low for the proxy.")
        }
    }

    private val server = SourceSocksServer(
        cellular = session,
        resolver = resolver,
        bindAddress = address,
        token = token,
        port = ports?.current(address) ?: 0,
        maximumRelays = limits.relay,
        setupReserve = limits.setupReserve,
        echo = echo,
    )

    override val localPort: Int get() = server.localPort

    override val activeConnections: Int get() = server.activeConnections

    override val totalConnections: Long get() = server.totalConnections

    override fun start() {
        try {
            server.start()
        } catch (failure: Exception) {
            // A saved port can be taken by another process. Choose a new port
            // on the next start. A paired target device learns it from an
            // authenticated status answer.
            ports?.clear()
            throw failure
        }
        if (ports != null) ports.remember(server.localPort)
    }

    override fun close() = server.stop()
}
