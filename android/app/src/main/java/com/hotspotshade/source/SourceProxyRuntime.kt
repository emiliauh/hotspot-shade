package com.hotspotshade.source

import android.Manifest
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import androidx.annotation.RequiresApi
import androidx.annotation.RequiresPermission
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
 * The controller-owned listener binding.
 *
 * One value carries every field that a pairing answer reports about the live
 * run: the state, the bound port, the bound address, and the relay counts. A
 * reader takes it in one call, so a start or a stop cannot mix two runs in one
 * answer. This value stays inside the app process. It is never logged, shown,
 * or sent to the source device. The pairing responder uses it to name only a
 * port and address that the proxy actually bound.
 */
internal data class SourceProxyBinding(
    val state: SourceProxyState,
    val active: Boolean,
    val port: Int,
    val address: InetAddress?,
    val connections: Int = 0,
    val totalConnections: Long = 0L,
    /**
     * Identifies one controller run for the life of this process.
     *
     * A new run gets a new value even when it binds the same address and port.
     * The background status host closes its listener when this value changes,
     * so a stopped and restarted run cannot keep serving from an older
     * listener. Zero means that no run identity is known.
     */
    val runId: Long = 0L,
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
    private const val PREFERENCES_NAME = "hotspotshade-source"

    @Volatile
    private var testEnvironment: SourceProxyEnvironment? = null

    private val lock = Any()
    private var lastStateValue: SourceProxyState = SourceProxyState.IDLE
    private var lastStopReasonValue: SourceProxyStopReason = SourceProxyStopReason.NONE
    private var lastPortValue: Int = 0
    private var lastBoundAddressValue: InetAddress? = null
    private var stoppedAtValue: Long? = null
    private var activeController: SourceProxyController? = null
    private var sharedTetheredEvidence: SharedTetheredInterfaceEvidence? = null
    // One process-wide counter names each run. A new controller, or a live
    // report that no controller owns, takes the next value. The background
    // status host fences its listener against this value.
    private var nextRunId: Long = 0L
    private var activeRunId: Long = 0L
    private var recordedRunId: Long = 0L

    // Recent activity. Both trackers keep their own state and the log has a
    // leaf lock, so recording under [lock] cannot deadlock.
    private val proxyActivity = ProxyActivityTracker()
    private val connectionActivity = ConnectionActivityTracker()

    /** Record the connection usage line when the open count crosses a bound. */
    private fun trackConnections(running: Boolean, connections: Int) {
        connectionActivity.onCount(running, connections, System.currentTimeMillis())
            ?.let(ActivityLog::record)
    }

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
        val open = activeController?.connectionCount ?: 0
        trackConnections(lastStateValue == SourceProxyState.RUNNING, open)
        SourceProxyObservation(
            state = lastStateValue,
            reason = lastStopReasonValue,
            port = lastPortValue,
            connections = open,
            totalConnections = activeController?.totalConnections ?: 0L,
            stoppedAtMillis = stoppedAtValue,
        )
    }

    /**
     * Return the binding that the pairing responder may name.
     *
     * A live controller is authoritative. Its bound address and port are set
     * as soon as the listener binds, before the run publishes RUNNING. When no
     * controller is attached, the last recorded report is used; a test can
     * record the address with the report.
     */
    fun binding(): SourceProxyBinding = synchronized(lock) {
        val controller = activeController
        if (controller != null) {
            val binding = controller.binding()
            if (binding.active || binding.state != SourceProxyState.IDLE) {
                // The controller owns the report. Name the exact run that this
                // controller was attached for, even if the controller reused
                // an address and port from an older run.
                trackConnections(
                    binding.state == SourceProxyState.RUNNING,
                    binding.connections,
                )
                return@synchronized binding.copy(runId = activeRunId)
            }
        }
        val live = lastStateValue == SourceProxyState.RUNNING ||
            lastStateValue == SourceProxyState.WAITING_FOR_NETWORK
        SourceProxyBinding(
            state = lastStateValue,
            active = live,
            port = if (live) lastPortValue else 0,
            address = if (live) lastBoundAddressValue else null,
            // The fallback report has no live controller, so it has no relay
            // counters to read.
            connections = 0,
            totalConnections = 0L,
            runId = if (live) recordedRunId else 0L,
        )
    }

    /**
     * Attach the controller that serves the current run, or null after it ends.
     *
     * The API 36 tethering callback stays registered for the process. The
     * pairing listener and the source proxy share one reading, so a service
     * stop must not remove a callback that the pairing listener still uses. A
     * later start reuses the same callback. A test environment reset or the
     * process teardown closes it.
     */
    fun attach(controller: SourceProxyController?) {
        synchronized(lock) {
            if (controller == null) {
                activeController = null
                activeRunId = 0L
            } else if (controller !== activeController) {
                nextRunId += 1
                activeRunId = nextRunId
                activeController = controller
            }
        }
    }

    /**
     * Clear the previous run report before a new start request.
     *
     * The app calls this method for every start request, including a repeated
     * one that the service will not turn into a new run. An attached active
     * controller keeps its report, so a second start request cannot hide a
     * live run and leave the app on Starting. A service that still finds an
     * active controller records the controller snapshot again.
     */
    fun requestStart() {
        synchronized(lock) {
            if (activeController?.isActive == true) return
            // A new request makes the next report a new run for the log, so
            // a second failed start logs its own reason.
            proxyActivity.reset()
            connectionActivity.reset()
            lastStateValue = SourceProxyState.IDLE
            lastStopReasonValue = SourceProxyStopReason.NONE
            lastPortValue = 0
            lastBoundAddressValue = null
            stoppedAtValue = null
        }
    }

    /** Return the source token store for this app. */
    fun tokenStore(context: Context): AndroidKeystoreTokenStore =
        AndroidKeystoreTokenStore.forContext(context)

    /** Return the shared preferences that hold non-secret pairing data. */
    fun preferences(context: Context): android.content.SharedPreferences =
        context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)

    /**
     * Return the production hotspot finder.
     *
     * On Android 16 or later the finder also reads the public tethering
     * callback. The callback class is constructed only after the SDK check, so
     * Android 8 through 15 never load it. The callback is process scoped. A
     * service stop does not remove it. A test environment reset or the process
     * teardown closes it.
     */
    @RequiresPermission(Manifest.permission.ACCESS_NETWORK_STATE)
    fun hotspotFinder(context: Context): HotspotAddressFinder {
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
            ?: throw IllegalStateException("The connectivity service is not available.")
        val observation = NetworkInterfaceObservationReader(
            ConnectivityNetworkSource(connectivity),
        )
        return NetworkInterfaceHotspotAddressFinder(
            PlatformInterfaceSource(),
            { observation.read() },
            tetheredInterfaceEvidence(context),
        )
    }

    /**
     * Return the process-scoped tethering evidence, or an unavailable source.
     *
     * The SDK check runs before the API 36 class is named. A failed
     * registration returns an unavailable source, so the finder keeps the
     * name rules instead of treating the failure as an empty tethering set.
     * The next finder created after a failure retries the registration on the
     * same source. A source that is still registered ignores the retry.
     */
    private fun tetheredInterfaceEvidence(context: Context): TetheredInterfaceEvidenceSource {
        if (!supportsTetheredInterfaceCallback(Build.VERSION.SDK_INT)) {
            return TetheredInterfaceEvidenceSource { TetheredInterfaceState.Unavailable }
        }
        val shared = synchronized(lock) {
            sharedTetheredEvidence ?: SharedTetheredInterfaceEvidence(
                factory = {
                    try {
                        createApi36TetheredEvidence(context)
                    } catch (_: Exception) {
                        null
                    }
                },
            ).also { sharedTetheredEvidence = it }
        }
        return try {
            // Registration can block on the tethering service. It runs outside
            // the runtime lock so the UI can still read [observation]. A
            // failed registration is retried on the next finder creation; a
            // successful source ignores the retry.
            shared.processSource()
        } catch (_: Exception) {
            // The finder still reads Unavailable and uses the name rules. The
            // next call retries.
            TetheredInterfaceEvidenceSource { TetheredInterfaceState.Unavailable }
        }
    }

    /**
     * Construct the API 36 callback source.
     *
     * The caller enters this method only when
     * [supportsTetheredInterfaceCallback] returned true. Lint checks the
     * annotation and keeps the SDK 26 through 35 paths from naming the API 36
     * class.
     */
    @RequiresApi(Build.VERSION_CODES.BAKLAVA)
    private fun createApi36TetheredEvidence(context: Context): TetheredInterfaceEvidence =
        // The shared source starts this object once after it attaches it. Do not
        // register here: a second creator can lose the attach race, and a start
        // inside the shared lock would block status reads on the tethering
        // service.
        TetheredInterfaceEvidence(
            Api36TetheredInterfaceRegistration(context.applicationContext),
        )

    /** Install an environment for an instrumented test. */
    fun installTestEnvironment(environment: SourceProxyEnvironment) {
        testEnvironment = environment
        resetObservation()
        closeTetheredEvidence()
    }

    /** Remove the test environment. */
    fun clearTestEnvironment() {
        testEnvironment = null
        resetObservation()
        closeTetheredEvidence()
    }

    /** Remove the API 36 callback for a test environment reset or teardown. */
    private fun closeTetheredEvidence() {
        val evidenceToClose = synchronized(lock) {
            sharedTetheredEvidence.also { sharedTetheredEvidence = null }
        }
        evidenceToClose?.close()
    }

    /** Clear the test observation. */
    fun resetObservation() {
        synchronized(lock) {
            lastStateValue = SourceProxyState.IDLE
            lastStopReasonValue = SourceProxyStopReason.NONE
            lastPortValue = 0
            lastBoundAddressValue = null
            stoppedAtValue = null
            activeController = null
            activeRunId = 0L
            recordedRunId = 0L
            proxyActivity.reset()
            connectionActivity.reset()
        }
    }

    /**
     * Record one state report. It holds no token or host.
     *
     * [boundAddress] is optional. The production service reads the controller
     * binding instead. A JVM test can record the address that it simulates.
     */
    fun record(snapshot: SourceProxySnapshot, boundAddress: InetAddress? = null) {
        synchronized(lock) {
            val liveNow = snapshot.state == SourceProxyState.RUNNING ||
                snapshot.state == SourceProxyState.WAITING_FOR_NETWORK
            val wasLive = lastStateValue == SourceProxyState.RUNNING ||
                lastStateValue == SourceProxyState.WAITING_FOR_NETWORK
            if (liveNow) {
                if (!wasLive || recordedRunId == 0L) {
                    nextRunId += 1
                    recordedRunId = nextRunId
                }
            } else {
                recordedRunId = 0L
            }
            lastStateValue = snapshot.state
            lastStopReasonValue = snapshot.reason
            lastPortValue = snapshot.port
            lastBoundAddressValue = if (snapshot.state == SourceProxyState.RUNNING ||
                snapshot.state == SourceProxyState.WAITING_FOR_NETWORK
            ) {
                boundAddress
            } else {
                null
            }
            if (snapshot.state == SourceProxyState.STOPPED) {
                stoppedAtValue = System.currentTimeMillis()
            }
            proxyActivity.onReport(snapshot.state, snapshot.reason)?.let(ActivityLog::record)
            if (snapshot.state != SourceProxyState.RUNNING) connectionActivity.reset()
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

/**
 * Read every network that ConnectivityManager reports.
 *
 * Each interface name, capability, and link-properties call runs during the
 * observation read. A null or thrown value reaches
 * [NetworkInterfaceObservationReader], which keeps the names it already read
 * and returns a partial observation. This source never drops a network from
 * the list.
 */
private class ConnectivityNetworkSource(
    private val connectivity: ConnectivityManager,
) : NetworkListSource {
    // allNetworks is the only snapshot API that lists every local network.
    // The callback API reports only networks that match a request.
    @Suppress("DEPRECATION")
    @RequiresPermission(Manifest.permission.ACCESS_NETWORK_STATE)
    override fun read(): List<ObservedNetwork> =
        connectivity.allNetworks.map { network ->
            object : ObservedNetwork {
                override fun transports(): ObservedTransports? {
                    val capabilities = connectivity.getNetworkCapabilities(network)
                        ?: return null
                    return ObservedTransports(
                        isCellular = capabilities.hasTransport(
                            NetworkCapabilities.TRANSPORT_CELLULAR,
                        ),
                        isWifi = capabilities.hasTransport(
                            NetworkCapabilities.TRANSPORT_WIFI,
                        ),
                        isVpn = capabilities.hasTransport(
                            NetworkCapabilities.TRANSPORT_VPN,
                        ),
                    )
                }

                override fun interfaceName(): String? =
                    connectivity.getLinkProperties(network)?.interfaceName
            }
        }
}

private class SocksServerHandle(
    private val session: CellularSession,
    private val resolver: SourceHostResolver,
    private val echo: SourceEchoSender,
    private val address: InetAddress,
    private val token: String,
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

    @Volatile
    private var server: SourceSocksServer? = null

    override val localPort: Int get() = server?.localPort ?: 0

    override val activeConnections: Int get() = server?.activeConnections ?: 0

    override val totalConnections: Long get() = server?.totalConnections ?: 0L

    /** True while the real listener accepts connections. */
    override val isRunning: Boolean get() = server?.isRunning == true

    /** The fixed server failure label, or null. */
    override val failureReason: String? get() = server?.failureReason

    /**
     * Claim and bind one port inside the bind gate.
     *
     * A pairing answer that runs during this section gets NOT_ACTIVE instead
     * of probing the proxy's own new listener and naming a port that never
     * bound. A failed start keeps the remembered port, and a successful start
     * saves the port that actually bound.
     */
    override fun start() {
        val started = ProxyBindGate.duringBind {
            val chosen = ports?.claim(address) ?: 0
            val candidate = SourceSocksServer(
                cellular = session,
                resolver = resolver,
                bindAddress = address,
                token = token,
                // Do not persist a candidate before the listener binds.
                port = chosen,
                maximumRelays = limits.relay,
                setupReserve = limits.setupReserve,
                echo = echo,
            )
            try {
                candidate.start()
            } catch (failure: Exception) {
                try {
                    candidate.stop()
                } catch (_: Exception) {
                    // The listener did not start.
                }
                throw failure
            }
            try {
                ports?.remember(candidate.localPort)
            } catch (_: Exception) {
                // A settings write failure must not stop a listener that
                // already bound. The next start probes the remembered value.
            }
            candidate
        }
        server = started
    }

    override fun close() {
        server?.stop()
    }
}
