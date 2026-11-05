package com.hotspotshade.source

import java.io.Closeable
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.ConnectException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NoRouteToHostException
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Duration
import java.util.concurrent.Callable
import java.util.concurrent.CancellationException
import java.util.concurrent.ExecutionException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadFactory
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * Resolve a destination name on the selected cellular network.
 *
 * The real adapter must call `Network.getAllByName()` on that network. Do not
 * use the process default resolver. The caller owns the deadline.
 */
internal fun interface SourceHostResolver {
    fun resolve(host: String): List<InetAddress>
}

/**
 * Serve the source device SOCKS5 contract on one injected listener address.
 *
 * Every destination TCP or UDP socket comes from [CellularSession]. A domain
 * name goes through [SourceHostResolver] only. This class never calls
 * `InetAddress.getByName()` or `getaddrinfo()`.
 *
 * The proxy accepts method 2 (username and password) only. The username is
 * `hotspotshade`. The caller injects the token. A failed authentication gets
 * one `[1, 1]` reply and a close.
 *
 * A TCP CONNECT gets one success or failure reply. Command `0x80` carries
 * length-prefixed UDP datagrams over the TCP session. Command `0x81` sends one
 * echo probe. Command `0x82` keeps one echo session open for more probes. See
 * [SourceEchoWire]. Reply codes match the iOS source proxy:
 *
 * - 0: success.
 * - 1: general failure, deadline, or capacity refusal.
 * - 4: destination network or host unreachable.
 * - 5: destination refused the connection.
 * - 7: command not supported.
 * - 8: address type not supported, or an echo target that is not accepted.
 *
 * The phase rule follows `SourceSocksCapacity`. A handshake has a 30 second
 * bound. A destination connect has a 4 second bound. An open TCP relay has no
 * idle bound. A UDP flow and a half-closed TCP flow have a 300 second idle
 * bound. The server never closes a healthy open TCP relay for silence.
 *
 * The client and destination TCP sockets set no-delay and keepalive. The
 * Android system keepalive defaults apply. The app cannot set the iOS 60/10/3
 * values through the Java socket API.
 *
 * The server holds at most [maximumRelays] relay sessions and [setupReserve]
 * extra setup sessions. It never closes an open TCP relay to make room. A
 * refused relay request gets code 1. A new connection beyond the total bound
 * closes the most overdue stale session first. It closes the client before the
 * greeting when no session is stale.
 *
 * A persistent echo session holds one of 16 echo slots and no relay slot. Its
 * request has a 5 second bound. Its idle window is 30 seconds. Its lifetime is
 * 300 seconds.
 *
 * [stop] closes the listener and every session. It is idempotent. A stopped
 * server cannot start again. The caller must pass the hotspot address.
 */
internal class SourceSocksServer(
    private val cellular: CellularSession,
    private val resolver: SourceHostResolver,
    private val bindAddress: InetAddress,
    token: String,
    private val port: Int = 0,
    private val maximumRelays: Int = MAXIMUM_RELAYS,
    private val setupReserve: Int = SETUP_RESERVE,
    private val connectTimeout: Duration = Duration.ofSeconds(4),
    private val handshakeTimeout: Duration = Duration.ofSeconds(30),
    private val udpIdleTimeout: Duration = Duration.ofSeconds(300),
    private val echo: SourceEchoSender? = null,
    private val echoRequestTimeout: Duration = Duration.ofSeconds(5),
    private val echoIdleTimeout: Duration = Duration.ofSeconds(30),
    private val echoLifetime: Duration = Duration.ofSeconds(300),
    private val echoAttemptTimeout: Duration = Duration.ofSeconds(3),
    private val persistentEchoLimit: Int = SourceSocksCapacity.MAXIMUM_PERSISTENT_ECHO_SESSIONS,
    private val housekeepingInterval: Duration = Duration.ofMillis(500),
) : Closeable {
    internal companion object {
        /** The relay slots that the source device proxy gives to open flows. */
        const val MAXIMUM_RELAYS = SourceSocksCapacity.MAXIMUM_RELAYS

        /** The setup slots that relay sessions cannot use. */
        const val SETUP_RESERVE = SourceSocksCapacity.SETUP_RESERVE

        /** The total session bound. */
        const val MAXIMUM_SESSIONS = SourceSocksCapacity.MAXIMUM_SESSIONS

        /** The most persistent echo sessions that the server grants. */
        const val MAXIMUM_PERSISTENT_ECHO_SESSIONS =
            SourceSocksCapacity.MAXIMUM_PERSISTENT_ECHO_SESSIONS

        private const val SOCKS_VERSION = 5
        private const val AUTH_VERSION = 1
        private const val METHOD_USERNAME_PASSWORD = 2
        private const val METHOD_NONE_ACCEPTABLE = 0xFF
        private const val COMMAND_CONNECT = 1
        private const val COMMAND_UDP = 0x80
        private const val COMMAND_ECHO = SourceEchoWire.COMMAND
        private const val COMMAND_ECHO_PERSISTENT = SourceEchoWire.PERSISTENT_COMMAND
        private const val ADDRESS_IPV4 = 1
        private const val ADDRESS_DOMAIN = 3
        private const val ADDRESS_IPV6 = 4
        private const val REPLY_SUCCEEDED = 0
        private const val REPLY_GENERAL_FAILURE = 1
        private const val REPLY_UNREACHABLE = 4
        private const val REPLY_REFUSED = 5
        private const val REPLY_COMMAND_NOT_SUPPORTED = 7
        private const val REPLY_ADDRESS_NOT_SUPPORTED = 8
        private const val MAX_DATAGRAM = 1472
        private const val CLIENT_BUFFER = 16 * 1024
        private const val ACCEPT_SLICE_MILLIS = 1_000
        private val USERNAME = "hotspotshade".toByteArray(StandardCharsets.US_ASCII)
        private val EMPTY = ByteArray(0)
    }

    private enum class State { NEW, RUNNING, STOPPED }

    private val tokenBytes = token.toByteArray(StandardCharsets.UTF_8)
    private val lifecycleLock = Any()
    private val sessionLock = Any()
    private val sessions = LinkedHashSet<Session>()
    private val sessionIds = AtomicLong()
    private val relayTotal = AtomicLong()
    private val persistentEchoCount = AtomicInteger()
    private val sessionLimit = maximumRelays + setupReserve
    private val policy = SourceSocksCapacity.Policy(
        handshakeMillis = handshakeTimeout.toMillis().coerceAtLeast(1),
        connectMillis = (connectTimeout.toMillis() * 2).coerceAtLeast(1),
        relayIdleMillis = udpIdleTimeout.toMillis().coerceAtLeast(1),
    )
    private var relayCount = 0

    @Volatile
    private var listener: ServerSocket? = null

    @Volatile
    private var acceptThread: Thread? = null

    @Volatile
    private var housekeepingThread: Thread? = null

    @Volatile
    private var resolverExecutor: ExecutorService? = null

    @Volatile
    private var state = State.NEW

    @Volatile
    private var boundPort = 0

    init {
        require(!bindAddress.isAnyLocalAddress) {
            "The source listener needs an explicit address."
        }
        require(port in 0..65_535) {
            "The source listener port is out of range."
        }
        require(token.isNotEmpty()) {
            "The source token must not be empty."
        }
        require(maximumRelays in 1..65_535) {
            "The relay limit is out of range."
        }
        require(setupReserve in 0..65_535) {
            "The setup reserve is out of range."
        }
        require(!connectTimeout.isZero && !connectTimeout.isNegative) {
            "The connect timeout must be positive."
        }
        require(!handshakeTimeout.isZero && !handshakeTimeout.isNegative) {
            "The handshake timeout must be positive."
        }
        require(!udpIdleTimeout.isZero && !udpIdleTimeout.isNegative) {
            "The UDP idle timeout must be positive."
        }
        require(!echoRequestTimeout.isZero && !echoRequestTimeout.isNegative) {
            "The echo request timeout must be positive."
        }
        require(!echoIdleTimeout.isZero && !echoIdleTimeout.isNegative) {
            "The echo idle timeout must be positive."
        }
        require(!echoLifetime.isZero && !echoLifetime.isNegative) {
            "The echo lifetime must be positive."
        }
        require(!echoAttemptTimeout.isZero && !echoAttemptTimeout.isNegative) {
            "The echo attempt timeout must be positive."
        }
        require(persistentEchoLimit in 1..255) {
            "The persistent echo limit is out of range."
        }
        require(!housekeepingInterval.isZero && !housekeepingInterval.isNegative) {
            "The housekeeping interval must be positive."
        }
    }

    /** The port that the listener bound, or 0 before a start. */
    val localPort: Int get() = boundPort

    /** True between a successful start and the first stop. */
    val isRunning: Boolean get() = state == State.RUNNING

    /** The relay cap of this run. It follows the open-file limit. */
    val relayLimit: Int get() = maximumRelays

    /** The total session cap of this run. It follows the open-file limit. */
    val totalSessionLimit: Int get() = sessionLimit

    /**
     * The open relay count. It holds no address, host, or port.
     *
     * The count includes TCP CONNECT and UDP sessions after the relay grant.
     * It falls when a session closes. The value is safe to show in the app.
     */
    val activeConnections: Int
        get() = synchronized(sessionLock) { relayCount }

    /**
     * The relay count since the start. It holds no address, host, or port.
     *
     * The count includes every granted relay. A refused relay does not count.
     */
    val totalConnections: Long get() = relayTotal.get()

    /**
     * Bind the listener and accept sessions. Call this method once.
     *
     * The method binds [bindAddress] and [port] before it returns. A port of 0
     * selects an ephemeral port. A bind failure closes the listener and makes
     * this object unusable.
     */
    fun start() {
        synchronized(lifecycleLock) {
            check(state == State.NEW) { "The source server cannot restart." }
            val server = ServerSocket()
            try {
                server.reuseAddress = false
                server.bind(InetSocketAddress(bindAddress, port))
                server.soTimeout = ACCEPT_SLICE_MILLIS
            } catch (_: Exception) {
                closeQuietly(server)
                state = State.STOPPED
                throw IOException("The source listener could not bind.")
            }
            listener = server
            boundPort = server.localPort
            resolverExecutor = Executors.newCachedThreadPool(daemonFactory("source-resolve"))
            state = State.RUNNING
            val worker = Thread({ acceptLoop(server) }, "source-accept")
            worker.isDaemon = true
            acceptThread = worker
            try {
                worker.start()
            } catch (_: Exception) {
                state = State.STOPPED
                listener = null
                acceptThread = null
                resolverExecutor?.shutdownNow()
                resolverExecutor = null
                closeQuietly(server)
                throw IOException("The source listener could not start.")
            }
            val keeper = Thread({ housekeepingLoop() }, "source-capacity")
            keeper.isDaemon = true
            housekeepingThread = keeper
            try {
                keeper.start()
            } catch (_: Exception) {
                state = State.STOPPED
                listener = null
                closeQuietly(server)
                acceptThread?.interrupt()
                acceptThread = null
                resolverExecutor?.shutdownNow()
                resolverExecutor = null
                throw IOException("The source capacity thread could not start.")
            }
        }
    }

    /**
     * Close the listener and every session. This method is idempotent.
     *
     * A stopped server does not restart. A later [start] call throws
     * [IllegalStateException].
     */
    override fun close() = stop()

    /** Close the listener and every session. This method is idempotent. */
    fun stop() {
        var active: List<Session> = emptyList()
        var acceptWorker: Thread? = null
        var keeper: Thread? = null
        synchronized(lifecycleLock) {
            if (state == State.STOPPED) return
            state = State.STOPPED
            val server = listener
            listener = null
            closeQuietly(server)
            acceptWorker = acceptThread
            acceptThread = null
            keeper = housekeepingThread
            housekeepingThread = null
            resolverExecutor?.shutdownNow()
            resolverExecutor = null
            synchronized(sessionLock) {
                active = sessions.toList()
            }
        }
        if (keeper != null && keeper !== Thread.currentThread()) {
            keeper.interrupt()
            try {
                keeper.join(1_000)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
            }
        }
        for (session in active) {
            session.close()
        }
        for (session in active) {
            val worker = session.workerThread ?: continue
            if (worker === Thread.currentThread()) continue
            worker.interrupt()
            try {
                worker.join(1_000)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
            }
        }
        if (acceptWorker != null && acceptWorker !== Thread.currentThread()) {
            try {
                acceptWorker.join(1_000)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
            }
        }
    }

    override fun toString(): String = "SourceSocksServer"

    private fun acceptLoop(server: ServerSocket) {
        while (state == State.RUNNING) {
            val client = try {
                server.accept()
            } catch (_: SocketTimeoutException) {
                continue
            } catch (_: Exception) {
                break
            }
            if (state != State.RUNNING) {
                closeQuietly(client)
                break
            }
            val session = admit(client)
            if (session == null) {
                closeQuietly(client)
            }
        }
    }

    /**
     * Apply the phase bound to every session. An open TCP relay is never
     * closed for silence. A control session is bounded by the echo timers.
     */
    private fun housekeepingLoop() {
        val interval = housekeepingInterval.toMillis().coerceAtLeast(1)
        while (state == State.RUNNING) {
            try {
                Thread.sleep(interval)
            } catch (_: InterruptedException) {
                return
            }
            if (state != State.RUNNING) return
            val active = synchronized(sessionLock) { sessions.toList() }
            val now = System.nanoTime()
            for (session in active) {
                if (session.isClosed) continue
                if (session.echoIdleExpired(now) || session.echoLifetimeExpired(now)) {
                    session.close()
                    continue
                }
                if (session.isControlActive()) continue
                val view = session.phaseSession(now)
                when (
                    SourceSocksCapacity.idleAction(
                        phase = view.phase,
                        phaseMillis = view.phaseMillis,
                        idleMillis = view.idleMillis,
                        policy = policy,
                    )
                ) {
                    is SourceSocksCapacity.IdleAction.Close -> session.close()
                    is SourceSocksCapacity.IdleAction.Rearm -> Unit
                }
            }
        }
    }

    private fun admit(client: Socket): Session? {
        var evicted: Session? = null
        val session: Session
        synchronized(sessionLock) {
            if (state != State.RUNNING) return null
            if (sessions.size >= sessionLimit) {
                val stale = SourceSocksCapacity.staleSession(
                    sessions = phaseSessionsLocked(System.nanoTime()),
                    policy = policy,
                ) ?: return null
                evicted = sessions.firstOrNull { it.id == stale.id }
                if (evicted == null) return null
                detachLocked(evicted)
            }
            session = Session(sessionIds.incrementAndGet(), client)
            sessions.add(session)
        }
        evicted?.close()
        val worker = Thread({ session.run() }, "source-session-${session.id}")
        worker.isDaemon = true
        session.attach(worker)
        worker.start()
        return session
    }

    private fun phaseSessionsLocked(now: Long): List<SourceSocksCapacity.PhaseSession> =
        sessions.map { it.phaseSession(now) }

    /** Remove one session from the table and release its relay slot. */
    private fun detachLocked(session: Session): Boolean {
        if (!sessions.remove(session)) return false
        if (session.relayGranted) {
            relayCount = maxOf(0, relayCount - 1)
        }
        return true
    }

    private fun sessionClosed(session: Session) {
        synchronized(sessionLock) { detachLocked(session) }
    }

    private fun grantRelay(session: Session): Boolean {
        var victim: Session? = null
        val granted: Boolean
        synchronized(sessionLock) {
            when {
                session.isClosed -> granted = false
                session.relayGranted -> granted = true
                relayCount < maximumRelays -> {
                    session.noteRelayGranted()
                    relayCount += 1
                    relayTotal.incrementAndGet()
                    granted = true
                }
                else -> {
                    val stale = SourceSocksCapacity.staleSession(
                        sessions = phaseSessionsLocked(System.nanoTime()),
                        relayOnly = true,
                        policy = policy,
                    )
                    val staleSession = stale?.let { view -> sessions.firstOrNull { it.id == view.id } }
                    if (staleSession != null) {
                        detachLocked(staleSession)
                        victim = staleSession
                        session.noteRelayGranted()
                        relayCount += 1
                        relayTotal.incrementAndGet()
                        granted = true
                    } else {
                        granted = false
                    }
                }
            }
        }
        victim?.close()
        return granted
    }

    private inner class Session(val id: Long, private val client: Socket) {
        private val closeLock = Any()
        private val clientWriteLock = Any()
        private val destinationWriteLock = Any()
        private val relayDone = AtomicInteger()
        private val stateLock = Any()
        private var tcpFlow: CellularFlow<Socket>? = null
        private var udpFlow: CellularFlow<DatagramSocket>? = null

        private var phase = SourceSocksCapacity.Phase.HANDSHAKE
        private var phaseStartedNanos = System.nanoTime()
        private var lastActivityNanos = phaseStartedNanos
        private var awaitsRelay = false
        private var replyPending = false
        private var controlActive = false
        private var echoIdleAtNanos = 0L
        private var echoLifetimeAtNanos = 0L
        private var persistentSlot = false

        @Volatile
        private var closed = false

        @Volatile
        private var worker: Thread? = null

        @Volatile
        private var hasRelay = false

        val isClosed: Boolean get() = closed
        val relayGranted: Boolean get() = hasRelay
        val workerThread: Thread? get() = worker

        fun attach(thread: Thread) {
            worker = thread
        }

        fun noteRelayGranted() {
            hasRelay = true
        }

        fun isControlActive(): Boolean = synchronized(stateLock) { controlActive }

        /** The capacity view of this session. The housekeeping thread reads it. */
        fun phaseSession(now: Long): SourceSocksCapacity.PhaseSession = synchronized(stateLock) {
            SourceSocksCapacity.PhaseSession(
                id = id,
                phase = phase,
                phaseMillis = nanosToMillis(now - phaseStartedNanos),
                idleMillis = nanosToMillis(now - lastActivityNanos),
                protectedFromCapacity = awaitsRelay || replyPending || controlActive,
            )
        }

        fun run() {
            try {
                if (closed) return
                client.tcpNoDelay = true
                client.keepAlive = true
                val input = client.getInputStream()
                val output = client.getOutputStream()
                val request = readHandshake(input, output) ?: return
                when (request.command) {
                    COMMAND_CONNECT -> serveTcp(request, input, output)
                    COMMAND_UDP -> serveUdp(request, input, output)
                    COMMAND_ECHO, COMMAND_ECHO_PERSISTENT -> serveEcho(request, input, output)
                }
            } catch (_: Exception) {
                // The finally block closes the session. Do not log a message.
            } finally {
                close()
            }
        }

        fun close() {
            val releaseEcho: Boolean
            synchronized(closeLock) {
                if (closed) return
                closed = true
                releaseEcho = persistentSlot
                persistentSlot = false
                closeQuietly(client)
                closeFlow(tcpFlow)
                closeFlow(udpFlow)
                tcpFlow = null
                udpFlow = null
            }
            if (releaseEcho) persistentEchoCount.decrementAndGet()
            sessionClosed(this)
        }

        fun echoIdleExpired(now: Long): Boolean = synchronized(stateLock) {
            echoIdleAtNanos != 0L && now >= echoIdleAtNanos
        }

        fun echoLifetimeExpired(now: Long): Boolean = synchronized(stateLock) {
            echoLifetimeAtNanos != 0L && now >= echoLifetimeAtNanos
        }

        private fun markPhase(next: SourceSocksCapacity.Phase) {
            synchronized(stateLock) {
                phase = next
                phaseStartedNanos = System.nanoTime()
                lastActivityNanos = phaseStartedNanos
            }
        }

        private fun markConnecting() = markPhase(SourceSocksCapacity.Phase.CONNECTING)

        private fun markAwaitingRelay() {
            synchronized(stateLock) {
                phase = SourceSocksCapacity.Phase.AWAITING_RELAY
                phaseStartedNanos = System.nanoTime()
                awaitsRelay = true
            }
        }

        private fun admitRelayPhase(datagram: Boolean): Boolean = synchronized(stateLock) {
            if (phase != SourceSocksCapacity.Phase.AWAITING_RELAY || !awaitsRelay || replyPending) {
                false
            } else {
                phase = if (datagram) {
                    SourceSocksCapacity.Phase.UDP
                } else {
                    SourceSocksCapacity.Phase.OPEN_TCP
                }
                phaseStartedNanos = System.nanoTime()
                awaitsRelay = false
                true
            }
        }

        private fun denyRelay() {
            synchronized(stateLock) {
                if (phase == SourceSocksCapacity.Phase.AWAITING_RELAY) {
                    phase = SourceSocksCapacity.Phase.CONNECTING
                    phaseStartedNanos = System.nanoTime()
                    awaitsRelay = false
                }
            }
        }

        private fun beginReply() {
            synchronized(stateLock) { replyPending = true }
        }

        private fun finishReply() {
            synchronized(stateLock) { replyPending = false }
        }

        private fun beginControl() {
            synchronized(stateLock) {
                if (phase == SourceSocksCapacity.Phase.HANDSHAKE) controlActive = true
            }
        }

        private fun noteHalfClose() {
            synchronized(stateLock) {
                if (phase == SourceSocksCapacity.Phase.OPEN_TCP) {
                    phase = SourceSocksCapacity.Phase.HALF_CLOSED
                    phaseStartedNanos = System.nanoTime()
                    lastActivityNanos = phaseStartedNanos
                }
            }
        }

        private fun touch() {
            synchronized(stateLock) { lastActivityNanos = System.nanoTime() }
        }

        private fun startEchoTimers() {
            val now = System.nanoTime()
            synchronized(stateLock) {
                echoIdleAtNanos = now + echoIdleTimeout.toNanos()
                echoLifetimeAtNanos = now + echoLifetime.toNanos()
            }
        }

        private fun resetEchoIdle() {
            val now = System.nanoTime()
            synchronized(stateLock) {
                echoIdleAtNanos = now + echoIdleTimeout.toNanos()
            }
        }

        private fun acquirePersistentSlot(): Boolean {
            synchronized(closeLock) {
                if (closed) return false
                if (persistentSlot) return true
                while (true) {
                    val current = persistentEchoCount.get()
                    if (current >= persistentEchoLimit) return false
                    if (persistentEchoCount.compareAndSet(current, current + 1)) {
                        persistentSlot = true
                        return true
                    }
                }
            }
        }

        private fun trackTcp(flow: CellularFlow<Socket>): Boolean = synchronized(closeLock) {
            if (closed) {
                false
            } else {
                tcpFlow = flow
                true
            }
        }

        private fun untrackTcp(flow: CellularFlow<Socket>) {
            synchronized(closeLock) {
                if (tcpFlow === flow) tcpFlow = null
            }
        }

        private fun trackUdp(flow: CellularFlow<DatagramSocket>): Boolean = synchronized(closeLock) {
            if (closed) {
                false
            } else {
                udpFlow = flow
                true
            }
        }

        private fun untrackUdp(flow: CellularFlow<DatagramSocket>) {
            synchronized(closeLock) {
                if (udpFlow === flow) udpFlow = null
            }
        }

        private fun readHandshake(input: InputStream, output: OutputStream): Request? {
            val deadline = System.nanoTime() + handshakeTimeout.toNanos()
            val greeting = readExactly(input, 2, deadline)
            if ((greeting[0].toInt() and 0xFF) != SOCKS_VERSION) return null
            val methodCount = greeting[1].toInt() and 0xFF
            if (methodCount == 0) return null
            val methods = readExactly(input, methodCount, deadline)
            if (methods.none { (it.toInt() and 0xFF) == METHOD_USERNAME_PASSWORD }) {
                writeSmallReply(output, SOCKS_VERSION, METHOD_NONE_ACCEPTABLE)
                return null
            }
            writeSmallReply(output, SOCKS_VERSION, METHOD_USERNAME_PASSWORD)

            val authHeader = readExactly(input, 2, deadline)
            if ((authHeader[0].toInt() and 0xFF) != AUTH_VERSION) return null
            val userLength = authHeader[1].toInt() and 0xFF
            if (userLength == 0) return null
            val user = readExactly(input, userLength, deadline)
            val passwordLength = readExactly(input, 1, deadline)[0].toInt() and 0xFF
            if (passwordLength == 0) {
                writeSmallReply(output, AUTH_VERSION, 1)
                return null
            }
            val password = readExactly(input, passwordLength, deadline)
            val userOk = MessageDigest.isEqual(USERNAME, user)
            val tokenOk = MessageDigest.isEqual(tokenBytes, password)
            password.fill(0)
            val valid = userOk && tokenOk
            writeSmallReply(output, AUTH_VERSION, if (valid) 0 else 1)
            if (!valid) return null

            val header = readExactly(input, 4, deadline)
            if ((header[0].toInt() and 0xFF) != SOCKS_VERSION) return null
            if ((header[2].toInt() and 0xFF) != 0) return null
            val command = header[1].toInt() and 0xFF
            val addressType = header[3].toInt() and 0xFF

            if (command == COMMAND_ECHO || command == COMMAND_ECHO_PERSISTENT) {
                if (addressType != ADDRESS_IPV4 && addressType != ADDRESS_IPV6) {
                    writeReply(output, REPLY_ADDRESS_NOT_SUPPORTED)
                    return null
                }
                val count = if (addressType == ADDRESS_IPV4) 4 else 16
                val address = readExactly(input, count, deadline)
                val portBytes = readExactly(input, 2, deadline)
                val destinationPort = ((portBytes[0].toInt() and 0xFF) shl 8) or
                    (portBytes[1].toInt() and 0xFF)
                val target = SourceEchoWire.target(addressType, address, destinationPort)
                if (target == null) {
                    writeReply(output, REPLY_ADDRESS_NOT_SUPPORTED)
                    return null
                }
                client.soTimeout = 0
                return Request(
                    command = command,
                    target = null,
                    port = 0,
                    echoTarget = target,
                    persistent = command == COMMAND_ECHO_PERSISTENT,
                )
            }

            if (command != COMMAND_CONNECT && command != COMMAND_UDP) {
                writeReply(output, REPLY_COMMAND_NOT_SUPPORTED)
                return null
            }
            val target = readTarget(input, addressType, deadline, output) ?: return null
            val portBytes = readExactly(input, 2, deadline)
            val destinationPort = ((portBytes[0].toInt() and 0xFF) shl 8) or
                (portBytes[1].toInt() and 0xFF)
            if (destinationPort == 0) {
                writeReply(output, REPLY_GENERAL_FAILURE)
                return null
            }
            client.soTimeout = 0
            return Request(command = command, target = target, port = destinationPort)
        }

        private fun readTarget(
            input: InputStream,
            addressType: Int,
            deadline: Long,
            output: OutputStream,
        ): Target? {
            return when (addressType) {
                ADDRESS_IPV4 -> {
                    val address = addressOf(readExactly(input, 4, deadline))
                    if (address == null) {
                        writeReply(output, REPLY_ADDRESS_NOT_SUPPORTED)
                        null
                    } else {
                        Target.Address(address)
                    }
                }
                ADDRESS_IPV6 -> {
                    val address = addressOf(readExactly(input, 16, deadline))
                    if (address == null) {
                        writeReply(output, REPLY_ADDRESS_NOT_SUPPORTED)
                        null
                    } else {
                        Target.Address(address)
                    }
                }
                ADDRESS_DOMAIN -> {
                    val length = readExactly(input, 1, deadline)[0].toInt() and 0xFF
                    if (length == 0) {
                        writeReply(output, REPLY_ADDRESS_NOT_SUPPORTED)
                        return null
                    }
                    val name = decodeName(readExactly(input, length, deadline))
                    if (name == null) {
                        writeReply(output, REPLY_ADDRESS_NOT_SUPPORTED)
                        null
                    } else {
                        Target.Name(name)
                    }
                }
                else -> {
                    writeReply(output, REPLY_ADDRESS_NOT_SUPPORTED)
                    null
                }
            }
        }

        private fun readExactly(input: InputStream, count: Int, deadline: Long): ByteArray {
            val bytes = ByteArray(count)
            var offset = 0
            while (offset < count) {
                val remaining = deadline - System.nanoTime()
                if (remaining <= 0) throw SocketTimeoutException()
                client.soTimeout = millisFrom(remaining)
                val read = input.read(bytes, offset, count - offset)
                if (read < 0) throw EOFException()
                offset += read
            }
            return bytes
        }

        private fun readFully(input: InputStream, count: Int): ByteArray {
            val bytes = ByteArray(count)
            var offset = 0
            while (offset < count) {
                val read = input.read(bytes, offset, count - offset)
                if (read < 0) throw EOFException()
                offset += read
            }
            return bytes
        }

        private fun writeSmallReply(output: OutputStream, first: Int, second: Int) {
            synchronized(clientWriteLock) {
                output.write(byteArrayOf(first.toByte(), second.toByte()))
                output.flush()
            }
        }

        private fun writeReply(output: OutputStream, code: Int) {
            val reply = byteArrayOf(
                SOCKS_VERSION.toByte(),
                code.toByte(),
                0,
                ADDRESS_IPV4.toByte(),
                0,
                0,
                0,
                0,
                0,
                0,
            )
            synchronized(clientWriteLock) {
                output.write(reply)
                output.flush()
            }
        }

        /** Send one final failure reply and keep the reply protection. */
        private fun writeFailureReply(output: OutputStream, code: Int) {
            beginReply()
            try {
                writeReply(output, code)
            } catch (_: Exception) {
                // The client is gone. The finally block closes the session.
            }
        }

        private fun serveTcp(request: Request, input: InputStream, output: OutputStream) {
            markConnecting()
            val flow = try {
                connectTcp(request.target ?: return, request.port)
            } catch (failure: ConnectFailure) {
                writeFailureReply(output, failure.replyCode)
                return
            } catch (_: Exception) {
                writeFailureReply(output, REPLY_GENERAL_FAILURE)
                return
            }
            markAwaitingRelay()
            if (!grantRelay(this)) {
                denyRelay()
                untrackTcp(flow)
                closeFlow(flow)
                writeFailureReply(output, REPLY_GENERAL_FAILURE)
                return
            }
            if (!admitRelayPhase(datagram = false)) {
                untrackTcp(flow)
                closeFlow(flow)
                writeFailureReply(output, REPLY_GENERAL_FAILURE)
                return
            }
            beginReply()
            try {
                writeReply(output, REPLY_SUCCEEDED)
            } catch (failure: Exception) {
                throw failure
            } finally {
                finishReply()
            }
            relayTcp(flow.socket, input, output)
        }

        private fun connectTcp(target: Target, destinationPort: Int): CellularFlow<Socket> {
            val deadline = System.nanoTime() + connectTimeout.toNanos()
            val addresses = resolve(target, deadline)
            var lastFailure: IOException? = null
            for (address in addresses) {
                val remaining = deadline - System.nanoTime()
                if (remaining <= 0) break
                val flow = try {
                    cellular.tcp()
                } catch (_: Exception) {
                    throw ConnectFailure(REPLY_GENERAL_FAILURE)
                }
                if (!trackTcp(flow)) {
                    closeFlow(flow)
                    throw ConnectFailure(REPLY_GENERAL_FAILURE)
                }
                try {
                    flow.socket.tcpNoDelay = true
                    flow.socket.keepAlive = true
                    flow.socket.connect(InetSocketAddress(address, destinationPort), millisFrom(remaining))
                    return flow
                } catch (failure: IOException) {
                    lastFailure = failure
                    untrackTcp(flow)
                    closeFlow(flow)
                } catch (_: Exception) {
                    untrackTcp(flow)
                    closeFlow(flow)
                    throw ConnectFailure(REPLY_GENERAL_FAILURE)
                }
            }
            throw ConnectFailure(replyCodeFor(lastFailure))
        }

        private fun serveUdp(request: Request, input: InputStream, output: OutputStream) {
            markConnecting()
            val deadline = System.nanoTime() + connectTimeout.toNanos()
            val address = try {
                resolve(request.target ?: return, deadline).firstOrNull()
            } catch (_: ConnectFailure) {
                writeFailureReply(output, REPLY_GENERAL_FAILURE)
                return
            } catch (_: Exception) {
                writeFailureReply(output, REPLY_GENERAL_FAILURE)
                return
            }
            if (address == null) {
                writeFailureReply(output, REPLY_GENERAL_FAILURE)
                return
            }
            val flow = try {
                cellular.udp()
            } catch (_: Exception) {
                writeFailureReply(output, REPLY_GENERAL_FAILURE)
                return
            }
            if (!trackUdp(flow)) {
                closeFlow(flow)
                writeFailureReply(output, REPLY_GENERAL_FAILURE)
                return
            }
            val socket = flow.socket
            try {
                socket.connect(InetSocketAddress(address, request.port))
            } catch (_: Exception) {
                untrackUdp(flow)
                closeFlow(flow)
                writeFailureReply(output, REPLY_GENERAL_FAILURE)
                return
            }
            markAwaitingRelay()
            if (!grantRelay(this)) {
                denyRelay()
                untrackUdp(flow)
                closeFlow(flow)
                writeFailureReply(output, REPLY_GENERAL_FAILURE)
                return
            }
            if (!admitRelayPhase(datagram = true)) {
                untrackUdp(flow)
                closeFlow(flow)
                writeFailureReply(output, REPLY_GENERAL_FAILURE)
                return
            }
            beginReply()
            try {
                writeReply(output, REPLY_SUCCEEDED)
            } finally {
                finishReply()
            }
            startUdpReader(socket, output)
            readUdpFrames(input, socket)
        }

        private fun startUdpReader(socket: DatagramSocket, output: OutputStream) {
            val reader = Thread({
                try {
                    val buffer = ByteArray(MAX_DATAGRAM + 1)
                    while (!closed) {
                        val packet = DatagramPacket(buffer, buffer.size)
                        socket.receive(packet)
                        touch()
                        if (packet.length > MAX_DATAGRAM) {
                            close()
                            break
                        }
                        val payload = packet.data.copyOfRange(
                            packet.offset,
                            packet.offset + packet.length,
                        )
                        writeDatagram(output, payload)
                    }
                } catch (_: Exception) {
                    // A closed socket or a stopped session ends the reader.
                } finally {
                    close()
                }
            }, "source-udp-in")
            reader.isDaemon = true
            reader.start()
        }

        private fun writeDatagram(output: OutputStream, payload: ByteArray) {
            val header = byteArrayOf(
                (payload.size ushr 8).toByte(),
                payload.size.toByte(),
            )
            synchronized(clientWriteLock) {
                output.write(header)
                output.write(payload)
                output.flush()
            }
        }

        private fun readUdpFrames(input: InputStream, socket: DatagramSocket) {
            client.soTimeout = millisFrom(udpIdleTimeout.toNanos())
            val destination = socket.remoteSocketAddress as? InetSocketAddress
                ?: throw IOException("The UDP destination is not connected.")
            while (!closed) {
                val header = readFully(input, 2)
                val length = ((header[0].toInt() and 0xFF) shl 8) or
                    (header[1].toInt() and 0xFF)
                if (length > MAX_DATAGRAM) {
                    close()
                    return
                }
                val payload = if (length == 0) EMPTY else readFully(input, length)
                touch()
                socket.send(DatagramPacket(payload, payload.size, destination.address, destination.port))
            }
        }

        private fun relayTcp(destination: Socket, clientInput: InputStream, clientOutput: OutputStream) {
            val destinationInput = destination.getInputStream()
            val destinationOutput = destination.getOutputStream()
            val up = Thread({
                pump(
                    clientInput,
                    destinationOutput,
                    destinationWriteLock,
                    onEnd = {
                        noteHalfClose()
                        shutdownOutputQuietly(destination)
                    },
                )
            }, "source-relay-up")
            up.isDaemon = true
            val down = Thread({
                pump(
                    destinationInput,
                    clientOutput,
                    clientWriteLock,
                    onEnd = {
                        noteHalfClose()
                        shutdownOutputQuietly(client)
                    },
                )
            }, "source-relay-down")
            down.isDaemon = true
            up.start()
            down.start()
            try {
                up.join()
                down.join()
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                close()
            }
        }

        private fun pump(
            input: InputStream,
            output: OutputStream,
            writeLock: Any,
            onEnd: () -> Unit,
        ) {
            try {
                val buffer = ByteArray(CLIENT_BUFFER)
                while (!closed) {
                    val read = input.read(buffer)
                    if (read < 0) {
                        onEnd()
                        return
                    }
                    if (read == 0) continue
                    touch()
                    synchronized(writeLock) {
                        output.write(buffer, 0, read)
                        output.flush()
                    }
                }
            } catch (_: Exception) {
                close()
            } finally {
                if (relayDone.incrementAndGet() == 2) close()
            }
        }

        private fun serveEcho(request: Request, input: InputStream, output: OutputStream) {
            val target = request.echoTarget ?: return
            if (request.persistent && !acquirePersistentSlot()) {
                writeFailureReply(output, REPLY_GENERAL_FAILURE)
                return
            }
            beginControl()
            beginReply()
            try {
                writeReply(output, REPLY_SUCCEEDED)
            } finally {
                finishReply()
            }
            if (request.persistent) {
                servePersistentEcho(target, input, output)
            } else {
                serveSingleEcho(target, input, output)
            }
        }

        private fun serveSingleEcho(
            target: EchoTarget,
            input: InputStream,
            output: OutputStream,
        ) {
            client.soTimeout = millisFrom(echoRequestTimeout.toNanos())
            val header = readFully(input, 2)
            val length = ((header[0].toInt() and 0xFF) shl 8) or (header[1].toInt() and 0xFF)
            if (length > SourceEchoWire.MAXIMUM_PAYLOAD) {
                writeEchoResponse(output, EchoStatus.FAILED, EMPTY)
                return
            }
            val payload = if (length == 0) EMPTY else readFully(input, length)
            touch()
            val result = echo?.send(target, payload, echoAttemptTimeout.toMillis())
                ?: EchoResult(EchoStatus.FAILED)
            val echoed = result.status == EchoStatus.SUCCESS &&
                result.payload.size == payload.size &&
                result.payload.contentEquals(payload)
            val status = if (echoed) EchoStatus.SUCCESS else {
                if (result.status == EchoStatus.SUCCESS) EchoStatus.FAILED else result.status
            }
            writeEchoResponse(output, status, if (echoed) payload else EMPTY)
        }

        private fun servePersistentEcho(
            target: EchoTarget,
            input: InputStream,
            output: OutputStream,
        ) {
            val sender = echo ?: run {
                writeEchoResponse(output, EchoStatus.FAILED, EMPTY)
                return
            }
            startEchoTimers()
            while (!closed && state == State.RUNNING) {
                client.soTimeout = millisFrom(echoIdleTimeout.toNanos())
                val header = readFully(input, 2)
                val length = ((header[0].toInt() and 0xFF) shl 8) or
                    (header[1].toInt() and 0xFF)
                if (length > SourceEchoWire.MAXIMUM_PAYLOAD) {
                    close()
                    return
                }
                val payload = if (length == 0) EMPTY else readFully(input, length)
                touch()
                resetEchoIdle()
                val result = sender.send(target, payload, echoAttemptTimeout.toMillis())
                val echoed = result.status == EchoStatus.SUCCESS &&
                    result.payload.size == payload.size &&
                    result.payload.contentEquals(payload)
                val status = if (echoed) EchoStatus.SUCCESS else {
                    if (result.status == EchoStatus.SUCCESS) EchoStatus.FAILED else result.status
                }
                writeEchoResponse(output, status, if (echoed) payload else EMPTY)
                if (!echoed) {
                    close()
                    return
                }
                resetEchoIdle()
            }
        }

        private fun writeEchoResponse(
            output: OutputStream,
            status: EchoStatus,
            payload: ByteArray,
        ) {
            val frame = ByteArray(3 + payload.size)
            frame[0] = status.wire.toByte()
            frame[1] = ((payload.size shr 8) and 0xFF).toByte()
            frame[2] = (payload.size and 0xFF).toByte()
            payload.copyInto(frame, 3)
            synchronized(clientWriteLock) {
                output.write(frame)
                output.flush()
            }
        }
    }

    private sealed class Target {
        class Address(val address: InetAddress) : Target() {
            override fun toString(): String = "Target.Address"
        }

        class Name(val host: String) : Target() {
            override fun toString(): String = "Target.Name"
        }
    }

    private class Request(
        val command: Int,
        val target: Target?,
        val port: Int,
        val echoTarget: EchoTarget? = null,
        val persistent: Boolean = false,
    ) {
        override fun toString(): String = "SourceSocksRequest"
    }

    private class ConnectFailure(val replyCode: Int) : Exception() {
        override fun toString(): String = "ConnectFailure"
    }

    private fun resolve(target: Target, deadline: Long): List<InetAddress> = when (target) {
        is Target.Address -> listOf(target.address)
        is Target.Name -> resolveName(target.host, deadline)
    }

    private fun resolveName(host: String, deadline: Long): List<InetAddress> {
        val remaining = deadline - System.nanoTime()
        if (remaining <= 0) throw ConnectFailure(REPLY_GENERAL_FAILURE)
        val executor = resolverExecutor ?: throw ConnectFailure(REPLY_GENERAL_FAILURE)
        val future = try {
            executor.submit(Callable { resolver.resolve(host) })
        } catch (_: RejectedExecutionException) {
            throw ConnectFailure(REPLY_GENERAL_FAILURE)
        }
        val addresses = try {
            future.get(remaining, TimeUnit.NANOSECONDS)
        } catch (_: TimeoutException) {
            future.cancel(true)
            throw ConnectFailure(REPLY_GENERAL_FAILURE)
        } catch (_: InterruptedException) {
            future.cancel(true)
            Thread.currentThread().interrupt()
            throw ConnectFailure(REPLY_GENERAL_FAILURE)
        } catch (_: ExecutionException) {
            throw ConnectFailure(REPLY_GENERAL_FAILURE)
        } catch (_: CancellationException) {
            throw ConnectFailure(REPLY_GENERAL_FAILURE)
        }
        if (addresses.isEmpty()) throw ConnectFailure(REPLY_GENERAL_FAILURE)
        return addresses
    }

    private fun replyCodeFor(failure: IOException?): Int = when (failure) {
        is ConnectException -> REPLY_REFUSED
        is NoRouteToHostException -> REPLY_UNREACHABLE
        else -> REPLY_GENERAL_FAILURE
    }

    private fun addressOf(bytes: ByteArray): InetAddress? = try {
        // A byte array is a literal. This method does not resolve a name.
        InetAddress.getByAddress(bytes)
    } catch (_: Exception) {
        null
    }

    private fun decodeName(bytes: ByteArray): String? {
        val decoder = StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
        val name = try {
            decoder.decode(ByteBuffer.wrap(bytes)).toString()
        } catch (_: CharacterCodingException) {
            return null
        }
        if (name.isEmpty() || name.indexOf('\u0000') >= 0) return null
        return name
    }

    private fun millisFrom(nanos: Long): Int =
        maxOf(1L, nanos / 1_000_000L).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()

    private fun nanosToMillis(nanos: Long): Long = maxOf(0L, nanos / 1_000_000L)

    private fun daemonFactory(prefix: String): ThreadFactory {
        val count = AtomicInteger()
        return ThreadFactory { runnable ->
            Thread(runnable, "$prefix-${count.incrementAndGet()}").apply {
                isDaemon = true
            }
        }
    }

    private fun closeFlow(flow: CellularFlow<*>?) {
        if (flow == null) return
        try {
            flow.close()
        } catch (_: Exception) {
            // A failed close must not hide the session end.
        }
    }

    private fun closeQuietly(closeable: Closeable?) {
        if (closeable == null) return
        try {
            closeable.close()
        } catch (_: Exception) {
            // The session is already ending.
        }
    }

    private fun shutdownOutputQuietly(socket: Socket?) {
        if (socket == null) return
        try {
            socket.shutdownOutput()
        } catch (_: Exception) {
            // The other end already closed.
        }
    }
}
