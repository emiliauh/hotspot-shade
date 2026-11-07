package com.hotspotshade.source

import java.io.Closeable
import java.io.IOException
import java.net.InetAddress
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

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
    LISTENER_FAILED,
    TOKEN_MISSING,
    TOKEN_UNREADABLE,
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

    /**
     * True while the listener still accepts connections.
     *
     * The production handle reads the server state. A test fake may leave the
     * default true when it does not exercise listener health.
     */
    val isRunning: Boolean get() = true

    /**
     * A fixed label for a failure that stopped the listener, or null.
     *
     * The label is a word such as `accept`, never an address, host, token, or
     * exception text.
     */
    val failureReason: String? get() = null

    /** Bind the listener. */
    fun start()
}

/**
 * Watch one published listener for an unexpected stop.
 *
 * The production monitor is one daemon thread per run. It calls
 * [onFailure] at most once. [close] is non-blocking and does not interrupt a
 * failure callback that is already running on the same thread.
 */
internal interface SourceServerHealthMonitor : Closeable {
    /** Start watching. This call is idempotent. */
    fun start()
}

/** Build one health monitor for one published listener. */
internal fun interface SourceServerHealthMonitorFactory {
    fun create(
        server: SourceServerHandle,
        onFailure: () -> Unit,
    ): SourceServerHealthMonitor

    companion object {
        /** A test or a caller that supplies no listener health. */
        val NONE: SourceServerHealthMonitorFactory =
            SourceServerHealthMonitorFactory { _, _ -> NoSourceServerHealthMonitor }

        /** The production monitor. One daemon thread checks the live handle. */
        val PRODUCTION: SourceServerHealthMonitorFactory =
            SourceServerHealthMonitorFactory { server, onFailure ->
                PollingSourceServerHealthMonitor(server, onFailure)
            }
    }
}

private object NoSourceServerHealthMonitor : SourceServerHealthMonitor {
    override fun start() = Unit

    override fun close() = Unit
}

/** The production listener health monitor. */
internal class PollingSourceServerHealthMonitor(
    private val server: SourceServerHandle,
    private val onFailure: () -> Unit,
    private val pollMillis: Long = SERVER_HEALTH_POLL_MILLIS,
) : SourceServerHealthMonitor {
    private val worker = Thread({ poll() }, "source-server-health").apply {
        isDaemon = true
    }

    @Volatile
    private var watching = true

    override fun start() {
        if (worker.state == Thread.State.NEW) worker.start()
    }

    private fun poll() {
        while (watching) {
            if (!server.isRunning) {
                if (watching) onFailure()
                return
            }
            try {
                Thread.sleep(pollMillis)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return
            }
        }
    }

    override fun close() {
        watching = false
        if (worker !== Thread.currentThread()) worker.interrupt()
    }

    private companion object {
        const val SERVER_HEALTH_POLL_MILLIS = 250L
    }
}

/** The service receives each state change. A callback can arrive on a network thread. */
internal fun interface SourceProxyListener {
    fun onStateChanged(snapshot: SourceProxySnapshot)
}

/**
 * Run one controller task off the calling thread.
 *
 * Production supplies one daemon thread that runs the bounded hotspot wait and
 * the session setup. A JVM test supplies a manual queue so it can decide when
 * each step runs. The queue is shut down on every exit path.
 */
internal interface SourceProxyTaskQueue {
    /** Run one task. Throw when the queue is already shut down. */
    fun execute(task: Runnable)

    /**
     * Drop queued work and stop the worker. This call is idempotent.
     *
     * A shutdown that runs on the worker thread must not interrupt that
     * thread: the cleanup that follows the stop uses the same thread. A
     * shutdown from another thread interrupts the worker so a bounded wait
     * ends at once.
     */
    fun shutdown()
}

/**
 * The production queue: one daemon thread per owner.
 *
 * The controller uses one queue for the hotspot wait and the session setup.
 * The service uses a separate queue for the run lifecycle, so a slow token
 * load or a slow listener close never runs on the main thread.
 */
internal class SingleThreadSourceProxyTaskQueue(
    private val threadName: String = "source-proxy-controller",
) : SourceProxyTaskQueue {
    private val workerThread = AtomicReference<Thread?>(null)
    private val executor = ThreadPoolExecutor(
        1,
        1,
        0L,
        TimeUnit.MILLISECONDS,
        LinkedBlockingQueue(),
    ) { runnable ->
        Thread(runnable, threadName).apply {
            isDaemon = true
            workerThread.set(this)
        }
    }

    override fun execute(task: Runnable) = executor.execute(task)

    override fun shutdown() {
        if (workerThread.get() === Thread.currentThread()) {
            // Do not interrupt the cleanup that runs on this thread. Drop only
            // the work that has not started and let this task finish.
            executor.queue.clear()
            executor.shutdown()
        } else {
            executor.shutdownNow()
        }
    }
}

/**
 * Run one source proxy: wait for a confirmed hotspot address, wait for the
 * cellular network, bind the hotspot address, and stop on every loss.
 *
 * The controller never restarts itself. A stopped controller cannot start
 * again. The service creates a new controller only for a new start that the
 * user requests.
 *
 * The first hotspot probe runs on the controller task queue, never on the
 * caller thread. On Android 16 or later the API 36 tethering callback can be
 * registered before it delivers its first reading. The finder reports
 * [HotspotProbe.Pending] during that window. A pending probe is not a missing
 * hotspot: the start waits a bounded time for a real reading, with the same
 * bound as the evidence. The wait holds no controller lock. A stop, a terminal
 * state, or a lost run ends the wait at once and a late result binds nothing.
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
    private val serverHealthMonitorFactory: SourceServerHealthMonitorFactory =
        SourceServerHealthMonitorFactory.NONE,
    private val tokenGuard: SourceTokenGuard = SourceTokenGuard.shared,
    private val taskQueueFactory: () -> SourceProxyTaskQueue = {
        SingleThreadSourceProxyTaskQueue()
    },
    private val clockMillis: () -> Long = {
        TimeUnit.NANOSECONDS.toMillis(System.nanoTime())
    },
    private val sleepMillis: (Long) -> Unit = { millis -> Thread.sleep(millis) },
    private val pendingWaitMillis: Long = DEFAULT_PENDING_WAIT_MILLIS,
    private val pendingPollMillis: Long = DEFAULT_PENDING_POLL_MILLIS,
    /**
     * Saves the first source token. Null keeps the old rule: a start with no
     * stored token stops with TOKEN_MISSING. The service passes the token
     * store, which is also a [TokenWriter].
     */
    private val tokenWriter: TokenWriter? = null,
    private val tokenFactory: () -> String = { TokenRotation.newToken() },
) : SourceProxyServiceRun {
    init {
        require(pendingWaitMillis > 0) {
            "The hotspot pending wait must be positive."
        }
        require(pendingPollMillis > 0) {
            "The hotspot pending poll interval must be positive."
        }
    }

    private val lock = Any()
    private var phase = SourceProxyState.IDLE
    private var reason = SourceProxyStopReason.NONE
    private var token: String? = null
    private var holdsRunLease = false
    private var starting = false
    private var attempt = 0L
    private var monitor: CellularNetworkMonitor? = null
    private var server: SourceServerHandle? = null
    private var watch: HotspotWatch? = null
    private var healthMonitor: SourceServerHealthMonitor? = null
    private var listenerFailureValue: String? = null
    private var port = 0
    private var bindingPort = 0
    private var bindingAddress: InetAddress? = null
    private var pendingServer: SourceServerHandle? = null
    private var closeFailureValue: IOException? = null
    private var taskQueue: SourceProxyTaskQueue? = null
    private var activeTasks = 0
    private var taskGateClosed = false
    private var releasePending = false

    /** The current state. It stays IDLE while a start waits for its first probe. */
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

    /** True while a start waits, a run waits for the network, or flows are served. */
    override val isActive: Boolean
        get() = synchronized(lock) {
            starting ||
                phase == SourceProxyState.WAITING_FOR_NETWORK ||
                phase == SourceProxyState.RUNNING
        }

    /** The last cellular socket close failure, or null after a complete close. */
    override val closeFailure: IOException?
        get() = synchronized(lock) { closeFailureValue }

    /**
     * The fixed server failure label that ended the run, or null.
     *
     * The label is a word such as `accept`. It holds no address, host, token,
     * or exception text.
     */
    val listenerFailure: String?
        get() = synchronized(lock) { listenerFailureValue }

    /**
     * The listener binding that the pairing responder may name.
     *
     * The port and address are set as soon as the listener binds, before the
     * run publishes RUNNING. A start that has not bound yet reports an active
     * binding with port 0, so the pairing responder answers NOT_ACTIVE instead
     * of probing the port that the start is about to claim.
     */
    internal fun binding(): SourceProxyBinding = synchronized(lock) {
        // The state, the port, the address, and the relay counts belong to one
        // run. Read them under one lock so a stop cannot report a stopped
        // state with a live count, or the reverse. A listener that bound but
        // has not published yet owns the transition and its own counters.
        val live = server ?: pendingServer
        SourceProxyBinding(
            state = phase,
            active = starting ||
                phase == SourceProxyState.WAITING_FOR_NETWORK ||
                phase == SourceProxyState.RUNNING,
            port = bindingPort,
            address = bindingAddress,
            connections = live?.activeConnections ?: 0,
            totalConnections = live?.totalConnections ?: 0L,
            // The attempt number names this controller run. The process
            // runtime replaces it with a process-wide value when it attaches
            // the controller, so two controller instances cannot collide.
            runId = attempt,
        )
    }

    /**
     * The live state report.
     *
     * A repeated start request reads this to restore the report that it may
     * have cleared. The snapshot holds no token, address, or host.
     */
    override fun snapshot(): SourceProxySnapshot = synchronized(lock) { snapshotLocked() }

    /**
     * Start one run. Return false when this controller cannot start.
     *
     * A second call returns false. This includes a call while the first start
     * waits for its first hotspot probe, so one controller never creates a
     * second queue, monitor, watch, or run lease.
     *
     * The hotspot probe runs on the controller task queue. The method reports
     * a terminal snapshot for a token failure, and through the listener for a
     * missing hotspot or a failed setup.
     */
    override fun start(): Boolean {
        var initial: SourceProxySnapshot? = null
        var attemptToRun = 0L
        var guardAttempt = 0L
        synchronized(lock) {
            if (phase != SourceProxyState.IDLE || starting) return false
            starting = true
            // A harmless stop on a fresh controller must not block this start.
            taskGateClosed = false
            attempt += 1
            guardAttempt = attempt
        }
        // Take the run lease without the controller lock. A token rotation
        // holds the guard while it writes the store, and a status read must
        // not wait for that write.
        val acquired = tokenGuard.beginRun()
        var aborted = false
        var releaseGuard = false
        synchronized(lock) {
            if (!isStartingLocked(guardAttempt)) {
                // A stop won while the guard was acquired. It reported the
                // terminal state and did not see this lease yet.
                aborted = true
                releaseGuard = acquired
            } else if (!acquired) {
                // Another run owns the token lease. Do not load the token or
                // bind a listener over the live run. A stop can defer the
                // release until its last in-flight task returns, so a very
                // quick restart can arrive inside that window. Refusing here
                // is the safe outcome: the old task may still bind and close a
                // listener, and a rotation must not replace the token under
                // it. The person can start again once the task returns; the
                // service never restarts a run on its own.
                phase = SourceProxyState.STOPPED
                reason = SourceProxyStopReason.START_FAILED
                starting = false
                initial = snapshotLocked()
            } else {
                holdsRunLease = true
                attemptToRun = guardAttempt
            }
        }
        if (releaseGuard) tokenGuard.endRun()
        if (aborted) return false
        initial?.let { report ->
            listener.onStateChanged(report)
            return false
        }
        // Read the token outside the controller lock. The load can touch disk
        // and the Android Keystore, so a status read, a pairing binding read,
        // and a stop must not wait for it. The attempt number decides whether
        // the stop path already ended this start while the load ran.
        var stored: String? = null
        var unreadable = false
        try {
            stored = tokenStore.load()
        } catch (_: Exception) {
            // A stored token that cannot be read is not a missing token. Do
            // not send the person to pair again.
            unreadable = true
        }
        // A missing token on the first start is not a reason to send the
        // person to pair: iOS creates its token at launch and a manual SOCKS5
        // client needs one. The save goes through the token guard, like a
        // pairing save, and only when the store proves the token absent.
        var failedFirstToken = false
        val firstTokenWriter = tokenWriter
        if (!unreadable && stored == null && firstTokenWriter != null) {
            when (val outcome = createFirstToken(firstTokenWriter)) {
                is FirstToken.Created -> stored = outcome.token
                is FirstToken.Existing -> stored = outcome.token
                FirstToken.Unreadable -> unreadable = true
                FirstToken.Failed -> failedFirstToken = true
            }
        }
        synchronized(lock) {
            if (!isStartingLocked(attemptToRun)) {
                // A stop ended the run while the token was read. That path
                // already reported the terminal state and released the lease.
                return false
            }
            if (unreadable || (stored != null && !isUsableSourceToken(stored))) {
                // A stored token that cannot be read or is not usable is not
                // a missing token. Do not send the person to pair again over
                // a token that may still be there.
                phase = SourceProxyState.STOPPED
                reason = SourceProxyStopReason.TOKEN_UNREADABLE
                releaseRunLocked()
                starting = false
                initial = snapshotLocked()
            } else if (failedFirstToken) {
                // The first token could not be saved. Do not run without a
                // stored token: a target device could not pair for it later.
                phase = SourceProxyState.STOPPED
                reason = SourceProxyStopReason.START_FAILED
                releaseRunLocked()
                starting = false
                initial = snapshotLocked()
            } else if (stored == null) {
                phase = SourceProxyState.STOPPED
                reason = SourceProxyStopReason.TOKEN_MISSING
                releaseRunLocked()
                starting = false
                initial = snapshotLocked()
            } else {
                token = stored
                try {
                    // Keep one queue per controller. The start wait and every
                    // session setup share it, so the setup runs off the
                    // connectivity and caller threads.
                    taskQueue = taskQueueFactory()
                } catch (_: Exception) {
                    phase = SourceProxyState.STOPPED
                    reason = SourceProxyStopReason.START_FAILED
                    releaseRunLocked()
                    starting = false
                    initial = snapshotLocked()
                }
            }
        }
        initial?.let { report ->
            listener.onStateChanged(report)
            return false
        }
        val queue = synchronized(lock) {
            if (starting && attempt == attemptToRun) taskQueue else null
        } ?: run {
            // A stop ended the run before the wait was submitted.
            finish(SourceProxyStopReason.START_FAILED)
            return false
        }
        return try {
            queue.execute { runTask { awaitInitialHotspot(attemptToRun) } }
            true
        } catch (_: Exception) {
            // The stop path closed the queue before this submit.
            finish(SourceProxyStopReason.START_FAILED)
            false
        }
    }

    private sealed interface FirstToken {
        data class Created(val token: String) : FirstToken {
            override fun toString(): String = "Created([redacted])"
        }

        data class Existing(val token: String) : FirstToken {
            override fun toString(): String = "Existing([redacted])"
        }

        data object Unreadable : FirstToken

        data object Failed : FirstToken
    }

    /**
     * Save a first source token when the store still proves none exists.
     *
     * The store is read again inside the guard, so a pairing or a rotation
     * that saved a token first wins and this start uses that token. A failed
     * or uncertain save is never reported as created. The guard epoch moves
     * after a created token, so a pairing listener that holds an in-memory
     * candidate reloads the stored token instead of sealing a different one.
     * The caller holds no controller lock and no coordinator lock.
     */
    private fun createFirstToken(writer: TokenWriter): FirstToken {
        repeat(FIRST_TOKEN_ATTEMPTS) {
            var outcome: FirstToken = FirstToken.Failed
            var uncertain = false
            val ran = tokenGuard.savePairingToken(tokenGuard.epoch()) {
                val current = try {
                    tokenStore.load()
                } catch (_: Exception) {
                    outcome = FirstToken.Unreadable
                    return@savePairingToken
                }
                if (current != null) {
                    outcome = if (isUsableSourceToken(current)) {
                        FirstToken.Existing(current)
                    } else {
                        FirstToken.Unreadable
                    }
                    return@savePairingToken
                }
                val candidate = tokenFactory()
                if (!isUsableSourceToken(candidate)) return@savePairingToken
                try {
                    writer.save(candidate)
                } catch (failure: TokenWriteUncertainException) {
                    uncertain = true
                    throw failure
                }
                outcome = FirstToken.Created(candidate)
            }
            if (uncertain) {
                // The token may or may not be durable. The pairing rule is the
                // same: an uncertain save fails. Do not run on a token that a
                // later read happens to show; the person can start again.
                ActivityLog.record(ActivityEvent.TOKEN_SAVE_FAILED)
                return FirstToken.Failed
            }
            if (ran) {
                if (outcome is FirstToken.Created) {
                    ActivityLog.record(ActivityEvent.TOKEN_CREATED)
                    tokenGuard.invalidate()
                }
                return outcome
            }
            // The epoch moved or the save failed. A failed save leaves the
            // outcome at Failed; try once more with a fresh epoch.
        }
        ActivityLog.record(ActivityEvent.TOKEN_SAVE_FAILED)
        return FirstToken.Failed
    }

    /** Stop the run and close every owned resource. This call is idempotent. */
    override fun stop() = finish(SourceProxyStopReason.USER_STOP)

    /**
     * Run one controller task with the run lease held.
     *
     * A task that begins after [finish] closed the gate does nothing. A task
     * that already runs owns the lease until it returns, because it may still
     * close a listener that it created. [finish] therefore transfers the lease
     * to this task instead of releasing it under the worker. The release runs
     * after the last in-flight task returns, never while holding the lock.
     */
    private fun runTask(task: Runnable) {
        synchronized(lock) {
            if (taskGateClosed) return
            activeTasks += 1
        }
        try {
            task.run()
        } finally {
            var releaseRun = false
            synchronized(lock) {
                activeTasks -= 1
                if (activeTasks == 0 && releasePending) {
                    releasePending = false
                    releaseRun = true
                }
            }
            if (releaseRun) tokenGuard.endRun()
        }
    }

    /**
     * Wait a bounded time for the first usable probe.
     *
     * This task runs on the controller queue. It never takes the controller
     * lock across a probe or a sleep. A pending probe is retried until the
     * caller's bound; an absent or unknown probe takes the normal not-found
     * path at once.
     */
    private fun awaitInitialHotspot(capturedAttempt: Long) {
        val deadline = clockMillis() + pendingWaitMillis
        while (true) {
            if (!isStarting(capturedAttempt)) return
            val probe = probeSafely()
            if (probe !is HotspotProbe.Pending) {
                completeStart(capturedAttempt, probe)
                return
            }
            val remaining = deadline - clockMillis()
            if (remaining <= 0L) {
                // No run was bound, so this is not a hotspot loss.
                finishIfStarting(capturedAttempt, SourceProxyStopReason.HOTSPOT_NOT_FOUND)
                return
            }
            sleepBeforeRetry(minOf(pendingPollMillis, remaining))
        }
    }

    /**
     * Continue the normal start path with one non-pending probe.
     *
     * The controller lock is held only to publish the state. Selection and
     * monitor construction do not block on a platform call.
     */
    private fun completeStart(capturedAttempt: Long, probe: HotspotProbe) {
        val hotspot = confirmedAddress(probe)
        var report: SourceProxySnapshot? = null
        var monitorToStart: CellularNetworkMonitor? = null
        var queueToShutdown: SourceProxyTaskQueue? = null
        synchronized(lock) {
            if (!isStartingLocked(capturedAttempt)) return
            if (hotspot == null) {
                phase = SourceProxyState.STOPPED
                reason = SourceProxyStopReason.HOTSPOT_NOT_FOUND
                starting = false
                attempt += 1
                token = null
                port = 0
                bindingPort = 0
                bindingAddress = null
                queueToShutdown = taskQueue
                taskQueue = null
                releaseRunLocked()
                report = snapshotLocked()
            } else {
                try {
                    val selection = ObservingSelection(selectionFactory()) { event ->
                        onNetworkStopped(event)
                    }
                    val newMonitor = CellularNetworkMonitor(selection, ::openSession)
                    monitor = newMonitor
                    monitorToStart = newMonitor
                    phase = SourceProxyState.WAITING_FOR_NETWORK
                    starting = false
                    report = snapshotLocked()
                } catch (_: Exception) {
                    phase = SourceProxyState.STOPPED
                    reason = SourceProxyStopReason.START_FAILED
                    starting = false
                    attempt += 1
                    token = null
                    port = 0
                    bindingPort = 0
                    bindingAddress = null
                    queueToShutdown = taskQueue
                    taskQueue = null
                    releaseRunLocked()
                    report = snapshotLocked()
                }
            }
        }
        val finished = report ?: return
        queueToShutdown?.shutdown()
        val toStart = monitorToStart
        if (toStart == null) {
            listener.onStateChanged(finished)
            return
        }
        // Skip a late WAITING report when a stop already reported the terminal
        // state and closed this monitor.
        val stillWaiting = synchronized(lock) {
            phase == SourceProxyState.WAITING_FOR_NETWORK && attempt == capturedAttempt
        }
        if (!stillWaiting) return
        listener.onStateChanged(finished)
        try {
            toStart.start()
        } catch (_: Exception) {
            finish(SourceProxyStopReason.START_FAILED)
        }
    }

    /**
     * Open one cellular session for a selected network.
     *
     * The call returns the session at once and queues the hotspot wait and the
     * listener setup. The network monitor holds its own lock around this call,
     * so the bounded wait must not run here. On a pending callback the session
     * stays open while the queue waits; a deadline stops the run and closes
     * the session through the monitor.
     */
    private fun openSession(binding: CellularBinding): CellularSession {
        val session = CellularSession(CellularSockets(binding))
        val capturedAttempt: Long
        val tokenValue: String?
        val queue: SourceProxyTaskQueue?
        synchronized(lock) {
            if (phase != SourceProxyState.WAITING_FOR_NETWORK) {
                closeQuietly(session)
                throw IOException("The proxy is not waiting for the hotspot.")
            }
            capturedAttempt = attempt
            tokenValue = token
            queue = taskQueue
        }
        if (tokenValue == null) {
            closeQuietly(session)
            finish(SourceProxyStopReason.TOKEN_MISSING)
            throw IOException("The source token is not available.")
        }
        if (queue == null) {
            closeQuietly(session)
            throw IOException("The proxy is stopping.")
        }
        try {
            queue.execute {
                runTask {
                    awaitSessionHotspot(session, binding, tokenValue, capturedAttempt)
                }
            }
        } catch (_: Exception) {
            closeQuietly(session)
            throw IOException("The proxy is stopping.")
        }
        return session
    }

    /**
     * Wait for a hotspot reading before the listener setup.
     *
     * A pending callback is retried with the same bound as the start path. A
     * deadline reports one HOTSPOT_NOT_FOUND and closes the session. A healthy
     * session is not closed merely because the callback is briefly pending.
     */
    private fun awaitSessionHotspot(
        session: CellularSession,
        binding: CellularBinding,
        tokenValue: String,
        capturedAttempt: Long,
    ) {
        val deadline = clockMillis() + pendingWaitMillis
        while (true) {
            if (!isWaitingForHotspot(capturedAttempt)) {
                closeQuietly(session)
                return
            }
            val probe = probeSafely()
            if (probe !is HotspotProbe.Pending) {
                val hotspot = confirmedAddress(probe)
                if (hotspot == null) {
                    finishIfWaiting(capturedAttempt, SourceProxyStopReason.HOTSPOT_NOT_FOUND)
                    return
                }
                setupSession(session, binding, hotspot, tokenValue, capturedAttempt)
                return
            }
            val remaining = deadline - clockMillis()
            if (remaining <= 0L) {
                finishIfWaiting(capturedAttempt, SourceProxyStopReason.HOTSPOT_NOT_FOUND)
                return
            }
            sleepBeforeRetry(minOf(pendingPollMillis, remaining))
        }
    }

    /**
     * Bind the listener for one confirmed hotspot address.
     *
     * A stop that wins the race closes the new resources instead of publishing
     * them. The session belongs to the network monitor until the run ends.
     */
    private fun setupSession(
        session: CellularSession,
        binding: CellularBinding,
        hotspot: InetAddress,
        tokenValue: String,
        capturedAttempt: Long,
    ) {
        if (!isWaitingForHotspot(capturedAttempt)) {
            closeQuietly(session)
            return
        }
        val resolver = try {
            resolverFactory(binding)
        } catch (_: Exception) {
            closeQuietly(session)
            finishIfWaiting(capturedAttempt, SourceProxyStopReason.START_FAILED)
            return
        }
        // A stop can arrive during any setup step. Do not construct or bind a
        // listener after it. The attempt number under the lock is the lease
        // that every step checks.
        if (!isWaitingForHotspot(capturedAttempt)) {
            closeQuietly(session)
            return
        }
        val echo = try {
            echoFactory(binding)
        } catch (_: Exception) {
            closeQuietly(session)
            finishIfWaiting(capturedAttempt, SourceProxyStopReason.START_FAILED)
            return
        }
        if (!isWaitingForHotspot(capturedAttempt)) {
            closeQuietly(session)
            return
        }
        val newServer = try {
            serverFactory(session, resolver, echo, hotspot, tokenValue)
        } catch (_: Exception) {
            closeQuietly(session)
            finishIfWaiting(capturedAttempt, SourceProxyStopReason.START_FAILED)
            return
        }
        if (!isWaitingForHotspot(capturedAttempt)) {
            closeQuietly(newServer)
            closeQuietly(session)
            return
        }
        try {
            newServer.start()
        } catch (_: Exception) {
            closeQuietly(newServer)
            closeQuietly(session)
            finishIfWaiting(capturedAttempt, SourceProxyStopReason.BIND_FAILED)
            return
        }
        if (!isWaitingForHotspot(capturedAttempt)) {
            closeQuietly(newServer)
            closeQuietly(session)
            return
        }
        // Publish the real binding before the run reports RUNNING. A pairing
        // answer that arrives during the remaining setup names the port and
        // address that actually bound. A stop that won the race clears the
        // binding and closes this listener below.
        val bound = synchronized(lock) {
            if (phase == SourceProxyState.WAITING_FOR_NETWORK &&
                attempt == capturedAttempt &&
                !taskGateClosed
            ) {
                pendingServer = newServer
                bindingPort = newServer.localPort
                bindingAddress = hotspot
                true
            } else {
                false
            }
        }
        if (!bound) {
            closeQuietly(newServer)
            closeQuietly(session)
            return
        }
        val newWatch = try {
            watchFactory(hotspot)
        } catch (_: Exception) {
            closeQuietly(newServer)
            closeQuietly(session)
            finishIfWaiting(capturedAttempt, SourceProxyStopReason.START_FAILED)
            return
        }
        if (!isWaitingForHotspot(capturedAttempt)) {
            stopWatchQuietly(newWatch)
            closeQuietly(newServer)
            closeQuietly(session)
            return
        }
        try {
            newWatch.start { onHotspotLost() }
        } catch (_: Exception) {
            stopWatchQuietly(newWatch)
            closeQuietly(newServer)
            closeQuietly(session)
            finishIfWaiting(capturedAttempt, SourceProxyStopReason.START_FAILED)
            return
        }
        val running: SourceProxySnapshot?
        synchronized(lock) {
            running = if (phase == SourceProxyState.WAITING_FOR_NETWORK &&
                attempt == capturedAttempt
            ) {
                server = newServer
                pendingServer = null
                watch = newWatch
                port = newServer.localPort
                token = null
                phase = SourceProxyState.RUNNING
                snapshotLocked()
            } else {
                null
            }
        }
        val published = running
        if (published == null) {
            // A stop raced with the setup. Close the new resources.
            stopWatchQuietly(newWatch)
            closeQuietly(newServer)
            closeQuietly(session)
            return
        }
        // Skip a late RUNNING report when a stop already reported the terminal
        // state and closed these resources.
        val stillRunning = synchronized(lock) {
            phase == SourceProxyState.RUNNING &&
                attempt == capturedAttempt &&
                server === newServer
        }
        if (!stillRunning) return
        // A bound listener must never report RUNNING without a health watcher.
        // A failed or unstartable watcher stops the run instead of leaving a
        // dead listener invisible.
        val health = try {
            serverHealthMonitorFactory.create(newServer) {
                onServerFailed(capturedAttempt, newServer)
            }
        } catch (_: Exception) {
            finishIfRunning(capturedAttempt, SourceProxyStopReason.LISTENER_FAILED)
            return
        }
        val healthAttached = synchronized(lock) {
            if (phase == SourceProxyState.RUNNING &&
                attempt == capturedAttempt &&
                server === newServer
            ) {
                healthMonitor = health
                true
            } else {
                false
            }
        }
        if (!healthAttached) {
            closeHealthQuietly(health)
            return
        }
        try {
            health.start()
        } catch (_: Exception) {
            val stillAttached = synchronized(lock) {
                if (healthMonitor === health) healthMonitor = null
                phase == SourceProxyState.RUNNING &&
                    attempt == capturedAttempt &&
                    server === newServer
            }
            closeHealthQuietly(health)
            if (stillAttached) finish(SourceProxyStopReason.LISTENER_FAILED)
            return
        }
        val runningAfterHealth = synchronized(lock) {
            phase == SourceProxyState.RUNNING &&
                attempt == capturedAttempt &&
                server === newServer
        }
        if (!runningAfterHealth) return
        listener.onStateChanged(published)
    }

    /** Stop the run when its listener dies unexpectedly. */
    private fun onServerFailed(
        capturedAttempt: Long,
        failedServer: SourceServerHandle,
    ) {
        val shouldFinish = synchronized(lock) {
            phase == SourceProxyState.RUNNING &&
                attempt == capturedAttempt &&
                server === failedServer
        }
        if (shouldFinish) finish(SourceProxyStopReason.LISTENER_FAILED)
    }

    private fun onHotspotLost() {
        finish(SourceProxyStopReason.HOTSPOT_LOST)
    }

    private fun onNetworkStopped(event: SourceProxyStopReason) {
        finish(event)
    }

    private fun finish(newReason: SourceProxyStopReason) {
        val stopServers = mutableListOf<SourceServerHandle>()
        var stopWatch: HotspotWatch? = null
        var stopMonitor: CellularNetworkMonitor? = null
        var stopQueue: SourceProxyTaskQueue? = null
        var stopHealth: SourceServerHealthMonitor? = null
        var stoppedSnapshot: SourceProxySnapshot? = null
        var transitioned = false
        var releaseRun = false
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
                listenerFailureValue = server?.failureReason
                server?.let { stopServers.add(it) }
                server = null
                // The setup task owns a listener that bound but did not
                // publish. It closes that listener after it sees this stop;
                // closing it here would race the setup task and break the run
                // lease order. Clear the pairing binding so no answer can name
                // it.
                pendingServer = null
                bindingPort = 0
                bindingAddress = null
                stopWatch = watch
                watch = null
                stopHealth = healthMonitor
                healthMonitor = null
                stoppedSnapshot = snapshotLocked()
            }
            // Invalidate every queued or running wait for this run.
            starting = false
            attempt += 1
            stopQueue = taskQueue
            taskQueue = null
            // No task may start after this stop. A task that is already
            // running may still create and close a listener, so it keeps the
            // run lease until it returns.
            taskGateClosed = true
            if (holdsRunLease) {
                holdsRunLease = false
                releasePending = true
            }
            if (releasePending && activeTasks == 0) {
                releasePending = false
                releaseRun = true
            }
            // Retry a monitor close after a reported failure. Do not notify again.
            stopMonitor = monitor
            monitor = null
        }
        if (!transitioned && stopMonitor == null && stopQueue == null &&
            !releaseRun && stopHealth == null
        ) {
            return
        }
        // Drop queued work first, so a late wait cannot bind after the stop.
        stopQueue?.shutdown()
        // Close the health watcher before the server. An intentional stop must
        // not look like a listener failure.
        closeHealthQuietly(stopHealth)
        try {
            stopWatch?.stop()
        } catch (_: Exception) {
            // The watch is already ending.
        }
        for (stopServer in stopServers) {
            try {
                stopServer.close()
            } catch (_: Exception) {
                // The server is already ending.
            }
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
        if (releaseRun) {
            // Release the token lease only after the listener is closed, so a
            // rotation cannot replace the token under a live server.
            tokenGuard.endRun()
        }
        if (transitioned && stoppedSnapshot != null) {
            listener.onStateChanged(stoppedSnapshot)
        }
    }

    /** Clear the in-memory token and release the run lease. */
    private fun releaseRunLocked() {
        token = null
        if (holdsRunLease) {
            holdsRunLease = false
            tokenGuard.endRun()
        }
    }

    private fun snapshotLocked() = SourceProxySnapshot(phase, reason, port)

    private fun isStarting(capturedAttempt: Long): Boolean = synchronized(lock) {
        isStartingLocked(capturedAttempt)
    }

    private fun isStartingLocked(capturedAttempt: Long): Boolean =
        starting && attempt == capturedAttempt && phase == SourceProxyState.IDLE

    private fun isWaitingForHotspot(capturedAttempt: Long): Boolean = synchronized(lock) {
        phase == SourceProxyState.WAITING_FOR_NETWORK && attempt == capturedAttempt
    }

    private fun finishIfStarting(capturedAttempt: Long, newReason: SourceProxyStopReason) {
        val shouldFinish = synchronized(lock) { isStartingLocked(capturedAttempt) }
        if (shouldFinish) finish(newReason)
    }

    private fun finishIfWaiting(capturedAttempt: Long, newReason: SourceProxyStopReason) {
        val shouldFinish = isWaitingForHotspot(capturedAttempt)
        if (shouldFinish) finish(newReason)
    }

    private fun finishIfRunning(capturedAttempt: Long, newReason: SourceProxyStopReason) {
        val shouldFinish = synchronized(lock) {
            phase == SourceProxyState.RUNNING &&
                attempt == capturedAttempt &&
                server != null
        }
        if (shouldFinish) finish(newReason)
    }

    private fun probeSafely(): HotspotProbe = try {
        hotspotFinder.probe()
    } catch (_: Exception) {
        HotspotProbe.Unknown
    }

    /**
     * Return the best confirmed address from one probe.
     *
     * A tie between two candidates of the best rank has no confirmed address,
     * because the finder cannot tell them apart. A pending or unknown probe
     * never yields an address.
     */
    private fun confirmedAddress(probe: HotspotProbe): InetAddress? {
        val observed = probe as? HotspotProbe.Observed ?: return null
        val best = observed.candidates.minByOrNull { it.rank } ?: return null
        if (observed.candidates.count { it.rank == best.rank } != 1) return null
        return best.address
    }

    private fun sleepBeforeRetry(millis: Long) {
        try {
            sleepMillis(millis)
        } catch (_: InterruptedException) {
            // A stop shut the queue down. The loop checks the run state next.
            Thread.currentThread().interrupt()
        }
    }

    private fun closeQuietly(closeable: Closeable?) {
        if (closeable == null) return
        try {
            closeable.close()
        } catch (_: Exception) {
            // The resource is already ending.
        }
    }

    private fun stopWatchQuietly(watch: HotspotWatch?) {
        if (watch == null) return
        try {
            watch.stop()
        } catch (_: Exception) {
            // The watch is already ending.
        }
    }

    private fun closeHealthQuietly(health: SourceServerHealthMonitor?) {
        if (health == null) return
        try {
            health.close()
        } catch (_: Exception) {
            // The watcher is already ending.
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

    internal companion object {
        /**
         * The bounded wait for the first tethering reading.
         *
         * It matches [TetheredInterfaceEvidence.DEFAULT_PENDING_TIMEOUT_MILLIS]
         * so the controller and the evidence fall back together. Keep the two
         * in step when either changes.
         */
        const val DEFAULT_PENDING_WAIT_MILLIS =
            TetheredInterfaceEvidence.DEFAULT_PENDING_TIMEOUT_MILLIS

        /** The retry interval while a tethering callback is pending. */
        const val DEFAULT_PENDING_POLL_MILLIS = 250L

        /** Tries to save the first token when a rotation moves the epoch. */
        private const val FIRST_TOKEN_ATTEMPTS = 2
    }
}
