package com.hotspotshade.source.pairing

import java.io.Closeable
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.Executors
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ThreadFactory
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

/**
 * One live pairing listener. The coordinator holds this interface so a JVM
 * test can substitute a fake listener and prove the lock order.
 */
internal interface PairingListener : Closeable {
    /** The bound TCP port, or 0 before a successful start. */
    val localPort: Int

    /** True while the listener accepts connections. */
    fun isRunning(): Boolean

    /** Bind the listener. */
    fun start()

    /** Approve the prompt that the person saw. */
    fun allow(prompt: PairingPrompt): Boolean

    /** Deny the prompt that the person saw. */
    fun deny(prompt: PairingPrompt)

    /** Mark the app as visible. */
    fun activate()

    /** Mark the app as hidden. */
    fun deactivate()
}

/**
 * The source device pairing listener.
 *
 * The listener binds one hotspot address and TCP port 18090. It never binds
 * the any-local address. It holds at most [MAX_CONNECTIONS] sockets and at
 * most [MAX_IDLE_CONNECTIONS] sockets that have sent no frame. Each socket
 * runs one [PairingResponder] connection on a daemon thread.
 *
 * A connection that sends no complete frame within [idleTimeoutMillis] is
 * closed. A new connection evicts the oldest idle connection, so a set of
 * silent sockets cannot block a real target device.
 *
 * The listener opens no other socket. It logs no address, code, key, or
 * token. The host shows the prompt and calls [allow] or [deny]. Host callbacks
 * run serially on one shared bounded dispatcher lane. A blocked callback
 * delays later callbacks on that listener, including prompt clearing, but it
 * does not create a thread for a replacement listener and does not delay
 * close. Callbacks admitted before close may finish after it; queued obsolete
 * prompts are discarded.
 */
internal class PairingServer(
    private val responder: PairingResponder,
    private val bindAddress: InetAddress,
    private val port: Int = PairingProtocol.PAIRING_PORT,
    private val onPromptChanged: (PairingPrompt?) -> Unit,
    private val onPairingSucceeded: () -> Unit = {},
    /**
     * Queued after the fixed rejection write is attempted and the connection
     * is closed when the token could not be saved. Delivery is best effort,
     * may occur after close, and carries no token or error text.
     */
    private val onTokenCommitFailed: () -> Unit = {},
    private val idleTimeoutMillis: Long = IDLE_TIMEOUT_MILLIS,
    private val clock: () -> Long = { System.nanoTime() / 1_000_000L },
    private val connectionThreadFactory: ThreadFactory = daemonFactory("pairing-connection"),
    private val writeFrames: (Socket, List<ByteArray>) -> Unit = { socket, frames ->
        val stream = socket.getOutputStream()
        for (frame in frames) stream.write(frame)
        stream.flush()
    },
    private val callbackDispatcher: PairingCallbackDispatcher = PairingCallbackDispatcher.shared,
) : PairingListener {
    private val lock = Any()
    // Host callbacks are serialized per listener, never run under lock, and
    // never create a replacement listener's thread or delay close.
    private val callbacks = callbackDispatcher
    private var callbackScheduled = false
    private var promptPending = false
    private var pendingPrompt: PairingPrompt? = null
    private var successPending = false
    private var tokenFailurePending = false
    private var closed = false
    private val connections = LinkedHashMap<ConnectionId, ConnectionState>()
    private val connectionIds = AtomicLong(1)
    // Eviction closes a socket but its worker may still be unwinding. Bound
    // queued workers too, so repeated evictions cannot grow an unbounded queue.
    private val executor = ThreadPoolExecutor(
        MAX_CONNECTIONS, MAX_CONNECTIONS, 0L, TimeUnit.MILLISECONDS,
        ArrayBlockingQueue(MAX_CONNECTIONS), connectionThreadFactory,
        ThreadPoolExecutor.AbortPolicy(),
    )
    private val scheduler: ScheduledExecutorService =
        Executors.newSingleThreadScheduledExecutor(daemonFactory("pairing-timer"))

    @Volatile
    private var running = false

    @Volatile
    private var appActive = true
    private var serverSocket: ServerSocket? = null
    private var acceptThread: Thread? = null
    private var lastPrompt: PairingPrompt? = null
    private var started = false

    init {
        require(!bindAddress.isAnyLocalAddress) {
            "The pairing listener must bind one hotspot address."
        }
        require(port in 0..65535) { "The pairing port is out of range." }
        require(idleTimeoutMillis > 0) { "The idle timeout must be positive." }
    }

    /** The bound TCP port, or 0 before a successful start. */
    override val localPort: Int
        get() = synchronized(lock) { serverSocket?.localPort ?: 0 }

    /** True while the listener accepts connections. */
    override fun isRunning(): Boolean = running

    /** Bind the listener. This call is not idempotent. */
    override fun start() {
        synchronized(lock) {
            check(!closed && !started) { "The pairing listener can start only once." }
            started = true
            val socket = ServerSocket()
            socket.reuseAddress = true
            try {
                socket.bind(InetSocketAddress(bindAddress, port), MAX_CONNECTIONS)
            } catch (failure: Exception) {
                try {
                    socket.close()
                } catch (_: IOException) {
                    // The bind already failed.
                }
                throw failure
            }
            serverSocket = socket
            running = true
            val thread = Thread({ acceptLoop() }, "pairing-listener").apply { isDaemon = true }
            acceptThread = thread
            thread.start()
            scheduler.scheduleWithFixedDelay(
                { tick() },
                TICK_MILLIS,
                TICK_MILLIS,
                TimeUnit.MILLISECONDS,
            )
        }
    }

    /** Approve the prompt. True means the OK frame was written locally, not that the target received it. */
    override fun allow(prompt: PairingPrompt): Boolean {
        val output = try {
            synchronized(lock) {
                responder.decide(prompt.connection, prompt.id, prompt.code, true).also { notifyPromptLocked() }
            }
        } catch (_: Throwable) {
            return false
        } ?: return false
        val written = deliver(output)
        return output.status == PairingStatus.OK && written
    }

    /** Deny the prompt that the person saw. */
    override fun deny(prompt: PairingPrompt) {
        val output = try {
            synchronized(lock) {
                responder.decide(prompt.connection, prompt.id, prompt.code, false).also { notifyPromptLocked() }
            }
        } catch (_: Throwable) {
            return
        } ?: return
        deliver(output)
    }

    /** Mark the app as visible. A live prompt becomes visible. */
    override fun activate() {
        appActive = true
        synchronized(lock) { responder.activate(); notifyPromptLocked() }
        notifyPrompt()
    }

    /** Mark the app as hidden. A live prompt gets a bounded extension. */
    override fun deactivate() {
        appActive = false
        val output = try {
            synchronized(lock) { responder.deactivate().also { notifyPromptLocked() } }
        } catch (_: Throwable) {
            null
        }
        if (output != null) deliver(output)
        notifyPrompt()
    }

    /** Close the listener and every connection. This call is idempotent. */
    override fun close() {
        var sockets: List<Socket> = emptyList()
        var socket: ServerSocket? = null
        var accept: Thread? = null
        synchronized(lock) {
            if (closed) return
            closed = true
            running = false
            socket = serverSocket
            serverSocket = null
            accept = acceptThread
            acceptThread = null
            sockets = connections.values.map { it.socket }
            connections.clear()
            lastPrompt = null
            pendingPrompt = null
            successPending = false
            tokenFailurePending = false
            promptPending = true
            scheduleCallbackLocked()
        }
        try {
            socket?.close()
        } catch (_: IOException) {
            // The listener is already closing.
        }
        for (connection in sockets) {
            closeQuietly(connection)
        }
        accept?.interrupt()
        scheduler.shutdownNow()
        executor.shutdownNow()
    }

    private fun acceptLoop() {
        while (running) {
            val socket = try {
                synchronized(lock) { serverSocket }?.accept()
            } catch (_: IOException) {
                if (!running) break
                continue
            } ?: break
            val connection = connectionIds.getAndIncrement()
            var evicted: Socket? = null
            var accepted = false
            synchronized(lock) {
                if (!running) {
                    evicted = socket
                } else {
                    val idle = connections.entries.filter { it.value.frames == 0 }
                    val overTotal = connections.size >= MAX_CONNECTIONS
                    val overIdle = idle.size >= MAX_IDLE_CONNECTIONS
                    if ((overTotal || overIdle) && idle.isNotEmpty()) {
                        val oldest = idle.minByOrNull { it.value.openedAt }
                        if (oldest != null) {
                            connections.remove(oldest.key)
                            evicted = oldest.value.socket
                        }
                    }
                    if (connections.size < MAX_CONNECTIONS) {
                        connections[connection] = ConnectionState(socket, clock())
                        accepted = true
                    } else {
                        evicted = socket
                    }
                }
            }
            evicted?.let { closeQuietly(it) }
            if (!accepted) continue
            try {
                socket.tcpNoDelay = true
                socket.soTimeout = READ_TIMEOUT_MILLIS
                executor.execute { serve(socket, connection) }
            } catch (_: Exception) {
                synchronized(lock) { connections.remove(connection) }
                closeQuietly(socket)
            }
        }
    }

    private fun serve(socket: Socket, connection: ConnectionId) {
        val peer = PeerAddress.text(socket.inetAddress)
        val reader = PairingFrameReader()
        val buffer = ByteArray(1024)
        try {
            val input = socket.getInputStream()
            while (running) {
                if (idleExpired(connection)) break
                val count = try {
                    input.read(buffer)
                } catch (_: SocketTimeoutException) {
                    tick()
                    continue
                } catch (_: IOException) {
                    break
                }
                if (count < 0) break
                if (count == 0) continue
                val received = buffer.copyOf(count)
                try {
                    reader.push(received)
                } catch (_: PairingException) {
                    deliver(invalid(connection, peer))
                    break
                }
                var open = true
                while (open) {
                    val payload = try {
                        reader.nextFrame()
                    } catch (_: PairingException) {
                        deliver(invalid(connection, peer))
                        open = false
                        break
                    } ?: break
                    markFrame(connection)
                    val output = try {
                        synchronized(lock) {
                            responder.receive(connection, payload, peer, appActive).also { notifyPromptLocked() }
                        }
                    } catch (_: PairingException) {
                        // A host error means close the connection and send no
                        // pending frame.
                        open = false
                        break
                    }
                    if (!deliver(output) || output.close) open = false
                }
                if (!open) break
            }
        } catch (_: IOException) {
            // The socket closed while the connection served it.
        } finally {
            synchronized(lock) { connections.remove(connection) }
            synchronized(lock) { responder.connectionClosed(connection); notifyPromptLocked() }
            notifyPrompt()
            closeQuietly(socket)
        }
    }

    private fun invalid(connection: ConnectionId, peer: String): PairingOutput {
        return try {
            synchronized(lock) { responder.receiveInvalid(connection, peer).also { notifyPromptLocked() } }
        } catch (_: PairingException) {
            PairingOutput(
                connection,
                listOf(PairingProtocol.frame(PairingProtocol.encodeResultStatus(PairingStatus.REJECTED))),
                true,
                null,
            )
        }
    }

    private fun markFrame(connection: ConnectionId) {
        synchronized(lock) {
            val state = connections[connection] ?: return
            state.frames += 1
        }
    }

    private fun idleExpired(connection: ConnectionId): Boolean {
        synchronized(lock) {
            val state = connections[connection] ?: return true
            return state.frames == 0 && clock() - state.openedAt >= idleTimeoutMillis
        }
    }

    private fun tick() {
        if (!running) return
        val output = try {
            synchronized(lock) { responder.tick().also { notifyPromptLocked() } }
        } catch (_: Throwable) {
            null
        }
        if (output != null) deliver(output)
        notifyPrompt()
    }

    private fun deliver(output: PairingOutput): Boolean {
        val socket = synchronized(lock) {
            // A close that won the race clears the connection map. Do not
            // write a sealed result after the listener stopped.
            if (!running) null else connections[output.connection]?.socket
        }
        var written = false
        if (socket != null) {
            synchronized(socket) {
                try {
                    writeFrames(socket, output.frames)
                    written = true
                } catch (_: IOException) {
                    // The peer closed the connection. The session ends below.
                }
                if (output.close || !written) {
                    try {
                        socket.shutdownOutput()
                    } catch (_: IOException) {
                        // The socket is already closing.
                    }
                    closeQuietly(socket)
                }
            }
        }
        val accepted = synchronized(lock) {
            val active = written && running
            if (!closed && output.tokenCommitFailed) {
                tokenFailurePending = true
                scheduleCallbackLocked()
            }
            if (active && !output.tokenCommitFailed && output.status == PairingStatus.OK) {
                // Admission is ordered with close. An admitted callback can run
                // after close; a local write does not prove target receipt.
                successPending = true
                scheduleCallbackLocked()
            }
            active
        }
        notifyPrompt()
        return accepted
    }

    private fun notifyPrompt() = synchronized(lock) { notifyPromptLocked() }

    // Invalidate queued prompts atomically with responder state changes, before writes.
    private fun notifyPromptLocked() {
        if (!running) return
        val prompt = try { responder.pendingPrompt() } catch (_: Throwable) { null }
        if (prompt == lastPrompt) return
        lastPrompt = prompt
        pendingPrompt = prompt
        promptPending = true
        scheduleCallbackLocked()
    }

    // Bound pending work even if a host callback blocks. Repeated events
    // coalesce on this listener's dispatcher lane. A refused dispatch keeps one
    // bounded retry ticket, so a pending prompt or the close clear is delivered
    // when a worker frees without another listener event.
    private fun scheduleCallbackLocked() {
        if (callbackScheduled) return
        val accepted = try {
            callbacks.dispatchOrRetry(this) { drainCallbacks() }
        } catch (_: Throwable) {
            // A host dispatcher failure leaves the pending flags set. A later
            // event or close retries.
            false
        }
        if (accepted) callbackScheduled = true
    }

    private fun drainCallbacks() {
        try {
            while (true) {
                var retire = false
                val callback: (() -> Unit)? = synchronized(lock) {
                    when {
                        promptPending -> {
                            val prompt = pendingPrompt
                            promptPending = false
                            { onPromptChanged(prompt) }
                        }
                        tokenFailurePending -> {
                            tokenFailurePending = false
                            { onTokenCommitFailed() }
                        }
                        successPending -> {
                            successPending = false
                            { onPairingSucceeded() }
                        }
                        else -> {
                            callbackScheduled = false
                            retire = closed
                            null
                        }
                    }
                }
                if (callback == null) {
                    if (retire) callbacks.retire(this)
                    return
                }
                // Once admitted, a callback cannot be recalled by close.
                safelyNotify(callback)
            }
        } finally {
            // A host callback that throws an Error used to escape this loop
            // with callbackScheduled still set, so every later event saw a
            // scheduled lane and the clear never ran. Release the flag and
            // retry when pending work remains.
            synchronized(lock) {
                if (callbackScheduled && (promptPending || successPending || tokenFailurePending)) {
                    callbackScheduled = false
                    scheduleCallbackLocked()
                }
            }
        }
    }

    private inline fun safelyNotify(callback: () -> Unit) {
        try {
            callback()
        } catch (_: Throwable) {
            // Host failures must not break the listener or expose secrets.
        }
    }

    private fun closeQuietly(socket: Socket) {
        try {
            socket.close()
        } catch (_: IOException) {
            // The socket is already closing.
        }
    }

    private class ConnectionState(
        val socket: Socket,
        val openedAt: Long,
    ) {
        var frames: Int = 0
    }

    private companion object {
        const val MAX_CONNECTIONS = 8
        const val MAX_IDLE_CONNECTIONS = 4
        const val IDLE_TIMEOUT_MILLIS = 10_000L
        const val READ_TIMEOUT_MILLIS = 500
        const val TICK_MILLIS = 250L

        fun daemonFactory(name: String): ThreadFactory = ThreadFactory { runnable ->
            Thread(runnable, name).apply { isDaemon = true }
        }
    }
}
