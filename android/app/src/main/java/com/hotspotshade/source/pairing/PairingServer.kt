package com.hotspotshade.source.pairing

import java.io.Closeable
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ThreadFactory
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * The source device pairing listener.
 *
 * The listener binds one hotspot address and TCP port 18090. It never binds
 * the any-local address. It holds at most [MAX_CONNECTIONS] sockets. Each
 * socket runs one [PairingResponder] connection on a daemon thread.
 *
 * The listener opens no other socket. It logs no address, code, key, or
 * token. The host shows the prompt and calls [allow] or [deny].
 */
internal class PairingServer(
    private val responder: PairingResponder,
    private val bindAddress: InetAddress,
    private val port: Int = PairingProtocol.PAIRING_PORT,
    private val onPromptChanged: (PairingPrompt?) -> Unit,
    private val onPairingSucceeded: () -> Unit,
    private val connectionThreadFactory: ThreadFactory = daemonFactory("pairing-connection"),
) : Closeable {
    private val lock = Any()
    private val promptLock = Any()
    private val connections = HashMap<ConnectionId, Socket>()
    private val connectionIds = AtomicLong(1)
    private val activeConnections = AtomicInteger(0)
    private val executor = Executors.newFixedThreadPool(MAX_CONNECTIONS) { runnable ->
        connectionThreadFactory.newThread(runnable)
    }
    private val scheduler: ScheduledExecutorService =
        Executors.newSingleThreadScheduledExecutor(daemonFactory("pairing-timer"))

    @Volatile
    private var running = false
    private var serverSocket: ServerSocket? = null
    private var acceptThread: Thread? = null
    private var lastPrompt: PairingPrompt? = null
    private var started = false

    init {
        require(!bindAddress.isAnyLocalAddress) {
            "The pairing listener must bind one hotspot address."
        }
        require(port in 0..65535) { "The pairing port is out of range." }
    }

    /** The bound TCP port, or 0 before a successful start. */
    val localPort: Int
        get() = synchronized(lock) { serverSocket?.localPort ?: 0 }

    /** True while the listener accepts connections. */
    fun isRunning(): Boolean = running

    /** Bind the listener. This call is not idempotent. */
    fun start() {
        synchronized(lock) {
            check(!started) { "The pairing listener can start only once." }
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
        }
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

    /** Approve the prompt that the person saw. Return true on a successful result. */
    fun allow(prompt: PairingPrompt): Boolean {
        val output = try {
            synchronized(lock) {
                responder.decide(prompt.connection, prompt.id, prompt.code, true)
            }
        } catch (_: PairingException) {
            return false
        } ?: return false
        deliver(output)
        return output.status == PairingStatus.OK
    }

    /** Deny the prompt that the person saw. */
    fun deny(prompt: PairingPrompt) {
        val output = try {
            synchronized(lock) {
                responder.decide(prompt.connection, prompt.id, prompt.code, false)
            }
        } catch (_: PairingException) {
            return
        } ?: return
        deliver(output)
    }

    /** Mark the app as visible. A live prompt becomes visible. */
    fun activate() {
        synchronized(lock) { responder.activate() }
        notifyPrompt()
    }

    /** Mark the app as hidden. A live prompt gets a bounded extension. */
    fun deactivate() {
        val output = try {
            synchronized(lock) { responder.deactivate() }
        } catch (_: PairingException) {
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
            if (!started) return
            running = false
            socket = serverSocket
            serverSocket = null
            accept = acceptThread
            acceptThread = null
            sockets = connections.values.toList()
            connections.clear()
        }
        try {
            socket?.close()
        } catch (_: IOException) {
            // The listener is already closing.
        }
        for (connection in sockets) {
            try {
                connection.close()
            } catch (_: IOException) {
                // The connection is already closing.
            }
        }
        accept?.interrupt()
        scheduler.shutdownNow()
        executor.shutdownNow()
        synchronized(promptLock) {
            lastPrompt = null
        }
        onPromptChanged(null)
    }

    private fun acceptLoop() {
        while (running) {
            val socket = try {
                synchronized(lock) { serverSocket }?.accept()
            } catch (_: IOException) {
                if (!running) break
                continue
            } ?: break
            if (activeConnections.incrementAndGet() > MAX_CONNECTIONS) {
                activeConnections.decrementAndGet()
                closeQuietly(socket)
                continue
            }
            try {
                socket.tcpNoDelay = true
                socket.soTimeout = READ_TIMEOUT_MILLIS
                executor.execute { serve(socket) }
            } catch (_: Exception) {
                activeConnections.decrementAndGet()
                closeQuietly(socket)
            }
        }
    }

    private fun serve(socket: Socket) {
        val connection = connectionIds.getAndIncrement()
        val peer = PeerAddress.text(socket.inetAddress)
        synchronized(lock) { connections[connection] = socket }
        val reader = PairingFrameReader()
        val buffer = ByteArray(1024)
        try {
            val input = socket.getInputStream()
            while (running) {
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
                    val output = try {
                        synchronized(lock) { responder.receive(connection, payload, peer, true) }
                    } catch (_: PairingException) {
                        // A host error means close the connection and send no
                        // pending frame.
                        open = false
                        break
                    }
                    deliver(output)
                    if (output.close) open = false
                }
                if (!open) break
            }
        } catch (_: IOException) {
            // The socket closed while the connection served it.
        } finally {
            synchronized(lock) { connections.remove(connection) }
            synchronized(lock) { responder.connectionClosed(connection) }
            notifyPrompt()
            closeQuietly(socket)
            activeConnections.decrementAndGet()
        }
    }

    private fun invalid(connection: ConnectionId, peer: String): PairingOutput {
        return try {
            synchronized(lock) { responder.receiveInvalid(connection, peer) }
        } catch (_: PairingException) {
            PairingOutput(
                connection,
                listOf(PairingProtocol.frame(PairingProtocol.encodeResultStatus(PairingStatus.REJECTED))),
                true,
                null,
            )
        }
    }

    private fun tick() {
        if (!running) return
        val output = try {
            synchronized(lock) { responder.tick() }
        } catch (_: PairingException) {
            null
        }
        if (output != null) deliver(output)
        notifyPrompt()
    }

    private fun deliver(output: PairingOutput) {
        val socket = synchronized(lock) { connections[output.connection] }
        if (socket != null) {
            synchronized(socket) {
                try {
                    val stream = socket.getOutputStream()
                    for (frame in output.frames) stream.write(frame)
                    stream.flush()
                } catch (_: IOException) {
                    // The peer closed the connection. The session ends below.
                }
                if (output.close) {
                    try {
                        socket.shutdownOutput()
                    } catch (_: IOException) {
                        // The socket is already closing.
                    }
                    closeQuietly(socket)
                }
            }
        }
        if (output.status == PairingStatus.OK) {
            try {
                onPairingSucceeded()
            } catch (_: Exception) {
                // The host cannot save the token. The next start reports
                // TOKEN_MISSING. The result already left the device.
            }
        }
        notifyPrompt()
    }

    private fun notifyPrompt() {
        val prompt = try {
            synchronized(lock) { responder.pendingPrompt() }
        } catch (_: Exception) {
            null
        }
        val changed = synchronized(promptLock) {
            if (prompt == lastPrompt) {
                false
            } else {
                lastPrompt = prompt
                true
            }
        }
        if (changed) onPromptChanged(prompt)
    }

    private fun closeQuietly(socket: Socket) {
        try {
            socket.close()
        } catch (_: IOException) {
            // The socket is already closing.
        }
    }

    private companion object {
        const val MAX_CONNECTIONS = 8
        const val READ_TIMEOUT_MILLIS = 500
        const val TICK_MILLIS = 250L

        fun daemonFactory(name: String): ThreadFactory = ThreadFactory { runnable ->
            Thread(runnable, name).apply { isDaemon = true }
        }
    }
}
