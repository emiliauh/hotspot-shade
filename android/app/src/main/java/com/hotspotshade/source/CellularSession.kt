package com.hotspotshade.source

import java.io.Closeable
import java.io.IOException
import java.net.DatagramSocket
import java.net.Socket

/** One socket and its registration. Close this handle when the flow ends. */
internal class CellularFlow<T : Closeable>(
    val socket: T,
    private val release: (T) -> Unit,
) : Closeable {
    private val lock = Any()
    private var closed = false

    override fun close() {
        synchronized(lock) {
            if (closed) return
            socket.close()
            closed = true
            release(socket)
        }
    }
}

/**
 * Own the sockets for one selected cellular network. The service must close
 * the session on stop or when the network callback reports loss. A stopped
 * session cannot be reused or restarted.
 *
 * The socket bound follows the total session cap: 256 relays plus 32 setup
 * sessions. A setup session can hold one destination socket while it
 * connects.
 */
internal class CellularSession(
    private val sockets: CellularSockets,
    private val maximumFlows: Int = SourceSocksCapacity.MAXIMUM_SESSIONS,
) : Closeable {
    init {
        require(maximumFlows in 1..512)
    }

    private val lock = Any()
    private val cleanupLock = Any()
    private val active = mutableSetOf<Closeable>()
    private var stopped = false

    fun tcp(): CellularFlow<Socket> = open { track, release -> sockets.tcp(track, release) }
    fun udp(): CellularFlow<DatagramSocket> = open { track, release -> sockets.udp(track, release) }

    private fun <T : Closeable> open(create: ((T) -> Unit, (T) -> Unit) -> T): CellularFlow<T> {
        val socket = create(
            { candidate ->
                synchronized(lock) {
                    if (stopped) throw IOException("The cellular session is stopped.")
                    if (active.size >= maximumFlows) throw IOException("The cellular session is full.")
                    active.add(candidate)
                }
            },
            { candidate -> synchronized(lock) { active.remove(candidate) } },
        )
        synchronized(lock) {
            if (!stopped) {
                return CellularFlow(socket) { released ->
                    synchronized(lock) { active.remove(released) }
                }
            }
        }
        // Stop can run while the socket binds. Do not return it after stop.
        socket.close()
        synchronized(lock) { active.remove(socket) }
        throw IOException("The cellular session is stopped.")
    }

    override fun close() {
        synchronized(cleanupLock) {
            val pending = synchronized(lock) {
                stopped = true
                active.toList()
            }
            var error: IOException? = null
            for (socket in pending) {
                try {
                    socket.close()
                    synchronized(lock) { active.remove(socket) }
                } catch (failure: Exception) {
                    if (error == null) error = IOException("Could not close all cellular sockets.")
                    error.addSuppressed(failure)
                }
            }
            error?.let { throw it }
        }
    }
}
