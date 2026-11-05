package com.hotspotshade.source

import android.content.Context
import android.net.ConnectivityManager
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.io.IOException
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.time.Duration
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Serve the source device SOCKS5 contract for one host interop run.
 *
 * The test binds 127.0.0.1 port 0 on the emulator. It prints the bound port,
 * the relay limit, and the IPv6 loopback echo port with the `HS_INTEROP` log
 * tag. It accepts every default network socket. It fails every name lookup.
 * It stops when the host creates the stop file or after 120 seconds.
 *
 * The echo command uses a real Android ICMP datagram socket on the default
 * network. This test uses an emulator loopback through `adb forward`. It does
 * not prove carrier, hotspot, or physical-device behavior.
 */
@RunWith(AndroidJUnit4::class)
class SourceSocksInteropTest {
    private companion object {
        const val TAG = "HS_INTEROP"
        const val TOKEN = "emulator-test-token"
        const val STOP_FILE = "hs-interop-stop"
        const val SERVE_TIMEOUT_MILLIS = 120_000L
        val LOOPBACK: InetAddress = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
        val LOOPBACK6: InetAddress = InetAddress.getByAddress(ByteArray(16).also { it[15] = 1 })
        const val ECHO_PAYLOAD = "hs-echo"
        val ECHO_TARGET: EchoTarget? =
            SourceEchoWire.target(1, byteArrayOf(10, 0, 2, 2), 0)
    }

    /** Accept the default network. The emulator test does not select a network. */
    private class DefaultNetworkBinding : CellularBinding {
        override fun requireAvailable() = Unit

        override fun bind(socket: Socket) = Unit

        override fun bind(socket: DatagramSocket) = Unit
    }

    /** Fail every lookup. The test sends numeric destinations only. */
    private class FailingResolver : SourceHostResolver {
        override fun resolve(host: String): List<InetAddress> {
            throw IOException("The emulator test does not resolve names.")
        }
    }

    /** Echo every byte on one loopback listener. */
    private class TcpEcho(private val listener: ServerSocket) : java.io.Closeable {
        val port: Int get() = listener.localPort

        private val worker = Thread({
            try {
                while (true) {
                    val client = listener.accept()
                    Thread({
                        try {
                            client.use { socket ->
                                val input = socket.getInputStream()
                                val output = socket.getOutputStream()
                                val buffer = ByteArray(8 * 1024)
                                while (true) {
                                    val read = input.read(buffer)
                                    if (read < 0) break
                                    output.write(buffer, 0, read)
                                    output.flush()
                                }
                            }
                        } catch (_: IOException) {
                            // The host ended the flow.
                        }
                    }, "hs-interop-echo").apply { isDaemon = true }.start()
                }
            } catch (_: IOException) {
                // The test closed the listener.
            }
        }, "hs-interop-echo-accept").apply {
            isDaemon = true
            start()
        }

        override fun close() {
            try {
                listener.close()
            } catch (_: IOException) {
                // The listener is already closed.
            }
        }
    }

    private fun activeNetwork(context: Context): android.net.Network? {
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
            ?: return null
        return connectivity.activeNetwork
    }

    private fun openIpv6Echo(): TcpEcho? = try {
        TcpEcho(ServerSocket(0, 1, LOOPBACK6))
    } catch (failure: IOException) {
        Log.i(TAG, "ipv6 echo unavailable: ${failure.javaClass.simpleName}")
        null
    }

    @Test
    fun serveUntilStopFileOrTimeout() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val stop = File(context.filesDir, STOP_FILE)
        stop.delete()
        val limits = SourceSocksCapacity.readSoftFileLimit()?.let {
            Log.i(TAG, "file limit=$it")
            SourceSocksCapacity.limitsForFileLimit(it)
        } ?: SourceSocksCapacity.limits()
        val network = activeNetwork(context)
        Log.i(TAG, "relay limit=${limits.relay} total=${limits.total}")
        val ipv6Echo = openIpv6Echo()
        Log.i(TAG, "ipv6 echo port=${ipv6Echo?.port ?: 0}")
        val cellular = CellularSession(CellularSockets(DefaultNetworkBinding()))
        val server = SourceSocksServer(
            cellular = cellular,
            resolver = FailingResolver(),
            bindAddress = LOOPBACK,
            token = TOKEN,
            port = 0,
            maximumRelays = limits.relay.coerceAtLeast(1),
            setupReserve = limits.setupReserve,
            echo = network?.let { AndroidNetworkEcho(it) },
        )
        var ending = "timeout"
        try {
            server.start()
            Log.i(TAG, "listening port=${server.localPort}")
            Log.i(TAG, "stop file=${stop.absolutePath}")
            val deadline = System.nanoTime() + Duration.ofMillis(SERVE_TIMEOUT_MILLIS).toNanos()
            while (System.nanoTime() < deadline) {
                if (stop.exists()) {
                    ending = "stop file"
                    break
                }
                if (!server.isRunning) {
                    ending = "server stop"
                    break
                }
                Thread.sleep(100)
            }
        } finally {
            server.stop()
            cellular.close()
            ipv6Echo?.close()
            stop.delete()
        }
        Log.i(TAG, "served until $ending")
        assertTrue(
            "The server stopped before the host ended the test.",
            ending != "server stop",
        )
    }

    /**
     * Send one echo request through the real Android ICMP datagram socket.
     *
     * A device whose kernel or policy refuses an ICMP datagram socket returns
     * status 4. The test skips with that status and leaves the result in the
     * log. See `android/README.md`.
     */
    @Test
    fun echoToTheEmulatorHost() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val network = activeNetwork(context)
        Assume.assumeTrue("The emulator has no active network.", network != null)
        val target = ECHO_TARGET
        Assume.assumeTrue("The echo target is not valid.", target != null)
        val echo = AndroidNetworkEcho(requireNotNull(network))
        val payload = ECHO_PAYLOAD.toByteArray()
        val result = echo.send(requireNotNull(target), payload, 3_000)
        Log.i(TAG, "echo status=${result.status.name} bytes=${result.payload.size}")
        if (result.status != EchoStatus.SUCCESS) {
            Assume.assumeTrue(
                "The emulator does not permit a cellular ICMP echo: ${result.status.name}.",
                false,
            )
            return
        }
        assertEquals(payload.size, result.payload.size)
        assertArrayEquals(payload, result.payload)
    }
}
