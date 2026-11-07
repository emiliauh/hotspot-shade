package com.hotspotshade.source

import android.Manifest
import android.app.Instrumentation
import android.app.Notification
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.os.Build
import android.util.Log
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.hotspotshade.demo.MainActivity
import com.hotspotshade.source.pairing.MemoryPairingTrustStore
import java.io.Closeable
import java.io.File
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.file.Files
import java.security.KeyStore
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Run the real source proxy service on the booted emulator.
 *
 * The emulator's own non-loopback address 10.0.2.15 stands in for the
 * hotspot address. The emulator default network stands in for the cellular
 * network. The test opens a loopback bridge because adb forward reaches the
 * emulator loopback, while the service binds the hotspot address only. The
 * host test reads the bridge port from the log and forwards a host port to
 * it. The test logs no token, address, or host.
 *
 * An emulator does not prove carrier, hotspot, or physical-device behavior.
 */
@RunWith(AndroidJUnit4::class)
class SourceProxyServiceInstrumentedTest {
    @Test
    fun serviceServesTheSocksContractOnTheMimickedHotspotAddress() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        grantNotificationPermission(instrumentation, context)
        stopExistingService(context)
        val selection = TestSelection(context)
        SourceProxyRuntime.installTestEnvironment(testEnvironment(selection))
        val bridge = LoopbackBridge(HOTSPOT) { SourceProxyRuntime.lastPort }
        val stop = File(context.filesDir, STOP_FILE)
        stop.delete()
        bridge.start()
        val scenario = ActivityScenario.launch(MainActivity::class.java)
        var ipv6Echo: TcpEchoOnHotspot? = null
        try {
            ipv6Echo = try {
                TcpEchoOnHotspot(InetAddress.getByAddress(ByteArray(16).also { it[15] = 1 }))
            } catch (_: java.io.IOException) {
                null
            }
            SourceProxyService.start(context)
            assertTrue(
                "The service must report a state.",
                waitUntil(START_TIMEOUT_MILLIS) {
                    SourceProxyRuntime.lastState == SourceProxyState.RUNNING ||
                        SourceProxyRuntime.lastState == SourceProxyState.STOPPED
                },
            )
            assertEquals(
                "The proxy must run. It stopped with ${SourceProxyRuntime.lastStopReason}.",
                SourceProxyState.RUNNING,
                SourceProxyRuntime.lastState,
            )
            assertTrue("The server must bind a port.", SourceProxyRuntime.lastPort > 0)

            // A second start request must not create a second run or replace
            // the running notification with the waiting text.
            SourceProxyService.start(context)
            Thread.sleep(500)
            assertEquals(SourceProxyState.RUNNING, SourceProxyRuntime.lastState)
            assertEquals(1, selection.starts)
            assertTrue(
                "The running notification must say what the proxy does.",
                runningNotificationText(context) == RUNNING_NOTIFICATION_TEXT,
            )

            Log.i(TAG, "bridge=${bridge.port}")
            Log.i(TAG, "ipv6 echo port=${ipv6Echo?.port ?: 0}")

            var ending = "timeout"
            val deadline = System.nanoTime() +
                TimeUnit.MILLISECONDS.toNanos(SERVE_TIMEOUT_MILLIS)
            while (System.nanoTime() < deadline) {
                if (stop.exists()) {
                    ending = "stop file"
                    break
                }
                if (SourceProxyRuntime.lastState != SourceProxyState.RUNNING) {
                    ending = "unexpected stop"
                    break
                }
                Thread.sleep(100)
            }
            assertFalse(
                "The service stopped before the host ended the test: " +
                    "${SourceProxyRuntime.lastStopReason}.",
                ending == "unexpected stop",
            )
        } finally {
            ipv6Echo?.close()
            SourceProxyService.stop(context)
            assertTrue(
                "The service must stop.",
                waitUntil(STOP_TIMEOUT_MILLIS) {
                    SourceProxyRuntime.lastState == SourceProxyState.STOPPED
                },
            )
            assertEquals(SourceProxyState.STOPPED, SourceProxyRuntime.lastState)
            assertEquals(SourceProxyStopReason.USER_STOP, SourceProxyRuntime.lastStopReason)
            assertEquals(0, SourceProxyRuntime.lastPort)
            scenario.close()
            bridge.close()
            SourceProxyRuntime.clearTestEnvironment()
            stop.delete()
            context.stopService(Intent(context, SourceProxyService::class.java))
        }
    }

    @Test
    fun networkLossStopsTheServiceWithoutARestart() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        grantNotificationPermission(instrumentation, context)
        stopExistingService(context)
        val selection = TestSelection(context)
        SourceProxyRuntime.installTestEnvironment(testEnvironment(selection))
        val scenario = ActivityScenario.launch(MainActivity::class.java)
        try {
            SourceProxyService.start(context)
            assertTrue(
                "The service must run before the loss.",
                waitUntil(START_TIMEOUT_MILLIS) {
                    SourceProxyRuntime.lastState == SourceProxyState.RUNNING ||
                        SourceProxyRuntime.lastState == SourceProxyState.STOPPED
                },
            )
            assertEquals(SourceProxyState.RUNNING, SourceProxyRuntime.lastState)

            selection.lose()

            assertTrue(
                "A lost network must stop the service.",
                waitUntil(STOP_TIMEOUT_MILLIS) {
                    SourceProxyRuntime.lastState == SourceProxyState.STOPPED
                },
            )
            assertEquals(SourceProxyStopReason.NETWORK_LOST, SourceProxyRuntime.lastStopReason)
            assertEquals(0, SourceProxyRuntime.lastPort)
            Thread.sleep(2_000)
            assertEquals(SourceProxyState.STOPPED, SourceProxyRuntime.lastState)
            assertEquals(1, selection.starts)
        } finally {
            context.stopService(Intent(context, SourceProxyService::class.java))
            scenario.close()
            SourceProxyRuntime.clearTestEnvironment()
        }
    }

    @Test
    fun keystoreTokenStoreRoundTrip() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val alias = "hs-token-roundtrip-${UUID.randomUUID()}"
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        check(!keyStore.containsAlias(alias)) { "The disposable test alias already exists." }
        val directory = Files.createTempDirectory(context.cacheDir.toPath(), "hs-token-roundtrip-").toFile()
        val file = File(directory, "source-token.bin")
        val store = AndroidKeystoreTokenStore(file, codec = KeystoreTokenFileCodec(keyAlias = alias))
        try {
            store.save(TOKEN)
            assertEquals(TOKEN, store.load())
            org.junit.Assert.assertThrows(TokenDeleteException::class.java) { store.clear() }
            assertEquals(TOKEN, store.load())
        } finally {
            try {
                keyStore.deleteEntry(alias)
                check(!keyStore.containsAlias(alias)) { "The disposable test key was not removed." }
            } finally {
                check(directory.deleteRecursively()) { "The disposable test directory was not removed." }
            }
        }
    }

    @Test
    fun runtimeObservationReportsRunningStateAndRealConnectionCount() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        stopExistingService(context)
        val selection = TestSelection(context)
        SourceProxyRuntime.installTestEnvironment(testEnvironment(selection))
        val echo = TcpEchoOnHotspot()
        val scenario = ActivityScenario.launch(MainActivity::class.java)
        try {
            SourceProxyService.start(context)
            assertTrue(
                "The service must report a state.",
                waitUntil(START_TIMEOUT_MILLIS) {
                    SourceProxyRuntime.lastState == SourceProxyState.RUNNING ||
                        SourceProxyRuntime.lastState == SourceProxyState.STOPPED
                },
            )
            assertEquals(SourceProxyState.RUNNING, SourceProxyRuntime.lastState)
            val running = SourceProxyRuntime.observation()
            assertEquals(SourceProxyState.RUNNING, running.state)
            assertEquals(0, running.connections)
            assertEquals(0L, running.totalConnections)
            assertTrue("The server must bind a port.", running.port > 0)

            val client = openRelay(HOTSPOT, running.port, echo.port)
            try {
                assertTrue(
                    "The open count must include the new relay.",
                    waitUntil(5_000) { SourceProxyRuntime.observation().connections == 1 },
                )
                assertEquals(1L, SourceProxyRuntime.observation().totalConnections)
                val payload = "emulator relay check".toByteArray(Charsets.US_ASCII)
                client.getOutputStream().write(payload)
                client.getOutputStream().flush()
                org.junit.Assert.assertArrayEquals(payload, readExactly(client.getInputStream(), payload.size))
            } finally {
                client.close()
            }
            assertTrue(
                "The open count must fall when the relay closes.",
                waitUntil(5_000) { SourceProxyRuntime.observation().connections == 0 },
            )
            assertEquals(1L, SourceProxyRuntime.observation().totalConnections)
        } finally {
            SourceProxyService.stop(context)
            assertTrue(
                "The service must stop.",
                waitUntil(STOP_TIMEOUT_MILLIS) {
                    SourceProxyRuntime.lastState == SourceProxyState.STOPPED
                },
            )
            assertEquals(0, SourceProxyRuntime.observation().connections)
            scenario.close()
            echo.close()
            SourceProxyRuntime.clearTestEnvironment()
            context.stopService(Intent(context, SourceProxyService::class.java))
        }
    }

    @Test
    fun sharedPreferencesTrustStoreForgetsOneAndAll() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val preferences = context.getSharedPreferences(
            "hotspotshade-source-test",
            Context.MODE_PRIVATE,
        )
        preferences.edit().clear().commit()
        val store = FilePairingTrustStore(File(context.cacheDir, "trust-instrumented"), preferences)
        val first = ByteArray(32) { 0x11 }
        val second = ByteArray(32) { 0x22 }
        try {
            store.add(first)
            store.add(second)
            assertEquals(2, store.count)
            val targets = store.targets()
            assertEquals(2, targets.size)
            assertTrue(store.forget(targets.first().id))
            assertEquals(1, store.count)
            store.forgetAll()
            assertEquals(0, store.count)
        } finally {
            store.forgetAll()
            preferences.edit().clear().commit()
        }
    }

    @Test
    fun pairingAdminRotatesTheRealTokenFile() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val alias = "hs-token-rotation-${UUID.randomUUID()}"
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        check(!keyStore.containsAlias(alias)) { "The disposable test alias already exists." }
        val directory = Files.createTempDirectory(context.cacheDir.toPath(), "hs-token-rotation-").toFile()
        val file = File(directory, "source-token.bin")
        val store = AndroidKeystoreTokenStore(file, codec = KeystoreTokenFileCodec(keyAlias = alias))
        val admin = PairingAdmin(
            trust = MemoryPairingTrustStore(),
            tokenStore = store,
            tokenFactory = { "rotated-instrumented-token" },
            isProxyActive = { false },
            guard = SourceTokenGuard(),
        )
        try {
            store.save(TOKEN)
            assertEquals(TokenRotateResult.ROTATED, admin.rotateToken())
            assertEquals("rotated-instrumented-token", store.load())
        } finally {
            try {
                keyStore.deleteEntry(alias)
                check(!keyStore.containsAlias(alias)) { "The disposable test key was not removed." }
            } finally {
                check(directory.deleteRecursively()) { "The disposable test directory was not removed." }
            }
        }
    }

    @Test
    fun networkResolverResolvesOnTheDefaultNetwork() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val connectivity = requireNotNull(
            context.getSystemService(ConnectivityManager::class.java),
        )
        val network = connectivity.activeNetwork
        assertNotNull("The emulator must have a default network.", network)
        val addresses = NetworkResolver(network!!).resolve("localhost")
        assertTrue("The network lookup must answer for localhost.", addresses.isNotEmpty())
    }

    /**
     * Open one authenticated SOCKS5 CONNECT flow.
     *
     * The test uses the fixed test token. The helper logs no token or address.
     */
    private fun openRelay(address: InetAddress, port: Int, destinationPort: Int): Socket {
        val socket = Socket()
        socket.connect(InetSocketAddress(address, port), 3_000)
        socket.soTimeout = 3_000
        val input = socket.getInputStream()
        val output = socket.getOutputStream()
        output.write(byteArrayOf(5, 1, 2))
        output.flush()
        val method = readExactly(input, 2)
        assertEquals(5, method[0].toInt())
        assertEquals(2, method[1].toInt())
        val user = "hotspotshade".toByteArray(Charsets.US_ASCII)
        val token = TOKEN.toByteArray(Charsets.US_ASCII)
        val auth = ByteArray(3 + user.size + token.size)
        auth[0] = 1
        auth[1] = user.size.toByte()
        user.copyInto(auth, 2)
        auth[2 + user.size] = token.size.toByte()
        token.copyInto(auth, 3 + user.size)
        output.write(auth)
        output.flush()
        val authReply = readExactly(input, 2)
        assertEquals(1, authReply[0].toInt())
        assertEquals(0, authReply[1].toInt())
        val host = address.address
        val request = byteArrayOf(
            5,
            1,
            0,
            1,
            host[0],
            host[1],
            host[2],
            host[3],
            (destinationPort shr 8).toByte(),
            destinationPort.toByte(),
        )
        output.write(request)
        output.flush()
        val reply = readExactly(input, 10)
        assertEquals(0, reply[1].toInt())
        return socket
    }

    private fun readExactly(input: java.io.InputStream, count: Int): ByteArray {
        val bytes = ByteArray(count)
        var offset = 0
        while (offset < count) {
            val read = input.read(bytes, offset, count - offset)
            if (read < 0) throw IllegalStateException("The connection ended.")
            offset += read
        }
        return bytes
    }

    private class TcpEchoOnHotspot(address: InetAddress? = null) : Closeable {
        private val listener = ServerSocket(0, 4, address)
        private val workers = Executors.newCachedThreadPool { runnable ->
            Thread(runnable, "source-test-echo").apply { isDaemon = true }
        }

        @Volatile
        private var closed = false

        val port: Int get() = listener.localPort

        init {
            workers.execute {
                while (!closed) {
                    val client = try {
                        listener.accept()
                    } catch (_: Exception) {
                        break
                    }
                    workers.execute {
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
                        } catch (_: Exception) {
                            // The test closed the flow.
                        }
                    }
                }
            }
        }

        override fun close() {
            closed = true
            try {
                listener.close()
            } catch (_: Exception) {
                // The listener is already closed.
            }
            workers.shutdownNow()
        }
    }

    private fun testEnvironment(selection: TestSelection): SourceProxyEnvironment {
        val finder = TestOnlyHotspotFinder(TestOnlyHotspot.EMULATOR_ADDRESS)
        return SourceProxyEnvironment(
            tokenStore = TokenStore { TOKEN },
            hotspotFinder = finder,
            selectionFactory = { selection },
            resolverFactory = { binding ->
                val selected = binding as SelectedCellularNetworkBinding
                NetworkResolver(selected.network)
            },
            echoFactory = { binding ->
                val selected = binding as SelectedCellularNetworkBinding
                AndroidNetworkEcho(selected.network)
            },
            serverFactory = SourceProxyRuntime.serverFactory(),
            watchFactory = { address ->
                PeriodicHotspotWatch(finder, address, periodMillis = 500)
            },
        )
    }

    private fun stopExistingService(context: Context) {
        context.stopService(Intent(context, SourceProxyService::class.java))
        Thread.sleep(500)
    }

    private fun runningNotificationText(context: Context): String? {
        val manager = requireNotNull(
            context.getSystemService(NotificationManager::class.java),
        )
        return manager.activeNotifications
            .mapNotNull { status ->
                status.notification.extras.getCharSequence(Notification.EXTRA_TEXT)?.toString()
            }
            .firstOrNull { text -> text == RUNNING_NOTIFICATION_TEXT }
    }

    private fun grantNotificationPermission(
        instrumentation: Instrumentation,
        context: Context,
    ) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        if (androidx.core.content.ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.POST_NOTIFICATIONS,
            ) == android.content.pm.PackageManager.PERMISSION_GRANTED
        ) {
            return
        }
        try {
            instrumentation.uiAutomation.grantRuntimePermission(
                context.packageName,
                Manifest.permission.POST_NOTIFICATIONS,
            )
        } catch (_: Exception) {
            // The service runs without a notification permission.
        }
    }

    private fun waitUntil(timeoutMillis: Long, condition: () -> Boolean): Boolean {
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
        while (System.nanoTime() < deadline) {
            if (condition()) return true
            Thread.sleep(50)
        }
        return condition()
    }

    private class DefaultNetworkBinding(
        override val network: Network,
    ) : SelectedCellularNetworkBinding {
        override fun requireAvailable() = Unit
        override fun bind(socket: Socket) = Unit
        override fun bind(socket: DatagramSocket) = Unit
    }

    /** Report the emulator default network as the selected cellular network. */
    private class TestSelection(context: Context) : CellularNetworkSelection {
        private val connectivity = requireNotNull(
            context.getSystemService(ConnectivityManager::class.java),
        )
        private val lock = Any()
        private var listener: CellularNetworkSelection.Listener? = null

        @Volatile
        var starts = 0
            private set

        @Volatile
        var stops = 0
            private set

        override fun start(listener: CellularNetworkSelection.Listener) {
            starts += 1
            synchronized(lock) { this.listener = listener }
            val network = connectivity.activeNetwork
                ?: throw IllegalStateException("The emulator has no default network.")
            val binding = DefaultNetworkBinding(network)
            val target = listener
            Thread({
                try {
                    Thread.sleep(250)
                } catch (_: InterruptedException) {
                    return@Thread
                }
                target.onAvailable(binding)
            }, "source-test-selection").apply { isDaemon = true }.start()
        }

        override fun stop() {
            stops += 1
            synchronized(lock) { listener = null }
        }

        fun lose() {
            val target = synchronized(lock) { listener }
            target?.onLost()
        }
    }

    /**
     * Forward emulator loopback connections to the bound hotspot address.
     *
     * The bridge is a test tool. adb forward connects to the emulator
     * loopback. The service binds the hotspot address only.
     */
    private class LoopbackBridge(
        private val destination: InetAddress,
        private val destinationPort: () -> Int,
    ) : Closeable {
        private val workers = Executors.newCachedThreadPool { runnable ->
            Thread(runnable, "source-test-bridge").apply { isDaemon = true }
        }
        private val listener = ServerSocket(0, 16, LOOPBACK)

        @Volatile
        private var closed = false

        val port: Int get() = listener.localPort

        fun start() {
            workers.execute {
                while (!closed) {
                    val client = try {
                        listener.accept()
                    } catch (_: Exception) {
                        break
                    }
                    val targetPort = destinationPort()
                    if (targetPort <= 0) {
                        closeQuietly(client)
                        continue
                    }
                    try {
                        workers.execute { relay(client, targetPort) }
                    } catch (_: Exception) {
                        closeQuietly(client)
                    }
                }
            }
        }

        private fun relay(client: Socket, targetPort: Int) {
            val server = Socket()
            try {
                server.connect(InetSocketAddress(destination, targetPort), 3_000)
            } catch (_: Exception) {
                closeQuietly(client)
                closeQuietly(server)
                return
            }
            val up = Thread({ pump(client, server) }, "source-test-bridge-up").apply {
                isDaemon = true
            }
            val down = Thread({ pump(server, client) }, "source-test-bridge-down").apply {
                isDaemon = true
            }
            up.start()
            down.start()
        }

        private fun pump(from: Socket, to: Socket) {
            try {
                val input = from.getInputStream()
                val output = to.getOutputStream()
                val buffer = ByteArray(16 * 1024)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    output.write(buffer, 0, count)
                    output.flush()
                }
            } catch (_: Exception) {
                // The connection ended.
            } finally {
                closeQuietly(from)
                closeQuietly(to)
            }
        }

        override fun close() {
            closed = true
            closeQuietly(listener)
            workers.shutdownNow()
        }

        private fun closeQuietly(closeable: Closeable?) {
            try {
                closeable?.close()
            } catch (_: Exception) {
                // The connection is already closed.
            }
        }
    }

    private companion object {
        const val TAG = "HS_SERVICE_INTEROP"
        const val TOKEN = "emulator-test-token"
        const val STOP_FILE = "hs-service-interop-stop"
        const val START_TIMEOUT_MILLIS = 15_000L
        const val STOP_TIMEOUT_MILLIS = 10_000L
        const val SERVE_TIMEOUT_MILLIS = 180_000L
        const val RUNNING_NOTIFICATION_TEXT =
            "The source proxy is running. Target devices can connect through the hotspot."
        val HOTSPOT: InetAddress = TestOnlyHotspot.EMULATOR_ADDRESS
        val LOOPBACK: InetAddress = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
    }
}
