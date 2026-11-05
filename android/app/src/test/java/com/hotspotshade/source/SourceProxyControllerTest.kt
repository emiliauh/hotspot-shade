package com.hotspotshade.source

import java.io.IOException
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SourceProxyControllerTest {
    private class FakeSelection : CellularNetworkSelection {
        lateinit var callback: CellularNetworkSelection.Listener
        var starts = 0
        var stops = 0

        override fun start(listener: CellularNetworkSelection.Listener) {
            starts += 1
            callback = listener
        }

        override fun stop() {
            stops += 1
        }
    }

    private class FakeBinding : CellularBinding {
        override fun requireAvailable() = Unit
        override fun bind(socket: Socket) = Unit
        override fun bind(socket: DatagramSocket) = Unit
    }

    private class FakeFinder(var address: InetAddress?) : HotspotAddressFinder {
        var calls = 0

        override fun findHotspotAddress(): InetAddress? {
            calls += 1
            return address
        }
    }

    private class FakeTokenStore(var token: String?) : TokenStore {
        override fun load(): String? = token
    }

    private class FakeServer(private val failStart: Boolean) : SourceServerHandle {
        var starts = 0
        var stops = 0
        var closed = false
        var open = 0
        var total = 0L

        override val localPort: Int = PORT

        override val activeConnections: Int get() = open

        override val totalConnections: Long get() = total

        override fun start() {
            if (failStart) throw IOException("The listener cannot bind.")
            starts += 1
        }

        override fun close() {
            stops += 1
            closed = true
            open = 0
        }
    }

    private class FakeWatch(private val failStart: Boolean) : HotspotWatch {
        var started = false
        var stops = 0
        var lost: (() -> Unit)? = null

        override fun start(onLost: () -> Unit) {
            if (failStart) throw IllegalStateException("The watch cannot start.")
            started = true
            lost = onLost
        }

        override fun stop() {
            stops += 1
        }

        fun lose() {
            lost?.invoke()
        }
    }

    private class RecordingListener : SourceProxyListener {
        val snapshots = mutableListOf<SourceProxySnapshot>()

        override fun onStateChanged(snapshot: SourceProxySnapshot) {
            snapshots += snapshot
        }

        val terminals: List<SourceProxySnapshot>
            get() = snapshots.filter { it.state == SourceProxyState.STOPPED }
    }

    private class Harness(
        hotspot: InetAddress? = HOTSPOT,
        token: String? = TOKEN,
        failBind: Boolean = false,
        failResolver: Boolean = false,
        failWatch: Boolean = false,
    ) {
        val selection = FakeSelection()
        val binding = FakeBinding()
        val finder = FakeFinder(hotspot)
        val tokenStore = FakeTokenStore(token)
        val listener = RecordingListener()
        val servers = mutableListOf<FakeServer>()
        val watches = mutableListOf<FakeWatch>()
        val requestedAddresses = mutableListOf<InetAddress>()
        val resolverCalls = AtomicInteger()
        private val failBindValue = failBind
        private val failWatchValue = failWatch

        val controller = SourceProxyController(
            tokenStore = tokenStore,
            hotspotFinder = finder,
            selectionFactory = { selection },
            resolverFactory = {
                resolverCalls.incrementAndGet()
                if (failResolver) throw IOException("The resolver cannot start.")
                SourceHostResolver { emptyList() }
            },
            echoFactory = {
                SourceEchoSender { _, _, _ -> EchoResult(EchoStatus.FAILED) }
            },
            serverFactory = { _, _, _, address, _ ->
                requestedAddresses += address
                FakeServer(failBindValue).also { servers += it }
            },
            watchFactory = {
                FakeWatch(failWatchValue).also { watches += it }
            },
            listener = listener,
        )

        fun start(): Boolean = controller.start()

        fun available() = selection.callback.onAvailable(binding)
    }

    @Test
    fun startWaitsForTheCellularNetwork() {
        val harness = Harness()

        assertTrue(harness.start())

        assertEquals(SourceProxyState.WAITING_FOR_NETWORK, harness.controller.state)
        assertEquals(SourceProxyStopReason.NONE, harness.controller.stopReason)
        assertEquals(1, harness.selection.starts)
        assertTrue(harness.servers.isEmpty())
        assertEquals(
            listOf(SourceProxyState.WAITING_FOR_NETWORK),
            harness.listener.snapshots.map { it.state },
        )
    }

    @Test
    fun availableBindsOnlyTheHotspotAddress() {
        val harness = Harness()
        harness.start()

        harness.available()

        assertEquals(SourceProxyState.RUNNING, harness.controller.state)
        assertEquals(listOf(HOTSPOT), harness.requestedAddresses)
        assertFalse(harness.requestedAddresses.single().isAnyLocalAddress)
        assertEquals(PORT, harness.controller.localPort)
        assertEquals(1, harness.servers.single().starts)
        assertTrue(harness.watches.single().started)
        assertEquals(
            listOf(SourceProxyState.WAITING_FOR_NETWORK, SourceProxyState.RUNNING),
            harness.listener.snapshots.map { it.state },
        )
        assertEquals(1, harness.resolverCalls.get())
    }

    @Test
    fun connectionCountComesFromTheServer() {
        val harness = Harness()
        harness.start()
        assertEquals(0, harness.controller.connectionCount)
        assertEquals(0L, harness.controller.totalConnections)

        harness.available()
        val server = harness.servers.single()
        server.open = 3
        server.total = 7L

        assertEquals(3, harness.controller.connectionCount)
        assertEquals(7L, harness.controller.totalConnections)

        harness.controller.stop()

        assertEquals(0, harness.controller.connectionCount)
        assertEquals(0L, harness.controller.totalConnections)
    }

    @Test
    fun hotspotMissingStopsBeforeTheMonitor() {
        val harness = Harness(hotspot = null)

        assertFalse(harness.start())

        assertEquals(SourceProxyState.STOPPED, harness.controller.state)
        assertEquals(SourceProxyStopReason.HOTSPOT_NOT_FOUND, harness.controller.stopReason)
        assertEquals(0, harness.selection.starts)
        assertTrue(harness.servers.isEmpty())
        assertEquals(1, harness.listener.terminals.size)
        assertEquals(
            SourceProxyStopReason.HOTSPOT_NOT_FOUND,
            harness.listener.terminals.single().reason,
        )
    }

    @Test
    fun hotspotMissingAtSetupStopsWithoutABind() {
        val harness = Harness()
        harness.start()
        harness.finder.address = null

        harness.available()

        assertEquals(SourceProxyState.STOPPED, harness.controller.state)
        assertEquals(SourceProxyStopReason.HOTSPOT_NOT_FOUND, harness.controller.stopReason)
        assertTrue(harness.servers.isEmpty())
        assertEquals(1, harness.selection.stops)
        assertEquals(1, harness.listener.terminals.size)
        assertEquals(0, harness.controller.localPort)
    }

    @Test
    fun networkLostClosesTheServerAndTheWatch() {
        val harness = Harness()
        harness.start()
        harness.available()
        val server = harness.servers.single()
        val watch = harness.watches.single()

        harness.selection.callback.onLost()

        assertEquals(SourceProxyState.STOPPED, harness.controller.state)
        assertEquals(SourceProxyStopReason.NETWORK_LOST, harness.controller.stopReason)
        assertTrue(server.closed)
        assertEquals(1, server.stops)
        assertEquals(1, watch.stops)
        assertEquals(1, harness.selection.stops)
        assertEquals(1, harness.listener.terminals.size)
        assertEquals(0, harness.controller.localPort)
    }

    @Test
    fun capabilityLossStopsTheRun() {
        val harness = Harness()
        harness.start()
        harness.available()

        harness.selection.callback.onCapabilitiesLost()

        assertEquals(SourceProxyState.STOPPED, harness.controller.state)
        assertEquals(SourceProxyStopReason.CAPABILITIES_LOST, harness.controller.stopReason)
        assertTrue(harness.servers.single().closed)
        assertEquals(1, harness.listener.terminals.size)
    }

    @Test
    fun networkUnavailableStopsTheRun() {
        val harness = Harness()
        harness.start()

        harness.selection.callback.onUnavailable()

        assertEquals(SourceProxyState.STOPPED, harness.controller.state)
        assertEquals(SourceProxyStopReason.NETWORK_UNAVAILABLE, harness.controller.stopReason)
        assertEquals(1, harness.selection.stops)
        assertEquals(1, harness.listener.terminals.size)
    }

    @Test
    fun userStopClosesEverythingOneTime() {
        val harness = Harness()
        harness.start()
        harness.available()
        val server = harness.servers.single()
        val watch = harness.watches.single()

        harness.controller.stop()
        harness.controller.stop()

        assertEquals(SourceProxyState.STOPPED, harness.controller.state)
        assertEquals(SourceProxyStopReason.USER_STOP, harness.controller.stopReason)
        assertEquals(1, server.stops)
        assertEquals(1, watch.stops)
        assertEquals(1, harness.selection.stops)
        assertEquals(1, harness.listener.terminals.size)
        assertNull(harness.controller.closeFailure)
    }

    @Test
    fun doubleStartDoesNotCreateASecondRun() {
        val harness = Harness()
        assertTrue(harness.start())

        assertFalse(harness.start())
        harness.available()
        assertFalse(harness.start())

        assertEquals(1, harness.selection.starts)
        assertEquals(1, harness.servers.size)
        assertEquals(1, harness.watches.size)
        assertEquals(
            listOf(SourceProxyState.WAITING_FOR_NETWORK, SourceProxyState.RUNNING),
            harness.listener.snapshots.map { it.state },
        )
    }

    @Test
    fun stoppedControllerRefusesARestart() {
        val harness = Harness()
        harness.start()
        harness.available()
        harness.controller.stop()

        assertFalse(harness.start())

        assertEquals(1, harness.selection.starts)
        assertEquals(1, harness.servers.size)
        assertEquals(1, harness.listener.terminals.size)
        assertEquals(SourceProxyStopReason.USER_STOP, harness.controller.stopReason)
    }

    @Test
    fun lateAvailabilityAfterStopDoesNotStartAnything() {
        val harness = Harness()
        harness.start()
        harness.controller.stop()

        harness.available()

        assertTrue(harness.servers.isEmpty())
        assertTrue(harness.watches.isEmpty())
        assertEquals(1, harness.selection.starts)
        assertEquals(1, harness.selection.stops)
        assertEquals(1, harness.listener.terminals.size)
        assertEquals(SourceProxyStopReason.USER_STOP, harness.controller.stopReason)
    }

    @Test
    fun lateLossAfterStopDoesNotNotifyAgain() {
        val harness = Harness()
        harness.start()
        harness.available()
        harness.controller.stop()

        harness.selection.callback.onLost()
        harness.watches.single().lose()
        harness.selection.callback.onUnavailable()

        assertEquals(1, harness.listener.terminals.size)
        assertEquals(SourceProxyStopReason.USER_STOP, harness.controller.stopReason)
        assertEquals(1, harness.servers.single().stops)
    }

    @Test
    fun hotspotLossStopsTheRun() {
        val harness = Harness()
        harness.start()
        harness.available()

        harness.watches.single().lose()

        assertEquals(SourceProxyState.STOPPED, harness.controller.state)
        assertEquals(SourceProxyStopReason.HOTSPOT_LOST, harness.controller.stopReason)
        assertTrue(harness.servers.single().closed)
        assertEquals(1, harness.watches.single().stops)
        assertEquals(1, harness.selection.stops)
        assertEquals(1, harness.listener.terminals.size)
    }

    @Test
    fun tokenMissingStopsBeforeTheMonitor() {
        val harness = Harness(token = null)

        assertFalse(harness.start())

        assertEquals(SourceProxyState.STOPPED, harness.controller.state)
        assertEquals(SourceProxyStopReason.TOKEN_MISSING, harness.controller.stopReason)
        assertEquals(0, harness.selection.starts)
        assertTrue(harness.servers.isEmpty())
        assertEquals(1, harness.listener.terminals.size)
    }

    @Test
    fun bindFailureStopsTheRun() {
        val harness = Harness(failBind = true)
        harness.start()

        harness.available()

        assertEquals(SourceProxyState.STOPPED, harness.controller.state)
        assertEquals(SourceProxyStopReason.BIND_FAILED, harness.controller.stopReason)
        assertTrue(harness.servers.single().closed)
        assertTrue(harness.watches.isEmpty())
        assertEquals(1, harness.selection.stops)
        assertEquals(1, harness.listener.terminals.size)
        assertEquals(0, harness.controller.localPort)
    }

    @Test
    fun resolverFailureStopsTheRun() {
        val harness = Harness(failResolver = true)
        harness.start()

        harness.available()

        assertEquals(SourceProxyState.STOPPED, harness.controller.state)
        assertEquals(SourceProxyStopReason.START_FAILED, harness.controller.stopReason)
        assertTrue(harness.servers.isEmpty())
        assertEquals(1, harness.selection.stops)
        assertEquals(1, harness.listener.terminals.size)
    }

    @Test
    fun watchFailureStopsTheRun() {
        val harness = Harness(failWatch = true)
        harness.start()

        harness.available()

        assertEquals(SourceProxyState.STOPPED, harness.controller.state)
        assertEquals(SourceProxyStopReason.START_FAILED, harness.controller.stopReason)
        assertTrue(harness.servers.single().closed)
        assertEquals(1, harness.watches.single().stops)
        assertEquals(1, harness.listener.terminals.size)
    }

    @Test
    fun stopWhileWaitingIsClean() {
        val harness = Harness()
        harness.start()

        harness.controller.stop()

        assertEquals(SourceProxyState.STOPPED, harness.controller.state)
        assertEquals(SourceProxyStopReason.USER_STOP, harness.controller.stopReason)
        assertEquals(1, harness.selection.stops)
        assertEquals(1, harness.listener.terminals.size)
    }

    @Test
    fun snapshotsHoldNoTokenOrAddress() {
        val harness = Harness()
        harness.start()
        harness.available()
        harness.controller.stop()

        val text = harness.listener.snapshots.joinToString()
        val address = HOTSPOT.hostAddress ?: ""
        assertFalse(text.contains(TOKEN))
        assertFalse(address.isNotEmpty() && text.contains(address))
    }

    private companion object {
        const val PORT = 40123
        const val TOKEN = "controller-test-token"
        val HOTSPOT: InetAddress = InetAddress.getByName("192.168.43.1")
    }
}
