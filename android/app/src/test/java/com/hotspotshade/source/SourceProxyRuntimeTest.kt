package com.hotspotshade.source

import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Tests for the status report that the app reads.
 *
 * These are JVM tests. They do not start the Android service, bind a listener,
 * or touch a device. They cover the repeated start request that used to clear a
 * live report and leave the app on Starting.
 */
class SourceProxyRuntimeTest {
    @Before
    fun setUp() {
        SourceProxyRuntime.resetObservation()
    }

    @After
    fun tearDown() {
        SourceProxyRuntime.attach(null)
        SourceProxyRuntime.resetObservation()
    }

    private class FakeSelection : CellularNetworkSelection {
        lateinit var callback: CellularNetworkSelection.Listener

        override fun start(listener: CellularNetworkSelection.Listener) {
            callback = listener
        }

        override fun stop() = Unit
    }

    private class FakeBinding : CellularBinding {
        override fun requireAvailable() = Unit
        override fun bind(socket: Socket) = Unit
        override fun bind(socket: DatagramSocket) = Unit
    }

    private class FakeServer : SourceServerHandle {
        override val localPort: Int = 40123
        override val activeConnections: Int = 0
        override val totalConnections: Long = 0L
        var closed = false

        override fun start() = Unit

        override fun close() {
            closed = true
        }
    }

    private class FakeWatch : HotspotWatch {
        override fun start(onLost: () -> Unit) = Unit
        override fun stop() = Unit
    }

    private class RunningHarness {
        val selection = FakeSelection()
        val queue = ManualSourceProxyTaskQueue()
        val server = FakeServer()
        val guard = SourceTokenGuard()
        val controller = SourceProxyController(
            tokenStore = TokenStore { "runtime-test-token" },
            hotspotFinder = object : HotspotAddressFinder {
                override fun probe(): HotspotProbe = observed(HOTSPOT)
            },
            selectionFactory = { selection },
            resolverFactory = { SourceHostResolver { emptyList() } },
            echoFactory = { SourceEchoSender { _, _, _ -> EchoResult(EchoStatus.FAILED) } },
            serverFactory = { _, _, _, _, _ -> server },
            watchFactory = { FakeWatch() },
            listener = SourceProxyListener { },
            tokenGuard = guard,
            taskQueueFactory = { queue },
            clockMillis = { 0L },
            sleepMillis = { },
        )

        fun run() {
            assertTrue(controller.start())
            queue.runAll()
            selection.callback.onAvailable(FakeBinding())
            queue.runAll()
            assertEquals(SourceProxyState.RUNNING, controller.state)
        }

        fun close() {
            controller.stop()
            queue.shutdown()
        }
    }

    @Test
    fun requestStartKeepsALiveRunReport() {
        val harness = RunningHarness()
        try {
            harness.run()
            SourceProxyRuntime.attach(harness.controller)
            SourceProxyRuntime.record(harness.controller.snapshot())
            assertEquals(SourceProxyState.RUNNING, SourceProxyRuntime.lastState)
            assertEquals(40123, SourceProxyRuntime.lastPort)

            SourceProxyRuntime.requestStart()

            assertEquals(
                "A repeated start must not hide a live run.",
                SourceProxyState.RUNNING,
                SourceProxyRuntime.lastState,
            )
            assertEquals(40123, SourceProxyRuntime.lastPort)
            assertEquals(SourceProxyStopReason.NONE, SourceProxyRuntime.lastStopReason)
            assertTrue(SourceProxyRuntime.observation().connections == 0)
        } finally {
            SourceProxyRuntime.attach(null)
            harness.close()
        }
    }

    @Test
    fun requestStartClearsAFinishedRun() {
        SourceProxyRuntime.attach(null)
        SourceProxyRuntime.record(
            SourceProxySnapshot(SourceProxyState.STOPPED, SourceProxyStopReason.USER_STOP, 0),
        )

        SourceProxyRuntime.requestStart()

        assertEquals(SourceProxyState.IDLE, SourceProxyRuntime.lastState)
        assertEquals(SourceProxyStopReason.NONE, SourceProxyRuntime.lastStopReason)
        assertEquals(0, SourceProxyRuntime.lastPort)
    }

    @Test
    fun aRepeatedStartRestoresTheControllerSnapshot() {
        val harness = RunningHarness()
        try {
            harness.run()
            // Simulate the clear that an earlier repeated start performed.
            SourceProxyRuntime.resetObservation()
            assertEquals(SourceProxyState.IDLE, SourceProxyRuntime.lastState)

            SourceProxyRuntime.attach(harness.controller)
            SourceProxyRuntime.record(harness.controller.snapshot())

            assertEquals(SourceProxyState.RUNNING, SourceProxyRuntime.lastState)
            assertEquals(40123, SourceProxyRuntime.lastPort)
            assertFalse(harness.server.closed)
        } finally {
            SourceProxyRuntime.attach(null)
            harness.close()
        }
    }

    @Test
    fun thePairingBindingComesFromOneControllerSnapshot() {
        val harness = RunningHarness()
        try {
            harness.run()
            SourceProxyRuntime.attach(harness.controller)
            SourceProxyRuntime.record(harness.controller.snapshot())

            val live = SourceProxyRuntime.binding()
            assertEquals(SourceProxyState.RUNNING, live.state)
            assertTrue(live.active)
            assertEquals(40123, live.port)
            assertEquals(HOTSPOT, live.address)
            assertEquals(0, live.connections)
            assertEquals(0L, live.totalConnections)

            harness.controller.stop()

            val stopped = SourceProxyRuntime.binding()
            assertEquals(SourceProxyState.STOPPED, stopped.state)
            assertFalse(stopped.active)
            assertEquals(0, stopped.port)
            assertEquals(null, stopped.address)
            assertEquals(0, stopped.connections)
            assertEquals(0L, stopped.totalConnections)
        } finally {
            SourceProxyRuntime.attach(null)
            harness.close()
        }
    }

    @Test
    fun aTokenRotationUsesTheBindingSnapshotAcrossAStop() {
        val harness = RunningHarness()
        var written: String? = null
        val admin = PairingAdmin(
            trust = com.hotspotshade.source.pairing.MemoryPairingTrustStore(),
            tokenStore = TokenWriter { token -> written = token },
            tokenFactory = { "new-token" },
            guard = SourceTokenGuard(),
        )
        try {
            harness.run()
            SourceProxyRuntime.attach(harness.controller)
            SourceProxyRuntime.record(harness.controller.snapshot())

            assertEquals(
                "A live binding must refuse the rotation.",
                TokenRotateResult.REFUSED_RUNNING,
                admin.rotateToken(),
            )
            assertEquals(null, written)

            harness.controller.stop()

            assertEquals(
                "A stopped binding must allow the rotation.",
                TokenRotateResult.ROTATED,
                admin.rotateToken(),
            )
            assertEquals("new-token", written)
        } finally {
            SourceProxyRuntime.attach(null)
            harness.close()
        }
    }

    private companion object {
        val HOTSPOT: InetAddress = InetAddress.getByName("192.168.43.1")

        fun observed(address: InetAddress): HotspotProbe.Observed = HotspotProbe.Observed(
            candidates = listOf(HotspotCandidate(rank = 0, address = address)),
            excludedAddresses = emptySet(),
        )
    }
}
