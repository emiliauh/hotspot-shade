package com.hotspotshade.source

import java.io.IOException
import java.net.DatagramSocket
import java.net.Socket
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class CellularNetworkMonitorTest {
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

    private class Harness(
        private val newSocket: () -> Socket = { Socket() },
    ) {
        val selection = FakeSelection()
        val bindings = mutableListOf<CellularBinding>()
        val sessions = mutableListOf<CellularSession>()
        val flows = mutableListOf<CellularFlow<Socket>>()

        val monitor = CellularNetworkMonitor(selection) { binding ->
            bindings += binding
            val session = CellularSession(CellularSockets(binding, newTcp = newSocket))
            sessions += session
            flows += session.tcp()
            session
        }

        fun open(): FakeBinding {
            val binding = FakeBinding()
            selection.callback.onAvailable(binding)
            return binding
        }
    }

    @Test fun startRequestsOneSelectionAndWaitsForANetwork() {
        val harness = Harness()
        harness.monitor.start()
        assertEquals(1, harness.selection.starts)
        assertEquals(CellularNetworkMonitor.State.SELECTING, harness.monitor.state)
        assertEquals(CellularNetworkMonitor.StopReason.NONE, harness.monitor.stopReason)
        assertTrue(harness.sessions.isEmpty())
    }

    @Test fun availableOpensOneSessionForTheSelectedBinding() {
        val harness = Harness()
        harness.monitor.start()
        val binding = harness.open()
        assertEquals(CellularNetworkMonitor.State.OPEN, harness.monitor.state)
        assertSame(binding, harness.bindings.single())
        assertEquals(1, harness.sessions.size)
        assertEquals(1, harness.flows.size)
        assertEquals(0, harness.selection.stops)
    }

    @Test fun lostClosesTheSessionAndReleasesTheRequest() {
        val harness = Harness()
        harness.monitor.start()
        harness.open()
        val session = harness.sessions.single()
        val flow = harness.flows.single()

        harness.selection.callback.onLost()

        assertTrue(flow.socket.isClosed)
        assertEquals(CellularNetworkMonitor.State.STOPPED, harness.monitor.state)
        assertEquals(CellularNetworkMonitor.StopReason.NETWORK_LOST, harness.monitor.stopReason)
        assertEquals(1, harness.selection.stops)
        try {
            session.tcp()
            fail("A lost network must not accept a new flow")
        } catch (_: IOException) {
            // Expected.
        }
    }

    @Test fun capabilityLossClosesTheSessionAndReleasesTheRequest() {
        val harness = Harness()
        harness.monitor.start()
        harness.open()
        val flow = harness.flows.single()

        harness.selection.callback.onCapabilitiesLost()

        assertTrue(flow.socket.isClosed)
        assertEquals(CellularNetworkMonitor.State.STOPPED, harness.monitor.state)
        assertEquals(CellularNetworkMonitor.StopReason.CAPABILITIES_LOST, harness.monitor.stopReason)
        assertEquals(1, harness.selection.stops)
    }

    @Test fun unavailableStopsWithoutASession() {
        val harness = Harness()
        harness.monitor.start()

        harness.selection.callback.onUnavailable()

        assertEquals(CellularNetworkMonitor.State.STOPPED, harness.monitor.state)
        assertEquals(CellularNetworkMonitor.StopReason.UNAVAILABLE, harness.monitor.stopReason)
        assertTrue(harness.sessions.isEmpty())
        assertEquals(1, harness.selection.stops)
    }

    @Test fun lossDoesNotRestartTheSelectionOrASession() {
        val harness = Harness()
        harness.monitor.start()
        harness.open()
        harness.selection.callback.onLost()

        harness.selection.callback.onAvailable(FakeBinding())
        harness.selection.callback.onLost()

        assertEquals(1, harness.selection.starts)
        assertEquals(1, harness.selection.stops)
        assertEquals(1, harness.sessions.size)
        assertEquals(CellularNetworkMonitor.State.STOPPED, harness.monitor.state)
        assertEquals(CellularNetworkMonitor.StopReason.NETWORK_LOST, harness.monitor.stopReason)
        try {
            harness.monitor.start()
            fail("A monitor must not start a second time")
        } catch (_: IllegalStateException) {
            // Expected.
        }
    }

    @Test fun closeBeforeAvailabilityIgnoresTheLateNetwork() {
        val harness = Harness()
        harness.monitor.start()

        harness.monitor.close()
        harness.selection.callback.onAvailable(FakeBinding())

        assertEquals(CellularNetworkMonitor.State.STOPPED, harness.monitor.state)
        assertEquals(CellularNetworkMonitor.StopReason.SERVICE_STOP, harness.monitor.stopReason)
        assertTrue(harness.sessions.isEmpty())
        assertEquals(1, harness.selection.starts)
        assertEquals(1, harness.selection.stops)
    }

    @Test fun closeIsIdempotentAndIgnoresLateLoss() {
        val harness = Harness()
        harness.monitor.start()
        harness.open()
        val flow = harness.flows.single()

        harness.monitor.close()
        harness.monitor.close()
        harness.selection.callback.onLost()

        assertTrue(flow.socket.isClosed)
        assertEquals(CellularNetworkMonitor.State.STOPPED, harness.monitor.state)
        assertEquals(CellularNetworkMonitor.StopReason.SERVICE_STOP, harness.monitor.stopReason)
        assertEquals(1, harness.selection.stops)
    }

    @Test fun closeFailureIsReportedAndRetried() {
        val socket = object : Socket() {
            var attempts = 0
            override fun close() {
                attempts += 1
                if (attempts == 1) throw IOException("first close failed")
                super.close()
            }
        }
        val harness = Harness(newSocket = { socket })
        harness.monitor.start()
        harness.open()

        harness.monitor.close()

        assertEquals(1, socket.attempts)
        assertFalse(socket.isClosed)
        assertNotNull(harness.monitor.closeFailure)
        assertEquals(1, harness.selection.stops)

        harness.monitor.close()

        assertEquals(2, socket.attempts)
        assertTrue(socket.isClosed)
        assertNull(harness.monitor.closeFailure)
        assertEquals(1, harness.selection.stops)
    }

    @Test fun sessionFailureStopsSelection() {
        val selection = FakeSelection()
        val monitor = CellularNetworkMonitor(selection) {
            throw IllegalStateException("The session cannot start.")
        }
        monitor.start()

        selection.callback.onAvailable(FakeBinding())

        assertEquals(CellularNetworkMonitor.State.STOPPED, monitor.state)
        assertEquals(CellularNetworkMonitor.StopReason.UNAVAILABLE, monitor.stopReason)
        assertEquals(1, selection.stops)
        monitor.close()
        assertEquals(1, selection.stops)
    }
}
