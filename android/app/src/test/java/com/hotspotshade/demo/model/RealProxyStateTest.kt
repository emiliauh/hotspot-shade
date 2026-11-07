package com.hotspotshade.demo.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RealProxyStateTest {
    @Test
    fun tokenMissingSaysPairFirst() {
        val state = RealProxyState(
            phase = RealProxyPhase.STOPPED,
            stopReason = RealStopReason.TOKEN_MISSING,
        )

        assertEquals("Pair first", state.statusTitle)
        assertTrue(state.statusMessage.contains("Pair first"))
        assertEquals(StatusKind.ATTENTION, state.statusKind)
        assertEquals("Start", state.actionTitle)
    }

    @Test
    fun missingHotspotSaysWaitingForTheHotspot() {
        val state = RealProxyState(phase = RealProxyPhase.WAITING_FOR_HOTSPOT)

        assertEquals("Waiting for the hotspot", state.statusTitle)
        assertTrue(state.statusMessage.contains("Turn on the hotspot"))
        assertEquals(StatusKind.ATTENTION, state.statusKind)
        assertFalse(state.active)
        assertFalse(state.running)
        assertEquals("Start", state.actionTitle)
    }

    @Test
    fun waitingForCellularIsItsOwnState() {
        val state = RealProxyState(phase = RealProxyPhase.WAITING_FOR_CELLULAR)

        assertEquals("Waiting for the cellular network", state.statusTitle)
        assertTrue(state.statusMessage.contains("Waiting for the cellular network"))
        assertTrue(state.active)
    }

    @Test
    fun runningShowsTheRealCounts() {
        val state = RealProxyState(
            phase = RealProxyPhase.RUNNING,
            port = 41234,
            connections = 2,
            totalConnections = 9,
        )

        assertEquals("On", state.statusTitle)
        assertEquals("Stop", state.actionTitle)
        assertEquals("Target device connected", state.usageTitle)
        assertEquals(
            listOf("Open connections: 2.", "Connections since start: 9."),
            state.connectionLines,
        )
        assertEquals("41234", state.portText)
        assertNull(state.lastStopText)
    }

    @Test
    fun stoppedRunShowsThePlainReason() {
        val state = RealProxyState(
            phase = RealProxyPhase.STOPPED,
            stopReason = RealStopReason.NETWORK_LOST,
            stoppedAtMillis = 1_700_000_000_000,
        )

        assertEquals("Needs attention", state.statusTitle)
        assertTrue(state.statusMessage.contains("The cellular network is gone"))
        assertEquals("Last stop: The cellular network is gone.", state.lastStopText)
        assertEquals("Start", state.actionTitle)
        assertTrue(state.connectionLines.isEmpty())
    }

    @Test
    fun userStopShowsOff() {
        val state = RealProxyState(
            phase = RealProxyPhase.STOPPED,
            stopReason = RealStopReason.USER,
        )

        assertEquals("Off", state.statusTitle)
        assertEquals(StatusKind.OFF, state.statusKind)
    }

    @Test
    fun usageSummaryUsesTheTrustedCount() {
        val running = RealProxyState(phase = RealProxyPhase.RUNNING)
        val idle = RealProxyState()

        assertEquals(
            "Not paired. Open HotspotShade on your target device to pair.",
            running.usageSummary(0),
        )
        assertEquals(
            "Paired with 1 target device. The proxy is ready.",
            running.usageSummary(1),
        )
        assertEquals("Paired with 3 target devices.", idle.usageSummary(3))
    }

    @Test
    fun diagnosticsHoldCountsOnly() {
        val state = RealProxyState(
            phase = RealProxyPhase.RUNNING,
            port = 41234,
            connections = 2,
            totalConnections = 9,
        )

        val report = state.diagnosticsReport("on", "1.2.3")

        assertTrue(report.contains("Open connections: 2"))
        assertTrue(report.contains("Connections since start: 9"))
        assertTrue(report.contains("Pairing listener: on"))
        assertTrue(report.contains("Version: 1.2.3"))
        assertFalse(report.contains("demo"))
        assertFalse(report.contains("192.168."))
        assertFalse(report.contains("token="))
        assertFalse(report.contains("key="))
    }

    @Test
    fun portTextIsEmptyBeforeTheStart() {
        val state = RealProxyState()

        assertEquals("Chosen when the proxy starts.", state.portText)
        assertEquals("Start", state.actionTitle)
        assertEquals("Off", state.statusTitle)
    }
}
