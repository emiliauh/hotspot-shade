package com.hotspotshade.demo

import com.hotspotshade.demo.model.RealProxyPhase
import com.hotspotshade.demo.model.RealStopReason
import com.hotspotshade.source.SourceProxyObservation
import com.hotspotshade.source.SourceProxyState
import com.hotspotshade.source.SourceProxyStopReason
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ProxyStatusMappingTest {
    private fun observation(
        state: SourceProxyState,
        reason: SourceProxyStopReason = SourceProxyStopReason.NONE,
        port: Int = 0,
        connections: Int = 0,
        total: Long = 0,
        stoppedAt: Long? = null,
    ) = SourceProxyObservation(state, reason, port, connections, total, stoppedAt)

    @Test
    fun idleWithAPendingStartShowsStarting() {
        val state = ProxyStatusMapping.state(
            observation(SourceProxyState.IDLE),
            startPending = true,
        )

        assertEquals(RealProxyPhase.STARTING, state.phase)
        assertEquals(RealStopReason.NONE, state.stopReason)
    }

    @Test
    fun idleWithoutAPendingStartShowsOff() {
        val state = ProxyStatusMapping.state(
            observation(SourceProxyState.IDLE),
            startPending = false,
        )

        assertEquals(RealProxyPhase.OFF, state.phase)
    }

    @Test
    fun waitingForNetworkShowsWaitingForCellular() {
        val state = ProxyStatusMapping.state(
            observation(SourceProxyState.WAITING_FOR_NETWORK),
            startPending = true,
        )

        assertEquals(RealProxyPhase.WAITING_FOR_CELLULAR, state.phase)
    }

    @Test
    fun runningCarriesTheCountsAndPort() {
        val state = ProxyStatusMapping.state(
            observation(
                state = SourceProxyState.RUNNING,
                port = 41234,
                connections = 3,
                total = 8,
            ),
            startPending = true,
        )

        assertEquals(RealProxyPhase.RUNNING, state.phase)
        assertEquals(41234, state.port)
        assertEquals(3, state.connections)
        assertEquals(8L, state.totalConnections)
    }

    @Test
    fun missingHotspotMapsToWaitingForTheHotspot() {
        val state = ProxyStatusMapping.state(
            observation(
                state = SourceProxyState.STOPPED,
                reason = SourceProxyStopReason.HOTSPOT_NOT_FOUND,
                stoppedAt = 123,
            ),
            startPending = true,
        )

        assertEquals(RealProxyPhase.WAITING_FOR_HOTSPOT, state.phase)
        assertEquals(RealStopReason.HOTSPOT_NOT_FOUND, state.stopReason)
        assertEquals(123L, state.stoppedAtMillis)
    }

    @Test
    fun everyStopReasonHasAPlainValue() {
        val expected = mapOf(
            SourceProxyStopReason.NONE to RealStopReason.NONE,
            SourceProxyStopReason.USER_STOP to RealStopReason.USER,
            SourceProxyStopReason.NETWORK_LOST to RealStopReason.NETWORK_LOST,
            SourceProxyStopReason.CAPABILITIES_LOST to RealStopReason.CAPABILITIES_LOST,
            SourceProxyStopReason.NETWORK_UNAVAILABLE to RealStopReason.NETWORK_UNAVAILABLE,
            SourceProxyStopReason.HOTSPOT_NOT_FOUND to RealStopReason.HOTSPOT_NOT_FOUND,
            SourceProxyStopReason.HOTSPOT_LOST to RealStopReason.HOTSPOT_LOST,
            SourceProxyStopReason.BIND_FAILED to RealStopReason.BIND_FAILED,
            SourceProxyStopReason.START_FAILED to RealStopReason.START_FAILED,
            SourceProxyStopReason.LISTENER_FAILED to RealStopReason.LISTENER_FAILED,
            SourceProxyStopReason.TOKEN_MISSING to RealStopReason.TOKEN_MISSING,
            SourceProxyStopReason.TOKEN_UNREADABLE to RealStopReason.TOKEN_UNREADABLE,
        )

        assertEquals(expected, SourceProxyStopReason.entries.associateWith(ProxyStatusMapping::reason))
    }

    @Test
    fun tokenMissingStopsWithPairFirst() {
        val state = ProxyStatusMapping.state(
            observation(
                state = SourceProxyState.STOPPED,
                reason = SourceProxyStopReason.TOKEN_MISSING,
            ),
            startPending = true,
        )

        assertEquals(RealProxyPhase.STOPPED, state.phase)
        assertEquals(RealStopReason.TOKEN_MISSING, state.stopReason)
        assertEquals("Pair first", state.statusTitle)
    }

    @Test
    fun tokenUnreadableDoesNotAskForANewPairing() {
        val state = ProxyStatusMapping.state(
            observation(
                state = SourceProxyState.STOPPED,
                reason = SourceProxyStopReason.TOKEN_UNREADABLE,
            ),
            startPending = true,
        )

        assertEquals(RealProxyPhase.STOPPED, state.phase)
        assertEquals(RealStopReason.TOKEN_UNREADABLE, state.stopReason)
        assertEquals("Needs attention", state.statusTitle)
        assertTrue(state.statusMessage.contains("could not be read"))
        assertTrue(
            "The message must say the app does not replace the token on its own.",
            state.statusMessage.contains("never replaces the token on its own"),
        )
        assertTrue(state.statusMessage.contains("rotate the source token"))
        assertFalse(state.statusMessage.contains("Pair first"))
    }
}
