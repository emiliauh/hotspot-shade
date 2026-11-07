package com.hotspotshade.source

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SourceSocksCapacityTest {
    private fun session(
        id: Long,
        phase: SourceSocksCapacity.Phase,
        phaseMillis: Long = 0,
        idleMillis: Long = 0,
        protected: Boolean = false,
    ) = SourceSocksCapacity.PhaseSession(
        id = id,
        phase = phase,
        phaseMillis = phaseMillis,
        idleMillis = idleMillis,
        protectedFromCapacity = protected,
    )

    @Test
    fun phaseBoundsMatchTheSourceDeviceContract() {
        assertEquals(30_000L, SourceSocksCapacity.HANDSHAKE_MILLIS)
        assertEquals(8_000L, SourceSocksCapacity.CONNECT_MILLIS)
        assertEquals(2_000L, SourceSocksCapacity.RELAY_GRANT_MILLIS)
        assertEquals(300_000L, SourceSocksCapacity.RELAY_IDLE_MILLIS)
        assertEquals(300_000L, SourceSocksCapacity.OPEN_TCP_RECHECK_MILLIS)
        assertEquals(16, SourceSocksCapacity.MAXIMUM_PERSISTENT_ECHO_SESSIONS)
        assertEquals(6, SourceSocksCapacity.Phase.entries.size)
    }

    @Test
    fun setupAndRelayPhasesSplitTheSlots() {
        assertTrue(SourceSocksCapacity.Phase.HANDSHAKE.isSetup)
        assertTrue(SourceSocksCapacity.Phase.CONNECTING.isSetup)
        assertTrue(SourceSocksCapacity.Phase.AWAITING_RELAY.isSetup)
        assertTrue(SourceSocksCapacity.Phase.OPEN_TCP.isRelay)
        assertTrue(SourceSocksCapacity.Phase.UDP.isRelay)
        assertTrue(SourceSocksCapacity.Phase.HALF_CLOSED.isRelay)
    }

    @Test
    fun fileLimitGivesTheSessionCap() {
        assertEquals(288, SourceSocksCapacity.sessionLimit(32_768))
        // (1024 - 32) / 9 = 110.
        assertEquals(110, SourceSocksCapacity.sessionLimit(1_024))
        // A limit at or below the reserve gives no session.
        assertEquals(0, SourceSocksCapacity.sessionLimit(32))
        assertEquals(0, SourceSocksCapacity.sessionLimit(40))
        assertEquals(1, SourceSocksCapacity.sessionLimit(41))
    }

    @Test
    fun limitsKeepTheSetupShareAtALowerTotal() {
        assertEquals(
            SourceSocksCapacity.Limits(total = 288, setupReserve = 32, relay = 256),
            SourceSocksCapacity.limits(288),
        )
        // ceil(110 / 9) = 13.
        assertEquals(
            SourceSocksCapacity.Limits(total = 110, setupReserve = 13, relay = 97),
            SourceSocksCapacity.limits(110),
        )
        assertEquals(
            SourceSocksCapacity.Limits(total = 1, setupReserve = 0, relay = 1),
            SourceSocksCapacity.limits(1),
        )
        assertEquals(
            SourceSocksCapacity.Limits(total = 0, setupReserve = 0, relay = 0),
            SourceSocksCapacity.limits(0),
        )
    }

    @Test
    fun workerLimitAddsOnePumpPerRelayAndTheEvictionOverlap() {
        assertEquals(546, SourceSocksCapacity.workerLimit())
        assertEquals(
            SourceSocksCapacity.MAXIMUM_SESSIONS +
                SourceSocksCapacity.MAXIMUM_RELAYS +
                SourceSocksCapacity.WORKER_EVICTION_OVERLAP,
            SourceSocksCapacity.workerLimit(),
        )
        val limits = SourceSocksCapacity.limitsForFileLimit(1_024)
        assertEquals(209, SourceSocksCapacity.workerLimit(limits.total, limits.relay))
        // A single relay still needs its session worker and one pump worker.
        assertEquals(4, SourceSocksCapacity.workerLimit(sessions = 1, relays = 1))
    }

    @Test
    fun resolverConcurrencyStaysBounded() {
        assertEquals(8, SourceSocksCapacity.MAXIMUM_RESOLVER_THREADS)
        assertEquals(8, SourceSocksCapacity.MAXIMUM_RESOLVER_QUEUE)
        assertEquals(8, SourceSocksCapacity.resolverThreads(288))
        assertEquals(2, SourceSocksCapacity.resolverThreads(2))
        assertEquals(0, SourceSocksCapacity.resolverThreads(0))
        assertEquals(8, SourceSocksCapacity.resolverQueue(288))
        assertEquals(2, SourceSocksCapacity.resolverQueue(2))
        assertEquals(0, SourceSocksCapacity.resolverQueue(0))
        assertEquals(2, SourceSocksCapacity.WORKER_EVICTION_OVERLAP)
    }

    @Test
    fun fileLimitLimitMatchesTheCapacityWarning() {
        val limits = SourceSocksCapacity.limitsForFileLimit(1_024)
        assertEquals(110, limits.total)
        assertEquals(97, limits.relay)
        val warning = SourceSocksCapacity.capacityWarning(limits)
        assertNotNull(warning)
        assertTrue(warning!!.contains("97"))
        assertTrue(warning.contains("224"))
        assertNull(SourceSocksCapacity.capacityWarning(SourceSocksCapacity.limits(288)))
    }

    @Test
    fun aHandshakeClosesAtItsBound() {
        val phase = SourceSocksCapacity.Phase.HANDSHAKE
        assertNull(SourceSocksCapacity.closeReason(session(1, phase, phaseMillis = 29_999)))
        assertEquals(
            SourceSocksCapacity.CloseReason.HANDSHAKE_EXPIRED,
            SourceSocksCapacity.closeReason(session(1, phase, phaseMillis = 30_000)),
        )
    }

    @Test
    fun aConnectClosesAtItsBound() {
        val phase = SourceSocksCapacity.Phase.CONNECTING
        assertNull(SourceSocksCapacity.closeReason(session(1, phase, phaseMillis = 7_999)))
        assertEquals(
            SourceSocksCapacity.CloseReason.CONNECT_EXPIRED,
            SourceSocksCapacity.closeReason(session(1, phase, phaseMillis = 8_000)),
        )
    }

    @Test
    fun aRelayGrantClosesAtItsBound() {
        val phase = SourceSocksCapacity.Phase.AWAITING_RELAY
        assertNull(SourceSocksCapacity.closeReason(session(1, phase, phaseMillis = 1_999)))
        assertEquals(
            SourceSocksCapacity.CloseReason.RELAY_GRANT_EXPIRED,
            SourceSocksCapacity.closeReason(session(1, phase, phaseMillis = 2_000)),
        )
    }

    @Test
    fun aUdpFlowClosesAtTheIdleBound() {
        val phase = SourceSocksCapacity.Phase.UDP
        assertNull(SourceSocksCapacity.closeReason(session(1, phase, idleMillis = 299_999)))
        assertEquals(
            SourceSocksCapacity.CloseReason.UDP_IDLE,
            SourceSocksCapacity.closeReason(session(1, phase, idleMillis = 300_000)),
        )
    }

    @Test
    fun aHalfClosedFlowClosesAtTheIdleBound() {
        val phase = SourceSocksCapacity.Phase.HALF_CLOSED
        assertNull(SourceSocksCapacity.closeReason(session(1, phase, idleMillis = 299_999)))
        assertEquals(
            SourceSocksCapacity.CloseReason.HALF_CLOSED_IDLE,
            SourceSocksCapacity.closeReason(session(1, phase, idleMillis = 300_000)),
        )
    }

    @Test
    fun anOpenTcpRelayNeverClosesForSilence() {
        val phase = SourceSocksCapacity.Phase.OPEN_TCP
        assertNull(SourceSocksCapacity.closeReason(session(1, phase, idleMillis = 10_000_000)))
        assertEquals(
            SourceSocksCapacity.IdleAction.Rearm(SourceSocksCapacity.OPEN_TCP_RECHECK_MILLIS),
            SourceSocksCapacity.idleAction(phase, phaseMillis = 0, idleMillis = 10_000_000),
        )
    }

    @Test
    fun idleActionClosesOnlyAtTheBound() {
        assertEquals(
            SourceSocksCapacity.IdleAction.Rearm(1_000),
            SourceSocksCapacity.idleAction(
                SourceSocksCapacity.Phase.HANDSHAKE,
                phaseMillis = 29_000,
                idleMillis = 0,
            ),
        )
        assertEquals(
            SourceSocksCapacity.IdleAction.Close(SourceSocksCapacity.CloseReason.HANDSHAKE_EXPIRED),
            SourceSocksCapacity.idleAction(
                SourceSocksCapacity.Phase.HANDSHAKE,
                phaseMillis = 30_000,
                idleMillis = 0,
            ),
        )
        assertEquals(
            SourceSocksCapacity.IdleAction.Close(SourceSocksCapacity.CloseReason.UDP_IDLE),
            SourceSocksCapacity.idleAction(
                SourceSocksCapacity.Phase.UDP,
                phaseMillis = 0,
                idleMillis = 300_000,
            ),
        )
    }

    @Test
    fun theMostOverdueStaleSessionWins() {
        val chosen = SourceSocksCapacity.staleSession(
            listOf(
                session(1, SourceSocksCapacity.Phase.HANDSHAKE, phaseMillis = 31_000),
                session(2, SourceSocksCapacity.Phase.UDP, idleMillis = 305_000),
                session(3, SourceSocksCapacity.Phase.HANDSHAKE, phaseMillis = 40_000),
            ),
        )
        assertEquals(3L, chosen?.id)
    }

    @Test
    fun aProtectedSessionIsNotStale() {
        val chosen = SourceSocksCapacity.staleSession(
            listOf(
                session(
                    1,
                    SourceSocksCapacity.Phase.HANDSHAKE,
                    phaseMillis = 90_000,
                    protected = true,
                ),
                session(2, SourceSocksCapacity.Phase.HANDSHAKE, phaseMillis = 31_000),
            ),
        )
        assertEquals(2L, chosen?.id)
    }

    @Test
    fun aRelayRequestOnlySeesRelayPhases() {
        val sessions = listOf(
            session(1, SourceSocksCapacity.Phase.HANDSHAKE, phaseMillis = 90_000),
            session(2, SourceSocksCapacity.Phase.OPEN_TCP, idleMillis = 900_000),
        )
        assertNull(SourceSocksCapacity.staleSession(sessions, relayOnly = true))
        assertEquals(1L, SourceSocksCapacity.staleSession(sessions)?.id)
    }

    @Test
    fun anOpenRelayIsNotSelectedForATie() {
        assertNull(
            SourceSocksCapacity.staleSession(
                listOf(
                    session(1, SourceSocksCapacity.Phase.OPEN_TCP, idleMillis = 999_000),
                    session(2, SourceSocksCapacity.Phase.OPEN_TCP, idleMillis = 999_000),
                ),
            ),
        )
    }

    @Test
    fun theFileLimitParserReadsTheSoftValue() {
        val text = """
            Limit                     Soft Limit           Hard Limit           Units
            Max cpu time              unlimited            unlimited            seconds
            Max open files            1024                 4096                 files
        """.trimIndent()
        assertEquals(1024, SourceSocksCapacity.parseSoftFileLimit(text))
        val unlimited = "Max open files            unlimited            unlimited            files"
        assertEquals(Int.MAX_VALUE, SourceSocksCapacity.parseSoftFileLimit(unlimited))
        assertNull(SourceSocksCapacity.parseSoftFileLimit("Max processes 10 10 processes"))
        assertNull(SourceSocksCapacity.parseSoftFileLimit("Max open files many many files"))
    }
}
