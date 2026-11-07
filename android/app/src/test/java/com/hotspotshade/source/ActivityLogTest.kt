package com.hotspotshade.source

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ActivityLogTest {
    @Test
    fun theLogKeepsTheNewestFiftyEntriesNewestFirst() {
        var now = 0L
        val log = ActivityLog(clock = { ++now })
        repeat(ActivityLog.CAPACITY + 10) { index ->
            log.record(if (index % 2 == 0) ActivityEvent.PROXY_STARTED else ActivityEvent.STOP_USER)
        }

        val entries = log.entries()

        assertEquals(50, ActivityLog.CAPACITY)
        assertEquals(ActivityLog.CAPACITY, entries.size)
        assertEquals("Newest first.", 60L, entries.first().timeMillis)
        assertEquals("The oldest ten were dropped.", 11L, entries.last().timeMillis)
    }

    @Test
    fun theRevisionMovesWithEveryChange() {
        val log = ActivityLog(capacity = 2, clock = { 1L })
        val start = log.revision()
        log.record(ActivityEvent.PROXY_STARTED)
        assertNotEquals(start, log.revision())
        val afterRecord = log.revision()
        log.clear()
        assertNotEquals(afterRecord, log.revision())
        assertTrue(log.entries().isEmpty())
    }

    @Test
    fun everyFixedSentenceIsPlainAndHoldsNoNumberAddressOrSecret() {
        for (event in ActivityEvent.entries) {
            val text = event.message
            assertTrue("$event must end like a sentence.", text.endsWith("."))
            assertFalse("$event must hold no digit.", text.any { it.isDigit() })
            assertFalse("$event must hold no address punctuation.", text.any { it in ":/@=" })
            assertFalse("$event must not name a token value.", text.lowercase().contains("0x"))
        }
        assertEquals(ActivityEvent.entries.size, ActivityEvent.entries.map { it.message }.toSet().size)
    }

    @Test
    fun iosWordingIsKeptWhereBothAppsHaveTheEvent() {
        assertEquals("Proxy started.", ActivityEvent.PROXY_STARTED.message)
        assertEquals("You stopped the proxy.", ActivityEvent.STOP_USER.message)
        assertEquals("A target device was added.", ActivityEvent.TARGET_ADDED.message)
        assertEquals("A target device was removed.", ActivityEvent.TARGET_REMOVED.message)
        assertEquals("Paired target devices forgotten.", ActivityEvent.TARGETS_FORGOTTEN.message)
    }

    @Test
    fun everyStopReasonHasItsOwnLine() {
        val lines = SourceProxyStopReason.entries
            .filter { it != SourceProxyStopReason.NONE }
            .map { ActivityEvent.forStop(it) }
        assertEquals(lines.size, lines.toSet().size)
        assertEquals(ActivityEvent.STOP_OTHER, ActivityEvent.forStop(SourceProxyStopReason.NONE))
    }

    @Test
    fun oneStartLogsOnceAndANetworkFlapLogsItsOwnLines() {
        val tracker = ProxyActivityTracker()
        val none = SourceProxyStopReason.NONE

        assertEquals(
            ActivityEvent.WAITING_FOR_CELLULAR,
            tracker.onReport(SourceProxyState.WAITING_FOR_NETWORK, none),
        )
        assertEquals(null, tracker.onReport(SourceProxyState.WAITING_FOR_NETWORK, none))
        assertEquals(ActivityEvent.PROXY_STARTED, tracker.onReport(SourceProxyState.RUNNING, none))
        assertEquals(null, tracker.onReport(SourceProxyState.RUNNING, none))
        assertEquals(
            ActivityEvent.WAITING_FOR_CELLULAR,
            tracker.onReport(SourceProxyState.WAITING_FOR_NETWORK, none),
        )
        assertEquals(ActivityEvent.CELLULAR_BACK, tracker.onReport(SourceProxyState.RUNNING, none))
        assertEquals(
            ActivityEvent.STOP_HOTSPOT_LOST,
            tracker.onReport(SourceProxyState.STOPPED, SourceProxyStopReason.HOTSPOT_LOST),
        )
        assertEquals(
            null,
            tracker.onReport(SourceProxyState.STOPPED, SourceProxyStopReason.HOTSPOT_LOST),
        )
        // A new run starts clean and logs its start again.
        assertEquals(ActivityEvent.PROXY_STARTED, tracker.onReport(SourceProxyState.RUNNING, none))
    }

    @Test
    fun aResetMakesASecondFailedStartLogItsReasonAgain() {
        val tracker = ProxyActivityTracker()
        val stopped = SourceProxyState.STOPPED
        val reason = SourceProxyStopReason.HOTSPOT_NOT_FOUND
        assertEquals(ActivityEvent.STOP_HOTSPOT_NOT_FOUND, tracker.onReport(stopped, reason))
        assertEquals(null, tracker.onReport(stopped, reason))
        tracker.reset()
        assertEquals(ActivityEvent.STOP_HOTSPOT_NOT_FOUND, tracker.onReport(stopped, reason))
    }

    @Test
    fun usageIsLoggedWhenTheFirstConnectionOpensAndWhenItStaysIdleForAMinute() {
        val tracker = ConnectionActivityTracker(idleMillis = 60_000L)

        assertEquals(null, tracker.onCount(true, 0, 0L))
        assertEquals(ActivityEvent.TARGET_USING, tracker.onCount(true, 1, 1_000L))
        assertEquals("More connections add no line.", null, tracker.onCount(true, 5, 2_000L))
        assertEquals("A short gap is not idle.", null, tracker.onCount(true, 0, 3_000L))
        assertEquals(null, tracker.onCount(true, 0, 40_000L))
        assertEquals("A returning connection clears the gap.", null, tracker.onCount(true, 1, 41_000L))
        assertEquals(null, tracker.onCount(true, 0, 42_000L))
        assertEquals(null, tracker.onCount(true, 0, 101_000L))
        assertEquals(ActivityEvent.TARGET_IDLE, tracker.onCount(true, 0, 102_000L))
        assertEquals("Idle logs once.", null, tracker.onCount(true, 0, 200_000L))
        assertEquals(ActivityEvent.TARGET_USING, tracker.onCount(true, 2, 201_000L))
    }

    @Test
    fun aStoppedProxyResetsUsageWithoutALine() {
        val tracker = ConnectionActivityTracker(idleMillis = 10L)
        assertEquals(ActivityEvent.TARGET_USING, tracker.onCount(true, 1, 0L))
        assertEquals(null, tracker.onCount(false, 0, 5L))
        assertEquals(null, tracker.onCount(true, 0, 100L))
        assertEquals(ActivityEvent.TARGET_USING, tracker.onCount(true, 1, 200L))
    }

    @Test
    fun theRuntimeReportsLogProxyStartAndStopAndNoPortOrAddress() {
        ActivityLog.shared.clear()
        SourceProxyRuntime.resetObservation()
        try {
            SourceProxyRuntime.record(
                SourceProxySnapshot(SourceProxyState.RUNNING, SourceProxyStopReason.NONE, 40123),
                java.net.InetAddress.getByName("192.168.43.1"),
            )
            SourceProxyRuntime.record(
                SourceProxySnapshot(SourceProxyState.STOPPED, SourceProxyStopReason.USER_STOP, 0),
            )

            val messages = ActivityLog.shared.entries().map { it.message }

            assertEquals(listOf("You stopped the proxy.", "Proxy started."), messages)
            assertTrue(messages.none { it.contains("40123") || it.contains("192.168") })
        } finally {
            SourceProxyRuntime.resetObservation()
            ActivityLog.shared.clear()
        }
    }

    @Test
    fun theRuntimeLogsUsageFromTheControllerCountWhileTheProxyRuns() {
        // The count comes from a live controller, which a JVM test does not
        // attach. A stopped report must reset usage and add no usage line.
        ActivityLog.shared.clear()
        SourceProxyRuntime.resetObservation()
        try {
            SourceProxyRuntime.record(
                SourceProxySnapshot(SourceProxyState.RUNNING, SourceProxyStopReason.NONE, 40123),
            )
            SourceProxyRuntime.observation()
            assertEquals(
                listOf(ActivityEvent.PROXY_STARTED),
                ActivityLog.shared.entries().map { it.event },
            )
        } finally {
            SourceProxyRuntime.resetObservation()
            ActivityLog.shared.clear()
        }
    }

}
