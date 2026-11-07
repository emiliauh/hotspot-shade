package com.hotspotshade.source

import java.net.InetAddress
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Tests for the source proxy service lifecycle decisions.
 *
 * These are JVM tests. They start no service, bind no listener, and touch no
 * device. They cover the report that the service records when Android destroys
 * it: a live run must not stay RUNNING in the process report.
 */
class SourceProxyServiceLifecycleTest {
    @Before
    fun setUp() {
        SourceProxyRuntime.resetObservation()
    }

    @After
    fun tearDown() {
        SourceProxyRuntime.attach(null)
        SourceProxyRuntime.resetObservation()
    }

    @Test
    fun aDestroyedRunningServiceRecordsStopped() {
        val report = SourceProxyServiceLifecycle.destroyedReport(
            SourceProxySnapshot(SourceProxyState.RUNNING, SourceProxyStopReason.NONE, 40123),
        )

        assertEquals(SourceProxyState.STOPPED, report.state)
        assertEquals(
            "A run that had not ended is a user stop from the app.",
            SourceProxyStopReason.USER_STOP,
            report.reason,
        )
        assertEquals("A closed listener has no port.", 0, report.port)
    }

    @Test
    fun aDestroyedWaitingServiceRecordsStopped() {
        val report = SourceProxyServiceLifecycle.destroyedReport(
            SourceProxySnapshot(
                SourceProxyState.WAITING_FOR_NETWORK,
                SourceProxyStopReason.NONE,
                0,
            ),
        )

        assertEquals(SourceProxyState.STOPPED, report.state)
        assertEquals(SourceProxyStopReason.USER_STOP, report.reason)
    }

    @Test
    fun aDestroyedServiceKeepsARealStopReason() {
        val report = SourceProxyServiceLifecycle.destroyedReport(
            SourceProxySnapshot(SourceProxyState.STOPPED, SourceProxyStopReason.HOTSPOT_LOST, 0),
        )

        assertEquals(SourceProxyState.STOPPED, report.state)
        assertEquals(
            "A completed stop keeps its own reason.",
            SourceProxyStopReason.HOTSPOT_LOST,
            report.reason,
        )
    }

    @Test
    fun aMissingSnapshotBecomesAUserStop() {
        val report = SourceProxyServiceLifecycle.destroyedReport(null)

        assertEquals(SourceProxyState.STOPPED, report.state)
        assertEquals(SourceProxyStopReason.USER_STOP, report.reason)
        assertEquals(0, report.port)
    }

    @Test
    fun aDestroyedRunStopsSnapshotsRecordsThenDetaches() {
        val trace = mutableListOf<String>()
        var recorded: SourceProxySnapshot? = null

        SourceProxyServiceLifecycle.finishDestroyedRun(
            stop = { trace += "stop" },
            snapshot = {
                trace += "snapshot"
                SourceProxySnapshot(SourceProxyState.RUNNING, SourceProxyStopReason.NONE, 40123)
            },
            record = {
                trace += "record"
                recorded = it
            },
            detach = { trace += "detach" },
        )

        assertEquals(listOf("stop", "snapshot", "record", "detach"), trace)
        assertEquals(SourceProxyState.STOPPED, recorded?.state)
        assertEquals(SourceProxyStopReason.USER_STOP, recorded?.reason)
        assertEquals(0, recorded?.port)
    }

    @Test
    fun aThrowingStopStillRecordsTheTerminalReportAndDetaches() {
        var recorded: SourceProxySnapshot? = null
        var detached = false

        SourceProxyServiceLifecycle.finishDestroyedRun(
            stop = { throw IllegalStateException("The cleanup failed.") },
            snapshot = {
                SourceProxySnapshot(SourceProxyState.RUNNING, SourceProxyStopReason.NONE, 40123)
            },
            record = { recorded = it },
            detach = { detached = true },
        )

        assertEquals(SourceProxyState.STOPPED, recorded?.state)
        assertEquals(SourceProxyStopReason.USER_STOP, recorded?.reason)
        assertTrue("A failed stop must still detach.", detached)
    }

    @Test
    fun aThrowingSnapshotRecordsAUserStopAndDetaches() {
        var recorded: SourceProxySnapshot? = null
        var detached = false

        SourceProxyServiceLifecycle.finishDestroyedRun(
            stop = { },
            snapshot = { throw IllegalStateException("The controller is gone.") },
            record = { recorded = it },
            detach = { detached = true },
        )

        assertEquals(SourceProxyState.STOPPED, recorded?.state)
        assertEquals(SourceProxyStopReason.USER_STOP, recorded?.reason)
        assertTrue("A failed snapshot must still detach.", detached)
    }

    @Test
    fun aThrowingRecordStillDetaches() {
        var detached = false

        SourceProxyServiceLifecycle.finishDestroyedRun(
            stop = { },
            snapshot = { SourceProxySnapshot(SourceProxyState.STOPPED, SourceProxyStopReason.NONE, 0) },
            record = { throw IllegalStateException("The report failed.") },
            detach = { detached = true },
        )

        assertTrue("A failed report must still detach.", detached)
    }

    @Test
    fun aStaleRunningReportDoesNotStayActiveAfterDestroy() {
        val address: InetAddress = InetAddress.getByName("192.168.43.1")
        SourceProxyRuntime.record(
            SourceProxySnapshot(SourceProxyState.RUNNING, SourceProxyStopReason.NONE, 40123),
            boundAddress = address,
        )
        val live = SourceProxyRuntime.binding()
        assertEquals(SourceProxyState.RUNNING, live.state)
        assertEquals(address, live.address)

        // The service stops its controller and detaches it. Its listener post
        // is dropped, so the service records the terminal report itself. It
        // records before the detach so a reader never falls back to the old
        // RUNNING report in the window between the two calls.
        SourceProxyRuntime.record(
            SourceProxyServiceLifecycle.destroyedReport(
                SourceProxySnapshot(SourceProxyState.RUNNING, SourceProxyStopReason.NONE, 40123),
            ),
        )
        SourceProxyRuntime.attach(null)

        val stopped = SourceProxyRuntime.binding()
        assertEquals(SourceProxyState.STOPPED, stopped.state)
        assertFalse("A destroyed service must not report a live run.", stopped.active)
        assertEquals(0, stopped.port)
        assertNull("A stopped run has no bound address.", stopped.address)
        assertEquals(SourceProxyState.STOPPED, SourceProxyRuntime.lastState)
        assertEquals(SourceProxyStopReason.USER_STOP, SourceProxyRuntime.lastStopReason)
        assertTrue(
            "A terminal report records a stop time.",
            SourceProxyRuntime.observation().stoppedAtMillis != null,
        )
    }

    @Test
    fun backgroundStatusIsOnSoTheTargetKeepsItsStatusAnswer() {
        // The visible listener stops with the activity. Without the host the
        // target stops the tunnel after 90 seconds of silence. The status-only
        // policy and its fences have their own host and loopback tests.
        assertTrue(
            "The background status host is the only answer on port 18090 while " +
                "the activity is hidden.",
            SourceProxyServiceLifecycle.BACKGROUND_STATUS_ENABLED,
        )
    }

    @Test
    fun onlyARunningSnapshotShowsTheRunningNotification() {
        assertTrue(
            SourceProxyServiceLifecycle.showsRunning(
                SourceProxySnapshot(SourceProxyState.RUNNING, SourceProxyStopReason.NONE, 40123),
            ),
        )
        assertFalse(
            SourceProxyServiceLifecycle.showsRunning(
                SourceProxySnapshot(
                    SourceProxyState.WAITING_FOR_NETWORK,
                    SourceProxyStopReason.NONE,
                    0,
                ),
            ),
        )
        assertFalse(
            SourceProxyServiceLifecycle.showsRunning(
                SourceProxySnapshot(SourceProxyState.STOPPED, SourceProxyStopReason.USER_STOP, 0),
            ),
        )
    }
}
