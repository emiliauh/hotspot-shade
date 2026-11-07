package com.hotspotshade.source

import java.io.IOException
import java.util.concurrent.CopyOnWriteArrayList
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests for the service run coordinator.
 *
 * These are JVM tests. The manual queue decides when every start, stop, and
 * close runs, so the tests are deterministic. They start no Android service,
 * bind no listener, and touch no device or network. They prove that the
 * caller returns before the blocking work and that each run reports one
 * terminal state.
 */
class SourceProxyServiceCoordinatorTest {
    private class Report(
        val snapshot: SourceProxySnapshot,
        val generation: Long,
    )

    private class FakeRun(
        private val listener: SourceProxyListener,
        private val startResult: Boolean = true,
        private val throwOnStart: Boolean = false,
    ) : SourceProxyServiceRun {
        var active = false
        var starts = 0
        var stops = 0

        @Volatile
        var closeFailureValue: IOException? = null

        override val isActive: Boolean get() = active

        override val closeFailure: IOException? get() = closeFailureValue

        override fun snapshot(): SourceProxySnapshot = SourceProxySnapshot(
            if (active) SourceProxyState.RUNNING else SourceProxyState.STOPPED,
            SourceProxyStopReason.NONE,
            if (active) PORT else 0,
        )

        override fun start(): Boolean {
            starts += 1
            if (throwOnStart) throw IOException("The run cannot start.")
            active = startResult
            if (!startResult) {
                listener.onStateChanged(
                    SourceProxySnapshot(
                        SourceProxyState.STOPPED,
                        SourceProxyStopReason.TOKEN_MISSING,
                        0,
                    ),
                )
            }
            return startResult
        }

        override fun stop() {
            stops += 1
            active = false
            listener.onStateChanged(
                SourceProxySnapshot(
                    SourceProxyState.STOPPED,
                    SourceProxyStopReason.USER_STOP,
                    0,
                ),
            )
        }

        fun report(snapshot: SourceProxySnapshot) {
            listener.onStateChanged(snapshot)
        }
    }    private class Harness(
        private val startResult: Boolean = true,
        private val throwOnStart: Boolean = false,
        private val failFactory: Boolean = false,
    ) {
        val queue = ManualSourceProxyTaskQueue()
        val runs = CopyOnWriteArrayList<FakeRun>()
        val states = CopyOnWriteArrayList<Report>()
        val terminals = CopyOnWriteArrayList<Report>()
        val coordinator = SourceProxyServiceCoordinator(
            queue = queue,
            runFactory = { listener ->
                if (failFactory) throw IllegalStateException("The run cannot be built.")
                FakeRun(listener, startResult, throwOnStart).also { runs += it }
            },
            onState = { snapshot, generation -> states += Report(snapshot, generation) },
            onTerminal = { snapshot, generation -> terminals += Report(snapshot, generation) },
        )

        fun start(): SourceProxyServiceStart = coordinator.start()

        fun queuedStart(): SourceProxyServiceStart.Queued =
            start() as SourceProxyServiceStart.Queued
    }

    @Test
    fun aStartQueuesWorkWithoutRunningItOnTheCaller() {
        val harness = Harness()

        val result = harness.queuedStart()

        assertEquals("The call returns at once.", 0, harness.runs.size)
        assertTrue(harness.states.isEmpty())
        assertTrue(harness.terminals.isEmpty())
        assertEquals(1L, result.generation)

        harness.queue.runAll()

        assertEquals(1, harness.runs.size)
        assertEquals(1, harness.runs.single().starts)
    }

    @Test
    fun aRepeatedStartWhileQueuedDoesNotCreateASecondRun() {
        val harness = Harness()
        val first = harness.queuedStart()

        val second = harness.start()

        assertTrue(second is SourceProxyServiceStart.Starting)
        assertEquals(
            "A repeated start keeps the pending generation.",
            first.generation,
            (second as SourceProxyServiceStart.Starting).generation,
        )

        harness.queue.runAll()

        assertEquals(1, harness.runs.size)
        assertEquals(1, harness.runs.single().starts)
    }

    @Test
    fun anActiveRunReturnsItsSnapshotWithoutNewWork() {
        val harness = Harness()
        harness.queuedStart()
        harness.queue.runAll()
        val run = harness.runs.single()
        run.active = true

        val result = harness.start()

        assertTrue(result is SourceProxyServiceStart.Active)
        val active = result as SourceProxyServiceStart.Active
        assertEquals(SourceProxyState.RUNNING, active.snapshot.state)
        assertEquals(PORT, active.snapshot.port)
        assertFalse("An active start must queue no work.", harness.queue.runNext())
        assertEquals(1, harness.runs.size)
    }

    @Test
    fun aStopBeforeTheQueuedStartRunsCreatesNoRun() {
        val harness = Harness()
        harness.queuedStart()

        assertEquals(SourceProxyServiceStop.QUEUED, harness.coordinator.stop())
        assertEquals("Stop must not create the run on the caller.", 0, harness.runs.size)

        harness.queue.runAll()

        assertTrue("A cancelled start must create no run.", harness.runs.isEmpty())
        assertEquals(1, harness.terminals.size)
        assertEquals(SourceProxyStopReason.USER_STOP, harness.terminals.single().snapshot.reason)
        assertFalse(harness.coordinator.hasPendingRun())
    }

    @Test
    fun aStopRunsTheCloseOnTheQueueNotTheCaller() {
        val harness = Harness()
        harness.queuedStart()
        harness.queue.runAll()
        val run = harness.runs.single()
        run.active = true

        assertEquals(SourceProxyServiceStop.QUEUED, harness.coordinator.stop())

        assertEquals("Stop must not close on the caller.", 0, run.stops)
        assertTrue(harness.terminals.isEmpty())

        harness.queue.runAll()

        assertEquals(1, run.stops)
        assertEquals(1, harness.terminals.size)
        assertEquals(SourceProxyStopReason.USER_STOP, harness.terminals.single().snapshot.reason)
    }

    @Test
    fun aRepeatedStopClosesAndReportsOneTime() {
        val harness = Harness()
        harness.queuedStart()
        harness.queue.runAll()
        val run = harness.runs.single()
        run.active = true

        harness.coordinator.stop()
        harness.coordinator.stop()
        harness.queue.runAll()

        assertEquals(1, run.stops)
        assertEquals(1, harness.terminals.size)
    }

    @Test
    fun stopWithNoRunAndNoStartIsIdle() {
        val harness = Harness()

        assertEquals(SourceProxyServiceStop.IDLE, harness.coordinator.stop())
        assertFalse(harness.coordinator.hasPendingRun())
        assertFalse(harness.queue.runNext())
    }

    @Test
    fun aDestroyStopsTheRunOnTheQueueAndReportsNothing() {
        val harness = Harness()
        harness.queuedStart()
        harness.queue.runAll()
        val run = harness.runs.single()
        run.active = true

        harness.coordinator.destroy()

        assertEquals("Destroy must not close on the caller.", 0, run.stops)
        assertTrue(harness.terminals.isEmpty())

        harness.queue.runAll()

        assertEquals(1, run.stops)
        assertTrue(
            "A destroyed service must not publish another state.",
            harness.terminals.isEmpty(),
        )
        assertTrue(harness.queue.shutdown)
        assertFalse(harness.coordinator.hasPendingRun())
    }

    @Test
    fun aDestroyBeforeTheQueuedStartRunsCreatesNoRun() {
        val harness = Harness()
        harness.queuedStart()

        harness.coordinator.destroy()
        harness.queue.runAll()

        assertTrue(harness.runs.isEmpty())
        assertTrue(harness.terminals.isEmpty())
        assertTrue(harness.queue.shutdown)
    }

    @Test
    fun aDestroyIsIdempotent() {
        val harness = Harness()
        harness.queuedStart()
        harness.queue.runAll()
        val run = harness.runs.single()
        run.active = true

        harness.coordinator.destroy()
        harness.coordinator.destroy()
        harness.queue.runAll()

        assertEquals(1, run.stops)
        assertTrue(harness.queue.shutdown)
    }

    @Test
    fun aFactoryFailureReportsOneStartFailed() {
        val harness = Harness(failFactory = true)

        harness.queuedStart()
        harness.queue.runAll()

        assertTrue(harness.runs.isEmpty())
        assertEquals(1, harness.terminals.size)
        assertEquals(
            SourceProxyStopReason.START_FAILED,
            harness.terminals.single().snapshot.reason,
        )
        assertFalse(harness.coordinator.hasPendingRun())
    }

    @Test
    fun aStartExceptionStopsTheRunAndReportsStartFailed() {
        val harness = Harness(throwOnStart = true)

        harness.queuedStart()
        harness.queue.runAll()

        val run = harness.runs.single()
        assertEquals("The failed run must still close.", 1, run.stops)
        assertEquals(1, harness.terminals.size)
        assertEquals(
            "A failed start must not report the stop reason as the outcome.",
            SourceProxyStopReason.START_FAILED,
            harness.terminals.single().snapshot.reason,
        )
    }

    @Test
    fun aRefusedStartKeepsItsOwnTerminalReason() {
        val harness = Harness(startResult = false)

        harness.queuedStart()
        harness.queue.runAll()

        assertEquals(1, harness.terminals.size)
        assertEquals(
            SourceProxyStopReason.TOKEN_MISSING,
            harness.terminals.single().snapshot.reason,
        )
        assertFalse(harness.coordinator.hasPendingRun())
    }

    @Test
    fun aStartAfterTheQueueClosesIsRefused() {
        val harness = Harness()
        harness.queuedStart()
        harness.queue.runAll()
        // A second run must not start over the reported terminal state.
        harness.coordinator.stop()
        harness.queue.runAll()
        harness.queue.shutdown()

        val result = harness.start()

        assertEquals(SourceProxyServiceStart.Refused, result)
        assertFalse(harness.coordinator.hasPendingRun())
    }

    @Test
    fun aReportFromAnOldRunIsIgnoredAfterANewStart() {
        val harness = Harness()
        harness.queuedStart()
        harness.queue.runAll()
        val old = harness.runs.single()
        old.active = true
        harness.coordinator.stop()
        harness.queue.runAll()
        assertEquals(1, harness.terminals.size)

        harness.queuedStart()
        harness.queue.runAll()
        assertEquals(2, harness.runs.size)

        old.report(
            SourceProxySnapshot(
                SourceProxyState.STOPPED,
                SourceProxyStopReason.NETWORK_LOST,
                0,
            ),
        )

        assertEquals(
            "A late report from the closed run must not reach the service.",
            1,
            harness.terminals.size,
        )
        assertTrue(harness.queue.runNext().not())
    }

    @Test
    fun aDelayedTerminalDoesNotCancelANewerQueuedStart() {
        val harness = Harness()
        harness.queuedStart()
        harness.queue.runAll()
        val old = harness.runs.single()
        old.active = true
        // The controller has moved to STOPPED but its terminal report has not
        // reached the coordinator yet.
        old.active = false

        val result = harness.queuedStart()
        assertEquals(2L, result.generation)

        old.report(
            SourceProxySnapshot(
                SourceProxyState.STOPPED,
                SourceProxyStopReason.NETWORK_LOST,
                0,
            ),
        )

        harness.queue.runAll()

        assertEquals("The new start must still build its run.", 2, harness.runs.size)
        assertEquals(1, harness.runs[1].starts)
        assertEquals(
            "The old terminal must not turn the new start into a user stop.",
            1,
            harness.terminals.size,
        )
        assertEquals(SourceProxyStopReason.NETWORK_LOST, harness.terminals.single().snapshot.reason)
        assertTrue(harness.coordinator.hasPendingRun())
    }

    @Test
    fun anIncompleteCloseIsRetriedOnTheQueue() {
        val harness = Harness()
        harness.queuedStart()
        harness.queue.runAll()
        val run = harness.runs.single()
        run.active = true
        run.closeFailureValue = IOException("The session did not close.")

        run.report(
            SourceProxySnapshot(
                SourceProxyState.STOPPED,
                SourceProxyStopReason.NETWORK_LOST,
                0,
            ),
        )

        assertEquals(1, harness.terminals.size)
        assertEquals(SourceProxyStopReason.NETWORK_LOST, harness.terminals.single().snapshot.reason)
        assertEquals("The retry must wait for the queue.", 0, run.stops)

        harness.queue.runAll()

        assertEquals(1, run.stops)
    }

    @Test
    fun hasPendingRunFollowsTheStartAndTheTerminalState() {
        val harness = Harness()
        assertFalse(harness.coordinator.hasPendingRun())

        harness.queuedStart()
        assertTrue(harness.coordinator.hasPendingRun())

        harness.queue.runAll()
        assertTrue(harness.coordinator.hasPendingRun())

        harness.coordinator.stop()
        assertTrue(harness.coordinator.hasPendingRun())

        harness.queue.runAll()
        assertFalse(harness.coordinator.hasPendingRun())
    }

    @Test
    fun aStartAfterAStopReArmsAQueuedStart() {
        val harness = Harness()
        harness.queuedStart()
        harness.coordinator.stop()

        val result = harness.start()

        assertTrue(result is SourceProxyServiceStart.Starting)
        harness.queue.runAll()

        assertEquals(1, harness.runs.size)
        assertEquals(1, harness.runs.single().starts)
        assertTrue(harness.terminals.isEmpty())
    }

    private companion object {
        const val PORT = 40123
    }
}
