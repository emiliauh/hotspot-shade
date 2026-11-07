package com.hotspotshade.source

import java.util.concurrent.CountDownLatch
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests for the generation gate on the real pairing UI callbacks.
 *
 * A callback that was posted before a stop or a restart must not publish a
 * prompt or a listener state after the next generation starts.
 */
class PairingUiGateTest {
    @Test
    fun aCallbackFromAStoppedListenerIsStale() {
        val gate = PairingUiGate()
        val first = gate.begin()
        assertTrue(gate.isCurrent(first))

        gate.invalidate()

        assertFalse("A late prompt from the old listener must be dropped.", gate.isCurrent(first))
    }

    @Test
    fun aRestartKeepsOnlyTheNewGenerationCurrent() {
        val gate = PairingUiGate()
        val first = gate.begin()
        gate.invalidate()
        val second = gate.begin()

        assertTrue(gate.isCurrent(second))
        assertFalse(gate.isCurrent(first))
    }

    @Test
    fun concurrentInvalidationCannotRestoreAnOldGeneration() {
        val gate = PairingUiGate()
        val old = gate.begin()
        val start = CountDownLatch(1)
        val threads = (0 until 8).map {
            Thread({
                start.await()
                gate.invalidate()
            }).also { it.start() }
        }
        start.countDown()
        for (thread in threads) thread.join(10_000)

        assertFalse(gate.isCurrent(old))
        val next = gate.begin()
        assertTrue(gate.isCurrent(next))
    }
}

/** Queued callbacks model work that completes after a stop or a new read. */
class PairingDelayedResultTest {
    @Test
    fun delayedStartSuccessAndFailureCannotClearNewStart() {
        for (success in listOf(true, false)) {
            val gate = PairingUiGate()
            val old = gate.begin()
            var starting = true
            var closed = false
            val callback = gate.guarded(old, stale = { closed = success }) { starting = false }
            gate.invalidate()
            gate.begin()
            callback()
            assertTrue(starting)
            assertTrue(!success || closed)
        }
    }

    @Test
    fun delayedSnapshotsAndCancellationDoNotPublish() {
        val listener = PairingUiGate()
        val list = PairingUiGate()
        val generation = listener.begin()
        val listGeneration = list.begin()
        var targets = listOf("original")
        var unavailable = false
        fun result(value: List<String>?) = listener.guarded(generation) {
            if (list.isCurrent(listGeneration)) {
                if (value == null) unavailable = true else targets = value
            }
        }
        val success = result(listOf("stale"))
        val failure = result(null)
        listener.invalidate()
        listener.begin()
        success()
        failure()
        assertTrue(targets == listOf("original"))
        assertFalse(unavailable)
        val current = listener.snapshot()
        val cancelled = listener.guarded(current) {
            if (list.isCurrent(listGeneration)) targets = listOf("cancelled")
        }
        list.invalidate()
        cancelled()
        assertTrue(targets == listOf("original"))
    }

    @Test
    fun sameCountSnapshotStillPublishes() {
        val gate = PairingUiGate()
        val generation = gate.begin()
        var targets = listOf("first")
        val callback = gate.guarded(generation) { targets = listOf("second") }
        callback()
        assertTrue(targets == listOf("second"))
    }
}
