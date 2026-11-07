package com.hotspotshade.source

import android.app.Application
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PairingViewModelQueueTest {
    private class Harness {
        val worker = ArrayDeque<() -> Unit>()
        val main = ArrayDeque<() -> Unit>()
        val delayed = ArrayDeque<() -> Unit>()
        var result: List<TrustedTarget>? = emptyList()
        val model = PairingViewModel(Application(), PairingViewModelTestHooks(
            worker = { worker.addLast(it) },
            main = { main.addLast(it) },
            delayed = { task, delay ->
                assertEquals(30_000L, delay)
                delayed.addLast(task)
            },
            readTargets = { result },
        ))
        fun workers() { while (worker.isNotEmpty()) worker.removeFirst()() }
        fun mains() { while (main.isNotEmpty()) main.removeFirst()() }
    }

    @Test
    fun reopenWaitsForNewSnapshotAndDropsStaleSuccessAndFailure() {
        for (stale in listOf(listOf(TrustedTarget("old", "Old")), null)) {
            val h = Harness()
            h.model.setVisible(true)
            h.model.setTrustListVisible(true)
            h.result = stale
            h.workers()
            h.model.setTrustListVisible(false)
            h.model.setTrustListVisible(true)
            assertNull(h.model.trustUnavailable)
            assertTrue(h.model.targets.isEmpty())
            h.mains()
            assertNull(h.model.trustUnavailable)
            h.result = listOf(TrustedTarget("new", "New"))
            h.workers()
            h.mains()
            assertEquals(false, h.model.trustUnavailable)
            assertEquals("new", h.model.targets.single().id)
        }
    }

    @Test
    fun pollingStopsWhenHiddenAndPublishesChangedSnapshotWhenVisible() {
        val h = Harness()
        h.model.setVisible(true)
        h.model.setTrustListVisible(true)
        h.result = listOf(TrustedTarget("one", "One"))
        h.workers()
        h.mains()
        h.result = listOf(TrustedTarget("two", "Two"))
        h.delayed.removeFirst()()
        h.workers()
        h.mains()
        assertEquals("two", h.model.targets.single().id)
        h.model.setVisible(false)
        assertNull(h.model.trustUnavailable)
        assertTrue(h.model.targets.isEmpty())
        h.delayed.removeFirst()()
        h.workers()
        h.mains()
        assertTrue(h.delayed.isEmpty())
        assertNull(h.model.trustUnavailable)
    }

    @Test
    fun pendingDisablesForgetAndCurrentFailureAllowsReset() {
        val h = Harness()
        h.model.setVisible(true)
        h.model.setTrustListVisible(true)
        val queued = h.worker.size
        h.model.forgetTarget("old")
        h.model.forgetAllTargets()
        assertEquals(queued, h.worker.size)
        h.result = null
        h.workers()
        h.mains()
        assertEquals(true, h.model.trustUnavailable)
        h.model.forgetAllTargets()
        assertEquals(1, h.worker.size)
    }
}
