package com.hotspotshade.source.pairing

import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ThreadFactory
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Deterministic tests for the shared bounded host-callback dispatcher.
 *
 * Every test releases a deliberately blocked callback before it finishes. No
 * test needs a device, socket, route, or external network.
 */
class PairingCallbackDispatcherTest {
    @Test
    fun blockedCallbacksDoNotCreateThreadsForReplacementOwners() {
        val counter = ThreadCounter()
        val dispatcher = PairingCallbackDispatcher(
            workerCount = 2,
            maxOwners = 8,
            threadFactory = counter.factory,
        )
        val entered = CountDownLatch(2)
        val release = CountDownLatch(1)
        val owners = (0 until 8).map { Any() }
        val extra = Any()
        try {
            owners.forEach { owner ->
                assertTrue(
                    dispatcher.dispatch(owner) {
                        entered.countDown()
                        release.await(5, TimeUnit.SECONDS)
                    },
                )
            }
            assertTrue("Both workers must reach a blocked callback.", entered.await(5, TimeUnit.SECONDS))
            assertEquals("A blocked owner must not add a worker.", 2, counter.created.get())
            assertEquals(8, dispatcher.trackedOwnerCount())
            assertEquals(6, dispatcher.queuedOwnerCount())

            // A ninth owner is refused rather than adding a thread or growing
            // the waiting queue past its bound. The caller keeps its pending
            // work and retries after a lane is released.
            assertFalse(dispatcher.dispatch(extra) { })
            assertEquals("Refusal must not create a thread.", 2, counter.created.get())
            assertEquals(8, dispatcher.trackedOwnerCount())
            assertEquals(6, dispatcher.queuedOwnerCount())
        } finally {
            release.countDown()
            owners.forEach { dispatcher.retire(it) }
            dispatcher.shutdown()
        }
        assertTrue(waitUntil { dispatcher.liveWorkerCount() == 0 })
    }

    @Test
    fun repeatedEventsForOneBlockedOwnerKeepOnlyTheLatestAction() {
        val dispatcher = PairingCallbackDispatcher(workerCount = 1, maxOwners = 4)
        val owner = Any()
        val firstEntered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val lastDone = CountDownLatch(1)
        val seen = Collections.synchronizedList(mutableListOf<Int>())
        try {
            assertTrue(
                dispatcher.dispatch(owner) {
                    seen.add(0)
                    firstEntered.countDown()
                    release.await(5, TimeUnit.SECONDS)
                },
            )
            assertTrue(firstEntered.await(5, TimeUnit.SECONDS))
            repeat(1_000) { index ->
                assertTrue(
                    dispatcher.dispatch(owner) {
                        seen.add(index + 1)
                        if (index == 999) lastDone.countDown()
                    },
                )
            }
            assertEquals("Coalescing must keep one lane for the owner.", 1, dispatcher.trackedOwnerCount())
            release.countDown()
            assertTrue("The latest queued action must run.", lastDone.await(5, TimeUnit.SECONDS))
            assertEquals(listOf(0, 1_000), synchronized(seen) { seen.toList() })
        } finally {
            release.countDown()
            dispatcher.shutdown()
        }
    }

    @Test
    fun reentrantDispatchRunsAfterTheCurrentCallback() {
        val dispatcher = PairingCallbackDispatcher(workerCount = 1, maxOwners = 4)
        val owner = Any()
        val done = CountDownLatch(1)
        val order = Collections.synchronizedList(mutableListOf<Int>())
        try {
            assertTrue(
                dispatcher.dispatch(owner) {
                    order.add(1)
                    assertTrue(
                        dispatcher.dispatch(owner) {
                            order.add(2)
                            done.countDown()
                        },
                    )
                },
            )
            assertTrue(done.await(5, TimeUnit.SECONDS))
            assertEquals(listOf(1, 2), synchronized(order) { order.toList() })
        } finally {
            dispatcher.shutdown()
        }
    }

    @Test
    fun retiringAContinuedOwnerDropsItsQueuedWork() {
        val dispatcher = PairingCallbackDispatcher(workerCount = 1, maxOwners = 4)
        val owner = Any()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val queuedRan = CountDownLatch(1)
        try {
            assertTrue(
                dispatcher.dispatch(owner) {
                    entered.countDown()
                    release.await(5, TimeUnit.SECONDS)
                },
            )
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            assertTrue(dispatcher.dispatch(owner) { queuedRan.countDown() })
            dispatcher.retire(owner)
            release.countDown()
            assertFalse(
                "A retired owner must not run work queued behind its blocked callback.",
                queuedRan.await(300, TimeUnit.MILLISECONDS),
            )
            assertTrue(waitUntil { dispatcher.trackedOwnerCount() == 0 })
        } finally {
            release.countDown()
            dispatcher.shutdown()
        }
    }

    @Test
    fun runningOwnersRejectNewWorkAndRetirementMakesRoom() {
        val dispatcher = PairingCallbackDispatcher(workerCount = 2, maxOwners = 2)
        val first = Any()
        val second = Any()
        val entered = CountDownLatch(2)
        val release = CountDownLatch(1)
        val accepted = CountDownLatch(1)
        try {
            repeat(2) { index ->
                assertTrue(
                    dispatcher.dispatch(if (index == 0) first else second) {
                        entered.countDown()
                        release.await(5, TimeUnit.SECONDS)
                    },
                )
            }
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            val third = Any()
            assertFalse(
                "A full set of running owners must refuse rather than grow.",
                dispatcher.dispatch(third) { accepted.countDown() },
            )
            assertEquals(2, dispatcher.trackedOwnerCount())
            assertEquals(0, dispatcher.queuedOwnerCount())

            release.countDown()
            dispatcher.retire(first)
            dispatcher.retire(second)
            assertTrue(waitUntil { dispatcher.trackedOwnerCount() == 0 })
            assertTrue("A later event can retry after space is free.", dispatcher.dispatch(third) { accepted.countDown() })
            assertTrue(accepted.await(5, TimeUnit.SECONDS))
        } finally {
            release.countDown()
            dispatcher.shutdown()
        }
    }

    @Test
    fun replacementOwnersCannotGrowTheTrackedSetOrQueue() {
        val counter = ThreadCounter()
        val dispatcher = PairingCallbackDispatcher(
            workerCount = 1,
            maxOwners = 4,
            threadFactory = counter.factory,
        )
        val first = Any()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val ran = AtomicInteger(0)
        try {
            assertTrue(
                dispatcher.dispatch(first) {
                    entered.countDown()
                    release.await(5, TimeUnit.SECONDS)
                },
            )
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            var refused = false
            repeat(64) {
                if (!dispatcher.dispatch(Any()) { ran.incrementAndGet() }) refused = true
                assertTrue(dispatcher.trackedOwnerCount() <= 4)
                assertTrue(dispatcher.queuedOwnerCount() <= 4)
            }
            assertTrue("A full queue must refuse new owners.", refused)
            assertEquals("Replacements must not create new workers.", 1, counter.created.get())
            release.countDown()
            assertTrue(waitUntil { ran.get() > 0 })
        } finally {
            release.countDown()
            dispatcher.shutdown()
        }
        assertTrue(waitUntil { dispatcher.liveWorkerCount() == 0 })
    }

    @Test
    fun aThrowingHostCallbackDoesNotBreakLaterLanes() {
        val dispatcher = PairingCallbackDispatcher(workerCount = 1, maxOwners = 4)
        val failed = Any()
        val next = Any()
        val done = CountDownLatch(1)
        try {
            assertTrue(dispatcher.dispatch(failed) { error("host callback failed") })
            assertTrue(dispatcher.dispatch(next) { done.countDown() })
            assertTrue("A host failure must not stop the worker.", done.await(5, TimeUnit.SECONDS))
        } finally {
            dispatcher.retire(failed)
            dispatcher.retire(next)
            dispatcher.shutdown()
        }
    }

    @Test
    fun aThrowingErrorDoesNotReduceTheWorkerPool() {
        val counter = ThreadCounter()
        val dispatcher = PairingCallbackDispatcher(
            workerCount = 1,
            maxOwners = 2,
            threadFactory = counter.factory,
        )
        val after = CountDownLatch(1)
        try {
            assertTrue(dispatcher.dispatch(Any()) { throw AssertionError("host callback failed") })
            assertTrue(dispatcher.dispatch(Any()) { after.countDown() })
            assertTrue("An Error must not kill the only worker.", after.await(5, TimeUnit.SECONDS))
            assertEquals(1, dispatcher.liveWorkerCount())
            assertEquals("The dispatcher must keep its worker.", 1, counter.created.get())
        } finally {
            dispatcher.shutdown()
        }
        assertTrue(waitUntil { dispatcher.liveWorkerCount() == 0 })
    }

    @Test
    fun idleLanesAreEvictedBeforeANewOwnerIsRefused() {
        val dispatcher = PairingCallbackDispatcher(workerCount = 1, maxOwners = 2)
        val first = Any()
        val second = Any()
        val third = Any()
        val firstDone = CountDownLatch(1)
        val secondDone = CountDownLatch(1)
        val thirdDone = CountDownLatch(1)
        try {
            assertTrue(dispatcher.dispatch(first) { firstDone.countDown() })
            assertTrue(dispatcher.dispatch(second) { secondDone.countDown() })
            assertTrue(firstDone.await(5, TimeUnit.SECONDS))
            assertTrue(secondDone.await(5, TimeUnit.SECONDS))
            assertTrue(
                "A completed lane stays tracked as an idle lane.",
                waitUntil { dispatcher.trackedOwnerCount() == 2 },
            )

            assertTrue(
                "An idle lane must be released before an owner is refused.",
                dispatcher.dispatch(third) { thirdDone.countDown() },
            )
            assertTrue(thirdDone.await(5, TimeUnit.SECONDS))
            assertEquals(2, dispatcher.trackedOwnerCount())
        } finally {
            dispatcher.retire(first)
            dispatcher.retire(second)
            dispatcher.retire(third)
            dispatcher.shutdown()
        }
    }

    @Test
    fun refusedDispatchIsRetriedWhenALaneFinishes() {
        val dispatcher = PairingCallbackDispatcher(workerCount = 1, maxOwners = 1)
        val blocker = Any()
        val waiting = Any()
        val blockerEntered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val waitingRan = CountDownLatch(1)
        try {
            assertTrue(
                dispatcher.dispatch(blocker) {
                    blockerEntered.countDown()
                    release.await(5, TimeUnit.SECONDS)
                },
            )
            assertTrue(blockerEntered.await(5, TimeUnit.SECONDS))
            assertTrue(
                "A refused lane must keep one bounded retry ticket.",
                dispatcher.dispatchOrRetry(waiting) { waitingRan.countDown() },
            )
            assertEquals(1, dispatcher.retryOwnerCount())
            assertFalse("The ticket must not run while the lane is full.", waitingRan.await(200, TimeUnit.MILLISECONDS))

            release.countDown()
            assertTrue(
                "A freed worker must deliver the ticket without another event.",
                waitingRan.await(5, TimeUnit.SECONDS),
            )
            assertTrue(waitUntil { dispatcher.retryOwnerCount() == 0 })
        } finally {
            release.countDown()
            dispatcher.retire(blocker)
            dispatcher.retire(waiting)
            dispatcher.shutdown()
        }
    }

    @Test
    fun retryTicketsStayBoundedByTheLaneLimit() {
        val dispatcher = PairingCallbackDispatcher(workerCount = 1, maxOwners = 1)
        val blocker = Any()
        val blockerEntered = CountDownLatch(1)
        val release = CountDownLatch(1)
        try {
            assertTrue(
                dispatcher.dispatch(blocker) {
                    blockerEntered.countDown()
                    release.await(5, TimeUnit.SECONDS)
                },
            )
            assertTrue(blockerEntered.await(5, TimeUnit.SECONDS))

            assertTrue(dispatcher.dispatchOrRetry(Any()) { })
            assertFalse(dispatcher.dispatchOrRetry(Any()) { })
            assertFalse(dispatcher.dispatchOrRetry(Any()) { })
            assertEquals(1, dispatcher.retryOwnerCount())
        } finally {
            release.countDown()
            dispatcher.retire(blocker)
            dispatcher.shutdown()
        }
    }

    private fun waitUntil(condition: () -> Boolean): Boolean {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (System.nanoTime() < deadline) {
            if (condition()) return true
            Thread.sleep(10)
        }
        return condition()
    }

    private class ThreadCounter {
        val created = AtomicInteger(0)
        private val live = AtomicInteger(0)

        val factory = ThreadFactory { runnable ->
            Thread(
                {
                    live.incrementAndGet()
                    try {
                        runnable.run()
                    } finally {
                        live.decrementAndGet()
                    }
                },
                "test-pairing-callback-${created.getAndIncrement()}",
            ).apply { isDaemon = true }
        }
    }
}
