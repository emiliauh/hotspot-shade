package com.hotspotshade.source

import java.net.InetAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests for the periodic hotspot watch.
 *
 * The watch closes at once when the bound address belongs to an interface
 * that a reported network holds. It debounces an uncertain probe. One good
 * probe clears the miss count. It reports at most one loss.
 */
class HotspotWatchTest {
    private val expected = InetAddress.getByName("192.168.43.1")

    private fun hit(address: InetAddress = expected) = HotspotProbe.Observed(
        candidates = listOf(HotspotCandidate(rank = 0, address = address)),
        excludedAddresses = emptySet(),
    )

    private fun uncertain() = HotspotProbe.Observed(
        candidates = emptyList(),
        excludedAddresses = emptySet(),
    )

    private fun unsafe(address: InetAddress) = HotspotProbe.Observed(
        candidates = emptyList(),
        excludedAddresses = setOf(address),
    )

    private class FakeFinder(var result: HotspotProbe) : HotspotAddressFinder {
        val calls = AtomicInteger()

        override fun probe(): HotspotProbe {
            calls.incrementAndGet()
            return result
        }
    }

    /** Return the next scripted answer, then repeat the last answer. */
    private class ScriptedFinder(private val answers: List<HotspotProbe>) : HotspotAddressFinder {
        val calls = AtomicInteger()

        override fun probe(): HotspotProbe {
            val index = calls.getAndIncrement()
            return answers[minOf(index, answers.lastIndex)]
        }
    }

    private class ThrowingOnceFinder(private val then: HotspotProbe) : HotspotAddressFinder {
        val calls = AtomicInteger()

        override fun probe(): HotspotProbe {
            if (calls.getAndIncrement() == 0) {
                error("The finder could not read the interfaces.")
            }
            return then
        }
    }

    @Test
    fun reportsOneLossWhenTheAddressDisappears() {
        val finder = FakeFinder(hit())
        val watch = PeriodicHotspotWatch(
            finder,
            expected,
            periodMillis = 20,
            missingChecksBeforeLoss = 2,
        )
        val losses = AtomicInteger()
        val firstLoss = CountDownLatch(1)
        watch.start {
            losses.incrementAndGet()
            firstLoss.countDown()
        }
        try {
            waitForCalls(finder.calls, 1)
            finder.result = uncertain()

            assertTrue("The watch must report the loss.", firstLoss.await(5, TimeUnit.SECONDS))
            Thread.sleep(150)
            assertEquals(1, losses.get())
        } finally {
            watch.stop()
        }
    }

    @Test
    fun reportsImmediatelyWhenTheBoundInterfaceIsAReportedClient() {
        val finder = FakeFinder(hit())
        // A high miss count would need many uncertain probes. The unsafe probe
        // must not wait for it.
        val watch = PeriodicHotspotWatch(
            finder,
            expected,
            periodMillis = 20,
            missingChecksBeforeLoss = 100,
        )
        val losses = AtomicInteger()
        val firstLoss = CountDownLatch(1)
        watch.start {
            losses.incrementAndGet()
            firstLoss.countDown()
        }
        try {
            waitForCalls(finder.calls, 1)
            finder.result = unsafe(expected)

            assertTrue(
                "An excluded bound interface must close the watch at once.",
                firstLoss.await(5, TimeUnit.SECONDS),
            )
            Thread.sleep(150)
            assertEquals(1, losses.get())
        } finally {
            watch.stop()
        }
    }

    @Test
    fun oneTransientMissDoesNotReportALoss() {
        // The first check sees the bound address. The second misses it. The
        // third sees it again.
        val finder = ScriptedFinder(listOf(hit(), uncertain(), hit()))
        val watch = PeriodicHotspotWatch(
            finder,
            expected,
            periodMillis = 20,
            missingChecksBeforeLoss = 2,
        )
        val losses = AtomicInteger()
        watch.start { losses.incrementAndGet() }
        try {
            waitForCalls(finder.calls, 3)
            Thread.sleep(100)
            assertEquals(0, losses.get())
        } finally {
            watch.stop()
        }
    }

    @Test
    fun aPendingFirstReadingDoesNotReportALoss() {
        val finder = ScriptedFinder(listOf(HotspotProbe.Pending, hit()))
        val watch = PeriodicHotspotWatch(
            finder,
            expected,
            periodMillis = 20,
            missingChecksBeforeLoss = 1,
        )
        val losses = AtomicInteger()
        watch.start { losses.incrementAndGet() }
        try {
            waitForCalls(finder.calls, 5)
            Thread.sleep(100)
            assertEquals(0, losses.get())
        } finally {
            watch.stop()
        }
    }

    @Test
    fun pendingChecksDoNotAddToTheMissingCount() {
        val finder = ScriptedFinder(
            listOf(HotspotProbe.Pending, uncertain(), HotspotProbe.Pending, uncertain()),
        )
        val watch = PeriodicHotspotWatch(
            finder,
            expected,
            periodMillis = 20,
            missingChecksBeforeLoss = 2,
        )
        val losses = AtomicInteger()
        val firstLoss = CountDownLatch(1)
        watch.start {
            losses.incrementAndGet()
            firstLoss.countDown()
        }
        try {
            assertTrue(
                "Only the two uncertain checks must count.",
                firstLoss.await(5, TimeUnit.SECONDS),
            )
            Thread.sleep(150)
            assertEquals(1, losses.get())
        } finally {
            watch.stop()
        }
    }

    @Test
    fun aStuckPendingReadingStopsTheWatchAfterTheBound() {
        val finder = ScriptedFinder(listOf(HotspotProbe.Pending))
        val watch = PeriodicHotspotWatch(
            finder,
            expected,
            periodMillis = 20,
            missingChecksBeforeLoss = 2,
            pendingChecksBeforeUncertain = 2,
        )
        val losses = AtomicInteger()
        val firstLoss = CountDownLatch(1)
        watch.start {
            losses.incrementAndGet()
            firstLoss.countDown()
        }
        try {
            assertTrue(
                "A stuck pending reading must not blind the watch.",
                firstLoss.await(5, TimeUnit.SECONDS),
            )
            Thread.sleep(150)
            assertEquals(1, losses.get())
        } finally {
            watch.stop()
        }
    }

    @Test
    fun aMissingObservationThenRecoveryDoesNotReport() {
        // An unknown read is uncertain once, then the next check finds the
        // bound address again.
        val finder = ScriptedFinder(listOf(HotspotProbe.Unknown, hit()))
        val watch = PeriodicHotspotWatch(
            finder,
            expected,
            periodMillis = 20,
            missingChecksBeforeLoss = 3,
        )
        val losses = AtomicInteger()
        watch.start { losses.incrementAndGet() }
        try {
            waitForCalls(finder.calls, 3)
            Thread.sleep(100)
            assertEquals(0, losses.get())
        } finally {
            watch.stop()
        }
    }

    @Test
    fun aThrownProbeIsUncertainAndDoesNotReportAlone() {
        val finder = ThrowingOnceFinder(hit())
        val watch = PeriodicHotspotWatch(
            finder,
            expected,
            periodMillis = 20,
            missingChecksBeforeLoss = 2,
        )
        val losses = AtomicInteger()
        watch.start { losses.incrementAndGet() }
        try {
            waitForCalls(finder.calls, 3)
            Thread.sleep(100)
            assertEquals(0, losses.get())
        } finally {
            watch.stop()
        }
    }

    @Test
    fun reportsExactlyOneLossAfterSustainedMisses() {
        val finder = ScriptedFinder(
            listOf(hit(), uncertain(), uncertain(), uncertain(), uncertain(), uncertain()),
        )
        val watch = PeriodicHotspotWatch(
            finder,
            expected,
            periodMillis = 20,
            missingChecksBeforeLoss = 3,
        )
        val losses = AtomicInteger()
        val firstLoss = CountDownLatch(1)
        watch.start {
            losses.incrementAndGet()
            firstLoss.countDown()
        }
        try {
            assertTrue("The watch must report the loss.", firstLoss.await(5, TimeUnit.SECONDS))
            Thread.sleep(200)
            assertEquals(1, losses.get())
        } finally {
            watch.stop()
        }
    }

    @Test
    fun doesNotReportWhileTheAddressStays() {
        val finder = FakeFinder(hit())
        val watch = PeriodicHotspotWatch(finder, expected, periodMillis = 20)
        val losses = AtomicInteger()
        watch.start { losses.incrementAndGet() }
        try {
            Thread.sleep(150)
            assertTrue(finder.calls.get() >= 2)
            assertEquals(0, losses.get())
        } finally {
            watch.stop()
        }
    }

    @Test
    fun stopBeforeTheLossDoesNotReport() {
        val finder = FakeFinder(hit())
        val watch = PeriodicHotspotWatch(finder, expected, periodMillis = 20)
        val losses = AtomicInteger()
        watch.start { losses.incrementAndGet() }
        watch.stop()
        finder.result = unsafe(expected)

        Thread.sleep(150)

        assertEquals(0, losses.get())
    }

    @Test
    fun stopIsIdempotent() {
        val finder = FakeFinder(hit())
        val watch = PeriodicHotspotWatch(finder, expected, periodMillis = 20)
        watch.start {}
        watch.stop()
        watch.stop()
    }

    @Test
    fun theDefaultPendingBackstopOutlastsTheEvidenceTimeout() {
        val backstopMillis = PeriodicHotspotWatch.DEFAULT_PERIOD_MILLIS *
            HotspotWatchPolicy.DEFAULT_PENDING_CHECKS_BEFORE_UNCERTAIN

        assertTrue(
            "The watch pending backstop must not cut before the evidence fallback.",
            backstopMillis > TetheredInterfaceEvidence.DEFAULT_PENDING_TIMEOUT_MILLIS,
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsANonPositiveMissingCheckCount() {
        PeriodicHotspotWatch(
            FakeFinder(hit()),
            expected,
            periodMillis = 20,
            missingChecksBeforeLoss = 0,
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsANonPositivePeriod() {
        PeriodicHotspotWatch(
            FakeFinder(hit()),
            expected,
            periodMillis = 0,
        )
    }

    private fun waitForCalls(calls: AtomicInteger, minimum: Int) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (calls.get() < minimum && System.nanoTime() < deadline) {
            Thread.sleep(10)
        }
        assertTrue("The watch must read the address.", calls.get() >= minimum)
    }
}
