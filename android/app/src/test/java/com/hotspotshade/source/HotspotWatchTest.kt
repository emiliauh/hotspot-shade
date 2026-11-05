package com.hotspotshade.source

import java.net.InetAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class HotspotWatchTest {
    private class FakeFinder(var address: InetAddress?) : HotspotAddressFinder {
        val calls = AtomicInteger()

        override fun findHotspotAddress(): InetAddress? {
            calls.incrementAndGet()
            return address
        }
    }

    private val expected = InetAddress.getByName("192.168.43.1")

    @Test
    fun reportsOneLossWhenTheAddressDisappears() {
        val finder = FakeFinder(expected)
        val watch = PeriodicHotspotWatch(finder, expected, periodMillis = 20)
        val losses = AtomicInteger()
        val firstLoss = CountDownLatch(1)
        watch.start {
            losses.incrementAndGet()
            firstLoss.countDown()
        }
        try {
            waitForCalls(finder)
            finder.address = null

            assertTrue("The watch must report the loss.", firstLoss.await(5, TimeUnit.SECONDS))
            Thread.sleep(150)
            assertEquals(1, losses.get())
        } finally {
            watch.stop()
        }
    }

    @Test
    fun doesNotReportWhileTheAddressStays() {
        val finder = FakeFinder(expected)
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
        val finder = FakeFinder(expected)
        val watch = PeriodicHotspotWatch(finder, expected, periodMillis = 20)
        val losses = AtomicInteger()
        watch.start { losses.incrementAndGet() }
        watch.stop()
        finder.address = null

        Thread.sleep(150)

        assertEquals(0, losses.get())
    }

    @Test
    fun stopIsIdempotent() {
        val finder = FakeFinder(expected)
        val watch = PeriodicHotspotWatch(finder, expected, periodMillis = 20)
        watch.start {}
        watch.stop()
        watch.stop()
    }

    private fun waitForCalls(finder: FakeFinder) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (finder.calls.get() == 0 && System.nanoTime() < deadline) {
            Thread.sleep(10)
        }
        assertTrue("The watch must read the address.", finder.calls.get() > 0)
    }
}
