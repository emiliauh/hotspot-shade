package com.hotspotshade.source

import java.io.IOException
import java.net.DatagramSocket
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class CellularSessionTest {
    private open class FakeBinding : CellularBinding {
        override fun requireAvailable() = Unit
        override fun bind(socket: Socket) = Unit
        override fun bind(socket: DatagramSocket) = Unit
    }

    private class CountingSocket : Socket() {
        val closes = AtomicInteger()
        override fun close() {
            closes.incrementAndGet()
            super.close()
        }
    }

    @Test fun stopClosesFlowsAndRefusesNewOnes() {
        val session = CellularSession(CellularSockets(FakeBinding()))
        val tcp = session.tcp()
        val udp = session.udp()
        session.close()
        assertTrue(tcp.socket.isClosed)
        assertTrue(udp.socket.isClosed)
        session.close()
        tcp.close()
        udp.close()
        try {
            session.tcp()
            fail("A stopped session must refuse new sockets")
        } catch (_: IOException) {
            // Expected.
        }
    }

    @Test fun closedFlowIsNotRetainedUntilSessionStop() {
        val socket = CountingSocket()
        val session = CellularSession(CellularSockets(FakeBinding(), newTcp = { socket }))
        val flow = session.tcp()
        flow.close()
        flow.close()
        session.close()
        assertEquals(1, socket.closes.get())
    }

    @Test fun capacityIsBoundedAndAClosedFlowReleasesItsSlot() {
        val session = CellularSession(CellularSockets(FakeBinding()), maximumFlows = 1)
        val first = session.tcp()
        try {
            try {
                session.udp()
                fail("A full session must refuse new sockets")
            } catch (_: IOException) {
                // Expected.
            }
            first.close()
            session.udp().close()
        } finally {
            first.close()
            session.close()
        }
    }

    @Test fun stopDuringBindingClosesSocketBeforeBindingFinishes() {
        val entered = CountDownLatch(1)
        val resume = CountDownLatch(1)
        val socket = Socket()
        val binding = object : FakeBinding() {
            override fun bind(socket: Socket) {
                entered.countDown()
                check(resume.await(5, TimeUnit.SECONDS))
            }
        }
        val session = CellularSession(CellularSockets(binding, newTcp = { socket }))
        val executor = Executors.newSingleThreadExecutor()
        try {
            val open = executor.submit<Boolean> {
                try {
                    session.tcp().close()
                    false
                } catch (_: IOException) {
                    true
                }
            }
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            session.close()
            assertTrue(socket.isClosed)
            resume.countDown()
            assertTrue(open.get(5, TimeUnit.SECONDS))
        } finally {
            resume.countDown()
            executor.shutdownNow()
            session.close()
        }
    }

    @Test fun failedBindingIsRemovedFromSession() {
        val socket = CountingSocket()
        val binding = object : FakeBinding() {
            override fun bind(socket: Socket) { throw IOException("bind failed") }
        }
        val session = CellularSession(CellularSockets(binding, newTcp = { socket }))
        try {
            session.tcp()
            fail("Expected a binding failure")
        } catch (_: IOException) {
            assertTrue(socket.isClosed)
        }
        session.close()
        assertEquals(1, socket.closes.get())
    }

    @Test fun failedCloseCanBeRetriedBySession() {
        val socket = object : Socket() {
            var attempts = 0
            override fun close() {
                attempts += 1
                if (attempts == 1) throw IOException("first close failed")
                super.close()
            }
        }
        val session = CellularSession(CellularSockets(FakeBinding(), newTcp = { socket }))
        val flow = session.tcp()
        try {
            flow.close()
            fail("Expected the close failure")
        } catch (_: IOException) {
            assertEquals(1, socket.attempts)
        }
        session.close()
        assertTrue(socket.isClosed)
        assertEquals(2, socket.attempts)
    }

    @Test fun sessionRetriesSocketWhoseCloseFailedDuringBinding() {
        val socket = object : Socket() {
            var attempts = 0
            override fun close() {
                attempts += 1
                if (attempts == 1) throw IOException("first close failed")
                super.close()
            }
        }
        val binding = object : FakeBinding() {
            override fun bind(socket: Socket) { throw IOException("bind failed") }
        }
        val session = CellularSession(CellularSockets(binding, newTcp = { socket }))
        try {
            session.tcp()
            fail("Expected a binding failure")
        } catch (failure: IOException) {
            assertEquals(1, failure.suppressed.size)
        }
        session.close()
        assertTrue(socket.isClosed)
        assertEquals(2, socket.attempts)
    }
}
