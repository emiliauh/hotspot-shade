package com.hotspotshade.source

import java.io.IOException
import java.net.DatagramSocket
import java.net.Socket
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class CellularSocketsTest {
    private class FakeBinding : CellularBinding {
        val events = mutableListOf<String>()
        var failCheck = 0
        var failBind = false
        var tcp: Socket? = null
        var udp: DatagramSocket? = null

        override fun requireAvailable() {
            events.add("check")
            if (events.count { it == "check" } == failCheck) throw IOException("unavailable")
        }

        override fun bind(socket: Socket) {
            events.add("bind")
            tcp = socket
            assertFalse(socket.isConnected)
            if (failBind) throw IOException("bind failed")
        }

        override fun bind(socket: DatagramSocket) {
            events.add("bind")
            udp = socket
            assertFalse(socket.isConnected)
            if (failBind) throw IOException("bind failed")
        }
    }

    @Test fun createsDistinctUnconnectedSocketsAfterBothChecks() {
        val binding = FakeBinding()
        val sockets = CellularSockets(binding)
        val first = sockets.tcp()
        val second = sockets.tcp()
        val datagram = sockets.udp()
        try {
            assertTrue(first !== second)
            assertFalse(first.isConnected)
            assertFalse(datagram.isConnected)
            assertSame(second, binding.tcp)
            assertSame(datagram, binding.udp)
            assertEquals(listOf("check", "bind", "check", "check", "bind", "check", "check", "bind", "check"), binding.events)
        } finally {
            first.close()
            second.close()
            datagram.close()
        }
    }

    @Test fun closesTcpWhenBindingOrRecheckFails() {
        for (failBind in listOf(true, false)) {
            val binding = FakeBinding().apply {
                this.failBind = failBind
                if (!failBind) failCheck = 2
            }
            try {
                CellularSockets(binding).tcp()
                fail("Expected an error")
            } catch (_: IOException) {
                assertTrue(binding.tcp!!.isClosed)
            }
        }
    }

    @Test fun closesUdpWhenBindingOrRecheckFails() {
        for (failBind in listOf(true, false)) {
            val binding = FakeBinding().apply {
                this.failBind = failBind
                if (!failBind) failCheck = 2
            }
            try {
                CellularSockets(binding).udp()
                fail("Expected an error")
            } catch (_: IOException) {
                assertTrue(binding.udp!!.isClosed)
            }
        }
    }

    @Test fun doesNotBindWhenNetworkIsUnavailable() {
        val binding = FakeBinding().apply { failCheck = 1 }
        val socket = Socket()
        try {
            CellularSockets(binding, newTcp = { socket }).tcp()
            fail("Expected an error")
        } catch (_: IOException) {
            assertEquals(listOf("check"), binding.events)
            assertTrue(socket.isClosed)
        }
    }
}
