package com.hotspotshade.source

import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Tests for the saved source proxy port. No socket is opened. */
class ProxyPortPolicyTest {
    private val hotspot = InetAddress.getByName("127.0.0.1")

    @Test
    fun aSavedPortStaysStable() {
        val store = FakeStore(31000)
        val probe = FakeProbe(alwaysFree = true)
        val policy = ProxyPortPolicy(store, probe)
        assertEquals(31000, policy.current(hotspot))
        assertEquals(31000, policy.current(hotspot))
        assertEquals(0, probe.freeCalls)
    }

    @Test
    fun aFreePortIsChosenAndSaved() {
        val store = FakeStore(0)
        val probe = FakeProbe(alwaysFree = true)
        val policy = ProxyPortPolicy(store, probe)
        val port = policy.current(hotspot)
        assertTrue(port in 20_000..59_999)
        assertTrue(port != 18_090)
        assertEquals(port, store.value)
        assertEquals(1, probe.freeCalls)
        assertEquals(port, policy.current(hotspot))
    }

    @Test
    fun theFallbackUsesTheOperatingSystemPort() {
        val store = FakeStore(0)
        val probe = FakeProbe(alwaysFree = false, fallback = 41_234)
        val policy = ProxyPortPolicy(store, probe)
        assertEquals(41_234, policy.current(hotspot))
        assertEquals(41_234, store.value)
    }

    @Test
    fun anUnusableSavedPortIsReplaced() {
        val store = FakeStore(18_090)
        val probe = FakeProbe(alwaysFree = true)
        val policy = ProxyPortPolicy(store, probe)
        val port = policy.current(hotspot)
        assertTrue(port in 20_000..59_999)
        assertEquals(port, store.value)
    }

    @Test
    fun rememberRejectsThePairingPortAndClearRemovesTheValue() {
        val store = FakeStore(0)
        val policy = ProxyPortPolicy(store, FakeProbe(alwaysFree = true))
        policy.remember(18_090)
        assertEquals(0, store.value)
        policy.remember(1080)
        assertEquals(1080, store.value)
        policy.clear()
        assertEquals(0, store.value)
    }

    private class FakeStore(var value: Int) : ProxyPortStore {
        override fun load(): Int = value

        override fun save(port: Int) {
            value = port
        }

        override fun clear() {
            value = 0
        }
    }

    private class FakeProbe(
        private val alwaysFree: Boolean,
        private val fallback: Int = 0,
    ) : PortProbe {
        var freeCalls = 0
            private set

        override fun isFree(address: InetAddress, port: Int): Boolean {
            freeCalls += 1
            return alwaysFree
        }

        override fun freePort(address: InetAddress): Int = fallback
    }
}
