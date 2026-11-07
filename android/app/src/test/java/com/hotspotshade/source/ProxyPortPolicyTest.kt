package com.hotspotshade.source

import java.net.InetAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Tests for the saved source proxy port. No socket is opened. */
class ProxyPortPolicyTest {
    private val hotspot = InetAddress.getByName("127.0.0.1")

    @Test
    fun aFreeSavedPortIsReservedWithoutAWrite() {
        val store = FakeStore(31000)
        val probe = FakeProbe(free = { true })
        val policy = ProxyPortPolicy(store, probe)

        assertEquals(31000, policy.reserve(hotspot))
        assertEquals(31000, policy.reserve(hotspot))
        assertEquals("A free saved port needs no write.", 31000, store.value)
        assertEquals("The port must be checked before it is promised.", 2, probe.freeCalls)
    }

    @Test
    fun anOccupiedSavedPortIsReplacedAndSaved() {
        val store = FakeStore(31000)
        // Every candidate is taken except the fallback, so the replacement is
        // deterministic.
        val probe = FakeProbe(free = { false }, fallback = 41_234)
        val policy = ProxyPortPolicy(store, probe)

        val reserved = policy.reserve(hotspot)

        assertEquals(
            "A pairing result must not promise the occupied remembered port.",
            41_234,
            reserved,
        )
        assertEquals("The next start must claim the reserved port.", 41_234, store.value)
        assertEquals("The next start reuses the reserved port.", 41_234, policy.claim(hotspot))
    }

    @Test
    fun aReservationThatCannotBeSavedReturnsNull() {
        val store = FakeStore(31000, failSave = true)
        val probe = FakeProbe(free = { false }, fallback = 41_234)
        val policy = ProxyPortPolicy(store, probe)

        assertNull(
            "A port that the next start cannot reuse must not be promised.",
            policy.reserve(hotspot),
        )
        assertEquals("A failed save leaves the remembered port.", 31000, store.value)
    }

    @Test
    fun anExhaustedPortRangeReturnsNull() {
        val store = FakeStore(0)
        val probe = FakeProbe(free = { false }, fallback = 0)
        val policy = ProxyPortPolicy(store, probe)

        assertNull(policy.reserve(hotspot))
        assertEquals(0, store.value)
    }

    @Test
    fun aProbeFailureReturnsNull() {
        val store = FakeStore(31000)
        val probe = object : PortProbe {
            override fun isFree(address: InetAddress, port: Int): Boolean =
                throw IllegalStateException("The probe failed.")

            override fun freePort(address: InetAddress): Int =
                throw IllegalStateException("The probe failed.")
        }
        val policy = ProxyPortPolicy(store, probe)

        assertNull("An unproven port must not be promised.", policy.reserve(hotspot))
        assertEquals(31000, store.value)
    }

    @Test
    fun aSavedPortThatAnotherProcessTookIsReplacedForOneStartOnly() {
        val store = FakeStore(31000)
        val probe = FakeProbe(free = { false }, fallback = 41_234)
        val policy = ProxyPortPolicy(store, probe)

        assertEquals("A taken saved port is replaced for this attempt.", 41_234, policy.claim(hotspot))
        assertEquals(
            "A failed start must not erase the remembered port.",
            31000,
            store.value,
        )
    }

    @Test
    fun claimKeepsAFreeSavedPort() {
        val store = FakeStore(31000)
        val probe = FakeProbe(free = { true })
        val policy = ProxyPortPolicy(store, probe)

        assertEquals(31000, policy.claim(hotspot))
        assertEquals(31000, store.value)
        assertEquals(1, probe.freeCalls)
    }

    @Test
    fun claimDoesNotPersistACandidateBeforeTheListenerBinds() {
        val store = FakeStore(0)
        val probe = FakeProbe(free = { true })
        val policy = ProxyPortPolicy(store, probe)

        val port = policy.claim(hotspot)

        assertTrue(port in 20_000..59_999)
        assertEquals("A candidate must not replace the remembered port.", 0, store.value)
        policy.remember(port)
        assertEquals(port, store.value)
    }

    @Test
    fun rememberRejectsThePairingPortAndClearRemovesTheValue() {
        val store = FakeStore(0)
        val policy = ProxyPortPolicy(store, FakeProbe(free = { true }))
        policy.remember(18_090)
        assertEquals(0, store.value)
        policy.remember(1080)
        assertEquals(1080, store.value)
        policy.clear()
        assertEquals(0, store.value)
    }

    @Test
    fun anAdvisoryProbeDoesNotRunDuringARealBind() {
        val store = FakeStore(31000)
        val probe = FakeProbe(free = { true })
        val policy = ProxyPortPolicy(store, probe)
        val binding = CountDownLatch(1)
        val release = CountDownLatch(1)
        val binder = Thread {
            ProxyBindGate.duringBind {
                binding.countDown()
                release.await(5, TimeUnit.SECONDS)
            }
        }
        binder.start()
        try {
            assertTrue(binding.await(5, TimeUnit.SECONDS))
            assertNull(
                "A probe must not race a real bind.",
                policy.reserve(hotspot),
            )
            assertEquals("No port probe may run during the bind.", 0, probe.freeCalls)
        } finally {
            release.countDown()
            binder.join(5_000)
            assertFalse(binder.isAlive)
        }
        assertEquals(
            "The advisory probe runs again after the bind.",
            31000,
            policy.reserve(hotspot),
        )
    }

    private class FakeStore(
        var value: Int,
        private val failSave: Boolean = false,
    ) : ProxyPortStore {
        override fun load(): Int = value

        override fun save(port: Int) {
            if (failSave) throw IllegalStateException("The port store cannot be written.")
            value = port
        }

        override fun clear() {
            value = 0
        }
    }

    private class FakeProbe(
        private val free: (Int) -> Boolean,
        private val fallback: Int = 0,
    ) : PortProbe {
        var freeCalls = 0
            private set

        override fun isFree(address: InetAddress, port: Int): Boolean {
            freeCalls += 1
            return free(port)
        }

        override fun freePort(address: InetAddress): Int = fallback
    }
}
