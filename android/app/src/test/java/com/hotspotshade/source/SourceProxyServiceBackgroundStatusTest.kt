package com.hotspotshade.source

import com.hotspotshade.source.pairing.MemoryPairingTrustStore
import com.hotspotshade.source.pairing.PairingIdentity
import com.hotspotshade.source.pairing.PairingListener
import com.hotspotshade.source.pairing.PairingPrompt
import java.net.InetAddress
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests the background status lifecycle that the source proxy service owns.
 *
 * The service starts the host for every run and stops it at every run
 * terminal. The gate is on (`BACKGROUND_STATUS_ENABLED`) after the status-only
 * responder policy, the run identity fence, and the token epoch fence were
 * reviewed. These tests cover the host contract that the service uses: stop
 * the host at every run terminal, start a fresh host for every new run, and
 * never open a listener for a late token load after stop. They use a fake
 * listener and touch no hotspot.
 */
class SourceProxyServiceBackgroundStatusTest {
    @Test
    fun aNewRunStartsAFreshHostAndTokenLoad() {
        val harness = Harness()
        harness.host.start()
        assertEquals(1, harness.listeners.size)
        val first = harness.listeners.single()
        assertEquals(1, harness.tokenLoads)

        // The service stops the host when the run ends.
        harness.host.stop()
        assertEquals(1, first.closeCount)

        // A new run after a rotation must not reuse the old listener or the
        // token that it loaded.
        harness.token = "rotated-token"
        harness.host.start()

        assertEquals(2, harness.listeners.size)
        assertEquals(2, harness.tokenLoads)
        assertTrue(harness.listeners[1].started)
    }

    @Test
    fun aStoppedHostStaysClosed() {
        val harness = Harness()
        harness.host.start()
        val first = harness.listeners.single()

        harness.host.stop()
        harness.host.tickNow()

        assertEquals(1, harness.listeners.size)
        assertEquals(1, first.closeCount)
        assertTrue(!first.isRunning())
    }

    @Test
    fun aStopDuringTheTokenLoadOpensNothing() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val returned = CountDownLatch(1)
        val harness = Harness(
            pollMillis = 10L,
            onLoad = {
                entered.countDown()
                awaitIgnoringInterrupt(release)
                returned.countDown()
            },
        )
        harness.host.start()
        try {
            assertTrue(
                "The token load must be in flight.",
                entered.await(5, TimeUnit.SECONDS),
            )
            harness.host.stop()
        } finally {
            release.countDown()
        }
        assertTrue(
            "The blocked load must end after the stop.",
            returned.await(5, TimeUnit.SECONDS),
        )
        assertEquals(
            "A stopped host must not open a listener for a late load.",
            0,
            harness.listeners.size,
        )
    }

    private class Harness(
        var visible: Boolean = false,
        var binding: SourceProxyBinding = sourceBinding(),
        var token: String? = TOKEN,
        pollMillis: Long = 0L,
        private val onLoad: (() -> Unit)? = null,
    ) {
        val listeners = CopyOnWriteArrayList<FakeListener>()
        var tokenLoads = 0
        val host = BackgroundStatusHost(
            binding = { this.binding },
            visible = { this.visible },
            loadToken = {
                tokenLoads += 1
                onLoad?.invoke()
                token
            },
            trust = MemoryPairingTrustStore(),
            identity = FakeIdentity,
            clock = { 0L },
            listenerFactory = { _, _, _, _ ->
                FakeListener().also { listeners += it }
            },
            pollMillis = pollMillis,
        )
    }

    private class FakeListener : PairingListener {
        var started = false
        var closeCount = 0
        private var running = false

        override val localPort: Int get() = 18090

        override fun isRunning(): Boolean = running

        override fun start() {
            running = true
            started = true
        }

        override fun allow(prompt: PairingPrompt): Boolean = false

        override fun deny(prompt: PairingPrompt) = Unit

        override fun activate() = Unit

        override fun deactivate() = Unit

        override fun close() {
            closeCount += 1
            running = false
        }
    }

    private object FakeIdentity : PairingIdentity {
        override fun ephemeralSecret(): ByteArray = ByteArray(32) { 1 }

        override fun nonce(): ByteArray = ByteArray(12) { 2 }
    }

    private companion object {
        const val TOKEN = "service-background-test-token"

        fun sourceBinding(): SourceProxyBinding = SourceProxyBinding(
            state = SourceProxyState.RUNNING,
            active = true,
            port = 23456,
            address = InetAddress.getByName("192.0.2.10"),
        )

        fun awaitIgnoringInterrupt(latch: CountDownLatch) {
            var interrupted = false
            while (true) {
                try {
                    latch.await()
                    break
                } catch (_: InterruptedException) {
                    // A host stop interrupts the scheduler. The fake load
                    // still models a Keystore read that ignores interruption.
                    interrupted = true
                }
            }
            if (interrupted) Thread.currentThread().interrupt()
        }
    }
}
