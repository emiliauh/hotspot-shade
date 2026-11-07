package com.hotspotshade.source

import com.hotspotshade.source.pairing.MemoryPairingTrustStore
import com.hotspotshade.source.pairing.PairingIdentity
import com.hotspotshade.source.pairing.PairingListener
import com.hotspotshade.source.pairing.PairingPrompt
import com.hotspotshade.source.pairing.PromptId
import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class BackgroundStatusHostTest {
    @Test
    fun aVisibleProcessKeepsThePairingPortForTheActivity() {
        val harness = Harness(visible = true)
        harness.host.start()

        assertEquals(0, harness.listeners.size)

        harness.visible = false
        harness.host.tickNow()

        assertEquals(1, harness.listeners.size)
        assertTrue(harness.listeners[0].started)
        assertTrue(harness.listeners[0].deactivated)
    }

    @Test
    fun theActivityReleasesThePortAtOnceWithoutWaitingForATick() {
        val harness = Harness()
        harness.host.start()
        val first = harness.listeners.single()
        assertTrue(first.isRunning())

        // The activity start calls this on the worker before its own bind.
        BackgroundStatusHost.releasePortNow()

        assertEquals(1, first.closeCount)
        assertTrue(!first.isRunning())
        harness.host.stop()
    }

    @Test
    fun aStoppedHostIsNotReleasedAgainByTheActivity() {
        val harness = Harness()
        harness.host.start()
        val first = harness.listeners.single()
        harness.host.stop()

        BackgroundStatusHost.releasePortNow()

        assertEquals("Stop closed it once; the registry forgot the host.", 1, first.closeCount)
    }

    @Test
    fun aSchedulerFactoryFailureRollsBackSoALaterStartWorks() {
        var failFactory = true
        val listeners = mutableListOf<FakeListener>()
        val host = BackgroundStatusHost(
            binding = { sourceBinding() },
            visible = { false },
            loadToken = { "test-token" },
            trust = MemoryPairingTrustStore(),
            identity = FakeIdentity,
            clock = { 0L },
            tokenEpoch = { 0L },
            listenerFactory = { _, _, _, _ -> FakeListener().also { listeners.add(it) } },
            schedulerFactory = {
                if (failFactory) throw IllegalStateException("no thread")
                java.util.concurrent.Executors.newSingleThreadScheduledExecutor()
            },
            pollMillis = 20L,
        )

        host.start()
        assertEquals(0, listeners.size)

        failFactory = false
        host.start()
        try {
            val deadline = System.nanoTime() + 5_000_000_000L
            while (listeners.isEmpty() && System.nanoTime() < deadline) Thread.sleep(10)
            assertEquals("The second start must run.", 1, listeners.size)
        } finally {
            host.stop()
        }
    }

    @Test
    fun theListenerStopsWhenTheActivityReturns() {
        val harness = Harness()
        harness.host.start()
        val first = harness.listeners.single()

        harness.visible = true
        harness.host.tickNow()

        assertEquals(1, first.closeCount)
        assertTrue(!first.isRunning())

        harness.visible = false
        harness.host.tickNow()

        assertEquals(2, harness.listeners.size)
        assertTrue(harness.listeners[1].started)
    }

    @Test
    fun anIdleRunDoesNotOpenTheListener() {
        for (binding in listOf(
            sourceBinding(active = false),
            sourceBinding(state = SourceProxyState.IDLE),
            sourceBinding(port = 0),
            sourceBinding(address = "0.0.0.0"),
        )) {
            val harness = Harness(binding = binding)
            harness.host.start()
            assertEquals(0, harness.listeners.size)
        }
    }

    @Test
    fun aWaitingRunKeepsTheListener() {
        val harness = Harness(
            binding = sourceBinding(state = SourceProxyState.WAITING_FOR_NETWORK),
        )
        harness.host.start()

        assertEquals(1, harness.listeners.size)
        assertTrue(harness.listeners.single().started)
    }

    @Test
    fun aStoppedRunClosesTheListener() {
        val harness = Harness()
        harness.host.start()
        val first = harness.listeners.single()

        harness.binding = sourceBinding(active = false)
        harness.host.tickNow()

        assertEquals(1, first.closeCount)
        assertEquals(1, harness.listeners.size)
    }

    @Test
    fun aChangedHotspotAddressRebinds() {
        val harness = Harness(binding = sourceBinding(address = "192.0.2.10"))
        harness.host.start()
        val first = harness.listeners.single()

        harness.binding = sourceBinding(address = "192.0.2.11")
        harness.host.tickNow()

        assertEquals(1, first.closeCount)
        assertEquals(2, harness.listeners.size)
        assertEquals("192.0.2.11", harness.lastAddress?.hostAddress)
    }

    @Test
    fun aChangedProxyPortRebinds() {
        val harness = Harness()
        harness.host.start()
        val first = harness.listeners.single()

        harness.binding = harness.binding.copy(port = 23457)
        harness.host.tickNow()

        assertEquals(1, first.closeCount)
        assertEquals(2, harness.listeners.size)
    }

    @Test
    fun aLiveListenerDoesNotReloadTheTokenEveryTick() {
        val harness = Harness()
        harness.host.start()

        assertEquals(1, harness.tokenLoads)
        harness.host.tickNow()
        harness.host.tickNow()

        assertEquals(1, harness.tokenLoads)
    }

    @Test
    fun aChangedRunIdentityRebindsAtTheSameAddressAndPort() {
        val harness = Harness()
        harness.host.start()
        val first = harness.listeners.single()

        harness.binding = harness.binding.copy(runId = 2)
        harness.host.tickNow()

        assertEquals(1, first.closeCount)
        assertEquals(2, harness.listeners.size)
        assertEquals(2, harness.tokenLoads)
    }

    @Test
    fun aChangedTokenEpochRebindsAndReloadsTheToken() {
        val harness = Harness()
        harness.host.start()
        val first = harness.listeners.single()

        harness.token = "rotated-token"
        harness.epoch = 2
        harness.host.tickNow()

        assertEquals(1, first.closeCount)
        assertEquals(2, harness.listeners.size)
        assertEquals(2, harness.tokenLoads)
    }

    @Test
    fun aMissingTokenAfterAStoppedRunDoesNotOpen() {
        val harness = Harness()
        harness.host.start()
        val first = harness.listeners.single()

        harness.binding = sourceBinding(active = false)
        harness.host.tickNow()
        assertEquals(1, first.closeCount)

        harness.token = null
        harness.binding = sourceBinding()
        harness.host.tickNow()

        assertEquals(1, harness.listeners.size)
    }

    @Test
    fun aBindFailureIsRetriedOnTheNextTick() {
        val harness = Harness(failedStarts = 1)
        harness.host.start()

        assertEquals(1, harness.listeners.size)
        assertTrue(!harness.listeners[0].started)

        harness.host.tickNow()

        assertEquals(2, harness.listeners.size)
        assertTrue(harness.listeners[1].started)
    }

    @Test
    fun aPromptIsDeniedWithoutDisplayOrNotification() {
        val harness = Harness()
        harness.host.start()
        val listener = harness.listeners.single()
        val callback = harness.lastPrompt ?: error("the listener was not built")

        callback(PairingPrompt(PromptId(1L), 1L, "123 456"))

        assertEquals(1, listener.denied.size)
    }

    @Test
    fun stopClosesTheListenerAndDoesNotRestart() {
        val harness = Harness()
        harness.host.start()
        val listener = harness.listeners.single()

        harness.host.stop()
        harness.host.tickNow()

        assertEquals(1, listener.closeCount)
        assertEquals(1, harness.listeners.size)
    }

    private class Harness(
        var binding: SourceProxyBinding = sourceBinding(),
        var visible: Boolean = false,
        var token: String? = "test-token",
        var epoch: Long = 0L,
        private var failedStarts: Int = 0,
    ) {
        val listeners = mutableListOf<FakeListener>()
        var tokenLoads = 0
        var lastPrompt: ((PairingPrompt?) -> Unit)? = null
        var lastAddress: InetAddress? = null
        val host = BackgroundStatusHost(
            binding = { binding },
            visible = { visible },
            loadToken = {
                tokenLoads += 1
                token
            },
            trust = MemoryPairingTrustStore(),
            identity = FakeIdentity,
            clock = { 0L },
            tokenEpoch = { epoch },
            listenerFactory = { _, address, _, onPrompt ->
                lastAddress = address
                lastPrompt = onPrompt
                val fail = failedStarts > 0
                if (fail) failedStarts -= 1
                FakeListener(failStart = fail).also { listeners.add(it) }
            },
            pollMillis = 0L,
        )
    }

    private class FakeListener(
        private val failStart: Boolean = false,
    ) : PairingListener {
        var started = false
        var deactivated = false
        var closeCount = 0
        val denied = mutableListOf<PairingPrompt>()
        private var running = false

        override val localPort: Int get() = 18090
        override fun isRunning(): Boolean = running

        override fun start() {
            if (failStart) throw IllegalStateException("the bind failed")
            running = true
            started = true
        }

        override fun allow(prompt: PairingPrompt): Boolean = false

        override fun deny(prompt: PairingPrompt) {
            denied.add(prompt)
        }

        override fun activate() = Unit

        override fun deactivate() {
            deactivated = true
        }

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
        fun sourceBinding(
            address: String = "192.0.2.10",
            port: Int = 23456,
            state: SourceProxyState = SourceProxyState.RUNNING,
            active: Boolean = true,
        ): SourceProxyBinding = SourceProxyBinding(
            state = state,
            active = active,
            port = port,
            address = InetAddress.getByName(address),
        )
    }
}
