package com.hotspotshade.source

import com.hotspotshade.source.pairing.MemoryPairingTrustStore
import java.io.IOException
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Deterministic tests for the source token between a proxy start, a pairing
 * result, and a rotation.
 *
 * The tests use a fresh guard and latches. They bind no route, use no hotspot,
 * and do not touch the real Keystore.
 */
class SourceTokenRaceTest {
    private val hotspot: InetAddress = InetAddress.getByName("192.168.43.1")

    @Test
    fun rotationIsRefusedWhileARunHoldsTheGuard() {
        val guard = SourceTokenGuard()
        val store = FakeTokenStore("old-token")
        val admin = admin(store, guard, "new-token")

        assertTrue(guard.beginRun())
        try {
            assertEquals(TokenRotateResult.REFUSED_RUNNING, admin.rotateToken())
            assertEquals("old-token", store.token)
        } finally {
            guard.endRun()
        }

        assertEquals(TokenRotateResult.ROTATED, admin.rotateToken())
        assertEquals("new-token", store.token)
    }

    @Test
    fun aRotationThatFinishesFirstIsTheTokenTheRunLoads() {
        val guard = SourceTokenGuard()
        val store = FakeTokenStore("old-token")
        val admin = admin(store, guard, "new-token")
        assertEquals(TokenRotateResult.ROTATED, admin.rotateToken())

        val harness = Harness(tokenStore = store, guard = guard)
        try {
            assertTrue(harness.start())
            harness.available()
            assertEquals("new-token", harness.requestedTokens.single())
        } finally {
            harness.controller.stop()
        }
    }

    @Test
    fun aStartThatLoadsFirstMakesTheRotationRefuse() {
        val guard = SourceTokenGuard()
        val store = FakeTokenStore("old-token")
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        store.loadEntered = entered
        store.releaseLoad = release
        val harness = Harness(tokenStore = store, guard = guard)
        val admin = admin(store, guard, "new-token")

        val starter = Thread({ harness.start() }, "test-proxy-start")
        starter.start()
        assertTrue("The start must hold the guard while it loads.", entered.await(5, TimeUnit.SECONDS))
        try {
            assertEquals(
                "A rotation must not replace the token under a live start.",
                TokenRotateResult.REFUSED_RUNNING,
                admin.rotateToken(),
            )
            assertEquals("old-token", store.token)
        } finally {
            release.countDown()
        }
        starter.join(5_000)
        assertFalse(starter.isAlive)
        assertEquals(SourceProxyState.WAITING_FOR_NETWORK, harness.controller.state)
        harness.controller.stop()
    }

    @Test
    fun aLatePairingSaveCannotOverwriteARotation() {
        val guard = SourceTokenGuard()
        val store = FakeTokenStore("old-token")
        val oldEpoch = guard.epoch()

        assertEquals(TokenRotateResult.ROTATED, admin(store, guard, "new-token").rotateToken())
        val saved = guard.savePairingToken(oldEpoch) { store.save("old-token") }

        assertFalse("The stale result must not be saved.", saved)
        assertEquals("new-token", store.token)
    }

    @Test
    fun aPairingSaveBeforeARotationIsReplacedByTheRotation() {
        val guard = SourceTokenGuard()
        val store = FakeTokenStore(null)
        val epoch = guard.epoch()

        assertTrue(guard.savePairingToken(epoch) { store.save("paired-token") })
        assertEquals("paired-token", store.token)
        assertEquals(TokenRotateResult.ROTATED, admin(store, guard, "new-token").rotateToken())
        assertEquals("new-token", store.token)
    }

    @Test
    fun aFailedStartReleasesTheGuardForALaterRotation() {
        val guard = SourceTokenGuard()
        val store = FakeTokenStore("old-token")
        store.failRead = true
        val harness = Harness(tokenStore = store, guard = guard)

        assertFalse(harness.start())
        assertEquals(SourceProxyStopReason.TOKEN_UNREADABLE, harness.controller.stopReason)
        assertEquals(
            "The start must not overwrite an unreadable token.",
            "old-token",
            store.token,
        )
        assertEquals(
            "A failed start must not keep the token lease.",
            TokenRotateResult.ROTATED,
            admin(store, guard, "new-token").rotateToken(),
        )
        assertEquals("new-token", store.token)
    }

    @Test
    fun aMissingTokenDoesNotBecomeAnUnreadableToken() {
        val guard = SourceTokenGuard()
        val store = FakeTokenStore(null)
        val harness = Harness(tokenStore = store, guard = guard)

        assertFalse(harness.start())
        assertEquals(SourceProxyStopReason.TOKEN_MISSING, harness.controller.stopReason)
        assertEquals(
            "A missing token must not keep the run lease.",
            TokenRotateResult.ROTATED,
            admin(store, guard, "new-token").rotateToken(),
        )
    }

    @Test
    fun aRotationFailureWritesNothingAndKeepsTheEpoch() {
        val guard = SourceTokenGuard()
        val store = FakeTokenStore("old-token")
        val epoch = guard.epoch()
        val admin = PairingAdmin(
            trust = MemoryPairingTrustStore(),
            tokenStore = TokenWriter { throw IOException("The store is full.") },
            tokenFactory = { "new-token" },
            isProxyActive = { false },
            guard = guard,
        )

        assertEquals(TokenRotateResult.FAILED, admin.rotateToken())
        assertEquals("old-token", store.token)
        assertEquals(epoch, guard.epoch())
        assertTrue(guard.savePairingToken(epoch) { store.save("paired-token") })
    }

    @Test
    fun uncertainRotationMovesEpochAndRejectsOldPairing() {
        val guard = SourceTokenGuard()
        val epoch = guard.epoch()
        val admin = admin(TokenWriter { throw TokenWriteUncertainException(IOException("sync")) }, guard, "new-token")
        assertEquals(TokenRotateResult.FAILED, admin.rotateToken())
        assertTrue(guard.epoch() > epoch)
        assertFalse(guard.savePairingToken(epoch) { throw AssertionError("stale write") })
    }
    
    private fun admin(
        store: TokenWriter,
        guard: SourceTokenGuard,
        token: String,
    ): PairingAdmin = PairingAdmin(
        trust = MemoryPairingTrustStore(),
        tokenStore = store,
        tokenFactory = { token },
        isProxyActive = { false },
        guard = guard,
    )

    private class FakeTokenStore(var token: String?) : TokenStore, TokenWriter {
        @Volatile
        var failRead = false

        @Volatile
        var loadEntered: CountDownLatch? = null

        @Volatile
        var releaseLoad: CountDownLatch? = null

        override fun load(): String? {
            loadEntered?.countDown()
            releaseLoad?.await(5, TimeUnit.SECONDS)
            if (failRead) throw TokenReadException("The stored token cannot be read.")
            return token
        }

        override fun save(token: String) {
            this.token = token
        }
    }

    private class FakeSelection : CellularNetworkSelection {
        lateinit var callback: CellularNetworkSelection.Listener

        override fun start(listener: CellularNetworkSelection.Listener) {
            callback = listener
        }

        override fun stop() = Unit
    }

    private class FakeBinding : CellularBinding {
        override fun requireAvailable() = Unit

        override fun bind(socket: Socket) = Unit

        override fun bind(socket: DatagramSocket) = Unit
    }

    private class FakeFinder(private val address: InetAddress?) : HotspotAddressFinder {
        override fun probe(): HotspotProbe = if (address == null) {
            HotspotProbe.Observed(emptyList(), emptySet())
        } else {
            HotspotProbe.Observed(
                candidates = listOf(HotspotCandidate(rank = 0, address = address)),
                excludedAddresses = emptySet(),
            )
        }
    }

    private class FakeServer : SourceServerHandle {
        override val localPort: Int = 40124

        override val activeConnections: Int = 0

        override val totalConnections: Long = 0

        override fun start() = Unit

        override fun close() = Unit
    }

    private inner class Harness(
        private val tokenStore: FakeTokenStore,
        val guard: SourceTokenGuard,
    ) {
        val selection = FakeSelection()
        val requestedTokens = mutableListOf<String>()
        val queue = ManualSourceProxyTaskQueue()
        var nowMillis = 0L
        val controller = SourceProxyController(
            tokenStore = tokenStore,
            hotspotFinder = FakeFinder(hotspot),
            selectionFactory = { selection },
            resolverFactory = { SourceHostResolver { emptyList() } },
            echoFactory = { SourceEchoSender { _, _, _ -> EchoResult(EchoStatus.FAILED) } },
            serverFactory = { _, _, _, _, token ->
                requestedTokens += token
                FakeServer()
            },
            watchFactory = {
                object : HotspotWatch {
                    override fun start(onLost: () -> Unit) = Unit

                    override fun stop() = Unit
                }
            },
            listener = SourceProxyListener { },
            tokenGuard = guard,
            taskQueueFactory = { queue },
            clockMillis = { nowMillis },
            sleepMillis = { millis -> nowMillis += millis },
        )

        fun start(): Boolean {
            val started = controller.start()
            queue.runAll()
            return started
        }

        fun available() {
            selection.callback.onAvailable(FakeBinding())
            queue.runAll()
        }
    }
}
