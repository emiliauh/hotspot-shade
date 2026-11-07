package com.hotspotshade.source

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.hotspotshade.source.pairing.MemoryPairingTrustStore
import com.hotspotshade.source.pairing.PairingPrompt
import com.hotspotshade.source.pairing.PairingServer
import java.io.File
import java.net.InetAddress
import java.time.Duration
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Serve the real pairing coordinator on the emulator loopback for one host run.
 *
 * The emulator has no hotspot interface. This test uses the test-only
 * [TestOnlyHotspotFinder] from the androidTest source set. The finder reports
 * the loopback address. A release build does not compile that finder.
 *
 * The coordinator binds port 0 and prints the bound port with the
 * `HS_PAIRING_INTEROP` tag. The host forwards a TCP port to the guest and runs
 * `rust/tests/android_pairing_interop.rs` with the real target `pair_at`
 * client. This test approves each prompt automatically, because no person can
 * tap the emulator screen during the automated run.
 *
 * The fixture counts the OK results that the real listener delivered, not the
 * token writes. The store already holds the fixed token, so a pairing that
 * verifies the same durable token saves nothing. The first pairing is unknown
 * and prompts. The second pairing uses the trusted key and prompts no one.
 * One listener connection can seal at most one OK result, so two results prove
 * two completed pairings.
 *
 * This is a loopback interop test. It does not prove hotspot-only binding,
 * carrier behavior, or physical-device behavior.
 */
@RunWith(AndroidJUnit4::class)
class PairingInteropTest {
    private companion object {
        const val TAG = "HS_PAIRING_INTEROP"
        const val TOKEN = "emulator-pairing-token"
        const val PROXY_PORT = 1080
        const val STOP_FILE = "hs-pairing-interop-stop"
        const val SERVE_TIMEOUT_MILLIS = 120_000L
        const val REQUIRED_PAIRINGS = 2
    }

    @Test
    fun serveRealPairingsUntilStopFileOrTimeout() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val stop = File(context.filesDir, STOP_FILE)
        stop.delete()
        val tokenStore = TestTokenStore(TOKEN)
        val pairings = AtomicInteger(0)
        val prompts = AtomicInteger(0)
        val coordinatorRef = AtomicReference<PairingCoordinator?>(null)
        val approver = Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "pairing-interop-approver").apply { isDaemon = true }
        }
        val coordinator = PairingCoordinator(
            finder = TestOnlyHotspotFinder(TestOnlyHotspot.LOOPBACK),
            tokenStore = tokenStore,
            tokenWriter = tokenStore,
            trust = MemoryPairingTrustStore(),
            ports = ProxyPortPolicy(
                store = object : ProxyPortStore {
                    override fun load(): Int = PROXY_PORT

                    override fun save(port: Int) = Unit

                    override fun clear() = Unit
                },
                probe = object : PortProbe {
                    override fun isFree(address: InetAddress, port: Int): Boolean = true

                    override fun freePort(address: InetAddress): Int = PROXY_PORT
                },
            ),
            onPrompt = { prompt: PairingPrompt? ->
                if (prompt != null) {
                    prompts.incrementAndGet()
                    approver.execute {
                        coordinatorRef.get()?.allow(prompt)
                    }
                }
            },
            onState = { _, _ -> },
            clock = { android.os.SystemClock.elapsedRealtime() },
            pairingPort = 0,
            // Count the OK results that the real listener delivered. A
            // pairing that verifies the stored token writes nothing, so a
            // writer count cannot prove that a pairing completed. The
            // listener seals one OK result per handshake, so the count names
            // completed pairings.
            listenerFactory = {
                    responder,
                    bindAddress,
                    port,
                    onPromptChanged,
                    _,
                    onTokenCommitFailed,
                ->
                PairingServer(
                    responder = responder,
                    bindAddress = bindAddress,
                    port = port,
                    onPromptChanged = onPromptChanged,
                    onPairingSucceeded = { pairings.incrementAndGet() },
                    onTokenCommitFailed = onTokenCommitFailed,
                )
            },
        )
        coordinatorRef.set(coordinator)
        var ending = "timeout"
        try {
            coordinator.start()
            var port = 0
            val deadline = System.nanoTime() + Duration.ofMillis(SERVE_TIMEOUT_MILLIS).toNanos()
            while (port <= 0 && System.nanoTime() < deadline) {
                port = coordinator.localPort
                if (port <= 0) Thread.sleep(20)
            }
            if (port <= 0) throw AssertionError("The pairing listener did not bind a port.")
            Log.i(TAG, "listening port=$port")
            Log.i(TAG, "stop file=${stop.absolutePath}")
            while (System.nanoTime() < deadline) {
                if (pairings.get() >= REQUIRED_PAIRINGS) break
                if (stop.exists()) {
                    ending = "stop file"
                    break
                }
                if (coordinator.localPort <= 0) {
                    ending = "server stop"
                    break
                }
                Thread.sleep(100)
            }
            if (ending == "timeout" && pairings.get() >= REQUIRED_PAIRINGS) {
                ending = "pairings complete"
                while (!stop.exists() && System.nanoTime() < deadline) {
                    Thread.sleep(100)
                }
            }
            // A stop file can arrive between the delivered result and its
            // callback. Wait a short bounded time so the assertion does not
            // depend on that ordering. A stopped listener cannot finish a
            // pairing, so it does not wait.
            if (ending != "server stop") {
                val settle = System.nanoTime() + Duration.ofSeconds(5).toNanos()
                while (pairings.get() < REQUIRED_PAIRINGS && System.nanoTime() < settle) {
                    Thread.sleep(50)
                }
            }
            Log.i(TAG, "pairings=${pairings.get()} prompts=${prompts.get()}")
        } finally {
            coordinator.stop()
            approver.shutdownNow()
            stop.delete()
        }
        Log.i(TAG, "served until $ending")
        assertTrue(
            "The listener stopped before the host ended the test.",
            ending != "server stop",
        )
        assertTrue(
            "The real target client must complete two pairings. " +
                "Completed pairings: ${pairings.get()}.",
            pairings.get() >= REQUIRED_PAIRINGS,
        )
        assertTrue(
            "The first pairing must come from an unknown target device. " +
                "Prompts: ${prompts.get()}.",
            prompts.get() >= 1,
        )
    }

    /**
     * Hold the fixed public test token in memory. The test writes no token to
     * storage or a log.
     *
     * The store already holds the token, so a pairing that verifies the same
     * durable value saves nothing. That is the production behavior, and this
     * test does not count saves.
     */
    private class TestTokenStore(private val token: String) : TokenStore, TokenWriter {
        override fun load(): String = token

        override fun save(token: String) = Unit
    }
}
