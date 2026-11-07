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
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Serve the real pairing coordinator for the target lifecycle interop test.
 *
 * The emulator has no hotspot interface. This test uses the test-only
 * [TestOnlyHotspotFinder] from the androidTest source set, which reports the
 * loopback address. A release build does not compile that finder.
 *
 * The coordinator binds port 0 and prints the bound port with the
 * `HS_PAIRING_LIFECYCLE` tag. The host forwards TCP port 18090 to the guest
 * listener and runs `rust/tests/android_pairing_interop.rs`. The public
 * `status` and `forget_attempt` target-device clients use the fixed pairing
 * port 18090, so the host forward must use 18090.
 *
 * The host drives this sequence:
 *
 * 1. An unknown target device pairs. This fixture approves the one prompt.
 * 2. The same trusted key pairs again and must not prompt.
 * 3. The trusted key asks for status and receives the fixed proxy values.
 * 4. An unknown key asks for status and is rejected.
 * 5. The trusted key sends FORGET. The real responder removes the key.
 * 6. The same key asks for status again and is rejected.
 *
 * The fixture approves only its first prompt and denies every later prompt. A
 * known-key second pairing that prompted anyway would therefore fail on the
 * host with `Phone(Denied)` instead of being silently approved. At the end of
 * the run the fixture asserts exact counts: two completed pairings, one
 * prompt, no denials, and no trusted target left.
 *
 * The fixture counts OK results that the real listener delivered, not token
 * writes. The in-memory store already holds the fixed token, so a pairing that
 * verifies the same value saves nothing. One listener connection can seal at
 * most one OK result, so two results prove two completed pairings.
 *
 * The remote FORGET answer is a plaintext v1 RESULT. This fixture uses an
 * in-memory trust store, so the follow-up status proves that this run no
 * longer trusts the key. It does not prove durable remote revocation.
 *
 * This is a loopback interop test. It does not prove hotspot-only binding,
 * carrier behavior, physical-device behavior, or durable token storage.
 */
@RunWith(AndroidJUnit4::class)
class PairingLifecycleInteropTest {
    private companion object {
        const val TAG = "HS_PAIRING_LIFECYCLE"
        const val TOKEN = "emulator-pairing-token"
        const val PROXY_PORT = 1080
        const val STOP_FILE = "hs-pairing-lifecycle-stop"
        const val SERVE_TIMEOUT_MILLIS = 120_000L
        const val EXPECTED_PAIRINGS = 2
        const val EXPECTED_PROMPTS = 1
    }

    @Test
    fun servePairingLifecycleUntilStopFileOrTimeout() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val stop = File(context.filesDir, STOP_FILE)
        stop.delete()
        // The authenticated status answer reads the proxy binding. Clear any
        // report left by an earlier test so this run reports no live proxy.
        SourceProxyRuntime.resetObservation()
        val tokenStore = LifecycleTokenStore(TOKEN)
        val trust = MemoryPairingTrustStore()
        val pairings = AtomicInteger(0)
        val prompts = AtomicInteger(0)
        val denials = AtomicInteger(0)
        val coordinatorRef = AtomicReference<PairingCoordinator?>(null)
        val approver = Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "pairing-lifecycle-approver").apply { isDaemon = true }
        }
        val coordinator = PairingCoordinator(
            finder = TestOnlyHotspotFinder(TestOnlyHotspot.LOOPBACK),
            tokenStore = tokenStore,
            tokenWriter = tokenStore,
            trust = trust,
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
                    val seen = prompts.incrementAndGet()
                    // Approve only the first, unknown-target prompt. A later
                    // prompt means the trusted key was not recognized. Deny
                    // it, so the host sees a failed pairing instead of a
                    // second prompt that the automated fixture approved.
                    approver.execute {
                        if (seen == EXPECTED_PROMPTS) {
                            coordinatorRef.get()?.allow(prompt)
                        } else {
                            denials.incrementAndGet()
                            coordinatorRef.get()?.deny(prompt)
                        }
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
            // A stop file can arrive between the delivered result and its
            // callback. Wait a short bounded time so the exact pairing count
            // does not depend on that ordering. A stopped listener cannot
            // finish a pairing, so it does not wait.
            if (ending != "server stop") {
                val settle = System.nanoTime() + Duration.ofSeconds(5).toNanos()
                while (pairings.get() < EXPECTED_PAIRINGS && System.nanoTime() < settle) {
                    Thread.sleep(50)
                }
            }
            Log.i(
                TAG,
                "ending=$ending pairings=${pairings.get()} prompts=${prompts.get()} " +
                    "denials=${denials.get()} trusted=${trust.count}",
            )
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
        assertEquals(
            "The real target client must complete exactly two pairings.",
            EXPECTED_PAIRINGS.toLong(),
            pairings.get().toLong(),
        )
        assertEquals(
            "The unknown first pairing must prompt exactly once.",
            EXPECTED_PROMPTS.toLong(),
            prompts.get().toLong(),
        )
        assertEquals(
            "A trusted-key pairing must not prompt again.",
            0L,
            denials.get().toLong(),
        )
        assertEquals(
            "The remote Forget must remove the only trusted target.",
            0L,
            trust.count.toLong(),
        )
    }

    /**
     * Hold the fixed public test token in memory. The test writes no token to
     * storage or a log.
     *
     * The store already holds the token, so a pairing that verifies the same
     * value saves nothing. The fixture never writes the token to disk.
     */
    private class LifecycleTokenStore(private val token: String) : TokenStore, TokenWriter {
        override fun load(): String = token

        override fun save(token: String) = Unit
    }
}
