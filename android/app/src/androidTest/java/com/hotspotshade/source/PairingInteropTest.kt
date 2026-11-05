package com.hotspotshade.source

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.hotspotshade.source.pairing.MemoryPairingTrustStore
import com.hotspotshade.source.pairing.PairingCredentials
import com.hotspotshade.source.pairing.PairingProtocol
import com.hotspotshade.source.pairing.PairingResponder
import com.hotspotshade.source.pairing.PairingServer
import com.hotspotshade.source.pairing.ProxyStatus
import com.hotspotshade.source.pairing.SecureRandomPairingIdentity
import java.io.File
import java.net.Inet4Address
import java.net.InetAddress
import java.time.Duration
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Serve the real pairing protocol on the emulator loopback for one host run.
 *
 * The listener binds 127.0.0.1 with port 0 and prints the bound port with the
 * `HS_PAIRING_INTEROP` tag. The host forwards a TCP port to the guest and runs
 * `rust/tests/android_pairing_interop.rs` with the real target `pair_at`
 * client. This test approves each prompt automatically, because no person can
 * tap the emulator screen during the automated run.
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
        val loopback = InetAddress.getByName("127.0.0.1")
        val credentials = PairingCredentials.create(
            loopback as Inet4Address,
            PROXY_PORT,
            TOKEN,
        ) ?: throw AssertionError("The fixed test credentials are not usable.")
        val trust = MemoryPairingTrustStore()
        val responder = PairingResponder(
            trust = trust,
            credentials = { credentials },
            status = {
                ProxyStatus(
                    proxyRunning = false,
                    foreground = true,
                    connections = 0,
                    port = PROXY_PORT,
                    host = loopback,
                )
            },
            identity = SecureRandomPairingIdentity(),
            clock = { android.os.SystemClock.elapsedRealtime() },
        )
        val serverRef = AtomicReference<PairingServer?>(null)
        val pairings = AtomicInteger(0)
        val approver = Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "pairing-interop-approver").apply { isDaemon = true }
        }
        val server = PairingServer(
            responder = responder,
            bindAddress = loopback,
            port = 0,
            onPromptChanged = { prompt ->
                if (prompt != null) {
                    approver.execute {
                        serverRef.get()?.allow(prompt)
                    }
                }
            },
            onPairingSucceeded = { pairings.incrementAndGet() },
        )
        serverRef.set(server)
        var ending = "timeout"
        try {
            server.start()
            Log.i(TAG, "listening port=${server.localPort}")
            Log.i(TAG, "stop file=${stop.absolutePath}")
            val deadline = System.nanoTime() + Duration.ofMillis(SERVE_TIMEOUT_MILLIS).toNanos()
            while (System.nanoTime() < deadline) {
                if (pairings.get() >= REQUIRED_PAIRINGS) break
                if (stop.exists()) {
                    ending = "stop file"
                    break
                }
                if (!server.isRunning()) {
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
            Log.i(TAG, "pairings=${pairings.get()} trusted=${trust.count}")
        } finally {
            server.close()
            approver.shutdownNow()
            stop.delete()
        }
        Log.i(TAG, "served until $ending")
        assertTrue(
            "The listener stopped before the host ended the test.",
            ending != "server stop",
        )
        assertTrue(
            "The real target client must complete two pairings. Pairings: ${pairings.get()}.",
            pairings.get() >= REQUIRED_PAIRINGS,
        )
    }
}
