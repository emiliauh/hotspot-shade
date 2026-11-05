package com.hotspotshade.source

import com.hotspotshade.source.pairing.ChallengeOrResult
import com.hotspotshade.source.pairing.MemoryPairingTrustStore
import com.hotspotshade.source.pairing.PairingCredentials
import com.hotspotshade.source.pairing.PairingIdentity
import com.hotspotshade.source.pairing.PairingKeys
import com.hotspotshade.source.pairing.PairingPrompt
import com.hotspotshade.source.pairing.PairingProtocol
import com.hotspotshade.source.pairing.ResultMessage
import com.hotspotshade.source.pairing.X25519
import java.io.DataInputStream
import java.io.InputStream
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Integration test for the real coordinator on loopback.
 *
 * It proves that a successful pairing saves the token with [TokenWriter], so
 * the source proxy start finds a token instead of `TOKEN_MISSING`.
 */
class PairingCoordinatorTest {
    private val loopback = InetAddress.getByName("127.0.0.1")

    @Test
    fun aSuccessfulPairingSavesTheToken() {
        val store = FakeStore()
        val prompt = AtomicReference<PairingPrompt?>(null)
        val shown = CountDownLatch(1)
        val states = mutableListOf<PairingListenerState>()
        val coordinator = PairingCoordinator(
            finder = object : HotspotAddressFinder {
                override fun findHotspotAddress(): InetAddress = loopback
            },
            tokenStore = store,
            tokenWriter = store,
            trust = MemoryPairingTrustStore(),
            ports = ProxyPortPolicy(
                store = object : ProxyPortStore {
                    private var port = 0

                    override fun load(): Int = port

                    override fun save(port: Int) {
                        this.port = port
                    }

                    override fun clear() {
                        port = 0
                    }
                },
                probe = object : PortProbe {
                    override fun isFree(address: InetAddress, port: Int): Boolean = true

                    override fun freePort(address: InetAddress): Int = 1080
                },
            ),
            onPrompt = { current ->
                prompt.set(current)
                if (current != null) shown.countDown()
            },
            onState = { state, _ ->
                synchronized(states) { states.add(state) }
            },
            clock = { 0L },
            identity = TestIdentity(),
            pairingPort = 0,
        )
        coordinator.start()
        try {
            val port = waitForPort(coordinator)
            assertTrue(port > 0)
            Socket().use { socket ->
                socket.soTimeout = 5_000
                socket.connect(InetSocketAddress(loopback, port), 5_000)
                val output = socket.getOutputStream()
                val target = Target()
                output.write(PairingProtocol.frame(target.hello()))
                output.flush()
                target.acceptHostChallenge(readPayload(socket.getInputStream()))
                output.write(PairingProtocol.frame(target.reveal()))
                output.flush()
                assertTrue("The real prompt must appear.", shown.await(5, TimeUnit.SECONDS))
                assertNotNull(prompt.get())
                coordinator.allow(prompt.get()!!)
                val result = PairingProtocol.decodeResult(readPayload(socket.getInputStream()))
                assertTrue(result is ResultMessage.Ok)
                val credentials = target.openResult(result as ResultMessage.Ok)
                assertEquals(store.saved, credentials.token)
                assertEquals(store.saved, store.load())
                assertTrue(store.saved!!.isNotEmpty())
            }
        } finally {
            coordinator.stop()
        }
        assertTrue(
            "The coordinator must report a stopped listener.",
            synchronized(states) { states.contains(PairingListenerState.STOPPED) },
        )
    }

    private fun waitForPort(coordinator: PairingCoordinator): Int {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (System.nanoTime() < deadline) {
            val port = coordinator.localPort
            if (port > 0) return port
            Thread.sleep(20)
        }
        return 0
    }

    private fun readPayload(input: InputStream): ByteArray {
        val stream = DataInputStream(input)
        val length = stream.readUnsignedShort()
        assertTrue(length > 0)
        val payload = ByteArray(length)
        stream.readFully(payload)
        return payload
    }

    private class FakeStore : TokenStore, TokenWriter {
        var saved: String? = null
            private set

        override fun load(): String? = saved

        override fun save(token: String) {
            saved = token
        }
    }

    private class TestIdentity : PairingIdentity {
        private var counter = 0

        override fun ephemeralSecret(): ByteArray = ByteArray(32) { 0x33 }

        override fun nonce(): ByteArray {
            val value = ByteArray(12) { 0x44 }
            value[1] = counter.toByte()
            counter += 1
            return value
        }
    }

    private inner class Target {
        private val lSSecret = ByteArray(32) { 0x11 }
        private val lESecret = ByteArray(32) { 0x22 }
        private val lS = X25519.publicKey(lSSecret)!!
        private val lE = X25519.publicKey(lESecret)!!
        private var pE: ByteArray? = null
        private var keys: PairingKeys? = null

        fun hello(): ByteArray =
            PairingProtocol.encodeHello(lS, PairingProtocol.commitment(lE, lS))

        fun acceptHostChallenge(payload: ByteArray) {
            val decoded = PairingProtocol.decodeChallenge(payload)
            if (decoded !is ChallengeOrResult.Challenge) {
                throw AssertionError("The app did not send a challenge.")
            }
            pE = decoded.pE
        }

        fun reveal(): ByteArray {
            val publicEphemeral = pE ?: throw AssertionError("No challenge.")
            val ee = X25519.agree(lESecret, publicEphemeral)!!
            val es = X25519.agree(lSSecret, publicEphemeral)!!
            val derived = PairingProtocol.deriveKeys(
                ee,
                es,
                PairingProtocol.transcriptHash(lS, lE, publicEphemeral),
            )
            ee.fill(0)
            es.fill(0)
            keys = derived
            return PairingProtocol.encodeReveal(lE, PairingProtocol.laptopProof(derived))
        }

        fun openResult(message: ResultMessage.Ok): PairingCredentials =
            PairingProtocol.openCredentials(keys!!, message.nonce, message.ciphertext)
    }
}
