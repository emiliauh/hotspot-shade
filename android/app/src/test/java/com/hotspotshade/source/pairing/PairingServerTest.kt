package com.hotspotshade.source.pairing

import java.io.DataInputStream
import java.io.InputStream
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Loopback tests for the real pairing listener. They bind the loopback
 * address and port 0. They open no route and use no hotspot or carrier.
 */
class PairingServerTest {
    private val loopback = InetAddress.getByName("127.0.0.1")
    private val token = "server-test-token-0123456789"
    private val host = loopback as Inet4Address
    private val credentials = PairingCredentials.create(host, 1080, token)!!
    private val clock = AtomicLong(0)

    @Test
    fun allowSendsCredentialsAndRaisesTheSuccessCallback() {
        val trust = MemoryPairingTrustStore()
        val responder = responder(trust)
        val prompt = AtomicReference<PairingPrompt?>(null)
        val shown = CountDownLatch(1)
        val succeeded = AtomicInteger(0)
        val server = PairingServer(
            responder = responder,
            bindAddress = loopback,
            port = 0,
            onPromptChanged = { current ->
                prompt.set(current)
                if (current != null) shown.countDown()
            },
            onPairingSucceeded = { succeeded.incrementAndGet() },
        )
        server.start()
        try {
            assertTrue(server.localPort > 0)
            Socket().use { socket ->
                socket.soTimeout = 5_000
                socket.connect(InetSocketAddress(loopback, server.localPort), 5_000)
                val output = socket.getOutputStream()
                val target = ClientTarget()
                output.write(PairingProtocol.frame(target.hello()))
                output.flush()
                target.acceptHostChallenge(readPayload(socket.getInputStream()))

                output.write(PairingProtocol.frame(target.reveal()))
                output.flush()
                assertTrue("The prompt must appear.", shown.await(5, TimeUnit.SECONDS))
                assertNotNull(prompt.get())
                assertFalse(prompt.get()!!.toString().contains(prompt.get()!!.code))

                assertTrue(server.allow(prompt.get()!!))
                val result = readPayload(socket.getInputStream())
                val decoded = PairingProtocol.decodeResult(result)
                assertTrue(decoded is ResultMessage.Ok)
                val received = target.openResult(decoded as ResultMessage.Ok)
                assertEquals(token, received.token)
                assertEquals(1080, received.port)
                assertEquals(host, received.host)
            }
            assertEquals(1, succeeded.get())
            assertEquals(1, trust.count)
        } finally {
            server.close()
        }
    }

    @Test
    fun denySendsDeniedWithoutTrustOrSuccess() {
        val trust = MemoryPairingTrustStore()
        val responder = responder(trust)
        val prompt = AtomicReference<PairingPrompt?>(null)
        val shown = CountDownLatch(1)
        val succeeded = AtomicInteger(0)
        val server = PairingServer(
            responder = responder,
            bindAddress = loopback,
            port = 0,
            onPromptChanged = { current ->
                prompt.set(current)
                if (current != null) shown.countDown()
            },
            onPairingSucceeded = { succeeded.incrementAndGet() },
        )
        server.start()
        try {
            Socket().use { socket ->
                socket.soTimeout = 5_000
                socket.connect(InetSocketAddress(loopback, server.localPort), 5_000)
                val output = socket.getOutputStream()
                val target = ClientTarget()
                output.write(PairingProtocol.frame(target.hello()))
                output.flush()
                target.acceptHostChallenge(readPayload(socket.getInputStream()))
                output.write(PairingProtocol.frame(target.reveal()))
                output.flush()
                assertTrue(shown.await(5, TimeUnit.SECONDS))
                server.deny(prompt.get()!!)
                val result = readPayload(socket.getInputStream())
                val decoded = PairingProtocol.decodeResult(result)
                assertEquals(PairingStatus.DENIED, (decoded as ResultMessage.Status).status)
            }
            assertEquals(0, succeeded.get())
            assertEquals(0, trust.count)
        } finally {
            server.close()
        }
    }

    @Test
    fun aBadFirstFrameGetsOneRejectedResultAndAClose() {
        val trust = MemoryPairingTrustStore()
        val responder = responder(trust)
        val server = PairingServer(
            responder = responder,
            bindAddress = loopback,
            port = 0,
            onPromptChanged = { },
            onPairingSucceeded = { },
        )
        server.start()
        try {
            Socket().use { socket ->
                socket.soTimeout = 5_000
                socket.connect(InetSocketAddress(loopback, server.localPort), 5_000)
                val output = socket.getOutputStream()
                output.write(PairingProtocol.frame(byteArrayOf(1, 2, 3)))
                output.flush()
                val result = readPayload(socket.getInputStream())
                val decoded = PairingProtocol.decodeResult(result)
                assertEquals(PairingStatus.REJECTED, (decoded as ResultMessage.Status).status)
                assertEquals(-1, socket.getInputStream().read())
            }
        } finally {
            server.close()
        }
    }

    private fun responder(trust: PairingTrustStore): PairingResponder = PairingResponder(
        trust = trust,
        credentials = { credentials },
        status = {
            ProxyStatus(
                proxyRunning = false,
                foreground = true,
                connections = 0,
                port = 1080,
                host = host,
            )
        },
        identity = ServerIdentity(),
        clock = { clock.get() },
    )

    private fun readPayload(input: InputStream): ByteArray {
        val stream = DataInputStream(input)
        val length = stream.readUnsignedShort()
        assertTrue("The frame must not be empty.", length > 0)
        val payload = ByteArray(length)
        stream.readFully(payload)
        return payload
    }

    private class ServerIdentity : PairingIdentity {
        private var nonceCounter = 0

        override fun ephemeralSecret(): ByteArray = ByteArray(32) { 0x33 }

        override fun nonce(): ByteArray {
            val value = ByteArray(12) { 0x44 }
            value[1] = nonceCounter.toByte()
            nonceCounter += 1
            return value
        }
    }

    private inner class ClientTarget {
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
                throw AssertionError("The source device did not send a challenge.")
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
