package com.hotspotshade.source

import com.hotspotshade.source.pairing.ChallengeOrResult
import com.hotspotshade.source.pairing.PairingKeys
import com.hotspotshade.source.pairing.PairingProtocol
import com.hotspotshade.source.pairing.PairingServer
import com.hotspotshade.source.pairing.PairingStatus
import com.hotspotshade.source.pairing.PairingTrustStore
import com.hotspotshade.source.pairing.ResultMessage
import com.hotspotshade.source.pairing.SecureRandomPairingIdentity
import com.hotspotshade.source.pairing.X25519
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Drives the real [PairingServer] and [PairingResponder] behind the background
 * host over loopback.
 *
 * These tests prove the host wiring and the status-only policy. They do not
 * open a route, a TUN device, or a hotspot interface, and a JVM pass does not
 * prove carrier or physical-device behavior.
 */
class BackgroundStatusHostWiringTest {
    private val targetPrivateKey = ByteArray(32) { 0x11 }
    private val targetPublicKey = X25519.publicKey(targetPrivateKey)!!
    private val unknownPrivateKey = ByteArray(32) { 0x55 }
    private val token = "background-status-token-0123456789"
    private val rotatedToken = "rotated-background-token-0123456789"
    private val proxyHost = InetAddress.getByName("127.0.0.1") as Inet4Address
    private val proxyPort = 23456

    @Test
    fun knownTargetGetsAnAuthenticatedStatusAnswer() {
        val harness = RealHarness()
        harness.trust.seed(targetPublicKey)
        try {
            harness.host.start()
            val listener = harness.listeners.single()
            val client = Client(listener.localPort, targetPrivateKey)
            try {
                client.beginKnownStatus()
                val status = client.readStatus()

                assertEquals(1, status.plaintext[20].toInt())
                assertEquals(0, status.plaintext[21].toInt())
                assertEquals(0, status.plaintext[22].toInt())
                assertEquals(0, status.plaintext[23].toInt())
                assertEquals(proxyPort, status.port())
                assertEquals("127.0.0.1", status.hostText())
                assertFalse(status.rawText().contains(token))
            } finally {
                client.close()
            }
            assertEquals(0, harness.trust.addCalls)
            assertEquals(0, harness.trust.removeCalls)
            assertEquals(0, harness.promptCallbacks)
        } finally {
            harness.close()
        }
    }

    @Test
    fun knownRepairIsRejectedWithoutATokenOrTrustWrite() {
        val harness = RealHarness()
        harness.trust.seed(targetPublicKey)
        try {
            harness.host.start()
            val client = Client(harness.listeners.single().localPort, targetPrivateKey)
            try {
                client.send(client.hello(flags = 0))
                val result = client.readResult()

                assertEquals(PairingStatus.REJECTED, result)
                assertFalse(client.rawText().contains(token))
            } finally {
                client.close()
            }
            assertEquals(0, harness.trust.addCalls)
            assertEquals(0, harness.trust.removeCalls)
            assertEquals(1, harness.trust.count)
            assertEquals(0, harness.promptCallbacks)
            assertEquals(0, harness.pendingPrompts)
        } finally {
            harness.close()
        }
    }

    @Test
    fun knownForgetIsRejectedWithoutATrustMutation() {
        val harness = RealHarness()
        harness.trust.seed(targetPublicKey)
        try {
            harness.host.start()
            val client = Client(harness.listeners.single().localPort, targetPrivateKey)
            try {
                client.send(client.hello(flags = 2))
                val result = client.readResult()

                assertEquals(PairingStatus.REJECTED, result)
                assertFalse(client.rawText().contains(token))
            } finally {
                client.close()
            }
            assertEquals(0, harness.trust.addCalls)
            assertEquals(0, harness.trust.removeCalls)
            assertEquals(1, harness.trust.count)
            assertEquals(0, harness.promptCallbacks)
            assertEquals(0, harness.pendingPrompts)
        } finally {
            harness.close()
        }
    }

    @Test
    fun unknownPairingAndStatusAreRejectedWithoutAPromptOrTrustWrite() {
        val harness = RealHarness()
        try {
            harness.host.start()
            val listener = harness.listeners.single()
            for (flags in listOf(0, 1, 2)) {
                val client = Client(listener.localPort, unknownPrivateKey)
                try {
                    client.send(client.hello(flags = flags))
                    val result = client.readResult()

                    assertEquals(PairingStatus.REJECTED, result)
                    assertFalse(client.rawText().contains(token))
                } finally {
                    client.close()
                }
            }
            assertEquals(0, harness.trust.addCalls)
            assertEquals(0, harness.trust.removeCalls)
            assertEquals(0, harness.trust.count)
            assertEquals(0, harness.promptCallbacks)
            assertEquals(0, harness.pendingPrompts)
        } finally {
            harness.close()
        }
    }

    @Test
    fun aChangedRunFencesTheOldListenerBeforeTheNextTick() {
        val harness = RealHarness()
        harness.trust.seed(targetPublicKey)
        try {
            harness.host.start()
            val first = harness.listeners.single()
            val client = Client(first.localPort, targetPrivateKey)
            try {
                client.beginKnownStatus()
                // A new run bounds the same address and port before the host
                // polls. The old listener must not answer for the new run.
                harness.binding = harness.binding.copy(runId = 2, connections = 1)
                assertEquals(PairingStatus.REJECTED, client.readStatusResult())

                harness.host.tickNow()

                assertFalse(first.isRunning())
                assertEquals(2, harness.listeners.size)
                assertEquals(2, harness.tokenLoads)
                assertEquals(token, harness.loadedTokens.last())
            } finally {
                client.close()
            }

            val second = harness.listeners.last()
            val fresh = Client(second.localPort, targetPrivateKey)
            try {
                fresh.beginKnownStatus()
                assertEquals(1, fresh.readStatus().plaintext[20].toInt())
            } finally {
                fresh.close()
            }
        } finally {
            harness.close()
        }
    }

    @Test
    fun aChangedTokenEpochFencesTheOldListenerAndReloadsTheToken() {
        val harness = RealHarness()
        harness.trust.seed(targetPublicKey)
        try {
            harness.host.start()
            val first = harness.listeners.single()
            val client = Client(first.localPort, targetPrivateKey)
            try {
                client.beginKnownStatus()
                harness.token = rotatedToken
                harness.epoch = 2
                assertEquals(PairingStatus.REJECTED, client.readStatusResult())

                harness.host.tickNow()

                assertFalse(first.isRunning())
                assertEquals(2, harness.listeners.size)
                assertEquals(2, harness.tokenLoads)
                assertEquals(rotatedToken, harness.loadedTokens.last())
            } finally {
                client.close()
            }

            val second = harness.listeners.last()
            val fresh = Client(second.localPort, targetPrivateKey)
            try {
                fresh.beginKnownStatus()
                assertEquals(1, fresh.readStatus().plaintext[20].toInt())
            } finally {
                fresh.close()
            }
        } finally {
            harness.close()
        }
    }

    @Test
    fun aStoppedRunRejectsAnAuthenticatedStatusBeforeTheTickClosesIt() {
        val harness = RealHarness()
        harness.trust.seed(targetPublicKey)
        try {
            harness.host.start()
            val first = harness.listeners.single()
            val client = Client(first.localPort, targetPrivateKey)
            try {
                client.beginKnownStatus()
                harness.binding = harness.binding.copy(
                    state = SourceProxyState.STOPPED,
                    active = false,
                    port = 0,
                    address = null,
                )
                assertEquals(PairingStatus.REJECTED, client.readStatusResult())

                harness.host.tickNow()
                assertFalse(first.isRunning())
                assertEquals(1, harness.listeners.size)
            } finally {
                client.close()
            }
        } finally {
            harness.close()
        }
    }

    @Test
    fun stopClosesARealListenerAndLeavesThePortClosed() {
        val harness = RealHarness()
        harness.trust.seed(targetPublicKey)
        try {
            harness.host.start()
            val first = harness.listeners.single()
            val client = Client(first.localPort, targetPrivateKey)
            try {
                client.send(client.hello(flags = 1))
                harness.host.stop()

                assertFalse(first.isRunning())
                var payload = client.readPayloadOrNull()
                var reads = 0
                while (payload != null && reads < 4) {
                    assertFalse(String(payload, Charsets.ISO_8859_1).contains(token))
                    payload = client.readPayloadOrNull()
                    reads += 1
                }
                assertNull(payload)
                harness.host.tickNow()
                assertEquals(1, harness.listeners.size)
            } finally {
                client.close()
            }
        } finally {
            harness.close()
        }
    }

    private inner class RealHarness {
        var binding: SourceProxyBinding = sourceBinding(runId = 1)
        var token: String? = this@BackgroundStatusHostWiringTest.token
        var epoch: Long = 1
        var visible: Boolean = false
        val trust = HostRecordingTrustStore()
        val listeners = CopyOnWriteArrayList<PairingServer>()
        val loadedTokens = CopyOnWriteArrayList<String?>()
        var tokenLoads = 0
        var promptCallbacks = 0
        var pendingPrompts = 0

        val host = BackgroundStatusHost(
            binding = { this.binding },
            visible = { this.visible },
            loadToken = {
                tokenLoads += 1
                loadedTokens += token
                token
            },
            trust = trust,
            identity = SecureRandomPairingIdentity(),
            clock = { System.nanoTime() / 1_000_000L },
            tokenEpoch = { epoch },
            listenerFactory = { responder, address, _, onPrompt ->
                // The host always names port 18090. A loopback test binds an
                // ephemeral port so it cannot collide with another test run.
                PairingServer(
                    responder = responder,
                    bindAddress = address,
                    port = 0,
                    onPromptChanged = { prompt ->
                        if (prompt != null) {
                            promptCallbacks += 1
                            pendingPrompts += 1
                        }
                        onPrompt(prompt)
                    },
                    idleTimeoutMillis = 5_000L,
                ).also { listeners += it }
            },
            pollMillis = 0L,
        )

        fun close() {
            host.stop()
            for (listener in listeners) {
                try {
                    listener.close()
                } catch (_: Exception) {
                    // The listener is already closing.
                }
            }
        }
    }

    private inner class Client(
        port: Int,
        privateKey: ByteArray,
    ) : AutoCloseable {
        private val socket = Socket().apply {
            connect(InetSocketAddress(InetAddress.getByName("127.0.0.1"), port), 2_000)
            soTimeout = 3_000
            tcpNoDelay = true
        }
        private val input = DataInputStream(socket.getInputStream())
        private val output = DataOutputStream(socket.getOutputStream())
        private val lSPrivate = privateKey
        private val lEPrivate = ByteArray(32) { 0x22 }
        private val lS = X25519.publicKey(lSPrivate)!!
        private val lE = X25519.publicKey(lEPrivate)!!
        private var pE: ByteArray? = null
        private var keys: PairingKeys? = null
        private var nonceCounter = 0
        private val lastRaw = ArrayList<Byte>()

        fun hello(flags: Int? = null): ByteArray {
            val message = PairingProtocol.encodeHello(
                lS,
                PairingProtocol.commitment(lE, lS),
            )
            return if (flags == null) message else message + byteArrayOf(flags.toByte())
        }

        fun send(payload: ByteArray) {
            output.write(PairingProtocol.frame(payload))
            output.flush()
        }

        fun beginKnownStatus() {
            send(hello(flags = 1))
            val challenge = PairingProtocol.decodeChallenge(readPayload())
            if (challenge !is ChallengeOrResult.Challenge) {
                throw AssertionError("The listener did not send a known challenge.")
            }
            pE = challenge.pE
            val publicEphemeral = pE ?: throw AssertionError("No challenge.")
            val ee = X25519.agree(lEPrivate, publicEphemeral)!!
            val es = X25519.agree(lSPrivate, publicEphemeral)!!
            val derived = PairingProtocol.deriveKeys(
                ee,
                es,
                PairingProtocol.transcriptHash(lS, lE, publicEphemeral),
            )
            ee.fill(0)
            es.fill(0)
            keys = derived
            send(
                PairingProtocol.encodeReveal(
                    lE,
                    PairingProtocol.laptopProof(derived),
                ),
            )
        }

        fun readStatus(): StatusAnswer {
            val plaintext = readStatusPlaintext()
            return StatusAnswer(plaintext)
        }

        fun readStatusResult(): PairingStatus {
            sendStatusRequest()
            val result = readResult()
            return result
        }

        private fun readStatusPlaintext(): ByteArray {
            sendStatusRequest()
            val message = readPayload()
            if ((message[0].toInt() and 0xFF) != PairingProtocol.MSG_STATUS) {
                throw AssertionError("The listener did not answer with STATUS.")
            }
            val nonce = message.copyOfRange(1, 13)
            val ciphertext = message.copyOfRange(13, message.size)
            return PairingProtocol.openMessage(keys!!, nonce, ciphertext)
                ?: throw AssertionError("The status answer did not open.")
        }

        private fun sendStatusRequest() {
            nonceCounter += 1
            val nonce = ByteArray(12)
            nonce[0] = nonceCounter.toByte()
            val challenge = ByteArray(16) { 0x55 }
            val plaintext = challenge + byteArrayOf(0)
            send(
                byteArrayOf(PairingProtocol.MSG_STATUS_REQ.toByte()) + nonce +
                    PairingProtocol.sealMessage(keys!!, nonce, plaintext),
            )
        }

        fun readResult(): PairingStatus {
            val message = readPayload()
            val decoded = PairingProtocol.decodeResult(message)
                ?: throw AssertionError("The listener did not send a RESULT.")
            return when (decoded) {
                is ResultMessage.Status -> decoded.status
                is ResultMessage.Ok -> throw AssertionError("An OK result carried credentials.")
            }
        }

        fun readPayloadOrNull(): ByteArray? = try {
            readPayload()
        } catch (_: IOException) {
            null
        }

        fun rawText(): String = synchronized(lastRaw) {
            lastRaw.toByteArray().toString(Charsets.ISO_8859_1)
        }

        private fun readPayload(): ByteArray {
            val length = input.readUnsignedShort()
            if (length == 0 || length > PairingProtocol.MAX_FRAME) {
                throw IOException("The frame length is invalid.")
            }
            val payload = ByteArray(length)
            input.readFully(payload)
            synchronized(lastRaw) {
                lastRaw += payload.toList()
            }
            return payload
        }

        override fun close() {
            try {
                socket.close()
            } catch (_: IOException) {
                // The socket is already closing.
            }
        }
    }

    private class StatusAnswer(val plaintext: ByteArray) {
        fun port(): Int =
            ((plaintext[24].toInt() and 0xFF) shl 8) or (plaintext[25].toInt() and 0xFF)

        fun hostText(): String {
            val length = plaintext[26].toInt() and 0xFF
            return String(plaintext, 27, length, Charsets.US_ASCII)
        }

        fun rawText(): String = String(plaintext, Charsets.ISO_8859_1)
    }

    /** A trust store that counts the mutations that the responder makes. */
    private class HostRecordingTrustStore : PairingTrustStore {
        private val lock = Any()
        private val keys = LinkedHashSet<String>()
        var addCalls = 0
        var removeCalls = 0

        fun seed(publicKey: ByteArray) {
            synchronized(lock) { keys.add(PairingProtocol.hex(publicKey)) }
        }

        override fun contains(publicKey: ByteArray): Boolean =
            synchronized(lock) { keys.contains(PairingProtocol.hex(publicKey)) }

        override fun add(publicKey: ByteArray) {
            synchronized(lock) {
                addCalls += 1
                keys.add(PairingProtocol.hex(publicKey))
            }
        }

        override fun remove(publicKey: ByteArray) {
            synchronized(lock) {
                removeCalls += 1
                keys.remove(PairingProtocol.hex(publicKey))
            }
        }

        override val count: Int
            get() = synchronized(lock) { keys.size }
    }

    private fun sourceBinding(runId: Long): SourceProxyBinding = SourceProxyBinding(
        state = SourceProxyState.RUNNING,
        active = true,
        port = proxyPort,
        address = proxyHost,
        runId = runId,
    )
}
