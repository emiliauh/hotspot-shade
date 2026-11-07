package com.hotspotshade.source.pairing

import java.net.Inet4Address
import java.net.InetAddress
import java.util.Random
import java.util.concurrent.atomic.AtomicLong
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Malformed-frame and state-machine fuzzing for the pairing parser and
 * responder. The tests assert that only [PairingException] escapes, that the
 * session and budget maps stay bounded, and that no unapproved key becomes
 * trusted.
 */
class MalformedFrameFuzzTest {
    private val host = InetAddress.getByName("172.20.10.1") as Inet4Address
    private val token = "test-token-0123456789abcdef"
    private val credentials = PairingCredentials.create(host, 1080, token)!!
    private val status = ProxyStatus(
        proxyRunning = true,
        foreground = true,
        connections = 0,
        port = 1080,
        host = host,
    )

    @Test
    fun randomDecoderInputsDoNotEscapeAsUncheckedExceptions() {
        val random = Random(0x5EED)
        repeat(2500) { index ->
            val bytes = ByteArray(random.nextInt(600)).also(random::nextBytes)
            assertOnlyPairingException("decodeHello $index") { PairingProtocol.decodeHello(bytes) }
            assertOnlyPairingException("decodeChallenge $index") { PairingProtocol.decodeChallenge(bytes) }
            assertOnlyPairingException("decodeResult $index") { PairingProtocol.decodeResult(bytes) }
            assertOnlyPairingException("decodeReveal $index") { PairingProtocol.decodeReveal(bytes) }
            assertOnlyPairingException("decodeCredentials $index") { PairingProtocol.decodeCredentials(bytes) }
            val peer = buildString {
                repeat(random.nextInt(80)) {
                    append((0x21 + random.nextInt(0x5E)).toChar())
                }
            }
            assertOnlyPairingException("canonical $index") { PeerAddress.canonical(peer) }
            assertOnlyPairingException("frame $index") { PairingProtocol.frame(bytes) }
        }
    }

    @Test
    fun frameReaderStaysBoundedUnderRandomChunks() {
        val random = Random(0xF00D)
        repeat(500) { round ->
            val reader = PairingFrameReader()
            var stop = false
            while (!stop) {
                val chunk = ByteArray(random.nextInt(1200)).also(random::nextBytes)
                try {
                    reader.push(chunk)
                } catch (_: PairingException) {
                    assertTrue(reader.bufferedLength() <= PairingProtocol.MAX_BUFFERED)
                    stop = true
                    continue
                }
                while (true) {
                    val frame = try {
                        reader.nextFrame()
                    } catch (_: PairingException) {
                        stop = true
                        break
                    } ?: break
                    assertTrue("round $round", frame.isNotEmpty())
                    assertTrue("round $round", frame.size <= PairingProtocol.MAX_FRAME)
                }
                assertTrue(reader.bufferedLength() <= PairingProtocol.MAX_BUFFERED)
                if (random.nextInt(50) == 0) stop = true
            }
        }
    }

    @Test
    fun frameReaderDrainsSeveralMaximumFrames() {
        val random = Random(0xBEEF)
        val reader = PairingFrameReader()
        val payloads = List(4) { index -> ByteArray(PairingProtocol.MAX_FRAME) { (index + 1).toByte() } }
        val stream = payloads.map { PairingProtocol.frame(it) }.reduce { a, b -> a + b }
        var offset = 0
        while (offset < stream.size) {
            val count = minOf(1 + random.nextInt(37), stream.size - offset)
            reader.push(stream.copyOfRange(offset, offset + count))
            offset += count
        }
        for (payload in payloads) {
            assertArrayEquals(payload, reader.nextFrame())
        }
        assertNull(reader.nextFrame())
    }

    @Test
    fun responderSurvivesRandomFramesAndNeverTrustsWithoutADecision() {
        val trust = MemoryPairingTrustStore()
        val clock = AtomicLong(0)
        val responder = PairingResponder(
            trust = trust,
            credentials = { credentials },
            status = { status },
            identity = CounterIdentity(),
            clock = { clock.get() },
        )
        val random = Random(0x1234_5678)
        val peers = listOf(
            "10.0.0.1",
            "10.0.0.2",
            "192.0.2.9",
            "2001:db8::1",
            "2001:0db8:0000:0000:0000:0000:0000:0001",
        )
        repeat(4000) { index ->
            val connection = random.nextInt(12).toLong()
            val peer = peers[random.nextInt(peers.size)]
            val frame = when (random.nextInt(12)) {
                0 -> PairingProtocol.encodeHello(randomBytes(random, 32), randomBytes(random, 32))
                1 -> PairingProtocol.encodeHello(randomBytes(random, 32), randomBytes(random, 32)) +
                    byteArrayOf(random.nextInt(4).toByte())
                2 -> PairingProtocol.encodeReveal(randomBytes(random, 32), randomBytes(random, 32))
                3 -> PairingProtocol.encodeResultStatus(
                    PairingStatus.entries[random.nextInt(PairingStatus.entries.size)],
                )
                else -> randomBytes(random, random.nextInt(600))
            }
            try {
                responder.receive(connection, frame, peer, random.nextBoolean())
            } catch (_: PairingException) {
                // A fixed protocol error is allowed. Any other exception fails.
            } catch (failure: Throwable) {
                throw AssertionError("iteration $index threw ${failure.javaClass.name}: ${failure.message}", failure)
            }
            assertTrue(responder.activeSessions() in 0..4)
            assertTrue(responder.promptFailureCount() >= 0)
            assertTrue(responder.trackedInvalidPeers() <= 256)
            responder.pendingPrompt()?.let { prompt ->
                assertTrue(prompt.code.matches(Regex("\\d{3} \\d{3}")))
                assertFalse(prompt.toString().contains(prompt.code))
            }
            if (index % 17 == 0) {
                try {
                    responder.tick()
                } catch (_: PairingException) {
                    // A fixed clock error is allowed.
                }
            }
            if (index % 31 == 0) responder.connectionClosed(connection)
        }
        assertEquals(0, trust.count)
    }

    @Test
    fun authenticatedSessionsRejectRandomCommandsWithoutChangingTrust() {
        val trust = MemoryPairingTrustStore()
        val clock = AtomicLong(0)
        val lS = X25519.publicKey(ByteArray(32) { 0x11 })!!
        trust.add(lS)
        val responder = PairingResponder(
            trust = trust,
            credentials = { credentials },
            status = { status },
            identity = CounterIdentity(),
            clock = { clock.get() },
        )
        val random = Random(0xABCD)
        for (iteration in 0 until 24) {
            val target = Target(lS)
            val flags = iteration % 3
            val connection = 1000L + iteration
            val challengeOutput = responder.receive(connection, target.hello(flags), "10.0.0.9", true)
            target.acceptChallenge(challengeOutput)
            val revealOutput = responder.receive(connection, target.reveal(), "10.0.0.9", true)
            if (flags == 0) {
                assertEquals(PairingStatus.OK, revealOutput.status)
            } else {
                assertTrue(revealOutput.frames.isEmpty())
            }

            val messageType = if (flags == 2) PairingProtocol.MSG_FORGET else PairingProtocol.MSG_STATUS_REQ
            val randomCommand = byteArrayOf(messageType.toByte()) +
                randomBytes(random, 12) +
                randomBytes(random, 16 + random.nextInt(64))
            try {
                responder.receive(connection, randomCommand, "10.0.0.9", true)
            } catch (_: PairingException) {
                // A fixed protocol error is allowed.
            } catch (failure: Throwable) {
                throw AssertionError("command $iteration threw ${failure.javaClass.name}", failure)
            }
            assertTrue(trust.contains(lS))
            responder.connectionClosed(connection)
        }
    }

    /**
     * Ten malformed frames from one peer must start the invalid-message
     * backoff. The next valid HELLO from that peer must get RESULT REJECTED,
     * not a CHALLENGE. A prune that removes the active budget would fail this
     * test open.
     */
    @Test
    fun invalidMessageBackoffRejectsTheNextHello() {
        val trust = MemoryPairingTrustStore()
        val clock = AtomicLong(0)
        val responder = PairingResponder(
            trust = trust,
            credentials = { credentials },
            status = { status },
            identity = CounterIdentity(),
            clock = { clock.get() },
        )
        val badFrame = byteArrayOf(0x00)
        repeat(10) {
            responder.receive(1000L + it, badFrame, "10.0.0.1", true)
        }
        val hello = PairingProtocol.encodeHello(
            ByteArray(32) { 0x11 },
            ByteArray(32) { 0x22 },
        )
        val output = responder.receive(2000, hello, "10.0.0.1", true)
        val payload = payload(output)
        assertEquals(PairingProtocol.MSG_RESULT, payload[0].toInt() and 0xFF)
        assertEquals(PairingStatus.REJECTED.wire, payload[1].toInt() and 0xFF)
        assertEquals(0, trust.count)
    }

    @Test
    fun invalidMessageBackoffExpiresAfterTheWindow() {
        val trust = MemoryPairingTrustStore()
        val clock = AtomicLong(0)
        val responder = PairingResponder(
            trust = trust,
            credentials = { credentials },
            status = { status },
            identity = CounterIdentity(),
            clock = { clock.get() },
        )
        val badFrame = byteArrayOf(0x00)
        repeat(10) {
            responder.receive(1000L + it, badFrame, "10.0.0.1", true)
        }
        clock.set(61_000)
        val hello = PairingProtocol.encodeHello(
            ByteArray(32) { 0x11 },
            ByteArray(32) { 0x22 },
        )
        val output = responder.receive(62_000, hello, "10.0.0.1", true)
        val payload = payload(output)
        assertEquals(PairingProtocol.MSG_CHALLENGE, payload[0].toInt() and 0xFF)
    }

    /**
     * The invalid-message map must stay bounded and must keep a budget for a
     * new peer when it is full. The old code dropped the new record, so one
     * peer could rotate addresses and keep the fast path open.
     */
    @Test
    fun invalidBudgetStaysBoundedAndKeepsTheNewPeer() {
        val trust = MemoryPairingTrustStore()
        val clock = AtomicLong(0)
        val responder = PairingResponder(
            trust = trust,
            credentials = { credentials },
            status = { status },
            identity = CounterIdentity(),
            clock = { clock.get() },
        )
        val badFrame = byteArrayOf(0x00)
        var connection = 1L
        repeat(300) { peerIndex ->
            repeat(10) {
                responder.receive(connection++, badFrame, "peer-$peerIndex", true)
            }
        }
        assertEquals(256, responder.trackedInvalidPeers())

        val hello = PairingProtocol.encodeHello(
            ByteArray(32) { 0x11 },
            ByteArray(32) { 0x22 },
        )
        val output = responder.receive(connection, hello, "peer-299", true)
        val payload = payload(output)
        assertEquals(PairingProtocol.MSG_RESULT, payload[0].toInt() and 0xFF)
        assertEquals(PairingStatus.REJECTED.wire, payload[1].toInt() and 0xFF)
        assertEquals(256, responder.trackedInvalidPeers())
    }

    @Test
    fun decisionMustMatchConnectionPromptAndCode() {
        val trust = MemoryPairingTrustStore()
        val clock = AtomicLong(0)
        val responder = PairingResponder(
            trust = trust,
            credentials = { credentials },
            status = { status },
            identity = CounterIdentity(),
            clock = { clock.get() },
        )
        val target = Target(X25519.publicKey(ByteArray(32) { 0x11 })!!)
        val challenge = responder.receive(7, target.hello(0), "10.0.0.7", true)
        target.acceptChallenge(challenge)
        responder.receive(7, target.reveal(), "10.0.0.7", true)
        val prompt = responder.pendingPrompt() ?: throw AssertionError("no prompt")

        assertNull(responder.decide(prompt.connection + 1, prompt.id, prompt.code, true))
        assertNull(responder.decide(prompt.connection, PromptId(prompt.id.value + 1), prompt.code, true))
        val wrongCode = if (prompt.code == "000 000") "999 999" else "000 000"
        assertNull(responder.decide(prompt.connection, prompt.id, wrongCode, true))
        assertEquals(0, trust.count)
        assertNotNull(responder.pendingPrompt())

        val allowed = responder.decide(prompt.connection, prompt.id, prompt.code, true)
        assertEquals(PairingStatus.OK, allowed?.status)
        assertEquals(1, trust.count)
    }

    private fun assertOnlyPairingException(label: String, block: () -> Unit) {
        try {
            block()
        } catch (_: PairingException) {
            return
        } catch (failure: Throwable) {
            throw AssertionError("$label threw ${failure.javaClass.name}: ${failure.message}", failure)
        }
    }

    private fun randomBytes(random: Random, size: Int): ByteArray =
        ByteArray(size).also(random::nextBytes)

    private fun payload(output: PairingOutput): ByteArray {
        val frame = output.frames.single()
        val length = ((frame[0].toInt() and 0xFF) shl 8) or (frame[1].toInt() and 0xFF)
        assertEquals(frame.size, 2 + length)
        return frame.copyOfRange(2, frame.size)
    }

    private class CounterIdentity : PairingIdentity {
        private var nonceCounter = 0

        override fun ephemeralSecret(): ByteArray = ByteArray(32) { 0x33 }

        override fun nonce(): ByteArray {
            val value = ByteArray(12) { 0x44 }
            value[1] = nonceCounter.toByte()
            nonceCounter += 1
            return value
        }
    }

    private inner class Target(private val lS: ByteArray) {
        private val lSPrivate = ByteArray(32) { 0x11 }
        private val lEPrivate = ByteArray(32) { 0x22 }
        private val lE = X25519.publicKey(lEPrivate)!!
        private var pE: ByteArray? = null
        private var keys: PairingKeys? = null

        fun hello(flags: Int): ByteArray =
            PairingProtocol.encodeHello(lS, PairingProtocol.commitment(lE, lS)) +
                byteArrayOf(flags.toByte())

        fun acceptChallenge(output: PairingOutput) {
            val frame = output.frames.single()
            val payload = frame.copyOfRange(2, frame.size)
            val decoded = PairingProtocol.decodeChallenge(payload)
            if (decoded !is ChallengeOrResult.Challenge) {
                throw AssertionError("no challenge")
            }
            pE = decoded.pE
        }

        fun reveal(): ByteArray {
            val publicEphemeral = pE ?: throw AssertionError("no challenge")
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
            return PairingProtocol.encodeReveal(lE, PairingProtocol.laptopProof(derived))
        }
    }
}
