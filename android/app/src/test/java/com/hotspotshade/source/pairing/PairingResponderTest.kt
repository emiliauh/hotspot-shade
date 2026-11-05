package com.hotspotshade.source.pairing

import java.net.Inet4Address
import java.net.InetAddress
import java.util.ArrayDeque
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * State machine tests. The fixed keys and nonces are public test values. The
 * behavior mirrors `rust/src/source_pairing.rs`.
 */
class PairingResponderTest {
    private val lSPrivate = ByteArray(32) { 0x11 }
    private val lEPrivate = ByteArray(32) { 0x22 }
    private val pEPrivate = ByteArray(32) { 0x33 }
    private val firstNonce = ByteArray(12) { 0x44 }
    private val token = "test-token-0123456789abcdef"
    private val host = InetAddress.getByName("172.20.10.1") as Inet4Address
    private val status = ProxyStatus(
        proxyRunning = true,
        foreground = true,
        connections = 2,
        port = 1080,
        host = host,
        sequence = 1,
    )
    private val trust = MemoryPairingTrustStore()
    private val clock = TestClock()
    private val identity = TestIdentity()
    private var credentials: PairingCredentials? =
        PairingCredentials.create(host, 1080, token)

    private fun responder(): PairingResponder = PairingResponder(
        trust = trust,
        credentials = { credentials },
        status = { status },
        identity = identity,
        clock = { clock.now },
    )

    @Test
    fun fullHandshakePromptsAndReturnsCredentials() {
        val responder = responder()
        val target = Target()
        val challenge = responder.receive(1, target.hello(), "peer", true)
        val (known, pE) = target.acceptChallenge(challenge)
        assertFalse(known)
        assertEquals(
            "7b0d47d93427f8311160781c7c733fd89f88970aef490d8aa0ee19a4cb8a1b14",
            PairingProtocol.hex(pE),
        )
        assertNull(responder.pendingPrompt())

        val proof = responder.receive(1, target.reveal(), "peer", true)
        assertTrue(proof.frames.isEmpty())
        assertFalse(proof.close)
        val prompt = responder.pendingPrompt()!!
        assertEquals("500 104", prompt.code)
        assertEquals(1L, prompt.connection)
        assertEquals(0, trust.count)
        assertFalse(prompt.toString().contains(prompt.code))
        assertTrue(prompt.toString().contains("[redacted]"))

        val allowed = responder.decide(prompt.connection, prompt.id, prompt.code, true)!!
        assertEquals(PairingStatus.OK, allowed.status)
        assertFalse(allowed.close)
        assertEquals(1, trust.count)
        assertNull(responder.pendingPrompt())

        val message = payload(allowed)
        assertEquals(PairingProtocol.MSG_RESULT, message[0].toInt())
        assertEquals(PairingStatus.OK.wire, message[1].toInt())
        assertArrayEquals(firstNonce, message.copyOfRange(2, 14))
        assertEquals(
            "132a89d1add706e92d7844032a37f2486c9f386e21255687facf153edc23e7dced55371101721d50afaa326d1fb62e2c" +
                "270f1501bb51d043e9c8",
            PairingProtocol.hex(message.copyOfRange(14, message.size)),
        )
        val received = target.openResult(allowed)
        assertEquals(host, received.host)
        assertEquals(1080, received.port)
        assertEquals(token, received.token)
    }

    @Test
    fun perPeerChallengeBudgetIsFourAndChargesBeforeTheSecret() {
        val responder = responder()
        for (connection in 0L until 4L) {
            val target = Target()
            val output = responder.receive(connection, target.hello(), "peer-a", true)
            assertFalse(target.acceptChallenge(output).first)
            responder.connectionClosed(connection)
        }
        assertEquals(4, identity.ephemeralCalls)
        val target = Target()
        val refused = responder.receive(10, target.hello(), "peer-a", true)
        assertEquals(4, identity.ephemeralCalls)
        assertEquals(PairingStatus.BUSY, resultStatus(refused))
        assertEquals(0, responder.activeSessions())

        val other = Target()
        val output = responder.receive(11, other.hello(), "peer-b", true)
        assertFalse(other.acceptChallenge(output).first)
        responder.connectionClosed(11)
        assertEquals(5, identity.ephemeralCalls)
    }

    @Test
    fun globalChallengeBudgetIsEight() {
        val responder = responder()
        for (connection in 0L until 8L) {
            val target = Target()
            val output = responder.receive(connection, target.hello(), "peer-$connection", true)
            assertFalse(target.acceptChallenge(output).first)
            responder.connectionClosed(connection)
        }
        assertEquals(8, identity.ephemeralCalls)
        val target = Target()
        val refused = responder.receive(100, target.hello(), "other", true)
        assertEquals(PairingStatus.BUSY, resultStatus(refused))
        assertEquals(8, identity.ephemeralCalls)

        clock.advance(60_000)
        val fresh = Target()
        val output = responder.receive(101, fresh.hello(), "other", true)
        assertFalse(fresh.acceptChallenge(output).first)
        assertEquals(9, identity.ephemeralCalls)
    }

    @Test
    fun pairingOffDoesNotChargeTheChallengeBudget() {
        credentials = null
        val responder = responder()
        for (connection in 0L until 9L) {
            val target = Target()
            val output = responder.receive(connection, target.hello(), "peer-$connection", true)
            assertEquals(PairingStatus.NOT_ACTIVE, resultStatus(output))
            responder.connectionClosed(connection)
        }
        assertEquals(0, identity.ephemeralCalls)

        credentials = PairingCredentials.create(host, 1080, token)
        val target = Target()
        val output = responder.receive(20, target.hello(), "peer-new", true)
        assertFalse(target.acceptChallenge(output).first)
        assertEquals(1, identity.ephemeralCalls)
    }

    @Test
    fun canonicalPeersShareOneBudget() {
        val responder = responder()
        for (connection in 0L until 4L) {
            val target = Target()
            val output = responder.receive(connection, target.hello(), "2001:db8::1", true)
            assertFalse(target.acceptChallenge(output).first)
            responder.connectionClosed(connection)
        }
        val same = Target()
        val refused = responder.receive(
            10,
            same.hello(),
            "2001:0db8:0000:0000:0000:0000:0000:0001",
            true,
        )
        assertEquals(PairingStatus.BUSY, resultStatus(refused))

        val mappedTrust = MemoryPairingTrustStore()
        val mapped = PairingResponder(
            trust = mappedTrust,
            credentials = { PairingCredentials.create(host, 1080, token) },
            status = { status },
            identity = TestIdentity(),
            clock = { clock.now },
        )
        for (connection in 20L until 24L) {
            val target = Target()
            val output = mapped.receive(connection, target.hello(), "192.0.2.1", true)
            assertFalse(target.acceptChallenge(output).first)
            mapped.connectionClosed(connection)
        }
        for ((index, peer) in listOf("::ffff:192.0.2.1", "::ffff:c000:201").withIndex()) {
            val target = Target()
            val output = mapped.receive(30L + index, target.hello(), peer, true)
            assertEquals(PairingStatus.BUSY, resultStatus(output))
        }
        assertThrows(PairingException::class.java) {
            mapped.receive(40, Target().hello(), "192.0.2.1:443", true)
        }
        assertThrows(PairingException::class.java) {
            mapped.receive(41, Target().hello(), "fe80::1%en0", true)
        }
        assertThrows(PairingException::class.java) {
            mapped.receive(42, Target().hello(), "", true)
        }
        assertThrows(PairingException::class.java) {
            mapped.receive(43, Target().hello(), "a".repeat(65), true)
        }
    }

    @Test
    fun decisionIsBoundToConnectionPromptCodeAndDeadline() {
        val responder = responder()
        val target = Target()
        val challenge = responder.receive(1, target.hello(), "peer", true)
        target.acceptChallenge(challenge)
        responder.receive(1, target.reveal(), "peer", true)
        val prompt = responder.pendingPrompt()!!

        assertNull(responder.decide(prompt.connection + 1, prompt.id, prompt.code, true))
        assertNull(responder.decide(prompt.connection, PromptId(prompt.id.value + 1), prompt.code, true))
        assertNull(responder.decide(prompt.connection, prompt.id, "000 000", true))
        assertEquals(prompt, responder.pendingPrompt())
        assertEquals(0, trust.count)

        clock.advance(60_000)
        val expired = responder.decide(prompt.connection, prompt.id, prompt.code, true)!!
        assertEquals(PairingStatus.TIMED_OUT, resultStatus(expired))
        assertEquals(0, trust.count)
        assertNull(responder.pendingPrompt())
    }

    @Test
    fun visiblePromptTimeoutCountsAndAllowsANewHandshake() {
        val responder = responder()
        val target = Target()
        val challenge = responder.receive(1, target.hello(), "peer", true)
        target.acceptChallenge(challenge)
        responder.receive(1, target.reveal(), "peer", true)
        assertTrue(responder.pendingPrompt() != null)
        clock.advance(60_000)
        val output = responder.tick()!!
        assertEquals(PairingStatus.TIMED_OUT, resultStatus(output))
        assertEquals(1, responder.promptFailureCount())

        val fresh = Target()
        val next = responder.receive(2, fresh.hello(), "peer", true)
        assertFalse(fresh.acceptChallenge(next).first)
    }

    @Test
    fun deactivateExtendsThePromptOnceToTheCap() {
        val responder = responder()
        val target = Target()
        val challenge = responder.receive(1, target.hello(), "peer", true)
        target.acceptChallenge(challenge)
        responder.receive(1, target.reveal(), "peer", true)
        assertEquals(60_000L, responder.nextDeadline())

        clock.advance(30_000)
        assertNull(responder.deactivate())
        assertEquals(150_000L, responder.nextDeadline())
        clock.advance(1_000)
        assertNull(responder.deactivate())
        assertEquals(150_000L, responder.nextDeadline())
        clock.advance(60_000)
        assertNull(responder.deactivate())
        assertEquals(150_000L, responder.nextDeadline())

        clock.now = 150_000
        val output = responder.tick()!!
        assertEquals(PairingStatus.TIMED_OUT, resultStatus(output))
    }

    @Test
    fun inactivePromptTimesOutWithoutAPromptFailure() {
        val responder = responder()
        val target = Target()
        val challenge = responder.receive(1, target.hello(), "peer", false)
        target.acceptChallenge(challenge)
        responder.receive(1, target.reveal(), "peer", false)
        assertEquals(120_000L, responder.nextDeadline())
        clock.advance(120_000)
        val output = responder.tick()!!
        assertEquals(PairingStatus.TIMED_OUT, resultStatus(output))
        assertEquals(0, responder.promptFailureCount())
    }

    @Test
    fun knownTargetSkipsThePromptAndStatusIsAuthenticated() {
        trust.add(X25519.publicKey(lSPrivate)!!)
        val responder = responder()
        val target = Target()
        val challenge = responder.receive(1, target.hello(flags = 1), "peer", true)
        val (known, _) = target.acceptChallenge(challenge)
        assertTrue(known)
        val proof = responder.receive(1, target.reveal(), "peer", true)
        assertTrue(proof.frames.isEmpty())
        assertNull(responder.pendingPrompt())

        val direct = Target()
        val directChallenge = responder.receive(2, direct.hello(), "peer", true)
        assertTrue(direct.acceptChallenge(directChallenge).first)
        val directResult = responder.receive(2, direct.reveal(), "peer", true)
        assertEquals(PairingStatus.OK, directResult.status)
        assertNull(responder.pendingPrompt())
        assertEquals(token, direct.openResult(directResult).token)

        val request = target.statusRequest(ByteArray(16) { 0x55 }, ByteArray(12) { 0x44 }, 0)
        val answer = responder.receive(1, request, "peer", true)
        assertTrue(answer.close)
        assertNull(answer.status)
        val plaintext = target.openStatus(answer)
        assertArrayEquals(ByteArray(16) { 0x55 }, plaintext.copyOfRange(0, 16))
        assertEquals(1, plaintext[19].toInt())
        assertEquals(1, plaintext[20].toInt())
        assertEquals(2, plaintext[23].toInt())
        assertEquals(1080, ((plaintext[24].toInt() and 0xFF) shl 8) or (plaintext[25].toInt() and 0xFF))
        assertEquals(1, trust.count)
    }

    @Test
    fun forgetRequiresTrustAndRemovesTheKey() {
        trust.add(X25519.publicKey(lSPrivate)!!)
        val responder = responder()
        val target = Target()
        val challenge = responder.receive(1, target.hello(flags = 2), "peer", true)
        assertTrue(target.acceptChallenge(challenge).first)
        responder.receive(1, target.reveal(), "peer", true)
        val forget = target.forgetRequest(ByteArray(12) { 0x44 }, ByteArray(0))
        val answer = responder.receive(1, forget, "peer", true)
        assertEquals(PairingStatus.OK, resultStatus(answer))
        assertEquals(0, trust.count)

        // A second forget from the same key has no trust and is rejected.
        val second = Target()
        val again = responder.receive(2, second.hello(flags = 2), "peer", true)
        assertEquals(PairingStatus.REJECTED, resultStatus(again))
    }

    @Test
    fun threeDenialsLockThePeerAndOtherPeersContinue() {
        val responder = responder()
        repeat(3) { index ->
            val target = Target()
            val challenge = responder.receive(index.toLong() + 1, target.hello(), "peer-x", true)
            target.acceptChallenge(challenge)
            responder.receive(index.toLong() + 1, target.reveal(), "peer-x", true)
            val prompt = responder.pendingPrompt()!!
            val denied = responder.decide(prompt.connection, prompt.id, prompt.code, false)!!
            assertEquals(PairingStatus.DENIED, resultStatus(denied))
        }
        val locked = Target()
        val refused = responder.receive(10, locked.hello(), "peer-x", true)
        assertEquals(PairingStatus.LOCKED_OUT, resultStatus(refused))

        val other = Target()
        val output = responder.receive(11, other.hello(), "peer-y", true)
        assertFalse(other.acceptChallenge(output).first)
    }

    @Test
    fun sessionsAreBoundedAndCloseReleasesASlot() {
        val responder = responder()
        for (connection in 0L until 4L) {
            val target = Target()
            val output = responder.receive(connection, target.hello(), "peer-$connection", true)
            assertFalse(target.acceptChallenge(output).first)
        }
        val fifth = Target()
        val refused = responder.receive(10, fifth.hello(), "peer-five", true)
        assertEquals(PairingStatus.BUSY, resultStatus(refused))
        assertNull(refused.status)
        responder.connectionClosed(0)
        val fresh = Target()
        val output = responder.receive(11, fresh.hello(), "peer-six", true)
        assertFalse(fresh.acceptChallenge(output).first)
    }

    @Test
    fun statusDuringThePromptIsRejected() {
        val responder = responder()
        val target = Target()
        val challenge = responder.receive(1, target.hello(), "peer", true)
        target.acceptChallenge(challenge)
        responder.receive(1, target.reveal(), "peer", true)
        assertTrue(responder.pendingPrompt() != null)
        val request = target.statusRequest(ByteArray(16) { 0x55 }, ByteArray(12) { 0x44 }, 0)
        val answer = responder.receive(1, request, "peer", true)
        assertEquals(PairingStatus.REJECTED, resultStatus(answer))
        assertNull(responder.pendingPrompt())
    }

    @Test
    fun badProofIsRejectedWithoutAPrompt() {
        val responder = responder()
        val target = Target()
        val challenge = responder.receive(1, target.hello(), "peer", true)
        target.acceptChallenge(challenge)
        val reveal = target.reveal()
        reveal[33] = (reveal[33].toInt() xor 1).toByte()
        val answer = responder.receive(1, reveal, "peer", true)
        assertEquals(PairingStatus.REJECTED, resultStatus(answer))
        assertNull(responder.pendingPrompt())
        assertEquals(0, trust.count)
    }

    @Test
    fun receiveInvalidReleasesTheSessionBeforeThePeerError() {
        val responder = responder()
        val target = Target()
        val challenge = responder.receive(1, target.hello(), "peer", true)
        target.acceptChallenge(challenge)
        responder.receive(1, target.reveal(), "peer", true)
        assertTrue(responder.pendingPrompt() != null)
        assertThrows(PairingException::class.java) {
            responder.receiveInvalid(1, "")
        }
        assertEquals(0, responder.activeSessions())
        assertNull(responder.pendingPrompt())
        assertNull(responder.nextDeadline())

        val fresh = Target()
        val output = responder.receive(2, fresh.hello(), "peer", true)
        assertFalse(fresh.acceptChallenge(output).first)
        responder.receive(2, fresh.reveal(), "peer", true)
        assertTrue(responder.pendingPrompt() != null)
    }

    @Test
    fun credentiallessApprovalIsNotActive() {
        val responder = responder()
        val target = Target()
        val challenge = responder.receive(1, target.hello(), "peer", true)
        target.acceptChallenge(challenge)
        responder.receive(1, target.reveal(), "peer", true)
        val prompt = responder.pendingPrompt()!!
        credentials = null
        val answer = responder.decide(prompt.connection, prompt.id, prompt.code, true)!!
        assertEquals(PairingStatus.NOT_ACTIVE, resultStatus(answer))
        assertEquals(0, trust.count)
    }

    @Test
    fun clockCannotMoveBackwards() {
        val responder = responder()
        val target = Target()
        responder.receive(1, target.hello(), "peer", true)
        clock.advance(-1)
        assertThrows(PairingException::class.java) {
            responder.receive(2, Target().hello(), "peer", true)
        }
    }

    private fun resultStatus(output: PairingOutput): PairingStatus? {
        val message = payload(output)
        if (message.size == 2 && message[0].toInt() == PairingProtocol.MSG_RESULT) {
            return PairingStatus.fromWire(message[1].toInt() and 0xFF)
        }
        val decoded = PairingProtocol.decodeResult(message) ?: return null
        return (decoded as? ResultMessage.Status)?.status
    }

    private fun payload(output: PairingOutput): ByteArray {
        assertEquals(1, output.frames.size)
        val frame = output.frames[0]
        val length = ((frame[0].toInt() and 0xFF) shl 8) or (frame[1].toInt() and 0xFF)
        assertEquals(frame.size, 2 + length)
        return frame.copyOfRange(2, frame.size)
    }

    private class TestClock {
        var now: Long = 0

        fun advance(milliseconds: Long) {
            now += milliseconds
        }
    }

    private class TestIdentity : PairingIdentity {
        var ephemeralCalls = 0
        private val nonces = ArrayDeque<ByteArray>().apply {
            for (index in 0 until 32) {
                val value = ByteArray(12) { 0x44 }
                if (index != 0) value[1] = index.toByte()
                addLast(value)
            }
        }

        override fun ephemeralSecret(): ByteArray {
            ephemeralCalls += 1
            return ByteArray(32) { 0x33 }
        }

        override fun nonce(): ByteArray = nonces.removeFirst()
    }

    private inner class Target {
        private val lSSecret: ByteArray = lSPrivate
        private val lESecret: ByteArray = lEPrivate

        private var pE: ByteArray? = null
        private var keys: PairingKeys? = null
        private val lS: ByteArray = X25519.publicKey(lSSecret)!!
        private val lE: ByteArray = X25519.publicKey(lESecret)!!

        fun hello(flags: Int? = null): ByteArray {
            val message = PairingProtocol.encodeHello(lS, PairingProtocol.commitment(lE, lS))
            return if (flags == null) message else message + byteArrayOf(flags.toByte())
        }

        fun acceptChallenge(output: PairingOutput): Pair<Boolean, ByteArray> {
            val message = payload(output)
            val decoded = PairingProtocol.decodeChallenge(message)
                ?: throw AssertionError("The source device did not send a challenge.")
            if (decoded !is ChallengeOrResult.Challenge) {
                throw AssertionError("The source device refused the challenge.")
            }
            pE = decoded.pE
            return decoded.known to decoded.pE
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

        fun statusRequest(challenge: ByteArray, nonce: ByteArray, flags: Int): ByteArray {
            val plaintext = challenge + byteArrayOf(flags.toByte())
            return byteArrayOf(PairingProtocol.MSG_STATUS_REQ.toByte()) + nonce +
                PairingProtocol.sealMessage(keys!!, nonce, plaintext)
        }

        fun forgetRequest(nonce: ByteArray, plaintext: ByteArray): ByteArray =
            byteArrayOf(PairingProtocol.MSG_FORGET.toByte()) + nonce +
                PairingProtocol.sealMessage(keys!!, nonce, plaintext)

        fun openStatus(output: PairingOutput): ByteArray {
            val message = payload(output)
            assertEquals(PairingProtocol.MSG_STATUS, message[0].toInt())
            return PairingProtocol.openMessage(
                keys!!,
                message.copyOfRange(1, 13),
                message.copyOfRange(13, message.size),
            ) ?: throw AssertionError("The status did not open.")
        }

        fun openResult(output: PairingOutput): PairingCredentials {
            val message = payload(output)
            val decoded = PairingProtocol.decodeResult(message)
            if (decoded !is ResultMessage.Ok) throw AssertionError("The result is not OK.")
            return PairingProtocol.openCredentials(keys!!, decoded.nonce, decoded.ciphertext)
        }
    }
}
