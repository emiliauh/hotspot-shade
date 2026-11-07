package com.hotspotshade.source.pairing

import java.net.Inet4Address
import java.net.InetAddress
import java.util.ArrayDeque
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import com.hotspotshade.source.PairingAdmin
import com.hotspotshade.source.PairingTrustGate
import com.hotspotshade.source.SourceTokenGuard
import com.hotspotshade.source.TokenWriter
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

    /** A responder that uses the test gate. */
    private fun responder(trustGate: PairingTrustGate): PairingResponder = PairingResponder(
        trust = trust,
        credentials = { credentials },
        status = { status },
        identity = identity,
        clock = { clock.now },
        trustGate = trustGate,
    )

    /** The settings-page admin over the same trust store and gate. */
    private fun admin(trustGate: PairingTrustGate): PairingAdmin = PairingAdmin(
        trust = trust,
        tokenStore = TokenWriter { },
        tokenFactory = { "new-token-value" },
        isProxyActive = { false },
        guard = SourceTokenGuard(),
        trustGate = trustGate,
    )

    private fun knownKeyHex(): String =
        PairingProtocol.hex(X25519.publicKey(lSPrivate)!!)

    @Test
    fun trustStoreWriteFailureSendsRejectedAndKeepsNoSession() {
        val failing = object : PairingTrustStore {
            override fun contains(publicKey: ByteArray): Boolean = false

            override fun add(publicKey: ByteArray) {
                throw PairingException(PairingError.TRUST_STORE)
            }

            override fun remove(publicKey: ByteArray) = Unit

            override val count: Int
                get() = 0
        }
        val responder = PairingResponder(
            trust = failing,
            credentials = { credentials },
            status = { status },
            identity = identity,
            clock = { clock.now },
        )
        val target = Target()
        target.acceptChallenge(responder.receive(1, target.hello(), "peer", true))
        responder.receive(1, target.reveal(), "peer", true)
        val prompt = responder.pendingPrompt() ?: throw AssertionError("no prompt")

        val output = responder.decide(prompt.connection, prompt.id, prompt.code, true)!!

        assertEquals(PairingStatus.REJECTED, output.status)
        assertTrue(output.close)
        assertEquals(0, responder.activeSessions())
        assertNull(responder.pendingPrompt())
    }

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
    fun statusOnlyRejectsKnownRepairBeforeCredentialOrTrustWork() {
        val key = X25519.publicKey(lSPrivate)!!
        val recording = ResponderRecordingTrustStore().apply { seed(key) }
        var credentialCalls = 0
        var commitCalls = 0
        val responder = PairingResponder(
            trust = recording,
            credentials = {
                credentialCalls += 1
                credentials
            },
            status = { status },
            identity = identity,
            clock = { clock.now },
            commitToken = {
                commitCalls += 1
                true
            },
            mode = PairingResponderMode.STATUS_ONLY,
        )
        val target = Target()

        val output = responder.receive(1, target.hello(flags = 0), "peer", true)

        assertEquals(PairingStatus.REJECTED, resultStatus(output))
        assertTrue(output.close)
        assertEquals(0, credentialCalls)
        assertEquals(0, commitCalls)
        assertEquals(0, recording.containsCalls)
        assertEquals(0, recording.addCalls)
        assertEquals(0, recording.removeCalls)
        assertEquals(0, identity.ephemeralCalls)
        assertEquals(0, responder.activeSessions())
        assertNull(responder.pendingPrompt())
        assertFalse(outputText(output).contains(token))
    }

    @Test
    fun statusOnlyRejectsKnownForgetBeforeTrustMutation() {
        val key = X25519.publicKey(lSPrivate)!!
        val recording = ResponderRecordingTrustStore().apply { seed(key) }
        var credentialCalls = 0
        val responder = PairingResponder(
            trust = recording,
            credentials = {
                credentialCalls += 1
                credentials
            },
            status = { status },
            identity = identity,
            clock = { clock.now },
            mode = PairingResponderMode.STATUS_ONLY,
        )
        val target = Target()

        val output = responder.receive(1, target.hello(flags = 2), "peer", true)

        assertEquals(PairingStatus.REJECTED, resultStatus(output))
        assertTrue(output.close)
        assertEquals(0, credentialCalls)
        assertEquals(0, recording.containsCalls)
        assertEquals(0, recording.addCalls)
        assertEquals(0, recording.removeCalls)
        assertEquals(1, recording.count)
        assertEquals(0, identity.ephemeralCalls)
        assertNull(responder.pendingPrompt())
    }

    @Test
    fun statusOnlyRejectsUnknownPairingAndStatusWithoutAPrompt() {
        val recording = ResponderRecordingTrustStore()
        var credentialCalls = 0
        val responder = PairingResponder(
            trust = recording,
            credentials = {
                credentialCalls += 1
                credentials
            },
            status = { status },
            identity = identity,
            clock = { clock.now },
            mode = PairingResponderMode.STATUS_ONLY,
        )

        for ((index, flags) in listOf(0, 1, 2).withIndex()) {
            val target = Target()
            val output = responder.receive(
                index.toLong() + 1,
                target.hello(flags = flags),
                "peer-$flags",
                true,
            )

            assertEquals(PairingStatus.REJECTED, resultStatus(output))
            assertTrue(output.close)
            assertFalse(outputText(output).contains(token))
        }

        assertEquals(0, credentialCalls)
        // Flags 0 and 2 are rejected before the trust read. The status flag
        // still reads trust to learn that the key is unknown, then rejects.
        assertEquals(1, recording.containsCalls)
        assertEquals(0, recording.addCalls)
        assertEquals(0, recording.removeCalls)
        assertEquals(0, identity.ephemeralCalls)
        assertEquals(0, responder.activeSessions())
        assertNull(responder.pendingPrompt())
    }

    @Test
    fun statusOnlyStillAnswersKnownTargetStatusWithoutTrustMutation() {
        val key = X25519.publicKey(lSPrivate)!!
        val recording = ResponderRecordingTrustStore().apply { seed(key) }
        val responder = PairingResponder(
            trust = recording,
            credentials = { credentials },
            status = { status },
            identity = identity,
            clock = { clock.now },
            mode = PairingResponderMode.STATUS_ONLY,
        )
        val target = Target()
        val challenge = responder.receive(1, target.hello(flags = 1), "peer", true)
        assertTrue(target.acceptChallenge(challenge).first)
        val proof = responder.receive(1, target.reveal(), "peer", true)
        assertTrue(proof.frames.isEmpty())
        assertFalse(proof.close)

        val request = target.statusRequest(ByteArray(16) { 0x55 }, ByteArray(12) { 0x44 }, 0)
        val answer = responder.receive(1, request, "peer", true)

        assertTrue(answer.close)
        assertNull(answer.status)
        val plaintext = target.openStatus(answer)
        assertArrayEquals(ByteArray(16) { 0x55 }, plaintext.copyOfRange(0, 16))
        assertEquals(1, plaintext[20].toInt())
        assertEquals(2, plaintext[23].toInt())
        assertEquals(1080, ((plaintext[24].toInt() and 0xFF) shl 8) or (plaintext[25].toInt() and 0xFF))
        assertFalse(outputText(answer).contains(token))
        assertTrue(recording.containsCalls > 0)
        assertEquals(0, recording.addCalls)
        assertEquals(0, recording.removeCalls)
        assertEquals(1, recording.count)
        assertNull(responder.pendingPrompt())
    }

    @Test
    fun fullModeStillAllowsKnownRepairAndForget() {
        val key = X25519.publicKey(lSPrivate)!!
        trust.add(key)
        val responder = responder()

        val repair = Target()
        val challenge = responder.receive(1, repair.hello(flags = 0), "peer", true)
        assertTrue(repair.acceptChallenge(challenge).first)
        val repaired = responder.receive(1, repair.reveal(), "peer", true)
        assertEquals(PairingStatus.OK, repaired.status)
        assertEquals(token, repair.openResult(repaired).token)
        assertEquals(1, trust.count)

        val forget = Target()
        val forgetChallenge = responder.receive(2, forget.hello(flags = 2), "peer", true)
        assertTrue(forget.acceptChallenge(forgetChallenge).first)
        responder.receive(2, forget.reveal(), "peer", true)
        val answer = responder.receive(
            2,
            forget.forgetRequest(ByteArray(12) { 0x44 }, ByteArray(0)),
            "peer",
            true,
        )
        assertEquals(PairingStatus.OK, resultStatus(answer))
        assertEquals(0, trust.count)
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

    @Test
    fun aFailedTokenCommitRejectsWithoutTrust() {
        var commits = 0
        val responder = PairingResponder(
            trust = trust,
            credentials = { credentials },
            status = { status },
            identity = identity,
            clock = { clock.now },
            commitToken = {
                commits += 1
                false
            },
        )
        val target = Target()
        val challenge = responder.receive(1, target.hello(), "peer", true)
        target.acceptChallenge(challenge)
        responder.receive(1, target.reveal(), "peer", true)
        val prompt = responder.pendingPrompt()!!

        val output = responder.decide(prompt.connection, prompt.id, prompt.code, true)!!

        assertEquals(1, commits)
        assertEquals(PairingStatus.REJECTED, output.status)
        assertTrue(output.tokenCommitFailed)
        assertEquals(0, trust.count)
    }

    @Test
    fun aTokenCommitThatARotationSupersededSendsNoOldToken() {
        val guard = SourceTokenGuard()
        val saved = AtomicReference<String?>(null)
        val epoch = guard.epoch()
        val responder = PairingResponder(
            trust = trust,
            credentials = { credentials },
            status = { status },
            identity = identity,
            clock = { clock.now },
            commitToken = { value ->
                guard.savePairingToken(epoch) { saved.set(value) }
            },
        )
        val target = Target()
        val challenge = responder.receive(1, target.hello(), "peer", true)
        target.acceptChallenge(challenge)
        responder.receive(1, target.reveal(), "peer", true)
        val prompt = responder.pendingPrompt()!!

        // A rotation wins while the prompt is visible. The sealed result
        // carries the old epoch and must not write or send the old token.
        assertEquals(
            com.hotspotshade.source.TokenMutationResult.WRITTEN,
            guard.rotate { saved.set("rotated-token") },
        )
        val output = responder.decide(prompt.connection, prompt.id, prompt.code, true)!!

        assertEquals(PairingStatus.REJECTED, output.status)
        assertTrue(output.tokenCommitFailed)
        assertEquals("rotated-token", saved.get())
        assertEquals(0, trust.count)
    }

    @Test
    fun aStatusAnswerUsesOneCredentialSnapshot() {
        trust.add(X25519.publicKey(lSPrivate)!!)
        var credentialCalls = 0
        var statusCalls = 0
        val responder = PairingResponder(
            trust = trust,
            credentials = {
                credentialCalls += 1
                credentials
            },
            status = { throw AssertionError("The status callback must not probe again.") },
            identity = identity,
            clock = { clock.now },
            statusFor = {
                statusCalls += 1
                status
            },
        )
        val target = Target()
        val challenge = responder.receive(1, target.hello(flags = 1), "peer", true)
        assertTrue(target.acceptChallenge(challenge).first)
        responder.receive(1, target.reveal(), "peer", true)

        val request = target.statusRequest(ByteArray(16) { 0x55 }, ByteArray(12) { 0x44 }, 0)
        val answer = responder.receive(1, request, "peer", true)

        assertTrue(answer.close)
        target.openStatus(answer)
        assertEquals(1, credentialCalls)
        assertEquals(1, statusCalls)
    }

    // The known-claim budget. Limits match rust/src/source_pairing.rs and
    // ios/HotspotProxy/Pairing.swift: 8 per source address, 16 in total, in a
    // 60 second window, with one refund for each verified proof.

    /** Run one known HELLO. Returns the target and the challenge answer. */
    private fun knownHello(
        responder: PairingResponder,
        connection: Long,
        peer: String,
        flags: Int? = 1,
    ): Pair<Target, PairingOutput> {
        val target = Target()
        return target to responder.receive(connection, target.hello(flags), peer, true)
    }

    private fun tampered(reveal: ByteArray): ByteArray {
        // The proof is the last 32 bytes. A claim without the private key
        // cannot produce a valid one.
        reveal[reveal.size - 1] = (reveal[reveal.size - 1].toInt() xor 1).toByte()
        return reveal
    }

    @Test
    fun knownKeyClaimsHaveABoundedChallengeBudget() {
        trust.add(X25519.publicKey(lSPrivate)!!)
        val responder = responder()

        for (connection in 0L until 8L) {
            val (target, output) = knownHello(responder, connection, "peer-a")
            assertTrue(target.acceptChallenge(output).first)
            responder.connectionClosed(connection)
        }
        assertEquals(8, identity.ephemeralCalls)

        val (_, refused) = knownHello(responder, 20, "peer-a")
        assertEquals(PairingStatus.BUSY, resultStatus(refused))
        assertTrue(refused.close)
        assertEquals(8, identity.ephemeralCalls)
        assertEquals(0, responder.activeSessions())

        // Another source address has its own budget up to the global limit of 16.
        val (other, otherOutput) = knownHello(responder, 21, "peer-b")
        assertTrue(other.acceptChallenge(otherOutput).first)
        responder.connectionClosed(21)
        for (index in 0 until 7) {
            val connection = 30L + index
            val (target, output) = knownHello(responder, connection, "peer-c$index")
            assertTrue(target.acceptChallenge(output).first)
            responder.connectionClosed(connection)
        }
        assertEquals(16, identity.ephemeralCalls)
        val (_, global) = knownHello(responder, 40, "peer-d")
        assertEquals(PairingStatus.BUSY, resultStatus(global))
        assertEquals(16, identity.ephemeralCalls)

        // The window clears the known-claim budget.
        clock.advance(60_000)
        val (fresh, freshOutput) = knownHello(responder, 42, "peer-a")
        assertTrue(fresh.acceptChallenge(freshOutput).first)
        assertEquals(17, identity.ephemeralCalls)
    }

    @Test
    fun knownAndUnknownChallengeBudgetsAreSeparate() {
        val responder = responder()
        // Spend the whole unknown budget for one peer (4) with the fixed key.
        for (connection in 0L until 4L) {
            val (target, output) = knownHello(responder, connection, "peer-a", flags = null)
            assertFalse(target.acceptChallenge(output).first)
            responder.connectionClosed(connection)
        }
        val (_, unknownBusy) = knownHello(responder, 10, "peer-a", flags = null)
        assertEquals(PairingStatus.BUSY, resultStatus(unknownBusy))

        // The same address can still claim a trusted key: the known budget is untouched.
        trust.add(X25519.publicKey(lSPrivate)!!)
        for (connection in 20L until 28L) {
            val (target, output) = knownHello(responder, connection, "peer-a", flags = 1)
            assertTrue(target.acceptChallenge(output).first)
            responder.connectionClosed(connection)
        }
        val (_, knownBusy) = knownHello(responder, 30, "peer-a", flags = 1)
        assertEquals(PairingStatus.BUSY, resultStatus(knownBusy))
        assertEquals(12, identity.ephemeralCalls)
    }

    @Test
    fun pairingOffStillChargesAKnownClaimButNotAnUnknownOne() {
        credentials = null
        val responder = responder()
        // Pairing off: an unknown key gets NOT_ACTIVE and is never charged.
        for (connection in 0L until 9L) {
            val (_, output) = knownHello(responder, connection, "peer-a", flags = null)
            assertEquals(PairingStatus.NOT_ACTIVE, resultStatus(output))
        }
        assertEquals(0, identity.ephemeralCalls)

        // A trusted key is still a claim that costs key generation, so it pays.
        trust.add(X25519.publicKey(lSPrivate)!!)
        for (connection in 20L until 28L) {
            val (target, output) = knownHello(responder, connection, "peer-a")
            assertTrue(target.acceptChallenge(output).first)
            responder.connectionClosed(connection)
        }
        val (_, busy) = knownHello(responder, 30, "peer-a")
        assertEquals(PairingStatus.BUSY, resultStatus(busy))
        assertEquals(8, identity.ephemeralCalls)
    }

    @Test
    fun sustainedKnownStatusProbesRefundTheirChallengeCharge() {
        trust.add(X25519.publicKey(lSPrivate)!!)
        val responder = responder()

        // A presence check runs about every 2 seconds. Every verified proof
        // must refund its own charge, or a real target device would lock
        // itself out of its own source device.
        for (round in 0L until 30L) {
            clock.now = round * 2_000
            val (probe, output) = knownHello(responder, round, "172.20.10.2")
            assertFalse("probe $round gets a challenge", output.close)
            assertTrue("probe $round sees a known challenge", probe.acceptChallenge(output).first)
            val result = responder.receive(round, probe.reveal(), "172.20.10.2", true)
            assertTrue(result.frames.isEmpty())
            assertFalse(result.close)
            responder.connectionClosed(round)
        }
        assertEquals(30, identity.ephemeralCalls)
        assertEquals(0, responder.activeSessions())

        // The refunds returned every charge, so the full budget is available again.
        for (connection in 100L until 108L) {
            val (target, output) = knownHello(responder, connection, "172.20.10.2")
            assertTrue(target.acceptChallenge(output).first)
            responder.connectionClosed(connection)
        }
        val (_, busy) = knownHello(responder, 120, "172.20.10.2")
        assertEquals(PairingStatus.BUSY, resultStatus(busy))
    }

    @Test
    fun everyKnownCommandRefundsAtItsVerifiedProof() {
        trust.add(X25519.publicKey(lSPrivate)!!)
        val responder = responder()
        // flags 0 (direct credentials), 1 (status) and 2 (forget): each verified
        // proof refunds. No command follows the proof here, so trust stays.
        for ((index, flags) in listOf<Int?>(null, 1, 1, null, 1, 2).withIndex()) {
            val connection = index.toLong()
            val (target, output) = knownHello(responder, connection, "peer-a", flags)
            assertTrue(target.acceptChallenge(output).first)
            responder.receive(connection, target.reveal(), "peer-a", true)
            responder.connectionClosed(connection)
        }
        // After six verified proofs the peer budget holds no charge: the full
        // 8 known claims fit again.
        for (connection in 100L until 108L) {
            val (target, output) = knownHello(responder, connection, "peer-a")
            assertTrue(target.acceptChallenge(output).first)
            responder.connectionClosed(connection)
        }
        val (_, busy) = knownHello(responder, 120, "peer-a")
        assertEquals(PairingStatus.BUSY, resultStatus(busy))
    }

    @Test
    fun aBadProofDoesNotRefundAKnownClaim() {
        trust.add(X25519.publicKey(lSPrivate)!!)
        val responder = responder()
        for (round in 0L until 8L) {
            val (probe, output) = knownHello(responder, round, "peer-x", flags = null)
            assertTrue(probe.acceptChallenge(output).first)
            val answer = responder.receive(round, tampered(probe.reveal()), "peer-x", true)
            assertEquals(PairingStatus.REJECTED, resultStatus(answer))
            responder.connectionClosed(round)
        }
        assertEquals(8, identity.ephemeralCalls)

        val (_, busy) = knownHello(responder, 40, "peer-x", flags = null)
        assertEquals(PairingStatus.BUSY, resultStatus(busy))
        assertEquals(8, identity.ephemeralCalls)
        assertEquals(0, responder.activeSessions())
    }

    @Test
    fun anUnprovenKnownClaimThatTimesOutOrClosesIsNotRefunded() {
        trust.add(X25519.publicKey(lSPrivate)!!)
        val responder = responder()
        // Four claims are dropped by close, four by the 5 second reveal deadline.
        for (connection in 0L until 4L) {
            val (target, output) = knownHello(responder, connection, "peer-a")
            assertTrue(target.acceptChallenge(output).first)
            responder.connectionClosed(connection)
        }
        for (connection in 10L until 14L) {
            val (target, output) = knownHello(responder, connection, "peer-a")
            assertTrue(target.acceptChallenge(output).first)
        }
        clock.advance(5_000)
        responder.tick()
        for (connection in 10L until 14L) responder.connectionClosed(connection)
        assertEquals(0, responder.activeSessions())

        val (_, busy) = knownHello(responder, 20, "peer-a")
        assertEquals(PairingStatus.BUSY, resultStatus(busy))
        assertEquals(8, identity.ephemeralCalls)

    }

    @Test
    fun aLateRevealAfterTheDeadlineDoesNotRefund() {
        trust.add(X25519.publicKey(lSPrivate)!!)
        val responder = responder()
        for (connection in 0L until 8L) {
            val (target, output) = knownHello(responder, connection, "peer-a", flags = null)
            assertTrue(target.acceptChallenge(output).first)
            clock.advance(5_000)
            val answer = responder.receive(connection, target.reveal(), "peer-a", true)
            assertEquals(PairingStatus.TIMED_OUT, resultStatus(answer))
            responder.connectionClosed(connection)
        }
        val (_, busy) = knownHello(responder, 20, "peer-a", flags = null)
        assertEquals(PairingStatus.BUSY, resultStatus(busy))
        assertEquals(8, identity.ephemeralCalls)
    }

    @Test
    fun aLockedOutPeerStillPairsAKnownKeyAndKnownProofsStillRefund() {
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
        val (_, locked) = knownHello(responder, 10, "peer-x", flags = null)
        assertEquals(PairingStatus.LOCKED_OUT, resultStatus(locked))

        // The lockout is for unknown keys. After the person trusts the key,
        // the same locked address passes the known path and gets its refunds.
        trust.add(X25519.publicKey(lSPrivate)!!)
        for (round in 20L until 40L) {
            val (target, output) = knownHello(responder, round, "peer-x")
            assertTrue("round $round", target.acceptChallenge(output).first)
            responder.receive(round, target.reveal(), "peer-x", true)
            responder.connectionClosed(round)
        }
    }

    @Test
    fun aDenialDoesNotTouchTheKnownBudget() {
        val responder = responder()
        val target = Target()
        val challenge = responder.receive(1, target.hello(), "peer-a", true)
        assertFalse(target.acceptChallenge(challenge).first)
        responder.receive(1, target.reveal(), "peer-a", true)
        val prompt = responder.pendingPrompt()!!
        val denied = responder.decide(prompt.connection, prompt.id, prompt.code, false)!!
        assertEquals(PairingStatus.DENIED, resultStatus(denied))

        trust.add(X25519.publicKey(lSPrivate)!!)
        for (connection in 10L until 18L) {
            val (known, output) = knownHello(responder, connection, "peer-a")
            assertTrue(known.acceptChallenge(output).first)
            responder.connectionClosed(connection)
        }
        val (_, busy) = knownHello(responder, 30, "peer-a")
        assertEquals(PairingStatus.BUSY, resultStatus(busy))
    }

    @Test
    fun aForgetThatWinsRejectsAKnownCredentialDecision() {
        trust.add(X25519.publicKey(lSPrivate)!!)
        val gate = CoordinatedTrustGate()
        val responder = responder(gate)
        val admin = admin(gate)
        val target = Target()
        val challenge = responder.receive(1, target.hello(), "peer-a", true)
        assertTrue(target.acceptChallenge(challenge).first)

        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        gate.beforeDecision = {
            entered.countDown()
            assertTrue("the test must release the decision", release.await(5, TimeUnit.SECONDS))
        }
        val result = AtomicReference<PairingOutput?>(null)
        val failure = AtomicReference<Throwable?>(null)
        val decisionThread = Thread({
            try {
                result.set(responder.receive(1, target.reveal(), "peer-a", true))
            } catch (error: Throwable) {
                failure.set(error)
            }
        }, "pairing-decision")
        decisionThread.start()
        assertTrue("the decision must reach the boundary", entered.await(5, TimeUnit.SECONDS))

        // Forget takes the boundary first. The waiting decision must see the
        // removed key and must not build credentials.
        assertTrue(admin.forget(knownKeyHex()))
        assertEquals(0, trust.count)
        release.countDown()
        decisionThread.join(5_000)
        assertFalse(decisionThread.isAlive)
        assertNull(failure.get())
        val output = result.get()!!
        assertEquals(PairingStatus.REJECTED, resultStatus(output))
        assertTrue(output.close)
        assertEquals(1, gate.revision())
        assertEquals(0, responder.activeSessions())
    }

    @Test
    fun aCredentialDecisionThatWinsIsNotRetractedByALaterForget() {
        trust.add(X25519.publicKey(lSPrivate)!!)
        val gate = CoordinatedTrustGate()
        val responder = responder(gate)
        val admin = admin(gate)
        val target = Target()
        val challenge = responder.receive(1, target.hello(), "peer-a", true)
        assertTrue(target.acceptChallenge(challenge).first)

        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        gate.afterDecisionEntered = {
            entered.countDown()
            assertTrue("the test must release the decision", release.await(5, TimeUnit.SECONDS))
        }
        val result = AtomicReference<PairingOutput?>(null)
        val decisionFailure = AtomicReference<Throwable?>(null)
        val decisionThread = Thread({
            try {
                result.set(responder.receive(1, target.reveal(), "peer-a", true))
            } catch (error: Throwable) {
                decisionFailure.set(error)
            }
        }, "pairing-decision")
        decisionThread.start()
        assertTrue("the decision must hold the boundary", entered.await(5, TimeUnit.SECONDS))

        val forgotten = AtomicReference<Boolean?>(null)
        val forgetFailure = AtomicReference<Throwable?>(null)
        val forgetThread = Thread({
            try {
                forgotten.set(admin.forget(knownKeyHex()))
            } catch (error: Throwable) {
                forgetFailure.set(error)
            }
        }, "settings-forget")
        forgetThread.start()
        Thread.sleep(100)
        assertTrue("Forget must wait for the sealed decision", forgetThread.isAlive)

        release.countDown()
        decisionThread.join(5_000)
        forgetThread.join(5_000)
        assertFalse(decisionThread.isAlive)
        assertFalse(forgetThread.isAlive)
        assertNull(decisionFailure.get())
        assertNull(forgetFailure.get())
        assertEquals(true, forgotten.get())
        assertEquals(0, trust.count)
        assertEquals(1, gate.revision())

        // The decision sealed the credentials before Forget ran. The boundary
        // cannot retract that sealed frame; the test records the honest
        // behavior instead of claiming a recall.
        val output = result.get()!!
        assertEquals(PairingStatus.OK, output.status)
        assertEquals(token, target.openResult(output).token)
    }

    @Test
    fun aStatusDecisionThatWinsIsNotRetractedByALaterForget() {
        trust.add(X25519.publicKey(lSPrivate)!!)
        val gate = CoordinatedTrustGate()
        val responder = responder(gate)
        val admin = admin(gate)
        val target = Target()
        val challenge = responder.receive(1, target.hello(flags = 1), "peer-a", true)
        assertTrue(target.acceptChallenge(challenge).first)
        assertTrue(responder.receive(1, target.reveal(), "peer-a", true).frames.isEmpty())
        val request = target.statusRequest(ByteArray(16) { 0x55 }, ByteArray(12) { 0x44 }, 0)

        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        gate.afterDecisionEntered = {
            entered.countDown()
            assertTrue("the test must release the decision", release.await(5, TimeUnit.SECONDS))
        }
        val result = AtomicReference<PairingOutput?>(null)
        val decisionFailure = AtomicReference<Throwable?>(null)
        val decisionThread = Thread({
            try {
                result.set(responder.receive(1, request, "peer-a", true))
            } catch (error: Throwable) {
                decisionFailure.set(error)
            }
        }, "pairing-status")
        decisionThread.start()
        assertTrue("the status must hold the boundary", entered.await(5, TimeUnit.SECONDS))

        val forgotten = AtomicReference<Boolean?>(null)
        val forgetFailure = AtomicReference<Throwable?>(null)
        val forgetThread = Thread({
            try {
                forgotten.set(admin.forgetAll())
            } catch (error: Throwable) {
                forgetFailure.set(error)
            }
        }, "settings-forget")
        forgetThread.start()
        Thread.sleep(100)
        assertTrue("Forget must wait for the sealed status", forgetThread.isAlive)

        release.countDown()
        decisionThread.join(5_000)
        forgetThread.join(5_000)
        assertFalse(decisionThread.isAlive)
        assertFalse(forgetThread.isAlive)
        assertNull(decisionFailure.get())
        assertNull(forgetFailure.get())
        assertEquals(true, forgotten.get())
        assertEquals(0, trust.count)
        assertEquals(1, gate.revision())

        // The status answer was sealed before Forget ran. The boundary does not
        // pretend to recall that frame.
        val output = result.get()!!
        assertArrayEquals(
            ByteArray(16) { 0x55 },
            target.openStatus(output).copyOfRange(0, 16),
        )
    }

    @Test
    fun aForgetThatWinsRejectsAKnownStatusDecision() {
        trust.add(X25519.publicKey(lSPrivate)!!)
        val gate = CoordinatedTrustGate()
        val responder = responder(gate)
        val admin = admin(gate)
        val target = Target()
        val challenge = responder.receive(1, target.hello(flags = 1), "peer-a", true)
        assertTrue(target.acceptChallenge(challenge).first)
        val proof = responder.receive(1, target.reveal(), "peer-a", true)
        assertTrue(proof.frames.isEmpty())
        val request = target.statusRequest(ByteArray(16) { 0x55 }, ByteArray(12) { 0x44 }, 0)

        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        gate.beforeDecision = {
            entered.countDown()
            assertTrue("the test must release the decision", release.await(5, TimeUnit.SECONDS))
        }
        val result = AtomicReference<PairingOutput?>(null)
        val failure = AtomicReference<Throwable?>(null)
        val decisionThread = Thread({
            try {
                result.set(responder.receive(1, request, "peer-a", true))
            } catch (error: Throwable) {
                failure.set(error)
            }
        }, "pairing-status")
        decisionThread.start()
        assertTrue("the status must reach the boundary", entered.await(5, TimeUnit.SECONDS))

        assertTrue(admin.forgetAll())
        assertEquals(0, trust.count)
        release.countDown()
        decisionThread.join(5_000)
        assertFalse(decisionThread.isAlive)
        assertNull(failure.get())
        val output = result.get()!!
        assertEquals(PairingStatus.REJECTED, resultStatus(output))
        assertTrue(output.close)
        assertEquals(1, gate.revision())
    }

    @Test
    fun aTargetForgetUsesTheSameMutationBoundary() {
        trust.add(X25519.publicKey(lSPrivate)!!)
        val gate = CoordinatedTrustGate()
        val responder = responder(gate)
        val target = Target()
        val challenge = responder.receive(1, target.hello(flags = 2), "peer-a", true)
        assertTrue(target.acceptChallenge(challenge).first)
        responder.receive(1, target.reveal(), "peer-a", true)
        assertEquals(0, gate.revision())

        val forget = target.forgetRequest(ByteArray(12) { 0x44 }, ByteArray(0))
        val answer = responder.receive(1, forget, "peer-a", true)
        assertEquals(PairingStatus.OK, resultStatus(answer))
        assertEquals(0, trust.count)
        assertEquals(1, gate.revision())
    }

    @Test
    fun forgettingTheKeyDuringAKnownHandshakeRejectsAndStillRefunds() {
        val key = X25519.publicKey(lSPrivate)!!
        trust.add(key)
        val responder = responder()
        for (round in 0L until 8L) {
            val (target, output) = knownHello(responder, round, "peer-a")
            assertTrue(target.acceptChallenge(output).first)
            // The person taps Forget while the handshake runs.
            trust.remove(key)
            val answer = responder.receive(round, target.reveal(), "peer-a", true)
            assertEquals(PairingStatus.REJECTED, resultStatus(answer))
            assertTrue(answer.close)
            trust.add(key)
            responder.connectionClosed(round)
        }
        // The proof was verified, so every charge came back like on Rust and iOS.
        for (connection in 20L until 28L) {
            val (target, output) = knownHello(responder, connection, "peer-a")
            assertTrue(target.acceptChallenge(output).first)
            responder.connectionClosed(connection)
        }
        val (_, busy) = knownHello(responder, 40, "peer-a")
        assertEquals(PairingStatus.BUSY, resultStatus(busy))
    }

    @Test
    fun aKeyForgottenBeforeTheHelloIsChargedToTheUnknownBudget() {
        val key = X25519.publicKey(lSPrivate)!!
        trust.add(key)
        val responder = responder()
        trust.remove(key)
        for (connection in 0L until 4L) {
            val (target, output) = knownHello(responder, connection, "peer-a", flags = null)
            assertFalse(target.acceptChallenge(output).first)
            responder.connectionClosed(connection)
        }
        val (_, busy) = knownHello(responder, 10, "peer-a", flags = null)
        assertEquals(PairingStatus.BUSY, resultStatus(busy))
    }

    @Test
    fun interleavedSessionsFromOneAddressKeepTheBudgetBalanced() {
        trust.add(X25519.publicKey(lSPrivate)!!)
        val responder = responder()
        // Four sessions run at once from one address: two prove, two do not.
        val sessions = (0L until 4L).map { connection ->
            val (target, output) = knownHello(responder, connection, "peer-a", flags = null)
            assertTrue(target.acceptChallenge(output).first)
            connection to target
        }
        // Reveal out of order. Each verified proof returns only the charge that
        // its own session paid, so the two unproven charges stay.
        val order = listOf(2L, 0L, 3L, 1L)
        for (connection in order) {
            val target = sessions.first { it.first == connection }.second
            val reveal = if (connection % 2 == 0L) target.reveal() else tampered(target.reveal())
            responder.receive(connection, reveal, "peer-a", true)
            responder.connectionClosed(connection)
        }
        // 4 charged, 2 refunded: exactly 2 remain, so 6 more fit and the 7th is refused.
        for (connection in 10L until 16L) {
            val (target, output) = knownHello(responder, connection, "peer-a", flags = 1)
            assertTrue("claim $connection", target.acceptChallenge(output).first)
            responder.connectionClosed(connection)
        }
        val (_, busy) = knownHello(responder, 30, "peer-a", flags = 1)
        assertEquals(PairingStatus.BUSY, resultStatus(busy))
    }

    @Test
    fun aVerifiedProofRefundsOnlyItsOwnSessionCharge() {
        trust.add(X25519.publicKey(lSPrivate)!!)
        val responder = responder()

        // At t=0 the first known session is charged.
        val (older, olderOutput) = knownHello(responder, 1, "172.20.10.2")
        assertTrue(older.acceptChallenge(olderOutput).first)

        // At t=4 a second session from the same address is charged. Both are
        // live and each paid its own challenge.
        clock.now = 4_000
        val (newer, newerOutput) = knownHello(responder, 2, "172.20.10.2")
        assertTrue(newer.acceptChallenge(newerOutput).first)

        // Only the older session proves, before its 5 second deadline. Its
        // refund must remove the t=0 charge, not the latest t=4 charge.
        val proof = responder.receive(1, older.reveal(), "172.20.10.2", true)
        assertTrue(proof.frames.isEmpty())
        assertFalse(proof.close)
        responder.connectionClosed(1)
        responder.connectionClosed(2)

        // At t=61 the t=0 charge would have expired. The unproven t=4 charge
        // keeps its own window, so seven new claims fit and the eighth is
        // refused. Removing the latest charge would have allowed eight.
        clock.now = 61_000
        for (connection in 10L until 17L) {
            val (probe, output) = knownHello(responder, connection, "172.20.10.2")
            assertFalse("claim $connection after the refund", output.close)
            assertTrue(probe.acceptChallenge(output).first)
            responder.connectionClosed(connection)
        }
        val (_, busy) = knownHello(responder, 30, "172.20.10.2")
        assertEquals(PairingStatus.BUSY, resultStatus(busy))
        assertEquals(9, identity.ephemeralCalls)
        assertEquals(0, responder.activeSessions())
    }

    @Test
    fun aRefundNeverReturnsAnotherAddressesCharge() {
        trust.add(X25519.publicKey(lSPrivate)!!)
        val responder = responder()
        // peer-b spends its whole budget with bad proofs.
        for (round in 0L until 8L) {
            val (probe, output) = knownHello(responder, round, "peer-b", flags = null)
            assertTrue(probe.acceptChallenge(output).first)
            responder.receive(round, tampered(probe.reveal()), "peer-b", true)
            responder.connectionClosed(round)
        }
        // peer-a proves many times. Its refunds are its own.
        for (round in 100L until 130L) {
            val (probe, output) = knownHello(responder, round, "peer-a")
            assertTrue(probe.acceptChallenge(output).first)
            responder.receive(round, probe.reveal(), "peer-a", true)
            responder.connectionClosed(round)
        }
        val (_, busy) = knownHello(responder, 200, "peer-b", flags = null)
        assertEquals(PairingStatus.BUSY, resultStatus(busy))
    }

    @Test
    fun theKnownBudgetStopsAMapOfManyAddressesFromGrowingWithoutBound() {
        trust.add(X25519.publicKey(lSPrivate)!!)
        val responder = responder()
        var issued = 0
        for (index in 0 until 200) {
            val (_, output) = knownHello(responder, index.toLong(), "10.0.${index / 200}.${index % 200 + 1}")
            if (output.frames.isNotEmpty() && resultStatus(output) == null) issued += 1
            responder.connectionClosed(index.toLong())
        }
        // 16 in total across all addresses, whatever the address count.
        assertEquals(16, issued)
        assertEquals(16, identity.ephemeralCalls)
    }

    @Test
    fun threadsThatShareTheResponderLockGetNoMoreThanTheKnownBudgetWithBadProofs() {
        trust.add(X25519.publicKey(lSPrivate)!!)
        val responder = responder()
        val lock = Any()
        val issued = java.util.concurrent.atomic.AtomicInteger()
        val failures = java.util.concurrent.CopyOnWriteArrayList<Throwable>()
        // Four threads keep at most four sessions open, so the session limit
        // never answers BUSY. Only the budget can.
        val threads = (0 until 4).map { thread ->
            Thread {
                try {
                    for (attempt in 0 until 6) {
                        val connection = thread * 100L + attempt
                        val target = Target()
                        val output = synchronized(lock) {
                            responder.receive(connection, target.hello(1), "peer-a", true)
                        }
                        if (resultStatus(output) != null) continue
                        issued.incrementAndGet()
                        target.acceptChallenge(output)
                        val reveal = tampered(target.reveal())
                        synchronized(lock) {
                            responder.receive(connection, reveal, "peer-a", true)
                            responder.connectionClosed(connection)
                        }
                    }
                } catch (error: Throwable) {
                    failures.add(error)
                }
            }
        }
        threads.forEach { it.start() }
        threads.forEach { it.join(30_000) }
        assertTrue(failures.toString(), failures.isEmpty())
        assertEquals(8, issued.get())
        assertEquals(8, identity.ephemeralCalls)
        assertEquals(0, responder.activeSessions())
    }

    @Test
    fun threadsThatProveTheirKnownKeyAreNeverRefusedByTheBudget() {
        trust.add(X25519.publicKey(lSPrivate)!!)
        val responder = responder()
        val lock = Any()
        val refused = java.util.concurrent.atomic.AtomicInteger()
        val failures = java.util.concurrent.CopyOnWriteArrayList<Throwable>()
        val threads = (0 until 4).map { thread ->
            Thread {
                try {
                    for (attempt in 0 until 6) {
                        val connection = thread * 100L + attempt
                        val target = Target()
                        val output = synchronized(lock) {
                            responder.receive(connection, target.hello(1), "peer-a", true)
                        }
                        if (resultStatus(output) != null) {
                            refused.incrementAndGet()
                            continue
                        }
                        target.acceptChallenge(output)
                        val reveal = target.reveal()
                        synchronized(lock) {
                            responder.receive(connection, reveal, "peer-a", true)
                            responder.connectionClosed(connection)
                        }
                    }
                } catch (error: Throwable) {
                    failures.add(error)
                }
            }
        }
        threads.forEach { it.start() }
        threads.forEach { it.join(30_000) }
        assertTrue(failures.toString(), failures.isEmpty())
        // At most four proofs are in flight, below the limit of 8, so a real
        // target device is never refused by its own presence checks.
        assertEquals(0, refused.get())
        assertEquals(24, identity.ephemeralCalls)
        assertEquals(0, responder.activeSessions())
    }

    private fun outputText(output: PairingOutput): String =
        output.frames.joinToString("|") { String(it, Charsets.ISO_8859_1) }

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

    /**
     * A trust gate with test latches.
     *
     * The hooks run outside the lock for [beforeDecision] and
     * [beforeMutation], so a test can let the other side win the race.
     * [afterDecisionEntered] and [afterMutationEntered] run inside the lock,
     * so a test can hold the boundary open.
     */
    private class CoordinatedTrustGate : PairingTrustGate {
        private val lock = Any()
        private var revisionValue = 0L

        @Volatile
        var beforeDecision: (() -> Unit)? = null

        @Volatile
        var afterDecisionEntered: (() -> Unit)? = null

        @Volatile
        var beforeMutation: (() -> Unit)? = null

        @Volatile
        var afterMutationEntered: (() -> Unit)? = null

        override fun revision(): Long = synchronized(lock) { revisionValue }

        override fun <T> decision(block: (Long) -> T): T {
            beforeDecision?.invoke()
            return synchronized(lock) {
                afterDecisionEntered?.invoke()
                block(revisionValue)
            }
        }

        override fun <T> mutation(block: () -> T): T {
            beforeMutation?.invoke()
            return synchronized(lock) {
                afterMutationEntered?.invoke()
                val result = block()
                revisionValue += 1
                result
            }
        }
    }

    /** A trust store that counts the mutations that the responder makes. */
    private class ResponderRecordingTrustStore : PairingTrustStore {
        private val lock = Any()
        private val keys = LinkedHashSet<String>()
        var containsCalls = 0
        var addCalls = 0
        var removeCalls = 0

        fun seed(publicKey: ByteArray) {
            synchronized(lock) { keys.add(PairingProtocol.hex(publicKey)) }
        }

        override fun contains(publicKey: ByteArray): Boolean = synchronized(lock) {
            containsCalls += 1
            keys.contains(PairingProtocol.hex(publicKey))
        }

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
