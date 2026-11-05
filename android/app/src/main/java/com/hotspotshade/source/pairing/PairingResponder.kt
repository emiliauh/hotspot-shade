package com.hotspotshade.source.pairing

import com.hotspotshade.source.PairingTrustAdmin
import com.hotspotshade.source.TrustFingerprint
import com.hotspotshade.source.TrustedTarget
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicLong

/** A host connection identifier. The host keeps it stable for one connection. */
internal typealias ConnectionId = Long

/** Identifies one displayed decision, even if a connection ID is reused. */
internal class PromptId(val value: Long) {
    override fun equals(other: Any?): Boolean = other is PromptId && value == other.value

    override fun hashCode(): Int = value.hashCode()

    override fun toString(): String = "PromptId($value)"
}

/**
 * One atomic snapshot for the host to display and later approve or deny.
 *
 * Text output redacts the displayed code. A log line must not hold a value
 * that a person reads from the screen.
 */
internal class PairingPrompt(
    val id: PromptId,
    val connection: ConnectionId,
    val code: String,
) {
    override fun equals(other: Any?): Boolean = other is PairingPrompt &&
        id == other.id && connection == other.connection && code == other.code

    override fun hashCode(): Int = 31 * (31 * id.hashCode() + connection.hashCode()) + code.hashCode()

    override fun toString(): String =
        "PairingPrompt(id=$id, connection=$connection, code=[redacted])"
}

/** One host action after a frame, a timer expiry, or a user decision. */
internal class PairingOutput(
    val connection: ConnectionId,
    val frames: List<ByteArray>,
    val close: Boolean,
    val status: PairingStatus?,
) {
    override fun toString(): String =
        "PairingOutput(connection=$connection, frameCount=${frames.size}, close=$close, status=$status)"
}

/** The per-session identity material. A real host uses a fresh value each time. */
internal interface PairingIdentity {
    fun ephemeralSecret(): ByteArray

    fun nonce(): ByteArray
}

/** The platform random source. */
internal class SecureRandomPairingIdentity(
    private val random: SecureRandom = SecureRandom(),
) : PairingIdentity {
    override fun ephemeralSecret(): ByteArray = ByteArray(32).also { random.nextBytes(it) }

    override fun nonce(): ByteArray = ByteArray(12).also { random.nextBytes(it) }
}

/** The list of target-device static public keys that this source device trusts. */
internal interface PairingTrustStore {
    fun contains(publicKey: ByteArray): Boolean

    fun add(publicKey: ByteArray)

    fun remove(publicKey: ByteArray)

    val count: Int
}

/** A trust store in process memory. Use it for tests and previews only. */
internal class MemoryPairingTrustStore : PairingTrustStore, PairingTrustAdmin {
    private val lock = Any()
    private val keys = LinkedHashSet<String>()

    override fun contains(publicKey: ByteArray): Boolean =
        synchronized(lock) { keys.contains(PairingProtocol.hex(publicKey)) }

    override fun add(publicKey: ByteArray) {
        synchronized(lock) { keys.add(PairingProtocol.hex(publicKey)) }
    }

    override fun remove(publicKey: ByteArray) {
        synchronized(lock) { keys.remove(PairingProtocol.hex(publicKey)) }
    }

    override val count: Int
        get() = synchronized(lock) { keys.size }

    override fun targets(): List<TrustedTarget> = synchronized(lock) {
        keys.map { key -> TrustedTarget(id = key, label = TrustFingerprint.label(key)) }
            .sortedWith(compareBy({ it.label }, { it.id }))
    }

    override fun forget(id: String): Boolean = synchronized(lock) { keys.remove(id) }

    override fun forgetAll() {
        synchronized(lock) { keys.clear() }
    }

    fun clear() {
        synchronized(lock) { keys.clear() }
    }
}

private class InvalidBudget {
    val failures = mutableListOf<Long>()
    var until: Long = 0
    var level: Int = 0
}

private sealed interface Stage {
    class AwaitingReveal(
        val ephemeral: ByteArray,
        val pE: ByteArray,
        val commit: ByteArray,
    ) : Stage

    class AwaitingDecision(val keys: PairingKeys, val id: PromptId) : Stage

    class Authenticated(val keys: PairingKeys) : Stage
}

private class Session(
    val connection: ConnectionId,
    val lS: ByteArray,
    val known: Boolean,
    val flags: Int,
    var shownActive: Boolean,
    var deadline: Long,
    var firstDeactivate: Long?,
    val peer: String,
    val nonces: MutableList<ByteArray>,
    var stage: Stage,
)

/**
 * The source-device pairing responder state machine.
 *
 * One pairing decision runs at a time. The host calls every method on one
 * thread or with its own lock. Do not call one responder from two threads.
 *
 * The behavior matches `rust/src/source_pairing.rs`. The clock is monotonic
 * milliseconds. The state machine charges the per-address and global challenge
 * budgets before it creates the ephemeral secret, and only when the source
 * device has pairing credentials.
 */
internal class PairingResponder(
    private val trust: PairingTrustStore,
    private val credentials: () -> PairingCredentials?,
    private val status: () -> ProxyStatus?,
    private val identity: PairingIdentity,
    private val clock: () -> Long,
) {
    private val sessions = LinkedHashMap<ConnectionId, Session>()
    private val unknownBudget = HashMap<String, MutableList<Long>>()
    private val unknownChallenges = HashMap<String, MutableList<Long>>()
    private val invalidBudget = HashMap<String, InvalidBudget>()
    private val failures = HashMap<String, MutableList<Long>>()
    private val lockouts = HashMap<String, Long>()
    private var decision: ConnectionId? = null
    private var appActive = false
    private var lastNow = 0L

    /** Return the current unexpired prompt, or null. */
    fun pendingPrompt(): PairingPrompt? {
        val connection = decision ?: return null
        val session = sessions[connection] ?: return null
        val now = clock()
        if (now < lastNow || now >= session.deadline) return null
        val stage = session.stage as? Stage.AwaitingDecision ?: return null
        return PairingPrompt(
            id = stage.id,
            connection = connection,
            code = PairingProtocol.formatCode(PairingProtocol.sasCode(stage.keys.sas)),
        )
    }

    /** The earliest session deadline, or null. */
    fun nextDeadline(): Long? = sessions.values.minOfOrNull { it.deadline }

    /** The active session count. */
    fun activeSessions(): Int = sessions.size

    /** The recorded prompt failures. It holds no address and no key. */
    fun promptFailureCount(): Int = failures.values.sumOf { it.size }

    /**
     * Handle one complete frame payload. The length prefix is not part of
     * [frame].
     */
    fun receive(
        connection: ConnectionId,
        frame: ByteArray,
        peer: String,
        appActive: Boolean,
    ): PairingOutput {
        val canonicalPeer = PeerAddress.canonical(peer)
        val now = now()
        this.appActive = appActive
        if (appActive) {
            val active = decision
            if (active != null) {
                val pending = sessions[active]
                if (pending != null && pending.stage is Stage.AwaitingDecision &&
                    now < pending.deadline
                ) {
                    pending.shownActive = true
                }
            }
        }

        if (frame.isEmpty() || frame.size > PairingProtocol.MAX_FRAME) {
            val sessionPeer = sessions.remove(connection)?.also { it.wipe() }?.peer ?: canonicalPeer
            clearDecision(connection)
            return bad(connection, sessionPeer, now)
        }

        val existing = sessions.remove(connection)
        if (existing != null) {
            if (now >= existing.deadline) return expire(existing, now)
            when (val stage = existing.stage) {
                is Stage.AwaitingReveal -> return receiveReveal(existing, stage, frame, now)
                is Stage.AwaitingDecision -> {
                    val sessionPeer = existing.peer
                    clearDecision(connection)
                    existing.wipe()
                    return if ((frame[0].toInt() and 0xFF) == PairingProtocol.MSG_STATUS_REQ) {
                        reply(connection, PairingStatus.REJECTED, true)
                    } else {
                        bad(connection, sessionPeer, now)
                    }
                }

                is Stage.Authenticated -> return receiveAuthenticated(existing, stage, frame)
            }
        }

        if (sessions.size >= MAX_SESSIONS) {
            return reply(connection, PairingStatus.BUSY, false)
        }

        val hello = PairingProtocol.decodeHello(frame)
        if (hello == null) return bad(connection, canonicalPeer, now)
        val lS = hello.first
        val commit = hello.second
        val flags = if (frame.size == 67) frame[66].toInt() and 0xFF else 0
        val known = trust.contains(lS)

        if (flags > 2) return reply(connection, PairingStatus.REJECTED, false)
        if (!known && flags != 0) return reply(connection, PairingStatus.REJECTED, false)
        if (!known && isLocked(canonicalPeer, now)) {
            return reply(connection, PairingStatus.LOCKED_OUT, true)
        }
        if (!known && invalidBackoffActive(canonicalPeer, now)) {
            return reply(connection, PairingStatus.REJECTED, true)
        }
        if (!known) {
            if (credentials() == null) {
                return reply(connection, PairingStatus.NOT_ACTIVE, true)
            }
            pruneChallenges(now)
            if (challengeBudgetUsed(canonicalPeer)) {
                return reply(connection, PairingStatus.BUSY, false)
            }
            chargeChallenge(canonicalPeer, now)
        }

        val secret = identity.ephemeralSecret()
        if (secret.size != 32) {
            secret.fill(0)
            throw PairingException(PairingError.IDENTITY)
        }
        val publicEphemeral = X25519.publicKey(secret)
        if (publicEphemeral == null) {
            secret.fill(0)
            throw PairingException(PairingError.IDENTITY)
        }
        val challenge = PairingProtocol.frame(
            PairingProtocol.encodeChallenge(publicEphemeral, known),
        )
        val deadline = now + REVEAL_MILLIS
        sessions[connection] = Session(
            connection = connection,
            lS = lS,
            known = known,
            flags = flags,
            shownActive = false,
            deadline = deadline,
            firstDeactivate = null,
            peer = canonicalPeer,
            nonces = mutableListOf(),
            stage = Stage.AwaitingReveal(secret, publicEphemeral, commit),
        )
        return PairingOutput(connection, listOf(challenge), false, null)
    }

    /**
     * Handle a frame parser error. This method removes the session and the
     * decision before it checks the peer text. A failed check must not leak a
     * session slot or leave a prompt unanswerable.
     */
    fun receiveInvalid(connection: ConnectionId, peer: String): PairingOutput {
        val sessionPeer = sessions.remove(connection)?.also { it.wipe() }?.peer
        clearDecision(connection)
        val canonicalPeer = PeerAddress.canonical(peer)
        val now = now()
        return bad(connection, sessionPeer ?: canonicalPeer, now)
    }

    /**
     * Apply the user decision to the pending prompt. The connection, the
     * prompt ID, and the code must name the prompt that the person saw.
     */
    fun decide(
        connection: ConnectionId,
        promptId: PromptId,
        code: String,
        allow: Boolean,
    ): PairingOutput? {
        val now = now()
        if (decision != connection) return null
        val current = sessions[connection] ?: return null
        val stage = current.stage as? Stage.AwaitingDecision ?: return null
        val expectedCode = PairingProtocol.formatCode(PairingProtocol.sasCode(stage.keys.sas))
        if (stage.id != promptId || expectedCode != code) return null
        if (now >= current.deadline) {
            sessions.remove(connection)
            return expire(current, now)
        }
        decision = null
        sessions.remove(connection)
        if (!allow) {
            current.wipe()
            return finish(connection, current.peer, PairingStatus.DENIED, now)
        }
        return success(current, stage.keys, now, addTrust = true)
    }

    /** Expire the earliest session whose deadline passed. */
    fun tick(): PairingOutput? {
        val now = now()
        val connection = sessions.entries
            .filter { now >= it.value.deadline }
            .minByOrNull { it.value.deadline }
            ?.key
            ?: return null
        val session = sessions.remove(connection) ?: return null
        return expire(session, now)
    }

    /** Mark the app as active. A live prompt becomes visible. */
    fun activate() {
        appActive = true
        val now = clock()
        if (now < lastNow) return
        lastNow = now
        val connection = decision ?: return
        val session = sessions[connection] ?: return
        if (session.stage is Stage.AwaitingDecision && now < session.deadline) {
            session.shownActive = true
        }
    }

    /**
     * Mark the app as inactive. A live prompt gets at most 120 seconds after
     * the first inactive notice. Repeated calls cannot extend it past that
     * limit.
     */
    fun deactivate(): PairingOutput? {
        val now = now()
        appActive = false
        val connection = decision ?: return null
        val session = sessions[connection] ?: return null
        if (session.stage !is Stage.AwaitingDecision) return null
        if (now >= session.deadline) {
            sessions.remove(connection)
            return expire(session, now)
        }
        val first = session.firstDeactivate ?: now.also { session.firstDeactivate = it }
        val cap = first + INACTIVE_DECISION_MILLIS
        val extended = minOf(now + INACTIVE_DECISION_MILLIS, cap)
        if (extended > session.deadline) session.deadline = extended
        return null
    }

    /** Drop all state for one closed connection. */
    fun connectionClosed(connection: ConnectionId) {
        sessions.remove(connection)?.wipe()
        clearDecision(connection)
        pruneAll()
    }

    private fun receiveReveal(
        session: Session,
        stage: Stage.AwaitingReveal,
        frame: ByteArray,
        now: Long,
    ): PairingOutput {
        val reveal = PairingProtocol.decodeReveal(frame)
        if (reveal == null) {
            session.wipe()
            return bad(session.connection, session.peer, now)
        }
        val lE = reveal.first
        val proof = reveal.second
        if (!PairingProtocol.commitment(lE, session.lS).contentEquals(stage.commit)) {
            session.wipe()
            return bad(session.connection, session.peer, now)
        }
        val ee = X25519.agree(stage.ephemeral, lE)
        val es = X25519.agree(stage.ephemeral, session.lS)
        if (ee == null || es == null) {
            session.wipe()
            return bad(session.connection, session.peer, now)
        }
        val h = PairingProtocol.transcriptHash(session.lS, lE, stage.pE)
        val keys = PairingProtocol.deriveKeys(ee, es, h)
        ee.fill(0)
        es.fill(0)
        h.fill(0)
        if (!PairingProtocol.verifyProof(keys, proof)) {
            keys.wipe()
            session.wipe()
            return bad(session.connection, session.peer, now)
        }
        stage.ephemeral.fill(0)
        stage.pE.fill(0)

        if (session.known) {
            if (!trust.contains(session.lS)) {
                keys.wipe()
                return reply(session.connection, PairingStatus.REJECTED, true)
            }
            if (session.flags == 0) {
                return success(session, keys, now, addTrust = false)
            }
            session.stage = Stage.Authenticated(keys)
            session.deadline = now + REVEAL_MILLIS
            sessions[session.connection] = session
            return PairingOutput(session.connection, emptyList(), false, null)
        }

        val active = decision
        if (active != null && sessions[active] == null) {
            decision = null
        }
        if (decision != null) {
            keys.wipe()
            return reply(session.connection, PairingStatus.BUSY, true)
        }
        if (credentials() == null) {
            keys.wipe()
            return reply(session.connection, PairingStatus.NOT_ACTIVE, true)
        }
        pruneUnknown(now)
        if (!unknownBudget.containsKey(session.peer) && unknownBudget.size >= MAX_TRACKED_PEERS) {
            keys.wipe()
            return reply(session.connection, PairingStatus.LOCKED_OUT, true)
        }
        val attempts = unknownBudget.getOrPut(session.peer) { mutableListOf() }
        if (attempts.size >= MAX_UNKNOWN_ATTEMPTS) {
            keys.wipe()
            return reply(session.connection, PairingStatus.LOCKED_OUT, true)
        }
        attempts.add(now)

        session.deadline = now + if (appActive) DECISION_MILLIS else INACTIVE_DECISION_MILLIS
        session.shownActive = appActive
        session.stage = Stage.AwaitingDecision(keys, nextPromptId())
        sessions[session.connection] = session
        decision = session.connection
        return PairingOutput(session.connection, emptyList(), false, null)
    }

    private fun success(
        session: Session,
        keys: PairingKeys,
        now: Long,
        addTrust: Boolean,
    ): PairingOutput {
        val current = credentials()
        if (current == null) {
            keys.wipe()
            return reply(session.connection, PairingStatus.NOT_ACTIVE, true)
        }
        val nonce = identity.nonce()
        if (nonce.size != 12 || session.nonces.any { it.contentEquals(nonce) } ||
            session.nonces.size >= MAX_SESSION_NONCES
        ) {
            nonce.fill(0)
            keys.wipe()
            throw PairingException(PairingError.IDENTITY)
        }
        val ciphertext = try {
            PairingProtocol.sealCredentials(keys, nonce, current)
        } catch (failure: Exception) {
            nonce.fill(0)
            keys.wipe()
            throw failure
        }
        val message = PairingProtocol.frame(
            PairingProtocol.encodeResultOk(nonce, ciphertext),
        )
        if (addTrust) {
            try {
                trust.add(session.lS)
            } catch (failure: Exception) {
                nonce.fill(0)
                ciphertext.fill(0)
                keys.wipe()
                throw failure
            }
        }
        session.nonces.add(nonce)
        session.stage = Stage.Authenticated(keys)
        session.deadline = now + REVEAL_MILLIS
        sessions[session.connection] = session
        return PairingOutput(
            session.connection,
            listOf(message),
            false,
            PairingStatus.OK,
        )
    }

    private fun receiveAuthenticated(
        session: Session,
        stage: Stage.Authenticated,
        frame: ByteArray,
    ): PairingOutput {
        val keys = stage.keys
        if (frame.size < 29 || !trust.contains(session.lS)) {
            keys.wipe()
            return reply(session.connection, PairingStatus.REJECTED, true)
        }
        if (session.flags == 2) {
            if ((frame[0].toInt() and 0xFF) != PairingProtocol.MSG_FORGET) {
                keys.wipe()
                return reply(session.connection, PairingStatus.REJECTED, true)
            }
            val plaintext = openCommand(keys, frame, PairingProtocol.MSG_FORGET)
            if (plaintext == null || plaintext.isNotEmpty()) {
                plaintext?.fill(0)
                keys.wipe()
                return reply(session.connection, PairingStatus.REJECTED, true)
            }
            plaintext.fill(0)
            try {
                trust.remove(session.lS)
            } finally {
                keys.wipe()
            }
            return reply(session.connection, PairingStatus.OK, false)
        }
        if (session.flags > 1) {
            keys.wipe()
            return reply(session.connection, PairingStatus.REJECTED, true)
        }
        if ((frame[0].toInt() and 0xFF) != PairingProtocol.MSG_STATUS_REQ) {
            keys.wipe()
            return reply(session.connection, PairingStatus.REJECTED, true)
        }
        val plaintext = openCommand(keys, frame, PairingProtocol.MSG_STATUS_REQ)
        if (plaintext == null || plaintext.size != 17 || plaintext[16] != 0.toByte()) {
            plaintext?.fill(0)
            keys.wipe()
            return reply(session.connection, PairingStatus.REJECTED, true)
        }
        val currentStatus = status()
        val currentCredentials = credentials()
        if (currentStatus == null || currentCredentials == null ||
            currentStatus.host != currentCredentials.host
        ) {
            plaintext.fill(0)
            keys.wipe()
            return reply(session.connection, PairingStatus.REJECTED, true)
        }
        val message = try {
            PairingProtocol.encodeStatus(currentStatus, plaintext.copyOfRange(0, 16))
        } catch (failure: Exception) {
            plaintext.fill(0)
            keys.wipe()
            throw failure
        }
        plaintext.fill(0)
        val nonce = identity.nonce()
        if (nonce.size != 12 || session.nonces.any { it.contentEquals(nonce) } ||
            session.nonces.size >= MAX_SESSION_NONCES
        ) {
            nonce.fill(0)
            keys.wipe()
            throw PairingException(PairingError.IDENTITY)
        }
        val ciphertext = try {
            PairingProtocol.sealMessage(keys, nonce, message)
        } catch (failure: Exception) {
            nonce.fill(0)
            keys.wipe()
            throw failure
        }
        val payload = ByteArray(1 + 12 + ciphertext.size)
        payload[0] = PairingProtocol.MSG_STATUS.toByte()
        nonce.copyInto(payload, 1)
        ciphertext.copyInto(payload, 13)
        keys.wipe()
        return PairingOutput(
            session.connection,
            listOf(PairingProtocol.frame(payload)),
            true,
            null,
        )
    }

    private fun expire(session: Session, now: Long): PairingOutput {
        val connection = session.connection
        val counts = session.stage is Stage.AwaitingDecision && session.shownActive && appActive
        val peer = session.peer
        clearDecision(connection)
        session.wipe()
        return if (counts) {
            finish(connection, peer, PairingStatus.TIMED_OUT, now)
        } else {
            reply(connection, PairingStatus.TIMED_OUT, true)
        }
    }

    private fun finish(
        connection: ConnectionId,
        peer: String,
        pairingStatus: PairingStatus,
        now: Long,
    ): PairingOutput {
        val recent = failures[peer]?.filter { now - it < FAILURE_WINDOW_MILLIS }?.toMutableList()
            ?: mutableListOf()
        recent.add(now)
        if (recent.size >= FAILURES_FOR_LOCKOUT) {
            lockouts.entries.removeAll { now >= it.value }
            if (lockouts.containsKey(peer) || lockouts.size < MAX_TRACKED_PEERS) {
                lockouts[peer] = now + LOCKOUT_MILLIS
            }
            unknownBudget.remove(peer)
            recent.clear()
        }
        if (recent.isEmpty()) {
            failures.remove(peer)
        } else if (failures.containsKey(peer) || failures.size < MAX_TRACKED_PEERS) {
            failures[peer] = recent
        }
        return reply(connection, pairingStatus, true)
    }

    private fun bad(connection: ConnectionId, peer: String, now: Long): PairingOutput {
        pruneInvalid(now)
        if (invalidBudget.containsKey(peer) || invalidBudget.size < MAX_TRACKED_PEERS) {
            val budget = invalidBudget.getOrPut(peer) { InvalidBudget() }
            budget.failures.removeAll { now - it >= INVALID_WINDOW_MILLIS }
            budget.failures.add(now)
            if (budget.failures.size >= MAX_INVALID_FAILURES) {
                val seconds = 1L shl budget.level.coerceAtMost(MAX_BACKOFF_LEVEL)
                budget.until = now + seconds * 1000
                budget.level = (budget.level + 1).coerceAtMost(MAX_BACKOFF_LEVEL)
                budget.failures.clear()
            }
        }
        return reply(connection, PairingStatus.REJECTED, true)
    }

    private fun reply(
        connection: ConnectionId,
        pairingStatus: PairingStatus,
        log: Boolean,
    ): PairingOutput {
        clearDecision(connection)
        return PairingOutput(
            connection,
            listOf(PairingProtocol.frame(PairingProtocol.encodeResultStatus(pairingStatus))),
            true,
            if (log) pairingStatus else null,
        )
    }

    private fun clearDecision(connection: ConnectionId) {
        if (decision == connection) decision = null
    }

    private fun isLocked(peer: String, now: Long): Boolean {
        lockouts.entries.removeAll { now >= it.value }
        return lockouts.containsKey(peer)
    }

    private fun invalidBackoffActive(peer: String, now: Long): Boolean {
        pruneInvalid(now)
        return invalidBudget[peer]?.let { now < it.until } ?: false
    }

    private fun pruneUnknown(now: Long) {
        unknownBudget.entries.removeAll { (_, attempts) ->
            attempts.removeAll { now - it >= UNKNOWN_WINDOW_MILLIS }
            attempts.isEmpty()
        }
    }

    private fun pruneChallenges(now: Long) {
        unknownChallenges.entries.removeAll { (_, challenges) ->
            challenges.removeAll { now - it >= CHALLENGE_WINDOW_MILLIS }
            challenges.isEmpty()
        }
    }

    private fun challengeBudgetUsed(peer: String): Boolean {
        val peerCount = unknownChallenges[peer]?.size ?: 0
        val total = unknownChallenges.values.sumOf { it.size }
        return peerCount >= MAX_PEER_CHALLENGES || total >= MAX_UNKNOWN_CHALLENGES
    }

    private fun chargeChallenge(peer: String, now: Long) {
        unknownChallenges.getOrPut(peer) { mutableListOf() }.add(now)
    }

    private fun pruneInvalid(now: Long) {
        invalidBudget.entries.removeAll { (_, budget) ->
            budget.failures.removeAll { now - it >= INVALID_WINDOW_MILLIS }
            now < budget.until || budget.failures.isNotEmpty()
        }
    }

    private fun pruneAll() {
        val now = lastNow
        pruneUnknown(now)
        pruneChallenges(now)
        pruneInvalid(now)
        failures.entries.removeAll { (_, recent) ->
            recent.removeAll { now - it >= FAILURE_WINDOW_MILLIS }
            recent.isEmpty()
        }
        lockouts.entries.removeAll { now >= it.value }
    }

    private fun now(): Long {
        val now = clock()
        if (now < lastNow) throw PairingException(PairingError.CLOCK)
        lastNow = now
        return now
    }

    private fun openCommand(
        keys: PairingKeys,
        frame: ByteArray,
        messageType: Int,
    ): ByteArray? {
        if (frame.size < 29 || (frame[0].toInt() and 0xFF) != messageType) return null
        val nonce = frame.copyOfRange(1, 13)
        val ciphertext = frame.copyOfRange(13, frame.size)
        val plaintext = PairingProtocol.openMessage(keys, nonce, ciphertext)
        nonce.fill(0)
        ciphertext.fill(0)
        return plaintext
    }

    private fun Session.wipe() {
        when (val current = stage) {
            is Stage.AwaitingReveal -> {
                current.ephemeral.fill(0)
                current.pE.fill(0)
                current.commit.fill(0)
            }

            is Stage.AwaitingDecision -> current.keys.wipe()
            is Stage.Authenticated -> current.keys.wipe()
        }
        for (nonce in nonces) nonce.fill(0)
        nonces.clear()
    }

    private fun nextPromptId(): PromptId {
        val value = NEXT_PROMPT_ID.getAndIncrement()
        if (value <= 0) throw PairingException(PairingError.PROTOCOL)
        return PromptId(value)
    }

    private companion object {
        const val MAX_SESSIONS = 4
        const val MAX_TRACKED_PEERS = 256
        const val MAX_UNKNOWN_ATTEMPTS = 3
        const val MAX_INVALID_FAILURES = 10
        const val FAILURES_FOR_LOCKOUT = 3
        const val MAX_BACKOFF_LEVEL = 2
        const val REVEAL_MILLIS = 5_000L
        const val DECISION_MILLIS = 60_000L
        const val INACTIVE_DECISION_MILLIS = 120_000L
        const val LOCKOUT_MILLIS = 30_000L
        const val UNKNOWN_WINDOW_MILLIS = 600_000L
        const val FAILURE_WINDOW_MILLIS = 60_000L
        const val INVALID_WINDOW_MILLIS = 60_000L
        const val MAX_SESSION_NONCES = 4
        const val MAX_UNKNOWN_CHALLENGES = 8
        const val MAX_PEER_CHALLENGES = 4
        const val CHALLENGE_WINDOW_MILLIS = 60_000L
        val NEXT_PROMPT_ID = AtomicLong(1)
    }
}
