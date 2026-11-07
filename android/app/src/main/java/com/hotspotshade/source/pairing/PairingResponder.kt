package com.hotspotshade.source.pairing

import com.hotspotshade.source.PairingTrustAdmin
import com.hotspotshade.source.PairingTrustGate
import com.hotspotshade.source.ProcessPairingTrustGate
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
    /**
     * True when a success could not be sealed because the token could not be
     * saved. The frames carry a fixed rejection, and no trust was added.
     */
    val tokenCommitFailed: Boolean = false,
) {
    override fun toString(): String =
        "PairingOutput(connection=$connection, frameCount=${frames.size}, " +
            "close=$close, status=$status, tokenCommitFailed=$tokenCommitFailed)"
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

/** A trust store in process memory. Tests use it. The app does not. */
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

/**
 * One charge in a challenge budget.
 *
 * [id] names the session that paid the charge. [at] is the charge time, which
 * keeps its own expiry even if another session proves later.
 */
private class ChallengeCharge(val id: Long, val at: Long)

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
    /** The challenge charge that this session paid. A verified known proof refunds this exact charge. */
    val charge: Long,
    var stage: Stage,
)

/**
 * What one pairing responder may answer.
 *
 * [FULL] is the visible pairing listener. It keeps the v1 behavior: a trusted
 * target may pair again without a prompt, an unknown target reaches the host
 * prompt, and a trusted target may send Forget.
 *
 * [STATUS_ONLY] is the background status listener. It answers an authenticated
 * status request from a trusted target and rejects pairing, re-pairing, and
 * Forget before any credential callback, prompt, or trust mutation. An unknown
 * key is rejected before a challenge, so no prompt can exist in the
 * background.
 */
internal enum class PairingResponderMode {
    FULL,
    STATUS_ONLY,
}

/**
 * The source-device pairing responder state machine.
 *
 * One pairing decision runs at a time. The host calls every method on one
 * thread or with its own lock. Do not call one responder from two threads.
 * The trust check that allows a credential or status answer, and the build that
 * depends on it, run under [PairingTrustGate]. An administrative Forget that
 * uses the same gate is therefore ordered before the check or after the sealed
 * result. It cannot interleave a stale trust read with a credential build.
 *
 * The behavior matches `rust/src/source_pairing.rs`. The clock is monotonic
 * milliseconds. The state machine charges the per-address and global challenge
 * budgets before it creates the ephemeral secret. An unknown key is charged
 * only when the source device has pairing credentials.
 *
 * A HELLO that claims a trusted key uses a separate known-claim budget:
 * [MAX_KNOWN_PEER_CHALLENGES] for one source address and
 * [MAX_KNOWN_CHALLENGES] across all source addresses in the same window. A
 * public key is public, so the claim is unproven until the REVEAL proof. A
 * verified proof refunds exactly the charge that its own session paid, so a
 * real target device is not limited by its own presence checks and a staggered
 * unproven session keeps its charge and expiry. A bad proof, a timeout, and a
 * closed connection do not refund. The budgets are an availability limit, not
 * an authentication limit.
 */
internal class PairingResponder(
    private val trust: PairingTrustStore,
    private val credentials: () -> PairingCredentials?,
    private val status: () -> ProxyStatus? = { null },
    private val identity: PairingIdentity,
    private val clock: () -> Long,
    /**
     * Persist the token before a success result is sealed or trust is added.
     *
     * The source token must be stored before the target device receives it.
     * Return false on a failed or superseded write; the responder then sends a
     * fixed rejection and adds no trust. This callback runs while the listener
     * holds its own lock, so it must not call back into the listener.
     */
    private val commitToken: (String) -> Boolean = { true },
    /**
     * Build the status answer from the same credential snapshot that the
     * caller just built. This avoids a second port probe. When it is null the
     * older [status] callback is used.
     */
    private val statusFor: ((PairingCredentials) -> ProxyStatus?)? = null,
    /**
     * Serialize a trust decision with the credential or status build that
     * depends on it. The app uses the process gate so a settings Forget and
     * this responder share one boundary.
     */
    private val trustGate: PairingTrustGate = ProcessPairingTrustGate,
    /**
     * The visible listener uses [PairingResponderMode.FULL]. The background
     * status listener uses [PairingResponderMode.STATUS_ONLY], which rejects
     * pairing and Forget before any credential callback, prompt, or trust
     * mutation.
     */
    private val mode: PairingResponderMode = PairingResponderMode.FULL,
) {
    private val statusOnly = mode == PairingResponderMode.STATUS_ONLY
    private val sessions = LinkedHashMap<ConnectionId, Session>()
    private val unknownBudget = HashMap<String, MutableList<Long>>()
    private val unknownChallenges = HashMap<String, MutableList<ChallengeCharge>>()

    /**
     * The charges of the challenges for a claimed trusted key, for each source
     * address. The sum of the lists is at most [MAX_KNOWN_CHALLENGES], so the
     * map stays small. Each charge has a unique identifier, so a refund removes
     * the proven session's charge and no other.
     */
    private val knownChallenges = HashMap<String, MutableList<ChallengeCharge>>()

    /**
     * The next challenge identifier. It is unique for the life of the
     * responder. Wrapping after 2^63 charges cannot collide with a live charge
     * in practice.
     */
    private var nextChallengeId = 0L
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

    /** The count of tracked invalid-message budgets. The map stays bounded. */
    internal fun trackedInvalidPeers(): Int = invalidBudget.size

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
        // The background listener serves an authenticated status request from
        // a trusted key only. Reject a pairing (flag 0), a re-pairing (flag 0
        // from a trusted key), and Forget (flag 2) before trust is read, a
        // challenge is charged, a credential callback runs, or a prompt can
        // exist. A malformed flag above 2 takes the same path.
        if (statusOnly && flags != 1) {
            return reply(connection, PairingStatus.REJECTED, false)
        }
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
            // A source device with pairing off answers NOT_ACTIVE. It must not
            // charge the challenge budget, or the peer is locked out later.
            if (credentials() == null) {
                return reply(connection, PairingStatus.NOT_ACTIVE, true)
            }
        }
        pruneChallenges(now)
        // Charge the per-address and global budgets before the ephemeral
        // secret exists. A claimed trusted key is unproven until the REVEAL
        // proof, so it pays the known-claim budget.
        if (challengeBudgetUsed(canonicalPeer, known)) {
            return reply(connection, PairingStatus.BUSY, false)
        }
        val charge = chargeChallenge(canonicalPeer, now, known)

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
            charge = charge,
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
            // The proof shows that the peer holds the claimed key, so the
            // challenge was not wasted work. Refund exactly this session's
            // charge, not the latest charge for the address, so a staggered
            // unproven session keeps its own charge and its own expiry.
            refundKnownChallenge(session.peer, session.charge)
            // The trust list can change while the handshake runs. Recheck it
            // and build the credentials or authenticated session under one
            // decision boundary, so a concurrent Forget is ordered before this
            // check or after the result is sealed.
            return trustGate.decision {
                if (!trust.contains(session.lS)) {
                    keys.wipe()
                    return@decision reply(session.connection, PairingStatus.REJECTED, true)
                }
                if (statusOnly && session.flags != 1) {
                    // Defense in depth. The HELLO gate above already rejects
                    // this value before a session exists. Keep the check here
                    // too, so no later change can reach the credential path.
                    keys.wipe()
                    return@decision reply(session.connection, PairingStatus.REJECTED, true)
                }
                if (session.flags == 0) {
                    successLocked(session, keys, now, addTrust = false)
                } else {
                    session.stage = Stage.Authenticated(keys)
                    session.deadline = now + REVEAL_MILLIS
                    sessions[session.connection] = session
                    PairingOutput(session.connection, emptyList(), false, null)
                }
            }
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

    /**
     * Build a success result under the trust decision boundary.
     *
     * For a newly approved target this boundary covers the credential
     * snapshot, the token commit, and the trust add. For a known target the
     * caller already rechecked trust inside the same boundary and calls
     * [successLocked] directly. A concurrent Forget therefore runs before the
     * boundary section or after the result is sealed. It cannot remove trust
     * between a check and a credential build.
     */
    private fun success(
        session: Session,
        keys: PairingKeys,
        now: Long,
        addTrust: Boolean,
    ): PairingOutput = trustGate.decision {
        successLocked(session, keys, now, addTrust)
    }

    private fun successLocked(
        session: Session,
        keys: PairingKeys,
        now: Long,
        addTrust: Boolean,
    ): PairingOutput {
        if (statusOnly) {
            // The background listener never seals credentials. Check this
            // before the credential callback, so a future pairing path cannot
            // disclose the token even if it forgets the HELLO gate.
            keys.wipe()
            return reply(session.connection, PairingStatus.REJECTED, true)
        }
        val current = credentials()
        if (current == null) {
            keys.wipe()
            return reply(session.connection, PairingStatus.NOT_ACTIVE, true)
        }
        // The token must be durable before the target device sees it and
        // before this source device trusts the target. A failed or superseded
        // write sends a fixed rejection, adds no trust, and seals nothing.
        if (!commitToken(current.token)) {
            keys.wipe()
            return reply(
                session.connection,
                PairingStatus.REJECTED,
                true,
                tokenCommitFailed = true,
            )
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
            } catch (_: Exception) {
                nonce.fill(0)
                ciphertext.fill(0)
                keys.wipe()
                // A trust-store failure is a local failure. Send a rejection
                // and close instead of leaking an unchecked exception to the
                // host callback. The saved token stays in place: the same
                // token is still the active source token, and the next pairing
                // can add trust.
                return reply(session.connection, PairingStatus.REJECTED, true)
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
        if (frame.size < 29) {
            keys.wipe()
            return reply(session.connection, PairingStatus.REJECTED, true)
        }
        if (statusOnly && session.flags != 1) {
            // Defense in depth. The HELLO gate above never creates a Forget or
            // pairing session in status-only mode. This check runs before the
            // trust mutation below, so a future path cannot remove a key in
            // the background.
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
            // The target device asks to forget itself. The check and the
            // removal use the same mutation boundary as the settings page, so
            // the two cannot interleave a stale trust read and a write.
            return trustGate.mutation {
                if (!trust.contains(session.lS)) {
                    keys.wipe()
                    return@mutation reply(session.connection, PairingStatus.REJECTED, true)
                }
                try {
                    trust.remove(session.lS)
                } finally {
                    keys.wipe()
                }
                reply(session.connection, PairingStatus.OK, false)
            }
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
        // The trust check, the credential snapshot, the status snapshot, and
        // the sealed answer are one decision. A concurrent Forget is ordered
        // before this check or after the answer is sealed; it cannot remove
        // trust between the check and the status build.
        return trustGate.decision {
            if (!trust.contains(session.lS)) {
                plaintext.fill(0)
                keys.wipe()
                return@decision reply(session.connection, PairingStatus.REJECTED, true)
            }
            val currentCredentials = credentials()
            if (currentCredentials == null) {
                plaintext.fill(0)
                keys.wipe()
                return@decision reply(session.connection, PairingStatus.REJECTED, true)
            }
            val currentStatus = statusFor?.invoke(currentCredentials) ?: status()
            if (currentStatus == null || currentStatus.host != currentCredentials.host) {
                plaintext.fill(0)
                keys.wipe()
                return@decision reply(session.connection, PairingStatus.REJECTED, true)
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
            PairingOutput(
                session.connection,
                listOf(PairingProtocol.frame(payload)),
                true,
                null,
            )
        }
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
            if (!lockouts.containsKey(peer) && lockouts.size >= MAX_TRACKED_PEERS) {
                evictSoonestLockout()
            }
            lockouts[peer] = now + LOCKOUT_MILLIS
            unknownBudget.remove(peer)
            recent.clear()
        }
        if (recent.isEmpty()) {
            failures.remove(peer)
        } else {
            if (!failures.containsKey(peer) && failures.size >= MAX_TRACKED_PEERS) {
                evictOldestFailure()
            }
            failures[peer] = recent
        }
        return reply(connection, pairingStatus, true)
    }

    private fun bad(connection: ConnectionId, peer: String, now: Long): PairingOutput {
        pruneInvalid(now)
        val budget = invalidBudget[peer] ?: run {
            if (invalidBudget.size >= MAX_TRACKED_PEERS) {
                // The map is full. Evict the record that expires first, so the
                // new peer still gets its own budget. Do not drop the record
                // for the new peer: that would let one address rotate its
                // peers and keep the fast path open.
                evictOldestInvalid()
            }
            InvalidBudget().also { invalidBudget[peer] = it }
        }
        budget.failures.removeAll { now - it >= INVALID_WINDOW_MILLIS }
        budget.failures.add(now)
        if (budget.failures.size >= MAX_INVALID_FAILURES) {
            val seconds = 1L shl budget.level.coerceAtMost(MAX_BACKOFF_LEVEL)
            budget.until = now + seconds * 1000
            budget.level = (budget.level + 1).coerceAtMost(MAX_BACKOFF_LEVEL)
            budget.failures.clear()
        }
        return reply(connection, PairingStatus.REJECTED, true)
    }

    private fun reply(
        connection: ConnectionId,
        pairingStatus: PairingStatus,
        log: Boolean,
        tokenCommitFailed: Boolean = false,
    ): PairingOutput {
        clearDecision(connection)
        return PairingOutput(
            connection,
            listOf(PairingProtocol.frame(PairingProtocol.encodeResultStatus(pairingStatus))),
            true,
            if (log) pairingStatus else null,
            tokenCommitFailed,
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
        for (map in listOf(unknownChallenges, knownChallenges)) {
            map.entries.removeAll { (_, challenges) ->
                challenges.removeAll { now - it.at >= CHALLENGE_WINDOW_MILLIS }
                challenges.isEmpty()
            }
        }
    }

    /**
     * True when the source address or the whole responder has no challenge
     * budget left for the current window. A claimed trusted key uses its own
     * budget. Call [pruneChallenges] first.
     */
    private fun challengeBudgetUsed(peer: String, known: Boolean): Boolean {
        val map = if (known) knownChallenges else unknownChallenges
        val peerLimit = if (known) MAX_KNOWN_PEER_CHALLENGES else MAX_PEER_CHALLENGES
        val globalLimit = if (known) MAX_KNOWN_CHALLENGES else MAX_UNKNOWN_CHALLENGES
        val peerCount = map[peer]?.size ?: 0
        val total = map.values.sumOf { it.size }
        return peerCount >= peerLimit || total >= globalLimit
    }

    /**
     * Charge one challenge and return its identifier. The caller stores the
     * identifier in the session that the charge paid for. The budget check runs
     * first, so the map never holds more than its global limit.
     */
    private fun chargeChallenge(peer: String, now: Long, known: Boolean): Long {
        val id = nextChallengeId
        nextChallengeId += 1
        val map = if (known) knownChallenges else unknownChallenges
        map.getOrPut(peer) { mutableListOf() }.add(ChallengeCharge(id, now))
        return id
    }

    /**
     * Return one known-challenge charge after a verified proof. The caller
     * passes the identifier that the proven session recorded, so the refund
     * cannot return a later unproven charge for the same address. A charge that
     * already expired is a no-op. A target device that holds the claimed key is
     * not limited by its own presence checks.
     */
    private fun refundKnownChallenge(peer: String, charge: Long) {
        val charges = knownChallenges[peer] ?: return
        val index = charges.indexOfFirst { it.id == charge }
        if (index < 0) return
        charges.removeAt(index)
        if (charges.isEmpty()) knownChallenges.remove(peer)
    }

    private fun pruneInvalid(now: Long) {
        invalidBudget.entries.removeAll { (_, budget) ->
            budget.failures.removeAll { now - it >= INVALID_WINDOW_MILLIS }
            now >= budget.until && budget.failures.isEmpty()
        }
    }

    /** Remove the invalid-message budget that expires first. */
    private fun evictOldestInvalid() {
        val oldest = invalidBudget.entries.minWithOrNull(
            compareBy(
                { it.value.until },
                { it.value.failures.minOrNull() ?: Long.MAX_VALUE },
            ),
        ) ?: return
        invalidBudget.remove(oldest.key)
    }

    /** Remove the oldest prompt-failure record. */
    private fun evictOldestFailure() {
        val oldest = failures.entries.minWithOrNull(
            compareBy({ it.value.minOrNull() ?: Long.MAX_VALUE }),
        ) ?: return
        failures.remove(oldest.key)
    }

    /** Remove the lockout that ends first. */
    private fun evictSoonestLockout() {
        val soonest = lockouts.entries.minWithOrNull(compareBy { it.value }) ?: return
        lockouts.remove(soonest.key)
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
        const val MAX_KNOWN_PEER_CHALLENGES = 8
        const val MAX_KNOWN_CHALLENGES = 16
        const val CHALLENGE_WINDOW_MILLIS = 60_000L
        val NEXT_PROMPT_ID = AtomicLong(1)
    }
}
