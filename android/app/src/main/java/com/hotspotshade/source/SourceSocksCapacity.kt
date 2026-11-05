package com.hotspotshade.source

import java.io.File

/**
 * Capacity and phase rules for the source proxy.
 *
 * The phase-aware rules follow `ios/HotspotProxy/SessionCapacity.swift`. An
 * open TCP relay never closes for silence. Only a phase with a real bound
 * closes. The relay cap follows the open-file limit of the process.
 *
 * The decision helpers are pure. The tests call them without a socket.
 */
internal object SourceSocksCapacity {
    /** The relay slots that the source proxy gives to open flows. */
    const val MAXIMUM_RELAYS = 256

    /** The setup slots that relay sessions cannot use. */
    const val SETUP_RESERVE = 32

    /** The total session bound with the nominal relay cap. */
    const val MAXIMUM_SESSIONS = MAXIMUM_RELAYS + SETUP_RESERVE

    /** A handshake has this bound. The exchange is small. */
    const val HANDSHAKE_MILLIS = 30_000L

    /** Twice the 4 second destination connect deadline. It is a safety net. */
    const val CONNECT_MILLIS = 8_000L

    /** The server answers a relay request at once. This bound is a safety net. */
    const val RELAY_GRANT_MILLIS = 2_000L

    /** A UDP flow and a half-closed TCP flow have this idle bound. */
    const val RELAY_IDLE_MILLIS = 300_000L

    /** An open TCP relay rechecks after this wait. It never closes for it. */
    const val OPEN_TCP_RECHECK_MILLIS = 300_000L

    /** File descriptors that the process needs outside the session table. */
    const val RESERVED_FILE_DESCRIPTORS = 32

    /** One session can hold the client socket, the destination, and one retry. */
    const val SOCKETS_PER_SESSION = 3

    /** A stop and a start can overlap, so three runs share the limit. */
    const val OVERLAPPING_RUNS = 3

    /** The descriptors that one session can need across three runs. */
    const val DESCRIPTORS_PER_SESSION = SOCKETS_PER_SESSION * OVERLAPPING_RUNS

    /** The relay capacity of the earlier total, without the fd limit. */
    const val PRIOR_RELAY_BASELINE = MAXIMUM_RELAYS - SETUP_RESERVE

    /** The most persistent echo sessions that the server grants. */
    const val MAXIMUM_PERSISTENT_ECHO_SESSIONS = 16

    /** One step in the life of an accepted session. */
    enum class Phase {
        /** The client is in the greeting or the authentication exchange. */
        HANDSHAKE,

        /** The client sent a request. The destination connect has no result. */
        CONNECTING,

        /** The client asked for a relay slot. The server has not answered. */
        AWAITING_RELAY,

        /** Both directions of the TCP relay are open. The relay is healthy. */
        OPEN_TCP,

        /** A datagram flow carries length-prefixed UDP frames over TCP. */
        UDP,

        /** One direction of a TCP relay finished. The other direction can send. */
        HALF_CLOSED,
        ;

        /** A setup phase does not hold a relay slot. */
        val isSetup: Boolean
            get() = this == HANDSHAKE || this == CONNECTING || this == AWAITING_RELAY

        /** A relay phase holds a relay slot. */
        val isRelay: Boolean get() = !isSetup
    }

    /** Why the phase rule closes a session. */
    enum class CloseReason {
        HANDSHAKE_EXPIRED,
        CONNECT_EXPIRED,
        RELAY_GRANT_EXPIRED,
        UDP_IDLE,
        HALF_CLOSED_IDLE,
    }

    /** The split of one total session limit. */
    data class Limits(
        val total: Int,
        val setupReserve: Int,
        val relay: Int,
    )

    /**
     * The phase bounds for one server. The defaults are the contract values.
     * A test can shorten them without a long wait.
     */
    data class Policy(
        val handshakeMillis: Long = HANDSHAKE_MILLIS,
        val connectMillis: Long = CONNECT_MILLIS,
        val relayGrantMillis: Long = RELAY_GRANT_MILLIS,
        val relayIdleMillis: Long = RELAY_IDLE_MILLIS,
    )

    /** One live session, as the capacity rule sees it. */
    data class PhaseSession(
        val id: Long,
        val phase: Phase,
        val phaseMillis: Long,
        val idleMillis: Long,
        val protectedFromCapacity: Boolean = false,
    )

    /** The action for one housekeeping check. */
    sealed interface IdleAction {
        /** Close the session. The phase bound expired. */
        data class Close(val reason: CloseReason) : IdleAction

        /** Keep the session open. Check again after this delay. */
        data class Rearm(val afterMillis: Long) : IdleAction
    }

    /** The most sessions that one soft file limit supports. */
    fun sessionLimit(softFileLimit: Int): Int {
        val usable = if (softFileLimit > RESERVED_FILE_DESCRIPTORS) {
            softFileLimit - RESERVED_FILE_DESCRIPTORS
        } else {
            0
        }
        if (usable <= 0) return 0
        return minOf(MAXIMUM_SESSIONS, usable / DESCRIPTORS_PER_SESSION)
    }

    /**
     * Split one total limit.
     *
     * The setup reserve keeps the same share at a lower total. A total of one
     * gives the one slot to a relay.
     */
    fun limits(total: Int = MAXIMUM_SESSIONS): Limits {
        val bounded = maxOf(0, minOf(total, MAXIMUM_SESSIONS))
        if (bounded <= 1) return Limits(total = bounded, setupReserve = 0, relay = bounded)
        val shareStep = MAXIMUM_SESSIONS / SETUP_RESERVE
        val share = maxOf(1, (bounded + shareStep - 1) / shareStep)
        val reserve = minOf(SETUP_RESERVE, share)
        return Limits(total = bounded, setupReserve = reserve, relay = bounded - reserve)
    }

    /** The limits for one observed soft file limit. */
    fun limitsForFileLimit(softFileLimit: Int): Limits = limits(total = sessionLimit(softFileLimit))

    /**
     * A plain warning for a relay cap below the earlier baseline.
     *
     * The message holds counts only. A full cap returns null.
     *
     * The app does not show this warning yet. Keep the helper out of the
     * server path until the app has a row for the relay limit.
     */
    fun capacityWarning(limits: Limits?): String? {
        val relay = limits?.relay ?: return null
        if (relay >= PRIOR_RELAY_BASELINE) return null
        return "The relay limit is $relay sessions. The earlier app gave " +
            "$PRIOR_RELAY_BASELINE. Close other apps and restart HotspotShade."
    }

    /** The reason to close one session, or null when the phase has no bound. */
    fun closeReason(
        session: PhaseSession,
        policy: Policy = Policy(),
    ): CloseReason? = when (session.phase) {
        Phase.HANDSHAKE ->
            if (session.phaseMillis >= policy.handshakeMillis) CloseReason.HANDSHAKE_EXPIRED else null
        Phase.CONNECTING ->
            if (session.phaseMillis >= policy.connectMillis) CloseReason.CONNECT_EXPIRED else null
        Phase.AWAITING_RELAY ->
            if (session.phaseMillis >= policy.relayGrantMillis) {
                CloseReason.RELAY_GRANT_EXPIRED
            } else {
                null
            }
        Phase.UDP ->
            if (session.idleMillis >= policy.relayIdleMillis) CloseReason.UDP_IDLE else null
        Phase.HALF_CLOSED ->
            if (session.idleMillis >= policy.relayIdleMillis) CloseReason.HALF_CLOSED_IDLE else null
        Phase.OPEN_TCP -> null
    }

    /** The milliseconds past the phase bound. An open TCP relay returns zero. */
    fun overdueMillis(session: PhaseSession, policy: Policy = Policy()): Long =
        when (session.phase) {
            Phase.HANDSHAKE -> session.phaseMillis - policy.handshakeMillis
            Phase.CONNECTING -> session.phaseMillis - policy.connectMillis
            Phase.AWAITING_RELAY -> session.phaseMillis - policy.relayGrantMillis
            Phase.UDP, Phase.HALF_CLOSED -> session.idleMillis - policy.relayIdleMillis
            Phase.OPEN_TCP -> 0L
        }

    /**
     * The most overdue stale session, or null when no session is past its
     * bound. A protected session is not a candidate. An open TCP relay is
     * never a candidate. The lowest identifier breaks a tie.
     *
     * Set [relayOnly] to select a stale relay phase for a relay request.
     */
    fun staleSession(
        sessions: List<PhaseSession>,
        relayOnly: Boolean = false,
        policy: Policy = Policy(),
    ): PhaseSession? {
        var best: PhaseSession? = null
        var bestOverdue = Long.MIN_VALUE
        for (session in sessions) {
            if (session.protectedFromCapacity) continue
            if (relayOnly && !session.phase.isRelay) continue
            if (closeReason(session, policy) == null) continue
            val overdue = overdueMillis(session, policy)
            val better = best == null || overdue > bestOverdue ||
                (overdue == bestOverdue && session.id < best.id)
            if (better) {
                best = session
                bestOverdue = overdue
            }
        }
        return best
    }

    /**
     * The action for one housekeeping check.
     *
     * An open TCP relay always rearms. Silence alone never closes it.
     */
    fun idleAction(
        phase: Phase,
        phaseMillis: Long,
        idleMillis: Long,
        policy: Policy = Policy(),
    ): IdleAction = when (phase) {
        Phase.HANDSHAKE ->
            bounded(phaseMillis, policy.handshakeMillis, CloseReason.HANDSHAKE_EXPIRED)
        Phase.CONNECTING ->
            bounded(phaseMillis, policy.connectMillis, CloseReason.CONNECT_EXPIRED)
        Phase.AWAITING_RELAY ->
            bounded(phaseMillis, policy.relayGrantMillis, CloseReason.RELAY_GRANT_EXPIRED)
        Phase.UDP -> bounded(idleMillis, policy.relayIdleMillis, CloseReason.UDP_IDLE)
        Phase.HALF_CLOSED ->
            bounded(idleMillis, policy.relayIdleMillis, CloseReason.HALF_CLOSED_IDLE)
        Phase.OPEN_TCP -> IdleAction.Rearm(OPEN_TCP_RECHECK_MILLIS)
    }

    private fun bounded(value: Long, bound: Long, reason: CloseReason): IdleAction =
        if (value < bound) {
            IdleAction.Rearm(maxOf(MINIMUM_REARM_MILLIS, bound - value))
        } else {
            IdleAction.Close(reason)
        }

    /** The shortest wait before the next check. */
    const val MINIMUM_REARM_MILLIS = 1L

    /** The default soft file limit when the process cannot read its own limit. */
    fun parseSoftFileLimit(text: String): Int? {
        for (line in text.lineSequence()) {
            if (!line.startsWith("Max open files")) continue
            val parts = line.trim().split(WHITESPACE)
            val soft = parts.getOrNull(3) ?: return null
            if (soft == "unlimited") return Int.MAX_VALUE
            val value = soft.toLongOrNull() ?: return null
            if (value < 0) return null
            return value.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
        }
        return null
    }

    /** Read the soft open-file limit of this process, or null when unreadable. */
    fun readSoftFileLimit(): Int? = try {
        parseSoftFileLimit(File("/proc/self/limits").readText())
    } catch (_: Exception) {
        null
    }

    private val WHITESPACE = Regex("\\s+")
}
