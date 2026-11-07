package com.hotspotshade.source

/** The result of a token rotation that a running proxy can block. */
internal enum class TokenMutationResult {
    WRITTEN,
    REFUSED_RUNNING,
    FAILED,
}

/**
 * Coordinate the source token between the pairing listener, a rotation, and
 * one source proxy run.
 *
 * A proxy run holds the guard from the token load until it closes its
 * resources. A rotation takes the same guard and is refused while a run holds
 * it. If a start and a rotation arrive together, one of them wins: the run
 * keeps the old token and the rotation is refused, or the rotation finishes
 * and the run loads the new token.
 *
 * Each pairing result records the token epoch that its server was created in.
 * A rotation moves the epoch, so a result that was sealed before the rotation
 * cannot be written back over the new token. The epoch governs the stored
 * token, not a frame that was already committed and is in flight. A rotation
 * between the commit and the sealed result can still deliver the token that
 * the rotation replaces; the target then has to pair again to receive the new
 * token. A rotation is refused while a proxy run holds the guard, so that
 * window belongs to the pairing listener only.
 *
 * The production app uses [shared]. A JVM test creates its own guard so one
 * test cannot hold a run lease in another test.
 */
internal class SourceTokenGuard {
    private val lock = Any()
    private var runHeld = false
    private var epochValue = 0L
    private val epochListeners = mutableSetOf<() -> Unit>()

    fun addEpochListener(listener: () -> Unit) = synchronized(lock) { epochListeners.add(listener); Unit }

    fun removeEpochListener(listener: () -> Unit) = synchronized(lock) { epochListeners.remove(listener); Unit }

    private fun notifyEpochListeners(listeners: List<() -> Unit>) {
        listeners.forEach { listener -> try { listener() } catch (_: Exception) { } }
    }

    /** The current token epoch. */
    fun epoch(): Long = synchronized(lock) { epochValue }

    /** Run [block] under the guard. The block must not call back into it. */
    fun <T> withLock(block: () -> T): T = synchronized(lock, block)

    /**
     * Mark one proxy run as active.
     *
     * Return false when another run already holds the guard. The caller must
     * not load the token or bind a listener in that case.
     */
    fun beginRun(): Boolean = synchronized(lock) {
        if (runHeld) {
            false
        } else {
            runHeld = true
            true
        }
    }

    /** Release the run lease. This call is idempotent. */
    fun endRun() {
        synchronized(lock) { runHeld = false }
    }

    /** True while a proxy run holds the lease. */
    fun isRunHeld(): Boolean = synchronized(lock) { runHeld }

    /**
     * Mark every pairing result created before now as stale.
     *
     * A stored token changed outside a rotation moves the epoch without
     * writing. A result that was sealed before the reload then cannot write
     * the old token back over the new one.
     */
    fun invalidate(): Long {
        val (epoch, listeners) = synchronized(lock) {
            epochValue += 1
            epochValue to epochListeners.toList()
        }
        notifyEpochListeners(listeners)
        return epoch
    }

    /**
     * Save a rotated token unless a proxy run holds the guard.
     *
     * [write] throws to report a failed save. The epoch moves only after a
     * successful write or a post-rename uncertain write. A refusal writes nothing.
     */
    fun rotate(write: () -> Unit): TokenMutationResult {
        val (result, listeners) = synchronized(lock) {
            if (runHeld) return@synchronized TokenMutationResult.REFUSED_RUNNING to emptyList()
            val result = try {
                write()
                epochValue += 1
                TokenMutationResult.WRITTEN
            } catch (_: TokenWriteUncertainException) {
                epochValue += 1
                TokenMutationResult.FAILED
            } catch (_: Exception) {
                return@synchronized TokenMutationResult.FAILED to emptyList()
            }
            result to epochListeners.toList()
        }
        notifyEpochListeners(listeners)
        return result
    }

    /**
     * Save the token that one pairing result sealed.
     *
     * The save runs only when no rotation has moved the epoch since the
     * result's server was created. An ordinary failed write returns false and
     * leaves the epoch alone, because the stored token did not change. A
     * post-rename uncertain write returns false and moves the epoch: the
     * visible token may already be the requested one, so every cached copy is
     * stale and a result from the old epoch must not save again.
     */
    fun savePairingToken(epoch: Long, write: () -> Unit): Boolean {
        val (saved, listeners) = synchronized(lock) {
            if (epoch != epochValue) return@synchronized false to emptyList()
            try {
                write()
                true to emptyList()
            } catch (_: TokenWriteUncertainException) {
                epochValue += 1
                false to epochListeners.toList()
            } catch (_: Exception) {
                false to emptyList()
            }
        }
        notifyEpochListeners(listeners)
        return saved
    }

    companion object {
        /** The guard for the app process. */
        val shared = SourceTokenGuard()
    }
}
