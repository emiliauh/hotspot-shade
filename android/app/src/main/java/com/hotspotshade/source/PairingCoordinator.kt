package com.hotspotshade.source

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.SystemClock
import androidx.core.content.ContextCompat
import com.hotspotshade.source.pairing.PairingCallbackDispatcher
import com.hotspotshade.source.pairing.PairingCredentials
import com.hotspotshade.source.pairing.PairingIdentity
import com.hotspotshade.source.pairing.PairingListener
import com.hotspotshade.source.pairing.PairingPrompt
import com.hotspotshade.source.pairing.PairingProtocol
import com.hotspotshade.source.pairing.PairingResponder
import com.hotspotshade.source.pairing.PairingServer
import com.hotspotshade.source.pairing.PairingTrustStore
import com.hotspotshade.source.pairing.ProxyStatus
import com.hotspotshade.source.pairing.SecureRandomPairingIdentity
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit

/** The state of the real pairing listener. */
internal enum class PairingListenerState {
    STOPPED,
    NO_HOTSPOT,
    LISTENING,
    /**
     * A stored source token exists but cannot be read, or it is empty or not
     * printable. The listener does not start, because generating a replacement
     * would overwrite the stored token. A listener that already holds the
     * token stops answering until the next refresh reloads the store. The
     * person can rotate the token or clear the app data.
     */
    TOKEN_UNREADABLE,
    FAILED,
}

/**
 * Run the real pairing listener while the app is open.
 *
 * The coordinator finds the hotspot address, creates a responder with the
 * current proxy credentials, and binds TCP port 18090 on that address only. A
 * hotspot change closes the old listener and binds the new address. A stop
 * closes the listener and every connection.
 *
 * The token is stored in memory until a pairing succeeds. A successful pairing
 * saves it with [TokenWriter], so the source proxy start finds a token instead
 * of `TOKEN_MISSING`.
 */
internal class PairingCoordinator(
    private val finder: HotspotAddressFinder,
    private val tokenStore: TokenStore,
    private val tokenWriter: TokenWriter,
    private val trust: PairingTrustStore,
    private val ports: ProxyPortPolicy,
    private val onPrompt: (PairingPrompt?) -> Unit,
    private val onState: (PairingListenerState, Int) -> Unit,
    /**
     * Called when a successful pairing sealed a token that the app could not
     * save. The callback must show a fixed message and must not receive or log
     * the token.
     */
    private val onTokenSaveFailed: () -> Unit = {},
    private val dispatchPublication: (() -> Unit) -> Unit = { it() },
    private val clock: () -> Long = { SystemClock.elapsedRealtime() },
    private val identity: PairingIdentity = SecureRandomPairingIdentity(),
    private val tokenFactory: () -> String = { TokenRotation.newToken() },
    private val pairingPort: Int = com.hotspotshade.source.pairing.PairingProtocol.PAIRING_PORT,
    private val guard: SourceTokenGuard = SourceTokenGuard.shared,
    private val schedulerFactory: () -> ScheduledExecutorService = {
        Executors.newSingleThreadScheduledExecutor { runnable ->
            Thread(runnable, "pairing-coordinator").apply { isDaemon = true }
        }
    },
    private val callbackDispatcher: PairingCallbackDispatcher = PairingCallbackDispatcher.shared,
    /**
     * A test seam that runs after a guarded rotation write and before the
     * coordinator reloads the store. A test uses it to interleave another
     * rotation. Production never sets it.
     */
    private val afterRotationWrite: () -> Unit = {},
    private val listenerFactory: (
        responder: PairingResponder,
        bindAddress: java.net.InetAddress,
        port: Int,
        onPromptChanged: (PairingPrompt?) -> Unit,
        onPairingSucceeded: () -> Unit,
        onTokenCommitFailed: () -> Unit,
    ) -> PairingListener = { responder, bindAddress, port, onPrompt, onSuccess, onTokenFailed ->
        PairingServer(
            responder = responder,
            bindAddress = bindAddress,
            port = port,
            onPromptChanged = onPrompt,
            onPairingSucceeded = onSuccess,
            onTokenCommitFailed = onTokenFailed,
            callbackDispatcher = callbackDispatcher,
        )
    },
    /**
     * A test seam that runs in [create] after a bound listener passed the
     * generation check and before its state publication. A test uses it to
     * commit a pairing result on the new listener while the creation is still
     * in flight. Production never sets it.
     *
     * The seam runs while [create] holds [refreshLock]. A commit that it drives
     * must use the listener path, which never takes [refreshLock]: stop holds
     * that lock while it closes the listener, so a commit that took it would
     * deadlock.
     */
    private val afterBind: () -> Unit = {},
) {
    /**
     * The bound pairing port, or 0 when the listener is off.
     *
     * The reference is detached under the coordinator lock, then read outside
     * it. Reading it under the lock would invert the listener lock order: the
     * responder holds the listener lock while it asks for credentials.
     */
    val localPort: Int
        get() {
            val current = synchronized(lock) { server }
            return current?.localPort ?: 0
        }
    private val lock = Any()

    /**
     * Serialize start, stop, refresh, and reload.
     *
     * The timer thread, the app thread, and a token rotation can all change
     * the listener. Without this lock two refreshes could bind two servers,
     * and a reload could race a refresh and leave the old token in use.
     */
    private val refreshLock = Any()
    private val epochListener: () -> Unit = { invalidateChangedEpoch() }
    private var scheduler: ScheduledExecutorService? = null
    private var server: PairingListener? = null
    private var address: java.net.InetAddress? = null
    private var token: String? = null
    /**
     * Moves on every stop, reload, rotation, and listener replacement. A
     * result or a bind that belongs to an older generation is discarded.
     */
    private var generation: Long = 0L
    private var callbackGeneration: Long = -1L
    private var displayedPrompt: PairingPrompt? = null
    // One lane per coordinator start. A blocked publication callback on an
    // old lane cannot consume the next start's dispatcher thread.
    private var publicationOwner: Any? = Any()
    private var publicationScheduledFor: Any? = null
    private var pendingPromptPublication: PairingPrompt? = null
    private var promptPublicationPending = false
    private var pendingStatePublication: PendingState? = null
    private var tokenFailurePending = false

    /**
     * The guard epoch that [token] belongs to.
     *
     * A rotation through another admin instance moves the guard epoch without
     * touching this field. The next listener creation then reloads the store
     * instead of publishing the old token.
     */
    private var tokenEpoch: Long = -1L
    private var running = false
    private var state = PairingListenerState.STOPPED
    private var trustedCount = 0
    private var stateRevision = 0L

    /**
     * The token epoch that [state] describes, or null when the state does not
     * depend on the stored token.
     *
     * A repeated publication carries the same tag, so a rotation that lands
     * before the publication reaches the host also supersedes a repeated
     * TOKEN_UNREADABLE report.
     */
    private var stateGuardEpoch: Long? = null

    /** Start the listener and the periodic hotspot check. */
    fun start() {
        synchronized(refreshLock) {
            synchronized(lock) {
                if (running) return
                running = true
                publicationOwner = Any()
                token = null
                tokenEpoch = -1L
                generation += 1
                // A start supersedes any state or clear left by a previous
                // stop. The new lane reports the state that this start finds.
                pendingPromptPublication = null
                promptPublicationPending = false
                pendingStatePublication = null
                tokenFailurePending = false
            }
            var executor: ScheduledExecutorService? = null
            try {
                guard.addEpochListener(epochListener)
                val created = schedulerFactory()
                executor = created
                created.scheduleWithFixedDelay(
                    {
                        // A thrown exception cancels every later run of a
                        // ScheduledExecutorService task. Report one fixed failed
                        // state and retry on the next period instead.
                        val refreshGeneration = synchronized(lock) { generation }
                        runPairingRefresh(
                            refresh = { refresh() },
                            onFailure = { publishIfCurrent(refreshGeneration, PairingListenerState.FAILED) },
                        )
                    },
                    0L,
                    REFRESH_MILLIS,
                    TimeUnit.MILLISECONDS,
                )
                synchronized(lock) { scheduler = created }
                executor = null
            } catch (_: Throwable) {
                // A scheduler that could not start must not leave the
                // coordinator in a running state with no timer. Roll back and
                // publish one fixed failure.
                synchronized(lock) {
                    running = false
                    scheduler = null
                    token = null
                    tokenEpoch = -1L
                    generation += 1
                    state = PairingListenerState.FAILED
                    stateGuardEpoch = null
                    stateRevision += 1
                    pendingPromptPublication = null
                    promptPublicationPending = true
                    pendingStatePublication = PendingState(
                        value = PairingListenerState.FAILED,
                        count = trustedCount,
                    )
                    tokenFailurePending = false
                    schedulePublicationLocked()
                }
                guard.removeEpochListener(epochListener)
                executor?.shutdownNow()
            }
        }
    }

    /** Stop the listener and every connection. This call is idempotent. */
    fun stop() {
        synchronized(refreshLock) {
            val executor: ScheduledExecutorService?
            val active: PairingListener?
            val count = try {
                trust.count
            } catch (_: Exception) {
                synchronized(lock) { trustedCount }
            }
            synchronized(lock) {
                if (!running) return
                running = false
                executor = scheduler
                scheduler = null
                active = server
                server = null
                callbackGeneration = -1L
                displayedPrompt = null
                address = null
                token = null
                tokenEpoch = -1L
                generation += 1
                state = PairingListenerState.STOPPED
                stateGuardEpoch = null
                stateRevision += 1
                trustedCount = count
                // Queue the clear and the stopped state in one step. A drain
                // that sees no pending work retires this lane, so splitting
                // these two publications could lose the stopped state.
                pendingPromptPublication = null
                promptPublicationPending = true
                pendingStatePublication = PendingState(
                    value = PairingListenerState.STOPPED,
                    count = count,
                )
                tokenFailurePending = false
                schedulePublicationLocked()
            }
            guard.removeEpochListener(epochListener)
            executor?.shutdownNow()
            active?.close()
        }
    }

    /** Approve the prompt that the person saw. */
    fun allow(prompt: PairingPrompt) = decide(prompt, true)

    /** Deny the prompt that the person saw. */
    fun deny(prompt: PairingPrompt) = decide(prompt, false)

    private fun decide(prompt: PairingPrompt, allow: Boolean) {
        synchronized(refreshLock) {
            val active = synchronized(lock) {
                if (tokenEpoch != guard.epoch() || displayedPrompt !== prompt) null else server.also { displayedPrompt = null }
            }
            if (allow) active?.allow(prompt) else active?.deny(prompt)
            publishCurrentState()
        }
    }

    /** Mark the app as visible. */
    fun activate() {
        synchronized(lock) { server }?.activate()
    }

    /** Mark the app as hidden. A live prompt gets a bounded extension. */
    fun deactivate() {
        synchronized(lock) { server }?.deactivate()
    }

    /**
     * Load the stored token again and rebind the listener.
     *
     * The app calls this method after an external token change. A normal
     * rotation through [rotateToken] does the same work atomically.
     */
    fun reloadToken() {
        synchronized(refreshLock) {
            var close: PairingListener? = null
            val restart = synchronized(lock) {
                token = null
                tokenEpoch = -1L
                generation += 1
                close = server
                server = null
                callbackGeneration = -1L
                displayedPrompt = null
                address = null
                running
            }
            // Invalidate results sealed before the reload before the new
            // listener can answer. The guard epoch moves without a write.
            guard.invalidate()
            publishPromptClear()
            close?.close()
            if (restart) refreshLocked()
        }
    }

    /**
     * Replace the source token and rebind the listener in one step.
     *
     * The guard refuses the rotation while a proxy run holds it. A pairing
     * result that was sealed before this rotation carries an older epoch and
     * cannot be saved over the new token.
     */
    fun rotateToken(): TokenRotateResult {
        synchronized(refreshLock) {
            val result = guard.rotate {
                val candidate = tokenFactory()
                tokenWriter.save(candidate)
            }
            if (result != TokenMutationResult.WRITTEN) {
                if (result == TokenMutationResult.FAILED) reloadToken()
                return when (result) {
                    TokenMutationResult.REFUSED_RUNNING -> TokenRotateResult.REFUSED_RUNNING
                    else -> TokenRotateResult.FAILED
                }
            }
            // A test can run another rotation here. The coordinator must not
            // label the value that this write produced with an epoch that a
            // newer write already owns.
            try {
                afterRotationWrite()
            } catch (_: Throwable) {
                // The test seam must not break a completed rotation.
            }
            var close: PairingListener? = null
            synchronized(lock) {
                // Do not cache the value this rotation wrote. Another rotation
                // can commit between the guarded write and this block, so
                // reading guard.epoch() here would attach the older token to
                // the newer epoch and could save it over the newer token. The
                // refresh below reloads the store under the guard and caches
                // the value with the epoch that actually holds it.
                token = null
                tokenEpoch = -1L
                generation += 1
                close = server
                server = null
                callbackGeneration = -1L
                displayedPrompt = null
                address = null
            }
            publishPromptClear()
            close?.close()
            if (synchronized(lock) { running }) refreshLocked()
            return TokenRotateResult.ROTATED
        }
    }

    /** Publish the trusted target count after a forget action. */
    fun trustChanged() {
        publishCurrentState()
    }

    private fun refresh() {
        synchronized(refreshLock) { refreshLocked() }
    }

    /** Run one refresh on the caller thread. A test uses this. */
    internal fun refreshNow() = refresh()

    private fun refreshLocked() {
        val probe = try {
            finder.probe()
        } catch (_: Exception) {
            HotspotProbe.Unknown
        }
        invalidateChangedEpoch()
        if (probe == HotspotProbe.Pending) {
            // The API 36 tethering callback is registered but has not delivered
            // its first reading. The finder has no safe address yet. Keep any
            // live listener: a pending first reading is a bounded wait, not a
            // lost hotspot. The evidence falls back to the name rules after
            // its timeout, so the next refresh can still close a real loss.
            return
        }
        val hotspot = confirmedAddress(probe)
        var close: PairingListener? = null
        var createFor: java.net.InetAddress? = null
        var createGeneration: Long = -1L
        var publish: PairingListenerState = PairingListenerState.STOPPED
        synchronized(lock) {
            if (!running) return
            if (hotspot == null && server == null && state == PairingListenerState.NO_HOTSPOT) return
            if (hotspot == null) {
                close = server
                server = null
                callbackGeneration = -1L
                displayedPrompt = null
                address = null
                generation += 1
                state = PairingListenerState.NO_HOTSPOT
                stateGuardEpoch = null
                publish = state
            } else if (server != null && address == hotspot && tokenEpoch == guard.epoch()) {
                // No state changed; avoid queueing an identical periodic update.
            } else {
                close = server
                server = null
                callbackGeneration = -1L
                displayedPrompt = null
                address = hotspot
                generation += 1
                createFor = hotspot
                createGeneration = generation
                callbackGeneration = generation
            }
        }
        if (close != null || createFor != null || hotspot == null) publishPromptClear()
        close?.close()
        if (createFor != null) create(createFor, createGeneration)
        if (publish != PairingListenerState.STOPPED) publish(publish)
    }

    /**
     * Return the one confirmed hotspot address in an observation.
     *
     * A pending or unreadable probe has no address. A tie between two
     * candidates of the best rank is ambiguous, so it has no address either.
     */
    private fun confirmedAddress(probe: HotspotProbe): java.net.InetAddress? {
        val observed = probe as? HotspotProbe.Observed ?: return null
        val best = observed.candidates.minByOrNull { it.rank } ?: return null
        if (observed.candidates.count { it.rank == best.rank } != 1) return null
        return best.address
    }

    private fun create(hotspot: java.net.InetAddress, expectedGeneration: Long) {
        val snapshot = synchronized(lock) {
            if (!running || address != hotspot || generation != expectedGeneration) return
            currentTokenLocked()
        }
        val currentToken = when (snapshot) {
            is TokenSnapshot.Present -> snapshot.token
            is TokenSnapshot.StoredUnreadable -> {
                // A stored token that cannot be read, or that is empty or not
                // printable, must not be replaced by a generated one. The state
                // tells the person how to recover. Tag the report with the
                // generation and epoch of this creation, so a concurrent token
                // commit or rotation cannot let it overwrite a newer state.
                publishForGeneration(
                    expectedGeneration,
                    PairingListenerState.TOKEN_UNREADABLE,
                    snapshot.epoch,
                )
                return
            }
            is TokenSnapshot.GenerationFailed -> {
                publishForGeneration(expectedGeneration, PairingListenerState.FAILED, snapshot.epoch)
                return
            }
        }
        if (hotspot !is java.net.Inet4Address) {
            // The pairing result carries one IPv4 gateway. An address of
            // another family cannot produce valid credentials.
            publishForGeneration(expectedGeneration, PairingListenerState.FAILED, snapshot.epoch)
            return
        }
        // Build the credentials at answer time, not at listener creation. A
        // proxy that starts, stops, or changes its port while the listener is
        // open must not leave a stale port in a pairing result.
        val credentialsForListener: () -> PairingCredentials? = {
            currentCredentials(expectedGeneration, hotspot, currentToken)
        }
        val responder = PairingResponder(
            trust = trust,
            credentials = credentialsForListener,
            statusFor = { credentials -> currentStatus(credentials) },
            identity = identity,
            clock = clock,
            commitToken = { value ->
                commitPairingToken(
                    generation = expectedGeneration,
                    hotspot = hotspot,
                    expectedToken = currentToken,
                    epoch = snapshot.epoch,
                    value = value,
                )
            },
        )
        val newServer = listenerFactory(
            responder,
            hotspot,
            pairingPort,
            { prompt ->
                publishListenerPrompt(expectedGeneration, prompt)
            },
            { },
            {
                try {
                    publishListenerFailure(expectedGeneration)
                } catch (_: Exception) {
                    // A host callback must not break the pairing listener.
                }
            },
        )
        responder.activate()
        try {
            newServer.start()
        } catch (_: Exception) {
            try {
                newServer.close()
            } catch (_: Exception) {
                // The listener did not start.
            }
            publishForGeneration(expectedGeneration, PairingListenerState.FAILED, snapshot.epoch)
            return
        }
        var discard: PairingListener? = null
        var listening: Publication? = null
        synchronized(lock) {
            if (!running || address != hotspot || generation != expectedGeneration) {
                // A stop, reload, hotspot change, or token commit raced with
                // the bind. Do not leave the listener running. Close it outside
                // the coordinator lock: the responder holds the listener lock
                // while it asks for credentials.
                discard = newServer
            } else {
                server = newServer
                // Move the state with the bind, under the same lock. A
                // concurrent trustChanged republishes the state that it reads,
                // so a STOPPED or NO_HOTSPOT left here could commit while
                // this creation waits inside the trust read that publishState
                // does next. The revision check would then drop the LISTENING
                // report, and the next refresh sees a bound listener with an
                // unchanged state and publishes nothing, so the stale value
                // would stay until a hotspot change. The state now names the
                // bound listener before any host work runs.
                // Keep the revision bump with this state change: bumping it
                // alone could let trustChanged publish the old state and
                // cause the LISTENING publication to be dropped.
                state = PairingListenerState.LISTENING
                stateGuardEpoch = snapshot.epoch
                listening = Publication(generation, ++stateRevision)
            }
        }
        if (discard != null) {
            discard.close()
            return
        }
        // The commit path that a test drives from this seam runs on the
        // listener thread and must not take [refreshLock]: stop holds that
        // lock while it closes the listener. A commit takes only the
        // coordinator lock, and never while it holds the guard.
        try {
            afterBind()
        } catch (_: Throwable) {
            // A test seam must not break a started listener.
        }
        listening?.let { marker ->
            publishState(PairingListenerState.LISTENING, marker, snapshot.epoch)
        }
    }

    /**
     * Drop the cached token when the guard epoch moved.
     *
     * The coordinator lock is taken first and the guard epoch is read inside
     * it. The guard never calls back into this class while it holds its own
     * lock, so the order stays coordinator lock, then guard.
     */
    private fun invalidateChangedEpoch() {
        synchronized(lock) {
            if (!running) return
            val epoch = guard.epoch()
            if (pendingStatePublication?.let { it.guardEpoch != null && it.guardEpoch != epoch } == true) {
                // A commit that found an unreadable or replaced token clears
                // the cached token before it queues TOKEN_UNREADABLE, so the
                // check below cannot see the change. Drop the queued report on
                // its own: a rotation or reload now owns the stored token.
                pendingStatePublication = null
            }
            if (tokenEpoch < 0 || tokenEpoch == epoch) return
            token = null
            tokenEpoch = -1L
            address = null
            generation += 1
            callbackGeneration = -1L
            displayedPrompt = null
            clearPublicationLocked()
        }
    }

    private fun publishListenerPrompt(expected: Long, prompt: PairingPrompt?) {
        invalidateChangedEpoch()
        synchronized(lock) {
            if (!running || callbackGeneration != expected) return
            displayedPrompt = prompt
            pendingPromptPublication = prompt
            promptPublicationPending = true
            schedulePublicationLocked()
        }
    }

    private fun publishListenerFailure(expected: Long) {
        // An uncertain save moves the guard epoch inside the commit. The epoch
        // listener drops the cached token and resets the listener generation,
        // so this callback then belongs to a stale generation and is dropped.
        // That is deliberate: the visible target may already hold the token, so
        // a fixed "could not be saved" message can be false. The next refresh
        // reloads the store and reports the state it actually finds.
        invalidateChangedEpoch()
        synchronized(lock) {
            if (!running || callbackGeneration != expected) return
            tokenFailurePending = true
            schedulePublicationLocked()
        }
    }

    private fun publishPromptClear() = synchronized(lock) { clearPublicationLocked() }

    private fun clearPublicationLocked() {
        pendingPromptPublication = null
        promptPublicationPending = true
        pendingStatePublication = null
        tokenFailurePending = false
        schedulePublicationLocked()
    }

    // Callers may hold refreshLock or a listener lock. The shared bounded
    // dispatcher runs host code off-thread and outside both locks. A refused
    // dispatch keeps one bounded retry ticket, so the stopped state or a
    // pending prompt is published when a worker frees without another event.
    private fun schedulePublicationLocked() {
        val owner = publicationOwner ?: return
        if (publicationScheduledFor === owner) return
        publicationScheduledFor = owner
        val accepted = try {
            callbackDispatcher.dispatchOrRetry(owner) {
                try {
                    dispatchPublication { drainPublications(owner) }
                } catch (_: Throwable) {
                    // A host dispatcher failure leaves the pending values. The
                    // next event retries; stop does not wait for a retry.
                    synchronized(lock) {
                        if (publicationScheduledFor === owner) publicationScheduledFor = null
                    }
                }
            }
        } catch (_: Throwable) {
            false
        }
        if (!accepted && publicationScheduledFor === owner) {
            publicationScheduledFor = null
        }
    }

    private fun drainPublications(owner: Any) {
        try {
            while (true) {
                invalidateChangedEpoch()
                var retire = false
                val action: (() -> Unit)? = synchronized(lock) {
                    if (publicationOwner !== owner) {
                        // A stop and a new start replaced this lane. Leave any
                        // pending values for the new lane and release this one.
                        retire = true
                        schedulePublicationLocked()
                        null
                    } else {
                        when {
                            promptPublicationPending -> {
                                val prompt = pendingPromptPublication
                                promptPublicationPending = false
                                { onPrompt(prompt) }
                            }
                            pendingStatePublication != null -> {
                                val pending = pendingStatePublication!!
                                pendingStatePublication = null
                                // A queued value that describes one stored
                                // token is stale once the guard moved past its
                                // epoch, because a rotation or reload then owns
                                // the token. The queue-time check alone cannot
                                // prove that: the epoch can change after the
                                // value is queued. Read the epoch under the
                                // coordinator lock, which is the documented
                                // order: coordinator lock, then guard.
                                val stale = pending.guardEpoch != null &&
                                    (pending.guardEpoch != guard.epoch() ||
                                        (pending.generation != null &&
                                            pending.generation != generation))
                                if (stale) {
                                    // Drop the superseded report and keep the
                                    // lane for a newer value. The next refresh
                                    // publishes the state of the new epoch.
                                    { }
                                } else {
                                    { onState(pending.value, pending.count) }
                                }
                            }
                            tokenFailurePending -> {
                                tokenFailurePending = false
                                { onTokenSaveFailed() }
                            }
                            else -> {
                                if (publicationScheduledFor === owner) publicationScheduledFor = null
                                if (!running) {
                                    publicationOwner = null
                                    retire = true
                                }
                                null
                            }
                        }
                    }
                }
                if (action == null) {
                    if (retire) callbackDispatcher.retire(owner)
                    return
                }
                // An admitted callback can finish after invalidation. Host code
                // never runs while either internal lock is held.
                try { action() } catch (_: Throwable) { }
            }
        } finally {
            // A host callback that throws an Error used to escape with the
            // publication flag still set, so the stopped state could never be
            // scheduled again. Release the flag and retry the remaining work.
            synchronized(lock) {
                if (publicationOwner === owner &&
                    publicationScheduledFor === owner &&
                    (promptPublicationPending || pendingStatePublication != null || tokenFailurePending)
                ) {
                    publicationScheduledFor = null
                    schedulePublicationLocked()
                }
            }
        }
    }

    /**
     * Build one credential set for a pairing result or a status answer.
     *
     * The token and the hotspot must still belong to the live listener. The
     * port comes from the controller-owned binding when a proxy run is
     * starting or live, otherwise from an advisory free-port probe. A null
     * result means the listener cannot name honest credentials, and the
     * responder answers NOT_ACTIVE instead of sending a stale value.
     */
    private fun currentCredentials(
        generation: Long,
        hotspot: java.net.Inet4Address,
        expectedToken: String,
    ): PairingCredentials? {
        if (!isCurrentListener(generation, hotspot, expectedToken)) return null
        // Take one controller binding snapshot. The running flag, the port,
        // and the relay count in an answer must come from the same run.
        val binding = SourceProxyRuntime.binding()
        val port = currentPairingPort(binding, generation, hotspot, expectedToken) ?: return null
        val credentials = PairingCredentials.create(hotspot, port, expectedToken) ?: return null
        // A stop, reload, or rotation during the port probe must not send a
        // result.
        return if (isCurrentListener(generation, hotspot, expectedToken)) credentials else null
    }

    private fun isCurrentListener(
        generation: Long,
        hotspot: java.net.InetAddress,
        expectedToken: String,
    ): Boolean = synchronized(lock) {
        running &&
            this.generation == generation &&
            address == hotspot &&
            token == expectedToken && tokenEpoch == guard.epoch()
    }

    /**
     * Return the port that the target device must use, or null.
     *
     * A live or starting proxy is authoritative: only a port and address that
     * the controller actually bound are honest. While a start owns the bind
     * section the answer is null, so the responder sends NOT_ACTIVE instead of
     * probing the proxy's own new listener. A stopped proxy has no binding, so
     * an advisory free-port probe may suggest the next port. That probe is not
     * a reservation: another process can still take the port before the start
     * binds it, and the authenticated status answer reports the bound value.
     */
    private fun currentPairingPort(
        binding: SourceProxyBinding,
        generation: Long,
        hotspot: java.net.InetAddress,
        expectedToken: String,
    ): Int? {
        if (binding.active || binding.state == SourceProxyState.RUNNING) {
            if (binding.address != hotspot) return null
            return binding.port.takeIf {
                it in 1024..65535 && it != PairingProtocol.PAIRING_PORT
            }
        }
        if (!isCurrentListener(generation, hotspot, expectedToken)) return null
        return try {
            ports.reserve(hotspot)
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Build one status answer from one controller binding snapshot.
     *
     * A live answer must still name the port and address that the credentials
     * carry. A controller that changed between the credential snapshot and
     * this call has no honest answer, so the responder sends REJECTED instead
     * of mixing two runs. A stopped proxy reports `proxyRunning` false, no
     * connections, and the remembered port that the credentials named.
     */
    private fun currentStatus(credentials: PairingCredentials): ProxyStatus? {
        val binding = SourceProxyRuntime.binding()
        val live = binding.active &&
            (binding.state == SourceProxyState.RUNNING ||
                binding.state == SourceProxyState.WAITING_FOR_NETWORK)
        if (live &&
            (binding.address != credentials.host || binding.port != credentials.port)
        ) {
            return null
        }
        return ProxyStatus(
            proxyRunning = live,
            foreground = true,
            connections = if (live) binding.connections else 0,
            port = credentials.port,
            host = credentials.host,
            sequence = 0,
        )
    }

    /**
     * Save the token that the source device sealed into the result.
     *
     * This runs on the listener thread while it holds the listener lock, so it
     * must not take [refreshLock]: a stop holds that lock while it closes the
     * listener. The guard epoch refuses a result that a rotation or reload
     * superseded. A failed write returns false, and the responder sends a
     * fixed rejection and adds no trust.
     *
     * The compare and the write run under the guard. Every token write in this
     * process takes that guard first, so the compare sees the one stored value
     * that the write would replace. A second pairing listener, a rotation, or
     * a reload cannot interleave. A stored token that is missing is written; a
     * stored token that equals the result is rewritten so a corrupt no-backup
     * target is repaired and the older files copy is removed. An ordinary
     * failed repair still succeeds because the same token stays readable,
     * while an uncertain write invalidates the cached token and fails the
     * pairing; a different stored token, a stored token that cannot be read,
     * and a stored token that is empty or not printable are never replaced.
     * The order inside the guarded block is guard, then store. Do not take
     * the coordinator lock while holding the guard: create takes the
     * coordinator lock and then the guard, and the reverse would deadlock.
     */
    private fun commitPairingToken(
        generation: Long,
        hotspot: java.net.InetAddress,
        expectedToken: String,
        epoch: Long,
        value: String,
    ): Boolean {
        if (value != expectedToken) return false
        if (!isCurrentListener(generation, hotspot, expectedToken)) return false
        var accepted = false
        var invalidateCachedToken = false
        var storedUnreadable = false
        val saved = guard.savePairingToken(epoch) {
            val stored = try {
                tokenStore.load()
            } catch (_: Exception) {
                // A stored token that cannot be read is not a missing token.
                // Writing now could destroy the only credential.
                // The listener also cannot prove its cached token is current.
                invalidateCachedToken = true
                storedUnreadable = true
                return@savePairingToken
            }
            accepted = when (stored) {
                null -> {
                    try {
                        tokenWriter.save(value)
                        true
                    } catch (failure: TokenWriteUncertainException) {
                        invalidateCachedToken = true
                        throw failure
                    } catch (_: Exception) {
                        false
                    }
                }
                value -> {
                    // The listener loaded this token from the store, so a
                    // pairing seals the same value. Rewrite it anyway: the
                    // active copy may be the older files-directory file while
                    // the no-backup target is corrupt. The rewrite repairs
                    // that target and removes the stale copy. An ordinary
                    // failed repair must not reject a pairing whose token is
                    // still readable, and the next successful save retries
                    // it. An uncertain write is different: the target may
                    // now be corrupt or unreadable, so the cached token is
                    // invalidated and the pairing fails.
                    try {
                        tokenWriter.save(value)
                    } catch (failure: TokenWriteUncertainException) {
                        invalidateCachedToken = true
                        throw failure
                    } catch (_: Exception) {
                        // The readable copy is still the same token.
                    }
                    true
                }
                // Another listener saved a different credential first. The
                // sealed result names a token that this device no longer
                // uses, so it must not replace the stored one. A different
                // value that is empty or not printable leaves the listener
                // with no usable token, which TOKEN_UNREADABLE reports.
                else -> {
                    invalidateCachedToken = true
                    storedUnreadable = !isUsableSourceToken(stored)
                    false
                }
            }
        }
        if (invalidateCachedToken) {
            // The cached token is stale or cannot be verified. Drop it outside the
            // guard. The guard is held only inside savePairingToken, and the
            // coordinator lock is never taken while the guard is held, so the
            // order stays coordinator lock, then guard.
            invalidateStaleToken(generation, hotspot, expectedToken, epoch, storedUnreadable)
        }
        return saved && accepted
    }

    /**
     * Discard a cached token that the store no longer holds.
     *
     * Another coordinator saved a different token, or the stored token cannot
     * be read or is not usable, so this listener cannot safely use its cache.
     * The method clears the cache, moves the generation so every answer of the
     * old listener gets NOT_ACTIVE, and clears [address] so the next refresh
     * closes the old listener and creates a new one that reloads the store. It
     * does not close the listener itself: the caller runs on the listener
     * thread while it holds the listener lock, and a close from there could
     * deadlock. It takes only the coordinator lock, never [refreshLock] or the
     * guard. A superseded listener, reload, or stop makes this a no-op.
     */
    private fun invalidateStaleToken(
        generation: Long,
        hotspot: java.net.InetAddress,
        expectedToken: String,
        expectedEpoch: Long,
        storedUnreadable: Boolean,
    ) {
        synchronized(lock) {
            if (!running || this.generation != generation || address != hotspot ||
                token != expectedToken
            ) {
                return
            }
            token = null
            tokenEpoch = -1L
            address = null
            this.generation += 1
            callbackGeneration = -1L
            displayedPrompt = null
            clearPublicationLocked()
            if (storedUnreadable && guard.epoch() == expectedEpoch) {
                // Publish without entering refreshLock or the listener. The
                // stale listener is still bound until refresh closes it, but
                // its generation can no longer return credentials or status.
                state = PairingListenerState.TOKEN_UNREADABLE
                stateGuardEpoch = expectedEpoch
                stateRevision += 1
                // Tag the report with the epoch and generation that it
                // describes. A rotation that moves the guard after this call
                // owns the stored token, so the drain drops this value instead
                // of showing a report about a superseded credential.
                pendingStatePublication = PendingState(
                    value = PairingListenerState.TOKEN_UNREADABLE,
                    count = trustedCount,
                    guardEpoch = expectedEpoch,
                    generation = this.generation,
                )
                schedulePublicationLocked()
            }
        }
    }

    /**
     * Return the token for one listener creation.
     *
     * A missing token gets one generated value, kept in memory until a pairing
     * saves it. A stored token that cannot be read or is not usable returns
     * [TokenSnapshot.StoredUnreadable]: this method never generates a
     * replacement, because that would overwrite a stored token on the next
     * pairing success. A random-source failure returns
     * [TokenSnapshot.GenerationFailed].
     */
    private fun currentTokenLocked(): TokenSnapshot = guard.withLock {
        val epoch = guard.epoch()
        val cached = token
        if (cached != null && tokenEpoch == epoch) {
            return@withLock TokenSnapshot.Present(cached, epoch)
        }
        val stored = try {
            tokenStore.load()
        } catch (_: Exception) {
            token = null
            tokenEpoch = -1L
            return@withLock TokenSnapshot.StoredUnreadable(epoch)
        }
        val value = when {
            stored == null -> try {
                tokenFactory()
            } catch (_: Exception) {
                token = null
                tokenEpoch = -1L
                return@withLock TokenSnapshot.GenerationFailed(epoch)
            }
            isUsableSourceToken(stored) -> stored
            else -> {
                // A stored value that is empty or not printable is corrupt.
                // It is unreadable, not absent, so it must not be replaced.
                token = null
                tokenEpoch = -1L
                return@withLock TokenSnapshot.StoredUnreadable(epoch)
            }
        }
        token = value
        tokenEpoch = epoch
        TokenSnapshot.Present(value, epoch)
    }

    /**
     * Publish the state that the coordinator already holds.
     *
     * The read and the publication are one operation. When a newer state
     * replaced the captured one, this call drops the older value instead of
     * overwriting the newer report.
     */
    private fun publishCurrentState() {
        val (value, marker, epoch) = synchronized(lock) {
            if (!running) return
            Triple(state, Publication(generation, stateRevision), stateGuardEpoch)
        }
        publishState(value, marker, epoch)
    }

    private fun publishIfCurrent(expected: Long, value: PairingListenerState) {
        synchronized(refreshLock) {
            publishState(value, Publication(expected, null), null)
        }
    }

    /**
     * Publish a state that only one listener creation may report.
     *
     * A commit, reload, stop, or hotspot change that lands after the token load
     * moves the generation and publishes its own state first. This call then
     * drops the older value.
     */
    private fun publishForGeneration(
        expectedGeneration: Long,
        value: PairingListenerState,
        guardEpoch: Long?,
    ) {
        publishState(value, Publication(expectedGeneration, null), guardEpoch)
    }

    /**
     * Write [value] as the current state and queue one publication of it.
     *
     * The state and the revision move before the trust store is read, so a
     * later state that lands during that read wins and this publication is
     * dropped instead of overwriting it.
     */
    private fun publish(value: PairingListenerState) {
        val marker = synchronized(lock) {
            if (!running) return
            state = value
            Publication(generation, ++stateRevision)
        }
        publishState(value, marker, null)
    }

    /**
     * Queue one state publication for [value].
     *
     * [marker] names the state that the caller saw. A newer state, a stop, a
     * reload, or a token rotation moves the generation or the revision and
     * drops this value instead of letting it overwrite the newer one.
     * [guardEpoch] tags a value that describes one stored token, so the drain
     * can refuse a report for a superseded epoch. The count is read outside the
     * coordinator lock, because a trust store call is host work.
     */
    private fun publishState(
        value: PairingListenerState,
        marker: Publication,
        guardEpoch: Long?,
    ) {
        val count = try {
            trust.count
        } catch (_: Exception) {
            synchronized(lock) { trustedCount }
        }
        synchronized(lock) {
            if (!running || generation != marker.generation) return
            if (marker.revision != null && stateRevision != marker.revision) return
            state = value
            stateGuardEpoch = guardEpoch
            stateRevision += 1
            trustedCount = count
            pendingStatePublication = PendingState(
                value = value,
                count = count,
                guardEpoch = guardEpoch,
                generation = if (guardEpoch != null) generation else null,
            )
            schedulePublicationLocked()
        }
    }

    private sealed interface TokenSnapshot {
        /** The guard epoch that this snapshot was read at. */
        val epoch: Long

        data class Present(val token: String, override val epoch: Long) : TokenSnapshot

        /**
         * A stored token exists but cannot be read, or it is empty or not
         * printable.
         */
        data class StoredUnreadable(override val epoch: Long) : TokenSnapshot

        /** No token is stored and the random source failed. */
        data class GenerationFailed(override val epoch: Long) : TokenSnapshot
    }

    /**
     * One state value and the publication order that produced it.
     *
     * A caller captures one when it observes the state. A null revision means
     * that only the generation must still match.
     */
    private data class Publication(val generation: Long, val revision: Long?)

    /**
     * One queued state publication.
     *
     * [guardEpoch] is the token epoch that the value describes, or null when
     * the value does not depend on the stored token. [generation] is the
     * listener generation that the value describes. The drain compares both
     * with the live values, because a rotation or a later commit can move them
     * after the value is queued, and a report about a superseded token must not
     * reach the host.
     */
    private data class PendingState(
        val value: PairingListenerState,
        val count: Int,
        val guardEpoch: Long? = null,
        val generation: Long? = null,
    )

    private companion object {
        const val REFRESH_MILLIS = 3_000L
    }
}

/**
 * Run one periodic pairing refresh.
 *
 * A ScheduledExecutorService stops running a task for good after its body
 * throws. This wrapper keeps one bad refresh, including an [Error], from
 * cancelling every later check. [onFailure] publishes a fixed safe state and
 * never exception text.
 */
internal inline fun runPairingRefresh(
    refresh: () -> Unit,
    onFailure: () -> Unit,
) {
    try {
        refresh()
    } catch (_: Throwable) {
        try {
            onFailure()
        } catch (_: Throwable) {
            // A failure publisher must not cancel the scheduled refresh.
        }
    }
}

/** Build the production pairing coordinator. Return null without network permission. */
internal object PairingRuntime {
    fun coordinator(
        context: Context,
        onPrompt: (PairingPrompt?) -> Unit,
        onState: (PairingListenerState, Int) -> Unit,
        onTokenSaveFailed: () -> Unit = {},
        dispatchPublication: (() -> Unit) -> Unit = { it() },
    ): PairingCoordinator? {
        if (ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.ACCESS_NETWORK_STATE,
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            return null
        }
        val preferences = SourceProxyRuntime.preferences(context)
        val store = SourceProxyRuntime.tokenStore(context)
        @Suppress("MissingPermission")
        val finder = SourceProxyRuntime.hotspotFinder(context)
        return PairingCoordinator(
            finder = finder,
            tokenStore = store,
            tokenWriter = store,
            trust = FilePairingTrustStore(java.io.File(context.noBackupFilesDir, "pairing-trust"), preferences),
            ports = ProxyPortPolicy(SharedPreferencesProxyPortStore(preferences)),
            onPrompt = onPrompt,
            onState = onState,
            onTokenSaveFailed = onTokenSaveFailed,
            dispatchPublication = dispatchPublication,
        )
    }

    /** Build the admin actions for the real trust list and the source token. */
    fun admin(context: Context): PairingAdmin = PairingAdmin(
        trust = FilePairingTrustStore(java.io.File(context.noBackupFilesDir, "pairing-trust"), SourceProxyRuntime.preferences(context)),
        tokenStore = SourceProxyRuntime.tokenStore(context),
    )
}
