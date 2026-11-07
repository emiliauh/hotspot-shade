package com.hotspotshade.source

import android.app.Application
import android.os.Handler
import android.os.Looper
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import com.hotspotshade.source.pairing.PairingPrompt
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicReference

/** The state of the real pairing listener, for the app UI. */
enum class RealPairingListener {
    STOPPED,
    NO_HOTSPOT,
    LISTENING,
    TOKEN_UNREADABLE,
    FAILED,
}

/** The fixed text for one real pairing listener state. */
internal fun pairingListenerMessage(listener: RealPairingListener): String = when (listener) {
    RealPairingListener.LISTENING ->
        "On. This app waits for a target device on the hotspot."
    RealPairingListener.NO_HOTSPOT ->
        "Off. Turn on the hotspot and open this app."
    RealPairingListener.TOKEN_UNREADABLE ->
        "The stored source token cannot be read or is not usable. Try again later. " +
            "The app never replaces the token on its own. To replace it, rotate the " +
            "source token; target devices will need to pair again."
    RealPairingListener.FAILED ->
        "The pairing listener could not start. Close and open this app."
    RealPairingListener.STOPPED ->
        "Off. Open this app to pair."
}

internal fun targetConfirmationMessage(confirmation: TargetConfirmation): String = when (confirmation) {
    TargetConfirmation.CONFIRMED -> "Confirmed in this app session"
    TargetConfirmation.REQUIRED -> "Confirmation required when pairing"
    TargetConfirmation.UNKNOWN -> "Confirmation status unknown"
}

/** Map the internal listener state to the UI state. */
internal fun PairingListenerState.toRealPairingListener(): RealPairingListener = when (this) {
    PairingListenerState.STOPPED -> RealPairingListener.STOPPED
    PairingListenerState.NO_HOTSPOT -> RealPairingListener.NO_HOTSPOT
    PairingListenerState.LISTENING -> RealPairingListener.LISTENING
    PairingListenerState.TOKEN_UNREADABLE -> RealPairingListener.TOKEN_UNREADABLE
    PairingListenerState.FAILED -> RealPairingListener.FAILED
}

/** The real listener state and the count of paired target devices. */
data class RealPairingStatus(
    val listener: RealPairingListener = RealPairingListener.STOPPED,
    val trustedTargets: Int = 0,
)

/**
 * Gate callbacks from a listener generation that is no longer current.
 *
 * The view model starts one listener per visible period. A stop or a restart
 * moves the generation. A delayed main-thread callback from the old listener
 * then changes no state, so an old prompt cannot reappear after a stop.
 */
internal class PairingUiGate {
    private val lock = Any()
    private var current = 0L

    /** Move to a new generation and return it. */
    fun begin(): Long = synchronized(lock) { ++current }

    /** Make every outstanding callback stale. */
    fun invalidate() {
        synchronized(lock) { current += 1 }
    }

    /** True when [generation] is still the current one. */
    fun isCurrent(generation: Long): Boolean = synchronized(lock) { generation == current }

    fun snapshot(): Long = synchronized(lock) { current }

    /** Wrap a main-thread result so an invalidated generation cannot publish it. */
    fun guarded(generation: Long, stale: () -> Unit = {}, action: () -> Unit): () -> Unit = {
        if (isCurrent(generation)) action() else stale()
    }
}

/**
 * One real pairing request for the app UI.
 *
 * The request holds the exact prompt snapshot. An approval uses this snapshot,
 * so a stale or replaced prompt cannot be approved.
 */
class RealPairingRequest internal constructor(
    val code: String,
    internal val prompt: PairingPrompt,
) {
    override fun toString(): String = "RealPairingRequest(code=[redacted])"
}

/**
 * Hold the real pairing listener for the visible app.
 *
 * The view model starts the listener when the activity starts and stops it
 * when the activity stops. It holds no token. All list changes arrive on the
 * main thread.
 *
 * The listener, the Keystore, and the trust list can block on disk or on a
 * socket. Every such call runs on one daemon worker. The main thread only
 * publishes state.
 *
 * A prompt that arrives while the app is not visible posts a notification.
 * The notification holds no code. The app never approves a request from a
 * notification.
 */
internal interface PairingListenerHandle {
    fun start()
    fun stop()
    fun activate()
    fun deactivate()
    fun allow(prompt: PairingPrompt)
    fun deny(prompt: PairingPrompt)
    fun trustChanged()
    fun rotateToken(): TokenRotateResult
}

internal class CoordinatorHandle(private val value: PairingCoordinator) : PairingListenerHandle {
    override fun start() = value.start()
    override fun stop() = value.stop()
    override fun activate() = value.activate()
    override fun deactivate() = value.deactivate()
    override fun allow(prompt: PairingPrompt) = value.allow(prompt)
    override fun deny(prompt: PairingPrompt) = value.deny(prompt)
    override fun trustChanged() = value.trustChanged()
    override fun rotateToken() = value.rotateToken()
}

internal class PairingViewModelTestHooks(
    val worker: (() -> Unit) -> Unit,
    val main: (() -> Unit) -> Unit,
    val delayed: (() -> Unit, Long) -> Unit,
    val readTargets: () -> List<TrustedTarget>?,
    val cancelNotification: () -> Unit = {},
    val listenerFactory: (((PairingPrompt?) -> Unit), ((PairingListenerState, Int) -> Unit), (() -> Unit)) -> PairingListenerHandle? = { _, _, _ -> null },
    val forget: (String?) -> Boolean = { false },
    val useCoordinatorPublication: Boolean = false,
    val coordinatorFactory: (((PairingPrompt?) -> Unit), ((PairingListenerState, Int) -> Unit), (() -> Unit), ((() -> Unit) -> Unit)) -> PairingListenerHandle? = { _, _, _, _ -> null },
)

class PairingViewModel internal constructor(
    application: Application,
    private val testHooks: PairingViewModelTestHooks?,
) : AndroidViewModel(application) {
    constructor(application: Application) : this(application, null)
    var prompt by mutableStateOf<RealPairingRequest?>(null)
        private set

    var status by mutableStateOf(RealPairingStatus())
        private set

    internal var targets by mutableStateOf<List<TrustedTarget>>(emptyList())
        private set

    internal var trustUnavailable by mutableStateOf<Boolean?>(null)
        private set

    internal var message by mutableStateOf<String?>(null)
        private set

    private val handler = if (testHooks == null) Handler(Looper.getMainLooper()) else null
    private fun post(block: () -> Unit) {
        if (testHooks != null) testHooks.main(block) else handler!!.post(block)
    }
    private fun postDelayed(block: () -> Unit, delay: Long) {
        if (testHooks != null) testHooks.delayed(block, delay) else handler!!.postDelayed(block, delay)
    }
    private fun cancelNotification() {
        if (testHooks != null) testHooks.cancelNotification() else PairingNotifications.cancel(getApplication())
    }
    private val io = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "pairing-admin").apply { isDaemon = true }
    }
    private var coordinator: PairingListenerHandle? = null

    /**
     * The coordinator that the worker thread created, before the main thread
     * publishes it to [coordinator].
     *
     * A token rotation runs on the same worker. Without this field a rotation
     * that arrives after the listener started but before the main thread sees
     * it would save the new token and still leave the old listener running.
     */
    private val workerCoordinator = AtomicReference<PairingListenerHandle?>(null)
    private val ownershipLock = Any()
    private var mutationPending = false
    private var admin: PairingAdmin? = null
    private var visible = false
    private var starting = false
    private val gate = PairingUiGate()
    private val listGate = PairingUiGate()
    private var listVisible = false

    @Volatile
    private var cleared = false

    private fun runOnIo(block: () -> Unit) {
        if (testHooks != null) {
            testHooks.worker(block)
            return
        }
        try {
            io.execute(block)
        } catch (_: java.util.concurrent.RejectedExecutionException) {
            // The view model is cleared. No work may start.
        }
    }

    /**
     * Stop one coordinator off the main thread.
     *
     * The normal path queues the close on the worker. After the view model is
     * cleared the worker is already shut down, so the teardown path closes it
     * here instead of leaving a listener behind.
     */
    private fun stopOffMain(active: PairingListenerHandle) {
        if (testHooks != null) {
            testHooks.worker { active.stop() }
            return
        }
        try {
            io.execute { active.stop() }
        } catch (_: java.util.concurrent.RejectedExecutionException) {
            try {
                active.stop()
            } catch (_: Exception) {
                // The listener is already closing.
            }
        }
    }

    /** Tell the view model whether the activity is visible. */
    fun setVisible(value: Boolean) {
        visible = value
        if (!value) {
            listGate.invalidate()
            trustUnavailable = null
            targets = emptyList()
        }
        if (value && listVisible) beginTargetRefresh()
        if (value) {
            cancelNotification()
            // Take port 18090 from the background status host before this
            // activity's listener binds. activityStarted() bumps the port-owner
            // fence at once, so a host tick that read "not visible" earlier
            // cannot publish a listener afterward. releasePortNow() runs on the
            // one worker before the coordinator's first bind and closes any
            // listener the host already holds.
            BackgroundStatusHost.activityStarted()
            runOnIo {
                BackgroundStatusHost.releasePortNow()
                coordinator?.activate()
            }
        } else {
            BackgroundStatusHost.activityStopped()
            runOnIo { coordinator?.deactivate() }
        }
    }

    /** Start the listener. A second call has no effect. */
    fun start() {
        if (coordinator != null || starting) return
        starting = true
        val generationAtStart = gate.begin()
        if (listVisible && visible) beginTargetRefresh()
        runOnIo {
            if (!gate.isCurrent(generationAtStart) || cleared) return@runOnIo
            workerCoordinator.get()?.let { previous ->
                previous.stop()
                workerCoordinator.compareAndSet(previous, null)
            }
            if (cleared) {
                post {
                    if (gate.isCurrent(generationAtStart)) starting = false
                }
                return@runOnIo
            }
            try {
                if (admin == null) admin = PairingRuntime.admin(getApplication())
            } catch (_: Exception) {
                // The listener can still start. The trust list reports the
                // failure on its own path.
            }
            val usesCoordinatorPublication = testHooks?.useCoordinatorPublication == true
            val created = try {
                val publish: (() -> Unit) -> Unit = { action ->
                    if (testHooks != null && !usesCoordinatorPublication) post(action) else action()
                }
                val onPrompt: (PairingPrompt?) -> Unit = { current ->
                    publish { if (gate.isCurrent(generationAtStart)) onPrompt(current) }
                }
                val onState: (PairingListenerState, Int) -> Unit = { listener, trusted ->
                    publish { if (gate.isCurrent(generationAtStart)) status = RealPairingStatus(listener.toRealPairingListener(), trusted) }
                }
                val onTokenSaveFailed: () -> Unit = {
                    ActivityLog.record(ActivityEvent.TOKEN_SAVE_FAILED)
                    publish { if (gate.isCurrent(generationAtStart)) {
                        message = "The source token could not be saved. Pair the target " +
                            "device again before you start the proxy."
                    } }
                }
                if (usesCoordinatorPublication) testHooks!!.coordinatorFactory(onPrompt, onState, onTokenSaveFailed) { post(it) }
                else if (testHooks != null) testHooks.listenerFactory(onPrompt, onState, onTokenSaveFailed)
                else PairingRuntime.coordinator(
                    context = getApplication(),
                    onPrompt = onPrompt,
                    onState = onState,
                    onTokenSaveFailed = onTokenSaveFailed,
                    dispatchPublication = { post(it) },
                )?.let(::CoordinatorHandle)
            } catch (_: Exception) {
                null
            }
            if (created == null) {
                post(gate.guarded(generationAtStart) {
                    if (!cleared) {
                        starting = false
                        prompt = null
                        status = RealPairingStatus(RealPairingListener.FAILED, 0)
                    }
                })
                return@runOnIo
            }
            val published = synchronized(ownershipLock) {
                if (cleared || !gate.isCurrent(generationAtStart)) false
                else { workerCoordinator.set(created); true }
            }
            val started = if (!published) {
                false
            } else {
                try {
                    created.start()
                    true
                } catch (_: Exception) {
                    false
                }
            }
            if (!started) {
                workerCoordinator.compareAndSet(created, null)
                val failureGeneration = synchronized(ownershipLock) {
                    if (gate.isCurrent(generationAtStart)) gate.begin() else null
                }
                try {
                    created.stop()
                } catch (_: Exception) {
                    // The listener never started.
                }
                if (failureGeneration != null) post(gate.guarded(failureGeneration) {
                    if (!cleared) {
                        starting = false
                        prompt = null
                        status = RealPairingStatus(RealPairingListener.FAILED, 0)
                        // The failed start invalidated earlier list reads.
                        if (listVisible && visible) beginTargetRefresh()
                    }
                })
                return@runOnIo
            }
            post(gate.guarded(generationAtStart, stale = {
                workerCoordinator.compareAndSet(created, null)
                stopOffMain(created)
            }) {
                starting = false
                coordinator = created
                if (!visible) {
                    runOnIo {
                        if (gate.isCurrent(generationAtStart)) created.deactivate()
                    }
                }
            })
        }
    }

    /** Stop the listener. A second call has no effect. */
    fun stop() {
        val workerActive = synchronized(ownershipLock) {
            gate.invalidate()
            workerCoordinator.getAndSet(null)
        }
        val active = coordinator ?: workerActive
        coordinator = null
        starting = false
        listGate.invalidate()
        prompt = null
        cancelNotification()
        status = status.copy(listener = RealPairingListener.STOPPED)
        active?.let { stopOffMain(it) }
    }

    /** Approve the current real request. */
    fun allow() {
        val current = prompt ?: return
        val active = coordinator ?: workerCoordinator.get()
        prompt = null
        if (active != null) {
            ActivityLog.record(ActivityEvent.PAIRING_ALLOWED)
            runOnIo {
                active.allow(current.prompt)
                post { if (listVisible && visible && !cleared) refreshTargets() }
            }
        }
    }

    /** Deny the current real request. */
    fun deny() {
        val current = prompt ?: return
        val active = coordinator ?: workerCoordinator.get()
        prompt = null
        if (active != null) {
            ActivityLog.record(ActivityEvent.PAIRING_DENIED)
            runOnIo {
                active.deny(current.prompt)
                post { if (listVisible && visible && !cleared) refreshTargets() }
            }
        }
    }

    /** Remove one trusted target device. */
    internal fun forgetTarget(id: String) {
        if (!visible || !listVisible || mutationPending || trustUnavailable != false || targets.none { it.id == id }) return
        mutateTrust(id)
    }

    /** Remove every trusted target device. */
    internal fun forgetAllTargets() {
        if (!visible || !listVisible || mutationPending || trustUnavailable == null) return
        mutateTrust(null)
    }

    private fun mutateTrust(id: String?) {
        mutationPending = true
        trustUnavailable = null
        runOnIo {
            val changed = try {
                if (testHooks != null) testHooks.forget(id)
                else if (id == null) admin?.forgetAll() ?: false else admin?.forget(id) ?: false
            } catch (_: Exception) { false }
            if (changed) {
                ActivityLog.record(
                    if (id == null) ActivityEvent.TARGETS_FORGOTTEN else ActivityEvent.TARGET_REMOVED,
                )
                try { workerCoordinator.get()?.trustChanged() } catch (_: Exception) { }
            }
            post {
                message = if (id == null) {
                    if (changed) "All target devices are forgotten. Each one must pair again with a prompt. Their saved tokens can still work."
                    else "The trust reset could not be confirmed. Existing tokens may still work."
                } else {
                    if (changed) "The target device is forgotten. It must pair again with a prompt. Its saved token can still work."
                    else "Forgetting the target device could not be confirmed. Its token may still work."
                }
                finishMutationWithSnapshot()
            }
        }
    }

    private fun finishMutationWithSnapshot() {
        if (!listVisible || !visible || cleared) {
            mutationPending = false
            return
        }
        refreshTargets(onComplete = { current ->
            if (current || !listVisible || !visible || cleared) mutationPending = false
            else finishMutationWithSnapshot()
        })
    }

    /** Replace the source token. The result arrives as a one-line message. */
    internal fun rotateToken() {
        runOnIo {
            val active = workerCoordinator.get()
            val result = active?.rotateToken() ?: admin?.rotateToken() ?: TokenRotateResult.FAILED
            when (result) {
                TokenRotateResult.ROTATED -> ActivityLog.record(ActivityEvent.TOKEN_ROTATED)
                TokenRotateResult.FAILED ->
                    ActivityLog.record(ActivityEvent.TOKEN_ROTATION_UNCONFIRMED)
                TokenRotateResult.REFUSED_RUNNING -> Unit
            }
            post {
                message = when (result) {
                    TokenRotateResult.ROTATED ->
                        "The source token is new. Paired target devices must pair again."
                    TokenRotateResult.REFUSED_RUNNING -> "Stop the proxy before you rotate the token."
                    TokenRotateResult.FAILED ->
                        "The source token change could not be confirmed. Paired target devices may need to pair again."
                }
            }
        }
    }

    /** Clear the one-line result message. */
    internal fun clearMessage() {
        message = null
    }

    override fun onCleared() {
        cleared = true
        val workerActive = synchronized(ownershipLock) {
            gate.invalidate()
            workerCoordinator.getAndSet(null)
        }
        val active = coordinator ?: workerActive
        coordinator = null
        prompt = null
        if (active != null) stopOffMain(active)
        io.shutdown()
        cancelNotification()
        super.onCleared()
    }

    private fun onPrompt(current: PairingPrompt?) {
        prompt = current?.let { RealPairingRequest(it.code, it) }
        if (current == null) {
            cancelNotification()
        } else if (!visible) {
            PairingNotifications.show(getApplication())
        }
    }

    /** Refresh only while the saved target list is visible. */
    internal fun setTrustListVisible(value: Boolean) {
        if (listVisible == value) return
        listVisible = value
        listGate.invalidate()
        trustUnavailable = null
        targets = emptyList()
        if (value && visible && !cleared) beginTargetRefresh()
    }

    private fun beginTargetRefresh() {
        val listGeneration = listGate.begin()
        refreshTargets(listGeneration) { current ->
            if (current) scheduleTargetRefresh(listGeneration)
        }
    }

    private fun scheduleTargetRefresh(listGeneration: Long) {
        postDelayed({
            if (listGate.isCurrent(listGeneration) && listVisible && visible && !cleared) {
                refreshTargets(listGeneration) { current -> if (current) scheduleTargetRefresh(listGeneration) }
            }
        }, 30_000L)
    }

    private fun refreshTargets(listGeneration: Long = listGate.snapshot(), onComplete: (Boolean) -> Unit = {}) {
        if (!listVisible || !visible || cleared) return
        val listenerGeneration = gate.snapshot()
        runOnIo {
            val current = if (testHooks != null) null else admin ?: try {
                PairingRuntime.admin(getApplication()).also { admin = it }
            } catch (_: Exception) {
                null
            }
            val loaded = try {
                if (testHooks != null) testHooks.readTargets() else current?.targets()
            } catch (_: Exception) {
                null
            }
            post {
                val currentSnapshot = gate.isCurrent(listenerGeneration) && listGate.isCurrent(listGeneration) && listVisible && visible && !cleared
                if (currentSnapshot) {
                    if (loaded == null) {
                        trustUnavailable = true
                        message = "The trusted target list could not be read."
                    } else {
                        trustUnavailable = false
                        targets = loaded
                        status = status.copy(trustedTargets = loaded.size)
                    }
                }
                onComplete(currentSnapshot)
            }
        }
    }
}
