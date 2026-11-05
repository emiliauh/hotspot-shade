package com.hotspotshade.source

import android.app.Application
import android.os.Handler
import android.os.Looper
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import com.hotspotshade.source.pairing.PairingPrompt

/** The state of the real pairing listener, for the app UI. */
enum class RealPairingListener {
    STOPPED,
    NO_HOTSPOT,
    LISTENING,
    FAILED,
}

/** The real listener state and the count of paired target devices. */
data class RealPairingStatus(
    val listener: RealPairingListener = RealPairingListener.STOPPED,
    val trustedTargets: Int = 0,
)

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
 * A prompt that arrives while the app is not visible posts a notification.
 * The notification holds no code. The app never approves a request from a
 * notification.
 */
class PairingViewModel(application: Application) : AndroidViewModel(application) {
    var prompt by mutableStateOf<RealPairingRequest?>(null)
        private set

    var status by mutableStateOf(RealPairingStatus())
        private set

    internal var targets by mutableStateOf<List<TrustedTarget>>(emptyList())
        private set

    internal var message by mutableStateOf<String?>(null)
        private set

    private val handler = Handler(Looper.getMainLooper())
    private var coordinator: PairingCoordinator? = null
    private var admin: PairingAdmin? = null
    private var visible = false

    /** Tell the view model whether the activity is visible. */
    fun setVisible(value: Boolean) {
        visible = value
        if (value) PairingNotifications.cancel(getApplication())
    }

    /** Start the listener. A second call has no effect. */
    fun start() {
        if (coordinator != null) return
        if (admin == null) admin = PairingRuntime.admin(getApplication())
        refreshTargets()
        val created = PairingRuntime.coordinator(
            context = getApplication(),
            onPrompt = { current ->
                handler.post { onPrompt(current) }
            },
            onState = { listener, trusted ->
                handler.post {
                    status = RealPairingStatus(listener.toUi(), trusted)
                    refreshTargets()
                }
            },
        )
        if (created == null) {
            status = RealPairingStatus(RealPairingListener.FAILED, 0)
            return
        }
        coordinator = created
        created.start()
    }

    /** Stop the listener. A second call has no effect. */
    fun stop() {
        val active = coordinator
        coordinator = null
        prompt = null
        PairingNotifications.cancel(getApplication())
        active?.stop()
        status = status.copy(listener = RealPairingListener.STOPPED)
    }

    /** Approve the current real request. */
    fun allow() {
        val current = prompt ?: return
        prompt = null
        coordinator?.allow(current.prompt)
        refreshTargets()
    }

    /** Deny the current real request. */
    fun deny() {
        val current = prompt ?: return
        prompt = null
        coordinator?.deny(current.prompt)
        refreshTargets()
    }

    /** Remove one trusted target device. */
    internal fun forgetTarget(id: String) {
        val changed = admin?.forget(id) ?: false
        if (!changed) return
        refreshTargets()
        coordinator?.trustChanged()
        message = "The target device is forgotten. It must pair again to connect."
    }

    /** Remove every trusted target device. */
    internal fun forgetAllTargets() {
        admin?.forgetAll()
        refreshTargets()
        coordinator?.trustChanged()
        message = "All target devices are forgotten. Each one must pair again."
    }

    /** Replace the source token. Return the result for the app dialog. */
    internal fun rotateToken(): TokenRotateResult {
        val result = admin?.rotateToken() ?: TokenRotateResult.FAILED
        message = when (result) {
            TokenRotateResult.ROTATED -> {
                coordinator?.reloadToken()
                "The source token is new. Paired target devices must pair again."
            }
            TokenRotateResult.REFUSED_RUNNING -> "Stop the proxy before you rotate the token."
            TokenRotateResult.FAILED -> "The source token could not be changed."
        }
        return result
    }

    /** Clear the one-line result message. */
    internal fun clearMessage() {
        message = null
    }

    override fun onCleared() {
        coordinator?.stop()
        coordinator = null
        PairingNotifications.cancel(getApplication())
        super.onCleared()
    }

    private fun onPrompt(current: PairingPrompt?) {
        prompt = current?.let { RealPairingRequest(it.code, it) }
        if (current == null) {
            PairingNotifications.cancel(getApplication())
        } else if (!visible) {
            PairingNotifications.show(getApplication())
        }
    }

    private fun refreshTargets() {
        val current = admin ?: return
        targets = try {
            current.targets()
        } catch (_: Exception) {
            emptyList()
        }
        status = status.copy(trustedTargets = targets.size)
    }

    private fun PairingListenerState.toUi(): RealPairingListener = when (this) {
        PairingListenerState.STOPPED -> RealPairingListener.STOPPED
        PairingListenerState.NO_HOTSPOT -> RealPairingListener.NO_HOTSPOT
        PairingListenerState.LISTENING -> RealPairingListener.LISTENING
        PairingListenerState.FAILED -> RealPairingListener.FAILED
    }
}
