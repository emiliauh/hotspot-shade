package com.hotspotshade.demo

import android.Manifest
import android.app.Application
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.core.content.ContextCompat
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.hotspotshade.demo.model.ClipboardClearScheduler
import com.hotspotshade.demo.model.ClipboardPrivacy
import com.hotspotshade.demo.model.ConnectionClipboard
import com.hotspotshade.demo.model.ConnectionCopyResult
import com.hotspotshade.demo.model.ClipboardSnapshot
import com.hotspotshade.demo.model.ManualConnectionPolicy
import com.hotspotshade.demo.model.ManualConnectionSession
import com.hotspotshade.demo.model.ManualRevealResult
import com.hotspotshade.demo.model.TokenClipboard
import com.hotspotshade.demo.model.TokenClipboardController
import com.hotspotshade.demo.model.TokenCopyResult
import com.hotspotshade.source.HotspotProbe
import com.hotspotshade.source.SharedPreferencesProxyPortStore
import com.hotspotshade.source.SourceProxyRuntime
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** The real values that the manual connection block needs. */
internal data class ManualConnectionSnapshot(
    val address: String?,
    val addressCheckFailed: Boolean,
    val savedPort: Int,
    val token: String?,
    /** A stored token exists but the app cannot read it. It is not absent. */
    val tokenUnreadable: Boolean = false,
    /** The API 36 tethering callback has not delivered its first reading. */
    val addressPending: Boolean = false,
) {
    /** Never print the token or the address. */
    override fun toString(): String =
        "ManualConnectionSnapshot(address=${if (address == null) "none" else "present"}, " +
            "addressCheckFailed=$addressCheckFailed, addressPending=$addressPending, " +
            "savedPort=$savedPort, token=${if (token == null) "none" else "[redacted]"}, " +
            "tokenUnreadable=$tokenUnreadable)"
}

/** Read the real manual connection values. A JVM test can use a fake. */
internal interface ManualConnectionSource {
    fun load(): ManualConnectionSnapshot
}

/**
 * Read the hotspot address, the saved port, and the stored token.
 *
 * The address comes from the same strict finder that the proxy uses. An
 * address is present only when one hotspot candidate is confirmed. A null
 * address is a missing hotspot, an unreadable interface list, or a pending
 * first tethering reading, and the snapshot keeps those states apart. The
 * token is read from the Keystore-backed store. Nothing here logs a value or
 * writes one to an error.
 */
internal class AndroidManualConnectionSource(
    private val context: Context,
) : ManualConnectionSource {
    override fun load(): ManualConnectionSnapshot {
        val address = hotspotAddress()
        val savedPort = try {
            SharedPreferencesProxyPortStore(SourceProxyRuntime.preferences(context)).load()
        } catch (_: Exception) {
            0
        }
        var tokenUnreadable = false
        val token = try {
            SourceProxyRuntime.tokenStore(context).load()
        } catch (_: Exception) {
            // The store distinguishes a missing file from an unreadable one by
            // throwing. Any failure here means the app cannot prove the token
            // is absent, so the UI must not say that it is.
            tokenUnreadable = true
            null
        }
        return ManualConnectionSnapshot(
            address = address.value,
            addressCheckFailed = address.checkFailed,
            savedPort = savedPort,
            token = token,
            tokenUnreadable = tokenUnreadable,
            addressPending = address.pending,
        )
    }

    private fun hasNetworkStatePermission(): Boolean =
        ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.ACCESS_NETWORK_STATE,
        ) == PackageManager.PERMISSION_GRANTED

    /**
     * Read one hotspot observation.
     *
     * A pending first API 36 callback is not a missing hotspot. It is a
     * bounded wait, so the UI shows that the app is still waiting instead of
     * telling the person to turn on a hotspot that may already be on.
     */
    private fun hotspotAddress(): AddressRead {
        if (!hasNetworkStatePermission()) {
            return AddressRead(value = null, checkFailed = true)
        }
        val probe = try {
            SourceProxyRuntime.hotspotFinder(context).probe()
        } catch (_: Exception) {
            HotspotProbe.Unknown
        }
        return when (probe) {
            HotspotProbe.Pending -> AddressRead(value = null, pending = true)
            HotspotProbe.Unknown -> AddressRead(value = null, checkFailed = true)
            is HotspotProbe.Observed -> AddressRead(value = bestAddress(probe))
        }
    }

    private fun bestAddress(observed: HotspotProbe.Observed): String? {
        val best = observed.candidates.minByOrNull { it.rank } ?: return null
        if (observed.candidates.count { it.rank == best.rank } != 1) return null
        return best.address.hostAddress
    }

    private data class AddressRead(
        val value: String?,
        val pending: Boolean = false,
        val checkFailed: Boolean = false,
    )
}

/**
 * The real Android clipboard for the token copy.
 *
 * Android 13 and later get the sensitive extra, which asks the system to hide
 * the clip preview. That flag does not stop a paste, and a system that does
 * not honor it can still show a preview. Android 9 and later use
 * clearPrimaryClip. Android 8.0 and 8.1 replace the clip with empty text,
 * which is the best call on those versions.
 *
 * The platform has no clipboard expiry. The controller sets one bounded clear
 * request. A clipboard read can be refused when the app is in the background
 * on Android 10 and later, so the clear can be skipped. A skipped clear is
 * safer than clearing a newer item that the app cannot inspect.
 */
internal class AndroidTokenClipboard(context: Context) : TokenClipboard {
    private val appContext = context.applicationContext
    private val manager = appContext.getSystemService(ClipboardManager::class.java)

    override fun current(): ClipboardSnapshot? {
        val currentManager = manager ?: return null
        // Check the description before requesting clip contents. Another app
        // can replace the clip between these reads, so check the label again.
        val label = try {
            currentManager.primaryClipDescription?.label?.toString()
        } catch (_: Exception) {
            return null
        }
        if (label != ManualConnectionPolicy.TOKEN_CLIP_LABEL) return null
        val clip = try {
            currentManager.primaryClip
        } catch (_: Exception) {
            return null
        } ?: return null
        if (clip.description?.label?.toString() != label || clip.itemCount == 0) return null
        val item = clip.getItemAt(0)
        return ClipboardSnapshot(
            text = item.text?.toString(),
            label = clip.description?.label?.toString(),
            createdAtMillis = clip.description?.timestamp,
        )
    }

    override fun setSensitiveText(text: String, label: String) {
        val currentManager = manager
            ?: throw IllegalStateException("The clipboard is not available.")
        val clip = ClipData.newPlainText(label, text)
        if (ClipboardPrivacy.marksSensitive(Build.VERSION.SDK_INT)) {
            val extras = PersistableBundle()
            extras.putBoolean(ClipboardPrivacy.SENSITIVE_EXTRA, true)
            clip.description.extras = extras
        }
        currentManager.setPrimaryClip(clip)
    }

    override fun clear() {
        val currentManager = manager ?: return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            ClipboardPrivacy.clearsPrimaryClip(Build.VERSION.SDK_INT)
        ) {
            currentManager.clearPrimaryClip()
        } else {
            currentManager.setPrimaryClip(ClipData.newPlainText("", ""))
        }
    }
}

/**
 * The real Android clipboard for the connection details copy.
 *
 * The text holds no token, so the clip has no sensitive flag and no clear. It
 * replaces whatever the clipboard held, including an earlier token copy.
 */
internal class AndroidConnectionClipboard(context: Context) : ConnectionClipboard {
    private val manager = context.applicationContext.getSystemService(ClipboardManager::class.java)

    override fun setText(text: String, label: String) {
        val currentManager = manager
            ?: throw IllegalStateException("The clipboard is not available.")
        currentManager.setPrimaryClip(ClipData.newPlainText(label, text))
    }
}

/** Run the delayed clipboard clear on the main looper. */
internal class MainThreadClipboardClearScheduler : ClipboardClearScheduler {
    private val handler = Handler(Looper.getMainLooper())

    override fun schedule(delayMillis: Long, action: () -> Unit) {
        handler.postDelayed(action, delayMillis)
    }
}

/**
 * Hold the real manual connection values for Settings.
 *
 * The view model performs the reads off the main thread. It keeps the token in
 * memory and copies it into Compose state only while the timed reveal is open.
 * The token is never logged and never placed in a report.
 */
class ManualConnectionViewModel(application: Application) : AndroidViewModel(application) {
    private val source: ManualConnectionSource = AndroidManualConnectionSource(application)
    private val session = ManualConnectionSession(
        TokenClipboardController(
            AndroidTokenClipboard(application),
            MainThreadClipboardClearScheduler(),
        ),
        connectionClipboard = AndroidConnectionClipboard(application),
    ).also { it.setProxyRunning(false) }

    var state by mutableStateOf(session.state)
        private set

    /** The visible token text, or null while the token is hidden. */
    var revealedToken by mutableStateOf<String?>(null)
        private set

    /** The clock for the reveal countdown. It updates only while revealed. */
    var nowMillis by mutableLongStateOf(System.currentTimeMillis())
        private set

    private var savedPort = 0
    private var runningPort = 0
    private var refreshJob: Job? = null
    private var revealJob: Job? = null
    private var copyJob: Job? = null

    /** Read the address, port, and token again. */
    fun refresh() {
        refreshJob?.cancel()
        session.setLoading()
        sync()
        refreshJob = viewModelScope.launch {
            val loaded = try {
                withContext(Dispatchers.IO) { source.load() }
            } catch (_: Exception) {
                null
            }
            if (loaded == null) {
                // The read failed. Do not claim that the token is absent: the
                // app cannot prove it. Keep the last token state and report the
                // address check as failed.
                session.setConnection(
                    address = null,
                    port = resolvedPort(),
                    addressCheckFailed = true,
                    addressPending = false,
                )
                sync()
                return@launch
            }
            savedPort = loaded.savedPort
            session.setConnection(
                address = loaded.address,
                port = resolvedPort(),
                addressCheckFailed = loaded.addressCheckFailed,
                addressPending = loaded.addressPending,
            )
            session.setToken(loaded.token, loaded.tokenUnreadable)
            if (!session.hasToken()) {
                revealJob?.cancel()
                revealJob = null
            }
            sync()
        }
    }

    /** Keep the displayed port in step with the running proxy. */
    fun setRunningPort(port: Int) {
        runningPort = if (port in 1..65_535) port else 0
        session.setPort(resolvedPort())
        session.setProxyRunning(runningPort in 1..65_535)
        sync()
    }

    /** Show or hide the token. A show is always time bounded. */
    fun toggleToken() {
        if (session.state.tokenVisible) {
            hideToken()
            return
        }
        nowMillis = System.currentTimeMillis()
        val result = session.reveal()
        sync()
        if (result == ManualRevealResult.REVEALED) startRevealTicker()
    }

    /** Copy the token only while a person can see it. */
    fun copyToken() {
        val result = session.copy()
        sync()
        copyJob?.cancel()
        if (result == TokenCopyResult.COPIED ||
            result == TokenCopyResult.ALREADY_ON_CLIPBOARD
        ) {
            copyJob = viewModelScope.launch {
                delay(COPY_CONFIRM_MILLIS)
                session.clearCopyMessage()
                sync()
            }
        }
    }

    /** Copy the address, port, and username. The text never holds the token. */
    fun copyConnectionDetails() {
        val result = session.copyConnectionDetails()
        sync()
        copyJob?.cancel()
        if (result != ConnectionCopyResult.NONE) {
            copyJob = viewModelScope.launch {
                delay(COPY_CONFIRM_MILLIS)
                session.clearCopyMessage()
                sync()
            }
        }
    }

    /** Hide the token when Settings is no longer on screen. */
    fun hideTokenNow() {
        hideToken()
    }

    /** Hide the token when the app leaves the foreground. */
    fun onBackground() {
        revealJob?.cancel()
        revealJob = null
        copyJob?.cancel()
        copyJob = null
        session.onBackground()
        sync()
    }

    /**
     * Hide any shown token after a token write request.
     *
     * The write can fail, so this does not assume a new value. It only closes
     * the old display and reads the store again.
     */
    fun onTokenWriteAttempted() {
        hideToken()
        sync()
        refresh()
    }

    private fun hideToken() {
        revealJob?.cancel()
        revealJob = null
        session.hide()
        sync()
    }

    private fun startRevealTicker() {
        revealJob?.cancel()
        nowMillis = System.currentTimeMillis()
        revealJob = viewModelScope.launch {
            while (isActive && session.state.tokenVisible) {
                delay(REVEAL_TICK_MILLIS)
                nowMillis = System.currentTimeMillis()
                session.expire()
                sync()
                if (!session.state.tokenVisible) break
            }
        }
    }

    private fun resolvedPort(): Int =
        if (runningPort in 1..65_535) runningPort else savedPort

    private fun sync() {
        state = session.state
        revealedToken = session.visibleToken()
    }

    private companion object {
        const val REVEAL_TICK_MILLIS = 500L
        const val COPY_CONFIRM_MILLIS = 2_000L
    }
}
