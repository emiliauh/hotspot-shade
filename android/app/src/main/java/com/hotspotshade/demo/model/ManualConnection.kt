package com.hotspotshade.demo.model

import com.hotspotshade.source.SourceSocksServer
import com.hotspotshade.source.isUsableSourceToken
import kotlin.math.max

/** The result of one token copy request. */
enum class TokenCopyResult {
    NONE,
    COPIED,
    ALREADY_ON_CLIPBOARD,
    REFUSED_HIDDEN,
    REFUSED_ABSENT,
    FAILED,
}

/** The result of one Copy connection details request. */
enum class ConnectionCopyResult { NONE, COPIED, UNAVAILABLE, FAILED }

/**
 * Write plain, non-secret text to the clipboard.
 *
 * The connection details hold the address, the port, and the SOCKS5 username.
 * They never hold the token, so the write carries no sensitive flag and
 * schedules no clear. A JVM test supplies a fake.
 */
fun interface ConnectionClipboard {
    fun setText(text: String, label: String)
}

/** The result of one token reveal request. */
enum class ManualRevealResult { REVEALED, UNAVAILABLE }

/**
 * The real manual connection values for another SOCKS5 client.
 *
 * The state holds the local address, the port, and flags. It never holds the
 * source token. The token text is kept in [ManualConnectionSession] and is
 * exposed only while a timed reveal is open. Logs, error text, and diagnostics
 * must not receive a token from this state.
 */
data class ManualConnectionState(
    val loading: Boolean = true,
    val address: String? = null,
    val addressCheckFailed: Boolean = false,
    /** The API 36 tethering callback has not delivered its first reading. */
    val addressPending: Boolean = false,
    val port: Int = 0,
    val tokenAvailable: Boolean = false,
    /** A stored token exists but the app cannot read it. It is not absent. */
    val tokenUnreadable: Boolean = false,
    val tokenVisible: Boolean = false,
    val revealUntilMillis: Long? = null,
    val copy: TokenCopyResult = TokenCopyResult.NONE,
    val connectionCopy: ConnectionCopyResult = ConnectionCopyResult.NONE,
) {
    /**
     * True when the address and the port are real, so Copy connection details
     * can write them. It never depends on the token.
     */
    val connectionDetailsAvailable: Boolean
        get() = ManualConnectionPolicy.connectionDetailsText(address, port) != null

    /** A short confirmation or refusal for Copy connection details. */
    val connectionCopyMessage: String?
        get() = when (connectionCopy) {
            ConnectionCopyResult.NONE -> null
            ConnectionCopyResult.COPIED -> "The connection details are copied."
            ConnectionCopyResult.UNAVAILABLE ->
                "The hotspot address or the port is not known yet, so there is nothing to copy."
            ConnectionCopyResult.FAILED -> "The app could not copy the connection details."
        }

    /** The plain hotspot address line, with loading and empty states. */
    val addressText: String
        get() = when {
            address != null -> address
            loading -> "Checking the hotspot address."
            addressPending -> "Waiting for the system hotspot reading."
            addressCheckFailed -> "The app could not read the hotspot address."
            else -> "No hotspot address. Turn on the hotspot and refresh."
        }

    /** The port line. A saved port is stable across starts. */
    val portText: String
        get() = if (port in MINIMUM_PORT..MAXIMUM_PORT) {
            port.toString()
        } else {
            "Chosen when the proxy starts."
        }

    /** The SOCKS5 username. It is not secret. */
    val usernameText: String get() = ManualConnectionPolicy.SOCKS_USERNAME

    /** The token line when the token cannot be shown. */
    val tokenStateText: String
        get() = when {
            tokenUnreadable ->
                "The stored token cannot be read. Tap Refresh connection to try again."
            !tokenAvailable -> "No token is stored yet. Start the proxy once and the app creates it."
            tokenVisible -> "The token is shown below. It hides again after 30 seconds."
            else -> "The token is hidden. Tap Show token to see it."
        }

    /** A short confirmation or refusal for the copy action. */
    val copyMessage: String?
        get() = when (copy) {
            TokenCopyResult.NONE -> null
            TokenCopyResult.COPIED -> "The token is copied."
            TokenCopyResult.ALREADY_ON_CLIPBOARD -> "The token is already on the clipboard."
            TokenCopyResult.REFUSED_HIDDEN -> "Show the token before you copy it."
            TokenCopyResult.REFUSED_ABSENT -> if (tokenUnreadable) {
                "The stored token cannot be read, so there is nothing to copy."
            } else {
                "No token is stored, so there is nothing to copy."
            }
            TokenCopyResult.FAILED -> "The app could not copy the token."
        }

    /** The whole seconds left in the timed reveal. Zero when it is closed. */
    fun tokenSecondsRemainingAt(nowMillis: Long): Int =
        ManualConnectionPolicy.remainingSeconds(revealUntilMillis, nowMillis)

    /**
     * Text for a log or a report. It never holds the token.
     *
     * The address is a local value. It is not included here because the
     * settings diagnostics report stays address free.
     */
    override fun toString(): String =
        "ManualConnectionState(port=$port, tokenAvailable=$tokenAvailable, " +
            "tokenUnreadable=$tokenUnreadable, tokenVisible=$tokenVisible, " +
            "addressPending=$addressPending, loading=$loading)"

    companion object {
        const val MINIMUM_PORT = 1024
        const val MAXIMUM_PORT = 65535
    }
}

/** The pure reveal, expire, and copy policy for the real manual connection. */
object ManualConnectionPolicy {
    /** The SOCKS5 username that the source proxy accepts. */
    const val SOCKS_USERNAME = SourceSocksServer.SOCKS_USERNAME

    /** How long one explicit token reveal stays open. */
    const val TOKEN_REVEAL_SECONDS = 30

    /** How long the app asks the platform to keep a copied token. */
    const val CLIPBOARD_CLEAR_SECONDS = 120

    /** The label that marks a clip written by this app. */
    const val TOKEN_CLIP_LABEL = "HotspotShade source token"

    /** The label of the connection details clip. It never holds a token. */
    const val CONNECTION_CLIP_LABEL = "HotspotShade connection details"

    /**
     * The text that Copy connection details writes, or null when the address
     * or the port is not real. It names the token field but never holds a
     * token or any other secret. The wording follows the iOS app.
     */
    fun connectionDetailsText(address: String?, port: Int): String? {
        val host = address?.trim().orEmpty()
        if (host.isEmpty() || host.any { it.isWhitespace() }) return null
        if (port !in ManualConnectionState.MINIMUM_PORT..ManualConnectionState.MAXIMUM_PORT) {
            return null
        }
        return "HotspotShade SOCKS5 proxy\n" +
            "Server: $host:$port\n" +
            "Username: $SOCKS_USERNAME\n" +
            "Password: the source token. Show it in HotspotShade Settings, Manual connection.\n" +
            "Use remote DNS, for example a socks5h proxy URL, so names resolve on the " +
            "source device.\n"
    }

    const val USERNAME_NOTE =
        "The other app must support SOCKS5 username and password authentication."

    const val HIDDEN_NOTE =
        "The token is hidden. Tap Show token to see it. It hides again after 30 " +
            "seconds or when the app goes to the background."

    /**
     * The precise limits of an Android clipboard copy.
     *
     * Android has no system enforced clipboard expiry. The app asks for a
     * clear after about two minutes. It clears only when it can still read the
     * clip, the clip still holds this token with this app's label, and no newer
     * clip has replaced it.
     */
    const val CLIPBOARD_NOTE =
        "Android does not enforce a clipboard expiry. The app asks for a clear " +
            "after about two minutes, and clears only when the clip still holds " +
            "this token and no newer item has replaced it. Android 10 and later " +
            "can refuse the read while the app is in the background, so a copy " +
            "can stay. Android 13 and later can hide the clipboard preview when " +
            "the system honors the sensitive flag. Before Android 13, the system " +
            "can show a preview with the token. Any app you paste into can still " +
            "read it. A keyboard, a clipboard history tool, or a vendor sync " +
            "feature can keep a copy. Clear the clipboard yourself if that matters."

    /** Open one timed reveal. The token stays hidden when none is stored. */
    fun reveal(state: ManualConnectionState, nowMillis: Long): ManualConnectionState =
        if (!state.tokenAvailable) {
            state.copy(tokenVisible = false, revealUntilMillis = null)
        } else {
            state.copy(
                tokenVisible = true,
                revealUntilMillis = nowMillis + TOKEN_REVEAL_SECONDS * 1_000L,
                copy = TokenCopyResult.NONE,
            )
        }

    /** Close the reveal now. */
    fun hide(state: ManualConnectionState): ManualConnectionState =
        state.copy(
            tokenVisible = false,
            revealUntilMillis = null,
            copy = TokenCopyResult.NONE,
            connectionCopy = ConnectionCopyResult.NONE,
        )

    /** Close the reveal when its deadline has passed. */
    fun expire(state: ManualConnectionState, nowMillis: Long): ManualConnectionState {
        if (!state.tokenVisible) return state
        val until = state.revealUntilMillis ?: return hide(state)
        return if (nowMillis >= until) hide(state) else state
    }

    /** The whole seconds left, rounded up. Zero when no reveal is open. */
    fun remainingSeconds(untilMillis: Long?, nowMillis: Long): Int {
        val until = untilMillis ?: return 0
        val remaining = until - nowMillis
        return max(0, ((remaining + 999L) / 1_000L).toInt())
    }

    /** True only when a person can see the token. */
    fun canCopy(state: ManualConnectionState): Boolean =
        state.tokenVisible && state.tokenAvailable
}

/** One text clip as the app can read it. */
data class ClipboardSnapshot(
    val text: String?,
    val label: String?,
    /** The platform clip timestamp, or null when it cannot be read. */
    val createdAtMillis: Long? = null,
) {
    /** Never print the text. The current clip can hold another app's secret. */
    override fun toString(): String =
        "ClipboardSnapshot(text=${if (text == null) "none" else "[redacted]"}, " +
            "label=$label, createdAtMillis=$createdAtMillis)"
}

/**
 * The clipboard operations that the token copy needs.
 *
 * A JVM test supplies a fake. The production class is the only place that
 * touches android.content.ClipboardManager.
 */
interface TokenClipboard {
    /** Return the current clip, or null when the app cannot read it. */
    fun current(): ClipboardSnapshot?

    /** Write one text clip that the platform should treat as sensitive. */
    fun setSensitiveText(text: String, label: String)

    /** Clear the primary clip, or replace it with empty text on old versions. */
    fun clear()
}

/** Run one delayed clipboard clear. A JVM test supplies a fake. */
fun interface ClipboardClearScheduler {
    fun schedule(delayMillis: Long, action: () -> Unit)
}

/** The platform version rules for the clipboard protections. */
object ClipboardPrivacy {
    /**
     * The platform extra that marks a clip as sensitive in the preview.
     *
     * The value matches ClipDescription.EXTRA_IS_SENSITIVE, which arrived in
     * Android 13. The app writes the value itself so an older platform never
     * loads the newer class field.
     */
    const val SENSITIVE_EXTRA = "android.content.extra.IS_SENSITIVE"

    /** Android 13 (API 33) and later support the sensitive preview flag. */
    fun marksSensitive(sdkInt: Int): Boolean = sdkInt >= 33

    /**
     * Android 9 (API 28) and later can clear the primary clip.
     *
     * Android 8.0 and 8.1 replace the clip with empty text instead. Neither is
     * a secure erase.
     */
    fun clearsPrimaryClip(sdkInt: Int): Boolean = sdkInt >= 28
}

/**
 * Copy one token and ask for a bounded clipboard clear.
 *
 * The controller writes the clip once. A second copy of the same clip is
 * refused as unnecessary. Each write takes a new generation. A scheduled
 * clear runs only when its generation is still current, the clip still has
 * this app's label, and the text still equals the copied token. A platform
 * clip timestamp newer than the write also stops the clear, so a newer item
 * is never removed.
 */
class TokenClipboardController(
    private val clipboard: TokenClipboard,
    private val scheduler: ClipboardClearScheduler,
    private val clearDelayMillis: Long =
        ManualConnectionPolicy.CLIPBOARD_CLEAR_SECONDS * 1_000L,
    private val nowMillis: () -> Long = { System.currentTimeMillis() },
) {
    private var generation = 0

    /** Copy [token], or report why no write happened. */
    fun copy(token: String): TokenCopyResult {
        if (token.isEmpty()) return TokenCopyResult.REFUSED_ABSENT
        val current = read()
        if (current?.text == token && current.label == ManualConnectionPolicy.TOKEN_CLIP_LABEL) {
            return TokenCopyResult.ALREADY_ON_CLIPBOARD
        }
        return try {
            clipboard.setSensitiveText(token, ManualConnectionPolicy.TOKEN_CLIP_LABEL)
            val writtenAt = nowMillis()
            scheduleClear(token, ++generation, writtenAt)
            TokenCopyResult.COPIED
        } catch (_: Exception) {
            TokenCopyResult.FAILED
        }
    }

    private fun scheduleClear(token: String, ownedGeneration: Int, writtenAtMillis: Long) {
        scheduler.schedule(clearDelayMillis) {
            if (ownedGeneration != generation) return@schedule
            val current = read() ?: return@schedule
            if (current.text != token) return@schedule
            if (current.label != ManualConnectionPolicy.TOKEN_CLIP_LABEL) return@schedule
            val createdAt = current.createdAtMillis
            if (createdAt != null && createdAt > writtenAtMillis) return@schedule
            try {
                clipboard.clear()
            } catch (_: Exception) {
                // The clip can change between the read and the clear. A failed
                // clear leaves the person's clipboard unchanged.
            }
        }
    }

    private fun read(): ClipboardSnapshot? = try {
        clipboard.current()
    } catch (_: Exception) {
        null
    }
}

/**
 * Hold the real manual connection values and the timed token reveal.
 *
 * A JVM test drives this class with a fake clock and a fake clipboard. The
 * view model only copies [state] into Compose state. The token itself is never
 * part of [ManualConnectionState].
 */
class ManualConnectionSession(
    private val clipboard: TokenClipboardController,
    private val connectionClipboard: ConnectionClipboard? = null,
    // Keep the clock last: a test passes it as a trailing lambda.
    private val clock: () -> Long = { System.currentTimeMillis() },
) {
    var state: ManualConnectionState = ManualConnectionState()
        private set

    private var token: String? = null

    /** Mark a refresh in progress. Existing addresses and token stay visible. */
    fun setLoading() {
        state = state.copy(loading = true)
    }

    /** Set the real address and the current or saved port. */
    fun setConnection(
        address: String?,
        port: Int,
        addressCheckFailed: Boolean,
        addressPending: Boolean = false,
    ) {
        state = state.copy(
            loading = false,
            address = address,
            addressCheckFailed = addressCheckFailed,
            addressPending = addressPending,
            port = port,
        )
    }

    /** Set the current port only. A zero value falls back to the saved port. */
    fun setPort(port: Int) {
        state = state.copy(port = port)
    }

    /**
     * Replace the stored token.
     *
     * A missing token closes the reveal and refuses a display. A stored token
     * that the app cannot read is not absent: it keeps [ManualConnectionState
     * .tokenUnreadable] so the UI can offer the right recovery. A changed token
     * also closes the reveal, so a stale value is never shown.
     */
    fun setToken(value: String?, unreadable: Boolean = false) {
        val next = if (unreadable) null else value?.takeIf(::isUsableSourceToken)
        val changed = next != token
        token = next
        state = when {
            next == null -> ManualConnectionPolicy.hide(state).copy(
                tokenAvailable = false,
                tokenUnreadable = unreadable || value != null,
                copy = TokenCopyResult.NONE,
            )

            changed -> ManualConnectionPolicy.hide(state).copy(
                tokenAvailable = true,
                tokenUnreadable = false,
            )

            else -> state.copy(tokenAvailable = true, tokenUnreadable = false)
        }
    }

    /** Open one explicit timed reveal. */
    fun reveal(): ManualRevealResult {
        if (token == null) {
            state = ManualConnectionPolicy.hide(state).copy(tokenAvailable = false)
            return ManualRevealResult.UNAVAILABLE
        }
        state = ManualConnectionPolicy.reveal(state, clock())
        return ManualRevealResult.REVEALED
    }

    /** Close the reveal now. */
    fun hide() {
        state = ManualConnectionPolicy.hide(state)
    }

    /** Close the reveal when its deadline has passed. Return true on a change. */
    fun expire(): Boolean {
        if (!state.tokenVisible) return false
        val next = ManualConnectionPolicy.expire(state, clock())
        val changed = next != state
        state = next
        return changed
    }

    /**
     * Hide the token when the app goes to the background.
     *
     * The clipboard copy is not revoked. The person may still paste it into
     * the other app. Only the display is closed.
     */
    fun onBackground() {
        state = ManualConnectionPolicy.hide(state)
    }

    /** Copy the token only while the reveal is open. */
    fun copy(): TokenCopyResult {
        val value = token
        val result = when {
            value == null -> TokenCopyResult.REFUSED_ABSENT
            !ManualConnectionPolicy.canCopy(state) -> TokenCopyResult.REFUSED_HIDDEN
            else -> clipboard.copy(value)
        }
        state = state.copy(copy = result, connectionCopy = ConnectionCopyResult.NONE)
        return result
    }

    /** Remove the copy confirmation after its short display. */
    fun clearCopyMessage() {
        if (state.copy != TokenCopyResult.NONE ||
            state.connectionCopy != ConnectionCopyResult.NONE
        ) {
            state = state.copy(
                copy = TokenCopyResult.NONE,
                connectionCopy = ConnectionCopyResult.NONE,
            )
        }
    }

    /**
     * Copy the address, the port, and the SOCKS5 username.
     *
     * The text never holds the token, so the copy does not need a reveal. It
     * replaces any token copy on the clipboard. The token clear request looks
     * for the token label and the token text, so it leaves this clip alone.
     */
    fun copyConnectionDetails(): ConnectionCopyResult {
        val text = ManualConnectionPolicy.connectionDetailsText(state.address, state.port)
        val result = when {
            text == null -> ConnectionCopyResult.UNAVAILABLE
            connectionClipboard == null -> ConnectionCopyResult.FAILED
            else -> try {
                connectionClipboard.setText(text, ManualConnectionPolicy.CONNECTION_CLIP_LABEL)
                ConnectionCopyResult.COPIED
            } catch (_: Exception) {
                ConnectionCopyResult.FAILED
            }
        }
        state = state.copy(connectionCopy = result, copy = TokenCopyResult.NONE)
        return result
    }

    /** The token text, but only while the timed reveal is open. */
    fun visibleToken(): String? = token.takeIf { state.tokenVisible }

    /** True when a stored token exists. It does not reveal it. */
    fun hasToken(): Boolean = token != null
}
