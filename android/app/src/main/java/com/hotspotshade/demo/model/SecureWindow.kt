package com.hotspotshade.demo.model

/**
 * Apply or clear the screen-capture block on the activity window.
 *
 * A JVM test supplies a fake. The production class is the only place that
 * touches android.view.Window.
 */
fun interface SecureWindow {
    /** Set the window block. True adds it and false clears it. */
    fun setSecure(secure: Boolean)
}

/**
 * Keep the screen-capture block in step with the real token reveal.
 *
 * The block is on only while the real Settings token is visible. It turns off
 * when the reveal closes, when the app goes to the background, and when the
 * 30 second reveal expires. A call that does not change the state does not
 * touch the window.
 */
class SecureWindowController(
    private val window: SecureWindow,
) {
    private var secure = false

    /** True while the window blocks screenshots and the recents thumbnail. */
    val isSecure: Boolean get() = secure

    /** Request the block state for the current reveal. */
    fun update(tokenRevealed: Boolean) {
        if (tokenRevealed == secure) return
        secure = tokenRevealed
        window.setSecure(tokenRevealed)
    }

    /** Clear the block when the app leaves the foreground. */
    fun onBackground() {
        update(tokenRevealed = false)
    }
}
