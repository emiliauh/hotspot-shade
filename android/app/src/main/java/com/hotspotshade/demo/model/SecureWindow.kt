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
 * The block is on while the real Settings token is visible. It turns off when
 * the reveal closes and when the 30 second reveal expires. A call that does
 * not change the state does not touch the window.
 *
 * Going to the background does not clear the block. The system takes the
 * recents snapshot after onStop returns, and the last drawn frame can still
 * show the token. [onBackground] therefore holds the block. While the hold is
 * on, a "not revealed" update does not clear it, even when a recomposition
 * reports the token hidden after onStop. [onForeground] ends the hold and
 * applies the current reveal state, so the block clears only when the app is
 * back on screen and the token is no longer drawn.
 */
class SecureWindowController(
    private val window: SecureWindow,
) {
    private var secure = false
    private var backgrounded = false

    /** True while the window blocks screenshots and the recents thumbnail. */
    val isSecure: Boolean get() = secure

    /** Request the block state for the current reveal. */
    fun update(tokenRevealed: Boolean) {
        if (!tokenRevealed && backgrounded) return
        if (tokenRevealed == secure) return
        secure = tokenRevealed
        window.setSecure(tokenRevealed)
    }

    /**
     * Hold the block while the app is in the background. Call this before the
     * token is hidden, so no later update can clear the block early.
     */
    fun onBackground() {
        backgrounded = true
    }

    /**
     * End the hold and apply [tokenRevealed]. Call this when the activity
     * starts again and the state already shows the token hidden.
     */
    fun onForeground(tokenRevealed: Boolean) {
        backgrounded = false
        update(tokenRevealed)
    }
}
