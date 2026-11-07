package com.hotspotshade.demo.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SecureWindowControllerTest {
    private class FakeSecureWindow : SecureWindow {
        val calls = mutableListOf<Boolean>()

        override fun setSecure(secure: Boolean) {
            calls += secure
        }
    }

    @Test
    fun theBlockFollowsTheTokenReveal() {
        val window = FakeSecureWindow()
        val controller = SecureWindowController(window)

        controller.update(tokenRevealed = true)
        assertTrue(controller.isSecure)
        assertEquals(listOf(true), window.calls)

        controller.update(tokenRevealed = false)
        assertFalse(controller.isSecure)
        assertEquals(listOf(true, false), window.calls)
    }

    @Test
    fun repeatedStatesDoNotTouchTheWindow() {
        val window = FakeSecureWindow()
        val controller = SecureWindowController(window)

        controller.update(tokenRevealed = false)
        controller.update(tokenRevealed = true)
        controller.update(tokenRevealed = true)
        controller.update(tokenRevealed = false)
        controller.update(tokenRevealed = false)

        assertEquals(listOf(true, false), window.calls)
    }

    @Test
    fun theBackgroundPathClearsAnOpenReveal() {
        val window = FakeSecureWindow()
        val controller = SecureWindowController(window)
        controller.update(tokenRevealed = true)

        controller.onBackground()

        assertFalse(controller.isSecure)
        assertEquals(listOf(true, false), window.calls)
    }

    @Test
    fun theThirtySecondTimeoutClearsAnOpenReveal() {
        val window = FakeSecureWindow()
        val controller = SecureWindowController(window)
        val revealed = ManualConnectionPolicy.reveal(
            ManualConnectionState(tokenAvailable = true),
            nowMillis = 1_000L,
        )
        controller.update(tokenRevealed = revealed.tokenVisible)
        assertTrue(controller.isSecure)

        val expired = ManualConnectionPolicy.expire(revealed, nowMillis = 31_000L)
        controller.update(tokenRevealed = expired.tokenVisible)

        assertFalse(controller.isSecure)
        assertEquals(listOf(true, false), window.calls)
    }
}
