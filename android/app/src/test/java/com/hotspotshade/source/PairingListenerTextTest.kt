package com.hotspotshade.source

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests for the real pairing listener text.
 *
 * The unreadable-token state must be different from a general failure and must
 * name a recovery action. An unusable value is the same state, so the message
 * must name both shapes. Every state needs its own text, so a new state cannot
 * silently fall back to another state's message.
 */
class PairingListenerTextTest {
    @Test
    fun theUnreadableTokenStateHasItsOwnRecoveryMessage() {
        val message = pairingListenerMessage(RealPairingListener.TOKEN_UNREADABLE)

        assertTrue(message.contains("cannot be read"))
        assertTrue(
            "An empty or not printable stored value is the same state.",
            message.contains("not usable"),
        )
        assertTrue(
            "The message must say the app does not replace the token on its own.",
            message.contains("never replaces the token on its own"),
        )
        assertTrue(message.contains("rotate the source token"))
        assertTrue(message.contains("pair again"))
        assertFalse(message.contains("clear the app data"))
        assertNotEquals(
            "An unreadable token is not a general listener failure.",
            pairingListenerMessage(RealPairingListener.FAILED),
            message,
        )
    }

    @Test
    fun everyListenerStateHasADistinctNonEmptyMessage() {
        val messages = RealPairingListener.entries.map { pairingListenerMessage(it) }

        assertTrue(messages.all { it.isNotBlank() })
        assertEquals(
            "Two listener states must not share one message.",
            messages.size,
            messages.toSet().size,
        )
    }

    @Test
    fun theInternalUnreadableStateMapsToTheUiState() {
        assertEquals(
            RealPairingListener.TOKEN_UNREADABLE,
            PairingListenerState.TOKEN_UNREADABLE.toRealPairingListener(),
        )
        assertEquals(
            RealPairingListener.FAILED,
            PairingListenerState.FAILED.toRealPairingListener(),
        )
        assertEquals(
            RealPairingListener.LISTENING,
            PairingListenerState.LISTENING.toRealPairingListener(),
        )
        assertEquals(
            RealPairingListener.NO_HOTSPOT,
            PairingListenerState.NO_HOTSPOT.toRealPairingListener(),
        )
        assertEquals(
            RealPairingListener.STOPPED,
            PairingListenerState.STOPPED.toRealPairingListener(),
        )
    }
}
