package com.hotspotshade.source

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests for the one token rule that the pairing listener, a pairing result,
 * and a proxy start share.
 *
 * These are JVM tests. They read no file and touch no device.
 */
class TokenUsabilityTest {
    @Test
    fun aPrintableTokenOfOneTo255CharactersIsUsable() {
        assertTrue(isUsableSourceToken("a"))
        assertTrue(isUsableSourceToken("paired-token"))
        assertTrue(isUsableSourceToken("a".repeat(255)))
        assertTrue(isUsableSourceToken("~!\"#"))
    }

    @Test
    fun anEmptyOrTooLongTokenIsNotUsable() {
        assertFalse(isUsableSourceToken(""))
        assertFalse(isUsableSourceToken("a".repeat(256)))
    }

    @Test
    fun aTokenWithASpaceOrControlCharacterIsNotUsable() {
        assertFalse(isUsableSourceToken("bad token"))
        assertFalse(isUsableSourceToken("tab\there"))
        assertFalse(isUsableSourceToken("line\nfeed"))
        assertFalse(isUsableSourceToken("\u0000"))
        assertFalse(isUsableSourceToken("\u007f"))
        assertFalse(isUsableSourceToken("caf\u00e9"))
    }
}
