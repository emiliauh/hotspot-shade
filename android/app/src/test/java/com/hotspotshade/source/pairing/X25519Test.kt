package com.hotspotshade.source.pairing

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertNotNull
import org.junit.Test

/**
 * Fixed public X25519 vectors. The RFC 7748 vectors and the pairing parity
 * values come from public documents. They are not secrets.
 */
class X25519Test {
    private fun hex(value: String): ByteArray = PairingProtocol.unhex(value)

    @Test
    fun rfc7748Section52Vector() {
        val alicePrivate = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        val alicePublic = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        val bobPrivate = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        val bobPublic = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        val shared = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

        assertArrayEquals(alicePublic, X25519.publicKey(alicePrivate)!!)
        assertArrayEquals(bobPublic, X25519.publicKey(bobPrivate)!!)
        assertArrayEquals(shared, X25519.agree(alicePrivate, bobPublic)!!)
        assertArrayEquals(shared, X25519.agree(bobPrivate, alicePublic)!!)
    }

    @Test
    fun rfc7748Section612OneIteration() {
        val scalar = hex("0900000000000000000000000000000000000000000000000000000000000000")
        val point = hex("0900000000000000000000000000000000000000000000000000000000000000")
        val expected = hex("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
        assertArrayEquals(expected, X25519.agree(scalar, point)!!)
    }

    @Test
    fun parityPublicKeysMatchTheRustAndSwiftSuites() {
        assertEquals(
            "7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13",
            PairingProtocol.hex(X25519.publicKey(ByteArray(32) { 0x11 })!!),
        )
        assertEquals(
            "0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20",
            PairingProtocol.hex(X25519.publicKey(ByteArray(32) { 0x22 })!!),
        )
        assertEquals(
            "7b0d47d93427f8311160781c7c733fd89f88970aef490d8aa0ee19a4cb8a1b14",
            PairingProtocol.hex(X25519.publicKey(ByteArray(32) { 0x33 })!!),
        )
    }

    @Test
    fun lowOrderAndShortKeysAreRejected() {
        val privateKey = ByteArray(32) { 0x33 }
        assertNull(X25519.agree(privateKey, ByteArray(32)))
        val one = ByteArray(32).also { it[0] = 1 }
        assertNull(X25519.agree(privateKey, one))
        assertNull(X25519.agree(ByteArray(31), ByteArray(32)))
        assertNull(X25519.publicKey(ByteArray(31)))
        assertNotNull(X25519.agree(privateKey, X25519.publicKey(privateKey)!!))
    }
}
