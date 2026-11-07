package com.hotspotshade.source.pairing

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

/** Fixed public HKDF-SHA256 vectors from RFC 5869, test cases 1 and 3. */
class HkdfTest {
    @Test
    fun rfc5869TestCaseOne() {
        val input = ByteArray(22) { 0x0B }
        val salt = PairingProtocol.unhex("000102030405060708090a0b0c")
        val info = PairingProtocol.unhex("f0f1f2f3f4f5f6f7f8f9")
        val pseudoRandomKey = Hkdf.extract(salt, input)
        assertEquals(
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
            PairingProtocol.hex(pseudoRandomKey),
        )
        val output = Hkdf.expand(pseudoRandomKey, info, 42)
        assertArrayEquals(
            PairingProtocol.unhex(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
                    "34007208d5b887185865",
            ),
            output,
        )
    }

    /**
     * RFC 5869 case 3 uses an empty salt. The extract step must use a string
     * of 32 zero bytes. An empty HMAC key is not portable and some providers
     * reject it.
     */
    @Test
    fun rfc5869TestCaseThreeWithAnEmptySalt() {
        val input = ByteArray(22) { 0x0B }
        val pseudoRandomKey = Hkdf.extract(ByteArray(0), input)
        assertEquals(
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
            PairingProtocol.hex(pseudoRandomKey),
        )
        val output = Hkdf.expand(pseudoRandomKey, ByteArray(0), 42)
        assertArrayEquals(
            PairingProtocol.unhex(
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d" +
                    "9d201395faa4b61a96c8",
            ),
            output,
        )
    }
}
