package com.hotspotshade.source.pairing

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** Fixed public ChaCha20-Poly1305 vectors from RFC 8439. */
class ChaCha20Poly1305Test {
    private fun hex(value: String): ByteArray = PairingProtocol.unhex(value)

    @Test
    fun rfc8439Section252Poly1305Vector() {
        val key = hex(
            "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
        )
        val message = "Cryptographic Forum Research Group".toByteArray(Charsets.US_ASCII)
        assertEquals(
            "a8061dc1305136c6c22b8baf0c0127a9",
            PairingProtocol.hex(ChaCha20Poly1305.poly1305ForTest(key, message)),
        )
    }

    @Test
    fun rfc8439Section282AeadVector() {
        val key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        val nonce = hex("070000004041424344454647")
        val aad = hex("50515253c0c1c2c3c4c5c6c7")
        val plaintext = hex(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a20496620492063" +
                "6f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73" +
                "637265656e20776f756c642062652069742e",
        )
        val ciphertext = hex(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1" +
                "a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3" +
                "ff4def08e4b7a9de576d26586cec64b6116",
        )
        val tag = hex("1ae10b594f09e26a7e902ecbd0600691")

        val polyKey = ChaCha20Poly1305.blockForTest(key, 0, nonce).copyOf(32)
        assertEquals(
            "7bac2b252db447af09b67a55a4e955840ae1d6731075d9eb2a9375783ed553ff",
            PairingProtocol.hex(polyKey),
        )
        val manual = aad + ByteArray(4) + ciphertext + ByteArray(14) +
            byteArrayOf(12, 0, 0, 0, 0, 0, 0, 0) +
            byteArrayOf(ciphertext.size.toByte(), 0, 0, 0, 0, 0, 0, 0)
        assertEquals(
            PairingProtocol.hex(tag),
            PairingProtocol.hex(referencePoly1305(polyKey, manual)),
        )
        assertEquals(
            PairingProtocol.hex(tag),
            PairingProtocol.hex(ChaCha20Poly1305.poly1305ForTest(polyKey, manual)),
        )

        val sealed = ChaCha20Poly1305.seal(key, nonce, plaintext, aad)
        assertEquals(PairingProtocol.hex(ciphertext + tag), PairingProtocol.hex(sealed!!))
        assertArrayEquals(plaintext, ChaCha20Poly1305.open(key, nonce, sealed, aad)!!)
    }

    private fun referencePoly1305(key: ByteArray, message: ByteArray): ByteArray {
        val r = java.math.BigInteger(1, key.copyOfRange(0, 16).reversedArray())
            .and(java.math.BigInteger("0ffffffc0ffffffc0ffffffc0fffffff", 16))
        val s = java.math.BigInteger(1, key.copyOfRange(16, 32).reversedArray())
        val p = java.math.BigInteger.ONE.shiftLeft(130)
            .subtract(java.math.BigInteger.valueOf(5))
        var accumulator = java.math.BigInteger.ZERO
        var offset = 0
        while (offset < message.size) {
            val count = minOf(16, message.size - offset)
            var value = java.math.BigInteger(
                1,
                message.copyOfRange(offset, offset + count).reversedArray(),
            )
            value = value.add(java.math.BigInteger.ONE.shiftLeft(8 * count))
            accumulator = accumulator.add(value).multiply(r).mod(p)
            offset += count
        }
        val tag = accumulator.add(s).mod(java.math.BigInteger.ONE.shiftLeft(128))
        val bigEndian = tag.toByteArray()
        val output = ByteArray(16)
        for (index in output.indices) {
            val source = bigEndian.size - 1 - index
            output[index] = if (source >= 0) bigEndian[source] else 0
        }
        return output
    }

    @Test
    fun emptyValuesRoundTripAndTamperFails() {
        val key = ByteArray(32) { 0x5A }
        val nonce = ByteArray(12) { 0x44 }
        val aad = ByteArray(0)
        val plaintext = ByteArray(0)
        val sealed = ChaCha20Poly1305.seal(key, nonce, plaintext, aad)!!
        assertEquals(ChaCha20Poly1305.TAG_BYTES, sealed.size)
        assertArrayEquals(plaintext, ChaCha20Poly1305.open(key, nonce, sealed, aad)!!)

        val data = "a short pairing message".toByteArray(Charsets.US_ASCII)
        val sealedData = ChaCha20Poly1305.seal(key, nonce, data, aad)!!
        sealedData[0] = (sealedData[0].toInt() xor 1).toByte()
        assertNull(ChaCha20Poly1305.open(key, nonce, sealedData, aad))
        val wrongAad = byteArrayOf(1)
        val good = ChaCha20Poly1305.seal(key, nonce, data, aad)!!
        assertNull(ChaCha20Poly1305.open(key, nonce, good, wrongAad))
        assertNull(ChaCha20Poly1305.open(ByteArray(31), nonce, good, aad))
        assertNull(ChaCha20Poly1305.open(key, ByteArray(11), good, aad))
        assertNull(ChaCha20Poly1305.open(key, nonce, ByteArray(15), aad))
    }
}
