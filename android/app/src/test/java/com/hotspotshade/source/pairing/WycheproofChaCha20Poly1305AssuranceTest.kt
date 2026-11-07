package com.hotspotshade.source.pairing

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.GeneralSecurityException
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Project Wycheproof ChaCha20-Poly1305 vectors for the Kotlin port in
 * `ChaCha20Poly1305.kt`.
 *
 * The fixture is a lossless TSV conversion of the complete test case set in
 * `testvectors_v1/chacha20_poly1305_test.json` at the pinned commit. Its
 * header holds the source, version, and license. The values are public test
 * data, not secrets.
 *
 * The wire layout under test is ciphertext followed by the 16-byte tag. Every
 * valid case must seal to the known value and open back to the message. Every
 * invalid case must be rejected by `open`, and a nonce that is not 12 bytes
 * must be rejected by both `seal` and `open`.
 *
 * JDK 17 has a ChaCha20-Poly1305 cipher, so the test compares the Kotlin
 * result with the platform provider for the 96-bit-nonce cases. A JCA
 * rejection is not used as an oracle for the other nonce sizes, because the
 * Kotlin API rejects them by contract instead of accepting a variable nonce.
 */
class WycheproofChaCha20Poly1305AssuranceTest {
    private class Vector(
        val tcId: Int,
        val result: String,
        val flags: String,
        val ivSize: Int,
        val keySize: Int,
        val tagSize: Int,
        val key: String,
        val iv: String,
        val aad: String,
        val msg: String,
        val ct: String,
        val tag: String,
        val comment: String,
    )

    private fun hex(value: String): ByteArray =
        if (value == "-") ByteArray(0) else PairingProtocol.unhex(value)

    private fun loadVectors(): List<Vector> {
        val stream = javaClass.getResourceAsStream(RESOURCE)
            ?: error("The ChaCha20-Poly1305 vector fixture is missing: $RESOURCE")
        val vectors = mutableListOf<Vector>()
        stream.bufferedReader(Charsets.UTF_8).useLines { lines ->
            for (line in lines) {
                if (line.isBlank() || line.startsWith("#")) continue
                val parts = line.split('\t')
                check(parts.size == 13) { "A vector row has ${parts.size} fields." }
                vectors.add(
                    Vector(
                        tcId = parts[0].toInt(),
                        result = parts[1],
                        flags = parts[2],
                        ivSize = parts[3].toInt(),
                        keySize = parts[4].toInt(),
                        tagSize = parts[5].toInt(),
                        key = parts[6],
                        iv = parts[7],
                        aad = parts[8],
                        msg = parts[9],
                        ct = parts[10],
                        tag = parts[11],
                        comment = parts[12],
                    ),
                )
            }
        }
        return vectors
    }

    @Test
    fun fixtureHoldsTheCompletePinnedVectorSet() {
        val vectors = loadVectors()
        assertEquals(325, vectors.size)
        assertEquals(325, vectors.map { it.tcId }.toSet().size)
        assertEquals(256, vectors.count { it.result == "valid" })
        assertEquals(69, vectors.count { it.result == "invalid" })
        assertEquals(316, vectors.count { it.ivSize == 96 })
        assertEquals(9, vectors.count { it.ivSize != 96 })
        assertEquals(60, vectors.count { it.result == "invalid" && it.ivSize == 96 })
        for (vector in vectors) {
            assertEquals("tcId ${vector.tcId}", 256, vector.keySize)
            assertEquals("tcId ${vector.tcId}", 128, vector.tagSize)
            if (vector.result == "valid") {
                assertEquals("tcId ${vector.tcId}", 96, vector.ivSize)
            }
        }
    }

    @Test
    fun validVectorsSealAndOpenToTheKnownValues() {
        val valid = loadVectors().filter { it.result == "valid" }
        assertEquals(256, valid.size)
        for (vector in valid) {
            val key = hex(vector.key)
            val nonce = hex(vector.iv)
            val aad = hex(vector.aad)
            val message = hex(vector.msg)
            val ciphertext = hex(vector.ct)
            val tag = hex(vector.tag)
            assertEquals("tcId ${vector.tcId}", 16, tag.size)
            val expected = ciphertext + tag
            val sealed = ChaCha20Poly1305.seal(key, nonce, message, aad)
            assertNotNull("tcId ${vector.tcId} (${vector.comment}) returned null", sealed)
            assertArrayEquals(
                "tcId ${vector.tcId} (${vector.comment})",
                expected,
                sealed,
            )
            val opened = ChaCha20Poly1305.open(key, nonce, sealed!!, aad)
            assertArrayEquals(
                "tcId ${vector.tcId} (${vector.comment})",
                message,
                opened,
            )
        }
    }

    @Test
    fun invalidVectorsAreRejected() {
        val invalid = loadVectors().filter { it.result == "invalid" }
        assertEquals(69, invalid.size)
        for (vector in invalid) {
            val key = hex(vector.key)
            val nonce = hex(vector.iv)
            val aad = hex(vector.aad)
            val sealed = hex(vector.ct) + hex(vector.tag)
            assertNull(
                "tcId ${vector.tcId} (${vector.comment}) must be rejected",
                ChaCha20Poly1305.open(key, nonce, sealed, aad),
            )
            if (vector.ivSize != 96) {
                assertNull(
                    "tcId ${vector.tcId} seal must reject a ${vector.ivSize}-bit nonce",
                    ChaCha20Poly1305.seal(key, nonce, hex(vector.msg), aad),
                )
            }
        }
    }

    @Test
    fun platformProviderAgreesOnEveryValidVector() {
        var compared = 0
        for (vector in loadVectors().filter { it.result == "valid" }) {
            val key = hex(vector.key)
            val nonce = hex(vector.iv)
            val aad = hex(vector.aad)
            val message = hex(vector.msg)
            val sealed = platformSeal(key, nonce, message, aad)
            assertNotNull("JDK rejected valid tcId ${vector.tcId}", sealed)
            assertArrayEquals(
                "tcId ${vector.tcId} (${vector.comment})",
                hex(vector.ct) + hex(vector.tag),
                sealed,
            )
            val opened = platformOpen(key, nonce, sealed!!, aad)
            assertArrayEquals(
                "tcId ${vector.tcId} (${vector.comment})",
                message,
                opened,
            )
            compared += 1
        }
        assertEquals(256, compared)
    }

    @Test
    fun platformProviderAlsoRejectsEveryInvalidVector() {
        var checked = 0
        for (vector in loadVectors().filter { it.result == "invalid" }) {
            val sealed = hex(vector.ct) + hex(vector.tag)
            assertNull(
                "JDK accepted invalid tcId ${vector.tcId}",
                platformOpen(hex(vector.key), hex(vector.iv), sealed, hex(vector.aad)),
            )
            checked += 1
        }
        assertEquals(69, checked)
    }

    @Test
    fun tamperedTagCiphertextAndAadAreRejected() {
        val vectors = loadVectors().filter {
            it.result == "valid" && it.ivSize == 96 && hex(it.ct).isNotEmpty()
        }
        assertTrue(vectors.size >= 16)
        for (vector in vectors.take(16)) {
            val key = hex(vector.key)
            val nonce = hex(vector.iv)
            val aad = hex(vector.aad)
            val message = hex(vector.msg)
            val sealed = ChaCha20Poly1305.seal(key, nonce, message, aad)!!
            val tagStart = sealed.size - 16
            for (index in 0 until 16) {
                val tampered = sealed.copyOf()
                tampered[tagStart + index] =
                    (tampered[tagStart + index].toInt() xor 1).toByte()
                assertNull(
                    "tcId ${vector.tcId} accepted a tag bit flip at $index",
                    ChaCha20Poly1305.open(key, nonce, tampered, aad),
                )
            }
            val ciphertextTamper = sealed.copyOf()
            ciphertextTamper[0] = (ciphertextTamper[0].toInt() xor 1).toByte()
            assertNull(
                "tcId ${vector.tcId} accepted a ciphertext bit flip",
                ChaCha20Poly1305.open(key, nonce, ciphertextTamper, aad),
            )
            val aadTamper = aad.copyOf()
            if (aadTamper.isEmpty()) {
                assertNull(
                    "tcId ${vector.tcId} accepted a different AAD",
                    ChaCha20Poly1305.open(key, nonce, sealed, byteArrayOf(1)),
                )
            } else {
                aadTamper[0] = (aadTamper[0].toInt() xor 1).toByte()
                assertNull(
                    "tcId ${vector.tcId} accepted an AAD bit flip",
                    ChaCha20Poly1305.open(key, nonce, sealed, aadTamper),
                )
            }
            assertNull(
                "tcId ${vector.tcId} accepted a truncated tag",
                ChaCha20Poly1305.open(key, nonce, sealed.copyOf(sealed.size - 1), aad),
            )
            val wrongNonce = nonce.copyOf()
            wrongNonce[0] = (wrongNonce[0].toInt() xor 1).toByte()
            assertNull(
                "tcId ${vector.tcId} accepted a different nonce",
                ChaCha20Poly1305.open(key, wrongNonce, sealed, aad),
            )
            val wrongKey = key.copyOf()
            wrongKey[0] = (wrongKey[0].toInt() xor 1).toByte()
            assertNull(
                "tcId ${vector.tcId} accepted a different key",
                ChaCha20Poly1305.open(wrongKey, nonce, sealed, aad),
            )
        }
    }

    @Test
    fun wrongKeyNonceAndSealedSizesReturnNull() {
        val key = ByteArray(32) { 0x5A }
        val nonce = ByteArray(12) { 0x44 }
        val message = "a short pairing message".toByteArray(Charsets.US_ASCII)
        val sealed = ChaCha20Poly1305.seal(key, nonce, message, ByteArray(0))!!
        assertNull(ChaCha20Poly1305.seal(ByteArray(31), nonce, message, ByteArray(0)))
        assertNull(ChaCha20Poly1305.seal(key, ByteArray(11), message, ByteArray(0)))
        assertNull(ChaCha20Poly1305.seal(key, ByteArray(13), message, ByteArray(0)))
        assertNull(ChaCha20Poly1305.open(ByteArray(31), nonce, sealed, ByteArray(0)))
        assertNull(ChaCha20Poly1305.open(key, ByteArray(11), sealed, ByteArray(0)))
        assertNull(ChaCha20Poly1305.open(key, nonce, ByteArray(15), ByteArray(0)))
        assertNull(ChaCha20Poly1305.open(key, nonce, ByteArray(0), ByteArray(0)))
        assertArrayEquals(
            message,
            ChaCha20Poly1305.open(key, nonce, sealed, ByteArray(0))!!,
        )
    }

    private fun platformSeal(
        key: ByteArray,
        nonce: ByteArray,
        message: ByteArray,
        aad: ByteArray,
    ): ByteArray? {
        return try {
            val cipher = Cipher.getInstance("ChaCha20-Poly1305")
            cipher.init(
                Cipher.ENCRYPT_MODE,
                SecretKeySpec(key, "ChaCha20"),
                IvParameterSpec(nonce),
            )
            cipher.updateAAD(aad)
            cipher.doFinal(message)
        } catch (error: GeneralSecurityException) {
            null
        }
    }

    private fun platformOpen(
        key: ByteArray,
        nonce: ByteArray,
        sealed: ByteArray,
        aad: ByteArray,
    ): ByteArray? {
        return try {
            val cipher = Cipher.getInstance("ChaCha20-Poly1305")
            cipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(key, "ChaCha20"),
                IvParameterSpec(nonce),
            )
            cipher.updateAAD(aad)
            cipher.doFinal(sealed)
        } catch (error: GeneralSecurityException) {
            null
        }
    }

    private companion object {
        const val RESOURCE = "/crypto_vectors/wycheproof_chacha20_poly1305_v1.tsv"
    }
}
