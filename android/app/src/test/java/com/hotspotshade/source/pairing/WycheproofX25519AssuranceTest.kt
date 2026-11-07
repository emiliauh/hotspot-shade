package com.hotspotshade.source.pairing

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.security.KeyFactory
import java.security.spec.NamedParameterSpec
import java.security.spec.XECPrivateKeySpec
import java.security.spec.XECPublicKeySpec
import javax.crypto.KeyAgreement

/**
 * Project Wycheproof X25519 vectors for the Kotlin port in `X25519.kt`.
 *
 * The fixture is a lossless TSV conversion of the complete test case set in
 * `testvectors_v1/x25519_test.json` at the pinned commit. Its header holds the
 * source, version, and license. The values are public test data, not secrets.
 *
 * The Android app rejects a low-order public key by returning null when the
 * shared secret is all zero. Wycheproof marks those cases "acceptable" for
 * both outcomes, so null is a valid result. Every other case must match the
 * shared secret in the vector.
 *
 * JDK 17 has an X25519 KeyAgreement, so the test compares the Kotlin result
 * with the platform provider for the 264 "valid" vectors. The provider is not
 * used as an oracle for the 254 "acceptable" cases: for tcId 91 the tested
 * JDK 17 provider returned a different value for a non-canonical public key
 * than the vector, and providers differ on twist and low-order points.
 */
class WycheproofX25519AssuranceTest {
    private class Vector(
        val tcId: Int,
        val result: String,
        val flags: String,
        val privateKey: String,
        val publicKey: String,
        val shared: String,
        val comment: String,
    )

    private fun hex(value: String): ByteArray = PairingProtocol.unhex(value)

    private fun loadVectors(): List<Vector> {
        val stream = javaClass.getResourceAsStream(RESOURCE)
            ?: error("The X25519 vector fixture is missing: $RESOURCE")
        val vectors = mutableListOf<Vector>()
        stream.bufferedReader(Charsets.UTF_8).useLines { lines ->
            for (line in lines) {
                if (line.isBlank() || line.startsWith("#")) continue
                val parts = line.split('\t')
                check(parts.size == 7) { "A vector row has ${parts.size} fields." }
                vectors.add(
                    Vector(
                        tcId = parts[0].toInt(),
                        result = parts[1],
                        flags = parts[2],
                        privateKey = parts[3],
                        publicKey = parts[4],
                        shared = parts[5],
                        comment = parts[6],
                    ),
                )
            }
        }
        return vectors
    }

    @Test
    fun fixtureHoldsTheCompletePinnedVectorSet() {
        val vectors = loadVectors()
        assertEquals(518, vectors.size)
        assertEquals(518, vectors.map { it.tcId }.toSet().size)
        assertEquals(264, vectors.count { it.result == "valid" })
        assertEquals(254, vectors.count { it.result == "acceptable" })
        assertEquals(31, vectors.count { it.flags.contains("ZeroSharedSecret") })
        assertEquals(31, vectors.count { it.flags.contains("LowOrderPublic") })
        assertEquals(19, vectors.count { it.flags.contains("NonCanonicalPublic") })
        assertEquals(7, vectors.count { it.flags.contains("EdgeCasePrivateKey") })
        assertEquals(14, vectors.count { it.flags.contains("EdgeCaseShared") })
        for (vector in vectors) {
            assertEquals("tcId ${vector.tcId}", 32, hex(vector.privateKey).size)
            assertEquals("tcId ${vector.tcId}", 32, hex(vector.publicKey).size)
            assertEquals("tcId ${vector.tcId}", 32, hex(vector.shared).size)
        }
    }

    @Test
    fun acceptedVectorsMatchTheSpecifiedSharedSecret() {
        val accepted = loadVectors().filter { !it.flags.contains("ZeroSharedSecret") }
        assertEquals(487, accepted.size)
        for (vector in accepted) {
            val actual = X25519.agree(hex(vector.privateKey), hex(vector.publicKey))
            assertNotNull("tcId ${vector.tcId} (${vector.comment}) returned null", actual)
            assertArrayEquals(
                "tcId ${vector.tcId} (${vector.comment})",
                hex(vector.shared),
                actual,
            )
        }
    }

    @Test
    fun lowOrderVectorsAreRejectedAsAllZero() {
        val lowOrder = loadVectors().filter { it.flags.contains("ZeroSharedSecret") }
        assertEquals(31, lowOrder.size)
        for (vector in lowOrder) {
            assertTrue(
                "tcId ${vector.tcId} does not carry an all-zero shared secret",
                hex(vector.shared).all { it == 0.toByte() },
            )
            assertNull(
                "tcId ${vector.tcId} (${vector.comment}) must be rejected",
                X25519.agree(hex(vector.privateKey), hex(vector.publicKey)),
            )
        }
    }

    @Test
    fun nonCanonicalPublicKeysMatchTheSpecifiedSharedSecret() {
        val nonCanonical = loadVectors()
            .filter { it.flags.contains("NonCanonicalPublic") && !it.flags.contains("ZeroSharedSecret") }
        assertEquals(13, nonCanonical.size)
        for (vector in nonCanonical) {
            val actual = X25519.agree(hex(vector.privateKey), hex(vector.publicKey))
            assertNotNull("tcId ${vector.tcId} (${vector.comment}) returned null", actual)
            assertArrayEquals(
                "tcId ${vector.tcId} (${vector.comment})",
                hex(vector.shared),
                actual,
            )
        }
    }

    @Test
    fun edgeCasePrivateAndSharedVectorsMatch() {
        val edgeCases = loadVectors().filter {
            it.flags.contains("EdgeCasePrivateKey") || it.flags.contains("EdgeCaseShared") ||
                it.flags.contains("SmallPublicKey")
        }
        assertEquals(29, edgeCases.size)
        for (vector in edgeCases) {
            val actual = X25519.agree(hex(vector.privateKey), hex(vector.publicKey))
            if (vector.flags.contains("ZeroSharedSecret")) {
                assertNull("tcId ${vector.tcId}", actual)
            } else {
                assertNotNull("tcId ${vector.tcId}", actual)
                assertArrayEquals("tcId ${vector.tcId}", hex(vector.shared), actual)
            }
        }
    }

    @Test
    fun platformProviderAgreesOnEveryValidVector() {
        var compared = 0
        for (vector in loadVectors().filter { it.result == "valid" }) {
            val jca = platformAgreement(hex(vector.privateKey), hex(vector.publicKey))
            assertNotNull("JDK rejected valid tcId ${vector.tcId}", jca)
            assertArrayEquals(
                "tcId ${vector.tcId} (${vector.comment})",
                hex(vector.shared),
                jca,
            )
            compared += 1
        }
        assertEquals(264, compared)
    }

    @Test
    fun wrongSizesReturnNull() {
        val privateKey = ByteArray(32) { 0x33 }
        val publicKey = X25519.publicKey(privateKey)!!
        assertNull(X25519.publicKey(ByteArray(31)))
        assertNull(X25519.publicKey(ByteArray(33)))
        assertNull(X25519.agree(ByteArray(31), publicKey))
        assertNull(X25519.agree(privateKey, ByteArray(31)))
        assertNull(X25519.agree(privateKey, ByteArray(33)))
        assertNotNull(X25519.agree(privateKey, publicKey))
    }

    /** Run the JDK provider, or return null when it rejects the input. */
    private fun platformAgreement(privateKey: ByteArray, publicKey: ByteArray): ByteArray? {
        return try {
            val factory = KeyFactory.getInstance("X25519")
            val private = factory.generatePrivate(
                XECPrivateKeySpec(NamedParameterSpec.X25519, privateKey),
            )
            val public = factory.generatePublic(
                XECPublicKeySpec(
                    NamedParameterSpec.X25519,
                    BigInteger(1, publicKey.reversedArray()),
                ),
            )
            val agreement = KeyAgreement.getInstance("X25519")
            agreement.init(private)
            agreement.doPhase(public, true)
            agreement.generateSecret()
        } catch (error: java.security.GeneralSecurityException) {
            null
        }
    }

    private companion object {
        const val RESOURCE = "/crypto_vectors/wycheproof_x25519_v1.tsv"
    }
}
