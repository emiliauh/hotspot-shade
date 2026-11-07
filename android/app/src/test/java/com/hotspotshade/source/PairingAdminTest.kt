package com.hotspotshade.source

import com.hotspotshade.source.pairing.MemoryPairingTrustStore
import com.hotspotshade.source.pairing.PairingProtocol
import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PairingAdminTest {
    private val firstKey = ByteArray(32) { 0x11 }
    private val secondKey = ByteArray(32) { 0x22 }

    @Test
    fun confirmationTextDescribesOnlyLocalConfirmation() {
        assertEquals("Confirmed in this app session", targetConfirmationMessage(TargetConfirmation.CONFIRMED))
        assertEquals("Confirmation required when pairing", targetConfirmationMessage(TargetConfirmation.REQUIRED))
        assertEquals("Confirmation status unknown", targetConfirmationMessage(TargetConfirmation.UNKNOWN))
        assertEquals(TargetConfirmation.UNKNOWN, TrustedTarget("id", "label").confirmation)
    }

    @Test
    fun targetsShowShortLabelsThatHideTheKey() {
        val trust = MemoryPairingTrustStore()
        trust.add(firstKey)
        trust.add(secondKey)

        val targets = trust.targets()

        assertEquals(2, targets.size)
        assertEquals(2, targets.map { it.label }.toSet().size)
        for (target in targets) {
            assertTrue(target.label.startsWith("Target device "))
            assertEquals("Target device ".length + 8, target.label.length)
            assertFalse(target.label.contains(PairingProtocol.hex(firstKey)))
            assertFalse(target.label.contains(PairingProtocol.hex(secondKey)))
            assertFalse(target.toString().contains(target.id))
        }
    }

    @Test
    fun forgetRemovesOneTarget() {
        val trust = MemoryPairingTrustStore()
        trust.add(firstKey)
        trust.add(secondKey)
        val first = trust.targets().first()
        val forgotten = if (first.id == PairingProtocol.hex(firstKey)) firstKey else secondKey
        val remaining = if (first.id == PairingProtocol.hex(firstKey)) secondKey else firstKey

        assertTrue(trust.forget(first.id))
        assertEquals(1, trust.count)
        assertFalse(trust.contains(forgotten))
        assertTrue(trust.contains(remaining))
        assertFalse(trust.forget(first.id))
    }

    @Test
    fun forgetAllRemovesEveryTarget() {
        val trust = MemoryPairingTrustStore()
        trust.add(firstKey)
        trust.add(secondKey)

        trust.forgetAll()

        assertEquals(0, trust.count)
        assertTrue(trust.targets().isEmpty())
    }

    @Test
    fun fingerprintIsStableAndShort() {
        val encoded = base64(firstKey)

        assertEquals(TrustFingerprint.label(encoded), TrustFingerprint.label(encoded))
        assertNotEquals(
            TrustFingerprint.label(encoded),
            TrustFingerprint.label(base64(secondKey)),
        )
        assertFalse(TrustFingerprint.label(encoded).contains(encoded))
    }

    @Test
    fun tokenRotationWritesOneNewToken() {
        val written = mutableListOf<String>()
        val admin = PairingAdmin(
            trust = MemoryPairingTrustStore(),
            tokenStore = TokenWriter { written += it },
            tokenFactory = { "new-token-value" },
            isProxyActive = { false },
        )

        assertEquals(TokenRotateResult.ROTATED, admin.rotateToken())
        assertEquals(listOf("new-token-value"), written)
    }

    @Test
    fun tokenRotationIsRefusedWhileTheProxyRuns() {
        val written = mutableListOf<String>()
        val admin = PairingAdmin(
            trust = MemoryPairingTrustStore(),
            tokenStore = TokenWriter { written += it },
            tokenFactory = { "new-token-value" },
            isProxyActive = { true },
        )

        assertEquals(TokenRotateResult.REFUSED_RUNNING, admin.rotateToken())
        assertTrue(written.isEmpty())
    }

    @Test
    fun tokenRotationReportsAFailedWrite() {
        val admin = PairingAdmin(
            trust = MemoryPairingTrustStore(),
            tokenStore = TokenWriter { throw IllegalStateException("The store is locked.") },
            tokenFactory = { "new-token-value" },
            isProxyActive = { false },
        )

        assertEquals(TokenRotateResult.FAILED, admin.rotateToken())
    }

    @Test
    fun newTokenIs32BytesOfHexAndChanges() {
        val first = TokenRotation.newToken()
        val second = TokenRotation.newToken()

        assertEquals(64, first.length)
        assertTrue(first.all { it in "0123456789abcdef" })
        assertNotEquals(first, second)
    }

    @Test
    fun trustActionsReportAFailedStore() {
        val failing = object : PairingTrustAdmin {
            override fun targets(): List<TrustedTarget> =
                throw IllegalStateException("The trust list cannot be read.")

            override fun forget(id: String): Boolean =
                throw IllegalStateException("The trust list cannot be read.")

            override fun forgetAll() {
                throw IllegalStateException("The trust list cannot be written.")
            }
        }
        val admin = PairingAdmin(
            trust = failing,
            tokenStore = TokenWriter { },
            tokenFactory = { "new-token-value" },
            isProxyActive = { false },
        )

        assertFalse(admin.forget("target"))
        assertFalse(admin.forgetAll())
    }

    private fun base64(key: ByteArray): String = Base64.getEncoder().encodeToString(key)
}
