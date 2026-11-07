package com.hotspotshade.source

import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Deterministic tests for the hotspot loss decision.
 *
 * A hit resets the miss count. A known-unsafe probe reports at once. An
 * uncertain probe reports only at the exact configured miss count. The policy
 * latches after one report.
 */
class HotspotWatchPolicyTest {
    private val expected = InetAddress.getByName("192.168.43.1")
    private val other = InetAddress.getByName("192.168.42.129")

    private fun hit(address: InetAddress = expected) = HotspotProbe.Observed(
        candidates = listOf(HotspotCandidate(rank = 0, address = address)),
        excludedAddresses = emptySet(),
    )

    private fun uncertain() = HotspotProbe.Observed(
        candidates = emptyList(),
        excludedAddresses = emptySet(),
    )

    private fun unsafe(address: InetAddress) = HotspotProbe.Observed(
        candidates = emptyList(),
        excludedAddresses = setOf(address),
    )

    private fun newPolicy(
        missingChecksBeforeLoss: Int = 3,
        pendingChecksBeforeUncertain: Int =
            HotspotWatchPolicy.DEFAULT_PENDING_CHECKS_BEFORE_UNCERTAIN,
    ) = HotspotWatchPolicy(
        expected,
        missingChecksBeforeLoss,
        pendingChecksBeforeUncertain,
    )

    @Test
    fun classifiesTheBoundCandidateAsValid() {
        assertEquals(
            HotspotProbeVerdict.VALID,
            newPolicy().classify(hit()),
        )
    }

    @Test
    fun classifiesAnExcludedBoundAddressAsKnownUnsafe() {
        assertEquals(
            HotspotProbeVerdict.KNOWN_UNSAFE,
            newPolicy().classify(unsafe(expected)),
        )
    }

    @Test
    fun classifiesAMissingCandidateAsUncertain() {
        assertEquals(
            HotspotProbeVerdict.UNCERTAIN,
            newPolicy().classify(uncertain()),
        )
        assertEquals(
            HotspotProbeVerdict.UNCERTAIN,
            newPolicy().classify(hit(other)),
        )
    }

    @Test
    fun classifiesAnUnknownReadAsUncertain() {
        assertEquals(
            HotspotProbeVerdict.UNCERTAIN,
            newPolicy().classify(HotspotProbe.Unknown),
        )
    }

    @Test
    fun classifiesAPendingFirstReadingAsPending() {
        assertEquals(
            HotspotProbeVerdict.PENDING,
            newPolicy().classify(HotspotProbe.Pending),
        )
    }

    @Test
    fun aPendingProbeNeitherClearsNorAdvancesTheMissCount() {
        val policy = newPolicy(missingChecksBeforeLoss = 2)

        assertFalse(policy.onProbe(uncertain()))
        assertFalse(policy.onProbe(HotspotProbe.Pending))
        assertFalse(policy.onProbe(HotspotProbe.Pending))
        assertTrue("The two misses must still add up.", policy.onProbe(uncertain()))
    }

    @Test
    fun pendingProbesWithinTheBoundNeverReportALoss() {
        val policy = newPolicy(
            missingChecksBeforeLoss = 1,
            pendingChecksBeforeUncertain = 4,
        )

        repeat(3) {
            assertFalse(policy.onProbe(HotspotProbe.Pending))
        }
    }

    @Test
    fun aSustainedPendingReadingCountsAsUncertainAfterTheBound() {
        val policy = newPolicy(
            missingChecksBeforeLoss = 1,
            pendingChecksBeforeUncertain = 4,
        )

        repeat(3) {
            assertFalse(policy.onProbe(HotspotProbe.Pending))
        }
        assertTrue(
            "The fourth pending probe must count as uncertain.",
            policy.onProbe(HotspotProbe.Pending),
        )
    }

    @Test
    fun aHitClearsThePendingCount() {
        val policy = newPolicy(
            missingChecksBeforeLoss = 1,
            pendingChecksBeforeUncertain = 3,
        )

        assertFalse(policy.onProbe(HotspotProbe.Pending))
        assertFalse(policy.onProbe(HotspotProbe.Pending))
        assertFalse(policy.onProbe(hit()))
        assertFalse(policy.onProbe(HotspotProbe.Pending))
        assertFalse(policy.onProbe(HotspotProbe.Pending))
        assertTrue(policy.onProbe(HotspotProbe.Pending))
    }

    @Test
    fun anUncertainProbeClearsThePendingCount() {
        val policy = newPolicy(
            missingChecksBeforeLoss = 3,
            pendingChecksBeforeUncertain = 2,
        )

        assertFalse(policy.onProbe(HotspotProbe.Pending))
        assertFalse(policy.onProbe(uncertain()))
        assertFalse(policy.onProbe(HotspotProbe.Pending))
        assertFalse(policy.onProbe(uncertain()))
        assertTrue(policy.onProbe(uncertain()))
    }

    @Test
    fun aHitClearsTheMissCount() {
        val policy = newPolicy(missingChecksBeforeLoss = 2)

        assertFalse(policy.onProbe(uncertain()))
        assertFalse(policy.onProbe(hit()))
        assertFalse("The hit must clear the earlier miss.", policy.onProbe(uncertain()))
        assertTrue(policy.onProbe(uncertain()))
    }

    @Test
    fun exactlyTheConfiguredMissCountReportsOneLoss() {
        val policy = newPolicy(missingChecksBeforeLoss = 3)

        assertFalse(policy.onProbe(uncertain()))
        assertFalse(policy.onProbe(uncertain()))
        assertTrue(policy.onProbe(uncertain()))
        assertFalse("The policy must report at most one loss.", policy.onProbe(uncertain()))
        assertFalse(policy.onProbe(hit()))
    }

    @Test
    fun anUnsafeProbeReportsAtOnce() {
        val policy = newPolicy(missingChecksBeforeLoss = 10)

        assertTrue(policy.onProbe(unsafe(expected)))
        assertFalse("The policy must report at most one loss.", policy.onProbe(unsafe(expected)))
    }

    @Test
    fun aHitAfterTheLatchDoesNotReportAgain() {
        val policy = newPolicy(missingChecksBeforeLoss = 1)

        assertTrue(policy.onProbe(uncertain()))
        assertFalse(policy.onProbe(hit()))
        assertFalse(policy.onProbe(unsafe(expected)))
    }

    @Test
    fun anUnsafeProbeForAnotherAddressIsUncertain() {
        val policy = newPolicy(missingChecksBeforeLoss = 2)

        assertFalse(policy.onProbe(unsafe(other)))
        assertTrue(policy.onProbe(unsafe(other)))
    }

    @Test
    fun anUnknownProbeIsUncertain() {
        val policy = newPolicy(missingChecksBeforeLoss = 2)

        assertFalse(policy.onProbe(HotspotProbe.Unknown))
        assertTrue(policy.onProbe(HotspotProbe.Unknown))
    }

    @Test
    fun aDifferentConfirmedAddressIsAMiss() {
        val policy = newPolicy(missingChecksBeforeLoss = 2)

        assertFalse(policy.onProbe(hit(other)))
        assertTrue(policy.onProbe(hit(other)))
    }

    @Test
    fun aBoundCandidateBesideABetterCandidateIsAHit() {
        val policy = newPolicy(missingChecksBeforeLoss = 2)
        val besideABetterCandidate = HotspotProbe.Observed(
            candidates = listOf(
                HotspotCandidate(rank = 0, address = other),
                HotspotCandidate(rank = 3, address = expected),
            ),
            excludedAddresses = emptySet(),
        )

        assertFalse(policy.onProbe(besideABetterCandidate))
        assertFalse(policy.onProbe(uncertain()))
        assertTrue("The candidate must have cleared the miss count.", policy.onProbe(uncertain()))
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsAZeroMissCount() {
        HotspotWatchPolicy(expected, 0)
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsANegativeMissCount() {
        HotspotWatchPolicy(expected, -1)
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsAZeroPendingCount() {
        HotspotWatchPolicy(expected, 1, 0)
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsANegativePendingCount() {
        HotspotWatchPolicy(expected, 1, -1)
    }
}
