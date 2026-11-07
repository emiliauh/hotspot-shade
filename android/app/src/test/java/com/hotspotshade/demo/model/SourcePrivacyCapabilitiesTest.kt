package com.hotspotshade.demo.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Hermetic tests for the truthful source device capability report.
 *
 * The report is a pure function of a platform level number. These tests open no
 * socket, read no interface, use no token, and need no device. They hold the
 * product wording that `docs/SNI_HIDING_PLAN.md` requires: hide is proposed and
 * unavailable, an API level is not usable ECH support, the relay conceals no
 * name, and the report claims no running proxy or tunnel state.
 */
class SourcePrivacyCapabilitiesTest {
    private val api36 = SourcePrivacyCapabilities.report(36)
    private val api37 = SourcePrivacyCapabilities.report(37)

    @Test
    fun offIsTheOnlyModeAndIsTheBuildDefault() {
        assertEquals(PrivacyMode.OFF, api36.defaultMode)
        assertEquals("Off", api36.defaultModeText)

        val off = api36.row(PrivacyMode.OFF)
        assertEquals(PrivacyAvailability.DEFAULT, off.availability)
        assertTrue(off.availableInBuild)
        assertTrue(off.stateText.startsWith("Default"))
        assertTrue(off.detail.contains("hides no destination name"))
    }

    @Test
    fun onlyOneAvailabilityValueIsAvailableInThisBuild() {
        val available = PrivacyAvailability.entries.filter { it.availableInBuild }

        assertEquals(listOf(PrivacyAvailability.DEFAULT), available)
        for (value in PrivacyAvailability.entries) {
            assertFalse(value.name, value.valueText.isBlank())
            assertFalse(value.name, value.valueText.contains("In force"))
            assertFalse(value.name, value.valueText.contains("runs now"))
        }
    }

    @Test
    fun everyOtherModeIsUnavailableAndOffersNoSwitch() {
        assertEquals(PrivacyMode.all.size, api36.modes.size)
        val others = api36.modes.filter { it.mode != PrivacyMode.OFF }

        assertEquals(4, others.size)
        assertEquals(4, api36.unavailableModes.size)
        for (row in others) {
            assertFalse(row.mode.name, row.availableInBuild)
            assertTrue(row.mode.name, row.detail.isNotBlank())
            assertTrue(
                row.mode.name,
                row.stateText.startsWith("Unavailable") ||
                    row.stateText.startsWith("Excluded"),
            )
        }
        for (row in api36.modes) {
            if (row.mode == PrivacyMode.OFF) {
                assertTrue(row.availableInBuild)
                assertEquals(PrivacyAvailability.DEFAULT, row.availability)
            } else {
                assertFalse(row.availableInBuild)
                assertNotEquals(PrivacyAvailability.DEFAULT, row.availability)
            }
        }
    }

    @Test
    fun reportClaimsNoRunningState() {
        for (report in listOf(api36, api37)) {
            assertEquals("Off", report.defaultModeText)

            for (text in report.allTexts()) {
                assertFalse(text, text.contains("In force"))
                assertFalse(text, text.contains("runs now"))
                assertFalse(text, text.contains("is running"))
                assertFalse(text, text.contains("only mode this build runs"))
            }

            val defaultRow = report.row(PrivacyMode.OFF)
            assertTrue(defaultRow.stateText.startsWith("Default"))
            assertTrue(defaultRow.stateText.contains("not a running state"))
            assertTrue(defaultRow.stateText.contains("reports no proxy or tunnel state"))
            assertTrue(report.storageNote.contains("reports no proxy or tunnel state"))
        }
    }

    @Test
    fun shapeIsProposedAndDoesNotClaimHiding() {
        val shape = api36.row(PrivacyMode.SHAPE)

        assertEquals(PrivacyAvailability.PROPOSED, shape.availability)
        assertEquals("Unavailable. Proposed, not built.", shape.stateText)
        assertTrue(shape.detail.contains("copies every byte"))
        assertTrue(shape.detail.contains("cannot re-cut"))
        assertTrue(shape.detail.contains("would not hide the server name"))
        assertTrue(shape.detail.contains("cannot pad the handshake"))
    }

    @Test
    fun hideIsProposedAndIsNotAnEngineFeature() {
        val hide = api36.row(PrivacyMode.HIDE)

        assertEquals(PrivacyAvailability.PROPOSED, hide.availability)
        assertEquals("Unavailable. Proposed, not built.", hide.stateText)
        assertFalse(hide.availableInBuild)
        assertTrue(hide.detail.contains("TLS client that the product owns"))
        assertTrue(hide.detail.contains("No client boundary is settled"))
        assertTrue(hide.detail.contains("no code exists in this build"))
        assertFalse(hide.detail.contains("target device engine"))
        assertFalse(hide.detail.contains("belongs in"))
        assertFalse(hide.detail.contains("runs in"))
    }

    @Test
    fun noRowAdvertisesAnEngineFeature() {
        for (report in listOf(api36, api37)) {
            for (row in report.modes) {
                assertFalse(row.mode.name, row.detail.contains("in the target engine"))
                assertFalse(row.mode.name, row.detail.contains("available on this"))
                assertFalse(row.mode.name, row.stateText.contains("is on"))
                assertFalse(row.mode.name, row.stateText.contains("On."))
            }
        }
    }

    @Test
    fun coverIsDeferredAndNeedsAnOwnedEndpoint() {
        val cover = api36.row(PrivacyMode.COVER)

        assertEquals(PrivacyAvailability.DEFERRED, cover.availability)
        assertEquals("Unavailable. Deferred. No endpoint is configured.", cover.stateText)
        assertTrue(cover.detail.contains("endpoint that you own"))
        assertTrue(cover.detail.contains("no external relay or VPS"))
        assertTrue(cover.detail.contains("no switch"))
        assertTrue(cover.detail.contains("out of scope"))
    }

    @Test
    fun terminateIsOutOfScope() {
        val terminate = api36.row(PrivacyMode.TERMINATE)

        assertEquals(PrivacyAvailability.OUT_OF_SCOPE, terminate.availability)
        assertEquals("Excluded. Out of scope for this project.", terminate.stateText)
        assertTrue(terminate.detail.contains("certificate pinning"))
        assertTrue(terminate.detail.contains("second TLS session"))
        assertTrue(terminate.detail.contains("does not build"))
    }

    @Test
    fun platformEchReportsApiPresenceOnly() {
        val absent = api36.fact(CapabilityFact.ECH_PLATFORM)
        assertEquals("No API surface on this Android version", absent.valueText)
        assertTrue(absent.detail.contains("API 37"))
        assertTrue(absent.detail.contains("version number only"))

        val present = api37.fact(CapabilityFact.ECH_PLATFORM)
        assertEquals("Reported API surface, unverified", present.valueText)
        assertTrue(present.detail.contains("not proof"))
        assertTrue(present.detail.contains("does not use ECH"))
        assertTrue(present.detail.contains("API 36"))
    }

    @Test
    fun apiPresenceIsNotUsableSupport() {
        val present = api37.fact(CapabilityFact.ECH_PLATFORM)
        val text = present.valueText + " " + present.detail

        assertTrue(present.valueText.contains("unverified"))
        assertFalse(text.contains("supported", ignoreCase = true))
        assertFalse(text.contains("in use", ignoreCase = true))
        assertFalse(text.contains("works", ignoreCase = true))
        assertFalse(present.valueText.startsWith("Yes"))
    }

    @Test
    fun relayNeverClaimsEchOnAnyPlatform() {
        for (report in listOf(api36, api37)) {
            val relay = report.fact(CapabilityFact.ECH_RELAY)
            assertEquals("Never used", relay.valueText)
            assertTrue(relay.detail.contains("opens no TLS session"))
            assertTrue(relay.detail.contains("conceals no name"))
        }
    }

    @Test
    fun sniControlIsNotClaimedInTheRelay() {
        val sni = api36.fact(CapabilityFact.SNI_CONTROL)

        assertEquals("Not available in the relay", sni.valueText)
        assertTrue(sni.detail.contains("cannot change the ClientHello"))
        assertTrue(sni.detail.contains("opens none"))
    }

    @Test
    fun backgroundRelayIsForegroundOnlyAndNotGuaranteed() {
        val background = api36.fact(CapabilityFact.BACKGROUND_RELAY)

        assertEquals("Foreground service, not guaranteed", background.valueText)
        assertTrue(background.detail.contains("Android can still stop it"))
        assertTrue(background.detail.contains("does not restart it by itself"))
        assertTrue(background.detail.contains("No background operation is promised"))
        assertFalse(background.detail.contains("always"))
        assertFalse(background.valueText.startsWith("Yes"))
    }

    @Test
    fun reportIsReadOnlyAndDoesNotChangeTheProxy() {
        assertTrue(api36.storageNote.contains("report, not a control"))
        assertTrue(api36.storageNote.contains("saves no mode"))
        assertTrue(api36.storageNote.contains("does not change the proxy"))
    }

    @Test
    fun introSaysTheRelayConcealsNothingAndAnAppMayConcealItself() {
        assertTrue(api36.intro.contains("conceals no destination name"))
        assertTrue(api36.intro.contains("can still be visible"))
        assertTrue(api36.intro.contains("unless an application hides it"))
        assertTrue(api36.intro.contains("encrypted DNS"))
        assertFalse(api36.intro.contains("carrier still sees the destination name"))
        assertFalse(api36.intro.contains("is on"))
    }

    @Test
    fun limitsSayWhatOffDoesNotHide() {
        val limits = api36.limits.joinToString(" ")

        assertTrue(limits.contains("Off hides nothing in the relay"))
        assertTrue(limits.contains("TLS server name"))
        assertTrue(limits.contains("DNS names"))
        assertTrue(limits.contains("TLS fingerprint"))
        assertTrue(limits.contains("flow size and timing"))
        assertTrue(limits.contains("operating-system fingerprint"))
        assertTrue(limits.contains("not of a mode"))
    }

    @Test
    fun limitsKeepApplicationSuppliedConcealmentSeparate() {
        val limits = api36.limits.joinToString(" ")

        assertTrue(limits.contains("application can use its own ECH or encrypted DNS"))
        assertTrue(limits.contains("outside this relay"))
        assertTrue(limits.contains("not a mode of this app"))
    }

    @Test
    fun reportHoldsNoNameAddressOrToken() {
        val texts = api36.allTexts() + api37.allTexts()
        assertTrue(texts.isNotEmpty())

        for (text in texts) {
            assertFalse(text, IPV4.containsMatchIn(text))
            assertFalse(text, text.contains("://"))
            assertFalse(text, text.contains("@"))
            assertFalse(text, text.contains("token", ignoreCase = true))
            assertFalse(text, text.contains("bearer", ignoreCase = true))
            assertFalse(text, text.contains("cloudflare", ignoreCase = true))
            assertFalse(text, text.contains("echconfig", ignoreCase = true))
            assertFalse(text, text.contains("localhost", ignoreCase = true))
        }
    }

    @Test
    fun reportTextIsPlainAscii() {
        for (text in api36.allTexts()) {
            for (character in text) {
                assertTrue(
                    "Unexpected character in: $text",
                    character.code in 0x20..0x7e || character == '\n',
                )
            }
        }
    }

    @Test
    fun reportToStringIsFixedAndCountsOnly() {
        assertEquals(
            "SourcePrivacyReport(default_mode=off, modes=5, facts=4)",
            api36.toString(),
        )
        assertFalse(api36.toString().contains("In force"))
        assertFalse(api36.toString().contains("Unavailable"))
    }

    @Test
    fun reportBuildsTheSameFactsOnEveryPlatform() {
        assertEquals(4, api36.facts.size)
        assertEquals(api36.facts.map { it.fact }, api37.facts.map { it.fact })
        assertEquals(
            api36.facts.filter { it.fact != CapabilityFact.ECH_PLATFORM },
            api37.facts.filter { it.fact != CapabilityFact.ECH_PLATFORM },
        )
    }

    private fun SourcePrivacyReport.row(mode: PrivacyMode): PrivacyModeRow =
        modes.first { it.mode == mode }

    private fun SourcePrivacyReport.fact(fact: CapabilityFact): CapabilityFactRow =
        facts.first { it.fact == fact }

    private fun SourcePrivacyReport.allTexts(): List<String> =
        listOf(intro, storageNote) +
            limits +
            modes.flatMap { listOf(it.title, it.stateText, it.detail) } +
            facts.flatMap { listOf(it.title, it.valueText, it.detail) }

    private companion object {
        val IPV4 = Regex("""\d{1,3}(\.\d{1,3}){3}""")
    }
}
