package com.hotspotshade.demo.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DemoModelTest {

    @Test
    fun pairingDisplayMatchesTheIosStates() {
        val idle = DemoState()
        assertEquals(PairingActivity.NOT_PAIRED, idle.pairingActivity)
        assertEquals(DemoState.NOT_PAIRED_TEXT, idle.usageSummary)

        val paired = idle.copy(trustedCount = 1)
        assertEquals(PairingActivity.PAIRED, paired.pairingActivity)
        assertEquals("Paired with 1 target device.", paired.usageSummary)
        assertEquals(DemoState.WAITING_TITLE, paired.usageTitle)

        val pairing = idle.copy(pairingCode = "482193", listenerReady = true)
        assertEquals(PairingActivity.PAIRING, pairing.pairingActivity)
        assertEquals(DemoState.PAIRING_TEXT, pairing.usageSummary)

        val stale = pairing.copy(listenerReady = false)
        assertEquals(PairingActivity.NOT_PAIRED, stale.pairingActivity)

        val inUse = paired.copy(
            authenticatedSessions = 1,
            lastTrafficAgeSeconds = DemoState.RECENT_TRAFFIC_SECONDS,
        )
        assertEquals(PairingActivity.IN_USE, inUse.pairingActivity)
        assertEquals(DemoState.IN_USE_TEXT, inUse.usageSummary)
        assertEquals(DemoState.CONNECTED_TITLE, inUse.usageTitle)

        val oldTraffic = paired.copy(authenticatedSessions = 1, lastTrafficAgeSeconds = 61)
        assertEquals(PairingActivity.PAIRED, oldTraffic.pairingActivity)
    }

    @Test
    fun dashboardStatusUsesPlainMessages() {
        val off = DemoState()
        assertEquals("Off", off.statusTitle)
        assertEquals(DemoState.OFF_MESSAGE, off.statusMessage)
        assertEquals(StatusKind.OFF, off.statusKind)

        val starting = off.copy(proxy = ProxyState.STARTING)
        assertEquals("Starting", starting.statusTitle)
        assertEquals(StatusKind.STARTING, starting.statusKind)

        val on = DemoState(proxy = ProxyState.ON, trustedCount = 1)
        assertEquals("On", on.statusTitle)
        assertEquals("Paired with 1 target device.", on.statusMessage)
        assertEquals(StatusKind.ON, on.statusKind)

        val pairing = on.copy(pairingCode = "482193")
        assertEquals(StatusKind.PAIRING, pairing.statusKind)

        val failed = on.copy(
            proxy = ProxyState.FAILED,
            startFailure = "The proxy could not start. Try again.",
        )
        assertEquals("Needs attention", failed.statusTitle)
        assertEquals("The proxy could not start. Try again.", failed.statusMessage)
        assertEquals(StatusKind.ATTENTION, failed.statusKind)
    }

    @Test
    fun startAndStopRecordPlainActivity() {
        val started = DemoEngine.requestStart(DemoState())
        assertEquals(ProxyState.STARTING, started.proxy)
        assertTrue(started.running)
        assertTrue(started.activity.isEmpty())

        val listening = DemoEngine.finishStart(started, nowMillis = 1_000)
        assertEquals(ProxyState.ON, listening.proxy)
        assertEquals("Proxy started.", listening.activity.single().message)
        assertEquals(1_000, listening.activity.single().timeMillis)

        val stopped = DemoEngine.stop(listening, nowMillis = 2_000)
        assertEquals(ProxyState.OFF, stopped.proxy)
        assertEquals(StopReason.USER, stopped.lastStop)
        assertEquals(2_000L, stopped.lastStopAtMillis)
        assertFalse(stopped.offerRestart)
        assertEquals(listOf("Proxy started.", "You stopped the proxy."), stopped.activity.map { it.message })
    }

    @Test
    fun repeatedFinishStartDoesNotDuplicateActivity() {
        val started = DemoEngine.requestStart(DemoState())
        val once = DemoEngine.finishStart(started, 1_000)
        val twice = DemoEngine.finishStart(once, 2_000)
        assertEquals(once, twice)
        assertEquals(1, twice.activity.size)
    }

    @Test
    fun invalidPortUsesThePlainFailureState() {
        val failed = DemoEngine.failStart(DemoState(port = "80"), DemoEngine.INVALID_PORT, 5_000)
        assertEquals(ProxyState.FAILED, failed.proxy)
        assertEquals(DemoEngine.INVALID_PORT, failed.startFailure)
        assertEquals("Needs attention", failed.statusTitle)
        assertEquals(StopReason.FAILED, failed.lastStop)
        assertEquals(DemoEngine.INVALID_PORT, failed.activity.single().message)
    }

    @Test
    fun pairingAllowAndDenyClearTheCode() {
        val request = DemoEngine.requestPairing(DemoState(), "482193")
        assertEquals(PairingActivity.PAIRING, request.pairingActivity)
        assertEquals("482 193", DemoEngine.formatPairingCode(request.pairingCode!!))
        assertEquals(ProxyState.ON, request.proxy)

        val allowed = DemoEngine.allowPairing(request, 3_000)
        assertNull(allowed.pairingCode)
        assertFalse(allowed.pairingInProgress)
        assertEquals(1, allowed.trustedCount)
        assertEquals(PairingActivity.IN_USE, allowed.pairingActivity)
        assertEquals("A target device was added.", allowed.activity.last().message)

        val denied = DemoEngine.denyPairing(
            DemoEngine.requestPairing(DemoState(), "111222"),
            4_000,
        )
        assertNull(denied.pairingCode)
        assertEquals(0, denied.trustedCount)
        assertEquals(PairingActivity.NOT_PAIRED, denied.pairingActivity)
        assertEquals("A pairing request was denied.", denied.activity.last().message)
    }

    @Test
    fun pairingInProgressHasNoPromptCode() {
        val waiting = DemoEngine.setPairingScenario(DemoState(), PairingActivity.PAIRING)
        assertEquals(PairingActivity.PAIRING, waiting.pairingActivity)
        assertNull(waiting.pairingCode)
        assertTrue(waiting.pairingInProgress)

        val allowed = DemoEngine.allowPairing(waiting, 1_000)
        assertEquals(1, allowed.trustedCount)
        assertEquals(PairingActivity.IN_USE, allowed.pairingActivity)
    }

    @Test
    fun forgettingAllClearsThePairState() {
        val inUse = DemoState(
            proxy = ProxyState.ON,
            trustedCount = 2,
            authenticatedSessions = 1,
            lastTrafficAgeSeconds = 0,
        )
        val cleared = DemoEngine.forgetAll(inUse, 9_000)
        assertEquals(0, cleared.trustedCount)
        assertEquals(PairingActivity.NOT_PAIRED, cleared.pairingActivity)
        assertEquals("Paired target devices forgotten.", cleared.activity.last().message)
        assertEquals(DemoState.NO_TARGET_DEVICES_TEXT, cleared.settingsPairingText)
    }

    @Test
    fun settingsPairingRowUsesOneState() {
        assertEquals(
            PairingGlyph.LINK_PLUS,
            DemoState().settingsPairingGlyph,
        )
        assertEquals(
            PairingGlyph.LINK,
            DemoState(pairingCode = "482193").settingsPairingGlyph,
        )
        assertEquals(
            PairingGlyph.SEAL,
            DemoState(proxy = ProxyState.ON, trustedCount = 1).settingsPairingGlyph,
        )
        assertEquals(
            PairingGlyph.SEAL,
            DemoState(
                proxy = ProxyState.ON,
                trustedCount = 1,
                authenticatedSessions = 1,
                lastTrafficAgeSeconds = 0,
            ).settingsPairingGlyph,
        )
        assertEquals(
            PairingGlyph.NETWORK,
            DemoState(
                proxy = ProxyState.ON,
                authenticatedSessions = 1,
                lastTrafficAgeSeconds = 0,
            ).settingsPairingGlyph,
        )
    }

    @Test
    fun portRulesMatchTheIosApp() {
        assertTrue(DemoEngine.isValidPort("1024"))
        assertTrue(DemoEngine.isValidPort("65535"))
        assertTrue(DemoEngine.isValidPort("20000"))
        assertFalse(DemoEngine.isValidPort("1023"))
        assertFalse(DemoEngine.isValidPort("18090"))
        assertFalse(DemoEngine.isValidPort("65536"))
        assertFalse(DemoEngine.isValidPort(""))
        assertFalse(DemoEngine.isValidPort("abc"))
        assertEquals("12345", DemoEngine.sanitizePort("12a3456"))
        assertEquals("", DemoEngine.sanitizePort("abc"))

        val custom = DemoEngine.setPortText(DemoState(), "2345")
        assertFalse(custom.portAutomatic)
        assertEquals("2345", custom.port)

        val automatic = DemoEngine.setPortAutomatic(custom, true)
        assertTrue(automatic.portAutomatic)
        assertEquals(DemoEngine.DEFAULT_PORT, automatic.port)
    }

    @Test
    fun tokenRevealHidesAfterThirtySeconds() {
        val revealed = DemoEngine.revealToken(DemoState(), nowMillis = 1_000)
        assertTrue(revealed.tokenVisible)
        assertEquals(30, revealed.tokenSecondsRemainingAt(1_000))
        assertEquals(1, revealed.tokenSecondsRemainingAt(30_999))
        assertEquals(0, revealed.tokenSecondsRemainingAt(31_000))
        assertTrue(DemoEngine.expireToken(revealed, 30_999).tokenVisible)
        assertFalse(DemoEngine.expireToken(revealed, 31_000).tokenVisible)

        val hidden = DemoEngine.expireToken(revealed, 31_000)
        assertNull(hidden.tokenRevealUntilMillis)
    }

    @Test
    fun rotatingTheTokenHidesItAndChangesTheValue() {
        val revealed = DemoEngine.revealToken(DemoState(), 1_000)
        val rotated = DemoEngine.rotateToken(revealed)
        assertFalse(rotated.tokenVisible)
        assertTrue(rotated.token.startsWith("demo-"))
        assertTrue(rotated.token != revealed.token)
    }

    @Test
    fun activityKeepsTheNewestFiftyEntries() {
        var state = DemoState()
        repeat(55) { index ->
            state = DemoEngine.addActivity(state, "Event $index", index.toLong())
        }
        assertEquals(DemoEngine.MAX_ACTIVITY, state.activity.size)
        assertEquals("Event 5", state.activity.first().message)
        assertEquals("Event 54", state.activity.last().message)
        assertEquals(56L, state.nextActivityId)
    }

    @Test
    fun sampleDataIsLabeledSimulated() {
        assertTrue(DemoEngine.SAMPLE_CONNECTION_LINES.first().startsWith("Simulated sample:"))
        assertTrue(DemoEngine.SAMPLE_DETAILS.all { it.startsWith("Simulated detail:") })
        val on = DemoState(proxy = ProxyState.ON)
        assertEquals(DemoEngine.SAMPLE_CONNECTION_LINES, on.connectionLines)
        assertTrue(DemoState().connectionLines.isEmpty())
    }

    @Test
    fun sampleConnectionLedgerAddsUp() {
        val lines = DemoEngine.SAMPLE_CONNECTION_LINES
        assertEquals(3, lines.size)

        val attempts = countBefore(lines[0], "attempts")
        val worked = countBefore(lines[0], "worked")
        val failed = countBefore(lines[0], "did not")
        val cancelled = countBefore(lines[1], "were cancelled")
        val webFailures = countBefore(lines[2], "web")
        val dnsFailures = countBefore(lines[2], "DNS lookup")

        assertEquals(14, attempts)
        assertEquals(9, worked)
        assertEquals(3, failed)
        assertEquals(2, cancelled)
        assertEquals(attempts, worked + failed + cancelled)
        assertEquals(failed, webFailures + dnsFailures)
    }

    private fun countBefore(line: String, label: String): Int {
        val match = Regex("""(\d+)\s+${Regex.escape(label)}""").find(line)
            ?: error("No count before \"$label\" in \"$line\"")
        return match.groupValues[1].toInt()
    }

    @Test
    fun diagnosticsHoldNoTokenPortOrAddress() {
        val state = DemoState(
            proxy = ProxyState.ON,
            trustedCount = 2,
            token = "demo-secret-value",
            port = "23456",
        )
        val report = DemoEngine.diagnosticsReport(state)
        assertTrue(report.contains("HotspotShade Android demo"))
        assertTrue(report.contains("State: On"))
        assertTrue(report.contains("Paired target devices: 2"))
        assertFalse(report.contains("demo-secret-value"))
        assertFalse(report.contains("23456"))
        assertFalse(report.contains("192.0.2.1"))
    }

    @Test
    fun keepAwakeMessagesTellTheTruth() {
        assertEquals(
            DemoState.KEEP_AWAKE_OFF,
            DemoState(keepAwake = false).keepAwakeMessage,
        )
        assertEquals(
            DemoState.PERMISSION_OFF,
            DemoState(simulatedLocationOff = true).keepAwakeMessage,
        )
        assertEquals(
            DemoState.STARTS_WITH_PROXY,
            DemoState(proxy = ProxyState.OFF).keepAwakeMessage,
        )
        assertEquals(
            DemoState.KEEPING_AWAKE_DEMO,
            DemoState(proxy = ProxyState.ON).keepAwakeMessage,
        )
    }

    @Test
    fun resetKeepsAppearanceButClearsDemoData() {
        val state = DemoState(
            proxy = ProxyState.ON,
            trustedCount = 1,
            activity = listOf(ActivityEntry(1, 0, "Proxy started.")),
            theme = ThemeChoice.DARK,
            reduceMotion = true,
        )
        val reset = DemoEngine.reset(state)
        assertEquals(ThemeChoice.DARK, reset.theme)
        assertTrue(reset.reduceMotion)
        assertEquals(ProxyState.OFF, reset.proxy)
        assertEquals(0, reset.trustedCount)
        assertTrue(reset.activity.isEmpty())
        assertEquals(PairingActivity.NOT_PAIRED, reset.pairingActivity)
    }

    @Test
    fun previewModeIsOffByDefaultAndResetClearsIt() {
        val state = DemoState(previewMode = true)

        val reset = DemoEngine.reset(state)

        assertFalse(reset.previewMode)
        assertTrue(DemoEngine.setPreviewMode(state, true).previewMode)
        assertFalse(DemoEngine.setPreviewMode(state, false).previewMode)
    }

    @Test
    fun pairingCodeSpeakingAndFormatting() {
        assertEquals("482 193", DemoEngine.formatPairingCode("482193"))
        assertEquals("48219", DemoEngine.formatPairingCode("48219"))
        assertEquals("4 8 2 1 9 3", DemoEngine.spokenPairingCode("482193"))
    }

    @Test
    fun lastStopPreviewStopsTheProxyAndSetsTheRestartOffer() {
        val on = DemoState(proxy = ProxyState.ON, trustedCount = 1)
        val stopped = DemoEngine.setLastStop(on, StopReason.HOTSPOT_LOST, 7_000)
        assertEquals(ProxyState.OFF, stopped.proxy)
        assertEquals(StopReason.HOTSPOT_LOST, stopped.lastStop)
        assertEquals(7_000L, stopped.lastStopAtMillis)
        assertFalse(stopped.offerRestart)
        assertEquals(1, stopped.trustedCount)
        assertEquals(PairingActivity.PAIRED, stopped.pairingActivity)

        val closed = DemoEngine.setLastStop(on, StopReason.APP_CLOSED, 8_000)
        assertTrue(closed.offerRestart)

        val cleared = DemoEngine.setLastStop(on, null, 9_000)
        assertNull(cleared.lastStop)
        assertNull(cleared.lastStopAtMillis)
        assertFalse(cleared.offerRestart)
        assertEquals(ProxyState.ON, cleared.proxy)
    }

    @Test
    fun proxyScenariosSetOneCoherentState() {
        val failed = DemoEngine.setProxyScenario(DemoState(), ProxyState.FAILED, 5_000)
        assertEquals(ProxyState.FAILED, failed.proxy)
        assertEquals(DemoState.START_FAILED, failed.startFailure)
        assertEquals(StopReason.FAILED, failed.lastStop)

        val on = DemoEngine.setProxyScenario(failed, ProxyState.ON, 6_000)
        assertEquals(ProxyState.ON, on.proxy)
        assertNull(on.startFailure)
        assertNull(on.lastStop)

        val starting = DemoEngine.setProxyScenario(on, ProxyState.STARTING, 7_000)
        assertEquals(ProxyState.STARTING, starting.proxy)
        assertTrue(starting.running)
    }

    @Test
    fun notificationTextMarksSimulation() {
        assertTrue(
            DemoState(notifications = NotificationStatus.ALLOWED)
                .notificationStatusText
                .startsWith("Simulated:"),
        )
        assertTrue(
            DemoState(notifications = NotificationStatus.DENIED)
                .notificationStatusText
                .startsWith("Simulated:"),
        )
        assertTrue(
            DemoState(notifications = NotificationStatus.NOT_DETERMINED)
                .notificationStatusText
                .startsWith("Simulated:"),
        )
    }
}
