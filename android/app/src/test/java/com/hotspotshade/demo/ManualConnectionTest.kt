package com.hotspotshade.demo

import com.hotspotshade.demo.model.ClipboardClearScheduler
import com.hotspotshade.demo.model.ClipboardPrivacy
import com.hotspotshade.demo.model.ClipboardSnapshot
import com.hotspotshade.demo.model.ConnectionClipboard
import com.hotspotshade.demo.model.ConnectionCopyResult
import com.hotspotshade.demo.model.ManualConnectionPolicy
import com.hotspotshade.demo.model.ManualConnectionSession
import com.hotspotshade.demo.model.ManualRevealResult
import com.hotspotshade.demo.model.RealProxyState
import com.hotspotshade.demo.model.TokenClipboard
import com.hotspotshade.demo.model.TokenClipboardController
import com.hotspotshade.demo.model.TokenCopyResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ManualConnectionTest {
    private val token = "00112233445566778899aabbccddeeff"
    private val otherToken = "ffeeddccbbaa99887766554433221100"
    private var now = 10_000L

    private class FakeClipboard : TokenClipboard {
        var text: String? = null
        var label: String? = null
        var createdAtMillis: Long? = null
        var writes = 0
        var clears = 0
        var failRead = false
        var failWrite = false
        var failClear = false

        override fun current(): ClipboardSnapshot? {
            if (failRead) throw IllegalStateException("The clip cannot be read.")
            if (text == null && label == null) return null
            return ClipboardSnapshot(
                text = text,
                label = label,
                createdAtMillis = createdAtMillis,
            )
        }

        override fun setSensitiveText(text: String, label: String) {
            if (failWrite) throw IllegalStateException("The clip cannot be written.")
            writes += 1
            this.text = text
            this.label = label
        }

        override fun clear() {
            if (failClear) throw IllegalStateException("The clip cannot be cleared.")
            clears += 1
            text = null
            label = null
        }
    }

    private class FakeScheduler : ClipboardClearScheduler {
        val delays = mutableListOf<Long>()
        val actions = mutableListOf<() -> Unit>()

        override fun schedule(delayMillis: Long, action: () -> Unit) {
            delays += delayMillis
            actions += action
        }
    }

    private class Fixture {
        val clipboard = FakeClipboard()
        val scheduler = FakeScheduler()
        var clockMillis = 1_000_000L
        val controller = TokenClipboardController(
            clipboard,
            scheduler,
            nowMillis = { clockMillis },
        )
    }

    private fun session(fixture: Fixture, token: String? = null): ManualConnectionSession {
        val session = ManualConnectionSession(fixture.controller) { now }
        session.setConnection("192.168.43.1", 41_234, addressCheckFailed = false)
        session.setToken(token)
        return session
    }

    private class FakeConnectionClipboard : ConnectionClipboard {
        var text: String? = null
        var label: String? = null
        var writes = 0
        var fail = false

        override fun setText(text: String, label: String) {
            if (fail) throw IllegalStateException("The clip cannot be written.")
            writes += 1
            this.text = text
            this.label = label
        }
    }

    private fun detailsSession(
        fixture: Fixture,
        connection: FakeConnectionClipboard?,
        address: String? = "192.168.43.1",
        port: Int = 41_234,
        token: String? = null,
    ): ManualConnectionSession {
        val session = ManualConnectionSession(fixture.controller, connection) { now }
        session.setConnection(address, port, addressCheckFailed = address == null)
        session.setToken(token)
        return session
    }

    @Test
    fun copyConnectionDetailsWritesTheAddressPortAndUsernameOnly() {
        val fixture = Fixture()
        val connection = FakeConnectionClipboard()
        val session = detailsSession(fixture, connection, token = token)

        assertTrue(session.state.connectionDetailsAvailable)
        assertEquals(ConnectionCopyResult.COPIED, session.copyConnectionDetails())

        val text = connection.text!!
        assertEquals(ManualConnectionPolicy.CONNECTION_CLIP_LABEL, connection.label)
        assertTrue(text.contains("Server: 192.168.43.1:41234"))
        assertTrue(text.contains("Username: hotspotshade"))
        assertFalse("The copy never holds the token.", text.contains(token))
        assertEquals("The connection details are copied.", session.state.connectionCopyMessage)
        assertEquals(0, fixture.clipboard.writes)
        assertEquals("No clear is scheduled for a non-secret copy.", 0, fixture.scheduler.actions.size)
    }

    @Test
    fun copyConnectionDetailsNeedsNoTokenAndNoReveal() {
        val fixture = Fixture()
        val connection = FakeConnectionClipboard()
        val session = detailsSession(fixture, connection, token = null)

        assertFalse(session.state.tokenAvailable)
        assertEquals(ConnectionCopyResult.COPIED, session.copyConnectionDetails())
        assertEquals(1, connection.writes)
    }

    @Test
    fun copyConnectionDetailsRefusesAnUnknownAddressOrPort() {
        val fixture = Fixture()
        for ((address, port) in listOf(
            null to 41_234,
            "192.168.43.1" to 0,
            "192.168.43.1" to 80,
            "192.168.43.1" to 70_000,
            "bad address" to 41_234,
            " " to 41_234,
        )) {
            val connection = FakeConnectionClipboard()
            val session = detailsSession(fixture, connection, address, port)

            assertFalse(session.state.connectionDetailsAvailable)
            assertEquals(ConnectionCopyResult.UNAVAILABLE, session.copyConnectionDetails())
            assertEquals(0, connection.writes)
            assertTrue(session.state.connectionCopyMessage!!.contains("nothing to copy"))
        }
    }

    @Test
    fun copyConnectionDetailsReportsAFailedWriteAndAMissingClipboard() {
        val fixture = Fixture()
        val failing = FakeConnectionClipboard().apply { fail = true }
        val failed = detailsSession(fixture, failing)
        assertEquals(ConnectionCopyResult.FAILED, failed.copyConnectionDetails())
        assertEquals(
            "The app could not copy the connection details.",
            failed.state.connectionCopyMessage,
        )

        val none = detailsSession(fixture, null)
        assertEquals(ConnectionCopyResult.FAILED, none.copyConnectionDetails())
    }

    @Test
    fun theTokenClearLeavesTheConnectionDetailsClipAlone() {
        val fixture = Fixture()
        val connection = FakeConnectionClipboard()
        val session = detailsSession(fixture, connection, token = token)
        session.reveal()
        assertEquals(TokenCopyResult.COPIED, session.copy())
        // The details replace the token clip. The scheduled clear must find a
        // different label and leave the clipboard alone.
        assertEquals(ConnectionCopyResult.COPIED, session.copyConnectionDetails())
        fixture.clipboard.text = connection.text
        fixture.clipboard.label = connection.label

        fixture.scheduler.actions.single().invoke()

        assertEquals(0, fixture.clipboard.clears)
        assertEquals(connection.text, fixture.clipboard.text)
        assertEquals(
            "The token copy message goes away when the details replace it.",
            TokenCopyResult.NONE,
            session.state.copy,
        )
    }

    @Test
    fun theConnectionCopyMessageClearsOnHideBackgroundAndTimeout() {
        val fixture = Fixture()
        val session = detailsSession(fixture, FakeConnectionClipboard(), token = token)
        session.copyConnectionDetails()
        session.clearCopyMessage()
        assertNull(session.state.connectionCopyMessage)

        session.copyConnectionDetails()
        session.onBackground()
        assertNull(session.state.connectionCopyMessage)

        session.copyConnectionDetails()
        session.hide()
        assertNull(session.state.connectionCopyMessage)
    }

    @Test
    fun theCopyTextNamesTheTokenFieldButNeverHoldsAToken() {
        val text = ManualConnectionPolicy.connectionDetailsText("192.168.43.1", 41_234)!!
        assertTrue(text.startsWith("HotspotShade SOCKS5 proxy\n"))
        assertTrue(text.contains("Password: the source token."))
        assertTrue(text.contains("socks5h"))
        assertNull(ManualConnectionPolicy.connectionDetailsText(null, 41_234))
    }

    @Test
    fun revealIsExplicitAndExpiresAtTheDeadline() {
        val fixture = Fixture()
        val session = session(fixture, token)

        assertEquals(ManualRevealResult.REVEALED, session.reveal())
        assertTrue(session.state.tokenVisible)
        assertEquals(30, session.state.tokenSecondsRemainingAt(now))
        assertEquals(token, session.visibleToken())

        now = 39_999L
        assertFalse(session.expire())
        assertTrue(session.state.tokenVisible)

        now = 40_000L
        assertTrue(session.expire())
        assertFalse(session.state.tokenVisible)
        assertNull(session.visibleToken())
        assertEquals(0, session.state.tokenSecondsRemainingAt(now))
    }

    @Test
    fun leavingTheForegroundHidesTheToken() {
        val fixture = Fixture()
        val session = session(fixture, token)
        session.reveal()
        assertTrue(session.state.tokenVisible)

        session.onBackground()

        assertFalse(session.state.tokenVisible)
        assertNull(session.visibleToken())
        assertNull(session.state.revealUntilMillis)
    }

    @Test
    fun aMissingTokenIsNeverShownOrCopied() {
        val fixture = Fixture()
        val session = session(fixture, token = null)

        assertEquals(ManualRevealResult.UNAVAILABLE, session.reveal())
        assertFalse(session.state.tokenVisible)
        assertNull(session.visibleToken())

        assertEquals(TokenCopyResult.REFUSED_ABSENT, session.copy())
        assertEquals(0, fixture.clipboard.writes)
        assertEquals("No token is stored, so there is nothing to copy.", session.state.copyMessage)
    }

    @Test
    fun copyRequiresAVisibleTokenAndAvoidsARepeatedWrite() {
        val fixture = Fixture()
        val session = session(fixture, token)

        assertEquals(TokenCopyResult.REFUSED_HIDDEN, session.copy())
        assertEquals(0, fixture.clipboard.writes)
        assertEquals("Show the token before you copy it.", session.state.copyMessage)

        session.reveal()
        assertEquals(TokenCopyResult.COPIED, session.copy())
        assertEquals(1, fixture.clipboard.writes)
        assertEquals(token, fixture.clipboard.text)
        assertEquals(ManualConnectionPolicy.TOKEN_CLIP_LABEL, fixture.clipboard.label)
        assertEquals(120_000L, fixture.scheduler.delays.single())

        assertEquals(TokenCopyResult.ALREADY_ON_CLIPBOARD, session.copy())
        assertEquals(1, fixture.clipboard.writes)
        assertEquals(1, fixture.scheduler.actions.size)
    }

    @Test
    fun failedWriteIsReportedAndSchedulesNoClear() {
        val fixture = Fixture()
        fixture.clipboard.failWrite = true
        val session = session(fixture, token)
        session.reveal()

        assertEquals(TokenCopyResult.FAILED, session.copy())
        assertEquals("The app could not copy the token.", session.state.copyMessage)
        assertTrue(fixture.scheduler.actions.isEmpty())
    }

    @Test
    fun theScheduledClearRemovesOnlyThisAppsUnchangedClip() {
        val fixture = Fixture()
        val controller = fixture.controller
        assertEquals(TokenCopyResult.COPIED, controller.copy(token))
        assertEquals(1, fixture.scheduler.actions.size)

        fixture.clipboard.createdAtMillis = fixture.clockMillis
        fixture.scheduler.actions.single()()

        assertEquals(1, fixture.clipboard.clears)
        assertNull(fixture.clipboard.text)
    }

    @Test
    fun theScheduledClearNeverRemovesANewerItem() {
        val fixture = Fixture()
        val controller = fixture.controller
        controller.copy(token)

        fixture.clipboard.text = "a newer clip"
        fixture.clipboard.label = "Another app"
        fixture.scheduler.actions.single()()

        assertEquals(0, fixture.clipboard.clears)
        assertEquals("a newer clip", fixture.clipboard.text)
        assertEquals("Another app", fixture.clipboard.label)
    }

    @Test
    fun theScheduledClearRequiresTheAppLabel() {
        val fixture = Fixture()
        val controller = fixture.controller
        controller.copy(token)

        fixture.clipboard.text = token
        fixture.clipboard.label = "Another app"
        fixture.scheduler.actions.single()()

        assertEquals(0, fixture.clipboard.clears)
        assertEquals(token, fixture.clipboard.text)
    }

    @Test
    fun aNewerClipWithTheSameTextAndLabelIsNotCleared() {
        val fixture = Fixture()
        val controller = fixture.controller
        controller.copy(token)

        fixture.clipboard.text = token
        fixture.clipboard.label = ManualConnectionPolicy.TOKEN_CLIP_LABEL
        fixture.clipboard.createdAtMillis = fixture.clockMillis + 1
        fixture.scheduler.actions.single()()

        assertEquals(0, fixture.clipboard.clears)
        assertEquals(token, fixture.clipboard.text)
    }

    @Test
    fun aNewCopySupersedesAnOlderClear() {
        val fixture = Fixture()
        val controller = fixture.controller
        controller.copy(token)

        fixture.clipboard.text = "another value"
        fixture.clipboard.label = "Another app"
        controller.copy(token)
        assertEquals(2, fixture.clipboard.writes)
        assertEquals(2, fixture.scheduler.actions.size)

        fixture.scheduler.actions[0]()
        assertEquals(0, fixture.clipboard.clears)

        fixture.scheduler.actions[1]()
        assertEquals(1, fixture.clipboard.clears)
    }

    @Test
    fun anUnreadableClipboardIsNeverCleared() {
        val fixture = Fixture()
        val controller = fixture.controller
        controller.copy(token)

        fixture.clipboard.failRead = true
        fixture.clipboard.text = token
        fixture.clipboard.label = ManualConnectionPolicy.TOKEN_CLIP_LABEL
        fixture.scheduler.actions.single()()

        assertEquals(0, fixture.clipboard.clears)
    }

    @Test
    fun aFailedClearLeavesTheClipAlone() {
        val fixture = Fixture()
        val controller = fixture.controller
        controller.copy(token)
        fixture.clipboard.failClear = true

        fixture.scheduler.actions.single()()

        assertEquals(0, fixture.clipboard.clears)
        assertEquals(token, fixture.clipboard.text)
    }

    @Test
    fun platformPrivacyRulesFollowTheApiLevel() {
        assertFalse(ClipboardPrivacy.marksSensitive(26))
        assertFalse(ClipboardPrivacy.marksSensitive(32))
        assertTrue(ClipboardPrivacy.marksSensitive(33))
        assertTrue(ClipboardPrivacy.marksSensitive(36))

        assertFalse(ClipboardPrivacy.clearsPrimaryClip(26))
        assertFalse(ClipboardPrivacy.clearsPrimaryClip(27))
        assertTrue(ClipboardPrivacy.clearsPrimaryClip(28))
        assertTrue(ClipboardPrivacy.clearsPrimaryClip(33))
    }

    @Test
    fun aChangedTokenClosesTheOldReveal() {
        val fixture = Fixture()
        val session = session(fixture, token)
        session.reveal()

        session.setToken(otherToken)

        assertFalse(session.state.tokenVisible)
        assertNull(session.visibleToken())
        assertEquals(ManualRevealResult.REVEALED, session.reveal())
        assertEquals(otherToken, session.visibleToken())
    }

    @Test
    fun theRealStateNeverCarriesTheTokenIntoReports() {
        val fixture = Fixture()
        val session = session(fixture, token)
        session.reveal()

        assertFalse(session.state.toString().contains(token))
        assertFalse(session.state.addressText.contains(token))
        assertFalse(ManualConnectionPolicy.CLIPBOARD_NOTE.contains(token))
        assertFalse(ManualConnectionPolicy.HIDDEN_NOTE.contains(token))

        val snapshot = ManualConnectionSnapshot(
            address = "192.168.43.1",
            addressCheckFailed = false,
            savedPort = 41_234,
            token = token,
        )
        assertFalse(snapshot.toString().contains(token))
        assertFalse(snapshot.toString().contains("192.168.43.1"))

        val clip = ClipboardSnapshot(
            text = token,
            label = ManualConnectionPolicy.TOKEN_CLIP_LABEL,
            createdAtMillis = 1_000,
        )
        assertFalse(clip.toString().contains(token))

        val diagnostics = RealProxyState().diagnosticsReport("on", "1.2.3")
        assertFalse(diagnostics.contains(token))
        assertFalse(diagnostics.contains("192.168.43.1"))
    }

    @Test
    fun manualValuesHavePlainLoadingEmptyAndErrorStates() {
        val fixture = Fixture()
        val session = ManualConnectionSession(fixture.controller) { now }

        assertEquals("Checking the hotspot address.", session.state.addressText)
        assertEquals("Chosen when the proxy starts.", session.state.portText)
        assertEquals("hotspotshade", session.state.usernameText)

        session.setConnection(
            address = null,
            port = 0,
            addressCheckFailed = false,
        )
        assertEquals(
            "No hotspot address. Turn on the hotspot and refresh.",
            session.state.addressText,
        )

        session.setConnection(
            address = null,
            port = 0,
            addressCheckFailed = true,
        )
        assertEquals(
            "The app could not read the hotspot address.",
            session.state.addressText,
        )

        session.setConnection(
            address = "192.168.43.1",
            port = 41_234,
            addressCheckFailed = false,
        )
        assertEquals("192.168.43.1", session.state.addressText)
        assertEquals("41234", session.state.portText)

        session.setPort(0)
        assertEquals("Chosen when the proxy starts.", session.state.portText)
    }

    @Test
    fun aPendingHotspotReadingIsNotReportedAsMissing() {
        val fixture = Fixture()
        val session = session(fixture, token = null)

        session.setConnection(
            address = null,
            port = 0,
            addressCheckFailed = false,
            addressPending = true,
        )

        assertTrue(session.state.addressPending)
        assertEquals(
            "Waiting for the system hotspot reading.",
            session.state.addressText,
        )

        session.setConnection(
            address = "192.168.43.1",
            port = 41_234,
            addressCheckFailed = false,
        )
        assertFalse(session.state.addressPending)
        assertEquals("192.168.43.1", session.state.addressText)
    }

    @Test
    fun anUnreadableTokenIsNotReportedAsAbsent() {
        val fixture = Fixture()
        val session = session(fixture, token = token)
        session.reveal()
        assertTrue(session.state.tokenVisible)

        session.setToken(null, unreadable = true)

        assertFalse(session.state.tokenVisible)
        assertFalse(session.state.tokenAvailable)
        assertTrue(session.state.tokenUnreadable)
        assertEquals(
            "The stored token cannot be read. Tap Refresh connection to try again.",
            session.state.tokenStateText,
        )
        assertEquals(ManualRevealResult.UNAVAILABLE, session.reveal())
        assertEquals(TokenCopyResult.REFUSED_ABSENT, session.copy())
        assertEquals(
            "The stored token cannot be read, so there is nothing to copy.",
            session.state.copyMessage,
        )
        assertEquals(0, fixture.clipboard.writes)

        session.setToken(token)
        assertTrue(session.state.tokenAvailable)
        assertFalse(session.state.tokenUnreadable)

        session.setToken(null)
        assertFalse(session.state.tokenUnreadable)
        assertEquals(
            "No token is stored yet. Start the proxy once and the app creates it.",
            session.state.tokenStateText,
        )
    }

    @Test
    fun unusableStoredTokenCannotBeRevealedOrCopied() {
        val fixture = Fixture()
        val session = session(fixture, token = token)
        session.reveal()

        for (invalid in listOf("", "bad token", "x".repeat(256), "caf\u00e9")) {
            session.setToken(invalid)
            assertFalse(session.state.tokenVisible)
            assertFalse(session.state.tokenAvailable)
            assertTrue(session.state.tokenUnreadable)
            assertEquals(ManualRevealResult.UNAVAILABLE, session.reveal())
            assertEquals(TokenCopyResult.REFUSED_ABSENT, session.copy())
        }
        assertEquals(0, fixture.clipboard.writes)
        session.setToken(token)
        assertTrue(session.state.tokenAvailable)
        assertFalse(session.state.tokenUnreadable)
        session.reveal()
        session.setToken(token, unreadable = true)
        assertFalse(session.state.tokenVisible)
        assertFalse(session.state.tokenAvailable)
        assertTrue(session.state.tokenUnreadable)
        assertEquals(ManualRevealResult.UNAVAILABLE, session.reveal())
    }

    @Test
    fun hiddenAndAbsentTokenTextMatchesTheControls() {
        val fixture = Fixture()
        val session = session(fixture, token = null)
        assertEquals(
            "No token is stored yet. Start the proxy once and the app creates it.",
            session.state.tokenStateText,
        )

        session.setToken(token)
        assertEquals(
            "The token is hidden. Tap Show token to see it.",
            session.state.tokenStateText,
        )

        session.reveal()
        assertEquals(
            "The token is shown below. It hides again after 30 seconds.",
            session.state.tokenStateText,
        )
    }
}
