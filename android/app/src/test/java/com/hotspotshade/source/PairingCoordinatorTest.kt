package com.hotspotshade.source

import com.hotspotshade.source.pairing.ChallengeOrResult
import com.hotspotshade.source.pairing.MemoryPairingTrustStore
import com.hotspotshade.source.pairing.PairingCallbackDispatcher
import com.hotspotshade.source.pairing.PairingCredentials
import com.hotspotshade.source.pairing.PairingIdentity
import com.hotspotshade.source.pairing.PairingKeys
import com.hotspotshade.source.pairing.PairingListener
import com.hotspotshade.source.pairing.PairingPrompt
import com.hotspotshade.source.pairing.PairingProtocol
import com.hotspotshade.source.pairing.PairingResponder
import com.hotspotshade.source.pairing.PairingServer
import com.hotspotshade.source.pairing.PairingStatus
import com.hotspotshade.source.pairing.PairingTrustStore
import com.hotspotshade.source.pairing.ResultMessage
import com.hotspotshade.source.pairing.X25519
import java.io.DataInputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ThreadFactory
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Integration test for the real coordinator on loopback.
 *
 * It proves that a successful pairing saves the token with [TokenWriter], so
 * the source proxy start finds a token instead of `TOKEN_MISSING`. It also
 * proves that concurrent token reloads keep one listener and use the new
 * token.
 */
class PairingCoordinatorTest {
    private val loopback = InetAddress.getByName("127.0.0.1")

    @Before
    fun resetRuntime() {
        SourceProxyRuntime.resetObservation()
    }

    @After
    fun clearRuntime() {
        SourceProxyRuntime.resetObservation()
    }

    @Test
    fun aSuccessfulPairingSavesTheToken() {
        val store = FakeStore()
        val prompt = AtomicReference<PairingPrompt?>(null)
        val shown = CountDownLatch(1)
        val states = mutableListOf<PairingListenerState>()
        val coordinator = coordinator(store, prompt, shown, states)
        coordinator.start()
        try {
            val port = waitForPort(coordinator)
            assertTrue(port > 0)
            Socket().use { socket ->
                socket.soTimeout = 5_000
                socket.connect(InetSocketAddress(loopback, port), 5_000)
                val output = socket.getOutputStream()
                val target = Target()
                output.write(PairingProtocol.frame(target.hello()))
                output.flush()
                target.acceptHostChallenge(readPayload(socket.getInputStream()))
                output.write(PairingProtocol.frame(target.reveal()))
                output.flush()
                assertTrue("The real prompt must appear.", shown.await(5, TimeUnit.SECONDS))
                assertNotNull(prompt.get())
                coordinator.allow(prompt.get()!!)
                val result = PairingProtocol.decodeResult(readPayload(socket.getInputStream()))
                assertTrue(result is ResultMessage.Ok)
                val credentials = target.openResult(result as ResultMessage.Ok)
                assertEquals(store.saved, credentials.token)
                assertEquals(store.saved, store.load())
                assertTrue(store.saved!!.isNotEmpty())
            }
        } finally {
            coordinator.stop()
        }
        assertTrue(
            "The coordinator must report a stopped listener.",
            waitForState(states, PairingListenerState.STOPPED),
        )
    }

    @Test
    fun concurrentReloadsKeepOneListenerAndUseTheNewToken() {
        val store = FakeStore()
        store.saved = "first-token"
        val prompt = AtomicReference<PairingPrompt?>(null)
        val shown = CountDownLatch(1)
        val states = mutableListOf<PairingListenerState>()
        val coordinator = coordinator(store, prompt, shown, states)
        coordinator.start()
        try {
            assertTrue(waitForPort(coordinator) > 0)
            store.saved = "second-token"

            val threads = (0 until 4).map { index ->
                Thread({ coordinator.reloadToken() }, "test-reload-$index").also { it.start() }
            }
            for (thread in threads) {
                thread.join(10_000)
                assertFalse(thread.isAlive)
            }

            val port = waitForPort(coordinator)
            assertTrue("One listener must stay bound.", port > 0)
            Socket().use { socket ->
                socket.soTimeout = 5_000
                socket.connect(InetSocketAddress(loopback, port), 5_000)
                val output = socket.getOutputStream()
                val target = Target()
                output.write(PairingProtocol.frame(target.hello()))
                output.flush()
                target.acceptHostChallenge(readPayload(socket.getInputStream()))
                output.write(PairingProtocol.frame(target.reveal()))
                output.flush()
                assertTrue(shown.await(5, TimeUnit.SECONDS))
                coordinator.allow(prompt.get()!!)
                val result = PairingProtocol.decodeResult(readPayload(socket.getInputStream()))
                assertTrue(result is ResultMessage.Ok)
                val credentials = target.openResult(result as ResultMessage.Ok)
                assertEquals("second-token", credentials.token)
            }
            assertEquals("second-token", store.saved)
        } finally {
            coordinator.stop()
        }
    }

    @Test
    fun anUnreadableStoredTokenReportsItsOwnState() {
        val store = FakeStore()
        store.failRead = true
        val prompt = AtomicReference<PairingPrompt?>(null)
        val shown = CountDownLatch(1)
        val states = mutableListOf<PairingListenerState>()
        val coordinator = coordinator(store, prompt, shown, states)
        coordinator.start()
        try {
            assertTrue(waitForState(states, PairingListenerState.TOKEN_UNREADABLE))
            assertFalse(
                "An unreadable token is not a general listener failure.",
                synchronized(states) { states.contains(PairingListenerState.FAILED) },
            )
            assertEquals("An unreadable token must not be replaced.", null, store.saved)
            assertEquals(0, store.saves)
        } finally {
            coordinator.stop()
        }
    }

    @Test
    fun anUnusableStoredTokenIsUnreadableAndIsNotReplaced() {
        for (value in listOf("", "bad token", "tab\there", "x".repeat(256))) {
            val store = FakeStore()
            store.saved = value
            val prompt = AtomicReference<PairingPrompt?>(null)
            val shown = CountDownLatch(1)
            val states = mutableListOf<PairingListenerState>()
            val coordinator = coordinator(store, prompt, shown, states)
            coordinator.start()
            try {
                assertTrue(
                    "The stored value must be refused: length=${value.length}",
                    waitForState(states, PairingListenerState.TOKEN_UNREADABLE),
                )
                assertFalse(
                    "An unusable value is not a general listener failure.",
                    synchronized(states) { states.contains(PairingListenerState.FAILED) },
                )
                assertEquals("An unusable token must not be replaced.", value, store.saved)
                assertEquals(0, store.saves)
            } finally {
                coordinator.stop()
            }
        }
    }

    @Test
    fun aPairingDoesNotReplaceADifferentStoredToken() {
        val store = FakeStore()
        store.saved = "first-token"
        val trust = MemoryPairingTrustStore()
        val prompt = AtomicReference<PairingPrompt?>(null)
        val shown = CountDownLatch(1)
        val states = mutableListOf<PairingListenerState>()
        val coordinator = coordinator(store, prompt, shown, states, trust = trust)
        coordinator.start()
        try {
            assertTrue(waitForPort(coordinator) > 0)
            // Another listener or a rotation through another admin instance
            // stores a different valid token after this listener was created.
            store.saved = "other-valid-token"

            val result = pairResultOnce(coordinator, prompt, shown)

            assertTrue(
                "A sealed token must not replace a different stored token.",
                result is ResultMessage.Status,
            )
            assertEquals(PairingStatus.REJECTED, (result as ResultMessage.Status).status)
            assertEquals("other-valid-token", store.saved)
            assertEquals("A refused save must add no trust.", 0, trust.count)
        } finally {
            coordinator.stop()
        }
    }

    @Test
    fun aPairingDoesNotReplaceAnUnreadableStoredToken() {
        val store = FakeStore()
        store.saved = "first-token"
        val trust = MemoryPairingTrustStore()
        val prompt = AtomicReference<PairingPrompt?>(null)
        val shown = CountDownLatch(1)
        val states = mutableListOf<PairingListenerState>()
        val scheduler = AtomicReference<java.util.concurrent.ScheduledExecutorService>()
        val coordinator = coordinator(store, prompt, shown, states, trust = trust,
            schedulerFactory = { trackingScheduler(scheduler) })
        coordinator.start()
        try {
            // Wait for the first state before the periodic refresh is stopped,
            // so the assertions below observe the commit-time publication and
            // not a later refresh.
            assertTrue(waitForState(states, PairingListenerState.LISTENING))
            assertTrue("The periodic refresh must stop.", stopScheduler(scheduler.get()!!))
            // The listener already holds the token in memory. The store fails
            // at the commit step.
            store.failRead = true

            val result = pairResultOnce(coordinator, prompt, shown)

            assertTrue(
                "An unreadable stored token must refuse the save.",
                result is ResultMessage.Status,
            )
            assertEquals(PairingStatus.REJECTED, (result as ResultMessage.Status).status)
            assertEquals("first-token", store.saved)
            assertEquals("A refused save must add no trust.", 0, trust.count)

            assertTrue("The unreadable state must be published before refresh.",
                waitForState(states, PairingListenerState.TOKEN_UNREADABLE))
            assertEquals(
                "The unreadable state must stay the latest one before a refresh.",
                PairingListenerState.TOKEN_UNREADABLE,
                lastState(states),
            )
            assertTrue("The stale listener remains bound until refresh.", coordinator.localPort > 0)
            coordinator.refreshNow()
            assertTrue("An unreadable store must invalidate the cached listener.",
                waitForState(states, PairingListenerState.TOKEN_UNREADABLE))
            assertEquals("The stale listener must be closed.", 0, coordinator.localPort)
            assertEquals(
                "A later refresh must not report a listening listener.",
                PairingListenerState.TOKEN_UNREADABLE,
                lastState(states),
            )
        } finally {
            coordinator.stop()
        }
    }

    @Test
    fun aDifferentValidStoredTokenAtCommitIsNotReportedUnreadable() {
        val store = FakeStore()
        store.saved = "first-token"
        val trust = MemoryPairingTrustStore()
        val prompt = AtomicReference<PairingPrompt?>(null)
        val shown = CountDownLatch(1)
        val states = mutableListOf<PairingListenerState>()
        val scheduler = AtomicReference<java.util.concurrent.ScheduledExecutorService>()
        val coordinator = coordinator(store, prompt, shown, states, trust = trust,
            schedulerFactory = { trackingScheduler(scheduler) })
        coordinator.start()
        try {
            assertTrue(waitForState(states, PairingListenerState.LISTENING))
            assertTrue("The periodic refresh must stop.", stopScheduler(scheduler.get()!!))
            // A usable token replaces the stored one after this listener loaded
            // its own. The commit must refuse the save, and a usable replacement
            // is not an unreadable or failed credential.
            store.saved = "other-valid-token"

            val result = pairResultOnce(coordinator, prompt, shown)

            assertEquals(PairingStatus.REJECTED, (result as ResultMessage.Status).status)
            assertEquals("other-valid-token", store.saved)
            assertEquals("A refused save must add no trust.", 0, trust.count)
            assertFalse(
                "A usable replacement token is not unreadable.",
                synchronized(states) { states.contains(PairingListenerState.TOKEN_UNREADABLE) },
            )
            assertFalse(
                "A refused save is not a listener failure.",
                synchronized(states) { states.contains(PairingListenerState.FAILED) },
            )
            assertEquals(
                "The bound listener stays the latest state until a refresh.",
                PairingListenerState.LISTENING,
                lastState(states),
            )
        } finally {
            coordinator.stop()
        }
    }

    @Test
    fun anUnusableStoredTokenAtCommitReportsUnreadableWithoutGeneratingAToken() {
        val store = FakeStore()
        store.saved = "first-token"
        val trust = MemoryPairingTrustStore()
        val generated = AtomicInteger(0)
        val prompt = AtomicReference<PairingPrompt?>(null)
        val shown = CountDownLatch(1)
        val states = mutableListOf<PairingListenerState>()
        val scheduler = AtomicReference<java.util.concurrent.ScheduledExecutorService>()
        val coordinator = coordinator(
            store,
            prompt,
            shown,
            states,
            trust = trust,
            tokenFactory = {
                generated.incrementAndGet()
                "generated-token"
            },
            schedulerFactory = { trackingScheduler(scheduler) },
        )
        coordinator.start()
        try {
            assertTrue(waitForState(states, PairingListenerState.LISTENING))
            assertEquals("The listener must use the stored token.", 0, generated.get())
            assertTrue("The periodic refresh must stop.", stopScheduler(scheduler.get()!!))
            // A readable but unusable value replaces the token at commit time.
            store.saved = "bad token"

            val result = pairResultOnce(coordinator, prompt, shown)

            assertEquals(PairingStatus.REJECTED, (result as ResultMessage.Status).status)
            assertEquals("An unusable token must not be replaced.", "bad token", store.saved)
            assertEquals("A refused save must write no token.", 0, store.saves)
            assertEquals("A refused save must add no trust.", 0, trust.count)
            assertTrue(
                "An unusable stored token must report its own state.",
                waitForState(states, PairingListenerState.TOKEN_UNREADABLE),
            )
            assertEquals(PairingListenerState.TOKEN_UNREADABLE, lastState(states))
            assertFalse(
                "An unusable token is not a general listener failure.",
                synchronized(states) { states.contains(PairingListenerState.FAILED) },
            )
            assertEquals("No replacement may be generated.", 0, generated.get())

            coordinator.refreshNow()
            assertTrue(
                "The refresh must keep reporting the unusable token.",
                waitForState(states, PairingListenerState.TOKEN_UNREADABLE),
            )
            assertEquals("The unusable value must close the listener.", 0, coordinator.localPort)
            assertEquals("bad token", store.saved)
            assertEquals("No replacement may be generated.", 0, generated.get())
        } finally {
            coordinator.stop()
        }
    }

    @Test
    fun aRejectedPairingDropsTheStaleTokenSoTheNextPairingUsesTheStoredOne() {
        val store = FakeStore()
        store.saved = "first-token"
        val trust = MemoryPairingTrustStore()
        val prompt = AtomicReference<PairingPrompt?>(null)
        val shown = CountDownLatch(1)
        val states = mutableListOf<PairingListenerState>()
        val coordinator = coordinator(store, prompt, shown, states, trust = trust)
        coordinator.start()
        try {
            assertTrue(waitForPort(coordinator) > 0)
            store.saved = "other-valid-token"

            val first = pairResultOnce(coordinator, prompt, shown)
            assertEquals(PairingStatus.REJECTED, (first as ResultMessage.Status).status)
            assertEquals(0, trust.count)

            // The next refresh closes the stale listener and reloads the store.
            coordinator.refreshNow()

            val second = pairResultPolling(coordinator, prompt)
            assertTrue("The next pairing must succeed.", second.result is ResultMessage.Ok)
            assertEquals(
                "The next pairing must carry the stored token, not the stale cache.",
                "other-valid-token",
                second.credentials?.token,
            )
            assertEquals("other-valid-token", store.saved)
            assertEquals(1, trust.count)
        } finally {
            coordinator.stop()
        }
    }

    @Test
    fun aLosingCoordinatorPairsWithTheWinnersTokenAfterItsRefresh() {
        val store = FakeStore()
        val guard = SourceTokenGuard()
        val trustA = MemoryPairingTrustStore()
        val trustB = MemoryPairingTrustStore()
        val promptA = AtomicReference<PairingPrompt?>(null)
        val promptB = AtomicReference<PairingPrompt?>(null)
        val shownA = CountDownLatch(1)
        val shownB = CountDownLatch(1)
        val coordinatorA = coordinator(
            store, promptA, shownA, mutableListOf(),
            guard = guard, trust = trustA, tokenFactory = { "generated-a" },
        )
        val coordinatorB = coordinator(
            store, promptB, shownB, mutableListOf(),
            guard = guard, trust = trustB, tokenFactory = { "generated-b" },
        )
        coordinatorA.start()
        coordinatorB.start()
        try {
            assertTrue(waitForPort(coordinatorA) > 0)
            assertTrue(waitForPort(coordinatorB) > 0)

            // A pairs first and stores its token. B still caches its own.
            val winner = pairOnce(coordinatorA, promptA, shownA)
            assertEquals("generated-a", winner.token)
            assertEquals("generated-a", store.saved)

            // B's sealed token is not the stored one, so B is refused.
            val refused = pairResultOnce(coordinatorB, promptB, shownB)
            assertEquals(PairingStatus.REJECTED, (refused as ResultMessage.Status).status)
            assertEquals("generated-a", store.saved)
            assertEquals(1, trustA.count)
            assertEquals("A refused save must add no trust.", 0, trustB.count)

            coordinatorB.refreshNow()

            // B's next pairing carries the winner's token. It does not repeat
            // the stale "generated-b" value.
            val retry = pairResultPolling(coordinatorB, promptB)
            assertTrue("The next pairing on B must succeed.", retry.result is ResultMessage.Ok)
            assertEquals("generated-a", retry.credentials?.token)
            assertEquals("generated-a", store.saved)
            assertEquals(1, trustB.count)
        } finally {
            coordinatorA.stop()
            coordinatorB.stop()
        }
    }

    @Test
    fun aTransientReadAtCommitRefusesTheSaveWithTheRealStore() {
        val directory = Files.createTempDirectory("hotspotshade-pairing-read").toFile()
        try {
            val target = File(directory, "source-token.bin")
            target.writeText("token-stored", Charsets.UTF_8)
            var failing = false
            val store = AndroidKeystoreTokenStore(
                target,
                codec = TokenOnlyCodec(),
                // FileNotFoundException is the EACCES and EMFILE shape. It is
                // not a missing file.
                readFile = { file ->
                    if (failing) throw java.io.FileNotFoundException("denied (Permission denied)")
                    NioTokenFileReader.read(file)
                },
            )
            val trust = MemoryPairingTrustStore()
            val prompt = AtomicReference<PairingPrompt?>(null)
            val shown = CountDownLatch(1)
            val coordinator = coordinator(store, prompt, shown, mutableListOf(), trust = trust)
            coordinator.start()
            try {
                assertTrue(waitForPort(coordinator) > 0)
                failing = true

                val result = pairResultOnce(coordinator, prompt, shown)

                assertEquals(PairingStatus.REJECTED, (result as ResultMessage.Status).status)
                assertEquals("A refused save must add no trust.", 0, trust.count)
                assertEquals(
                    "The commit must not overwrite a token it could not read.",
                    "token-stored",
                    target.readText(Charsets.UTF_8),
                )
                assertEquals(listOf(target.name), directory.list()?.toList())
            } finally {
                coordinator.stop()
            }
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun aTransientReadAtListenerCreationNeitherGeneratesNorSavesATokenWithTheRealStore() {
        val directory = Files.createTempDirectory("hotspotshade-pairing-read").toFile()
        try {
            val target = File(directory, "source-token.bin")
            target.writeText("token-stored", Charsets.UTF_8)
            val store = AndroidKeystoreTokenStore(
                target,
                codec = TokenOnlyCodec(),
                readFile = { throw java.io.FileNotFoundException("denied (Permission denied)") },
            )
            val generated = java.util.concurrent.atomic.AtomicInteger(0)
            val states = mutableListOf<PairingListenerState>()
            val coordinator = coordinator(
                store,
                AtomicReference<PairingPrompt?>(null),
                CountDownLatch(1),
                states,
                tokenFactory = {
                    generated.incrementAndGet()
                    "token-generated"
                },
            )
            coordinator.start()
            try {
                assertTrue(waitForState(states, PairingListenerState.TOKEN_UNREADABLE))
                assertFalse(
                    "An unreadable token is not a missing token.",
                    synchronized(states) { states.contains(PairingListenerState.LISTENING) },
                )
                assertEquals("No replacement may be generated.", 0, generated.get())
                assertEquals("token-stored", target.readText(Charsets.UTF_8))
                assertEquals(listOf(target.name), directory.list()?.toList())
            } finally {
                coordinator.stop()
            }
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun aPairingWhoseTokenIsAlreadyStoredSucceedsAndRewritesTheTarget() {
        val store = FakeStore()
        store.saved = "first-token"
        val trust = MemoryPairingTrustStore()
        val prompt = AtomicReference<PairingPrompt?>(null)
        val shown = CountDownLatch(1)
        val states = mutableListOf<PairingListenerState>()
        val coordinator = coordinator(store, prompt, shown, states, trust = trust)
        coordinator.start()
        try {
            val credentials = pairOnce(coordinator, prompt, shown)

            assertEquals("first-token", credentials.token)
            assertEquals(
                "An equal token is rewritten so a corrupt no-backup target is repaired.",
                1,
                store.saves,
            )
            assertEquals(1, trust.count)
        } finally {
            coordinator.stop()
        }
    }

    @Test
    fun aSuccessfulPairingRepairsACorruptNoBackupTarget() {
        val directory = Files.createTempDirectory("hotspotshade-pairing-token").toFile()
        try {
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeText("corrupt", Charsets.UTF_8)
            legacy.writeText("token-legacy", Charsets.UTF_8)
            val store = AndroidKeystoreTokenStore(target, legacy, TokenOnlyCodec())
            val prompt = AtomicReference<PairingPrompt?>(null)
            val shown = CountDownLatch(1)
            val states = mutableListOf<PairingListenerState>()
            val coordinator = coordinator(store, prompt, shown, states)
            coordinator.start()
            try {
                val credentials = pairOnce(coordinator, prompt, shown)

                assertEquals("token-legacy", credentials.token)
                assertEquals(
                    "A successful pairing repairs the no-backup target.",
                    "token-legacy",
                    target.readText(Charsets.UTF_8),
                )
                assertFalse(
                    "The legacy copy is removed once the target holds the token.",
                    legacy.exists(),
                )
                assertEquals("token-legacy", store.load())
            } finally {
                coordinator.stop()
            }
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun aFailedTargetRepairStillAcceptsTheSameStoredToken() {
        val store = FakeStore()
        store.saved = "first-token"
        store.failSave = true
        val trust = MemoryPairingTrustStore()
        val prompt = AtomicReference<PairingPrompt?>(null)
        val shown = CountDownLatch(1)
        val states = mutableListOf<PairingListenerState>()
        val coordinator = coordinator(store, prompt, shown, states, trust = trust)
        coordinator.start()
        try {
            val credentials = pairOnce(coordinator, prompt, shown)

            assertEquals("first-token", credentials.token)
            assertEquals(
                "A failed repair must not change the readable stored token.",
                "first-token",
                store.saved,
            )
            assertEquals(
                "A failed repair must not reject a pairing with the same token.",
                1,
                trust.count,
            )
        } finally {
            coordinator.stop()
        }
    }

    @Test
    fun anUncertainEqualTokenRepairRejectsThePairingAndReloadsTheListener() {
        val directory = Files.createTempDirectory("hotspotshade-pairing-uncertain").toFile()
        try {
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeText("token-old", Charsets.UTF_8)
            var failSync = true
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                TokenOnlyCodec(),
                syncTargetParent = { file ->
                    if (failSync) throw IOException("The target directory could not be synced.")
                    syncTokenParent(file)
                },
            )
            val guard = SourceTokenGuard()
            val epoch = guard.epoch()
            val trust = MemoryPairingTrustStore()
            val prompt = AtomicReference<PairingPrompt?>(null)
            val shown = CountDownLatch(1)
            val states = mutableListOf<PairingListenerState>()
            val scheduler = AtomicReference<java.util.concurrent.ScheduledExecutorService>()
            val saveFailures = AtomicInteger(0)
            val coordinator = coordinator(
                store,
                prompt,
                shown,
                states,
                guard = guard,
                trust = trust,
                onTokenSaveFailed = { saveFailures.incrementAndGet() },
                schedulerFactory = { trackingScheduler(scheduler) },
            )
            coordinator.start()
            try {
                assertTrue(waitForState(states, PairingListenerState.LISTENING))
                assertTrue("The periodic refresh must stop.", stopScheduler(scheduler.get()!!))
                // An older copy appears after the listener loaded the target.
                // The marker keeps the target authoritative, so the commit
                // compares the same token and repairs the target.
                legacy.writeText("token-legacy", Charsets.UTF_8)
                LegacyTokenMarker.record(legacyMarkerFileFor(target))

                val first = pairResultOnce(coordinator, prompt, shown)

                assertTrue(
                    "An uncertain save must not send a success result.",
                    first is ResultMessage.Status,
                )
                assertEquals(PairingStatus.REJECTED, (first as ResultMessage.Status).status)
                assertEquals("An uncertain save must add no trust.", 0, trust.count)
                assertEquals(
                    "The visible target keeps the token the listener sealed.",
                    "token-old",
                    target.readText(Charsets.UTF_8),
                )
                assertEquals(
                    "The kept readable copy is not deleted.",
                    "token-legacy",
                    legacy.readText(Charsets.UTF_8),
                )
                assertTrue("An uncertain write must move the guard epoch.", guard.epoch() > epoch)
                assertFalse(
                    "A result from the old epoch must not save.",
                    guard.savePairingToken(epoch) { throw AssertionError("stale write") },
                )
                // The epoch listener drops the cached token before the listener
                // can queue its token-failure callback. The visible status after
                // a reload is the accurate report, so a fixed "not saved"
                // message would be false here.
                Thread.sleep(200)
                assertEquals(
                    "A stale generation must not report a token failure.",
                    0,
                    saveFailures.get(),
                )
                assertFalse(
                    "The reloaded status must describe the readable target.",
                    synchronized(states) { states.contains(PairingListenerState.TOKEN_UNREADABLE) },
                )

                // The stale listener is still bound, but its generation can no
                // longer answer with the cached token.
                assertTrue("The stale listener stays bound until a refresh.", coordinator.localPort > 0)
                val stale = pairResultOnce(coordinator, prompt, shown)
                assertEquals(
                    PairingStatus.NOT_ACTIVE,
                    (stale as ResultMessage.Status).status,
                )
                assertEquals("The stale listener must add no trust.", 0, trust.count)

                failSync = false
                coordinator.refreshNow()
                val reloaded = pairResultPolling(coordinator, prompt)
                assertTrue("The reloaded listener must pair.", reloaded.result is ResultMessage.Ok)
                assertEquals("token-old", reloaded.credentials?.token)
                assertEquals("token-old", store.load())
                assertEquals("The reloaded listener adds the pairing trust.", 1, trust.count)
                assertEquals(
                    "No stale failure message may arrive after the reload.",
                    0,
                    saveFailures.get(),
                )
            } finally {
                coordinator.stop()
            }
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun anUncertainSaveIsReloadedByThePeriodicRefresh() {
        val directory = Files.createTempDirectory("hotspotshade-pairing-periodic").toFile()
        try {
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeText("token-old", Charsets.UTF_8)
            val failSync = java.util.concurrent.atomic.AtomicBoolean(true)
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                TokenOnlyCodec(),
                syncTargetParent = { file ->
                    if (failSync.get()) throw IOException("The target directory could not be synced.")
                    syncTokenParent(file)
                },
            )
            val prompt = AtomicReference<PairingPrompt?>(null)
            val shown = CountDownLatch(1)
            val states = mutableListOf<PairingListenerState>()
            val binds = AtomicInteger(0)
            val rebound = CountDownLatch(1)
            val trust = MemoryPairingTrustStore()
            val coordinator = coordinator(
                store, prompt, shown, states,
                trust = trust,
                afterBind = { if (binds.incrementAndGet() == 2) rebound.countDown() },
            )
            coordinator.start()
            try {
                assertTrue(waitForState(states, PairingListenerState.LISTENING))
                legacy.writeText("token-legacy", Charsets.UTF_8)
                LegacyTokenMarker.record(legacyMarkerFileFor(target))

                val first = pairResultOnce(coordinator, prompt, shown)
                assertEquals(PairingStatus.REJECTED, (first as ResultMessage.Status).status)
                assertEquals(0, trust.count)
                failSync.set(false)

                assertTrue("The scheduled refresh must replace the stale listener.",
                    rebound.await(10, TimeUnit.SECONDS))
                val reloaded = pairResultPolling(coordinator, prompt)
                assertTrue(reloaded.result is ResultMessage.Ok)
                assertEquals("token-old", reloaded.credentials?.token)
                assertEquals(1, trust.count)
            } finally {
                coordinator.stop()
            }
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun twoCoordinatorsSaveOnlyOneGeneratedToken() {
        val store = FakeStore()
        val guard = SourceTokenGuard()
        val trust = MemoryPairingTrustStore()
        val saveFailures = java.util.concurrent.atomic.AtomicInteger(0)
        val promptA = AtomicReference<PairingPrompt?>(null)
        val shownA = CountDownLatch(1)
        val promptB = AtomicReference<PairingPrompt?>(null)
        val shownB = CountDownLatch(1)
        val statesA = mutableListOf<PairingListenerState>()
        val statesB = mutableListOf<PairingListenerState>()
        val coordinatorA = coordinator(
            store,
            promptA,
            shownA,
            statesA,
            guard = guard,
            trust = trust,
            tokenFactory = { "generated-a" },
            onTokenSaveFailed = { saveFailures.incrementAndGet() },
        )
        val coordinatorB = coordinator(
            store,
            promptB,
            shownB,
            statesB,
            guard = guard,
            trust = trust,
            tokenFactory = { "generated-b" },
            onTokenSaveFailed = { saveFailures.incrementAndGet() },
        )
        coordinatorA.start()
        coordinatorB.start()
        val outcomes = java.util.Collections.synchronizedList(
            mutableListOf<PairOutcome>(),
        )
        val barrier = java.util.concurrent.CyclicBarrier(2)
        try {
            assertTrue(waitForPort(coordinatorA) > 0)
            assertTrue(waitForPort(coordinatorB) > 0)
            // Both pairings reach the prompt before either is allowed. The
            // shared guard then serializes the two commits, so one compare
            // sees the token that the other just saved.
            val first = Thread({
                outcomes += pairResultWithCredentials(coordinatorA, promptA, shownA, barrier)
            }, "pairing-a")
            val second = Thread({
                outcomes += pairResultWithCredentials(coordinatorB, promptB, shownB, barrier)
            }, "pairing-b")
            first.start()
            second.start()
            first.join(10_000)
            second.join(10_000)
            assertFalse("A pairing must not hang.", first.isAlive)
            assertFalse("A pairing must not hang.", second.isAlive)

            assertEquals("Both listeners must answer.", 2, outcomes.size)
            val ok = outcomes.filter { it.result is ResultMessage.Ok }
            val refused = outcomes.filter { it.result is ResultMessage.Status }
            assertEquals("Exactly one pairing may save a token.", 1, ok.size)
            assertEquals("The other pairing must be refused.", 1, refused.size)
            assertEquals(
                PairingStatus.REJECTED,
                (refused.single().result as ResultMessage.Status).status,
            )
            assertEquals(
                "The saved token is the one the winner sealed.",
                ok.single().credentials?.token,
                store.saved,
            )
            assertTrue(
                "The stored token must be one of the generated values.",
                store.saved == "generated-a" || store.saved == "generated-b",
            )
            assertEquals("One token, one trusted target.", 1, trust.count)
            assertEquals("The superseded listener cannot report a stale failure.", 0, saveFailures.get())
        } finally {
            coordinatorA.stop()
            coordinatorB.stop()
        }
    }

    @Test
    fun aTokenGenerationFailureReportsAGeneralFailure() {
        val store = FakeStore()
        val prompt = AtomicReference<PairingPrompt?>(null)
        val shown = CountDownLatch(1)
        val states = mutableListOf<PairingListenerState>()
        val coordinator = coordinator(
            store,
            prompt,
            shown,
            states,
            tokenFactory = { throw IllegalStateException("The random source failed.") },
        )
        coordinator.start()
        try {
            assertTrue(waitForState(states, PairingListenerState.FAILED))
            assertFalse(
                "A generation failure is not an unreadable stored token.",
                synchronized(states) { states.contains(PairingListenerState.TOKEN_UNREADABLE) },
            )
        } finally {
            coordinator.stop()
        }
    }

    @Test
    fun anOccupiedRememberedPortIsNotAdvertised() {
        val store = FakeStore()
        store.saved = "first-token"
        val portStore = PortStore(31000)
        val portProbe = FakePortProbe(free = { false }, fallback = 41234)
        val prompt = AtomicReference<PairingPrompt?>(null)
        val shown = CountDownLatch(1)
        val states = mutableListOf<PairingListenerState>()
        val coordinator = coordinator(
            store,
            prompt,
            shown,
            states,
            portStore = portStore,
            portProbe = portProbe,
        )
        coordinator.start()
        try {
            val credentials = pairOnce(coordinator, prompt, shown)
            assertEquals(
                "The pairing result must name the free replacement port.",
                41234,
                credentials.port,
            )
            assertEquals(
                "The next start must claim the advertised port.",
                41234,
                portStore.value,
            )
        } finally {
            coordinator.stop()
        }
    }

    @Test
    fun aProxyThatStartsWhilePairingIsAdvertisedAtItsBoundPort() {
        val store = FakeStore()
        store.saved = "first-token"
        val portStore = PortStore(31000)
        val prompt = AtomicReference<PairingPrompt?>(null)
        val shown = CountDownLatch(1)
        val states = mutableListOf<PairingListenerState>()
        val coordinator = coordinator(
            store,
            prompt,
            shown,
            states,
            portStore = portStore,
        )
        coordinator.start()
        try {
            assertTrue(waitForPort(coordinator) > 0)
            // The proxy starts after the pairing listener was created. The
            // listener must report the port that actually bound.
            SourceProxyRuntime.record(
                SourceProxySnapshot(
                    state = SourceProxyState.RUNNING,
                    reason = SourceProxyStopReason.NONE,
                    port = 41234,
                ),
                boundAddress = loopback,
            )

            val credentials = pairOnce(coordinator, prompt, shown)

            assertEquals(41234, credentials.port)
            assertNotEquals(
                "The pre-start reservation must not be sent after the proxy bound.",
                31000,
                credentials.port,
            )
        } finally {
            coordinator.stop()
        }
    }

    @Test
    fun aPortThatCannotBeReservedIsNotPromised() {
        val store = FakeStore()
        store.saved = "first-token"
        val portStore = PortStore(31000)
        val portProbe = FakePortProbe(free = { false }, fallback = 0)
        val prompt = AtomicReference<PairingPrompt?>(null)
        val shown = CountDownLatch(1)
        val states = mutableListOf<PairingListenerState>()
        val coordinator = coordinator(
            store,
            prompt,
            shown,
            states,
            portStore = portStore,
            portProbe = portProbe,
        )
        coordinator.start()
        try {
            val port = waitForPort(coordinator)
            assertTrue(port > 0)
            Socket().use { socket ->
                socket.soTimeout = 5_000
                socket.connect(InetSocketAddress(loopback, port), 5_000)
                val output = socket.getOutputStream()
                val target = Target()
                output.write(PairingProtocol.frame(target.hello()))
                output.flush()
                val first = readPayload(socket.getInputStream())
                val result = if ((first[0].toInt() and 0xFF) == PairingProtocol.MSG_CHALLENGE) {
                    target.acceptHostChallenge(first)
                    output.write(PairingProtocol.frame(target.reveal()))
                    output.flush()
                    PairingProtocol.decodeResult(readPayload(socket.getInputStream()))
                } else {
                    PairingProtocol.decodeResult(first)
                }

                assertTrue(
                    "An unproven port must be refused, not promised.",
                    result is ResultMessage.Status,
                )
                assertEquals(PairingStatus.NOT_ACTIVE, (result as ResultMessage.Status).status)
                assertFalse(
                    "A refused pairing must not show a prompt.",
                    shown.await(200, TimeUnit.MILLISECONDS),
                )
            }
        } finally {
            coordinator.stop()
        }
    }

    @Test
    fun aFailedTokenSaveIsReportedAndSendsNoSuccess() {
        val store = FakeStore()
        // No token is stored. The listener generates one and must write it.
        store.failSave = true
        val trust = MemoryPairingTrustStore()
        val prompt = AtomicReference<PairingPrompt?>(null)
        val shown = CountDownLatch(1)
        val states = mutableListOf<PairingListenerState>()
        val saveFailed = CountDownLatch(1)
        val coordinator = coordinator(
            store,
            prompt,
            shown,
            states,
            trust = trust,
            onTokenSaveFailed = { saveFailed.countDown() },
        )
        coordinator.start()
        try {
            val result = pairResultOnce(coordinator, prompt, shown)
            assertTrue(
                "A failed token save must send a fixed rejection, not OK.",
                result is ResultMessage.Status,
            )
            assertEquals(PairingStatus.REJECTED, (result as ResultMessage.Status).status)
            assertTrue(
                "A failed token save must be reported to the host.",
                saveFailed.await(5, TimeUnit.SECONDS),
            )
            assertEquals(
                "A failed save must write no token.",
                null,
                store.saved,
            )
            assertEquals("A failed save must add no trust.", 0, trust.count)
        } finally {
            coordinator.stop()
        }
    }

    @Test
    fun aWaitingProxyWithABoundPortIsAdvertisedAtThatPort() {
        val store = FakeStore()
        store.saved = "first-token"
        val portStore = PortStore(31000)
        // The advisory probe would pick 41234. A bound transition port must
        // win, and the probe must not run at all.
        val portProbe = FakePortProbe(free = { false }, fallback = 41234)
        val prompt = AtomicReference<PairingPrompt?>(null)
        val shown = CountDownLatch(1)
        val states = mutableListOf<PairingListenerState>()
        val coordinator = coordinator(
            store,
            prompt,
            shown,
            states,
            portStore = portStore,
            portProbe = portProbe,
        )
        coordinator.start()
        try {
            assertTrue(waitForPort(coordinator) > 0)
            SourceProxyRuntime.record(
                SourceProxySnapshot(
                    state = SourceProxyState.WAITING_FOR_NETWORK,
                    reason = SourceProxyStopReason.NONE,
                    port = 32000,
                ),
                boundAddress = loopback,
            )

            val credentials = pairOnce(coordinator, prompt, shown)

            assertEquals(32000, credentials.port)
            assertEquals(
                "A bound transition port must not overwrite the saved port.",
                31000,
                portStore.value,
            )
        } finally {
            SourceProxyRuntime.attach(null)
            coordinator.stop()
        }
    }

    @Test
    fun aStartingProxyWithoutABoundPortIsNotActive() {
        val store = FakeStore()
        store.saved = "first-token"
        val portStore = PortStore(31000)
        val portProbe = FakePortProbe(free = { true }, fallback = 41234)
        val prompt = AtomicReference<PairingPrompt?>(null)
        val shown = CountDownLatch(1)
        val states = mutableListOf<PairingListenerState>()
        val coordinator = coordinator(
            store,
            prompt,
            shown,
            states,
            portStore = portStore,
            portProbe = portProbe,
        )
        coordinator.start()
        try {
            assertTrue(waitForPort(coordinator) > 0)
            SourceProxyRuntime.record(
                SourceProxySnapshot(
                    state = SourceProxyState.WAITING_FOR_NETWORK,
                    reason = SourceProxyStopReason.NONE,
                    port = 0,
                ),
                boundAddress = loopback,
            )

            val result = pairResultOnce(coordinator, prompt, shown)

            assertTrue(
                "A start that has not bound must not promise a port.",
                result is ResultMessage.Status,
            )
            assertEquals(
                PairingStatus.NOT_ACTIVE,
                (result as ResultMessage.Status).status,
            )
            assertEquals("first-token", store.saved)
        } finally {
            SourceProxyRuntime.attach(null)
            coordinator.stop()
        }
    }

    @Test
    fun aPendingFirstReadingKeepsALiveListener() {
        val store = FakeStore()
        store.saved = "first-token"
        val finder = MutableFinder(
            HotspotProbe.Observed(
                candidates = listOf(HotspotCandidate(rank = 0, address = loopback)),
                excludedAddresses = emptySet(),
            ),
        )
        val prompt = AtomicReference<PairingPrompt?>(null)
        val shown = CountDownLatch(1)
        val states = mutableListOf<PairingListenerState>()
        val coordinator = coordinator(store, prompt, shown, states, finder = finder)
        coordinator.start()
        try {
            val port = waitForPort(coordinator)
            assertTrue(port > 0)

            finder.probeValue = HotspotProbe.Pending
            coordinator.refreshNow()

            assertEquals(
                "A pending first API 36 reading must not stop pairing.",
                port,
                coordinator.localPort,
            )
        } finally {
            coordinator.stop()
        }
    }

    @Test
    fun aRefreshExceptionDoesNotCancelTheNextRefresh() {
        var runs = 0
        var failures = 0

        runPairingRefresh(
            refresh = {
                runs += 1
                throw IllegalStateException("The finder failed.")
            },
            onFailure = { failures += 1 },
        )
        runPairingRefresh(refresh = { runs += 1 }, onFailure = { failures += 1 })

        assertEquals("The failing run must be counted once.", 1, failures)
        assertEquals("A later refresh must still run.", 2, runs)
    }

    @Test
    fun rotationIsRefusedWhileAProxyRunHoldsTheGuard() {
        val store = FakeStore()
        store.saved = "first-token"
        val guard = SourceTokenGuard()
        val prompt = AtomicReference<PairingPrompt?>(null)
        val shown = CountDownLatch(1)
        val states = mutableListOf<PairingListenerState>()
        val coordinator = coordinator(
            store,
            prompt,
            shown,
            states,
            guard = guard,
            tokenFactory = { "rotated-token" },
        )
        coordinator.start()
        try {
            assertTrue(waitForPort(coordinator) > 0)
            assertTrue(guard.beginRun())

            assertEquals(TokenRotateResult.REFUSED_RUNNING, coordinator.rotateToken())
            assertEquals("first-token", store.saved)

            guard.endRun()
            assertEquals(TokenRotateResult.ROTATED, coordinator.rotateToken())
            assertEquals("rotated-token", store.saved)
        } finally {
            guard.endRun()
            coordinator.stop()
        }
    }

    @Test
    fun uncertainRotationReloadsVisibleTokenBeforePairing() {
        val store = FakeStore().apply { saved = "first-token"; uncertainSave = true }
        val prompt = AtomicReference<PairingPrompt?>(null)
        val shown = CountDownLatch(1)
        val coordinator = coordinator(store, prompt, shown, mutableListOf(), tokenFactory = { "rotated-token" })
        coordinator.start()
        try {
            assertTrue(waitForPort(coordinator) > 0)
            assertEquals(TokenRotateResult.FAILED, coordinator.rotateToken())
            assertEquals("rotated-token", store.saved)
            assertEquals("rotated-token", pairOnce(coordinator, prompt, shown).token)
        } finally {
            coordinator.stop()
        }
    }

    @Test
    fun aRotationRebindsTheListenerWithTheNewToken() {
        val store = FakeStore()
        store.saved = "first-token"
        val prompt = AtomicReference<PairingPrompt?>(null)
        val shown = CountDownLatch(1)
        val states = mutableListOf<PairingListenerState>()
        val coordinator = coordinator(
            store,
            prompt,
            shown,
            states,
            tokenFactory = { "rotated-token" },
        )
        coordinator.start()
        try {
            assertTrue(waitForPort(coordinator) > 0)
            assertEquals(TokenRotateResult.ROTATED, coordinator.rotateToken())

            val port = waitForPort(coordinator)
            assertTrue("The listener must rebind with the new token.", port > 0)
            Socket().use { socket ->
                socket.soTimeout = 5_000
                socket.connect(InetSocketAddress(loopback, port), 5_000)
                val output = socket.getOutputStream()
                val target = Target()
                output.write(PairingProtocol.frame(target.hello()))
                output.flush()
                target.acceptHostChallenge(readPayload(socket.getInputStream()))
                output.write(PairingProtocol.frame(target.reveal()))
                output.flush()
                assertTrue(shown.await(5, TimeUnit.SECONDS))
                coordinator.allow(prompt.get()!!)
                val result = PairingProtocol.decodeResult(readPayload(socket.getInputStream()))
                assertTrue(result is ResultMessage.Ok)
                val credentials = target.openResult(result as ResultMessage.Ok)
                assertEquals("rotated-token", credentials.token)
            }
            assertEquals("rotated-token", store.saved)
        } finally {
            coordinator.stop()
        }
    }

    @Test
    fun localPortDoesNotHoldTheCoordinatorLockWhileTheListenerLockIsBusy() {
        val store = FakeStore()
        store.saved = "first-token"
        val prompt = AtomicReference<PairingPrompt?>(null)
        val shown = CountDownLatch(1)
        val states = mutableListOf<PairingListenerState>()
        val started = CountDownLatch(1)
        val getterEntered = CountDownLatch(1)
        val getterRelease = CountDownLatch(1)
        val listener = object : PairingListener {
            override val localPort: Int
                get() {
                    getterEntered.countDown()
                    getterRelease.await(5, TimeUnit.SECONDS)
                    return 23456
                }

            override fun isRunning(): Boolean = true

            override fun start() {
                started.countDown()
            }

            override fun allow(prompt: PairingPrompt): Boolean = false

            override fun deny(prompt: PairingPrompt) = Unit

            override fun activate() = Unit

            override fun deactivate() = Unit

            override fun close() = Unit
        }
        val coordinator = coordinator(
            store,
            prompt,
            shown,
            states,
            listenerFactory = { _, _, _, _, _, _ -> listener },
        )
        coordinator.start()
        try {
            assertTrue(started.await(5, TimeUnit.SECONDS))
            val portValue = java.util.concurrent.atomic.AtomicInteger(-1)
            val reader = Thread { portValue.set(coordinator.localPort) }
            reader.start()
            assertTrue(
                "The port getter must reach the listener.",
                getterEntered.await(5, TimeUnit.SECONDS),
            )
            // The getter is blocked inside the listener. A stop must still
            // take the coordinator lock, because the getter detached the
            // listener reference before it called into it.
            val stopper = Thread { coordinator.stop() }
            stopper.start()
            stopper.join(2_000)
            assertFalse(
                "The coordinator lock must not be held across a listener call.",
                stopper.isAlive,
            )
            getterRelease.countDown()
            reader.join(5_000)
            assertEquals(23456, portValue.get())
        } finally {
            getterRelease.countDown()
            coordinator.stop()
        }
    }

    @Test
    fun aDiscardedBindClosesOutsideTheCoordinatorLock() {
        val store = FakeStore()
        store.saved = "first-token"
        val prompt = AtomicReference<PairingPrompt?>(null)
        val shown = CountDownLatch(1)
        val states = mutableListOf<PairingListenerState>()
        val coordinatorRef = AtomicReference<PairingCoordinator?>(null)
        val closeEntered = CountDownLatch(1)
        val closeRelease = CountDownLatch(1)
        val listener = object : PairingListener {
            override val localPort: Int = 0

            override fun isRunning(): Boolean = false

            override fun start() {
                // Stop the coordinator while its create call is in flight. The
                // post-bind check then has to discard this listener.
                coordinatorRef.get()?.stop()
            }

            override fun allow(prompt: PairingPrompt): Boolean = false

            override fun deny(prompt: PairingPrompt) = Unit

            override fun activate() = Unit

            override fun deactivate() = Unit

            override fun close() {
                closeEntered.countDown()
                closeRelease.await(5, TimeUnit.SECONDS)
            }
        }
        val coordinator = coordinator(
            store,
            prompt,
            shown,
            states,
            listenerFactory = { _, _, _, _, _, _ -> listener },
        )
        coordinatorRef.set(coordinator)
        coordinator.start()
        try {
            assertTrue(
                "The discarded listener must be closed.",
                closeEntered.await(5, TimeUnit.SECONDS),
            )
            val portValue = java.util.concurrent.atomic.AtomicInteger(-1)
            val reader = Thread { portValue.set(coordinator.localPort) }
            reader.start()
            reader.join(2_000)
            assertFalse(
                "A close during create must not hold the coordinator lock.",
                reader.isAlive,
            )
            assertEquals(0, portValue.get())
        } finally {
            closeRelease.countDown()
            coordinator.stop()
        }
    }

    @Test
    fun aRotationRebindsBeforeAPendingPromptCanSendTheOldToken() {
        val store = FakeStore()
        store.saved = "first-token"
        val trust = MemoryPairingTrustStore()
        val prompt = AtomicReference<PairingPrompt?>(null)
        val shown = CountDownLatch(1)
        val states = mutableListOf<PairingListenerState>()
        val coordinator = coordinator(
            store,
            prompt,
            shown,
            states,
            trust = trust,
            tokenFactory = { "rotated-token" },
        )
        coordinator.start()
        try {
            val port = waitForPort(coordinator)
            assertTrue(port > 0)
            Socket().use { socket ->
                socket.soTimeout = 5_000
                socket.connect(InetSocketAddress(loopback, port), 5_000)
                val output = socket.getOutputStream()
                val target = Target()
                output.write(PairingProtocol.frame(target.hello()))
                output.flush()
                target.acceptHostChallenge(readPayload(socket.getInputStream()))
                output.write(PairingProtocol.frame(target.reveal()))
                output.flush()
                assertTrue(shown.await(5, TimeUnit.SECONDS))
                val pending = prompt.get()!!
                // Rotate while the person still sees the prompt. The old
                // listener is closed, so the prompt cannot be approved on the
                // new listener and no result is sealed for it. This covers the
                // pending prompt only: a result that committed just before
                // the rotation can already be in flight, so the epoch guards
                // the stored token, not a frame the rotation missed.
                assertEquals(TokenRotateResult.ROTATED, coordinator.rotateToken())
                coordinator.allow(pending)
            }
            assertEquals("rotated-token", store.saved)
            assertEquals("A stale result must add no trust.", 0, trust.count)
        } finally {
            coordinator.stop()
        }
    }

    @Test
    fun replacedRealListenerRejectsOldCallbacks() {
        val store = FakeStore().apply { saved = "first-token" }
        val prompt = AtomicReference<PairingPrompt?>(null)
        val failures = java.util.concurrent.atomic.AtomicInteger()
        val callbacks = java.util.Collections.synchronizedList(
            mutableListOf<Pair<(PairingPrompt?) -> Unit, () -> Unit>>()
        )
        val coordinator = coordinator(store, prompt, CountDownLatch(1), mutableListOf(),
            onTokenSaveFailed = { failures.incrementAndGet() },
            listenerFactory = { responder, address, port, onPrompt, onSuccess, onFailure ->
                callbacks.add(onPrompt to onFailure)
                com.hotspotshade.source.pairing.PairingServer(
                    responder, address, port, onPrompt, onSuccess, onFailure,
                )
            },
        )
        coordinator.start()
        try {
            assertTrue(waitForPort(coordinator) > 0)
            val old = callbacks[0]
            coordinator.reloadToken()
            assertTrue(waitForPort(coordinator) > 0)
            val fresh = callbacks[1]
            val current = PairingPrompt(com.hotspotshade.source.pairing.PromptId(10L), 20L, "123456")
            fresh.first(current)
            val stale = Thread { old.first(null); old.second() }
            stale.start()
            stale.join(5_000)
            assertFalse(stale.isAlive)
            assertTrue(waitUntil { prompt.get() == current })
            assertEquals(0, failures.get())
            fresh.second()
            assertTrue(waitUntil { failures.get() == 1 })
        } finally { coordinator.stop() }
    }

    @Test
    fun queuedOldListenerEventsCannotChangeViewModelAfterReplacement() {
        val main = java.util.concurrent.LinkedBlockingQueue<() -> Unit>()
        val worker = ArrayDeque<() -> Unit>()
        val callbacks = java.util.Collections.synchronizedList(mutableListOf<Pair<(PairingPrompt?) -> Unit, () -> Unit>>())
        lateinit var real: PairingCoordinator
        val model = PairingViewModel(android.app.Application(), PairingViewModelTestHooks(
            worker = { worker.addLast(it) }, main = { main.add(it) },
            delayed = { _, _ -> }, readTargets = { emptyList() }, useCoordinatorPublication = true,
            coordinatorFactory = { onPrompt, onState, onFailure, dispatch ->
                val store = FakeStore().apply { saved = "first-token" }
                real = PairingCoordinator(
                    finder = MutableFinder(HotspotProbe.Observed(
                        candidates = listOf(HotspotCandidate(rank = 0, address = loopback)), excludedAddresses = emptySet(),
                    )), tokenStore = store, tokenWriter = store, trust = MemoryPairingTrustStore(),
                    ports = ProxyPortPolicy(store = PortStore(), probe = FakePortProbe()),
                    onPrompt = onPrompt, onState = onState, onTokenSaveFailed = onFailure,
                    dispatchPublication = dispatch, identity = TestIdentity(), guard = SourceTokenGuard(),
                    listenerFactory = { _, _, _, prompt, _, failure ->
                        callbacks.add(prompt to failure)
                        object : PairingListener {
                            override val localPort = 1
                            override fun start() {}
                            override fun isRunning() = true
                            override fun close() {}
                            override fun allow(prompt: PairingPrompt) = error("stale approval")
                            override fun deny(prompt: PairingPrompt) = error("stale denial")
                            override fun activate() {}
                            override fun deactivate() {}
                        }
                    },
                )
                CoordinatorHandle(real)
            },
        ))
        fun drain() { main.poll(2, TimeUnit.SECONDS)?.invoke(); while (true) (main.poll() ?: break)() }
        model.setVisible(true); worker.removeFirst()()
        model.start(); worker.removeFirst()(); real.refreshNow(); drain()
        val old = callbacks.single()
        val first = PairingPrompt(com.hotspotshade.source.pairing.PromptId(100), 1, "123456")
        old.first(first); drain()
        assertEquals("123456", model.prompt?.code)
        old.first(null); old.second() // Admitted before replacement, delivered afterward.
        val delayedClear = main.poll(2, TimeUnit.SECONDS)!!
        real.reloadToken(); delayedClear(); drain()
        assertEquals(null, model.prompt)
        val fresh = callbacks[1]
        fresh.first(PairingPrompt(com.hotspotshade.source.pairing.PromptId(101), 2, "654321"))
        drain()
        assertEquals("654321", model.prompt?.code)
        assertEquals(null, model.message)
        model.allow(); real.reloadToken()
        while (worker.isNotEmpty()) worker.removeFirst()()
        drain()
        assertEquals(null, model.prompt)
        real.stop(); real.start(); real.refreshNow(); drain()
        assertEquals(RealPairingListener.LISTENING, model.status.listener)
        real.stop()
    }

    @Test
    fun aQueuedUnreadableReportIsDroppedWhenTheTokenEpochMoves() {
        val store = FakeStore().apply { saved = "first-token" }
        val guard = SourceTokenGuard()
        val dispatch = java.util.concurrent.LinkedBlockingQueue<() -> Unit>()
        val prompt = AtomicReference<PairingPrompt?>(null)
        val states = mutableListOf<PairingListenerState>()
        val scheduler = AtomicReference<java.util.concurrent.ScheduledExecutorService>()
        val coordinator = coordinator(
            store,
            prompt,
            CountDownLatch(1),
            states,
            guard = guard,
            schedulerFactory = { trackingScheduler(scheduler) },
            dispatchPublication = { dispatch.add(it) },
        )
        coordinator.start()
        try {
            assertTrue(
                "The listener must report its first state.",
                waitUntil {
                    runQueuedPublications(dispatch)
                    synchronized(states) { states.contains(PairingListenerState.LISTENING) }
                },
            )
            assertTrue("The periodic refresh must stop.", stopScheduler(scheduler.get()!!))
            store.failRead = true

            // Pair by hand: the prompt publication goes through the held lane,
            // so the test runs it before approving.
            val port = waitForPort(coordinator)
            assertTrue("The pairing listener must bind.", port > 0)
            Socket().use { socket ->
                socket.soTimeout = 5_000
                socket.connect(InetSocketAddress(loopback, port), 5_000)
                val output = socket.getOutputStream()
                val target = Target()
                output.write(PairingProtocol.frame(target.hello()))
                output.flush()
                target.acceptHostChallenge(readPayload(socket.getInputStream()))
                output.write(PairingProtocol.frame(target.reveal()))
                output.flush()
                runQueuedPublications(dispatch)
                val current = prompt.get()
                assertNotNull("The queued prompt must reach the host.", current)
                coordinator.allow(current!!)
                val result = PairingProtocol.decodeResult(readPayload(socket.getInputStream()))
                assertEquals(
                    PairingStatus.REJECTED,
                    (result as ResultMessage.Status).status,
                )
            }

            // The commit queued TOKEN_UNREADABLE for the token epoch that this
            // listener read. A rotation moves the guard before the host lane
            // runs, so the queued report describes a superseded credential and
            // must not reach the host.
            guard.invalidate()
            runQueuedPublications(dispatch)

            assertFalse(
                "A report for a superseded token epoch must not publish.",
                synchronized(states) { states.contains(PairingListenerState.TOKEN_UNREADABLE) },
            )
            assertEquals(
                "The rotation must not leave a new state to publish.",
                PairingListenerState.LISTENING,
                lastState(states),
            )

            // The next refresh reports the state of the new epoch, so the drop
            // replaces the report instead of losing it.
            coordinator.refreshNow()
            assertTrue(
                "The new epoch must report its own unreadable state.",
                waitUntil {
                    runQueuedPublications(dispatch)
                    synchronized(states) { lastState(states) == PairingListenerState.TOKEN_UNREADABLE }
                },
            )
            assertEquals("The unusable store must close the listener.", 0, coordinator.localPort)
        } finally {
            coordinator.stop()
        }
    }

    @Test
    fun aDelayedCreateAfterAnEpochChangeReportsNoListening() {
        val store = FakeStore().apply { saved = "first-token" }
        val guard = SourceTokenGuard()
        val bound = CountDownLatch(1)
        val release = CountDownLatch(1)
        val closed = CountDownLatch(1)
        val states = mutableListOf<PairingListenerState>()
        val scheduler = AtomicReference<java.util.concurrent.ScheduledExecutorService>()
        val coordinator = coordinator(
            store,
            AtomicReference<PairingPrompt?>(null),
            CountDownLatch(1),
            states,
            guard = guard,
            schedulerFactory = { trackingScheduler(scheduler) },
            listenerFactory = { _, _, _, _, _, _ ->
                object : PairingListener {
                    override val localPort: Int = 1
                    override fun isRunning() = true
                    override fun start() {
                        bound.countDown()
                        release.await(5, TimeUnit.SECONDS)
                    }
                    override fun allow(prompt: PairingPrompt) = false
                    override fun deny(prompt: PairingPrompt) = Unit
                    override fun activate() = Unit
                    override fun deactivate() = Unit
                    override fun close() = closed.countDown()
                }
            },
        )
        coordinator.start()
        try {
            assertTrue("The bind must start.", bound.await(5, TimeUnit.SECONDS))
            // A rotation lands after the token load and while the creation is
            // still binding. The delayed creation belongs to the old epoch.
            guard.invalidate()
            release.countDown()
            assertTrue("The delayed listener must be discarded.", closed.await(5, TimeUnit.SECONDS))
            assertTrue("The periodic refresh must stop.", stopScheduler(scheduler.get()!!))
            assertFalse(
                "A discarded creation must not report LISTENING.",
                synchronized(states) { states.contains(PairingListenerState.LISTENING) },
            )
            assertEquals("No listener may stay bound.", 0, coordinator.localPort)

            coordinator.refreshNow()
            assertTrue(
                "A later creation must report the new epoch as listening.",
                waitForState(states, PairingListenerState.LISTENING),
            )
        } finally {
            release.countDown()
            coordinator.stop()
        }
    }

    @Test
    fun aTokenCommitAfterTheBindDoesNotPublishListening() {
        val store = FakeStore().apply { saved = "first-token" }
        val trust = MemoryPairingTrustStore()
        val target = Target()
        trust.add(target.publicKey())
        val reveal = CountDownLatch(1)
        val committed = CountDownLatch(1)
        val boundPort = AtomicInteger(0)
        val definiteClose = CountDownLatch(1)
        val pairingError = AtomicReference<Throwable?>(null)
        val states = mutableListOf<PairingListenerState>()
        val scheduler = AtomicReference<java.util.concurrent.ScheduledExecutorService>()
        val coordinator = coordinator(
            store,
            AtomicReference<PairingPrompt?>(null),
            CountDownLatch(1),
            states,
            trust = trust,
            schedulerFactory = { trackingScheduler(scheduler) },
            listenerFactory = { responder, address, port, onPrompt, onSuccess, onFailure ->
                val inner = PairingServer(responder, address, port, onPrompt, onSuccess, onFailure)
                object : PairingListener {
                    override val localPort: Int get() = inner.localPort
                    override fun isRunning(): Boolean = inner.isRunning()
                    override fun start() {
                        inner.start()
                        boundPort.set(inner.localPort)
                    }
                    override fun allow(prompt: PairingPrompt) = inner.allow(prompt)
                    override fun deny(prompt: PairingPrompt) = inner.deny(prompt)
                    override fun activate() = inner.activate()
                    override fun deactivate() = inner.deactivate()
                    override fun close() {
                        try {
                            inner.close()
                        } finally {
                            definiteClose.countDown()
                        }
                    }
                }
            },
            afterBind = {
                // The listener is bound and the creation passed its generation
                // check. Make the stored token unreadable, then let the already
                // trusted target commit its result on this listener. The commit
                // publishes TOKEN_UNREADABLE, and the creation must not replace
                // it with LISTENING.
                store.failRead = true
                reveal.countDown()
                assertTrue("The trusted pairing must finish.", committed.await(5, TimeUnit.SECONDS))
            },
        )
        val pairing = Thread({
            try {
                assertTrue("The listener must bind.", reveal.await(5, TimeUnit.SECONDS))
                val port = boundPort.get()
                assertTrue("The bound port must be known before the reveal.", port > 0)
                Socket().use { socket ->
                    socket.soTimeout = 5_000
                    socket.connect(InetSocketAddress(loopback, port), 5_000)
                    val output = socket.getOutputStream()
                    output.write(PairingProtocol.frame(target.hello()))
                    output.flush()
                    target.acceptHostChallenge(readPayload(socket.getInputStream()))
                    output.write(PairingProtocol.frame(target.reveal()))
                    output.flush()
                    val result = PairingProtocol.decodeResult(readPayload(socket.getInputStream()))
                    assertTrue(
                        "A refused commit must send a fixed status.",
                        result is ResultMessage.Status,
                    )
                    assertEquals(PairingStatus.REJECTED, (result as ResultMessage.Status).status)
                }
            } catch (failure: Throwable) {
                pairingError.set(failure)
            } finally {
                committed.countDown()
            }
        }, "trusted-pairing")
        pairing.start()
        coordinator.start()
        try {
            assertTrue(
                "The commit must report an unreadable token.",
                waitForState(states, PairingListenerState.TOKEN_UNREADABLE),
            )
            assertFalse(
                "A delayed creation must not report LISTENING after the commit.",
                synchronized(states) { states.contains(PairingListenerState.LISTENING) },
            )
            assertEquals(
                "The unreadable report must stay the latest state.",
                PairingListenerState.TOKEN_UNREADABLE,
                lastState(states),
            )
            assertEquals("first-token", store.saved)
            assertEquals("A refused save must write no token.", 0, store.saves)
            assertTrue(
                "A refused save must not add a second trusted target.",
                trust.contains(target.publicKey()),
            )
            assertEquals("The refused save must add no trust.", 1, trust.count)
            assertTrue("The stale listener remains bound until refresh.", coordinator.localPort > 0)

            coordinator.refreshNow()
            assertEquals(
                "The unreadable store must close the stale listener.",
                0,
                coordinator.localPort,
            )
            assertTrue("The periodic refresh must stop.", stopScheduler(scheduler.get()!!))
        } finally {
            pairing.join(10_000)
            coordinator.stop()
            assertTrue("The listener must be closed.", definiteClose.await(5, TimeUnit.SECONDS))
            val failure = pairingError.get()
            if (failure != null) throw AssertionError("The trusted pairing failed.", failure)
        }
    }

    @Test
    fun trustChangedDuringTheListeningCountKeepsTheBoundListenerListening() {
        val store = FakeStore().apply { saved = "first-token" }
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val trust = BlockingTrustCountStore(entered, release)
        val states = mutableListOf<PairingListenerState>()
        val dispatch = java.util.concurrent.LinkedBlockingQueue<() -> Unit>()
        val scheduler = AtomicReference<java.util.concurrent.ScheduledExecutorService>()
        val coordinator = coordinator(
            store,
            AtomicReference<PairingPrompt?>(null),
            CountDownLatch(1),
            states,
            trust = trust,
            schedulerFactory = { trackingScheduler(scheduler) },
            dispatchPublication = { dispatch.add(it) },
        )
        coordinator.start()
        try {
            // The listener is bound, and its creation is inside the trust read
            // that precedes the LISTENING publication.
            assertTrue(
                "The creation must reach the trust read after the bind.",
                entered.await(5, TimeUnit.SECONDS),
            )
            assertTrue("The listener must already be bound.", coordinator.localPort > 0)

            // Republish while the create-time LISTENING publication is still
            // inside the count read. The state must already name the bound
            // listener, so this report is LISTENING as well and the creation's
            // now superseded report can be dropped.
            coordinator.trustChanged()
            release.countDown()
            coordinator.refreshNow()
            assertTrue("The periodic refresh must stop.", stopScheduler(scheduler.get()!!))

            assertTrue(
                "The latest state must name the bound listener.",
                waitUntil {
                    runQueuedPublications(dispatch)
                    lastState(states) == PairingListenerState.LISTENING
                },
            )
            assertEquals(
                "A stale STOPPED or NO_HOTSPOT must not stand in for a bound listener.",
                listOf(PairingListenerState.LISTENING),
                synchronized(states) { states.toList() },
            )
            assertTrue("The bound listener must stay bound.", coordinator.localPort > 0)
        } finally {
            release.countDown()
            coordinator.stop()
        }
    }

    @Test
    fun changedEpochDropsQueuedPromptAndRefusesItsDecision() {
        val guard = SourceTokenGuard()
        val queue = java.util.concurrent.LinkedBlockingQueue<() -> Unit>()
        val callbacks = java.util.concurrent.LinkedBlockingQueue<(PairingPrompt?) -> Unit>()
        val shown = AtomicReference<PairingPrompt?>(null)
        val decisions = java.util.concurrent.atomic.AtomicInteger()
        val store = FakeStore().apply { saved = "first-token" }
        val coordinator = PairingCoordinator(
            finder = MutableFinder(HotspotProbe.Observed(listOf(HotspotCandidate(0, loopback)), emptySet())),
            tokenStore = store, tokenWriter = store, trust = MemoryPairingTrustStore(),
            ports = ProxyPortPolicy(PortStore(), FakePortProbe()), onPrompt = { shown.set(it) },
            onState = { _, _ -> }, dispatchPublication = { queue.add(it) }, guard = guard,
            identity = TestIdentity(), listenerFactory = { _, _, _, prompt, _, _ ->
                callbacks.add(prompt)
                object : PairingListener {
                    override val localPort = 1
                    override fun start() {}
                    override fun isRunning() = true
                    override fun close() {}
                    override fun allow(prompt: PairingPrompt): Boolean { decisions.incrementAndGet(); return true }
                    override fun deny(prompt: PairingPrompt) { decisions.incrementAndGet() }
                    override fun activate() {}
                    override fun deactivate() {}
                }
            },
        )
        coordinator.start()
        try {
            val callback = callbacks.poll(5, TimeUnit.SECONDS)!!
            val prompt = PairingPrompt(com.hotspotshade.source.pairing.PromptId(900), 1, "123456")
            callback(prompt)
            queue.poll(5, TimeUnit.SECONDS)!!()
            assertEquals(prompt, shown.get())
            callback(prompt)
            val drain = queue.poll(5, TimeUnit.SECONDS)!!
            guard.invalidate()
            // The guard invalidates the coordinator before returning.
            coordinator.allow(prompt)
            drain()
            assertEquals(null, shown.get())
            assertEquals(0, decisions.get())
            callback(prompt)
            assertEquals(null, shown.get())
        } finally { coordinator.stop() }
    }

    @Test
    fun blockedMainQueueCoalescesRepeatedListenerEvents() {
        val queue = java.util.concurrent.LinkedBlockingQueue<() -> Unit>()
        val callbacks = java.util.concurrent.LinkedBlockingQueue<(PairingPrompt?) -> Unit>()
        val shown = AtomicReference<PairingPrompt?>(null)
        val store = FakeStore().apply { saved = "first-token" }
        val coordinator = PairingCoordinator(
            finder = MutableFinder(HotspotProbe.Observed(listOf(HotspotCandidate(0, loopback)), emptySet())),
            tokenStore = store, tokenWriter = store, trust = MemoryPairingTrustStore(),
            ports = ProxyPortPolicy(PortStore(), FakePortProbe()), onPrompt = { shown.set(it) },
            onState = { _, _ -> }, dispatchPublication = { queue.add(it) }, guard = SourceTokenGuard(),
            identity = TestIdentity(), listenerFactory = { _, _, _, prompt, _, _ ->
                callbacks.add(prompt)
                object : PairingListener {
                    override val localPort = 1
                    override fun start() {}
                    override fun isRunning() = true
                    override fun close() {}
                    override fun allow(prompt: PairingPrompt) = true
                    override fun deny(prompt: PairingPrompt) {}
                    override fun activate() {}
                    override fun deactivate() {}
                }
            },
        )
        coordinator.start()
        try {
            val callback = callbacks.poll(5, TimeUnit.SECONDS)!!
            val drain = queue.poll(5, TimeUnit.SECONDS)!!
            var last: PairingPrompt? = null
            repeat(1_000) {
                last = PairingPrompt(com.hotspotshade.source.pairing.PromptId(it.toLong()), it.toLong(), "123456")
                callback(last)
                coordinator.trustChanged()
            }
            assertTrue(queue.isEmpty())
            drain()
            assertEquals(last, shown.get())
            assertTrue(queue.isEmpty())
        } finally { coordinator.stop() }
    }

    @Test
    fun repeatedCoordinatorReplacementKeepsPublicationThreadsBounded() {
        val created = AtomicInteger(0)
        val factory = ThreadFactory { runnable ->
            Thread(
                runnable,
                "test-pairing-publication-${created.getAndIncrement()}",
            ).apply { isDaemon = true }
        }
        val dispatcher = PairingCallbackDispatcher(
            workerCount = 2,
            maxOwners = 8,
            threadFactory = factory,
        )
        val first = CountDownLatch(1)
        val second = CountDownLatch(1)
        val third = CountDownLatch(1)
        val release = CountDownLatch(1)
        val states = mutableListOf<PairingListenerState>()
        val callbacks = java.util.concurrent.LinkedBlockingQueue<(PairingPrompt?) -> Unit>()
        val coordinators = mutableListOf<PairingCoordinator>()
        try {
            repeat(3) { index ->
                val store = FakeStore().apply { saved = "token-$index" }
                val coordinator = coordinator(
                    store = store,
                    prompt = AtomicReference<PairingPrompt?>(null),
                    shown = CountDownLatch(1),
                    states = states,
                    callbackDispatcher = dispatcher,
                    promptHandler = { current ->
                        if (current != null) {
                            when (index) {
                                0 -> first.countDown()
                                1 -> second.countDown()
                                else -> third.countDown()
                            }
                            release.await(5, TimeUnit.SECONDS)
                        }
                    },
                    listenerFactory = { _, _, _, onPrompt, _, _ ->
                        callbacks.add(onPrompt)
                        object : PairingListener {
                            override val localPort = 1
                            override fun start() = Unit
                            override fun isRunning() = true
                            override fun close() = Unit
                            override fun allow(prompt: PairingPrompt) = true
                            override fun deny(prompt: PairingPrompt) = Unit
                            override fun activate() = Unit
                            override fun deactivate() = Unit
                        }
                    },
                )
                coordinators += coordinator
                coordinator.start()
                val callback = callbacks.poll(5, TimeUnit.SECONDS)
                    ?: throw AssertionError("The coordinator did not create a listener.")
                callback(PairingPrompt(com.hotspotshade.source.pairing.PromptId(300L + index), 1, "123456"))

                when (index) {
                    0 -> {
                        assertTrue("The first publication must block.", first.await(5, TimeUnit.SECONDS))
                        val stopped = CountDownLatch(1)
                        Thread {
                            coordinator.stop()
                            stopped.countDown()
                        }.start()
                        assertTrue(
                            "Stop must not wait for a blocked publication callback.",
                            stopped.await(2, TimeUnit.SECONDS),
                        )
                    }
                    1 -> assertTrue(
                        "A replacement coordinator must still publish on the bounded pool.",
                        second.await(5, TimeUnit.SECONDS),
                    )
                }
            }
            assertFalse(
                "Two blocked old coordinators leave the third publication queued.",
                third.await(300, TimeUnit.MILLISECONDS),
            )
            assertEquals("Replacement must not create a third callback thread.", 2, created.get())

            release.countDown()
            assertTrue("The queued publication must run after a worker frees.", third.await(5, TimeUnit.SECONDS))
            assertEquals("Replacement must not create a third callback thread.", 2, created.get())
            assertTrue(
                "A stop that overlapped a blocked callback must still publish STOPPED.",
                waitUntil { synchronized(states) { states.contains(PairingListenerState.STOPPED) } },
            )
        } finally {
            release.countDown()
            coordinators.forEach { it.stop() }
            dispatcher.shutdown()
        }
    }

    @Test
    fun replacementDropsOldListenerEventsWhileAPublicationIsBlocked() {
        val dispatcher = PairingCallbackDispatcher(workerCount = 1, maxOwners = 4)
        val callbacks = java.util.concurrent.LinkedBlockingQueue<(PairingPrompt?) -> Unit>()
        val shown = java.util.Collections.synchronizedList(mutableListOf<PairingPrompt>())
        val firstEntered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val store = FakeStore().apply { saved = "first-token" }
        val coordinator = PairingCoordinator(
            finder = MutableFinder(
                HotspotProbe.Observed(listOf(HotspotCandidate(0, loopback)), emptySet()),
            ),
            tokenStore = store,
            tokenWriter = store,
            trust = MemoryPairingTrustStore(),
            ports = ProxyPortPolicy(PortStore(), FakePortProbe()),
            onPrompt = { current ->
                if (current != null) {
                    shown.add(current)
                    if (shown.size == 1) {
                        firstEntered.countDown()
                        release.await(5, TimeUnit.SECONDS)
                    }
                }
            },
            onState = { _, _ -> },
            clock = { 0L },
            identity = TestIdentity(),
            pairingPort = 0,
            guard = SourceTokenGuard(),
            tokenFactory = { "rotated-token" },
            callbackDispatcher = dispatcher,
            listenerFactory = { _, _, _, onPrompt, _, _ ->
                callbacks.add(onPrompt)
                fakeListener(onPrompt)
            },
        )
        coordinator.start()
        try {
            val old = callbacks.poll(5, TimeUnit.SECONDS)
                ?: throw AssertionError("The first listener did not start.")
            val oldPrompt = PairingPrompt(com.hotspotshade.source.pairing.PromptId(500), 1, "123456")
            old(oldPrompt)
            assertTrue("The old prompt must block the publication lane.", firstEntered.await(5, TimeUnit.SECONDS))

            coordinator.reloadToken()
            val fresh = callbacks.poll(5, TimeUnit.SECONDS)
                ?: throw AssertionError("The replacement listener did not start.")
            val freshPrompt = PairingPrompt(com.hotspotshade.source.pairing.PromptId(501), 1, "654321")
            fresh(freshPrompt)
            old(PairingPrompt(com.hotspotshade.source.pairing.PromptId(502), 1, "111111"))

            release.countDown()
            assertTrue(
                "The replacement prompt must survive the blocked old callback.",
                waitUntil { synchronized(shown) { shown.contains(freshPrompt) } },
            )
            assertEquals(
                "A stale listener event must not appear after replacement.",
                listOf(oldPrompt, freshPrompt),
                synchronized(shown) { shown.toList() },
            )
        } finally {
            release.countDown()
            coordinator.stop()
            dispatcher.shutdown()
        }
    }

    @Test
    fun publicationDispatcherFailureIsRetriedByTheNextEvent() {
        val dispatcher = PairingCallbackDispatcher(workerCount = 1, maxOwners = 4)
        val states = mutableListOf<PairingListenerState>()
        val firstFailure = CountDownLatch(1)
        val queued = java.util.concurrent.LinkedBlockingQueue<() -> Unit>()
        val failFirst = java.util.concurrent.atomic.AtomicBoolean(true)
        val store = FakeStore().apply { saved = "first-token" }
        val coordinator = PairingCoordinator(
            finder = MutableFinder(
                HotspotProbe.Observed(listOf(HotspotCandidate(0, loopback)), emptySet()),
            ),
            tokenStore = store,
            tokenWriter = store,
            trust = MemoryPairingTrustStore(),
            ports = ProxyPortPolicy(PortStore(), FakePortProbe()),
            onPrompt = { },
            onState = { state, _ -> synchronized(states) { states.add(state) } },
            dispatchPublication = { action ->
                if (failFirst.getAndSet(false)) {
                    firstFailure.countDown()
                    throw IllegalStateException("The host dispatcher failed.")
                }
                queued.add(action)
            },
            clock = { 0L },
            identity = TestIdentity(),
            pairingPort = 0,
            guard = SourceTokenGuard(),
            tokenFactory = { "rotated-token" },
            callbackDispatcher = dispatcher,
            listenerFactory = { _, _, _, onPrompt, _, _ -> fakeListener(onPrompt) },
        )
        coordinator.start()
        try {
            assertTrue("The first publication must fail.", firstFailure.await(5, TimeUnit.SECONDS))
            coordinator.refreshNow()

            // The failure is reported before the dispatcher wrapper clears its
            // scheduling flag. Retry on later events until one is admitted.
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
            var drain = queued.poll()
            while (drain == null && System.nanoTime() < deadline) {
                coordinator.trustChanged()
                drain = queued.poll(20, TimeUnit.MILLISECONDS)
            }
            checkNotNull(drain) { "The next event must retry publication." }
            drain()
            assertTrue(
                "A retried publication must still report the listener state.",
                waitUntil { synchronized(states) { states.contains(PairingListenerState.LISTENING) } },
            )
        } finally {
            coordinator.stop()
            while (true) {
                val action = queued.poll(200, TimeUnit.MILLISECONDS) ?: break
                action()
            }
            dispatcher.shutdown()
        }
    }

    @Test
    fun hostCallbackCanReenterWhileAnotherThreadStops() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val stopped = CountDownLatch(1)
        val callbackDone = CountDownLatch(1)
        val callbacks = java.util.concurrent.LinkedBlockingQueue<(PairingPrompt?) -> Unit>()
        val store = FakeStore().apply { saved = "first-token" }
        lateinit var coordinator: PairingCoordinator
        coordinator = PairingCoordinator(
            finder = MutableFinder(HotspotProbe.Observed(listOf(HotspotCandidate(0, loopback)), emptySet())),
            tokenStore = store, tokenWriter = store, trust = MemoryPairingTrustStore(),
            ports = ProxyPortPolicy(PortStore(), FakePortProbe()), onPrompt = { prompt ->
                if (prompt != null) {
                    entered.countDown()
                    release.await(5, TimeUnit.SECONDS)
                    coordinator.refreshNow()
                    callbackDone.countDown()
                }
            }, onState = { _, _ -> }, guard = SourceTokenGuard(), identity = TestIdentity(),
            listenerFactory = { _, _, _, prompt, _, _ ->
                callbacks.add(prompt)
                object : PairingListener {
                    override val localPort = 1
                    override fun start() {}
                    override fun isRunning() = true
                    override fun close() {}
                    override fun allow(prompt: PairingPrompt) = true
                    override fun deny(prompt: PairingPrompt) {}
                    override fun activate() {}
                    override fun deactivate() {}
                }
            },
        )
        coordinator.start()
        try {
            callbacks.poll(5, TimeUnit.SECONDS)!!(PairingPrompt(com.hotspotshade.source.pairing.PromptId(901), 1, "123456"))
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            val stopper = Thread { coordinator.stop(); stopped.countDown() }
            stopper.start()
            assertTrue("Stop must not wait for host callback.", stopped.await(5, TimeUnit.SECONDS))
            release.countDown()
            assertTrue(callbackDone.await(5, TimeUnit.SECONDS))
            stopper.join(5_000)
        } finally { release.countDown(); coordinator.stop() }
    }

    @Test
    fun aConcurrentRotationCannotAttachTheOlderTokenToTheNewerEpoch() {
        val store = FakeStore().apply { saved = "first-token" }
        val guard = SourceTokenGuard()
        val prompt = AtomicReference<PairingPrompt?>(null)
        val admin = AtomicReference<PairingAdmin?>(null)
        val adminResult = AtomicReference<TokenRotateResult?>(null)
        val coordinator = coordinator(
            store,
            prompt,
            CountDownLatch(1),
            mutableListOf(),
            guard = guard,
            tokenFactory = { "coordinator-token" },
            afterRotationWrite = { adminResult.set(admin.get()!!.rotateToken()) },
        )
        admin.set(
            PairingAdmin(
                trust = MemoryPairingTrustStore(),
                tokenStore = store,
                tokenFactory = { "admin-token" },
                isProxyActive = { false },
                guard = guard,
            ),
        )
        coordinator.start()
        try {
            assertTrue(waitForPort(coordinator) > 0)
            assertEquals(TokenRotateResult.ROTATED, coordinator.rotateToken())
            assertEquals("The interleaved rotation must write.", TokenRotateResult.ROTATED, adminResult.get())
            assertEquals("admin-token", store.saved)

            coordinator.refreshNow()

            // The coordinator must reload the store under the guard instead of
            // caching its own older value under the epoch the admin rotation
            // now owns.
            assertEquals(
                "The next pairing must carry the stored token.",
                "admin-token",
                pairResultPolling(coordinator, prompt).credentials?.token,
            )
            assertEquals("admin-token", store.saved)
        } finally {
            coordinator.stop()
        }
    }

    @Test
    fun aFailedSchedulerStartDoesNotLeaveTheCoordinatorRunning() {
        var attempts = 0
        val states = mutableListOf<PairingListenerState>()
        val prompt = AtomicReference<PairingPrompt?>(null)
        fun workingScheduler(): java.util.concurrent.ScheduledExecutorService =
            java.util.concurrent.Executors.newSingleThreadScheduledExecutor { runnable ->
                Thread(runnable, "test-pairing-coordinator-retry").apply { isDaemon = true }
            }
        val coordinator = coordinator(
            FakeStore().apply { saved = "first-token" },
            prompt,
            CountDownLatch(1),
            states,
            schedulerFactory = {
                attempts += 1
                when (attempts) {
                    1 -> throw IllegalStateException("The scheduler could not start.")
                    // A factory that returns a stopped executor makes
                    // scheduleWithFixedDelay throw after creation.
                    2 -> workingScheduler().apply { shutdownNow() }
                    else -> workingScheduler()
                }
            },
        )
        coordinator.start()
        try {
            assertTrue(
                "A scheduler that cannot start must report one fixed failure.",
                waitForState(states, PairingListenerState.FAILED),
            )
            assertEquals("No listener may stay bound without a scheduler.", 0, coordinator.localPort)

            coordinator.start()
            assertEquals(
                "A scheduler that rejects its task must not bind a listener.",
                0,
                coordinator.localPort,
            )

            coordinator.start()
            assertTrue("A later start must bind the listener.", waitForPort(coordinator) > 0)
        } finally {
            coordinator.stop()
        }
    }

    @Test
    fun aThrowingStateCallbackDoesNotWedgeTheStoppedPublication() {
        val states = java.util.Collections.synchronizedList(mutableListOf<PairingListenerState>())
        val coordinator = coordinator(
            FakeStore().apply { saved = "first-token" },
            AtomicReference<PairingPrompt?>(null),
            CountDownLatch(1),
            mutableListOf(),
            stateHandler = { state, _ ->
                if (state == PairingListenerState.LISTENING) {
                    throw AssertionError("The host state callback failed.")
                }
                states.add(state)
                Unit
            },
        )
        coordinator.start()
        try {
            assertTrue(waitForPort(coordinator) > 0)
            coordinator.stop()
            assertTrue(
                "A throwing state callback must not strand the stopped state.",
                waitUntil { synchronized(states) { states.contains(PairingListenerState.STOPPED) } },
            )
        } finally {
            coordinator.stop()
        }
    }

    @Test
    fun aRefusedPublicationIsDeliveredWhenALaneFrees() {
        val dispatcher = PairingCallbackDispatcher(workerCount = 1, maxOwners = 1)
        val blocker = Any()
        val blockerEntered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val states = mutableListOf<PairingListenerState>()
        assertTrue(
            dispatcher.dispatch(blocker) {
                blockerEntered.countDown()
                release.await(5, TimeUnit.SECONDS)
            },
        )
        assertTrue(blockerEntered.await(5, TimeUnit.SECONDS))
        val coordinator = coordinator(
            FakeStore().apply { saved = "first-token" },
            AtomicReference<PairingPrompt?>(null),
            CountDownLatch(1),
            states,
            callbackDispatcher = dispatcher,
            listenerFactory = { _, _, _, _, _, _ -> fakeListener { } },
        )
        coordinator.start()
        try {
            assertTrue(waitForPort(coordinator) > 0)
            coordinator.stop()
            assertFalse(
                "The stopped state must not publish while the lane is full.",
                synchronized(states) { states.contains(PairingListenerState.STOPPED) },
            )

            // No coordinator event follows the release.
            release.countDown()
            assertTrue(
                "The retry ticket must publish the last state when room opens.",
                waitUntil { synchronized(states) { states.contains(PairingListenerState.STOPPED) } },
            )
            assertEquals(
                "The stopped state must be the published state, not a stale start.",
                0,
                synchronized(states) { states.count { it == PairingListenerState.LISTENING } },
            )
        } finally {
            release.countDown()
            coordinator.stop()
            dispatcher.shutdown()
        }
    }

    private fun fakeListener(onPrompt: (PairingPrompt?) -> Unit): PairingListener =
        object : PairingListener {
            override val localPort = 1
            override fun start() = Unit
            override fun isRunning() = true
            override fun close() = Unit
            override fun allow(prompt: PairingPrompt) = true
            override fun deny(prompt: PairingPrompt) = Unit
            override fun activate() = Unit
            override fun deactivate() = Unit
        }

    private fun waitUntil(condition: () -> Boolean): Boolean {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (System.nanoTime() < deadline) {
            if (condition()) return true
            Thread.yield()
        }
        return condition()
    }

    /** A scheduler whose handle a test can stop after the first state arrives. */
    private fun trackingScheduler(
        ref: AtomicReference<java.util.concurrent.ScheduledExecutorService>,
    ): java.util.concurrent.ScheduledExecutorService =
        java.util.concurrent.Executors.newSingleThreadScheduledExecutor { runnable ->
            Thread(runnable, "test-pairing-coordinator").apply { isDaemon = true }
        }.also { ref.set(it) }

    /**
     * Stop the periodic refresh and wait for a running one to finish.
     *
     * A test that asserts on the latest state needs no refresh after the first
     * one. Waiting for termination keeps a refresh in flight from publishing a
     * second state later.
     */
    private fun stopScheduler(scheduler: java.util.concurrent.ScheduledExecutorService): Boolean {
        scheduler.shutdown()
        return scheduler.awaitTermination(5, TimeUnit.SECONDS)
    }

    /** The last state that the host received. */
    private fun lastState(states: MutableList<PairingListenerState>): PairingListenerState? =
        synchronized(states) { states.lastOrNull() }

    /** Run every publication that a controlled dispatcher queued. */
    private fun runQueuedPublications(queue: java.util.concurrent.BlockingQueue<() -> Unit>) {
        while (true) {
            val action = queue.poll(20, TimeUnit.MILLISECONDS) ?: return
            action()
        }
    }

    private fun waitForState(
        states: MutableList<PairingListenerState>,
        expected: PairingListenerState,
    ): Boolean {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (System.nanoTime() < deadline) {
            if (synchronized(states) { states.contains(expected) }) return true
            Thread.sleep(20)
        }
        return synchronized(states) { states.contains(expected) }
    }

    private fun <T> coordinator(
        store: T,
        prompt: AtomicReference<PairingPrompt?>,
        shown: CountDownLatch,
        states: MutableList<PairingListenerState>,
        guard: SourceTokenGuard = SourceTokenGuard(),
        tokenFactory: () -> String = { "rotated-token" },
        finder: HotspotAddressFinder = MutableFinder(
            HotspotProbe.Observed(
                candidates = listOf(HotspotCandidate(rank = 0, address = loopback)),
                excludedAddresses = emptySet(),
            ),
        ),
        portStore: PortStore = PortStore(),
        portProbe: FakePortProbe = FakePortProbe(),
        trust: PairingTrustStore = MemoryPairingTrustStore(),
        onTokenSaveFailed: () -> Unit = {},
        callbackDispatcher: PairingCallbackDispatcher = PairingCallbackDispatcher.shared,
        promptHandler: ((PairingPrompt?) -> Unit)? = null,
        stateHandler: ((PairingListenerState, Int) -> Unit)? = null,
        schedulerFactory: () -> java.util.concurrent.ScheduledExecutorService = {
            java.util.concurrent.Executors.newSingleThreadScheduledExecutor { runnable ->
                Thread(runnable, "test-pairing-coordinator").apply { isDaemon = true }
            }
        },
        afterRotationWrite: () -> Unit = {},
        afterBind: () -> Unit = {},
        dispatchPublication: (() -> Unit) -> Unit = { it() },
        listenerFactory: (
            PairingResponder,
            InetAddress,
            Int,
            (PairingPrompt?) -> Unit,
            () -> Unit,
            () -> Unit,
        ) -> PairingListener = { responder, address, port, onPrompt, onSuccess, onTokenFailed ->
            com.hotspotshade.source.pairing.PairingServer(
                responder = responder,
                bindAddress = address,
                port = port,
                onPromptChanged = onPrompt,
                onPairingSucceeded = onSuccess,
                onTokenCommitFailed = onTokenFailed,
                callbackDispatcher = callbackDispatcher,
            )
        },
    ): PairingCoordinator where T : TokenStore, T : TokenWriter = PairingCoordinator(
        finder = finder,
        tokenStore = store,
        tokenWriter = store,
        trust = trust,
        ports = ProxyPortPolicy(store = portStore, probe = portProbe),
        onPrompt = promptHandler ?: { current ->
            prompt.set(current)
            if (current != null) shown.countDown()
        },
        onState = stateHandler ?: { state, _ ->
            synchronized(states) { states.add(state) }
            Unit
        },
        onTokenSaveFailed = onTokenSaveFailed,
        clock = { 0L },
        identity = TestIdentity(),
        pairingPort = 0,
        guard = guard,
        tokenFactory = tokenFactory,
        callbackDispatcher = callbackDispatcher,
        schedulerFactory = schedulerFactory,
        afterRotationWrite = afterRotationWrite,
        afterBind = afterBind,
        dispatchPublication = dispatchPublication,
        listenerFactory = listenerFactory,
    )

    /** Run one full pairing and return the credentials that the result sealed. */
    private fun pairOnce(
        coordinator: PairingCoordinator,
        prompt: AtomicReference<PairingPrompt?>,
        shown: CountDownLatch,
    ): PairingCredentials {
        val port = waitForPort(coordinator)
        assertTrue("The pairing listener must bind.", port > 0)
        Socket().use { socket ->
            socket.soTimeout = 5_000
            socket.connect(InetSocketAddress(loopback, port), 5_000)
            val output = socket.getOutputStream()
            val target = Target()
            output.write(PairingProtocol.frame(target.hello()))
            output.flush()
            target.acceptHostChallenge(readPayload(socket.getInputStream()))
            output.write(PairingProtocol.frame(target.reveal()))
            output.flush()
            assertTrue("The real prompt must appear.", shown.await(5, TimeUnit.SECONDS))
            val current = prompt.get()
            assertNotNull(current)
            coordinator.allow(current!!)
            val result = PairingProtocol.decodeResult(readPayload(socket.getInputStream()))
            assertTrue(result is ResultMessage.Ok)
            return target.openResult(result as ResultMessage.Ok)
        }
    }

    /** Run one full pairing and return the decoded result, Ok or Status. */
    private fun pairResultOnce(
        coordinator: PairingCoordinator,
        prompt: AtomicReference<PairingPrompt?>,
        shown: CountDownLatch,
    ): ResultMessage {
        val port = waitForPort(coordinator)
        assertTrue("The pairing listener must bind.", port > 0)
        Socket().use { socket ->
            socket.soTimeout = 5_000
            socket.connect(InetSocketAddress(loopback, port), 5_000)
            val output = socket.getOutputStream()
            val target = Target()
            output.write(PairingProtocol.frame(target.hello()))
            output.flush()
            val first = readPayload(socket.getInputStream())
            if ((first[0].toInt() and 0xFF) != PairingProtocol.MSG_CHALLENGE) {
                return PairingProtocol.decodeResult(first)
                    ?: throw AssertionError("The listener sent an unreadable result.")
            }
            target.acceptHostChallenge(first)
            output.write(PairingProtocol.frame(target.reveal()))
            output.flush()
            // A refusal may arrive without a prompt.
            val promptResult = awaitPromptOrResult(prompt, shown, socket)
            if (promptResult != null) return promptResult
            val current = prompt.get()
            assertNotNull(current)
            coordinator.allow(current!!)
            return PairingProtocol.decodeResult(readPayload(socket.getInputStream()))
                ?: throw AssertionError("The listener sent an unreadable result.")
        }
    }

    /**
     * Run one pairing and wait for a fresh prompt by polling.
     *
     * A test that pairs twice on one coordinator cannot reuse a latch that the
     * first prompt already released.
     */
    private fun pairResultPolling(
        coordinator: PairingCoordinator,
        prompt: AtomicReference<PairingPrompt?>,
    ): PairOutcome {
        prompt.set(null)
        val port = waitForPort(coordinator)
        assertTrue("The pairing listener must bind.", port > 0)
        Socket().use { socket ->
            socket.soTimeout = 10_000
            socket.connect(InetSocketAddress(loopback, port), 5_000)
            val output = socket.getOutputStream()
            val target = Target()
            output.write(PairingProtocol.frame(target.hello()))
            output.flush()
            target.acceptHostChallenge(readPayload(socket.getInputStream()))
            output.write(PairingProtocol.frame(target.reveal()))
            output.flush()
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
            while (prompt.get() == null && System.nanoTime() < deadline) Thread.sleep(20)
            val current = prompt.get()
            assertNotNull("The real prompt must appear.", current)
            coordinator.allow(current!!)
            val result = PairingProtocol.decodeResult(readPayload(socket.getInputStream()))
                ?: throw AssertionError("The listener sent an unreadable result.")
            return when (result) {
                is ResultMessage.Ok -> PairOutcome(result, target.openResult(result))
                is ResultMessage.Status -> PairOutcome(result, null)
            }
        }
    }

    /** One pairing result and the credentials that its sealed result opened. */
    private class PairOutcome(
        val result: ResultMessage,
        val credentials: PairingCredentials?,
    )

    /**
     * Run one pairing and wait at [barrier] after the prompt appears.
     *
     * Two coordinators can then approve together, so their guarded token saves
     * contend in a fixed way.
     */
    private fun pairResultWithCredentials(
        coordinator: PairingCoordinator,
        prompt: AtomicReference<PairingPrompt?>,
        shown: CountDownLatch,
        barrier: java.util.concurrent.CyclicBarrier,
    ): PairOutcome {
        val port = waitForPort(coordinator)
        assertTrue("The pairing listener must bind.", port > 0)
        Socket().use { socket ->
            socket.soTimeout = 10_000
            socket.connect(InetSocketAddress(loopback, port), 5_000)
            val output = socket.getOutputStream()
            val target = Target()
            output.write(PairingProtocol.frame(target.hello()))
            output.flush()
            target.acceptHostChallenge(readPayload(socket.getInputStream()))
            output.write(PairingProtocol.frame(target.reveal()))
            output.flush()
            assertTrue("The real prompt must appear.", shown.await(5, TimeUnit.SECONDS))
            barrier.await(5, TimeUnit.SECONDS)
            coordinator.allow(prompt.get()!!)
            val result = PairingProtocol.decodeResult(readPayload(socket.getInputStream()))
                ?: throw AssertionError("The listener sent an unreadable result.")
            return when (result) {
                is ResultMessage.Ok -> PairOutcome(result, target.openResult(result))
                is ResultMessage.Status -> PairOutcome(result, null)
            }
        }
    }

    /**
     * Wait for a prompt. When the listener refuses instead, return the
     * decoded status so a test can assert NOT_ACTIVE.
     */
    private fun awaitPromptOrResult(
        prompt: AtomicReference<PairingPrompt?>,
        shown: CountDownLatch,
        socket: Socket,
    ): ResultMessage? {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
        while (System.nanoTime() < deadline) {
            if (shown.await(20, TimeUnit.MILLISECONDS)) return null
            if (prompt.get() == null && socket.getInputStream().available() > 0) {
                return PairingProtocol.decodeResult(readPayload(socket.getInputStream()))
            }
        }
        if (shown.await(1, TimeUnit.SECONDS)) return null
        if (socket.getInputStream().available() > 0) {
            return PairingProtocol.decodeResult(readPayload(socket.getInputStream()))
        }
        throw AssertionError("The listener sent neither a prompt nor a result.")
    }

    private fun waitForPort(coordinator: PairingCoordinator): Int {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (System.nanoTime() < deadline) {
            val port = coordinator.localPort
            if (port > 0) return port
            Thread.sleep(20)
        }
        return 0
    }

    private fun readPayload(input: InputStream): ByteArray {
        val stream = DataInputStream(input)
        val length = stream.readUnsignedShort()
        assertTrue(length > 0)
        val payload = ByteArray(length)
        stream.readFully(payload)
        return payload
    }

    private class TokenOnlyCodec : TokenFileCodec {
        override fun encode(token: String): ByteArray = token.toByteArray(Charsets.UTF_8)

        override fun decode(bytes: ByteArray): String {
            val value = bytes.toString(Charsets.UTF_8)
            if (!value.startsWith("token-")) {
                throw TokenReadException(
                    "The source token file is not valid.",
                    kind = TokenReadKind.CORRUPT,
                )
            }
            return value
        }
    }

    private class FakeStore : TokenStore, TokenWriter {
        @Volatile
        var saved: String? = null

        @Volatile
        var failRead = false

        @Volatile
        var failSave = false

        @Volatile
        var uncertainSave = false

        @Volatile
        var saves = 0

        override fun load(): String? {
            if (failRead) throw TokenReadException("The stored token cannot be read.")
            return saved
        }

        override fun save(token: String) {
            if (failSave) throw IllegalStateException("The token store cannot be written.")
            saved = token
            if (uncertainSave) {
                uncertainSave = false
                throw TokenWriteUncertainException(java.io.IOException("sync"))
            }
            saves += 1
        }
    }

    /**
     * A trust store whose count blocks one call.
     *
     * The coordinator reads the trusted count outside its lock before it
     * publishes a state. A test holds the create-time LISTENING publication
     * inside that read so it can interleave another publication.
     */
    private class BlockingTrustCountStore(
        private val entered: CountDownLatch,
        private val release: CountDownLatch,
    ) : PairingTrustStore {
        private val blockedOnce = java.util.concurrent.atomic.AtomicBoolean(true)
        private val keys = java.util.Collections.synchronizedSet(mutableSetOf<String>())

        override fun contains(publicKey: ByteArray): Boolean =
            keys.contains(PairingProtocol.hex(publicKey))

        override fun add(publicKey: ByteArray) {
            keys.add(PairingProtocol.hex(publicKey))
        }

        override fun remove(publicKey: ByteArray) {
            keys.remove(PairingProtocol.hex(publicKey))
        }

        override val count: Int
            get() {
                if (blockedOnce.compareAndSet(true, false)) {
                    entered.countDown()
                    release.await(5, TimeUnit.SECONDS)
                }
                return synchronized(keys) { keys.size }
            }
    }

    private class PortStore(var value: Int = 0) : ProxyPortStore {
        override fun load(): Int = value

        override fun save(port: Int) {
            value = port
        }

        override fun clear() {
            value = 0
        }
    }

    private class FakePortProbe(
        private val free: (Int) -> Boolean = { true },
        private val fallback: Int = 0,
    ) : PortProbe {
        override fun isFree(address: InetAddress, port: Int): Boolean = free(port)

        override fun freePort(address: InetAddress): Int = fallback
    }

    private class MutableFinder(initial: HotspotProbe) : HotspotAddressFinder {
        @Volatile
        var probeValue: HotspotProbe = initial

        override fun probe(): HotspotProbe = probeValue
    }

    private class TestIdentity : PairingIdentity {
        private var counter = 0

        override fun ephemeralSecret(): ByteArray = ByteArray(32) { 0x33 }

        override fun nonce(): ByteArray {
            val value = ByteArray(12) { 0x44 }
            value[1] = counter.toByte()
            counter += 1
            return value
        }
    }

    private inner class Target {
        private val lSSecret = ByteArray(32) { 0x11 }
        private val lEPrivate = ByteArray(32) { 0x22 }
        private val lS = X25519.publicKey(lSSecret)!!
        private val lE = X25519.publicKey(lEPrivate)!!
        private var pE: ByteArray? = null
        private var keys: PairingKeys? = null

        fun hello(): ByteArray =
            PairingProtocol.encodeHello(lS, PairingProtocol.commitment(lE, lS))

        /** The claimed static key, for a trust store that already knows it. */
        fun publicKey(): ByteArray = lS.copyOf()

        fun acceptHostChallenge(payload: ByteArray) {
            val decoded = PairingProtocol.decodeChallenge(payload)
            if (decoded !is ChallengeOrResult.Challenge) {
                throw AssertionError("The app did not send a challenge.")
            }
            pE = decoded.pE
        }

        fun reveal(): ByteArray {
            val publicEphemeral = pE ?: throw AssertionError("No challenge.")
            val ee = X25519.agree(lEPrivate, publicEphemeral)!!
            val es = X25519.agree(lSSecret, publicEphemeral)!!
            val derived = PairingProtocol.deriveKeys(
                ee,
                es,
                PairingProtocol.transcriptHash(lS, lE, publicEphemeral),
            )
            ee.fill(0)
            es.fill(0)
            keys = derived
            return PairingProtocol.encodeReveal(lE, PairingProtocol.laptopProof(derived))
        }

        fun openResult(message: ResultMessage.Ok): PairingCredentials =
            PairingProtocol.openCredentials(keys!!, message.nonce, message.ciphertext)
    }
}
