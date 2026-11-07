package com.hotspotshade.source.pairing

import java.io.DataInputStream
import java.io.IOException
import java.io.InputStream
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ThreadFactory
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Loopback tests for the real pairing listener. They bind the loopback
 * address and port 0. They open no route and use no hotspot or carrier.
 */
class PairingServerTest {
    private val loopback = InetAddress.getByName("127.0.0.1")
    private val token = "server-test-token-0123456789"
    private val host = loopback as Inet4Address
    private val credentials = PairingCredentials.create(host, 1080, token)!!
    private val clock = AtomicLong(0)

    @Test
    fun closeBeforeStartPreventsLaterStart() {
        val server = PairingServer(responder(MemoryPairingTrustStore()), loopback, 0, {})
        server.close()
        try {
            server.start()
            throw AssertionError("A closed listener must not start")
        } catch (_: IllegalStateException) {
            assertFalse(server.isRunning())
            assertEquals(0, server.localPort)
        }
    }

    @Test
    fun promptClearsBeforeBlockedResultWriteCompletes() {
        val prompt = AtomicReference<PairingPrompt?>()
        val shown = CountDownLatch(1)
        val cleared = CountDownLatch(1)
        val writing = CountDownLatch(1)
        val release = CountDownLatch(1)
        val writes = AtomicInteger()
        val trust = MemoryPairingTrustStore()
        val server = PairingServer(
            responder(trust), loopback, 0,
            onPromptChanged = { if (it == null) cleared.countDown() else { prompt.set(it); shown.countDown() } },
            writeFrames = { socket, frames ->
                if (frames.isNotEmpty() && writes.incrementAndGet() == 2) {
                    writing.countDown()
                    check(release.await(5, TimeUnit.SECONDS))
                } else {
                    frames.forEach { socket.getOutputStream().write(it) }
                    socket.getOutputStream().flush()
                }
            },
        )
        server.start()
        try {
            Socket(loopback, server.localPort).use { socket ->
                socket.soTimeout = 5_000
                val target = ClientTarget()
                socket.getOutputStream().write(PairingProtocol.frame(target.hello()))
                target.acceptHostChallenge(readPayload(socket.getInputStream()))
                socket.getOutputStream().write(PairingProtocol.frame(target.reveal()))
                assertTrue(shown.await(5, TimeUnit.SECONDS))
                val approval = Thread { server.allow(prompt.get()!!) }
                approval.start()
                assertTrue(writing.await(5, TimeUnit.SECONDS))
                assertTrue("Prompt clears while the result write is blocked", cleared.await(5, TimeUnit.SECONDS))
                assertEquals(1, trust.count)
                release.countDown()
                approval.join(5_000)
                assertFalse(approval.isAlive)
            }
        } finally { release.countDown(); server.close() }
    }

    @Test
    fun stopDuringResultWriteSuppressesSuccessCallback() {
        val trust = MemoryPairingTrustStore()
        val prompt = AtomicReference<PairingPrompt?>(null)
        val shown = CountDownLatch(1)
        val writingResult = CountDownLatch(1)
        val releaseWrite = CountDownLatch(1)
        val finished = CountDownLatch(1)
        val succeeded = AtomicInteger(0)
        val result = AtomicReference<Boolean?>(null)
        val writes = AtomicInteger(0)
        val server = PairingServer(
            responder = responder(trust), bindAddress = loopback, port = 0,
            onPromptChanged = { current ->
                prompt.set(current)
                if (current != null) shown.countDown()
            },
            onPairingSucceeded = { succeeded.incrementAndGet() },
            writeFrames = { socket, frames ->
                if (frames.isNotEmpty() && writes.incrementAndGet() == 2) {
                    writingResult.countDown()
                    check(releaseWrite.await(5, TimeUnit.SECONDS))
                    // Model a local write that completed as stop closed the socket.
                } else {
                    val stream = socket.getOutputStream()
                    frames.forEach { stream.write(it) }
                    stream.flush()
                }
            },
        )
        server.start()
        try {
            Socket().use { socket ->
                socket.soTimeout = 5_000
                socket.connect(InetSocketAddress(loopback, server.localPort), 5_000)
                val target = ClientTarget()
                socket.getOutputStream().write(PairingProtocol.frame(target.hello()))
                socket.getOutputStream().flush()
                target.acceptHostChallenge(readPayload(socket.getInputStream()))
                socket.getOutputStream().write(PairingProtocol.frame(target.reveal()))
                socket.getOutputStream().flush()
                assertTrue(shown.await(5, TimeUnit.SECONDS))
                val approval = Thread {
                    try { result.set(server.allow(prompt.get()!!)) } finally { finished.countDown() }
                }
                approval.start()
                assertTrue(writingResult.await(5, TimeUnit.SECONDS))
                val stop = Thread { server.close() }
                stop.start()
                val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
                while (server.isRunning() && System.nanoTime() < deadline) Thread.yield()
                assertFalse(server.isRunning())
                releaseWrite.countDown()
                assertTrue(finished.await(5, TimeUnit.SECONDS))
                stop.join(5_000)
                assertFalse(stop.isAlive)
                assertEquals(false, result.get())
                assertEquals(0, succeeded.get())
                assertEquals(1, trust.count)
            }
        } finally {
            releaseWrite.countDown()
            server.close()
        }
    }

    @Test
    fun failedResultWriteDoesNotReportSuccessButRetainsApprovedTrust() {
        val trust = MemoryPairingTrustStore()
        val prompt = AtomicReference<PairingPrompt?>(null)
        val shown = CountDownLatch(1)
        val succeeded = AtomicInteger(0)
        val writes = AtomicInteger(0)
        val server = PairingServer(
            responder = responder(trust),
            bindAddress = loopback,
            port = 0,
            onPromptChanged = { current ->
                prompt.set(current)
                if (current != null) shown.countDown()
            },
            onPairingSucceeded = { succeeded.incrementAndGet() },
            writeFrames = { socket, frames ->
                if (frames.isNotEmpty() && writes.incrementAndGet() == 2) {
                    throw IOException("injected result failure")
                }
                val stream = socket.getOutputStream()
                frames.forEach { stream.write(it) }
                stream.flush()
            },
        )
        server.start()
        try {
            Socket().use { socket ->
                socket.soTimeout = 5_000
                socket.connect(InetSocketAddress(loopback, server.localPort), 5_000)
                val target = ClientTarget()
                socket.getOutputStream().write(PairingProtocol.frame(target.hello()))
                socket.getOutputStream().flush()
                target.acceptHostChallenge(readPayload(socket.getInputStream()))
                socket.getOutputStream().write(PairingProtocol.frame(target.reveal()))
                socket.getOutputStream().flush()
                assertTrue(shown.await(5, TimeUnit.SECONDS))
                assertFalse(server.allow(prompt.get()!!))
                assertEquals(-1, socket.getInputStream().read())
                assertEquals(0, succeeded.get())
                // The v1 responder commits trust before sending the result.
                // A write failure cannot undo an already approved record.
                assertEquals(1, trust.count)
            }
        } finally {
            server.close()
        }
    }

    @Test
    fun allowSendsCredentialsAndRaisesTheSuccessCallback() {
        val trust = MemoryPairingTrustStore()
        val responder = responder(trust)
        val prompt = AtomicReference<PairingPrompt?>(null)
        val shown = CountDownLatch(1)
        val succeeded = AtomicInteger(0)
        val successNotified = CountDownLatch(1)
        val server = PairingServer(
            responder = responder,
            bindAddress = loopback,
            port = 0,
            onPromptChanged = { current ->
                prompt.set(current)
                if (current != null) shown.countDown()
            },
            onPairingSucceeded = { succeeded.incrementAndGet(); successNotified.countDown() },
        )
        server.start()
        try {
            assertTrue(server.localPort > 0)
            Socket().use { socket ->
                socket.soTimeout = 5_000
                socket.connect(InetSocketAddress(loopback, server.localPort), 5_000)
                val output = socket.getOutputStream()
                val target = ClientTarget()
                output.write(PairingProtocol.frame(target.hello()))
                output.flush()
                target.acceptHostChallenge(readPayload(socket.getInputStream()))

                output.write(PairingProtocol.frame(target.reveal()))
                output.flush()
                assertTrue("The prompt must appear.", shown.await(5, TimeUnit.SECONDS))
                assertNotNull(prompt.get())
                assertFalse(prompt.get()!!.toString().contains(prompt.get()!!.code))

                assertTrue(server.allow(prompt.get()!!))
                val result = readPayload(socket.getInputStream())
                val decoded = PairingProtocol.decodeResult(result)
                assertTrue(decoded is ResultMessage.Ok)
                val received = target.openResult(decoded as ResultMessage.Ok)
                assertEquals(token, received.token)
                assertEquals(1080, received.port)
                assertEquals(host, received.host)
            }
            assertTrue(successNotified.await(5, TimeUnit.SECONDS))
            assertEquals(1, succeeded.get())
            assertEquals(1, trust.count)
        } finally {
            server.close()
        }
    }

    @Test
    fun denySendsDeniedWithoutTrustOrSuccess() {
        val trust = MemoryPairingTrustStore()
        val responder = responder(trust)
        val prompt = AtomicReference<PairingPrompt?>(null)
        val shown = CountDownLatch(1)
        val succeeded = AtomicInteger(0)
        val server = PairingServer(
            responder = responder,
            bindAddress = loopback,
            port = 0,
            onPromptChanged = { current ->
                prompt.set(current)
                if (current != null) shown.countDown()
            },
            onPairingSucceeded = { succeeded.incrementAndGet() },
        )
        server.start()
        try {
            Socket().use { socket ->
                socket.soTimeout = 5_000
                socket.connect(InetSocketAddress(loopback, server.localPort), 5_000)
                val output = socket.getOutputStream()
                val target = ClientTarget()
                output.write(PairingProtocol.frame(target.hello()))
                output.flush()
                target.acceptHostChallenge(readPayload(socket.getInputStream()))
                output.write(PairingProtocol.frame(target.reveal()))
                output.flush()
                assertTrue(shown.await(5, TimeUnit.SECONDS))
                server.deny(prompt.get()!!)
                val result = readPayload(socket.getInputStream())
                val decoded = PairingProtocol.decodeResult(result)
                assertEquals(PairingStatus.DENIED, (decoded as ResultMessage.Status).status)
            }
            assertEquals(0, succeeded.get())
            assertEquals(0, trust.count)
        } finally {
            server.close()
        }
    }

    @Test
    fun aBadFirstFrameGetsOneRejectedResultAndAClose() {
        val trust = MemoryPairingTrustStore()
        val responder = responder(trust)
        val server = PairingServer(
            responder = responder,
            bindAddress = loopback,
            port = 0,
            onPromptChanged = { },
            onPairingSucceeded = { },
        )
        server.start()
        try {
            Socket().use { socket ->
                socket.soTimeout = 5_000
                socket.connect(InetSocketAddress(loopback, server.localPort), 5_000)
                val output = socket.getOutputStream()
                output.write(PairingProtocol.frame(byteArrayOf(1, 2, 3)))
                output.flush()
                val result = readPayload(socket.getInputStream())
                val decoded = PairingProtocol.decodeResult(result)
                assertEquals(PairingStatus.REJECTED, (decoded as ResultMessage.Status).status)
                assertEquals(-1, socket.getInputStream().read())
            }
        } finally {
            server.close()
        }
    }

    @Test
    fun idleConnectionsDoNotBlockAValidClient() {
        val responder = responder(MemoryPairingTrustStore())
        val server = PairingServer(
            responder = responder,
            bindAddress = loopback,
            port = 0,
            onPromptChanged = { },
            onPairingSucceeded = { },
        )
        server.start()
        val idle = mutableListOf<Socket>()
        try {
            repeat(8) {
                val socket = Socket()
                socket.connect(InetSocketAddress(loopback, server.localPort), 3_000)
                idle += socket
            }
            Thread.sleep(1_000)

            Socket().use { ninth ->
                ninth.soTimeout = 5_000
                ninth.connect(InetSocketAddress(loopback, server.localPort), 3_000)
                ninth.getOutputStream().write(PairingProtocol.frame(validHello()))
                ninth.getOutputStream().flush()
                val payload = readPayload(ninth.getInputStream())
                assertEquals(
                    "An idle set must not block a real target device.",
                    PairingProtocol.MSG_CHALLENGE,
                    payload[0].toInt() and 0xFF,
                )
            }
        } finally {
            for (socket in idle) {
                try {
                    socket.close()
                } catch (_: Exception) {
                    // The test is ending.
                }
            }
            server.close()
        }
    }

    @Test
    fun anIdleConnectionIsClosedAtTheDeadline() {
        val server = PairingServer(
            responder = responder(MemoryPairingTrustStore()),
            bindAddress = loopback,
            port = 0,
            onPromptChanged = { },
            onPairingSucceeded = { },
            idleTimeoutMillis = 400,
        )
        server.start()
        try {
            Socket().use { socket ->
                socket.soTimeout = 5_000
                socket.connect(InetSocketAddress(loopback, server.localPort), 3_000)
                assertEquals(
                    "The listener must close a connection that sends no frame.",
                    -1,
                    socket.getInputStream().read(),
                )
            }
        } finally {
            server.close()
        }
    }

    @Test
    fun connectionWorkQueueRejectsChurnWhenWorkersAreBlocked() {
        val entered = CountDownLatch(8)
        val release = CountDownLatch(1)
        val server = PairingServer(
            responder = responder(MemoryPairingTrustStore()),
            bindAddress = loopback,
            port = 0,
            onPromptChanged = { },
            connectionThreadFactory = java.util.concurrent.ThreadFactory { task ->
                Thread {
                    entered.countDown()
                    try {
                        release.await()
                        task.run()
                    } catch (_: InterruptedException) {
                        Thread.currentThread().interrupt()
                    }
                }.apply { isDaemon = true }
            },
        )
        val sockets = mutableListOf<Socket>()
        server.start()
        try {
            repeat(8) {
                sockets += Socket().apply { connect(InetSocketAddress(loopback, server.localPort), 3_000) }
            }
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            repeat(16) {
                sockets += Socket().apply { connect(InetSocketAddress(loopback, server.localPort), 3_000) }
            }
            val last = sockets.last()
            last.soTimeout = 5_000
            assertEquals("A saturated work queue must reject new sockets.", -1, last.getInputStream().read())
        } finally {
            server.close()
            release.countDown()
            sockets.forEach { it.close() }
        }
    }

    @Test
    fun deactivateGivesAnUnknownSessionTheInactiveDeadline() {
        val responder = responder(MemoryPairingTrustStore())
        val server = PairingServer(
            responder = responder,
            bindAddress = loopback,
            port = 0,
            onPromptChanged = { },
            onPairingSucceeded = { },
        )
        server.start()
        try {
            server.deactivate()
            Socket().use { socket ->
                socket.soTimeout = 5_000
                socket.connect(InetSocketAddress(loopback, server.localPort), 3_000)
                val output = socket.getOutputStream()
                val target = ClientTarget()
                output.write(PairingProtocol.frame(target.hello()))
                output.flush()
                target.acceptHostChallenge(readPayload(socket.getInputStream()))
                output.write(PairingProtocol.frame(target.reveal()))
                output.flush()
                assertTrue(
                    "A hidden app gets the 120 second inactive deadline.",
                    waitForDeadline(responder, 120_000L),
                )
            }
        } finally {
            server.close()
        }
    }

    @Test
    fun activateGivesAnUnknownSessionTheActiveDeadline() {
        val responder = responder(MemoryPairingTrustStore())
        val server = PairingServer(
            responder = responder,
            bindAddress = loopback,
            port = 0,
            onPromptChanged = { },
            onPairingSucceeded = { },
        )
        server.start()
        try {
            server.activate()
            Socket().use { socket ->
                socket.soTimeout = 5_000
                socket.connect(InetSocketAddress(loopback, server.localPort), 3_000)
                val output = socket.getOutputStream()
                val target = ClientTarget()
                output.write(PairingProtocol.frame(target.hello()))
                output.flush()
                target.acceptHostChallenge(readPayload(socket.getInputStream()))
                output.write(PairingProtocol.frame(target.reveal()))
                output.flush()
                assertTrue(
                    "A visible app gets the 60 second active deadline.",
                    waitForDeadline(responder, 60_000L),
                )
            }
        } finally {
            server.close()
        }
    }

    @Test
    fun aThrowingHostCallbackDoesNotBreakTheListener() {
        val trust = MemoryPairingTrustStore()
        val responder = responder(trust)
        val prompt = AtomicReference<PairingPrompt?>(null)
        val shown = CountDownLatch(1)
        val server = PairingServer(
            responder = responder,
            bindAddress = loopback,
            port = 0,
            onPromptChanged = { current ->
                prompt.set(current)
                if (current != null) shown.countDown()
                throw IllegalStateException("The host callback failed.")
            },
            onPairingSucceeded = { throw IllegalStateException("The host callback failed.") },
        )
        server.start()
        try {
            Socket().use { socket ->
                socket.soTimeout = 5_000
                socket.connect(InetSocketAddress(loopback, server.localPort), 5_000)
                val output = socket.getOutputStream()
                val target = ClientTarget()
                output.write(PairingProtocol.frame(target.hello()))
                output.flush()
                target.acceptHostChallenge(readPayload(socket.getInputStream()))
                output.write(PairingProtocol.frame(target.reveal()))
                output.flush()
                assertTrue("The prompt must still reach the host.", shown.await(5, TimeUnit.SECONDS))
                assertNotNull(prompt.get())
                assertTrue(server.allow(prompt.get()!!))
                val result = PairingProtocol.decodeResult(readPayload(socket.getInputStream()))
                assertTrue(result is ResultMessage.Ok)
            }
        } finally {
            server.close()
        }
    }

    @Test
    fun blockedPromptIsFollowedByCloseClearAndCloseDoesNotWait() {
        val prompt = AtomicReference<PairingPrompt?>()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val cleared = CountDownLatch(1)
        val events = java.util.Collections.synchronizedList(mutableListOf<String>())
        val server = PairingServer(
            responder = responder(MemoryPairingTrustStore()), bindAddress = loopback, port = 0,
            onPromptChanged = { current ->
                if (current != null) {
                    prompt.set(current)
                    entered.countDown()
                    release.await(5, TimeUnit.SECONDS)
                    events.add("prompt")
                } else {
                    events.add("clear")
                    cleared.countDown()
                }
            },
        )
        server.start()
        try {
            Socket(loopback, server.localPort).use { socket ->
                socket.soTimeout = 5_000
                val target = ClientTarget()
                socket.getOutputStream().write(PairingProtocol.frame(target.hello()))
                target.acceptHostChallenge(readPayload(socket.getInputStream()))
                socket.getOutputStream().write(PairingProtocol.frame(target.reveal()))
                assertTrue(entered.await(5, TimeUnit.SECONDS))
                assertTrue(server.allow(prompt.get()!!))
                val stopped = CountDownLatch(1)
                Thread { server.close(); stopped.countDown() }.start()
                assertTrue(stopped.await(2, TimeUnit.SECONDS))
                release.countDown()
                assertTrue(cleared.await(5, TimeUnit.SECONDS))
                assertEquals(listOf("prompt", "clear"), events.toList())
            }
        } finally {
            release.countDown()
            server.close()
        }
    }

    @Test
    fun successCallbackCanWaitForClose() {
        val prompt = AtomicReference<PairingPrompt?>()
        val shown = CountDownLatch(1)
        val done = CountDownLatch(1)
        val closeFinished = AtomicReference(false)
        lateinit var server: PairingServer
        server = PairingServer(
            responder = responder(MemoryPairingTrustStore()), bindAddress = loopback, port = 0,
            onPromptChanged = { if (it != null) { prompt.set(it); shown.countDown() } },
            onPairingSucceeded = {
                val closed = CountDownLatch(1)
                Thread { server.close(); closed.countDown() }.start()
                closeFinished.set(closed.await(2, TimeUnit.SECONDS))
                done.countDown()
            },
        )
        server.start()
        try {
            Socket(loopback, server.localPort).use { socket ->
                socket.soTimeout = 5_000
                val target = ClientTarget()
                socket.getOutputStream().write(PairingProtocol.frame(target.hello()))
                target.acceptHostChallenge(readPayload(socket.getInputStream()))
                socket.getOutputStream().write(PairingProtocol.frame(target.reveal()))
                assertTrue(shown.await(5, TimeUnit.SECONDS))
                assertTrue(server.allow(prompt.get()!!))
                assertTrue(done.await(5, TimeUnit.SECONDS))
                assertTrue(closeFinished.get())
            }
        } finally { server.close() }
    }

    @Test
    fun repeatedListenerReplacementKeepsCallbackThreadsBounded() {
        val created = AtomicInteger(0)
        val factory = ThreadFactory { runnable ->
            Thread(
                runnable,
                "test-pairing-server-callback-${created.getAndIncrement()}",
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
        val servers = mutableListOf<PairingServer>()
        val sockets = mutableListOf<Socket>()
        try {
            repeat(3) { index ->
                val server = PairingServer(
                    responder(MemoryPairingTrustStore()),
                    loopback,
                    0,
                    onPromptChanged = { current ->
                        if (current != null) {
                            when (index) {
                                0 -> first.countDown()
                                1 -> second.countDown()
                                else -> third.countDown()
                            }
                            release.await(5, TimeUnit.SECONDS)
                        }
                    },
                    callbackDispatcher = dispatcher,
                )
                servers += server
                server.start()
                val socket = Socket(loopback, server.localPort).apply { soTimeout = 5_000 }
                sockets += socket
                val target = ClientTarget()
                socket.getOutputStream().write(PairingProtocol.frame(target.hello()))
                target.acceptHostChallenge(readPayload(socket.getInputStream()))
                socket.getOutputStream().write(PairingProtocol.frame(target.reveal()))

                if (index < 2) {
                    val shown = if (index == 0) first else second
                    assertTrue("Listener $index must show its prompt.", shown.await(5, TimeUnit.SECONDS))
                    assertEquals("A blocked old callback must not add a thread.", 2, created.get())
                }
                if (index == 0) {
                    // Close while the first callback still holds a worker.
                    server.close()
                }
            }
            assertFalse(
                "Both workers are blocked, so the third prompt waits in the bounded queue.",
                third.await(300, TimeUnit.MILLISECONDS),
            )
            assertEquals("Replacement must not create a third callback thread.", 2, created.get())

            release.countDown()
            assertTrue("The queued prompt must run after a worker frees.", third.await(5, TimeUnit.SECONDS))
            assertEquals("Replacement must not create a third callback thread.", 2, created.get())
        } finally {
            release.countDown()
            sockets.forEach { runCatching { it.close() } }
            servers.forEach { it.close() }
            dispatcher.shutdown()
        }
    }

    @Test
    fun closeClearIsDeliveredAfterSaturationWithoutAnotherEvent() {
        val dispatcher = PairingCallbackDispatcher(workerCount = 1, maxOwners = 1)
        val blocker = Any()
        val blockerEntered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val prompts = AtomicInteger(0)
        val cleared = CountDownLatch(1)
        val responder = responder(MemoryPairingTrustStore())
        val server = PairingServer(
            responder = responder,
            bindAddress = loopback,
            port = 0,
            onPromptChanged = { current ->
                if (current == null) cleared.countDown() else prompts.incrementAndGet()
            },
            callbackDispatcher = dispatcher,
        )
        assertTrue(
            dispatcher.dispatch(blocker) {
                blockerEntered.countDown()
                release.await(5, TimeUnit.SECONDS)
            },
        )
        assertTrue(blockerEntered.await(5, TimeUnit.SECONDS))
        server.start()
        try {
            Socket(loopback, server.localPort).use { socket ->
                socket.soTimeout = 5_000
                val target = ClientTarget()
                socket.getOutputStream().write(PairingProtocol.frame(target.hello()))
                target.acceptHostChallenge(readPayload(socket.getInputStream()))
                socket.getOutputStream().write(PairingProtocol.frame(target.reveal()))

                assertTrue(
                    "The responder must hold a prompt before close.",
                    waitUntil { responder.pendingPrompt() != null },
                )
                assertEquals("A refused lane must deliver no prompt callback.", 0, prompts.get())

                val stopped = CountDownLatch(1)
                Thread {
                    server.close()
                    stopped.countDown()
                }.start()
                assertTrue("Close must not wait for the callback dispatcher.", stopped.await(2, TimeUnit.SECONDS))
                assertEquals("The prompt and clear must coalesce into no prompt.", 0, prompts.get())

                // No listener event follows. The retry ticket must deliver the
                // close clear as soon as the blocking lane finishes.
                release.countDown()
                assertTrue("The close clear must survive saturation.", cleared.await(5, TimeUnit.SECONDS))
                assertEquals(0, prompts.get())
                assertTrue(waitUntil { dispatcher.retryOwnerCount() == 0 })
            }
        } finally {
            release.countDown()
            server.close()
            dispatcher.shutdown()
        }
    }

    @Test
    fun refusedPromptIsDeliveredAfterSaturationWithoutAnotherEvent() {
        val dispatcher = PairingCallbackDispatcher(workerCount = 1, maxOwners = 1)
        val blocker = Any()
        val blockerEntered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val prompt = AtomicReference<PairingPrompt?>()
        val shown = CountDownLatch(1)
        val server = PairingServer(
            responder = responder(MemoryPairingTrustStore()),
            bindAddress = loopback,
            port = 0,
            onPromptChanged = { current ->
                if (current != null) {
                    prompt.set(current)
                    shown.countDown()
                }
            },
            callbackDispatcher = dispatcher,
        )
        assertTrue(
            dispatcher.dispatch(blocker) {
                blockerEntered.countDown()
                release.await(5, TimeUnit.SECONDS)
            },
        )
        assertTrue(blockerEntered.await(5, TimeUnit.SECONDS))
        server.start()
        try {
            Socket(loopback, server.localPort).use { socket ->
                socket.soTimeout = 5_000
                val target = ClientTarget()
                socket.getOutputStream().write(PairingProtocol.frame(target.hello()))
                target.acceptHostChallenge(readPayload(socket.getInputStream()))
                socket.getOutputStream().write(PairingProtocol.frame(target.reveal()))
                assertFalse("A saturated lane must delay the prompt.", shown.await(200, TimeUnit.MILLISECONDS))

                // No listener event follows the release.
                release.countDown()
                assertTrue(
                    "The pending prompt must publish when a worker frees.",
                    shown.await(5, TimeUnit.SECONDS),
                )
                assertNotNull(prompt.get())
            }
        } finally {
            release.countDown()
            server.close()
            dispatcher.shutdown()
        }
    }

    @Test
    fun aThrowingPromptErrorDoesNotWedgeTheCallbackLane() {
        val cleared = CountDownLatch(1)
        val prompts = AtomicInteger(0)
        val server = PairingServer(
            responder = responder(MemoryPairingTrustStore()),
            bindAddress = loopback,
            port = 0,
            onPromptChanged = { current ->
                if (current == null) {
                    cleared.countDown()
                } else {
                    prompts.incrementAndGet()
                    throw AssertionError("The host prompt callback failed.")
                }
            },
        )
        server.start()
        try {
            Socket(loopback, server.localPort).use { socket ->
                socket.soTimeout = 5_000
                val target = ClientTarget()
                socket.getOutputStream().write(PairingProtocol.frame(target.hello()))
                target.acceptHostChallenge(readPayload(socket.getInputStream()))
                socket.getOutputStream().write(PairingProtocol.frame(target.reveal()))
                assertTrue("The prompt callback must run once.", waitUntil { prompts.get() == 1 })
            }
        } finally {
            server.close()
        }
        assertTrue(
            "A throwing prompt callback must not strand the close clear.",
            cleared.await(5, TimeUnit.SECONDS),
        )
    }

    @Test
    fun tokenFailureNotifiesAfterRejectedConnectionCloses() {
        val prompt = AtomicReference<PairingPrompt?>()
        val shown = CountDownLatch(1)
        val notified = CountDownLatch(1)
        val resultSocket = AtomicReference<Socket>()
        val closedAtCallback = AtomicReference(false)
        val trust = MemoryPairingTrustStore()
        val failing = PairingResponder(
            trust = trust, credentials = { credentials },
            status = { ProxyStatus(false, true, 0, 1080, host) },
            identity = ServerIdentity(), clock = { clock.get() }, commitToken = { false },
        )
        val server = PairingServer(
            responder = failing, bindAddress = loopback, port = 0,
            onPromptChanged = { if (it != null) { prompt.set(it); shown.countDown() } },
            onTokenCommitFailed = { closedAtCallback.set(resultSocket.get().isClosed); notified.countDown() },
            writeFrames = { socket, frames ->
                resultSocket.set(socket)
                frames.forEach { socket.getOutputStream().write(it) }
                socket.getOutputStream().flush()
            },
        )
        server.start()
        try {
            Socket(loopback, server.localPort).use { socket ->
                socket.soTimeout = 5_000
                val target = ClientTarget()
                socket.getOutputStream().write(PairingProtocol.frame(target.hello()))
                target.acceptHostChallenge(readPayload(socket.getInputStream()))
                socket.getOutputStream().write(PairingProtocol.frame(target.reveal()))
                assertTrue(shown.await(5, TimeUnit.SECONDS))
                assertFalse(server.allow(prompt.get()!!))
                assertTrue(PairingProtocol.decodeResult(readPayload(socket.getInputStream())) is ResultMessage.Status)
                assertEquals(-1, socket.getInputStream().read())
                assertTrue(notified.await(5, TimeUnit.SECONDS))
                assertTrue(closedAtCallback.get())
                assertEquals(0, trust.count)
            }
        } finally { server.close() }
    }

    private fun waitUntil(condition: () -> Boolean): Boolean {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (System.nanoTime() < deadline) {
            if (condition()) return true
            Thread.sleep(10)
        }
        return condition()
    }

    private fun waitForDeadline(responder: PairingResponder, expected: Long): Boolean {
        val deadline = System.nanoTime() + 5_000_000_000L
        while (System.nanoTime() < deadline) {
            if (currentDeadline(responder) == expected) return true
            Thread.sleep(20)
        }
        return currentDeadline(responder) == expected
    }

    // The server owns the responder and may change its session map on the
    // connection thread. Concurrent inspection is not a production path, so a
    // read that collides with an update is retried instead of failing the test.
    private fun currentDeadline(responder: PairingResponder): Long? = try {
        responder.nextDeadline()
    } catch (_: java.util.ConcurrentModificationException) {
        null
    }

    private fun validHello(): ByteArray = PairingProtocol.encodeHello(
        ByteArray(32) { 0x11 },
        ByteArray(32) { 0x22 },
    )

    private fun responder(trust: PairingTrustStore): PairingResponder = PairingResponder(
        trust = trust,
        credentials = { credentials },
        status = {
            ProxyStatus(
                proxyRunning = false,
                foreground = true,
                connections = 0,
                port = 1080,
                host = host,
            )
        },
        identity = ServerIdentity(),
        clock = { clock.get() },
    )

    private fun readPayload(input: InputStream): ByteArray {
        val stream = DataInputStream(input)
        val length = stream.readUnsignedShort()
        assertTrue("The frame must not be empty.", length > 0)
        val payload = ByteArray(length)
        stream.readFully(payload)
        return payload
    }

    private class ServerIdentity : PairingIdentity {
        private var nonceCounter = 0

        override fun ephemeralSecret(): ByteArray = ByteArray(32) { 0x33 }

        override fun nonce(): ByteArray {
            val value = ByteArray(12) { 0x44 }
            value[1] = nonceCounter.toByte()
            nonceCounter += 1
            return value
        }
    }

    private inner class ClientTarget {
        private val lSSecret = ByteArray(32) { 0x11 }
        private val lESecret = ByteArray(32) { 0x22 }
        private val lS = X25519.publicKey(lSSecret)!!
        private val lE = X25519.publicKey(lESecret)!!
        private var pE: ByteArray? = null
        private var keys: PairingKeys? = null

        fun hello(): ByteArray =
            PairingProtocol.encodeHello(lS, PairingProtocol.commitment(lE, lS))

        fun acceptHostChallenge(payload: ByteArray) {
            val decoded = PairingProtocol.decodeChallenge(payload)
            if (decoded !is ChallengeOrResult.Challenge) {
                throw AssertionError("The source device did not send a challenge.")
            }
            pE = decoded.pE
        }

        fun reveal(): ByteArray {
            val publicEphemeral = pE ?: throw AssertionError("No challenge.")
            val ee = X25519.agree(lESecret, publicEphemeral)!!
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
