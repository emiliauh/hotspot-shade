package com.hotspotshade.source

import java.io.IOException
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SourceProxyControllerTest {
    private class FakeSelection : CellularNetworkSelection {
        lateinit var callback: CellularNetworkSelection.Listener
        var starts = 0
        var stops = 0

        override fun start(listener: CellularNetworkSelection.Listener) {
            starts += 1
            callback = listener
        }

        override fun stop() {
            stops += 1
        }
    }

    private class FakeBinding : CellularBinding {
        override fun requireAvailable() = Unit
        override fun bind(socket: Socket) = Unit
        override fun bind(socket: DatagramSocket) = Unit
    }

    private class FakeFinder(var address: InetAddress?) : HotspotAddressFinder {
        var calls = 0
        var probeFactory: (() -> HotspotProbe)? = null

        override fun probe(): HotspotProbe {
            calls += 1
            probeFactory?.let { return it() }
            val current = address
            return if (current == null) {
                HotspotProbe.Observed(emptyList(), emptySet())
            } else {
                HotspotProbe.Observed(
                    candidates = listOf(HotspotCandidate(rank = 0, address = current)),
                    excludedAddresses = emptySet(),
                )
            }
        }
    }

    private class FakeTokenStore(var token: String?) : TokenStore {
        override fun load(): String? = token
    }

    private class FakeServer(private val failStart: Boolean) : SourceServerHandle {
        var starts = 0
        var stops = 0
        var closed = false
        var open = 0
        var total = 0L
        var onStart: (() -> Unit)? = null
        var onClose: (() -> Unit)? = null

        @Volatile
        var running = false

        @Volatile
        var failureLabel: String? = null

        override val localPort: Int = PORT

        override val activeConnections: Int get() = open

        override val totalConnections: Long get() = total

        override val isRunning: Boolean get() = running

        override val failureReason: String? get() = failureLabel

        override fun start() {
            onStart?.invoke()
            if (failStart) throw IOException("The listener cannot bind.")
            starts += 1
            running = true
        }

        override fun close() {
            onClose?.invoke()
            stops += 1
            closed = true
            open = 0
            running = false
        }

        fun failListener(label: String) {
            running = false
            failureLabel = label
        }
    }

    private class ManualHealthMonitor(
        private val onFailure: () -> Unit,
    ) : SourceServerHealthMonitor {
        var started = false
        var closed = false
        var failStart = false

        override fun start() {
            if (failStart) throw IllegalStateException("The health monitor cannot start.")
            started = true
        }

        override fun close() {
            closed = true
        }

        fun fail() {
            onFailure()
        }
    }

    private class ManualHealthFactory : SourceServerHealthMonitorFactory {
        val monitors = CopyOnWriteArrayList<ManualHealthMonitor>()
        var failStart = false

        override fun create(
            server: SourceServerHandle,
            onFailure: () -> Unit,
        ): SourceServerHealthMonitor = ManualHealthMonitor(onFailure).also {
            it.failStart = failStart
            monitors += it
        }
    }

    private class FakeWatch(private val failStart: Boolean) : HotspotWatch {
        var started = false
        var stops = 0
        var lost: (() -> Unit)? = null

        override fun start(onLost: () -> Unit) {
            if (failStart) throw IllegalStateException("The watch cannot start.")
            started = true
            lost = onLost
        }

        override fun stop() {
            stops += 1
        }

        fun lose() {
            lost?.invoke()
        }
    }

    private class RecordingListener : SourceProxyListener {
        val snapshots = CopyOnWriteArrayList<SourceProxySnapshot>()

        override fun onStateChanged(snapshot: SourceProxySnapshot) {
            snapshots += snapshot
        }

        val terminals: List<SourceProxySnapshot>
            get() = snapshots.filter { it.state == SourceProxyState.STOPPED }
    }

    private class Harness(
        hotspot: InetAddress? = HOTSPOT,
        token: String? = TOKEN,
        failBind: Boolean = false,
        failResolver: Boolean = false,
        failWatch: Boolean = false,
        finderOverride: HotspotAddressFinder? = null,
        clockMillisOverride: (() -> Long)? = null,
        sleepMillisOverride: ((Long) -> Unit)? = null,
        tokenGuard: SourceTokenGuard = SourceTokenGuard(),
        healthFactory: ManualHealthFactory = ManualHealthFactory(),
        writer: TokenWriter? = null,
        tokenStoreOverride: TokenStore? = null,
        newToken: (() -> String)? = null,
    ) {
        val selection = FakeSelection()
        val binding = FakeBinding()
        val finder = FakeFinder(hotspot)
        private val effectiveFinder = finderOverride ?: finder
        val tokenStore = FakeTokenStore(token)
        val listener = RecordingListener()
        val guard = tokenGuard
        val health = healthFactory
        val queue = ManualSourceProxyTaskQueue()
        val servers = CopyOnWriteArrayList<FakeServer>()
        val watches = CopyOnWriteArrayList<FakeWatch>()
        val requestedAddresses = CopyOnWriteArrayList<InetAddress>()
        val requestedTokens = CopyOnWriteArrayList<String>()
        val resolverCalls = AtomicInteger()
        var beforeResolver: (() -> Unit)? = null
        var beforeWatchFactory: (() -> Unit)? = null
        var configureServer: ((FakeServer) -> Unit)? = null
        var configureWatch: ((FakeWatch) -> Unit)? = null
        var nowMillis = 0L
        private val failBindValue = failBind
        private val failWatchValue = failWatch

        val controller = SourceProxyController(
            tokenStore = tokenStoreOverride ?: tokenStore,
            hotspotFinder = effectiveFinder,
            selectionFactory = { selection },
            resolverFactory = {
                beforeResolver?.invoke()
                resolverCalls.incrementAndGet()
                if (failResolver) throw IOException("The resolver cannot start.")
                SourceHostResolver { emptyList() }
            },
            echoFactory = {
                SourceEchoSender { _, _, _ -> EchoResult(EchoStatus.FAILED) }
            },
            serverFactory = { _, _, _, address, serverToken ->
                requestedTokens += serverToken
                requestedAddresses += address
                FakeServer(failBindValue).also {
                    configureServer?.invoke(it)
                    servers += it
                }
            },
            watchFactory = {
                beforeWatchFactory?.invoke()
                FakeWatch(failWatchValue).also {
                    configureWatch?.invoke(it)
                    watches += it
                }
            },
            listener = listener,
            serverHealthMonitorFactory = healthFactory,
            tokenGuard = guard,
            taskQueueFactory = { queue },
            tokenWriter = writer,
            tokenFactory = newToken ?: { "generated-test-token" },
            clockMillis = clockMillisOverride ?: { nowMillis },
            sleepMillis = sleepMillisOverride ?: { millis -> nowMillis += millis },
        )

        /** Submit a start. The caller decides when the queued probe runs. */
        fun start(): Boolean = controller.start()

        /** Run every queued start or session task. */
        fun runTasks() {
            queue.runAll()
        }

        /** Deliver one cellular network and finish its session setup. */
        fun available() {
            availableQueued()
            queue.runAll()
        }

        /** Deliver one cellular network without running the session setup. */
        fun availableQueued() {
            selection.callback.onAvailable(binding)
        }
    }

    @Test
    fun startWaitsForTheCellularNetwork() {
        val harness = Harness()

        assertTrue(harness.start())
        harness.runTasks()

        assertEquals(SourceProxyState.WAITING_FOR_NETWORK, harness.controller.state)
        assertEquals(SourceProxyStopReason.NONE, harness.controller.stopReason)
        assertEquals(1, harness.selection.starts)
        assertTrue(harness.servers.isEmpty())
        assertEquals(
            listOf(SourceProxyState.WAITING_FOR_NETWORK),
            harness.listener.snapshots.map { it.state },
        )
    }

    @Test
    fun aBoundListenerIsVisibleWhileTheRunIsStillWaiting() {
        val harness = Harness()
        harness.start()
        harness.runTasks()

        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        harness.beforeWatchFactory = {
            entered.countDown()
            awaitIgnoringInterrupt(release)
        }
        harness.availableQueued()
        val worker = daemon("controller-binding") {
            assertTrue(harness.queue.runNext())
        }
        worker.start()
        try {
            assertTrue("The bind must be in flight.", entered.await(5, TimeUnit.SECONDS))

            val binding = harness.controller.binding()
            assertEquals(SourceProxyState.WAITING_FOR_NETWORK, binding.state)
            assertTrue("A bound transition is active.", binding.active)
            assertEquals(PORT, binding.port)
            assertEquals(HOTSPOT, binding.address)
        } finally {
            release.countDown()
        }
        worker.join(5_000)
        assertFalse(worker.isAlive)
        assertEquals(SourceProxyState.RUNNING, harness.controller.state)
        assertEquals(PORT, harness.controller.binding().port)
    }

    @Test
    fun availableBindsOnlyTheHotspotAddress() {
        val harness = Harness()
        harness.start()
        harness.runTasks()

        harness.available()

        assertEquals(SourceProxyState.RUNNING, harness.controller.state)
        assertEquals(listOf(HOTSPOT), harness.requestedAddresses)
        assertFalse(harness.requestedAddresses.single().isAnyLocalAddress)
        assertEquals(PORT, harness.controller.localPort)
        assertEquals(1, harness.servers.single().starts)
        assertTrue(harness.watches.single().started)
        assertEquals(
            listOf(SourceProxyState.WAITING_FOR_NETWORK, SourceProxyState.RUNNING),
            harness.listener.snapshots.map { it.state },
        )
        assertEquals(1, harness.resolverCalls.get())
    }

    @Test
    fun theBindingSnapshotCarriesOneRunAndClearsOnStop() {
        val harness = Harness()
        harness.start()
        harness.runTasks()
        harness.available()
        val server = harness.servers.single()
        server.open = 2
        server.total = 5L

        val live = harness.controller.binding()
        assertEquals(SourceProxyState.RUNNING, live.state)
        assertTrue(live.active)
        assertEquals(PORT, live.port)
        assertEquals(HOTSPOT, live.address)
        assertEquals("The count belongs to the same run.", 2, live.connections)
        assertEquals(5L, live.totalConnections)

        harness.controller.stop()

        val stopped = harness.controller.binding()
        assertEquals(SourceProxyState.STOPPED, stopped.state)
        assertFalse(stopped.active)
        assertEquals(0, stopped.port)
        assertNull(stopped.address)
        assertEquals(0, stopped.connections)
        assertEquals(0L, stopped.totalConnections)
    }

    @Test
    fun aStartUnderTheDeferredLeaseIsRefusedAndASecondStartAfterReleaseWorks() {
        val guard = SourceTokenGuard()
        val sleepEntered = CountDownLatch(1)
        val releaseSleep = CountDownLatch(1)
        val first = Harness(
            tokenGuard = guard,
            finderOverride = object : HotspotAddressFinder {
                override fun probe(): HotspotProbe = HotspotProbe.Pending
            },
            sleepMillisOverride = {
                sleepEntered.countDown()
                awaitIgnoringInterrupt(releaseSleep)
            },
        )
        assertTrue(first.start())
        val worker = daemon("controller-first-wait") { first.queue.runNext() }
        worker.start()
        val secondQueue = ManualSourceProxyTaskQueue()
        val secondListener = RecordingListener()
        val second = controllerWith(
            tokenStore = first.tokenStore,
            guard = guard,
            queue = secondQueue,
            finder = FakeFinder(HOTSPOT),
            listener = secondListener,
        )
        val thirdQueue = ManualSourceProxyTaskQueue()
        val thirdListener = RecordingListener()
        val third = controllerWith(
            tokenStore = first.tokenStore,
            guard = guard,
            queue = thirdQueue,
            finder = FakeFinder(HOTSPOT),
            listener = thirdListener,
        )
        try {
            assertTrue("The first wait must be in flight.", sleepEntered.await(5, TimeUnit.SECONDS))

            first.controller.stop()
            assertTrue(
                "The in-flight wait keeps the run lease until it returns.",
                guard.isRunHeld(),
            )
            assertFalse(
                "A second run must not start under a live token lease.",
                second.start(),
            )
            assertEquals(SourceProxyStopReason.START_FAILED, second.stopReason)
            assertEquals(
                "A refused start reports one terminal state and binds nothing.",
                listOf(SourceProxyState.STOPPED),
                secondListener.snapshots.map { it.state },
            )
            assertTrue(secondListener.terminals.isNotEmpty())
            assertFalse("A refused start must queue no wait.", secondQueue.runNext())
        } finally {
            releaseSleep.countDown()
        }
        worker.join(5_000)
        assertFalse("The first wait must end.", worker.isAlive)
        assertFalse(
            "The lease must be released after the last task returns.",
            guard.isRunHeld(),
        )

        assertTrue("A start after the release must run.", third.start())
        thirdQueue.runAll()
        assertEquals(SourceProxyState.WAITING_FOR_NETWORK, third.state)
        assertEquals(
            listOf(SourceProxyState.WAITING_FOR_NETWORK),
            thirdListener.snapshots.map { it.state },
        )
        third.stop()
    }

    @Test
    fun connectionCountComesFromTheServer() {
        val harness = Harness()
        harness.start()
        harness.runTasks()
        assertEquals(0, harness.controller.connectionCount)
        assertEquals(0L, harness.controller.totalConnections)

        harness.available()
        val server = harness.servers.single()
        server.open = 3
        server.total = 7L

        assertEquals(3, harness.controller.connectionCount)
        assertEquals(7L, harness.controller.totalConnections)

        harness.controller.stop()

        assertEquals(0, harness.controller.connectionCount)
        assertEquals(0L, harness.controller.totalConnections)
    }

    @Test
    fun pendingProbeThenObservedStartsNormally() {
        val harness = Harness()
        var pendingReadings = 2
        harness.finder.probeFactory = {
            if (pendingReadings-- > 0) {
                HotspotProbe.Pending
            } else {
                observed(HOTSPOT)
            }
        }

        assertTrue(harness.start())
        assertEquals("A pending start must not bind anything.", 0, harness.selection.starts)
        assertTrue(harness.controller.isActive)
        assertFalse(harness.start())

        harness.runTasks()

        assertEquals(SourceProxyState.WAITING_FOR_NETWORK, harness.controller.state)
        assertTrue(harness.listener.terminals.isEmpty())

        harness.available()

        assertEquals(SourceProxyState.RUNNING, harness.controller.state)
        assertEquals(listOf(HOTSPOT), harness.requestedAddresses)
        assertTrue(harness.listener.terminals.isEmpty())
        assertEquals(
            "One probe per wait step, with no second address read.",
            4,
            harness.finder.calls,
        )
    }

    @Test
    fun pendingProbeUntilTheDeadlineReportsNotFoundOnce() {
        val harness = Harness()
        harness.finder.probeFactory = { HotspotProbe.Pending }

        assertTrue(harness.start())
        harness.runTasks()

        assertEquals(SourceProxyState.STOPPED, harness.controller.state)
        assertEquals(SourceProxyStopReason.HOTSPOT_NOT_FOUND, harness.controller.stopReason)
        assertEquals(1, harness.listener.terminals.size)
        assertEquals(
            SourceProxyStopReason.HOTSPOT_NOT_FOUND,
            harness.listener.terminals.single().reason,
        )
        assertTrue("Nothing may bind without a reading.", harness.servers.isEmpty())
        assertTrue(harness.watches.isEmpty())
        assertTrue(harness.requestedAddresses.isEmpty())
        assertEquals("The monitor must never start.", 0, harness.selection.starts)
        assertTrue("The bounded wait must poll.", harness.finder.calls > 1)
        assertEquals(
            "The wait must use the evidence bound.",
            SourceProxyController.DEFAULT_PENDING_WAIT_MILLIS,
            harness.nowMillis,
        )
        assertTrue(harness.queue.shutdown)
        assertFalse("The deadline must release the run lease.", harness.guard.isRunHeld())

        // A late reading after the terminal state changes nothing.
        val callsAtStop = harness.finder.calls
        harness.finder.probeFactory = { observed(HOTSPOT) }
        harness.runTasks()
        assertEquals(callsAtStop, harness.finder.calls)
        assertEquals(SourceProxyState.STOPPED, harness.controller.state)
        assertEquals(1, harness.listener.terminals.size)
    }

    @Test
    fun stopDuringThePendingWaitReportsUserStopOnce() {
        val harness = Harness()
        var stopped = false
        harness.finder.probeFactory = {
            if (!stopped) {
                stopped = true
                harness.controller.stop()
            }
            HotspotProbe.Pending
        }

        assertTrue(harness.start())
        harness.runTasks()

        assertEquals(SourceProxyState.STOPPED, harness.controller.state)
        assertEquals(SourceProxyStopReason.USER_STOP, harness.controller.stopReason)
        assertEquals(1, harness.listener.terminals.size)
        assertTrue(harness.servers.isEmpty())
        assertTrue(harness.watches.isEmpty())
        assertTrue(harness.queue.shutdown)
        assertFalse(harness.guard.isRunHeld())
    }

    @Test
    fun lateObservedProbeAfterTheStopBindsNothing() {
        val harness = Harness()
        var stopped = false
        harness.finder.probeFactory = {
            if (!stopped) {
                stopped = true
                harness.controller.stop()
            }
            observed(HOTSPOT)
        }

        assertTrue(harness.start())
        harness.runTasks()

        assertEquals(SourceProxyState.STOPPED, harness.controller.state)
        assertEquals(SourceProxyStopReason.USER_STOP, harness.controller.stopReason)
        assertEquals(1, harness.listener.terminals.size)
        assertTrue(harness.servers.isEmpty())
        assertTrue(harness.requestedAddresses.isEmpty())
    }

    @Test
    fun aSecondStartDuringThePendingWaitIsRefused() {
        val harness = Harness()
        harness.finder.probeFactory = { HotspotProbe.Pending }

        assertTrue(harness.start())
        assertFalse("A second start must not create a second run.", harness.start())

        harness.runTasks()

        assertEquals(SourceProxyState.STOPPED, harness.controller.state)
        assertEquals(SourceProxyStopReason.HOTSPOT_NOT_FOUND, harness.controller.stopReason)
        assertEquals(1, harness.listener.terminals.size)
        assertTrue(harness.servers.isEmpty())
        assertEquals(0, harness.selection.starts)
        assertFalse(harness.controller.isActive)
    }

    @Test
    fun repeatedAvailabilityCreatesNoSecondListener() {
        val harness = Harness()
        harness.start()
        harness.runTasks()
        harness.available()

        harness.availableQueued()
        harness.runTasks()

        assertEquals(1, harness.servers.size)
        assertEquals(1, harness.watches.size)
        assertEquals(1, harness.servers.single().starts)
        assertFalse(harness.start())
    }

    @Test
    fun aTokenRotationIsRefusedDuringThePendingWait() {
        val harness = Harness()
        harness.finder.probeFactory = { HotspotProbe.Pending }
        val writes = AtomicInteger()

        assertTrue(harness.start())
        assertEquals(
            TokenMutationResult.REFUSED_RUNNING,
            harness.guard.rotate { writes.incrementAndGet() },
        )
        assertEquals(0, writes.get())

        harness.runTasks()

        assertEquals(SourceProxyStopReason.HOTSPOT_NOT_FOUND, harness.controller.stopReason)
        assertFalse(harness.guard.isRunHeld())
        assertEquals(TokenMutationResult.WRITTEN, harness.guard.rotate { writes.incrementAndGet() })
        assertEquals(1, writes.get())
    }

    @Test
    fun pendingSessionProbeThenObservedStartsWithoutATerminalNotFound() {
        val harness = Harness()
        harness.start()
        harness.runTasks()
        assertEquals(SourceProxyState.WAITING_FOR_NETWORK, harness.controller.state)

        var pendingReadings = 2
        harness.finder.probeFactory = {
            if (pendingReadings-- > 0) {
                HotspotProbe.Pending
            } else {
                observed(HOTSPOT)
            }
        }
        harness.availableQueued()
        assertEquals(
            "The session setup must wait off the monitor thread.",
            SourceProxyState.WAITING_FOR_NETWORK,
            harness.controller.state,
        )

        harness.runTasks()

        assertEquals(SourceProxyState.RUNNING, harness.controller.state)
        assertTrue(harness.listener.terminals.isEmpty())
        assertEquals(listOf(HOTSPOT), harness.requestedAddresses)
        assertTrue(harness.watches.single().started)
        assertEquals("A healthy session must stay open.", 0, harness.selection.stops)
    }

    @Test
    fun pendingSessionProbeUntilTheDeadlineStopsAndClosesTheSession() {
        val harness = Harness()
        harness.start()
        harness.runTasks()
        assertEquals(SourceProxyState.WAITING_FOR_NETWORK, harness.controller.state)

        harness.finder.probeFactory = { HotspotProbe.Pending }
        harness.availableQueued()
        harness.runTasks()

        assertEquals(SourceProxyState.STOPPED, harness.controller.state)
        assertEquals(SourceProxyStopReason.HOTSPOT_NOT_FOUND, harness.controller.stopReason)
        assertEquals(1, harness.listener.terminals.size)
        assertTrue(harness.servers.isEmpty())
        assertTrue(harness.watches.isEmpty())
        assertEquals("The monitor must close the cellular session.", 1, harness.selection.stops)
        assertTrue(harness.queue.shutdown)
        assertFalse(harness.guard.isRunHeld())
    }

    @Test
    fun stopDuringThePendingSessionWaitReportsUserStopAndClosesTheSession() {
        val harness = Harness()
        harness.start()
        harness.runTasks()
        assertEquals(SourceProxyState.WAITING_FOR_NETWORK, harness.controller.state)

        var stopped = false
        harness.finder.probeFactory = {
            if (!stopped) {
                stopped = true
                harness.controller.stop()
            }
            HotspotProbe.Pending
        }
        harness.availableQueued()
        harness.runTasks()

        assertEquals(SourceProxyState.STOPPED, harness.controller.state)
        assertEquals(SourceProxyStopReason.USER_STOP, harness.controller.stopReason)
        assertEquals(1, harness.listener.terminals.size)
        assertTrue(harness.servers.isEmpty())
        assertTrue(harness.watches.isEmpty())
        assertEquals("The monitor must close the cellular session.", 1, harness.selection.stops)
        assertTrue(harness.queue.shutdown)
        assertFalse(harness.guard.isRunHeld())
    }

    @Test
    fun stopDuringSessionSetupDoesNotBindAListener() {
        val harness = Harness()
        harness.start()
        harness.runTasks()
        assertEquals(SourceProxyState.WAITING_FOR_NETWORK, harness.controller.state)

        harness.beforeResolver = { harness.controller.stop() }
        harness.available()

        assertEquals(SourceProxyState.STOPPED, harness.controller.state)
        assertEquals(SourceProxyStopReason.USER_STOP, harness.controller.stopReason)
        assertEquals(1, harness.listener.terminals.size)
        assertTrue("No listener may be constructed after stop.", harness.servers.isEmpty())
        assertTrue(harness.watches.isEmpty())
        assertEquals("The monitor must close the cellular session.", 1, harness.selection.stops)
        assertTrue(harness.queue.shutdown)
        assertFalse(harness.guard.isRunHeld())
    }

    @Test
    fun hotspotMissingStopsBeforeTheMonitor() {
        val harness = Harness(hotspot = null)

        assertTrue(harness.start())
        harness.runTasks()

        assertEquals(SourceProxyState.STOPPED, harness.controller.state)
        assertEquals(SourceProxyStopReason.HOTSPOT_NOT_FOUND, harness.controller.stopReason)
        assertEquals(0, harness.selection.starts)
        assertTrue(harness.servers.isEmpty())
        assertEquals(1, harness.listener.terminals.size)
        assertEquals(
            SourceProxyStopReason.HOTSPOT_NOT_FOUND,
            harness.listener.terminals.single().reason,
        )
    }

    @Test
    fun hotspotMissingAtSetupStopsWithoutABind() {
        val harness = Harness()
        harness.start()
        harness.runTasks()
        harness.finder.address = null

        harness.available()

        assertEquals(SourceProxyState.STOPPED, harness.controller.state)
        assertEquals(SourceProxyStopReason.HOTSPOT_NOT_FOUND, harness.controller.stopReason)
        assertTrue(harness.servers.isEmpty())
        assertEquals(1, harness.selection.stops)
        assertEquals(1, harness.listener.terminals.size)
        assertEquals(0, harness.controller.localPort)
    }

    @Test
    fun networkLostClosesTheServerAndTheWatch() {
        val harness = Harness()
        harness.start()
        harness.runTasks()
        harness.available()
        val server = harness.servers.single()
        val watch = harness.watches.single()

        harness.selection.callback.onLost()

        assertEquals(SourceProxyState.STOPPED, harness.controller.state)
        assertEquals(SourceProxyStopReason.NETWORK_LOST, harness.controller.stopReason)
        assertTrue(server.closed)
        assertEquals(1, server.stops)
        assertEquals(1, watch.stops)
        assertEquals(1, harness.selection.stops)
        assertEquals(1, harness.listener.terminals.size)
        assertEquals(0, harness.controller.localPort)
    }

    @Test
    fun capabilityLossStopsTheRun() {
        val harness = Harness()
        harness.start()
        harness.runTasks()
        harness.available()

        harness.selection.callback.onCapabilitiesLost()

        assertEquals(SourceProxyState.STOPPED, harness.controller.state)
        assertEquals(SourceProxyStopReason.CAPABILITIES_LOST, harness.controller.stopReason)
        assertTrue(harness.servers.single().closed)
        assertEquals(1, harness.listener.terminals.size)
    }

    @Test
    fun networkUnavailableStopsTheRun() {
        val harness = Harness()
        harness.start()
        harness.runTasks()

        harness.selection.callback.onUnavailable()

        assertEquals(SourceProxyState.STOPPED, harness.controller.state)
        assertEquals(SourceProxyStopReason.NETWORK_UNAVAILABLE, harness.controller.stopReason)
        assertEquals(1, harness.selection.stops)
        assertEquals(1, harness.listener.terminals.size)
    }

    @Test
    fun userStopClosesEverythingOneTime() {
        val harness = Harness()
        harness.start()
        harness.runTasks()
        harness.available()
        val server = harness.servers.single()
        val watch = harness.watches.single()

        harness.controller.stop()
        harness.controller.stop()

        assertEquals(SourceProxyState.STOPPED, harness.controller.state)
        assertEquals(SourceProxyStopReason.USER_STOP, harness.controller.stopReason)
        assertEquals(1, server.stops)
        assertEquals(1, watch.stops)
        assertEquals(1, harness.selection.stops)
        assertEquals(1, harness.listener.terminals.size)
        assertNull(harness.controller.closeFailure)
    }

    @Test
    fun theProductionHealthMonitorReportsAnUnexpectedListenerStop() {
        val server = FakeServer(failStart = false)
        server.start()
        val failed = CountDownLatch(1)
        val monitor = PollingSourceServerHealthMonitor(
            server = server,
            onFailure = { failed.countDown() },
            pollMillis = 10L,
        )
        monitor.start()
        try {
            server.failListener("accept")
            assertTrue(
                "The watcher must report the stopped listener.",
                failed.await(5, TimeUnit.SECONDS),
            )
        } finally {
            monitor.close()
        }
    }

    @Test
    fun aListenerFailureStopsTheRunWithItsOwnReason() {
        val harness = Harness()
        harness.start()
        harness.runTasks()
        harness.available()
        val server = harness.servers.single()
        val health = harness.health.monitors.single()
        assertTrue("A running listener must have a health watcher.", health.started)
        assertTrue(server.isRunning)

        server.failListener("accept")
        health.fail()

        assertEquals(SourceProxyState.STOPPED, harness.controller.state)
        assertEquals(SourceProxyStopReason.LISTENER_FAILED, harness.controller.stopReason)
        assertEquals("accept", harness.controller.listenerFailure)
        assertTrue(server.closed)
        assertEquals(1, server.stops)
        assertEquals(1, harness.watches.single().stops)
        assertEquals(1, harness.selection.stops)
        assertEquals(1, harness.listener.terminals.size)
        assertEquals(
            SourceProxyStopReason.LISTENER_FAILED,
            harness.listener.terminals.single().reason,
        )
        assertTrue("The run must close its health watcher.", health.closed)
        assertFalse(harness.guard.isRunHeld())
    }

    @Test
    fun aLateListenerFailureAfterAUserStopDoesNotChangeTheReason() {
        val harness = Harness()
        harness.start()
        harness.runTasks()
        harness.available()
        val server = harness.servers.single()
        val health = harness.health.monitors.single()

        harness.controller.stop()

        assertEquals(SourceProxyStopReason.USER_STOP, harness.controller.stopReason)
        assertNull(harness.controller.listenerFailure)
        assertTrue(health.closed)

        server.failListener("accept")
        health.fail()

        assertEquals(SourceProxyStopReason.USER_STOP, harness.controller.stopReason)
        assertEquals(1, harness.listener.terminals.size)
        assertEquals(1, server.stops)
    }

    @Test
    fun aHealthMonitorThatCannotStartStopsTheRun() {
        val health = ManualHealthFactory().apply { failStart = true }
        val harness = Harness(healthFactory = health)

        harness.start()
        harness.runTasks()
        harness.available()

        assertEquals(SourceProxyState.STOPPED, harness.controller.state)
        assertEquals(SourceProxyStopReason.LISTENER_FAILED, harness.controller.stopReason)
        assertTrue(harness.servers.single().closed)
        assertEquals(1, harness.watches.single().stops)
        assertEquals(1, harness.listener.terminals.size)
        assertEquals(
            SourceProxyStopReason.LISTENER_FAILED,
            harness.listener.terminals.single().reason,
        )
        assertTrue(health.monitors.single().closed)
        assertFalse(harness.guard.isRunHeld())
    }

    @Test
    fun doubleStartDoesNotCreateASecondRun() {
        val harness = Harness()
        assertTrue(harness.start())
        harness.runTasks()

        assertFalse(harness.start())
        harness.available()
        assertFalse(harness.start())

        assertEquals(1, harness.selection.starts)
        assertEquals(1, harness.servers.size)
        assertEquals(1, harness.watches.size)
        assertEquals(
            listOf(SourceProxyState.WAITING_FOR_NETWORK, SourceProxyState.RUNNING),
            harness.listener.snapshots.map { it.state },
        )
    }

    @Test
    fun stoppedControllerRefusesARestart() {
        val harness = Harness()
        harness.start()
        harness.runTasks()
        harness.available()
        harness.controller.stop()

        assertFalse(harness.start())

        assertEquals(1, harness.selection.starts)
        assertEquals(1, harness.servers.size)
        assertEquals(1, harness.listener.terminals.size)
        assertEquals(SourceProxyStopReason.USER_STOP, harness.controller.stopReason)
    }

    @Test
    fun lateAvailabilityAfterStopDoesNotStartAnything() {
        val harness = Harness()
        harness.start()
        harness.runTasks()
        harness.controller.stop()

        harness.available()

        assertTrue(harness.servers.isEmpty())
        assertTrue(harness.watches.isEmpty())
        assertEquals(1, harness.selection.starts)
        assertEquals(1, harness.selection.stops)
        assertEquals(1, harness.listener.terminals.size)
        assertEquals(SourceProxyStopReason.USER_STOP, harness.controller.stopReason)
    }

    @Test
    fun lateLossAfterStopDoesNotNotifyAgain() {
        val harness = Harness()
        harness.start()
        harness.runTasks()
        harness.available()
        harness.controller.stop()

        harness.selection.callback.onLost()
        harness.watches.single().lose()
        harness.selection.callback.onUnavailable()

        assertEquals(1, harness.listener.terminals.size)
        assertEquals(SourceProxyStopReason.USER_STOP, harness.controller.stopReason)
        assertEquals(1, harness.servers.single().stops)
    }

    @Test
    fun hotspotLossStopsTheRun() {
        val harness = Harness()
        harness.start()
        harness.runTasks()
        harness.available()

        harness.watches.single().lose()

        assertEquals(SourceProxyState.STOPPED, harness.controller.state)
        assertEquals(SourceProxyStopReason.HOTSPOT_LOST, harness.controller.stopReason)
        assertTrue(harness.servers.single().closed)
        assertEquals(1, harness.watches.single().stops)
        assertEquals(1, harness.selection.stops)
        assertEquals(1, harness.listener.terminals.size)
    }

    @Test
    fun tokenMissingStopsBeforeTheMonitor() {
        val harness = Harness(token = null)

        assertFalse(harness.start())

        assertEquals(SourceProxyState.STOPPED, harness.controller.state)
        assertEquals(SourceProxyStopReason.TOKEN_MISSING, harness.controller.stopReason)
        assertEquals(0, harness.selection.starts)
        assertTrue(harness.servers.isEmpty())
        assertEquals(1, harness.listener.terminals.size)
    }

    @Test
    fun anUnusableStoredTokenIsUnreadableNotMissing() {
        // The pairing listener rejects the same values as unusable. A start
        // must agree with it, so it never binds a token the listener would
        // report as TOKEN_UNREADABLE.
        val unusable = listOf("", "bad token", "tab\there", "line\nfeed", "x".repeat(256))
        for (token in unusable) {
            val harness = Harness(token = token)

            assertFalse("The token must be refused: length=${token.length}", harness.start())

            assertEquals(
                "The token must be reported as unreadable, not missing.",
                SourceProxyStopReason.TOKEN_UNREADABLE,
                harness.controller.stopReason,
            )
            assertEquals(0, harness.selection.starts)
            assertTrue(harness.servers.isEmpty())
            assertEquals(1, harness.listener.terminals.size)
            assertFalse(harness.guard.isRunHeld())
        }
    }

    @Test
    fun aBlockedTokenGuardDoesNotBlockStateReadsOrStop() {
        val guard = SourceTokenGuard()
        val rotationStarted = CountDownLatch(1)
        val releaseRotation = CountDownLatch(1)
        val rotator = daemon("controller-rotation") {
            guard.rotate {
                rotationStarted.countDown()
                awaitIgnoringInterrupt(releaseRotation)
            }
        }
        rotator.start()
        assertTrue(
            "The rotation must hold the guard.",
            rotationStarted.await(5, TimeUnit.SECONDS),
        )
        val controller = controllerWith(
            tokenStore = FakeTokenStore(TOKEN),
            guard = guard,
            queue = ManualSourceProxyTaskQueue(),
            finder = FakeFinder(HOTSPOT),
            listener = RecordingListener(),
        )
        val started = AtomicBoolean(true)
        val starter = daemon("controller-guard") { started.set(controller.start()) }
        starter.start()
        try {
            val activeDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
            while (!controller.isActive && System.nanoTime() < activeDeadline) {
                Thread.yield()
            }
            assertTrue(
                "The start must publish its active flag before it waits for the guard.",
                controller.isActive,
            )
            val readState = AtomicReference<SourceProxyState>()
            val readActive = AtomicBoolean()
            val reader = daemon("controller-guard-read") {
                readState.set(controller.state)
                readActive.set(controller.isActive)
            }
            reader.start()
            reader.join(2_000)
            assertFalse(
                "A state read must not wait for the token guard under the controller lock.",
                reader.isAlive,
            )
            assertEquals(SourceProxyState.IDLE, readState.get())
            assertTrue(readActive.get())

            val stopper = daemon("controller-guard-stop") { controller.stop() }
            stopper.start()
            stopper.join(2_000)
            assertFalse(
                "A stop must not wait for the token guard under the controller lock.",
                stopper.isAlive,
            )
            assertEquals(SourceProxyState.STOPPED, controller.state)
            assertEquals(SourceProxyStopReason.USER_STOP, controller.stopReason)
        } finally {
            releaseRotation.countDown()
        }
        starter.join(5_000)
        rotator.join(5_000)
        assertFalse("The stop wins over the guarded start.", started.get())
        assertFalse("The aborted start must release its lease.", guard.isRunHeld())
    }

    @Test
    fun aSlowTokenLoadDoesNotBlockStateReadsOrStop() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val store = object : TokenStore {
            override fun load(): String? {
                entered.countDown()
                awaitIgnoringInterrupt(release)
                return TOKEN
            }
        }
        val queue = ManualSourceProxyTaskQueue()
        val listener = RecordingListener()
        val guard = SourceTokenGuard()
        val controller = controllerWith(
            tokenStore = store,
            guard = guard,
            queue = queue,
            finder = FakeFinder(HOTSPOT),
            listener = listener,
        )
        val started = AtomicBoolean(true)
        val starter = daemon("controller-token-load") { started.set(controller.start()) }
        starter.start()
        try {
            assertTrue("The token load must be in flight.", entered.await(5, TimeUnit.SECONDS))

            assertEquals(SourceProxyState.IDLE, controller.state)
            assertTrue(controller.isActive)
            assertEquals(
                "A status read must not wait for the token load.",
                0,
                controller.connectionCount,
            )
            assertEquals(0L, controller.totalConnections)
            assertEquals(SourceProxyState.IDLE, controller.snapshot().state)

            val stopper = daemon("controller-token-load-stop") { controller.stop() }
            stopper.start()
            stopper.join(2_000)
            assertFalse(
                "A stop must not wait for the token load under the controller lock.",
                stopper.isAlive,
            )
            assertEquals(SourceProxyState.STOPPED, controller.state)
            assertEquals(SourceProxyStopReason.USER_STOP, controller.stopReason)
        } finally {
            release.countDown()
        }
        starter.join(5_000)
        assertFalse("The start must end after the token load returns.", starter.isAlive)
        assertFalse("The stop wins over the slow token load.", started.get())
        assertEquals(SourceProxyState.STOPPED, controller.state)
        assertEquals(SourceProxyStopReason.USER_STOP, controller.stopReason)
        assertEquals(1, listener.terminals.size)
        assertFalse("The stop must release the run lease.", guard.isRunHeld())
    }

    @Test
    fun aMaximumLengthPrintableTokenStarts() {
        val harness = Harness(token = "a".repeat(255))

        assertTrue(harness.start())
        harness.runTasks()
        harness.available()

        assertEquals(SourceProxyState.RUNNING, harness.controller.state)
        assertEquals(SourceProxyStopReason.NONE, harness.controller.stopReason)
    }

    @Test
    fun bindFailureStopsTheRun() {
        val harness = Harness(failBind = true)
        harness.start()
        harness.runTasks()

        harness.available()

        assertEquals(SourceProxyState.STOPPED, harness.controller.state)
        assertEquals(SourceProxyStopReason.BIND_FAILED, harness.controller.stopReason)
        assertTrue(harness.servers.single().closed)
        assertTrue(harness.watches.isEmpty())
        assertEquals(1, harness.selection.stops)
        assertEquals(1, harness.listener.terminals.size)
        assertEquals(0, harness.controller.localPort)
    }

    @Test
    fun resolverFailureStopsTheRun() {
        val harness = Harness(failResolver = true)
        harness.start()
        harness.runTasks()

        harness.available()

        assertEquals(SourceProxyState.STOPPED, harness.controller.state)
        assertEquals(SourceProxyStopReason.START_FAILED, harness.controller.stopReason)
        assertTrue(harness.servers.isEmpty())
        assertEquals(1, harness.selection.stops)
        assertEquals(1, harness.listener.terminals.size)
    }

    @Test
    fun watchFailureStopsTheRun() {
        val harness = Harness(failWatch = true)
        harness.start()
        harness.runTasks()

        harness.available()

        assertEquals(SourceProxyState.STOPPED, harness.controller.state)
        assertEquals(SourceProxyStopReason.START_FAILED, harness.controller.stopReason)
        assertTrue(harness.servers.single().closed)
        assertEquals(1, harness.watches.single().stops)
        assertEquals(1, harness.listener.terminals.size)
    }

    @Test
    fun stopWhileWaitingIsClean() {
        val harness = Harness()
        harness.start()
        harness.runTasks()

        harness.controller.stop()

        assertEquals(SourceProxyState.STOPPED, harness.controller.state)
        assertEquals(SourceProxyStopReason.USER_STOP, harness.controller.stopReason)
        assertEquals(1, harness.selection.stops)
        assertEquals(1, harness.listener.terminals.size)
    }

    @Test
    fun snapshotsHoldNoTokenOrAddress() {
        val harness = Harness()
        harness.start()
        harness.runTasks()
        harness.available()
        harness.controller.stop()

        val text = harness.listener.snapshots.joinToString()
        val address = HOTSPOT.hostAddress ?: ""
        assertFalse(text.contains(TOKEN))
        assertFalse(address.isNotEmpty() && text.contains(address))
    }

    @Test
    fun snapshotDuringThePendingStartReportsIdleAndActive() {
        val harness = Harness()
        harness.finder.probeFactory = { HotspotProbe.Pending }

        assertTrue(harness.start())

        val snapshot = harness.controller.snapshot()
        assertEquals(SourceProxyState.IDLE, snapshot.state)
        assertEquals(SourceProxyStopReason.NONE, snapshot.reason)
        assertEquals(0, snapshot.port)
        assertTrue(harness.controller.isActive)
    }

    @Test
    fun snapshotReportsTheLiveRun() {
        val harness = Harness()
        harness.start()
        harness.runTasks()
        harness.available()

        val snapshot = harness.controller.snapshot()
        assertEquals(SourceProxyState.RUNNING, snapshot.state)
        assertEquals(SourceProxyStopReason.NONE, snapshot.reason)
        assertEquals(PORT, snapshot.port)
    }

    @Test
    fun aStopDuringServerStartKeepsTheLeaseUntilTheListenerCloses() {
        val harness = Harness()
        harness.start()
        harness.runTasks()
        assertEquals(SourceProxyState.WAITING_FOR_NETWORK, harness.controller.state)

        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val leaseAtClose = AtomicBoolean(false)
        harness.configureServer = { server ->
            server.onStart = {
                entered.countDown()
                awaitIgnoringInterrupt(release)
            }
            server.onClose = { leaseAtClose.set(harness.guard.isRunHeld()) }
        }
        harness.availableQueued()
        val worker = daemon("controller-setup") {
            assertTrue(harness.queue.runNext())
        }
        worker.start()
        try {
            assertTrue("The listener start must be in flight.", entered.await(5, TimeUnit.SECONDS))

            val stopper = daemon("controller-stop") {
                harness.controller.stop()
                harness.controller.stop()
            }
            stopper.start()
            stopper.join(2_000)
            assertFalse(
                "Stop must not wait for the worker under the controller lock.",
                stopper.isAlive,
            )

            assertTrue(
                "The in-flight listener must keep the run lease.",
                harness.guard.isRunHeld(),
            )
            assertFalse("The listener must still be open.", leaseAtClose.get())
            assertFalse(harness.servers.single().closed)
        } finally {
            release.countDown()
        }
        worker.join(5_000)
        assertFalse(worker.isAlive)

        val server = harness.servers.single()
        assertEquals(SourceProxyState.STOPPED, harness.controller.state)
        assertEquals(SourceProxyStopReason.USER_STOP, harness.controller.stopReason)
        assertTrue(server.closed)
        assertEquals(1, server.stops)
        assertTrue(
            "The lease must still be held while the listener closes.",
            leaseAtClose.get(),
        )
        assertFalse(
            "The lease must be released after the listener closes.",
            harness.guard.isRunHeld(),
        )
        assertEquals(1, harness.listener.terminals.size)
        assertTrue(
            "A late listener must not publish RUNNING.",
            harness.listener.snapshots.none { it.state == SourceProxyState.RUNNING },
        )
        assertTrue(harness.queue.shutdown)
    }

    @Test
    fun aStopDuringTheWatchFactoryKeepsTheLeaseUntilTheBoundListenerCloses() {
        val harness = Harness()
        harness.start()
        harness.runTasks()

        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val leaseAtClose = AtomicBoolean(false)
        harness.configureServer = { server ->
            server.onClose = { leaseAtClose.set(harness.guard.isRunHeld()) }
        }
        harness.beforeWatchFactory = {
            entered.countDown()
            awaitIgnoringInterrupt(release)
        }
        harness.availableQueued()
        val worker = daemon("controller-setup") {
            assertTrue(harness.queue.runNext())
        }
        worker.start()
        try {
            assertTrue("The watch factory must be in flight.", entered.await(5, TimeUnit.SECONDS))

            val server = harness.servers.single()
            assertEquals("The listener is bound before the watch.", 1, server.starts)

            val stopper = daemon("controller-stop") {
                harness.controller.stop()
                harness.controller.stop()
            }
            stopper.start()
            stopper.join(2_000)
            assertFalse(
                "Stop must not wait for the worker under the controller lock.",
                stopper.isAlive,
            )

            assertTrue(
                "The bound listener must keep the run lease.",
                harness.guard.isRunHeld(),
            )
            assertFalse("The worker still owns the listener.", server.closed)
        } finally {
            release.countDown()
        }
        worker.join(5_000)
        assertFalse(worker.isAlive)

        val server = harness.servers.single()
        assertTrue("The worker must close the late listener.", server.closed)
        assertTrue(
            "The lease must still be held while the listener closes.",
            leaseAtClose.get(),
        )
        assertFalse(harness.guard.isRunHeld())
        assertEquals(SourceProxyStopReason.USER_STOP, harness.controller.stopReason)
        assertEquals(1, harness.listener.terminals.size)
        assertEquals(1, harness.watches.single().stops)
        assertTrue(
            "A late listener must not publish RUNNING.",
            harness.listener.snapshots.none { it.state == SourceProxyState.RUNNING },
        )
    }

    @Test
    fun aQueueShutdownOnItsOwnWorkerDoesNotInterruptTheCleanup() {
        val queue = SingleThreadSourceProxyTaskQueue()
        val ran = CountDownLatch(1)
        val interrupted = AtomicBoolean(true)

        queue.execute {
            queue.shutdown()
            interrupted.set(Thread.currentThread().isInterrupted)
            ran.countDown()
        }

        assertTrue(ran.await(5, TimeUnit.SECONDS))
        assertFalse(
            "A stop on the worker must not interrupt its own cleanup.",
            interrupted.get(),
        )
    }

    @Test
    fun aQueueShutdownFromAnotherThreadInterruptsTheWait() {
        val queue = SingleThreadSourceProxyTaskQueue()
        val started = CountDownLatch(1)
        val interrupted = CountDownLatch(1)

        queue.execute {
            started.countDown()
            try {
                Thread.sleep(60_000)
            } catch (_: InterruptedException) {
                interrupted.countDown()
            }
        }
        assertTrue(started.await(5, TimeUnit.SECONDS))

        queue.shutdown()

        assertTrue(
            "A stop from another thread must interrupt a bounded wait.",
            interrupted.await(5, TimeUnit.SECONDS),
        )
    }

    @Test
    fun theControllerAndTheEvidenceExpireOnTheSameSharedClock() {
        val nowNanos = AtomicLong(0L)
        val evidence = TetheredInterfaceEvidence(
            registration = FakeRegistration(),
            clock = { nowNanos.get() },
        )
        assertTrue(evidence.start())
        val finder = object : HotspotAddressFinder {
            override fun probe(): HotspotProbe = when (evidence.snapshot()) {
                TetheredInterfaceState.AwaitingFirstReading -> HotspotProbe.Pending
                is TetheredInterfaceState.Known -> observed(HOTSPOT)
                TetheredInterfaceState.Unavailable -> HotspotProbe.Observed(
                    candidates = emptyList(),
                    excludedAddresses = emptySet(),
                )
            }
        }
        val harness = Harness(
            finderOverride = finder,
            clockMillisOverride = {
                TimeUnit.NANOSECONDS.toMillis(nowNanos.get())
            },
            sleepMillisOverride = { millis ->
                nowNanos.addAndGet(TimeUnit.MILLISECONDS.toNanos(millis))
            },
        )
        try {
            assertEquals(
                "The controller wait must match the evidence bound.",
                TetheredInterfaceEvidence.DEFAULT_PENDING_TIMEOUT_MILLIS,
                SourceProxyController.DEFAULT_PENDING_WAIT_MILLIS,
            )

            assertTrue(harness.start())
            harness.runTasks()

            assertEquals(
                SourceProxyStopReason.HOTSPOT_NOT_FOUND,
                harness.controller.stopReason,
            )
            assertEquals(
                "The controller must not stop while the evidence is pending.",
                TetheredInterfaceEvidence.DEFAULT_PENDING_TIMEOUT_MILLIS,
                TimeUnit.NANOSECONDS.toMillis(nowNanos.get()),
            )
            assertEquals(TetheredInterfaceState.Unavailable, evidence.snapshot())
            assertTrue(harness.servers.isEmpty())
            assertTrue(harness.requestedAddresses.isEmpty())
        } finally {
            evidence.close()
        }
    }

    private class FakeRegistration : TetheredInterfaceRegistration {
        override fun register(listener: (TetheredInterfaceReading?) -> Unit): Boolean = true

        override fun unregister() = Unit
    }

    /** Build one more controller over a shared guard and token store. */
    private fun controllerWith(
        tokenStore: TokenStore,
        guard: SourceTokenGuard,
        queue: ManualSourceProxyTaskQueue,
        finder: HotspotAddressFinder,
        listener: SourceProxyListener,
    ): SourceProxyController = SourceProxyController(
        tokenStore = tokenStore,
        hotspotFinder = finder,
        selectionFactory = { FakeSelection() },
        resolverFactory = { SourceHostResolver { emptyList() } },
        echoFactory = { SourceEchoSender { _, _, _ -> EchoResult(EchoStatus.FAILED) } },
        serverFactory = { _, _, _, _, _ -> FakeServer(failStart = false) },
        watchFactory = { FakeWatch(failStart = false) },
        listener = listener,
        tokenGuard = guard,
        taskQueueFactory = { queue },
        clockMillis = { 0L },
        sleepMillis = { },
    )

    @Test
    fun firstStartCreatesTheTokenThroughTheWriterAndGuard() {
        ActivityLog.shared.clear()
        lateinit var harness: Harness
        harness = Harness(
            token = null,
            writer = TokenWriter { saved -> harness.tokenStore.token = saved },
            newToken = { "created-first-token" },
        )
        val epochBefore = harness.guard.epoch()

        assertTrue(harness.start())
        harness.runTasks()
        harness.available()

        assertEquals("created-first-token", harness.tokenStore.token)
        assertEquals(SourceProxyState.RUNNING, harness.controller.state)
        assertEquals(listOf("created-first-token"), harness.requestedTokens.toList())
        assertEquals(
            "A created token moves the guard epoch so a pairing listener reloads it.",
            epochBefore + 1,
            harness.guard.epoch(),
        )
        assertTrue(
            ActivityLog.shared.entries().any { it.event == ActivityEvent.TOKEN_CREATED },
        )
        assertFalse(
            "The log line never holds the token.",
            ActivityLog.shared.entries().any { it.message.contains("created-first-token") },
        )
    }

    @Test
    fun aSecondStartKeepsTheCreatedToken() {
        lateinit var harness: Harness
        var factoryCalls = 0
        harness = Harness(
            token = null,
            writer = TokenWriter { saved -> harness.tokenStore.token = saved },
            newToken = { factoryCalls += 1; "created-once-$factoryCalls" },
        )
        assertTrue(harness.start())
        harness.runTasks()
        harness.controller.stop()

        val second = SourceProxyController(
            tokenStore = harness.tokenStore,
            hotspotFinder = harness.finder,
            selectionFactory = { harness.selection },
            resolverFactory = { SourceHostResolver { emptyList() } },
            echoFactory = { SourceEchoSender { _, _, _ -> EchoResult(EchoStatus.FAILED) } },
            serverFactory = { _, _, _, _, _ -> FakeServer(false) },
            watchFactory = { FakeWatch(false) },
            listener = RecordingListener(),
            tokenGuard = harness.guard,
            taskQueueFactory = { ManualSourceProxyTaskQueue() },
            tokenWriter = TokenWriter { throw AssertionError("A stored token is never rewritten.") },
        )
        assertTrue(second.start())

        assertEquals("created-once-1", harness.tokenStore.token)
        assertEquals(1, factoryCalls)
    }

    @Test
    fun aFailedFirstTokenSaveStopsWithStartFailedAndStoresNothing() {
        val harness = Harness(
            token = null,
            writer = TokenWriter { throw IOException("The disk refused the write.") },
        )

        assertFalse(harness.start())

        assertEquals(SourceProxyStopReason.START_FAILED, harness.controller.stopReason)
        assertNull(harness.tokenStore.token)
        assertEquals(0, harness.selection.starts)
        assertTrue(harness.servers.isEmpty())
        assertFalse(harness.guard.isRunHeld())
        assertEquals(1, harness.listener.terminals.size)
    }

    @Test
    fun aTokenSavedByAnotherWriterBeforeTheGuardedReloadWins() {
        val reads = AtomicInteger()
        val racing = TokenStore {
            // The first read sees no token. A pairing saves one before the
            // guarded read, so the second read finds it.
            if (reads.incrementAndGet() == 1) null else "pairing-saved-token"
        }
        val harness = Harness(
            token = null,
            tokenStoreOverride = racing,
            writer = TokenWriter { throw AssertionError("The start must not overwrite it.") },
        )

        assertTrue(harness.start())
        harness.runTasks()
        harness.available()

        assertEquals(listOf("pairing-saved-token"), harness.requestedTokens.toList())
    }

    @Test
    fun anUnreadableStoreInsideTheGuardIsUnreadableNotCreated() {
        val reads = AtomicInteger()
        val flaky = TokenStore {
            if (reads.incrementAndGet() == 1) {
                null
            } else {
                throw TokenReadException("busy", IOException("busy"), TokenReadKind.TRANSIENT)
            }
        }
        val harness = Harness(
            token = null,
            tokenStoreOverride = flaky,
            writer = TokenWriter { throw AssertionError("An unreadable store is never replaced.") },
        )

        assertFalse(harness.start())

        assertEquals(SourceProxyStopReason.TOKEN_UNREADABLE, harness.controller.stopReason)
        assertTrue(harness.servers.isEmpty())
    }

    @Test
    fun anUncertainFirstSaveFailsTheStartEvenIfItLanded() {
        lateinit var harness: Harness
        var writes = 0
        harness = Harness(
            token = null,
            writer = TokenWriter { saved ->
                writes += 1
                harness.tokenStore.token = saved
                throw TokenWriteUncertainException(IOException("sync failed"))
            },
            newToken = { "landed-token" },
        )

        assertFalse(harness.start())

        assertEquals(1, writes)
        assertEquals(SourceProxyStopReason.START_FAILED, harness.controller.stopReason)
        assertTrue(harness.servers.isEmpty())
        assertFalse(harness.guard.isRunHeld())
    }

    @Test
    fun withoutAWriterAMissingTokenStillStopsAsMissing() {
        val harness = Harness(token = null, writer = null)

        assertFalse(harness.start())

        assertEquals(SourceProxyStopReason.TOKEN_MISSING, harness.controller.stopReason)
    }

    private fun daemon(name: String, body: () -> Unit): Thread =
        Thread(body, name).apply { isDaemon = true }

    private fun awaitIgnoringInterrupt(latch: CountDownLatch) {
        var interrupted = false
        while (true) {
            try {
                latch.await()
                break
            } catch (_: InterruptedException) {
                // A factory can ignore interruption until the listener closes.
                interrupted = true
            }
        }
        if (interrupted) Thread.currentThread().interrupt()
    }

    private companion object {
        const val PORT = 40123
        const val TOKEN = "controller-test-token"
        val HOTSPOT: InetAddress = InetAddress.getByName("192.168.43.1")

        fun observed(address: InetAddress): HotspotProbe.Observed = HotspotProbe.Observed(
            candidates = listOf(HotspotCandidate(rank = 0, address = address)),
            excludedAddresses = emptySet(),
        )
    }
}
