package com.hotspotshade.source

import android.app.Application
import com.hotspotshade.source.pairing.PairingPrompt
import com.hotspotshade.source.pairing.PromptId
import org.junit.Assert.*
import org.junit.Test

class PairingViewModelLifecycleTest {
    private class Listener(val callback: (PairingPrompt?) -> Unit) : PairingListenerHandle {
        var starts = 0
        var stops = 0
        var approvals = 0
        var rotations = 0
        var rotationResult = TokenRotateResult.ROTATED
        var startAction: () -> Unit = {}
        override fun start() { starts++; startAction() }
        override fun stop() { stops++ }
        override fun activate() {}
        override fun deactivate() {}
        override fun allow(prompt: PairingPrompt) { approvals++ }
        override fun deny(prompt: PairingPrompt) {}
        override fun trustChanged() {}
        override fun rotateToken(): TokenRotateResult { rotations++; return rotationResult }
    }
    private class Harness {
        val worker = ArrayDeque<() -> Unit>()
        val main = ArrayDeque<() -> Unit>()
        val listeners = mutableListOf<Listener>()
        var configure: (Listener) -> Unit = {}
        var snapshot: List<TrustedTarget>? = listOf(TrustedTarget("old", "Old"))
        var mutations = 0
        var failMutation = false
        val model = PairingViewModel(Application(), PairingViewModelTestHooks(
            worker = { worker.addLast(it) }, main = { main.addLast(it) },
            delayed = { _, _ -> }, readTargets = { snapshot },
            listenerFactory = { prompt, _, _ -> Listener(prompt).also { listeners.add(it); configure(it) } },
            forget = { mutations++; if (failMutation) error("failure"); true },
        ))
        fun work() { while (worker.isNotEmpty()) worker.removeFirst()() }
        fun publish() { while (main.isNotEmpty()) main.removeFirst()() }
        fun settle() { while (worker.isNotEmpty() || main.isNotEmpty()) { work(); publish() } }
    }
    @Test fun promptDuringStartCanBeApprovedBeforePublicationAndRotationUsesOwner() {
        val h = Harness()
        h.model.setVisible(true)
        h.configure = { listener -> listener.startAction = {
            listener.callback(PairingPrompt(PromptId(1), 1, "123456"))
            h.publish(); h.model.allow(); h.model.rotateToken()
        } }
        h.model.start(); h.settle()
        assertEquals(1, h.listeners.single().approvals)
        assertEquals(1, h.listeners.single().rotations)
        assertNull(h.model.prompt)
    }
    @Test fun failedRotationReportsAnUnconfirmedOutcome() {
        val h = Harness()
        h.configure = { it.rotationResult = TokenRotateResult.FAILED }
        h.model.start(); h.settle()
        h.model.rotateToken(); h.settle()
        assertEquals(1, h.listeners.single().rotations)
        assertEquals(
            "The source token change could not be confirmed. Paired target devices may need to pair again.",
            h.model.message,
        )
    }
    @Test fun failureAndStaleStartAreTornDownAndRestartWorks() {
        val h = Harness()
        h.configure = { listener -> listener.startAction = {
            listener.callback(PairingPrompt(PromptId(3), 3, "123456"))
            error("start failed")
        } }
        h.model.start(); h.settle()
        assertEquals(RealPairingListener.FAILED, h.model.status.listener)
        assertNull(h.model.prompt)
        assertEquals(1, h.listeners[0].stops)
        h.configure = { }
        h.model.start(); h.work()
        val stale = h.listeners[1]
        h.model.stop(); h.model.start(); h.publish(); h.settle()
        assertTrue(stale.stops >= 1)
        assertEquals(1, h.listeners[2].starts)
        stale.callback(PairingPrompt(PromptId(2), 2, "123456")); h.publish()
        assertNull(h.model.prompt)
    }
    @Test fun failedStartRefreshesAListWhoseResultWasInvalidated() {
        val h = Harness()
        h.model.setVisible(true)
        h.model.setTrustListVisible(true)
        h.configure = { listener -> listener.startAction = { error("start failed") } }
        h.model.start()
        // Complete the initial list read and the failed start before delivering
        // either result to the main queue.
        h.work()
        h.publish()
        h.settle()
        assertEquals(RealPairingListener.FAILED, h.model.status.listener)
        assertEquals(false, h.model.trustUnavailable)
        assertEquals("old", h.model.targets.single().id)
    }
    @Test fun stopDuringCreationClosesUnpublishedListener() {
        val h = Harness()
        h.configure = { h.model.stop() }
        h.model.start(); h.settle()
        assertEquals(0, h.listeners.single().starts)
        assertEquals(1, h.listeners.single().stops)
        assertEquals(RealPairingListener.STOPPED, h.model.status.listener)
    }
    @Test fun repeatedMutationsWaitForFreshSnapshotAcrossReopenAndFailure() {
        val h = Harness()
        h.model.setVisible(true); h.model.setTrustListVisible(true); h.settle()
        h.model.forgetAllTargets(); h.model.forgetAllTargets(); h.model.forgetTarget("old")
        h.work()
        h.model.stop()
        h.model.setTrustListVisible(false); h.model.setTrustListVisible(true)
        h.model.start(); h.publish()
        h.model.forgetAllTargets()
        assertEquals(1, h.mutations)
        h.snapshot = listOf(TrustedTarget("new", "New")); h.settle()
        assertEquals("new", h.model.targets.single().id)
        assertEquals(1, h.mutations)
        h.failMutation = true
        h.model.forgetTarget("new"); h.settle()
        assertEquals(2, h.mutations)
        assertEquals(false, h.model.trustUnavailable)
        h.failMutation = false
        h.model.forgetTarget("new"); h.settle()
        assertEquals(3, h.mutations)
    }
}
