package com.hotspotshade.source.pairing

import java.util.ArrayDeque
import java.util.IdentityHashMap
import java.util.concurrent.ThreadFactory
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * Dispatch host callbacks on a process-wide bounded set of daemon threads.
 *
 * A listener or coordinator owns one lane. Work for one lane is serialized and
 * coalesced: while the lane is running or queued, a newer action replaces the
 * older one. A blocked host callback therefore occupies at most one worker and
 * cannot create a new thread for the next listener or coordinator.
 *
 * The owner table, the waiting queue, and the retry set are bounded. When the
 * table is full, an idle lane is released before new work is refused. A lane
 * with queued or running work is never dropped. A running lane is never
 * interrupted or waited for, so close and stop do not depend on host code.
 * Actions run outside the dispatcher lock. A retired lane drops queued work
 * and runs no new action; an action that was already admitted may finish.
 *
 * A refused dispatch can leave a pending publication with no later event to
 * carry it. [dispatchOrRetry] keeps one bounded retry ticket per lane. When a
 * lane finishes, retires, or is evicted, the dispatcher immediately tries the
 * tickets again on the thread that freed the room. Dispatch only queues a
 * lane; it runs no host code on that thread. A ticket holds no thread and the
 * dispatcher never spins.
 *
 * A host callback that throws any [Throwable], including an [Error], cannot
 * break a worker or strand lane bookkeeping. A worker that still exits
 * unexpectedly is replaced while the dispatcher is not stopped, so the pool
 * keeps its configured size.
 */
internal class PairingCallbackDispatcher(
    private val workerCount: Int = DEFAULT_WORKER_COUNT,
    private val maxOwners: Int = DEFAULT_MAX_OWNERS,
    private val threadFactory: ThreadFactory = daemonFactory(),
) {
    init {
        require(workerCount > 0) { "The callback dispatcher needs at least one worker." }
        require(maxOwners > 0) { "The callback dispatcher needs at least one lane." }
    }

    private val lock = ReentrantLock()
    private val idle = lock.newCondition()
    private val queue = ArrayDeque<OwnerState>()
    private val owners = IdentityHashMap<Any, OwnerState>()
    // A refused lane keeps at most one ticket. The set is bounded by
    // maxOwners, so a full process cannot grow retry state without limit.
    private val retries = IdentityHashMap<Any, RetryTicket>()
    private val liveWorkers = AtomicInteger(0)
    private var stopped = false

    init {
        repeat(workerCount) { startWorker() }
    }

    /**
     * Queue one action for [owner].
     *
     * Repeated calls coalesce to the latest action. Return false when the lane
     * table is full and no idle lane can be released. The caller keeps its
     * pending state and may try again on a later event or use
     * [dispatchOrRetry].
     */
    fun dispatch(owner: Any, action: () -> Unit): Boolean = lock.withLock {
        if (stopped) return false
        if (!dispatchLocked(owner, action)) return false
        retries.remove(owner)
        true
    }

    /**
     * Queue one action, or keep a bounded retry ticket for it.
     *
     * Return true when the action is queued now or a ticket will retry it as
     * soon as a lane frees. Return false only when the retry set is full, so
     * the caller must keep its pending state and retry on a later event.
     */
    fun dispatchOrRetry(owner: Any, action: () -> Unit): Boolean = lock.withLock {
        if (stopped) return false
        if (dispatchLocked(owner, action)) {
            retries.remove(owner)
            return true
        }
        if (retries.size >= maxOwners && !retries.containsKey(owner)) return false
        val ticket = retries[owner] ?: RetryTicket(owner).also { retries[owner] = it }
        ticket.action = action
        true
    }

    /**
     * Stop this lane.
     *
     * Queued work and a retry ticket are dropped. An action that already
     * started may finish. The call returns without waiting for a blocked host
     * callback.
     */
    fun retire(owner: Any) {
        lock.withLock {
            retries.remove(owner)
            val state = owners[owner]
            if (state == null) {
                retryPendingLocked()
                return
            }
            state.retired = true
            state.action = null
            if (!state.running) {
                if (state.queued) {
                    queue.remove(state)
                    state.queued = false
                }
                owners.remove(owner)
            }
            // A blocked action frees no room yet. The worker retries when it
            // finishes, so this call stays non-blocking.
            retryPendingLocked()
        }
    }

    /** Stop every worker for a test-owned dispatcher. This does not interrupt host code. */
    internal fun shutdown() {
        lock.withLock {
            stopped = true
            queue.clear()
            owners.clear()
            retries.clear()
            idle.signalAll()
        }
    }

    /** The number of worker threads that are currently alive. */
    internal fun liveWorkerCount(): Int = liveWorkers.get()

    /** The number of admitted lanes, including a lane with a blocked callback. */
    internal fun trackedOwnerCount(): Int = lock.withLock { owners.size }

    /** The number of lanes waiting for a worker. */
    internal fun queuedOwnerCount(): Int = lock.withLock { queue.size }

    /** The number of lanes waiting for room to open. */
    internal fun retryOwnerCount(): Int = lock.withLock { retries.size }

    private fun dispatchLocked(owner: Any, action: () -> Unit): Boolean {
        var state = owners[owner]
        if (state == null) {
            if (owners.size >= maxOwners && !evictIdleLocked()) return false
            state = OwnerState(owner)
            owners[owner] = state
        }
        if (state.retired) return false
        state.action = action
        if (!state.queued && !state.running) {
            state.queued = true
            queue.addLast(state)
            idle.signal()
        }
        return true
    }

    private fun evictIdleLocked(): Boolean {
        val victim = owners.values.firstOrNull {
            !it.running && !it.queued && it.action == null
        } ?: return false
        owners.remove(victim.owner)
        return true
    }

    /**
     * Try every ticket while the caller holds [lock].
     *
     * [dispatchLocked] only adds a lane to the queue, so no host code runs on
     * the caller's thread. Call this only where room may have just opened.
     */
    private fun retryPendingLocked() {
        if (stopped || retries.isEmpty()) return
        val iterator = retries.values.iterator()
        while (iterator.hasNext()) {
            val ticket = iterator.next()
            val action = ticket.action
            if (action == null) {
                iterator.remove()
                continue
            }
            if (dispatchLocked(ticket.owner, action)) iterator.remove()
        }
    }

    private fun startWorker() {
        val thread = try {
            threadFactory.newThread { workerLoop() }
        } catch (_: Throwable) {
            return
        }
        thread.isDaemon = true
        try {
            thread.start()
        } catch (_: Throwable) {
            // The dispatcher keeps its remaining workers.
        }
    }

    private fun workerLoop() {
        liveWorkers.incrementAndGet()
        try {
            while (true) {
                val state = try {
                    lock.withLock {
                        while (queue.isEmpty() && !stopped) idle.await()
                        if (stopped) return
                        val next = queue.removeFirst()
                        next.queued = false
                        next.running = true
                        next
                    }
                } catch (_: InterruptedException) {
                    return
                } catch (_: Throwable) {
                    // An internal failure must not silently reduce the pool.
                    continue
                }
                var action: (() -> Unit)? = null
                try {
                    action = lock.withLock {
                        if (state.retired) {
                            null
                        } else {
                            state.action.also { state.action = null }
                        }
                    }
                    action?.invoke()
                } catch (_: Throwable) {
                    // Host failures, including an Error, must not break the
                    // dispatcher or leave the lane marked running forever.
                } finally {
                    lock.withLock {
                        state.running = false
                        if (stopped || state.retired) {
                            state.action = null
                            if (owners[state.owner] === state) owners.remove(state.owner)
                        } else if (state.action != null && !state.queued) {
                            state.queued = true
                            queue.addLast(state)
                            idle.signal()
                        }
                        retryPendingLocked()
                    }
                }
            }
        } finally {
            liveWorkers.decrementAndGet()
            // Replace a worker that exited for a reason other than shutdown,
            // so a queued lane or a retry ticket is never stranded.
            if (lock.withLock { !stopped }) startWorker()
        }
    }

    private class OwnerState(val owner: Any) {
        var action: (() -> Unit)? = null
        var queued = false
        var running = false
        var retired = false
    }

    private class RetryTicket(val owner: Any) {
        var action: (() -> Unit)? = null
    }

    companion object {
        /** The process-wide dispatcher. Every listener and coordinator shares it. */
        val shared = PairingCallbackDispatcher()

        const val DEFAULT_WORKER_COUNT = 2
        const val DEFAULT_MAX_OWNERS = 16

        internal fun daemonFactory(): ThreadFactory {
            val index = AtomicInteger(0)
            return ThreadFactory { runnable ->
                Thread(runnable, "pairing-callback-${index.getAndIncrement()}").apply {
                    isDaemon = true
                }
            }
        }
    }
}
