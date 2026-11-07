package com.hotspotshade.source

import java.util.ArrayDeque
import java.util.concurrent.RejectedExecutionException

/**
 * A deterministic controller queue for JVM tests.
 *
 * The test decides when each start wait or session setup runs. [shutdown]
 * drops queued work, as the production single-thread executor does after a
 * stop. A concurrency test can run one task on its own thread with [runNext]
 * while the test thread stops the controller. The tests stay hermetic: no
 * platform clock is read and no route or interface is touched.
 */
internal class ManualSourceProxyTaskQueue : SourceProxyTaskQueue {
    private val lock = Any()
    private val tasks = ArrayDeque<Runnable>()

    @Volatile
    var shutdown = false
        private set

    override fun execute(task: Runnable) {
        synchronized(lock) {
            if (shutdown) throw RejectedExecutionException("The queue is shut down.")
            tasks.addLast(task)
        }
    }

    override fun shutdown() {
        synchronized(lock) {
            shutdown = true
            tasks.clear()
        }
    }

    /** Run queued work until the queue is empty or shut down. */
    fun runAll() {
        while (true) {
            val task = take() ?: return
            task.run()
        }
    }

    /**
     * Run one queued task on the calling thread.
     *
     * Return false when the queue is shut down or empty. A task that was
     * already taken keeps running after a shutdown, as a worker task does.
     */
    fun runNext(): Boolean {
        val task = take() ?: return false
        task.run()
        return true
    }

    private fun take(): Runnable? = synchronized(lock) {
        if (shutdown) return null
        tasks.pollFirst()
    }
}
