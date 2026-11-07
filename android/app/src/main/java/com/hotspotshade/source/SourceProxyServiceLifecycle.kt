package com.hotspotshade.source

import java.io.IOException

/**
 * One source proxy run that the service owns.
 *
 * The service queue calls [start] and [stop] off the main thread. A status
 * read and a snapshot are short, so the service and the app can ask for the
 * current state from another thread while a stop runs.
 */
internal interface SourceProxyServiceRun {
    /** True while the run waits, binds, or serves flows. */
    val isActive: Boolean

    /** The current state. It holds no token, address, or host. */
    fun snapshot(): SourceProxySnapshot

    /** Start the run. Return false when it refuses to start. */
    fun start(): Boolean

    /** Stop the run. This call is idempotent. */
    fun stop()

    /** The last socket close failure, or null after a complete close. */
    val closeFailure: IOException?
}

/** The result of one service start request. */
internal sealed interface SourceProxyServiceStart {
    /** The coordinator queued the first work item for this generation. */
    data class Queued(val generation: Long) : SourceProxyServiceStart

    /** A run is live. The service re-asserts its notification and report. */
    data class Active(
        val generation: Long,
        val snapshot: SourceProxySnapshot,
    ) : SourceProxyServiceStart

    /** A start is already queued or in progress. It must not be duplicated. */
    data class Starting(val generation: Long) : SourceProxyServiceStart

    /** The coordinator cannot accept work, because it is destroyed or closed. */
    data object Refused : SourceProxyServiceStart
}

/** The result of one service stop request. */
internal enum class SourceProxyServiceStop {
    /** The coordinator queued the stop. The terminal report ends the service. */
    QUEUED,

    /** No run exists and no start is pending. The service can stop now. */
    IDLE,

    /** The service is already destroyed. */
    IGNORED,
}

/**
 * Serialize one source proxy service run and keep its state honest.
 *
 * The service calls [start], [stop], and [destroy] on the main thread. Every
 * blocking step runs on the supplied queue instead: the environment build, the
 * token load, the listener bind, the socket closes, and the thread joins. The
 * main thread only posts a notification and records a short snapshot.
 *
 * A start request takes one generation. A second request while that start is
 * queued or in progress returns [SourceProxyServiceStart.Starting] and does
 * not create a second run. A stop or a destroy cancels a start that has not
 * reached its run yet. A callback from an older run is dropped by identity.
 * The last terminal report wins exactly once per run, and the coordinator
 * stays silent after a destroy.
 *
 * This class holds no Android framework type, so a JVM test can drive every
 * race with a manual queue. It never starts a thread itself.
 */
internal class SourceProxyServiceCoordinator(
    private val queue: SourceProxyTaskQueue,
    private val runFactory: (SourceProxyListener) -> SourceProxyServiceRun,
    private val onState: (SourceProxySnapshot, Long) -> Unit,
    private val onTerminal: (SourceProxySnapshot, Long) -> Unit,
) {
    private val lock = Any()
    private var generation = 0L
    private var run: SourceProxyServiceRun? = null
    private var runGeneration = 0L
    private var startPending = false
    private var cancelRequested = false
    private var stopping: SourceProxyServiceRun? = null
    private var failureRun: SourceProxyServiceRun? = null
    private var destroyed = false

    /** True while a run exists or a start is queued or in progress. */
    fun hasPendingRun(): Boolean = synchronized(lock) {
        !destroyed && (startPending || run != null)
    }

    /** Accept one start request. This call never blocks on run work. */
    fun start(): SourceProxyServiceStart {
        var queuedGeneration = 0L
        synchronized(lock) {
            if (destroyed) return SourceProxyServiceStart.Refused
            val current = run
            if (current != null && current.isActive) {
                return SourceProxyServiceStart.Active(generation, current.snapshot())
            }
            if (startPending) {
                // A stop arrived before this request. The queued start has
                // not run yet, so it can serve the new request.
                cancelRequested = false
                return SourceProxyServiceStart.Starting(generation)
            }
            generation += 1
            queuedGeneration = generation
            startPending = true
            cancelRequested = false
        }
        if (!submit { doStart(queuedGeneration) }) {
            synchronized(lock) {
                if (generation == queuedGeneration && startPending) {
                    startPending = false
                }
            }
            return SourceProxyServiceStart.Refused
        }
        return SourceProxyServiceStart.Queued(queuedGeneration)
    }

    /** Accept one stop request. This call never blocks on run work. */
    fun stop(): SourceProxyServiceStop {
        var target: SourceProxyServiceRun? = null
        synchronized(lock) {
            if (destroyed) return SourceProxyServiceStop.IGNORED
            cancelRequested = true
            val current = run
            if (current != null) {
                if (stopping !== current) {
                    stopping = current
                    target = current
                }
            } else if (!startPending) {
                return SourceProxyServiceStop.IDLE
            }
        }
        val toStop = target
        if (toStop != null && !submit { doStop(toStop) }) {
            synchronized(lock) { if (stopping === toStop) stopping = null }
            return SourceProxyServiceStop.IDLE
        }
        return SourceProxyServiceStop.QUEUED
    }

    /**
     * Cancel a pending start and stop the current run on the queue.
     *
     * The service records its own terminal report and detaches before it
     * calls this method. The coordinator does not report state after destroy.
     * The queue is shut down on its own worker after the last cleanup, so the
     * destroy never interrupts a close that is already running.
     */
    fun destroy() {
        synchronized(lock) {
            if (destroyed) return
            destroyed = true
            cancelRequested = true
        }
        submit { doDestroy() }
    }

    /**
     * Build one run, publish it, and start it on the service queue.
     *
     * The run is published before its start. A stop that arrives while the
     * start waits for the token or the queue takes the run through [doStop].
     */
    private fun doStart(requested: Long) {
        val proceed = synchronized(lock) {
            !destroyed && !cancelRequested && startPending && generation == requested
        }
        if (!proceed) {
            reportAbortedStart(requested)
            return
        }
        var created: SourceProxyServiceRun? = null
        val listener = SourceProxyListener { snapshot ->
            val current = created
            if (current != null) onRunSnapshot(current, snapshot)
        }
        val newRun = try {
            runFactory(listener)
        } catch (_: Exception) {
            reportFailedStart(requested)
            return
        }
        created = newRun
        val accepted = synchronized(lock) {
            if (!destroyed && !cancelRequested && startPending && generation == requested) {
                run = newRun
                runGeneration = requested
                true
            } else {
                false
            }
        }
        if (!accepted) {
            // The stop or destroy won before the run was published. Stop the
            // run before it starts, and never publish its report.
            closeQuietly(newRun)
            reportAbortedStart(requested)
            return
        }
        var started = false
        var failure: Exception? = null
        try {
            started = newRun.start()
        } catch (caught: Exception) {
            failure = caught
        }
        val stillCurrent = synchronized(lock) {
            if (run === newRun && runGeneration == requested) {
                startPending = false
                true
            } else {
                false
            }
        }
        if (failure != null) {
            // A dead run must report START_FAILED, not the stop reason that
            // its cleanup normally reports.
            synchronized(lock) {
                if (run === newRun) failureRun = newRun
            }
            closeQuietly(newRun)
            val missing = synchronized(lock) {
                if (run === newRun) {
                    clearRunLocked()
                    true
                } else {
                    false
                }
            }
            if (missing) {
                reportTerminal(
                    SourceProxySnapshot(
                        SourceProxyState.STOPPED,
                        SourceProxyStopReason.START_FAILED,
                        0,
                    ),
                    requested,
                )
            }
            return
        }
        if (!started && stillCurrent) {
            // A refused start normally reports its own terminal. Report one
            // here only when no terminal arrived, so the service never stays
            // on Starting after a refused start.
            val missing = synchronized(lock) {
                if (run === newRun) {
                    clearRunLocked()
                    true
                } else {
                    false
                }
            }
            if (missing) {
                reportTerminal(
                    SourceProxySnapshot(
                        SourceProxyState.STOPPED,
                        SourceProxyStopReason.START_FAILED,
                        0,
                    ),
                    requested,
                )
            }
        }
    }

    /** Stop one published run on the service queue. */
    private fun doStop(target: SourceProxyServiceRun) {
        try {
            target.stop()
        } catch (_: Exception) {
            // The terminal report below still runs.
        }
        // Retry one incomplete socket close on the same worker. The service
        // used to retry it on the main thread.
        if (target.closeFailure != null) {
            try {
                target.stop()
            } catch (_: Exception) {
                // The run is already ending.
            }
        }
        var missing = false
        var stoppedGeneration = 0L
        synchronized(lock) {
            if (stopping === target) stopping = null
            if (run === target) {
                stoppedGeneration = runGeneration
                // A newer start can be accepted after this run stops being
                // active but before its terminal report arrives. Keep that
                // pending start alive.
                val newerStart = generation != runGeneration
                run = null
                runGeneration = 0
                if (!newerStart) startPending = false
                missing = true
            }
        }
        if (missing) {
            reportTerminal(
                SourceProxySnapshot(
                    SourceProxyState.STOPPED,
                    SourceProxyStopReason.USER_STOP,
                    0,
                ),
                stoppedGeneration,
            )
        }
    }

    /** Stop any published run and close the service queue on its worker. */
    private fun doDestroy() {
        val target = synchronized(lock) { run }
        if (target != null) {
            try {
                target.stop()
            } catch (_: Exception) {
                // Best effort. The queue still closes.
            }
            if (target.closeFailure != null) {
                try {
                    target.stop()
                } catch (_: Exception) {
                    // The run is already ending.
                }
            }
            synchronized(lock) {
                if (run === target) clearRunLocked()
            }
        }
        synchronized(lock) {
            startPending = false
            cancelRequested = false
            stopping = null
            failureRun = null
            runGeneration = 0
        }
        try {
            queue.shutdown()
        } catch (_: Exception) {
            // The queue is already closed.
        }
    }

    /** Forward one run report, or consume its terminal state exactly once. */
    private fun onRunSnapshot(created: SourceProxyServiceRun, snapshot: SourceProxySnapshot) {
        var currentGeneration = 0L
        var terminal = false
        var failed = false
        var retryClose = false
        synchronized(lock) {
            if (run !== created) return
            currentGeneration = runGeneration
            if (snapshot.state == SourceProxyState.STOPPED) {
                terminal = true
                failed = failureRun === created
                retryClose = stopping !== created && created.closeFailure != null
                // A newer start can be accepted after this run stops being
                // active but before this terminal report arrives. Do not
                // cancel that pending start.
                val newerStart = generation != runGeneration
                if (stopping === created) stopping = null
                if (failureRun === created) failureRun = null
                run = null
                runGeneration = 0
                if (!newerStart) startPending = false
            }
        }
        if (destroyed) return
        if (!terminal) {
            onState(snapshot, currentGeneration)
            return
        }
        val report = if (failed) {
            snapshot.copy(reason = SourceProxyStopReason.START_FAILED)
        } else {
            snapshot
        }
        onTerminal(report, currentGeneration)
        if (retryClose) {
            // A spontaneous stop can report an incomplete close. Retry it on
            // the service queue, never on the thread that reported the state.
            submit {
                try {
                    created.stop()
                } catch (_: Exception) {
                    // The run is already ending.
                }
            }
        }
    }

    /** Report a start that a stop or a destroy cancelled before its run. */
    private fun reportAbortedStart(requested: Long) {
        var report = false
        var restart = false
        synchronized(lock) {
            if (!destroyed && generation == requested && startPending && !cancelRequested) {
                // A new start re-armed this pending request before the worker
                // observed the stop. Run it now instead of dropping it.
                restart = true
            } else {
                if (startPending && generation == requested) startPending = false
                report = !destroyed
            }
        }
        if (restart) {
            doStart(requested)
            return
        }
        if (report) {
            reportTerminal(
                SourceProxySnapshot(
                    SourceProxyState.STOPPED,
                    SourceProxyStopReason.USER_STOP,
                    0,
                ),
                requested,
            )
        }
    }

    /** Report a factory failure that never produced a run. */
    private fun reportFailedStart(requested: Long) {
        val report = synchronized(lock) {
            if (startPending && generation == requested) startPending = false
            !destroyed && generation == requested
        }
        if (report) {
            reportTerminal(
                SourceProxySnapshot(
                    SourceProxyState.STOPPED,
                    SourceProxyStopReason.START_FAILED,
                    0,
                ),
                requested,
            )
        }
    }

    /** Send one synthetic terminal report unless the service is gone. */
    private fun reportTerminal(snapshot: SourceProxySnapshot, reportGeneration: Long) {
        if (synchronized(lock) { destroyed }) return
        onTerminal(snapshot, reportGeneration)
    }

    /** Clear the published run. The caller holds [lock]. */
    private fun clearRunLocked() {
        run = null
        runGeneration = 0
        startPending = false
    }

    /** Run one service task. A rejected queue reports a closed coordinator. */
    private fun submit(task: () -> Unit): Boolean = try {
        queue.execute {
            try {
                task()
            } catch (_: Exception) {
                // A task failure must not kill the service worker.
            }
        }
        true
    } catch (_: Exception) {
        false
    }

    private fun closeQuietly(runToClose: SourceProxyServiceRun?) {
        if (runToClose == null) return
        try {
            runToClose.stop()
        } catch (_: Exception) {
            // The run is already ending.
        }
    }
}

/**
 * The lifecycle decisions of the source proxy service that do not need the
 * Android framework.
 *
 * The service is destroyed on the main thread. Its controller reports the
 * terminal state through the listener, and that report is posted to the same
 * main thread. The post then finds no controller and is dropped. This object
 * holds the fixed decision that keeps the process report honest in that case.
 * A JVM test checks it without a service, a device, or a network.
 */
internal object SourceProxyServiceLifecycle {
    /**
     * Whether the service may start the background status host.
     *
     * Enabled 2026-11-06 after the status-only responder policy, the run
     * identity fence, and the token epoch fence were reviewed. Without it the
     * target stops the tunnel 90 seconds after the activity leaves the
     * screen, because the visible listener is the only one on port 18090. The
     * host rejects pairing, re-pair, and Forget before a credential callback,
     * prompt, or trust mutation, binds only the controller's live hotspot
     * address, and fences one run and one token epoch. It answers only a
     * target key that was confirmed in this process, so it never weakens the
     * in-process trust rule. Those rules have JVM and loopback tests only. A
     * real-device background test (screen lock, OEM background limits, a real
     * hotspot) is still open. Do not describe this as proven on a phone.
     */
    const val BACKGROUND_STATUS_ENABLED = true

    /**
     * Return the terminal report to record when the service is destroyed.
     *
     * A live or waiting run must not stay `RUNNING` in the process report
     * after its service is gone, because the app and the pairing responder
     * read that report. The report keeps a real stop reason and uses
     * `USER_STOP` for a run that had not ended; the platform has no separate
     * reason for a service that is destroyed while it runs. It never carries a
     * port: the listener is closed or about to close.
     *
     * The deferred in-flight lease is unchanged. The controller releases the
     * run lease after its last task returns, so a rotation still cannot
     * replace the token under a listener that the task is closing.
     */
    fun destroyedReport(snapshot: SourceProxySnapshot?): SourceProxySnapshot {
        val reason = snapshot?.reason?.takeIf { it != SourceProxyStopReason.NONE }
            ?: SourceProxyStopReason.USER_STOP
        return SourceProxySnapshot(
            state = SourceProxyState.STOPPED,
            reason = reason,
            port = 0,
        )
    }

    /**
     * Stop one controller and record its terminal report before detaching it.
     *
     * [record] must run before [detach]. A reader that sees no attached
     * controller falls back to the last recorded report, so detaching first
     * would briefly expose the previous `RUNNING` report and a stale binding
     * to a pairing answer. A failed stop or a failed snapshot still records a
     * terminal report and still detaches, so a broken cleanup cannot leave the
     * old live report in place.
     *
     * The service passes a stop callback that only queues the worker, so this
     * helper stays fast on the main thread.
     */
    fun finishDestroyedRun(
        stop: () -> Unit,
        snapshot: () -> SourceProxySnapshot?,
        record: (SourceProxySnapshot) -> Unit,
        detach: () -> Unit,
    ) {
        try {
            stop()
        } catch (_: Exception) {
            // Cleanup is best effort. The report and the detach still run.
        }
        try {
            val report = try {
                destroyedReport(snapshot())
            } catch (_: Exception) {
                destroyedReport(null)
            }
            record(report)
        } catch (_: Exception) {
            // The process report is best effort too. Detach must still run.
        } finally {
            detach()
        }
    }

    /** True when a repeated start must show the running notification. */
    fun showsRunning(snapshot: SourceProxySnapshot): Boolean =
        snapshot.state == SourceProxyState.RUNNING
}
