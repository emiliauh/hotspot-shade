package com.hotspotshade.source

import java.net.InetAddress
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit

/** Report when the bound hotspot address disappears. A JVM test uses a fake. */
internal interface HotspotWatch {
    /** Start the watch. It reports at most one loss. */
    fun start(onLost: () -> Unit)

    /** Stop the watch. This call is idempotent. */
    fun stop()
}

/**
 * The meaning of one probe for the bound hotspot address.
 *
 * The watch closes at once on [KNOWN_UNSAFE] and debounces [UNCERTAIN]. It
 * clears the miss count on [VALID]. A [PENDING] probe neither clears nor
 * advances the miss count for a bounded run, because the API 36 callback has
 * not delivered its first reading yet. Pending is bounded twice: the evidence
 * falls back after [TetheredInterfaceEvidence.DEFAULT_PENDING_TIMEOUT_MILLIS],
 * and the watch policy counts a pending probe as uncertain after
 * [HotspotWatchPolicy.DEFAULT_PENDING_CHECKS_BEFORE_UNCERTAIN] consecutive
 * probes. A callback that never fires therefore cannot leave the watch blind
 * to a lost hotspot.
 */
internal enum class HotspotProbeVerdict {
    /** The bound address is a confirmed tethering candidate. */
    VALID,

    /** The bound address belongs to an interface that a reported network holds. */
    KNOWN_UNSAFE,

    /** The probe does not decide whether the bound interface is still tethering. */
    UNCERTAIN,

    /** The first tethering callback reading has not arrived yet. */
    PENDING,
}

/**
 * The loss decision for one hotspot watch.
 *
 * A [HotspotProbeVerdict.VALID] probe clears the miss count. A
 * [HotspotProbeVerdict.KNOWN_UNSAFE] probe reports a loss at once, because no
 * later check can turn a client or upstream interface into a hotspot. A
 * [HotspotProbeVerdict.UNCERTAIN] probe reports a loss only after
 * [missingChecksBeforeLoss] consecutive misses. A
 * [HotspotProbeVerdict.PENDING] probe leaves the count unchanged for
 * [pendingChecksBeforeUncertain] consecutive probes, because the first API 36
 * callback delivery has not arrived. After that bound the probe counts as
 * uncertain, so a callback that never fires cannot leave the watch blind. The
 * evidence normally expires its own pending state first. The policy reports at
 * most one loss and never restarts anything.
 */
internal class HotspotWatchPolicy(
    private val expected: InetAddress,
    private val missingChecksBeforeLoss: Int,
    private val pendingChecksBeforeUncertain: Int = DEFAULT_PENDING_CHECKS_BEFORE_UNCERTAIN,
) {
    init {
        require(missingChecksBeforeLoss > 0) {
            "The hotspot watch missing-check count must be positive."
        }
        require(pendingChecksBeforeUncertain > 0) {
            "The hotspot watch pending-check count must be positive."
        }
    }

    private var missingChecks = 0
    private var pendingChecks = 0
    private var reported = false

    /** Return what one probe says about the bound address. */
    fun classify(probe: HotspotProbe): HotspotProbeVerdict = when (probe) {
        HotspotProbe.Unknown -> HotspotProbeVerdict.UNCERTAIN
        HotspotProbe.Pending -> HotspotProbeVerdict.PENDING
        is HotspotProbe.Observed -> when {
            expected in probe.excludedAddresses -> HotspotProbeVerdict.KNOWN_UNSAFE
            probe.candidates.any { it.address == expected } -> HotspotProbeVerdict.VALID
            else -> HotspotProbeVerdict.UNCERTAIN
        }
    }

    /** Return true exactly once, when this probe must stop the run. */
    fun onProbe(probe: HotspotProbe): Boolean {
        if (reported) return false
        return when (classify(probe)) {
            HotspotProbeVerdict.VALID -> {
                pendingChecks = 0
                missingChecks = 0
                false
            }
            HotspotProbeVerdict.KNOWN_UNSAFE -> reportLoss()
            HotspotProbeVerdict.UNCERTAIN -> {
                pendingChecks = 0
                miss()
            }
            // The API 36 callback is registered but has not delivered its
            // first reading. The bound address was already confirmed before
            // the watch started, so a short pending run neither clears nor
            // advances the miss count. After the pending bound, the probe is
            // no longer trustworthy and counts as an uncertain miss.
            HotspotProbeVerdict.PENDING -> {
                pendingChecks += 1
                if (pendingChecks < pendingChecksBeforeUncertain) {
                    false
                } else {
                    miss()
                }
            }
        }
    }

    private fun miss(): Boolean {
        missingChecks += 1
        return if (missingChecks >= missingChecksBeforeLoss) reportLoss() else false
    }

    private fun reportLoss(): Boolean {
        reported = true
        return true
    }

    internal companion object {
        /**
         * The number of consecutive pending probes before each one counts as
         * an uncertain miss. At the two-second watch period this is about
         * eight seconds, which is safely longer than the evidence pending
         * timeout. It is a backstop for a stuck callback, not the normal path.
         */
        const val DEFAULT_PENDING_CHECKS_BEFORE_UNCERTAIN = 4
    }
}

/**
 * Check the hotspot address with one periodic task.
 *
 * The watch asks the finder for one probe. A probe that confirms the bound
 * address is a hit. A probe that finds the bound address on an upstream or
 * client interface stops the run at once. A probe with no usable observation
 * stops the run only after [DEFAULT_MISSING_CHECKS_BEFORE_LOSS] consecutive
 * misses, about 6 seconds at the default period, so one failed or incomplete
 * platform observation does not stop a healthy run.
 *
 * On Android 16 or later, an API 36 tethering callback that stops naming the
 * bound interface is also an uncertain probe, not an immediate loss. A
 * callback can arrive late, and cutting a live run on one stale reading is
 * worse than waiting for the next two checks. The same miss count therefore
 * covers a missing observation and an authoritative set that no longer names
 * the bound address. A pending first reading does not advance the count for a
 * bounded run. The evidence falls back after its pending timeout, and the
 * policy counts a stuck pending probe as uncertain after
 * [HotspotWatchPolicy.DEFAULT_PENDING_CHECKS_BEFORE_UNCERTAIN] probes, so a
 * callback that never fires cannot hide a loss. It reports at most one loss
 * and never restarts anything.
 */
internal class PeriodicHotspotWatch(
    private val finder: HotspotAddressFinder,
    expected: InetAddress,
    private val periodMillis: Long = DEFAULT_PERIOD_MILLIS,
    missingChecksBeforeLoss: Int = DEFAULT_MISSING_CHECKS_BEFORE_LOSS,
    pendingChecksBeforeUncertain: Int =
        HotspotWatchPolicy.DEFAULT_PENDING_CHECKS_BEFORE_UNCERTAIN,
    private val schedulerFactory: () -> ScheduledExecutorService = {
        Executors.newSingleThreadScheduledExecutor { runnable ->
            Thread(runnable, "source-hotspot-watch").apply { isDaemon = true }
        }
    },
) : HotspotWatch {
    private val lock = Any()
    private val policy = HotspotWatchPolicy(
        expected,
        missingChecksBeforeLoss,
        pendingChecksBeforeUncertain,
    )
    private var scheduler: ScheduledExecutorService? = null
    private var stopped = false

    init {
        require(periodMillis > 0) { "The hotspot watch period must be positive." }
    }

    override fun start(onLost: () -> Unit) {
        synchronized(lock) {
            check(scheduler == null && !stopped) { "The hotspot watch can start only once." }
            val executor = schedulerFactory()
            scheduler = executor
            executor.scheduleWithFixedDelay(
                {
                    val probe = try {
                        finder.probe()
                    } catch (_: Exception) {
                        HotspotProbe.Unknown
                    }
                    val fire = synchronized(lock) {
                        if (stopped) false else policy.onProbe(probe)
                    }
                    if (fire) onLost()
                },
                periodMillis,
                periodMillis,
                TimeUnit.MILLISECONDS,
            )
        }
    }

    override fun stop() {
        val executor = synchronized(lock) {
            stopped = true
            scheduler.also { scheduler = null }
        }
        executor?.shutdown()
    }

    internal companion object {
        const val DEFAULT_PERIOD_MILLIS = 2_000L

        /** Three checks at the default period is about 6 seconds. */
        const val DEFAULT_MISSING_CHECKS_BEFORE_LOSS = 3
    }
}
