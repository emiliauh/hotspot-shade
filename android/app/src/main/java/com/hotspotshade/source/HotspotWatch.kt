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
 * Check the hotspot address with one periodic task.
 *
 * The watch compares the current hotspot address with the address that the
 * server bound. It reports a loss when the interface is gone or changed. It
 * never restarts anything.
 */
internal class PeriodicHotspotWatch(
    private val finder: HotspotAddressFinder,
    private val expected: InetAddress,
    private val periodMillis: Long = DEFAULT_PERIOD_MILLIS,
    private val schedulerFactory: () -> ScheduledExecutorService = {
        Executors.newSingleThreadScheduledExecutor { runnable ->
            Thread(runnable, "source-hotspot-watch").apply { isDaemon = true }
        }
    },
) : HotspotWatch {
    private val lock = Any()
    private var scheduler: ScheduledExecutorService? = null
    private var stopped = false
    private var reported = false

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
                    val current = try {
                        finder.findHotspotAddress()
                    } catch (_: Exception) {
                        null
                    }
                    if (current != expected) {
                        val fire = synchronized(lock) {
                            if (stopped || reported) {
                                false
                            } else {
                                reported = true
                                true
                            }
                        }
                        if (fire) onLost()
                    }
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
    }
}
