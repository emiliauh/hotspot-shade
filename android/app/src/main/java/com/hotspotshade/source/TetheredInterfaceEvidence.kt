package com.hotspotshade.source

import android.Manifest
import android.content.Context
import android.net.TetheringInterface
import android.net.TetheringManager
import android.os.Build
import androidx.annotation.ChecksSdkIntAtLeast
import androidx.annotation.RequiresApi
import androidx.annotation.RequiresPermission
import java.io.Closeable
import java.util.Locale
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * The documented physical tethering types that the app accepts.
 *
 * `TetheringInterface.getType()` returns one of the platform tethering type
 * values. The public Android 36 SDK exposes only `TETHERING_WIFI` as a named
 * constant, so the other documented values are repeated here from the platform
 * `TetheringManager` contract. The virtual and WiGig values are deliberately
 * absent: both are hidden or internal types, and a virtual interface such as
 * `avf_tap_fixed` must never become the source listener address.
 *
 * The declared order is the ranking order. A Wi-Fi access point wins over a
 * USB or NCM tethered interface, and a generic physical link comes last. The
 * name is not part of the rank.
 */
internal enum class TetheredInterfaceKind(
    val platformType: Int,
    val rank: Int,
) {
    WIFI(PLATFORM_TYPE_WIFI, 0),
    WIFI_P2P(PLATFORM_TYPE_WIFI_P2P, 1),
    USB(PLATFORM_TYPE_USB, 2),
    NCM(PLATFORM_TYPE_NCM, 3),
    ETHERNET(PLATFORM_TYPE_ETHERNET, 4),
    BLUETOOTH(PLATFORM_TYPE_BLUETOOTH, 5),
    ;

    companion object {
        /**
         * Type value for `TETHERING_WIGIG`. It is an internal platform type and
         * is not accepted as a source hotpot interface.
         */
        internal const val PLATFORM_TYPE_WIGIG = 6

        /**
         * Type value for `TETHERING_VIRTUAL`. It is the AVF tethering type and
         * is not a physical source hotspot.
         */
        internal const val PLATFORM_TYPE_VIRTUAL = 7

        /** Return the accepted kind for a platform type, or null to reject it. */
        fun fromPlatformType(type: Int): TetheredInterfaceKind? =
            entries.firstOrNull { it.platformType == type }

        /**
         * Infer a kind from a name. This exists only for tests and for a
         * defensive name-only reading. Production readings always carry the
         * platform `getType()` value.
         */
        fun inferFromName(name: String): TetheredInterfaceKind? {
            val lower = name.trim().lowercase(Locale.ROOT)
            return when {
                lower.startsWith("swlan") ||
                    lower.startsWith("ap") ||
                    lower.startsWith("softap") ||
                    lower.startsWith("wlan") -> WIFI
                lower.startsWith("rndis") || lower.startsWith("usb") -> USB
                lower.startsWith("ncm") -> NCM
                lower.startsWith("bt-pan") -> BLUETOOTH
                lower.startsWith("eth") -> ETHERNET
                else -> null
            }
        }
    }
}

private const val PLATFORM_TYPE_WIFI = 0
private const val PLATFORM_TYPE_USB = 1
private const val PLATFORM_TYPE_BLUETOOTH = 2
private const val PLATFORM_TYPE_WIFI_P2P = 3
private const val PLATFORM_TYPE_NCM = 4
private const val PLATFORM_TYPE_ETHERNET = 5

/**
 * One complete reading of the platform tethering callback.
 *
 * [interfaces] maps a lowercase interface name to its validated physical
 * tethering kind. An empty map is positive evidence that the platform reports
 * no documented physical tethering interface.
 */
internal data class TetheredInterfaceReading(
    val interfaces: Map<String, TetheredInterfaceKind>,
)

/**
 * One delivered reading of the platform tethering callback.
 *
 * [Known] is positive, specific evidence: the platform named every tethered
 * interface it considers physical. An empty [Known] map means the platform
 * said that no accepted physical interface is tethered. It is not the same
 * value as an unknown read.
 *
 * [AwaitingFirstReading] means the callback is registered but no reading has
 * arrived yet. The finder must not fall back to the name rules in this state,
 * because a name guess could bind a client interface before the platform has
 * spoken. The state is bounded: after [TetheredInterfaceEvidence.DEFAULT_PENDING_TIMEOUT_MILLIS]
 * the evidence reports [Unavailable] until a reading arrives. A reading that
 * arrives after the bound still replaces the fallback.
 *
 * [Unavailable] means the app has no trustworthy tethering evidence: Android
 * 15 or earlier, a failed registration, a delivered null or partial reading,
 * or a callback that stayed pending past its bounded wait. An unavailable
 * reading must never be treated as a complete empty set, and it must never
 * confirm an interface by itself. The finder may use the documented name rules
 * in this state.
 */
internal sealed interface TetheredInterfaceState {
    /** No trustworthy tethering evidence is available. */
    data object Unavailable : TetheredInterfaceState

    /** The callback is registered but has not delivered its first reading. */
    data object AwaitingFirstReading : TetheredInterfaceState

    /**
     * The platform named the current accepted physical tethered interfaces.
     *
     * [interfaces] maps lowercase names to their platform type. An empty map
     * is positive evidence that no accepted physical interface is tethered.
     */
    data class Known(
        val interfaces: Map<String, TetheredInterfaceKind>,
    ) : TetheredInterfaceState {
        /**
         * Build a name-only reading for tests. The kind is inferred from the
         * name, and a name with no recognized kind is dropped. Production code
         * always supplies the platform type.
         */
        constructor(interfaceNames: Set<String>) : this(infer(interfaceNames))

        /** The lowercase interface names. */
        val interfaceNames: Set<String> get() = interfaces.keys

        private companion object {
            fun infer(names: Set<String>): Map<String, TetheredInterfaceKind> {
                val result = LinkedHashMap<String, TetheredInterfaceKind>(names.size)
                for (raw in names) {
                    val name = raw.trim().lowercase(Locale.ROOT)
                    if (name.isEmpty()) continue
                    val kind = TetheredInterfaceKind.inferFromName(name) ?: continue
                    result[name] = kind
                }
                return result
            }
        }
    }
}

/** Read the current tethering evidence. A JVM test supplies a fake. */
internal fun interface TetheredInterfaceEvidenceSource {
    /** Return the latest reading. This call never blocks on a platform call. */
    fun snapshot(): TetheredInterfaceState
}

/**
 * The API 36 tethering callback, behind a small interface.
 *
 * A JVM test supplies a fake registrar. The production registrar is the only
 * code that touches `android.net.TetheringManager`.
 *
 * The listener receives a validated reading, or null when the delivered set
 * was malformed or only partially readable. It may be called before [register]
 * returns, and it may be called from another thread.
 */
internal interface TetheredInterfaceRegistration {
    /**
     * Register the callback and return false when registration fails.
     *
     * The listener receives null for a malformed or partial read. It never
     * receives an invented empty set.
     */
    @RequiresPermission(Manifest.permission.ACCESS_NETWORK_STATE)
    fun register(listener: (TetheredInterfaceReading?) -> Unit): Boolean

    /** Remove the callback. This call is idempotent. */
    fun unregister()
}

/**
 * One platform tethering interface, behind a small interface.
 *
 * The production adapter reads `TetheringInterface.getInterface()` and
 * `TetheringInterface.getType()`. A JVM test supplies a fake so the type
 * validation runs without a device.
 */
internal interface TetheredInterfaceObservation {
    /** Return the interface name, or null when the platform did not report one. */
    fun interfaceName(): String?

    /** Return the platform tethering type, or null when it is not available. */
    fun type(): Int?
}

/**
 * Read and validate one complete platform set.
 *
 * A missing name, a thrown getter, a duplicate name, or a missing type makes
 * the whole reading unavailable. A virtual type, the internal WiGig type, and
 * any unknown type are rejected and do not become candidates. A set that
 * contains only rejected entries becomes an empty map, which is authoritative
 * positive evidence that no accepted physical interface is tethered.
 */
internal fun readTetheredInterfaces(
    observations: Iterable<TetheredInterfaceObservation>,
): Map<String, TetheredInterfaceKind>? {
    val result = LinkedHashMap<String, TetheredInterfaceKind>()
    for (observation in observations) {
        val rawName = try {
            observation.interfaceName()
        } catch (_: Exception) {
            return null
        }
        val name = rawName?.trim()?.lowercase(Locale.ROOT)
        if (name.isNullOrEmpty()) return null
        val type = try {
            observation.type()
        } catch (_: Exception) {
            return null
        } ?: return null
        val kind = TetheredInterfaceKind.fromPlatformType(type) ?: continue
        if (result.put(name, kind) != null) {
            // Two entries with one name disagree. The reading is not reliable.
            return null
        }
    }
    return result
}

/**
 * Hold the latest callback reading for one evidence object.
 *
 * The state is thread safe. [start] registers and may be called again after a
 * failed registration to retry. [close] clears the state and unregisters once.
 * A callback that arrives after [close] is ignored, so a stale event cannot
 * revive a closed source.
 *
 * A successful registration starts in [TetheredInterfaceState.AwaitingFirstReading].
 * It changes to [TetheredInterfaceState.Known] or
 * [TetheredInterfaceState.Unavailable] only after the platform delivers a
 * reading, or to [TetheredInterfaceState.Unavailable] after
 * [DEFAULT_PENDING_TIMEOUT_MILLIS] with no reading. The callback stays
 * registered after that fallback, so a late reading still becomes
 * [TetheredInterfaceState.Known]. A failed registration stays
 * [TetheredInterfaceState.Unavailable] so the finder can use the name rules.
 *
 * The timeout is bounded so a callback that never fires cannot make the
 * finder report [HotspotProbe.Pending] or the watch ignore a lost hotspot
 * forever.
 */
internal class TetheredInterfaceEvidence(
    private val registration: TetheredInterfaceRegistration,
    private val clock: () -> Long = System::nanoTime,
    pendingTimeoutMillis: Long = DEFAULT_PENDING_TIMEOUT_MILLIS,
) : TetheredInterfaceEvidenceSource, Closeable {
    private val lock = Any()
    private val startLock = Any()
    private val pendingTimeoutNanos = TimeUnit.MILLISECONDS.toNanos(pendingTimeoutMillis)
    private var stateValue: TetheredInterfaceState = TetheredInterfaceState.Unavailable
    private var pendingDeadlineNanos: Long? = null
    private var registered = false
    private var starting = false
    private var attempted = false
    private var receivedReading = false
    private var closed = false

    init {
        require(pendingTimeoutMillis > 0) {
            "The tethering pending timeout must be positive."
        }
    }

    /**
     * Register the callback. Return false when registration fails.
     *
     * A second call after a successful registration returns true without a
     * second registration. A later call after a failure retries. A call after
     * [close] returns false.
     */
    @RequiresPermission(Manifest.permission.ACCESS_NETWORK_STATE)
    fun start(): Boolean {
        synchronized(startLock) {
            synchronized(lock) {
                if (closed) return false
                if (registered) return true
                starting = true
                attempted = true
            }
            val registeredNow = try {
                registration.register { reading -> onChanged(reading) }
            } catch (_: Exception) {
                false
            }
            val closeNow = synchronized(lock) {
                starting = false
                if (registeredNow && !closed) {
                    registered = true
                    if (!receivedReading) {
                        stateValue = TetheredInterfaceState.AwaitingFirstReading
                        pendingDeadlineNanos = clock() + pendingTimeoutNanos
                    }
                } else if (!registeredNow) {
                    // A failed registration is unavailable, not pending. A
                    // callback that arrived during the failed attempt is not
                    // trustworthy, so discard it as well. The next start call
                    // retries the registration.
                    receivedReading = false
                    stateValue = TetheredInterfaceState.Unavailable
                    pendingDeadlineNanos = null
                }
                closed
            }
            if (registeredNow && closeNow) {
                // close() ran while the platform call was in flight. Remove the
                // late registration so no callback outlives the source.
                try {
                    registration.unregister()
                } catch (_: Exception) {
                    // The platform is already gone.
                }
                synchronized(lock) { registered = false }
                return false
            }
            return registeredNow && !closeNow
        }
    }

    override fun snapshot(): TetheredInterfaceState = synchronized(lock) {
        expirePendingLocked()
        stateValue
    }

    /**
     * Turn an expired first-reading wait into unavailable.
     *
     * The callback stays registered. A later reading still becomes
     * [TetheredInterfaceState.Known], so the fallback is a bounded wait rather
     * than a permanent verdict. Keeping the fallback here means the finder and
     * the watch see one time source.
     */
    private fun expirePendingLocked() {
        if (stateValue != TetheredInterfaceState.AwaitingFirstReading) return
        val deadline = pendingDeadlineNanos ?: return
        if (clock() >= deadline) {
            stateValue = TetheredInterfaceState.Unavailable
            pendingDeadlineNanos = null
        }
    }

    override fun close() {
        val unregister = synchronized(lock) {
            if (closed) {
                false
            } else {
                closed = true
                stateValue = TetheredInterfaceState.Unavailable
                pendingDeadlineNanos = null
                receivedReading = false
                // Call unregister after any start attempt, including a failed
                // one. A failed registration can still own a daemon executor,
                // and a start that is still in flight is removed by the late
                // registration path in start().
                attempted || registered
            }
        }
        if (!unregister) return
        try {
            registration.unregister()
        } catch (_: Exception) {
            // The platform is already gone. The state is unavailable either way.
        }
        synchronized(lock) {
            registered = false
            attempted = false
        }
    }

    private fun onChanged(reading: TetheredInterfaceReading?) {
        val next = if (reading == null) {
            TetheredInterfaceState.Unavailable
        } else {
            normalize(reading.interfaces)
        }
        synchronized(lock) {
            // Accept a callback that arrives while register is still running.
            // Reject one after failure or close, because the app cannot trust
            // the callback lifecycle then.
            if (closed || (!registered && !starting)) return
            receivedReading = true
            stateValue = next
            pendingDeadlineNanos = null
        }
    }

    /**
     * Normalize one complete map.
     *
     * A blank name or a duplicate makes the whole reading unavailable, so the
     * finder cannot use a subset as if it were the complete tethering state.
     * An empty input stays empty and is positive evidence.
     */
    private fun normalize(
        interfaces: Map<String, TetheredInterfaceKind>,
    ): TetheredInterfaceState {
        if (interfaces.isEmpty()) return TetheredInterfaceState.Known(emptyMap())
        val normalized = LinkedHashMap<String, TetheredInterfaceKind>(interfaces.size)
        for ((rawName, kind) in interfaces) {
            val name = rawName.trim().lowercase(Locale.ROOT)
            if (name.isEmpty()) return TetheredInterfaceState.Unavailable
            if (normalized.put(name, kind) != null) {
                return TetheredInterfaceState.Unavailable
            }
        }
        return TetheredInterfaceState.Known(normalized)
    }

    internal companion object {
        /**
         * The bounded wait for the first callback reading.
         *
         * The platform normally delivers the current set during registration.
         * Three seconds covers a slow binder call without hiding a hotspot
         * loss from the two-second watch for long. After this bound the
         * callback is treated as unavailable, never as an empty set.
         */
        const val DEFAULT_PENDING_TIMEOUT_MILLIS = 3_000L
    }
}

/**
 * Share one [TetheredInterfaceEvidence] between the pairing listener and the
 * source proxy service.
 *
 * Every explicit caller takes a lease with [acquire] and returns it with
 * [release]. The evidence unregisters when the last lease is released, so a
 * service stop never removes a callback that the pairing listener still uses.
 * A failed registration is retried by the next [acquire].
 *
 * Production calls [processSource] instead. That holds one process lease that
 * [release] cannot remove, so a service stop never leaves an active finder
 * pointing at a closed callback. [close] releases the process lease and is used
 * by tests and process teardown.
 *
 * The evidence object is created outside the shared lock. Registration can block
 * on the tethering service, and a status read must not wait for it. Two callers
 * that create at the same time keep one object and close the other before it
 * registers, so the platform sees one callback. [processSource] and [acquire]
 * call [TetheredInterfaceEvidence.start] once per call, which retries a failed
 * registration and is a no-op after a successful one.
 */
internal class SharedTetheredInterfaceEvidence(
    private val factory: () -> TetheredInterfaceEvidence?,
    initialLeases: Int = 0,
) : Closeable {
    private val lock = Any()
    private var evidence: TetheredInterfaceEvidence? = null
    private var leases = initialLeases
    private var acquiring = 0
    private var processHeld = false
    private var closed = false

    init {
        require(initialLeases >= 0) { "The initial lease count must not be negative." }
    }

    /**
     * Return the one process-scoped source and keep it alive until [close].
     *
     * A failed registration is retried on the next call. A successful source
     * ignores the retry. The process lease is not released by [release], so a
     * pairing listener that releases its lease cannot close the callback that a
     * later finder or watch still reads.
     */
    fun processSource(): TetheredInterfaceEvidenceSource {
        synchronized(lock) {
            if (closed) return UNAVAILABLE
            processHeld = true
        }
        val target = evidenceOrCreate() ?: return UNAVAILABLE
        return start(target)
    }

    /** Take one explicit lease and return the shared source. */
    fun acquire(): TetheredInterfaceEvidenceSource {
        synchronized(lock) {
            if (closed) return UNAVAILABLE
            leases += 1
            acquiring += 1
        }
        val target = try {
            evidenceOrCreate()
        } finally {
            synchronized(lock) { acquiring -= 1 }
        }
        if (target == null) {
            // The factory failed. Do not leave a lease that the caller cannot
            // release, or a later release can close a healthy source.
            synchronized(lock) {
                if (leases > acquiring) leases -= 1
            }
            return UNAVAILABLE
        }
        return start(target)
    }

    /**
     * Return one explicit lease. This call is idempotent for an underflow.
     *
     * A release that races with an unfinished [acquire] does not consume the
     * acquiring lease. The caller that acquires has not received its source
     * yet, so it cannot be the caller that releases.
     */
    fun release() {
        val toClose: TetheredInterfaceEvidence?
        synchronized(lock) {
            if (leases <= acquiring) return
            leases -= 1
            if (leases != 0 || processHeld) return
            toClose = evidence
            evidence = null
        }
        toClose?.close()
    }

    /** Drop the process lease, every explicit lease, and the shared callback. */
    override fun close() {
        val toClose: TetheredInterfaceEvidence?
        synchronized(lock) {
            closed = true
            processHeld = false
            leases = 0
            // Do not reset acquiring here. An acquire that is still finishing
            // decrements its own reservation, and resetting would underflow it.
            toClose = evidence
            evidence = null
        }
        toClose?.close()
    }

    /**
     * Return the shared evidence, creating and attaching one when needed.
     *
     * The factory runs outside the lock. A second creator closes its object
     * before it registers, so only the attached object ever reaches the
     * platform. A close that wins the race closes the new object too.
     */
    private fun evidenceOrCreate(): TetheredInterfaceEvidence? {
        val current = synchronized(lock) { if (closed) null else evidence }
        if (current != null) return current
        val created = try {
            factory()
        } catch (_: Exception) {
            null
        } ?: return null
        val winner = synchronized(lock) {
            if (closed) null else evidence ?: created.also { evidence = it }
        }
        if (winner !== created) created.close()
        return winner
    }

    /** Retry a failed registration, then return the source. */
    private fun start(target: TetheredInterfaceEvidence): TetheredInterfaceEvidenceSource {
        try {
            target.start()
        } catch (_: Exception) {
            // The source reports unavailable and the next call retries.
        }
        return target
    }

    private companion object {
        val UNAVAILABLE = TetheredInterfaceEvidenceSource {
            TetheredInterfaceState.Unavailable
        }
    }
}

/**
 * True when this SDK has the public tethering callback.
 *
 * The annotation tells Android Lint that a true result is an API 36 SDK guard,
 * so the API 36 class can be named only inside the guarded branch. A JVM test
 * checks the boundary values.
 */
@ChecksSdkIntAtLeast(api = Build.VERSION_CODES.BAKLAVA, parameter = 0)
internal fun supportsTetheredInterfaceCallback(sdkInt: Int): Boolean =
    sdkInt >= Build.VERSION_CODES.BAKLAVA

/**
 * Read one real platform set. This overload is for the API 36 instrumented
 * test; the JVM tests use [TetheredInterfaceObservation] fakes.
 */
@RequiresApi(Build.VERSION_CODES.BAKLAVA)
internal fun readTetheredInterfaces(
    interfaces: Set<TetheringInterface>,
): Map<String, TetheredInterfaceKind>? =
    readTetheredInterfaces(interfaces.map { PlatformTetheredInterface(it) })

/** The production adapter for one platform tethering interface. */
@RequiresApi(Build.VERSION_CODES.BAKLAVA)
internal class PlatformTetheredInterface(
    private val value: TetheringInterface,
) : TetheredInterfaceObservation {
    override fun interfaceName(): String? = value.getInterface()

    override fun type(): Int? = value.getType()
}

/**
 * The API 36 implementation of [TetheredInterfaceRegistration].
 *
 * This class is the only place that loads `TetheringManager` and
 * `TetheringInterface`. The caller must check [supportsTetheredInterfaceCallback]
 * before it constructs this class, so Android 8 through 15 never load it.
 *
 * The callback runs on one daemon executor. It only copies and validates the
 * interface names and types and posts them to the evidence. It never blocks on
 * a platform call.
 *
 * The SDK marks `onTetheredInterfacesChanged` as non-null. The null wording in
 * the `registerTetheringEventCallback` documentation refers to
 * `onUpstreamChanged`, whose `Network` argument may be null. The public API 36
 * signature is `Set<TetheringInterface>`, so a plain Kotlin object override is
 * used. A thrown read or a malformed entry still becomes unavailable instead
 * of throwing through the callback.
 */
@RequiresApi(Build.VERSION_CODES.BAKLAVA)
internal class Api36TetheredInterfaceRegistration(
    context: Context,
) : TetheredInterfaceRegistration {
    private val manager: TetheringManager? =
        context.applicationContext.getSystemService(TetheringManager::class.java)

    private val lock = Any()

    // The callback executor reads this field while register and unregister
    // write it under the lock. Volatile makes the latest listener visible
    // without making the platform callback take the lock.
    @Volatile
    private var listener: ((TetheredInterfaceReading?) -> Unit)? = null
    private var closed = false
    private var registering = false
    private var registered = false
    private var callbackRemoved = false

    private val callback: TetheringManager.TetheringEventCallback =
        object : TetheringManager.TetheringEventCallback {
            override fun onTetheredInterfacesChanged(interfaces: Set<TetheringInterface>) {
                val reading = try {
                    readTetheredInterfaces(interfaces.map { PlatformTetheredInterface(it) })
                } catch (_: Exception) {
                    null
                }
                listener?.invoke(reading?.let { TetheredInterfaceReading(it) })
            }
        }

    // Do not start a callback thread when the platform has no tethering
    // service. A null service leaves the evidence unavailable.
    private val executor: ExecutorService? = if (manager == null) {
        null
    } else {
        Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "source-tethering-evidence").apply { isDaemon = true }
        }
    }

    @RequiresPermission(Manifest.permission.ACCESS_NETWORK_STATE)
    override fun register(listener: (TetheredInterfaceReading?) -> Unit): Boolean {
        val currentManager = manager ?: return false
        val currentExecutor = executor ?: return false
        synchronized(lock) {
            if (closed) return false
            if (registered) {
                // The evidence already owns a live callback. A retry after a
                // successful registration only replaces the listener; it must
                // never register the same callback twice.
                this.listener = listener
                return true
            }
            this.listener = listener
            registering = true
        }
        val ok = try {
            currentManager.registerTetheringEventCallback(currentExecutor, callback)
            true
        } catch (_: Exception) {
            false
        }
        val closedNow = synchronized(lock) {
            registering = false
            if (ok) {
                registered = true
            } else if (this.listener === listener) {
                this.listener = null
            }
            closed
        }
        if (!ok) {
            // A failed call can still have installed the callback before it
            // threw. Remove any partial installation before the next retry so
            // one process never registers twice. A not-registered callback is
            // harmless here and the platform call is allowed to reject it.
            try {
                currentManager.unregisterTetheringEventCallback(callback)
            } catch (_: Exception) {
                // The callback was not installed, or the service is gone.
            }
            return false
        }
        if (closedNow) {
            // unregister() ran while the platform call was in flight.
            removeCallback()
            return false
        }
        return true
    }

    override fun unregister() {
        val removeNow = synchronized(lock) {
            closed = true
            listener = null
            !registering && registered
        }
        if (removeNow) {
            removeCallback()
            return
        }
        val stopExecutor = synchronized(lock) { !registering && !registered }
        if (stopExecutor) {
            // Registration failed or never started. There is no callback to
            // remove, but the executor must not stay alive.
            executor?.shutdownNow()
        }
    }

    /**
     * Remove the platform callback exactly once and stop the callback thread.
     *
     * A registration that completes after [unregister] called this method is
     * removed by [register] as soon as the platform call returns.
     */
    private fun removeCallback() {
        val remove = synchronized(lock) {
            if (callbackRemoved) {
                false
            } else {
                callbackRemoved = true
                registered = false
                true
            }
        }
        if (remove) {
            try {
                manager?.unregisterTetheringEventCallback(callback)
            } catch (_: Exception) {
                // The tethering service can already be gone.
            }
        }
        executor?.shutdownNow()
    }
}
