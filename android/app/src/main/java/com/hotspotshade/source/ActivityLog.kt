package com.hotspotshade.source

/**
 * One fixed Recent activity sentence.
 *
 * Every event carries a fixed plain sentence. The log API accepts only this
 * type, so a token, address, host, port, key, pairing code, or count can never
 * enter a log line by accident. The sentences match the iOS app where the
 * Android app has the same event.
 */
internal enum class ActivityEvent(val message: String) {
    PROXY_STARTED("Proxy started."),
    WAITING_FOR_CELLULAR("Waiting for the cellular network."),
    CELLULAR_BACK("The cellular network is back."),

    STOP_USER("You stopped the proxy."),
    STOP_NETWORK_LOST("The cellular network is gone. The proxy stopped."),
    STOP_CAPABILITIES_LOST("The cellular network changed. The proxy stopped."),
    STOP_NETWORK_UNAVAILABLE("No cellular network is available. The proxy stopped."),
    STOP_HOTSPOT_NOT_FOUND("The hotspot was not found, so the proxy did not start."),
    STOP_HOTSPOT_LOST("The hotspot is gone. The proxy stopped."),
    STOP_BIND_FAILED("The proxy could not listen on the hotspot address."),
    STOP_START_FAILED("The proxy could not start."),
    STOP_LISTENER_FAILED("The proxy listener stopped unexpectedly."),
    STOP_TOKEN_MISSING("No source token is stored."),
    STOP_TOKEN_UNREADABLE("The source token could not be read."),
    STOP_OTHER("The proxy stopped."),

    TARGET_USING("A target device is using the proxy."),
    TARGET_IDLE("No target device is using the proxy now."),

    PAIRING_ALLOWED("You allowed a pairing request."),
    PAIRING_DENIED("You denied a pairing request."),
    TARGET_ADDED("A target device was added."),
    TARGET_CONFIRMED("A saved target device paired again."),
    TARGET_REMOVED("A target device was removed."),
    TARGETS_FORGOTTEN("Paired target devices forgotten."),

    TOKEN_CREATED("The app created the source token."),
    TOKEN_ROTATED("The source token changed. Paired target devices must pair again."),
    TOKEN_ROTATION_UNCONFIRMED("The app could not confirm the source token change."),
    TOKEN_SAVE_FAILED("The source token could not be saved."),
    ;

    internal companion object {
        /** The event for one proxy stop reason. */
        fun forStop(reason: SourceProxyStopReason): ActivityEvent = when (reason) {
            SourceProxyStopReason.NONE -> STOP_OTHER
            SourceProxyStopReason.USER_STOP -> STOP_USER
            SourceProxyStopReason.NETWORK_LOST -> STOP_NETWORK_LOST
            SourceProxyStopReason.CAPABILITIES_LOST -> STOP_CAPABILITIES_LOST
            SourceProxyStopReason.NETWORK_UNAVAILABLE -> STOP_NETWORK_UNAVAILABLE
            SourceProxyStopReason.HOTSPOT_NOT_FOUND -> STOP_HOTSPOT_NOT_FOUND
            SourceProxyStopReason.HOTSPOT_LOST -> STOP_HOTSPOT_LOST
            SourceProxyStopReason.BIND_FAILED -> STOP_BIND_FAILED
            SourceProxyStopReason.START_FAILED -> STOP_START_FAILED
            SourceProxyStopReason.LISTENER_FAILED -> STOP_LISTENER_FAILED
            SourceProxyStopReason.TOKEN_MISSING -> STOP_TOKEN_MISSING
            SourceProxyStopReason.TOKEN_UNREADABLE -> STOP_TOKEN_UNREADABLE
        }
    }
}

/** One recorded event with its wall-clock time. */
internal data class ActivityEntry(val timeMillis: Long, val event: ActivityEvent) {
    val message: String get() = event.message
}

/**
 * A bounded in-memory activity log.
 *
 * The log keeps the newest [capacity] entries and drops the oldest. It is not
 * saved: a process restart empties it, the same as the iOS list. It holds only
 * [ActivityEvent] sentences. The lock is a leaf lock: no method calls out
 * while holding it, so a caller may record from inside its own lock.
 */
internal class ActivityLog(
    private val capacity: Int = CAPACITY,
    private val clock: () -> Long = { System.currentTimeMillis() },
) {
    private val lock = Any()
    private val items = ArrayDeque<ActivityEntry>()
    private var changes = 0L

    init {
        require(capacity > 0) { "capacity must be positive" }
    }

    /** Add one event and drop the oldest entry when the log is full. */
    fun record(event: ActivityEvent) {
        val now = clock()
        synchronized(lock) {
            items.addLast(ActivityEntry(now, event))
            while (items.size > capacity) items.removeFirst()
            changes += 1
        }
    }

    /** The entries, newest first. */
    fun entries(): List<ActivityEntry> = synchronized(lock) { items.reversed() }

    /** A value that changes with every record or clear. */
    fun revision(): Long = synchronized(lock) { changes }

    /** Remove every entry. A test uses this. */
    fun clear() {
        synchronized(lock) {
            items.clear()
            changes += 1
        }
    }

    internal companion object {
        /** The iOS app keeps 50 entries. */
        const val CAPACITY = 50

        /** The log for the app process. */
        val shared = ActivityLog()

        fun record(event: ActivityEvent) = shared.record(event)
    }
}

/**
 * Turn proxy state reports into activity events.
 *
 * One start logs "Proxy started." once, however often the cellular network
 * comes and goes. A repeated report of the same state logs nothing. A stop
 * logs its reason once.
 */
internal class ProxyActivityTracker {
    private var previous = SourceProxyState.IDLE
    private var startedLogged = false

    @Synchronized
    fun onReport(state: SourceProxyState, reason: SourceProxyStopReason): ActivityEvent? {
        val before = previous
        previous = state
        if (state == before) return null
        return when (state) {
            SourceProxyState.IDLE -> {
                startedLogged = false
                null
            }
            SourceProxyState.WAITING_FOR_NETWORK -> ActivityEvent.WAITING_FOR_CELLULAR
            SourceProxyState.RUNNING -> if (!startedLogged) {
                startedLogged = true
                ActivityEvent.PROXY_STARTED
            } else {
                ActivityEvent.CELLULAR_BACK
            }
            SourceProxyState.STOPPED -> {
                startedLogged = false
                ActivityEvent.forStop(reason)
            }
        }
    }

    /** Forget the previous report. A new start request calls this. */
    @Synchronized
    fun reset() {
        previous = SourceProxyState.IDLE
        startedLogged = false
    }
}

/**
 * Turn the open connection count into two usage events.
 *
 * The app polls the count, so a short connection can come and go between two
 * reads. The tracker therefore reports usage, not every connection. It logs
 * when the first connection opens, and it logs the idle line only after the
 * count has stayed at zero for [idleMillis]. A stop of the proxy resets the
 * tracker without a line; the stop reason has its own entry.
 */
internal class ConnectionActivityTracker(
    private val idleMillis: Long = IDLE_MILLIS,
) {
    private var inUse = false
    private var zeroSince: Long? = null

    @Synchronized
    fun onCount(running: Boolean, connections: Int, nowMillis: Long): ActivityEvent? {
        if (!running) {
            inUse = false
            zeroSince = null
            return null
        }
        if (connections > 0) {
            zeroSince = null
            if (inUse) return null
            inUse = true
            return ActivityEvent.TARGET_USING
        }
        if (!inUse) return null
        val since = zeroSince
        if (since == null) {
            zeroSince = nowMillis
            return null
        }
        if (nowMillis - since < idleMillis) return null
        inUse = false
        zeroSince = null
        return ActivityEvent.TARGET_IDLE
    }

    @Synchronized
    fun reset() {
        inUse = false
        zeroSince = null
    }

    internal companion object {
        /** The iOS app counts traffic from the last 60 seconds as in use. */
        const val IDLE_MILLIS = 60_000L
    }
}
