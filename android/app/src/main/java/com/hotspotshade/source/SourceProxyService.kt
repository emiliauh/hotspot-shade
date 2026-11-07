package com.hotspotshade.source

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import androidx.annotation.RequiresPermission
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import com.hotspotshade.demo.R

/**
 * Run the source proxy as a foreground service.
 *
 * The service starts one controller, shows what the proxy does, and stops
 * when the cellular network, the hotspot, or the person stops it. It returns
 * START_NOT_STICKY and never starts itself again. A new start needs the
 * person to request it.
 *
 * The main thread does only the foreground notification, the state gate, and
 * the bounded background status close. The environment build, the token load,
 * the hotspot wait, the listener bind, and every proxy close run on one
 * service queue. A proxy stop can close many sessions, so it must not run on
 * the main thread. The background status close closes at most four pairing
 * sockets and joins no thread.
 *
 * The service never logs the token, the hotspot address, or a host name.
 */
class SourceProxyService : Service() {
    private val mainHandler = Handler(Looper.getMainLooper())
    private val lock = Any()
    private var coordinator: SourceProxyServiceCoordinator? = null
    private var controller: SourceProxyController? = null
    private var backgroundStatus: BackgroundStatusHost? = null
    private var runGeneration = 0L

    @Volatile
    private var destroying = false

    private var foreground = false

    override fun onCreate() {
        super.onCreate()
        val manager = getSystemService(NotificationManager::class.java)
        val channel = NotificationChannel(
            CHANNEL_ID,
            CHANNEL_NAME,
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = CHANNEL_DESCRIPTION
            setShowBadge(false)
        }
        manager?.createNotificationChannel(channel)
        // The background status host answers authenticated status only, on the
        // live hotspot address, while the activity is not visible. It never
        // pairs. The gate stays explicit so one constant turns it off.
        backgroundStatus = if (SourceProxyServiceLifecycle.BACKGROUND_STATUS_ENABLED) {
            try {
                BackgroundStatusHost.create(applicationContext)
            } catch (_: Exception) {
                // The proxy still runs without background status. A missing
                // host fails closed: the target eventually sees no answer.
                null
            }
        } else {
            null
        }
        coordinator = SourceProxyServiceCoordinator(
            queue = SingleThreadSourceProxyTaskQueue("source-proxy-service"),
            runFactory = ::createRun,
            onState = { snapshot, generation ->
                mainHandler.post { applyState(snapshot, generation) }
            },
            onTerminal = { snapshot, generation ->
                mainHandler.post { applyTerminal(snapshot, generation) }
            },
        )
    }

    override fun onBind(intent: Intent?): IBinder? = null

    @RequiresPermission(Manifest.permission.ACCESS_NETWORK_STATE)
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            // A user stop ends presence now. The controller close runs on the
            // worker, but the background status listener must not keep
            // answering for a run that the person just stopped.
            stopBackgroundStatus()
            val outcome = coordinator?.stop()
            if (outcome != SourceProxyServiceStop.QUEUED) {
                stopSelf(startId)
            }
            return START_NOT_STICKY
        }
        if (intent?.action != ACTION_START) {
            stopSelf(startId)
            return START_NOT_STICKY
        }
        // Clear the report of the run before this request. This runs before
        // any worker can build a controller, and it keeps a live attached run
        // for a repeated start request.
        SourceProxyRuntime.requestStart()
        // The platform requires the foreground state before any slow work.
        // Use the live notification text for a repeated start so it does not
        // flicker back to the waiting text. Every step after this call runs on
        // the service queue.
        if (!startInForeground(buildStatusNotification(foregroundKind()))) {
            failStart()
            return START_NOT_STICKY
        }
        val active = coordinator
        if (active == null) {
            failStart()
            return START_NOT_STICKY
        }
        when (val result = active.start()) {
            is SourceProxyServiceStart.Queued -> {
                // A new run can carry a new token. Close any listener left
                // from the previous run and start a fresh host, so a rotated
                // token cannot be served from an old background listener.
                restartBackgroundStatus()
                synchronized(lock) { runGeneration = result.generation }
            }
            is SourceProxyServiceStart.Active -> {
                startBackgroundStatus()
                synchronized(lock) {
                    runGeneration = result.generation
                    controller?.let { SourceProxyRuntime.attach(it) }
                }
                // A second start request does not create a second run. Record
                // the live snapshot again because requestStart() may have
                // cleared the report for this request.
                SourceProxyRuntime.record(result.snapshot)
                updateForeground(buildStatusNotification(kindFor(result.snapshot)))
            }
            is SourceProxyServiceStart.Starting -> {
                startBackgroundStatus()
                synchronized(lock) {
                    runGeneration = result.generation
                    controller?.let { SourceProxyRuntime.attach(it) }
                }
                // The first request already showed the waiting notification.
            }
            SourceProxyServiceStart.Refused -> failStart()
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        destroying = true
        val active = synchronized(lock) {
            coordinator.also { coordinator = null }
        }
        val status = synchronized(lock) {
            backgroundStatus.also { backgroundStatus = null }
        }
        stopBackgroundStatus(status)
        val state = SourceProxyRuntime.lastState
        val hadWork = active?.hasPendingRun() == true ||
            state == SourceProxyState.RUNNING ||
            state == SourceProxyState.WAITING_FOR_NETWORK
        if (active != null) {
            // The stop only queues the worker. This method must return without
            // a socket close or a thread join on the main thread. The report
            // is read from the process record, not from the controller lock,
            // because a start can hold that lock while it reads the token.
            SourceProxyServiceLifecycle.finishDestroyedRun(
                stop = { active.destroy() },
                snapshot = {
                    SourceProxySnapshot(
                        SourceProxyRuntime.lastState,
                        SourceProxyRuntime.lastStopReason,
                        0,
                    )
                },
                record = { report ->
                    if (hadWork) SourceProxyRuntime.record(report)
                },
                detach = { SourceProxyRuntime.attach(null) },
            )
        } else {
            SourceProxyRuntime.attach(null)
        }
        synchronized(lock) { controller = null }
        foreground = false
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        super.onDestroy()
    }

    /** Build and publish one run on the service queue. */
    @RequiresPermission(Manifest.permission.ACCESS_NETWORK_STATE)
    private fun createRun(listener: SourceProxyListener): SourceProxyServiceRun {
        val environment = SourceProxyRuntime.environment(applicationContext)
        val newController = SourceProxyController(
            tokenStore = environment.tokenStore,
            hotspotFinder = environment.hotspotFinder,
            selectionFactory = environment.selectionFactory,
            resolverFactory = environment.resolverFactory,
            echoFactory = environment.echoFactory,
            serverFactory = environment.serverFactory,
            watchFactory = environment.watchFactory,
            listener = listener,
            serverHealthMonitorFactory = SourceServerHealthMonitorFactory.PRODUCTION,
            // The production store is also the writer. A test environment
            // whose store cannot write keeps the TOKEN_MISSING stop.
            tokenWriter = environment.tokenStore as? TokenWriter,
        )
        synchronized(lock) {
            if (!destroying) {
                controller = newController
                SourceProxyRuntime.attach(newController)
            }
        }
        return newController
    }

    /** Record one non-terminal state for the live run. */
    private fun applyState(snapshot: SourceProxySnapshot, generation: Long) {
        if (destroying) return
        if (snapshot.state == SourceProxyState.STOPPED) {
            applyTerminal(snapshot, generation)
            return
        }
        // Reattach the run for this exact generation. A repeated start
        // request clears the process report before it asks the coordinator,
        // so the first real state must publish the controller again.
        val current = synchronized(lock) {
            if (generation == runGeneration) controller else null
        } ?: return
        SourceProxyRuntime.attach(current)
        SourceProxyRuntime.record(snapshot)
        when (snapshot.state) {
            SourceProxyState.IDLE -> Unit
            SourceProxyState.WAITING_FOR_NETWORK -> {
                updateForeground(buildStatusNotification(StatusKind.WAITING))
            }
            SourceProxyState.RUNNING -> {
                updateForeground(buildStatusNotification(StatusKind.RUNNING))
            }
            SourceProxyState.STOPPED -> Unit
        }
    }

    /** Record the one terminal state for a run and end the service. */
    private fun applyTerminal(snapshot: SourceProxySnapshot, generation: Long) {
        if (destroying) return
        val current = synchronized(lock) { generation == runGeneration }
        if (!current) return
        SourceProxyRuntime.record(snapshot)
        synchronized(lock) { controller = null }
        SourceProxyRuntime.attach(null)
        // No run is live after this report. Close the background status
        // listener now so a rotated token cannot be served by the run that is
        // ending, and so a later start always creates a listener with the
        // token that it loaded.
        stopBackgroundStatus()
        finishRun(snapshot.reason, generation)
    }

    private fun finishRun(reason: SourceProxyStopReason, generation: Long) {
        if (destroying) return
        if (generation != synchronized(lock) { runGeneration }) return
        if (SourceProxyRuntime.lastState == SourceProxyState.IDLE) {
            // A start can fail before the controller reports. Record the
            // terminal state so the app does not stay on "Starting".
            SourceProxyRuntime.record(SourceProxySnapshot(SourceProxyState.STOPPED, reason, 0))
        }
        showFinalNotification(reason)
        foreground = false
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    /** End a start that the platform refused before any run existed. */
    private fun failStart() {
        if (destroying) return
        stopBackgroundStatus()
        synchronized(lock) {
            runGeneration += 1
            controller = null
        }
        SourceProxyRuntime.attach(null)
        SourceProxyRuntime.record(
            SourceProxySnapshot(
                SourceProxyState.STOPPED,
                SourceProxyStopReason.START_FAILED,
                0,
            ),
        )
        showFinalNotification(SourceProxyStopReason.START_FAILED)
        foreground = false
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun kindFor(snapshot: SourceProxySnapshot): StatusKind =
        if (SourceProxyServiceLifecycle.showsRunning(snapshot)) {
            StatusKind.RUNNING
        } else {
            StatusKind.WAITING
        }

    /** The notification kind for the run that the service already owns. */
    private fun foregroundKind(): StatusKind {
        val current = synchronized(lock) { controller } ?: return StatusKind.WAITING
        if (!current.isActive) return StatusKind.WAITING
        return kindFor(current.snapshot())
    }

    /** Start the background status host. A failure never stops the proxy. */
    private fun startBackgroundStatus() {
        if (!SourceProxyServiceLifecycle.BACKGROUND_STATUS_ENABLED) return
        val status = synchronized(lock) { backgroundStatus } ?: return
        try {
            status.start()
        } catch (_: Exception) {
            // The proxy still runs. The target sees no authenticated answer
            // until a later service start can create a working host.
        }
    }

    /**
     * Stop and start the host so a new run opens its listener with the token
     * that this run loaded.
     */
    private fun restartBackgroundStatus() {
        if (!SourceProxyServiceLifecycle.BACKGROUND_STATUS_ENABLED) return
        val status = synchronized(lock) { backgroundStatus } ?: return
        stopBackgroundStatus(status)
        startBackgroundStatus()
    }

    /** Stop one background status host. A failure never stops the proxy. */
    private fun stopBackgroundStatus(status: BackgroundStatusHost? = null) {
        if (!SourceProxyServiceLifecycle.BACKGROUND_STATUS_ENABLED) return
        val target = status ?: synchronized(lock) { backgroundStatus } ?: return
        try {
            target.stop()
        } catch (_: Exception) {
            // The listener is already closing.
        }
    }

    private fun startInForeground(notification: Notification): Boolean {
        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        } else {
            0
        }
        return try {
            ServiceCompat.startForeground(this, NOTIFICATION_ID, notification, type)
            foreground = true
            true
        } catch (_: RuntimeException) {
            foreground = false
            false
        }
    }

    private fun updateForeground(notification: Notification) {
        if (foreground) {
            val manager = getSystemService(NotificationManager::class.java)
            manager?.notify(NOTIFICATION_ID, notification)
        } else {
            startInForeground(notification)
        }
    }

    private fun buildStatusNotification(kind: StatusKind): Notification {
        val text = when (kind) {
            StatusKind.WAITING -> WAITING_TEXT
            StatusKind.RUNNING -> RUNNING_TEXT
        }
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentTitle(NOTIFICATION_TITLE)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .addAction(0, STOP_LABEL, stopPendingIntent())
            .build()
    }

    private fun showFinalNotification(reason: SourceProxyStopReason) {
        val text = finalText(reason)
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentTitle(FINAL_TITLE)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setOngoing(false)
            .setAutoCancel(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
            ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.POST_NOTIFICATIONS,
            ) == PackageManager.PERMISSION_GRANTED
        ) {
            val manager = getSystemService(NotificationManager::class.java)
            manager?.notify(RESULT_NOTIFICATION_ID, notification)
        }
    }

    private fun finalText(reason: SourceProxyStopReason): String = when (reason) {
        SourceProxyStopReason.USER_STOP -> "Stopped by you."
        SourceProxyStopReason.NETWORK_LOST -> "The cellular network is gone."
        SourceProxyStopReason.CAPABILITIES_LOST ->
            "The cellular network changed. The proxy stopped."
        SourceProxyStopReason.NETWORK_UNAVAILABLE -> "No cellular network is available."
        SourceProxyStopReason.HOTSPOT_NOT_FOUND ->
            "Hotspot not found. Turn on the hotspot and start again."
        SourceProxyStopReason.HOTSPOT_LOST -> "The hotspot is gone. The proxy stopped."
        SourceProxyStopReason.BIND_FAILED ->
            "The proxy could not listen on the hotspot address."
        SourceProxyStopReason.START_FAILED -> "The proxy could not start."
        SourceProxyStopReason.LISTENER_FAILED ->
            "The proxy listener stopped unexpectedly. Tap Start to try again."
        SourceProxyStopReason.TOKEN_MISSING ->
            "No source token is stored. Tap Start again; the app creates one."
        SourceProxyStopReason.TOKEN_UNREADABLE ->
            "The source token could not be read. Open the app for details."
        SourceProxyStopReason.NONE -> "The proxy stopped."
    }

    private fun stopPendingIntent(): PendingIntent {
        val intent = Intent(this, SourceProxyService::class.java).setAction(ACTION_STOP)
        return PendingIntent.getService(
            this,
            0,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
    }

    private enum class StatusKind { WAITING, RUNNING }

    internal companion object {
        const val ACTION_START = "com.hotspotshade.source.action.START"
        const val ACTION_STOP = "com.hotspotshade.source.action.STOP"

        private const val CHANNEL_ID = "source_proxy"
        private const val CHANNEL_NAME = "Source proxy"
        private const val CHANNEL_DESCRIPTION = "Shows when the source proxy runs."
        private const val NOTIFICATION_ID = 4101
        private const val RESULT_NOTIFICATION_ID = 4102
        private const val NOTIFICATION_TITLE = "Source proxy"
        private const val FINAL_TITLE = "Source proxy stopped"
        private const val WAITING_TEXT = "Waiting for the cellular network."
        private const val RUNNING_TEXT =
            "The source proxy is running. Target devices can connect through the hotspot."
        private const val STOP_LABEL = "Stop"

        /** Start the source proxy. Return false when the platform refuses the start. */
        fun start(context: Context): Boolean {
            val intent = Intent(context, SourceProxyService::class.java)
                .setAction(ACTION_START)
            return try {
                ContextCompat.startForegroundService(context, intent)
                true
            } catch (_: RuntimeException) {
                // The app is in the background or the platform refused the call.
                false
            }
        }

        /** Ask a running source proxy to stop. */
        fun stop(context: Context) {
            val intent = Intent(context, SourceProxyService::class.java)
                .setAction(ACTION_STOP)
            try {
                context.startService(intent)
            } catch (_: RuntimeException) {
                // The service is not running or the platform refused the call.
            }
        }
    }
}
