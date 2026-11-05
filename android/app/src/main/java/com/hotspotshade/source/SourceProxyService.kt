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
 * The service never logs the token, the hotspot address, or a host name.
 */
class SourceProxyService : Service() {
    private val mainHandler = Handler(Looper.getMainLooper())
    private val lock = Any()
    private var controller: SourceProxyController? = null
    private var runGeneration = 0L
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
    }

    override fun onBind(intent: Intent?): IBinder? = null

    @RequiresPermission(Manifest.permission.ACCESS_NETWORK_STATE)
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            val active = synchronized(lock) { controller }
            if (active == null) {
                stopSelf(startId)
            } else {
                active.stop()
            }
            return START_NOT_STICKY
        }
        if (intent?.action != ACTION_START) {
            stopSelf(startId)
            return START_NOT_STICKY
        }
        val existing = synchronized(lock) { controller }
        if (existing != null && existing.isActive) {
            // A second start request does not create a second run. Re-assert
            // the foreground state and keep the notification text correct.
            SourceProxyRuntime.attach(existing)
            val kind = if (existing.state == SourceProxyState.RUNNING) {
                StatusKind.RUNNING
            } else {
                StatusKind.WAITING
            }
            startInForeground(buildStatusNotification(kind))
            return START_NOT_STICKY
        }
        if (!startInForeground(buildStatusNotification(StatusKind.WAITING))) {
            SourceProxyRuntime.record(
                SourceProxySnapshot(SourceProxyState.STOPPED, SourceProxyStopReason.START_FAILED, 0),
            )
            stopSelf(startId)
            return START_NOT_STICKY
        }
        val generation = synchronized(lock) {
            runGeneration += 1
            runGeneration
        }
        val environment = try {
            SourceProxyRuntime.environment(applicationContext)
        } catch (_: Exception) {
            finishRun(SourceProxyStopReason.START_FAILED, generation)
            return START_NOT_STICKY
        }
        var created: SourceProxyController? = null
        val listener = SourceProxyListener { snapshot ->
            val source = created
            if (source != null) onSnapshot(source, snapshot, generation)
        }
        val newController = SourceProxyController(
            tokenStore = environment.tokenStore,
            hotspotFinder = environment.hotspotFinder,
            selectionFactory = environment.selectionFactory,
            resolverFactory = environment.resolverFactory,
            echoFactory = environment.echoFactory,
            serverFactory = environment.serverFactory,
            watchFactory = environment.watchFactory,
            listener = listener,
        )
        created = newController
        SourceProxyRuntime.resetObservation()
        SourceProxyRuntime.attach(newController)
        synchronized(lock) { controller = newController }
        try {
            newController.start()
        } catch (_: Exception) {
            newController.stop()
            finishRun(SourceProxyStopReason.START_FAILED, generation)
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        destroying = true
        val active = synchronized(lock) {
            controller.also { controller = null }
        }
        SourceProxyRuntime.attach(null)
        active?.stop()
        foreground = false
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        super.onDestroy()
    }

    private fun onSnapshot(
        source: SourceProxyController,
        snapshot: SourceProxySnapshot,
        generation: Long,
    ) {
        mainHandler.post {
            val current = synchronized(lock) { controller }
            if (current !== source) return@post
            SourceProxyRuntime.record(snapshot)
            when (snapshot.state) {
                SourceProxyState.IDLE -> Unit
                SourceProxyState.WAITING_FOR_NETWORK -> {
                    updateForeground(buildStatusNotification(StatusKind.WAITING))
                }
                SourceProxyState.RUNNING -> {
                    updateForeground(buildStatusNotification(StatusKind.RUNNING))
                }
                SourceProxyState.STOPPED -> {
                    synchronized(lock) { controller = null }
                    SourceProxyRuntime.attach(null)
                    if (source.closeFailure != null) {
                        // Retry one incomplete socket close before the service ends.
                        source.stop()
                    }
                    finishRun(snapshot.reason, generation)
                }
            }
        }
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
        SourceProxyStopReason.TOKEN_MISSING ->
            "No source token is stored. Pair a target device first."
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
