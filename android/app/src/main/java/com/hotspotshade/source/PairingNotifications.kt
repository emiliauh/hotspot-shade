package com.hotspotshade.source

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.hotspotshade.demo.MainActivity
import com.hotspotshade.demo.R

/**
 * Show a pairing request that arrives while the app is not visible.
 *
 * The notification holds no code, key, address, or token. The person must open
 * the app to see the code and choose Allow or Deny. The app never approves a
 * request from a notification.
 *
 * The pairing listener stops when the activity stops, so a request cannot
 * arrive while the app is fully in the background. This notice covers the
 * short interval when the activity is paused but the listener is still open.
 */
internal object PairingNotifications {
    const val CHANNEL_ID = "pairing"
    private const val NOTIFICATION_ID = 4103

    /** Create the channel. Call this method when the app starts. */
    fun ensureChannel(context: Context) {
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Pairing requests",
            NotificationManager.IMPORTANCE_DEFAULT,
        ).apply {
            description = "Shows when a target device asks to pair."
            setShowBadge(true)
        }
        manager.createNotificationChannel(channel)
    }

    /** Show one pairing request notice. */
    fun show(context: Context) {
        ensureChannel(context)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(
                context,
                android.Manifest.permission.POST_NOTIFICATIONS,
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            return
        }
        val manager = NotificationManagerCompat.from(context)
        if (!manager.areNotificationsEnabled()) return
        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pending = PendingIntent.getActivity(
            context,
            0,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentTitle("Pairing request")
            .setContentText("Open HotspotShade to review it.")
            .setStyle(
                NotificationCompat.BigTextStyle().bigText(
                    "A target device asks to pair. Open HotspotShade to check the code.",
                ),
            )
            .setContentIntent(pending)
            .setAutoCancel(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setCategory(NotificationCompat.CATEGORY_EVENT)
            .build()
        try {
            manager.notify(NOTIFICATION_ID, notification)
        } catch (_: SecurityException) {
            // The person has not allowed notifications. The in-app prompt
            // still shows when the app returns.
        }
    }

    /** Remove the pairing request notice. */
    fun cancel(context: Context) {
        NotificationManagerCompat.from(context).cancel(NOTIFICATION_ID)
    }
}
