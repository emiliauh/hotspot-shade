package com.hotspotshade.demo.ui

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import com.hotspotshade.source.SourceProxyRuntime

/** The app notification permission state and settings actions. */
internal object AppNotifications {
    private const val ASKED_KEY = "notification-asked"

    /** True when Android shows this app's notifications. */
    fun enabled(context: Context): Boolean =
        NotificationManagerCompat.from(context).areNotificationsEnabled()

    /** True when the app needs the notification permission request on this version. */
    fun needsPermission(context: Context): Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.POST_NOTIFICATIONS,
            ) != PackageManager.PERMISSION_GRANTED

    /** True after the app asked for the notification permission one time. */
    fun wasAsked(context: Context): Boolean =
        SourceProxyRuntime.preferences(context).getBoolean(ASKED_KEY, false)

    /** Remember that the app asked for the notification permission. */
    fun markAsked(context: Context) {
        SourceProxyRuntime.preferences(context).edit { putBoolean(ASKED_KEY, true) }
    }

    /** Open this app's notification settings. */
    fun openSettings(context: Context) {
        val intent = Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
            .putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName)
        try {
            context.startActivity(intent)
        } catch (_: Exception) {
            val fallback = Intent(
                Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                Uri.fromParts("package", context.packageName, null),
            )
            try {
                context.startActivity(fallback)
            } catch (_: Exception) {
                // The device has no settings screen for this app.
            }
        }
    }
}
