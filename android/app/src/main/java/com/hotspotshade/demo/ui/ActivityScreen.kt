package com.hotspotshade.demo.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.History
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.hotspotshade.demo.model.formatStopTime
import com.hotspotshade.demo.ui.theme.LocalHsTokens
import com.hotspotshade.source.ActivityEntry
import com.hotspotshade.source.ActivityLog
import kotlinx.coroutines.delay

/**
 * The Recent activity screen.
 *
 * It lists the real events that [ActivityLog] holds, newest first, with the
 * plain iOS wording. It reads the log again while it is on screen. It shows no
 * simulated entry: an empty log says so.
 */
@Composable
internal fun ActivityScreen() {
    val tokens = LocalHsTokens.current
    var entries by remember { mutableStateOf(ActivityLog.shared.entries()) }

    LaunchedEffect(Unit) {
        var seen = -1L
        while (true) {
            val revision = ActivityLog.shared.revision()
            if (revision != seen) {
                entries = ActivityLog.shared.entries()
                seen = revision
            }
            delay(REFRESH_MILLIS)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp)
            .padding(top = 16.dp, bottom = 32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .widthIn(max = 640.dp),
            verticalArrangement = Arrangement.spacedBy(24.dp),
        ) {
            if (entries.isEmpty()) {
                SettingsGroup {
                    SettingsStatusRow(
                        icon = Icons.Outlined.History,
                        tint = tokens.secondaryText,
                        text = "No activity yet.",
                    )
                    SectionDivider()
                    SettingsFootnote("Events appear here while the app runs.")
                }
            } else {
                SettingsGroup(title = "Recent activity") {
                    entries.forEachIndexed { index, entry ->
                        if (index > 0) SectionDivider()
                        ActivityRow(entry)
                    }
                }
            }
            SettingsGroup {
                SettingsFootnote(
                    "The list holds the latest ${ActivityLog.CAPACITY} events. It stays on " +
                        "this device and is not saved, so it is empty after the app " +
                        "restarts. It never holds a token, an address, a port, or a website.",
                )
            }
        }
    }
}

@Composable
private fun ActivityRow(entry: ActivityEntry) {
    val tokens = LocalHsTokens.current
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .semantics(mergeDescendants = true) {},
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        Text(
            text = entry.message,
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurface,
        )
        Text(
            text = formatStopTime(entry.timeMillis),
            style = MaterialTheme.typography.bodySmall,
            color = tokens.secondaryText,
        )
    }
}

private const val REFRESH_MILLIS = 1_000L
