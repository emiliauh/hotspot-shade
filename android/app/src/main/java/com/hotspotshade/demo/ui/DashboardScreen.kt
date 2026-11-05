package com.hotspotshade.demo.ui

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Bedtime
import androidx.compose.material.icons.outlined.Schedule
import androidx.compose.material.icons.outlined.Wifi
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.hotspotshade.demo.model.DemoEngine
import com.hotspotshade.demo.model.DemoState
import com.hotspotshade.demo.model.RealProxyState
import com.hotspotshade.demo.model.StatusKind
import com.hotspotshade.demo.ui.theme.LocalHsTokens
import com.hotspotshade.demo.ui.theme.LocalReduceMotion

/** The values that one Dashboard render shows. */
private data class DashboardDisplay(
    val statusTitle: String,
    val statusMessage: String,
    val statusKind: StatusKind,
    val running: Boolean,
    val actionTitle: String,
    val actionLabel: String,
    val usageTitle: String,
    val usageSummary: String,
    val usageDetail: String?,
    val connectionLines: List<String>,
    val connectionSimulated: Boolean,
    val connectionNote: String?,
    val lastStopLine: String?,
    val keepAwakeMessage: String,
    val showKeepAwakeSettings: Boolean,
)

@Composable
fun DashboardScreen(
    real: RealProxyState,
    preview: DemoState,
    previewMode: Boolean,
    trustedTargets: Int,
    onStartStop: () -> Unit,
    onOpenSettings: () -> Unit,
    onOpenPreview: () -> Unit,
) {
    val reduce = LocalReduceMotion.current
    val display = if (previewMode) {
        previewDisplay(preview)
    } else {
        realDisplay(real, trustedTargets)
    }
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp)
            .padding(top = 16.dp, bottom = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .widthIn(max = 640.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            StatusCard(
                display = display,
                previewMode = previewMode,
                onStartStop = onStartStop,
            )
            UsageCard(display = display)
            KeepAwakeCard(
                display = display,
                onOpenSettings = onOpenSettings,
            )
            AnimatedVisibility(
                visible = display.lastStopLine != null,
                enter = fadeIn(androidx.compose.animation.core.tween(if (reduce) 0 else 180)) +
                    expandVertically(animationSpec = androidx.compose.animation.core.tween(if (reduce) 0 else 200)),
                exit = fadeOut(androidx.compose.animation.core.tween(if (reduce) 0 else 120)) +
                    shrinkVertically(animationSpec = androidx.compose.animation.core.tween(if (reduce) 0 else 160)),
            ) {
                LastStopCard(line = display.lastStopLine.orEmpty())
            }
            if (!previewMode) {
                OutlinedButton(
                    onClick = onOpenPreview,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text("Open preview controls")
                }
            }
        }
    }
}

private fun realDisplay(real: RealProxyState, trustedTargets: Int): DashboardDisplay {
    val keepAwake = if (real.running) {
        "The proxy runs as a foreground service. Android keeps it awake while it is on."
    } else {
        "Starts when the proxy starts."
    }
    val lastStop = real.lastStopText?.let { line ->
        val time = real.stoppedAtMillis?.let { DemoEngine.formatTime(it) }
        if (time != null) "$line $time." else "$line."
    }
    return DashboardDisplay(
        statusTitle = real.statusTitle,
        statusMessage = real.statusMessage,
        statusKind = real.statusKind,
        running = real.running,
        actionTitle = real.actionTitle,
        actionLabel = if (real.active) "Stop proxy" else "Start proxy",
        usageTitle = real.usageTitle,
        usageSummary = real.usageSummary(trustedTargets),
        usageDetail = null,
        connectionLines = real.connectionLines,
        connectionSimulated = false,
        connectionNote = "Real counts. No address or host is shown.",
        lastStopLine = lastStop,
        keepAwakeMessage = keepAwake,
        showKeepAwakeSettings = false,
    )
}

private fun previewDisplay(state: DemoState): DashboardDisplay {
    val lastStop = if (state.lastStop != null) {
        val time = state.lastStopAtMillis?.let { DemoEngine.formatTime(it) }
        buildString {
            append("Last stop: ")
            append(state.lastStop.shortMessage)
            if (time != null) {
                append(" ")
                append(time)
                append(".")
            }
        }
    } else {
        null
    }
    return DashboardDisplay(
        statusTitle = state.statusTitle,
        statusMessage = state.statusMessage,
        statusKind = state.statusKind,
        running = state.running,
        actionTitle = if (state.running) {
            "Stop"
        } else if (state.offerRestart) {
            "Start again"
        } else {
            "Start"
        },
        actionLabel = if (state.running) "Stop preview" else "Start preview",
        usageTitle = state.usageTitle,
        usageSummary = state.usageSummary,
        usageDetail = state.usageDetail,
        connectionLines = state.connectionLines,
        connectionSimulated = true,
        connectionNote = null,
        lastStopLine = lastStop,
        keepAwakeMessage = state.keepAwakeMessage,
        showKeepAwakeSettings = !state.keepAwake || state.simulatedLocationOff,
    )
}

@Composable
private fun StatusCard(
    display: DashboardDisplay,
    previewMode: Boolean,
    onStartStop: () -> Unit,
) {
    val reduce = LocalReduceMotion.current
    val tokens = LocalHsTokens.current
    GlassCard {
        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Column(
                modifier = Modifier.semantics(mergeDescendants = true) {
                    contentDescription = "Proxy status. ${display.statusTitle}. ${display.statusMessage}"
                    liveRegion = LiveRegionMode.Polite
                },
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Row(
                    verticalAlignment = Alignment.Top,
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Box(Modifier.padding(top = 11.dp)) {
                        StatusDot(display.statusKind)
                    }
                    AnimatedContent(
                        targetState = display.statusTitle,
                        transitionSpec = {
                            (fadeIn(androidx.compose.animation.core.tween(if (reduce) 0 else 160)) +
                                slideInVertically(
                                    animationSpec = androidx.compose.animation.core.tween(if (reduce) 0 else 180),
                                    initialOffsetY = { it / 4 },
                                )) togetherWith fadeOut(
                                androidx.compose.animation.core.tween(if (reduce) 0 else 100),
                            )
                        },
                        label = "status title",
                    ) { title ->
                        Text(
                            text = title,
                            style = MaterialTheme.typography.headlineLarge,
                            color = MaterialTheme.colorScheme.onSurface,
                            modifier = Modifier.semantics { heading() },
                        )
                    }
                }
                AnimatedContent(
                    targetState = display.statusMessage,
                    transitionSpec = {
                        (fadeIn(androidx.compose.animation.core.tween(if (reduce) 0 else 180)) +
                            slideInVertically(
                                animationSpec = androidx.compose.animation.core.tween(if (reduce) 0 else 200),
                                initialOffsetY = { it / 5 },
                            )) togetherWith fadeOut(
                            androidx.compose.animation.core.tween(if (reduce) 0 else 100),
                        )
                    },
                    label = "status message",
                ) { message ->
                    Text(
                        text = message,
                        style = MaterialTheme.typography.bodyLarge,
                        color = tokens.secondaryText,
                        modifier = Modifier.padding(start = 23.dp),
                    )
                }
            }

            if (previewMode) {
                SimulatedBadge(text = "Preview")
            }

            PrimaryActionButton(
                title = display.actionTitle,
                accessibilityLabel = display.actionLabel,
                onClick = onStartStop,
            )
        }
    }
}

@Composable
private fun UsageCard(display: DashboardDisplay) {
    val tokens = LocalHsTokens.current
    GlassCard {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Icon(
                    imageVector = Icons.Outlined.Wifi,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(20.dp),
                )
                Text(
                    text = display.usageTitle,
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier
                        .weight(1f)
                        .semantics { heading() },
                )
            }
            Text(
                text = display.usageSummary,
                style = MaterialTheme.typography.bodyLarge,
                color = tokens.secondaryText,
            )
            display.usageDetail?.let { detail ->
                Text(
                    text = detail,
                    style = MaterialTheme.typography.bodyMedium,
                    color = tokens.secondaryText,
                )
            }
            if (display.connectionLines.isNotEmpty()) {
                Row(
                    modifier = Modifier.padding(top = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    if (display.connectionSimulated) {
                        SimulatedBadge()
                    }
                    Text(
                        text = if (display.connectionSimulated) {
                            "Connection attempts"
                        } else {
                            "Connections"
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = tokens.secondaryText,
                    )
                }
                Column(
                    modifier = Modifier.semantics(mergeDescendants = true) {
                        contentDescription = display.connectionLines.joinToString(" ")
                    },
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    display.connectionLines.forEachIndexed { index, line ->
                        Text(
                            text = line,
                            style = MaterialTheme.typography.bodyMedium,
                            color = if (index == 0) {
                                MaterialTheme.colorScheme.onSurface
                            } else {
                                tokens.secondaryText
                            },
                        )
                    }
                }
                display.connectionNote?.let { note ->
                    Text(
                        text = note,
                        style = MaterialTheme.typography.bodySmall,
                        color = tokens.secondaryText,
                    )
                }
            }
        }
    }
}

@Composable
private fun KeepAwakeCard(
    display: DashboardDisplay,
    onOpenSettings: () -> Unit,
) {
    val tokens = LocalHsTokens.current
    GlassCard {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Icon(
                    imageVector = Icons.Outlined.Bedtime,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(20.dp),
                )
                Text(
                    text = "Keeping awake",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.semantics { heading() },
                )
            }
            Text(
                text = display.keepAwakeMessage,
                style = MaterialTheme.typography.bodyMedium,
                color = tokens.secondaryText,
            )
            if (display.showKeepAwakeSettings) {
                OutlinedButton(
                    onClick = onOpenSettings,
                    modifier = Modifier.padding(top = 4.dp),
                ) {
                    Text("Open Settings")
                }
            }
        }
    }
}

@Composable
private fun LastStopCard(line: String) {
    val tokens = LocalHsTokens.current
    GlassCard(
        contentPadding = androidx.compose.foundation.layout.PaddingValues(
            horizontal = 24.dp,
            vertical = 16.dp,
        ),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .semantics(mergeDescendants = true) {},
            verticalAlignment = Alignment.Top,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Icon(
                imageVector = Icons.Outlined.Schedule,
                contentDescription = null,
                tint = tokens.secondaryText,
                modifier = Modifier
                    .padding(top = 2.dp)
                    .size(18.dp),
            )
            Text(
                text = line,
                style = MaterialTheme.typography.bodyMedium,
                color = tokens.secondaryText,
                modifier = Modifier.weight(1f),
            )
        }
    }
}
