package com.hotspotshade.demo.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.DeleteSweep
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.PlayArrow
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material3.BottomSheetDefaults
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.hotspotshade.demo.model.DemoState
import com.hotspotshade.demo.model.NotificationStatus
import com.hotspotshade.demo.model.PairingActivity
import com.hotspotshade.demo.model.ProxyState
import com.hotspotshade.demo.model.StopReason
import com.hotspotshade.demo.model.ThemeChoice
import com.hotspotshade.demo.ui.theme.LocalHsTokens

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PreviewControlsSheet(
    state: DemoState,
    previewMode: Boolean,
    onDismiss: () -> Unit,
    onPreviewMode: (Boolean) -> Unit,
    onProxyState: (ProxyState) -> Unit,
    onPairingState: (PairingActivity) -> Unit,
    onLastStop: (StopReason?) -> Unit,
    onNotifications: (NotificationStatus) -> Unit,
    onLocationOff: (Boolean) -> Unit,
    onAddEvent: () -> Unit,
    onAddDetail: () -> Unit,
    onOpenActivity: () -> Unit,
    onClearActivity: () -> Unit,
    onTheme: (ThemeChoice) -> Unit,
    onReduceMotion: (Boolean) -> Unit,
    onPlayDemo: () -> Unit,
    onResetDemo: () -> Unit,
) {
    val tokens = LocalHsTokens.current
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        containerColor = MaterialTheme.colorScheme.surface,
        contentColor = MaterialTheme.colorScheme.onSurface,
        scrimColor = tokens.scrim,
        dragHandle = {
            BottomSheetDefaults.DragHandle(color = tokens.secondaryText.copy(alpha = 0.45f))
        },
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .fillMaxHeight(0.92f)
                .padding(horizontal = 16.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Column(Modifier.weight(1f)) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Text(
                            text = "Preview controls",
                            style = MaterialTheme.typography.titleLarge,
                            modifier = Modifier.semantics { heading() },
                        )
                        SimulatedBadge("Demo")
                    }
                    Text(
                        text = "Change simulated state. No device is contacted.",
                        style = MaterialTheme.typography.bodySmall,
                        color = tokens.secondaryText,
                    )
                }
                TextButton(onClick = onDismiss) {
                    Text("Done")
                }
            }

            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f)
                    .verticalScroll(rememberScrollState())
                    .padding(top = 16.dp, bottom = 24.dp),
                verticalArrangement = Arrangement.spacedBy(24.dp),
            ) {
                ControlSection(title = "Preview mode") {
                    SettingsToggleRow(
                        title = "Preview mode",
                        checked = previewMode,
                        onCheckedChange = onPreviewMode,
                        description = "Shows simulated states on the Dashboard. " +
                            "The real proxy is not affected.",
                    )
                    Text(
                        text = "Turn on Preview mode to change the simulated values below. " +
                            "The real proxy keeps its state.",
                        style = MaterialTheme.typography.bodySmall,
                        color = tokens.secondaryText,
                        modifier = Modifier.padding(top = 8.dp),
                    )
                }

                ControlSection(title = "Proxy state") {
                    OptionChips(
                        options = listOf("Off", "Starting", "On", "Needs attention"),
                        selectedIndex = when (state.proxy) {
                            ProxyState.OFF -> 0
                            ProxyState.STARTING -> 1
                            ProxyState.ON -> 2
                            ProxyState.FAILED -> 3
                        },
                        enabled = previewMode,
                        onSelect = { index ->
                            onProxyState(
                                when (index) {
                                    0 -> ProxyState.OFF
                                    1 -> ProxyState.STARTING
                                    2 -> ProxyState.ON
                                    else -> ProxyState.FAILED
                                },
                            )
                        },
                    )
                }

                ControlSection(title = "Pairing") {
                    OptionChips(
                        options = listOf("Not paired", "Pair request", "Paired", "In use"),
                        selectedIndex = when (state.pairingActivity) {
                            PairingActivity.NOT_PAIRED -> 0
                            PairingActivity.PAIRING -> 1
                            PairingActivity.PAIRED -> 2
                            PairingActivity.IN_USE -> 3
                        },
                        enabled = previewMode,
                        onSelect = { index ->
                            onPairingState(
                                when (index) {
                                    0 -> PairingActivity.NOT_PAIRED
                                    1 -> PairingActivity.PAIRING
                                    2 -> PairingActivity.PAIRED
                                    else -> PairingActivity.IN_USE
                                },
                            )
                        },
                    )
                    Text(
                        text = "Pair request opens the Allow or Deny alert with a simulated code.",
                        style = MaterialTheme.typography.bodySmall,
                        color = tokens.secondaryText,
                        modifier = Modifier.padding(top = 8.dp),
                    )
                }

                ControlSection(title = "Last stop") {
                    OptionChips(
                        options = listOf("None", "You stopped it", "Hotspot off", "Error", "App closed"),
                        selectedIndex = when (state.lastStop) {
                            null -> 0
                            StopReason.USER -> 1
                            StopReason.HOTSPOT_LOST -> 2
                            StopReason.FAILED -> 3
                            StopReason.APP_CLOSED -> 4
                        },
                        enabled = previewMode,
                        onSelect = { index ->
                            onLastStop(
                                when (index) {
                                    0 -> null
                                    1 -> StopReason.USER
                                    2 -> StopReason.HOTSPOT_LOST
                                    3 -> StopReason.FAILED
                                    else -> StopReason.APP_CLOSED
                                },
                            )
                        },
                    )
                }

                ControlSection(title = "Notifications") {
                    OptionChips(
                        options = listOf("Allowed", "Denied", "Not asked"),
                        selectedIndex = when (state.notifications) {
                            NotificationStatus.ALLOWED -> 0
                            NotificationStatus.DENIED -> 1
                            NotificationStatus.NOT_DETERMINED -> 2
                        },
                        enabled = previewMode,
                        onSelect = { index ->
                            onNotifications(
                                when (index) {
                                    0 -> NotificationStatus.ALLOWED
                                    1 -> NotificationStatus.DENIED
                                    else -> NotificationStatus.NOT_DETERMINED
                                },
                            )
                        },
                    )
                }

                ControlSection(title = "Simulated conditions") {
                    SettingsToggleRow(
                        title = "Location is off",
                        checked = state.simulatedLocationOff,
                        onCheckedChange = onLocationOff,
                        description = "Shows the keep-awake attention state. No permission is requested.",
                    )
                }

                ControlSection(title = "Activity") {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        OutlinedButton(onClick = onAddEvent, modifier = Modifier.weight(1f)) {
                            Icon(
                                imageVector = Icons.Outlined.Add,
                                contentDescription = null,
                                modifier = Modifier.size(18.dp),
                            )
                            Spacer(Modifier.size(6.dp))
                            Text("Add event")
                        }
                        OutlinedButton(onClick = onAddDetail, modifier = Modifier.weight(1f)) {
                            Icon(
                                imageVector = Icons.Outlined.Description,
                                contentDescription = null,
                                modifier = Modifier.size(18.dp),
                            )
                            Spacer(Modifier.size(6.dp))
                            Text("Add detail")
                        }
                    }
                    OutlinedButton(
                        onClick = onOpenActivity,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 8.dp),
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.Description,
                            contentDescription = null,
                            modifier = Modifier.size(18.dp),
                        )
                        Spacer(Modifier.size(6.dp))
                        Text("Open recent activity")
                    }
                    OutlinedButton(
                        onClick = onClearActivity,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 8.dp),
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.DeleteSweep,
                            contentDescription = null,
                            modifier = Modifier.size(18.dp),
                        )
                        Spacer(Modifier.size(6.dp))
                        Text("Clear activity")
                    }
                }

                ControlSection(title = "Appearance") {
                    SegmentedControl(
                        options = listOf("System", "Light", "Dark"),
                        selectedIndex = when (state.theme) {
                            ThemeChoice.SYSTEM -> 0
                            ThemeChoice.LIGHT -> 1
                            ThemeChoice.DARK -> 2
                        },
                        onSelect = { index ->
                            onTheme(
                                when (index) {
                                    0 -> ThemeChoice.SYSTEM
                                    1 -> ThemeChoice.LIGHT
                                    else -> ThemeChoice.DARK
                                },
                            )
                        },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    SettingsToggleRow(
                        title = "Reduce motion",
                        checked = state.reduceMotion,
                        onCheckedChange = onReduceMotion,
                        description = "Uses short fades for status and list changes. " +
                            "System animation settings still apply.",
                        modifier = Modifier.padding(top = 8.dp),
                    )
                }

                ControlSection(title = "Demo") {
                    Button(
                        onClick = onPlayDemo,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.PlayArrow,
                            contentDescription = null,
                            modifier = Modifier.size(20.dp),
                        )
                        Spacer(Modifier.size(8.dp))
                        Text("Play state demo")
                    }
                    OutlinedButton(
                        onClick = onResetDemo,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 8.dp),
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.Refresh,
                            contentDescription = null,
                            modifier = Modifier.size(20.dp),
                        )
                        Spacer(Modifier.size(8.dp))
                        Text("Reset demo")
                    }
                }

                InfoNote(
                    text = "These controls change in-memory preview state only. " +
                        "The preview data is local. The real source proxy and the real " +
                        "pairing listener keep their own state.",
                )
            }
        }
    }
}

@Composable
private fun ControlSection(
    title: String,
    content: @Composable () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(
            text = title.uppercase(),
            style = MaterialTheme.typography.labelSmall,
            color = LocalHsTokens.current.secondaryText,
            modifier = Modifier.semantics { heading() },
        )
        content()
    }
}
