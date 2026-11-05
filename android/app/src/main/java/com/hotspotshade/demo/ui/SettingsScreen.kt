package com.hotspotshade.demo.ui

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.snap
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Bedtime
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.ExpandMore
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Link
import androidx.compose.material.icons.outlined.Notifications
import androidx.compose.material.icons.outlined.NotificationsNone
import androidx.compose.material.icons.outlined.NotificationsOff
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material.icons.outlined.Tune
import androidx.compose.material.icons.outlined.VerifiedUser
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.hotspotshade.demo.BuildConfig
import com.hotspotshade.demo.model.CopyTarget
import com.hotspotshade.demo.model.DemoEngine
import com.hotspotshade.demo.model.DemoState
import com.hotspotshade.demo.model.RealProxyState
import com.hotspotshade.demo.ui.theme.LocalHsTokens
import com.hotspotshade.demo.ui.theme.LocalReduceMotion
import com.hotspotshade.source.RealPairingListener
import com.hotspotshade.source.RealPairingStatus
import com.hotspotshade.source.TrustedTarget

@Composable
internal fun SettingsScreen(
    real: RealProxyState,
    pairing: RealPairingStatus,
    targets: List<TrustedTarget>,
    message: String?,
    preview: DemoState,
    previewMode: Boolean,
    notificationsEnabled: Boolean,
    nowMillis: Long,
    onOpenNotificationSettings: () -> Unit,
    onForgetTarget: (String) -> Unit,
    onForgetAllRequest: () -> Unit,
    onRotateTokenRequest: () -> Unit,
    onCopyDiagnostics: () -> Unit,
    onOpenPreviewControls: () -> Unit,
    onPreviewModeChange: (Boolean) -> Unit,
    onTogglePortAutomatic: (Boolean) -> Unit,
    onPortTextChange: (String) -> Unit,
    onToggleToken: () -> Unit,
    onCopyToken: () -> Unit,
    onCheckAddress: () -> Unit,
) {
    var advancedExpanded by rememberSaveable { mutableStateOf(false) }
    val reduce = LocalReduceMotion.current
    val tokens = LocalHsTokens.current
    val chevronRotation by animateFloatAsState(
        targetValue = if (advancedExpanded) 180f else 0f,
        animationSpec = if (reduce) snap() else tween(180, easing = FastOutSlowInEasing),
        label = "advanced chevron",
    )

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
            SettingsGroup(title = "Background") {
                SettingsStatusRow(
                    icon = Icons.Outlined.Bedtime,
                    tint = tokens.secondaryText,
                    text = "The proxy runs as a foreground service while it is on.",
                )
                SectionDivider()
                SettingsFootnote(
                    "Android shows a notification while the proxy runs. " +
                        "The proxy stops when you tap Stop or when the network is lost. " +
                        "It does not restart by itself.",
                )
            }

            SettingsGroup(title = "Notifications") {
                SettingsStatusRow(
                    icon = if (notificationsEnabled) {
                        Icons.Outlined.Notifications
                    } else {
                        Icons.Outlined.NotificationsOff
                    },
                    tint = if (notificationsEnabled) tokens.success else tokens.warning,
                    text = if (notificationsEnabled) {
                        "Notifications are on. The app shows a message while the proxy runs."
                    } else {
                        "Notifications are off. The proxy still runs, but Android hides its message."
                    },
                )
                if (!notificationsEnabled) {
                    SectionDivider()
                    SettingsActionRow(
                        title = "Open notification settings",
                        icon = Icons.Outlined.Notifications,
                        onClick = onOpenNotificationSettings,
                    )
                }
                SectionDivider()
                SettingsFootnote(
                    "The app asks for notification permission the first time you start " +
                        "the proxy on Android 13 or later.",
                )
            }

            SettingsGroup(title = "Pairing listener") {
                SettingsStatusRow(
                    icon = Icons.Outlined.Link,
                    tint = when (pairing.listener) {
                        RealPairingListener.LISTENING -> tokens.success
                        RealPairingListener.FAILED -> tokens.danger
                        else -> tokens.secondaryText
                    },
                    text = when (pairing.listener) {
                        RealPairingListener.LISTENING ->
                            "On. This app waits for a target device on the hotspot."
                        RealPairingListener.NO_HOTSPOT ->
                            "Off. Turn on the hotspot and open this app."
                        RealPairingListener.FAILED ->
                            "The pairing listener could not start. Close and open this app."
                        RealPairingListener.STOPPED ->
                            "Off. Open this app to pair."
                    },
                )
                SectionDivider()
                SettingsFootnote(
                    "Real pairing runs while this app is open. The listener binds the " +
                        "hotspot address only.",
                )
                SectionDivider()
                SettingsFootnote(
                    "The listener stops when the app is not open. A pairing request " +
                        "cannot arrive while the app is in the background. The app shows a " +
                        "notice if a request arrives while the screen is hidden but the " +
                        "listener is still open.",
                )
            }

            SettingsGroup(title = "Paired target devices") {
                if (targets.isEmpty()) {
                    SettingsStatusRow(
                        icon = Icons.Outlined.Link,
                        tint = tokens.secondaryText,
                        text = "No target devices are paired.",
                    )
                    SectionDivider()
                    SettingsFootnote(
                        "Open HotspotShade on a target device to pair. " +
                            "The pairing listener runs while this app is open.",
                    )
                } else {
                    targets.forEachIndexed { index, target ->
                        if (index > 0) SectionDivider()
                        TrustedTargetRow(
                            label = target.label,
                            onForget = { onForgetTarget(target.id) },
                        )
                    }
                    SectionDivider()
                    SettingsActionRow(
                        title = "Forget all target devices",
                        icon = Icons.Outlined.VerifiedUser,
                        destructive = true,
                        onClick = onForgetAllRequest,
                        hint = "Asks for confirmation.",
                    )
                }
                SectionDivider()
                SettingsFootnote(
                    "A forgotten target device keeps its copy until it contacts this " +
                        "source device again. It must pair again. A token rotation does not " +
                        "remove trust.",
                )
                if (message != null) {
                    SectionDivider()
                    SettingsFootnote(message)
                }
            }

            SettingsGroup {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable(
                            role = Role.Button,
                            onClickLabel = if (advancedExpanded) "Collapses Advanced" else "Expands Advanced",
                            onClick = { advancedExpanded = !advancedExpanded },
                        )
                        .padding(horizontal = 16.dp, vertical = 12.dp)
                        .minimumInteractiveComponentSize(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Icon(
                        imageVector = Icons.Outlined.Key,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(20.dp),
                    )
                    Text(
                        text = "Advanced",
                        style = MaterialTheme.typography.bodyLarge,
                        modifier = Modifier
                            .weight(1f)
                            .semantics { heading() },
                    )
                    Icon(
                        imageVector = Icons.Outlined.ExpandMore,
                        contentDescription = null,
                        tint = tokens.secondaryText,
                        modifier = Modifier
                            .size(22.dp)
                            .rotate(chevronRotation),
                    )
                }
                AnimatedVisibility(
                    visible = advancedExpanded,
                    enter = expandVertically(
                        animationSpec = tween(if (reduce) 0 else 220, easing = FastOutSlowInEasing),
                    ) + fadeIn(tween(if (reduce) 0 else 160)),
                    exit = shrinkVertically(
                        animationSpec = tween(if (reduce) 0 else 180, easing = FastOutSlowInEasing),
                    ) + fadeOut(tween(if (reduce) 0 else 100)),
                ) {
                    Column {
                        SectionDivider()
                        SettingsValueRow(label = "State", value = real.statusTitle)
                        SettingsValueRow(label = "Proxy port", value = real.portText)
                        SettingsValueRow(
                            label = "Open connections",
                            value = real.connections.toString(),
                        )
                        SettingsValueRow(
                            label = "Connections since start",
                            value = real.totalConnections.toString(),
                        )
                        SectionDivider()
                        SettingsActionRow(
                            title = "Rotate source token",
                            icon = Icons.Outlined.Refresh,
                            onClick = onRotateTokenRequest,
                            enabled = !real.active,
                            hint = "Asks for confirmation.",
                        )
                        SettingsFootnote(
                            "A new token makes every paired target device pair again. " +
                                "Rotation does not remove trust. The action is off while the proxy runs.",
                        )
                        SectionDivider()
                        SettingsActionRow(
                            title = "Copy diagnostics",
                            icon = Icons.Outlined.ContentCopy,
                            onClick = onCopyDiagnostics,
                        )
                        SectionDivider()
                        SettingsValueRow(label = "Version", value = BuildConfig.VERSION_NAME)
                        if (previewMode) {
                            PreviewAdvancedBlock(
                                state = preview,
                                nowMillis = nowMillis,
                                onTogglePortAutomatic = onTogglePortAutomatic,
                                onPortTextChange = onPortTextChange,
                                onToggleToken = onToggleToken,
                                onCopyToken = onCopyToken,
                                onCheckAddress = onCheckAddress,
                            )
                        }
                    }
                }
            }

            SettingsGroup(title = "Preview") {
                SettingsToggleRow(
                    title = "Preview mode",
                    checked = previewMode,
                    onCheckedChange = onPreviewModeChange,
                    description = "Shows simulated states on the Dashboard. The real proxy is not affected.",
                )
                SectionDivider()
                SettingsActionRow(
                    title = "Open preview controls",
                    icon = Icons.Outlined.Tune,
                    onClick = onOpenPreviewControls,
                )
                SectionDivider()
                SettingsFootnote(
                    "Preview values stay in memory. They do not change the real proxy, " +
                        "the trust list, or the token.",
                )
            }

            SettingsGroup(title = "About") {
                SettingsValueRow(label = "App", value = "HotspotShade for Android")
                SectionDivider()
                SettingsValueRow(label = "Version", value = BuildConfig.VERSION_NAME)
                SectionDivider()
                SettingsFootnote(
                    "This app controls the real source proxy. Preview mode is simulated. " +
                        "The Android target tunnel is not implemented.",
                )
            }

            InfoNote(
                text = "The Dashboard shows the real source proxy state. " +
                    "The preview controls are separate and labeled.",
            )
        }
    }
}

@Composable
private fun TrustedTargetRow(
    label: String,
    onForget: () -> Unit,
) {
    val tokens = LocalHsTokens.current
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(start = 16.dp, end = 8.dp, top = 4.dp, bottom = 4.dp)
            .minimumInteractiveComponentSize(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Icon(
            imageVector = Icons.Outlined.VerifiedUser,
            contentDescription = null,
            tint = tokens.success,
            modifier = Modifier.size(20.dp),
        )
        Text(
            text = label,
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.weight(1f),
        )
        TextButton(onClick = onForget) {
            Text("Forget")
        }
    }
}

@Composable
private fun PreviewAdvancedBlock(
    state: DemoState,
    nowMillis: Long,
    onTogglePortAutomatic: (Boolean) -> Unit,
    onPortTextChange: (String) -> Unit,
    onToggleToken: () -> Unit,
    onCopyToken: () -> Unit,
    onCheckAddress: () -> Unit,
) {
    val tokens = LocalHsTokens.current
    val reduce = LocalReduceMotion.current
    SectionDivider()
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(
            text = "Preview values",
            style = MaterialTheme.typography.titleSmall,
            modifier = Modifier.weight(1f),
        )
        SimulatedBadge()
    }
    SettingsToggleRow(
        title = "Choose the port automatically",
        checked = state.portAutomatic,
        onCheckedChange = onTogglePortAutomatic,
        enabled = !state.running,
        description = if (state.running) {
            "The port cannot change while the preview proxy runs."
        } else {
            null
        },
    )
    SectionDivider()
    if (state.portAutomatic) {
        SettingsValueRow(label = "Preview port", value = state.port)
    } else {
        OutlinedTextField(
            value = state.port,
            onValueChange = onPortTextChange,
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 12.dp),
            label = { Text("Preview port") },
            singleLine = true,
            enabled = !state.running,
            isError = !DemoEngine.isValidPort(state.port),
            supportingText = {
                if (!DemoEngine.isValidPort(state.port)) {
                    Text("Enter a port from 1024 to 65535. Port 18090 is reserved.")
                }
            },
            keyboardOptions = KeyboardOptions(
                keyboardType = KeyboardType.Number,
                imeAction = ImeAction.Done,
            ),
        )
    }
    SettingsFootnote("Enter a port from 1024 to 65535. Port 18090 is reserved.")
    SettingsFootnote("This value is simulated. The real port is chosen by the app.")
    SectionDivider()
    Column(Modifier.padding(horizontal = 16.dp, vertical = 12.dp)) {
        Text(
            text = "Preview hotspot address",
            style = MaterialTheme.typography.bodyLarge,
        )
        Text(
            text = "192.0.2.1 (simulated)",
            style = MaterialTheme.typography.bodyMedium,
            color = tokens.secondaryText,
            modifier = Modifier.padding(top = 4.dp),
        )
        Text(
            text = "The preview does not read network interfaces. 192.0.2.1 is a documentation address.",
            style = MaterialTheme.typography.bodySmall,
            color = tokens.secondaryText,
            modifier = Modifier.padding(top = 4.dp),
        )
    }
    SettingsActionRow(
        title = "Refresh preview address",
        icon = Icons.Outlined.Refresh,
        onClick = onCheckAddress,
        hint = "Reads the simulated address again.",
    )
    if (state.addressChecks > 0) {
        AnimatedContent(
            targetState = state.addressChecks,
            transitionSpec = {
                fadeIn(tween(if (reduce) 0 else 140)) togetherWith
                    fadeOut(tween(if (reduce) 0 else 90))
            },
            label = "address checks",
        ) { checks ->
            SettingsFootnote(
                "Address checked $checks ${if (checks == 1) "time" else "times"} in this preview.",
            )
        }
    }
    SectionDivider()
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = "Preview token",
            style = MaterialTheme.typography.bodyLarge,
            modifier = Modifier.weight(1f),
        )
        TextButton(
            onClick = onToggleToken,
            modifier = Modifier.padding(vertical = 0.dp),
        ) {
            Icon(
                imageVector = if (state.tokenVisible) {
                    Icons.Outlined.VisibilityOff
                } else {
                    Icons.Outlined.Visibility
                },
                contentDescription = null,
                modifier = Modifier.size(18.dp),
            )
            Spacer(Modifier.size(6.dp))
            Text(if (state.tokenVisible) "Hide token" else "Show token")
        }
    }
    AnimatedVisibility(
        visible = state.tokenVisible,
        enter = expandVertically(tween(if (reduce) 0 else 180)) +
            fadeIn(tween(if (reduce) 0 else 140)),
        exit = shrinkVertically(tween(if (reduce) 0 else 160)) +
            fadeOut(tween(if (reduce) 0 else 90)),
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Surface(
                shape = RoundedCornerShape(8.dp),
                color = tokens.tertiaryFill,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    text = state.token,
                    style = MaterialTheme.typography.bodyMedium.copy(
                        fontFamily = FontFamily.Monospace,
                    ),
                    modifier = Modifier.padding(12.dp),
                )
            }
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                TextButton(onClick = onCopyToken) {
                    Icon(
                        imageVector = Icons.Outlined.ContentCopy,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp),
                    )
                    Spacer(Modifier.size(6.dp))
                    Text("Copy token")
                }
                Text(
                    text = "Hides in ${state.tokenSecondsRemainingAt(nowMillis)} s",
                    style = MaterialTheme.typography.bodySmall,
                    color = tokens.secondaryText,
                )
            }
            if (state.copied == CopyTarget.TOKEN) {
                Text(
                    text = "The preview token is copied.",
                    style = MaterialTheme.typography.bodySmall,
                    color = tokens.secondaryText,
                )
            }
            Text(
                text = "This is a simulated token. It is not used or sent.",
                style = MaterialTheme.typography.bodySmall,
                color = tokens.secondaryText,
            )
        }
    }
    if (!state.tokenVisible) {
        SettingsFootnote(
            "The preview token is hidden. Tap Show token to see it. It hides again after 30 seconds.",
        )
    }
    SettingsFootnote(DemoEngine.ROTATE_TOKEN_NOTE)
}
