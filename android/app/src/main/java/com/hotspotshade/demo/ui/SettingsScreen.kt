package com.hotspotshade.demo.ui

import android.os.Build
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.snap
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
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
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Bedtime
import androidx.compose.material.icons.outlined.ChevronRight
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.ExpandMore
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Link
import androidx.compose.material.icons.outlined.Notifications
import androidx.compose.material.icons.outlined.NotificationsNone
import androidx.compose.material.icons.outlined.NotificationsOff
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material.icons.outlined.VerifiedUser
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.hotspotshade.demo.BuildConfig
import com.hotspotshade.demo.HotspotAdapterState
import com.hotspotshade.demo.model.ManualConnectionPolicy
import com.hotspotshade.demo.model.ManualConnectionState
import com.hotspotshade.demo.model.RealProxyState
import com.hotspotshade.demo.model.SourcePrivacyCapabilities
import com.hotspotshade.demo.model.SourcePrivacyReport
import com.hotspotshade.demo.model.TokenCopyResult
import com.hotspotshade.demo.ui.theme.LocalHsTokens
import com.hotspotshade.demo.ui.theme.LocalReduceMotion
import com.hotspotshade.source.RealPairingListener
import com.hotspotshade.source.RealPairingStatus
import com.hotspotshade.source.pairingListenerMessage
import com.hotspotshade.source.TrustedTarget
import com.hotspotshade.demo.model.ConnectionCopyResult
import com.hotspotshade.source.TargetConfirmation
import com.hotspotshade.source.targetConfirmationMessage

@Composable
internal fun SettingsScreen(
    real: RealProxyState,
    pairing: RealPairingStatus,
    targets: List<TrustedTarget>,
    trustUnavailable: Boolean?,
    message: String?,
    manual: ManualConnectionState,
    revealedToken: String?,
    manualNowMillis: Long,
    notificationsEnabled: Boolean,
    onOpenNotificationSettings: () -> Unit,
    onForgetTarget: (String) -> Unit,
    onForgetAllRequest: () -> Unit,
    onRotateTokenRequest: () -> Unit,
    onCopyDiagnostics: () -> Unit,
    onRefreshManual: () -> Unit,
    onToggleManualToken: () -> Unit,
    onCopyManualToken: () -> Unit,
    onCopyConnectionDetails: () -> Unit,
    adapter: HotspotAdapterState,
    onAdapterRefresh: () -> Unit,
    onAdapterSelect: (String?) -> Unit,
) {
    var advancedExpanded by rememberSaveable { mutableStateOf(false) }
    var showAdapterPicker by rememberSaveable { mutableStateOf(false) }
    val reduce = LocalReduceMotion.current
    val tokens = LocalHsTokens.current
    val privacyReport = remember { SourcePrivacyCapabilities.report(Build.VERSION.SDK_INT) }
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
                        RealPairingListener.TOKEN_UNREADABLE -> tokens.warning
                        else -> tokens.secondaryText
                    },
                    text = pairingListenerMessage(pairing.listener),
                )
                SectionDivider()
                SettingsFootnote(
                    "Real pairing runs while this app is open. The listener binds the " +
                        "hotspot address only.",
                )
                SectionDivider()
                SettingsFootnote(
                    "The pairing listener stops when the app is not open, so a pairing " +
                        "request cannot arrive in the background. The app shows a notice " +
                        "if a request arrives while the screen is hidden but the listener " +
                        "is still open. While the proxy runs and the app is hidden, a " +
                        "separate status-only listener answers a target device that was " +
                        "confirmed in this app session, so it keeps its link. It binds " +
                        "the hotspot address only. It never pairs, forgets, shows a " +
                        "prompt, or sends the token.",
                )
            }

            SettingsGroup(title = "Saved target devices") {
                if (trustUnavailable == null) {
                    SettingsStatusRow(
                        icon = Icons.Outlined.Link,
                        tint = tokens.secondaryText,
                        text = "Loading saved target devices.",
                    )
                } else if (trustUnavailable) {
                    SettingsStatusRow(
                        icon = Icons.Outlined.Link,
                        tint = tokens.warning,
                        text = "The trusted target list could not be read or saved. After upgrading, " +
                            "an existing legacy trust list requires forgetting all target devices " +
                            "and pairing them again. Try forgetting all to recover the list. " +
                            "A target with a saved token may still use the proxy.",
                    )
                } else if (targets.isEmpty()) {
                    SettingsStatusRow(
                        icon = Icons.Outlined.Link,
                        tint = tokens.secondaryText,
                        text = "No target devices are saved.",
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
                            confirmation = target.confirmation,
                            onForget = { onForgetTarget(target.id) },
                        )
                    }
                }
                if (trustUnavailable == true || (trustUnavailable == false && targets.isNotEmpty())) {
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
                    "After the app process restarts, a saved target device is listed as " +
                        "needing confirmation, and its next pairing attempt asks you again. " +
                        "The app does this on purpose: it cannot prove that a saved list " +
                        "survived a failed or interrupted write, so it will not trust a " +
                        "saved key without a fresh Allow. Until then the target cannot " +
                        "use status. An older app version reads and writes its own trust list and token. " +
                        "This version does not adopt trust changes made in the older version. " +
                        "If this version already saved a working token, it prefers that token " +
                        "when you upgrade again, so a token rotation done in the older version " +
                        "may not replace it. Forgetting a target device removes its trust, but " +
                        "a saved token can still grant access. Rotation changes the token, but " +
                        "power loss, restore, or downgrade can bring back older saved data. " +
                        "Reliable revocation has not been verified.",
                )
                if (message != null) {
                    SectionDivider()
                    SettingsFootnote(message)
                }
            }

            DestinationPrivacyGroup(report = privacyReport)

            ManualConnectionGroup(
                manual = manual,
                revealedToken = revealedToken,
                nowMillis = manualNowMillis,
                onRefresh = onRefreshManual,
                onToggleToken = onToggleManualToken,
                onCopyToken = onCopyManualToken,
                onCopyConnectionDetails = onCopyConnectionDetails,
            )

            HotspotAdapterGroup(
                adapter = adapter,
                onOpen = { showAdapterPicker = true },
            )

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
                    }
                }
            }

            SettingsGroup(title = "About") {
                SettingsValueRow(label = "App", value = "HotspotShade for Android")
                SectionDivider()
                SettingsValueRow(label = "Version", value = BuildConfig.VERSION_NAME)
                SectionDivider()
                SettingsFootnote(
                    "This app controls the real source proxy. " +
                        "The Android target tunnel is not implemented.",
                )
            }
        }
    }

    if (showAdapterPicker) {
        HotspotAdapterDialog(
            adapter = adapter,
            onSelect = { name ->
                showAdapterPicker = false
                onAdapterSelect(name)
            },
            onDismiss = { showAdapterPicker = false },
            onRefresh = onAdapterRefresh,
        )
    }
}

@Composable
private fun TrustedTargetRow(
    label: String,
    confirmation: TargetConfirmation,
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
            tint = tokens.secondaryText,
            modifier = Modifier.size(20.dp),
        )
        Column(modifier = Modifier.weight(1f)) {
            Text(text = label, style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurface)
            Text(text = targetConfirmationMessage(confirmation),
                style = MaterialTheme.typography.bodySmall, color = tokens.secondaryText)
        }
        TextButton(onClick = onForget, modifier = Modifier.semantics {
            contentDescription = "Forget $label"
        }) {
            Text("Forget")
        }
    }
}

@Composable
private fun DestinationPrivacyGroup(report: SourcePrivacyReport) {
    val tokens = LocalHsTokens.current
    SettingsGroup(title = "Destination privacy") {
        SettingsStatusRow(
            icon = Icons.Outlined.Visibility,
            tint = tokens.secondaryText,
            text = report.intro,
        )
        SectionDivider()
        SettingsFootnote(report.storageNote)
        report.modes.forEach { row ->
            SectionDivider()
            CapabilityRow(
                title = row.title,
                stateText = row.stateText,
                detail = row.detail,
            )
        }
        SectionDivider()
        CapabilityHeading(text = "What this build reports")
        report.facts.forEach { row ->
            SectionDivider()
            CapabilityRow(
                title = row.title,
                stateText = row.valueText,
                detail = row.detail,
            )
        }
        SectionDivider()
        report.limits.forEach { line -> SettingsFootnote(line) }
    }
}

@Composable
private fun CapabilityHeading(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.onSurface,
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .semantics { heading() },
    )
}

@Composable
private fun CapabilityRow(
    title: String,
    stateText: String,
    detail: String,
) {
    val tokens = LocalHsTokens.current
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .semantics(mergeDescendants = true) {},
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        Text(
            text = title,
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurface,
        )
        Text(
            text = stateText,
            style = MaterialTheme.typography.bodyMedium,
            color = tokens.secondaryText,
        )
        Text(
            text = detail,
            style = MaterialTheme.typography.bodySmall,
            color = tokens.secondaryText,
            modifier = Modifier.padding(top = 4.dp),
        )
    }
}

@Composable
private fun ManualConnectionGroup(
    manual: ManualConnectionState,
    revealedToken: String?,
    nowMillis: Long,
    onRefresh: () -> Unit,
    onToggleToken: () -> Unit,
    onCopyToken: () -> Unit,
    onCopyConnectionDetails: () -> Unit,
) {
    val tokens = LocalHsTokens.current
    val reduce = LocalReduceMotion.current
    SettingsGroup(title = "Manual connection") {
        SettingsStatusRow(
            icon = Icons.Outlined.Link,
            tint = tokens.secondaryText,
            text = "Use these values in another app that supports SOCKS5. They are " +
                "real values from this device.",
        )
        SectionDivider()
        SettingsValueRow(label = "SOCKS5 username", value = manual.usernameText)
        SettingsValueRow(label = "SOCKS5 password", value = "The source token")
        SectionDivider()
        SettingsValueRow(label = "Hotspot address", value = manual.addressText)
        SettingsActionRow(
            title = "Refresh connection",
            icon = Icons.Outlined.Refresh,
            onClick = onRefresh,
            enabled = !manual.loading,
            hint = "Reads the hotspot address, saved port, and token state again.",
        )
        SectionDivider()
        SettingsValueRow(label = "SOCKS5 port", value = manual.portText)
        SettingsFootnote(
            "The proxy uses the saved port when it starts. A paired target device " +
                "learns the port when it pairs.",
        )
        SectionDivider()
        SettingsActionRow(
            title = "Copy connection details",
            icon = Icons.Outlined.ContentCopy,
            onClick = onCopyConnectionDetails,
            enabled = manual.connectionDetailsAvailable,
            hint = "Copies the address, port, and user name. It does not copy the token.",
        )
        manual.connectionCopyMessage?.let { text ->
            Text(
                text = text,
                style = MaterialTheme.typography.bodySmall,
                color = if (manual.connectionCopy == ConnectionCopyResult.FAILED) {
                    tokens.danger
                } else {
                    tokens.secondaryText
                },
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
            )
        }
        SettingsFootnote(
            "The copy holds the address, the port, and the user name. It never holds the " +
                "token, and it replaces a token copy on the clipboard.",
        )
        SectionDivider()
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = "Source token",
                style = MaterialTheme.typography.bodyLarge,
                modifier = Modifier.weight(1f),
            )
            TextButton(
                onClick = onToggleToken,
                enabled = manual.tokenAvailable,
                modifier = Modifier.padding(vertical = 0.dp),
            ) {
                Icon(
                    imageVector = if (manual.tokenVisible) {
                        Icons.Outlined.VisibilityOff
                    } else {
                        Icons.Outlined.Visibility
                    },
                    contentDescription = null,
                    modifier = Modifier.size(18.dp),
                )
                Spacer(Modifier.size(6.dp))
                Text(if (manual.tokenVisible) "Hide token" else "Show token")
            }
        }
        if (manual.tokenUnreadable) {
            SettingsStatusRow(
                icon = Icons.Outlined.Key,
                tint = tokens.warning,
                text = manual.tokenStateText,
            )
            SettingsFootnote(
                "The app does not replace a token it cannot read. If the problem " +
                    "continues, you can try rotating the source token. Target " +
                    "devices will need the new token.",
            )
        } else if (!manual.tokenAvailable) {
            SettingsStatusRow(
                icon = Icons.Outlined.Key,
                tint = tokens.warning,
                text = "No token is stored yet. Start the proxy once and the app creates it.",
            )
            SettingsFootnote(
                "The app refuses to show or copy a token that does not exist.",
            )
        } else {
            AnimatedVisibility(
                visible = manual.tokenVisible && revealedToken != null,
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
                            text = revealedToken.orEmpty(),
                            style = MaterialTheme.typography.bodyMedium.copy(
                                fontFamily = FontFamily.Monospace,
                            ),
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(12.dp)
                                .clearAndSetSemantics {
                                    contentDescription = "Source token shown"
                                },
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
                            text = "Hides in ${manual.tokenSecondsRemainingAt(nowMillis)} s",
                            style = MaterialTheme.typography.bodySmall,
                            color = tokens.secondaryText,
                        )
                    }
                    val copyMessage = manual.copyMessage
                    if (copyMessage != null) {
                        val color = when (manual.copy) {
                            TokenCopyResult.FAILED -> tokens.danger
                            TokenCopyResult.REFUSED_HIDDEN,
                            TokenCopyResult.REFUSED_ABSENT,
                            -> tokens.warning
                            else -> tokens.secondaryText
                        }
                        Text(
                            text = copyMessage,
                            style = MaterialTheme.typography.bodySmall,
                            color = color,
                        )
                    }
                }
            }
            if (!manual.tokenVisible) {
                SettingsFootnote(ManualConnectionPolicy.HIDDEN_NOTE)
            }
        }
        SectionDivider()
        SettingsFootnote(ManualConnectionPolicy.USERNAME_NOTE)
        SettingsFootnote(ManualConnectionPolicy.CLIPBOARD_NOTE)
    }
}

@Composable
private fun HotspotAdapterGroup(
    adapter: HotspotAdapterState,
    onOpen: () -> Unit,
) {
    val tokens = LocalHsTokens.current
    SettingsGroup(title = "Hotspot network adapter") {
        HotspotAdapterRow(
            value = adapter.chosenName ?: "Automatic",
            onClick = onOpen,
        )
        SectionDivider()
        SettingsFootnote(
            "Choose which network interface the proxy treats as the hotspot. " +
                "The name is an inference, not proof, and the proxy still checks " +
                "that the interface is safe before it binds it. The change takes " +
                "effect on the next start.",
        )
        if (adapter.loading) {
            SectionDivider()
            SettingsStatusRow(
                icon = Icons.Outlined.Refresh,
                tint = tokens.secondaryText,
                text = "Reading interfaces…",
            )
        } else if (adapter.chosenName != null &&
            adapter.names.none { it == adapter.chosenName }
        ) {
            SectionDivider()
            SettingsStatusRow(
                icon = Icons.Outlined.Refresh,
                tint = tokens.warning,
                text = "The chosen interface was not found. The proxy will not start " +
                    "until it appears or you choose another.",
            )
        }
    }
}

@Composable
private fun HotspotAdapterRow(
    value: String,
    onClick: () -> Unit,
) {
    val tokens = LocalHsTokens.current
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(
                role = Role.Button,
                onClickLabel = "Choose the hotspot network adapter",
                onClick = onClick,
            )
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .minimumInteractiveComponentSize(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = "Hotspot network adapter",
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.weight(1f),
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            color = tokens.secondaryText,
        )
        Icon(
            imageVector = Icons.Outlined.ChevronRight,
            contentDescription = null,
            tint = tokens.secondaryText,
            modifier = Modifier.size(20.dp),
        )
    }
}

@Composable
private fun HotspotAdapterDialog(
    adapter: HotspotAdapterState,
    onSelect: (String?) -> Unit,
    onDismiss: () -> Unit,
    onRefresh: () -> Unit,
) {
    val tokens = LocalHsTokens.current
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = MaterialTheme.colorScheme.surface,
        title = {
            Text(
                text = "Hotspot network adapter",
                style = MaterialTheme.typography.headlineSmall,
            )
        },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState()),
            ) {
                AdapterOptionRow(
                    label = "Automatic",
                    selected = adapter.chosenName == null,
                    onClick = { onSelect(null) },
                )
                adapter.names.forEach { name ->
                    AdapterOptionRow(
                        label = name,
                        selected = adapter.chosenName == name,
                        onClick = { onSelect(name) },
                    )
                }
                val note: String = when {
                    adapter.loading -> "Reading interfaces…"
                    adapter.unavailable ->
                        "The interface list needs the network permission to load."
                    adapter.names.isEmpty() ->
                        "No safe interfaces were found. Turn on the hotspot and " +
                            "tap Refresh."
                    else -> ""
                }
                if (note.isNotEmpty()) {
                    Text(
                        text = note,
                        style = MaterialTheme.typography.bodySmall,
                        color = tokens.secondaryText,
                        modifier = Modifier.padding(top = 12.dp),
                    )
                }
                Text(
                    text = "The name records which interface you think is the hotspot. " +
                        "It is not proof. The proxy still checks the interface before " +
                        "it binds, and it refuses an interface that a reported " +
                        "network holds. The change takes effect on the next start.",
                    style = MaterialTheme.typography.bodySmall,
                    color = tokens.secondaryText,
                    modifier = Modifier.padding(top = 12.dp),
                )
            }
        },
        confirmButton = {
            TextButton(onClick = onRefresh) {
                Text("Refresh")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Close")
            }
        },
    )
}

@Composable
private fun AdapterOptionRow(
    label: String,
    selected: Boolean,
    onClick: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        RadioButton(selected = selected, onClick = null)
        Text(
            text = label,
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}

