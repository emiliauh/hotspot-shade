package com.hotspotshade.demo.ui

import android.Manifest
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.outlined.ChevronRight
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Link
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.Tune
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LargeTopAppBar
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.saveable.rememberSaveableStateHolder
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import com.hotspotshade.demo.DemoViewModel
import com.hotspotshade.demo.ProxyViewModel
import com.hotspotshade.demo.model.CopyTarget
import com.hotspotshade.demo.model.DemoEngine
import com.hotspotshade.demo.model.PairingActivity
import com.hotspotshade.demo.model.ThemeChoice
import com.hotspotshade.demo.ui.theme.LocalHsTokens
import com.hotspotshade.demo.ui.theme.LocalReduceMotion
import com.hotspotshade.source.PairingViewModel
import com.hotspotshade.source.RealPairingListener
import com.hotspotshade.source.RealPairingStatus
import com.hotspotshade.source.TrustedTarget
import kotlinx.coroutines.delay

private enum class AppTab(val label: String) {
    DASHBOARD("Dashboard"),
    SETTINGS("Settings"),
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppRoot(
    viewModel: DemoViewModel,
    pairingViewModel: PairingViewModel,
    proxyViewModel: ProxyViewModel,
) {
    val state = viewModel.state
    val real = proxyViewModel.state
    val realPrompt = pairingViewModel.prompt
    val realStatus = pairingViewModel.status
    val targets = pairingViewModel.targets
    val tokens = LocalHsTokens.current
    val reduce = LocalReduceMotion.current
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current
    val fontScale = LocalDensity.current.fontScale
    var tab by rememberSaveable { mutableStateOf(AppTab.DASHBOARD) }
    var showActivity by rememberSaveable { mutableStateOf(false) }
    var showControls by rememberSaveable { mutableStateOf(false) }
    var showForgetAll by rememberSaveable { mutableStateOf(false) }
    var forgetTargetId by rememberSaveable { mutableStateOf<String?>(null) }
    var showRotate by rememberSaveable { mutableStateOf(false) }
    var notificationsEnabled by remember { mutableStateOf(AppNotifications.enabled(context)) }
    val saveableState = rememberSaveableStateHolder()
    val topAppBarState = rememberTopAppBarState()
    val scrollBehavior = TopAppBarDefaults.exitUntilCollapsedScrollBehavior(topAppBarState)

    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) {
        AppNotifications.markAsked(context)
        notificationsEnabled = AppNotifications.enabled(context)
        proxyViewModel.start()
    }

    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        notificationsEnabled = AppNotifications.enabled(context)
    }

    LaunchedEffect(state.previewMode) {
        if (!state.previewMode) showActivity = false
    }

    LaunchedEffect(pairingViewModel.message) {
        if (pairingViewModel.message != null) {
            delay(4_000)
            pairingViewModel.clearMessage()
        }
    }

    LaunchedEffect(tab) {
        topAppBarState.heightOffset = 0f
        topAppBarState.contentOffset = 0f
    }

    val startProxy = {
        if (AppNotifications.needsPermission(context) && !AppNotifications.wasAsked(context)) {
            permissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            proxyViewModel.start()
        }
    }

    val onStartStop = {
        if (state.previewMode) {
            viewModel.startOrStop()
        } else if (real.active) {
            proxyViewModel.stop()
        } else {
            startProxy()
        }
    }

    Scaffold(
        modifier = Modifier
            .fillMaxSize()
            .nestedScroll(scrollBehavior.nestedScrollConnection),
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            LargeTopAppBar(
                title = {
                    Text(
                        text = tab.label,
                        modifier = Modifier.semantics { heading() },
                    )
                },
                actions = {
                    if (state.previewMode) {
                        IconButton(onClick = {
                            showControls = false
                            showActivity = true
                        }) {
                            Icon(
                                imageVector = Icons.Outlined.History,
                                contentDescription = "Recent activity",
                                tint = MaterialTheme.colorScheme.primary,
                            )
                        }
                    }
                    IconButton(onClick = { showControls = true }) {
                        Icon(
                            imageVector = Icons.Outlined.Tune,
                            contentDescription = "Preview controls",
                            tint = MaterialTheme.colorScheme.primary,
                        )
                    }
                },
                scrollBehavior = scrollBehavior,
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background,
                    scrolledContainerColor = MaterialTheme.colorScheme.surface,
                    titleContentColor = MaterialTheme.colorScheme.onBackground,
                    actionIconContentColor = MaterialTheme.colorScheme.primary,
                ),
            )
        },
        bottomBar = {
            Column {
                HorizontalDivider(thickness = 1.dp, color = tokens.separator)
                NavigationBar(
                    containerColor = MaterialTheme.colorScheme.surface,
                    contentColor = MaterialTheme.colorScheme.onSurface,
                    tonalElevation = 0.dp,
                ) {
                    AppTab.entries.forEach { item ->
                        val selected = tab == item
                        val icon = tabIcon(item, selected)
                        val showLabels = fontScale < 1.9f
                        NavigationBarItem(
                            selected = selected,
                            onClick = {
                                tab = item
                                showActivity = false
                                showControls = false
                            },
                            icon = {
                                Icon(
                                    imageVector = icon,
                                    contentDescription = if (showLabels) null else item.label,
                                    modifier = Modifier.size(24.dp),
                                )
                            },
                            label = if (showLabels) {
                                { Text(item.label) }
                            } else {
                                null
                            },
                            alwaysShowLabel = true,
                            colors = NavigationBarItemDefaults.colors(
                                selectedIconColor = MaterialTheme.colorScheme.primary,
                                selectedTextColor = MaterialTheme.colorScheme.primary,
                                indicatorColor = tokens.chipSurface,
                                unselectedIconColor = tokens.secondaryText,
                                unselectedTextColor = tokens.secondaryText,
                            ),
                        )
                    }
                }
            }
        },
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .imePadding(),
        ) {
            if (state.previewMode) {
                PreviewBanner(onOpenControls = { showControls = true })
            }
            AnimatedContent(
                targetState = tab,
                modifier = Modifier
                    .fillMaxSize()
                    .weight(1f),
                transitionSpec = {
                    val forward = targetState.ordinal > initialState.ordinal
                    if (reduce) {
                        fadeIn(androidx.compose.animation.core.tween(0)) togetherWith
                            fadeOut(androidx.compose.animation.core.tween(0))
                    } else {
                        (fadeIn(androidx.compose.animation.core.tween(180)) +
                            slideInHorizontally { if (forward) it / 18 else -it / 18 }) togetherWith
                            fadeOut(androidx.compose.animation.core.tween(120))
                    }
                },
                label = "tab content",
            ) { current ->
                saveableState.SaveableStateProvider(current.name) {
                    when (current) {
                        AppTab.DASHBOARD -> DashboardScreen(
                            real = real,
                            preview = state,
                            previewMode = state.previewMode,
                            trustedTargets = realStatus.trustedTargets,
                            onStartStop = onStartStop,
                            onOpenSettings = { tab = AppTab.SETTINGS },
                            onOpenPreview = { showControls = true },
                        )

                        AppTab.SETTINGS -> SettingsScreen(
                            real = real,
                            pairing = realStatus,
                            targets = targets,
                            message = pairingViewModel.message,
                            preview = state,
                            previewMode = state.previewMode,
                            notificationsEnabled = notificationsEnabled,
                            nowMillis = viewModel.nowMillis,
                            onOpenNotificationSettings = {
                                AppNotifications.openSettings(context)
                            },
                            onForgetTarget = { id -> forgetTargetId = id },
                            onForgetAllRequest = { showForgetAll = true },
                            onRotateTokenRequest = { showRotate = true },
                            onCopyDiagnostics = {
                                val report = real.diagnosticsReport(
                                    listenerLabel(realStatus.listener),
                                )
                                clipboard.setText(AnnotatedString(report))
                                viewModel.copy(CopyTarget.DIAGNOSTICS)
                            },
                            onOpenPreviewControls = { showControls = true },
                            onPreviewModeChange = viewModel::setPreviewMode,
                            onTogglePortAutomatic = viewModel::setPortAutomatic,
                            onPortTextChange = viewModel::setPortText,
                            onToggleToken = viewModel::toggleToken,
                            onCopyToken = {
                                if (state.tokenVisible) {
                                    clipboard.setText(AnnotatedString(state.token))
                                    viewModel.copy(CopyTarget.TOKEN)
                                }
                            },
                            onCheckAddress = viewModel::checkAddress,
                        )
                    }
                }
            }
        }
    }

    if (showActivity && state.previewMode) {
        ActivitySheet(
            entries = state.activity,
            details = state.details,
            onDismiss = { showActivity = false },
        )
    }

    if (showControls) {
        PreviewControlsSheet(
            state = state,
            previewMode = state.previewMode,
            onDismiss = { showControls = false },
            onPreviewMode = viewModel::setPreviewMode,
            onProxyState = viewModel::setProxyScenario,
            onPairingState = { activity ->
                if (state.previewMode) {
                    if (activity == PairingActivity.PAIRING) {
                        showControls = false
                        viewModel.triggerPairing()
                    } else {
                        viewModel.setPairingScenario(activity)
                    }
                }
            },
            onLastStop = viewModel::setLastStop,
            onNotifications = viewModel::setNotifications,
            onLocationOff = viewModel::setSimulatedLocationOff,
            onAddEvent = {
                viewModel.setPreviewMode(true)
                viewModel.addSampleEvent()
            },
            onAddDetail = {
                viewModel.setPreviewMode(true)
                viewModel.addSampleDetail()
            },
            onOpenActivity = {
                showControls = false
                viewModel.setPreviewMode(true)
                showActivity = true
            },
            onClearActivity = {
                viewModel.setPreviewMode(true)
                viewModel.clearActivity()
            },
            onTheme = viewModel::setTheme,
            onReduceMotion = viewModel::setReduceMotion,
            onPlayDemo = {
                showControls = false
                viewModel.setPreviewMode(true)
                viewModel.playDemo()
            },
            onResetDemo = {
                showControls = false
                showActivity = false
                viewModel.resetDemo()
            },
        )
    }

    val pairingCode = state.pairingCode
    if (realPrompt != null) {
        PairingDialog(
            code = realPrompt.code,
            simulated = false,
            onAllow = pairingViewModel::allow,
            onDeny = pairingViewModel::deny,
        )
    } else if (state.previewMode && pairingCode != null) {
        PairingDialog(
            code = pairingCode,
            simulated = true,
            onAllow = viewModel::allowPairing,
            onDeny = viewModel::denyPairing,
        )
    }

    if (showForgetAll) {
        val text = "Each target device keeps its copy until it contacts this source device again. " +
            "Each one must pair again."
        ConfirmDialog(
            title = "Forget all target devices?",
            text = text,
            confirmLabel = "Forget all",
            onConfirm = {
                showForgetAll = false
                pairingViewModel.forgetAllTargets()
            },
            onDismiss = { showForgetAll = false },
        )
    }

    val target = targets.firstOrNull { it.id == forgetTargetId }
    if (target != null) {
        ConfirmDialog(
            title = "Forget this target device?",
            text = "${target.label} keeps its copy until it contacts this source device " +
                "again. It must pair again.",
            confirmLabel = "Forget",
            onConfirm = {
                forgetTargetId = null
                pairingViewModel.forgetTarget(target.id)
            },
            onDismiss = { forgetTargetId = null },
        )
    }

    if (showRotate) {
        ConfirmDialog(
            title = "Rotate the source token?",
            text = "Every paired target device must pair again. The trust list stays, " +
                "so a known target device can pair without a new prompt.",
            confirmLabel = "Rotate",
            onConfirm = {
                showRotate = false
                pairingViewModel.rotateToken()
            },
            onDismiss = { showRotate = false },
        )
    }
}

@Composable
private fun PreviewBanner(onOpenControls: () -> Unit) {
    val tokens = LocalHsTokens.current
    val compact = LocalDensity.current.fontScale >= 1.3f
    Column(Modifier.fillMaxWidth()) {
        Surface(
            color = tokens.bannerSurface,
            contentColor = tokens.bannerText,
            modifier = Modifier
                .fillMaxWidth()
                .clickable(
                    role = Role.Button,
                    onClickLabel = "Opens preview controls",
                    onClick = onOpenControls,
                ),
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .minimumInteractiveComponentSize()
                    .padding(horizontal = 16.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Icon(
                    imageVector = Icons.Outlined.Info,
                    contentDescription = null,
                    tint = tokens.bannerText,
                    modifier = Modifier.size(18.dp),
                )
                if (compact) {
                    Text(
                        text = "Preview mode. Simulated data.",
                        style = MaterialTheme.typography.labelMedium,
                        color = tokens.bannerText,
                        fontWeight = FontWeight.SemiBold,
                        modifier = Modifier.weight(1f),
                    )
                } else {
                    Column(Modifier.weight(1f)) {
                        Text(
                            text = "Preview mode",
                            style = MaterialTheme.typography.labelMedium,
                            color = tokens.bannerText,
                            fontWeight = FontWeight.SemiBold,
                        )
                        Text(
                            text = "The Dashboard shows simulated values. The real proxy is not affected.",
                            style = MaterialTheme.typography.bodySmall,
                            color = tokens.bannerText.copy(alpha = 0.86f),
                        )
                    }
                    Text(
                        text = "Controls",
                        style = MaterialTheme.typography.labelMedium,
                        color = tokens.bannerText,
                    )
                }
                Icon(
                    imageVector = Icons.Outlined.ChevronRight,
                    contentDescription = null,
                    tint = tokens.bannerText,
                    modifier = Modifier.size(18.dp),
                )
            }
        }
        HorizontalDivider(thickness = 1.dp, color = tokens.bannerBorder)
    }
}

private fun listenerLabel(listener: RealPairingListener): String = when (listener) {
    RealPairingListener.LISTENING -> "on"
    RealPairingListener.NO_HOTSPOT -> "no hotspot"
    RealPairingListener.FAILED -> "failed"
    RealPairingListener.STOPPED -> "off"
}

private fun tabIcon(tab: AppTab, selected: Boolean): ImageVector = when (tab) {
    AppTab.DASHBOARD -> if (selected) Icons.Filled.Home else Icons.Outlined.Home
    AppTab.SETTINGS -> if (selected) Icons.Filled.Settings else Icons.Outlined.Settings
}

@Composable
private fun PairingDialog(
    code: String,
    simulated: Boolean,
    onAllow: () -> Unit,
    onDeny: () -> Unit,
) {
    val tokens = LocalHsTokens.current
    AlertDialog(
        onDismissRequest = onDeny,
        containerColor = MaterialTheme.colorScheme.surface,
        icon = {
            Icon(
                imageVector = Icons.Outlined.Link,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
            )
        },
        title = {
            Text(
                text = "Allow this target device?",
                style = MaterialTheme.typography.headlineSmall,
            )
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    text = "Check that the target device shows:",
                    style = MaterialTheme.typography.bodyMedium,
                    color = tokens.secondaryText,
                )
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = tokens.tertiaryFill,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        text = if (simulated) DemoEngine.formatPairingCode(code) else code,
                        style = MaterialTheme.typography.headlineMedium.copy(
                            fontFamily = FontFamily.Monospace,
                            letterSpacing = 2.sp,
                        ),
                        textAlign = TextAlign.Center,
                        color = MaterialTheme.colorScheme.onSurface,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 16.dp, horizontal = 12.dp)
                            .clearAndSetSemantics {
                                contentDescription = "Pairing code " +
                                    (if (simulated) {
                                        DemoEngine.spokenPairingCode(code)
                                    } else {
                                        code
                                    })
                            },
                    )
                }
                Text(
                    text = "Tap Allow only if it matches.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = tokens.secondaryText,
                )
                if (simulated) {
                    Text(
                        text = "Preview: this pairing request is simulated.",
                        style = MaterialTheme.typography.bodySmall,
                        color = tokens.warning,
                    )
                } else {
                    Text(
                        text = "Real pairing request. This code comes from a target device on the hotspot.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.primary,
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onAllow) {
                Text("Allow")
            }
        },
        dismissButton = {
            TextButton(onClick = onDeny) {
                Text("Deny")
            }
        },
    )
}

@Composable
private fun ConfirmDialog(
    title: String,
    text: String,
    confirmLabel: String,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    val tokens = LocalHsTokens.current
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = MaterialTheme.colorScheme.surface,
        title = {
            Text(
                text = title,
                style = MaterialTheme.typography.headlineSmall,
            )
        },
        text = {
            Text(
                text = text,
                style = MaterialTheme.typography.bodyMedium,
                color = tokens.secondaryText,
            )
        },
        confirmButton = {
            TextButton(
                onClick = onConfirm,
                colors = ButtonDefaults.textButtonColors(contentColor = tokens.danger),
            ) {
                Text(confirmLabel)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel")
            }
        },
    )
}
