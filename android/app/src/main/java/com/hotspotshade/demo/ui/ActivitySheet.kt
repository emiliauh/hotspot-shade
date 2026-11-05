package com.hotspotshade.demo.ui

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.History
import androidx.compose.material3.BottomSheetDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.hotspotshade.demo.model.ActivityEntry
import com.hotspotshade.demo.model.DemoEngine
import com.hotspotshade.demo.ui.theme.LocalHsTokens
import com.hotspotshade.demo.ui.theme.LocalReduceMotion

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ActivitySheet(
    entries: List<ActivityEntry>,
    details: List<String>,
    onDismiss: () -> Unit,
) {
    val tokens = LocalHsTokens.current
    val largeText = LocalDensity.current.fontScale >= 1.3f
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = largeText)
    var showDetails by rememberSaveable { mutableStateOf(false) }
    val reduce = LocalReduceMotion.current

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
                .fillMaxHeight(0.9f)
                .imePadding()
                .padding(horizontal = 16.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text(
                    text = "Recent activity",
                    style = MaterialTheme.typography.titleLarge,
                    modifier = Modifier
                        .weight(1f)
                        .semantics { heading() },
                )
                TextButton(onClick = onDismiss) {
                    Text("Done")
                }
            }
            SegmentedControl(
                options = listOf("Activity", "Details"),
                selectedIndex = if (showDetails) 1 else 0,
                onSelect = { showDetails = it == 1 },
                modifier = Modifier.fillMaxWidth(),
            )
            Text(
                text = if (showDetails) {
                    "Technical details are simulated. The real app never saves them."
                } else {
                    "Simulated event record. It stays in memory and clears when the app closes."
                },
                style = MaterialTheme.typography.bodySmall,
                color = tokens.secondaryText,
                modifier = Modifier.padding(top = 10.dp, bottom = 6.dp),
            )
            AnimatedContent(
                targetState = showDetails,
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                transitionSpec = {
                    if (reduce) {
                        fadeIn(androidx.compose.animation.core.tween(0)) togetherWith
                            fadeOut(androidx.compose.animation.core.tween(0))
                    } else if (targetState) {
                        (fadeIn(androidx.compose.animation.core.tween(160)) +
                            slideInHorizontally { it / 12 }) togetherWith
                            (fadeOut(androidx.compose.animation.core.tween(100)) +
                                slideOutHorizontally { -it / 12 })
                    } else {
                        (fadeIn(androidx.compose.animation.core.tween(160)) +
                            slideInHorizontally { -it / 12 }) togetherWith
                            (fadeOut(androidx.compose.animation.core.tween(100)) +
                                slideOutHorizontally { it / 12 })
                    }
                },
                label = "activity view",
            ) { showDetailsTab ->
                if (showDetailsTab) {
                    DetailsList(details)
                } else {
                    ActivityList(entries)
                }
            }
            Spacer(Modifier.size(8.dp))
        }
    }
}

@Composable
private fun ActivityList(entries: List<ActivityEntry>) {
    if (entries.isEmpty()) {
        EmptyState(
            icon = Icons.Outlined.History,
            title = "No activity yet.",
            detail = "Events appear here while the app runs.",
            modifier = Modifier.fillMaxSize(),
        )
        return
    }
    val reduce = LocalReduceMotion.current
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(bottom = 24.dp),
    ) {
        items(entries.asReversed(), key = { it.id }) { entry ->
            ActivityRow(
                entry = entry,
                modifier = if (reduce) {
                    Modifier
                } else {
                    Modifier.animateItem()
                },
            )
            HorizontalDivider(
                thickness = 1.dp,
                color = LocalHsTokens.current.separator,
            )
        }
    }
}

@Composable
private fun ActivityRow(
    entry: ActivityEntry,
    modifier: Modifier = Modifier,
) {
    val tokens = LocalHsTokens.current
    val timeText = DemoEngine.formatTime(entry.timeMillis)
    val largeText = LocalDensity.current.fontScale >= 1.5f
    val content: @Composable () -> Unit = {
        if (largeText) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 12.dp),
                verticalArrangement = Arrangement.spacedBy(2.dp),
            ) {
                ActivityTime(timeText)
                Text(
                    text = entry.message,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                )
            }
        } else {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 12.dp),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalAlignment = Alignment.Top,
            ) {
                ActivityTime(timeText, Modifier.width(58.dp))
                Text(
                    text = entry.message,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.weight(1f),
                )
            }
        }
    }
    androidx.compose.foundation.layout.Box(
        modifier = modifier
            .fillMaxWidth()
            .semantics(mergeDescendants = true) {
                contentDescription = "$timeText. ${entry.message}"
            },
    ) {
        content()
    }
}

@Composable
private fun ActivityTime(text: String, modifier: Modifier = Modifier) {
    Text(
        text = text,
        style = MaterialTheme.typography.bodySmall.copy(fontFeatureSettings = "tnum"),
        color = LocalHsTokens.current.secondaryText,
        modifier = modifier,
        textAlign = TextAlign.Start,
    )
}

@Composable
private fun DetailsList(details: List<String>) {
    if (details.isEmpty()) {
        EmptyState(
            icon = Icons.Outlined.Description,
            title = "No details yet.",
            detail = "Technical lines appear here while the app runs.",
            modifier = Modifier.fillMaxSize(),
        )
        return
    }
    val tokens = LocalHsTokens.current
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(bottom = 24.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        items(details.asReversed()) { line ->
            SelectionContainer {
                Text(
                    text = line,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        }
    }
}
