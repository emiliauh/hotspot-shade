package com.hotspotshade.demo

import android.Manifest
import android.app.Application
import android.content.pm.PackageManager
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.core.content.ContextCompat
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.hotspotshade.source.HotspotInterfaceChoice
import com.hotspotshade.source.HotspotInterfaceChoiceStore
import com.hotspotshade.source.SourceProxyRuntime
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The hotspot network adapter picker state.
 *
 * It holds interface names only. It never holds an address, so it cannot leak
 * one into a log, a report, or the activity list. [chosenName] is null for the
 * automatic choice.
 */
data class HotspotAdapterState(
    val chosenName: String?,
    val names: List<String>,
    val loading: Boolean = false,
    val unavailable: Boolean = false,
)

/**
 * Hold the hotspot network adapter choice for Settings.
 *
 * The picker lists the safe interface names from the same strict finder that
 * the proxy uses, read off the main thread. Saving a name writes it to the
 * existing preferences store; the proxy reads it again on the next start. A
 * null selection clears the choice back to Automatic.
 */
class HotspotAdapterViewModel(application: Application) : AndroidViewModel(application) {
    var state by mutableStateOf(HotspotAdapterState(chosenName = null, names = emptyList()))
        private set

    private val store = HotspotInterfaceChoiceStore(SourceProxyRuntime.preferences(application))

    init {
        refresh()
    }

    /** Read the current choice and the selectable interface names again. */
    fun refresh() {
        viewModelScope.launch {
            state = state.copy(loading = true)
            state = withContext(Dispatchers.IO) { readState() }
        }
    }

    /** Persist one selection. A null name clears the choice back to Automatic. */
    fun select(name: String?) {
        viewModelScope.launch {
            withContext(Dispatchers.IO) {
                try {
                    store.save(name)
                } catch (_: Exception) {
                    // The write failed. The next read shows the previous value,
                    // so the UI never pretends the choice was saved.
                }
            }
            refresh()
        }
    }

    private fun readState(): HotspotAdapterState {
        val permission = hasNetworkStatePermission()
        val chosen = try {
            store.load()
        } catch (_: Exception) {
            HotspotInterfaceChoice.Automatic
        }
        val names = if (!permission) {
            emptyList()
        } else {
            try {
                SourceProxyRuntime.hotspotFinder(getApplication())
                    .selectableInterfaces()
                    .map { it.interfaceName }
                    .distinct()
            } catch (_: Exception) {
                emptyList()
            }
        }
        return HotspotAdapterState(
            chosenName = (chosen as? HotspotInterfaceChoice.Selected)?.interfaceName,
            names = names,
            unavailable = !permission,
        )
    }

    private fun hasNetworkStatePermission(): Boolean =
        ContextCompat.checkSelfPermission(
            getApplication(),
            Manifest.permission.ACCESS_NETWORK_STATE,
        ) == PackageManager.PERMISSION_GRANTED
}
