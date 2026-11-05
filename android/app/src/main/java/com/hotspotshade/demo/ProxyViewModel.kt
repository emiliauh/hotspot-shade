package com.hotspotshade.demo

import android.app.Application
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.hotspotshade.demo.model.RealProxyPhase
import com.hotspotshade.demo.model.RealProxyState
import com.hotspotshade.demo.model.RealStopReason
import com.hotspotshade.source.SourceProxyRuntime
import com.hotspotshade.source.SourceProxyService
import com.hotspotshade.source.SourceProxyState
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * Hold the real source proxy state for the app UI.
 *
 * The view model reads the service report every second while the app is
 * visible. It starts and stops the foreground service on request. It holds no
 * token, address, or host.
 */
class ProxyViewModel(application: Application) : AndroidViewModel(application) {
    var state by mutableStateOf(RealProxyState())
        private set

    private var startPending = false
    private var visible = false
    private var pollJob: Job? = null

    /** Tell the view model whether the activity is visible. */
    fun setVisible(value: Boolean) {
        visible = value
        if (value) {
            refresh()
            startPolling()
        } else {
            stopPolling()
        }
    }

    /** Start or stop the proxy. The action follows the real state. */
    fun startOrStop() {
        if (state.active) stop() else start()
    }

    /** Start one source proxy run. */
    fun start() {
        startPending = true
        SourceProxyRuntime.requestStart()
        refresh()
        if (!SourceProxyService.start(getApplication())) {
            startPending = false
            state = state.copy(
                phase = RealProxyPhase.STOPPED,
                stopReason = RealStopReason.START_FAILED,
                stoppedAtMillis = System.currentTimeMillis(),
            )
        }
    }

    /** Ask the running proxy to stop. */
    fun stop() {
        startPending = false
        SourceProxyService.stop(getApplication())
        refresh()
    }

    /** Read the current report now. */
    fun refresh() {
        val observation = SourceProxyRuntime.observation()
        if (observation.state != SourceProxyState.IDLE) startPending = false
        state = ProxyStatusMapping.state(observation, startPending)
    }

    private fun startPolling() {
        pollJob?.cancel()
        if (!visible) return
        pollJob = viewModelScope.launch {
            while (isActive) {
                refresh()
                delay(POLL_MILLIS)
            }
        }
    }

    private fun stopPolling() {
        pollJob?.cancel()
        pollJob = null
    }

    private companion object {
        const val POLL_MILLIS = 1_000L
    }
}
