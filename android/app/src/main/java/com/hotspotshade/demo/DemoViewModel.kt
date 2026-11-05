package com.hotspotshade.demo

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.hotspotshade.demo.model.CopyTarget
import com.hotspotshade.demo.model.DemoEngine
import com.hotspotshade.demo.model.DemoState
import com.hotspotshade.demo.model.NotificationStatus
import com.hotspotshade.demo.model.PairingActivity
import com.hotspotshade.demo.model.ProxyState
import com.hotspotshade.demo.model.StopReason
import com.hotspotshade.demo.model.ThemeChoice
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlin.random.Random

/**
 * In-memory state for the visual demo.
 *
 * Every action changes local state only. No action opens a socket, starts a
 * service, requests a permission, reads a device address, or contacts another
 * device. The state clears when the app process ends.
 */
class DemoViewModel : ViewModel() {
    var state by mutableStateOf(DemoState())
        private set

    var nowMillis by mutableLongStateOf(System.currentTimeMillis())
        private set

    private var startJob: Job? = null
    private var playJob: Job? = null
    private var copyJob: Job? = null
    private var tokenJob: Job? = null

    fun startOrStop() {
        if (state.running) stop() else start()
    }

    fun start() {
        if (state.running) return
        playJob?.cancel()
        if (!DemoEngine.isValidPort(state.port)) {
            state = DemoEngine.failStart(
                state = state,
                message = DemoEngine.INVALID_PORT,
                nowMillis = System.currentTimeMillis(),
            )
            return
        }
        startJob?.cancel()
        state = DemoEngine.requestStart(state)
        startJob = viewModelScope.launch {
            delay(900)
            val started = DemoEngine.finishStart(state, System.currentTimeMillis())
            state = started
        }
    }

    fun stop() {
        startJob?.cancel()
        playJob?.cancel()
        stopTokenTicker()
        state = DemoEngine.stop(state, System.currentTimeMillis())
    }

    fun setProxyScenario(target: ProxyState) {
        startJob?.cancel()
        playJob?.cancel()
        state = DemoEngine.setProxyScenario(state, target, System.currentTimeMillis())
    }

    fun setPairingScenario(activity: PairingActivity) {
        when (activity) {
            PairingActivity.PAIRING -> triggerPairing()
            else -> {
                startJob?.cancel()
                state = DemoEngine.setPairingScenario(state, activity)
            }
        }
    }

    fun triggerPairing() {
        startJob?.cancel()
        playJob?.cancel()
        val code = newPairingCode()
        state = DemoEngine.requestPairing(state, code)
    }

    fun allowPairing() {
        state = DemoEngine.allowPairing(state, System.currentTimeMillis())
    }

    fun denyPairing() {
        state = DemoEngine.denyPairing(state, System.currentTimeMillis())
    }

    fun forgetAll() {
        startJob?.cancel()
        state = DemoEngine.forgetAll(state, System.currentTimeMillis())
    }

    fun setKeepAwake(enabled: Boolean) {
        state = DemoEngine.setKeepAwake(state, enabled)
    }

    fun setSimulatedLocationOff(off: Boolean) {
        state = DemoEngine.setSimulatedLocationOff(state, off)
    }

    fun setNotifications(status: NotificationStatus) {
        state = DemoEngine.setNotifications(state, status)
    }

    fun setPortAutomatic(automatic: Boolean) {
        if (state.running) return
        state = DemoEngine.setPortAutomatic(state, automatic)
    }

    fun setPortText(text: String) {
        if (state.running) return
        state = DemoEngine.setPortText(state, text)
    }

    fun toggleToken() {
        if (state.tokenVisible) {
            stopTokenTicker()
            state = DemoEngine.hideToken(state)
        } else {
            nowMillis = System.currentTimeMillis()
            state = DemoEngine.revealToken(state, nowMillis)
            startTokenTicker()
        }
    }

    fun rotateToken() {
        if (state.running) return
        stopTokenTicker()
        state = DemoEngine.rotateToken(state)
    }

    fun copy(target: CopyTarget) {
        state = DemoEngine.markCopied(state, target)
        copyJob?.cancel()
        copyJob = viewModelScope.launch {
            delay(2000)
            state = DemoEngine.clearCopied(state)
        }
    }

    fun addSampleEvent() {
        state = DemoEngine.addSampleEvent(state, System.currentTimeMillis())
    }

    fun addSampleDetail() {
        state = DemoEngine.addSampleDetail(state)
    }

    fun clearActivity() {
        state = DemoEngine.clearActivity(state)
    }

    fun checkAddress() {
        state = DemoEngine.checkAddress(state)
    }

    fun setLastStop(reason: StopReason?) {
        startJob?.cancel()
        state = DemoEngine.setLastStop(state, reason, System.currentTimeMillis())
    }

    fun setTheme(choice: ThemeChoice) {
        state = state.copy(theme = choice)
    }

    fun setReduceMotion(reduce: Boolean) {
        state = state.copy(reduceMotion = reduce)
    }

    /** Turn the simulated preview on or off. The real proxy is not affected. */
    fun setPreviewMode(enabled: Boolean) {
        state = DemoEngine.setPreviewMode(state, enabled)
    }

    fun resetDemo() {
        startJob?.cancel()
        playJob?.cancel()
        copyJob?.cancel()
        stopTokenTicker()
        state = DemoEngine.reset(state)
    }

    /**
     * Walk the main states in order. The sequence uses the same engine calls as
     * the buttons, so it shows the real transition animation.
     */
    fun playDemo() {
        startJob?.cancel()
        playJob?.cancel()
        copyJob?.cancel()
        stopTokenTicker()
        state = DemoEngine.reset(state)
        playJob = viewModelScope.launch {
            delay(350)
            state = DemoEngine.requestStart(state)
            delay(950)
            state = DemoEngine.finishStart(state, System.currentTimeMillis())
            delay(900)
            state = DemoEngine.setPairingScenario(state, PairingActivity.PAIRING)
            delay(1500)
            state = DemoEngine.allowPairing(state, System.currentTimeMillis())
            delay(1200)
            state = DemoEngine.setPairingScenario(state, PairingActivity.IN_USE)
            delay(1500)
            if (isActive) {
                state = DemoEngine.stop(
                    state = state,
                    nowMillis = System.currentTimeMillis(),
                    reason = StopReason.HOTSPOT_LOST,
                )
            }
        }
    }

    private fun startTokenTicker() {
        tokenJob?.cancel()
        tokenJob = viewModelScope.launch {
            while (isActive && state.tokenVisible) {
                delay(500)
                nowMillis = System.currentTimeMillis()
                state = DemoEngine.expireToken(state, nowMillis)
            }
        }
    }

    private fun stopTokenTicker() {
        tokenJob?.cancel()
        tokenJob = null
    }

    private fun newPairingCode(): String =
        Random.nextInt(0, 1_000_000).toString().padStart(6, '0')
}
