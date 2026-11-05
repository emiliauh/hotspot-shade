package com.hotspotshade.demo

import com.hotspotshade.demo.model.RealProxyPhase
import com.hotspotshade.demo.model.RealProxyState
import com.hotspotshade.demo.model.RealStopReason
import com.hotspotshade.source.SourceProxyObservation
import com.hotspotshade.source.SourceProxyState
import com.hotspotshade.source.SourceProxyStopReason

/** Map one source proxy report to the app UI state. The map is pure. */
internal object ProxyStatusMapping {
    fun state(observation: SourceProxyObservation, startPending: Boolean): RealProxyState {
        val phase = when (observation.state) {
            SourceProxyState.IDLE -> if (startPending) {
                RealProxyPhase.STARTING
            } else {
                RealProxyPhase.OFF
            }
            SourceProxyState.WAITING_FOR_NETWORK -> RealProxyPhase.WAITING_FOR_CELLULAR
            SourceProxyState.RUNNING -> RealProxyPhase.RUNNING
            SourceProxyState.STOPPED -> when (observation.reason) {
                SourceProxyStopReason.HOTSPOT_NOT_FOUND -> RealProxyPhase.WAITING_FOR_HOTSPOT
                else -> RealProxyPhase.STOPPED
            }
        }
        return RealProxyState(
            phase = phase,
            stopReason = reason(observation.reason),
            port = observation.port,
            connections = observation.connections,
            totalConnections = observation.totalConnections,
            stoppedAtMillis = observation.stoppedAtMillis,
        )
    }

    fun reason(value: SourceProxyStopReason): RealStopReason = when (value) {
        SourceProxyStopReason.NONE -> RealStopReason.NONE
        SourceProxyStopReason.USER_STOP -> RealStopReason.USER
        SourceProxyStopReason.NETWORK_LOST -> RealStopReason.NETWORK_LOST
        SourceProxyStopReason.CAPABILITIES_LOST -> RealStopReason.CAPABILITIES_LOST
        SourceProxyStopReason.NETWORK_UNAVAILABLE -> RealStopReason.NETWORK_UNAVAILABLE
        SourceProxyStopReason.HOTSPOT_NOT_FOUND -> RealStopReason.HOTSPOT_NOT_FOUND
        SourceProxyStopReason.HOTSPOT_LOST -> RealStopReason.HOTSPOT_LOST
        SourceProxyStopReason.BIND_FAILED -> RealStopReason.BIND_FAILED
        SourceProxyStopReason.START_FAILED -> RealStopReason.START_FAILED
        SourceProxyStopReason.TOKEN_MISSING -> RealStopReason.TOKEN_MISSING
    }
}
