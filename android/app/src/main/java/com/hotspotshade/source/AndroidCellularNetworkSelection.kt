package com.hotspotshade.source

import android.Manifest
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import androidx.annotation.RequiresPermission

/**
 * Select one eligible cellular network with ConnectivityManager.
 *
 * The request accepts only a cellular network with internet access that is not
 * a VPN. The selection reports the first network that matches. It reports a
 * loss when that network is gone or loses a required capability. It does not
 * request a replacement network after a loss. The service must create a new
 * selection for a new start that the user requests.
 */
internal class AndroidCellularNetworkSelection(
    private val connectivity: ConnectivityManager,
) : CellularNetworkSelection {
    private val lock = Any()
    private var listener: CellularNetworkSelection.Listener? = null
    private var active = false
    private var selected: Network? = null

    private val request = NetworkRequest.Builder()
        .addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
        .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        .build()

    @RequiresPermission(Manifest.permission.ACCESS_NETWORK_STATE)
    override fun start(listener: CellularNetworkSelection.Listener) {
        synchronized(lock) {
            check(!active) { "The cellular network selection is already started." }
            this.listener = listener
            active = true
        }
        try {
            connectivity.requestNetwork(request, callback)
        } catch (_: RuntimeException) {
            synchronized(lock) {
                active = false
                this.listener = null
                selected = null
            }
            listener.onUnavailable()
        }
    }

    @RequiresPermission(Manifest.permission.ACCESS_NETWORK_STATE)
    override fun stop() {
        synchronized(lock) {
            if (!active) return
            active = false
            listener = null
            selected = null
        }
        try {
            connectivity.unregisterNetworkCallback(callback)
        } catch (_: IllegalArgumentException) {
            // The platform already released the request.
        }
    }

    private val callback = object : ConnectivityManager.NetworkCallback() {
        @RequiresPermission(Manifest.permission.ACCESS_NETWORK_STATE)
        override fun onAvailable(network: Network) {
            if (!eligible(network)) return
            val target = synchronized(lock) {
                if (!active || selected != null) return
                selected = network
                listener
            }
            target?.onAvailable(AndroidCellularBinding(connectivity, network))
        }

        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
            if (isEligible(capabilities)) return
            val target = synchronized(lock) {
                if (!active || selected != network) return
                selected = null
                listener
            }
            target?.onCapabilitiesLost()
        }

        override fun onLost(network: Network) {
            val target = synchronized(lock) {
                if (!active || selected != network) return
                selected = null
                listener
            }
            target?.onLost()
        }

        override fun onUnavailable() {
            val target = synchronized(lock) {
                if (!active) return
                listener
            }
            target?.onUnavailable()
        }
    }

    @RequiresPermission(Manifest.permission.ACCESS_NETWORK_STATE)
    private fun eligible(network: Network): Boolean =
        isEligible(connectivity.getNetworkCapabilities(network))

    private fun isEligible(capabilities: NetworkCapabilities?): Boolean =
        capabilities != null &&
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) &&
            capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
}
