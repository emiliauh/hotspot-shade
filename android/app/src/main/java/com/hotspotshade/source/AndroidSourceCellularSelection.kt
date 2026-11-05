package com.hotspotshade.source

import android.Manifest
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import androidx.annotation.RequiresPermission
import java.io.IOException
import java.net.DatagramSocket
import java.net.Socket

/** A cellular binding that also holds the selected Network for DNS. */
internal interface SelectedCellularNetworkBinding : CellularBinding {
    val network: Network
}

/**
 * Select one eligible cellular network and keep its Network handle.
 *
 * AndroidCellularNetworkSelection is the tested selector, but its binding
 * does not expose the Network. NetworkResolver needs the handle so that a
 * name lookup runs on the selected cellular network only. This adapter has
 * the same eligibility rules and one extra reference.
 *
 * The request accepts only a cellular network with internet access that is
 * not a VPN. The selection reports the first network that matches. It reports
 * a loss when that network is gone or loses a required capability. It does
 * not request a replacement network after a loss.
 */
internal class AndroidSourceCellularSelection(
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
        val release = synchronized(lock) {
            if (!active) {
                false
            } else {
                active = false
                listener = null
                selected = null
                true
            }
        }
        if (!release) return
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
            target?.onAvailable(NetworkBinding(connectivity, network))
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

private class NetworkBinding(
    private val connectivity: ConnectivityManager,
    override val network: Network,
) : SelectedCellularNetworkBinding {
    @RequiresPermission(Manifest.permission.ACCESS_NETWORK_STATE)
    override fun requireAvailable() {
        val capabilities = connectivity.getNetworkCapabilities(network)
            ?: throw IOException("The cellular network is unavailable.")
        if (!capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ||
            !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) ||
            !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        ) {
            throw IOException("The selected network is not an eligible cellular network.")
        }
    }

    override fun bind(socket: Socket) = network.bindSocket(socket)

    override fun bind(socket: DatagramSocket) = network.bindSocket(socket)
}
