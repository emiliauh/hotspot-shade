package com.hotspotshade.source

import android.Manifest
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import java.io.IOException
import java.net.DatagramSocket
import java.net.Socket
import java.net.SocketAddress
import androidx.annotation.RequiresPermission

/** A cellular network selected by the source service, not the process default. */
internal interface CellularBinding {
    fun requireAvailable()
    fun bind(socket: Socket)
    fun bind(socket: DatagramSocket)
}

/** Bind each unconnected socket to the same Android Network. */
internal class AndroidCellularBinding(
    private val connectivity: ConnectivityManager,
    private val network: Network,
) : CellularBinding {
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

/**
 * Create one unconnected, cellular-bound socket for one source-device flow.
 * The caller owns the returned socket and must close it on stop or network loss.
 * A network callback must stop existing flows when the selected network is lost.
 * This boundary does not select the network, resolve names, or open a listener.
 */
internal class CellularSockets(
    private val binding: CellularBinding,
    private val newTcp: () -> Socket = { Socket() },
    private val newUdp: () -> DatagramSocket = { DatagramSocket(null as SocketAddress?) },
) {
    fun tcp(onCreated: (Socket) -> Unit = {}, onFailureClosed: (Socket) -> Unit = {}): Socket {
        val socket = newTcp()
        return prepare(socket, onCreated, onFailureClosed, { binding.bind(it) }) { it.close() }
    }

    fun udp(onCreated: (DatagramSocket) -> Unit = {}, onFailureClosed: (DatagramSocket) -> Unit = {}): DatagramSocket {
        val socket = newUdp()
        return prepare(socket, onCreated, onFailureClosed, { binding.bind(it) }) { it.close() }
    }

    private fun <T> prepare(
        socket: T,
        onCreated: (T) -> Unit,
        onFailureClosed: (T) -> Unit,
        bind: (T) -> Unit,
        close: (T) -> Unit,
    ): T {
        try {
            onCreated(socket)
            binding.requireAvailable()
            bind(socket)
            // A network can be lost or change capabilities during binding.
            binding.requireAvailable()
            return socket
        } catch (failure: Throwable) {
            try {
                close(socket)
                onFailureClosed(socket)
            } catch (closeFailure: Throwable) {
                failure.addSuppressed(closeFailure)
            }
            throw failure
        }
    }
}
