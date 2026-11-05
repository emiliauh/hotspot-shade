package com.hotspotshade.source

import java.net.Inet4Address
import java.net.InetAddress
import java.net.NetworkInterface

/** One local network interface and its addresses. A JVM test supplies these. */
internal class InterfaceSnapshot(
    val name: String,
    val isUp: Boolean,
    val isLoopback: Boolean,
    val addresses: List<InetAddress>,
)

/** Read the local network interfaces. */
internal fun interface InterfaceSource {
    fun read(): List<InterfaceSnapshot>
}

/** Read the local interfaces with java.net.NetworkInterface. */
internal class PlatformInterfaceSource : InterfaceSource {
    override fun read(): List<InterfaceSnapshot> {
        val result = mutableListOf<InterfaceSnapshot>()
        val interfaces = try {
            NetworkInterface.getNetworkInterfaces()
        } catch (_: Exception) {
            return result
        } ?: return result
        for (networkInterface in interfaces) {
            try {
                result += InterfaceSnapshot(
                    name = networkInterface.name,
                    isUp = networkInterface.isUp,
                    isLoopback = networkInterface.isLoopback,
                    addresses = networkInterface.interfaceAddresses.map { it.address },
                )
            } catch (_: Exception) {
                // An interface can vanish while it is read. Skip it.
            }
        }
        return result
    }
}

/**
 * Find the hotspot (tethering) IPv4 address of this device.
 *
 * The service binds the source listener to this address only. It never binds
 * the any-local address. A JVM test supplies a fake finder.
 */
internal interface HotspotAddressFinder {
    /** Return the hotspot address, or null when the device has no hotspot. */
    fun findHotspotAddress(): InetAddress?
}

/**
 * Find the hotspot address from the interface list.
 *
 * The finder skips loopback, down, cellular, VPN, and excluded interfaces.
 * The caller excludes the cellular and Wi-Fi client interfaces of
 * ConnectivityManager. A named tethering interface wins over a generic
 * private interface. When more than one tethering interface is up, the
 * Wi-Fi access point wins over USB tethering.
 */
internal class NetworkInterfaceHotspotAddressFinder(
    private val source: InterfaceSource,
    private val excludedNames: () -> Set<String>,
) : HotspotAddressFinder {
    override fun findHotspotAddress(): InetAddress? {
        val excluded = try {
            excludedNames().map { it.lowercase() }.toSet()
        } catch (_: Exception) {
            emptySet()
        }
        return source.read()
            .asSequence()
            .filter { it.isUp && !it.isLoopback }
            .filter { it.name.lowercase() !in excluded }
            .mapNotNull { snapshot ->
                val rank = rankOf(snapshot.name) ?: return@mapNotNull null
                val address = snapshot.addresses.firstOrNull { isPrivateIpv4(it) }
                    ?: return@mapNotNull null
                Candidate(rank, snapshot.name, address)
            }
            .sortedWith(compareBy({ it.rank }, { it.name }))
            .firstOrNull()
            ?.address
    }

    private fun rankOf(name: String): Int? {
        val lower = name.lowercase()
        if (VIRTUAL_PREFIXES.any { lower.startsWith(it) }) return null
        if (CELLULAR_PREFIXES.any { lower.startsWith(it) }) return null
        return when {
            lower.startsWith("swlan") -> 0
            lower.startsWith("ap") -> 1
            lower.startsWith("softap") -> 2
            lower.startsWith("wlan") && wlanIndex(lower) != 0 -> 3
            lower.startsWith("rndis") -> 4
            lower.startsWith("bt-pan") -> 5
            lower.startsWith("usb") -> 6
            lower.startsWith("wlan") -> 7
            else -> 8
        }
    }

    private fun wlanIndex(name: String): Int =
        name.removePrefix("wlan").takeWhile { it.isDigit() }.toIntOrNull() ?: 0

    private fun isPrivateIpv4(address: InetAddress): Boolean =
        address is Inet4Address &&
            !address.isAnyLocalAddress &&
            !address.isLoopbackAddress &&
            !address.isLinkLocalAddress &&
            address.isSiteLocalAddress

    private class Candidate(
        val rank: Int,
        val name: String,
        val address: InetAddress,
    )

    private companion object {
        val CELLULAR_PREFIXES = listOf("rmnet", "ccmni", "pdp", "clat", "radio", "wwan")
        val VIRTUAL_PREFIXES = listOf("tun", "ppp", "ipsec", "dummy")
    }
}
