package com.hotspotshade.source

import android.net.Network
import java.net.InetAddress

/** Resolve a host name with one injected lookup. A JVM test uses a fake. */
internal fun interface HostNameLookup {
    fun lookup(host: String): Array<InetAddress>
}

/**
 * Resolve destination names on the selected cellular network only.
 *
 * The service creates this adapter with the Network handle of the selected
 * cellular network. The adapter calls Network.getAllByName() on that network.
 * It never uses the process default resolver.
 */
internal class NetworkResolver(private val lookup: HostNameLookup) : SourceHostResolver {
    /** Resolve on one Android Network. The caller owns the deadline. */
    constructor(network: Network) : this(HostNameLookup { host -> network.getAllByName(host) })

    override fun resolve(host: String): List<InetAddress> = lookup.lookup(host).toList()
}
