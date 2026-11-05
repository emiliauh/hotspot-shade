package com.hotspotshade.source.pairing

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

/**
 * Canonical text for a pairing peer.
 *
 * The rate-limit budgets use this text as their key. Two spellings of one IP
 * address must share one budget. A text with a port or a zone is rejected,
 * because it would give one address more than one budget.
 *
 * The parser reads numeric addresses only. It never calls a name resolver.
 */
internal object PeerAddress {
    private const val MAX_PEER_LENGTH = 64

    /**
     * Return the rate-limit key for [peer], or throw
     * [PairingError.PEER] for an unusable value.
     */
    fun canonical(peer: String): String {
        val bytes = peer.toByteArray(Charsets.UTF_8)
        if (bytes.isEmpty() || bytes.size > MAX_PEER_LENGTH ||
            !bytes.all { (it.toInt() and 0xFF) in 0x21..0x7E }
        ) {
            throw PairingException(PairingError.PEER)
        }
        if (peer.contains('%')) throw PairingException(PairingError.PEER)

        parseIpv4(peer)?.let { return it.hostAddress ?: throw PairingException(PairingError.PEER) }
        parseIpv6(peer)?.let { address ->
            val mapped = mappedIpv4(address)
            if (mapped != null) {
                return InetAddress.getByAddress(mapped).hostAddress
                    ?: throw PairingException(PairingError.PEER)
            }
            return formatIpv6(address)
        }
        if (parsesAsSocketAddress(peer)) throw PairingException(PairingError.PEER)
        return peer
    }

    /** Return the text for one socket address without a zone or port. */
    fun text(address: InetAddress): String = when (address) {
        is Inet4Address -> address.hostAddress ?: ""
        is Inet6Address -> {
            val mapped = mappedIpv4(address.address)
            if (mapped != null) {
                InetAddress.getByAddress(mapped).hostAddress ?: ""
            } else {
                formatIpv6(address.address)
            }
        }

        else -> address.hostAddress ?: ""
    }

    /** Parse a strict dotted IPv4 address. Reject a leading zero. */
    fun parseIpv4(text: String): Inet4Address? {
        val parts = text.split('.')
        if (parts.size != 4) return null
        val bytes = ByteArray(4)
        for ((index, part) in parts.withIndex()) {
            if (part.isEmpty() || part.length > 3) return null
            if (part.length > 1 && part[0] == '0') return null
            if (!part.all { it.isDigit() }) return null
            val value = part.toIntOrNull() ?: return null
            if (value !in 0..255) return null
            bytes[index] = value.toByte()
        }
        return InetAddress.getByAddress(bytes) as? Inet4Address
    }

    /**
     * Parse an IPv6 address into 16 bytes. Support one `::` compression and an
     * embedded IPv4 address in the last 32 bits. Return null for a bad shape.
     */
    fun parseIpv6(text: String): ByteArray? {
        if (text.isEmpty() || text.contains('%')) return null
        if (!text.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' || it == ':' || it == '.' }) {
            return null
        }
        val doubleColon = text.indexOf("::")
        if (doubleColon >= 0 && text.indexOf("::", doubleColon + 2) >= 0) return null
        val headText: String
        val tailText: String?
        if (doubleColon >= 0) {
            headText = text.substring(0, doubleColon)
            tailText = text.substring(doubleColon + 2)
        } else {
            headText = text
            tailText = null
        }
        val head = parseGroups(headText) ?: return null
        val tail = tailText?.let { parseGroups(it) } ?: emptyList()
        val total = head.size + tail.size
        val groups: List<Int>
        if (doubleColon < 0) {
            if (total != 8) return null
            groups = head + tail
        } else {
            if (total >= 8) return null
            groups = head + List(8 - total) { 0 } + tail
        }
        val output = ByteArray(16)
        for (index in groups.indices) {
            output[2 * index] = ((groups[index] ushr 8) and 0xFF).toByte()
            output[2 * index + 1] = (groups[index] and 0xFF).toByte()
        }
        return output
    }

    /** Format 16 bytes as the RFC 5952 lower-case text. */
    fun formatIpv6(bytes: ByteArray): String {
        require(bytes.size == 16) { "The IPv6 value has the wrong size." }
        val groups = IntArray(8) {
            ((bytes[2 * it].toInt() and 0xFF) shl 8) or (bytes[2 * it + 1].toInt() and 0xFF)
        }
        var bestStart = -1
        var bestLength = 0
        var index = 0
        while (index < 8) {
            if (groups[index] != 0) {
                index += 1
                continue
            }
            val start = index
            while (index < 8 && groups[index] == 0) index += 1
            val length = index - start
            if (length >= 2 && length > bestLength) {
                bestStart = start
                bestLength = length
            }
        }
        val text = StringBuilder()
        if (bestStart < 0) {
            for (group in groups) {
                if (text.isNotEmpty()) text.append(':')
                text.append(group.toString(16))
            }
            return text.toString()
        }
        for (group in 0 until bestStart) {
            if (text.isNotEmpty()) text.append(':')
            text.append(groups[group].toString(16))
        }
        text.append("::")
        for (group in bestStart + bestLength until 8) {
            if (group > bestStart + bestLength) text.append(':')
            text.append(groups[group].toString(16))
        }
        return text.toString()
    }

    /** Return the four IPv4 bytes for an IPv4-mapped IPv6 address. */
    fun mappedIpv4(bytes: ByteArray): ByteArray? {
        if (bytes.size != 16) return null
        for (index in 0 until 10) if (bytes[index] != 0.toByte()) return null
        if (bytes[10] != 0xFF.toByte() || bytes[11] != 0xFF.toByte()) return null
        return bytes.copyOfRange(12, 16)
    }

    private fun parseGroups(part: String): List<Int>? {
        if (part.isEmpty()) return emptyList()
        val tokens = part.split(':')
        val groups = mutableListOf<Int>()
        for ((index, token) in tokens.withIndex()) {
            if (token.isEmpty()) return null
            if (token.contains('.')) {
                if (index != tokens.lastIndex) return null
                val ipv4 = parseIpv4(token) ?: return null
                groups += (ipv4.address[0].toInt() and 0xFF) shl 8 or
                    (ipv4.address[1].toInt() and 0xFF)
                groups += (ipv4.address[2].toInt() and 0xFF) shl 8 or
                    (ipv4.address[3].toInt() and 0xFF)
                continue
            }
            if (token.length > 4 || !token.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' }) {
                return null
            }
            groups += token.toInt(16)
        }
        return groups
    }

    private fun parsesAsSocketAddress(text: String): Boolean {
        val colon = text.lastIndexOf(':')
        if (colon <= 0 || colon == text.lastIndex) return false
        val host = text.substring(0, colon)
        val port = text.substring(colon + 1)
        if (port.length > 5 || !port.all { it.isDigit() }) return false
        val value = port.toIntOrNull() ?: return false
        if (value > 65535) return false
        if (host.length > 2 && host.startsWith("[") && host.endsWith("]")) {
            return parseIpv6(host.substring(1, host.length - 1)) != null
        }
        return parseIpv4(host) != null
    }
}
