package com.hotspotshade.source

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

/** The address family of one echo request. */
internal enum class EchoFamily { IPV4, IPV6 }

/** One numeric unicast echo destination. It holds no name. */
internal class EchoTarget(
    val family: EchoFamily,
    val address: InetAddress,
)

/**
 * One status of the private echo command.
 *
 * The values match `ios/HotspotProxy/CellularICMPEcho.swift` and the Rust
 * target device. Status 5 to 9 report an unusable path. Android has no path
 * monitor. It uses 6 when the selected network cannot bound the socket.
 */
internal enum class EchoStatus(val wire: Int) {
    SUCCESS(0),
    NO_CELLULAR(1),
    BUSY(2),
    TIMEOUT(3),
    FAILED(4),
    PATH_TIMEOUT(5),
    PATH_UNSATISFIED(6),
    PATH_NOT_CELLULAR(7),
    NO_CELLULAR_INTERFACE(8),
    AMBIGUOUS_CELLULAR(9),
    ;

    companion object {
        fun fromWire(value: Int): EchoStatus? = entries.firstOrNull { it.wire == value }
    }
}

/** One echo reply. An error reply has an empty payload. */
internal class EchoResult(
    val status: EchoStatus,
    val payload: ByteArray = EMPTY_PAYLOAD,
) {
    private companion object {
        val EMPTY_PAYLOAD = ByteArray(0)
    }
}

/** Send one echo probe on the selected cellular network. */
internal fun interface SourceEchoSender {
    fun send(target: EchoTarget, payload: ByteArray, timeoutMillis: Long): EchoResult
}

/**
 * The private echo wire format of the source device proxy.
 *
 * The listener accepts command `0x81` for one echo and command `0x82` for a
 * persistent echo session. The target device builds the request. The server
 * replies with a status byte, a big-endian length, and the payload.
 *
 * The rules match `ios/HotspotProxy/CellularICMPEcho.swift`. Port zero is
 * reserved for echo. Scoped, multicast, loopback, unspecified, and
 * IPv4-mapped IPv6 addresses are not accepted.
 */
internal object SourceEchoWire {
    /** The command for one echo request. */
    const val COMMAND = 0x81

    /** The command for one persistent echo session. */
    const val PERSISTENT_COMMAND = 0x82

    /** The largest payload in one echo frame. */
    const val MAXIMUM_PAYLOAD = 1200

    /** The nonce that detects a stale reply. */
    const val NONCE_BYTES = 16

    private const val TYPE_ECHO_REQUEST_V4 = 8
    private const val TYPE_ECHO_REPLY_V4 = 0
    private const val TYPE_ECHO_REQUEST_V6 = 128
    private const val TYPE_ECHO_REPLY_V6 = 129

    /**
     * Parse one echo target. Return null for a target that the command does
     * not accept.
     *
     * This method uses the address bytes only. It never resolves a name.
     */
    fun target(addressType: Int, address: ByteArray, port: Int): EchoTarget? {
        if (port != 0) return null
        return when (addressType) {
            1 -> {
                if (address.size != 4) return null
                val first = address[0].toInt() and 0xFF
                val second = address[1].toInt() and 0xFF
                if (first == 0 || first == 127 || first >= 224) return null
                if (first == 169 && second == 254) return null
                val parsed = addressOf(address) as? Inet4Address ?: return null
                EchoTarget(EchoFamily.IPV4, parsed)
            }
            4 -> {
                if (address.size != 16) return null
                val first = address[0].toInt() and 0xFF
                val second = address[1].toInt() and 0xFF
                if (first == 0xFF) return null
                if (first == 0xFE && (second and 0xC0) == 0x80) return null
                if (address.all { it == 0.toByte() }) return null
                if (address.dropLast(1).all { it == 0.toByte() } && address[15] == 1.toByte()) {
                    return null
                }
                if (address.take(10).all { it == 0.toByte() } &&
                    address[10] == 0xFF.toByte() && address[11] == 0xFF.toByte()
                ) {
                    return null
                }
                val parsed = addressOf(address) as? Inet6Address ?: return null
                EchoTarget(EchoFamily.IPV6, parsed)
            }
            else -> null
        }
    }

    /** Build one echo request packet for the kernel. */
    fun request(
        family: EchoFamily,
        payload: ByteArray,
        nonce: ByteArray,
        sequence: Int,
    ): ByteArray {
        require(payload.size <= MAXIMUM_PAYLOAD) { "The echo payload is too large." }
        require(nonce.size == NONCE_BYTES) { "The echo nonce has the wrong size." }
        val type = if (family == EchoFamily.IPV4) TYPE_ECHO_REQUEST_V4 else TYPE_ECHO_REQUEST_V6
        val packet = ByteArray(8 + nonce.size + payload.size)
        packet[0] = type.toByte()
        packet[1] = 0
        packet[4] = 0
        packet[5] = 0
        packet[6] = ((sequence shr 8) and 0xFF).toByte()
        packet[7] = (sequence and 0xFF).toByte()
        nonce.copyInto(packet, 8)
        payload.copyInto(packet, 8 + nonce.size)
        if (family == EchoFamily.IPV4) {
            // The IPv4 kernel can replace the checksum. A correct value is safe.
            val sum = checksum(packet)
            packet[2] = ((sum shr 8) and 0xFF).toByte()
            packet[3] = (sum and 0xFF).toByte()
        }
        return packet
    }

    /**
     * Validate one reply and return the echo payload, or null.
     *
     * The reply may include the IPv4 or IPv6 header. The kernel can omit it.
     */
    fun validateReply(
        reply: ByteArray,
        count: Int,
        family: EchoFamily,
        sequence: Int,
        nonce: ByteArray,
        payloadSize: Int,
    ): ByteArray? {
        if (count <= 0 || count > reply.size || reply.size < 4) return null
        if (payloadSize < 0 || payloadSize > MAXIMUM_PAYLOAD) return null
        if (nonce.size != NONCE_BYTES) return null
        val offset = when (family) {
            EchoFamily.IPV4 -> {
                val version = (reply[0].toInt() and 0xF0) shr 4
                if (version == 4) {
                    val header = (reply[0].toInt() and 0x0F) * 4
                    if (header < 20) return null
                    header
                } else {
                    0
                }
            }
            EchoFamily.IPV6 -> {
                val version = (reply[0].toInt() and 0xF0) shr 4
                if (version == 6) 40 else 0
            }
        }
        val expected = offset + 8 + NONCE_BYTES + payloadSize
        if (count != expected) return null
        val type = if (family == EchoFamily.IPV4) TYPE_ECHO_REPLY_V4 else TYPE_ECHO_REPLY_V6
        if ((reply[offset].toInt() and 0xFF) != type) return null
        if ((reply[offset + 1].toInt() and 0xFF) != 0) return null
        if ((reply[offset + 6].toInt() and 0xFF) != ((sequence shr 8) and 0xFF)) return null
        if ((reply[offset + 7].toInt() and 0xFF) != (sequence and 0xFF)) return null
        for (index in nonce.indices) {
            if (reply[offset + 8 + index] != nonce[index]) return null
        }
        if (family == EchoFamily.IPV4 && checksum(reply, offset, count - offset) != 0) return null
        return reply.copyOfRange(offset + 8 + NONCE_BYTES, count)
    }

    /** The one's complement checksum of a byte range. */
    fun checksum(bytes: ByteArray, offset: Int = 0, count: Int = bytes.size): Int {
        var sum = 0L
        var index = offset
        val end = offset + count
        while (index < end) {
            val high = (bytes[index].toInt() and 0xFF) shl 8
            val low = if (index + 1 < end) bytes[index + 1].toInt() and 0xFF else 0
            sum += (high or low).toLong()
            index += 2
        }
        while (sum shr 16 != 0L) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return (sum.inv().toInt()) and 0xFFFF
    }

    private fun addressOf(bytes: ByteArray): InetAddress? = try {
        // A byte array is a literal. This method does not resolve a name.
        InetAddress.getByAddress(bytes)
    } catch (_: Exception) {
        null
    }
}
