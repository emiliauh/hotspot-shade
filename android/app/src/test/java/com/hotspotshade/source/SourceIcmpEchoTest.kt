package com.hotspotshade.source

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class SourceIcmpEchoTest {
    private val nonce = ByteArray(SourceEchoWire.NONCE_BYTES) { (it + 1).toByte() }

    private fun replyFor(
        family: EchoFamily,
        payload: ByteArray,
        sequence: Int,
        withHeader: Boolean,
    ): ByteArray {
        val request = SourceEchoWire.request(family, payload, nonce, sequence)
        request[0] = if (family == EchoFamily.IPV4) 0 else 129.toByte()
        if (family == EchoFamily.IPV4) {
            request[2] = 0
            request[3] = 0
            val sum = SourceEchoWire.checksum(request)
            request[2] = ((sum shr 8) and 0xFF).toByte()
            request[3] = (sum and 0xFF).toByte()
        }
        if (!withHeader) return request
        return if (family == EchoFamily.IPV4) {
            val header = ByteArray(20)
            header[0] = 0x45
            header + request
        } else {
            val header = ByteArray(40)
            header[0] = 0x60
            header + request
        }
    }

    @Test
    fun ipv4TargetsFollowTheEchoRules() {
        assertNotNull(SourceEchoWire.target(1, byteArrayOf(1, 1, 1, 1), 0))
        assertNotNull(SourceEchoWire.target(1, byteArrayOf(10, 0, 2, 2), 0))
        assertEquals(EchoFamily.IPV4, SourceEchoWire.target(1, byteArrayOf(8, 8, 4, 4), 0)?.family)
        // A port is reserved for echo.
        assertNull(SourceEchoWire.target(1, byteArrayOf(1, 1, 1, 1), 53))
        // Unspecified, loopback, multicast, and link local.
        assertNull(SourceEchoWire.target(1, byteArrayOf(0, 0, 0, 0), 0))
        assertNull(SourceEchoWire.target(1, byteArrayOf(0, 1, 2, 3), 0))
        assertNull(SourceEchoWire.target(1, byteArrayOf(127, 0, 0, 1), 0))
        assertNull(SourceEchoWire.target(1, byteArrayOf(224.toByte(), 0, 0, 1), 0))
        assertNull(SourceEchoWire.target(1, byteArrayOf(169.toByte(), 254.toByte(), 1, 1), 0))
        // A domain is not an echo target.
        assertNull(SourceEchoWire.target(3, byteArrayOf(1, 1, 1, 1), 0))
        assertNull(SourceEchoWire.target(1, byteArrayOf(1, 1, 1), 0))
    }

    @Test
    fun ipv6TargetsFollowTheEchoRules() {
        val valid = byteArrayOf(
            0x20, 0x01, 0x0D, 0xB8.toByte(), 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 1,
        )
        assertNotNull(SourceEchoWire.target(4, valid, 0))
        assertEquals(EchoFamily.IPV6, SourceEchoWire.target(4, valid, 0)?.family)
        assertNull(SourceEchoWire.target(4, valid, 53))
        assertNull(SourceEchoWire.target(4, ByteArray(16), 0))
        assertNull(SourceEchoWire.target(4, ByteArray(16).also { it[15] = 1 }, 0))
        assertNull(SourceEchoWire.target(4, ByteArray(16).also { it[0] = 0xFF.toByte() }, 0))
        assertNull(
            SourceEchoWire.target(
                4,
                ByteArray(16).also {
                    it[0] = 0xFE.toByte()
                    it[1] = 0x80.toByte()
                    it[15] = 1
                },
                0,
            ),
        )
        assertNull(
            "An IPv4-mapped address is not accepted.",
            SourceEchoWire.target(
                4,
                byteArrayOf(
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0xFF.toByte(), 0xFF.toByte(), 1, 2, 3, 4,
                ),
                0,
            ),
        )
    }

    @Test
    fun ipv4ReplyValidatesAndReturnsThePayload() {
        val payload = "echo-probe".toByteArray()
        val sequence = 0x1234
        val reply = replyFor(EchoFamily.IPV4, payload, sequence, withHeader = false)
        val result = SourceEchoWire.validateReply(
            reply = reply,
            count = reply.size,
            family = EchoFamily.IPV4,
            sequence = sequence,
            nonce = nonce,
            payloadSize = payload.size,
        )
        assertArrayEquals(payload, result)
    }

    @Test
    fun ipv4ReplyWithTheHeaderValidates() {
        val payload = "with-header".toByteArray()
        val reply = replyFor(EchoFamily.IPV4, payload, 7, withHeader = true)
        val result = SourceEchoWire.validateReply(
            reply = reply,
            count = reply.size,
            family = EchoFamily.IPV4,
            sequence = 7,
            nonce = nonce,
            payloadSize = payload.size,
        )
        assertArrayEquals(payload, result)
    }

    @Test
    fun ipv6ReplyValidatesAndReturnsThePayload() {
        val payload = "v6-echo".toByteArray()
        val reply = replyFor(EchoFamily.IPV6, payload, 9, withHeader = false)
        val result = SourceEchoWire.validateReply(
            reply = reply,
            count = reply.size,
            family = EchoFamily.IPV6,
            sequence = 9,
            nonce = nonce,
            payloadSize = payload.size,
        )
        assertArrayEquals(payload, result)
    }

    @Test
    fun aWrongSequenceOrNonceIsRejected() {
        val payload = "bad".toByteArray()
        val reply = replyFor(EchoFamily.IPV4, payload, 1, withHeader = false)
        assertNull(
            SourceEchoWire.validateReply(reply, reply.size, EchoFamily.IPV4, 2, nonce, payload.size),
        )
        val wrongNonce = ByteArray(SourceEchoWire.NONCE_BYTES) { 9 }
        assertNull(
            SourceEchoWire.validateReply(
                reply,
                reply.size,
                EchoFamily.IPV4,
                1,
                wrongNonce,
                payload.size,
            ),
        )
    }

    @Test
    fun aReplyWithAnErrorTypeIsRejected() {
        val payload = "bad".toByteArray()
        val reply = replyFor(EchoFamily.IPV4, payload, 3, withHeader = false)
        reply[0] = 3
        reply[2] = 0
        reply[3] = 0
        val sum = SourceEchoWire.checksum(reply)
        reply[2] = ((sum shr 8) and 0xFF).toByte()
        reply[3] = (sum and 0xFF).toByte()
        assertNull(
            SourceEchoWire.validateReply(reply, reply.size, EchoFamily.IPV4, 3, nonce, payload.size),
        )
    }

    @Test
    fun aTruncatedOrOversizedReplyIsRejected() {
        val payload = "sized".toByteArray()
        val reply = replyFor(EchoFamily.IPV4, payload, 5, withHeader = false)
        assertNull(
            SourceEchoWire.validateReply(
                reply,
                reply.size - 1,
                EchoFamily.IPV4,
                5,
                nonce,
                payload.size,
            ),
        )
        assertNull(
            SourceEchoWire.validateReply(
                reply,
                reply.size,
                EchoFamily.IPV4,
                5,
                nonce,
                payload.size + 1,
            ),
        )
    }

    @Test
    fun theChecksumMatchesAKnownValue() {
        // The IPv4 header checksum of 45 00 00 14 00 00 00 00 40 01 00 00 7f 00 00 01 7f 00 00 01
        val header = byteArrayOf(
            0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01,
            0x00, 0x00, 0x7F, 0x00, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01,
        )
        assertEquals(0x7CE7, SourceEchoWire.checksum(header))
    }

    @Test
    fun aRequestHoldsTheNonceAndThePayload() {
        val payload = "abc".toByteArray()
        val packet = SourceEchoWire.request(EchoFamily.IPV4, payload, nonce, 0x0102)
        assertEquals(8 + nonce.size + payload.size, packet.size)
        assertEquals(8, packet[0].toInt())
        assertEquals(1, packet[6].toInt())
        assertEquals(2, packet[7].toInt())
        assertArrayEquals(nonce, packet.copyOfRange(8, 8 + nonce.size))
        assertArrayEquals(payload, packet.copyOfRange(8 + nonce.size, packet.size))
        assertEquals(0, SourceEchoWire.checksum(packet))
    }
}
