package com.hotspotshade.source

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests for the TLS ClientHello record shaper in SourceSocksServer.kt.
 *
 * The test opens no socket and uses no route, device, carrier, or phone. It
 * proves record framing and byte identity. It does not prove a real TLS
 * handshake; `rust/tests/tls_shape_handshake.rs` has the loopback handshake.
 */
class SourceClientHelloShaperTest {
    private fun clientHello(bodyLength: Int): ByteArray {
        val message = ByteArray(4 + bodyLength)
        message[0] = 1
        message[1] = ((bodyLength ushr 16) and 0xFF).toByte()
        message[2] = ((bodyLength ushr 8) and 0xFF).toByte()
        message[3] = (bodyLength and 0xFF).toByte()
        for (index in 0 until bodyLength) {
            message[4 + index] = (index % 251).toByte()
        }
        return message
    }

    private fun record(payload: ByteArray, versionMinor: Int = 1): ByteArray {
        val out = ByteArray(5 + payload.size)
        out[0] = 22
        out[1] = 3
        out[2] = versionMinor.toByte()
        out[3] = ((payload.size ushr 8) and 0xFF).toByte()
        out[4] = (payload.size and 0xFF).toByte()
        System.arraycopy(payload, 0, out, 5, payload.size)
        return out
    }

    private class Reassembled(
        val message: ByteArray,
        val records: Int,
        val largest: Int,
        val tail: ByteArray,
    )

    private fun reassemble(chunks: List<ByteArray>, messageLength: Int): Reassembled {
        val bytes = java.io.ByteArrayOutputStream()
        for (chunk in chunks) bytes.write(chunk)
        val all = bytes.toByteArray()
        var offset = 0
        val payload = java.io.ByteArrayOutputStream()
        var records = 0
        var largest = 0
        while (payload.size() < messageLength) {
            assertTrue("a record header is present", all.size - offset >= 5)
            assertEquals("a shaped record is a handshake record", 22, all[offset].toInt() and 0xFF)
            assertEquals("the record version is TLS", 3, all[offset + 1].toInt() and 0xFF)
            val length = ((all[offset + 3].toInt() and 0xFF) shl 8) or
                (all[offset + 4].toInt() and 0xFF)
            assertTrue("a record payload is complete", all.size - offset - 5 >= length)
            payload.write(all, offset + 5, length)
            largest = maxOf(largest, length)
            offset += 5 + length
            records += 1
        }
        return Reassembled(
            payload.toByteArray(),
            records,
            largest,
            all.copyOfRange(offset, all.size),
        )
    }

    @Test
    fun oneRecordClientHelloIsReframedAndReassembles() {
        val message = clientHello(300)
        val shaper = SourceClientHelloShaper()
        val chunks = shaper.feed(record(message))
        assertEquals(SourceClientHelloShaper.State.REFRAMED, shaper.state)
        assertTrue("the ClientHello spans many records", chunks.size > 1)
        val result = reassemble(chunks, message.size)
        assertArrayEquals("handshake bytes are identical", message, result.message)
        assertTrue(result.largest in 1..8)
        assertTrue(result.records > 1)
        assertEquals(0, result.tail.size)
    }

    @Test
    fun clientHelloSplitAcrossRecordsIsReassembled() {
        val message = clientHello(500)
        val shaper = SourceClientHelloShaper()
        val chunks = ArrayList<ByteArray>()
        chunks += shaper.feed(record(message.copyOfRange(0, 2), versionMinor = 3))
        chunks += shaper.feed(record(message.copyOfRange(2, 17), versionMinor = 3))
        chunks += shaper.feed(record(message.copyOfRange(17, message.size), versionMinor = 3))
        assertEquals(SourceClientHelloShaper.State.REFRAMED, shaper.state)
        assertArrayEquals(message, reassemble(chunks, message.size).message)
    }

    @Test
    fun aTinyFirstRecordIsShapedTheSameWhenFedWholeOrSplit() {
        // Regression: the first record carries one to three handshake bytes,
        // so the rest of the message arrives in the next record. The bytes
        // after the first record's payload are the next record header, not
        // length bytes of this message. Reading them as length bytes made the
        // whole input wait for a fabricated message length.
        for (first in 1..3) {
            val message = clientHello(300)
            val input = record(message.copyOfRange(0, first), versionMinor = 3) +
                record(message.copyOfRange(first, message.size), versionMinor = 3)
            val split = 5 + first

            val whole = SourceClientHelloShaper()
            val wholeChunks = whole.feed(input)
            assertEquals("first record of $first bytes", SourceClientHelloShaper.State.REFRAMED, whole.state)
            assertArrayEquals(message, reassemble(wholeChunks, message.size).message)

            val piecewise = SourceClientHelloShaper()
            val splitChunks = ArrayList<ByteArray>()
            splitChunks += piecewise.feed(input, 0, split)
            splitChunks += piecewise.feed(input, split, input.size - split)
            assertEquals(
                "first record of $first bytes takes the same path",
                whole.state,
                piecewise.state,
            )
            assertEquals(wholeChunks.size, splitChunks.size)
            wholeChunks.indices.forEach { assertArrayEquals(wholeChunks[it], splitChunks[it]) }
        }
    }

    @Test
    fun aTinyFirstRecordFollowedByApplicationDataPassesThroughUnchanged() {
        // A two-byte handshake prefix can still become a ClientHello, but the
        // next record is application data. The next record header is not
        // handshake bytes, so the whole input passes through unchanged.
        val prefix = record(byteArrayOf(1, 0), versionMinor = 3)
        val applicationData = byteArrayOf(23, 3, 3, 0, 4, 'd'.code.toByte(), 'a'.code.toByte(),
            't'.code.toByte(), 'a'.code.toByte())
        val input = prefix + applicationData
        val shaper = SourceClientHelloShaper()
        assertArrayEquals(input, shaper.feed(input).single())
        assertEquals(SourceClientHelloShaper.State.PASS_THROUGH, shaper.state)
        assertEquals(0, shaper.bufferedCount())
    }

    @Test
    fun oneByteFeedsMatchOneBigFeed() {
        val message = clientHello(120)
        val input = record(message)
        val whole = SourceClientHelloShaper().feed(input)
        val shaper = SourceClientHelloShaper()
        val split = ArrayList<ByteArray>()
        for (byte in input) {
            split += shaper.feed(byteArrayOf(byte))
        }
        assertEquals(whole.size, split.size)
        whole.indices.forEach { assertArrayEquals(whole[it], split[it]) }
    }

    @Test
    fun partialRecordsWaitWithoutOutput() {
        val message = clientHello(60)
        val input = record(message)
        val shaper = SourceClientHelloShaper()
        assertTrue(shaper.feed(input, 0, 3).isEmpty())
        assertEquals(3, shaper.bufferedCount())
        assertEquals(SourceClientHelloShaper.State.BUFFERING, shaper.state)
        val rest = shaper.feed(input, 3, input.size - 3)
        assertArrayEquals(message, reassemble(rest, message.size).message)
    }

    @Test
    fun bytesAfterTheClientHelloPassThroughUnchanged() {
        val message = clientHello(80)
        val shaper = SourceClientHelloShaper()
        val chunks = ArrayList<ByteArray>()
        chunks += shaper.feed(record(message) + "later application bytes".toByteArray())
        assertEquals(SourceClientHelloShaper.State.REFRAMED, shaper.state)
        val result = reassemble(chunks, message.size)
        assertArrayEquals(message, result.message)
        assertArrayEquals("later application bytes".toByteArray(), result.tail)
    }

    @Test
    fun dataAfterTheFirstHelloIsNeverReshaped() {
        val message = clientHello(64)
        val shaper = SourceClientHelloShaper()
        shaper.feed(record(message))
        val later = "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n".toByteArray()
        val chunks = shaper.feed(later)
        assertEquals(1, chunks.size)
        assertArrayEquals(later, chunks[0])
        val second = record(clientHello(100), versionMinor = 3)
        assertArrayEquals(second, shaper.feed(second).single())
    }

    @Test
    fun nonTlsInputPassesThrough() {
        val shaper = SourceClientHelloShaper()
        val input = "GET / HTTP/1.1\r\n\r\n".toByteArray()
        assertArrayEquals(input, shaper.feed(input).single())
        assertEquals(SourceClientHelloShaper.State.PASS_THROUGH, shaper.state)
    }

    @Test
    fun aHandshakeRecordThatIsNotAClientHelloPassesThrough() {
        val shaper = SourceClientHelloShaper()
        val input = record(byteArrayOf(2, 0, 0, 40) + ByteArray(40) { 7 })
        assertArrayEquals(input, shaper.feed(input).single())
        assertEquals(SourceClientHelloShaper.State.PASS_THROUGH, shaper.state)
    }

    @Test
    fun anOversizeClientHelloPassesThrough() {
        val shaper = SourceClientHelloShaper(clientHelloLimit = 1024)
        val input = record(clientHello(4096))
        assertArrayEquals(input, shaper.feed(input).single())
        assertEquals(SourceClientHelloShaper.State.PASS_THROUGH, shaper.state)
    }

    @Test
    fun aRecordCountAboveTheLimitPassesThrough() {
        val shaper = SourceClientHelloShaper(chunkLimit = 1, recordLimit = 8)
        val input = record(clientHello(100))
        assertArrayEquals(input, shaper.feed(input).single())
        assertEquals(SourceClientHelloShaper.State.PASS_THROUGH, shaper.state)
    }

    @Test
    fun leftoverHandshakeBytesCountTowardOutputRecordLimit() {
        val input = record(clientHello(96) + byteArrayOf(9, 8, 7))
        val limited = SourceClientHelloShaper(recordLimit = 23)
        assertArrayEquals(input, limited.feed(input).single())
        assertEquals(SourceClientHelloShaper.State.PASS_THROUGH, limited.state)

        val allowed = SourceClientHelloShaper(recordLimit = 24)
        val chunks = allowed.feed(input)
        assertEquals(SourceClientHelloShaper.State.REFRAMED, allowed.state)
        assertEquals(24, chunks.size)
    }

    @Test
    fun aCompleteClientHelloWithALongTailDoesNotTripTheBufferCap() {
        // A whole read can carry the ClientHello and more than the buffer cap
        // of later bytes. The complete message must still be reframed; only a
        // prefix that still needs more bytes is subject to the cap.
        val message = clientHello(120)
        val tail = ByteArray(SourceClientHelloShaper.DEFAULT_MAX_BUFFERED + 1024) {
            (it % 251).toByte()
        }
        val shaper = SourceClientHelloShaper()
        val result = reassemble(shaper.feed(record(message) + tail), message.size)
        assertEquals(SourceClientHelloShaper.State.REFRAMED, shaper.state)
        assertEquals(0, shaper.bufferedCount())
        assertArrayEquals(message, result.message)
        assertArrayEquals(tail, result.tail)
        assertTrue(result.largest in 1..8)
    }

    @Test
    fun aLongTailAfterTheClientHelloTakesTheSamePathWholeOrSplit() {
        val message = clientHello(200)
        val hello = record(message, versionMinor = 3)
        val tail = ByteArray(SourceClientHelloShaper.DEFAULT_MAX_BUFFERED + 4096) {
            ((it * 7) % 251).toByte()
        }

        val wholeShaper = SourceClientHelloShaper()
        val whole = reassemble(wholeShaper.feed(hello + tail), message.size)

        val splitShaper = SourceClientHelloShaper()
        val splitChunks = ArrayList<ByteArray>()
        splitChunks += splitShaper.feed(hello)
        splitChunks += splitShaper.feed(tail)
        val split = reassemble(splitChunks, message.size)

        assertEquals(SourceClientHelloShaper.State.REFRAMED, wholeShaper.state)
        assertEquals(wholeShaper.state, splitShaper.state)
        assertArrayEquals(whole.message, split.message)
        assertArrayEquals(whole.tail, split.tail)
        assertArrayEquals(tail, split.tail)
    }

    @Test
    fun anIncompleteHelloAboveTheBufferCapPassesThroughAndStaysBounded() {
        val shaper = SourceClientHelloShaper(clientHelloLimit = 1024, bufferLimit = 4096)
        // A handshake record that declares 16 KiB and starts a valid-looking
        // 1004 byte message. The record is incomplete and the held prefix is
        // over the cap, so the flow turns into a plain pass-through.
        val header = byteArrayOf(22, 3, 3, 0x40, 0)
        val payload = byteArrayOf(1, 0, 0x03, 0xe8.toByte()) + ByteArray(5000) { 9 }
        val input = header + payload
        val chunks = shaper.feed(input)
        assertEquals(SourceClientHelloShaper.State.PASS_THROUGH, shaper.state)
        assertEquals(0, shaper.bufferedCount())
        assertArrayEquals(input, concat(chunks))
    }

    @Test
    fun invalidOrEmptyInputChangesNothing() {
        val shaper = SourceClientHelloShaper()
        assertTrue(shaper.feed(ByteArray(0)).isEmpty())
        assertEquals(SourceClientHelloShaper.State.BUFFERING, shaper.state)
        assertEquals(1, SourceClientHelloShaper(chunkLimit = 0).maxChunk)
        assertEquals(8, SourceClientHelloShaper(chunkLimit = 99).maxChunk)
    }

    private fun concat(chunks: List<ByteArray>): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        for (chunk in chunks) out.write(chunk)
        return out.toByteArray()
    }

    @Test
    fun aShortWriteThatCannotBeTlsIsForwardedAtOnce() {
        // A request/response protocol sends one to four bytes and then waits
        // for a reply. Each of these is impossible as a TLS record at byte 0 or
        // byte 1, so the shaper must return it in the same call.
        val cases = listOf(
            byteArrayOf('P'.code.toByte()),
            "PI".toByteArray(),
            "PIN".toByteArray(),
            "PING".toByteArray(),
            "ls\n".toByteArray(),
            "GET ".toByteArray(),
            byteArrayOf(5, 1, 0),
            byteArrayOf(22, 4),
        )
        for (input in cases) {
            val shaper = SourceClientHelloShaper()
            val chunks = shaper.feed(input)
            assertEquals("one piece for ${input.toList()}", 1, chunks.size)
            assertArrayEquals("every byte is preserved", input, chunks.single())
            assertEquals(
                "no wait for more bytes for ${input.toList()}",
                SourceClientHelloShaper.State.PASS_THROUGH,
                shaper.state,
            )
            assertEquals("nothing stays buffered", 0, shaper.bufferedCount())
        }
    }

    @Test
    fun everySplitOfAShortRequestIsForwardedWithoutAStall() {
        val input = "PING".toByteArray()
        for (length in 1..input.size) {
            for (split in 0..length) {
                val shaper = SourceClientHelloShaper()
                val chunks = ArrayList<ByteArray>()
                chunks += shaper.feed(input, 0, split)
                chunks += shaper.feed(input, split, length - split)
                assertEquals(
                    "length $length split $split passes through",
                    SourceClientHelloShaper.State.PASS_THROUGH,
                    shaper.state,
                )
                assertArrayEquals(
                    "length $length split $split preserves every byte",
                    input.copyOfRange(0, length),
                    concat(chunks),
                )
            }
        }
    }

    @Test
    fun aRequestThatWaitsForAReplyIsNeverHeld() {
        // The sender writes one byte of a short request and stops. The shaper
        // must hand that byte over before the sender sends anything else.
        val shaper = SourceClientHelloShaper()
        val chunks = ArrayList<ByteArray>()
        for (byte in "PING /status\r\n".toByteArray()) {
            val piece = shaper.feed(byteArrayOf(byte))
            assertEquals("one byte goes out at once", 1, piece.size)
            chunks += piece
        }
        assertEquals(SourceClientHelloShaper.State.PASS_THROUGH, shaper.state)
        assertArrayEquals("PING /status\r\n".toByteArray(), concat(chunks))
        val reply = "OK\r\n".toByteArray()
        assertArrayEquals(reply, shaper.feed(reply).single())
    }

    @Test
    fun aTlsMajorVersionOtherThanThreeDecidesAtByteOne() {
        val shaper = SourceClientHelloShaper()
        assertTrue("one ambiguous byte is held", shaper.feed(byteArrayOf(22)).isEmpty())
        assertEquals(SourceClientHelloShaper.State.BUFFERING, shaper.state)
        assertEquals(1, shaper.bufferedCount())
        val decided = shaper.feed(byteArrayOf(4))
        assertEquals(SourceClientHelloShaper.State.PASS_THROUGH, shaper.state)
        assertEquals(0, shaper.bufferedCount())
        assertArrayEquals(byteArrayOf(22, 4), decided.single())
        assertArrayEquals("rest".toByteArray(), shaper.feed("rest".toByteArray()).single())
    }

    @Test
    fun aHandshakeTypeOtherThanClientHelloDecidesBeforeTheRecordEnds() {
        // A valid handshake header that declares 16 KiB of payload, then the
        // first payload byte. That byte is the message type. It is not 1, so
        // the record can never become a ClientHello.
        val header = byteArrayOf(22, 3, 3, 0x40, 0)
        val shaper = SourceClientHelloShaper()
        assertTrue("the record payload has not arrived", shaper.feed(header).isEmpty())
        assertEquals(SourceClientHelloShaper.State.BUFFERING, shaper.state)
        val decided = shaper.feed(byteArrayOf(2))
        assertEquals(SourceClientHelloShaper.State.PASS_THROUGH, shaper.state)
        assertEquals(0, shaper.bufferedCount())
        assertArrayEquals(header + byteArrayOf(2), decided.single())
    }

    @Test
    fun aHandshakeHeaderAcrossRecordsRejectsBeforeTheNextRecordEnds() {
        // The first record carries only the message type. The next record
        // starts with a declared length below the ClientHello minimum, so the
        // flow can never be a ClientHello even before the next record ends.
        val shaper = SourceClientHelloShaper()
        val first = record(byteArrayOf(1), versionMinor = 3)
        assertTrue("one handshake byte waits", shaper.feed(first).isEmpty())
        val secondHeader = byteArrayOf(22, 3, 3, 0x40, 0)
        val early = secondHeader + byteArrayOf(0, 0, 0)
        val decided = shaper.feed(early)
        assertEquals(SourceClientHelloShaper.State.PASS_THROUGH, shaper.state)
        assertEquals(0, shaper.bufferedCount())
        assertArrayEquals(first + early, concat(decided))
    }

    @Test
    fun aDeclaredClientHelloLengthIsCheckedBeforeTheRecordEnds() {
        // A handshake record that declares 16 KiB but starts a type 1 message
        // with length 0. That message is below the minimum, so it passes
        // through without waiting for the rest of the record.
        val prefix = byteArrayOf(22, 3, 3, 0x40, 0, 1, 0, 0, 0)
        val shaper = SourceClientHelloShaper()
        val chunks = shaper.feed(prefix)
        assertEquals(SourceClientHelloShaper.State.PASS_THROUGH, shaper.state)
        assertArrayEquals(prefix, chunks.single())
    }

    @Test
    fun aHeaderSplitIntoEveryFieldStillReassembles() {
        val message = clientHello(90)
        val input = record(message, versionMinor = 3)
        val parts = listOf(
            input.copyOfRange(0, 1),
            input.copyOfRange(1, 2),
            input.copyOfRange(2, 3),
            input.copyOfRange(3, 5),
            input.copyOfRange(5, 6),
            input.copyOfRange(6, input.size),
        )
        val shaper = SourceClientHelloShaper()
        val chunks = ArrayList<ByteArray>()
        for (part in parts) chunks += shaper.feed(part)
        assertEquals(SourceClientHelloShaper.State.REFRAMED, shaper.state)
        val result = reassemble(chunks, message.size)
        assertArrayEquals(message, result.message)
        assertTrue(result.largest in 1..8)
        assertEquals(0, result.tail.size)
    }

    @Test
    fun aValidHandshakeStillReframesWhenFedOneByteAtATime() {
        val message = clientHello(70)
        val shaper = SourceClientHelloShaper()
        val chunks = ArrayList<ByteArray>()
        for (byte in record(message, versionMinor = 3)) {
            chunks += shaper.feed(byteArrayOf(byte))
        }
        assertEquals(SourceClientHelloShaper.State.REFRAMED, shaper.state)
        assertEquals(0, shaper.bufferedCount())
        val result = reassemble(chunks, message.size)
        assertArrayEquals("handshake bytes are identical", message, result.message)
        assertTrue(result.largest in 1..8)
        assertEquals(0, result.tail.size)
    }

    @Test
    fun finishReleasesAnIncompleteClientHelloUnchangedOnce() {
        val input = record(clientHello(200))
        val partial = input.copyOfRange(0, 40)
        val shaper = SourceClientHelloShaper()
        assertTrue("an incomplete record emits nothing", shaper.feed(partial).isEmpty())
        assertEquals(partial.size, shaper.bufferedCount())
        val released = shaper.finish()
        assertArrayEquals("every held byte is released", partial, released.single())
        assertEquals(0, shaper.bufferedCount())
        assertEquals(SourceClientHelloShaper.State.PASS_THROUGH, shaper.state)
        // Exactly once. A repeat emits nothing, and later bytes pass through.
        assertTrue("finish never releases a second copy", shaper.finish().isEmpty())
        assertArrayEquals("later".toByteArray(), shaper.feed("later".toByteArray()).single())
    }

    @Test
    fun finishAfterAReframedHelloEmitsNothing() {
        val message = clientHello(64)
        val shaper = SourceClientHelloShaper()
        assertTrue(shaper.feed(record(message)).isNotEmpty())
        assertEquals(SourceClientHelloShaper.State.REFRAMED, shaper.state)
        assertTrue(shaper.finish().isEmpty())
        assertEquals(SourceClientHelloShaper.State.REFRAMED, shaper.state)
    }

    @Test
    fun finishWithNothingBufferedEmitsNothing() {
        val shaper = SourceClientHelloShaper()
        assertTrue(shaper.finish().isEmpty())
        assertEquals(SourceClientHelloShaper.State.PASS_THROUGH, shaper.state)
        assertTrue(shaper.finish().isEmpty())
    }

    @Test
    fun releasedBytesAreNotHeldForASecondWrite() {
        // A sink error can cut the write short. Once the shaper releases its
        // bytes it holds none, so a later call can never replay or duplicate
        // them, and a later byte is never shaped.
        val shaped = SourceClientHelloShaper()
        shaped.feed(record(clientHello(80)))
        assertEquals(0, shaped.bufferedCount())
        val later = "after the handshake".toByteArray()
        assertArrayEquals(later, shaped.feed(later).single())

        val plain = SourceClientHelloShaper()
        plain.feed("GET / HTTP/1.1\r\n".toByteArray())
        assertEquals(SourceClientHelloShaper.State.PASS_THROUGH, plain.state)
        assertEquals(0, plain.bufferedCount())
        assertArrayEquals("GET".toByteArray(), plain.feed("GET".toByteArray()).single())
    }
}
