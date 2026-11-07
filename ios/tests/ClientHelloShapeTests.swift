import Foundation

// Tests for the TLS ClientHello record shaper in ProxyServer.swift.
//
// The test is hermetic. It opens no socket and uses no route or device. It
// proves record framing, byte identity, and that an incomplete ClientHello is
// released unchanged exactly once at end of stream. It does not prove a real
// TLS handshake, a carrier, a hotspot, or a physical phone. The Rust port is
// the one with a real loopback handshake test.
//
// To run it, add this line to scripts/swift_tests.sh after the
// PROXY_SOURCES array is defined:
//   run ClientHelloShapeTests "${PROXY_SOURCES[@]}"

@main
struct ClientHelloShapeTests {
    static func check(_ condition: Bool, _ message: String, line: Int = #line) {
        if !condition {
            print("FAIL line \(line): \(message)")
            exit(1)
        }
    }

    /// A deterministic ClientHello shape. The body is not a real handshake,
    /// but the message header and length are real.
    static func clientHello(bodyLength: Int) -> [UInt8] {
        var message = [UInt8](repeating: 0, count: 4 + bodyLength)
        message[0] = 1
        message[1] = UInt8((bodyLength >> 16) & 0xff)
        message[2] = UInt8((bodyLength >> 8) & 0xff)
        message[3] = UInt8(bodyLength & 0xff)
        for index in 0..<bodyLength {
            message[4 + index] = UInt8(index % 251)
        }
        return message
    }

    static func record(_ payload: [UInt8], version: (UInt8, UInt8) = (3, 1)) -> Data {
        var out = Data()
        out.append(22)
        out.append(version.0)
        out.append(version.1)
        let length = UInt16(payload.count)
        out.append(UInt8(length >> 8))
        out.append(UInt8(length & 0xff))
        out.append(contentsOf: payload)
        return out
    }

    /// Split shaped output into record payloads until `messageLength` bytes are
    /// collected. Return the payload, the record count, the largest payload,
    /// and the offset of the first unshaped byte.
    static func reassemble(_ chunks: [Data], messageLength: Int) -> ([UInt8], Int, Int, Int) {
        var bytes: [UInt8] = []
        for chunk in chunks { bytes.append(contentsOf: chunk) }
        var offset = 0
        var payload: [UInt8] = []
        var records = 0
        var largest = 0
        while payload.count < messageLength {
            check(bytes.count - offset >= 5, "a record header is present")
            check(bytes[offset] == 22, "a shaped record is a handshake record")
            check(bytes[offset + 1] == 3, "the record version is TLS")
            let length = (Int(bytes[offset + 3]) << 8) | Int(bytes[offset + 4])
            check(bytes.count - offset - 5 >= length, "a record payload is complete")
            payload.append(contentsOf: bytes[(offset + 5)..<(offset + 5 + length)])
            largest = max(largest, length)
            offset += 5 + length
            records += 1
        }
        return (payload, records, largest, offset)
    }

    /// Concatenate the pieces into the exact byte stream a peer would read.
    static func joined(_ chunks: [Data]) -> Data {
        var out = Data()
        for chunk in chunks { out.append(chunk) }
        return out
    }

    /// Parse every complete handshake record in `bytes` and return the carried
    /// payload, the record count, and the largest record payload.
    static func parseAllRecords(_ bytes: [UInt8]) -> ([UInt8], Int, Int) {
        var payload: [UInt8] = []
        var offset = 0
        var records = 0
        var largest = 0
        while offset < bytes.count {
            check(bytes.count - offset >= 5, "a record header is present")
            check(bytes[offset] == 22, "a record is a handshake record")
            check(bytes[offset + 1] == 3, "a record version is TLS")
            let length = (Int(bytes[offset + 3]) << 8) | Int(bytes[offset + 4])
            check(bytes.count - offset - 5 >= length, "a record payload is complete")
            payload.append(contentsOf: bytes[(offset + 5)..<(offset + 5 + length)])
            largest = max(largest, length)
            offset += 5 + length
            records += 1
        }
        return (payload, records, largest)
    }

    /// Feed every part, then finish, so an incomplete prefix is released the
    /// way the relay releases it at end of stream.
    static func runFinished(_ parts: [Data]) -> ([Data], ClientHelloShaper.State) {
        var shaper = ClientHelloShaper()
        var chunks: [Data] = []
        for part in parts { chunks += shaper.feed(part) }
        chunks += shaper.finish()
        return (chunks, shaper.state)
    }

    /// The bytes a stream carries: the payload of every complete handshake
    /// record, followed by every byte after the last complete record. Only the
    /// record framing is removed, so a reshaped stream must carry the same
    /// bytes as its input.
    static func logicalBytes(_ bytes: [UInt8]) -> [UInt8] {
        var out: [UInt8] = []
        var offset = 0
        while bytes.count - offset >= 5 && bytes[offset] == 22 && bytes[offset + 1] == 3 {
            let length = (Int(bytes[offset + 3]) << 8) | Int(bytes[offset + 4])
            if length == 0 || length > ClientHelloShaper.maxRecordPayload
                || bytes.count - offset - 5 < length {
                break
            }
            out.append(contentsOf: bytes[(offset + 5)..<(offset + 5 + length)])
            offset += 5 + length
        }
        out.append(contentsOf: bytes[offset...])
        return out
    }

    static func main() {
        // One record is reframed into records of 1 to 8 payload bytes and
        // reassembles to the same handshake bytes.
        let message = clientHello(bodyLength: 300)
        var shaper = ClientHelloShaper()
        let chunks = shaper.feed(record(message))
        check(shaper.state == .reframed, "a complete ClientHello is reframed")
        check(chunks.count > 1, "the ClientHello spans many records")
        let (payload, records, largest, offset) = reassemble(chunks, messageLength: message.count)
        check(payload == message, "handshake bytes are identical")
        check(records > 1, "more than one record carries the message")
        check(largest <= 8 && largest >= 1, "record payloads are 1 to 8 bytes")
        check(offset == chunks.reduce(0) { $0 + $1.count }, "no tail bytes after the records")
        for chunk in chunks {
            check(chunk[chunk.startIndex + 1] == 3, "a shaped record keeps a TLS version")
        }

        // A ClientHello split across records reassembles.
        let splitMessage = clientHello(bodyLength: 500)
        var split = ClientHelloShaper()
        let first = record(Array(splitMessage[0..<2]), version: (3, 3))
        let second = record(Array(splitMessage[2..<17]), version: (3, 3))
        let third = record(Array(splitMessage[17...]), version: (3, 3))
        var splitChunks = split.feed(first)
        splitChunks += split.feed(second)
        splitChunks += split.feed(third)
        check(split.state == .reframed, "a split ClientHello is reframed")
        let splitPayload = reassemble(splitChunks, messageLength: splitMessage.count).0
        check(splitPayload == splitMessage, "split handshake bytes are identical")

        // One byte at a time gives the same output as one feed.
        var bytewise = ClientHelloShaper()
        var bytewiseChunks: [Data] = []
        for byte in record(message) {
            bytewiseChunks += bytewise.feed(Data([byte]))
        }
        check(bytewiseChunks == chunks, "bytewise feeds match one feed")

        // A partial record emits nothing until it is complete.
        var partial = ClientHelloShaper()
        let input = record(message)
        let partialChunks = partial.feed(input.prefix(3))
        check(partialChunks.isEmpty, "a partial header emits nothing")
        check(partial.bufferedCount == 3, "the partial header is buffered")
        let rest = partial.feed(input.dropFirst(3))
        check(reassemble(rest, messageLength: message.count).0 == message,
              "the rest completes the message")

        // Bytes after the ClientHello are unchanged, and a second ClientHello
        // on the same flow is not reshaped.
        var tail = ClientHelloShaper()
        var tailChunks = tail.feed(record(message))
        let later = Data("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n".utf8)
        tailChunks += tail.feed(later)
        check(tail.state == .reframed, "the flow stays reframed")
        check(tailChunks.last == later, "later bytes pass through unchanged")
        let secondHello = record(clientHello(bodyLength: 100), version: (3, 3))
        let secondChunks = tail.feed(secondHello)
        check(secondChunks == [secondHello], "a second ClientHello passes through")

        // A client that ends before the ClientHello is complete releases the
        // bytes it sent, unchanged, once, before the half-close.
        let wholeInput = record(message)
        let truncatedInput = Data(wholeInput.prefix(40))
        var truncated = ClientHelloShaper()
        var truncatedChunks = truncated.feed(truncatedInput)
        check(truncatedChunks.isEmpty, "a partial ClientHello emits nothing")
        check(truncated.isBuffering, "the flow still waits for the ClientHello")
        check(truncated.bufferedCount == truncatedInput.count, "every partial byte is held")
        let released = truncated.finish()
        check(released == [truncatedInput], "finish releases the held bytes unchanged")
        check(!truncated.isBuffering, "finish ends buffering")
        check(truncated.bufferedCount == 0, "finish releases the buffer")
        check(truncated.finish().isEmpty, "finish releases the bytes exactly once")
        truncatedChunks = truncated.feed(later)
        check(truncatedChunks == [later], "bytes after finish pass through unchanged")

        // A flow that already reframed its ClientHello has nothing to release.
        var finishedComplete = ClientHelloShaper()
        _ = finishedComplete.feed(record(message))
        check(finishedComplete.finish().isEmpty,
              "a reframed flow releases nothing at end of stream")

        // A flow that is not TLS passes through byte for byte.
        let plain = Data("GET / HTTP/1.1\r\n\r\n".utf8)
        var plainShaper = ClientHelloShaper()
        check(plainShaper.feed(plain) == [plain], "non-TLS bytes pass through")
        check(plainShaper.state == .passThrough, "non-TLS bytes end shaping")

        // A handshake record that is not a ClientHello passes through.
        var wrong = ClientHelloShaper()
        let serverHello = record([2, 0, 0, 40] + [UInt8](repeating: 7, count: 40))
        check(wrong.feed(serverHello) == [serverHello], "a non-ClientHello passes through")
        check(wrong.state == .passThrough, "a non-ClientHello ends shaping")

        // Reject an impossible handshake length even when its four-byte
        // header crosses records and the second record is incomplete.
        var splitInvalid = ClientHelloShaper()
        let firstRecord = Data([22, 3, 1, 0, 1, 1])
        let nextPrefix = Data([22, 3, 1, 0, 16, 255, 255, 255])
        check(splitInvalid.feed(firstRecord).isEmpty, "the short first record is held")
        check(splitInvalid.feed(nextPrefix) == [firstRecord + nextPrefix],
              "an impossible cross-record length passes through promptly")
        check(splitInvalid.state == .passThrough, "the invalid header ends shaping")

        // A ClientHello above the cap passes through unchanged.
        var huge = ClientHelloShaper(maxClientHello: 1024)
        let bigInput = record(clientHello(bodyLength: 4096))
        check(huge.feed(bigInput) == [bigInput], "a large ClientHello passes through")
        check(huge.state == .passThrough, "a large ClientHello ends shaping")

        // A record count above the limit passes through unchanged.
        var capped = ClientHelloShaper(maxChunk: 1, maxRecords: 8)
        let cappedInput = record(clientHello(bodyLength: 100))
        check(capped.feed(cappedInput) == [cappedInput], "too many records passes through")
        check(capped.state == .passThrough, "too many records ends shaping")

        // A short request/response protocol must pass through in the same call
        // at every length from 1 to 4. Waiting for a five byte record header
        // would stall a ping or another short protocol.
        for length in 1...4 {
            let input = Data(Array("PING".utf8).prefix(length))
            var short = ClientHelloShaper()
            check(short.feed(input) == [input],
                  "a \(length) byte non-TLS prefix passes through at once")
            check(short.state == .passThrough,
                  "a \(length) byte non-TLS prefix ends shaping")
            check(short.bufferedCount == 0, "a rejected prefix drops its buffer")
        }

        // A wrong content type is decided at byte zero.
        var wrongContentType = ClientHelloShaper()
        let applicationData = Data([23])
        check(wrongContentType.feed(applicationData) == [applicationData],
              "a non-handshake content type passes through at once")
        check(wrongContentType.state == .passThrough,
              "a non-handshake content type ends shaping")

        // A wrong TLS major version is decided at byte one, before the rest of
        // the record header arrives.
        var wrongVersion = ClientHelloShaper()
        check(wrongVersion.feed(Data([22])).isEmpty, "one ambiguous byte is held")
        check(wrongVersion.state == .buffering, "one ambiguous byte keeps buffering")
        let versionByte = Data([4])
        check(wrongVersion.feed(versionByte) == [Data([22]) + versionByte],
              "a wrong TLS major version passes through at byte one")
        check(wrongVersion.state == .passThrough,
              "a wrong TLS major version ends shaping")

        // A first record payload that is not a ClientHello passes through
        // before the whole record arrives. The record below declares 16 KiB.
        let slowHeader = Data([22, 3, 3, 0x40, 0x00])
        var wrongHandshake = ClientHelloShaper()
        check(wrongHandshake.feed(slowHeader).isEmpty,
              "a header with no payload bytes still waits")
        check(wrongHandshake.state == .buffering,
              "a header with no payload bytes keeps buffering")
        let serverHelloByte = Data([2])
        check(wrongHandshake.feed(serverHelloByte) == [slowHeader + serverHelloByte],
              "a non-ClientHello handshake type passes through before the record ends")
        check(wrongHandshake.state == .passThrough,
              "a non-ClientHello handshake type ends shaping")

        // An impossible ClientHello length passes through before the record
        // payload ends, so a large record cannot hold the flow.
        let impossibleLength = Data([22, 3, 3, 0x40, 0x00, 1, 0, 0, 0])
        var shortHello = ClientHelloShaper()
        check(shortHello.feed(impossibleLength) == [impossibleLength],
              "an impossible ClientHello length passes through before the payload ends")
        check(shortHello.state == .passThrough,
              "an impossible ClientHello length ends shaping")
        var splitShortHello = ClientHelloShaper()
        check(splitShortHello.feed(Data([22, 3, 3, 0x40, 0x00, 1, 0, 0])).isEmpty,
              "three message length bytes wait for the fourth")
        let lastLengthByte = Data([0])
        check(splitShortHello.feed(lastLengthByte) == [impossibleLength],
              "an impossible length is rejected as soon as its last byte arrives")
        check(splitShortHello.state == .passThrough,
              "a split impossible length ends shaping")

        // A zero or oversize record length is decided on the header alone.
        for badHeader in [Data([22, 3, 3, 0, 0]), Data([22, 3, 3, 0x40, 0x01])] {
            var bad = ClientHelloShaper()
            check(bad.feed(badHeader) == [badHeader],
                  "an impossible record length passes through at once")
            check(bad.state == .passThrough,
                  "an impossible record length ends shaping")
        }

        // A first record that carries only one to three handshake bytes must
        // not read the next record header as message length bytes. The whole
        // input and a split after the first record must take the same path.
        for firstLength in 1...3 {
            let tinyMessage = clientHello(bodyLength: 300)
            var tinyInput = record(Array(tinyMessage[0..<firstLength]), version: (3, 3))
            tinyInput.append(record(Array(tinyMessage[firstLength...]), version: (3, 3)))
            var wholeTiny = ClientHelloShaper()
            let wholeTinyChunks = wholeTiny.feed(tinyInput)
            check(wholeTiny.state == .reframed,
                  "a tiny first record of \(firstLength) bytes is reframed")
            check(reassemble(wholeTinyChunks, messageLength: tinyMessage.count).0 == tinyMessage,
                  "a tiny first record reassembles")
            let splitAt = 5 + firstLength
            var splitTiny = ClientHelloShaper()
            let splitTinyChunks = splitTiny.feed(tinyInput.prefix(splitAt))
                + splitTiny.feed(tinyInput.dropFirst(splitAt))
            check(splitTiny.state == .reframed,
                  "a split tiny first record of \(firstLength) bytes is reframed")
            check(joined(splitTinyChunks) == joined(wholeTinyChunks),
                  "a tiny first record emits the same bytes when split")
        }

        // A header split on each field boundary still reassembles.
        let fieldMessage = clientHello(bodyLength: 90)
        let fieldInput = record(fieldMessage)
        var fieldParts: [Data] = []
        var fieldStart = 0
        for cut in [1, 2, 3, 5, 6] {
            fieldParts.append(Data(fieldInput[fieldStart..<cut]))
            fieldStart = cut
        }
        fieldParts.append(Data(fieldInput[fieldStart...]))
        var fieldShaper = ClientHelloShaper()
        var fieldChunks: [Data] = []
        for part in fieldParts { fieldChunks += fieldShaper.feed(part) }
        check(fieldShaper.state == .reframed, "a field by field header is reframed")
        check(reassemble(fieldChunks, messageLength: fieldMessage.count).0 == fieldMessage,
              "a field by field header reassembles")

        // The buffer cap is checked after the parse. A complete ClientHello
        // followed by a tail above the cap must still be reframed, and every
        // split of those bytes must emit the same stream.
        let capMessage = clientHello(bodyLength: 100)
        var capInput = record(capMessage)
        let capTail = Data((0..<400).map { UInt8($0 % 251) })
        capInput.append(capTail)
        var capWhole = ClientHelloShaper(maxClientHello: 200, maxBuffered: 200)
        let wholeCapped = capWhole.feed(capInput)
        check(capWhole.state == .reframed,
              "a complete ClientHello with a large tail is reframed")
        check(reassemble(wholeCapped, messageLength: capMessage.count).0 == capMessage,
              "the ClientHello before a large tail reassembles")
        check(wholeCapped.last == capTail,
              "the tail after the ClientHello record is unchanged")
        let wholeCappedBytes = joined(wholeCapped)
        for split in 0...capInput.count {
            var splitShaper = ClientHelloShaper(maxClientHello: 200, maxBuffered: 200)
            var splitChunks = splitShaper.feed(Data(capInput.prefix(split)))
            splitChunks += splitShaper.feed(Data(capInput.dropFirst(split)))
            check(splitShaper.state == .reframed,
                  "the ClientHello and tail are reframed at split \(split)")
            check(joined(splitChunks) == wholeCappedBytes,
                  "split \(split) emits the same bytes as one feed")
        }

        // A corpus covers the early decision points and record boundaries.
        // Every two way split must emit the same bytes and take the same path
        // as one feed, and every carried byte must survive.
        let corpusMessage = clientHello(bodyLength: 300)
        var corpus: [(String, Data)] = []
        corpus.append(("one record", record(corpusMessage)))
        for firstLength in 1...4 {
            var input = record(Array(corpusMessage[0..<firstLength]), version: (3, 3))
            input.append(record(Array(corpusMessage[firstLength...]), version: (3, 3)))
            corpus.append(("first record carries \(firstLength) bytes", input))
        }
        var oneByteRecords = Data()
        for byte in corpusMessage {
            oneByteRecords.append(record([byte], version: (3, 1)))
        }
        corpus.append(("one byte records", oneByteRecords))
        var helloAndTail = record(corpusMessage)
        helloAndTail.append(Data("GET / HTTP/1.1\r\n\r\n".utf8))
        corpus.append(("hello and a tail", helloAndTail))
        var helloAndLater = record(corpusMessage)
        helloAndLater.append(record(clientHello(bodyLength: 24), version: (3, 3)))
        corpus.append(("hello and a later record", helloAndLater))
        corpus.append(("short protocol", Data("PING".utf8)))
        corpus.append(("http request", Data("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n".utf8)))
        corpus.append(("partial header", Data([22, 3])))
        corpus.append(("one byte handshake record", Data([22, 3, 1, 0, 1, 1])))
        corpus.append(("one byte record and a partial header", Data([22, 3, 3, 0, 1, 1, 22, 3])))
        corpus.append(("one byte record and a complete header",
                       Data([22, 3, 3, 0, 1, 1, 22, 3, 3, 0, 1])))
        corpus.append(("application data record", Data([23, 3, 3, 0, 4, 100, 97, 116, 97])))
        corpus.append(("server hello", record([2, 0, 0, 4, 0, 0, 0, 0], version: (3, 3))))
        corpus.append(("zero length record", Data([22, 3, 3, 0, 0])))
        for (name, input) in corpus {
            let whole = runFinished([input])
            let wholeBytes = joined(whole.0)
            check(logicalBytes(Array(wholeBytes)) == logicalBytes(Array(input)),
                  "\(name): every carried byte is conserved")
            for split in 0...input.count {
                let splitResult = runFinished([
                    Data(input.prefix(split)),
                    Data(input.dropFirst(split)),
                ])
                check(splitResult.1 == whole.1,
                      "\(name): split \(split) takes the same path")
                check(joined(splitResult.0) == wholeBytes,
                      "\(name): split \(split) emits the same bytes as one feed")
            }
        }

        // An incomplete prefix that never becomes a ClientHello is released
        // once it passes the buffer cap. The bound applies while it waits.
        var cappedBuffer = ClientHelloShaper(maxClientHello: 39, maxBuffered: 64)
        var overCap = Data(record([1]))
        overCap.append(contentsOf: [22, 3, 3, 1, 44])
        overCap.append(contentsOf: [UInt8](repeating: 0, count: 80))
        check(overCap.count > 64, "the test input passes the buffer cap")
        check(cappedBuffer.feed(overCap) == [overCap],
              "a buffer above the cap passes through unchanged")
        check(cappedBuffer.state == .passThrough, "a buffer above the cap ends shaping")
        check(cappedBuffer.bufferedCount == 0, "a buffer above the cap drops its bytes")

        // The write cap counts the records that carry handshake bytes after
        // the ClientHello. A 39 byte message needs ten records at the default
        // chunk size, so one full later record makes eleven.
        let writeMessage = clientHello(bodyLength: 35)
        let helloOnly = record(writeMessage)
        var tenRecords = ClientHelloShaper(maxRecords: 10)
        check(tenRecords.feed(helloOnly) != [], "a 39 byte hello fits in ten records")
        check(tenRecords.state == .reframed, "a 39 byte hello fits in ten records")

        var writePayload = writeMessage
        writePayload.append(contentsOf: [UInt8](
            repeating: 0,
            count: ClientHelloShaper.maxRecordPayload - writePayload.count))
        let writeInput = record(writePayload)
        var cappedWrite = ClientHelloShaper(maxRecords: 10)
        check(cappedWrite.feed(writeInput) == [writeInput],
              "leftover handshake records count toward the write cap")
        check(cappedWrite.state == .passThrough,
              "a write above the cap ends shaping")

        // One more slot allows the same flow. The leftover record is reframed
        // and every payload byte is preserved.
        var allowedWrite = ClientHelloShaper(maxRecords: 11)
        let allowedChunks = allowedWrite.feed(writeInput)
        check(allowedWrite.state == .reframed,
              "a write at the cap is reframed")
        let (allowedPayload, allowedRecords, allowedLargest) =
            parseAllRecords(Array(joined(allowedChunks)))
        check(allowedPayload == writePayload,
              "the ClientHello and leftover handshake bytes are identical")
        check(allowedRecords == 11, "the write uses the leftover record")
        check(allowedLargest <= ClientHelloShaper.maxRecordPayload,
              "a leftover record stays inside the TLS record cap")

        // End of stream with nothing buffered releases nothing and ends
        // buffering. A second call is still a no-op.
        var emptyEnd = ClientHelloShaper()
        check(emptyEnd.finish().isEmpty, "finish with nothing buffered emits nothing")
        check(!emptyEnd.isBuffering, "finish with nothing buffered ends buffering")
        check(emptyEnd.finish().isEmpty, "a second empty finish emits nothing")
        let afterEnd = Data("PING".utf8)
        check(emptyEnd.feed(afterEnd) == [afterEnd],
              "bytes after an empty finish pass through")

        // End of stream while a record header is incomplete releases those
        // bytes unchanged, exactly once.
        var headerEnd = ClientHelloShaper()
        let partialHeader = Data([22, 3])
        check(headerEnd.feed(partialHeader).isEmpty,
              "a partial header emits nothing before end of stream")
        check(headerEnd.finish() == [partialHeader],
              "finish releases an incomplete header unchanged")
        check(headerEnd.finish().isEmpty,
              "finish releases an incomplete header exactly once")

        // Empty input changes nothing.
        var empty = ClientHelloShaper()
        check(empty.feed(Data()).isEmpty, "empty input emits nothing")
        check(empty.state == .buffering, "empty input keeps buffering")

        print("ClientHello shape tests passed")
    }
}
