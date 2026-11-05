package com.hotspotshade.source.pairing

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.security.MessageDigest

/** The status byte in a RESULT message. The wire values match protocol v1. */
internal enum class PairingStatus(val wire: Int) {
    OK(0),
    DENIED(1),
    BUSY(2),
    REJECTED(3),
    TIMED_OUT(4),
    NOT_ACTIVE(5),
    LOCKED_OUT(6),
    ;

    companion object {
        fun fromWire(value: Int): PairingStatus? = entries.firstOrNull { it.wire == value }
    }
}

/** A fixed pairing failure. The text holds no secret. */
internal enum class PairingError {
    PROTOCOL,
    FRAME_TOO_LARGE,
    IDENTITY,
    TRUST_STORE,
    CLOCK,
    PEER,
    CONFIGURATION,
    ;

    fun message(): String = when (this) {
        PROTOCOL -> "The pairing message is invalid."
        FRAME_TOO_LARGE -> "The pairing message is too large."
        IDENTITY -> "The source device random source failed."
        TRUST_STORE -> "The source device trust store failed."
        CLOCK -> "The source device clock moved backwards."
        PEER -> "The pairing peer identifier is not usable."
        CONFIGURATION -> "The source device pairing settings are invalid."
    }
}

/** A host error. The host must close the connection and send no pending frame. */
internal class PairingException(val error: PairingError) : Exception(error.message())

/** The per-session key material. It redacts every value in text output. */
internal class PairingKeys(
    val h: ByteArray,
    val kEnc: ByteArray,
    val kProof: ByteArray,
    val sas: ByteArray,
) {
    /** Clear the key material. */
    fun wipe() {
        h.fill(0)
        kEnc.fill(0)
        kProof.fill(0)
        sas.fill(0)
    }

    override fun toString(): String = "PairingKeys([redacted])"
}

/**
 * The proxy credentials that the source device sends after approval.
 *
 * The token is private. Kotlin cannot erase a String, so the value stays in
 * memory for the life of the object. Text output hides it.
 */
internal class PairingCredentials private constructor(
    val host: Inet4Address,
    val port: Int,
    val token: String,
) {
    override fun equals(other: Any?): Boolean =
        other is PairingCredentials && host == other.host && port == other.port &&
            token == other.token

    override fun hashCode(): Int = 31 * (31 * host.hashCode() + port) + token.hashCode()

    override fun toString(): String =
        "PairingCredentials(host=$host, port=$port, token=[redacted])"

    companion object {
        /**
         * Create credentials for a pairing result. Return null for an unsafe
         * value. The port is 1024 to 65535 and is not the pairing port. The
         * token is 1 to 255 printable ASCII bytes.
         */
        fun create(host: InetAddress, port: Int, token: String): PairingCredentials? {
            if (host !is Inet4Address) return null
            if (host.isAnyLocalAddress || host.isMulticastAddress) return null
            if (port < 1024 || port > 65535 || port == PairingProtocol.PAIRING_PORT) return null
            if (token.isEmpty() || token.length > 255) return null
            if (!token.all { it.code in 0x21..0x7E }) return null
            return PairingCredentials(host, port, token)
        }

        /** Build a value from wire bytes after the shape checks. */
        fun fromWire(host: Inet4Address, port: Int, token: String): PairingCredentials =
            PairingCredentials(host, port, token)
    }
}

/** The live source device status on the authenticated pairing channel. */
internal class ProxyStatus(
    val proxyRunning: Boolean,
    val foreground: Boolean,
    val connections: Int,
    val port: Int,
    val host: Inet4Address,
    val sequence: Long = 0,
)

/** A parsed CHALLENGE or an early RESULT with a non-zero status. */
internal sealed interface ChallengeOrResult {
    class Challenge(val pE: ByteArray, val known: Boolean) : ChallengeOrResult

    class Status(val status: PairingStatus) : ChallengeOrResult
}

/** A parsed RESULT. */
internal sealed interface ResultMessage {
    class Status(val status: PairingStatus) : ResultMessage

    class Ok(val nonce: ByteArray, val ciphertext: ByteArray) : ResultMessage
}

/**
 * Pairing protocol v1, source device side.
 *
 * The wire format, the key schedule, the labels, and the fixed vectors match
 * `rust/src/pairing.rs` and `ios/HotspotProxy/Pairing.swift`.
 */
internal object PairingProtocol {
    const val PAIRING_PORT = 18090
    const val MAX_FRAME = 512
    const val VERSION = 1
    const val MSG_HELLO = 0x01
    const val MSG_CHALLENGE = 0x02
    const val MSG_REVEAL = 0x03
    const val MSG_RESULT = 0x04
    const val MSG_STATUS_REQ = 0x05
    const val MSG_STATUS = 0x06
    const val MSG_FORGET = 0x07
    const val HELLO_LENGTH = 66
    const val CHALLENGE_LENGTH = 34
    const val REVEAL_LENGTH = 65
    const val MAX_BUFFERED = 4 * (2 + MAX_FRAME)

    private val COMMIT_LABEL = "hotspotshade-commit-v1".toByteArray(Charsets.US_ASCII)
    private val PAIR_LABEL = "hotspotshade-pair-v1".toByteArray(Charsets.US_ASCII)
    private val PROOF_LABEL = "laptop".toByteArray(Charsets.US_ASCII)

    /** Lower-case hex for public test values only. */
    fun hex(bytes: ByteArray): String = buildString(bytes.size * 2) {
        for (byte in bytes) {
            append(HEX[(byte.toInt() shr 4) and 0x0F])
            append(HEX[byte.toInt() and 0x0F])
        }
    }

    /** Read lower-case hex. A test uses it for the fixed vectors. */
    fun unhex(text: String): ByteArray {
        require(text.length % 2 == 0) { "The hex text has an odd length." }
        val output = ByteArray(text.length / 2)
        for (index in output.indices) {
            output[index] = ((HEX.indexOf(text[2 * index]) shl 4) or
                HEX.indexOf(text[2 * index + 1])).toByte()
        }
        return output
    }

    /** SHA-256 over concatenated parts. */
    fun sha256(vararg parts: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        for (part in parts) digest.update(part)
        return digest.digest()
    }

    /** C = SHA256("hotspotshade-commit-v1" || L_e || L_s). */
    fun commitment(lE: ByteArray, lS: ByteArray): ByteArray = sha256(COMMIT_LABEL, lE, lS)

    /** h = SHA256("hotspotshade-pair-v1" || L_s || L_e || P_e). */
    fun transcriptHash(lS: ByteArray, lE: ByteArray, pE: ByteArray): ByteArray =
        sha256(PAIR_LABEL, lS, lE, pE)

    /** prk = HKDF-Extract(h, ee || es). Expand "enc", "proof", and "sas". */
    fun deriveKeys(ee: ByteArray, es: ByteArray, h: ByteArray): PairingKeys {
        val input = ByteArray(ee.size + es.size)
        ee.copyInto(input, 0)
        es.copyInto(input, ee.size)
        val pseudoRandomKey = Hkdf.extract(h, input)
        input.fill(0)
        val keys = PairingKeys(
            h = h.copyOf(),
            kEnc = Hkdf.expand(pseudoRandomKey, "enc".toByteArray(Charsets.US_ASCII), 32),
            kProof = Hkdf.expand(pseudoRandomKey, "proof".toByteArray(Charsets.US_ASCII), 32),
            sas = Hkdf.expand(pseudoRandomKey, "sas".toByteArray(Charsets.US_ASCII), 4),
        )
        pseudoRandomKey.fill(0)
        return keys
    }

    /** Six decimal digits: the u32 big-endian SAS value modulo 1000000. */
    fun sasCode(sas: ByteArray): String {
        require(sas.size == 4) { "The SAS has the wrong size." }
        val value = ((sas[0].toLong() and 0xFF) shl 24) or
            ((sas[1].toLong() and 0xFF) shl 16) or
            ((sas[2].toLong() and 0xFF) shl 8) or
            (sas[3].toLong() and 0xFF)
        return (value % 1_000_000L).toString().padStart(6, '0')
    }

    /** Show the code as two groups of three digits, for example "482 193". */
    fun formatCode(code: String): String =
        if (code.length == 6) "${code.substring(0, 3)} ${code.substring(3)}" else code

    /** proof = HMAC-SHA256(k_proof, "laptop" || h). */
    fun laptopProof(keys: PairingKeys): ByteArray {
        val data = ByteArray(PROOF_LABEL.size + keys.h.size)
        PROOF_LABEL.copyInto(data, 0)
        keys.h.copyInto(data, PROOF_LABEL.size)
        val proof = Hkdf.hmac(keys.kProof, data)
        data.fill(0)
        return proof
    }

    /** Check a proof in constant time. */
    fun verifyProof(keys: PairingKeys, proof: ByteArray): Boolean {
        val expected = laptopProof(keys)
        var difference = if (expected.size == proof.size) 0 else 1
        val length = minOf(expected.size, proof.size)
        for (index in 0 until length) {
            difference = difference or (expected[index].toInt() xor proof[index].toInt())
        }
        expected.fill(0)
        return difference == 0
    }

    /** RESULT plaintext: [port:u16][token_len:u8][token][host_len:u8][host]. */
    fun encodeCredentials(credentials: PairingCredentials): ByteArray {
        val token = credentials.token.toByteArray(Charsets.US_ASCII)
        val host = credentials.host.hostAddress?.toByteArray(Charsets.US_ASCII) ?: ByteArray(0)
        if (token.isEmpty() || token.size > 255 || host.isEmpty() || host.size > 255) {
            throw PairingException(PairingError.PROTOCOL)
        }
        val output = ByteArray(4 + token.size + host.size)
        output[0] = ((credentials.port ushr 8) and 0xFF).toByte()
        output[1] = (credentials.port and 0xFF).toByte()
        output[2] = token.size.toByte()
        token.copyInto(output, 3)
        output[3 + token.size] = host.size.toByte()
        host.copyInto(output, 4 + token.size)
        return output
    }

    /** Parse the RESULT plaintext with strict lengths. */
    fun decodeCredentials(bytes: ByteArray): PairingCredentials {
        if (bytes.size < 3) throw PairingException(PairingError.PROTOCOL)
        val port = ((bytes[0].toInt() and 0xFF) shl 8) or (bytes[1].toInt() and 0xFF)
        val tokenLength = bytes[2].toInt() and 0xFF
        if (port == 0 || tokenLength == 0 || bytes.size < 4 + tokenLength) {
            throw PairingException(PairingError.PROTOCOL)
        }
        val hostLength = bytes[3 + tokenLength].toInt() and 0xFF
        if (hostLength == 0 || bytes.size != 4 + tokenLength + hostLength) {
            throw PairingException(PairingError.PROTOCOL)
        }
        val tokenBytes = bytes.copyOfRange(3, 3 + tokenLength)
        if (!tokenBytes.all { (it.toInt() and 0xFF) in 0x21..0x7E }) {
            tokenBytes.fill(0)
            throw PairingException(PairingError.PROTOCOL)
        }
        val token = tokenBytes.toString(Charsets.US_ASCII)
        tokenBytes.fill(0)
        val hostText = bytes.copyOfRange(4 + tokenLength, bytes.size).toString(Charsets.US_ASCII)
        val host = PeerAddress.parseIpv4(hostText) ?: throw PairingException(PairingError.PROTOCOL)
        return PairingCredentials.fromWire(host, port, token)
    }

    /** Encrypt the credentials with k_enc, the nonce, and aad h. */
    fun sealCredentials(
        keys: PairingKeys,
        nonce: ByteArray,
        credentials: PairingCredentials,
    ): ByteArray {
        val plaintext = encodeCredentials(credentials)
        val ciphertext = ChaCha20Poly1305.seal(keys.kEnc, nonce, plaintext, keys.h)
            ?: throw PairingException(PairingError.PROTOCOL)
        plaintext.fill(0)
        return ciphertext
    }

    /** Decrypt and parse the credentials. */
    fun openCredentials(keys: PairingKeys, nonce: ByteArray, ciphertext: ByteArray): PairingCredentials {
        val plaintext = ChaCha20Poly1305.open(keys.kEnc, nonce, ciphertext, keys.h)
            ?: throw PairingException(PairingError.PROTOCOL)
        val credentials = try {
            decodeCredentials(plaintext)
        } finally {
            plaintext.fill(0)
        }
        return credentials
    }

    /** Seal one command or status message with k_enc and aad h. */
    fun sealMessage(keys: PairingKeys, nonce: ByteArray, plaintext: ByteArray): ByteArray =
        ChaCha20Poly1305.seal(keys.kEnc, nonce, plaintext, keys.h)
            ?: throw PairingException(PairingError.PROTOCOL)

    /** Open one command or status message. */
    fun openMessage(keys: PairingKeys, nonce: ByteArray, ciphertext: ByteArray): ByteArray? =
        ChaCha20Poly1305.open(keys.kEnc, nonce, ciphertext, keys.h)

    fun encodeHello(lS: ByteArray, commit: ByteArray): ByteArray {
        require(lS.size == 32 && commit.size == 32) { "The HELLO keys have the wrong size." }
        val output = ByteArray(HELLO_LENGTH)
        output[0] = MSG_HELLO.toByte()
        output[1] = VERSION.toByte()
        lS.copyInto(output, 2)
        commit.copyInto(output, 34)
        return output
    }

    /** Parse HELLO. Return (L_s, C), or null for a bad shape. */
    fun decodeHello(message: ByteArray): Pair<ByteArray, ByteArray>? {
        if (message.size != HELLO_LENGTH &&
            !(message.size == HELLO_LENGTH + 1 && (message[66].toInt() and 0xFC) == 0)
        ) {
            return null
        }
        if ((message[0].toInt() and 0xFF) != MSG_HELLO || (message[1].toInt() and 0xFF) != VERSION) {
            return null
        }
        return message.copyOfRange(2, 34) to message.copyOfRange(34, 66)
    }

    fun encodeChallenge(pE: ByteArray, known: Boolean): ByteArray {
        require(pE.size == 32) { "The challenge key has the wrong size." }
        val output = ByteArray(CHALLENGE_LENGTH)
        output[0] = MSG_CHALLENGE.toByte()
        pE.copyInto(output, 1)
        output[33] = if (known) 1 else 0
        return output
    }

    /** Parse CHALLENGE. The source device can also send a non-zero RESULT. */
    fun decodeChallenge(message: ByteArray): ChallengeOrResult? {
        val first = message.firstOrNull()?.toInt()?.and(0xFF)
        if (first == MSG_RESULT) {
            val result = decodeResult(message)
            return when (result) {
                is ResultMessage.Status -> ChallengeOrResult.Status(result.status)
                is ResultMessage.Ok -> null
                null -> null
            }
        }
        if (message.size != CHALLENGE_LENGTH || (message[0].toInt() and 0xFF) != MSG_CHALLENGE) {
            return null
        }
        val known = message[33].toInt() and 0xFF
        if (known > 1) return null
        return ChallengeOrResult.Challenge(message.copyOfRange(1, 33), known == 1)
    }

    fun encodeReveal(lE: ByteArray, proof: ByteArray): ByteArray {
        require(lE.size == 32 && proof.size == 32) { "The REVEAL values have the wrong size." }
        val output = ByteArray(REVEAL_LENGTH)
        output[0] = MSG_REVEAL.toByte()
        lE.copyInto(output, 1)
        proof.copyInto(output, 33)
        return output
    }

    /** Parse REVEAL. Return (L_e, proof), or null for a bad shape. */
    fun decodeReveal(message: ByteArray): Pair<ByteArray, ByteArray>? {
        if (message.size != REVEAL_LENGTH || (message[0].toInt() and 0xFF) != MSG_REVEAL) {
            return null
        }
        return message.copyOfRange(1, 33) to message.copyOfRange(33, 65)
    }

    fun encodeResultOk(nonce: ByteArray, ciphertext: ByteArray): ByteArray {
        require(nonce.size == 12) { "The nonce has the wrong size." }
        val output = ByteArray(2 + nonce.size + ciphertext.size)
        output[0] = MSG_RESULT.toByte()
        output[1] = PairingStatus.OK.wire.toByte()
        nonce.copyInto(output, 2)
        ciphertext.copyInto(output, 14)
        return output
    }

    fun encodeResultStatus(status: PairingStatus): ByteArray =
        byteArrayOf(MSG_RESULT.toByte(), status.wire.toByte())

    /** Parse RESULT. Return null for a bad shape. */
    fun decodeResult(message: ByteArray): ResultMessage? {
        if (message.size < 2 || (message[0].toInt() and 0xFF) != MSG_RESULT) return null
        val status = PairingStatus.fromWire(message[1].toInt() and 0xFF) ?: return null
        if (status != PairingStatus.OK) {
            if (message.size != 2) return null
            return ResultMessage.Status(status)
        }
        if (message.size < 2 + 12 + 16 + 12) return null
        return ResultMessage.Ok(
            nonce = message.copyOfRange(2, 14),
            ciphertext = message.copyOfRange(14, message.size),
        )
    }

    /** STATUS plaintext: challenge[16] || sequence[4] || flags || connections || port || host. */
    fun encodeStatus(status: ProxyStatus, challenge: ByteArray): ByteArray {
        if (challenge.size != 16) throw PairingException(PairingError.CONFIGURATION)
        if (status.port < 1024 || status.port > 65535 || status.port == PAIRING_PORT) {
            throw PairingException(PairingError.CONFIGURATION)
        }
        if (status.host.isAnyLocalAddress || status.host.isMulticastAddress) {
            throw PairingException(PairingError.CONFIGURATION)
        }
        val host = status.host.hostAddress?.toByteArray(Charsets.US_ASCII)
            ?: throw PairingException(PairingError.CONFIGURATION)
        if (host.isEmpty() || host.size > 21) throw PairingException(PairingError.CONFIGURATION)
        if (status.connections !in 0..65535) throw PairingException(PairingError.CONFIGURATION)
        val output = ByteArray(27 + host.size)
        challenge.copyInto(output, 0)
        output[16] = ((status.sequence ushr 24) and 0xFF).toByte()
        output[17] = ((status.sequence ushr 16) and 0xFF).toByte()
        output[18] = ((status.sequence ushr 8) and 0xFF).toByte()
        output[19] = (status.sequence and 0xFF).toByte()
        output[20] = if (status.proxyRunning) 1 else 0
        output[21] = if (status.foreground) 1 else 0
        output[22] = ((status.connections ushr 8) and 0xFF).toByte()
        output[23] = (status.connections and 0xFF).toByte()
        output[24] = ((status.port ushr 8) and 0xFF).toByte()
        output[25] = (status.port and 0xFF).toByte()
        output[26] = host.size.toByte()
        host.copyInto(output, 27)
        return output
    }

    /** Prefix the payload with its u16 big-endian length. */
    fun frame(payload: ByteArray): ByteArray {
        if (payload.isEmpty() || payload.size > MAX_FRAME) {
            throw PairingException(PairingError.PROTOCOL)
        }
        val output = ByteArray(2 + payload.size)
        output[0] = ((payload.size ushr 8) and 0xFF).toByte()
        output[1] = (payload.size and 0xFF).toByte()
        payload.copyInto(output, 2)
        return output
    }

    private val HEX = "0123456789abcdef".toCharArray()
}

/**
 * A bounded frame reader for one connection. It rejects an empty frame and a
 * payload above [PairingProtocol.MAX_FRAME]. The caller must drain complete
 * frames before it pushes again.
 */
internal class PairingFrameReader {
    private var buffer = ByteArray(0)

    fun push(bytes: ByteArray) {
        if (bytes.size > PairingProtocol.MAX_BUFFERED - buffer.size) {
            throw PairingException(PairingError.FRAME_TOO_LARGE)
        }
        val next = ByteArray(buffer.size + bytes.size)
        buffer.copyInto(next, 0)
        bytes.copyInto(next, buffer.size)
        buffer = next
    }

    /** Return the next payload, or null when more bytes are needed. */
    fun nextFrame(): ByteArray? {
        if (buffer.size < 2) return null
        val length = ((buffer[0].toInt() and 0xFF) shl 8) or (buffer[1].toInt() and 0xFF)
        if (length == 0 || length > PairingProtocol.MAX_FRAME) {
            throw PairingException(PairingError.PROTOCOL)
        }
        if (buffer.size < 2 + length) return null
        val payload = buffer.copyOfRange(2, 2 + length)
        buffer = buffer.copyOfRange(2 + length, buffer.size)
        return payload
    }

    fun bufferedLength(): Int = buffer.size
}
