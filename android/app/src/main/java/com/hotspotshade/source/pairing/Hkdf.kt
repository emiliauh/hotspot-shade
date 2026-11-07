package com.hotspotshade.source.pairing

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * HKDF with HMAC-SHA256 (RFC 5869).
 *
 * The pairing key schedule uses HKDF-Extract with the transcript hash as the
 * salt and `ee || es` as the input key material. The class uses the platform
 * HMAC. HMAC-SHA256 is available at Android API 26.
 */
internal object Hkdf {
    private const val ALGORITHM = "HmacSHA256"
    private const val HASH_BYTES = 32

    /** HMAC-SHA256. */
    fun hmac(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance(ALGORITHM)
        mac.init(SecretKeySpec(key, ALGORITHM))
        return mac.doFinal(data)
    }

    /**
     * HKDF-Extract: return HMAC(salt, input).
     *
     * RFC 5869 uses a string of 32 zero bytes when the salt is empty. An
     * empty HMAC key is not portable: some providers reject it. This method
     * substitutes the zero salt, so the result matches the RFC.
     */
    fun extract(salt: ByteArray, input: ByteArray): ByteArray {
        if (salt.isNotEmpty()) return hmac(salt, input)
        val zeroSalt = ByteArray(HASH_BYTES)
        return try {
            hmac(zeroSalt, input)
        } finally {
            zeroSalt.fill(0)
        }
    }

    /**
     * HKDF-Expand. The output length must be 1 to 255 times 32 bytes.
     */
    fun expand(pseudoRandomKey: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length > 0 && length <= 255 * HASH_BYTES) {
            "The HKDF output length is out of range."
        }
        val output = ByteArray(length)
        var previous = ByteArray(0)
        var offset = 0
        var counter = 1
        while (offset < length) {
            val mac = Mac.getInstance(ALGORITHM)
            mac.init(SecretKeySpec(pseudoRandomKey, ALGORITHM))
            mac.update(previous)
            mac.update(info)
            mac.update(counter.toByte())
            val block = mac.doFinal()
            previous.fill(0)
            previous = block
            val count = minOf(block.size, length - offset)
            block.copyInto(output, offset, 0, count)
            offset += count
            counter += 1
        }
        previous.fill(0)
        return output
    }
}
