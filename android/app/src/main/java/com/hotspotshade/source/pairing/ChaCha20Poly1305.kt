package com.hotspotshade.source.pairing

/**
 * ChaCha20-Poly1305 authenticated encryption (RFC 8439).
 *
 * This is a Kotlin port of the RFC 8439 reference functions. It returns
 * ciphertext followed by the 16-byte tag, the same layout as the Rust
 * `chacha20poly1305` crate and the Swift `ChaChaPoly` box. It needs no
 * platform crypto provider, because Android API 26 has no ChaCha20-Poly1305
 * cipher.
 *
 * Every pairing message uses a fresh nonce from the injected identity. The
 * caller must not reuse a nonce under one key.
 */
internal object ChaCha20Poly1305 {
    const val KEY_BYTES = 32
    const val NONCE_BYTES = 12
    const val TAG_BYTES = 16

    /**
     * Encrypt [plaintext] with [key] and [nonce]. Return ciphertext followed
     * by the tag. [aad] is authenticated but not encrypted.
     */
    fun seal(
        key: ByteArray,
        nonce: ByteArray,
        plaintext: ByteArray,
        aad: ByteArray,
    ): ByteArray? {
        if (key.size != KEY_BYTES || nonce.size != NONCE_BYTES) return null
        val ciphertext = ByteArray(plaintext.size)
        val first = chacha20Block(key, 0, nonce)
        val polyKey = first.copyOf(32)
        first.fill(0)
        var counter = 1
        var offset = 0
        while (offset < plaintext.size) {
            val current = chacha20Block(key, counter, nonce)
            val count = minOf(64, plaintext.size - offset)
            for (index in 0 until count) {
                ciphertext[offset + index] = (plaintext[offset + index].toInt() xor
                    current[index].toInt()).toByte()
            }
            current.fill(0)
            counter += 1
            offset += count
        }
        val macInput = macInput(aad, ciphertext)
        val tag = poly1305(polyKey, macInput)
        polyKey.fill(0)
        macInput.fill(0)
        return ciphertext + tag
    }

    /**
     * Verify and decrypt [sealed] (ciphertext followed by the tag). Return the
     * plaintext, or null when the tag does not match or a size is wrong.
     */
    fun open(
        key: ByteArray,
        nonce: ByteArray,
        sealed: ByteArray,
        aad: ByteArray,
    ): ByteArray? {
        if (key.size != KEY_BYTES || nonce.size != NONCE_BYTES) return null
        if (sealed.size < TAG_BYTES) return null
        val ciphertext = sealed.copyOfRange(0, sealed.size - TAG_BYTES)
        val tag = sealed.copyOfRange(sealed.size - TAG_BYTES, sealed.size)
        val first = chacha20Block(key, 0, nonce)
        val polyKey = first.copyOf(32)
        first.fill(0)
        val macInput = macInput(aad, ciphertext)
        val expected = poly1305(polyKey, macInput)
        polyKey.fill(0)
        macInput.fill(0)
        if (!constantTimeEquals(expected, tag)) {
            expected.fill(0)
            ciphertext.fill(0)
            return null
        }
        val plaintext = ByteArray(ciphertext.size)
        var counter = 1
        var offset = 0
        while (offset < ciphertext.size) {
            val current = chacha20Block(key, counter, nonce)
            val count = minOf(64, ciphertext.size - offset)
            for (index in 0 until count) {
                plaintext[offset + index] = (ciphertext[offset + index].toInt() xor
                    current[index].toInt()).toByte()
            }
            current.fill(0)
            counter += 1
            offset += count
        }
        expected.fill(0)
        ciphertext.fill(0)
        tag.fill(0)
        return plaintext
    }

    /** The RFC 8439 ChaCha20 block function for one 64-byte block. */
    internal fun blockForTest(key: ByteArray, counter: Int, nonce: ByteArray): ByteArray =
        chacha20Block(key, counter, nonce)

    private fun chacha20Block(key: ByteArray, counter: Int, nonce: ByteArray): ByteArray {
        val state = IntArray(16)
        state[0] = 0x61707865
        state[1] = 0x3320646E
        state[2] = 0x79622D32
        state[3] = 0x6B206574
        for (index in 0 until 8) state[4 + index] = load32(key, index * 4)
        state[12] = counter
        for (index in 0 until 3) state[13 + index] = load32(nonce, index * 4)
        val working = state.copyOf()
        repeat(10) {
            quarterRound(working, 0, 4, 8, 12)
            quarterRound(working, 1, 5, 9, 13)
            quarterRound(working, 2, 6, 10, 14)
            quarterRound(working, 3, 7, 11, 15)
            quarterRound(working, 0, 5, 10, 15)
            quarterRound(working, 1, 6, 11, 12)
            quarterRound(working, 2, 7, 8, 13)
            quarterRound(working, 3, 4, 9, 14)
        }
        val output = ByteArray(64)
        for (index in 0 until 16) {
            store32(output, index * 4, working[index] + state[index])
        }
        working.fill(0)
        state.fill(0)
        return output
    }

    private fun quarterRound(state: IntArray, a: Int, b: Int, c: Int, d: Int) {
        state[a] += state[b]
        state[d] = Integer.rotateLeft(state[d] xor state[a], 16)
        state[c] += state[d]
        state[b] = Integer.rotateLeft(state[b] xor state[c], 12)
        state[a] += state[b]
        state[d] = Integer.rotateLeft(state[d] xor state[a], 8)
        state[c] += state[d]
        state[b] = Integer.rotateLeft(state[b] xor state[c], 7)
    }

    /**
     * The Poly1305 one-time authenticator from poly1305-donna for 32-bit
     * limbs. The 26-bit limbs and the 64-bit products keep every product below
     * 2^63.
     */
    /** The raw Poly1305 tag. A test uses it with the RFC 8439 vector. */
    internal fun poly1305ForTest(key: ByteArray, message: ByteArray): ByteArray =
        poly1305(key, message)

    private fun poly1305(key: ByteArray, message: ByteArray): ByteArray {
        val r0 = unsigned(load32(key, 0)) and 0x3FFFFFF
        val r1 = (unsigned(load32(key, 3)) shr 2) and 0x3FFFF03
        val r2 = (unsigned(load32(key, 6)) shr 4) and 0x3FFC0FF
        val r3 = (unsigned(load32(key, 9)) shr 6) and 0x3F03FFF
        val r4 = (unsigned(load32(key, 12)) shr 8) and 0x00FFFFF
        val s1 = r1 * 5
        val s2 = r2 * 5
        val s3 = r3 * 5
        val s4 = r4 * 5
        var h0 = 0L
        var h1 = 0L
        var h2 = 0L
        var h3 = 0L
        var h4 = 0L
        val mask = 0x3FFFFFFL
        var offset = 0
        while (offset < message.size) {
            val count = minOf(16, message.size - offset)
            val block = ByteArray(16)
            message.copyInto(block, 0, offset, offset + count)
            val full = count == 16
            if (!full) block[count] = 1
            h0 += unsigned(load32(block, 0)) and mask
            h1 += (unsigned(load32(block, 3)) shr 2) and mask
            h2 += (unsigned(load32(block, 6)) shr 4) and mask
            h3 += (unsigned(load32(block, 9)) shr 6) and mask
            h4 += ((unsigned(load32(block, 12)) shr 8) and mask) or
                (if (full) 1L shl 24 else 0L)
            block.fill(0)

            val d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1
            val d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2
            val d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3
            val d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4
            val d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0

            var carry = d0 shr 26
            h0 = d0 and mask
            var value = d1 + carry
            carry = value shr 26
            h1 = value and mask
            value = d2 + carry
            carry = value shr 26
            h2 = value and mask
            value = d3 + carry
            carry = value shr 26
            h3 = value and mask
            value = d4 + carry
            carry = value shr 26
            h4 = value and mask
            h0 += carry * 5
            carry = h0 shr 26
            h0 = h0 and mask
            h1 += carry
            offset += count
        }

        var carry = h1 shr 26
        h1 = h1 and mask
        h2 += carry
        carry = h2 shr 26
        h2 = h2 and mask
        h3 += carry
        carry = h3 shr 26
        h3 = h3 and mask
        h4 += carry
        carry = h4 shr 26
        h4 = h4 and mask
        h0 += carry * 5
        carry = h0 shr 26
        h0 = h0 and mask
        h1 += carry

        var g0 = h0 + 5
        carry = g0 shr 26
        g0 = g0 and mask
        var g1 = h1 + carry
        carry = g1 shr 26
        g1 = g1 and mask
        var g2 = h2 + carry
        carry = g2 shr 26
        g2 = g2 and mask
        var g3 = h3 + carry
        carry = g3 shr 26
        g3 = g3 and mask
        var g4 = h4 + carry - (1L shl 26)
        val keep = g4 shr 63
        g0 = g0 and keep.inv()
        g1 = g1 and keep.inv()
        g2 = g2 and keep.inv()
        g3 = g3 and keep.inv()
        g4 = g4 and keep.inv()
        h0 = (h0 and keep) or g0
        h1 = (h1 and keep) or g1
        h2 = (h2 and keep) or g2
        h3 = (h3 and keep) or g3
        h4 = (h4 and keep) or g4

        val low0 = (h0 or (h1 shl 26)) and 0xFFFFFFFFL
        val low1 = ((h1 shr 6) or (h2 shl 20)) and 0xFFFFFFFFL
        val low2 = ((h2 shr 12) or (h3 shl 14)) and 0xFFFFFFFFL
        val low3 = ((h3 shr 18) or (h4 shl 8)) and 0xFFFFFFFFL

        var value = low0 + (load32(key, 16).toLong() and 0xFFFFFFFFL)
        val word0 = value and 0xFFFFFFFFL
        value = (value shr 32) + low1 + (load32(key, 20).toLong() and 0xFFFFFFFFL)
        val word1 = value and 0xFFFFFFFFL
        value = (value shr 32) + low2 + (load32(key, 24).toLong() and 0xFFFFFFFFL)
        val word2 = value and 0xFFFFFFFFL
        value = (value shr 32) + low3 + (load32(key, 28).toLong() and 0xFFFFFFFFL)
        val word3 = value and 0xFFFFFFFFL
        val tag = ByteArray(TAG_BYTES)
        store32(tag, 0, word0.toInt())
        store32(tag, 4, word1.toInt())
        store32(tag, 8, word2.toInt())
        store32(tag, 12, word3.toInt())
        return tag
    }

    private fun macInput(aad: ByteArray, ciphertext: ByteArray): ByteArray {
        val aadPad = (16 - (aad.size % 16)) % 16
        val cipherPad = (16 - (ciphertext.size % 16)) % 16
        val output = ByteArray(aad.size + aadPad + ciphertext.size + cipherPad + 16)
        var offset = 0
        aad.copyInto(output, offset)
        offset += aad.size + aadPad
        ciphertext.copyInto(output, offset)
        offset += ciphertext.size + cipherPad
        store64(output, offset, aad.size.toLong())
        store64(output, offset + 8, ciphertext.size.toLong())
        return output
    }

    private fun constantTimeEquals(left: ByteArray, right: ByteArray): Boolean {
        if (left.size != right.size) return false
        var difference = 0
        for (index in left.indices) {
            difference = difference or (left[index].toInt() xor right[index].toInt())
        }
        return difference == 0
    }

    private fun unsigned(value: Int): Long = value.toLong() and 0xFFFFFFFFL

    private fun load32(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xFF) or
            ((bytes[offset + 1].toInt() and 0xFF) shl 8) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 3].toInt() and 0xFF) shl 24)

    private fun store32(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = (value and 0xFF).toByte()
        bytes[offset + 1] = ((value ushr 8) and 0xFF).toByte()
        bytes[offset + 2] = ((value ushr 16) and 0xFF).toByte()
        bytes[offset + 3] = ((value ushr 24) and 0xFF).toByte()
    }

    private fun store64(bytes: ByteArray, offset: Int, value: Long) {
        for (index in 0 until 8) {
            bytes[offset + index] = ((value ushr (8 * index)) and 0xFF).toByte()
        }
    }
}
