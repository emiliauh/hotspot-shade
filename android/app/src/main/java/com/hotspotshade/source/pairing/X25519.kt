package com.hotspotshade.source.pairing

/**
 * X25519 key agreement (RFC 7748).
 *
 * This is a Kotlin port of the public-domain TweetNaCl `crypto_scalarmult`
 * routine. The field arithmetic uses 16 limbs of 16 bits in signed 64-bit
 * values. The conditional swap uses a mask and has no branch on the scalar
 * bit. The implementation performs one scalar multiplication in a few
 * milliseconds on a phone. It needs no platform crypto provider, because
 * Android API 26 has no X25519 key agreement.
 *
 * The class handles one pairing handshake at a time. It holds no state.
 */
internal object X25519 {
    private const val KEY_BYTES = 32
    private const val LIMBS = 16

    private val BASE_POINT = ByteArray(KEY_BYTES).also { it[0] = 9 }

    private val C_121665 = LongArray(LIMBS).also {
        it[0] = 0xDB41
        it[1] = 1
    }

    /**
     * Return the X25519 public key for [privateKey], or null when the key has
     * the wrong size.
     */
    fun publicKey(privateKey: ByteArray): ByteArray? {
        if (privateKey.size != KEY_BYTES) return null
        return scalarMult(privateKey, BASE_POINT)
    }

    /**
     * Return the shared secret, or null when a key has the wrong size or the
     * result is the all-zero value. An all-zero result means a low-order
     * point. The pairing handshake must reject it.
     */
    fun agree(privateKey: ByteArray, publicKey: ByteArray): ByteArray? {
        if (privateKey.size != KEY_BYTES || publicKey.size != KEY_BYTES) return null
        val shared = scalarMult(privateKey, publicKey) ?: return null
        if (shared.all { it == 0.toByte() }) {
            shared.fill(0)
            return null
        }
        return shared
    }

    /** The scalar multiplication from TweetNaCl. */
    private fun scalarMult(scalar: ByteArray, point: ByteArray): ByteArray? {
        if (scalar.size != KEY_BYTES || point.size != KEY_BYTES) return null
        val z = ByteArray(KEY_BYTES)
        for (index in 0 until KEY_BYTES - 1) z[index] = scalar[index]
        z[31] = (((scalar[31].toInt() and 0xFF) and 127) or 64).toByte()
        z[0] = ((scalar[0].toInt() and 0xFF) and 248).toByte()

        val x = LongArray(LIMBS)
        unpack25519(x, point)
        val a = LongArray(LIMBS)
        val b = LongArray(LIMBS)
        val c = LongArray(LIMBS)
        val d = LongArray(LIMBS)
        val e = LongArray(LIMBS)
        val f = LongArray(LIMBS)
        for (index in 0 until LIMBS) {
            b[index] = x[index]
            a[index] = 0
            c[index] = 0
            d[index] = 0
        }
        a[0] = 1
        d[0] = 1

        for (bit in 254 downTo 0) {
            val value = ((z[bit shr 3].toInt() and 0xFF) shr (bit and 7)) and 1
            select(a, b, value)
            select(c, d, value)
            add(e, a, c)
            subtract(a, a, c)
            add(c, b, d)
            subtract(b, b, d)
            square(d, e)
            square(f, a)
            multiply(a, c, a)
            multiply(c, b, e)
            add(e, a, c)
            subtract(a, a, c)
            square(b, a)
            subtract(c, d, f)
            multiply(a, c, C_121665)
            add(a, a, d)
            multiply(c, c, a)
            multiply(a, d, f)
            multiply(d, b, x)
            square(b, e)
            select(a, b, value)
            select(c, d, value)
        }

        val inverse = LongArray(LIMBS)
        invert25519(inverse, c)
        val result = LongArray(LIMBS)
        multiply(result, a, inverse)
        val output = ByteArray(KEY_BYTES)
        pack25519(output, result)
        z.fill(0)
        x.fill(0)
        a.fill(0)
        b.fill(0)
        c.fill(0)
        d.fill(0)
        e.fill(0)
        f.fill(0)
        inverse.fill(0)
        result.fill(0)
        return output
    }

    private fun car25519(value: LongArray) {
        for (index in 0 until LIMBS) {
            value[index] += 1L shl 16
            val carry = value[index] shr 16
            val target = if (index < 15) index + 1 else 0
            val add = if (index < 15) carry - 1 else 38 * (carry - 1)
            value[target] += add
            value[index] -= carry shl 16
        }
    }

    private fun select(left: LongArray, right: LongArray, bit: Int) {
        val mask = (bit.toLong() - 1L).inv()
        for (index in 0 until LIMBS) {
            val swap = mask and (left[index] xor right[index])
            left[index] = left[index] xor swap
            right[index] = right[index] xor swap
        }
    }

    private fun pack25519(output: ByteArray, input: LongArray) {
        val t = input.copyOf()
        car25519(t)
        car25519(t)
        car25519(t)
        val m = LongArray(LIMBS)
        repeat(2) {
            m[0] = t[0] - 0xFFED
            for (index in 1 until 15) {
                m[index] = t[index] - 0xFFFF - ((m[index - 1] shr 16) and 1)
                m[index - 1] = m[index - 1] and 0xFFFF
            }
            m[15] = t[15] - 0x7FFF - ((m[14] shr 16) and 1)
            val borrow = ((m[15] shr 16) and 1).toInt()
            m[14] = m[14] and 0xFFFF
            select(t, m, 1 - borrow)
        }
        for (index in 0 until LIMBS) {
            output[2 * index] = (t[index] and 0xFF).toByte()
            output[2 * index + 1] = ((t[index] shr 8) and 0xFF).toByte()
        }
        t.fill(0)
        m.fill(0)
    }

    private fun unpack25519(output: LongArray, input: ByteArray) {
        for (index in 0 until LIMBS) {
            output[index] = (input[2 * index].toLong() and 0xFF) +
                ((input[2 * index + 1].toLong() and 0xFF) shl 8)
        }
        output[15] = output[15] and 0x7FFF
    }

    private fun add(output: LongArray, left: LongArray, right: LongArray) {
        for (index in 0 until LIMBS) output[index] = left[index] + right[index]
    }

    private fun subtract(output: LongArray, left: LongArray, right: LongArray) {
        for (index in 0 until LIMBS) output[index] = left[index] - right[index]
    }

    private fun multiply(output: LongArray, left: LongArray, right: LongArray) {
        val t = LongArray(31)
        for (leftIndex in 0 until LIMBS) {
            for (rightIndex in 0 until LIMBS) {
                t[leftIndex + rightIndex] += left[leftIndex] * right[rightIndex]
            }
        }
        for (index in 0 until 15) t[index] += 38 * t[index + 16]
        for (index in 0 until LIMBS) output[index] = t[index]
        car25519(output)
        car25519(output)
        t.fill(0)
    }

    private fun square(output: LongArray, input: LongArray) {
        multiply(output, input, input)
    }

    private fun invert25519(output: LongArray, input: LongArray) {
        val c = input.copyOf()
        for (exponent in 253 downTo 0) {
            square(c, c)
            if (exponent != 2 && exponent != 4) multiply(c, c, input)
        }
        for (index in 0 until LIMBS) output[index] = c[index]
        c.fill(0)
    }
}
