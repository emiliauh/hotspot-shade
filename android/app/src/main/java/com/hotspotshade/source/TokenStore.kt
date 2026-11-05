package com.hotspotshade.source

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.io.FileOutputStream
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Provide the source device token to the source proxy.
 *
 * A JVM test uses an in-memory fake. The service never writes the token to a
 * log, a status message, or an error text.
 */
internal fun interface TokenStore {
    /** Return the stored token, or null when this device has no token. */
    fun load(): String?
}

/**
 * Save the source token after a successful pairing.
 *
 * The pairing listener uses this interface. A JVM test supplies a fake. The
 * token never goes to a log, a status message, or an error text.
 */
internal fun interface TokenWriter {
    /** Save one token. */
    fun save(token: String)
}

/**
 * Store the token in one app-private file with an Android Keystore AES key.
 *
 * TODO: Replace this class with EncryptedSharedPreferences when the project
 * approves the androidx.security.crypto dependency. This class has the same
 * security boundary: the ciphertext is in app-private storage and the key
 * stays in the Android Keystore.
 *
 * The file holds one version byte, one IV length byte, the IV, and the
 * ciphertext. A failed read returns null. This class does not log.
 */
internal class AndroidKeystoreTokenStore(private val file: File) : TokenStore, TokenWriter {
    override fun load(): String? {
        val bytes = try {
            file.readBytes()
        } catch (_: Exception) {
            return null
        }
        if (bytes.size < 3) return null
        if ((bytes[0].toInt() and 0xFF) != VERSION) return null
        val ivLength = bytes[1].toInt() and 0xFF
        if (ivLength < MINIMUM_IV_LENGTH || bytes.size <= 2 + ivLength) return null
        val iv = bytes.copyOfRange(2, 2 + ivLength)
        val ciphertext = bytes.copyOfRange(2 + ivLength, bytes.size)
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(TAG_BITS, iv))
            val plain = cipher.doFinal(ciphertext)
            val token = plain.toString(Charsets.UTF_8)
            plain.fill(0)
            if (token.isEmpty()) null else token
        } catch (_: Exception) {
            null
        }
    }

    /** Save one token. Call this method after a pairing approval. */
    override fun save(token: String) {
        require(token.isNotEmpty()) { "The source token must not be empty." }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val plain = token.toByteArray(Charsets.UTF_8)
        val ciphertext = try {
            cipher.doFinal(plain)
        } finally {
            plain.fill(0)
        }
        val iv = cipher.iv
        require(iv.size in MINIMUM_IV_LENGTH..MAXIMUM_IV_LENGTH) {
            "The cipher IV is out of range."
        }
        FileOutputStream(file).use { output ->
            output.write(VERSION)
            output.write(iv.size)
            output.write(iv)
            output.write(ciphertext)
            output.flush()
            output.fd.sync()
        }
    }

    /** Remove the stored token. */
    fun clear() {
        file.delete()
    }

    private fun key(): SecretKey {
        val store = KeyStore.getInstance(ANDROID_KEYSTORE)
        store.load(null)
        val existing = store.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry
        if (existing != null) return existing.secretKey
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return generator.generateKey()
    }

    private companion object {
        const val VERSION = 1
        const val KEY_ALIAS = "hotspotshade-source-token"
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val TAG_BITS = 128
        const val MINIMUM_IV_LENGTH = 12
        const val MAXIMUM_IV_LENGTH = 32
    }
}
