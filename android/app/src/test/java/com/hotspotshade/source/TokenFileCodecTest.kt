package com.hotspotshade.source

import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.security.KeyStoreException
import java.security.ProviderException
import javax.crypto.AEADBadTagException
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests for the real token file codec with plain AES keys.
 *
 * The Android Keystore is not available on the JVM. The codec takes separate
 * creating and lookup-only key seams, so these tests run the real header, IV,
 * and authentication checks and can prove which seam each path uses. They open
 * no file in the app's private storage and touch no device.
 */
class TokenFileCodecTest {
    @Test
    fun roundTripPreservesTheToken() {
        val codec = codec()
        assertEquals("paired-token", codec.decode(codec.encode("paired-token")))
    }

    @Test
    fun aFlippedTagByteIsVerifiedCorruption() {
        val codec = codec()
        val bytes = codec.encode("paired-token")
        bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 0x01).toByte()

        val failure = assertThrows(TokenReadException::class.java) { codec.decode(bytes) }
        assertEquals(TokenReadKind.CORRUPT, failure.kind)
    }

    @Test
    fun aWrongPresentKeyIsIndistinguishableFromCorruption() {
        val oldKey = newKey()
        val presentKey = newKey()
        val ciphertext = codec(oldKey).encode("paired-token")

        val failure = assertThrows(TokenReadException::class.java) {
            codec(presentKey).decode(ciphertext)
        }

        assertEquals(
            "A wrong present key produces the same authentication failure as a damaged tag.",
            TokenReadKind.CORRUPT,
            failure.kind,
        )
    }

    @Test
    fun aFlippedCiphertextByteIsVerifiedCorruption() {
        val codec = codec()
        val bytes = codec.encode("paired-token")
        // The first ciphertext byte follows the two header bytes and the IV.
        val index = 2 + (bytes[1].toInt() and 0xFF)
        bytes[index] = (bytes[index].toInt() xor 0x80).toByte()

        val failure = assertThrows(TokenReadException::class.java) { codec.decode(bytes) }
        assertEquals(TokenReadKind.CORRUPT, failure.kind)
    }

    @Test
    fun anInvalidContainerIsCorrupt() {
        val codec = codec()

        val short = assertThrows(TokenReadException::class.java) {
            codec.decode(byteArrayOf(1, 12))
        }
        assertEquals(TokenReadKind.CORRUPT, short.kind)

        val unknownVersion = assertThrows(TokenReadException::class.java) {
            codec.decode(byteArrayOf(9, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        }
        assertEquals(TokenReadKind.CORRUPT, unknownVersion.kind)

        val shortIv = assertThrows(TokenReadException::class.java) {
            codec.decode(codec.encode("paired-token").also { it[1] = 2 })
        }
        assertEquals(TokenReadKind.CORRUPT, shortIv.kind)

        val longIv = assertThrows(TokenReadException::class.java) {
            codec.decode(codec.encode("paired-token").also { it[1] = 33 })
        }
        assertEquals(TokenReadKind.CORRUPT, longIv.kind)
    }

    @Test
    fun ciphertextShorterThanGcmTagIsCorruptWithoutAccessingKey() {
        val codec = KeystoreTokenFileCodec(
            encryptionKey = { throw AssertionError("decode must not create a key") },
            decryptionKey = { throw AssertionError("key must not be read") },
        )
        for (length in 0 until 16) {
            val bytes = byteArrayOf(1, 12) + ByteArray(12 + length)
            assertEquals(TokenReadKind.CORRUPT,
                assertThrows(TokenReadException::class.java) { codec.decode(bytes) }.kind)
        }
    }

    @Test
    fun anAuthenticatedEmptyTokenIsCorrupt() {
        val codec = codec()
        val failure = assertThrows(TokenReadException::class.java) {
            codec.decode(codec.encode(""))
        }
        assertEquals(TokenReadKind.CORRUPT, failure.kind)
    }

    @Test
    fun decodeUsesTheLookupKeyAndNeverTheCreatingKey() {
        val key = newKey()
        val bytes = codec(key).encode("paired-token")
        var createCalls = 0
        val reader = KeystoreTokenFileCodec(
            encryptionKey = {
                createCalls += 1
                throw AssertionError("Decode must not use the creating key.")
            },
            decryptionKey = { key },
            cipherFactory = { Cipher.getInstance("AES/GCM/NoPadding") },
        )

        assertEquals("paired-token", reader.decode(bytes))
        assertEquals("Decode must not touch the creating key.", 0, createCalls)
    }

    @Test
    fun aMissingKeyIsTransientAndNeverCreatesOne() {
        val bytes = codec().encode("paired-token")
        var createCalls = 0
        val reader = KeystoreTokenFileCodec(
            encryptionKey = {
                createCalls += 1
                newKey()
            },
            decryptionKey = { throw KeyStoreException("The source token key is not available.") },
            cipherFactory = { Cipher.getInstance("AES/GCM/NoPadding") },
        )

        val failure = assertThrows(TokenReadException::class.java) { reader.decode(bytes) }

        assertEquals(TokenReadKind.TRANSIENT, failure.kind)
        assertEquals("A missing key must not create one.", 0, createCalls)
    }

    @Test
    fun aFailedKeyIsTransientNotCorrupt() {
        val codec = KeystoreTokenFileCodec(
            encryptionKey = { throw AssertionError("decode must not create a key") },
            decryptionKey = { throw KeyStoreException("The key is not available.") },
            cipherFactory = { Cipher.getInstance("AES/GCM/NoPadding") },
        )
        val bytes = codec().encode("paired-token")

        val failure = assertThrows(TokenReadException::class.java) { codec.decode(bytes) }
        assertEquals(TokenReadKind.TRANSIENT, failure.kind)
    }

    @Test
    fun aProviderInitFailureIsTransientNotCorrupt() {
        val codec = KeystoreTokenFileCodec(
            encryptionKey = { throw AssertionError("decode must not create a key") },
            decryptionKey = { newKey() },
            // A CBC cipher rejects the GCM parameter, as a provider that does
            // not support the requested parameters would.
            cipherFactory = { Cipher.getInstance("AES/CBC/PKCS5Padding") },
        )
        val bytes = codec().encode("paired-token")

        val failure = assertThrows(TokenReadException::class.java) { codec.decode(bytes) }
        assertEquals(TokenReadKind.TRANSIENT, failure.kind)
    }

    @Test
    fun onlyAnAuthenticationFailureIsCorrupt() {
        assertEquals(
            TokenReadKind.CORRUPT,
            tokenDecodeFailureKind(AEADBadTagException("The tag did not verify.")),
        )
        assertEquals(
            TokenReadKind.CORRUPT,
            tokenDecodeFailureKind(BadPaddingException("The padding did not verify.")),
        )
        assertEquals(
            TokenReadKind.TRANSIENT,
            tokenDecodeFailureKind(IllegalBlockSizeException("The provider failed.")),
        )
        assertEquals(
            TokenReadKind.TRANSIENT,
            tokenDecodeFailureKind(ProviderException("The provider failed.")),
        )
        assertEquals(
            TokenReadKind.TRANSIENT,
            tokenDecodeFailureKind(IOException("The read failed.")),
        )
    }

    @Test
    fun aKeystoreFailureNeverMakesTheLegacyCopyTheWinner() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            val writer = codec()
            target.writeBytes(writer.encode("target-token"))
            legacy.writeBytes(writer.encode("legacy-token"))

            val failing = KeystoreTokenFileCodec(
                encryptionKey = { throw AssertionError("A load must not create a key.") },
                decryptionKey = { throw KeyStoreException("The key is not available.") },
                cipherFactory = { Cipher.getInstance("AES/GCM/NoPadding") },
            )
            val store = AndroidKeystoreTokenStore(target, legacy, failing)

            val failure = assertThrows(TokenReadException::class.java) { store.load() }
            assertEquals(TokenReadKind.TRANSIENT, failure.kind)
            assertEquals(
                "A transient target failure must not switch to the legacy token.",
                target,
                store.activeFile(),
            )
            assertTrue("The legacy copy is not removed.", legacy.isFile)
            assertEquals(
                "The target file is unchanged.",
                "target-token",
                writer.decode(target.readBytes()),
            )
        }
    }

    @Test
    fun aMissingKeyDoesNotMoveALegacyCopyIntoTheTarget() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(legacy.parentFile).mkdirs()
            val writer = codec()
            legacy.writeBytes(writer.encode("legacy-token"))
            val missing = KeystoreTokenFileCodec(
                encryptionKey = { throw AssertionError("A load must not create a key.") },
                decryptionKey = { throw KeyStoreException("The source token key is not available.") },
                cipherFactory = { Cipher.getInstance("AES/GCM/NoPadding") },
            )
            val store = AndroidKeystoreTokenStore(target, legacy, missing)

            val failure = assertThrows(TokenReadException::class.java) { store.load() }

            assertEquals(TokenReadKind.TRANSIENT, failure.kind)
            assertEquals(
                "The unreadable legacy file stays the active file.",
                legacy,
                store.activeFile(),
            )
            assertFalse("A missing key must not create the target.", target.exists())
            assertFalse(
                "A missing key must not record a supersession marker.",
                legacyMarkerFileFor(target).exists(),
            )
            assertEquals("legacy-token", writer.decode(legacy.readBytes()))
        }
    }

    @Test
    fun aMissingKeyOnSaveDoesNotCreateAKeyOrReplaceTheTarget() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            val writer = codec()
            target.writeBytes(writer.encode("target-token"))
            var createCalls = 0
            val missing = KeystoreTokenFileCodec(
                encryptionKey = {
                    createCalls += 1
                    throw AssertionError("A refused save must not create a key.")
                },
                decryptionKey = { throw KeyStoreException("The source token key is not available.") },
                cipherFactory = { Cipher.getInstance("AES/GCM/NoPadding") },
            )
            val store = AndroidKeystoreTokenStore(target, codec = missing)

            assertThrows(IOException::class.java) { store.save("new-token") }

            assertEquals("The save must not create a key.", 0, createCalls)
            assertEquals("target-token", writer.decode(target.readBytes()))
        }
    }

    @Test
    fun aMissingKeyOnSaveKeepsTheOnlyLegacyCiphertext() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(legacy.parentFile).mkdirs()
            val writer = codec()
            val original = writer.encode("legacy-token")
            legacy.writeBytes(original)
            var generated: SecretKey? = null
            val missing = KeystoreTokenFileCodec(
                encryptionKey = { newKey().also { generated = it } },
                decryptionKey = { generated ?: throw KeyStoreException("missing key") },
                cipherFactory = { Cipher.getInstance("AES/GCM/NoPadding") },
            )
            val store = AndroidKeystoreTokenStore(target, legacy, missing)

            assertThrows(IOException::class.java) { store.save("new-token") }

            assertEquals(null, generated)
            assertFalse(target.exists())
            assertFalse(legacyMarkerFileFor(target).exists())
            assertTrue(original.contentEquals(legacy.readBytes()))
        }
    }

    @Test
    fun aSaveToAnAbsentTargetUsesTheCreatingKeyThenTheLookupKey() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val key = newKey()
            var createCalls = 0
            var lookupCalls = 0
            val codec = KeystoreTokenFileCodec(
                encryptionKey = {
                    createCalls += 1
                    key
                },
                decryptionKey = {
                    lookupCalls += 1
                    key
                },
                cipherFactory = { Cipher.getInstance("AES/GCM/NoPadding") },
            )

            AndroidKeystoreTokenStore(target, codec = codec).save("paired-token")

            assertEquals("A new target uses the creating key once.", 1, createCalls)
            assertEquals("The save verifies the target with the lookup key.", 1, lookupCalls)
            assertEquals("paired-token", codec.decode(target.readBytes()))
        }
    }

    @Test
    fun aVerifiedCorruptTargetFallsBackToAReadableLegacyCopy() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            val codec = codec()
            val corrupted = codec.encode("target-token")
            corrupted[corrupted.size - 1] = (corrupted[corrupted.size - 1].toInt() xor 0x01).toByte()
            target.writeBytes(corrupted)
            legacy.writeBytes(codec.encode("legacy-token"))

            val store = AndroidKeystoreTokenStore(target, legacy, codec)

            assertEquals("legacy-token", store.load())
            assertEquals(legacy, store.activeFile())
            assertTrue("The corrupt target stays for inspection.", target.isFile)
        }
    }

    private fun codec(key: SecretKey = newKey()): KeystoreTokenFileCodec =
        KeystoreTokenFileCodec(
            encryptionKey = { key },
            decryptionKey = { key },
            cipherFactory = { Cipher.getInstance("AES/GCM/NoPadding") },
        )

    private fun newKey(): SecretKey {
        val generator = KeyGenerator.getInstance("AES")
        generator.init(256)
        return generator.generateKey()
    }

    private fun withDirectory(block: (File) -> Unit) {
        val directory = Files.createTempDirectory("hotspotshade-codec-test").toFile()
        try {
            block(directory)
        } finally {
            directory.deleteRecursively()
        }
    }
}
