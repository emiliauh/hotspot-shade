package com.hotspotshade.source

import android.content.Context
import android.content.ContextWrapper
import android.content.pm.ApplicationInfo
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.io.IOException
import java.security.KeyStore
import java.util.UUID
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Exercise `AndroidKeystoreTokenStore.forContext` with the real Android
 * Keystore.
 *
 * Each test builds an isolated Context whose filesDir, noBackupFilesDir, and
 * applicationInfo.dataDir point at a temporary app-private directory. It uses
 * a disposable Android Keystore alias for encryption. The production app token
 * file, the production key alias, the trust list, and the real app data
 * directories are not written. The fixture checks their visible state before
 * and after the test.
 *
 * The test runs on an emulator or a disposable device. It does not prove
 * physical-device Keystore hardware behavior, power-loss durability, backup
 * behavior, or a real hotspot and carrier path.
 */
@RunWith(AndroidJUnit4::class)
class AndroidKeystoreTokenStoreForContextInstrumentedTest {
    @Test
    fun forContextUsesTheNoBackupTargetAndRotatesTheToken() {
        withFixture { fixture ->
            val store = fixture.store()

            assertEquals("An empty store selects the no-backup target.", fixture.target, store.activeFile())
            assertFalse(fixture.target.exists())
            assertFalse(fixture.legacy.exists())
            assertFalse(fixture.marker.exists())

            store.save(TOKEN_A)

            assertEquals(TOKEN_A, store.load())
            assertEquals(fixture.target, store.activeFile())
            assertTrue(
                "The production target must be the no-backup file.",
                fixture.target.isFile,
            )
            assertEquals(fixture.noBackupDirectory, fixture.target.parentFile)
            assertFalse("A save with no legacy copy must not create one.", fixture.legacy.exists())
            assertFalse("A save with no legacy copy needs no marker.", fixture.marker.exists())
            assertTrue("The real Android Keystore key is used.", fixture.disposableKeyExists())
            assertEquals(TOKEN_A, fixture.decode(fixture.target))

            store.save(TOKEN_B)

            assertEquals("A rotation replaces the stored token.", TOKEN_B, store.load())
            assertEquals(TOKEN_B, fixture.decode(fixture.target))
            assertFalse(fixture.legacy.exists())
            assertFalse(fixture.marker.exists())
            assertEquals(fixture.target, store.activeFile())
        }
    }

    @Test
    fun theOneArgumentForContextSelectsTheSameIsolatedTarget() {
        withFixture { fixture ->
            val productionStore = AndroidKeystoreTokenStore.forContext(fixture.isolatedContext)

            assertNull("An empty isolated store has no token.", productionStore.load())
            assertEquals(fixture.target, productionStore.activeFile())
        }
    }

    @Test
    fun aFilesDirTokenIsMigratedToTheNoBackupTargetWithoutAMarker() {
        withFixture { fixture ->
            fixture.write(fixture.legacy, TOKEN_LEGACY)
            assertTrue(fixture.legacy.isFile)
            assertFalse(fixture.target.exists())
            assertFalse(fixture.marker.exists())

            val store = fixture.store()

            assertEquals(
                "A token written by an older build must stay readable.",
                TOKEN_LEGACY,
                store.load(),
            )

            assertEquals(fixture.target, store.activeFile())
            assertTrue("The migration writes the no-backup target.", fixture.target.isFile)
            assertFalse("The migration removes the legacy copy.", fixture.legacy.exists())
            assertFalse(
                "A first legitimate migration must not record a marker.",
                fixture.marker.exists(),
            )
            assertEquals(TOKEN_LEGACY, fixture.decode(fixture.target))
        }
    }

    @Test
    fun aSaveWithAReadableLegacyCopyRecordsTheMarkerNextToTheTarget() {
        withFixture { fixture ->
            fixture.write(fixture.target, TOKEN_TARGET)
            fixture.write(fixture.legacy, TOKEN_LEGACY)

            fixture.store().save(TOKEN_NEW)

            assertEquals(
                "The marker belongs next to the no-backup target.",
                File(fixture.noBackupDirectory, "$TOKEN_FILE_NAME.legacy-superseded"),
                fixture.marker,
            )
            assertTrue(
                "The save must leave the supersession marker present. " +
                    "Existence is not a power-loss durability proof.",
                fixture.marker.isFile,
            )
            assertEquals(LegacyMarkerState.PRESENT, LegacyTokenMarker.state(fixture.marker))
            assertFalse(
                "The marker must not be written in the files directory.",
                File(fixture.filesDirectory, fixture.marker.name).exists(),
            )
            assertEquals(TOKEN_NEW, fixture.decode(fixture.target))
            assertFalse(
                "The stale legacy copy is removed after the confirmed save.",
                fixture.legacy.exists(),
            )
            assertEquals(TOKEN_NEW, fixture.store().load())
        }
    }

    @Test
    fun aFailedSaveBeforeTheTargetWriteLeavesTheReadableLegacyUsable() {
        withFixture { fixture ->
            fixture.write(fixture.legacy, TOKEN_LEGACY)
            val failingCodec = object : TokenFileCodec {
                override fun encode(token: String): ByteArray {
                    throw IOException("injected encode failure")
                }

                override fun decode(bytes: ByteArray): String = fixture.decodeBytes(bytes)
            }
            val store = fixture.store(failingCodec)

            assertThrows(IOException::class.java) { store.save(TOKEN_NEW) }

            assertFalse(
                "A failed save must not create the target.",
                fixture.target.exists(),
            )
            assertFalse(
                "A failed save before the target write must not latch the readable copy.",
                fixture.marker.exists(),
            )
            assertEquals(
                "The readable legacy ciphertext must stay unchanged.",
                TOKEN_LEGACY,
                fixture.decode(fixture.legacy),
            )

            // The real codec must still read and migrate the kept copy.
            val recovered = fixture.store()
            assertEquals(TOKEN_LEGACY, recovered.load())
            assertEquals(TOKEN_LEGACY, fixture.decode(fixture.target))
            assertFalse("The successful migration removes the legacy copy.", fixture.legacy.exists())
        }
    }

    @Test
    fun aMarkerBlocksLegacyFallbackAndASaveStillRotatesTheTarget() {
        withFixture { fixture ->
            fixture.write(fixture.legacy, TOKEN_LEGACY)
            LegacyTokenMarker.record(fixture.marker)
            val store = fixture.store()

            assertNull(
                "A missing target with a marker must not move the legacy token.",
                store.load(),
            )
            assertFalse(fixture.target.exists())
            assertEquals(TOKEN_LEGACY, fixture.decode(fixture.legacy))

            // Keep a valid container and corrupt the GCM tag, so the real
            // Android Keystore provider verifies the target.
            fixture.write(fixture.target, TOKEN_TARGET)
            fixture.flipLastByte(fixture.target)
            val failure = assertThrows(TokenReadException::class.java) { store.load() }
            assertEquals(
                "A corrupt target with a marker must not use the stale legacy token.",
                TokenReadKind.CORRUPT,
                failure.kind,
            )
            assertEquals(fixture.target, store.activeFile())
            assertEquals(TOKEN_LEGACY, fixture.decode(fixture.legacy))

            store.save(TOKEN_NEW)

            assertEquals(
                "A recorded marker must not block a rotation of the target.",
                TOKEN_NEW,
                store.load(),
            )
            assertEquals(TOKEN_NEW, fixture.decode(fixture.target))
            assertFalse(fixture.legacy.exists())
            assertTrue("The marker is a one-way latch.", fixture.marker.isFile)
        }
    }

    @Test
    fun aMissingKeyIsTransientAndDoesNotFallBackToTheLegacyCopy() {
        withFixture { fixture ->
            fixture.write(fixture.target, TOKEN_TARGET)
            fixture.write(fixture.legacy, TOKEN_LEGACY)
            val targetBytes = fixture.target.readBytes()
            val legacyBytes = fixture.legacy.readBytes()
            try {
                fixture.deleteDisposableKey()
                val store = fixture.store()

                val failure = assertThrows(TokenReadException::class.java) { store.load() }

                assertEquals(
                    "A missing decryption key is transient, not corrupt data.",
                    TokenReadKind.TRANSIENT,
                    failure.kind,
                )
                assertEquals(fixture.target, store.activeFile())
                assertFalse(
                    "A load must not recreate the disposable key.",
                    fixture.disposableKeyExists(),
                )
                assertArrayEquals(
                    "The target bytes must stay unchanged.",
                    targetBytes,
                    fixture.target.readBytes(),
                )
                assertArrayEquals(
                    "The legacy copy must stay unchanged.",
                    legacyBytes,
                    fixture.legacy.readBytes(),
                )
                assertFalse("A load must not record a marker.", fixture.marker.exists())
            } finally {
                targetBytes.fill(0)
                legacyBytes.fill(0)
            }
        }
    }

    @Test
    fun aMissingKeyWithOnlyALegacyCopyDoesNotCreateATargetOrKey() {
        withFixture { fixture ->
            fixture.write(fixture.legacy, TOKEN_LEGACY)
            val legacyBytes = fixture.legacy.readBytes()
            try {
                fixture.deleteDisposableKey()
                val store = fixture.store()

                val failure = assertThrows(TokenReadException::class.java) { store.load() }

                assertEquals(TokenReadKind.TRANSIENT, failure.kind)
                assertEquals(fixture.legacy, store.activeFile())
                assertFalse(
                    "A missing key must not move the legacy copy to the target.",
                    fixture.target.exists(),
                )
                assertFalse(
                    "A missing key must not create a disposable key.",
                    fixture.disposableKeyExists(),
                )
                assertFalse("A missing key must not record a marker.", fixture.marker.exists())
                assertArrayEquals(
                    "The legacy copy must stay unchanged.",
                    legacyBytes,
                    fixture.legacy.readBytes(),
                )
            } finally {
                legacyBytes.fill(0)
            }
        }
    }

    @Test
    fun aSaveWithAMissingKeyDoesNotCreateAKeyOrReplaceTheTarget() {
        withFixture { fixture ->
            fixture.write(fixture.target, TOKEN_TARGET)
            val targetBytes = fixture.target.readBytes()
            try {
                fixture.deleteDisposableKey()
                val store = fixture.store()

                assertThrows(IOException::class.java) { store.save(TOKEN_NEW) }

                assertFalse(
                    "A refused save must not create a disposable key.",
                    fixture.disposableKeyExists(),
                )
                assertArrayEquals(
                    "A refused save must not replace the target.",
                    targetBytes,
                    fixture.target.readBytes(),
                )
                assertFalse(fixture.legacy.exists())
                assertFalse(fixture.marker.exists())
            } finally {
                targetBytes.fill(0)
            }
        }
    }

    @Test
    fun aSaveWithAMissingKeyKeepsTheOnlyLegacyCiphertext() {
        withFixture { fixture ->
            fixture.write(fixture.legacy, TOKEN_LEGACY)
            val legacyBytes = fixture.legacy.readBytes()
            try {
                fixture.deleteDisposableKey()
                assertThrows(IOException::class.java) { fixture.store().save(TOKEN_NEW) }
                assertFalse(fixture.disposableKeyExists())
                assertFalse(fixture.target.exists())
                assertFalse(fixture.marker.exists())
                assertArrayEquals(legacyBytes, fixture.legacy.readBytes())
            } finally {
                legacyBytes.fill(0)
            }
        }
    }

    @Test
    fun aSaveKeepsCiphertextFromAFormerKeyAndLatchesTheMarker() {
        withFixture { fixture ->
            fixture.write(fixture.target, TOKEN_TARGET)
            fixture.writeWithOldKey(fixture.legacy, TOKEN_LEGACY)
            val legacyBytes = fixture.legacy.readBytes()
            try {
                val store = fixture.store()

                assertEquals(
                    "A readable target wins over a ciphertext from another key.",
                    TOKEN_TARGET,
                    store.load(),
                )
                assertTrue(
                    "The kept ciphertext needs the supersession marker.",
                    fixture.marker.isFile,
                )
                assertArrayEquals(
                    "A load must not change the wrong-key ciphertext.",
                    legacyBytes,
                    fixture.legacy.readBytes(),
                )

                store.save(TOKEN_NEW)

                assertEquals(TOKEN_NEW, fixture.decode(fixture.target))
                assertTrue("The marker is a one-way latch.", fixture.marker.isFile)
                assertArrayEquals(
                    "A save must not delete the wrong-key ciphertext.",
                    legacyBytes,
                    fixture.legacy.readBytes(),
                )

                assertTrue(fixture.target.delete())
                assertNull(
                    "The marker must block the stale legacy token.",
                    store.load(),
                )
                assertArrayEquals(legacyBytes, fixture.legacy.readBytes())
            } finally {
                legacyBytes.fill(0)
            }
        }
    }

    @Test
    fun anUnusableTokenCreatesNoKeyOrFile() {
        withFixture { fixture ->
            val store = fixture.store()

            assertThrows(IllegalArgumentException::class.java) {
                store.save("not a usable token")
            }

            assertFalse("An unusable token must not create the key.", fixture.disposableKeyExists())
            assertFalse(fixture.target.exists())
            assertFalse(fixture.legacy.exists())
            assertFalse(fixture.marker.exists())
            assertNull(store.load())
        }
    }

    private fun withFixture(block: (Fixture) -> Unit) {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val fixture = Fixture(instrumentation.targetContext)
        var bodyFailure: Throwable? = null
        try {
            block(fixture)
        } catch (failure: Throwable) {
            bodyFailure = failure
            throw failure
        } finally {
            try {
                fixture.close()
            } catch (cleanupFailure: Throwable) {
                if (bodyFailure == null) {
                    throw cleanupFailure
                }
                bodyFailure.addSuppressed(cleanupFailure)
            }
        }
    }

    /**
     * One isolated app-private directory tree and one disposable key alias.
     *
     * The real files are checked only with `exists()`. The test never opens
     * them.
     */
    private class Fixture(base: Context) {
        private val alias =
            "hs-token-for-context-" + UUID.randomUUID().toString().replace("-", "")
        private val oldAlias =
            "hs-token-for-context-old-" + UUID.randomUUID().toString().replace("-", "")
        private val root = File(
            base.cacheDir,
            "hs-token-for-context-${UUID.randomUUID()}",
        ).apply {
            if (!mkdirs() && !isDirectory) {
                throw IOException("The isolated token directory was not created.")
            }
        }
        init {
            if (androidKeystoreContains(alias) || androidKeystoreContains(oldAlias)) {
                throw IOException("The disposable token key already exists.")
            }
        }
        val filesDirectory = File(root, "files")
        val noBackupDirectory = File(root, "no_backup")
        val target = File(noBackupDirectory, TOKEN_FILE_NAME)
        val legacy = File(filesDirectory, TOKEN_FILE_NAME)
        val marker = File(noBackupDirectory, "$TOKEN_FILE_NAME.legacy-superseded")
        val isolatedContext = IsolatedTokenContext(
            base = base,
            filesDirectory = filesDirectory,
            noBackupDirectory = noBackupDirectory,
            dataDirectory = root,
        )
        private val codec = KeystoreTokenFileCodec(keyAlias = alias)
        private val oldCodec = KeystoreTokenFileCodec(keyAlias = oldAlias)
        private val dataDirectory = File(base.applicationInfo.dataDir)
        private val realTarget = File(dataDirectory, "no_backup/$TOKEN_FILE_NAME")
        private val realLegacy = File(dataDirectory, "files/$TOKEN_FILE_NAME")
        private val realMarker = File(realTarget.parentFile, realTarget.name + ".legacy-superseded")
        private val realTargetBefore = realTarget.exists()
        private val realLegacyBefore = realLegacy.exists()
        private val realMarkerBefore = realMarker.exists()
        private val productionKeyBefore = androidKeystoreContains(KeystoreTokenFileCodec.KEY_ALIAS)

        fun store(storeCodec: TokenFileCodec = codec): AndroidKeystoreTokenStore =
            AndroidKeystoreTokenStore.forContext(isolatedContext, storeCodec)

        fun write(file: File, token: String, writer: TokenFileCodec = codec) {
            val rootPath = root.absoluteFile.toPath().normalize()
            require(file.absoluteFile.toPath().normalize().startsWith(rootPath)) {
                "The fixture writes only its isolated token paths."
            }
            file.parentFile?.mkdirs()
            val bytes = writer.encode(token)
            try {
                file.writeBytes(bytes)
            } finally {
                bytes.fill(0)
            }
        }

        fun writeWithOldKey(file: File, token: String) = write(file, token, oldCodec)

        fun decode(file: File): String {
            val bytes = file.readBytes()
            return try {
                codec.decode(bytes)
            } finally {
                bytes.fill(0)
            }
        }

        fun decodeBytes(bytes: ByteArray): String = codec.decode(bytes)

        fun flipLastByte(file: File) {
            val bytes = file.readBytes()
            try {
                require(bytes.isNotEmpty()) { "The token file is empty." }
                bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 0x01).toByte()
                file.writeBytes(bytes)
            } finally {
                bytes.fill(0)
            }
        }

        fun disposableKeyExists(): Boolean = androidKeystoreContains(alias)

        fun deleteDisposableKey() {
            deleteKey(alias)
            deleteKey(oldAlias)
        }

        private fun deleteKey(keyAlias: String) {
            val keyStore = androidKeyStore()
            if (keyStore.containsAlias(keyAlias)) {
                keyStore.deleteEntry(keyAlias)
            }
            if (androidKeystoreContains(keyAlias)) {
                throw IOException("The disposable token key was not removed.")
            }
        }

        fun close() {
            var cleanupFailure: Throwable? = null
            try {
                deleteDisposableKey()
            } catch (failure: Throwable) {
                cleanupFailure = failure
            }
            try {
                if (!root.deleteRecursively()) {
                    throw IOException("The isolated token directory was not removed.")
                }
            } catch (failure: Throwable) {
                if (cleanupFailure == null) {
                    cleanupFailure = failure
                } else {
                    cleanupFailure.addSuppressed(failure)
                }
            }
            try {
                assertEquals(
                    "The real app target file state must not change.",
                    realTargetBefore,
                    realTarget.exists(),
                )
                assertEquals(
                    "The real app legacy file state must not change.",
                    realLegacyBefore,
                    realLegacy.exists(),
                )
                assertEquals(
                    "The real app marker state must not change.",
                    realMarkerBefore,
                    realMarker.exists(),
                )
                assertEquals(
                    "The production key alias must not change.",
                    productionKeyBefore,
                    androidKeystoreContains(KeystoreTokenFileCodec.KEY_ALIAS),
                )
            } catch (failure: Throwable) {
                if (cleanupFailure == null) {
                    cleanupFailure = failure
                } else {
                    cleanupFailure.addSuppressed(failure)
                }
            }
            cleanupFailure?.let { throw it }
        }

        private class IsolatedTokenContext(
            base: Context,
            private val filesDirectory: File,
            private val noBackupDirectory: File,
            dataDirectory: File,
        ) : ContextWrapper(base) {
            private val isolatedInfo = ApplicationInfo(base.applicationInfo).apply {
                dataDir = dataDirectory.absolutePath
            }

            override fun getFilesDir(): File = filesDirectory

            override fun getNoBackupFilesDir(): File = noBackupDirectory

            override fun getApplicationInfo(): ApplicationInfo = isolatedInfo
        }
    }
}

private const val TOKEN_FILE_NAME = "source-token.bin"
private const val TOKEN_A = "instrumented-token-a"
private const val TOKEN_B = "instrumented-token-b"
private const val TOKEN_NEW = "instrumented-token-new"
private const val TOKEN_LEGACY = "instrumented-legacy-token"
private const val TOKEN_TARGET = "instrumented-target-token"
private const val ANDROID_KEYSTORE = "AndroidKeyStore"

private fun androidKeyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
    load(null)
}

private fun androidKeystoreContains(alias: String): Boolean = androidKeyStore().containsAlias(alias)
