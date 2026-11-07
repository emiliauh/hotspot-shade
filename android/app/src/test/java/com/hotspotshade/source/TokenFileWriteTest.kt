package com.hotspotshade.source

import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests for the atomic token file writer.
 *
 * A failed write must leave the previous file in place and no temporary file.
 * The real store encrypts the bytes before it calls this writer.
 */
class TokenFileWriteTest {
    @Test
    fun writesAndReplacesTheFile() {
        withDirectory { directory ->
            val file = File(directory, "source-token.bin")
            AtomicFileWriter.write(file) { it.write(byteArrayOf(1, 2, 3)) }
            assertArrayEquals(byteArrayOf(1, 2, 3), file.readBytes())

            AtomicFileWriter.write(file) { it.write(byteArrayOf(4, 5)) }
            assertArrayEquals(byteArrayOf(4, 5), file.readBytes())
            assertEquals(listOf(file.name), directory.list()?.toList())
        }
    }

    @Test
    fun aFailedWriteKeepsThePreviousFile() {
        withDirectory { directory ->
            val file = File(directory, "source-token.bin")
            AtomicFileWriter.write(file) { it.write(byteArrayOf(1, 2, 3)) }

            assertThrows(IOException::class.java) {
                AtomicFileWriter.write(file) { output ->
                    output.write(byteArrayOf(9, 9, 9, 9))
                    throw IOException("The write failed.")
                }
            }

            assertArrayEquals(
                "A failed write must not replace the stored token.",
                byteArrayOf(1, 2, 3),
                file.readBytes(),
            )
            assertEquals("No temporary file may remain.", listOf(file.name), directory.list()?.toList())
        }
    }

    @Test
    fun aMoveErrorAfterReplacementIsUncertain() {
        withDirectory { directory ->
            val file = File(directory, "source-token.bin")
            file.writeText("old")
            assertThrows(TokenWriteUncertainException::class.java) {
                AtomicFileWriter.write(file, move = { from, to ->
                    Files.move(from, to, java.nio.file.StandardCopyOption.REPLACE_EXISTING)
                    throw IOException("injected after replacement")
                }) { it.write("new".toByteArray()) }
            }
            assertEquals("new", file.readText())
        }
    }

    @Test
    fun createsTheParentDirectory() {
        withDirectory { directory ->
            val file = File(File(directory, "nested"), "source-token.bin")
            AtomicFileWriter.write(file) { it.write(byteArrayOf(7)) }
            assertTrue(file.isFile)
            assertArrayEquals(byteArrayOf(7), file.readBytes())
        }
    }

    @Test
    fun aMissingFileIsNullAndACorruptFileIsAnUnreadableToken() {
        withDirectory { directory ->
            val file = File(directory, "source-token.bin")
            val store = AndroidKeystoreTokenStore(file)

            assertNull("A missing file is a missing token.", store.load())

            file.writeBytes(byteArrayOf(1, 2))
            assertThrows(TokenReadException::class.java) { store.load() }

            file.writeBytes(byteArrayOf(9, 1, 2, 3))
            assertThrows(TokenReadException::class.java) { store.load() }
        }
    }

    @Test
    fun aDottedPathIsCheckedAndUsedAsOneNormalizedPath() {
        withDirectory { directory ->
            val target = File(directory, "./no-backup/./source-token.bin")
            val normalized = File(directory, "no-backup/source-token.bin")
            val store = AndroidKeystoreTokenStore(target, codec = PlainCodec(), appRoot = directory)

            store.save("token-new")

            assertEquals("token-new", normalized.readText(Charsets.UTF_8))
            assertEquals(
                "The checked path is the path the store operates on.",
                normalized,
                store.activeFile(),
            )
            assertEquals("token-new", store.load())
        }
    }

    @Test
    fun aParentTraversalPathIsRejectedBeforeTheWriterCanUseIt() {
        withDirectory { directory ->
            val inside = File(directory, "inside").apply { mkdirs() }
            val outside = File(directory, "outside").apply { mkdirs() }
            Files.createSymbolicLink(File(inside, "link").toPath(), outside.toPath())
            val file = File(inside, "link/../token")

            assertThrows(IOException::class.java) {
                AtomicFileWriter.write(file) { it.write(byteArrayOf(1, 2, 3)) }
            }

            assertFalse(File(directory, "token").exists())
            assertFalse(File(outside, "token").exists())
            assertFalse(File(inside, "token").exists())
        }
    }

    @Test
    fun migrationMovesOneLegacyFileAndRemovesIt() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(legacy.parentFile).mkdirs()
            legacy.writeBytes(byteArrayOf(4, 5, 6))

            val primary = AndroidKeystoreTokenStore.migrateTokenFile(target, legacy)

            assertEquals(target, primary)
            assertArrayEquals(byteArrayOf(4, 5, 6), target.readBytes())
            assertFalse("The legacy file must not remain.", legacy.exists())
        }
    }

    @Test
    fun anExistingTargetWinsAndRemovesTheStaleLegacyCopy() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeBytes(byteArrayOf(1))
            legacy.writeBytes(byteArrayOf(2))

            val primary = AndroidKeystoreTokenStore.migrateTokenFile(target, legacy)

            assertEquals(target, primary)
            assertArrayEquals(byteArrayOf(1), target.readBytes())
            assertFalse(
                "A stale legacy file could restore a cleared token.",
                legacy.exists(),
            )
        }
    }

    @Test
    fun aFailedMigrationKeepsTheLegacyFile() {
        withDirectory { directory ->
            val blocked = File(directory, "blocked")
            blocked.writeBytes(byteArrayOf(1))
            val target = File(blocked, "source-token.bin")
            val legacy = File(directory, "source-token.bin")
            legacy.writeBytes(byteArrayOf(7, 8))

            val primary = AndroidKeystoreTokenStore.migrateTokenFile(target, legacy)

            assertEquals("A failed move keeps the old file usable.", legacy, primary)
            assertArrayEquals(byteArrayOf(7, 8), legacy.readBytes())
            assertFalse(target.exists())
        }
    }

    @Test
    fun concurrentMigrationsLeaveOneCompleteTargetFile() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(legacy.parentFile).mkdirs()
            legacy.writeBytes(byteArrayOf(9, 8, 7))
            val start = CountDownLatch(1)
            val results = java.util.Collections.synchronizedList(mutableListOf<File>())
            val failures = java.util.Collections.synchronizedList(mutableListOf<Throwable>())

            val threads = (0 until 8).map {
                Thread({
                    try {
                        start.await()
                        results += AndroidKeystoreTokenStore.migrateTokenFile(target, legacy)
                    } catch (failure: Throwable) {
                        failures += failure
                    }
                }).also { it.start() }
            }
            start.countDown()
            for (thread in threads) {
                thread.join(10_000)
                assertFalse("A migration must not hang.", thread.isAlive)
            }

            assertTrue("Every migration must complete without error: $failures", failures.isEmpty())
            assertEquals(8, results.size)
            assertArrayEquals(byteArrayOf(9, 8, 7), target.readBytes())
            assertFalse(legacy.exists())
            assertTrue(results.all { it == target })
        }
    }

    @Test
    fun clearIsBlockedAndKeepsBothCopies() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeBytes(byteArrayOf(1))
            legacy.writeBytes(byteArrayOf(2))

            assertThrows(TokenDeleteException::class.java) { AndroidKeystoreTokenStore(target, legacy).clear() }

            assertTrue(target.exists())
            assertTrue(
                "A cleared token must not come back from the legacy file.",
                legacy.exists(),
            )
        }
    }

    @Test
    fun anOldStoreWritesToTheTargetAfterAnotherMigration() {
        withDirectory { directory ->
            val blocker = File(directory, "blocked")
            blocker.writeBytes(byteArrayOf(0))
            val target = File(blocker, "source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(legacy.parentFile).mkdirs()
            legacy.writeText("old-token", Charsets.UTF_8)

            val oldStore = AndroidKeystoreTokenStore(target, legacy, PlainCodec())
            assertThrows(TokenReadException::class.java) { oldStore.activeFile() }
            assertThrows(TokenReadException::class.java) { oldStore.load() }
            assertEquals("old-token", legacy.readText())

            // Another instance completes the move after the target directory
            // becomes writable.
            assertTrue(blocker.delete())
            assertEquals(target, AndroidKeystoreTokenStore.migrateTokenFile(target, legacy))
            assertFalse(legacy.exists())

            // The long-lived instance must resolve the target again on every
            // operation. It must not recreate the legacy file.
            assertEquals(target, oldStore.activeFile())
            oldStore.save("new-token")

            assertEquals("new-token", target.readText(Charsets.UTF_8))
            assertFalse(
                "A long-lived store must not recreate the legacy file.",
                legacy.exists(),
            )
            assertEquals("new-token", oldStore.load())
        }
    }

    @Test
    fun aFailedTargetWriteKeepsTheLegacyCopyAndALaterSaveSucceeds() {
        withDirectory { directory ->
            val blocker = File(directory, "blocked")
            blocker.writeBytes(byteArrayOf(0))
            val target = File(blocker, "source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(legacy.parentFile).mkdirs()
            legacy.writeText("first-token", Charsets.UTF_8)

            val store = AndroidKeystoreTokenStore(target, legacy, PlainCodec())
            assertThrows(IOException::class.java) { store.save("written-to-legacy") }
            assertEquals(
                "A failed target write must not touch the readable legacy copy.",
                "first-token",
                legacy.readText(Charsets.UTF_8),
            )
            assertFalse(target.exists())

            // The next operation retries the move and reads the latest value.
            assertTrue(blocker.delete())
            assertEquals("first-token", store.load())
            assertTrue(target.isFile)
            assertFalse(legacy.exists())

            store.save("written-to-target")
            assertEquals("written-to-target", target.readText(Charsets.UTF_8))
            assertFalse(
                "A resolved store must not write the legacy file again.",
                legacy.exists(),
            )
        }
    }

    @Test
    fun concurrentOldStoreWritesAndMigrationsLeaveOneTarget() {
        withDirectory { directory ->
            val blocker = File(directory, "blocked")
            blocker.writeBytes(byteArrayOf(0))
            val target = File(blocker, "source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(legacy.parentFile).mkdirs()
            legacy.writeText("first-token", Charsets.UTF_8)

            val oldStore = AndroidKeystoreTokenStore(target, legacy, PlainCodec())
            // A blocked target refuses the write, and the legacy copy keeps
            // the previous token.
            assertThrows(IOException::class.java) { oldStore.save("before-migration") }
            assertEquals("first-token", legacy.readText(Charsets.UTF_8))

            assertTrue(blocker.delete())
            val start = CountDownLatch(1)
            val failures = java.util.Collections.synchronizedList(mutableListOf<Throwable>())
            val threads = (0 until 8).map { index ->
                Thread({
                    try {
                        start.await()
                        if (index % 2 == 0) {
                            AndroidKeystoreTokenStore.migrateTokenFile(target, legacy)
                        } else {
                            oldStore.save("old-store-$index")
                        }
                    } catch (failure: Throwable) {
                        failures += failure
                    }
                }).also { it.start() }
            }
            start.countDown()
            for (thread in threads) {
                thread.join(10_000)
                assertFalse("A migration must not hang.", thread.isAlive)
            }

            assertTrue("Every concurrent operation must complete without error: $failures", failures.isEmpty())
            assertTrue("The target file must exist.", target.isFile)
            assertFalse(
                "The legacy file must not survive a completed migration.",
                legacy.exists(),
            )
            assertEquals(target, oldStore.activeFile())
            val stored = oldStore.load()
            assertTrue(
                "The stored value must be one complete write.",
                stored == "first-token" || stored?.startsWith("old-store-") == true,
            )
        }
    }

    @Test
    fun blockedClearDoesNotDeleteEitherCopy() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeText("target-token", Charsets.UTF_8)
            legacy.writeText("legacy-token", Charsets.UTF_8)
            var deletes = 0
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                PlainCodec(),
                deleteFile = { deletes += 1; it.delete() },
            )

            // Clear is blocked until guarded, durable deletion exists. It must
            // not begin a delete that it cannot finish, so the injected delete
            // is never called.
            assertThrows(TokenDeleteException::class.java) { store.clear() }

            assertEquals("A blocked clear must not delete.", 0, deletes)
            assertTrue("A blocked clear must keep the target.", target.isFile)
            assertTrue("A blocked clear must keep the legacy copy.", legacy.isFile)
            assertEquals("target-token", store.load())
        }
    }

    @Test
    fun blockedClearKeepsTheOnlyReadableLegacyCopy() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeText("corrupt", Charsets.UTF_8)
            legacy.writeText("token-legacy", Charsets.UTF_8)
            var deletes = 0
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                ValidatingCodec(),
                deleteFile = { deletes += 1; it.delete() },
            )

            assertThrows(TokenDeleteException::class.java) { store.clear() }

            assertEquals("A blocked clear must not delete.", 0, deletes)
            assertTrue(
                "A blocked clear must not remove the only readable token.",
                legacy.isFile,
            )
            assertEquals("token-legacy", store.load())
        }
    }

    @Test
    fun aCorruptTargetFallsBackForLoadAndASaveRepairsTheTarget() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeText("corrupt", Charsets.UTF_8)
            legacy.writeText("token-legacy", Charsets.UTF_8)
            val store = AndroidKeystoreTokenStore(target, legacy, ValidatingCodec())

            assertEquals(
                "A corrupt target must not hide a readable legacy token.",
                "token-legacy",
                store.load(),
            )
            assertEquals("The readable legacy file is the active file.", legacy, store.activeFile())
            assertTrue("The readable legacy file must stay.", legacy.isFile)
            assertTrue("The corrupt target must stay for inspection.", target.isFile)

            store.save("token-new")

            assertEquals(
                "A save must repair the no-backup target first.",
                "token-new",
                target.readText(Charsets.UTF_8),
            )
            assertFalse(
                "The legacy copy is removed only after the target is confirmed.",
                legacy.exists(),
            )
            assertEquals("token-new", store.load())
        }
    }

    @Test
    fun aFailedVerificationBeforeTheTargetWriteKeepsTheReadableLegacyUsable() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeText("corrupt", Charsets.UTF_8)
            legacy.writeText("token-legacy", Charsets.UTF_8)
            val marker = legacyMarkerFileFor(target)
            val store = AndroidKeystoreTokenStore(target, legacy, ValidatingCodec())

            // The codec accepts token- values only, so the temporary file
            // cannot be verified and the rename never happens.
            assertThrows(TokenReadException::class.java) { store.save("not-a-token") }

            assertEquals(
                "A failed verification must leave the ambiguous target unchanged.",
                "corrupt",
                target.readText(Charsets.UTF_8),
            )
            assertTrue(
                "A failed verification must not remove the readable legacy copy.",
                legacy.isFile,
            )
            assertEquals("token-legacy", legacy.readText(Charsets.UTF_8))
            assertFalse(
                "A failed save before the target write must not latch a readable copy.",
                marker.exists(),
            )
            assertEquals(
                "A failed verification must leave no temporary file.",
                setOf(target.name),
                target.parentFile?.list()?.toSet(),
            )
            assertEquals(
                "The readable legacy copy stays usable after the failed save.",
                "token-legacy",
                store.load(),
            )
            assertEquals("token-legacy", legacy.readText(Charsets.UTF_8))
            assertEquals("corrupt", target.readText(Charsets.UTF_8))
        }
    }

    @Test
    fun aSaveWhoseTargetVerifiesADifferentValueKeepsTheReadableLegacyUsable() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeText("corrupt", Charsets.UTF_8)
            legacy.writeText("token-legacy", Charsets.UTF_8)
            val marker = legacyMarkerFileFor(target)
            val store = AndroidKeystoreTokenStore(target, legacy, SwappingCodec())

            // The codec encodes a different value than the token the caller
            // asked to store, so the temporary file cannot be accepted for
            // this token even though it decodes.
            assertThrows(TokenReadException::class.java) { store.save("token-new") }

            assertEquals(
                "A mismatched verification must leave the ambiguous target unchanged.",
                "corrupt",
                target.readText(Charsets.UTF_8),
            )
            assertTrue("The readable legacy copy must stay.", legacy.isFile)
            assertEquals("token-legacy", legacy.readText(Charsets.UTF_8))
            assertFalse(
                "A mismatched verification must not latch a readable copy.",
                marker.exists(),
            )
            assertEquals(
                "The readable legacy copy stays usable after the failed save.",
                "token-legacy",
                store.load(),
            )
            assertEquals(
                "A failed verification must leave no temporary file.",
                setOf(target.name),
                target.parentFile?.list()?.toSet(),
            )
        }
    }

    @Test
    fun aTransientSaveVerificationFailureKeepsTheReadableLegacyUsable() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeText("corrupt", Charsets.UTF_8)
            legacy.writeText("token-legacy", Charsets.UTF_8)
            val store = AndroidKeystoreTokenStore(target, legacy, TransientOnSaveCodec())

            val failure = assertThrows(TokenReadException::class.java) {
                store.save("token-transient")
            }

            assertEquals(
                "A Keystore or I/O failure is not proof of corruption.",
                TokenReadKind.TRANSIENT,
                failure.kind,
            )
            assertEquals(
                "The ambiguous target must not be replaced on a failed verification.",
                "corrupt",
                target.readText(Charsets.UTF_8),
            )
            assertTrue("The readable legacy copy must stay.", legacy.isFile)
            assertEquals("token-legacy", legacy.readText(Charsets.UTF_8))
            assertFalse(
                "A failed save before the target write must not latch a readable copy.",
                legacyMarkerFileFor(target).exists(),
            )
            assertEquals(
                "The readable legacy copy stays usable after the failed save.",
                "token-legacy",
                store.load(),
            )
        }
    }

    @Test
    fun saveRejectsAnUnusableTokenWithoutTouchingTheFiles() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeText("corrupt", Charsets.UTF_8)
            legacy.writeText("token-legacy", Charsets.UTF_8)
            val store = AndroidKeystoreTokenStore(target, legacy, ValidatingCodec())

            assertThrows(IllegalArgumentException::class.java) { store.save("bad token") }

            assertEquals("corrupt", target.readText(Charsets.UTF_8))
            assertEquals("token-legacy", legacy.readText(Charsets.UTF_8))
            assertEquals("token-legacy", store.load())
        }
    }

    @Test
    fun aFailedTargetDirectorySyncDuringMigrationKeepsTheLegacyCopy() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(legacy.parentFile).mkdirs()
            legacy.writeText("token-legacy", Charsets.UTF_8)
            var failSync = true
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                PlainCodec(),
                syncTargetParent = { if (failSync) throw IOException("sync failed") },
            )

            // The target write is visible but its directory entry is not
            // confirmed durable. Report the legacy copy for this call.
            assertEquals(legacy, store.activeFile())
            assertTrue("The readable legacy copy must stay.", legacy.isFile)
            assertEquals("token-legacy", target.readText(Charsets.UTF_8))

            failSync = false
            assertEquals("The next call retries the confirmed target.", target, store.activeFile())
            assertFalse("The legacy copy is removed after the retry.", legacy.exists())
            assertEquals("token-legacy", store.load())
        }
    }

    @Test
    fun aFailedMigrationVerificationKeepsTheReadableLegacyCopy() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(legacy.parentFile).mkdirs()
            legacy.writeText("token-legacy", Charsets.UTF_8)

            val primary = AndroidKeystoreTokenStore.migrateTokenFile(
                target = target,
                legacy = legacy,
                targetReadable = { false },
                legacyReadable = { true },
            )

            assertEquals("An unconfirmed target must not win.", legacy, primary)
            assertTrue("The only readable token must stay.", legacy.isFile)
        }
    }

    @Test
    fun aCrashAfterTheTargetWriteLatchesTheOldLegacyCopyInsteadOfDeletingIt() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeText("corrupt", Charsets.UTF_8)
            legacy.writeText("token-legacy", Charsets.UTF_8)
            val marker = legacyMarkerFileFor(target)

            // Simulate a crash after the atomic target write and before the
            // marker. The next load trusts the readable target, latches the
            // old copy, and keeps it.
            target.writeText("token-new", Charsets.UTF_8)
            val store = AndroidKeystoreTokenStore(target, legacy, ValidatingCodec())

            assertEquals("token-new", store.load())
            assertTrue("The differing old copy must be latched.", marker.isFile)
            assertTrue(
                "A differing old copy is kept for recovery, not deleted.",
                legacy.isFile,
            )
            assertEquals("token-legacy", legacy.readText(Charsets.UTF_8))

            assertTrue(target.delete())
            assertNull(
                "The latch keeps the kept old copy from becoming active.",
                store.load(),
            )
            assertEquals("token-legacy", legacy.readText(Charsets.UTF_8))
        }
    }

    @Test
    fun aFailedLegacyDeleteAfterAConfirmedSaveKeepsTheCopyUntilALaterSave() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeText("corrupt", Charsets.UTF_8)
            legacy.writeText("token-legacy", Charsets.UTF_8)
            val failLegacyDelete = java.util.concurrent.atomic.AtomicBoolean(true)
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                ValidatingCodec(),
                deleteFile = { file ->
                    if (file == legacy && failLegacyDelete.get()) false else file.delete()
                },
            )

            store.save("token-new")

            assertEquals("token-new", target.readText(Charsets.UTF_8))
            assertTrue(
                "A failed legacy delete keeps the copy, not the active token.",
                legacy.isFile,
            )
            assertEquals("The confirmed target wins.", "token-new", store.load())
            assertTrue(
                "A latched differing legacy copy is kept for recovery.",
                legacy.isFile,
            )

            failLegacyDelete.set(false)
            store.save("token-new")
            assertEquals("token-new", target.readText(Charsets.UTF_8))
            assertFalse("A later confirmed save removes the stale copy.", legacy.exists())
            assertEquals("token-new", store.load())
        }
    }

    @Test
    fun concurrentSavesRepairTheCorruptTargetAndLeaveOneCompleteToken() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeText("corrupt", Charsets.UTF_8)
            legacy.writeText("token-legacy", Charsets.UTF_8)
            val store = AndroidKeystoreTokenStore(target, legacy, ValidatingCodec())
            val start = CountDownLatch(1)
            val failures = java.util.Collections.synchronizedList(mutableListOf<Throwable>())
            val observed = java.util.Collections.synchronizedList(mutableListOf<String?>())

            val threads = (0 until 8).map { index ->
                Thread({
                    start.await()
                    try {
                        if (index % 2 == 0) {
                            store.save("token-$index")
                        } else {
                            observed += store.load()
                        }
                    } catch (failure: Throwable) {
                        failures += failure
                    }
                }).also { it.start() }
            }
            start.countDown()
            for (thread in threads) {
                thread.join(10_000)
                assertFalse("A save must not hang.", thread.isAlive)
            }

            assertTrue("Every save and load must finish.", failures.isEmpty())
            assertTrue("The target file must exist.", target.isFile)
            assertFalse(
                "The legacy copy must not survive a confirmed save.",
                legacy.exists(),
            )
            val stored = store.load()
            assertTrue(
                "The stored value must be one complete save.",
                stored?.startsWith("token-") == true,
            )
            assertTrue(
                "Every load must see a complete token.",
                observed.all { it == null || it.startsWith("token-") },
            )
        }
    }

    @Test
    fun anUnreadableTargetAndUnreadableLegacyStayUnreadable() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeText("corrupt", Charsets.UTF_8)
            legacy.writeText("also-corrupt", Charsets.UTF_8)
            val store = AndroidKeystoreTokenStore(target, legacy, ValidatingCodec())

            assertThrows(TokenReadException::class.java) { store.load() }

            assertTrue(target.isFile)
            assertTrue("An unreadable legacy copy is not deleted.", legacy.isFile)
        }
    }

    @Test
    fun aTransientTargetErrorDoesNotFallBackToAStaleLegacyCopy() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeText("transient", Charsets.UTF_8)
            legacy.writeText("token-legacy", Charsets.UTF_8)
            val store = AndroidKeystoreTokenStore(target, legacy, KindCodec())

            assertThrows(TokenReadException::class.java) { store.load() }
            assertEquals(
                "A transient target error must not switch to the legacy token.",
                target,
                store.activeFile(),
            )
            assertTrue("The readable legacy copy must stay.", legacy.isFile)
        }
    }

    @Test
    fun aCorruptLegacyCopyWithoutATargetIsUnreadableNotMissing() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(legacy.parentFile).mkdirs()
            legacy.writeText("corrupt", Charsets.UTF_8)
            val store = AndroidKeystoreTokenStore(target, legacy, KindCodec())

            assertThrows(TokenReadException::class.java) { store.load() }
            assertEquals(legacy, store.activeFile())
        }
    }

    @Test
    fun aDifferingReadableLegacyIsLatchedAndNeverDeletedByALoad() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeText("token-target", Charsets.UTF_8)
            legacy.writeText("token-legacy", Charsets.UTF_8)
            var deleteAttempts = 0
            val marker = legacyMarkerFileFor(target)
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                KindCodec(),
                deleteFile = { file ->
                    deleteAttempts += 1
                    false
                },
            )

            assertEquals(target, store.activeFile())
            assertEquals(target, store.activeFile())

            assertEquals("The readable target still wins.", "token-target", store.load())
            assertEquals(
                "A load must not delete a differing readable copy.",
                0,
                deleteAttempts,
            )
            assertTrue("A differing copy is kept for recovery.", legacy.isFile)
            assertTrue("The kept differing copy is latched.", marker.isFile)

            assertTrue(target.delete())
            assertNull(
                "The latch prevents the differing copy from becoming active.",
                store.load(),
            )
            assertTrue(legacy.isFile)
        }
    }

    @Test
    fun aFailedDeleteOfAnEqualLegacyCopyIsRetriedOnTheNextLoad() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeText("token-same", Charsets.UTF_8)
            legacy.writeText("token-same", Charsets.UTF_8)
            var deleteAttempts = 0
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                KindCodec(),
                deleteFile = {
                    deleteAttempts += 1
                    false
                },
            )

            assertEquals(target, store.activeFile())
            assertEquals(target, store.activeFile())

            assertEquals("The readable target still wins.", "token-same", store.load())
            assertTrue("A failed delete leaves the equal copy for a retry.", legacy.isFile)
            assertTrue("The delete must be retried.", deleteAttempts >= 2)
            assertFalse(
                "An equal copy needs no latch.",
                legacyMarkerFileFor(target).exists(),
            )
        }
    }

    @Test
    fun aWriteCanSyncItsParentDirectoryAndLeavesNoTemporaryFile() {
        withDirectory { directory ->
            val file = File(directory, "source-token.bin")
            AtomicFileWriter.write(file, syncParent = true) { it.write(byteArrayOf(3, 4)) }
            assertArrayEquals(byteArrayOf(3, 4), file.readBytes())
            assertEquals(setOf(file.name), directory.list()?.toSet())
        }
    }

    @Test
    fun aMarkerParentSyncFailureIsUncertainWhileTheMarkerIsVisible() {
        withDirectory { directory ->
            val marker = File(directory, "source-token.bin.legacy-superseded")

            assertThrows(TokenWriteUncertainException::class.java) {
                LegacyTokenMarker.recordWithParentSync(marker) {
                    throw IOException("The marker directory could not be synced.")
                }
            }

            assertEquals(
                "The renamed marker is visible even when its directory sync failed.",
                LegacyMarkerState.PRESENT,
                LegacyTokenMarker.state(marker),
            )
            assertTrue(marker.isFile)
            assertEquals(
                "The complete marker content was verified before the rename.",
                "hotspotshade legacy source token superseded v1\n",
                marker.readText(Charsets.US_ASCII),
            )
        }
    }

    @Test
    fun aReadableLegacyIsLatchedOnlyAfterTheTargetIsConfirmed() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeText("token-old-target", Charsets.UTF_8)
            legacy.writeText("token-old-legacy", Charsets.UTF_8)
            val marker = legacyMarkerFileFor(target)
            var targetWhenMarkerWasRecorded: String? = null
            var legacyWhenMarkerWasRecorded: String? = null
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                PlainCodec(),
                recordMarker = { file ->
                    targetWhenMarkerWasRecorded = target.readText(Charsets.UTF_8)
                    legacyWhenMarkerWasRecorded = legacy.readText(Charsets.UTF_8)
                    LegacyTokenMarker.record(file)
                },
            )

            store.save("token-new")

            assertEquals(
                "A readable legacy copy is latched only after the target is confirmed.",
                "token-new",
                targetWhenMarkerWasRecorded,
            )
            assertEquals(
                "The old readable copy is still available when the latch is written.",
                "token-old-legacy",
                legacyWhenMarkerWasRecorded,
            )
            assertTrue("The marker is durable after the target write.", marker.isFile)
            assertEquals("token-new", target.readText(Charsets.UTF_8))
            assertFalse("The readable stale copy is removed after the latch.", legacy.exists())
        }
    }

    @Test
    fun aFailedLatchAfterAConfirmedTargetKeepsBothTokensAndFailsClosed() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeText("token-target", Charsets.UTF_8)
            legacy.writeText("token-legacy", Charsets.UTF_8)
            val marker = legacyMarkerFileFor(target)
            var failMarker = true
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                PlainCodec(),
                recordMarker = { file ->
                    if (failMarker) throw IOException("The marker could not be written.")
                    LegacyTokenMarker.record(file)
                },
            )

            assertThrows(IOException::class.java) { store.save("token-new") }

            assertEquals(
                "The confirmed target keeps the requested token.",
                "token-new",
                target.readText(Charsets.UTF_8),
            )
            assertEquals(
                "The old readable copy is kept, not latched off silently.",
                "token-legacy",
                legacy.readText(Charsets.UTF_8),
            )
            assertFalse("A failed latch leaves no marker.", marker.exists())
            val failure = assertThrows(TokenReadException::class.java) { store.load() }
            assertEquals(
                "An unlatched differing copy must not be returned as authoritative.",
                TokenReadKind.TRANSIENT,
                failure.kind,
            )
            assertEquals("token-new", target.readText(Charsets.UTF_8))
            assertTrue(legacy.isFile)

            failMarker = false
            assertEquals("The retry latches the copy and returns the target.", "token-new", store.load())
            assertTrue(marker.isFile)
            assertTrue("The differing copy is kept for recovery.", legacy.isFile)
            assertTrue(target.delete())
            assertNull("The durable latch blocks the kept copy.", store.load())
        }
    }

    @Test
    fun aFailedSaveBeforeTheTargetWriteNeverLatchesTheReadableLegacy() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(legacy.parentFile).mkdirs()
            legacy.writeText("token-legacy", Charsets.UTF_8)
            var markerRecords = 0
            var failEncoding = true
            val codec = object : TokenFileCodec {
                override fun encode(token: String): ByteArray {
                    if (failEncoding) throw IOException("injected encode failure")
                    return token.toByteArray(Charsets.UTF_8)
                }

                override fun decode(bytes: ByteArray): String = bytes.toString(Charsets.UTF_8)
            }
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                codec,
                recordMarker = { file ->
                    markerRecords += 1
                    LegacyTokenMarker.record(file)
                },
            )

            assertThrows(IOException::class.java) { store.save("token-new") }

            assertFalse("A failed save must not create the target.", target.exists())
            assertEquals("The requested token is not written.", "token-legacy", legacy.readText(Charsets.UTF_8))
            assertEquals("No latch may be attempted before the target write.", 0, markerRecords)
            assertFalse(legacyMarkerFileFor(target).exists())
            assertEquals(
                "The readable legacy copy migrates on the next load.",
                "token-legacy",
                store.load(),
            )
            assertEquals("token-legacy", target.readText(Charsets.UTF_8))
            assertFalse(legacy.exists())

            failEncoding = false
            store.save("token-new")
            assertEquals("token-new", store.load())
            assertEquals("token-new", target.readText(Charsets.UTF_8))
            assertFalse(legacy.exists())
        }
    }

    @Test
    fun anEncodeFailureWithAnAbsentTargetKeepsTheLegacyCopyForTheNextLoad() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(legacy.parentFile).mkdirs()
            legacy.writeText("token-legacy", Charsets.UTF_8)
            var failEncoding = true
            val codec = object : TokenFileCodec {
                override fun encode(token: String): ByteArray {
                    if (failEncoding) throw IOException("injected encode failure")
                    return token.toByteArray(Charsets.UTF_8)
                }

                override fun decode(bytes: ByteArray): String = bytes.toString(Charsets.UTF_8)
            }
            val store = AndroidKeystoreTokenStore(target, legacy, codec)

            assertThrows(IOException::class.java) { store.save("token-new") }

            assertFalse("A failed save must not create the target.", target.exists())
            assertEquals("token-legacy", legacy.readText(Charsets.UTF_8))
            assertFalse(
                "A failed save must not latch a readable legacy copy.",
                legacyMarkerFileFor(target).exists(),
            )
            assertEquals("token-legacy", store.load())
            assertEquals("token-legacy", target.readText(Charsets.UTF_8))
            assertFalse(legacy.exists())
            failEncoding = false
            store.save("token-new")
            assertEquals("token-new", store.load())
            assertFalse(legacy.exists())
        }
    }

    @Test
    fun aTransientReadAfterTheLegacyProbeAbortsBeforeTheMarker() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeText("token-target", Charsets.UTF_8)
            legacy.writeText("token-legacy", Charsets.UTF_8)
            var legacyReads = 0
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                PlainCodec(),
                readFile = { file ->
                    if (file == legacy) {
                        legacyReads += 1
                        if (legacyReads > 1) {
                            throw IOException("The legacy token is transiently unreadable.")
                        }
                    }
                    NioTokenFileReader.read(file)
                },
            )

            assertThrows(IOException::class.java) { store.save("token-new") }

            assertEquals("token-target", target.readText(Charsets.UTF_8))
            assertEquals("token-legacy", legacy.readText(Charsets.UTF_8))
            assertFalse(
                "A transient legacy read must not record a marker.",
                legacyMarkerFileFor(target).exists(),
            )
            assertEquals("token-target", store.load())
        }
    }

    @Test
    fun aSaveWithoutALegacyCopyDoesNotCreateAMarker() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            target.writeText("token-old", Charsets.UTF_8)
            val store = AndroidKeystoreTokenStore(target, legacy, PlainCodec())

            store.save("token-new")

            assertEquals("token-new", target.readText(Charsets.UTF_8))
            assertFalse("No legacy file means no supersession risk.", legacy.exists())
            assertFalse(
                "A save with no legacy copy must not create a marker.",
                legacyMarkerFileFor(target).exists(),
            )
        }
    }

    @Test
    fun aLegacyOnlyUpgradeMigratesWithoutAMarker() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(legacy.parentFile).mkdirs()
            legacy.writeText("token-legacy", Charsets.UTF_8)
            val store = AndroidKeystoreTokenStore(target, legacy, PlainCodec())

            assertEquals("token-legacy", store.load())

            assertEquals("token-legacy", target.readText(Charsets.UTF_8))
            assertFalse("The legacy copy is removed after the move.", legacy.exists())
            assertFalse(
                "A first legitimate migration must not record a marker.",
                legacyMarkerFileFor(target).exists(),
            )
        }
    }

    @Test
    fun aMarkerPreventsAMissingTargetFromUsingTheLegacyCopy() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            legacy.writeText("token-old", Charsets.UTF_8)
            LegacyTokenMarker.record(legacyMarkerFileFor(target))
            val store = AndroidKeystoreTokenStore(target, legacy, PlainCodec())

            assertNull(store.load())
            assertFalse("The stale legacy copy must not be moved.", target.exists())
            assertEquals("token-old", legacy.readText(Charsets.UTF_8))
            assertEquals(target, store.activeFile())
        }
    }

    @Test
    fun anInvalidMarkerStillBlocksTheLegacyCopy() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            legacy.writeText("token-old", Charsets.UTF_8)
            val marker = legacyMarkerFileFor(target)
            marker.writeText("tampered", Charsets.UTF_8)
            val store = AndroidKeystoreTokenStore(target, legacy, PlainCodec())

            assertNull(store.load())
            assertFalse("A tampered marker still fails closed.", target.exists())
            assertEquals("token-old", legacy.readText(Charsets.UTF_8))
        }
    }

    @Test
    fun aMarkerPreventsASaveFromSeedingAStaleLegacyCopy() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            legacy.writeText("token-old", Charsets.UTF_8)
            LegacyTokenMarker.record(legacyMarkerFileFor(target))
            val store = AndroidKeystoreTokenStore(target, legacy, TransientOnSaveCodec())

            assertThrows(TokenReadException::class.java) {
                store.save("token-transient")
            }

            assertFalse(
                "A marker means the stale legacy token must not be copied to the target.",
                target.exists(),
            )
            assertEquals("token-old", legacy.readText(Charsets.UTF_8))
            assertNull("A missing target stays missing after the marker.", store.load())
        }
    }

    @Test
    fun anUnknownMarkerStopsASaveThatWouldNeedALatch() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            legacy.writeText("token-old", Charsets.UTF_8)
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                TransientOnSaveCodec(),
                markerState = { LegacyMarkerState.UNKNOWN },
            )

            assertThrows(IOException::class.java) {
                store.save("token-transient")
            }

            assertFalse(
                "An unknown marker must not move a possibly stale legacy token.",
                target.exists(),
            )
            assertFalse(legacyMarkerFileFor(target).exists())
            assertEquals("token-old", legacy.readText())
        }
    }

    @Test
    fun anEqualTokenSaveDoesNotCreateAMarker() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeText("token-same", Charsets.UTF_8)
            legacy.writeText("token-same", Charsets.UTF_8)
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                ValidatingCodec(),
                deleteFile = { false },
            )

            store.save("token-same")

            assertEquals("token-same", target.readText(Charsets.UTF_8))
            assertTrue("The failed delete leaves the equal legacy copy.", legacy.isFile)
            assertFalse(
                "An equal legacy token is not stale and needs no marker.",
                legacyMarkerFileFor(target).exists(),
            )

            target.writeText("", Charsets.UTF_8)
            val corrupting = AndroidKeystoreTokenStore(
                target,
                legacy,
                ValidatingCodec(),
                deleteFile = { false },
            )
            assertEquals(
                "An equal legacy copy stays recoverable without a marker.",
                "token-same",
                corrupting.load(),
            )
        }
    }

    @Test
    fun aSaveKeepsWrongKeyLegacyCiphertextForEveryTargetState() {
        withDirectory { directory ->
            val oldKey = newAesKey()
            val presentCodec = aesCodec(newAesKey())
            for (targetState in listOf("absent", "readable", "corrupt")) {
                val root = File(directory, targetState).apply { mkdirs() }
                val target = File(root, "no-backup/source-token.bin")
                val legacy = File(root, "files/source-token.bin")
                requireNotNull(target.parentFile).mkdirs()
                requireNotNull(legacy.parentFile).mkdirs()
                when (targetState) {
                    "readable" -> target.writeBytes(presentCodec.encode("token-target"))
                    "corrupt" -> {
                        val corrupt = presentCodec.encode("token-target")
                        corrupt[corrupt.size - 1] =
                            (corrupt[corrupt.size - 1].toInt() xor 0x01).toByte()
                        target.writeBytes(corrupt)
                    }
                }
                val legacyBytes = aesCodec(oldKey).encode("token-legacy")
                legacy.writeBytes(legacyBytes)
                var legacyDeletes = 0
                val store = AndroidKeystoreTokenStore(
                    target,
                    legacy,
                    presentCodec,
                    deleteFile = { file ->
                        if (file == legacy) legacyDeletes += 1
                        file.delete()
                    },
                    appRoot = root,
                )

                store.save("token-new")

                assertEquals(
                    "The new target must be readable for $targetState.",
                    "token-new",
                    presentCodec.decode(target.readBytes()),
                )
                assertArrayEquals(
                    "A wrong-key legacy ciphertext must stay for $targetState.",
                    legacyBytes,
                    legacy.readBytes(),
                )
                assertTrue(
                    "The kept legacy copy must be marked stale for $targetState.",
                    legacyMarkerFileFor(target).isFile,
                )
                assertEquals(
                    "A potentially recoverable legacy ciphertext must not be deleted for $targetState.",
                    0,
                    legacyDeletes,
                )
                assertEquals("token-new", store.load())

                store.save("token-second")

                assertEquals(
                    "A second save must rotate the target for $targetState.",
                    "token-second",
                    presentCodec.decode(target.readBytes()),
                )
                assertArrayEquals(
                    "A second save must keep the wrong-key ciphertext for $targetState.",
                    legacyBytes,
                    legacy.readBytes(),
                )
                assertTrue(
                    "A second save keeps the one-way marker for $targetState.",
                    legacyMarkerFileFor(target).isFile,
                )
                assertEquals(0, legacyDeletes)
            }
        }
    }

    @Test
    fun aWrongKeyLegacyCopyCannotBecomeActiveAfterTheTargetIsGone() {
        withDirectory { directory ->
            val presentCodec = aesCodec(newAesKey())
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeBytes(presentCodec.encode("token-target"))
            val legacyBytes = aesCodec(newAesKey()).encode("token-legacy")
            legacy.writeBytes(legacyBytes)
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                presentCodec,
                appRoot = directory,
            )

            store.save("token-new")
            assertTrue("The marker is recorded before the target can change.", legacyMarkerFileFor(target).isFile)
            assertTrue(target.delete())

            assertNull("The marker blocks the stale legacy token.", store.load())
            assertEquals(target, store.activeFile())
            assertFalse("The stale legacy copy must not be moved.", target.exists())
            assertArrayEquals(legacyBytes, legacy.readBytes())
        }
    }

    @Test
    fun aLoadWithAReadableTargetKeepsAWrongKeyLegacyCopyAndRecordsTheMarker() {
        withDirectory { directory ->
            val presentCodec = aesCodec(newAesKey())
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeBytes(presentCodec.encode("token-target"))
            val legacyBytes = aesCodec(newAesKey()).encode("token-legacy")
            legacy.writeBytes(legacyBytes)
            val marker = legacyMarkerFileFor(target)
            var legacyDeletes = 0
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                presentCodec,
                deleteFile = { file ->
                    if (file == legacy) legacyDeletes += 1
                    file.delete()
                },
                appRoot = directory,
            )

            assertEquals("token-target", store.load())

            assertArrayEquals(
                "A wrong-key legacy ciphertext must stay after a load.",
                legacyBytes,
                legacy.readBytes(),
            )
            assertTrue("The kept copy needs the supersession latch.", marker.isFile)
            assertEquals("A load must not delete the legacy ciphertext.", 0, legacyDeletes)
            assertEquals(target, store.activeFile())

            assertTrue(target.delete())
            assertNull("The marker blocks the stale legacy token.", store.load())
            assertArrayEquals(legacyBytes, legacy.readBytes())
        }
    }

    @Test
    fun aLoadWithAReadableTargetKeepsATransientLegacyCopyAndRecordsTheMarker() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeText("token-target", Charsets.UTF_8)
            legacy.writeText("token-legacy", Charsets.UTF_8)
            val marker = legacyMarkerFileFor(target)
            var legacyDeletes = 0
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                PlainCodec(),
                deleteFile = { file ->
                    if (file == legacy) legacyDeletes += 1
                    file.delete()
                },
                readFile = { file ->
                    if (file == legacy) throw IOException("The legacy token is transiently unreadable.")
                    NioTokenFileReader.read(file)
                },
                appRoot = directory,
            )

            assertEquals("token-target", store.load())

            assertTrue("A transient legacy copy must stay.", legacy.isFile)
            assertEquals("token-legacy", legacy.readText(Charsets.UTF_8))
            assertTrue("The kept copy needs the supersession latch.", marker.isFile)
            assertEquals("A load must not delete the legacy ciphertext.", 0, legacyDeletes)
        }
    }

    @Test
    fun anUnknownMarkerStopsASaveAndALoadThatWouldKeepAWrongKeyLegacyCopy() {
        withDirectory { directory ->
            val presentCodec = aesCodec(newAesKey())
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            val targetBytes = presentCodec.encode("token-target")
            target.writeBytes(targetBytes)
            val legacyBytes = aesCodec(newAesKey()).encode("token-legacy")
            legacy.writeBytes(legacyBytes)
            val marker = legacyMarkerFileFor(target)
            var legacyDeletes = 0
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                presentCodec,
                deleteFile = { file ->
                    if (file == legacy) legacyDeletes += 1
                    file.delete()
                },
                markerState = { LegacyMarkerState.UNKNOWN },
                appRoot = directory,
            )

            val loadFailure = assertThrows(TokenReadException::class.java) { store.load() }
            assertEquals(TokenReadKind.TRANSIENT, loadFailure.kind)
            assertArrayEquals(targetBytes, target.readBytes())
            assertArrayEquals(legacyBytes, legacy.readBytes())
            assertFalse("An unknown marker must not be created.", marker.exists())
            assertEquals(0, legacyDeletes)

            assertThrows(IOException::class.java) { store.save("token-new") }

            assertArrayEquals(targetBytes, target.readBytes())
            assertArrayEquals(legacyBytes, legacy.readBytes())
            assertFalse("An unknown marker must not be created.", marker.exists())
            assertEquals(0, legacyDeletes)
        }
    }

    @Test
    fun aMarkerThatCannotBeRecordedStopsASaveThatWouldKeepAWrongKeyLegacyCopy() {
        withDirectory { directory ->
            val presentCodec = aesCodec(newAesKey())
            for (targetState in listOf("absent", "readable", "corrupt")) {
                val root = File(directory, targetState).apply { mkdirs() }
                val target = File(root, "no-backup/source-token.bin")
                val legacy = File(root, "files/source-token.bin")
                requireNotNull(target.parentFile).mkdirs()
                requireNotNull(legacy.parentFile).mkdirs()
                val targetBytes = when (targetState) {
                    "readable" -> presentCodec.encode("token-target")
                    "corrupt" -> {
                        val corrupt = presentCodec.encode("token-target")
                        corrupt[corrupt.size - 1] =
                            (corrupt[corrupt.size - 1].toInt() xor 0x01).toByte()
                        corrupt
                    }
                    else -> null
                }
                targetBytes?.let { target.writeBytes(it) }
                val legacyBytes = aesCodec(newAesKey()).encode("token-legacy")
                legacy.writeBytes(legacyBytes)
                val marker = legacyMarkerFileFor(target)
                var legacyDeletes = 0
                val store = AndroidKeystoreTokenStore(
                    target,
                    legacy,
                    presentCodec,
                    deleteFile = { file ->
                        if (file == legacy) legacyDeletes += 1
                        file.delete()
                    },
                    recordMarker = { throw IOException("The marker could not be written.") },
                    appRoot = root,
                )

                assertThrows(IOException::class.java) { store.save("token-new") }

                if (targetBytes != null) {
                    assertArrayEquals(
                        "A failed marker write must not replace the target for $targetState.",
                        targetBytes,
                        target.readBytes(),
                    )
                } else {
                    assertFalse("A failed marker write must not create the target.", target.exists())
                }
                assertArrayEquals(
                    "A failed marker write must not touch the legacy ciphertext for $targetState.",
                    legacyBytes,
                    legacy.readBytes(),
                )
                assertFalse("A failed marker write leaves no marker.", marker.exists())
                assertEquals(0, legacyDeletes)
            }
        }
    }

    @Test
    fun aMarkerThatCannotBeRecordedStopsALoadThatWouldKeepAWrongKeyLegacyCopy() {
        withDirectory { directory ->
            val presentCodec = aesCodec(newAesKey())
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            val targetBytes = presentCodec.encode("token-target")
            target.writeBytes(targetBytes)
            val legacyBytes = aesCodec(newAesKey()).encode("token-legacy")
            legacy.writeBytes(legacyBytes)
            val marker = legacyMarkerFileFor(target)
            var legacyDeletes = 0
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                presentCodec,
                deleteFile = { file ->
                    if (file == legacy) legacyDeletes += 1
                    file.delete()
                },
                recordMarker = { throw IOException("The marker could not be written.") },
                appRoot = directory,
            )

            val failure = assertThrows(TokenReadException::class.java) { store.load() }

            assertEquals(TokenReadKind.TRANSIENT, failure.kind)
            assertArrayEquals(targetBytes, target.readBytes())
            assertArrayEquals(legacyBytes, legacy.readBytes())
            assertFalse("A failed marker write leaves no marker.", marker.exists())
            assertEquals(0, legacyDeletes)
        }
    }

    @Test
    fun anEncodeFailureAfterAKeptWrongKeyLegacyCopyKeepsTheMarkerAndRetries() {
        withDirectory { directory ->
            val presentCodec = aesCodec(newAesKey())
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            val targetBytes = presentCodec.encode("token-target")
            target.writeBytes(targetBytes)
            val legacyBytes = aesCodec(newAesKey()).encode("token-legacy")
            legacy.writeBytes(legacyBytes)
            val marker = legacyMarkerFileFor(target)
            var failEncoding = true
            var legacyDeletes = 0
            val codec = object : TokenFileCodec {
                override fun encode(token: String): ByteArray {
                    if (failEncoding) throw IOException("injected encode failure")
                    return presentCodec.encode(token)
                }

                override fun decode(bytes: ByteArray): String = presentCodec.decode(bytes)
            }
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                codec,
                deleteFile = { file ->
                    if (file == legacy) legacyDeletes += 1
                    file.delete()
                },
                appRoot = directory,
            )

            assertThrows(IOException::class.java) { store.save("token-new") }

            assertTrue("The marker is durable before the target write.", marker.isFile)
            assertArrayEquals(targetBytes, target.readBytes())
            assertArrayEquals(legacyBytes, legacy.readBytes())
            assertEquals(0, legacyDeletes)

            failEncoding = false
            store.save("token-new")

            assertEquals("token-new", presentCodec.decode(target.readBytes()))
            assertArrayEquals(legacyBytes, legacy.readBytes())
            assertTrue("The marker is a one-way latch.", marker.isFile)
            assertEquals("The retry must not delete the kept ciphertext.", 0, legacyDeletes)
            assertEquals("token-new", store.load())
        }
    }

    @Test
    fun clearKeepsTheMarkerAsAOneWayLatch() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeText("token-target", Charsets.UTF_8)
            legacy.writeText("token-legacy", Charsets.UTF_8)
            val marker = legacyMarkerFileFor(target)
            LegacyTokenMarker.record(marker)
            val store = AndroidKeystoreTokenStore(target, legacy, PlainCodec())

            assertThrows(TokenDeleteException::class.java) { store.clear() }

            assertTrue(target.exists())
            assertTrue(legacy.exists())
            assertTrue("Clear keeps the one-way supersession latch.", marker.isFile)
            assertEquals("token-target", store.load())
        }
    }

    @Test
    fun transientLegacyBeforeMarkerKeepsTheOnlyToken() {
        withDirectory { directory ->
            for (corruptTarget in listOf(false, true)) {
                val target = File(directory, "target-$corruptTarget")
                val legacy = File(directory, "legacy-$corruptTarget")
                legacy.writeText("token-old")
                if (corruptTarget) target.writeText("corrupt")
                val store = AndroidKeystoreTokenStore(target, legacy, ValidatingCodec(),
                    readFile = { file ->
                        if (file == legacy) throw IOException("transient")
                        NioTokenFileReader.read(file)
                    })
                assertThrows(IOException::class.java) { store.save("token-new") }
                assertFalse(legacyMarkerFileFor(target).exists())
                assertEquals("token-old", legacy.readText())
            }
        }
    }

    @Test
    fun transientSupersededLegacyDoesNotBlockRotationOfReadableTarget() {
        withDirectory { directory ->
            val target = File(directory, "target")
            val legacy = File(directory, "legacy")
            target.writeText("token-current")
            legacy.writeText("token-stale")
            legacyMarkerFileFor(target).writeText("marker")
            val store = AndroidKeystoreTokenStore(target, legacy, PlainCodec(),
                readFile = { file ->
                    if (file == legacy) throw IOException("transient")
                    NioTokenFileReader.read(file)
                })
            store.save("token-new")
            assertEquals("token-new", target.readText())
            assertTrue("The transient legacy copy is potentially recoverable.", legacy.isFile)
            assertEquals("token-stale", legacy.readText())
            assertTrue("The marker stays a one-way latch.", legacyMarkerFileFor(target).isFile)
        }
    }

    @Test
    fun failedTargetDirectorySyncKeepsLegacyAndReportsUncertain() {
        withDirectory { directory ->
            val target = File(directory, "target")
            val legacy = File(directory, "legacy")
            target.writeText("token-old")
            legacy.writeText("token-legacy")
            val marker = legacyMarkerFileFor(target)
            var failSync = true
            val store = AndroidKeystoreTokenStore(target, legacy, PlainCodec(),
                syncTargetParent = { if (failSync) throw IOException("sync failed") })
            assertThrows(TokenWriteUncertainException::class.java) { store.save("token-new") }
            assertEquals("token-new", target.readText())
            assertEquals("token-legacy", legacy.readText())
            assertFalse(
                "An unconfirmed target must not be latched as authoritative.",
                marker.exists(),
            )
            assertThrows(TokenReadException::class.java) { store.load() }
            assertFalse("An unconfirmed target must not be latched.", marker.exists())
            failSync = false
            assertEquals("token-new", store.load())
            assertTrue("The load latches the kept old copy.", marker.isFile)
            assertTrue(legacy.exists())
        }
    }

    @Test
    fun markerShapesAndUnknownStateNeverPermitFallback() {
        withDirectory { directory ->
            val target = File(directory, "target")
            val legacy = File(directory, "legacy")
            legacy.writeText("token-old")
            val marker = legacyMarkerFileFor(target)
            marker.writeText("")
            assertEquals(LegacyMarkerState.PRESENT, LegacyTokenMarker.state(marker))
            val store = AndroidKeystoreTokenStore(target, legacy, PlainCodec())
            assertNull(store.load())
            marker.delete()
            marker.mkdir()
            assertEquals(LegacyMarkerState.PRESENT, LegacyTokenMarker.state(marker))
            assertNull(store.load())
            val unknown = AndroidKeystoreTokenStore(target, legacy, PlainCodec(),
                markerState = { LegacyMarkerState.UNKNOWN })
            assertThrows(TokenReadException::class.java) { unknown.load() }
            assertThrows(IOException::class.java) { unknown.save("token-new") }
            assertEquals("token-old", legacy.readText())
        }
    }

    private fun aesCodec(key: SecretKey): KeystoreTokenFileCodec =
        KeystoreTokenFileCodec(
            encryptionKey = { key },
            decryptionKey = { key },
            cipherFactory = { Cipher.getInstance("AES/GCM/NoPadding") },
        )

    private fun newAesKey(): SecretKey {
        val generator = KeyGenerator.getInstance("AES")
        generator.init(256)
        return generator.generateKey()
    }

    private class KindCodec : TokenFileCodec {
        override fun encode(token: String): ByteArray = token.toByteArray(Charsets.UTF_8)

        override fun decode(bytes: ByteArray): String {
            val value = bytes.toString(Charsets.UTF_8)
            return when (value) {
                "transient" -> throw TokenReadException(
                    "The source token key is not available.",
                    kind = TokenReadKind.TRANSIENT,
                )
                "corrupt" -> throw TokenReadException(
                    "The source token file is not valid.",
                    kind = TokenReadKind.CORRUPT,
                )
                else -> value
            }
        }
    }

    private class PlainCodec : TokenFileCodec {
        override fun encode(token: String): ByteArray = token.toByteArray(Charsets.UTF_8)

        override fun decode(bytes: ByteArray): String = bytes.toString(Charsets.UTF_8)
    }

    /** A codec that accepts only the test's token shape. */
    private class ValidatingCodec : TokenFileCodec {
        override fun encode(token: String): ByteArray = token.toByteArray(Charsets.UTF_8)

        override fun decode(bytes: ByteArray): String {
            val value = bytes.toString(Charsets.UTF_8)
            if (!value.startsWith("token-")) {
                throw TokenReadException(
                    "The source token file is not valid.",
                    kind = TokenReadKind.CORRUPT,
                )
            }
            return value
        }
    }

    /** A codec whose encode and decode disagree with the requested token. */
    private class SwappingCodec : TokenFileCodec {
        override fun encode(token: String): ByteArray =
            "token-other".toByteArray(Charsets.UTF_8)

        override fun decode(bytes: ByteArray): String {
            val value = bytes.toString(Charsets.UTF_8)
            if (value == "corrupt") {
                throw TokenReadException(
                    "The source token file is not valid.",
                    kind = TokenReadKind.CORRUPT,
                )
            }
            return value
        }
    }

    /** A codec that reports a transient failure for one token value. */
    private class TransientOnSaveCodec : TokenFileCodec {
        override fun encode(token: String): ByteArray = token.toByteArray(Charsets.UTF_8)

        override fun decode(bytes: ByteArray): String {
            val value = bytes.toString(Charsets.UTF_8)
            return when (value) {
                "corrupt" -> throw TokenReadException(
                    "The source token file is not valid.",
                    kind = TokenReadKind.CORRUPT,
                )
                "token-transient" -> throw TokenReadException(
                    "The source token key is not available.",
                    kind = TokenReadKind.TRANSIENT,
                )
                else -> value
            }
        }
    }

    private fun withDirectory(block: (File) -> Unit) {
        val directory = Files.createTempDirectory("hotspotshade-token-test").toFile()
        try {
            block(directory)
        } finally {
            directory.deleteRecursively()
        }
    }
}
