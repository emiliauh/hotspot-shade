package com.hotspotshade.source

import java.io.File
import java.io.IOException
import java.nio.file.Files
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
 * Focused tests for the token-store failed-save and recovery policy.
 *
 * These tests use temporary directories and plain or AES keys. They touch no
 * device, no Keystore, no route, and no network. Every token value is a fixed
 * public test value.
 */
class TokenStoreRecoveryPolicyTest {
    @Test
    fun aFailedSaveOfTheRequestedLegacyTokenKeepsThatCopyAndLatchesItOnLoad() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeText("token-old", Charsets.UTF_8)
            legacy.writeText("token-new", Charsets.UTF_8)
            val marker = legacyMarkerFileFor(target)
            val codec = FailingEncodeCodec()
            val store = AndroidKeystoreTokenStore(target, legacy, codec)

            assertThrows(IOException::class.java) { store.save("token-new") }

            assertEquals(
                "A failed save must leave the readable target active.",
                "token-old",
                target.readText(Charsets.UTF_8),
            )
            assertTrue(
                "The requested legacy token must not be lost.",
                legacy.isFile,
            )
            assertEquals("token-new", legacy.readText(Charsets.UTF_8))
            assertFalse(
                "A save that never changed the target must not latch the legacy copy.",
                marker.exists(),
            )
            assertEquals(
                "The readable target still wins, but the legacy copy is kept.",
                "token-old",
                store.load(),
            )
            assertTrue(
                "A later load must not delete the requested legacy token.",
                legacy.isFile,
            )
            assertTrue(
                "The load latches the kept requested copy before returning.",
                marker.isFile,
            )

            codec.fail = false
            store.save("token-new")

            assertEquals("token-new", target.readText(Charsets.UTF_8))
            assertFalse("The successful retry removes the legacy copy.", legacy.exists())
            assertEquals("token-new", store.load())
        }
    }

    @Test
    fun aMarkerAndAbsentTargetKeepAnEqualRequestedTokenForARetry() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            legacy.writeText("token-new", Charsets.UTF_8)
            val marker = legacyMarkerFileFor(target)
            LegacyTokenMarker.record(marker)
            val codec = FailingEncodeCodec()
            val store = AndroidKeystoreTokenStore(target, legacy, codec)

            assertThrows(IOException::class.java) { store.save("token-new") }

            assertFalse("A failed save must not create the target.", target.exists())
            assertEquals("token-new", legacy.readText(Charsets.UTF_8))
            assertTrue(marker.isFile)
            assertNull(
                "The marker keeps a missing target missing instead of moving legacy.",
                store.load(),
            )
            assertTrue("The requested token stays for the retry.", legacy.isFile)

            codec.fail = false
            store.save("token-new")

            assertEquals("token-new", target.readText(Charsets.UTF_8))
            assertFalse(legacy.exists())
            assertEquals("token-new", store.load())
        }
    }

    @Test
    fun aRecordedMarkerAndAbsentTargetKeepCorruptLegacyCiphertextAndReportMissing() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(legacy.parentFile).mkdirs()
            legacy.writeText("corrupt", Charsets.UTF_8)
            val marker = legacyMarkerFileFor(target)
            val codec = FailingEncodeCodec(TokenOnlyCodec())
            val store = AndroidKeystoreTokenStore(target, legacy, codec)

            // An unreadable legacy copy is latched before the target changes.
            // The encode failure then leaves the target absent, so the latch is
            // the only record that the ciphertext is not the active token.
            val failure = assertThrows(IOException::class.java) { store.save("token-new") }

            assertFalse(
                "A latch before the target write is an ordinary failure.",
                failure is TokenWriteUncertainException,
            )
            assertFalse("A failed save must not create the target.", target.exists())
            assertEquals("The ambiguous ciphertext is preserved.", "corrupt", legacy.readText(Charsets.UTF_8))
            assertTrue("The unreadable legacy copy is latched.", marker.isFile)

            assertNull(
                "A present latch makes a missing target a missing token, not the old ciphertext.",
                store.load(),
            )
            assertFalse("The load must not seed the target from latched bytes.", target.exists())
            assertEquals("corrupt", legacy.readText(Charsets.UTF_8))

            codec.fail = false
            store.save("token-new")

            assertEquals("token-new", target.readText(Charsets.UTF_8))
            assertEquals("token-new", store.load())
            assertEquals(
                "A corrupt legacy copy is kept for recovery, not deleted.",
                "corrupt",
                legacy.readText(Charsets.UTF_8),
            )
        }
    }

    @Test
    fun aMarkerAndReadableTargetKeepADifferentRequestedCopyAfterAFailedSave() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeText("token-old", Charsets.UTF_8)
            legacy.writeText("token-new", Charsets.UTF_8)
            val marker = legacyMarkerFileFor(target)
            LegacyTokenMarker.record(marker)
            val codec = FailingEncodeCodec()
            val store = AndroidKeystoreTokenStore(target, legacy, codec)

            assertThrows(IOException::class.java) { store.save("token-new") }

            assertEquals("token-old", target.readText(Charsets.UTF_8))
            assertEquals("token-new", legacy.readText(Charsets.UTF_8))
            assertTrue(marker.isFile)
            assertEquals("token-old", store.load())
            assertTrue(
                "A differing latched copy is kept after the failed save.",
                legacy.isFile,
            )

            codec.fail = false
            store.save("token-new")

            assertEquals("token-new", target.readText(Charsets.UTF_8))
            assertFalse(legacy.exists())
            assertEquals("token-new", store.load())
        }
    }

    @Test
    fun aMarkerAndAbsentTargetRetryADifferentTokenWithoutMovingTheLegacy() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            legacy.writeText("token-old", Charsets.UTF_8)
            val marker = legacyMarkerFileFor(target)
            LegacyTokenMarker.record(marker)
            val codec = FailingEncodeCodec()
            val store = AndroidKeystoreTokenStore(target, legacy, codec)

            assertThrows(IOException::class.java) { store.save("token-new") }

            assertFalse(
                "A present marker must not move a stale legacy token into an absent target.",
                target.exists(),
            )
            assertEquals("token-old", legacy.readText(Charsets.UTF_8))
            assertNull("A present marker must not move the stale legacy token.", store.load())

            codec.fail = false
            store.save("token-new")

            assertEquals("token-new", target.readText(Charsets.UTF_8))
            assertFalse(legacy.exists())
            assertEquals("token-new", store.load())
        }
    }

    @Test
    fun anAbsentTargetReadableLegacySurvivesAFailedSaveWithoutAMarker() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(legacy.parentFile).mkdirs()
            legacy.writeText("token-new", Charsets.UTF_8)
            val marker = legacyMarkerFileFor(target)
            val codec = FailingEncodeCodec()
            val store = AndroidKeystoreTokenStore(target, legacy, codec)

            assertThrows(IOException::class.java) { store.save("token-new") }

            assertFalse(target.exists())
            assertFalse(
                "A readable legacy copy is latched only after the target is confirmed.",
                marker.exists(),
            )
            assertEquals(
                "The load migrates the requested equal token into the absent target.",
                "token-new",
                store.load(),
            )
            assertEquals(target, store.activeFile())
            assertTrue(target.isFile)
            assertFalse(legacy.exists())
            assertEquals("token-new", store.load())
        }
    }

    @Test
    fun aCorruptTargetReadableLegacySurvivesAFailedSaveWithoutAMarker() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeText("corrupt", Charsets.UTF_8)
            legacy.writeText("token-new", Charsets.UTF_8)
            val marker = legacyMarkerFileFor(target)
            val codec = FailingEncodeCodec(TokenOnlyCodec())
            val store = AndroidKeystoreTokenStore(target, legacy, codec)

            assertThrows(IOException::class.java) { store.save("token-new") }

            assertEquals(
                "The corrupt target must stay unchanged after the failed save.",
                "corrupt",
                target.readText(Charsets.UTF_8),
            )
            assertFalse(
                "A readable legacy copy is latched only after the target is confirmed.",
                marker.exists(),
            )
            assertEquals(
                "The readable legacy token still wins over the corrupt target.",
                "token-new",
                store.load(),
            )
            assertTrue(legacy.isFile)
            assertEquals("corrupt", target.readText(Charsets.UTF_8))
        }
    }

    @Test
    fun aMarkerAndCorruptTargetKeepAnEqualLegacyForARetry() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeText("corrupt", Charsets.UTF_8)
            legacy.writeText("token-new", Charsets.UTF_8)
            val marker = legacyMarkerFileFor(target)
            LegacyTokenMarker.record(marker)
            val codec = FailingEncodeCodec(TokenOnlyCodec())
            val store = AndroidKeystoreTokenStore(target, legacy, codec)

            assertThrows(IOException::class.java) { store.save("token-new") }

            assertEquals("corrupt", target.readText(Charsets.UTF_8))
            assertEquals("token-new", legacy.readText(Charsets.UTF_8))
            val failure = assertThrows(TokenReadException::class.java) { store.load() }
            assertEquals(
                "The marker keeps the corrupt target authoritative.",
                TokenReadKind.CORRUPT,
                failure.kind,
            )
            assertTrue("The equal legacy copy stays for the retry.", legacy.isFile)

            codec.fail = false
            store.save("token-new")

            assertEquals("token-new", target.readText(Charsets.UTF_8))
            assertFalse(legacy.exists())
            assertEquals("token-new", store.load())
        }
    }

    @Test
    fun aFailedSaveKeepsTheReadableLegacyUsableOverACorruptTarget() {
        withDirectory { directory ->
            val presentCodec = aesCodec(newAesKey())
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            val ambiguous = aesCodec(newAesKey()).encode("token-ambiguous")
            target.writeBytes(ambiguous)
            legacy.writeBytes(presentCodec.encode("token-legacy"))
            val marker = legacyMarkerFileFor(target)
            val codec = FailingEncodeCodec(presentCodec)
            val store = AndroidKeystoreTokenStore(target, legacy, codec, appRoot = directory)

            assertThrows(IOException::class.java) { store.save("token-new") }

            assertArrayEquals(
                "A failed save must not replace the ambiguous target.",
                ambiguous,
                target.readBytes(),
            )
            assertEquals(
                "The readable legacy copy must stay.",
                "token-legacy",
                presentCodec.decode(legacy.readBytes()),
            )
            assertFalse(
                "A failed save before the target write must not latch the readable copy.",
                marker.exists(),
            )
            assertEquals(
                "The only readable token must remain usable after the failed save.",
                "token-legacy",
                store.load(),
            )
            assertArrayEquals("The load must not change the target.", ambiguous, target.readBytes())
            assertTrue("The load keeps the readable legacy copy.", legacy.isFile)

            codec.fail = false
            store.save("token-new")

            assertEquals("token-new", presentCodec.decode(target.readBytes()))
            assertTrue("The confirmed save latches the old readable copy.", marker.isFile)
            assertFalse("The successful save removes the readable legacy copy.", legacy.exists())
            assertEquals("token-new", store.load())
        }
    }

    @Test
    fun aFailedLatchAfterACorruptTargetIsReplacedKeepsBothTokensAndFailsClosed() {
        withDirectory { directory ->
            val presentCodec = aesCodec(newAesKey())
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            val ambiguous = aesCodec(newAesKey()).encode("token-ambiguous")
            target.writeBytes(ambiguous)
            legacy.writeBytes(presentCodec.encode("token-legacy"))
            val marker = legacyMarkerFileFor(target)
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                presentCodec,
                recordMarker = { throw IOException("The marker could not be written.") },
                appRoot = directory,
            )

            assertThrows(IOException::class.java) { store.save("token-new") }

            assertEquals(
                "The verified replacement is written only after its bytes are confirmed.",
                "token-new",
                presentCodec.decode(target.readBytes()),
            )
            assertEquals(
                "The readable old copy is kept.",
                "token-legacy",
                presentCodec.decode(legacy.readBytes()),
            )
            assertFalse("A failed latch leaves no marker.", marker.exists())
            val failure = assertThrows(TokenReadException::class.java) { store.load() }
            assertEquals(
                "An unlatched differing copy must not be returned as authoritative.",
                TokenReadKind.TRANSIENT,
                failure.kind,
            )
            assertEquals("token-new", presentCodec.decode(target.readBytes()))
            assertEquals("token-legacy", presentCodec.decode(legacy.readBytes()))
        }
    }

    @Test
    fun aCorruptTargetWithoutALegacyCopyIsPreservedByAFailedSave() {
        withDirectory { directory ->
            val presentCodec = aesCodec(newAesKey())
            val target = File(directory, "no-backup/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            val ambiguous = aesCodec(newAesKey()).encode("token-ambiguous")
            target.writeBytes(ambiguous)
            val codec = FailingEncodeCodec(presentCodec)
            val store = AndroidKeystoreTokenStore(target, codec = codec, appRoot = directory)

            assertThrows(IOException::class.java) { store.save("token-new") }

            assertArrayEquals(ambiguous, target.readBytes())
            assertThrows(TokenReadException::class.java) { store.load() }
            assertArrayEquals("A load must not change the ambiguous target.", ambiguous, target.readBytes())
        }
    }

    @Test
    fun anUnusableTargetFallsBackToAUsableLegacyAndASaveRepairsTheTarget() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeText("bad token", Charsets.UTF_8)
            legacy.writeText("token-legacy", Charsets.UTF_8)
            val marker = legacyMarkerFileFor(target)
            val store = AndroidKeystoreTokenStore(target, legacy, PlainCodec())

            assertFalse(isUsableSourceToken("bad token"))
            assertEquals(
                "An unusable target must not hide the only usable token.",
                "token-legacy",
                store.load(),
            )
            assertEquals(legacy, store.activeFile())
            assertTrue("The unusable target is kept for inspection.", target.isFile)
            assertTrue("The usable legacy copy must stay.", legacy.isFile)

            store.save("token-new")

            assertEquals("token-new", target.readText(Charsets.UTF_8))
            assertFalse(legacy.exists())
            assertTrue("A readable legacy copy is latched after the repair is confirmed.", marker.isFile)
            assertEquals("token-new", store.load())
        }
    }

    @Test
    fun anUnusableStoredTokenIsUnreadableNotMissing() {
        withDirectory { directory ->
            for (value in listOf("bad token", "a".repeat(256), "tab\there")) {
                val target = File(directory, "target-${value.hashCode()}")
                target.writeText(value, Charsets.UTF_8)
                val store = AndroidKeystoreTokenStore(target, codec = PlainCodec())

                val failure = assertThrows(TokenReadException::class.java) { store.load() }

                assertEquals(
                    "An unusable value is corrupt, not transient.",
                    TokenReadKind.CORRUPT,
                    failure.kind,
                )
                assertEquals(target, store.activeFile())
                assertEquals(value, target.readText(Charsets.UTF_8))
            }
        }
    }

    @Test
    fun anUnusableLegacyCopyIsNotMovedOrTreatedAsMissing() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(legacy.parentFile).mkdirs()
            legacy.writeText("bad token", Charsets.UTF_8)
            val store = AndroidKeystoreTokenStore(target, legacy, PlainCodec())

            val failure = assertThrows(TokenReadException::class.java) { store.load() }

            assertEquals(TokenReadKind.CORRUPT, failure.kind)
            assertEquals(legacy, store.activeFile())
            assertFalse("An unusable legacy value must not be moved.", target.exists())
            assertEquals("bad token", legacy.readText(Charsets.UTF_8))
        }
    }

    @Test
    fun aMarkerKeepsAUsableLegacyCopyLatchedOffBehindAnUnusableTarget() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeText("bad token", Charsets.UTF_8)
            legacy.writeText("token-legacy", Charsets.UTF_8)
            val marker = legacyMarkerFileFor(target)
            LegacyTokenMarker.record(marker)
            val store = AndroidKeystoreTokenStore(target, legacy, PlainCodec())

            val failure = assertThrows(TokenReadException::class.java) { store.load() }

            assertEquals(TokenReadKind.CORRUPT, failure.kind)
            assertEquals(target, store.activeFile())
            assertEquals("bad token", target.readText(Charsets.UTF_8))
            assertTrue("The marker must not delete the legacy copy.", legacy.isFile)
            assertEquals("token-legacy", legacy.readText(Charsets.UTF_8))
        }
    }

    @Test
    fun anUnknownMarkerFailsClosedAndALaterAbsentMarkerCannotReactivateTheLegacy() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeText("token-target", Charsets.UTF_8)
            legacy.writeText("token-legacy", Charsets.UTF_8)
            val marker = legacyMarkerFileFor(target)
            var markerNow = LegacyMarkerState.UNKNOWN
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                PlainCodec(),
                markerState = {
                    if (markerNow == LegacyMarkerState.UNKNOWN) {
                        LegacyMarkerState.UNKNOWN
                    } else {
                        LegacyTokenMarker.state(marker)
                    }
                },
            )

            val failure = assertThrows(TokenReadException::class.java) { store.load() }

            assertEquals(
                "An unclassifiable latch must not return an unlatched target.",
                TokenReadKind.TRANSIENT,
                failure.kind,
            )
            assertTrue("Cleanup without a classified marker must not delete.", legacy.isFile)
            assertEquals("token-legacy", legacy.readText(Charsets.UTF_8))
            assertFalse("An unknown marker must not be created.", marker.exists())

            markerNow = LegacyMarkerState.ABSENT
            assertEquals(
                "A later classified marker latches the differing copy.",
                "token-target",
                store.load(),
            )
            assertTrue("The load records the latch.", marker.isFile)
            assertTrue("The differing copy is kept for recovery.", legacy.isFile)

            assertTrue(target.delete())
            assertNull(
                "A target loss after the latch must not reactivate the old copy.",
                store.load(),
            )
            assertEquals("token-legacy", legacy.readText(Charsets.UTF_8))
        }
    }

    @Test
    fun aFailedLegacyDirectorySyncDoesNotFailTheSaveOrUnlatchTheMarker() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeText("token-target", Charsets.UTF_8)
            legacy.writeText("token-legacy", Charsets.UTF_8)
            val marker = legacyMarkerFileFor(target)
            var legacySyncs = 0
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                PlainCodec(),
                syncLegacyParent = {
                    legacySyncs += 1
                    throw IOException("The legacy directory could not be synced.")
                },
            )

            store.save("token-new")

            assertEquals("token-new", target.readText(Charsets.UTF_8))
            assertFalse("The visible legacy entry is deleted.", legacy.exists())
            assertTrue("The marker is durable before the legacy cleanup.", marker.isFile)
            assertEquals(1, legacySyncs)
            assertEquals("token-new", store.load())

            // Simulate a power loss that restores the entry whose deletion was
            // not synced. The marker keeps a different old copy from becoming
            // active after the target is gone.
            legacy.writeText("token-legacy", Charsets.UTF_8)
            assertTrue(target.delete())
            assertNull("A latched old copy must not become active.", store.load())
            assertTrue(legacy.isFile)
        }
    }

    @Test
    fun aDifferingReadableLegacyWithoutAMarkerIsLatchedAndKeptNotDeleted() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeText("token-target", Charsets.UTF_8)
            legacy.writeText("token-legacy", Charsets.UTF_8)
            val marker = legacyMarkerFileFor(target)
            var deletes = 0
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                PlainCodec(),
                deleteFile = { file -> deletes += 1; file.delete() },
            )

            assertEquals("token-target", store.load())

            assertEquals("A load must not delete a differing readable copy.", 0, deletes)
            assertTrue("The differing copy is kept for recovery.", legacy.isFile)
            assertEquals("token-legacy", legacy.readText(Charsets.UTF_8))
            assertTrue("The kept copy is latched before the target is returned.", marker.isFile)

            // A failed save once requested that legacy token. Losing the target
            // must not make the kept copy active.
            assertTrue(target.delete())
            assertNull("The latch blocks the kept copy.", store.load())
            assertEquals("token-legacy", legacy.readText(Charsets.UTF_8))
        }
    }

    @Test
    fun anEqualLegacyCopyWhoseDeleteWasNotSyncedIsRemovedAgainOnTheNextLoad() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeText("token-same", Charsets.UTF_8)
            legacy.writeText("token-same", Charsets.UTF_8)
            var failSync = true
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                PlainCodec(),
                syncLegacyParent = {
                    if (failSync) throw IOException("The legacy directory could not be synced.")
                    syncTokenParent(it)
                },
            )

            assertEquals("token-same", store.load())
            assertFalse("The equal copy is removed after the target decodes.", legacy.exists())

            // Simulate a power loss that restores the entry whose deletion was
            // not synced. The copy is equal, so removing it is safe.
            legacy.writeText("token-same", Charsets.UTF_8)
            failSync = false
            assertEquals("token-same", store.load())
            assertFalse("The next load removes the restored equal copy.", legacy.exists())
        }
    }

    @Test
    fun aDurableMarkerSkipsTheTargetSyncOnLoad() {
        withDirectory { directory ->
            val presentCodec = aesCodec(newAesKey())
            for (legacyKind in listOf("differing", "corrupt")) {
                val root = File(directory, legacyKind).apply { mkdirs() }
                val target = File(root, "no-backup/source-token.bin")
                val legacy = File(root, "files/source-token.bin")
                requireNotNull(target.parentFile).mkdirs()
                requireNotNull(legacy.parentFile).mkdirs()
                target.writeBytes(presentCodec.encode("token-target"))
                val legacyBytes = if (legacyKind == "differing") {
                    presentCodec.encode("token-legacy")
                } else {
                    // A wrong-key ciphertext classifies as corrupt and is kept.
                    aesCodec(newAesKey()).encode("token-legacy")
                }
                legacy.writeBytes(legacyBytes)
                val marker = legacyMarkerFileFor(target)
                LegacyTokenMarker.record(marker)
                var targetSyncs = 0
                val store = AndroidKeystoreTokenStore(
                    target,
                    legacy,
                    presentCodec,
                    syncTargetParent = {
                        targetSyncs += 1
                        throw IOException("A durable marker must not need a target sync.")
                    },
                    appRoot = root,
                )

                assertEquals(
                    "The readable target wins for $legacyKind.",
                    "token-target",
                    store.load(),
                )

                assertEquals(
                    "A durable marker already holds the kept copy off for $legacyKind.",
                    0,
                    targetSyncs,
                )
                assertTrue("The marker stays a one-way latch for $legacyKind.", marker.isFile)
                assertArrayEquals(legacyBytes, legacy.readBytes())

                assertTrue(target.delete())
                assertNull(
                    "The durable latch still blocks the kept copy for $legacyKind.",
                    store.load(),
                )
                assertEquals(0, targetSyncs)
                assertArrayEquals(legacyBytes, legacy.readBytes())
            }
        }
    }

    @Test
    fun aNewLatchRequiresTheTargetSyncAndFailsClosedWhenItFails() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeText("token-target", Charsets.UTF_8)
            legacy.writeText("token-legacy", Charsets.UTF_8)
            val marker = legacyMarkerFileFor(target)
            var targetSyncs = 0
            val failing = AndroidKeystoreTokenStore(
                target,
                legacy,
                PlainCodec(),
                syncTargetParent = {
                    targetSyncs += 1
                    throw IOException("The target directory could not be synced.")
                },
            )

            val failure = assertThrows(TokenReadException::class.java) { failing.load() }

            assertEquals(TokenReadKind.TRANSIENT, failure.kind)
            assertEquals("A new latch requires one target sync.", 1, targetSyncs)
            assertFalse("A failed target sync must not latch.", marker.exists())
            assertEquals("token-target", target.readText(Charsets.UTF_8))
            assertEquals("token-legacy", legacy.readText(Charsets.UTF_8))

            val working = AndroidKeystoreTokenStore(target, legacy, PlainCodec())
            assertEquals("A confirmed target latches the kept copy.", "token-target", working.load())
            assertTrue(marker.isFile)
            assertTrue(legacy.isFile)
            assertTrue(target.delete())
            assertNull("The latch blocks the kept copy.", working.load())
            assertEquals("token-legacy", legacy.readText(Charsets.UTF_8))
        }
    }

    @Test
    fun aReadableTargetWithoutALegacyCopyDoesNotSyncOnLoad() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            target.writeText("token-target", Charsets.UTF_8)
            var targetSyncs = 0
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                PlainCodec(),
                syncTargetParent = {
                    targetSyncs += 1
                    throw IOException("A read with no legacy copy must not sync.")
                },
            )

            assertEquals("token-target", store.load())

            assertEquals("A read of a visible target adds no durability.", 0, targetSyncs)
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

    private class PlainCodec : TokenFileCodec {
        override fun encode(token: String): ByteArray = token.toByteArray(Charsets.UTF_8)

        override fun decode(bytes: ByteArray): String = bytes.toString(Charsets.UTF_8)
    }

    private class TokenOnlyCodec : TokenFileCodec {
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

    private class FailingEncodeCodec(
        private val delegate: TokenFileCodec = PlainCodec(),
    ) : TokenFileCodec {
        var fail = true

        override fun encode(token: String): ByteArray {
            if (fail) throw IOException("injected encode failure")
            return delegate.encode(token)
        }

        override fun decode(bytes: ByteArray): String = delegate.decode(bytes)
    }

    private fun withDirectory(block: (File) -> Unit) {
        val directory = Files.createTempDirectory("hotspotshade-token-recovery").toFile()
        try {
            block(directory)
        } finally {
            directory.deleteRecursively()
        }
    }
}
