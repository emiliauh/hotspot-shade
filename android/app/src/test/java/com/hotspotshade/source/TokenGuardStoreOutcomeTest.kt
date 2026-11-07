package com.hotspotshade.source

import java.io.File
import java.io.IOException
import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Outcome-level tests for the source token store behind the token guard.
 *
 * Each test uses the real [AndroidKeystoreTokenStore] over a temporary
 * directory and a fresh [SourceTokenGuard]. The tests prove which exception
 * the save path reports and how the guard epoch reacts to it. They touch no
 * device, no Keystore, no route, and no network. Every token value is a fixed
 * public test value.
 */
class TokenGuardStoreOutcomeTest {
    @Test
    fun aFailedMarkerBeforeTheTargetWriteKeepsTheEpochAndTheOldState() {
        withStore { target, legacy, marker ->
            // An unusable legacy value classifies as corrupt, so the store
            // latches it before it writes the target.
            legacy.writeText("bad token", Charsets.UTF_8)
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                PlainCodec(),
                recordMarker = { throw IOException("The marker could not be written.") },
            )
            val guard = SourceTokenGuard()
            val epoch = guard.epoch()

            val direct = assertThrows(IOException::class.java) { store.save("token-new") }

            assertFalse(
                "A marker failure before the target changes is an ordinary failure.",
                direct is TokenWriteUncertainException,
            )
            assertFalse("A failed save must not create the target.", target.exists())
            assertEquals("bad token", legacy.readText(Charsets.UTF_8))
            assertFalse(marker.exists())

            assertEquals(TokenMutationResult.FAILED, guard.rotate { store.save("token-new") })
            assertEquals("A pre-write failure must not move the epoch.", epoch, guard.epoch())
            assertTrue(
                "A pairing result from the same epoch is still current.",
                guard.savePairingToken(epoch) { },
            )
        }
    }

    @Test
    fun anUncertainMarkerBeforeTheTargetWriteRemainsAnOrdinarySaveFailure() {
        withStore { target, legacy, marker ->
            legacy.writeText("bad token", Charsets.UTF_8)
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                PlainCodec(),
                recordMarker = { file ->
                    LegacyTokenMarker.recordWithParentSync(file) {
                        throw IOException("The marker directory could not be synced.")
                    }
                },
            )
            val guard = SourceTokenGuard()
            val epoch = guard.epoch()
            var failure: IOException? = null

            val result = guard.rotate {
                try {
                    store.save("token-new")
                } catch (error: IOException) {
                    failure = error
                    throw error
                }
            }

            assertEquals(TokenMutationResult.FAILED, result)
            assertTrue("The store must report the failed marker write.", failure != null)
            assertFalse("The target has not changed, so this is not an uncertain token write.",
                failure is TokenWriteUncertainException)
            assertTrue("The real marker write reported uncertainty after its rename.",
                failure?.cause is TokenWriteUncertainException)
            assertTrue("The marker rename happened before the failed parent sync.", marker.isFile)
            assertFalse("The target was never written.", target.exists())
            assertEquals("bad token", legacy.readText(Charsets.UTF_8))
            assertEquals("The pre-target failure must not move the epoch.", epoch, guard.epoch())
            assertTrue(guard.savePairingToken(epoch) { })
        }
    }

    @Test
    fun aFailedMarkerAfterTheTargetWriteIsUncertainAndMovesTheEpoch() {
        withStore { target, legacy, marker ->
            target.writeText("token-old", Charsets.UTF_8)
            legacy.writeText("token-legacy", Charsets.UTF_8)
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                PlainCodec(),
                recordMarker = { throw IOException("The marker could not be written.") },
            )
            val guard = SourceTokenGuard()
            val epoch = guard.epoch()

            assertThrows(TokenWriteUncertainException::class.java) { store.save("token-new") }

            assertEquals(
                "The visible target may already hold the requested token.",
                "token-new",
                target.readText(Charsets.UTF_8),
            )
            assertEquals(
                "The old readable copy is kept, not latched off silently.",
                "token-legacy",
                legacy.readText(Charsets.UTF_8),
            )
            assertFalse("A failed marker leaves no marker.", marker.exists())

            assertEquals(
                "A marker failure after the target changed is an uncertain write.",
                TokenMutationResult.FAILED,
                guard.rotate { store.save("token-new-2") },
            )
            assertTrue(
                "An uncertain rotation must move the epoch.",
                guard.epoch() > epoch,
            )
            assertFalse(
                "A pairing result from the old epoch must not be saved.",
                guard.savePairingToken(epoch) { throw AssertionError("stale write") },
            )
            val loadFailure = assertThrows(TokenReadException::class.java) { store.load() }
            assertEquals(
                "An unlatched differing copy must fail closed until the latch exists.",
                TokenReadKind.TRANSIENT,
                loadFailure.kind,
            )
        }
    }

    @Test
    fun anEqualTokenPairingSaveNeedsNoMarkerAndKeepsTheEpoch() {
        withStore { target, legacy, marker ->
            target.writeText("token-same", Charsets.UTF_8)
            legacy.writeText("token-same", Charsets.UTF_8)
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                PlainCodec(),
                recordMarker = { throw IOException("An equal token must not need a marker.") },
            )
            val guard = SourceTokenGuard()
            val epoch = guard.epoch()

            assertTrue(
                "An equal token is a safe rewrite and needs no marker.",
                guard.savePairingToken(epoch) { store.save("token-same") },
            )

            assertEquals("A safe equal save must not move the epoch.", epoch, guard.epoch())
            assertEquals("token-same", target.readText(Charsets.UTF_8))
            assertFalse("The equal legacy copy is safe to remove.", legacy.exists())
            assertFalse("An equal token save must not create a marker.", marker.exists())
            assertEquals("token-same", store.load())
        }
    }

    @Test
    fun anEqualTokenRotationIsWrittenWhenTheLegacyDeleteFails() {
        withStore { target, legacy, marker ->
            target.writeText("token-same", Charsets.UTF_8)
            legacy.writeText("token-same", Charsets.UTF_8)
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                PlainCodec(),
                deleteFile = { false },
                recordMarker = { throw IOException("An equal token must not need a marker.") },
            )
            val guard = SourceTokenGuard()
            val epoch = guard.epoch()

            assertEquals(
                TokenMutationResult.WRITTEN,
                guard.rotate { store.save("token-same") },
            )

            assertTrue("A completed write moves the epoch.", guard.epoch() > epoch)
            assertEquals("token-same", target.readText(Charsets.UTF_8))
            assertTrue("A failed equal-copy delete leaves the copy for a retry.", legacy.isFile)
            assertFalse("An equal token save must not create a marker.", marker.exists())
            assertEquals("token-same", store.load())
        }
    }

    @Test
    fun anUncertainPairingSaveMovesTheEpochAndDropsTheOldResult() {
        withStore { target, legacy, marker ->
            // An equal token repair still rewrites the target. A failed target
            // directory sync after the rename is a post-write uncertain save.
            target.writeText("token-same", Charsets.UTF_8)
            legacy.writeText("token-same", Charsets.UTF_8)
            var failSync = true
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                PlainCodec(),
                syncTargetParent = { file ->
                    if (failSync) throw IOException("The target directory could not be synced.")
                    syncTokenParent(file)
                },
            )
            val guard = SourceTokenGuard()
            var notifications = 0
            guard.addEpochListener { notifications += 1 }
            val epoch = guard.epoch()

            assertFalse(
                "An uncertain repair must not report a saved pairing.",
                guard.savePairingToken(epoch) { store.save("token-same") },
            )

            assertEquals("token-same", target.readText(Charsets.UTF_8))
            assertEquals(
                "The legacy copy stays until the target directory is synced.",
                "token-same",
                legacy.readText(Charsets.UTF_8),
            )
            assertFalse("An equal token save needs no marker.", marker.exists())
            assertTrue("An uncertain write must move the epoch.", guard.epoch() > epoch)
            assertEquals("The cached listener must drop its token.", 1, notifications)
            assertFalse(
                "A result from the old epoch must not save.",
                guard.savePairingToken(epoch) { throw AssertionError("stale write") },
            )

            failSync = false
            assertTrue(
                "A result from the new epoch can save.",
                guard.savePairingToken(guard.epoch()) { store.save("token-same") },
            )
            assertEquals(
                "A successful save does not move the epoch or notify listeners.",
                1,
                notifications,
            )
            assertEquals("token-same", store.load())
            assertFalse("The confirmed repair removes the equal copy.", legacy.exists())
        }
    }

    @Test
    fun anOrdinaryPairingSaveFailureKeepsTheEpochAndTheResult() {
        withStore { target, legacy, marker ->
            target.writeText("token-old", Charsets.UTF_8)
            var failEncoding = true
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                object : TokenFileCodec {
                    override fun encode(token: String): ByteArray {
                        if (failEncoding) throw IOException("injected encode failure")
                        return token.toByteArray(Charsets.UTF_8)
                    }

                    override fun decode(bytes: ByteArray): String = bytes.toString(Charsets.UTF_8)
                },
            )
            val guard = SourceTokenGuard()
            var notifications = 0
            guard.addEpochListener { notifications += 1 }
            val epoch = guard.epoch()

            assertFalse(
                "A save that changes nothing must fail without a success.",
                guard.savePairingToken(epoch) { store.save("token-new") },
            )

            assertEquals("token-old", target.readText(Charsets.UTF_8))
            assertEquals("A pre-write failure must not move the epoch.", epoch, guard.epoch())
            assertEquals("A pre-write failure must not notify listeners.", 0, notifications)
            failEncoding = false
            assertTrue(
                "The same epoch is still current, so a retry can save.",
                guard.savePairingToken(epoch) { store.save("token-old") },
            )
            assertEquals("token-old", store.load())
            assertFalse("The failed save wrote no marker.", marker.exists())
        }
    }

    private fun withStore(block: (target: File, legacy: File, marker: File) -> Unit) {
        val directory = Files.createTempDirectory("hotspotshade-token-guard").toFile()
        try {
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            block(target, legacy, legacyMarkerFileFor(target))
        } finally {
            directory.deleteRecursively()
        }
    }

    private class PlainCodec : TokenFileCodec {
        override fun encode(token: String): ByteArray = token.toByteArray(Charsets.UTF_8)

        override fun decode(bytes: ByteArray): String = bytes.toString(Charsets.UTF_8)
    }
}
