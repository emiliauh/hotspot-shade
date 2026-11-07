package com.hotspotshade.source

import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import java.nio.file.AccessDeniedException
import java.nio.file.Files
import java.nio.file.FileSystemException
import java.nio.file.NoSuchFileException
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeFalse
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Hermetic tests for read errors on the token files.
 *
 * `FileNotFoundException` is the type that `FileInputStream` throws for a
 * missing file, for EACCES, for EMFILE, and for a directory. It is not proof of
 * absence. A `NoSuchFileException` also needs a path check proving absence.
 * The tests inject a reader, so no test needs a real permission fault or a
 * real file-descriptor shortage.
 */
class TokenFileReadErrorTest {
    private val nio = NioTokenFileReader

    @Test
    fun aFifoTokenPathIsRefusedWithoutWaitingForAWriter() {
        assumeTrue("mkfifo is required for this Unix fixture", File("/usr/bin/mkfifo").canExecute())
        withDirectory { directory ->
            val fifo = File(directory, "source-token.bin")
            val process = ProcessBuilder("/usr/bin/mkfifo", fifo.absolutePath).start()
            assertTrue("mkfifo did not finish", process.waitFor(5, TimeUnit.SECONDS))
            assertEquals(0, process.exitValue())
            val legacy = File(directory, "legacy").apply { writeText("token-legacy") }
            val worker = Executors.newSingleThreadExecutor { task ->
                Thread(task, "token-fifo-test").apply { isDaemon = true }
            }
            try {
                val result = worker.submit<ByteArray> { nio.read(fifo) }
                val error = assertThrows(ExecutionException::class.java) {
                    result.get(5, TimeUnit.SECONDS)
                }
                assertTrue("a FIFO must be a transient read error", error.cause is IOException)
                assertEquals("The source token path is not a regular file.", error.cause?.message)
                val store = AndroidKeystoreTokenStore(fifo, legacy, PlainCodec())
                val load = worker.submit<String?> { store.load() }
                val loadFailure = assertThrows(ExecutionException::class.java) {
                    load.get(5, TimeUnit.SECONDS)
                }
                assertEquals(TokenReadKind.TRANSIENT, (loadFailure.cause as TokenReadException).kind)
                assertEquals("token-legacy", legacy.readText())
            } finally {
                worker.shutdownNow()
            }
        }
    }

    private fun denied(): Nothing =
        throw FileNotFoundException("source-token.bin (Permission denied)")

    @Test
    fun parentTraversalCannotHideASymlinkInTokenPaths() {
        withDirectory { root ->
            val app = File(root, "app").apply { mkdirs() }
            val outside = File(root, "outside/child").apply { mkdirs() }
            val escaped = File(root, "outside/token").apply { writeText("token-outside") }
            Files.createSymbolicLink(File(app, "link").toPath(), outside.toPath())
            val target = File(app, "link/../token")
            val legacy = File(app, "legacy")
            val store = AndroidKeystoreTokenStore(target, legacy, PlainCodec(), appRoot = app)
            assertThrows(TokenReadException::class.java) { store.load() }
            assertThrows(IOException::class.java) { store.save("token-new") }
            assertEquals("token-outside", escaped.readText())
            assertFalse(File(app, "token").exists())
        }
    }

    @Test
    fun trustedAppRootDetectsLiveAliasAboveExistingCommonDirectory() {
        withDirectory { root ->
            val real = File(root, "real/app")
            val files = File(real, "files").apply { mkdirs() }
            File(real, "no_backup").mkdirs()
            val legacy = File(files, "token").apply { writeText("token-old") }
            Files.createSymbolicLink(File(root, "link").toPath(), File(root, "real").toPath())
            val target = File(root, "link/app/no_backup/token")
            val store = AndroidKeystoreTokenStore(
                target, File(root, "link/app/files/token"), PlainCodec(), appRoot = root,
            )
            assertThrows(TokenReadException::class.java) { store.load() }
            assertThrows(IOException::class.java) { store.save("token-new") }
            assertEquals("token-old", legacy.readText())
            assertFalse(target.exists())
        }
    }

    @Test
    fun trustedAppRootAllowsNormalMigrationAndRejectsOutsidePaths() {
        withDirectory { root ->
            val legacy = File(root, "app/files/token")
            val target = File(root, "app/no_backup/token")
            legacy.parentFile!!.mkdirs()
            legacy.writeText("token-old")
            val store = AndroidKeystoreTokenStore(target, legacy, PlainCodec(), appRoot = root)
            assertEquals("token-old", store.load())
            assertEquals("token-old", target.readText())
            val other = File(root, "other").apply { mkdirs() }
            val outside = AndroidKeystoreTokenStore(target, legacy, PlainCodec(), appRoot = other)
            assertThrows(TokenReadException::class.java) { outside.load() }
            assertThrows(IOException::class.java) { outside.save("token-new") }
            assertEquals("token-old", target.readText())
        }
    }

    @Test
    fun aSymlinkTrustedAppRootFailsClosed() {
        withDirectory { root ->
            val real = File(root, "real").apply { mkdirs() }
            val alias = File(root, "app")
            Files.createSymbolicLink(alias.toPath(), real.toPath())
            val target = File(alias, "no_backup/token")
            val legacy = File(alias, "files/token")
            val store = AndroidKeystoreTokenStore(target, legacy, PlainCodec(), appRoot = alias)

            assertThrows(TokenReadException::class.java) { store.load() }
            assertThrows(IOException::class.java) { store.save("token-new") }
            assertFalse(File(real, "no_backup/token").exists())
        }
    }

    @Test
    fun aMissingTrustedAppRootFailsClosedAndCreatesNothing() {
        withDirectory { root ->
            val app = File(root, "missing-app")
            val target = File(app, "no_backup/token")
            val legacy = File(app, "files/token")
            val store = AndroidKeystoreTokenStore(target, legacy, PlainCodec(), appRoot = app)

            // A missing anchor cannot prove that a missing child below it is
            // absent. Do not report TOKEN_MISSING and do not create the tree.
            val failure = assertThrows(TokenReadException::class.java) { store.load() }
            assertEquals(TokenReadKind.TRANSIENT, failure.kind)
            assertThrows(IOException::class.java) { store.save("token-new") }
            assertFalse("The store must not create a tree under a missing anchor.", app.exists())
        }
    }

    @Test
    fun aTrustedAppRootThatIsAFileFailsClosed() {
        withDirectory { root ->
            val app = File(root, "app").apply { writeText("not a directory") }
            val store = AndroidKeystoreTokenStore(
                File(app, "no_backup/token"),
                File(app, "files/token"),
                PlainCodec(),
                appRoot = app,
            )
            assertThrows(TokenReadException::class.java) { store.load() }
            assertThrows(IOException::class.java) { store.save("token-new") }
            assertEquals("not a directory", app.readText())
        }
    }

    @Test
    fun trustedAppRootAllowsSymlinkInPlatformPrefix() {
        withDirectory { root ->
            val real = File(root, "real/app").apply { mkdirs() }
            Files.createSymbolicLink(File(root, "prefix").toPath(), File(root, "real").toPath())
            val app = File(root, "prefix/app")
            val legacy = File(app, "files/token")
            val target = File(app, "no_backup/token")
            legacy.parentFile!!.mkdirs()
            legacy.writeText("token-old")
            val store = AndroidKeystoreTokenStore(target, legacy, PlainCodec(), appRoot = app)
            assertEquals("token-old", store.load())
            assertEquals("token-old", File(real, "no_backup/token").readText())
        }
    }

    @Test
    fun transientTargetBlocksExplicitSaveWithAbsentOrCorruptLegacy() {
        for (legacyContents in listOf<String?>(null, "")) {
            withDirectory { root ->
                val target = File(root, "no_backup/token")
                val legacy = File(root, "files/token")
                target.parentFile!!.mkdirs()
                target.writeText("token-current")
                if (legacyContents != null) {
                    legacy.parentFile!!.mkdirs()
                    legacy.writeText(legacyContents)
                }
                val store = AndroidKeystoreTokenStore(
                    target, legacy, CorruptOnEmptyCodec(),
                    readFile = { file -> if (file == target) denied() else nio.read(file) },
                    appRoot = root,
                )
                assertThrows(IOException::class.java) { store.save("token-new") }
                assertEquals("token-current", target.readText())
                assertFalse(legacyMarkerFileFor(target).exists())
                if (legacyContents != null) assertEquals(legacyContents, legacy.readText())
            }
        }
    }

    @Test
    fun danglingAndLiveAncestorAliasesNeverChangeEitherToken() {
        withDirectory { directory ->
            val target = File(directory, "target/token")
            val legacy = File(directory, "legacy/token")
            legacy.parentFile!!.mkdirs()
            legacy.writeText("token-legacy")
            Files.createSymbolicLink(target.parentFile!!.toPath(), File(directory, "missing").toPath())
            val store = AndroidKeystoreTokenStore(target, legacy, PlainCodec())
            assertThrows(TokenReadException::class.java) { store.load() }
            assertThrows(IOException::class.java) { store.save("token-new") }
            assertEquals("token-legacy", legacy.readText())
            Files.delete(target.parentFile!!.toPath())
            Files.createSymbolicLink(target.parentFile!!.toPath(), legacy.parentFile!!.toPath())
            assertThrows(TokenReadException::class.java) { store.load() }
            assertThrows(IOException::class.java) { store.save("token-new") }
            assertEquals("token-legacy", legacy.readText())
        }
    }

    @Test
    fun hardLinkedTargetAndLegacyAreRejectedWithoutDeletingEither() {
        withDirectory { directory ->
            val target = File(directory, "target")
            val legacy = File(directory, "legacy")
            target.writeText("token-current")
            Files.createLink(legacy.toPath(), target.toPath())
            val store = AndroidKeystoreTokenStore(target, legacy, PlainCodec())
            assertThrows(TokenReadException::class.java) { store.load() }
            assertThrows(IOException::class.java) { store.save("token-new") }
            assertEquals("token-current", target.readText())
            assertEquals("token-current", legacy.readText())
        }
    }

    @Test
    fun markerSymlinksAndAliasesNeverAuthorizeFallbackOrReplacement() {
        withDirectory { directory ->
            val target = File(directory, "target")
            val legacy = File(directory, "legacy")
            val marker = legacyMarkerFileFor(target)
            legacy.writeText("token-legacy")
            Files.createSymbolicLink(marker.toPath(), File(directory, "missing").toPath())
            assertEquals(LegacyMarkerState.UNKNOWN, LegacyTokenMarker.state(marker))
            val store = AndroidKeystoreTokenStore(target, legacy, PlainCodec())
            assertThrows(TokenReadException::class.java) { store.load() }
            assertThrows(IOException::class.java) { store.save("token-new") }
            Files.delete(marker.toPath())
            Files.createLink(marker.toPath(), legacy.toPath())
            assertThrows(TokenReadException::class.java) { store.load() }
            assertThrows(IOException::class.java) { store.save("token-new") }
            assertEquals("token-legacy", legacy.readText())
            assertFalse(target.exists())
        }
    }

    @Test
    fun danglingMarkerAncestorAndUnknownMarkerWithNoLegacyAreNotAbsence() {
        withDirectory { directory ->
            val target = File(directory, "target")
            val legacy = File(directory, "legacy")
            val markerDir = File(directory, "marker-dir")
            val marker = File(markerDir, "marker")
            Files.createSymbolicLink(markerDir.toPath(), File(directory, "missing").toPath())
            assertEquals(LegacyMarkerState.UNKNOWN, LegacyTokenMarker.state(marker))
            val store = AndroidKeystoreTokenStore(target, legacy, PlainCodec(), markerFile = marker)
            assertThrows(TokenReadException::class.java) { store.load() }
            assertThrows(IOException::class.java) { store.save("token-new") }
            assertFalse(target.exists())
            val unknown = AndroidKeystoreTokenStore(
                target, legacy, PlainCodec(), markerState = { LegacyMarkerState.UNKNOWN },
            )
            assertThrows(TokenReadException::class.java) { unknown.load() }
            assertThrows(IOException::class.java) { unknown.save("token-new") }
            assertFalse(target.exists())
        }
    }

    @Test
    fun aReadErrorIsNotReclassifiedAfterAnAncestorChanges() {
        withDirectory { directory ->
            val parent = File(directory, "parent")
            val target = File(parent, "token")
            parent.mkdir()
            val failure = assertThrows(FileSystemException::class.java) {
                NioTokenFileReader.readWith(target) {
                    parent.delete()
                    parent.writeText("replacement")
                    throw FileSystemException(target.path, null, "simulated read error")
                }
            }
            assertEquals("simulated read error", failure.reason)
            assertEquals("replacement", parent.readText())
        }
    }

    @Test
    fun aMissingPathIsAbsentAndLoadsAsNull() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                PlainCodec(),
                readFile = { throw NoSuchFileException(it.path) },
            )

            assertNull(store.load())
            assertEquals(target, store.activeFile())
        }
    }

    @Test
    fun noSuchFileForAnExistingTargetIsTransientAndDoesNotUseLegacy() {
        withDirectory { directory ->
            val target = File(directory, "target").apply { writeText("token-current") }
            val legacy = File(directory, "legacy").apply { writeText("token-legacy") }
            val store = AndroidKeystoreTokenStore(target, legacy, PlainCodec(), readFile = {
                if (it == target) throw NoSuchFileException(it.path)
                nio.read(it)
            })
            val failure = assertThrows(TokenReadException::class.java) { store.load() }
            assertEquals(TokenReadKind.TRANSIENT, failure.kind)
            assertEquals("token-current", target.readText())
            assertEquals("token-legacy", legacy.readText())
        }
    }

    @Test
    fun aDanglingTargetSymlinkIsTransientAndDoesNotUseLegacy() {
        withDirectory { directory ->
            val target = File(directory, "target")
            val legacy = File(directory, "legacy")
            legacy.writeText("token-legacy")
            Files.createSymbolicLink(target.toPath(), File(directory, "missing").toPath())
            val store = AndroidKeystoreTokenStore(target, legacy, PlainCodec())
            val failure = assertThrows(TokenReadException::class.java) { store.load() }
            assertEquals(TokenReadKind.TRANSIENT, failure.kind)
            assertEquals("token-legacy", legacy.readText())
        }
    }

    @Test
    fun aDanglingLegacySymlinkCannotBeMistakenForAnAbsentCopyDuringRotation() {
        withDirectory { directory ->
            val target = File(directory, "target")
            val legacy = File(directory, "legacy")
            target.writeText("token-current")
            Files.createSymbolicLink(legacy.toPath(), File(directory, "missing").toPath())
            val store = AndroidKeystoreTokenStore(target, legacy, PlainCodec())
            assertThrows(IOException::class.java) { store.save("token-new") }
            assertEquals("token-current", target.readText())
            assertTrue(Files.isSymbolicLink(legacy.toPath()))
        }
    }

    @Test
    fun aFileNotFoundExceptionIsATransientErrorNotAMissingToken() {
        withDirectory { directory ->
            val target = File(directory, "source-token.bin")
            target.writeText("token-stored", Charsets.UTF_8)
            val store = AndroidKeystoreTokenStore(
                target,
                codec = PlainCodec(),
                readFile = { denied() },
            )

            val failure = assertThrows(TokenReadException::class.java) { store.load() }

            assertEquals(TokenReadKind.TRANSIENT, failure.kind)
            assertEquals("The file must stay.", "token-stored", target.readText(Charsets.UTF_8))
        }
    }

    @Test
    fun everyOtherReadErrorIsTransientToo() {
        val failures = listOf<() -> Nothing>(
            { throw AccessDeniedException("source-token.bin") },
            { throw IOException("EMFILE (Too many open files)") },
            { throw SecurityException("denied") },
            { throw IllegalStateException("unexpected") },
        )
        for (failure in failures) {
            withDirectory { directory ->
                val target = File(directory, "source-token.bin")
                target.writeText("token-stored", Charsets.UTF_8)
                val store = AndroidKeystoreTokenStore(
                    target,
                    codec = PlainCodec(),
                    readFile = { failure() },
                )

                val thrown = assertThrows(TokenReadException::class.java) { store.load() }

                assertEquals(TokenReadKind.TRANSIENT, thrown.kind)
            }
        }
    }

    @Test
    fun aDeniedTargetNeverFallsBackToAReadableLegacyCopy() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeText("token-target", Charsets.UTF_8)
            legacy.writeText("token-legacy", Charsets.UTF_8)
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                PlainCodec(),
                readFile = { file -> if (file == target) denied() else nio.read(file) },
            )

            val failure = assertThrows(TokenReadException::class.java) { store.load() }

            assertEquals(TokenReadKind.TRANSIENT, failure.kind)
            assertEquals(target, store.activeFile())
            assertEquals("token-target", target.readText(Charsets.UTF_8))
            assertTrue("The legacy copy must stay.", legacy.isFile)
        }
    }

    @Test
    fun aDeniedLegacyCopyWithoutATargetIsUnreadableNotMissing() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(legacy.parentFile).mkdirs()
            legacy.writeText("token-legacy", Charsets.UTF_8)
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                PlainCodec(),
                readFile = { file -> if (file == legacy) denied() else nio.read(file) },
            )

            val failure = assertThrows(TokenReadException::class.java) { store.load() }

            assertEquals(TokenReadKind.TRANSIENT, failure.kind)
            assertEquals(legacy, store.activeFile())
            assertFalse("No target may be created from an unknown state.", target.exists())
            assertEquals("token-legacy", legacy.readText(Charsets.UTF_8))
        }
    }

    @Test
    fun aDeniedTargetDoesNotMoveOrDeleteTheLegacyCopy() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            legacy.writeText("token-legacy", Charsets.UTF_8)
            // The target read fails with the EACCES shape, although no file
            // exists there. The state is unknown, so the legacy copy is not
            // moved over it.
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                PlainCodec(),
                readFile = { file -> if (file == target) denied() else nio.read(file) },
            )

            assertThrows(TokenReadException::class.java) { store.load() }

            assertFalse("The target must not be written.", target.exists())
            assertTrue("The legacy copy must stay.", legacy.isFile)
        }
    }

    @Test
    fun aDirectoryAtTheTokenPathIsAnUnreadableTokenNotAMissingOne() {
        withDirectory { directory ->
            val target = File(directory, "source-token.bin")
            assertTrue(target.mkdirs())
            val store = AndroidKeystoreTokenStore(target, codec = PlainCodec())

            val failure = assertThrows(TokenReadException::class.java) { store.load() }

            assertEquals(TokenReadKind.TRANSIENT, failure.kind)
        }
    }

    @Test
    fun aRealUnreadableFileIsAnUnreadableTokenNotAMissingOne() {
        withDirectory { directory ->
            val target = File(directory, "source-token.bin")
            target.writeText("token-stored", Charsets.UTF_8)
            // A file that this process cannot read reproduces the EACCES
            // shape without an injected reader. Skip when the platform or the
            // user (for example root) ignores the permission.
            target.setReadable(false, false)
            try {
                assumeFalse("The platform ignores the read permission.", target.canRead())
                val store = AndroidKeystoreTokenStore(target, codec = PlainCodec())

                val failure = assertThrows(TokenReadException::class.java) { store.load() }

                assertEquals(TokenReadKind.TRANSIENT, failure.kind)
            } finally {
                target.setReadable(true, false)
            }
        }
    }

    @Test
    fun aTransientReadAfterAGoodLoadIsStillAnUnreadableToken() {
        withDirectory { directory ->
            val target = File(directory, "source-token.bin")
            target.writeText("token-stored", Charsets.UTF_8)
            var failing = false
            val store = AndroidKeystoreTokenStore(
                target,
                codec = PlainCodec(),
                readFile = { file -> if (failing) denied() else nio.read(file) },
            )
            assertEquals("token-stored", store.load())
            failing = true

            // The load reports an unreadable token, so a caller cannot take
            // it for a missing one. PairingCoordinatorTest covers the commit
            // half of the rule with the real store.
            assertThrows(TokenReadException::class.java) { store.load() }
            assertEquals("token-stored", target.readText(Charsets.UTF_8))
        }
    }

    /**
     * Pin the forward protection that android/README.md documents.
     *
     * A save records the legacy-supersession marker before it replaces the
     * target. A failed legacy delete may leave the stale copy in place, but a
     * later corrupt or missing target must not use it. The marker is written
     * by the new save path, so this test fails if the marker is skipped.
     */
    @Test
    fun aStaleLegacyCopyAfterAFailedDeleteCannotWinAfterTheMarker() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            legacy.writeText("token-old", Charsets.UTF_8)
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                PlainCodec(),
                deleteFile = { false },
            )
            store.save("token-new")
            assertTrue("The failed delete leaves the stale copy.", legacy.isFile)
            assertEquals("token-new", store.load())
            assertTrue(
                "The save must record the supersession marker.",
                legacyMarkerFileFor(target).isFile,
            )

            target.writeText("", Charsets.UTF_8)
            val corrupting = AndroidKeystoreTokenStore(
                target,
                legacy,
                CorruptOnEmptyCodec(),
                deleteFile = { false },
            )

            assertThrows(TokenReadException::class.java) { corrupting.load() }
            assertTrue("The stale legacy copy must stay untouched.", legacy.isFile)
            assertEquals("", target.readText(Charsets.UTF_8))
        }
    }

    @Test
    fun aMarkerThatCannotBeClassifiedDoesNotUseTheLegacyCopy() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(legacy.parentFile).mkdirs()
            legacy.writeText("token-legacy", Charsets.UTF_8)
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                PlainCodec(),
                markerState = { LegacyMarkerState.UNKNOWN },
            )

            val failure = assertThrows(TokenReadException::class.java) { store.load() }

            assertEquals(TokenReadKind.TRANSIENT, failure.kind)
            assertFalse("An unknown marker must not move the legacy copy.", target.exists())
            assertEquals("token-legacy", legacy.readText(Charsets.UTF_8))
        }
    }

    /**
     * Pin the deferred cleanup rule.
     *
     * The equal legacy copy is removed only after the target token has been
     * decoded. A read failure after the resolution must leave the duplicate
     * in place, so a transient target failure cannot remove the other copy.
     */
    @Test
    fun aFailedFinalTargetReadDoesNotDeleteTheEqualLegacyCopy() {
        withDirectory { directory ->
            val target = File(directory, "no-backup/source-token.bin")
            val legacy = File(directory, "files/source-token.bin")
            requireNotNull(target.parentFile).mkdirs()
            requireNotNull(legacy.parentFile).mkdirs()
            target.writeText("token-same", Charsets.UTF_8)
            legacy.writeText("token-same", Charsets.UTF_8)
            var targetReads = 0
            var failFinalRead = true
            val store = AndroidKeystoreTokenStore(
                target,
                legacy,
                PlainCodec(),
                readFile = { file ->
                    if (file == target) {
                        targetReads += 1
                        // The resolution reads the target twice: once for its
                        // state and once to compare the copies. The third read
                        // is the final decode of the returned token.
                        if (failFinalRead && targetReads >= 3) denied()
                    }
                    NioTokenFileReader.read(file)
                },
            )

            val failure = assertThrows(TokenReadException::class.java) { store.load() }
            assertEquals(TokenReadKind.TRANSIENT, failure.kind)
            assertTrue(
                "A failed final read must not delete the equal legacy copy.",
                legacy.isFile,
            )
            assertEquals("token-same", legacy.readText(Charsets.UTF_8))

            failFinalRead = false
            assertEquals("token-same", store.load())
            assertFalse("A later successful load removes the equal copy.", legacy.exists())
        }
    }

    private class PlainCodec : TokenFileCodec {
        override fun encode(token: String): ByteArray = token.toByteArray(Charsets.UTF_8)

        override fun decode(bytes: ByteArray): String = bytes.toString(Charsets.UTF_8)
    }

    private class CorruptOnEmptyCodec : TokenFileCodec {
        override fun encode(token: String): ByteArray = token.toByteArray(Charsets.UTF_8)

        override fun decode(bytes: ByteArray): String {
            if (bytes.isEmpty()) {
                throw TokenReadException(
                    "The source token file is empty.",
                    kind = TokenReadKind.CORRUPT,
                )
            }
            return bytes.toString(Charsets.UTF_8)
        }
    }

    private fun withDirectory(block: (File) -> Unit) {
        val directory = Files.createTempDirectory("hotspotshade-token-read").toFile()
        try {
            block(directory)
        } finally {
            directory.deleteRecursively()
        }
    }
}
