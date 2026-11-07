package com.hotspotshade.source

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.OutputStream
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.NoSuchFileException
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.security.KeyStore
import java.security.KeyStoreException
import javax.crypto.AEADBadTagException
import javax.crypto.BadPaddingException
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
    /**
     * Return the stored token, or null when this device has no token.
     *
     * A token that exists but cannot be read is not the same as a missing
     * token. The store throws [TokenReadException] in that case. A caller
     * must not generate a token and save it over an unreadable file.
     */
    fun load(): String?
}

/**
 * The stored token exists but cannot be read.
 *
 * The message and the cause hold no token. A caller must not replace the file
 * and must not report `TOKEN_MISSING`. [kind] says whether a retry with the
 * present key can help. A corrupt file is still kept, because a wrong present
 * key can make a recoverable ciphertext look corrupt.
 */
internal class TokenReadException(
    message: String,
    cause: Throwable? = null,
    val kind: TokenReadKind = TokenReadKind.TRANSIENT,
) : Exception(message, cause)

/**
 * Why a stored token could not be read with the present key.
 *
 * CORRUPT means the container, the bytes, or the authentication tag is invalid
 * for the present key, or the decoded value is not a usable token; a retry with
 * that key cannot help. An authentication failure does not prove that the
 * ciphertext is permanently unrecoverable: a present but wrong key produces
 * the same failure. A caller must keep such a file as potentially recoverable
 * instead of deleting it. TRANSIENT means an I/O or Keystore error may clear;
 * the migration must not treat a readable legacy copy as the winner in that
 * case.
 */
internal enum class TokenReadKind {
    CORRUPT,
    TRANSIENT,
}

/**
 * The result of probing one token file without exposing its token.
 *
 * CORRUPT means the file could not be decoded with the present key, or it
 * decoded to a value that cannot cross the wire. It does not prove that the
 * ciphertext is unrecoverable with another key, so a corrupt legacy copy is
 * kept and latched. TRANSIENT means the state could not be established; the
 * file is neither absent nor corrupt for decision purposes.
 */
internal enum class TokenFileState {
    ABSENT,
    READABLE,
    CORRUPT,
    TRANSIENT,
}

/**
 * The durable legacy-token supersession marker.
 *
 * PRESENT means a target write has superseded the legacy copy. The marker is
 * one way: a later target write never needs to remove it, and a corrupt,
 * missing, or unreadable target must not fall back to the legacy file.
 * ABSENT is proven absence. UNKNOWN is an I/O state that could not be
 * classified; a caller must not treat it as either permission to use the
 * legacy copy or as a missing token.
 */
internal enum class LegacyMarkerState {
    ABSENT,
    PRESENT,
    UNKNOWN,
}

private enum class PathState { ABSENT, PRESENT, UNKNOWN }

private fun hasParentTraversal(file: File): Boolean =
    file.toPath().any { it.toString() == ".." }

// Return the one absolute path that the checks and the file operations share.
// A raw path with a parent component is rejected instead of normalized: the
// kernel resolves ".." after any symlink in front of it, so the normalized
// path and the path the filesystem would use can name different entries. A
// "." or a repeated separator resolves to the same entry, so normalization is
// safe there. Every checked operation uses this value, never the caller's
// string.
private fun normalizedFile(file: File): File {
    if (hasParentTraversal(file)) {
        throw IOException("The source token path could not be classified.")
    }
    return file.absoluteFile.toPath().normalize().toFile()
}

private class CheckedPaths(
    val target: File,
    val legacy: File?,
    val marker: File?,
)

// Inspect from an app-private anchor, not from the filesystem root. On macOS
// system ancestors such as /var may legitimately be symlinks. This is not
// descriptor-relative traversal: it relies on app-private storage and one
// process owning these paths throughout each operation.
private fun pathState(file: File, anchor: File): PathState { return try {
    if (hasParentTraversal(file) || hasParentTraversal(anchor)) return PathState.UNKNOWN
    val root = anchor.absoluteFile.toPath().normalize()
    val path = file.absoluteFile.toPath().normalize()
    if (!path.startsWith(root)) {
        PathState.UNKNOWN
    } else {
        var current = root
        var missing = false
        val components = listOf(root) + root.relativize(path).map { component ->
            current = current.resolve(component)
            current
        }
        for ((index, component) in components.withIndex()) {
            if (missing) continue
            val attributes = try {
                Files.readAttributes(component, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
            } catch (_: NoSuchFileException) {
                missing = true
                continue
            }
            if (attributes.isSymbolicLink || (index < components.lastIndex && !attributes.isDirectory)) {
                return PathState.UNKNOWN
            }
        }
        if (missing) PathState.ABSENT else PathState.PRESENT
    }
} catch (_: Exception) {
    PathState.UNKNOWN
} }

// Find an existing directory without following a missing or symlink entry.
// This permits system symlinks above that directory on host JVM tests.
private fun nearestDirectory(file: File): File? {
    var parent = file.absoluteFile.parentFile
    while (parent != null) {
        try {
            val attrs = Files.readAttributes(parent.toPath(), BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
            return if (attrs.isDirectory && !attrs.isSymbolicLink) parent else null
        } catch (_: NoSuchFileException) {
            parent = parent.parentFile
        } catch (_: Exception) {
            return null
        }
    }
    return null
}

/**
 * Record and inspect the legacy-supersession marker.
 *
 * The marker holds a fixed version line. Its content is not a secret and is
 * not authenticated; any existing path counts as PRESENT so a corrupt,
 * truncated, or tampered marker fails closed. The write uses a temporary file,
 * a file sync, a verified rename, and a parent-directory sync. A caller that
 * latches an unreadable legacy copy must not replace the target until [record]
 * returns. A caller that latches a readable copy calls it after the target is
 * confirmed, so a save that fails before the target is confirmed leaves the
 * readable copy usable.
 */
internal object LegacyTokenMarker {
    private val CONTENT =
        "hotspotshade legacy source token superseded v1\n".toByteArray(Charsets.US_ASCII)

    /** Classify the marker path without creating it. */
    fun state(file: File): LegacyMarkerState { return try {
        if (hasParentTraversal(file)) return LegacyMarkerState.UNKNOWN
        val checked = file.absoluteFile.toPath().normalize().toFile()
        val anchor = nearestDirectory(checked) ?: return LegacyMarkerState.UNKNOWN
        when (pathState(checked, anchor)) {
            PathState.PRESENT -> LegacyMarkerState.PRESENT
            PathState.ABSENT -> LegacyMarkerState.ABSENT
            PathState.UNKNOWN -> LegacyMarkerState.UNKNOWN
        }
    } catch (_: Exception) {
        LegacyMarkerState.UNKNOWN
    } }

    /**
     * Make the marker durable.
     *
     * An existing marker is kept even when its content differs. Only the
     * parent directory is synced in that case. A failed write or sync throws.
     * A caller that has not yet replaced the target must not replace it. A
     * caller that already confirmed the target must report an uncertain write,
     * because the latch is not durable.
     */
    fun record(file: File) {
        record(file, ::syncParent)
    }

    /**
     * Record the marker with an injected parent sync. A JVM test uses this
     * narrow seam to fail the real sync step without weakening the production
     * writer, which always passes [syncParent].
     */
    internal fun recordWithParentSync(file: File, parentSync: (File) -> Unit) {
        record(file, parentSync)
    }

    private fun record(file: File, parentSync: (File) -> Unit) {
        val checked = normalizedFile(file)
        when (state(checked)) {
            LegacyMarkerState.PRESENT -> { parentSync(checked); return }
            LegacyMarkerState.UNKNOWN -> throw IOException("The source token state could not be read.")
            LegacyMarkerState.ABSENT -> Unit
        }
        AtomicFileWriter.write(
            file = checked,
            verify = { temporary ->
                val read = temporary.readBytes()
                try {
                    if (!read.contentEquals(CONTENT)) {
                        throw IOException("The legacy token marker could not be confirmed.")
                    }
                } finally {
                    read.fill(0)
                }
            },
            syncParent = true,
            parentSync = parentSync,
        ) { output -> output.write(CONTENT) }
    }

    private fun syncParent(file: File) {
        val directory = file.absoluteFile.parentFile
            ?: throw IOException("The legacy token marker has no parent directory.")
        try {
            FileChannel.open(directory.toPath(), StandardOpenOption.READ).use { channel ->
                channel.force(true)
            }
        } catch (failure: Exception) {
            throw IOException("The legacy token marker directory could not be synced.", failure)
        }
    }
}

/** The marker path next to the no-backup target file. */
internal fun legacyMarkerFileFor(targetFile: File): File {
    val parent = targetFile.absoluteFile.parentFile
        ?: throw IOException("The token file has no parent directory.")
    return File(parent, targetFile.name + LEGACY_MARKER_SUFFIX)
}

private const val LEGACY_MARKER_SUFFIX = ".legacy-superseded"

private fun defaultLegacyMarkerFile(targetFile: File, legacyFile: File?): File? =
    legacyFile?.takeIf { it != targetFile }?.let { legacyMarkerFileFor(targetFile) }

/**
 * True when a stored or generated token can cross the wire.
 *
 * The pairing listener, a pairing result, and a proxy start must agree on one
 * rule. A value that the pairing listener rejects as unreadable must not be
 * accepted by a start, or the two paths would name different tokens for the
 * same device. The rule is a non-empty printable ASCII value of at most 255
 * characters.
 */
internal fun isUsableSourceToken(token: String): Boolean =
    token.isNotEmpty() && token.length <= 255 && token.all { it.code in 0x21..0x7E }

/**
 * The stored token exists but could not be removed.
 *
 * A clear that reports this failure did not finish. The caller must show a
 * failure and must not describe the token as removed. The message and the
 * cause hold no token.
 */
internal class TokenDeleteException(
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause)

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
 * Read the complete bytes of one token file.
 *
 * Only [java.nio.file.NoSuchFileException] means the path is missing for an
 * injected reader. The production reader also checks the path without following
 * the final symlink. Any other
 * exception means the state is unknown. In particular
 * [java.io.FileNotFoundException] is not proof of absence: the `FileInputStream`
 * constructor reports EACCES, EMFILE, and a directory with that same type. The
 * store treats every exception except [java.nio.file.NoSuchFileException] as a
 * transient read failure. A JVM test injects a reader to simulate those errors.
 */
internal fun interface TokenFileReader {
    fun read(file: File): ByteArray
}

/**
 * The production reader. It uses NIO, which reports a missing path precisely.
 *
 * Other errors remain failures. A NoSuchFileException is checked against the
 * path state before it can mean absence; that check is not atomic.
 * A non-regular final path is refused before opening it, so a stable FIFO
 * cannot block this reader. This is a path check, not protection against a
 * concurrent writer replacing an app-private path between the check and open.
 */
internal object NioTokenFileReader : TokenFileReader {
    override fun read(file: File): ByteArray = readWith(file) {
        val path = it.toPath()
        val attributes = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        if (!attributes.isRegularFile) throw IOException("The source token path is not a regular file.")
        Files.readAllBytes(path)
    }

    internal fun readWith(file: File, read: (File) -> ByteArray): ByteArray = try {
        read(file)
    } catch (failure: java.nio.file.FileSystemException) {
        if (failure is NoSuchFileException &&
            !provenMissing(file)
        ) {
            throw IOException("The source token path could not be read.", failure)
        }
        throw failure
    }
}

/**
 * Read one token file, or return null when the path is missing.
 *
 * Any other failure propagates. The caller must treat it as a transient error,
 * never as an absent file.
 */
internal fun TokenFileReader.readOrNull(file: File): ByteArray? = try {
    read(file)
} catch (failure: NoSuchFileException) {
    if (provenMissing(file)) null else throw IOException("The source token path could not be classified.", failure)
}

/** True only when the platform proves that the path does not exist. */
private fun provenMissing(file: File): Boolean =
    nearestDirectory(file)?.let { pathState(file, it) == PathState.ABSENT } == true

/**
 * Write one file with a temporary file and one atomic rename.
 *
 * A crash during the write leaves the previous file in place. It does not
 * leave a truncated file. The caller can supply [verify] to check the complete
 * temporary file before the rename, so a failed check leaves the target
 * unchanged. The temporary file is removed on every path this JVM can observe.
 * A process kill can leave an orphan temporary file; a later write ignores it.
 */
internal class TokenWriteUncertainException(cause: Throwable) : IOException(
    "The source token replacement could not be made durable.", cause,
)

internal fun syncTokenParent(file: File) {
    val directory = file.absoluteFile.parentFile ?: throw IOException("The file has no parent directory.")
    FileChannel.open(directory.toPath(), StandardOpenOption.READ).use { it.force(true) }
}

internal object AtomicFileWriter {
    fun write(
        file: File,
        verify: ((File) -> Unit)? = null,
        syncParent: Boolean = false,
        parentSync: (File) -> Unit = ::syncTokenParent,
        move: (java.nio.file.Path, java.nio.file.Path) -> Unit = { from, to ->
            Files.move(from, to, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        },
        write: (OutputStream) -> Unit,
    ) {
        // A writer called directly, as the tests do, must not let a raw path
        // and a checked path name different entries.
        val target = normalizedFile(file)
        val directory = target.absoluteFile.parentFile
            ?: throw IOException("The file has no parent directory.")
        if (!directory.isDirectory && !directory.mkdirs()) {
            throw IOException("The file directory does not exist.")
        }
        val temporary = File.createTempFile("${target.name}.", ".tmp", directory)
        try {
            FileOutputStream(temporary).use { output ->
                write(output)
                output.flush()
                output.fd.sync()
            }
            // A failed check must leave the previous file in place. Do not
            // rename a temporary file that the caller could not confirm.
            verify?.invoke(temporary)
            try {
                move(temporary.toPath(), target.toPath())
            } catch (failure: Exception) {
                // A provider error does not establish whether the destination
                // changed. Force callers to re-read before using a cached token.
                throw TokenWriteUncertainException(failure)
            }
            if (syncParent) {
                try {
                    parentSync(target)
                } catch (failure: Exception) {
                    throw TokenWriteUncertainException(failure)
                }
            }
        } finally {
            if (temporary.exists()) temporary.delete()
        }
    }
}

/**
 * Encode and decode one complete token file.
 *
 * Production uses [KeystoreTokenFileCodec]. A JVM test supplies a fake so it
 * can exercise the migration and write paths without the Android Keystore.
 */
internal interface TokenFileCodec {
    /** Encode one token into the complete file bytes. */
    fun encode(token: String): ByteArray

    /** Decode one complete file. Throw [TokenReadException] when it is unreadable. */
    fun decode(bytes: ByteArray): String
}

/**
 * Classify one failed authenticated decryption.
 *
 * Only a verified authentication failure is [TokenReadKind.CORRUPT] for the
 * present key: the tag did not verify, so the ciphertext or the tag is invalid
 * for that key. This is not proof that the bytes are permanently unrecoverable:
 * a present but wrong key produces the same failure, so a caller must keep the
 * ciphertext as potentially recoverable. A provider, Keystore, or I/O failure
 * is [TokenReadKind.TRANSIENT]. A transient failure is not proof that the bytes
 * are corrupt, so the migration must not treat a readable legacy copy as the
 * winner.
 */
internal fun tokenDecodeFailureKind(failure: Exception): TokenReadKind = when (failure) {
    // GCM reports a tag mismatch as AEADBadTagException. Some providers use
    // the parent BadPaddingException for the same failure.
    is AEADBadTagException -> TokenReadKind.CORRUPT
    is BadPaddingException -> TokenReadKind.CORRUPT
    else -> TokenReadKind.TRANSIENT
}

/**
 * Encode the token with an Android Keystore AES key.
 *
 * The file holds one version byte, one IV length byte, the IV, and the
 * ciphertext. This class does not log.
 *
 * [encryptionKey] serves [encode], the save path, and may create the key on the
 * first save. [decryptionKey] serves [decode] and is lookup-only: a missing or
 * unreadable key throws, so a load reports a transient failure and never
 * creates a key or selects the legacy token. [cipherFactory] is injectable so a
 * JVM test can run the real classification with a plain AES key. [keyAlias] is
 * injectable so an instrumented test can use a disposable Android Keystore
 * key. Production uses the default key alias and the Android Keystore.
 */
internal class KeystoreTokenFileCodec(
    private val keyAlias: String = KEY_ALIAS,
    private val encryptionKey: () -> SecretKey = { platformKey(keyAlias, create = true) },
    private val decryptionKey: () -> SecretKey = { platformKey(keyAlias, create = false) },
    private val cipherFactory: () -> Cipher = { Cipher.getInstance(TRANSFORMATION) },
) : TokenFileCodec {
    override fun encode(token: String): ByteArray {
        val cipher = cipherFactory()
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey())
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
        return ByteArray(2 + iv.size + ciphertext.size).also { output ->
            output[0] = VERSION.toByte()
            output[1] = iv.size.toByte()
            iv.copyInto(output, 2)
            ciphertext.copyInto(output, 2 + iv.size)
        }
    }

    override fun decode(bytes: ByteArray): String {
        // The container shape is verified from the complete file. A retry
        // cannot make a short file, an unknown version, or a bad IV valid, so
        // these failures are corrupt. Only a crypto call can report a
        // transient Keystore or provider failure.
        if (bytes.size < 3) {
            throw TokenReadException(
                "The source token file is too short.",
                kind = TokenReadKind.CORRUPT,
            )
        }
        if ((bytes[0].toInt() and 0xFF) != VERSION) {
            throw TokenReadException(
                "The source token file has an unknown version.",
                kind = TokenReadKind.CORRUPT,
            )
        }
        val ivLength = bytes[1].toInt() and 0xFF
        if (ivLength < MINIMUM_IV_LENGTH || ivLength > MAXIMUM_IV_LENGTH ||
            bytes.size < 2 + ivLength + TAG_BITS / 8
        ) {
            throw TokenReadException(
                "The source token file has an invalid IV.",
                kind = TokenReadKind.CORRUPT,
            )
        }
        val iv = bytes.copyOfRange(2, 2 + ivLength)
        val ciphertext = bytes.copyOfRange(2 + ivLength, bytes.size)
        val cipher = try {
            val instance = cipherFactory()
            // A lookup-only key accessor runs here. A missing key must not
            // turn into a generated key and a later tag mismatch.
            instance.init(Cipher.DECRYPT_MODE, decryptionKey(), GCMParameterSpec(TAG_BITS, iv))
            instance
        } catch (failure: Exception) {
            // The Keystore, the key, or the provider is unavailable. The file
            // may be valid, so this must not be reported as corrupt data.
            throw TokenReadException(
                "The source token key is not available.",
                failure,
                TokenReadKind.TRANSIENT,
            )
        }
        val plain = try {
            cipher.doFinal(ciphertext)
        } catch (failure: Exception) {
            throw TokenReadException(
                "The source token file could not be decrypted.",
                failure,
                tokenDecodeFailureKind(failure),
            )
        }
        val token = try {
            plain.toString(Charsets.UTF_8)
        } finally {
            plain.fill(0)
        }
        if (token.isEmpty()) {
            throw TokenReadException(
                "The source token file is empty.",
                kind = TokenReadKind.CORRUPT,
            )
        }
        return token
    }

    internal companion object {
        internal const val KEY_ALIAS = "hotspotshade-source-token"
        private const val VERSION = 1
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val TAG_BITS = 128
        private const val MINIMUM_IV_LENGTH = 12
        private const val MAXIMUM_IV_LENGTH = 32

        /**
         * Return the Android Keystore key.
         *
         * [create] is true only on the save path. A load passes false, so a
         * missing key throws and never generates one.
         */
        private fun platformKey(alias: String, create: Boolean): SecretKey {
            val store = KeyStore.getInstance(ANDROID_KEYSTORE)
            store.load(null)
            val existing = store.getEntry(alias, null) as? KeyStore.SecretKeyEntry
            if (existing != null) return existing.secretKey
            if (!create) {
                throw KeyStoreException("The source token key is not available.")
            }
            val generator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                ANDROID_KEYSTORE,
            )
            generator.init(
                KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build(),
            )
            return generator.generateKey()
        }
    }
}

/**
 * Store the token in one app-private file with an Android Keystore AES key.
 *
 * TODO: Replace this class with EncryptedSharedPreferences when the project
 * approves the androidx.security.crypto dependency. This class has the same
 * security boundary: the ciphertext is in app-private storage and the key
 * stays in the Android Keystore.
 *
 * A missing file returns null. A file that exists and cannot be read throws
 * [TokenReadException]. A decoded value that cannot cross the wire is corrupt,
 * not a present token: the pairing listener, a pairing result, and a start all
 * use the same [isUsableSourceToken] rule. A missing or unreadable Keystore key
 * is a transient read error: a load never creates a key and never selects the
 * legacy copy for that failure. This class does not log.
 *
 * The target file lives in the no-backup directory. An older build wrote the
 * same file name in the files directory. This class resolves the active file
 * under the process lock on every load and save, so a store that was created
 * while the move failed retries the move later. A long-lived store therefore
 * cannot keep writing the legacy file after another instance completed the
 * move.
 *
 * The save path writes the no-backup target with a temporary file, syncs it,
 * verifies it, and replaces the token file with one atomic rename. It removes
 * a readable legacy copy only after the target is confirmed and the target
 * directory is synced. An unreadable legacy copy is kept: a wrong present key
 * produces the same authentication failure as damaged ciphertext, so the bytes
 * may still be recoverable with the correct key. Every failure after the
 * rename, including a failed target directory sync and a failed supersession
 * marker, throws [TokenWriteUncertainException] and retains any legacy copy.
 * Every instance uses one process-wide lock, so a load cannot see a
 * half-written file during a token rotation.
 * Path checks and file operations are not descriptor-anchored. They assume
 * app-private directories and a single process that owns them; another
 * process changing paths between checks and use is outside this boundary.
 *
 * The save path records a durable supersession marker in the no-backup
 * directory only after the target is confirmed when the legacy copy is
 * readable. A save that fails before the target is confirmed therefore leaves
 * the readable legacy copy usable. An unreadable legacy copy is latched before
 * the target changes because it is not a readable token and may be stale
 * ciphertext under another key. Once the marker exists, a corrupt or missing
 * target never uses the legacy copy. A load whose readable target leaves a
 * differing readable or unreadable legacy copy in place records the marker
 * before it returns the target, or fails closed when the marker cannot be
 * recorded or classified. The marker is a one-way latch and is not removed by
 * [clear]. A legacy-only upgrade has no marker, so its first move still works.
 *
 * A save that fails before the target is confirmed leaves a readable legacy
 * copy usable. A save that fails after the target is confirmed still changed
 * the visible target. It keeps any legacy copy and reports an uncertain
 * outcome. A later load fails closed until the latch is durable, because an
 * unlatched differing legacy copy is not treated as authoritative and the new
 * target is not returned while either copy could still be the active one.
 *
 * A legacy copy that is corrupt is never copied over an existing target. The
 * target may be valid ciphertext under another key, so the save latches the
 * ambiguous copy and replaces only the target it was asked to replace. A
 * failed save before that write leaves the ambiguous ciphertext unchanged.
 *
 * A test supplies [deleteFile] to simulate a failed delete and [readFile] to
 * simulate a read error. Production uses [File.delete] and [NioTokenFileReader].
 *
 * Only a path that the platform reports as missing
 * ([java.nio.file.NoSuchFileException]) is absent. Every other read error,
 * including a [java.io.FileNotFoundException] that stands for EACCES or EMFILE,
 * is transient: it never reports a missing token, never selects the legacy
 * copy, and never lets a caller generate a replacement token.
 */
internal class AndroidKeystoreTokenStore(
    private val targetFile: File,
    private val legacyFile: File? = null,
    private val codec: TokenFileCodec = KeystoreTokenFileCodec(),
    private val deleteFile: (File) -> Boolean = { it.delete() },
    private val readFile: TokenFileReader = NioTokenFileReader,
    private val markerFile: File? = defaultLegacyMarkerFile(targetFile, legacyFile),
    private val markerState: (File) -> LegacyMarkerState = LegacyTokenMarker::state,
    private val recordMarker: (File) -> Unit = LegacyTokenMarker::record,
    private val syncTargetParent: (File) -> Unit = ::syncTokenParent,
    private val syncLegacyParent: (File) -> Unit = ::syncTokenParent,
    private val appRoot: File? = null,
) : TokenStore, TokenWriter {
    private fun checkPaths(): CheckedPaths {
        if (appRoot != null && hasParentTraversal(appRoot)) {
            throw IOException("The source token path could not be classified.")
        }
        // Keep the raw comparison for the legacy file. Two raw paths that
        // differ only by "." name one entry, so the overlap check below must
        // still see both and reject them.
        val target = normalizedFile(targetFile)
        val legacy = legacyFile?.takeIf { it != targetFile }?.let(::normalizedFile)
        val marker = markerFile?.let(::normalizedFile)
        val paths = listOfNotNull(target, legacy, marker)
        var anchor = target.absoluteFile.toPath().normalize().parent
            ?: throw IOException("The source token path has no parent.")
        for (file in paths) {
            val parent = file.absoluteFile.toPath().normalize().parent
                ?: throw IOException("The source token path has no parent.")
            while (!parent.startsWith(anchor)) {
                anchor = anchor.parent ?: throw IOException("The source token paths have no common directory.")
            }
        }
        // Production supplies the platform app data directory as the trust
        // boundary. It must already exist as a directory; a missing anchor
        // cannot prove that a missing child below it is really absent. The
        // fallback supports standalone JVM stores with no Context; it cannot
        // detect aliases above the selected directory.
        val checkedAnchor = if (appRoot != null) {
            val root = normalizedFile(appRoot)
            val attributes = try {
                Files.readAttributes(root.toPath(), BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
            } catch (failure: Exception) {
                throw IOException("The source token directory could not be classified.", failure)
            }
            if (!attributes.isDirectory || attributes.isSymbolicLink) {
                throw IOException("The source token directory could not be classified.")
            }
            root
        } else {
            nearestDirectory(anchor.resolve(".token-path-check").toFile())
                ?: throw IOException("The source token directory could not be classified.")
        }
        val states = paths.map { pathState(it, checkedAnchor) }
        if (states.any { it == PathState.UNKNOWN }) {
            throw IOException("The source token path could not be classified.")
        }
        for (i in paths.indices) for (j in 0 until i) {
            val first = paths[i].absoluteFile.toPath().normalize()
            val second = paths[j].absoluteFile.toPath().normalize()
            if (first == second || (states[i] == PathState.PRESENT && states[j] == PathState.PRESENT &&
                    Files.isSameFile(first, second))) {
                throw IOException("The source token paths overlap.")
            }
        }
        return CheckedPaths(target, legacy, marker)
    }

    override fun load(): String? = synchronized(PROCESS_LOCK) {
        val paths = try { checkPaths() } catch (failure: Exception) {
            throw TokenReadException("The source token path could not be classified.", failure)
        }
        // A cleanup that removes a duplicate legacy copy runs only after this
        // call has decoded the returned token. A failed final read must not
        // leave the target as the only copy after the legacy copy was
        // deleted.
        val cleanups = mutableListOf<() -> Unit>()
        val source = resolveLocked(paths) { cleanups += it }
        val bytes = try {
            readFile.readOrNull(source)
        } catch (failure: Exception) {
            // The state is unknown. Do not report a missing token.
            throw TokenReadException("The source token file could not be read.", failure)
        } ?: return@synchronized null
        val token = try {
            codec.decode(bytes)
        } catch (failure: TokenReadException) {
            throw failure
        } catch (failure: Exception) {
            throw TokenReadException(
                "The source token file could not be decoded.",
                failure,
                TokenReadKind.TRANSIENT,
            )
        } finally {
            bytes.fill(0)
        }
        // A decoded value that cannot cross the wire is not a usable token.
        // Report it as unreadable instead of returning it as a present value.
        // The caller must not treat it as missing and must not replace it.
        if (!isUsableSourceToken(token)) {
            throw TokenReadException(
                "The source token file is not usable.",
                kind = TokenReadKind.CORRUPT,
            )
        }
        for (cleanup in cleanups) cleanup()
        token
    }

    /**
     * Save one token. Call this method after a pairing approval or a rotation.
     *
     * The write always goes to the no-backup target first. The complete target
     * file verifies as this token and its directory is synced before the
     * legacy copy is treated as superseded. A failed encode, write, or
     * verification therefore leaves both files unchanged. A failure after the
     * target is confirmed, including a failed marker, changed the visible
     * target and reports an uncertain outcome; both copies stay, and a later
     * load fails closed until the latch is durable.
     *
     * A readable legacy copy is removed only after the target is confirmed.
     * An unreadable legacy copy is kept: a wrong present key produces the same
     * authentication failure as damaged ciphertext, so those bytes may still be
     * recoverable with the correct key. The supersession marker is made durable
     * after the target is confirmed, except for an unreadable legacy copy,
     * which is latched before the target changes because it is not a readable
     * token. A marker write failure after the target is confirmed leaves the
     * new target and the old copy in place; a later load fails closed until the
     * marker can be recorded, so the stale copy cannot become active.
     *
     * An equal readable legacy token needs no marker. A differing readable
     * legacy token is stale after a confirmed target and is latched before it
     * is removed. If the marker cannot be recorded after the target changed,
     * the save reports an uncertain outcome and keeps both copies.
     *
     * The target rename is followed by a directory sync before legacy removal.
     * A sync or marker failure after rename reports an uncertain write: the
     * visible token may have changed, and a power loss may restore the previous
     * entry. In that case both copies stay, so a later load either returns a
     * confirmed target or fails closed.
     */
    override fun save(token: String) {
        require(isUsableSourceToken(token)) { "The source token is not usable." }
        synchronized(PROCESS_LOCK) {
            val paths = checkPaths()
            val target = paths.target
            val legacy = paths.legacy
            if (stateOf(target) == TokenFileState.TRANSIENT) {
                throw IOException("The source token file could not be read.")
            }
            // A previous deletion may be visible but not yet durable. Confirm
            // the legacy directory before relying on absence for a rotation.
            if (legacy != null && provenMissing(legacy) && legacy.absoluteFile.parentFile?.isDirectory == true) {
                syncLegacyParent(legacy)
            }
            // Inspect the legacy copy before encoding: encode may create a
            // missing Keystore key, which would turn an unreadable old
            // ciphertext into an apparent authentication failure.
            val marker = if (legacy != null) {
                prepareSaveLocked(target, legacy, paths.marker, token)
            } else {
                null
            }
            val bytes = codec.encode(token)
            try {
                AtomicFileWriter.write(
                    file = target,
                    syncParent = true,
                    parentSync = syncTargetParent,
                    verify = { temporary ->
                        val read = temporary.readBytes()
                        try {
                            if (codec.decode(read) != token) {
                                throw TokenReadException(
                                    "The source token file could not be confirmed.",
                                )
                            }
                        } finally {
                            read.fill(0)
                        }
                    },
                ) { output -> output.write(bytes) }
                // The target holds the confirmed token. Latch and remove the
                // legacy copy now. No latch was written before the target for
                // a readable copy, so a failed save above left it usable.
                if (legacy != null && marker != null) {
                    finishSaveLocked(marker, legacy, token)
                }
            } finally {
                bytes.fill(0)
            }
        }
    }

    /**
     * Inspect the legacy copy and latch an unreadable one before the target
     * changes.
     *
     * A readable legacy copy is not latched here: the marker is recorded after
     * the target is confirmed. A save that fails before the target changes then
     * leaves that copy usable instead of latching off the only readable token.
     * An unreadable copy is latched before the target changes because it is
     * not a readable token and may be stale ciphertext under another key.
     * If that latch succeeds but a later save fails while the target is absent,
     * a load reports a missing token. The unreadable legacy bytes stay on disk
     * but do not become a fallback while the marker remains present.
     *
     * A transient legacy copy is not proof of corruption. The save stops
     * unless a present marker and a readable target already show that the
     * target is authoritative. An unclassifiable marker stops the save while
     * both files are unchanged.
     *
     * Returns the marker path that [finishSaveLocked] records after the target
     * is confirmed.
     */
    private fun prepareSaveLocked(
        target: File,
        legacy: File,
        markerFile: File?,
        token: String,
    ): File {
        val marker = markerFor(target, legacy, markerFile)
        val initialMarkerState = markerState(marker)
        if (initialMarkerState == LegacyMarkerState.UNKNOWN) {
            throw IOException("The source token state could not be read.")
        }
        when (stateOf(legacy)) {
            TokenFileState.ABSENT -> Unit
            TokenFileState.CORRUPT -> {
                // The copy is potentially recoverable: a present but wrong
                // key produces the same authentication failure as damaged
                // ciphertext. Latch it before the target changes and keep it.
                recordSupersession(marker)
            }
            TokenFileState.TRANSIENT -> {
                // Once the marker is present, a readable target is
                // authoritative; an unreadable stale copy must not prevent
                // rotating that target. The copy stays because it may still be
                // recoverable under another key.
                if (initialMarkerState != LegacyMarkerState.PRESENT ||
                    stateOf(target) != TokenFileState.READABLE
                ) {
                    throw IOException("The legacy source token could not be read.")
                }
                recordSupersession(marker)
            }
            TokenFileState.READABLE -> {
                // Read the copy before encoding. A failure here is an ordinary
                // pre-write failure, so abort while the old state is intact.
                try {
                    readToken(legacy)
                } catch (failure: Exception) {
                    throw IOException("The legacy source token could not be read.", failure)
                }
            }
        }
        return marker
    }

    /**
     * Latch and remove the legacy copy after the target is confirmed.
     *
     * A readable copy is removed only after the marker is durable when it
     * differs from the new token. An equal copy needs no marker because it
     * cannot restore a different token. A copy that becomes unreadable after
     * the target write is kept and latched. Every marker failure here throws
     * [TokenWriteUncertainException]: the visible target may already hold the
     * requested token, so the caller must re-read before using a cached token
     * and must not treat the save as an ordinary, unchanged failure.
     */
    private fun finishSaveLocked(marker: File, legacy: File, token: String) {
        when (stateOf(legacy)) {
            TokenFileState.ABSENT -> Unit
            TokenFileState.READABLE -> {
                val legacyToken = try {
                    readToken(legacy)
                } catch (_: Exception) {
                    null
                }
                if (legacyToken == null) {
                    // The copy became unreadable after the target changed.
                    // Keep it and latch it before returning.
                    recordSupersessionAfterTarget(marker)
                    return
                }
                if (legacyToken != token) {
                    recordSupersessionAfterTarget(marker)
                }
                removeLegacy(legacy, deleteFile, syncLegacyParent)
            }
            TokenFileState.CORRUPT,
            TokenFileState.TRANSIENT,
            -> recordSupersessionAfterTarget(marker)
        }
    }

    /** Return the marker path, or fail the save when it cannot be recorded. */
    private fun markerFor(target: File, legacy: File, marker: File?): File =
        marker?.takeIf { it != target && it != legacy }
            ?: throw IOException("The source token state cannot be recorded.")

    /**
     * Make the marker durable before the target changes.
     *
     * A failed write or sync is an ordinary failure here: the target is still
     * the previous value, so the caller must leave it unchanged and report a
     * plain failure. A caller that already confirmed the target uses
     * [recordSupersessionAfterTarget] instead.
     */
    private fun recordSupersession(marker: File) {
        try {
            recordMarker(marker)
        } catch (failure: Exception) {
            throw IOException("The source token state could not be recorded.", failure)
        }
    }

    /**
     * Make the marker durable after the target may have changed.
     *
     * The visible target can already hold the requested token, so an ordinary
     * failure would let a caller keep a cached old token and would hide the
     * change from a guard epoch. Report every marker failure as an uncertain
     * write: the caller must re-read the store before using a token, and a
     * rotation or pairing result must be treated as superseded.
     */
    private fun recordSupersessionAfterTarget(marker: File) {
        try {
            recordMarker(marker)
        } catch (failure: Exception) {
            throw TokenWriteUncertainException(failure)
        }
    }

    /** Read, decode, and validate one readable token file. */
    private fun readToken(file: File): String {
        val bytes = readFile.read(file)
        val token = try {
            codec.decode(bytes)
        } finally {
            bytes.fill(0)
        }
        if (!isUsableSourceToken(token)) {
            throw TokenReadException(
                "The source token file is not usable.",
                kind = TokenReadKind.CORRUPT,
            )
        }
        return token
    }

    /**
     * Clear is blocked until guarded, durable deletion is implemented.
     *
     * A future implementation must remove the legacy copy before the target.
     * A crash between the two must not leave a removed target with a readable
     * legacy copy that restores the token. It must keep the supersession
     * marker as a one-way latch and use the same checked paths as load and
     * save.
     */
    fun clear(): Nothing = throw TokenDeleteException(
        "Clearing the source token is not supported.",
    )

    /** The file that the next load or save uses. A test uses this. */
    internal fun activeFile(): File = synchronized(PROCESS_LOCK) {
        val paths = try { checkPaths() } catch (failure: Exception) {
            throw TokenReadException("The source token path could not be classified.", failure)
        }
        resolveLocked(paths)
    }

    /**
     * Resolve the target or the legacy file for one operation.
     *
     * Call only while [PROCESS_LOCK] is held. A failed move returns the legacy
     * file for this operation and the next operation retries the move. A
     * target that exists but cannot be decoded does not win over a readable
     * legacy copy only when no supersession marker exists. A target that fails
     * with a transient Keystore or I/O error never falls back to the legacy
     * file: the legacy copy may be an older token, and a transient error must
     * not switch which token is active. A marker that cannot be classified
     * also prevents a legacy fallback.
     *
     * A readable target wins when the call can leave no unlatched legacy copy.
     * An equal readable legacy copy is a safe duplicate and may be removed. A
     * differing readable copy is kept and latched: it may be the token a
     * failed save requested before the target changed. A legacy copy that
     * cannot be decoded or read is kept because a wrong present key produces
     * the same failure as damaged ciphertext, and it is latched. The latch is
     * recorded before the readable target is returned, so a later target loss
     * cannot reactivate the kept copy. If the marker cannot be recorded or
     * classified, the call fails closed and changes neither file.
     *
     * When [scheduleCleanup] is non-null, a safe duplicate removal is handed
     * to it instead of running now. The caller runs the cleanup only after it
     * has decoded the returned token, so a failed final read cannot delete
     * the other copy.
     */
    private fun resolveLocked(
        paths: CheckedPaths,
        scheduleCleanup: ((() -> Unit) -> Unit)? = null,
    ): File {
        val target = paths.target
        val legacy = paths.legacy ?: return target
        if (legacy == target) return target
        return migrateTokenFileByState(
            target = target,
            legacy = legacy,
            targetState = ::stateOf,
            legacyState = ::stateOf,
            deleteFile = deleteFile,
            readFile = readFile,
            syncTargetParent = syncTargetParent,
            syncLegacyParent = syncLegacyParent,
            legacyMarkerState = {
                markerPath(paths, target, legacy)?.let(markerState)
                    ?: LegacyMarkerState.UNKNOWN
            },
            recordLegacyMarker = {
                val marker = markerPath(paths, target, legacy)
                    ?: throw IOException("The source token state cannot be recorded.")
                recordMarker(marker)
            },
            tokensEqual = { first, second ->
                // A read or decode failure here is not proof that the copies
                // differ or match. Keep the legacy copy unless both tokens are
                // proven equal.
                try {
                    readToken(first) == readToken(second)
                } catch (_: Exception) {
                    false
                }
            },
            preserveDifferingReadableLegacy = true,
            scheduleLegacyRemoval = scheduleCleanup,
        )
    }

    private fun markerPath(paths: CheckedPaths, target: File, legacy: File): File? =
        paths.marker?.takeIf { it != target && it != legacy }

    /**
     * Classify one token file.
     *
     * It reads and decodes the file, so a caller must use the result only to
     * choose an active file. The token text is discarded. A file that decodes
     * to a value that cannot cross the wire is [TokenFileState.CORRUPT], not
     * readable: the shared usability rule decides whether a value is a token.
     * Only a path that the platform reports as missing is
     * [TokenFileState.ABSENT]. Every other read error, including a
     * `FileNotFoundException` that stands for EACCES or EMFILE, and a path
     * that is not a regular file, is [TokenFileState.TRANSIENT].
     */
    private fun stateOf(file: File): TokenFileState {
        val bytes = try {
            readFile.readOrNull(file) ?: return TokenFileState.ABSENT
        } catch (_: Exception) {
            return TokenFileState.TRANSIENT
        }
        return try {
            val token = codec.decode(bytes)
            // A value that cannot cross the wire is not a usable token. Treat
            // it like an undecodable file so a usable legacy copy is not
            // deleted behind an unusable target.
            if (isUsableSourceToken(token)) {
                TokenFileState.READABLE
            } else {
                TokenFileState.CORRUPT
            }
        } catch (failure: TokenReadException) {
            if (failure.kind == TokenReadKind.CORRUPT) {
                TokenFileState.CORRUPT
            } else {
                TokenFileState.TRANSIENT
            }
        } catch (_: Exception) {
            TokenFileState.TRANSIENT
        } finally {
            bytes.fill(0)
        }
    }

    companion object Location {
        private const val TOKEN_FILE_NAME = "source-token.bin"

        /**
         * One lock for every token store in this process.
         *
         * The pairing listener and the settings page create separate
         * instances. A rotation must not race a load or a pairing save.
         */
        private val PROCESS_LOCK = Any()

        /**
         * Return the production token store for this app.
         *
         * The token file lives in [Context.getNoBackupFilesDir] so a backup
         * service cannot copy it even when a manifest rule is wrong. An older
         * build wrote the file to [Context.getFilesDir]. The first load or
         * save moves that file, so an upgrade does not lose an existing
         * pairing.
         *
         * [codec] is injectable so an instrumented test can use a disposable
         * key alias and an isolated Context. Production uses the default
         * Android Keystore codec.
         */
        fun forContext(
            context: Context,
            codec: TokenFileCodec = KeystoreTokenFileCodec(),
        ): AndroidKeystoreTokenStore {
            val target = File(context.noBackupFilesDir, TOKEN_FILE_NAME)
            val legacy = File(context.filesDir, TOKEN_FILE_NAME)
            // Keep both paths. The store resolves and retries the move under
            // the process lock on every operation, so a store that was created
            // during a failed move cannot keep writing the legacy file after
            // another instance completed the move.
            return AndroidKeystoreTokenStore(
                target,
                legacy,
                codec,
                appRoot = File(context.applicationInfo.dataDir),
            )
        }

        /**
         * Move one legacy token file to the no-backup directory.
         *
         * The migration runs under the process lock, so a rotation, a load,
         * a clear, and another migration cannot interleave. A target file that
         * decodes to a usable token wins. A readable legacy copy is removed so
         * a later clear cannot restore it. A legacy copy that cannot be decoded
         * is kept: a wrong present key produces the same authentication failure
         * as damaged ciphertext, so the bytes may still be recoverable. A target
         * that exists but cannot be decoded, or decodes to a value that cannot
         * cross the wire, never wins over a readable legacy copy: the legacy
         * copy stays in place and is used, so a corrupt or unusable target does
         * not delete the only usable token. A target with a transient Keystore
         * or I/O error never falls back to the legacy copy. A legacy copy that
         * is corrupt or transient is not treated as absent: the caller reports
         * an unreadable token, not a missing one. A failed write or a target
         * that does not verify as readable keeps the legacy file usable and a
         * later launch retries. A failed readable-legacy delete leaves both
         * files; the readable target wins and a later call retries the delete.
         *
         * This test seam has no marker writer and cannot compare tokens, so it
         * keeps the historical cleanup for a differing readable legacy copy.
         * The production store keeps such a copy and latches it. Unreadable
         * copies are kept here too; the store supplies the latch.
         */
        internal fun migrateTokenFile(
            target: File,
            legacy: File,
            targetReadable: (File) -> Boolean = { it.isFile },
            legacyReadable: (File) -> Boolean = { it.isFile },
            deleteFile: (File) -> Boolean = { it.delete() },
        ): File = synchronized(PROCESS_LOCK) {
            migrateTokenFileByState(
                target = target,
                legacy = legacy,
                targetState = { file -> stateFor(file, targetReadable) },
                legacyState = { file -> stateFor(file, legacyReadable) },
                deleteFile = deleteFile,
            )
        }

        /**
         * Resolve the target or the legacy file from their classified states.
         *
         * A readable target wins. An equal readable legacy copy is a safe
         * duplicate and may be removed after the target directory is synced.
         * When [preserveDifferingReadableLegacy] is true, a differing readable
         * legacy copy is kept and the supersession marker is made durable
         * before the target is returned, so a later target loss cannot
         * reactivate it. A marker that is already durable needs no new write
         * and no target sync. The test seam leaves that flag false because it
         * cannot compare tokens and has no marker writer.
         *
         * The target directory is synced only when this call will remove or
         * newly latch a legacy copy. A read of an already-visible target adds
         * no durability, and a durable present marker already holds a retained
         * copy off.
         *
         * A corrupt or transient legacy copy is kept and latched. An
         * unclassifiable marker fails closed. A transient target never falls
         * back to the legacy copy. A missing target uses a readable legacy copy
         * only when no latch exists; an unreadable legacy copy is returned as
         * an unreadable token, not as a missing one.
         *
         * [scheduleLegacyRemoval] defers a safe duplicate removal until the
         * caller has decoded the returned token.
         */
        internal fun migrateTokenFileByState(
            target: File,
            legacy: File,
            targetState: (File) -> TokenFileState,
            legacyState: (File) -> TokenFileState,
            deleteFile: (File) -> Boolean = { it.delete() },
            readFile: TokenFileReader = NioTokenFileReader,
            legacyMarkerState: () -> LegacyMarkerState = { LegacyMarkerState.ABSENT },
            recordLegacyMarker: (() -> Unit)? = null,
            syncTargetParent: (File) -> Unit = ::syncTokenParent,
            syncLegacyParent: (File) -> Unit = ::syncTokenParent,
            tokensEqual: (File, File) -> Boolean = { _, _ -> false },
            preserveDifferingReadableLegacy: Boolean = false,
            scheduleLegacyRemoval: ((() -> Unit) -> Unit)? = null,
        ): File = synchronized(PROCESS_LOCK) {
            val confirmRemoval: (() -> Unit) -> Unit = scheduleLegacyRemoval ?: { it() }
            val removeNow = {
                confirmRemoval { removeLegacy(legacy, deleteFile, syncLegacyParent) }
            }
            val targetResult = targetState(target)
            val legacyResult = legacyState(legacy)
            val marker = when (targetResult) {
                TokenFileState.CORRUPT,
                TokenFileState.ABSENT,
                -> readMarkerState(legacyMarkerState)
                TokenFileState.READABLE,
                TokenFileState.TRANSIENT,
                -> LegacyMarkerState.ABSENT
            }
            return@synchronized when (targetResult) {
                TokenFileState.READABLE -> {
                    // A target-directory sync is a guard for a decision that
                    // depends on the target being durable: removing an equal
                    // legacy copy, or recording a new latch. It is not a
                    // general durability refresh for a target that is already
                    // visible. A durable present marker already keeps a
                    // retained copy latched off, and a read with no legacy
                    // copy writes nothing, so neither case needs the sync.
                    var targetSync: Boolean? = null
                    fun targetSynced(): Boolean {
                        targetSync?.let { return it }
                        val result = try {
                            syncTargetParent(target)
                            true
                        } catch (_: Exception) {
                            false
                        }
                        targetSync = result
                        return result
                    }
                    when (legacyResult) {
                        TokenFileState.READABLE -> {
                            val equal = tokensEqual(target, legacy)
                            if (equal) {
                                // An equal copy cannot restore a different
                                // token, so removing it is safe once the
                                // target directory is confirmed. A failed
                                // removal leaves both copies and a later call
                                // retries.
                                if (targetSynced()) removeNow()
                            } else if (preserveDifferingReadableLegacy) {
                                // A differing copy may be the token a failed
                                // save requested before the target changed, or
                                // the previous token after a confirmed save.
                                // Keep it and latch it now, so a later target
                                // loss cannot make it active.
                                ensureLegacyLatch(
                                    legacyMarkerState,
                                    recordLegacyMarker,
                                    { targetSynced() },
                                )
                            } else if (targetSynced()) {
                                when (readMarkerState(legacyMarkerState)) {
                                    // The test seam has no token comparison and
                                    // no marker writer. Keep its historical
                                    // migration cleanup for a differing copy
                                    // only when no latch exists.
                                    LegacyMarkerState.ABSENT -> removeNow()
                                    // A latched readable copy that differs from
                                    // the target may be the token a failed save
                                    // requested before the target changed. Keep
                                    // it for recovery.
                                    LegacyMarkerState.PRESENT -> Unit
                                    // An unclassified marker must not authorize
                                    // a destructive cleanup.
                                    LegacyMarkerState.UNKNOWN -> Unit
                                }
                            }
                        }
                        // A corrupt or transient legacy copy may be a valid
                        // ciphertext under another key. Keep it and make the
                        // marker durable before returning the target, so a
                        // later missing or corrupt target cannot reactivate it.
                        TokenFileState.CORRUPT,
                        TokenFileState.TRANSIENT,
                        -> ensureLegacyLatch(
                            legacyMarkerState,
                            recordLegacyMarker,
                            { targetSynced() },
                        )
                        TokenFileState.ABSENT -> Unit
                    }
                    target
                }
                // A transient target error is not proof that the legacy copy
                // is newer or more valid. Keep using the target so the caller
                // reports an unreadable stored token instead of silently
                // switching tokens.
                TokenFileState.TRANSIENT -> target
                TokenFileState.CORRUPT -> when {
                    // A recorded marker makes the legacy copy stale even when
                    // the target can no longer be decoded.
                    marker == LegacyMarkerState.PRESENT -> target
                    marker == LegacyMarkerState.UNKNOWN -> throw unclassifiedMarkerFailure()
                    legacyResult == TokenFileState.READABLE -> legacy
                    else -> target
                }
                TokenFileState.ABSENT -> when {
                    // Once superseded, a missing target is a missing token. The
                    // legacy copy must not be moved back or read.
                    marker == LegacyMarkerState.PRESENT -> target
                    marker == LegacyMarkerState.UNKNOWN -> throw unclassifiedMarkerFailure()
                    else -> when (legacyResult) {
                        TokenFileState.ABSENT -> target
                        TokenFileState.READABLE ->
                            moveLegacy(
                                target,
                                legacy,
                                deleteFile,
                                readFile,
                                syncTargetParent,
                                syncLegacyParent,
                                onTargetConfirmed = confirmRemoval,
                            ) {
                                targetState(target) == TokenFileState.READABLE
                            }
                        // An unreadable legacy copy is an unreadable stored
                        // token. Returning the target would report
                        // TOKEN_MISSING.
                        TokenFileState.CORRUPT,
                        TokenFileState.TRANSIENT,
                        -> legacy
                    }
                }
            }
        }

        /**
         * Make the supersession latch durable before a readable target is
         * returned, or fail closed.
         *
         * UNKNOWN is not safe to write over: the real marker writer cannot
         * classify the path, and another writer could own it. Fail closed
         * instead of replacing it. A PRESENT marker is already durable, so the
         * latch needs no target sync. ABSENT may be recorded, but only after
         * [targetSynced] confirms the target directory entry. A marker
         * recorded against an unconfirmed target could outlive that target
         * after a power loss, so a failed sync fails closed before anything is
         * written. The result is read back and must be PRESENT. The test seam
         * has no writer, so ABSENT is left unlatched there.
         */
        private fun ensureLegacyLatch(
            read: () -> LegacyMarkerState,
            record: (() -> Unit)?,
            targetSynced: () -> Boolean,
        ) {
            when (readMarkerState(read)) {
                LegacyMarkerState.PRESENT -> Unit
                LegacyMarkerState.UNKNOWN -> throw unclassifiedMarkerFailure()
                LegacyMarkerState.ABSENT -> {
                    if (record == null) return
                    if (!targetSynced()) {
                        throw TokenReadException(
                            "The source token target could not be synced.",
                            kind = TokenReadKind.TRANSIENT,
                        )
                    }
                    try {
                        record()
                    } catch (failure: Exception) {
                        throw TokenReadException(
                            "The source token state could not be recorded.",
                            failure,
                            TokenReadKind.TRANSIENT,
                        )
                    }
                    if (readMarkerState(read) != LegacyMarkerState.PRESENT) {
                        throw unclassifiedMarkerFailure()
                    }
                }
            }
        }

        /**
         * A marker check that could not be classified must not select either
         * the legacy copy or a generated replacement. The caller reports an
         * unreadable stored token and retries later.
         */
        private fun unclassifiedMarkerFailure(): TokenReadException =
            TokenReadException(
                "The source token state could not be read.",
                kind = TokenReadKind.TRANSIENT,
            )

        private fun readMarkerState(read: () -> LegacyMarkerState): LegacyMarkerState = try {
            read()
        } catch (_: Exception) {
            LegacyMarkerState.UNKNOWN
        }

        private fun stateFor(file: File, readable: (File) -> Boolean): TokenFileState = try {
            when {
                !file.isFile -> TokenFileState.ABSENT
                readable(file) -> TokenFileState.READABLE
                else -> TokenFileState.CORRUPT
            }
        } catch (_: Exception) {
            TokenFileState.TRANSIENT
        }

        private fun moveLegacy(
            target: File,
            legacy: File,
            deleteFile: (File) -> Boolean,
            readFile: TokenFileReader,
            syncTargetParent: (File) -> Unit,
            syncLegacyParent: (File) -> Unit,
            onTargetConfirmed: (() -> Unit) -> Unit,
            targetIsReadable: () -> Boolean,
        ): File = try {
            val bytes = readFile.read(legacy)
            try {
                // Use the same target-directory durability rule as the save
                // path. A sync failure after the rename is uncertain, so the
                // legacy copy stays the active one for this call and a later
                // call retries the confirmed target.
                AtomicFileWriter.write(
                    target,
                    syncParent = true,
                    parentSync = syncTargetParent,
                ) { output -> output.write(bytes) }
            } finally {
                bytes.fill(0)
            }
            if (targetIsReadable()) {
                // A caller that has not decoded the returned token yet defers
                // this removal, so a failed final read keeps both copies.
                onTargetConfirmed { removeLegacy(legacy, deleteFile, syncLegacyParent) }
                target
            } else {
                // The target could not be confirmed. Keep the legacy copy so
                // the only readable token is not lost; a later call retries.
                legacy
            }
        } catch (_: Exception) {
            // Keep the old file usable for this launch. A later launch
            // retries the move.
            legacy
        }

        /**
         * Remove a duplicate or superseded legacy copy. A failed delete leaves
         * both files; the target wins. A later save retries the delete. A load
         * retries it only when the copy is proven equal to the target, so a
         * differing or unreadable copy is never deleted by a load. A caller
         * retries a failed deletion after a later successful target sync.
         *
         * A failed parent sync after a successful delete is also swallowed.
         * The deletion may reappear after a power loss, so a later call retries
         * it. An equal copy cannot restore a different token. When the save
         * path created a differing stale state, the supersession marker was
         * durable before the copy was deleted, so a reappearing copy stays
         * latched off.
         */
        private fun removeLegacy(
            legacy: File,
            deleteFile: (File) -> Boolean,
            syncParent: (File) -> Unit,
        ) {
            try {
                if (!provenMissing(legacy) && deleteFile(legacy)) {
                    syncParent(legacy)
                }
            } catch (_: Exception) {
                // The readable target still wins. A later call retries.
            }
        }
    }
}
