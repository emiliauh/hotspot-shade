package com.hotspotshade.source

import android.annotation.SuppressLint
import android.content.SharedPreferences
import com.hotspotshade.source.pairing.PairingError
import com.hotspotshade.source.pairing.PairingException
import com.hotspotshade.source.pairing.PairingProtocol
import com.hotspotshade.source.pairing.PairingTrustStore
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID

/**
 * One trusted target device, for the app list.
 *
 * [id] is the stored public key. It is public, but the app shows only [label].
 * Text output hides the id.
 */
internal enum class TargetConfirmation { CONFIRMED, REQUIRED, UNKNOWN }

internal data class TrustedTarget(
    val id: String,
    val label: String,
    val confirmation: TargetConfirmation = TargetConfirmation.UNKNOWN,
) {
    override fun toString(): String = "TrustedTarget($label)"
}

/** List and remove trusted target devices. A JVM test uses a fake. */
internal interface PairingTrustAdmin {
    /** Return the trusted targets. The order is stable. */
    fun targets(): List<TrustedTarget>

    /** Remove one target by its id. Return true when the list changed. */
    fun forget(id: String): Boolean

    /** Remove every trusted target. */
    fun forgetAll()
}

/**
 * Serialize a pairing trust decision against an administrative trust change.
 *
 * A pairing result is honest only when the trust decision that allowed it is
 * current while the responder builds the credentials or status answer. The
 * responder runs that check and build through [decision]. The settings page
 * runs Forget and Forget all through [mutation]. The two sections are mutually
 * exclusive, so a Forget that wins makes a waiting decision reject before it
 * creates credentials, and a decision that wins finishes before the Forget
 * removes the key.
 *
 * The boundary orders the decision and the mutation. It cannot retract a frame
 * that the listener already sealed or sent. A result sealed before a mutation
 * may still be written after the mutation returns. The target device may then
 * hold that token. Rotation changes the token, but its durability across power
 * loss and restore has not been established on a physical device.
 *
 * Lock order: the listener lock, then this gate, then the coordinator lock,
 * the token guard, and the trust or token store. A caller must not take this
 * gate while it holds the refresh lock, the coordinator lock, the token guard,
 * or a store lock. A trust mutation takes the gate and then the trust store.
 */
internal interface PairingTrustGate {
    /** The revision of the trust state. A mutation moves it once. */
    fun revision(): Long

    /**
     * Run one pairing trust check and the credential or status build that
     * depends on it. The value is the revision that the decision used.
     */
    fun <T> decision(block: (revision: Long) -> T): T

    /** Run one trust mutation and move the revision once it succeeds. */
    fun <T> mutation(block: () -> T): T
}

/** The gate for the app process. */
internal object ProcessPairingTrustGate : PairingTrustGate {
    private val lock = Any()
    private var revisionValue = 0L

    override fun revision(): Long = synchronized(lock) { revisionValue }

    override fun <T> decision(block: (revision: Long) -> T): T = synchronized(lock) {
        block(revisionValue)
    }

    override fun <T> mutation(block: () -> T): T = synchronized(lock) {
        val result = block()
        revisionValue += 1
        result
    }
}

/**
 * A short public label for one stored target key.
 *
 * The label is the first four bytes of the SHA-256 digest. It is stable for a
 * key and it does not show the key. Two keys can share a label with a low
 * probability.
 */
internal object TrustFingerprint {
    fun label(storedKey: String): String {
        val input = try {
            Base64.getDecoder().decode(storedKey)
        } catch (_: Exception) {
            storedKey.toByteArray(Charsets.UTF_8)
        }
        val digest = MessageDigest.getInstance("SHA-256").digest(input)
        val hex = buildString(8) {
            for (index in 0 until 4) {
                val value = digest[index].toInt() and 0xFF
                append(HEX[(value shr 4) and 0x0F])
                append(HEX[value and 0x0F])
            }
        }
        return "Target device $hex"
    }

    private const val HEX = "0123456789abcdef"
}

/**
 * Stored keys are pending confirmation on every process start. This is a
 * deliberate fail-closed control, not an oversight, and it differs from iOS,
 * which keeps trust across launches. The reason: a saved key is what lets a
 * target skip the Allow prompt, and this store cannot prove after a restart
 * that the file shows the person's last decision. A Forget whose first write
 * failed leaves the old key on disk with no record, a failed unlink or
 * directory sync can leave a replaced file in doubt, and there is no protocol
 * acknowledgement that a committed add reached the target. Re-confirming each
 * key in the new process means a key the person removed can never come back
 * silently. The price is one Allow per saved target after each process
 * restart. Only confirmation in this process activates a key.
 *
 * The intent blocks an interrupted transaction. A failed first intent may
 * leave no record, so a failed removal still requires token rotation. Legacy
 * preferences are left intact pending an upgrade decision. Older app versions
 * can read them after a downgrade; this store cannot enforce downgrade safety.
 */
internal class FilePairingTrustStore(
    private val file: java.io.File,
    private val preferences: SharedPreferences,
    private val disk: TrustDisk = RealTrustDisk,
) : PairingTrustStore, PairingTrustAdmin {
    private val intent get() = java.io.File(file.path + ".intent")
    private val migrated get() = java.io.File(file.path + ".migrated")
    private val identity get() = file.absoluteFile.normalize().path

    override fun contains(publicKey: ByteArray): Boolean = synchronized(LOCK) {
        load().contains(encode(publicKey)) && active[identity]?.contains(encode(publicKey)) == true
    }
    override fun add(publicKey: ByteArray) = synchronized(LOCK) {
        val keys = load()
        val key = encode(publicKey)
        val added = keys.add(key)
        if (added) save(keys)
        active.getOrPut(identity) { mutableSetOf() }.add(key)
        // The entry names no key. A failed save threw above and logged nothing.
        ActivityLog.record(if (added) ActivityEvent.TARGET_ADDED else ActivityEvent.TARGET_CONFIRMED)
        Unit
    }
    override fun remove(publicKey: ByteArray) = synchronized(LOCK) {
        val keys = load()
        val key = encode(publicKey)
        if (keys.remove(key)) {
            save(keys)
            ActivityLog.record(ActivityEvent.TARGET_REMOVED)
        }
        active[identity]?.remove(key)
        Unit
    }
    override val count: Int get() = synchronized(LOCK) { load().size }
    override fun targets(): List<TrustedTarget> = synchronized(LOCK) {
        load().map {
            val confirmation = if (active[identity]?.contains(it) == true) {
                TargetConfirmation.CONFIRMED
            } else {
                TargetConfirmation.REQUIRED
            }
            TrustedTarget(it, TrustFingerprint.label(it), confirmation)
        }
            .sortedWith(compareBy({ it.label }, { it.id }))
    }
    override fun forget(id: String): Boolean = synchronized(LOCK) {
        val keys = load()
        if (!keys.remove(id)) return@synchronized false
        save(keys)
        active[identity]?.remove(id)
        true
    }
    override fun forgetAll() = synchronized(LOCK) {
        transaction(emptySet())
        active.remove(identity)
        Unit
    }

    private fun load(): MutableSet<String> = guarded {
        if (identity in uncertain || disk.exists(intent)) fail()
        if (!disk.exists(migrated)) {
            // An existing data file without its migration marker is ambiguous.
            if (disk.exists(file) || preferences.contains(LEGACY_INTENT)) fail()
            val legacy = preferences.getStringSet(LEGACY_KEY, emptySet()) ?: fail()
            val keys = legacy.toMutableSet()
            validate(keys)
            // The old preferences format cannot prove that a key survived a
            // confirmed commit. An unrelated editor may have persisted a
            // failed add after removing its intent in memory. Do not promote
            // any such key without a new pairing confirmation.
            if (keys.isNotEmpty()) fail()
            transaction(keys)
        }
        if (!disk.exists(file)) fail()
        decode(disk.read(file))
    }

    private fun save(keys: Set<String>) = transaction(keys)

    private fun transaction(keys: Set<String>) = guarded {
        validate(keys)
        uncertain.add(identity)
        // A failed initial write has no durable record. The in-process latch
        // still blocks decisions until an explicit reset succeeds.
        disk.write(intent, MARKER)
        disk.write(migrated, MARKER)
        disk.write(file, (HEADER + keys.sorted().joinToString("\n", postfix = "\n"))
            .toByteArray(Charsets.US_ASCII))
        disk.delete(intent)
        uncertain.remove(identity)
        Unit
    }

    private fun decode(bytes: ByteArray): MutableSet<String> {
        if (bytes.size > MAX_BYTES) fail()
        val text = bytes.toString(Charsets.US_ASCII)
        if (!(text.startsWith(HEADER) || text.startsWith(OLD_HEADER)) || !text.endsWith("\n")) fail()
        val header = if (text.startsWith(HEADER)) HEADER else OLD_HEADER
        val lines = text.removePrefix(header).removeSuffix("\n")
        val keys = if (lines.isEmpty()) mutableSetOf() else lines.split('\n').toMutableSet()
        if (lines.isNotEmpty() && keys.size != lines.split('\n').size) fail()
        validate(keys)
        return keys
    }
    private fun validate(keys: Set<String>) {
        if (keys.size > MAX_KEYS) fail()
        keys.forEach { key ->
            val decoded = try { Base64.getDecoder().decode(key) } catch (_: Exception) { fail() }
            if (decoded.size != 32 || encode(decoded) != key) fail()
        }
    }
    private fun encode(key: ByteArray): String = Base64.getEncoder().encodeToString(key)
    private fun fail(): Nothing = throw PairingException(PairingError.TRUST_STORE)
    private inline fun <T> guarded(block: () -> T): T = try { block() } catch (_: Exception) { fail() }

    internal companion object {
        private const val LEGACY_KEY = "paired-targets"
        private const val LEGACY_INTENT = "paired-targets-write-intent"
        private const val HEADER = "hotspotshade-trust-pending-v2\n"
        private const val OLD_HEADER = "hotspotshade-trust-v1\n"
        private val MARKER = "hotspotshade-trust-transaction-v1\n".toByteArray(Charsets.US_ASCII)
        private const val MAX_KEYS = 4096
        private const val MAX_BYTES = 200_000
        private val LOCK = Any()
        private val uncertain = mutableSetOf<String>()
        private val active = mutableMapOf<String, MutableSet<String>>()
        // A test simulates process death. Production never clears the latch this way.
        internal fun simulateProcessRestartForTest() = synchronized(LOCK) { uncertain.clear(); active.clear() }
    }
}

/** Disk boundary for deterministic crash and I/O failure tests. */
internal interface TrustDisk {
    fun exists(file: java.io.File): Boolean
    fun read(file: java.io.File): ByteArray
    fun write(file: java.io.File, bytes: ByteArray)
    fun delete(file: java.io.File)
}

internal object RealTrustDisk : TrustDisk by FileTrustDisk()

/** The callback is used only by JVM tests to inject storage failures. */
internal class FileTrustDisk(private val checkpoint: (String) -> Unit = {}) : TrustDisk {
    override fun exists(file: java.io.File): Boolean {
        val path = file.toPath()
        if (java.nio.file.Files.exists(path, java.nio.file.LinkOption.NOFOLLOW_LINKS)) return true
        if (java.nio.file.Files.notExists(path, java.nio.file.LinkOption.NOFOLLOW_LINKS)) return false
        throw java.io.IOException("Trust path state is inconclusive")
    }
    override fun read(file: java.io.File): ByteArray {
        if (!java.nio.file.Files.isRegularFile(file.toPath(), java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            throw java.io.IOException("Trust file is not regular")
        }
        if (java.nio.file.Files.size(file.toPath()) > 200_000) throw java.io.IOException("Trust file too large")
        return java.nio.file.Files.readAllBytes(file.toPath())
    }
    override fun write(file: java.io.File, bytes: ByteArray) {
        val directory = file.absoluteFile.parentFile ?: throw java.io.IOException("Missing directory")
        if (!directory.isDirectory) throw java.io.IOException("Missing directory")
        val temp = java.io.File.createTempFile("trust-", ".tmp", directory)
        try {
            java.io.FileOutputStream(temp).use {
                checkpoint("before-write")
                it.write(bytes)
                checkpoint("after-write")
                it.fd.sync()
                checkpoint("after-file-sync")
            }
            checkpoint("before-rename")
            java.nio.file.Files.move(temp.toPath(), file.toPath(),
                java.nio.file.StandardCopyOption.ATOMIC_MOVE, java.nio.file.StandardCopyOption.REPLACE_EXISTING)
            checkpoint("after-rename")
            sync(directory)
        } finally { java.nio.file.Files.deleteIfExists(temp.toPath()) }
    }
    override fun delete(file: java.io.File) {
        checkpoint("before-delete")
        java.nio.file.Files.delete(file.toPath())
        checkpoint("after-delete")
        sync(file.absoluteFile.parentFile ?: throw java.io.IOException("Missing directory"))
    }
    private fun sync(directory: java.io.File) {
        checkpoint("before-directory-sync")
        java.nio.channels.FileChannel.open(directory.toPath(), java.nio.file.StandardOpenOption.READ)
            .use { it.force(true) }
        checkpoint("after-directory-sync")
    }
}

/** The result of a token rotation request. */
internal enum class TokenRotateResult {
    ROTATED,
    REFUSED_RUNNING,
    FAILED,
}

/** Create a new random source token. It is 32 bytes in lower-case hex. */
internal object TokenRotation {
    const val BYTE_COUNT = 32

    fun newToken(random: SecureRandom = SecureRandom()): String {
        val bytes = ByteArray(BYTE_COUNT)
        random.nextBytes(bytes)
        val token = PairingProtocol.hex(bytes)
        bytes.fill(0)
        return token
    }
}

/**
 * Change the real pairing stores from the app UI.
 *
 * A token rotation is refused while the proxy is active. A running proxy holds
 * the old token, and a rotation would break the paired target devices at the
 * next start. Rotation does not remove trust: a known target device can pair
 * again without a prompt.
 */
internal class PairingAdmin(
    private val trust: PairingTrustAdmin,
    private val tokenStore: TokenWriter,
    private val tokenFactory: () -> String = { TokenRotation.newToken() },
    private val isProxyActive: () -> Boolean = {
        // One binding snapshot: a start or a stop between two separate reads
        // must not report a run that no longer exists.
        SourceProxyRuntime.binding().active
    },
    private val guard: SourceTokenGuard = SourceTokenGuard.shared,
    private val trustGate: PairingTrustGate = ProcessPairingTrustGate,
) {
    fun targets(): List<TrustedTarget> = trust.targets()

    /**
     * Remove one target. Return false when the store cannot read or write.
     *
     * The mutation runs through [PairingTrustGate], so it is ordered against a
     * pairing trust decision that is building credentials or a status answer.
     */
    fun forget(id: String): Boolean = try {
        trustGate.mutation { trust.forget(id) }
    } catch (_: Exception) {
        false
    }

    /**
     * Remove every target. Return false when the store cannot write.
     *
     * The mutation runs through [PairingTrustGate]. A decision that already
     * sealed a result before this call is not retracted; see the gate comment.
     */
    fun forgetAll(): Boolean = try {
        trustGate.mutation { trust.forgetAll() }
        true
    } catch (_: Exception) {
        false
    }

    /**
     * Replace the source token.
     *
     * A proxy run holds the shared guard, so a rotation that arrives while a
     * run starts or serves flows is refused and writes nothing. The guard and
     * the epoch make the decision atomic with the run's token load.
     */
    fun rotateToken(): TokenRotateResult {
        // The runtime state is a fast refusal for the UI. The guard is the
        // authority: a start can be between its token load and its first
        // published state.
        if (isProxyActive()) return TokenRotateResult.REFUSED_RUNNING
        return when (guard.rotate { tokenStore.save(tokenFactory()) }) {
            TokenMutationResult.WRITTEN -> TokenRotateResult.ROTATED
            TokenMutationResult.REFUSED_RUNNING -> TokenRotateResult.REFUSED_RUNNING
            TokenMutationResult.FAILED -> TokenRotateResult.FAILED
        }
    }
}

/** One saved proxy port. A JVM test supplies a fake. */
internal interface ProxyPortStore {
    fun load(): Int

    fun save(port: Int)

    fun clear()
}

/** Store the proxy port in SharedPreferences. It is not secret. */
internal class SharedPreferencesProxyPortStore(
    private val preferences: SharedPreferences,
) : ProxyPortStore {
    override fun load(): Int = preferences.getInt(KEY, 0)

    @SuppressLint("ApplySharedPref", "UseKtx")
    override fun save(port: Int) {
        val saved = try {
            preferences.edit().putInt(KEY, port).commit()
        } catch (_: Exception) {
            false
        }
        if (!saved) throw IllegalStateException("The proxy port could not be saved.")
    }

    @SuppressLint("ApplySharedPref", "UseKtx")
    override fun clear() {
        val cleared = try {
            preferences.edit().remove(KEY).commit()
        } catch (_: Exception) {
            false
        }
        if (!cleared) throw IllegalStateException("The proxy port could not be cleared.")
    }

    private companion object {
        const val KEY = "proxy-port"
    }
}

/** Check whether a port is free on one local address. A JVM test uses a fake. */
internal interface PortProbe {
    fun isFree(address: InetAddress, port: Int): Boolean

    /** Ask the operating system for one free port on [address], or 0. */
    fun freePort(address: InetAddress): Int
}

/** Check a port with a short bind. It opens no egress socket and no route. */
internal class SocketPortProbe : PortProbe {
    override fun isFree(address: InetAddress, port: Int): Boolean {
        if (port < 1024 || port > 65535 || port == PairingProtocol.PAIRING_PORT) return false
        return try {
            ServerSocket().use { socket ->
                socket.reuseAddress = false
                socket.bind(InetSocketAddress(address, port), 1)
            }
            true
        } catch (_: Exception) {
            false
        }
    }

    override fun freePort(address: InetAddress): Int = try {
        var port = 0
        ServerSocket().use { socket ->
            socket.reuseAddress = false
            socket.bind(InetSocketAddress(address, 0), 1)
            port = socket.localPort
        }
        port
    } catch (_: Exception) {
        0
    }
}

/**
 * Serialize an advisory free-port probe against a real proxy bind.
 *
 * The operating system gives no way to hold a port between a pairing answer
 * and the next proxy start. The probe is therefore advisory. A start marks the
 * bind section here, and an advisory probe refuses to answer while it runs.
 * Without this gate a probe could see the proxy's own new listener as busy and
 * advertise a port that the proxy never bound.
 */
internal object ProxyBindGate {
    private val lock = Any()
    private var binding = false

    /** True while a proxy start owns the bind section. */
    fun isBinding(): Boolean = synchronized(lock) { binding }

    /**
     * Run one claim-and-bind section. The section must not start a pairing
     * listener or call back into this object.
     */
    fun <T> duringBind(block: () -> T): T {
        synchronized(lock) { binding = true }
        try {
            return block()
        } finally {
            synchronized(lock) { binding = false }
        }
    }

    /**
     * Run one advisory probe only when no bind is in progress. Return null
     * when a bind is in progress or the probe itself has no proven port.
     */
    fun <T> probeWhenIdle(block: () -> T?): T? = synchronized(lock) {
        if (binding) null else block()
    }
}

/**
 * Choose the source proxy port.
 *
 * A pairing answer and the next proxy start should name the same port. The
 * operating system cannot reserve a port for that gap, so [reserve] is only
 * an advisory free-port probe: it proves the port is free now and remembers
 * it, but another process can take it before the proxy binds. The start path
 * probes again with [claim] and saves the port that actually bound with
 * [remember]. The authenticated status answer then reports the bound port.
 *
 * [reserve] returns null while a proxy start owns the bind section, so it can
 * never advertise a port that the proxy is about to bind on another value.
 */
internal class ProxyPortPolicy(
    private val store: ProxyPortStore,
    private val probe: PortProbe = SocketPortProbe(),
    private val random: SecureRandom = SecureRandom(),
) {
    /**
     * Probe one advisory free port for a pairing answer, or return null.
     *
     * A saved port that is still free is returned as it is. A saved port that
     * another process now holds is replaced by a free port, and the new value
     * is saved so the next start prefers it. A failed save returns null: the
     * answer must not name a port that the next start cannot reuse. A probe
     * during a real bind returns null.
     */
    fun reserve(hotspot: InetAddress): Int? =
        ProxyBindGate.probeWhenIdle { reserveLocked(hotspot) }

    private fun reserveLocked(hotspot: InetAddress): Int? = synchronized(PROCESS_LOCK) {
        val saved = loadSaved()
        if (isUsable(saved) && isFree(hotspot, saved)) return@synchronized saved
        val picked = try {
            pick(hotspot)
        } catch (_: Exception) {
            return@synchronized null
        }
        if (!isUsable(picked)) return@synchronized null
        try {
            store.save(picked)
            picked
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Choose the port for one proxy start without saving a candidate.
     *
     * A saved port that is still free is stable across starts. A saved port
     * that another process now holds is replaced for this attempt. The caller
     * saves the bound port with [remember] only after the listener starts, so
     * a failed start cannot persist a candidate that never bound and cannot
     * erase the remembered port.
     */
    fun claim(hotspot: InetAddress): Int = synchronized(PROCESS_LOCK) {
        val saved = loadSaved()
        if (isUsable(saved) && isFree(hotspot, saved)) saved else pick(hotspot)
    }

    /** Save the port that the listener bound. */
    fun remember(port: Int) {
        synchronized(PROCESS_LOCK) {
            if (isUsable(port)) store.save(port)
        }
    }

    /** Remove the saved port. A test and a repair action use this. */
    fun clear() {
        synchronized(PROCESS_LOCK) { store.clear() }
    }

    private fun loadSaved(): Int = try {
        store.load()
    } catch (_: Exception) {
        0
    }

    private fun isFree(hotspot: InetAddress, port: Int): Boolean =
        try {
            probe.isFree(hotspot, port)
        } catch (_: Exception) {
            false
        }

    private fun pick(hotspot: InetAddress): Int {
        repeat(PICK_ATTEMPTS) {
            val candidate = MINIMUM_PORT + random.nextInt(MAXIMUM_PORT - MINIMUM_PORT + 1)
            if (candidate == PairingProtocol.PAIRING_PORT) return@repeat
            if (probe.isFree(hotspot, candidate)) return candidate
        }
        return probe.freePort(hotspot)
    }

    private fun isUsable(port: Int): Boolean =
        port in 1024..65535 && port != PairingProtocol.PAIRING_PORT

    private companion object {
        const val MINIMUM_PORT = 20_000
        const val MAXIMUM_PORT = 59_999
        const val PICK_ATTEMPTS = 8

        /**
         * One lock for every port policy in this process.
         *
         * The pairing listener and the source proxy create separate policy
         * instances over the same store. A reserve, a claim, and a remember
         * must not interleave their load and save steps.
         */
        val PROCESS_LOCK = Any()
    }
}
