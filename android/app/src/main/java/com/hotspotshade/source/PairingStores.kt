package com.hotspotshade.source

import android.content.SharedPreferences
import androidx.core.content.edit
import com.hotspotshade.source.pairing.PairingProtocol
import com.hotspotshade.source.pairing.PairingTrustStore
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/**
 * One trusted target device, for the app list.
 *
 * [id] is the stored public key. It is public, but the app shows only [label].
 * Text output hides the id.
 */
internal data class TrustedTarget(
    val id: String,
    val label: String,
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
 * Store the target-device public keys in SharedPreferences.
 *
 * Only public keys are stored. They are not secret, so this store does not use
 * the Android Keystore. The pairing token uses [TokenWriter] instead.
 */
internal class SharedPreferencesPairingTrustStore(
    private val preferences: SharedPreferences,
) : PairingTrustStore, PairingTrustAdmin {
    private val lock = Any()

    override fun contains(publicKey: ByteArray): Boolean =
        synchronized(lock) { load().contains(encode(publicKey)) }

    override fun add(publicKey: ByteArray) {
        synchronized(lock) {
            val keys = load()
            if (keys.add(encode(publicKey))) save(keys)
        }
    }

    override fun remove(publicKey: ByteArray) {
        synchronized(lock) {
            val keys = load()
            if (keys.remove(encode(publicKey))) save(keys)
        }
    }

    override val count: Int
        get() = synchronized(lock) { load().size }

    override fun targets(): List<TrustedTarget> = synchronized(lock) {
        load()
            .map { key -> TrustedTarget(id = key, label = TrustFingerprint.label(key)) }
            .sortedWith(compareBy({ it.label }, { it.id }))
    }

    override fun forget(id: String): Boolean = synchronized(lock) {
        val keys = load()
        if (!keys.remove(id)) return@synchronized false
        save(keys)
        true
    }

    override fun forgetAll() = clear()

    fun clear() {
        synchronized(lock) { preferences.edit { remove(KEY) } }
    }

    private fun load(): MutableSet<String> {
        val stored = try {
            preferences.getStringSet(KEY, emptySet())
        } catch (_: Exception) {
            null
        } ?: emptySet()
        return stored.toMutableSet()
    }

    private fun save(keys: Set<String>) {
        preferences.edit { putStringSet(KEY, keys) }
    }

    private fun encode(publicKey: ByteArray): String =
        Base64.getEncoder().encodeToString(publicKey)

    private companion object {
        const val KEY = "paired-targets"
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
        SourceProxyRuntime.lastState == SourceProxyState.RUNNING ||
            SourceProxyRuntime.lastState == SourceProxyState.WAITING_FOR_NETWORK
    },
) {
    fun targets(): List<TrustedTarget> = trust.targets()

    fun forget(id: String): Boolean = trust.forget(id)

    fun forgetAll() {
        trust.forgetAll()
    }

    fun rotateToken(): TokenRotateResult {
        if (isProxyActive()) return TokenRotateResult.REFUSED_RUNNING
        return try {
            tokenStore.save(tokenFactory())
            TokenRotateResult.ROTATED
        } catch (_: Exception) {
            TokenRotateResult.FAILED
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

    override fun save(port: Int) {
        preferences.edit { putInt(KEY, port) }
    }

    override fun clear() {
        preferences.edit { remove(KEY) }
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
 * Choose and save the source proxy port.
 *
 * The pairing result tells the target device this port. The source proxy binds
 * the same port on the next start. A saved port stays stable across launches,
 * so a paired target device keeps its stored value. A bind failure clears the
 * value, and the next start chooses a new port. The target device learns the
 * new port from an authenticated status answer.
 */
internal class ProxyPortPolicy(
    private val store: ProxyPortStore,
    private val probe: PortProbe = SocketPortProbe(),
    private val random: SecureRandom = SecureRandom(),
) {
    /** Return the saved port, or choose and save a free port on [hotspot]. */
    fun current(hotspot: InetAddress): Int {
        val saved = try {
            store.load()
        } catch (_: Exception) {
            0
        }
        if (isUsable(saved)) return saved
        val picked = pick(hotspot)
        if (picked != 0) {
            try {
                store.save(picked)
            } catch (_: Exception) {
                // The proxy cannot remember the port. Pairing still uses it.
            }
        }
        return picked
    }

    /** Save the port that the listener bound. */
    fun remember(port: Int) {
        if (isUsable(port)) store.save(port)
    }

    /** Remove the saved port after a bind failure. */
    fun clear() {
        store.clear()
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
    }
}
