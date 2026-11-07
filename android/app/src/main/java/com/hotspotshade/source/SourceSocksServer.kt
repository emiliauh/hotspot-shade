package com.hotspotshade.source

import java.io.Closeable
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.ConnectException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NoRouteToHostException
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Duration
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.Callable
import java.util.concurrent.CancellationException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutionException
import java.util.concurrent.ExecutorService
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.Semaphore
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadFactory
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.locks.LockSupport

/**
 * A real worker thread creation failure.
 *
 * The worker pool wraps every failure from the injected [ThreadFactory] in
 * this Error, so a factory that throws `RejectedExecutionException` is not
 * mistaken for a transient executor rejection at the thread ceiling. The
 * server stops closed on this Error.
 */
private class WorkerCreationFailure(cause: Throwable) :
    Error("The source worker thread could not start.", cause)

/**
 * Resolve a destination name on the selected cellular network.
 *
 * The real adapter must call `Network.getAllByName()` on that network. Do not
 * use the process default resolver. The caller owns the deadline.
 */
internal fun interface SourceHostResolver {
    fun resolve(host: String): List<InetAddress>
}

/**
 * Reframe the first TLS ClientHello on one relay direction.
 *
 * The relay carries opaque bytes. This shaper changes only the TLS record
 * framing of the first ClientHello handshake message. It does not change one
 * handshake byte, so the transcript hash is unchanged. A TLS peer reassembles
 * handshake messages across records (RFC 8446 section 5.1), so small records
 * are legal.
 *
 * It does not hide SNI, JA3/JA4, the destination address, DNS names, flow
 * size, or timing. It does not change the TLS version: a byte relay cannot
 * force the client's TLS version, and this shaper does not try. It does not
 * control TCP segmentation; the writes are small, but the local stack and the
 * network can coalesce them.
 *
 * The first record or records are buffered until the first ClientHello is
 * complete. That message is written again as records with 1 to 8 payload
 * bytes. Every later byte passes through unchanged. A non-TLS first byte, a
 * record that is not a handshake record, a message that is not a ClientHello,
 * a message above the cap, or a record count above the cap turns the whole
 * flow into a plain pass-through, byte for byte.
 *
 * A byte that rules out a ClientHello is released as soon as it arrives, so a
 * short request that waits for a reply is never held. The first byte decides
 * the content type, the second decides the TLS major version, and the first
 * payload byte of the first record decides the handshake type. An incomplete
 * ClientHello stays buffered until it completes, the buffer cap is reached, or
 * [finish] releases it unchanged at end of stream.
 *
 * This is a port of `rust/src/tls_shape.rs`, which has the real loopback
 * handshake test. It holds no address, host name, or SNI value, and it must
 * not log one. Shaping is off unless the caller passes it to the server.
 */
internal class SourceClientHelloShaper(
    chunkLimit: Int = DEFAULT_MAX_CHUNK,
    clientHelloLimit: Int = DEFAULT_MAX_CLIENT_HELLO,
    recordLimit: Int = DEFAULT_MAX_RECORDS,
    bufferLimit: Int = DEFAULT_MAX_BUFFERED,
) {
    internal enum class State { BUFFERING, REFRAMED, PASS_THROUGH }

    private enum class RecordStep { NEED_MORE, PASS_THROUGH, PROGRESS }

    internal companion object {
        /** A TLS handshake record content type. */
        const val HANDSHAKE_CONTENT_TYPE = 22

        /** The TLS major version. A record that does not start with 3 is not TLS. */
        const val TLS_MAJOR = 3

        /** The handshake type of a ClientHello. */
        const val CLIENT_HELLO_TYPE = 1

        /** The largest record payload in TLS 1.2 and 1.3. */
        const val MAX_RECORD_PAYLOAD = 16_384

        /**
         * The fixed part of a ClientHello: handshake header, version, random,
         * and session id length.
         */
        const val MIN_CLIENT_HELLO_MESSAGE = 4 + 2 + 32 + 1

        const val DEFAULT_MAX_CHUNK = 8
        const val DEFAULT_MAX_CLIENT_HELLO = 16 * 1024
        const val DEFAULT_MAX_RECORDS = 4096
        const val DEFAULT_MAX_BUFFERED = 64 * 1024
    }

    /** The largest payload of one written record. */
    val maxChunk = chunkLimit.coerceIn(1, DEFAULT_MAX_CHUNK)

    /** The largest ClientHello message that is reshaped. */
    val maxClientHello = clientHelloLimit.coerceAtLeast(MIN_CLIENT_HELLO_MESSAGE)

    /** The most handshake records read while the ClientHello is shaped. */
    val maxRecords = recordLimit.coerceAtLeast(1)

    /** The most raw bytes buffered while the flow waits for a ClientHello. */
    val maxBuffered = bufferLimit.coerceAtLeast(maxClientHello)

    var state = State.BUFFERING
        private set

    private val raw = java.io.ByteArrayOutputStream()
    private var rawView = ByteArray(0)
    private val payload = java.io.ByteArrayOutputStream()
    private var consumed = 0
    private var records = 0
    private var version = byteArrayOf(TLS_MAJOR.toByte(), 1)

    /** The number of bytes held while the flow waits for a ClientHello. */
    internal fun bufferedCount(): Int = rawView.size

    /**
     * Feed the next bytes from the client. The returned pieces go out in
     * order. While the ClientHello is shaped, each piece is one complete TLS
     * record. A pass-through piece is the unmodified input.
     *
     * A byte that rules out a ClientHello is returned in this call, unchanged.
     * A prefix that still looks like TLS stays buffered until the message
     * completes, [maxBuffered] is exceeded, or [finish] is called.
     */
    internal fun feed(
        data: ByteArray,
        offset: Int = 0,
        length: Int = data.size,
    ): List<ByteArray> {
        if (state != State.BUFFERING) {
            return if (length == 0) emptyList()
            else listOf(data.copyOfRange(offset, offset + length))
        }
        if (length == 0) return emptyList()
        raw.write(data, offset, length)
        rawView = raw.toByteArray()
        while (true) {
            if (payload.size() == 0) {
                when (takeRecord()) {
                    RecordStep.NEED_MORE -> return waitForMore()
                    RecordStep.PASS_THROUGH -> return passThrough()
                    RecordStep.PROGRESS -> continue
                }
            }
            val payloadView = payload.toByteArray()
            if ((payloadView[0].toInt() and 0xFF) != CLIENT_HELLO_TYPE) return passThrough()
            if (payloadView.size < 4) {
                when (takeRecord()) {
                    RecordStep.NEED_MORE -> return waitForMore()
                    RecordStep.PASS_THROUGH -> return passThrough()
                    RecordStep.PROGRESS -> continue
                }
            }
            val declared = ((payloadView[1].toInt() and 0xFF) shl 16) or
                ((payloadView[2].toInt() and 0xFF) shl 8) or
                (payloadView[3].toInt() and 0xFF)
            val messageLength = declared + 4
            if (messageLength < MIN_CLIENT_HELLO_MESSAGE || messageLength > maxClientHello) {
                return passThrough()
            }
            if (payloadView.size < messageLength) {
                when (takeRecord()) {
                    RecordStep.NEED_MORE -> return waitForMore()
                    RecordStep.PASS_THROUGH -> return passThrough()
                    RecordStep.PROGRESS -> continue
                }
            }
            return reframe(messageLength)
        }
    }

    /**
     * Release the bytes still held, unchanged and in order, when the client
     * ends the stream. Call it once, before the half-close.
     *
     * It returns at most one piece, which is the raw input in the order it
     * arrived. A second call returns nothing, and no later byte is shaped.
     */
    internal fun finish(): List<ByteArray> {
        if (state != State.BUFFERING) return emptyList()
        val bytes = rawView
        state = State.PASS_THROUGH
        release()
        return if (bytes.isEmpty()) emptyList() else listOf(bytes)
    }

    /**
     * Read one handshake record from the raw buffer.
     *
     * Each header byte is checked as soon as it is available. A record that
     * cannot be a handshake record is rejected without waiting for the rest of
     * the header or the payload.
     */
    private fun takeRecord(): RecordStep {
        val available = rawView.size - consumed
        if (available == 0) return RecordStep.NEED_MORE
        if ((rawView[consumed].toInt() and 0xFF) != HANDSHAKE_CONTENT_TYPE) {
            return RecordStep.PASS_THROUGH
        }
        if (available < 2) return RecordStep.NEED_MORE
        if ((rawView[consumed + 1].toInt() and 0xFF) != TLS_MAJOR) {
            return RecordStep.PASS_THROUGH
        }
        if (available < 5) return RecordStep.NEED_MORE
        val length = ((rawView[consumed + 3].toInt() and 0xFF) shl 8) or
            (rawView[consumed + 4].toInt() and 0xFF)
        if (length == 0 || length > MAX_RECORD_PAYLOAD) return RecordStep.PASS_THROUGH
        // Check the first handshake bytes as soon as they are present, even
        // when they straddle a record boundary. Only bytes inside the current
        // record are handshake bytes: a byte after its payload is the next
        // record header, not part of this message.
        val inRecord = minOf(available - 5, length)
        if (payload.size() < 4 && impossibleHandshakePrefix(inRecord)) {
            return RecordStep.PASS_THROUGH
        }
        if (available - 5 < length) return RecordStep.NEED_MORE
        if (records == 0) {
            version = byteArrayOf(rawView[consumed + 1], rawView[consumed + 2])
        }
        payload.write(rawView, consumed + 5, length)
        consumed += 5 + length
        records += 1
        if (records > maxRecords) return RecordStep.PASS_THROUGH
        return RecordStep.PROGRESS
    }

    /**
     * True when the first four handshake bytes are known and cannot start an
     * accepted ClientHello. Bytes already in [payload] come before the next
     * [availableInRecord] bytes of the current record. It returns false while
     * more bytes are needed to decide, so a valid small request can wait for
     * the rest of a ClientHello.
     */
    private fun impossibleHandshakePrefix(availableInRecord: Int): Boolean {
        val held = payload.size()
        if (held >= 4) return false
        val have = held + availableInRecord
        if (have < 1) return false
        val heldBytes = if (held == 0) ByteArray(0) else payload.toByteArray()
        val type = if (held > 0) heldBytes[0] else rawView[consumed + 5]
        if ((type.toInt() and 0xFF) != CLIENT_HELLO_TYPE) return true
        if (have < 4) return false
        val header = ByteArray(4)
        System.arraycopy(heldBytes, 0, header, 0, held)
        var index = 0
        while (held + index < 4) {
            header[held + index] = rawView[consumed + 5 + index]
            index += 1
        }
        val declared = ((header[1].toInt() and 0xFF) shl 16) or
            ((header[2].toInt() and 0xFF) shl 8) or
            (header[3].toInt() and 0xFF)
        val messageLength = declared + 4
        return messageLength < MIN_CLIENT_HELLO_MESSAGE || messageLength > maxClientHello
    }

    /**
     * Wait for the next bytes unless the held prefix already exceeds the
     * buffer cap. A complete ClientHello that arrives with a long tail is
     * parsed instead of discarded. With a small custom cap, a split prefix
     * may exceed the cap before the complete record arrives and pass through.
     */
    private fun waitForMore(): List<ByteArray> =
        if (rawView.size > maxBuffered) passThrough() else emptyList()

    /** Emit the ClientHello as small records, then the bytes after it. */
    private fun reframe(messageLength: Int): List<ByteArray> {
        val message = payload.toByteArray()
        val leftoverBytes = message.size - messageLength
        val leftoverRecords = (leftoverBytes + MAX_RECORD_PAYLOAD - 1) / MAX_RECORD_PAYLOAD
        if (recordsFor(messageLength) + leftoverRecords > maxRecords) return passThrough()
        val chunks = ArrayList<ByteArray>()
        var offset = 0
        var index = 0
        while (offset < messageLength) {
            val size = minOf(1 + (index % maxChunk), messageLength - offset)
            chunks.add(frame(message, offset, size))
            offset += size
            index += 1
        }
        // Handshake bytes that followed the ClientHello in the same records
        // stay in order and unchanged. Only their record framing is new.
        var rest = messageLength
        while (rest < message.size) {
            val size = minOf(MAX_RECORD_PAYLOAD, message.size - rest)
            chunks.add(frame(message, rest, size))
            rest += size
        }
        // Bytes after the records that carried the ClientHello were never
        // touched. They go out exactly as they arrived.
        if (consumed < rawView.size) {
            chunks.add(rawView.copyOfRange(consumed, rawView.size))
        }
        state = State.REFRAMED
        release()
        return chunks
    }

    /** Build one handshake record. */
    private fun frame(message: ByteArray, offset: Int, size: Int): ByteArray {
        val out = ByteArray(5 + size)
        out[0] = HANDSHAKE_CONTENT_TYPE.toByte()
        out[1] = version[0]
        out[2] = version[1]
        out[3] = ((size ushr 8) and 0xFF).toByte()
        out[4] = (size and 0xFF).toByte()
        System.arraycopy(message, offset, out, 5, size)
        return out
    }

    /** Give up shaping and release every buffered byte unchanged. */
    private fun passThrough(): List<ByteArray> {
        val bytes = rawView
        state = State.PASS_THROUGH
        release()
        return if (bytes.isEmpty()) emptyList() else listOf(bytes)
    }

    private fun release() {
        raw.reset()
        rawView = ByteArray(0)
        payload.reset()
        consumed = 0
        records = 0
    }

    /** The number of records that a split of [length] bytes needs. */
    private fun recordsFor(length: Int): Int {
        var count = 0
        var offset = 0
        while (offset < length) {
            offset += 1 + (count % maxChunk)
            count += 1
        }
        return count
    }
}

/**
 * Serve the source device SOCKS5 contract on one injected listener address.
 *
 * Every destination TCP or UDP socket comes from [CellularSession]. A domain
 * name goes through [SourceHostResolver] only. This class never calls
 * `InetAddress.getByName()` or `getaddrinfo()`.
 *
 * The proxy accepts method 2 (username and password) only. The username is
 * `hotspotshade`. The caller injects the token. A failed authentication gets
 * one `[1, 1]` reply and a close.
 *
 * A TCP CONNECT gets one success or failure reply. Command `0x80` carries
 * length-prefixed UDP datagrams over the TCP session. Command `0x81` sends one
 * echo probe. Command `0x82` keeps one echo session open for more probes. See
 * [SourceEchoWire]. Reply codes match the iOS source proxy:
 *
 * - 0: success.
 * - 1: general failure, deadline, or capacity refusal.
 * - 4: destination network or host unreachable.
 * - 5: destination refused the connection.
 * - 7: command not supported.
 * - 8: address type not supported, or an echo target that is not accepted.
 *
 * The phase rule follows `SourceSocksCapacity`. A handshake has a 30 second
 * bound. A destination connect has a 4 second bound. An open TCP relay has no
 * idle bound. A UDP flow and a half-closed TCP flow have a 300 second idle
 * bound. The server never closes a healthy open TCP relay for silence.
 *
 * The client and destination TCP sockets set no-delay and keepalive. The
 * Android system keepalive defaults apply. The app cannot set the iOS 60/10/3
 * values through the Java socket API.
 *
 * The server holds at most [maximumRelays] relay sessions and [setupReserve]
 * extra setup sessions. The constructor rejects a relay cap above
 * [MAXIMUM_RELAYS], a reserve above [SETUP_RESERVE], or a total above
 * [MAXIMUM_SESSIONS]. It never closes an open TCP relay to make room. A
 * refused relay request gets code 1. A new connection beyond the total bound
 * closes the most overdue stale session first. It closes the client before the
 * greeting when no session is stale.
 *
 * The server also bounds its worker threads. One worker serves one session,
 * and one extra worker pumps each open relay. The bound follows the session
 * and relay limits, so it still serves every documented flow. The session
 * worker runs one relay direction and the pump worker runs the other. A new
 * connection that cannot get a worker is closed before the greeting. A relay
 * request that cannot get a pump worker gets code 1. A worker that cannot
 * start stops the server closed instead of leaving a listener that accepts
 * nothing. A transient executor rejection at the ceiling refuses that one
 * flow instead of stopping the server: the executor has no free thread for
 * one instant, but it is still alive. Only a real thread creation failure or
 * a shutdown pool stops the server.
 *
 * Name lookups use at most [resolverLimit] workers and a queue of the same
 * bound. A lookup that cannot enter the queue is refused at once. A resolver
 * call that ignores the caller deadline keeps its worker until the call
 * returns; the server cannot replace that thread. [resolverStatus] reports
 * the abandoned count and [ResolverStatus.exhausted], so a caller can tell
 * that names cannot resolve again without a new server.
 *
 * A persistent echo session holds one of 16 echo slots and no relay slot. Its
 * request has a 5 second bound. Its idle window is 30 seconds. Its lifetime is
 * 300 seconds. A one-shot echo request also has one absolute 5 second bound
 * for the whole frame, so a slow trickle cannot hold a session slot.
 *
 * An explicit [tlsShape] reframes the first TLS ClientHello of a TCP relay into
 * records with 1 to 8 payload bytes. It is off by default. It changes only TLS
 * record framing and never one handshake byte. It does not hide SNI, JA3/JA4,
 * the destination, DNS names, or flow shape, and it does not control TCP
 * segmentation. See [SourceClientHelloShaper].
 *
 * [stop] closes the listener and every session. It is idempotent. A stop that
 * runs while another stop is cleaning up waits for that cleanup for a bounded
 * time and then reports [stopWasIncomplete]. A stopped server cannot start
 * again. The caller must pass the hotspot address.
 */
internal class SourceSocksServer(
    private val cellular: CellularSession,
    private val resolver: SourceHostResolver,
    private val bindAddress: InetAddress,
    token: String,
    private val port: Int = 0,
    private val maximumRelays: Int = MAXIMUM_RELAYS,
    private val setupReserve: Int = SETUP_RESERVE,
    private val connectTimeout: Duration = Duration.ofSeconds(4),
    private val handshakeTimeout: Duration = Duration.ofSeconds(30),
    private val udpIdleTimeout: Duration = Duration.ofSeconds(300),
    private val echo: SourceEchoSender? = null,
    private val echoRequestTimeout: Duration = Duration.ofSeconds(5),
    private val echoIdleTimeout: Duration = Duration.ofSeconds(30),
    private val echoLifetime: Duration = Duration.ofSeconds(300),
    private val echoAttemptTimeout: Duration = Duration.ofSeconds(3),
    private val persistentEchoLimit: Int = SourceSocksCapacity.MAXIMUM_PERSISTENT_ECHO_SESSIONS,
    private val housekeepingInterval: Duration = Duration.ofMillis(500),
    private val tlsShape: Boolean = false,
    private val workerThreadFactory: ThreadFactory? = null,
    private val resolverLimit: Int = SourceSocksCapacity.resolverThreads(
        maximumRelays + setupReserve,
    ),
    private val stopWaitTimeout: Duration = Duration.ofMillis(DEFAULT_STOP_WAIT_MILLIS),
    // Test seams. Production leaves these null. They select no address and
    // hold no secret.
    private val workerLimitOverride: Int? = null,
    private val listenerFactory: (() -> ServerSocket)? = null,
    private val workerExecutorFactory: ((Int, ThreadFactory) -> ThreadPoolExecutor)? = null,
) : Closeable {
    internal companion object {
        /** The relay slots that the source device proxy gives to open flows. */
        const val MAXIMUM_RELAYS = SourceSocksCapacity.MAXIMUM_RELAYS

        /** The setup slots that relay sessions cannot use. */
        const val SETUP_RESERVE = SourceSocksCapacity.SETUP_RESERVE

        /** The total session bound. */
        const val MAXIMUM_SESSIONS = SourceSocksCapacity.MAXIMUM_SESSIONS

        /** The most persistent echo sessions that the server grants. */
        const val MAXIMUM_PERSISTENT_ECHO_SESSIONS =
            SourceSocksCapacity.MAXIMUM_PERSISTENT_ECHO_SESSIONS

        /** The username accepted by the source proxy and shown in Settings. */
        internal const val SOCKS_USERNAME = "hotspotshade"

        private const val SOCKS_VERSION = 5
        private const val AUTH_VERSION = 1
        private const val METHOD_USERNAME_PASSWORD = 2
        private const val METHOD_NONE_ACCEPTABLE = 0xFF
        private const val COMMAND_CONNECT = 1
        private const val COMMAND_UDP = 0x80
        private const val COMMAND_ECHO = SourceEchoWire.COMMAND
        private const val COMMAND_ECHO_PERSISTENT = SourceEchoWire.PERSISTENT_COMMAND
        private const val ADDRESS_IPV4 = 1
        private const val ADDRESS_DOMAIN = 3
        private const val ADDRESS_IPV6 = 4
        private const val REPLY_SUCCEEDED = 0
        private const val REPLY_GENERAL_FAILURE = 1
        private const val REPLY_UNREACHABLE = 4
        private const val REPLY_REFUSED = 5
        private const val REPLY_COMMAND_NOT_SUPPORTED = 7
        private const val REPLY_ADDRESS_NOT_SUPPORTED = 8
        private const val MAX_DATAGRAM = 1472
        private const val CLIENT_BUFFER = 16 * 1024
        private const val ACCEPT_SLICE_MILLIS = 1_000

        /** The attempts for the narrow idle-worker timeout race. */
        private const val MAXIMUM_WORKER_START_ATTEMPTS = 3

        /** The wait between those attempts. It is short and bounded. */
        private const val WORKER_START_RETRY_NANOS = 1_000_000L

        /** The most that a concurrent stop waits for the cleanup in progress. */
        private const val DEFAULT_STOP_WAIT_MILLIS = 5_000L

        /** The wait for the housekeeping thread on every stop. */
        private const val KEEPER_JOIN_MILLIS = 1_000L

        /** The wait for the worker pool to drain on every stop. */
        private const val WORKER_DRAIN_MILLIS = 2_000L

        /** The wait for the accept thread on every stop. */
        private const val ACCEPT_JOIN_MILLIS = 1_000L

        private val USERNAME = SOCKS_USERNAME.toByteArray(StandardCharsets.US_ASCII)
        private val EMPTY = ByteArray(0)
    }

    private enum class State { NEW, RUNNING, STOPPED }

    /**
     * The resolver view of one run. It holds counts only.
     *
     * [exhausted] is the recovery limit: every resolver worker is inside a
     * call whose caller already gave up. Android cannot interrupt a resolver
     * that ignores the interrupt, so those workers stay gone. A new server is
     * the only recovery.
     */
    internal data class ResolverStatus(
        val threads: Int,
        val queueLimit: Int,
        val active: Int,
        val queued: Int,
        val rejections: Long,
        val abandoned: Int,
    ) {
        /** The lookups that are running or queued. */
        val outstanding: Int get() = active + queued

        /** True when no name lookup can finish without a new server. */
        val exhausted: Boolean get() = threads > 0 && abandoned >= threads
    }

    private val tokenBytes = token.toByteArray(StandardCharsets.UTF_8)
    private val tokenLock = Any()
    private val lifecycleLock = Any()
    private val sessionLock = Any()
    private val sessions = LinkedHashSet<Session>()
    private val sessionIds = AtomicLong()
    private val relayTotal = AtomicLong()
    private val persistentEchoCount = AtomicInteger()
    private val resolverActive = AtomicInteger()
    private val resolverOutstanding = AtomicInteger()
    private val resolverRejections = AtomicLong()
    private val resolverAbandoned = AtomicInteger()
    private val sessionLimit = maximumRelays + setupReserve

    /**
     * True on a worker task of this run. Stop reads it after the pool field is
     * gone, so a worker never waits for the pool that contains it.
     */
    private val inWorkerThread = ThreadLocal.withInitial { false }

    /**
     * The worker thread bound of this run. It is one session worker plus one
     * relay pump worker, with the eviction overlap.
     */
    val workerLimit: Int = workerLimitOverride ?: SourceSocksCapacity.workerLimit(
        sessions = sessionLimit,
        relays = maximumRelays,
    )

    private val stopWaitMillis = stopWaitTimeout.toMillis().coerceAtLeast(1)
    private val stopDone = CountDownLatch(1)

    private val policy = SourceSocksCapacity.Policy(
        handshakeMillis = handshakeTimeout.toMillis().coerceAtLeast(1),
        connectMillis = (connectTimeout.toMillis() * 2).coerceAtLeast(1),
        relayIdleMillis = udpIdleTimeout.toMillis().coerceAtLeast(1),
    )
    private var relayCount = 0

    @Volatile
    private var listener: ServerSocket? = null

    @Volatile
    private var acceptThread: Thread? = null

    @Volatile
    private var housekeepingThread: Thread? = null

    @Volatile
    private var resolverExecutor: ExecutorService? = null

    @Volatile
    private var workers: SourceWorkerPool? = null

    @Volatile
    private var state = State.NEW

    @Volatile
    private var failure: String? = null

    @Volatile
    private var boundPort = 0

    /** True while one stop call is closing the listener and every session. */
    @Volatile
    private var stopping = false

    /** True when a stop returned before the cleanup it waited for finished. */
    @Volatile
    private var stopIncomplete = false

    init {
        try {
            require(!bindAddress.isAnyLocalAddress) {
                "The source listener needs an explicit address."
            }
            require(port in 0..65_535) {
                "The source listener port is out of range."
            }
            require(token.isNotEmpty()) {
                "The source token must not be empty."
            }
            require(maximumRelays in 1..MAXIMUM_RELAYS) {
                "The relay limit is out of range."
            }
            require(setupReserve in 0..SETUP_RESERVE) {
                "The setup reserve is out of range."
            }
            require(sessionLimit <= MAXIMUM_SESSIONS) {
                "The session limit is above the declared cap."
            }
            require(resolverLimit in 1..SourceSocksCapacity.MAXIMUM_RESOLVER_THREADS) {
                "The resolver limit is out of range."
            }
            require(resolverLimit <= sessionLimit) {
                "The resolver limit is above the session cap."
            }
            require(workerLimitOverride == null ||
                workerLimitOverride in 1..SourceSocksCapacity.workerLimit(sessionLimit, maximumRelays)
            ) {
                "The worker limit override is out of range."
            }
            require(!stopWaitTimeout.isZero && !stopWaitTimeout.isNegative) {
                "The stop wait must be positive."
            }
            require(!connectTimeout.isZero && !connectTimeout.isNegative) {
                "The connect timeout must be positive."
            }
            require(!handshakeTimeout.isZero && !handshakeTimeout.isNegative) {
                "The handshake timeout must be positive."
            }
            require(!udpIdleTimeout.isZero && !udpIdleTimeout.isNegative) {
                "The UDP idle timeout must be positive."
            }
            require(!echoRequestTimeout.isZero && !echoRequestTimeout.isNegative) {
                "The echo request timeout must be positive."
            }
            require(!echoIdleTimeout.isZero && !echoIdleTimeout.isNegative) {
                "The echo idle timeout must be positive."
            }
            require(!echoLifetime.isZero && !echoLifetime.isNegative) {
                "The echo lifetime must be positive."
            }
            require(!echoAttemptTimeout.isZero && !echoAttemptTimeout.isNegative) {
                "The echo attempt timeout must be positive."
            }
            require(persistentEchoLimit in 1..255) {
                "The persistent echo limit is out of range."
            }
            require(!housekeepingInterval.isZero && !housekeepingInterval.isNegative) {
                "The housekeeping interval must be positive."
            }
        } catch (failure: Exception) {
            // The object is unusable. Clear the token copy before the error
            // leaves the constructor.
            tokenBytes.fill(0)
            throw failure
        }
    }

    /** The port that the listener bound, or 0 before a start. */
    val localPort: Int get() = boundPort

    /** True between a successful start and the first stop. */
    val isRunning: Boolean
        get() = state == State.RUNNING && acceptThread?.isAlive == true

    /** True when the in-memory token copy has been cleared. A test uses this. */
    internal fun tokenCopyIsCleared(): Boolean =
        synchronized(tokenLock) { tokenBytes.all { it == 0.toByte() } }

    /**
     * A fixed label for a failure that stopped the server, or null.
     *
     * The label is a word such as `worker_start`, never an address, host,
     * token, or exception text. A normal stop leaves it null.
     */
    internal val failureReason: String? get() = failure

    /** The relay cap of this run. It follows the open-file limit. */
    val relayLimit: Int get() = maximumRelays

    /** The total session cap of this run. It follows the open-file limit. */
    val totalSessionLimit: Int get() = sessionLimit

    /**
     * The open relay count. It holds no address, host, or port.
     *
     * The count includes TCP CONNECT and UDP sessions after the relay grant.
     * It falls when a session closes. The value is safe to show in the app.
     */
    val activeConnections: Int
        get() = synchronized(sessionLock) { relayCount }

    /**
     * The relay count since the start. It holds no address, host, or port.
     *
     * The count includes every granted relay. A refused relay does not count.
     */
    val totalConnections: Long get() = relayTotal.get()

    /** The worker permits that are free right now. A test reads this. */
    internal val availableWorkers: Int get() = workers?.availablePermits ?: 0

    /**
     * True when the stop cleanup finished. A concurrent stop waits for this
     * value for a bounded time.
     */
    internal val stopFinished: Boolean get() = stopDone.count == 0L

    /** True when a stop returned before the cleanup it waited for finished. */
    internal val stopWasIncomplete: Boolean get() = stopIncomplete

    /**
     * The resolver counters of this run. The value holds no host or address.
     *
     * A caller that exposes health reads [ResolverStatus.exhausted] to learn
     * that name lookups cannot recover until a new server exists.
     */
    internal fun resolverStatus(): ResolverStatus = ResolverStatus(
        threads = resolverLimit,
        queueLimit = resolverLimit,
        active = resolverActive.get(),
        queued = maxOf(0, resolverOutstanding.get() - resolverActive.get()),
        rejections = resolverRejections.get(),
        abandoned = resolverAbandoned.get(),
    )

    /**
     * One health report for the controller. It holds fixed labels and counts
     * only: no address, host, token, or key.
     *
     * The controller can poll this value after a start. `failureReason != null`
     * means the listener stopped because of a background failure, not a person.
     * `resolver.exhausted` means the listener still serves numeric targets but
     * name lookups cannot recover without a new server.
     */
    internal data class Health(
        val running: Boolean,
        val failureReason: String?,
        val stopFinished: Boolean,
        val stopIncomplete: Boolean,
        val resolver: ResolverStatus,
    ) {
        /** True when the listener cannot serve every kind of flow. */
        val degraded: Boolean get() = failureReason != null || resolver.exhausted
    }

    /** Take one health snapshot. */
    internal fun health(): Health = Health(
        running = isRunning,
        failureReason = failure,
        stopFinished = stopFinished,
        stopIncomplete = stopIncomplete,
        resolver = resolverStatus(),
    )

    /**
     * Bind the listener and accept sessions. Call this method once.
     *
     * The method binds [bindAddress] and [port] before it returns. A port of 0
     * selects an ephemeral port. A bind failure closes the listener and makes
     * this object unusable.
     */
    fun start() {
        synchronized(lifecycleLock) {
            check(state == State.NEW) { "The source server cannot restart." }
            val server = try {
                createListener()
            } catch (_: Exception) {
                state = State.STOPPED
                boundPort = 0
                tokenBytes.fill(0)
                stopDone.countDown()
                throw IOException("The source listener could not bind.")
            }
            listener = server
            boundPort = server.localPort
            try {
                workers = SourceWorkerPool(
                    limit = workerLimit,
                    threadFactory = workerThreadFactory ?: daemonFactory("source-worker"),
                    executorFactory = workerExecutorFactory,
                )
            } catch (_: Throwable) {
                cleanupFailedStart(server)
                throw IOException("The source worker pool could not start.")
            }
            try {
                // A fixed worker set with a bounded queue. A full queue
                // refuses the lookup at once. The earlier unbounded queue
                // could collect one dead entry for every waiting flow.
                val threads = resolverLimit
                resolverExecutor = ThreadPoolExecutor(
                    threads,
                    threads,
                    0L,
                    TimeUnit.MILLISECONDS,
                    ArrayBlockingQueue(threads),
                    daemonFactory("source-resolve"),
                    ThreadPoolExecutor.AbortPolicy(),
                )
            } catch (_: Throwable) {
                cleanupFailedStart(server)
                throw IOException("The source resolver pool could not start.")
            }
            state = State.RUNNING
            val worker = Thread({ acceptLoop(server) }, "source-accept")
            worker.isDaemon = true
            acceptThread = worker
            try {
                worker.start()
            } catch (_: Throwable) {
                cleanupFailedStart(server)
                throw IOException("The source listener could not start.")
            }
            val keeper = Thread({ housekeepingLoop() }, "source-capacity")
            keeper.isDaemon = true
            housekeepingThread = keeper
            try {
                keeper.start()
            } catch (_: Throwable) {
                cleanupFailedStart(server)
                throw IOException("The source capacity thread could not start.")
            }
        }
    }

    /** Create and bind the listener. A fake listens in a test. */
    private fun createListener(): ServerSocket {
        val server = listenerFactory?.invoke() ?: ServerSocket()
        try {
            server.reuseAddress = false
            server.bind(InetSocketAddress(bindAddress, port))
            server.soTimeout = ACCEPT_SLICE_MILLIS
            return server
        } catch (failure: Exception) {
            closeQuietly(server)
            throw failure
        }
    }

    /**
     * Close everything that a failed start created. The caller holds
     * [lifecycleLock]. The server becomes unusable and the token copy is
     * cleared.
     */
    private fun cleanupFailedStart(server: ServerSocket) {
        val accept = acceptThread
        val keeper = housekeepingThread
        state = State.STOPPED
        listener = null
        acceptThread = null
        housekeepingThread = null
        boundPort = 0
        closeQuietly(server)
        accept?.interrupt()
        keeper?.interrupt()
        resolverExecutor?.shutdownNow()
        resolverExecutor = null
        val active = synchronized(sessionLock) { sessions.toList() }
        for (session in active) {
            session.close()
        }
        val pool = workers
        workers = null
        pool?.shutdownAndAwait(KEEPER_JOIN_MILLIS)
        joinQuietly(accept, KEEPER_JOIN_MILLIS)
        joinQuietly(keeper, KEEPER_JOIN_MILLIS)
        clearToken()
        stopDone.countDown()
    }

    /**
     * Close the listener and every session. This method is idempotent.
     *
     * A stopped server does not restart. A later [start] call throws
     * [IllegalStateException].
     */
    override fun close() = stop()

    /**
     * Close the listener and every session. This method is idempotent.
     *
     * One call owns the cleanup. A concurrent call waits for that cleanup for
     * at most [stopWaitMillis] and then returns; [stopWasIncomplete] reports
     * that the wait expired. A call on a worker thread never waits for the
     * pool that contains it.
     */
    fun stop() {
        var server: ServerSocket? = null
        var active: List<Session> = emptyList()
        var acceptWorker: Thread? = null
        var keeper: Thread? = null
        var resolver: ExecutorService? = null
        var pool: SourceWorkerPool? = null
        var owner = false
        synchronized(lifecycleLock) {
            if (state == State.STOPPED) {
                // A failed start also needs a cleared copy, and a later stop
                // must still clear it even when the object never bound.
                clearToken()
            } else {
                owner = true
                state = State.STOPPED
                stopping = true
                // The server cannot restart, so no later authentication needs
                // the token bytes. The state check under the same lock rejects
                // a comparison that is already in flight.
                clearToken()
                server = listener
                listener = null
                acceptWorker = acceptThread
                acceptThread = null
                keeper = housekeepingThread
                housekeepingThread = null
                resolver = resolverExecutor
                resolverExecutor = null
                pool = workers
                workers = null
                synchronized(sessionLock) {
                    active = sessions.toList()
                }
            }
        }
        if (!owner) {
            awaitConcurrentStop()
            return
        }
        var drained = true
        try {
            // Close the listener outside the lifecycle lock, so a concurrent
            // stop can read the stopping state and wait on the latch. The
            // accept loop sees STOPPED and does not report a failure.
            closeQuietly(server)
            // Stop the phase loop before the sessions close, so it does not
            // race the close of the same session.
            keeper?.interrupt()
            drained = joinQuietly(keeper, KEEPER_JOIN_MILLIS) && drained
            for (session in active) {
                session.close()
            }
            resolver?.shutdownNow()
            // Every worker task is a daemon. Close the session sockets first,
            // then shut the bounded pool once. Waiting for each session in
            // turn could take one second per session.
            drained = (pool?.shutdownAndAwait(WORKER_DRAIN_MILLIS) ?: true) && drained
            drained = joinQuietly(acceptWorker, ACCEPT_JOIN_MILLIS) && drained
            if (!drained) stopIncomplete = true
        } finally {
            synchronized(lifecycleLock) { stopping = false }
            stopDone.countDown()
        }
    }

    /**
     * Wait for a cleanup that another thread owns. The wait is bounded. A
     * worker thread does not wait for the pool that contains it.
     */
    private fun awaitConcurrentStop() {
        if (!stopping || stopDone.count == 0L) return
        if (inWorkerThread.get() == true) return
        val finished = try {
            stopDone.await(stopWaitMillis, TimeUnit.MILLISECONDS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        }
        if (!finished) stopIncomplete = true
    }

    /**
     * Stop the server because a background thread failed. The label is fixed
     * and holds no address, host, or token.
     */
    private fun failStop(reason: String) {
        val shouldStop = synchronized(lifecycleLock) {
            if (state != State.RUNNING) {
                false
            } else {
                failure = reason
                true
            }
        }
        if (shouldStop) stop()
    }

    /** Return true when the thread is gone after the bounded join. */
    private fun joinQuietly(thread: Thread?, millis: Long): Boolean {
        if (thread == null || thread === Thread.currentThread()) return true
        try {
            thread.join(millis)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            return false
        }
        return !thread.isAlive
    }

    private fun clearToken() {
        synchronized(tokenLock) { tokenBytes.fill(0) }
    }

    override fun toString(): String = "SourceSocksServer"

    /**
     * Accept sessions until a normal stop closes the listener.
     *
     * An accept error while the server is running is a server failure, not a
     * normal stop. The loop reports it through [failStop], so the server never
     * stays in RUNNING with a dead accept thread.
     */
    private fun acceptLoop(server: ServerSocket) {
        var failureLabel: String? = null
        try {
            while (state == State.RUNNING) {
                val client = try {
                    server.accept()
                } catch (_: SocketTimeoutException) {
                    continue
                } catch (_: Exception) {
                    if (state == State.RUNNING) failureLabel = "accept"
                    break
                }
                if (state != State.RUNNING) {
                    closeQuietly(client)
                    break
                }
                val session = try {
                    admit(client)
                } catch (_: Throwable) {
                    closeQuietly(client)
                    failureLabel = "accept"
                    break
                }
                if (session == null) {
                    closeQuietly(client)
                }
            }
        } catch (_: Throwable) {
            if (state == State.RUNNING) failureLabel = "accept"
        } finally {
            if (failureLabel != null) {
                failStop(failureLabel)
            }
        }
    }

    /**
     * Apply the phase bound to every session. An open TCP relay is never
     * closed for silence. A control session is bounded by the echo timers.
     */
    private fun housekeepingLoop() {
        try {
            val interval = housekeepingInterval.toMillis().coerceAtLeast(1)
            while (state == State.RUNNING) {
                try {
                    Thread.sleep(interval)
                } catch (_: InterruptedException) {
                    return
                }
                if (state != State.RUNNING) return
                val active = synchronized(sessionLock) { sessions.toList() }
                val now = System.nanoTime()
                for (session in active) {
                    if (session.isClosed) continue
                    if (session.echoIdleExpired(now) || session.echoLifetimeExpired(now)) {
                        session.close()
                        continue
                    }
                    if (session.isControlActive()) continue
                    val view = session.phaseSession(now)
                    when (
                        SourceSocksCapacity.idleAction(
                            phase = view.phase,
                            phaseMillis = view.phaseMillis,
                            idleMillis = view.idleMillis,
                            policy = policy,
                        )
                    ) {
                        is SourceSocksCapacity.IdleAction.Close -> session.close()
                        is SourceSocksCapacity.IdleAction.Rearm -> Unit
                    }
                }
            }
        } catch (_: Throwable) {
            failStop("housekeeping")
        }
    }

    private fun admit(client: Socket): Session? {
        var evicted: Session? = null
        val session: Session
        synchronized(sessionLock) {
            if (state != State.RUNNING) return null
            if (sessions.size >= sessionLimit) {
                val stale = SourceSocksCapacity.staleSession(
                    sessions = phaseSessionsLocked(System.nanoTime()),
                    policy = policy,
                ) ?: return null
                evicted = sessions.firstOrNull { it.id == stale.id }
                if (evicted == null) return null
                detachLocked(evicted)
            }
            session = Session(sessionIds.incrementAndGet(), client)
            sessions.add(session)
        }
        evicted?.close()
        val started = try {
            workers?.tryStart { session.run() } ?: false
        } catch (_: Throwable) {
            session.close()
            failStop("worker_start")
            return null
        }
        if (!started) {
            // The worker pool is full. This is a capacity refusal, not a
            // server failure: close the client before the greeting.
            session.close()
            return null
        }
        return session
    }

    private fun phaseSessionsLocked(now: Long): List<SourceSocksCapacity.PhaseSession> =
        sessions.map { it.phaseSession(now) }

    /** Remove one session from the table and release its relay slot. */
    private fun detachLocked(session: Session): Boolean {
        if (!sessions.remove(session)) return false
        if (session.relayGranted) {
            relayCount = maxOf(0, relayCount - 1)
        }
        return true
    }

    private fun sessionClosed(session: Session) {
        synchronized(sessionLock) { detachLocked(session) }
    }

    private fun grantRelay(session: Session): Boolean {
        var victim: Session? = null
        val granted: Boolean
        synchronized(sessionLock) {
            when {
                session.isClosed -> granted = false
                session.relayGranted -> granted = true
                relayCount < maximumRelays -> {
                    session.noteRelayGranted()
                    relayCount += 1
                    relayTotal.incrementAndGet()
                    granted = true
                }
                else -> {
                    val stale = SourceSocksCapacity.staleSession(
                        sessions = phaseSessionsLocked(System.nanoTime()),
                        relayOnly = true,
                        policy = policy,
                    )
                    val staleSession = stale?.let { view -> sessions.firstOrNull { it.id == view.id } }
                    if (staleSession != null) {
                        detachLocked(staleSession)
                        victim = staleSession
                        session.noteRelayGranted()
                        relayCount += 1
                        relayTotal.incrementAndGet()
                        granted = true
                    } else {
                        granted = false
                    }
                }
            }
        }
        victim?.close()
        return granted
    }

    private inner class Session(val id: Long, private val client: Socket) {
        private val closeLock = Any()
        private val clientWriteLock = Any()
        private val destinationWriteLock = Any()
        private val relayDone = AtomicInteger()
        private val stateLock = Any()
        private var tcpFlow: CellularFlow<Socket>? = null
        private var udpFlow: CellularFlow<DatagramSocket>? = null

        private var phase = SourceSocksCapacity.Phase.HANDSHAKE
        private var phaseStartedNanos = System.nanoTime()
        private var lastActivityNanos = phaseStartedNanos
        private var awaitsRelay = false
        private var replyPending = false
        private var controlActive = false
        private var echoIdleAtNanos = 0L
        private var echoLifetimeAtNanos = 0L
        private var persistentSlot = false
        private var udpReaderGate: CountDownLatch? = null

        @Volatile
        private var closed = false

        @Volatile
        private var hasRelay = false

        val isClosed: Boolean get() = closed
        val relayGranted: Boolean get() = hasRelay

        fun noteRelayGranted() {
            hasRelay = true
        }

        fun isControlActive(): Boolean = synchronized(stateLock) { controlActive }

        /** The capacity view of this session. The housekeeping thread reads it. */
        fun phaseSession(now: Long): SourceSocksCapacity.PhaseSession = synchronized(stateLock) {
            SourceSocksCapacity.PhaseSession(
                id = id,
                phase = phase,
                phaseMillis = nanosToMillis(now - phaseStartedNanos),
                idleMillis = nanosToMillis(now - lastActivityNanos),
                protectedFromCapacity = awaitsRelay || replyPending || controlActive,
            )
        }

        fun run() {
            try {
                if (closed) return
                client.tcpNoDelay = true
                client.keepAlive = true
                val input = client.getInputStream()
                val output = client.getOutputStream()
                val request = readHandshake(input, output) ?: return
                when (request.command) {
                    COMMAND_CONNECT -> serveTcp(request, input, output)
                    COMMAND_UDP -> serveUdp(request, input, output)
                    COMMAND_ECHO, COMMAND_ECHO_PERSISTENT -> serveEcho(request, input, output)
                }
            } catch (_: Exception) {
                // The finally block closes the session. Do not log a message.
            } catch (_: Throwable) {
                // A worker that cannot start is a server failure, not one
                // closed flow. Stop every other worker and report closed.
                failStop("session")
            } finally {
                close()
            }
        }

        fun close() {
            val releaseEcho: Boolean
            val readerGate: CountDownLatch?
            synchronized(closeLock) {
                if (closed) return
                closed = true
                releaseEcho = persistentSlot
                persistentSlot = false
                readerGate = udpReaderGate
                udpReaderGate = null
                val tcp = tcpFlow
                val udp = udpFlow
                // Shut down both directions before the close. A relay pump
                // that is blocked in a write must return even if the peer
                // never reads. Without this, an evicted session can keep its
                // worker permit indefinitely.
                abortSocket(client)
                if (tcp != null) abortSocket(tcp.socket)
                closeQuietly(client)
                closeFlow(tcp)
                closeFlow(udp)
                tcpFlow = null
                udpFlow = null
            }
            if (releaseEcho) persistentEchoCount.decrementAndGet()
            readerGate?.countDown()
            sessionClosed(this)
        }

        fun echoIdleExpired(now: Long): Boolean = synchronized(stateLock) {
            echoIdleAtNanos != 0L && now >= echoIdleAtNanos
        }

        fun echoLifetimeExpired(now: Long): Boolean = synchronized(stateLock) {
            echoLifetimeAtNanos != 0L && now >= echoLifetimeAtNanos
        }

        private fun markPhase(next: SourceSocksCapacity.Phase) {
            synchronized(stateLock) {
                phase = next
                phaseStartedNanos = System.nanoTime()
                lastActivityNanos = phaseStartedNanos
            }
        }

        private fun markConnecting() = markPhase(SourceSocksCapacity.Phase.CONNECTING)

        private fun markAwaitingRelay() {
            synchronized(stateLock) {
                phase = SourceSocksCapacity.Phase.AWAITING_RELAY
                phaseStartedNanos = System.nanoTime()
                awaitsRelay = true
            }
        }

        private fun admitRelayPhase(datagram: Boolean): Boolean = synchronized(stateLock) {
            if (phase != SourceSocksCapacity.Phase.AWAITING_RELAY || !awaitsRelay || replyPending) {
                false
            } else {
                phase = if (datagram) {
                    SourceSocksCapacity.Phase.UDP
                } else {
                    SourceSocksCapacity.Phase.OPEN_TCP
                }
                phaseStartedNanos = System.nanoTime()
                awaitsRelay = false
                true
            }
        }

        private fun denyRelay() {
            synchronized(stateLock) {
                if (phase == SourceSocksCapacity.Phase.AWAITING_RELAY) {
                    phase = SourceSocksCapacity.Phase.CONNECTING
                    phaseStartedNanos = System.nanoTime()
                    awaitsRelay = false
                }
            }
        }

        private fun beginReply() {
            synchronized(stateLock) { replyPending = true }
        }

        private fun finishReply() {
            synchronized(stateLock) { replyPending = false }
        }

        private fun beginControl() {
            synchronized(stateLock) {
                if (phase == SourceSocksCapacity.Phase.HANDSHAKE) controlActive = true
            }
        }

        private fun noteHalfClose() {
            synchronized(stateLock) {
                if (phase == SourceSocksCapacity.Phase.OPEN_TCP) {
                    phase = SourceSocksCapacity.Phase.HALF_CLOSED
                    phaseStartedNanos = System.nanoTime()
                    lastActivityNanos = phaseStartedNanos
                }
            }
        }

        private fun touch() {
            synchronized(stateLock) { lastActivityNanos = System.nanoTime() }
        }

        private fun startEchoTimers() {
            val now = System.nanoTime()
            synchronized(stateLock) {
                echoIdleAtNanos = now + echoIdleTimeout.toNanos()
                echoLifetimeAtNanos = now + echoLifetime.toNanos()
            }
        }

        private fun resetEchoIdle() {
            val now = System.nanoTime()
            synchronized(stateLock) {
                echoIdleAtNanos = now + echoIdleTimeout.toNanos()
            }
        }

        private fun acquirePersistentSlot(): Boolean {
            synchronized(closeLock) {
                if (closed) return false
                if (persistentSlot) return true
                while (true) {
                    val current = persistentEchoCount.get()
                    if (current >= persistentEchoLimit) return false
                    if (persistentEchoCount.compareAndSet(current, current + 1)) {
                        persistentSlot = true
                        return true
                    }
                }
            }
        }

        private fun trackTcp(flow: CellularFlow<Socket>): Boolean = synchronized(closeLock) {
            if (closed) {
                false
            } else {
                tcpFlow = flow
                true
            }
        }

        private fun untrackTcp(flow: CellularFlow<Socket>) {
            synchronized(closeLock) {
                if (tcpFlow === flow) tcpFlow = null
            }
        }

        private fun trackUdp(flow: CellularFlow<DatagramSocket>): Boolean = synchronized(closeLock) {
            if (closed) {
                false
            } else {
                udpFlow = flow
                true
            }
        }

        private fun untrackUdp(flow: CellularFlow<DatagramSocket>) {
            synchronized(closeLock) {
                if (udpFlow === flow) udpFlow = null
            }
        }

        private fun trackUdpReader(gate: CountDownLatch): Boolean = synchronized(closeLock) {
            if (closed) {
                false
            } else {
                udpReaderGate = gate
                true
            }
        }

        private fun untrackUdpReader(gate: CountDownLatch) {
            synchronized(closeLock) {
                if (udpReaderGate === gate) udpReaderGate = null
            }
        }

        private fun readHandshake(input: InputStream, output: OutputStream): Request? {
            val deadline = System.nanoTime() + handshakeTimeout.toNanos()
            val greeting = readExactly(input, 2, deadline)
            if ((greeting[0].toInt() and 0xFF) != SOCKS_VERSION) return null
            val methodCount = greeting[1].toInt() and 0xFF
            if (methodCount == 0) return null
            val methods = readExactly(input, methodCount, deadline)
            if (methods.none { (it.toInt() and 0xFF) == METHOD_USERNAME_PASSWORD }) {
                writeSmallReply(output, SOCKS_VERSION, METHOD_NONE_ACCEPTABLE)
                return null
            }
            writeSmallReply(output, SOCKS_VERSION, METHOD_USERNAME_PASSWORD)

            val authHeader = readExactly(input, 2, deadline)
            if ((authHeader[0].toInt() and 0xFF) != AUTH_VERSION) return null
            val userLength = authHeader[1].toInt() and 0xFF
            if (userLength == 0) return null
            val user = readExactly(input, userLength, deadline)
            val passwordLength = readExactly(input, 1, deadline)[0].toInt() and 0xFF
            if (passwordLength == 0) {
                writeSmallReply(output, AUTH_VERSION, 1)
                return null
            }
            val password = readExactly(input, passwordLength, deadline)
            val userOk = MessageDigest.isEqual(USERNAME, user)
            // The comparison always runs, so the timing does not reveal which
            // field failed. A stop clears the bytes under the same lock and
            // rejects a comparison that is already in flight.
            val tokenOk = synchronized(tokenLock) {
                val matches = MessageDigest.isEqual(tokenBytes, password)
                matches && state == State.RUNNING
            }
            password.fill(0)
            val valid = userOk && tokenOk
            writeSmallReply(output, AUTH_VERSION, if (valid) 0 else 1)
            if (!valid) return null

            val header = readExactly(input, 4, deadline)
            if ((header[0].toInt() and 0xFF) != SOCKS_VERSION) return null
            if ((header[2].toInt() and 0xFF) != 0) return null
            val command = header[1].toInt() and 0xFF
            val addressType = header[3].toInt() and 0xFF

            if (command == COMMAND_ECHO || command == COMMAND_ECHO_PERSISTENT) {
                if (addressType != ADDRESS_IPV4 && addressType != ADDRESS_IPV6) {
                    writeReply(output, REPLY_ADDRESS_NOT_SUPPORTED)
                    return null
                }
                val count = if (addressType == ADDRESS_IPV4) 4 else 16
                val address = readExactly(input, count, deadline)
                val portBytes = readExactly(input, 2, deadline)
                val destinationPort = ((portBytes[0].toInt() and 0xFF) shl 8) or
                    (portBytes[1].toInt() and 0xFF)
                val target = SourceEchoWire.target(addressType, address, destinationPort)
                if (target == null) {
                    writeReply(output, REPLY_ADDRESS_NOT_SUPPORTED)
                    return null
                }
                client.soTimeout = 0
                return Request(
                    command = command,
                    target = null,
                    port = 0,
                    echoTarget = target,
                    persistent = command == COMMAND_ECHO_PERSISTENT,
                )
            }

            if (command != COMMAND_CONNECT && command != COMMAND_UDP) {
                writeReply(output, REPLY_COMMAND_NOT_SUPPORTED)
                return null
            }
            val target = readTarget(input, addressType, deadline, output) ?: return null
            val portBytes = readExactly(input, 2, deadline)
            val destinationPort = ((portBytes[0].toInt() and 0xFF) shl 8) or
                (portBytes[1].toInt() and 0xFF)
            if (destinationPort == 0) {
                writeReply(output, REPLY_GENERAL_FAILURE)
                return null
            }
            client.soTimeout = 0
            return Request(command = command, target = target, port = destinationPort)
        }

        private fun readTarget(
            input: InputStream,
            addressType: Int,
            deadline: Long,
            output: OutputStream,
        ): Target? {
            return when (addressType) {
                ADDRESS_IPV4 -> {
                    val address = addressOf(readExactly(input, 4, deadline))
                    if (address == null) {
                        writeReply(output, REPLY_ADDRESS_NOT_SUPPORTED)
                        null
                    } else {
                        Target.Address(address)
                    }
                }
                ADDRESS_IPV6 -> {
                    val address = addressOf(readExactly(input, 16, deadline))
                    if (address == null) {
                        writeReply(output, REPLY_ADDRESS_NOT_SUPPORTED)
                        null
                    } else {
                        Target.Address(address)
                    }
                }
                ADDRESS_DOMAIN -> {
                    val length = readExactly(input, 1, deadline)[0].toInt() and 0xFF
                    if (length == 0) {
                        writeReply(output, REPLY_ADDRESS_NOT_SUPPORTED)
                        return null
                    }
                    val name = decodeName(readExactly(input, length, deadline))
                    if (name == null) {
                        writeReply(output, REPLY_ADDRESS_NOT_SUPPORTED)
                        null
                    } else {
                        Target.Name(name)
                    }
                }
                else -> {
                    writeReply(output, REPLY_ADDRESS_NOT_SUPPORTED)
                    null
                }
            }
        }

        private fun readExactly(input: InputStream, count: Int, deadline: Long): ByteArray {
            val bytes = ByteArray(count)
            var offset = 0
            while (offset < count) {
                val remaining = deadline - System.nanoTime()
                if (remaining <= 0) throw SocketTimeoutException()
                client.soTimeout = millisFrom(remaining)
                val read = input.read(bytes, offset, count - offset)
                if (read < 0) throw EOFException()
                offset += read
            }
            return bytes
        }

        private fun readFully(input: InputStream, count: Int): ByteArray {
            val bytes = ByteArray(count)
            var offset = 0
            while (offset < count) {
                val read = input.read(bytes, offset, count - offset)
                if (read < 0) throw EOFException()
                offset += read
            }
            return bytes
        }

        private fun writeSmallReply(output: OutputStream, first: Int, second: Int) {
            synchronized(clientWriteLock) {
                output.write(byteArrayOf(first.toByte(), second.toByte()))
                output.flush()
            }
        }

        private fun writeReply(output: OutputStream, code: Int) {
            val reply = byteArrayOf(
                SOCKS_VERSION.toByte(),
                code.toByte(),
                0,
                ADDRESS_IPV4.toByte(),
                0,
                0,
                0,
                0,
                0,
                0,
            )
            synchronized(clientWriteLock) {
                output.write(reply)
                output.flush()
            }
        }

        /** Send one final failure reply and keep the reply protection. */
        private fun writeFailureReply(output: OutputStream, code: Int) {
            beginReply()
            try {
                writeReply(output, code)
            } catch (_: Exception) {
                // The client is gone. The finally block closes the session.
            }
        }

        private fun serveTcp(request: Request, input: InputStream, output: OutputStream) {
            markConnecting()
            val flow = try {
                connectTcp(request.target ?: return, request.port)
            } catch (failure: ConnectFailure) {
                writeFailureReply(output, failure.replyCode)
                return
            } catch (_: Exception) {
                writeFailureReply(output, REPLY_GENERAL_FAILURE)
                return
            }
            markAwaitingRelay()
            if (!grantRelay(this)) {
                denyRelay()
                untrackTcp(flow)
                closeFlow(flow)
                writeFailureReply(output, REPLY_GENERAL_FAILURE)
                return
            }
            if (!admitRelayPhase(datagram = false)) {
                untrackTcp(flow)
                closeFlow(flow)
                writeFailureReply(output, REPLY_GENERAL_FAILURE)
                return
            }
            val destination = flow.socket
            val destinationInput = try {
                destination.getInputStream()
            } catch (_: Exception) {
                writeFailureReply(output, REPLY_GENERAL_FAILURE)
                return
            }
            val destinationOutput = try {
                destination.getOutputStream()
            } catch (_: Exception) {
                writeFailureReply(output, REPLY_GENERAL_FAILURE)
                return
            }
            // Start the pump before the success reply. A pump that cannot
            // start must not report a relay that is not running. The session
            // worker pumps the other direction, so one relay uses two workers.
            val upDone = CountDownLatch(1)
            val pumpStarted = try {
                workers?.tryStart {
                    try {
                        pump(
                            input,
                            destinationOutput,
                            destinationWriteLock,
                            shape = tlsShape,
                            onEnd = {
                                noteHalfClose()
                                shutdownOutputQuietly(destination)
                            },
                        )
                    } finally {
                        upDone.countDown()
                    }
                } ?: false
            } catch (_: Throwable) {
                writeFailureReply(output, REPLY_GENERAL_FAILURE)
                failStop("worker_start")
                return
            }
            if (!pumpStarted) {
                writeFailureReply(output, REPLY_GENERAL_FAILURE)
                return
            }
            beginReply()
            try {
                writeReply(output, REPLY_SUCCEEDED)
            } finally {
                finishReply()
            }
            pump(
                destinationInput,
                output,
                clientWriteLock,
                shape = false,
                onEnd = {
                    noteHalfClose()
                    shutdownOutputQuietly(client)
                },
            )
            try {
                upDone.await()
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                close()
            }
        }

        private fun connectTcp(target: Target, destinationPort: Int): CellularFlow<Socket> {
            val deadline = System.nanoTime() + connectTimeout.toNanos()
            val addresses = resolve(target, deadline)
            var lastFailure: IOException? = null
            for (address in addresses) {
                val remaining = deadline - System.nanoTime()
                if (remaining <= 0) break
                val flow = try {
                    cellular.tcp()
                } catch (_: Exception) {
                    throw ConnectFailure(REPLY_GENERAL_FAILURE)
                }
                if (!trackTcp(flow)) {
                    closeFlow(flow)
                    throw ConnectFailure(REPLY_GENERAL_FAILURE)
                }
                try {
                    flow.socket.tcpNoDelay = true
                    flow.socket.keepAlive = true
                    flow.socket.connect(InetSocketAddress(address, destinationPort), millisFrom(remaining))
                    return flow
                } catch (failure: IOException) {
                    lastFailure = failure
                    untrackTcp(flow)
                    closeFlow(flow)
                } catch (_: Exception) {
                    untrackTcp(flow)
                    closeFlow(flow)
                    throw ConnectFailure(REPLY_GENERAL_FAILURE)
                }
            }
            throw ConnectFailure(replyCodeFor(lastFailure))
        }

        private fun serveUdp(request: Request, input: InputStream, output: OutputStream) {
            markConnecting()
            val deadline = System.nanoTime() + connectTimeout.toNanos()
            val address = try {
                resolve(request.target ?: return, deadline).firstOrNull()
            } catch (_: ConnectFailure) {
                writeFailureReply(output, REPLY_GENERAL_FAILURE)
                return
            } catch (_: Exception) {
                writeFailureReply(output, REPLY_GENERAL_FAILURE)
                return
            }
            if (address == null) {
                writeFailureReply(output, REPLY_GENERAL_FAILURE)
                return
            }
            val flow = try {
                cellular.udp()
            } catch (_: Exception) {
                writeFailureReply(output, REPLY_GENERAL_FAILURE)
                return
            }
            if (!trackUdp(flow)) {
                closeFlow(flow)
                writeFailureReply(output, REPLY_GENERAL_FAILURE)
                return
            }
            val socket = flow.socket
            try {
                socket.connect(InetSocketAddress(address, request.port))
            } catch (_: Exception) {
                untrackUdp(flow)
                closeFlow(flow)
                writeFailureReply(output, REPLY_GENERAL_FAILURE)
                return
            }
            markAwaitingRelay()
            if (!grantRelay(this)) {
                denyRelay()
                untrackUdp(flow)
                closeFlow(flow)
                writeFailureReply(output, REPLY_GENERAL_FAILURE)
                return
            }
            if (!admitRelayPhase(datagram = true)) {
                untrackUdp(flow)
                closeFlow(flow)
                writeFailureReply(output, REPLY_GENERAL_FAILURE)
                return
            }
            // Start the datagram reader before the success reply, but hold its
            // first read until the reply is on the wire. The session worker
            // reads the client direction, so one UDP relay uses two workers.
            val readerGate = CountDownLatch(1)
            if (!trackUdpReader(readerGate)) {
                untrackUdp(flow)
                closeFlow(flow)
                writeFailureReply(output, REPLY_GENERAL_FAILURE)
                return
            }
            val readerStarted = try {
                workers?.tryStart { udpReader(socket, output, readerGate) } ?: false
            } catch (_: Throwable) {
                untrackUdpReader(readerGate)
                readerGate.countDown()
                writeFailureReply(output, REPLY_GENERAL_FAILURE)
                failStop("worker_start")
                return
            }
            if (!readerStarted) {
                untrackUdpReader(readerGate)
                readerGate.countDown()
                untrackUdp(flow)
                closeFlow(flow)
                writeFailureReply(output, REPLY_GENERAL_FAILURE)
                return
            }
            beginReply()
            try {
                writeReply(output, REPLY_SUCCEEDED)
            } finally {
                finishReply()
                readerGate.countDown()
            }
            readUdpFrames(input, socket)
        }

        private fun udpReader(
            socket: DatagramSocket,
            output: OutputStream,
            gate: CountDownLatch,
        ) {
            try {
                gate.await()
                if (closed) return
                val buffer = ByteArray(MAX_DATAGRAM + 1)
                while (!closed) {
                    val packet = DatagramPacket(buffer, buffer.size)
                    socket.receive(packet)
                    touch()
                    if (packet.length > MAX_DATAGRAM) {
                        close()
                        break
                    }
                    val payload = packet.data.copyOfRange(
                        packet.offset,
                        packet.offset + packet.length,
                    )
                    writeDatagram(output, payload)
                }
            } catch (_: Exception) {
                // A closed socket, an interrupted stop, or a stopped session
                // ends the reader.
            } finally {
                close()
            }
        }

        private fun writeDatagram(output: OutputStream, payload: ByteArray) {
            val header = byteArrayOf(
                (payload.size ushr 8).toByte(),
                payload.size.toByte(),
            )
            synchronized(clientWriteLock) {
                if (closed) return
                output.write(header)
                output.write(payload)
                output.flush()
            }
        }

        private fun readUdpFrames(input: InputStream, socket: DatagramSocket) {
            client.soTimeout = millisFrom(udpIdleTimeout.toNanos())
            val destination = socket.remoteSocketAddress as? InetSocketAddress
                ?: throw IOException("The UDP destination is not connected.")
            while (!closed) {
                val header = readFully(input, 2)
                val length = ((header[0].toInt() and 0xFF) shl 8) or
                    (header[1].toInt() and 0xFF)
                if (length > MAX_DATAGRAM) {
                    close()
                    return
                }
                val payload = if (length == 0) EMPTY else readFully(input, length)
                touch()
                socket.send(DatagramPacket(payload, payload.size, destination.address, destination.port))
            }
        }

        private fun pump(
            input: InputStream,
            output: OutputStream,
            writeLock: Any,
            shape: Boolean = false,
            onEnd: () -> Unit,
        ) {
            var shaper: SourceClientHelloShaper? = if (shape) SourceClientHelloShaper() else null
            try {
                val buffer = ByteArray(CLIENT_BUFFER)
                while (!closed) {
                    val read = input.read(buffer)
                    if (read < 0) {
                        // Release a partial ClientHello before the half-close.
                        // The shaper holds bytes only while they still look
                        // like TLS, and the destination must see them.
                        val current = shaper
                        if (current != null) {
                            synchronized(writeLock) {
                                if (closed) return
                                for (chunk in current.finish()) {
                                    output.write(chunk)
                                }
                                shaper = null
                                output.flush()
                            }
                        }
                        onEnd()
                        return
                    }
                    if (read == 0) continue
                    touch()
                    synchronized(writeLock) {
                        // Do not start a new write after the session closed.
                        // A write already in the socket is aborted by
                        // Session.close through shutdownOutput.
                        if (closed) return
                        val current = shaper
                        if (current == null) {
                            output.write(buffer, 0, read)
                        } else {
                            for (chunk in current.feed(buffer, 0, read)) {
                                output.write(chunk)
                            }
                            if (current.state != SourceClientHelloShaper.State.BUFFERING) {
                                shaper = null
                            }
                        }
                        output.flush()
                    }
                }
            } catch (_: Exception) {
                close()
            } finally {
                if (relayDone.incrementAndGet() == 2) close()
            }
        }

        private fun serveEcho(request: Request, input: InputStream, output: OutputStream) {
            val target = request.echoTarget ?: return
            if (request.persistent && !acquirePersistentSlot()) {
                writeFailureReply(output, REPLY_GENERAL_FAILURE)
                return
            }
            beginControl()
            beginReply()
            try {
                writeReply(output, REPLY_SUCCEEDED)
            } finally {
                finishReply()
            }
            if (request.persistent) {
                servePersistentEcho(target, input, output)
            } else {
                serveSingleEcho(target, input, output)
            }
        }

        private fun serveSingleEcho(
            target: EchoTarget,
            input: InputStream,
            output: OutputStream,
        ) {
            // One absolute bound covers the whole frame, header and payload.
            // A timeout per read would let a client that sends one byte just
            // inside every timeout hold a session slot indefinitely.
            val deadline = System.nanoTime() + echoRequestTimeout.toNanos()
            val header = readExactly(input, 2, deadline)
            val length = ((header[0].toInt() and 0xFF) shl 8) or (header[1].toInt() and 0xFF)
            if (length > SourceEchoWire.MAXIMUM_PAYLOAD) {
                writeEchoResponse(output, EchoStatus.FAILED, EMPTY)
                return
            }
            val payload = if (length == 0) EMPTY else readExactly(input, length, deadline)
            touch()
            val result = echo?.send(target, payload, echoAttemptTimeout.toMillis())
                ?: EchoResult(EchoStatus.FAILED)
            val echoed = result.status == EchoStatus.SUCCESS &&
                result.payload.size == payload.size &&
                result.payload.contentEquals(payload)
            val status = if (echoed) EchoStatus.SUCCESS else {
                if (result.status == EchoStatus.SUCCESS) EchoStatus.FAILED else result.status
            }
            writeEchoResponse(output, status, if (echoed) payload else EMPTY)
        }

        private fun servePersistentEcho(
            target: EchoTarget,
            input: InputStream,
            output: OutputStream,
        ) {
            val sender = echo ?: run {
                writeEchoResponse(output, EchoStatus.FAILED, EMPTY)
                return
            }
            startEchoTimers()
            while (!closed && state == State.RUNNING) {
                client.soTimeout = millisFrom(echoIdleTimeout.toNanos())
                val header = readFully(input, 2)
                val length = ((header[0].toInt() and 0xFF) shl 8) or
                    (header[1].toInt() and 0xFF)
                if (length > SourceEchoWire.MAXIMUM_PAYLOAD) {
                    close()
                    return
                }
                val payload = if (length == 0) EMPTY else readFully(input, length)
                touch()
                resetEchoIdle()
                val result = sender.send(target, payload, echoAttemptTimeout.toMillis())
                val echoed = result.status == EchoStatus.SUCCESS &&
                    result.payload.size == payload.size &&
                    result.payload.contentEquals(payload)
                val status = if (echoed) EchoStatus.SUCCESS else {
                    if (result.status == EchoStatus.SUCCESS) EchoStatus.FAILED else result.status
                }
                writeEchoResponse(output, status, if (echoed) payload else EMPTY)
                if (!echoed) {
                    close()
                    return
                }
                resetEchoIdle()
            }
        }

        private fun writeEchoResponse(
            output: OutputStream,
            status: EchoStatus,
            payload: ByteArray,
        ) {
            val frame = ByteArray(3 + payload.size)
            frame[0] = status.wire.toByte()
            frame[1] = ((payload.size shr 8) and 0xFF).toByte()
            frame[2] = (payload.size and 0xFF).toByte()
            payload.copyInto(frame, 3)
            synchronized(clientWriteLock) {
                if (closed) return
                output.write(frame)
                output.flush()
            }
        }
    }

    /**
     * A bounded daemon worker pool for sessions and relay pumps.
     *
     * A pool thread runs a blocking socket loop. The permit count bounds the
     * active tasks, so a task is never queued behind another task. The caller
     * decides between a capacity refusal and a failure before a task starts.
     * The pool never creates more than [limit] threads. A thread that cannot
     * start is reported to the caller before the task begins.
     */
    private inner class SourceWorkerPool(
        val limit: Int,
        threadFactory: ThreadFactory,
        executorFactory: ((Int, ThreadFactory) -> ThreadPoolExecutor)?,
    ) {
        private val permits = Semaphore(limit)
        private val executor: ThreadPoolExecutor = run {
            val guarded = ThreadFactory { runnable ->
                try {
                    threadFactory.newThread(runnable)
                } catch (failure: Throwable) {
                    // A real thread creation failure must reach the caller as
                    // an Error, not as a transient executor rejection. The
                    // executor itself only rejects when it is at its ceiling
                    // or shut down.
                    throw WorkerCreationFailure(failure)
                }
            }
            executorFactory?.invoke(limit, guarded)
                ?: ThreadPoolExecutor(
                    0,
                    limit,
                    30L,
                    TimeUnit.SECONDS,
                    SynchronousQueue(),
                    guarded,
                )
        }

        /** The permits that no worker task holds right now. */
        val availablePermits: Int get() = permits.availablePermits()

        /**
         * Reserve one worker and start [task] on it. Return false when every
         * worker is busy. A thread that cannot start throws before [task]
         * runs, and the reserved permit is released.
         *
         * A rejection from a live executor is a capacity refusal, not a
         * server failure. The executor can reject while a finished worker
         * is still leaving its thread, even though the caller holds a
         * permit. Retry that narrow window a bounded number of times; then
         * refuse this one flow and leave every other session running. A
         * rejection from a shut-down executor still throws. A real thread
         * creation failure arrives as [WorkerCreationFailure] and also
         * throws.
         */
        fun tryStart(task: () -> Unit): Boolean {
            if (!permits.tryAcquire()) return false
            val wrapped = Runnable {
                try {
                    inWorkerThread.set(true)
                    task()
                } catch (failure: Throwable) {
                    // An error on a pump or reader task is not one closed
                    // flow. Stop the listener and every other session.
                    if (failure !is Exception) failStop("session")
                } finally {
                    inWorkerThread.remove()
                    permits.release()
                }
            }
            var attempts = 0
            while (true) {
                try {
                    executor.execute(wrapped)
                    return true
                } catch (failure: RejectedExecutionException) {
                    if (executor.isShutdown) {
                        permits.release()
                        throw failure
                    }
                    attempts += 1
                    if (attempts >= MAXIMUM_WORKER_START_ATTEMPTS) {
                        permits.release()
                        return false
                    }
                    LockSupport.parkNanos(WORKER_START_RETRY_NANOS)
                } catch (failure: Throwable) {
                    permits.release()
                    throw failure
                }
            }
        }

        /** True on a thread of this pool. A stop on it must not wait for itself. */
        fun isWorkerThread(): Boolean = inWorkerThread.get() == true

        /**
         * Interrupt and stop the pool, then wait up to [millis].
         *
         * A caller on a pool thread does not wait, because it is the worker
         * that must exit. It returns true: no bounded wait expired, and the
         * pool drains after this worker returns. Return false only when the
         * wait expired with a worker still running.
         */
        fun shutdownAndAwait(millis: Long): Boolean {
            executor.shutdownNow()
            if (isWorkerThread()) return true
            return try {
                executor.awaitTermination(millis, TimeUnit.MILLISECONDS)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                false
            }
        }
    }

    private sealed class Target {
        class Address(val address: InetAddress) : Target() {
            override fun toString(): String = "Target.Address"
        }

        class Name(val host: String) : Target() {
            override fun toString(): String = "Target.Name"
        }
    }

    private class Request(
        val command: Int,
        val target: Target?,
        val port: Int,
        val echoTarget: EchoTarget? = null,
        val persistent: Boolean = false,
    ) {
        override fun toString(): String = "SourceSocksRequest"
    }

    private class ConnectFailure(val replyCode: Int) : Exception() {
        override fun toString(): String = "ConnectFailure"
    }

    private fun resolve(target: Target, deadline: Long): List<InetAddress> = when (target) {
        is Target.Address -> listOf(target.address)
        is Target.Name -> resolveName(target.host, deadline)
    }

    private fun resolveName(host: String, deadline: Long): List<InetAddress> {
        val remaining = deadline - System.nanoTime()
        if (remaining <= 0) throw ConnectFailure(REPLY_GENERAL_FAILURE)
        val executor = resolverExecutor ?: throw ConnectFailure(REPLY_GENERAL_FAILURE)
        val lookup = ResolverLookup(host)
        resolverOutstanding.incrementAndGet()
        val future = try {
            executor.submit(lookup)
        } catch (_: RejectedExecutionException) {
            resolverOutstanding.decrementAndGet()
            // A full queue or a stopped pool refuses this lookup at once. It
            // is a capacity result for one flow, never a server failure.
            if (state == State.RUNNING && !executor.isShutdown) {
                resolverRejections.incrementAndGet()
            }
            throw ConnectFailure(REPLY_GENERAL_FAILURE)
        }
        val addresses = try {
            future.get(remaining, TimeUnit.NANOSECONDS)
        } catch (_: TimeoutException) {
            lookup.abandon()
            future.cancel(true)
            throw ConnectFailure(REPLY_GENERAL_FAILURE)
        } catch (_: InterruptedException) {
            lookup.abandon()
            future.cancel(true)
            Thread.currentThread().interrupt()
            throw ConnectFailure(REPLY_GENERAL_FAILURE)
        } catch (_: ExecutionException) {
            throw ConnectFailure(REPLY_GENERAL_FAILURE)
        } catch (_: CancellationException) {
            lookup.abandon()
            throw ConnectFailure(REPLY_GENERAL_FAILURE)
        }
        if (addresses.isEmpty()) throw ConnectFailure(REPLY_GENERAL_FAILURE)
        return addresses
    }

    /**
     * One name lookup. It tracks whether its caller gave up while the
     * resolver is still inside the call.
     *
     * A canceled task that is still queued never runs. Its outstanding count
     * stays until the executor drops it on stop, which is after the status
     * matters. A running task that ignores the interrupt keeps its worker and
     * stays in the abandoned count until it returns.
     */
    private inner class ResolverLookup(private val host: String) :
        Callable<List<InetAddress>> {
        private val lock = Any()
        private var started = false
        private var abandoned = false
        private var counted = false
        private var finished = false

        override fun call(): List<InetAddress> {
            val count = synchronized(lock) {
                started = true
                if (abandoned && !counted) {
                    counted = true
                    true
                } else {
                    false
                }
            }
            if (count) resolverAbandoned.incrementAndGet()
            resolverActive.incrementAndGet()
            try {
                return resolver.resolve(host)
            } finally {
                resolverActive.decrementAndGet()
                resolverOutstanding.decrementAndGet()
                val release = synchronized(lock) {
                    finished = true
                    if (counted) {
                        counted = false
                        true
                    } else {
                        false
                    }
                }
                if (release) resolverAbandoned.decrementAndGet()
            }
        }

        /**
         * Mark that the caller stopped waiting for this lookup.
         *
         * A task that never starts is canceled before it runs, so it holds no
         * worker and is not counted. A task that starts after the caller gave
         * up is counted here, because its resolver call can now keep a worker.
         */
        fun abandon() {
            val count = synchronized(lock) {
                if (finished || abandoned) {
                    false
                } else {
                    abandoned = true
                    if (started && !counted) {
                        counted = true
                        true
                    } else {
                        false
                    }
                }
            }
            if (count) resolverAbandoned.incrementAndGet()
        }
    }

    private fun replyCodeFor(failure: IOException?): Int = when (failure) {
        is ConnectException -> REPLY_REFUSED
        is NoRouteToHostException -> REPLY_UNREACHABLE
        else -> REPLY_GENERAL_FAILURE
    }

    private fun addressOf(bytes: ByteArray): InetAddress? = try {
        // A byte array is a literal. This method does not resolve a name.
        InetAddress.getByAddress(bytes)
    } catch (_: Exception) {
        null
    }

    private fun decodeName(bytes: ByteArray): String? {
        val decoder = StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
        val name = try {
            decoder.decode(ByteBuffer.wrap(bytes)).toString()
        } catch (_: CharacterCodingException) {
            return null
        }
        if (name.isEmpty() || name.indexOf('\u0000') >= 0) return null
        return name
    }

    private fun millisFrom(nanos: Long): Int =
        maxOf(1L, nanos / 1_000_000L).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()

    private fun nanosToMillis(nanos: Long): Long = maxOf(0L, nanos / 1_000_000L)

    private fun daemonFactory(prefix: String): ThreadFactory {
        val count = AtomicInteger()
        return ThreadFactory { runnable ->
            Thread(runnable, "$prefix-${count.incrementAndGet()}").apply {
                isDaemon = true
            }
        }
    }

    private fun closeFlow(flow: CellularFlow<*>?) {
        if (flow == null) return
        try {
            flow.close()
        } catch (_: Exception) {
            // A failed close must not hide the session end.
        }
    }

    private fun closeQuietly(closeable: Closeable?) {
        if (closeable == null) return
        try {
            closeable.close()
        } catch (_: Exception) {
            // The session is already ending.
        }
    }

    private fun shutdownOutputQuietly(socket: Socket?) {
        if (socket == null) return
        try {
            socket.shutdownOutput()
        } catch (_: Exception) {
            // The other end already closed.
        }
    }

    /**
     * Stop both directions of one TCP socket before it closes.
     *
     * A close alone does not reliably wake a thread that is blocked in a
     * write on every platform. Shutdown does. The session close path calls
     * this so an evicted relay cannot keep its worker permit.
     */
    private fun abortSocket(socket: Socket?) {
        if (socket == null) return
        try {
            socket.shutdownOutput()
        } catch (_: Exception) {
            // The socket is already closed or not connected.
        }
        try {
            socket.shutdownInput()
        } catch (_: Exception) {
            // The socket is already closed or not connected.
        }
    }
}
