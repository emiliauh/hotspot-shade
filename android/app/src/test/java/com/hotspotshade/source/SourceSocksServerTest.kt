package com.hotspotshade.source

import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NoRouteToHostException
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketAddress
import java.net.SocketException
import java.net.SocketTimeoutException
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadFactory
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Test

class SourceSocksServerTest {
    private companion object {
        const val TOKEN = "test-token-0123456789abcdef"
        const val COMMAND_CONNECT = 1
        const val COMMAND_UDP = 0x80
        const val COMMAND_ECHO = 0x81
        const val COMMAND_ECHO_PERSISTENT = 0x82
        val LOOPBACK: InetAddress = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
        val LOOPBACK6: InetAddress = InetAddress.getByAddress(ByteArray(16).also { it[15] = 1 })
    }

    private class FakeBinding : CellularBinding {
        val tcpBinds = AtomicInteger()
        val udpBinds = AtomicInteger()

        override fun requireAvailable() = Unit

        override fun bind(socket: Socket) {
            tcpBinds.incrementAndGet()
        }

        override fun bind(socket: DatagramSocket) {
            udpBinds.incrementAndGet()
        }
    }

    private class FakeResolver(
        private val answer: (String) -> List<InetAddress> = { emptyList() },
    ) : SourceHostResolver {
        private val requested = mutableListOf<String>()

        val names: List<String>
            get() = synchronized(requested) { requested.toList() }

        override fun resolve(host: String): List<InetAddress> {
            synchronized(requested) { requested.add(host) }
            return answer(host)
        }
    }

    private class FakeEcho(
        private val status: EchoStatus = EchoStatus.SUCCESS,
    ) : SourceEchoSender {
        private val payloads = mutableListOf<ByteArray>()

        val received: List<ByteArray>
            get() = synchronized(payloads) { payloads.map { it.copyOf() } }

        override fun send(target: EchoTarget, payload: ByteArray, timeoutMillis: Long): EchoResult {
            synchronized(payloads) { payloads.add(payload.copyOf()) }
            return if (status == EchoStatus.SUCCESS) {
                EchoResult(EchoStatus.SUCCESS, payload.copyOf())
            } else {
                EchoResult(status)
            }
        }
    }

    private class Harness(
        resolver: SourceHostResolver = FakeResolver(),
        maximumRelays: Int = SourceSocksServer.MAXIMUM_RELAYS,
        setupReserve: Int = SourceSocksServer.SETUP_RESERVE,
        connectTimeout: Duration = Duration.ofSeconds(4),
        handshakeTimeout: Duration = Duration.ofSeconds(30),
        udpIdleTimeout: Duration = Duration.ofSeconds(300),
        newTcp: () -> Socket = { Socket() },
        newUdp: () -> DatagramSocket = { DatagramSocket(null as SocketAddress?) },
        echo: SourceEchoSender? = null,
        echoRequestTimeout: Duration = Duration.ofSeconds(5),
        echoIdleTimeout: Duration = Duration.ofSeconds(30),
        echoLifetime: Duration = Duration.ofSeconds(300),
        echoAttemptTimeout: Duration = Duration.ofSeconds(3),
        persistentEchoLimit: Int = SourceSocksServer.MAXIMUM_PERSISTENT_ECHO_SESSIONS,
        housekeepingInterval: Duration = Duration.ofMillis(500),
        tlsShape: Boolean = false,
        workerThreadFactory: ThreadFactory? = null,
        resolverLimit: Int = SourceSocksCapacity.resolverThreads(maximumRelays + setupReserve),
        stopWaitTimeout: Duration = Duration.ofSeconds(5),
        workerLimitOverride: Int? = null,
        listenerFactory: (() -> ServerSocket)? = null,
        workerExecutorFactory: ((Int, ThreadFactory) -> ThreadPoolExecutor)? = null,
    ) : Closeable {
        val binding = FakeBinding()
        private val cellular = CellularSession(CellularSockets(binding, newTcp, newUdp))
        val server = SourceSocksServer(
            cellular = cellular,
            resolver = resolver,
            bindAddress = LOOPBACK,
            token = TOKEN,
            port = 0,
            maximumRelays = maximumRelays,
            setupReserve = setupReserve,
            connectTimeout = connectTimeout,
            handshakeTimeout = handshakeTimeout,
            udpIdleTimeout = udpIdleTimeout,
            echo = echo,
            echoRequestTimeout = echoRequestTimeout,
            echoIdleTimeout = echoIdleTimeout,
            echoLifetime = echoLifetime,
            echoAttemptTimeout = echoAttemptTimeout,
            persistentEchoLimit = persistentEchoLimit,
            housekeepingInterval = housekeepingInterval,
            tlsShape = tlsShape,
            workerThreadFactory = workerThreadFactory,
            resolverLimit = resolverLimit,
            stopWaitTimeout = stopWaitTimeout,
            workerLimitOverride = workerLimitOverride,
            listenerFactory = listenerFactory,
            workerExecutorFactory = workerExecutorFactory,
        )

        init {
            server.start()
        }

        val port: Int get() = server.localPort

        fun connect(): Socket {
            val socket = Socket()
            socket.connect(InetSocketAddress(LOOPBACK, port), 2_000)
            socket.soTimeout = 2_000
            return socket
        }

        override fun close() {
            server.stop()
            cellular.close()
        }
    }

    private class TcpEcho(
        private val listener: ServerSocket = ServerSocket(0, 1, LOOPBACK),
    ) : Closeable {
        val port: Int get() = listener.localPort

        private val worker = Thread({
            try {
                while (true) {
                    val client = listener.accept()
                    Thread({
                        try {
                            client.use { socket ->
                                val input = socket.getInputStream()
                                val output = socket.getOutputStream()
                                val buffer = ByteArray(8 * 1024)
                                while (true) {
                                    val read = input.read(buffer)
                                    if (read < 0) break
                                    output.write(buffer, 0, read)
                                    output.flush()
                                }
                            }
                        } catch (_: IOException) {
                            // The test closed the flow.
                        }
                    }, "test-echo").apply { isDaemon = true }.start()
                }
            } catch (_: IOException) {
                // The test closed the listener.
            }
        }, "test-echo-accept").apply {
            isDaemon = true
            start()
        }

        override fun close() {
            listener.close()
        }
    }

    private class UdpEcho(
        address: InetAddress = LOOPBACK,
    ) : Closeable {
        private val socket = DatagramSocket(0, address)

        val port: Int get() = socket.localPort

        private val worker = Thread({
            try {
                val buffer = ByteArray(2 * 1024)
                while (true) {
                    val packet = DatagramPacket(buffer, buffer.size)
                    socket.receive(packet)
                    socket.send(
                        DatagramPacket(packet.data, packet.length, packet.address, packet.port),
                    )
                }
            } catch (_: IOException) {
                // The test closed the socket.
            }
        }, "test-udp-echo").apply {
            isDaemon = true
            start()
        }

        override fun close() {
            socket.close()
        }
    }

    /**
     * Accept one connection, read until the client half-closes, then keep the
     * socket open for a while. The relay sees one finished direction.
     */
    /**
     * Read every byte of one connection, split the shaped ClientHello record
     * frames, keep the unshaped tail, and reply with one fixed line.
     */
    private class ClientHelloSink(private val messageLength: Int) : Closeable {
        private val listener = ServerSocket(0, 1, LOOPBACK)
        val port: Int get() = listener.localPort
        private val finished = CountDownLatch(1)
        @Volatile var payload: ByteArray? = null
        @Volatile var tail: ByteArray? = null
        @Volatile var records = 0
        @Volatile var largest = 0
        @Volatile var failure: String? = null

        private val worker = Thread({
            try {
                listener.accept().use { socket ->
                    val bytes = socket.getInputStream().readBytes()
                    var offset = 0
                    val collected = java.io.ByteArrayOutputStream()
                    var count = 0
                    var biggest = 0
                    while (collected.size() < messageLength) {
                        check(bytes.size - offset >= 5) { "a record header is present" }
                        check((bytes[offset].toInt() and 0xFF) == 22) {
                            "a shaped record is a handshake record"
                        }
                        check((bytes[offset + 1].toInt() and 0xFF) == 3) {
                            "a shaped record keeps a TLS version"
                        }
                        val length = ((bytes[offset + 3].toInt() and 0xFF) shl 8) or
                            (bytes[offset + 4].toInt() and 0xFF)
                        check(bytes.size - offset - 5 >= length) {
                            "a record payload is complete"
                        }
                        collected.write(bytes, offset + 5, length)
                        biggest = maxOf(biggest, length)
                        offset += 5 + length
                        count += 1
                    }
                    payload = collected.toByteArray()
                    tail = bytes.copyOfRange(offset, bytes.size)
                    records = count
                    largest = biggest
                    socket.getOutputStream().write(
                        "response".toByteArray(StandardCharsets.US_ASCII),
                    )
                    socket.getOutputStream().flush()
                }
            } catch (error: Exception) {
                failure = error.message ?: error.javaClass.simpleName
            } finally {
                finished.countDown()
                listener.close()
            }
        }, "test-client-hello-sink").apply {
            isDaemon = true
            start()
        }

        fun await(timeoutMillis: Long): Boolean =
            finished.await(timeoutMillis, TimeUnit.MILLISECONDS)

        override fun close() {
            listener.close()
        }
    }

    private class HalfClosedEcho : Closeable {
        private val listener = ServerSocket(0, 1, LOOPBACK)
        private val release = CountDownLatch(1)
        val port: Int get() = listener.localPort

        private val worker = Thread({
            try {
                val client = listener.accept()
                val buffer = ByteArray(1024)
                while (client.getInputStream().read(buffer) >= 0) {
                    // Discard the data. There is none in this test.
                }
                // The read side ended. Keep the write side open until the test
                // releases the socket.
                release.await(10, TimeUnit.SECONDS)
                client.close()
            } catch (_: Exception) {
                // The test closed the listener.
            }
        }, "test-half-close").apply {
            isDaemon = true
            start()
        }

        override fun close() {
            release.countDown()
            listener.close()
        }
    }

    private class TimeoutSocket : Socket() {
        @Volatile
        var lastTimeout = -1

        override fun connect(endpoint: SocketAddress?, timeout: Int) {
            lastTimeout = timeout
            throw SocketTimeoutException("connect timed out")
        }
    }

    /**
     * A worker factory whose thread fails to start at one index. The other
     * threads are normal daemon threads. The accept and housekeeping threads
     * do not come from this factory.
     */
    private class FailingThreadFactory(private val failAt: Int) : ThreadFactory {
        private val count = AtomicInteger()

        override fun newThread(runnable: Runnable): Thread {
            val index = count.incrementAndGet()
            if (index == failAt) {
                return object : Thread(runnable, "test-worker-$index") {
                    override fun start() {
                        throw OutOfMemoryError("test thread start failure")
                    }
                }.apply { isDaemon = true }
            }
            return Thread(runnable, "test-worker-$index").apply { isDaemon = true }
        }
    }

    /** A factory that fails at creation, not at Thread.start. */
    private class ThrowingThreadFactory : ThreadFactory {
        override fun newThread(runnable: Runnable): Thread =
            throw OutOfMemoryError("test thread creation failure")
    }

    /**
     * A live executor that throws [RejectedExecutionException] for a chosen
     * number of calls, as a saturated executor does at its ceiling.
     */
    private class RejectingExecutor(
        limit: Int,
        factory: ThreadFactory,
    ) : ThreadPoolExecutor(
        0,
        limit,
        30L,
        TimeUnit.SECONDS,
        SynchronousQueue(),
        factory,
    ) {
        private val remaining = AtomicInteger()

        fun reject(count: Int) {
            remaining.set(count)
        }

        override fun execute(command: Runnable) {
            while (true) {
                val current = remaining.get()
                if (current <= 0) break
                if (remaining.compareAndSet(current, current - 1)) {
                    throw RejectedExecutionException("test ceiling")
                }
            }
            super.execute(command)
        }
    }

    /** A listener that accepts one real client, then fails. */
    private class AcceptErrorServerSocket(
        private val errorGate: CountDownLatch,
    ) : ServerSocket() {
        private val calls = AtomicInteger()

        override fun accept(): Socket {
            if (calls.incrementAndGet() == 1) return super.accept()
            errorGate.await(5, TimeUnit.SECONDS)
            throw SocketException("test accept error")
        }
    }

    /** A listener whose close blocks until the test releases it. */
    private class SlowCloseServerSocket(
        private val closeStarted: CountDownLatch,
        private val releaseClose: CountDownLatch,
    ) : ServerSocket() {
        override fun close() {
            closeStarted.countDown()
            releaseClose.await(10, TimeUnit.SECONDS)
            super.close()
        }
    }

    /** A listener that returns one scripted socket, then accepts real ones. */
    private class ScriptedAcceptServerSocket(
        private val first: Socket,
    ) : ServerSocket() {
        private val count = AtomicInteger()

        override fun accept(): Socket =
            if (count.getAndIncrement() == 0) first else super.accept()
    }

    /** A destination that sends until the server closes the flow. */
    private class FirehoseServer : Closeable {
        private val listener = ServerSocket(0, 1, LOOPBACK)

        @Volatile
        private var connection: Socket? = null

        val port: Int get() = listener.localPort

        private val worker = Thread({
            try {
                val client = listener.accept()
                connection = client
                val output = client.getOutputStream()
                val chunk = ByteArray(8 * 1024)
                while (true) {
                    output.write(chunk)
                    output.flush()
                }
            } catch (_: IOException) {
                // The server closed the destination.
            }
        }, "test-firehose").apply {
            isDaemon = true
            start()
        }

        override fun close() {
            try {
                listener.close()
            } catch (_: IOException) {
                // Already closed.
            }
            try {
                connection?.close()
            } catch (_: IOException) {
                // Already closed.
            }
        }
    }

    /**
     * A server-side client socket with a controllable output stream.
     *
     * The output blocks on purpose. A close alone does not unblock it, so the
     * test proves that the session shutdown path calls shutdownOutput before
     * it closes the socket.
     */
    private class FakeClientSocket : Socket() {
        private val inputPipe = PipedInputStream(64 * 1024)
        private val inputWriter = PipedOutputStream(inputPipe)
        private val output = BlockingOutputStream()
        private val closed = AtomicBoolean()

        val writeBlocked: CountDownLatch get() = output.enteredBlock

        fun offer(bytes: ByteArray) {
            inputWriter.write(bytes)
            inputWriter.flush()
        }

        fun endInput() {
            try {
                inputWriter.close()
            } catch (_: IOException) {
                // Already closed.
            }
        }

        fun blockWrites() {
            output.blockWrites = true
        }

        fun forceAbort() {
            output.abort()
        }

        fun responseBytes(): ByteArray = output.snapshot()

        val outputAborted: Boolean get() = output.isAborted

        override fun getInputStream(): InputStream = inputPipe

        override fun getOutputStream(): OutputStream = output

        override fun setSoTimeout(timeout: Int) = Unit

        override fun getSoTimeout(): Int = 0

        override fun setTcpNoDelay(on: Boolean) = Unit

        override fun setKeepAlive(on: Boolean) = Unit

        override fun shutdownOutput() {
            output.abort()
        }

        override fun shutdownInput() {
            try {
                inputPipe.close()
            } catch (_: IOException) {
                // Already closed.
            }
        }

        override fun close() {
            if (!closed.compareAndSet(false, true)) return
            try {
                inputWriter.close()
            } catch (_: IOException) {
                // Already closed.
            }
            try {
                inputPipe.close()
            } catch (_: IOException) {
                // Already closed.
            }
            // Do not abort the output here. The production close path must
            // call shutdownOutput before close.
        }

        override fun isClosed(): Boolean = closed.get()
    }

    /** An output stream that blocks until it is aborted. */
    private class BlockingOutputStream : OutputStream() {
        private val buffer = ByteArrayOutputStream()
        private val bufferLock = Any()
        private val release = CountDownLatch(1)
        val enteredBlock = CountDownLatch(1)

        @Volatile
        var blockWrites = false

        @Volatile
        private var aborted = false

        val isAborted: Boolean get() = aborted

        override fun write(value: Int) {
            write(byteArrayOf(value.toByte()), 0, 1)
        }

        override fun write(bytes: ByteArray, offset: Int, length: Int) {
            if (blockWrites && !aborted) {
                enteredBlock.countDown()
                while (!aborted) {
                    try {
                        release.await(20, TimeUnit.MILLISECONDS)
                    } catch (_: InterruptedException) {
                        // Keep waiting until abort.
                    }
                }
            }
            if (aborted) throw SocketException("test output aborted")
            synchronized(bufferLock) { buffer.write(bytes, offset, length) }
        }

        override fun flush() = Unit

        fun abort() {
            aborted = true
            release.countDown()
        }

        fun snapshot(): ByteArray = synchronized(bufferLock) { buffer.toByteArray() }
    }

    /** A resolver that ignores interruption until the test releases it. */
    private class HoldingResolver : SourceHostResolver {
        private val release = CountDownLatch(1)
        private val started = AtomicInteger()

        val startedCount: Int get() = started.get()

        override fun resolve(host: String): List<InetAddress> {
            started.incrementAndGet()
            while (true) {
                try {
                    release.await()
                    return listOf(LOOPBACK)
                } catch (_: InterruptedException) {
                    // This resolver does not cooperate with cancellation.
                }
            }
        }

        fun releaseAll() {
            release.countDown()
        }
    }

    @Test
    fun authenticationSucceedsAndTcpConnectEchoes() {
        TcpEcho().use { echo ->
            Harness().use { harness ->
                harness.connect().use { client ->
                    negotiate(client)
                    write(client, ipv4Request(COMMAND_CONNECT, echo.port))
                    assertEquals(0, readReply(client.getInputStream()))
                    client.getOutputStream().write("hello".toByteArray())
                    client.getOutputStream().flush()
                    assertArrayEquals(
                        "hello".toByteArray(),
                        readExactly(client.getInputStream(), 5),
                    )
                }
            }
        }
    }

    @Test
    fun connectionCountersReportActiveAndTotalRelays() {
        TcpEcho().use { echo ->
            Harness().use { harness ->
                assertEquals(0, harness.server.activeConnections)
                assertEquals(0L, harness.server.totalConnections)
                val first = harness.connect()
                try {
                    negotiate(first)
                    write(first, ipv4Request(COMMAND_CONNECT, echo.port))
                    assertEquals(0, readReply(first.getInputStream()))
                    assertEquals(1, harness.server.activeConnections)
                    assertEquals(1L, harness.server.totalConnections)

                    val second = harness.connect()
                    try {
                        negotiate(second)
                        write(second, ipv4Request(COMMAND_CONNECT, echo.port))
                        assertEquals(0, readReply(second.getInputStream()))
                        assertEquals(2, harness.server.activeConnections)
                        assertEquals(2L, harness.server.totalConnections)
                    } finally {
                        second.close()
                    }
                } finally {
                    first.close()
                }
                assertTrue(
                    "The open count must fall when the flows close.",
                    waitFor(2_000) { harness.server.activeConnections == 0 },
                )
                assertEquals(2L, harness.server.totalConnections)
            }
        }
    }

    @Test
    fun wrongTokenGetsOneFailureReply() {
        Harness().use { harness ->
            harness.connect().use { client ->
                val input = client.getInputStream()
                val output = client.getOutputStream()
                output.write(byteArrayOf(5, 1, 2))
                output.flush()
                assertArrayEquals(byteArrayOf(5, 2), readExactly(input, 2))
                output.write(authBytes("wrong-token"))
                output.flush()
                assertArrayEquals(byteArrayOf(1, 1), readExactly(input, 2))
                assertEndOfStream(client)
            }
        }
    }

    @Test
    fun methodWithoutPasswordAuthenticationIsRejected() {
        Harness().use { harness ->
            harness.connect().use { client ->
                val input = client.getInputStream()
                val output = client.getOutputStream()
                output.write(byteArrayOf(5, 1, 0))
                output.flush()
                assertArrayEquals(byteArrayOf(5, 0xFF.toByte()), readExactly(input, 2))
                assertEndOfStream(client)
            }
        }
    }

    @Test
    fun domainRequestUsesTheInjectedResolver() {
        val resolver = FakeResolver { host ->
            if (host == "echo-source.test.invalid") listOf(LOOPBACK) else emptyList()
        }
        TcpEcho().use { echo ->
            Harness(resolver = resolver).use { harness ->
                harness.connect().use { client ->
                    negotiate(client)
                    write(client, domainRequest(echo.port, "echo-source.test.invalid"))
                    assertEquals(0, readReply(client.getInputStream()))
                    assertEquals(listOf("echo-source.test.invalid"), resolver.names)
                    client.getOutputStream().write("domain".toByteArray())
                    client.getOutputStream().flush()
                    assertArrayEquals(
                        "domain".toByteArray(),
                        readExactly(client.getInputStream(), 6),
                    )
                }
            }
        }
    }

    @Test
    fun udpFramesRoundTrip() {
        UdpEcho().use { echo ->
            Harness().use { harness ->
                harness.connect().use { client ->
                    negotiate(client)
                    write(client, ipv4Request(COMMAND_UDP, echo.port))
                    assertEquals(0, readReply(client.getInputStream()))
                    writeSlowly(client.getOutputStream(), frame("datagram"))
                    assertArrayEquals("datagram".toByteArray(), readFrame(client.getInputStream()))
                    write(client, frame("second"))
                    assertArrayEquals("second".toByteArray(), readFrame(client.getInputStream()))
                    assertTrue(harness.binding.udpBinds.get() >= 1)
                }
            }
        }
    }

    @Test
    fun generalFailureUsesCodeOne() {
        Harness().use { harness ->
            harness.connect().use { client ->
                negotiate(client)
                write(client, ipv4Request(COMMAND_CONNECT, 0))
                assertEquals(1, readReply(client.getInputStream()))
                assertEndOfStream(client)
            }
        }
    }

    @Test
    fun unreachableDestinationUsesCodeFour() {
        val fake = object : Socket() {
            override fun connect(endpoint: SocketAddress?, timeout: Int) {
                throw NoRouteToHostException("unreachable")
            }
        }
        Harness(newTcp = { fake }).use { harness ->
            harness.connect().use { client ->
                negotiate(client)
                write(client, ipv4Request(COMMAND_CONNECT, 9))
                assertEquals(4, readReply(client.getInputStream()))
                assertEndOfStream(client)
            }
        }
    }

    @Test
    fun refusedDestinationUsesCodeFive() {
        val closedPort = ServerSocket(0, 1, LOOPBACK).use { it.localPort }
        Harness().use { harness ->
            harness.connect().use { client ->
                negotiate(client)
                write(client, ipv4Request(COMMAND_CONNECT, closedPort))
                assertEquals(5, readReply(client.getInputStream()))
                assertEndOfStream(client)
            }
        }
    }

    @Test
    fun unsupportedCommandUsesCodeSeven() {
        Harness().use { harness ->
            harness.connect().use { client ->
                negotiate(client)
                write(client, byteArrayOf(5, 2, 0, 1))
                assertEquals(7, readReply(client.getInputStream()))
                assertEndOfStream(client)
            }
        }
    }

    @Test
    fun unsupportedAddressTypeUsesCodeEight() {
        Harness().use { harness ->
            harness.connect().use { client ->
                negotiate(client)
                write(client, byteArrayOf(5, 1, 0, 9))
                assertEquals(8, readReply(client.getInputStream()))
                assertEndOfStream(client)
            }
        }
    }

    @Test
    fun emptyDomainUsesCodeEight() {
        Harness().use { harness ->
            harness.connect().use { client ->
                negotiate(client)
                write(client, byteArrayOf(5, 1, 0, 3, 0))
                assertEquals(8, readReply(client.getInputStream()))
                assertEndOfStream(client)
            }
        }
    }

    @Test
    fun relayCapacityRefusesWithCodeOneAndKeepsAnOpenRelay() {
        TcpEcho().use { echo ->
            Harness(maximumRelays = 1, setupReserve = 1).use { harness ->
                harness.connect().use { first ->
                    negotiate(first)
                    write(first, ipv4Request(COMMAND_CONNECT, echo.port))
                    assertEquals(0, readReply(first.getInputStream()))
                    write(first, "one".toByteArray())
                    assertArrayEquals("one".toByteArray(), readExactly(first.getInputStream(), 3))
                    Thread.sleep(300)
                    harness.connect().use { second ->
                        negotiate(second)
                        write(second, ipv4Request(COMMAND_CONNECT, echo.port))
                        assertEquals(1, readReply(second.getInputStream()))
                        assertEndOfStream(second)
                    }
                    write(first, "still".toByteArray())
                    assertArrayEquals(
                        "still".toByteArray(),
                        readExactly(first.getInputStream(), 5),
                    )
                }
            }
        }
    }

    @Test
    fun totalCapacityClosesANewConnectionBeforeTheGreeting() {
        TcpEcho().use { echo ->
            Harness(maximumRelays = 1, setupReserve = 1).use { harness ->
                harness.connect().use { first ->
                    negotiate(first)
                    write(first, ipv4Request(COMMAND_CONNECT, echo.port))
                    assertEquals(0, readReply(first.getInputStream()))
                    harness.connect().use { second ->
                        negotiate(second)
                        harness.connect().use { third ->
                            assertEndOfStream(third)
                        }
                        write(second, ipv4Request(COMMAND_CONNECT, echo.port))
                        assertEquals(1, readReply(second.getInputStream()))
                        assertEndOfStream(second)
                    }
                    write(first, "alive".toByteArray())
                    assertArrayEquals(
                        "alive".toByteArray(),
                        readExactly(first.getInputStream(), 5),
                    )
                }
            }
        }
    }

    @Test
    fun partialReadsWorkOneByteAtATime() {
        TcpEcho().use { echo ->
            Harness().use { harness ->
                harness.connect().use { client ->
                    val input = client.getInputStream()
                    val output = client.getOutputStream()
                    writeSlowly(output, byteArrayOf(5, 1, 2))
                    assertArrayEquals(byteArrayOf(5, 2), readExactly(input, 2))
                    writeSlowly(output, authBytes(TOKEN))
                    assertArrayEquals(byteArrayOf(1, 0), readExactly(input, 2))
                    writeSlowly(output, ipv4Request(COMMAND_CONNECT, echo.port))
                    assertEquals(0, readReply(input))
                    output.write("slow".toByteArray())
                    output.flush()
                    assertArrayEquals("slow".toByteArray(), readExactly(input, 4))
                }
            }
        }
    }

    @Test
    fun stopClearsTheInMemoryToken() {
        Harness().use { harness ->
            val field = SourceSocksServer::class.java.getDeclaredField("tokenBytes")
            field.isAccessible = true
            val bytes = field.get(harness.server) as ByteArray
            assertArrayEquals(TOKEN.toByteArray(StandardCharsets.UTF_8), bytes)

            harness.server.stop()

            assertTrue(
                "A stopped server must clear its token copy.",
                bytes.all { it == 0.toByte() },
            )
        }
    }

    @Test
    fun stopClosesTheListenerAndEverySessionAndNeverRestarts() {
        TcpEcho().use { echo ->
            UdpEcho().use { udpEcho ->
                Harness().use { harness ->
                    harness.connect().use { tcp ->
                        negotiate(tcp)
                        write(tcp, ipv4Request(COMMAND_CONNECT, echo.port))
                        assertEquals(0, readReply(tcp.getInputStream()))
                        harness.connect().use { udp ->
                            negotiate(udp)
                            write(udp, ipv4Request(COMMAND_UDP, udpEcho.port))
                            assertEquals(0, readReply(udp.getInputStream()))
                            harness.connect().use { setup ->
                                negotiate(setup)
                                harness.server.stop()
                                assertFalse(harness.server.isRunning)
                                assertEndOfStream(tcp)
                                assertEndOfStream(udp)
                                assertEndOfStream(setup)
                                harness.server.stop()
                                try {
                                    harness.server.start()
                                    fail("A stopped source server must not restart.")
                                } catch (_: IllegalStateException) {
                                    // Expected.
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    @Test
    fun handshakeBoundClosesASilentClient() {
        Harness(handshakeTimeout = Duration.ofSeconds(1)).use { harness ->
            harness.connect().use { client ->
                assertEndOfStream(client)
            }
            harness.connect().use { client ->
                negotiate(client)
                assertEndOfStream(client)
            }
        }
    }

    @Test
    fun connectTimeoutIsUsedAndMapsToCodeOne() {
        val socket = TimeoutSocket()
        Harness(newTcp = { socket }, connectTimeout = Duration.ofMillis(250)).use { harness ->
            harness.connect().use { client ->
                negotiate(client)
                write(client, ipv4Request(COMMAND_CONNECT, 9))
                assertEquals(1, readReply(client.getInputStream()))
                assertTrue(socket.lastTimeout in 1..250)
                assertEndOfStream(client)
            }
        }
    }

    @Test
    fun resolverDeadlineIsBounded() {
        val started = CountDownLatch(1)
        val release = CountDownLatch(1)
        val resolver = SourceHostResolver {
            started.countDown()
            release.await(5, TimeUnit.SECONDS)
            listOf(LOOPBACK)
        }
        try {
            Harness(
                resolver = resolver,
                connectTimeout = Duration.ofMillis(250),
            ).use { harness ->
                harness.connect().use { client ->
                    negotiate(client)
                    write(client, domainRequest(9, "slow.test.invalid"))
                    assertTrue(started.await(1, TimeUnit.SECONDS))
                    assertEquals(1, readReply(client.getInputStream()))
                    assertEndOfStream(client)
                }
            }
        } finally {
            release.countDown()
        }
    }

    @Test
    fun ipv6LiteralConnects() {
        val loopback6 = InetAddress.getByAddress(ByteArray(16).also { it[15] = 1 })
        val echo = try {
            TcpEcho(ServerSocket(0, 1, loopback6))
        } catch (_: IOException) {
            assumeTrue("IPv6 loopback is not available.", false)
            return
        }
        echo.use {
            Harness().use { harness ->
                harness.connect().use { client ->
                    negotiate(client)
                    write(client, ipv6Request(echo.port, loopback6))
                    assertEquals(0, readReply(client.getInputStream()))
                    client.getOutputStream().write("v6".toByteArray())
                    client.getOutputStream().flush()
                    assertArrayEquals("v6".toByteArray(), readExactly(client.getInputStream(), 2))
                }
            }
        }
    }

    @Test
    fun toStringHidesTheTokenAndTheAddress() {
        Harness().use { harness ->
            val text = harness.server.toString()
            assertFalse(text.contains(TOKEN))
            assertFalse(text.contains("127.0.0.1"))
        }
    }

    @Test
    fun bindFailureMessageHidesTheAddress() {
        Harness().use { first ->
            val cellular = CellularSession(CellularSockets(FakeBinding()))
            val second = SourceSocksServer(
                cellular = cellular,
                resolver = FakeResolver(),
                bindAddress = LOOPBACK,
                token = TOKEN,
                port = first.port,
            )
            try {
                second.start()
                fail("The second listener must not bind.")
            } catch (failure: IOException) {
                val message = failure.message.orEmpty()
                assertFalse(message.contains("127.0.0.1"))
                assertFalse(message.contains(first.port.toString()))
            } finally {
                second.stop()
                cellular.close()
            }
        }
    }

    @Test
    fun echoCommandReturnsThePayload() {
        val echo = FakeEcho()
        Harness(echo = echo).use { harness ->
            harness.connect().use { client ->
                negotiate(client)
                write(client, echoRequest(COMMAND_ECHO, byteArrayOf(10, 0, 2, 2)))
                assertEquals(0, readReply(client.getInputStream()))
                write(client, frame("probe"))
                val (status, payload) = readEchoResponse(client.getInputStream())
                assertEquals(0, status)
                assertArrayEquals("probe".toByteArray(), payload)
                assertEquals(1, echo.received.size)
                assertArrayEquals("probe".toByteArray(), echo.received[0])
                // An echo session holds no relay slot.
                assertEquals(0, harness.server.activeConnections)
                assertEquals(0L, harness.server.totalConnections)
                assertEndOfStream(client)
            }
        }
    }

    @Test
    fun echoCommandWithoutASenderReturnsCodeFour() {
        Harness().use { harness ->
            harness.connect().use { client ->
                negotiate(client)
                write(client, echoRequest(COMMAND_ECHO, byteArrayOf(10, 0, 2, 2)))
                assertEquals(0, readReply(client.getInputStream()))
                write(client, frame("probe"))
                val (status, payload) = readEchoResponse(client.getInputStream())
                assertEquals(4, status)
                assertEquals(0, payload.size)
                assertEndOfStream(client)
            }
        }
    }

    @Test
    fun echoTargetWithAPortUsesCodeEight() {
        Harness(echo = FakeEcho()).use { harness ->
            harness.connect().use { client ->
                negotiate(client)
                write(client, echoRequest(COMMAND_ECHO, byteArrayOf(1, 1, 1, 1), port = 53))
                assertEquals(8, readReply(client.getInputStream()))
                assertEndOfStream(client)
            }
        }
    }

    @Test
    fun echoDomainTargetUsesCodeEight() {
        Harness(echo = FakeEcho()).use { harness ->
            harness.connect().use { client ->
                negotiate(client)
                write(client, byteArrayOf(5, COMMAND_ECHO.toByte(), 0, 3))
                assertEquals(8, readReply(client.getInputStream()))
                assertEndOfStream(client)
            }
        }
    }

    @Test
    fun echoPayloadOverTheLimitGetsAFailedStatus() {
        Harness(echo = FakeEcho()).use { harness ->
            harness.connect().use { client ->
                negotiate(client)
                write(client, echoRequest(COMMAND_ECHO, byteArrayOf(1, 1, 1, 1)))
                assertEquals(0, readReply(client.getInputStream()))
                // 1201 bytes is above the 1200 byte limit.
                write(client, byteArrayOf(0x04, 0xB1.toByte()))
                val (status, payload) = readEchoResponse(client.getInputStream())
                assertEquals(4, status)
                assertEquals(0, payload.size)
                assertEndOfStream(client)
            }
        }
    }

    @Test
    fun persistentEchoServesSeveralFrames() {
        val echo = FakeEcho()
        Harness(echo = echo).use { harness ->
            harness.connect().use { client ->
                negotiate(client)
                write(client, echoRequest(COMMAND_ECHO_PERSISTENT, byteArrayOf(1, 1, 1, 1)))
                assertEquals(0, readReply(client.getInputStream()))
                write(client, frame("one"))
                assertEquals(0, readEchoResponse(client.getInputStream()).first)
                write(client, frame("two"))
                val (status, payload) = readEchoResponse(client.getInputStream())
                assertEquals(0, status)
                assertArrayEquals("two".toByteArray(), payload)
                assertEquals(2, echo.received.size)
            }
        }
    }

    @Test
    fun persistentEchoGrantsAtMostSixteenSessions() {
        val sessions = mutableListOf<Socket>()
        try {
            Harness(echo = FakeEcho()).use { harness ->
                repeat(SourceSocksServer.MAXIMUM_PERSISTENT_ECHO_SESSIONS) {
                    val client = harness.connect()
                    negotiate(client)
                    write(client, echoRequest(COMMAND_ECHO_PERSISTENT, byteArrayOf(1, 1, 1, 1)))
                    assertEquals(0, readReply(client.getInputStream()))
                    sessions += client
                }
                harness.connect().use { extra ->
                    negotiate(extra)
                    write(extra, echoRequest(COMMAND_ECHO_PERSISTENT, byteArrayOf(1, 1, 1, 1)))
                    assertEquals(1, readReply(extra.getInputStream()))
                    assertEndOfStream(extra)
                }
                // The earlier sessions keep their echo slots.
                write(sessions[0], frame("still"))
                val (status, payload) = readEchoResponse(sessions[0].getInputStream())
                assertEquals(0, status)
                assertArrayEquals("still".toByteArray(), payload)
            }
        } finally {
            sessions.forEach { session ->
                try {
                    session.close()
                } catch (_: IOException) {
                    // The test already closed the socket.
                }
            }
        }
    }

    @Test
    fun persistentEchoClosesAfterTheIdleBound() {
        Harness(
            echo = FakeEcho(),
            echoIdleTimeout = Duration.ofMillis(200),
            housekeepingInterval = Duration.ofMillis(50),
        ).use { harness ->
            harness.connect().use { client ->
                negotiate(client)
                write(client, echoRequest(COMMAND_ECHO_PERSISTENT, byteArrayOf(1, 1, 1, 1)))
                assertEquals(0, readReply(client.getInputStream()))
                Thread.sleep(600)
                assertEndOfStream(client)
            }
        }
    }

    @Test
    fun persistentEchoClosesAtTheLifetime() {
        Harness(
            echo = FakeEcho(),
            echoIdleTimeout = Duration.ofSeconds(10),
            echoLifetime = Duration.ofMillis(250),
            housekeepingInterval = Duration.ofMillis(50),
        ).use { harness ->
            harness.connect().use { client ->
                negotiate(client)
                write(client, echoRequest(COMMAND_ECHO_PERSISTENT, byteArrayOf(1, 1, 1, 1)))
                assertEquals(0, readReply(client.getInputStream()))
                Thread.sleep(600)
                assertEndOfStream(client)
            }
        }
    }

    @Test
    fun oneShotEchoWithoutAPayloadClosesAtTheRequestBound() {
        Harness(
            echo = FakeEcho(),
            echoRequestTimeout = Duration.ofMillis(200),
        ).use { harness ->
            harness.connect().use { client ->
                negotiate(client)
                write(client, echoRequest(COMMAND_ECHO, byteArrayOf(1, 1, 1, 1)))
                assertEquals(0, readReply(client.getInputStream()))
                assertEndOfStream(client)
            }
        }
    }

    @Test
    fun openTcpRelayIsNotClosedForSilence() {
        TcpEcho().use { echo ->
            Harness(
                udpIdleTimeout = Duration.ofMillis(150),
                housekeepingInterval = Duration.ofMillis(50),
            ).use { harness ->
                harness.connect().use { client ->
                    negotiate(client)
                    write(client, ipv4Request(COMMAND_CONNECT, echo.port))
                    assertEquals(0, readReply(client.getInputStream()))
                    Thread.sleep(700)
                    write(client, "still".toByteArray())
                    assertArrayEquals(
                        "still".toByteArray(),
                        readExactly(client.getInputStream(), 5),
                    )
                }
            }
        }
    }

    @Test
    fun udpFlowClosesAfterTheIdleBound() {
        UdpEcho().use { echo ->
            Harness(
                udpIdleTimeout = Duration.ofMillis(200),
                housekeepingInterval = Duration.ofMillis(50),
            ).use { harness ->
                harness.connect().use { client ->
                    negotiate(client)
                    write(client, ipv4Request(COMMAND_UDP, echo.port))
                    assertEquals(0, readReply(client.getInputStream()))
                    Thread.sleep(700)
                    assertEndOfStream(client)
                }
            }
        }
    }

    @Test
    fun halfClosedFlowClosesAfterTheIdleBound() {
        HalfClosedEcho().use { echo ->
            Harness(
                udpIdleTimeout = Duration.ofMillis(200),
                housekeepingInterval = Duration.ofMillis(50),
            ).use { harness ->
                harness.connect().use { client ->
                    negotiate(client)
                    write(client, ipv4Request(COMMAND_CONNECT, echo.port))
                    assertEquals(0, readReply(client.getInputStream()))
                    client.shutdownOutput()
                    assertEndOfStream(client)
                }
            }
        }
    }

    @Test
    fun totalCapacityClosesAStaleHandshakeAndAccepts() {
        TcpEcho().use { echo ->
            Harness(
                maximumRelays = 1,
                setupReserve = 1,
                handshakeTimeout = Duration.ofMillis(150),
                housekeepingInterval = Duration.ofSeconds(60),
            ).use { harness ->
                val first = harness.connect()
                try {
                    Thread.sleep(400)
                    harness.connect().use { second ->
                        negotiate(second)
                        assertEndOfStream(first)
                        write(second, ipv4Request(COMMAND_CONNECT, echo.port))
                        assertEquals(0, readReply(second.getInputStream()))
                        write(second, "ok".toByteArray())
                        assertArrayEquals(
                            "ok".toByteArray(),
                            readExactly(second.getInputStream(), 2),
                        )
                    }
                } finally {
                    first.close()
                }
            }
        }
    }

    @Test
    fun theRelayLimitFollowsTheFileLimit() {
        val limits = SourceSocksCapacity.limitsForFileLimit(1_024)
        Harness(maximumRelays = limits.relay, setupReserve = limits.setupReserve).use { harness ->
            assertEquals(97, harness.server.relayLimit)
            assertEquals(110, harness.server.totalSessionLimit)
            assertEquals(209, harness.server.workerLimit)
        }
    }

    @Test
    fun theWorkerLimitCoversEveryDocumentedSessionAndRelay() {
        Harness().use { harness ->
            assertEquals(288, harness.server.totalSessionLimit)
            assertEquals(546, harness.server.workerLimit)
        }
    }

    @Test
    fun aSessionWorkerStartFailureStopsTheServerClosed() {
        Harness(workerThreadFactory = FailingThreadFactory(failAt = 1)).use { harness ->
            harness.connect().use { client ->
                assertEndOfStream(client)
            }
            assertTrue(
                "A server that cannot start a session worker must report stopped.",
                waitFor(2_000) { !harness.server.isRunning },
            )
            assertEquals("worker_start", harness.server.failureReason)
            assertTrue(
                "A failed worker start must clear the token copy.",
                waitFor(2_000) { harness.server.tokenCopyIsCleared() },
            )
            assertThrows(IOException::class.java) {
                Socket().use {
                    it.connect(InetSocketAddress(LOOPBACK, harness.port), 1_000)
                }
            }
        }
    }

    @Test
    fun aRelayPumpStartFailureReportsCodeOneAndStopsTheServerClosed() {
        TcpEcho().use { echo ->
            Harness(workerThreadFactory = FailingThreadFactory(failAt = 2)).use { harness ->
                harness.connect().use { client ->
                    negotiate(client)
                    write(client, ipv4Request(COMMAND_CONNECT, echo.port))
                    assertEquals(
                        "A relay must not report success when its pump cannot start.",
                        1,
                        readReply(client.getInputStream()),
                    )
                    assertEndOfStream(client)
                }
                assertTrue(
                    "A server that cannot start a relay pump must report stopped.",
                    waitFor(2_000) { !harness.server.isRunning },
                )
                assertEquals("worker_start", harness.server.failureReason)
                assertTrue(waitFor(2_000) { harness.server.tokenCopyIsCleared() })
            }
        }
    }

    @Test
    fun ipv6UdpAssociateRoundTrip() {
        val echo = try {
            UdpEcho(LOOPBACK6)
        } catch (_: IOException) {
            assumeTrue("IPv6 loopback is not available.", false)
            return
        }
        echo.use {
            Harness().use { harness ->
                harness.connect().use { client ->
                    negotiate(client)
                    write(client, ipv6Request(echo.port, LOOPBACK6, COMMAND_UDP))
                    assertEquals(0, readReply(client.getInputStream()))
                    write(client, frame("v6-udp"))
                    assertArrayEquals("v6-udp".toByteArray(), readFrame(client.getInputStream()))
                }
            }
        }
    }

    @Test
    fun ipv6DomainResolvesOnTheInjectedResolver() {
        val listener = try {
            ServerSocket(0, 1, LOOPBACK6)
        } catch (_: IOException) {
            assumeTrue("IPv6 loopback is not available.", false)
            return
        }
        TcpEcho(listener).use { echo ->
            val resolver = FakeResolver { host ->
                if (host == "v6-source.test.invalid") listOf(LOOPBACK6) else emptyList()
            }
            Harness(resolver = resolver).use { harness ->
                harness.connect().use { client ->
                    negotiate(client)
                    write(client, domainRequest(echo.port, "v6-source.test.invalid"))
                    assertEquals(0, readReply(client.getInputStream()))
                    write(client, "v6d".toByteArray())
                    assertArrayEquals("v6d".toByteArray(), readExactly(client.getInputStream(), 3))
                }
            }
        }
    }

    @Test
    fun shapeModeReframesTheFirstClientHelloAndKeepsEveryByte() {
        val message = clientHello(300)
        val tail = "later bytes".toByteArray(StandardCharsets.US_ASCII)
        ClientHelloSink(message.size).use { sink ->
            Harness(tlsShape = true).use { harness ->
                harness.connect().use { client ->
                    negotiate(client)
                    write(client, ipv4Request(COMMAND_CONNECT, sink.port))
                    assertEquals(0, readReply(client.getInputStream()))
                    client.getOutputStream().write(record(message) + tail)
                    client.getOutputStream().flush()
                    client.shutdownOutput()
                    assertArrayEquals(
                        "response".toByteArray(StandardCharsets.US_ASCII),
                        readExactly(client.getInputStream(), 8),
                    )
                    assertTrue("the destination finished", sink.await(3_000))
                    sink.failure?.let { fail(it) }
                    assertArrayEquals("handshake bytes are identical", message, sink.payload)
                    assertArrayEquals("later bytes are unchanged", tail, sink.tail)
                    assertTrue("the ClientHello spans many records", sink.records > 1)
                    assertTrue(
                        "no shaped record payload is larger than 8",
                        sink.largest in 1..8,
                    )
                }
            }
        }
    }

    @Test
    fun shapeOffKeepsTheSourceDeviceStreamByteForByte() {
        val message = clientHello(120)
        val tail = "tail".toByteArray(StandardCharsets.US_ASCII)
        ClientHelloSink(message.size).use { sink ->
            Harness(tlsShape = false).use { harness ->
                harness.connect().use { client ->
                    negotiate(client)
                    write(client, ipv4Request(COMMAND_CONNECT, sink.port))
                    assertEquals(0, readReply(client.getInputStream()))
                    client.getOutputStream().write(record(message) + tail)
                    client.getOutputStream().flush()
                    client.shutdownOutput()
                    assertArrayEquals(
                        "response".toByteArray(StandardCharsets.US_ASCII),
                        readExactly(client.getInputStream(), 8),
                    )
                    assertTrue("the destination finished", sink.await(3_000))
                    sink.failure?.let { fail(it) }
                    assertArrayEquals(message, sink.payload)
                    assertArrayEquals(tail, sink.tail)
                    assertEquals("shape off keeps one record", 1, sink.records)
                    assertEquals(message.size, sink.largest)
                }
            }
        }
    }

    @Test
    fun anAcceptErrorStopsTheServerAndClosesTheSession() {
        val gate = CountDownLatch(1)
        Harness(listenerFactory = { AcceptErrorServerSocket(gate) }).use { harness ->
            harness.connect().use { client ->
                negotiate(client)
                gate.countDown()
                assertTrue(
                    "An accept error must stop the server closed.",
                    waitFor(2_000) { harness.server.failureReason == "accept" },
                )
                assertFalse(harness.server.isRunning)
                val health = harness.server.health()
                assertFalse(health.running)
                assertEquals("accept", health.failureReason)
                assertTrue(health.degraded)
                assertEndOfStream(client)
                assertTrue(waitFor(2_000) { harness.server.tokenCopyIsCleared() })
                harness.server.stop()
                try {
                    harness.server.start()
                    fail("A server that failed in accept must not restart.")
                } catch (_: IllegalStateException) {
                    // Expected.
                }
            }
        }
    }

    @Test
    fun aConcurrentStopWaitsForTheActiveStopWithinItsBound() {
        val closeStarted = CountDownLatch(1)
        val releaseClose = CountDownLatch(1)
        Harness(
            listenerFactory = { SlowCloseServerSocket(closeStarted, releaseClose) },
            stopWaitTimeout = Duration.ofMillis(200),
        ).use { harness ->
            val owner = Thread({ harness.server.stop() }, "test-stop-owner").apply {
                isDaemon = true
                start()
            }
            try {
                assertTrue("The owner stop must begin closing.", closeStarted.await(2, TimeUnit.SECONDS))
                val waiterDone = CountDownLatch(1)
                var waiterIncomplete = false
                val waiter = Thread({
                    harness.server.stop()
                    waiterIncomplete = harness.server.stopWasIncomplete
                    waiterDone.countDown()
                }, "test-stop-waiter").apply {
                    isDaemon = true
                    start()
                }
                assertTrue(
                    "A concurrent stop must return within its bound.",
                    waiterDone.await(2, TimeUnit.SECONDS),
                )
                assertTrue("The waiter must report the bounded return.", waiterIncomplete)
                assertFalse("Cleanup must still be in progress.", harness.server.stopFinished)
                assertFalse("The waiter thread must have finished.", waiter.isAlive)
                assertTrue("The owner must still be cleaning up.", owner.isAlive)
            } finally {
                releaseClose.countDown()
            }
            owner.join(5_000)
            assertFalse("The owner stop must finish after the release.", owner.isAlive)
            assertTrue("The stop must report completion.", harness.server.stopFinished)
        }
    }

    @Test
    fun aTransientWorkerRejectionRefusesTheFlowAndKeepsTheServerServing() {
        TcpEcho().use { echo ->
            var executor: RejectingExecutor? = null
            Harness(workerExecutorFactory = { limit, factory ->
                RejectingExecutor(limit, factory).also { executor = it }
            }).use { harness ->
                harness.connect().use { first ->
                    negotiate(first)
                    write(first, ipv4Request(COMMAND_CONNECT, echo.port))
                    assertEquals(0, readReply(first.getInputStream()))
                    executor!!.reject(3)
                    harness.connect().use { second ->
                        assertEndOfStream(second)
                    }
                    assertTrue("A capacity refusal must not stop the server.", harness.server.isRunning)
                    assertNull(harness.server.failureReason)
                    write(first, "still".toByteArray())
                    assertArrayEquals(
                        "still".toByteArray(),
                        readExactly(first.getInputStream(), 5),
                    )
                }
                executor!!.reject(0)
                harness.connect().use { third ->
                    negotiate(third)
                    write(third, ipv4Request(COMMAND_CONNECT, echo.port))
                    assertEquals(0, readReply(third.getInputStream()))
                }
            }
        }
    }

    @Test
    fun aTransientPumpRejectionReportsCodeOneAndKeepsTheServerServing() {
        TcpEcho().use { echo ->
            var executor: RejectingExecutor? = null
            Harness(workerExecutorFactory = { limit, factory ->
                RejectingExecutor(limit, factory).also { executor = it }
            }).use { harness ->
                harness.connect().use { client ->
                    negotiate(client)
                    executor!!.reject(3)
                    write(client, ipv4Request(COMMAND_CONNECT, echo.port))
                    assertEquals(1, readReply(client.getInputStream()))
                    assertEndOfStream(client)
                }
                assertTrue("A capacity refusal must not stop the server.", harness.server.isRunning)
                assertNull(harness.server.failureReason)
                executor!!.reject(0)
                harness.connect().use { next ->
                    negotiate(next)
                    write(next, ipv4Request(COMMAND_CONNECT, echo.port))
                    assertEquals(0, readReply(next.getInputStream()))
                }
            }
        }
    }

    @Test
    fun aWorkerThreadCreationFailureStopsTheServerClosed() {
        Harness(workerThreadFactory = ThrowingThreadFactory()).use { harness ->
            harness.connect().use { client ->
                assertEndOfStream(client)
            }
            assertTrue(
                "A real thread creation failure must stop the server.",
                waitFor(2_000) { harness.server.failureReason == "worker_start" },
            )
            assertFalse(harness.server.isRunning)
            assertTrue(waitFor(2_000) { harness.server.tokenCopyIsCleared() })
        }
    }

    @Test
    fun theServerRejectsLimitsAboveTheDeclaredCaps() {
        val cellular = CellularSession(CellularSockets(FakeBinding()))
        try {
            assertThrows(IllegalArgumentException::class.java) {
                SourceSocksServer(
                    cellular = cellular,
                    resolver = FakeResolver(),
                    bindAddress = LOOPBACK,
                    token = TOKEN,
                    maximumRelays = SourceSocksServer.MAXIMUM_RELAYS + 1,
                )
            }
            assertThrows(IllegalArgumentException::class.java) {
                SourceSocksServer(
                    cellular = cellular,
                    resolver = FakeResolver(),
                    bindAddress = LOOPBACK,
                    token = TOKEN,
                    setupReserve = SourceSocksServer.SETUP_RESERVE + 1,
                )
            }
            assertThrows(IllegalArgumentException::class.java) {
                SourceSocksServer(
                    cellular = cellular,
                    resolver = FakeResolver(),
                    bindAddress = LOOPBACK,
                    token = TOKEN,
                    resolverLimit = 0,
                )
            }
            val largest = SourceSocksServer(
                cellular = cellular,
                resolver = FakeResolver(),
                bindAddress = LOOPBACK,
                token = TOKEN,
                maximumRelays = SourceSocksServer.MAXIMUM_RELAYS,
                setupReserve = SourceSocksServer.SETUP_RESERVE,
            )
            assertEquals(SourceSocksServer.MAXIMUM_SESSIONS, largest.totalSessionLimit)
            largest.stop()
        } finally {
            cellular.close()
        }
    }

    @Test
    fun theResolverQueueIsBoundedAndRefusesOverflow() {
        val resolver = HoldingResolver()
        Harness(
            resolver = resolver,
            maximumRelays = 4,
            setupReserve = 4,
            resolverLimit = 2,
            connectTimeout = Duration.ofSeconds(20),
        ).use { harness ->
            val clients = mutableListOf<Socket>()
            try {
                repeat(4) { index ->
                    val client = harness.connect()
                    clients += client
                    negotiate(client)
                    write(client, domainRequest(9, "hold-$index.test.invalid"))
                    assertTrue(
                        "Lookup $index must reach the resolver pool.",
                        waitFor(2_000) {
                            harness.server.resolverStatus().outstanding == index + 1
                        },
                    )
                }
                assertTrue(
                    "Two lookups run and two wait in the bounded queue.",
                    waitFor(2_000) {
                        val status = harness.server.resolverStatus()
                        status.active == 2 && status.queued == 2
                    },
                )
                val overflow = harness.connect()
                clients += overflow
                negotiate(overflow)
                write(overflow, domainRequest(9, "overflow.test.invalid"))
                assertEquals(1, readReply(overflow.getInputStream()))
                assertEndOfStream(overflow)
                assertTrue(harness.server.isRunning)
                assertNull(harness.server.failureReason)
                val status = harness.server.resolverStatus()
                assertEquals(2, status.threads)
                assertEquals(2, status.queueLimit)
                assertEquals(1L, status.rejections)
            } finally {
                resolver.releaseAll()
                clients.forEach { client ->
                    try {
                        client.close()
                    } catch (_: IOException) {
                        // Already closed.
                    }
                }
            }
        }
    }

    @Test
    fun anAbandonedLookupReportsTheRecoveryLimit() {
        val resolver = HoldingResolver()
        Harness(
            resolver = resolver,
            maximumRelays = 1,
            setupReserve = 1,
            resolverLimit = 1,
            connectTimeout = Duration.ofMillis(250),
        ).use { harness ->
            harness.connect().use { client ->
                negotiate(client)
                write(client, domainRequest(9, "stuck.test.invalid"))
                assertEquals(1, readReply(client.getInputStream()))
                assertEndOfStream(client)
            }
            assertTrue(
                "A lookup past its deadline must be reported as abandoned.",
                waitFor(2_000) { harness.server.resolverStatus().abandoned == 1 },
            )
            assertTrue(
                "A stuck resolver must report the recovery limit.",
                harness.server.resolverStatus().exhausted,
            )
            assertTrue(harness.server.health().degraded)
            assertTrue(harness.server.isRunning)
            assertNull(harness.server.failureReason)
            resolver.releaseAll()
            assertTrue(
                "A resolver that returns must release the abandoned count.",
                waitFor(2_000) { harness.server.resolverStatus().abandoned == 0 },
            )
            assertFalse(harness.server.resolverStatus().exhausted)
            assertFalse(harness.server.health().degraded)
        }
    }

    @Test
    fun oneShotEchoTrickleClosesAtTheAbsoluteDeadline() {
        val echo = FakeEcho()
        Harness(echo = echo, echoRequestTimeout = Duration.ofMillis(300)).use { harness ->
            harness.connect().use { client ->
                negotiate(client)
                write(client, echoRequest(COMMAND_ECHO, byteArrayOf(1, 1, 1, 1)))
                assertEquals(0, readReply(client.getInputStream()))
                val output = client.getOutputStream()
                try {
                    output.write(byteArrayOf(0, 8))
                    output.flush()
                    repeat(8) {
                        Thread.sleep(80)
                        output.write(0x41)
                        output.flush()
                    }
                } catch (_: IOException) {
                    // The server can close while the trickle is still running.
                }
                assertEndOfStream(client)
                assertTrue(
                    "A trickle must not complete the one-shot echo request.",
                    echo.received.isEmpty(),
                )
            }
        }
    }

    @Test
    fun anEvictedBlockedRelayReleasesItsWorkerPermit() {
        val firehose = FirehoseServer()
        val fake = FakeClientSocket()
        val listener = ScriptedAcceptServerSocket(fake)
        try {
            Harness(
                listenerFactory = { listener },
                maximumRelays = 1,
                setupReserve = 0,
                workerLimitOverride = 2,
                udpIdleTimeout = Duration.ofMillis(100),
                housekeepingInterval = Duration.ofSeconds(60),
            ).use { harness ->
                fake.offer(greetingAndAuth(TOKEN))
                fake.offer(ipv4Request(COMMAND_CONNECT, firehose.port))
                assertTrue(
                    "The scripted session must reach its success reply.",
                    waitFor(3_000) { fake.responseBytes().size >= 14 },
                )
                val reply = fake.responseBytes()
                assertEquals(5, reply[4].toInt())
                assertEquals(0, reply[5].toInt())
                fake.blockWrites()
                fake.endInput()
                assertTrue(
                    "The relay must block in a client write.",
                    fake.writeBlocked.await(3, TimeUnit.SECONDS),
                )
                // The half-closed phase passes its idle bound. Housekeeping
                // is long, so the eviction comes from the next admit.
                Thread.sleep(700)
                harness.connect().use { second ->
                    // The second connection evicts the stale session before
                    // it can be served. Closing it releases any permit it
                    // obtained.
                    second.close()
                }
                assertTrue(
                    "The eviction must abort the blocked client write.",
                    waitFor(2_000) { fake.outputAborted },
                )
                assertTrue(
                    "An evicted blocked write must release its worker permit.",
                    waitFor(3_000) { harness.server.availableWorkers == 2 },
                )
                harness.connect().use { third ->
                    negotiate(third)
                    write(third, ipv4Request(COMMAND_CONNECT, firehose.port))
                    assertEquals(0, readReply(third.getInputStream()))
                }
                assertTrue(harness.server.isRunning)
                assertNull(harness.server.failureReason)
            }
        } finally {
            fake.forceAbort()
            fake.endInput()
            listener.close()
            firehose.close()
        }
    }

    private fun greetingAndAuth(token: String): ByteArray =
        byteArrayOf(5, 1, 2) + authBytes(token)

    private fun clientHello(bodyLength: Int): ByteArray {
        val message = ByteArray(4 + bodyLength)
        message[0] = 1
        message[1] = ((bodyLength ushr 16) and 0xFF).toByte()
        message[2] = ((bodyLength ushr 8) and 0xFF).toByte()
        message[3] = (bodyLength and 0xFF).toByte()
        for (index in 0 until bodyLength) {
            message[4 + index] = (index % 251).toByte()
        }
        return message
    }

    private fun record(payload: ByteArray, versionMinor: Int = 1): ByteArray {
        val out = ByteArray(5 + payload.size)
        out[0] = 22
        out[1] = 3
        out[2] = versionMinor.toByte()
        out[3] = ((payload.size ushr 8) and 0xFF).toByte()
        out[4] = (payload.size and 0xFF).toByte()
        System.arraycopy(payload, 0, out, 5, payload.size)
        return out
    }

    private fun waitFor(timeoutMillis: Long, condition: () -> Boolean): Boolean {
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
        while (System.nanoTime() < deadline) {
            if (condition()) return true
            Thread.sleep(20)
        }
        return condition()
    }

    private fun negotiate(client: Socket, token: String = TOKEN) {
        val input = client.getInputStream()
        val output = client.getOutputStream()
        output.write(byteArrayOf(5, 1, 2))
        output.flush()
        assertArrayEquals(byteArrayOf(5, 2), readExactly(input, 2))
        output.write(authBytes(token))
        output.flush()
        assertArrayEquals(byteArrayOf(1, 0), readExactly(input, 2))
    }

    private fun authBytes(token: String): ByteArray {
        val user = "hotspotshade".toByteArray(StandardCharsets.US_ASCII)
        val secret = token.toByteArray(StandardCharsets.UTF_8)
        return byteArrayOf(
            1,
            user.size.toByte(),
            *user,
            secret.size.toByte(),
            *secret,
        )
    }

    private fun ipv4Request(command: Int, port: Int): ByteArray {
        val address = LOOPBACK.address
        return byteArrayOf(
            5,
            command.toByte(),
            0,
            1,
            address[0],
            address[1],
            address[2],
            address[3],
            (port ushr 8).toByte(),
            port.toByte(),
        )
    }

    private fun ipv6Request(
        port: Int,
        address: InetAddress,
        command: Int = COMMAND_CONNECT,
    ): ByteArray {
        val bytes = address.address
        return byteArrayOf(
            5,
            command.toByte(),
            0,
            4,
            *bytes,
            (port ushr 8).toByte(),
            port.toByte(),
        )
    }

    private fun echoRequest(
        command: Int,
        address: ByteArray,
        port: Int = 0,
        type: Int = 1,
    ): ByteArray = byteArrayOf(
        5,
        command.toByte(),
        0,
        type.toByte(),
        *address,
        (port ushr 8).toByte(),
        port.toByte(),
    )

    private fun domainRequest(port: Int, host: String): ByteArray {
        val name = host.toByteArray(StandardCharsets.UTF_8)
        return byteArrayOf(
            5,
            COMMAND_CONNECT.toByte(),
            0,
            3,
            name.size.toByte(),
            *name,
            (port ushr 8).toByte(),
            port.toByte(),
        )
    }

    private fun frame(payload: String): ByteArray {
        val bytes = payload.toByteArray(StandardCharsets.UTF_8)
        return byteArrayOf(
            (bytes.size ushr 8).toByte(),
            bytes.size.toByte(),
            *bytes,
        )
    }

    @Test
    fun aFailedStartClearsTheTokenCopy() {
        val occupied = ServerSocket(0, 1, LOOPBACK)
        try {
            val server = SourceSocksServer(
                cellular = CellularSession(CellularSockets(FakeBinding())),
                resolver = FakeResolver(),
                bindAddress = LOOPBACK,
                token = TOKEN,
                port = occupied.localPort,
            )

            assertThrows(IOException::class.java) { server.start() }

            assertTrue(
                "A failed bind must clear the in-memory token copy.",
                server.tokenCopyIsCleared(),
            )
            // A later stop must stay idempotent and keep the copy clear.
            server.stop()
            assertTrue(server.tokenCopyIsCleared())
        } finally {
            occupied.close()
        }
    }

    private fun write(client: Socket, bytes: ByteArray) {
        val output = client.getOutputStream()
        output.write(bytes)
        output.flush()
    }

    private fun writeSlowly(output: OutputStream, bytes: ByteArray) {
        for (byte in bytes) {
            output.write(byte.toInt())
            output.flush()
            Thread.sleep(2)
        }
    }

    private fun readReply(input: InputStream): Int {
        val reply = readExactly(input, 10)
        assertEquals(5, reply[0].toInt())
        assertEquals(0, reply[2].toInt())
        assertEquals(1, reply[3].toInt())
        for (index in 4..9) {
            assertEquals(0, reply[index].toInt())
        }
        return reply[1].toInt() and 0xFF
    }

    private fun readFrame(input: InputStream): ByteArray {
        val header = readExactly(input, 2)
        val length = ((header[0].toInt() and 0xFF) shl 8) or (header[1].toInt() and 0xFF)
        return readExactly(input, length)
    }

    private fun readEchoResponse(input: InputStream): Pair<Int, ByteArray> {
        val header = readExactly(input, 3)
        val status = header[0].toInt() and 0xFF
        val length = ((header[1].toInt() and 0xFF) shl 8) or (header[2].toInt() and 0xFF)
        return status to readExactly(input, length)
    }

    private fun readExactly(input: InputStream, count: Int): ByteArray {
        val bytes = ByteArray(count)
        var offset = 0
        while (offset < count) {
            val read = input.read(bytes, offset, count - offset)
            if (read < 0) throw EOFException()
            offset += read
        }
        return bytes
    }

    private fun assertEndOfStream(client: Socket) {
        try {
            assertEquals(-1, client.getInputStream().read())
        } catch (_: SocketException) {
            // A reset is also a closed session.
        }
    }
}
