package com.hotspotshade.source

import java.io.Closeable
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
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
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
