package com.hotspotshade.source.pairing

import java.net.Inet4Address
import java.net.InetAddress
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Fixed public parity vectors. `rust/src/pairing.rs`,
 * `rust/src/source_pairing.rs`, and `ios/tests/PairingTests.swift` hold the
 * same values. Change all three suites together.
 */
class PairingProtocolTest {
    private val lSPrivate = ByteArray(32) { 0x11 }
    private val lEPrivate = ByteArray(32) { 0x22 }
    private val pEPrivate = ByteArray(32) { 0x33 }
    private val nonce = ByteArray(12) { 0x44 }
    private val token = "test-token-0123456789abcdef"
    private val host = InetAddress.getByName("172.20.10.1") as Inet4Address
    private val lS = X25519.publicKey(lSPrivate)!!
    private val lE = X25519.publicKey(lEPrivate)!!
    private val pE = X25519.publicKey(pEPrivate)!!
    private val commit = PairingProtocol.commitment(lE, lS)
    private val keys: PairingKeys

    init {
        val ee = X25519.agree(pEPrivate, lE)!!
        val es = X25519.agree(pEPrivate, lS)!!
        keys = PairingProtocol.deriveKeys(ee, es, PairingProtocol.transcriptHash(lS, lE, pE))
        ee.fill(0)
        es.fill(0)
    }

    @Test
    fun parityKeyScheduleMatchesTheTargetAndSwiftSuites() {
        assertEquals("7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13", hex(lS))
        assertEquals("0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20", hex(lE))
        assertEquals("7b0d47d93427f8311160781c7c733fd89f88970aef490d8aa0ee19a4cb8a1b14", hex(pE))
        assertEquals(
            "c7bf4d2e3388ea312b7750dbcfc430402b2c6b1e457fe2ee1ffeae09a4fd3aeb",
            hex(commit),
        )
        assertEquals(
            "1fdc192faa0212a9aae7bb4f41b580227fd5ad3e5d777faae230dfe973f3e805",
            hex(X25519.agree(pEPrivate, lE)!!),
        )
        assertEquals(
            "5bf22caf31c0316785b0b9bc60e56d48582ce59435ce5b3c028052be42631e0f",
            hex(X25519.agree(pEPrivate, lS)!!),
        )
        assertEquals(
            "51e50f017883e3dde1ea99a473a142dfd758835adfdc933f706b3d2e9752b1b7",
            hex(keys.h),
        )
        assertEquals(
            "d15b719f5c092e967be6a0a355bb972014e6245ff4d7ea9a53434878b8358b78",
            hex(keys.kEnc),
        )
        assertEquals(
            "09089c6978faac4cc8f0ae44767a3fd8789346826ef99366d2f8c13e09ece263",
            hex(keys.kProof),
        )
        assertEquals("e961ca48", hex(keys.sas))
        assertEquals("500104", PairingProtocol.sasCode(keys.sas))
        assertEquals("500 104", PairingProtocol.formatCode("500104"))
        assertEquals(
            "7554e349e225b68c5c2310ce69bf08c44f6aac2c73ac5a11e75a8142c1f7f97a",
            hex(PairingProtocol.laptopProof(keys)),
        )
        assertTrue(PairingProtocol.verifyProof(keys, PairingProtocol.laptopProof(keys)))
        val proof = PairingProtocol.laptopProof(keys)
        proof[0] = (proof[0].toInt() xor 1).toByte()
        assertFalse(PairingProtocol.verifyProof(keys, proof))
    }

    @Test
    fun credentialCiphertextMatchesTheVectors() {
        val credentials = PairingCredentials.create(host, 1080, token)!!
        val ciphertext = PairingProtocol.sealCredentials(keys, nonce, credentials)
        assertEquals(
            "132a89d1add706e92d7844032a37f2486c9f386e21255687facf153edc23e7dced55371101721d50afaa326d1fb62e2c" +
                "270f1501bb51d043e9c8",
            hex(ciphertext),
        )
        val opened = PairingProtocol.openCredentials(keys, nonce, ciphertext)
        assertEquals(credentials, opened)
        assertEquals(host, opened.host)
        assertEquals(1080, opened.port)
        assertEquals(token, opened.token)
    }

    @Test
    fun helloForgetAndStatusVectorsMatchSwift() {
        val hello = PairingProtocol.encodeHello(lS, commit) + byteArrayOf(1)
        assertEquals("0101" + hex(lS) + hex(commit) + "01", hex(hello))

        val forget = byteArrayOf(PairingProtocol.MSG_FORGET.toByte()) + nonce +
            PairingProtocol.sealMessage(keys, nonce, ByteArray(0))
        assertEquals(
            "07444444444444444444444444db466ed9c760a7484fa50848950711f7",
            hex(forget),
        )

        val request = ByteArray(17) { 0x55 }
        request[16] = 0
        val sealedRequest = PairingProtocol.sealMessage(keys, nonce, request)
        assertEquals(
            "4247c7f09df127910c427a33114f972c5e2ad0449eded52ee1f8b60f3162ba126f",
            hex(sealedRequest),
        )

        val response = PairingProtocol.encodeStatus(
            ProxyStatus(
                proxyRunning = true,
                foreground = true,
                connections = 2,
                port = 1080,
                host = host,
                sequence = 1,
            ),
            ByteArray(16) { 0x55 },
        )
        val sealedResponse = PairingProtocol.sealMessage(keys, ByteArray(12) { 0x66 }, response)
        assertEquals(
            "85c1d284f91bc6a6749ad370bf6c6abe5f8d0a580845185b4292fe2e89545d589039f667f42eadf73ae2df6c3949ce" +
                "678dffda5da446",
            hex(sealedResponse),
        )
        val opened = PairingProtocol.openMessage(keys, ByteArray(12) { 0x66 }, sealedResponse)!!
        assertArrayEquals(response, opened)
    }

    @Test
    fun sasCodePadsAndWraps() {
        assertEquals("000007", PairingProtocol.sasCode(byteArrayOf(0, 0, 0, 7)))
        assertEquals("967295", PairingProtocol.sasCode(byteArrayOf(-1, -1, -1, -1)))
        assertEquals("500104", PairingProtocol.sasCode(PairingProtocol.unhex("e961ca48")))
    }

    @Test
    fun credentialsRejectUnsafeValuesAndRedactTheToken() {
        assertNull(PairingCredentials.create(host, 0, token))
        assertNull(PairingCredentials.create(host, 1023, token))
        assertNull(PairingCredentials.create(host, PairingProtocol.PAIRING_PORT, token))
        assertNull(PairingCredentials.create(host, 65536, token))
        assertNull(PairingCredentials.create(host, 1080, ""))
        assertNull(PairingCredentials.create(host, 1080, "bad token"))
        assertNull(PairingCredentials.create(host, 1080, "a".repeat(256)))
        assertNull(
            PairingCredentials.create(
                InetAddress.getByName("0.0.0.0") as Inet4Address,
                1080,
                token,
            ),
        )
        assertNull(
            PairingCredentials.create(
                InetAddress.getByName("239.1.1.1") as Inet4Address,
                1080,
                token,
            ),
        )
        val credentials = PairingCredentials.create(host, 1080, token)!!
        assertFalse(credentials.toString().contains(token))
        assertTrue(credentials.toString().contains("[redacted]"))
        assertFalse(keys.toString().contains(hex(keys.kEnc)))
        assertTrue(keys.toString().contains("[redacted]"))
    }

    @Test
    fun credentialsDecodeRejectsBadLengths() {
        val credentials = PairingCredentials.create(host, 1080, token)!!
        val encoded = PairingProtocol.encodeCredentials(credentials)
        assertEquals(credentials, PairingProtocol.decodeCredentials(encoded))
        assertThrows(PairingException::class.java) {
            PairingProtocol.decodeCredentials(encoded.copyOf(encoded.size - 1))
        }
        assertThrows(PairingException::class.java) {
            PairingProtocol.decodeCredentials(ByteArray(2))
        }
        val badToken = encoded.copyOf()
        badToken[3] = 0x20
        assertThrows(PairingException::class.java) {
            PairingProtocol.decodeCredentials(badToken)
        }
    }

    @Test
    fun decodeHelloRejectsBadFlagsAndShapes() {
        PairingProtocol.decodeHello(PairingProtocol.encodeHello(lS, commit))!!
        val withFlags = PairingProtocol.encodeHello(lS, commit) + byteArrayOf(3)
        PairingProtocol.decodeHello(withFlags)!!
        assertNull(PairingProtocol.decodeHello(withFlags + byteArrayOf(0)))
        val badFlag = PairingProtocol.encodeHello(lS, commit) + byteArrayOf(4)
        assertNull(PairingProtocol.decodeHello(badFlag))
        val badVersion = PairingProtocol.encodeHello(lS, commit).also { it[1] = 2 }
        assertNull(PairingProtocol.decodeHello(badVersion))
        assertNull(PairingProtocol.decodeHello(ByteArray(10)))
    }

    @Test
    fun frameReaderIsBounded() {
        val reader = PairingFrameReader()
        val payload = ByteArray(PairingProtocol.MAX_FRAME) { 0x42 }
        val frame = PairingProtocol.frame(payload)
        reader.push(frame.copyOfRange(0, 3))
        assertNull(reader.nextFrame())
        reader.push(frame.copyOfRange(3, frame.size))
        assertArrayEquals(payload, reader.nextFrame()!!)
        assertEquals(0, reader.bufferedLength())

        val zero = PairingFrameReader()
        zero.push(byteArrayOf(0, 0))
        assertThrows(PairingException::class.java) { zero.nextFrame() }

        val oversized = PairingFrameReader()
        oversized.push(byteArrayOf(0x02, 0x01))
        assertThrows(PairingException::class.java) { oversized.nextFrame() }

        val bounded = PairingFrameReader()
        assertThrows(PairingException::class.java) {
            bounded.push(ByteArray(PairingProtocol.MAX_BUFFERED + 1))
        }
    }

    @Test
    fun peerTextIsCanonicalAndRejectsPortsAndZones() {
        assertEquals("2001:db8::1", PeerAddress.canonical("2001:0db8:0000:0000:0000:0000:0000:0001"))
        assertEquals("2001:db8::1", PeerAddress.canonical("2001:db8::1"))
        assertEquals("192.0.2.1", PeerAddress.canonical("::ffff:192.0.2.1"))
        assertEquals("192.0.2.1", PeerAddress.canonical("::ffff:c000:201"))
        assertEquals("peer-a", PeerAddress.canonical("peer-a"))
        assertThrows(PairingException::class.java) {
            PeerAddress.canonical("192.0.2.1:443")
        }
        assertThrows(PairingException::class.java) {
            PeerAddress.canonical("[2001:db8::1]:443")
        }
        assertThrows(PairingException::class.java) {
            PeerAddress.canonical("fe80::1%en0")
        }
        assertThrows(PairingException::class.java) { PeerAddress.canonical("") }
        assertThrows(PairingException::class.java) { PeerAddress.canonical("peer\n") }
        assertThrows(PairingException::class.java) {
            PeerAddress.canonical("a".repeat(65))
        }
        assertEquals("::", PeerAddress.formatIpv6(ByteArray(16)))
        assertEquals("::1", PeerAddress.formatIpv6(PairingProtocol.unhex("00000000000000000000000000000001")))
        assertEquals(
            "2001:db8::1",
            PeerAddress.formatIpv6(PairingProtocol.unhex("20010db8000000000000000000000001")),
        )
    }

    private fun hex(bytes: ByteArray): String = PairingProtocol.hex(bytes)
}
