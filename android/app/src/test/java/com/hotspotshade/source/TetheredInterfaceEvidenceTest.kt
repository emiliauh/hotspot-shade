package com.hotspotshade.source

import java.net.InetAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests for the API 36 tethering evidence and its finder integration.
 *
 * These are JVM tests with fake registrations and fake interfaces. They do not
 * load `TetheringManager`, touch a device, or prove that a real phone delivers
 * the callback. A real phone and several vendor ROMs are still required.
 */
class TetheredInterfaceEvidenceTest {
    private class FakeRegistration(
        var result: Boolean = true,
    ) : TetheredInterfaceRegistration {
        private var listener: ((TetheredInterfaceReading?) -> Unit)? = null
        var registerCalls = 0
        var unregisterCalls = 0
        var onRegister: (() -> Unit)? = null

        override fun register(listener: (TetheredInterfaceReading?) -> Unit): Boolean {
            registerCalls += 1
            this.listener = listener
            onRegister?.invoke()
            return result
        }

        override fun unregister() {
            unregisterCalls += 1
        }

        fun emit(reading: TetheredInterfaceReading?) {
            listener?.invoke(reading)
        }

        fun emitNames(vararg names: String) {
            emit(readingOf(*names))
        }
    }

    private class FakeSource(
        @Volatile var interfaces: List<InterfaceSnapshot>,
    ) : InterfaceSource {
        val readCalls = AtomicInteger()

        override fun read(): List<InterfaceSnapshot> {
            readCalls.incrementAndGet()
            return interfaces
        }
    }

    private class FakeNetwork(
        private val transportsResult: () -> ObservedTransports?,
        private val nameResult: () -> String?,
    ) : ObservedNetwork {
        override fun transports(): ObservedTransports? = transportsResult()

        override fun interfaceName(): String? = nameResult()
    }

    private class FakeObservation(
        private val nameResult: () -> String?,
        private val typeResult: () -> Int?,
    ) : TetheredInterfaceObservation {
        override fun interfaceName(): String? = nameResult()

        override fun type(): Int? = typeResult()
    }

    private val wifiClient = ObservedTransports(isCellular = false, isWifi = true, isVpn = false)
    private val cellular = ObservedTransports(isCellular = true, isWifi = false, isVpn = false)

    private fun snapshot(
        name: String,
        vararg addresses: String,
        up: Boolean = true,
        loopback: Boolean = false,
    ) = InterfaceSnapshot(
        name = name,
        isUp = up,
        isLoopback = loopback,
        addresses = addresses.map { InetAddress.getByName(it) },
    )

    private fun observed(name: String, transports: ObservedTransports) =
        FakeNetwork({ transports }, { name })

    private fun observation(vararg networks: ObservedNetwork): NetworkInterfaceObservation =
        NetworkInterfaceObservationReader { networks.toList() }.read()

    private fun finder(
        source: InterfaceSource,
        evidence: TetheredInterfaceState,
        vararg networks: ObservedNetwork,
    ) = NetworkInterfaceHotspotAddressFinder(
        source,
        { observation(*networks) },
        TetheredInterfaceEvidenceSource { evidence },
    )

    private fun address(value: String) = InetAddress.getByName(value)

    private fun typed(name: String, kind: TetheredInterfaceKind) = name to kind

    private fun tethered(name: String?, type: Int?) =
        FakeObservation({ name }, { type })

    // --- Evidence lifecycle -------------------------------------------------

    @Test
    fun initialStateIsUnavailable() {
        val registration = FakeRegistration()
        val evidence = TetheredInterfaceEvidence(registration)

        assertEquals(TetheredInterfaceState.Unavailable, evidence.snapshot())
    }

    @Test
    fun startRegistersOnceAndWaitsForTheCallback() {
        val registration = FakeRegistration()
        val evidence = TetheredInterfaceEvidence(registration)

        assertTrue(evidence.start())
        assertTrue(evidence.start())
        assertEquals(1, registration.registerCalls)
        assertEquals(TetheredInterfaceState.AwaitingFirstReading, evidence.snapshot())
    }

    @Test
    fun aCompleteReadingBecomesKnownAndKeepsThePlatformTypes() {
        val registration = FakeRegistration()
        val evidence = TetheredInterfaceEvidence(registration)
        evidence.start()

        registration.emit(
            readingOf(
                typed("WLAN1", TetheredInterfaceKind.WIFI),
                typed(" usb0 ", TetheredInterfaceKind.USB),
            ),
        )

        assertEquals(
            TetheredInterfaceState.Known(
                mapOf(
                    "wlan1" to TetheredInterfaceKind.WIFI,
                    "usb0" to TetheredInterfaceKind.USB,
                ),
            ),
            evidence.snapshot(),
        )
    }

    @Test
    fun anEmptyReadingIsKnownAndAuthoritative() {
        val registration = FakeRegistration()
        val evidence = TetheredInterfaceEvidence(registration)
        evidence.start()

        registration.emit(TetheredInterfaceReading(emptyMap()))

        assertEquals(TetheredInterfaceState.Known(emptyMap()), evidence.snapshot())
    }

    @Test
    fun aNullReadingIsUnavailableNotEmpty() {
        val registration = FakeRegistration()
        val evidence = TetheredInterfaceEvidence(registration)
        evidence.start()
        registration.emitNames("ap0")

        registration.emit(null)

        assertEquals(TetheredInterfaceState.Unavailable, evidence.snapshot())
    }

    @Test
    fun aBlankNameMakesTheWholeReadingUnavailable() {
        val registration = FakeRegistration()
        val evidence = TetheredInterfaceEvidence(registration)
        evidence.start()

        registration.emit(
            readingOf(
                typed("ap0", TetheredInterfaceKind.WIFI),
                typed(" ", TetheredInterfaceKind.WIFI),
            ),
        )

        assertEquals(TetheredInterfaceState.Unavailable, evidence.snapshot())
    }

    @Test
    fun aDuplicateNormalizedNameMakesTheWholeReadingUnavailable() {
        val registration = FakeRegistration()
        val evidence = TetheredInterfaceEvidence(registration)
        evidence.start()

        registration.emit(
            readingOf(
                typed("ap0", TetheredInterfaceKind.WIFI),
                typed(" AP0 ", TetheredInterfaceKind.USB),
            ),
        )

        assertEquals(TetheredInterfaceState.Unavailable, evidence.snapshot())
    }

    @Test
    fun aCallbackThatArrivesDuringRegisterIsKept() {
        val registration = FakeRegistration()
        registration.onRegister = { registration.emitNames("ap0") }
        val evidence = TetheredInterfaceEvidence(registration)

        assertTrue(evidence.start())

        assertEquals(TetheredInterfaceState.Known(setOf("ap0")), evidence.snapshot())
    }

    @Test
    fun aFailedRegistrationIsUnavailableAndRejectsLaterEvents() {
        val registration = FakeRegistration(result = false)
        val evidence = TetheredInterfaceEvidence(registration)

        assertFalse(evidence.start())
        assertFalse("A failed registration must not report success later.", evidence.start())
        registration.emitNames("ap0")

        assertEquals(TetheredInterfaceState.Unavailable, evidence.snapshot())
        assertEquals(2, registration.registerCalls)
    }

    @Test
    fun aCallbackDuringAFailedRegistrationIsDiscarded() {
        val registration = FakeRegistration(result = false)
        registration.onRegister = { registration.emitNames("ap0") }
        val evidence = TetheredInterfaceEvidence(registration)

        assertFalse(evidence.start())

        assertEquals(TetheredInterfaceState.Unavailable, evidence.snapshot())
    }

    @Test
    fun aFailedRegistrationCanBeRetried() {
        val registration = FakeRegistration(result = false)
        val evidence = TetheredInterfaceEvidence(registration)

        assertFalse(evidence.start())
        assertEquals(TetheredInterfaceState.Unavailable, evidence.snapshot())

        registration.result = true
        assertTrue(evidence.start())
        assertEquals(TetheredInterfaceState.AwaitingFirstReading, evidence.snapshot())

        registration.emitNames("ap0")
        assertEquals(TetheredInterfaceState.Known(setOf("ap0")), evidence.snapshot())
    }

    @Test
    fun aPendingRegistrationFallsBackAfterTheBoundedWait() {
        val registration = FakeRegistration()
        val now = AtomicLong(0L)
        val evidence = TetheredInterfaceEvidence(
            registration,
            clock = { now.get() },
            pendingTimeoutMillis = 1_000,
        )

        assertTrue(evidence.start())
        assertEquals(TetheredInterfaceState.AwaitingFirstReading, evidence.snapshot())

        now.set(TimeUnit.MILLISECONDS.toNanos(999))
        assertEquals(TetheredInterfaceState.AwaitingFirstReading, evidence.snapshot())

        now.set(TimeUnit.MILLISECONDS.toNanos(1_000))
        assertEquals(TetheredInterfaceState.Unavailable, evidence.snapshot())
        assertEquals(
            "The callback must stay registered after the fallback.",
            0,
            registration.unregisterCalls,
        )
    }

    @Test
    fun aLateReadingAfterThePendingTimeoutStillBecomesKnown() {
        val registration = FakeRegistration()
        val now = AtomicLong(0L)
        val evidence = TetheredInterfaceEvidence(
            registration,
            { now.get() },
            pendingTimeoutMillis = 100,
        )
        evidence.start()
        now.set(TimeUnit.MILLISECONDS.toNanos(100))
        assertEquals(TetheredInterfaceState.Unavailable, evidence.snapshot())

        registration.emitNames("ap0")

        assertEquals(TetheredInterfaceState.Known(setOf("ap0")), evidence.snapshot())
    }

    @Test
    fun aReadingBeforeThePendingTimeoutCancelsTheFallback() {
        val registration = FakeRegistration()
        val now = AtomicLong(0L)
        val evidence = TetheredInterfaceEvidence(
            registration,
            { now.get() },
            pendingTimeoutMillis = 1_000,
        )
        evidence.start()
        now.set(TimeUnit.MILLISECONDS.toNanos(500))
        registration.emitNames("ap0")

        now.set(TimeUnit.MILLISECONDS.toNanos(10_000))

        assertEquals(TetheredInterfaceState.Known(setOf("ap0")), evidence.snapshot())
    }

    @Test
    fun aRetryAfterAFailedRegistrationStartsANewBoundedWait() {
        val registration = FakeRegistration(result = false)
        val now = AtomicLong(0L)
        val evidence = TetheredInterfaceEvidence(
            registration,
            { now.get() },
            pendingTimeoutMillis = 100,
        )
        assertFalse(evidence.start())
        now.set(TimeUnit.MILLISECONDS.toNanos(1_000))
        assertEquals(TetheredInterfaceState.Unavailable, evidence.snapshot())

        registration.result = true
        assertTrue(evidence.start())
        assertEquals(TetheredInterfaceState.AwaitingFirstReading, evidence.snapshot())

        now.set(TimeUnit.MILLISECONDS.toNanos(1_099))
        assertEquals(TetheredInterfaceState.AwaitingFirstReading, evidence.snapshot())
        now.set(TimeUnit.MILLISECONDS.toNanos(1_100))
        assertEquals(TetheredInterfaceState.Unavailable, evidence.snapshot())
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsANonPositivePendingTimeout() {
        TetheredInterfaceEvidence(FakeRegistration(), pendingTimeoutMillis = 0)
    }

    @Test
    fun aThrownRegistrationLeavesUnavailable() {
        val registration = object : TetheredInterfaceRegistration {
            override fun register(listener: (TetheredInterfaceReading?) -> Unit): Boolean =
                error("The tethering service refused the registration.")

            override fun unregister() = Unit
        }
        val evidence = TetheredInterfaceEvidence(registration)

        assertFalse(evidence.start())
        assertEquals(TetheredInterfaceState.Unavailable, evidence.snapshot())
    }

    @Test
    fun closeClearsTheStateAndUnregistersOnce() {
        val registration = FakeRegistration()
        val evidence = TetheredInterfaceEvidence(registration)
        evidence.start()
        registration.emitNames("ap0")

        evidence.close()
        evidence.close()

        assertEquals(1, registration.unregisterCalls)
        assertEquals(TetheredInterfaceState.Unavailable, evidence.snapshot())
    }

    @Test
    fun aStaleCallbackAfterCloseIsIgnored() {
        val registration = FakeRegistration()
        val evidence = TetheredInterfaceEvidence(registration)
        evidence.start()

        evidence.close()
        registration.emitNames("ap0")

        assertEquals(TetheredInterfaceState.Unavailable, evidence.snapshot())
    }

    @Test
    fun closeBeforeStartDoesNotUnregister() {
        val registration = FakeRegistration()
        val evidence = TetheredInterfaceEvidence(registration)

        evidence.close()

        assertEquals(0, registration.unregisterCalls)
        assertFalse(evidence.start())
        assertEquals(0, registration.registerCalls)
    }

    @Test
    fun closeAfterAFailedRegistrationReleasesTheRegistration() {
        val registration = FakeRegistration(result = false)
        val evidence = TetheredInterfaceEvidence(registration)
        assertFalse(evidence.start())

        evidence.close()

        assertEquals(1, registration.unregisterCalls)
        assertEquals(TetheredInterfaceState.Unavailable, evidence.snapshot())
    }

    @Test
    fun closeDuringRegisterRemovesTheLateRegistration() {
        lateinit var evidence: TetheredInterfaceEvidence
        val registration = FakeRegistration()
        registration.onRegister = { evidence.close() }
        evidence = TetheredInterfaceEvidence(registration)

        assertFalse(evidence.start())
        assertEquals(TetheredInterfaceState.Unavailable, evidence.snapshot())
        assertTrue(
            "The late registration must be removed.",
            registration.unregisterCalls >= 1,
        )
    }

    @Test
    fun aThrownUnregisterDoesNotEscapeClose() {
        val registration = object : TetheredInterfaceRegistration {
            override fun register(listener: (TetheredInterfaceReading?) -> Unit): Boolean = true

            override fun unregister() = error("The tethering service is already gone.")
        }
        val evidence = TetheredInterfaceEvidence(registration)
        evidence.start()

        evidence.close()

        assertEquals(TetheredInterfaceState.Unavailable, evidence.snapshot())
    }

    @Test
    fun aCallbackFromAnotherThreadBecomesVisible() {
        val registration = FakeRegistration()
        val evidence = TetheredInterfaceEvidence(registration)
        evidence.start()
        val started = CountDownLatch(1)
        val writer = Thread {
            started.countDown()
            registration.emitNames("ap0")
        }
        writer.start()
        started.await(5, TimeUnit.SECONDS)
        writer.join(5_000)

        assertEquals(TetheredInterfaceState.Known(setOf("ap0")), evidence.snapshot())
    }

    @Test
    fun aConcurrentSnapshotAndCallbackDoNotFail() {
        val registration = FakeRegistration()
        val evidence = TetheredInterfaceEvidence(registration)
        evidence.start()
        val failure = AtomicReference<Throwable?>(null)
        val writer = Thread {
            try {
                for (index in 0 until 2_000) {
                    registration.emitNames("ap$index")
                }
            } catch (error: Throwable) {
                failure.set(error)
            }
        }
        val reader = Thread {
            try {
                repeat(2_000) { evidence.snapshot() }
            } catch (error: Throwable) {
                failure.set(error)
            }
        }
        writer.start()
        reader.start()
        writer.join(5_000)
        reader.join(5_000)

        assertNull(failure.get())
        assertEquals(TetheredInterfaceState.Known(setOf("ap1999")), evidence.snapshot())
    }

    @Test
    fun theCallbackBoundaryIsApi36() {
        assertFalse(supportsTetheredInterfaceCallback(26))
        assertFalse(supportsTetheredInterfaceCallback(35))
        assertTrue(supportsTetheredInterfaceCallback(36))
        assertTrue(supportsTetheredInterfaceCallback(37))
    }

    // --- Platform type filtering --------------------------------------------

    @Test
    fun documentedPhysicalTypesAreAccepted() {
        for (kind in listOf(
            TetheredInterfaceKind.WIFI,
            TetheredInterfaceKind.WIFI_P2P,
            TetheredInterfaceKind.USB,
            TetheredInterfaceKind.NCM,
            TetheredInterfaceKind.ETHERNET,
            TetheredInterfaceKind.BLUETOOTH,
        )) {
            assertEquals(kind, TetheredInterfaceKind.fromPlatformType(kind.platformType))
        }
    }

    @Test
    fun virtualAndUnknownTypesAreRejected() {
        assertNull(TetheredInterfaceKind.fromPlatformType(TetheredInterfaceKind.PLATFORM_TYPE_VIRTUAL))
        assertNull(TetheredInterfaceKind.fromPlatformType(TetheredInterfaceKind.PLATFORM_TYPE_WIGIG))
        assertNull(TetheredInterfaceKind.fromPlatformType(-1))
        assertNull(TetheredInterfaceKind.fromPlatformType(8))
        assertNull(TetheredInterfaceKind.fromPlatformType(99))
    }

    @Test
    fun thePhysicalTypeRanksFollowTheDeclaredOrder() {
        val kinds = listOf(
            TetheredInterfaceKind.WIFI,
            TetheredInterfaceKind.WIFI_P2P,
            TetheredInterfaceKind.USB,
            TetheredInterfaceKind.NCM,
            TetheredInterfaceKind.ETHERNET,
            TetheredInterfaceKind.BLUETOOTH,
        )

        assertEquals(kinds.indices.toList(), kinds.map { it.rank })
    }

    @Test
    fun thePlatformTypeWinsAcrossEveryAcceptedKind() {
        val source = FakeSource(
            listOf(
                snapshot("bt0", "192.168.50.1"),
                snapshot("eth0", "192.168.50.2"),
                snapshot("ncm0", "192.168.50.3"),
                snapshot("usb0", "192.168.50.4"),
                snapshot("p2p0", "192.168.50.5"),
                snapshot("wlan0", "192.168.50.6"),
            ),
        )
        val evidence = TetheredInterfaceState.Known(
            linkedMapOf(
                "bt0" to TetheredInterfaceKind.BLUETOOTH,
                "eth0" to TetheredInterfaceKind.ETHERNET,
                "ncm0" to TetheredInterfaceKind.NCM,
                "usb0" to TetheredInterfaceKind.USB,
                "p2p0" to TetheredInterfaceKind.WIFI_P2P,
                "wlan0" to TetheredInterfaceKind.WIFI,
            ),
        )

        assertEquals(
            address("192.168.50.6"),
            finder(source, evidence).findHotspotAddress(),
        )
    }

    @Test
    fun aCompletePlatformSetKeepsEveryPhysicalType() {
        val reading = readTetheredInterfaces(
            listOf(
                tethered("wlan0", 0),
                tethered("p2p0", 3),
                tethered("usb0", 1),
                tethered("ncm0", 4),
                tethered("eth0", 5),
                tethered("bt-pan0", 2),
            ),
        )

        assertEquals(
            mapOf(
                "wlan0" to TetheredInterfaceKind.WIFI,
                "p2p0" to TetheredInterfaceKind.WIFI_P2P,
                "usb0" to TetheredInterfaceKind.USB,
                "ncm0" to TetheredInterfaceKind.NCM,
                "eth0" to TetheredInterfaceKind.ETHERNET,
                "bt-pan0" to TetheredInterfaceKind.BLUETOOTH,
            ),
            reading,
        )
    }

    @Test
    fun aVirtualOnlyPlatformSetBecomesEmptyPositiveEvidence() {
        val reading = readTetheredInterfaces(
            listOf(tethered("avf_tap_fixed", TetheredInterfaceKind.PLATFORM_TYPE_VIRTUAL)),
        )

        assertEquals(emptyMap<String, TetheredInterfaceKind>(), reading)
    }

    @Test
    fun aVirtualInterfaceDoesNotHideAPhysicalInterface() {
        val reading = readTetheredInterfaces(
            listOf(
                tethered("avf_tap_fixed", TetheredInterfaceKind.PLATFORM_TYPE_VIRTUAL),
                tethered("wlan0", 0),
            ),
        )

        assertEquals(mapOf("wlan0" to TetheredInterfaceKind.WIFI), reading)
    }

    @Test
    fun aWiGigOrUnknownTypeIsNotAPhysicalCandidate() {
        val reading = readTetheredInterfaces(
            listOf(
                tethered("wigig0", TetheredInterfaceKind.PLATFORM_TYPE_WIGIG),
                tethered("unknown0", 17),
                tethered("wlan0", 0),
            ),
        )

        assertEquals(mapOf("wlan0" to TetheredInterfaceKind.WIFI), reading)
    }

    @Test
    fun anEmptyPlatformSetIsEmptyEvidence() {
        assertEquals(emptyMap<String, TetheredInterfaceKind>(), readTetheredInterfaces(emptyList()))
    }

    @Test
    fun aMissingNameMakesThePlatformReadingUnavailable() {
        assertNull(readTetheredInterfaces(listOf(tethered(null, 0))))
        assertNull(readTetheredInterfaces(listOf(tethered(" ", 0))))
    }

    @Test
    fun aMissingTypeMakesThePlatformReadingUnavailable() {
        assertNull(readTetheredInterfaces(listOf(tethered("wlan0", null))))
    }

    @Test
    fun aThrownGetterMakesThePlatformReadingUnavailable() {
        assertNull(
            readTetheredInterfaces(
                listOf(FakeObservation({ error("No name.") }, { 0 })),
            ),
        )
        assertNull(
            readTetheredInterfaces(
                listOf(FakeObservation({ "wlan0" }, { error("No type.") })),
            ),
        )
    }

    @Test
    fun aDuplicatePlatformNameMakesTheReadingUnavailable() {
        assertNull(
            readTetheredInterfaces(
                listOf(
                    tethered("wlan0", 0),
                    tethered(" WLAN0 ", 1),
                ),
            ),
        )
    }

    @Test
    fun platformNamesCompareWithoutCase() {
        val reading = readTetheredInterfaces(listOf(tethered("WLAN0", 0)))

        assertEquals(mapOf("wlan0" to TetheredInterfaceKind.WIFI), reading)
    }

    // --- Finder integration -------------------------------------------------

    @Test
    fun pendingEvidenceReturnsPendingAndNoAddress() {
        val source = FakeSource(listOf(snapshot("ap0", "192.168.43.1")))
        val finder = finder(source, TetheredInterfaceState.AwaitingFirstReading)

        assertEquals(HotspotProbe.Pending, finder.probe())
        assertNull(finder.findHotspotAddress())
    }

    @Test
    fun pendingEvidenceDoesNotFallBackToAStrongName() {
        val source = FakeSource(listOf(snapshot("swlan0", "192.168.43.1")))
        val finder = finder(source, TetheredInterfaceState.AwaitingFirstReading)

        assertEquals(HotspotProbe.Pending, finder.probe())
        assertNull(finder.findHotspotAddress())
    }

    @Test
    fun pendingEvidenceReadsNoInterfaceListAndBindsNothing() {
        val source = FakeSource(listOf(snapshot("ap0", "192.168.43.1")))
        val finder = finder(source, TetheredInterfaceState.AwaitingFirstReading)

        assertEquals(HotspotProbe.Pending, finder.probe())
        assertEquals("A pending reading must not inspect or bind an interface.", 0, source.readCalls.get())
        assertNull(finder.findHotspotAddress())
    }

    @Test
    fun anEmptyKnownSetSuppressesAStrongName() {
        val source = FakeSource(listOf(snapshot("ap0", "192.168.43.1")))

        assertNull(
            finder(source, TetheredInterfaceState.Known(emptyMap())).findHotspotAddress(),
        )
        val probe = finder(
            source,
            TetheredInterfaceState.Known(emptyMap()),
        ).probe()
        assertTrue(probe is HotspotProbe.Observed)
        assertTrue((probe as HotspotProbe.Observed).candidates.isEmpty())
    }

    @Test
    fun aKnownNameOverridesThePrefixRules() {
        val source = FakeSource(listOf(snapshot("usb0", "192.168.42.129")))

        assertEquals(
            address("192.168.42.129"),
            finder(
                source,
                TetheredInterfaceState.Known(
                    mapOf("usb0" to TetheredInterfaceKind.USB),
                ),
            ).findHotspotAddress(),
        )
    }

    @Test
    fun aKnownWlanNameNeedsNoWifiClientObservation() {
        val source = FakeSource(listOf(snapshot("wlan1", "192.168.43.1")))

        assertEquals(
            address("192.168.43.1"),
            finder(
                source,
                TetheredInterfaceState.Known(
                    mapOf("wlan1" to TetheredInterfaceKind.WIFI),
                ),
                observed("rmnet_data0", cellular),
            ).findHotspotAddress(),
        )
    }

    @Test
    fun aKnownBtPanNameIsAccepted() {
        val source = FakeSource(listOf(snapshot("bt-pan0", "192.168.44.1")))

        assertEquals(
            address("192.168.44.1"),
            finder(
                source,
                TetheredInterfaceState.Known(
                    mapOf("bt-pan0" to TetheredInterfaceKind.BLUETOOTH),
                ),
            ).findHotspotAddress(),
        )
    }

    @Test
    fun anUnnamedStrongNameIsRejectedWhenEvidenceIsKnown() {
        val source = FakeSource(
            listOf(
                snapshot("ap0", "192.168.43.1"),
                snapshot("usb0", "192.168.42.129"),
            ),
        )

        assertEquals(
            address("192.168.42.129"),
            finder(
                source,
                TetheredInterfaceState.Known(
                    mapOf("usb0" to TetheredInterfaceKind.USB),
                ),
            ).findHotspotAddress(),
        )
    }

    @Test
    fun aConflictWithAReportedNetworkFailsClosedForEveryName() {
        val client = address("192.168.43.1")
        val source = FakeSource(
            listOf(
                snapshot("ap0", "192.168.43.1"),
                snapshot("rndis0", "192.168.42.129"),
            ),
        )
        val finder = finder(
            source,
            TetheredInterfaceState.Known(
                mapOf(
                    "ap0" to TetheredInterfaceKind.WIFI,
                    "rndis0" to TetheredInterfaceKind.USB,
                ),
            ),
            observed("ap0", wifiClient),
        )

        assertNull(finder.findHotspotAddress())
        val probe = finder.probe()
        assertTrue(probe is HotspotProbe.Observed)
        val observed = probe as HotspotProbe.Observed
        assertTrue(observed.candidates.isEmpty())
        assertTrue(client in observed.excludedAddresses)
    }

    @Test
    fun aKnownNameThatIsAlsoAClientFailsClosed() {
        val source = FakeSource(listOf(snapshot("wlan0", "192.168.1.24")))

        assertNull(
            finder(
                source,
                TetheredInterfaceState.Known(
                    mapOf("wlan0" to TetheredInterfaceKind.WIFI),
                ),
                observed("wlan0", wifiClient),
            ).findHotspotAddress(),
        )
    }

    @Test
    fun severalKnownNamesChooseTheBestTypeRank() {
        val source = FakeSource(
            listOf(
                snapshot("rndis0", "192.168.42.129"),
                snapshot("swlan0", "192.168.43.1"),
            ),
        )

        assertEquals(
            address("192.168.43.1"),
            finder(
                source,
                TetheredInterfaceState.Known(
                    mapOf(
                        "rndis0" to TetheredInterfaceKind.USB,
                        "swlan0" to TetheredInterfaceKind.WIFI,
                    ),
                ),
            ).findHotspotAddress(),
        )
    }

    @Test
    fun severalKnownNamesAtTheSameTypeRankFailClosed() {
        val source = FakeSource(
            listOf(
                snapshot("usb0", "192.168.42.1"),
                snapshot("usb1", "192.168.42.2"),
            ),
        )

        assertNull(
            finder(
                source,
                TetheredInterfaceState.Known(
                    mapOf(
                        "usb0" to TetheredInterfaceKind.USB,
                        "usb1" to TetheredInterfaceKind.USB,
                    ),
                ),
            ).findHotspotAddress(),
        )
    }

    @Test
    fun aKnownNameThatIsDownIsNotACandidate() {
        val source = FakeSource(
            listOf(snapshot("ap0", "192.168.43.1", up = false)),
        )

        assertNull(
            finder(
                source,
                TetheredInterfaceState.Known(
                    mapOf("ap0" to TetheredInterfaceKind.WIFI),
                ),
            ).findHotspotAddress(),
        )
    }

    @Test
    fun aKnownNameWithoutAPrivateIpv4IsNotACandidate() {
        val source = FakeSource(
            listOf(
                snapshot("ap0", "8.8.8.8", "2001:db8::1"),
                snapshot("softap0", "0.0.0.0"),
            ),
        )

        assertNull(
            finder(
                source,
                TetheredInterfaceState.Known(
                    mapOf(
                        "ap0" to TetheredInterfaceKind.WIFI,
                        "softap0" to TetheredInterfaceKind.WIFI,
                    ),
                ),
            ).findHotspotAddress(),
        )
    }

    @Test
    fun aKnownCellularOrVirtualNameIsNotACandidate() {
        val source = FakeSource(
            listOf(
                snapshot("rmnet_data0", "10.44.0.9"),
                snapshot("tun0", "10.8.0.2"),
            ),
        )

        assertNull(
            finder(
                source,
                TetheredInterfaceState.Known(
                    mapOf(
                        "rmnet_data0" to TetheredInterfaceKind.WIFI,
                        "tun0" to TetheredInterfaceKind.USB,
                    ),
                ),
            ).findHotspotAddress(),
        )
    }

    @Test
    fun anAvfTapNameIsNotACandidateEvenWithAnAcceptedType() {
        val source = FakeSource(
            listOf(snapshot("avf_tap_fixed", "192.168.42.1")),
        )

        assertNull(
            finder(
                source,
                TetheredInterfaceState.Known(
                    mapOf("avf_tap_fixed" to TetheredInterfaceKind.ETHERNET),
                ),
            ).findHotspotAddress(),
        )
    }

    @Test
    fun aKnownNameThatIsNotInTheInterfaceListIsNotInvented() {
        val source = FakeSource(listOf(snapshot("ap0", "192.168.43.1")))

        assertNull(
            finder(
                source,
                TetheredInterfaceState.Known(
                    mapOf("ap9" to TetheredInterfaceKind.WIFI),
                ),
            ).findHotspotAddress(),
        )
    }

    @Test
    fun aKnownNameIsUsedWhenTheNetworkObservationFailed() {
        val source = FakeSource(listOf(snapshot("usb0", "192.168.42.129")))
        val finder = NetworkInterfaceHotspotAddressFinder(
            source,
            { NetworkInterfaceObservation.Unknown },
            TetheredInterfaceEvidenceSource {
                TetheredInterfaceState.Known(
                    mapOf("usb0" to TetheredInterfaceKind.USB),
                )
            },
        )

        assertEquals(address("192.168.42.129"), finder.findHotspotAddress())
    }

    @Test
    fun aKnownNameThatAPartialObservationExcludesFailsClosed() {
        val source = FakeSource(
            listOf(
                snapshot("ap0", "192.168.43.1"),
                snapshot("rndis0", "192.168.42.129"),
            ),
        )
        val partial = observation(
            observed("ap0", wifiClient),
            FakeNetwork({ null }, { "rndis0" }),
        )
        val finder = NetworkInterfaceHotspotAddressFinder(
            source,
            { partial },
            TetheredInterfaceEvidenceSource {
                TetheredInterfaceState.Known(
                    mapOf(
                        "ap0" to TetheredInterfaceKind.WIFI,
                        "rndis0" to TetheredInterfaceKind.USB,
                    ),
                )
            },
        )

        assertNull(finder.findHotspotAddress())
    }

    @Test
    fun knownNamesCompareWithoutCase() {
        val source = FakeSource(listOf(snapshot("AP0", "192.168.43.1")))

        assertEquals(
            address("192.168.43.1"),
            finder(
                source,
                TetheredInterfaceState.Known(setOf("AP0")),
            ).findHotspotAddress(),
        )
    }

    @Test
    fun unavailableEvidenceKeepsTheNameRules() {
        val source = FakeSource(listOf(snapshot("ap0", "192.168.43.1")))

        assertEquals(
            address("192.168.43.1"),
            finder(source, TetheredInterfaceState.Unavailable).findHotspotAddress(),
        )
    }

    @Test
    fun unavailableEvidenceFallsBackToTheFallbackRankForAWlanWithoutAClient() {
        val source = FakeSource(listOf(snapshot("wlan1", "192.168.43.1")))

        // Unavailable evidence keeps the name rules, which admit the unreported
        // wlan1 at the fallback rank because it has one private IPv4 address
        // and a complete observation.
        assertEquals(
            address("192.168.43.1"),
            finder(source, TetheredInterfaceState.Unavailable).findHotspotAddress(),
        )
    }

    // --- Shared process lifetime --------------------------------------------

    @Test
    fun aSharedSourceClosesOnlyAfterTheLastLease() {
        val registration = FakeRegistration()
        val shared = SharedTetheredInterfaceEvidence(factory = {
            TetheredInterfaceEvidence(registration)
        })

        val first = shared.acquire()
        val second = shared.acquire()
        assertSame(first, second)

        shared.release()
        assertEquals("One lease still uses the callback.", 0, registration.unregisterCalls)

        shared.release()
        assertEquals(1, registration.unregisterCalls)
        assertEquals(TetheredInterfaceState.Unavailable, first.snapshot())
    }

    @Test
    fun aSharedSourceRetriesAFailedRegistration() {
        val registration = FakeRegistration(result = false)
        val shared = SharedTetheredInterfaceEvidence(factory = {
            TetheredInterfaceEvidence(registration)
        })

        val source = shared.acquire()
        assertEquals(TetheredInterfaceState.Unavailable, source.snapshot())
        assertEquals(1, registration.registerCalls)

        registration.result = true
        assertSame(source, shared.acquire())
        assertEquals(2, registration.registerCalls)
        assertEquals(TetheredInterfaceState.AwaitingFirstReading, source.snapshot())

        shared.close()
    }

    @Test
    fun aProcessSourceRegistersOnceAcrossCalls() {
        val registration = FakeRegistration()
        val shared = SharedTetheredInterfaceEvidence(factory = {
            TetheredInterfaceEvidence(registration)
        })

        val first = shared.processSource()
        val second = shared.processSource()
        assertSame(first, second)
        assertEquals(1, registration.registerCalls)
        assertEquals(TetheredInterfaceState.AwaitingFirstReading, first.snapshot())
    }

    @Test
    fun aProcessSourceRetriesAFailedRegistration() {
        val registration = FakeRegistration(result = false)
        val shared = SharedTetheredInterfaceEvidence(factory = {
            TetheredInterfaceEvidence(registration)
        })

        val source = shared.processSource()
        assertEquals(TetheredInterfaceState.Unavailable, source.snapshot())

        registration.result = true
        assertSame(source, shared.processSource())
        assertEquals(2, registration.registerCalls)
        assertEquals(TetheredInterfaceState.AwaitingFirstReading, source.snapshot())
    }

    @Test
    fun aProcessSourceAfterCloseIsUnavailable() {
        val registration = FakeRegistration()
        val shared = SharedTetheredInterfaceEvidence(factory = {
            TetheredInterfaceEvidence(registration)
        })
        shared.processSource()

        shared.close()

        assertEquals(
            TetheredInterfaceState.Unavailable,
            shared.processSource().snapshot(),
        )
        assertEquals(1, registration.unregisterCalls)
    }

    @Test
    fun aSharedSourceAfterCloseIsUnavailable() {
        val registration = FakeRegistration()
        val shared = SharedTetheredInterfaceEvidence(factory = {
            TetheredInterfaceEvidence(registration)
        })
        shared.acquire()

        shared.close()

        val source = shared.acquire()
        assertEquals(TetheredInterfaceState.Unavailable, source.snapshot())
        assertEquals(1, registration.unregisterCalls)
    }

    @Test
    fun aSharedSourceWithoutARegistrationIsUnavailable() {
        val shared = SharedTetheredInterfaceEvidence(factory = { null })

        assertEquals(
            TetheredInterfaceState.Unavailable,
            shared.acquire().snapshot(),
        )
    }

    @Test
    fun releasingAnUnheldSharedSourceDoesNothing() {
        val registration = FakeRegistration()
        val shared = SharedTetheredInterfaceEvidence(factory = {
            TetheredInterfaceEvidence(registration)
        })

        shared.release()
        shared.release()

        assertEquals(0, registration.registerCalls)
    }

    @Test
    fun aProcessLeaseSurvivesAnExplicitRelease() {
        val registration = FakeRegistration()
        val shared = SharedTetheredInterfaceEvidence(factory = {
            TetheredInterfaceEvidence(registration)
        })

        val process = shared.processSource()
        assertSame(process, shared.acquire())
        shared.release()

        assertEquals(
            "A service lease must not close the process source.",
            0,
            registration.unregisterCalls,
        )
        assertEquals(TetheredInterfaceState.AwaitingFirstReading, process.snapshot())

        shared.close()
        assertEquals(1, registration.unregisterCalls)
    }

    @Test
    fun aFailedFactoryDoesNotLeaveALease() {
        val registration = FakeRegistration()
        var fail = true
        val shared = SharedTetheredInterfaceEvidence(factory = {
            if (fail) null else TetheredInterfaceEvidence(registration)
        })

        assertEquals(TetheredInterfaceState.Unavailable, shared.acquire().snapshot())

        fail = false
        val source = shared.acquire()
        assertEquals(TetheredInterfaceState.AwaitingFirstReading, source.snapshot())
        shared.release()

        assertEquals(
            "The failed acquire must not keep a lease.",
            1,
            registration.unregisterCalls,
        )
    }

    @Test
    fun closeDuringAcquireLeavesNoRegistrationOrLease() {
        val registration = FakeRegistration()
        val entered = CountDownLatch(1)
        val proceed = CountDownLatch(1)
        val shared = SharedTetheredInterfaceEvidence(factory = {
            entered.countDown()
            proceed.await(5, TimeUnit.SECONDS)
            TetheredInterfaceEvidence(registration)
        })
        val result = AtomicReference<TetheredInterfaceEvidenceSource?>(null)
        val thread = Thread { result.set(shared.acquire()) }
        thread.start()
        try {
            assertTrue(
                "The acquire must enter the factory.",
                entered.await(5, TimeUnit.SECONDS),
            )
            shared.close()
        } finally {
            proceed.countDown()
        }
        thread.join(5_000)

        assertEquals(TetheredInterfaceState.Unavailable, result.get()!!.snapshot())
        assertEquals(
            "A closed acquire must not register.",
            0,
            registration.registerCalls,
        )
        shared.release()
        assertEquals(0, registration.unregisterCalls)
    }

    @Test
    fun concurrentCreatorsLeaveOneRegistration() {
        val registration = FakeRegistration()
        val shared = SharedTetheredInterfaceEvidence(factory = {
            TetheredInterfaceEvidence(registration)
        })
        val barrier = CyclicBarrier(2)
        val results = arrayOfNulls<TetheredInterfaceEvidenceSource>(2)
        val threads = (0 until 2).map { index ->
            Thread {
                barrier.await(5, TimeUnit.SECONDS)
                results[index] = shared.processSource()
            }
        }

        threads.forEach { it.start() }
        threads.forEach { it.join(5_000) }

        assertSame(results[0], results[1])
        assertEquals(1, registration.registerCalls)
        shared.close()
    }

    // --- Watch integration --------------------------------------------------

    private class MutableEvidence(var state: TetheredInterfaceState) :
        TetheredInterfaceEvidenceSource {
        override fun snapshot(): TetheredInterfaceState = state
    }

    private fun watchFinder(
        source: InterfaceSource,
        evidence: MutableEvidence,
    ) = NetworkInterfaceHotspotAddressFinder(
        source,
        { NetworkInterfaceObservation.Complete(emptySet(), emptySet()) },
        evidence,
    )

    private fun waitForCalls(calls: AtomicInteger, minimum: Int) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (calls.get() < minimum && System.nanoTime() < deadline) {
            Thread.sleep(10)
        }
        assertTrue("The watch must read the address.", calls.get() >= minimum)
    }

    @Test
    fun aKnownEmptySetStopsTheWatchAfterTheDebounce() {
        val expected = address("192.168.43.1")
        val evidence = MutableEvidence(
            TetheredInterfaceState.Known(mapOf("ap0" to TetheredInterfaceKind.WIFI)),
        )
        val finder = CountingFinder(
            watchFinder(FakeSource(listOf(snapshot("ap0", "192.168.43.1"))), evidence),
        )
        val watch = PeriodicHotspotWatch(
            finder,
            expected,
            periodMillis = 20,
            missingChecksBeforeLoss = 2,
        )
        val losses = AtomicInteger()
        val firstLoss = CountDownLatch(1)
        watch.start {
            losses.incrementAndGet()
            firstLoss.countDown()
        }
        try {
            waitForCalls(finder.calls, 1)
            evidence.state = TetheredInterfaceState.Known(emptyMap())

            assertTrue("The watch must report the loss.", firstLoss.await(5, TimeUnit.SECONDS))
            Thread.sleep(150)
            assertEquals(1, losses.get())
        } finally {
            watch.stop()
        }
    }

    @Test
    fun pendingEvidenceDoesNotAdvanceTheWatchLossCount() {
        val expected = address("192.168.43.1")
        val evidence = MutableEvidence(TetheredInterfaceState.AwaitingFirstReading)
        val finder = CountingFinder(
            watchFinder(FakeSource(listOf(snapshot("ap0", "192.168.43.1"))), evidence),
        )
        val watch = PeriodicHotspotWatch(
            finder,
            expected,
            periodMillis = 20,
            missingChecksBeforeLoss = 2,
            pendingChecksBeforeUncertain = 100,
        )
        val losses = AtomicInteger()
        watch.start { losses.incrementAndGet() }
        try {
            waitForCalls(finder.calls, 5)
            Thread.sleep(100)
            assertEquals(0, losses.get())
        } finally {
            watch.stop()
        }
    }

    @Test
    fun pendingEvidenceThenAnEmptySetStopsTheWatchAfterTheDebounce() {
        val expected = address("192.168.43.1")
        val evidence = MutableEvidence(TetheredInterfaceState.AwaitingFirstReading)
        val finder = CountingFinder(
            watchFinder(FakeSource(listOf(snapshot("ap0", "192.168.43.1"))), evidence),
        )
        val watch = PeriodicHotspotWatch(
            finder,
            expected,
            periodMillis = 20,
            missingChecksBeforeLoss = 2,
        )
        val losses = AtomicInteger()
        val firstLoss = CountDownLatch(1)
        watch.start {
            losses.incrementAndGet()
            firstLoss.countDown()
        }
        try {
            waitForCalls(finder.calls, 3)
            evidence.state = TetheredInterfaceState.Known(emptyMap())

            assertTrue("The watch must report the loss.", firstLoss.await(5, TimeUnit.SECONDS))
            Thread.sleep(150)
            assertEquals(1, losses.get())
        } finally {
            watch.stop()
        }
    }

    @Test
    fun aRetriedRegistrationWithoutACallbackDoesNotBlindTheWatch() {
        val expected = address("192.168.43.1")
        val registration = FakeRegistration(result = false)
        val now = AtomicLong(0L)
        val evidence = TetheredInterfaceEvidence(
            registration,
            { now.get() },
            pendingTimeoutMillis = 100,
        )
        val shared = SharedTetheredInterfaceEvidence(factory = { evidence })
        val source = FakeSource(listOf(snapshot("ap0", "192.168.43.1")))
        val finder = CountingFinder(
            NetworkInterfaceHotspotAddressFinder(
                source,
                { NetworkInterfaceObservation.Complete(emptySet(), emptySet()) },
                shared.processSource(),
            ),
        )
        val watch = PeriodicHotspotWatch(
            finder,
            expected,
            periodMillis = 20,
            missingChecksBeforeLoss = 2,
        )
        val losses = AtomicInteger()
        val firstLoss = CountDownLatch(1)
        watch.start {
            losses.incrementAndGet()
            firstLoss.countDown()
        }
        try {
            // The failed registration falls back to the name rules, so the
            // bound address is a valid candidate.
            waitForCalls(finder.calls, 2)
            assertEquals(0, losses.get())

            // A retry succeeds but no callback arrives.
            registration.result = true
            shared.processSource()
            val beforeRetryProbes = finder.calls.get()
            waitForCalls(finder.calls, beforeRetryProbes + 2)
            assertEquals("A pending reading must not look like a loss.", 0, losses.get())

            // The callback never arrives. The bounded wait expires, and the
            // hotspot interface is gone.
            now.set(TimeUnit.MILLISECONDS.toNanos(100))
            source.interfaces = emptyList()

            assertTrue(
                "A retried registration without a callback must not blind the watch.",
                firstLoss.await(5, TimeUnit.SECONDS),
            )
            Thread.sleep(150)
            assertEquals(1, losses.get())
        } finally {
            watch.stop()
            shared.close()
        }
    }

    @Test
    fun anUnavailableInitialReadingUsesTheHeuristicAndDoesNotStop() {
        val expected = address("192.168.43.1")
        val evidence = MutableEvidence(TetheredInterfaceState.Unavailable)
        val finder = CountingFinder(
            watchFinder(FakeSource(listOf(snapshot("ap0", "192.168.43.1"))), evidence),
        )
        val watch = PeriodicHotspotWatch(
            finder,
            expected,
            periodMillis = 20,
            missingChecksBeforeLoss = 2,
        )
        val losses = AtomicInteger()
        watch.start { losses.incrementAndGet() }
        try {
            waitForCalls(finder.calls, 3)
            Thread.sleep(100)
            assertEquals(0, losses.get())
        } finally {
            watch.stop()
        }
    }

    @Test
    fun aSwitchToAnotherKnownNameStopsTheWatchAfterTheDebounce() {
        val expected = address("192.168.43.1")
        val evidence = MutableEvidence(
            TetheredInterfaceState.Known(mapOf("ap0" to TetheredInterfaceKind.WIFI)),
        )
        val finder = CountingFinder(
            watchFinder(
                FakeSource(
                    listOf(
                        snapshot("ap0", "192.168.43.1"),
                        snapshot("rndis0", "192.168.42.129"),
                    ),
                ),
                evidence,
            ),
        )
        val watch = PeriodicHotspotWatch(
            finder,
            expected,
            periodMillis = 20,
            missingChecksBeforeLoss = 2,
        )
        val losses = AtomicInteger()
        val firstLoss = CountDownLatch(1)
        watch.start {
            losses.incrementAndGet()
            firstLoss.countDown()
        }
        try {
            waitForCalls(finder.calls, 1)
            evidence.state = TetheredInterfaceState.Known(
                mapOf("rndis0" to TetheredInterfaceKind.USB),
            )

            assertTrue("The watch must report the loss.", firstLoss.await(5, TimeUnit.SECONDS))
            Thread.sleep(150)
            assertEquals(1, losses.get())
        } finally {
            watch.stop()
        }
    }

    private class CountingFinder(
        private val delegate: HotspotAddressFinder,
    ) : HotspotAddressFinder {
        val calls = AtomicInteger()

        override fun probe(): HotspotProbe {
            calls.incrementAndGet()
            return delegate.probe()
        }
    }
}

/**
 * Test-only readers for the evidence value. A name-only reader infers the kind
 * from the interface name. Production code always supplies the platform type.
 */
private fun readingOf(
    vararg names: String,
): TetheredInterfaceReading = TetheredInterfaceReading(
    names.associateWith { name ->
        TetheredInterfaceKind.inferFromName(name) ?: TetheredInterfaceKind.WIFI
    },
)

private fun readingOf(
    vararg entries: Pair<String, TetheredInterfaceKind>,
): TetheredInterfaceReading = TetheredInterfaceReading(linkedMapOf(*entries))
