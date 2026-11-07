package com.hotspotshade.source

import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests for the strict hotspot finder.
 *
 * Every interface that a reported network holds is excluded, whatever its
 * transport is. A strong tether name is admitted as a candidate but does not
 * prove the tethering role. A `wlan*` name is a weak concurrency candidate: it
 * needs one complete observation that names an unambiguous Wi-Fi station
 * outside the tether name prefixes. A reported `wlan*`, access point, USB,
 * Ethernet, or P2P name is not station evidence, because the platform can
 * report a tether role under that name. A generic interface such as `eth*` or
 * `wg*` is never a hotspot. An unconfirmed interface gives null, so the
 * listener does not bind a client, VPN, or Bluetooth PAN address.
 */
class HotspotAddressFinderTest {
    private class FakeSource(var interfaces: List<InterfaceSnapshot>) : InterfaceSource {
        override fun read(): List<InterfaceSnapshot> = interfaces
    }

    private class BrokenSource : InterfaceSource {
        override fun read(): List<InterfaceSnapshot> =
            error("The platform refused the interface list.")
    }

    private class FakeNetwork(
        private val transportsResult: () -> ObservedTransports?,
        private val nameResult: () -> String?,
    ) : ObservedNetwork {
        override fun transports(): ObservedTransports? = transportsResult()

        override fun interfaceName(): String? = nameResult()
    }

    private val cellular = ObservedTransports(isCellular = true, isWifi = false, isVpn = false)
    private val wifiClient = ObservedTransports(isCellular = false, isWifi = true, isVpn = false)
    private val vpn = ObservedTransports(isCellular = false, isWifi = false, isVpn = true)

    // A Bluetooth PAN client reports no cellular, Wi-Fi, or VPN transport. The
    // reader excludes every reported name, so the transport does not matter.
    private val bluetoothClient = ObservedTransports(
        isCellular = false,
        isWifi = false,
        isVpn = false,
    )

    private fun snapshot(
        name: String,
        vararg addresses: String,
        up: Boolean = true,
        loopback: Boolean = false,
        virtual: Boolean = false,
        pointToPoint: Boolean = false,
    ) = InterfaceSnapshot(
        name = name,
        isUp = up,
        isLoopback = loopback,
        addresses = addresses.map { InetAddress.getByName(it) },
        isVirtual = virtual,
        isPointToPoint = pointToPoint,
    )

    private fun observed(name: String, transports: ObservedTransports) =
        FakeNetwork({ transports }, { name })

    private fun observation(vararg networks: ObservedNetwork): NetworkInterfaceObservation =
        NetworkInterfaceObservationReader { networks.toList() }.read()

    private fun finder(
        source: InterfaceSource,
        vararg networks: ObservedNetwork,
    ) = NetworkInterfaceHotspotAddressFinder(source, { observation(*networks) })

    private fun finder(
        source: InterfaceSource,
        fixed: NetworkInterfaceObservation,
    ) = NetworkInterfaceHotspotAddressFinder(source, { fixed })

    private fun probe(
        source: InterfaceSource,
        vararg networks: ObservedNetwork,
    ): HotspotProbe = finder(source, *networks).probe()

    private fun probe(
        source: InterfaceSource,
        fixed: NetworkInterfaceObservation,
    ): HotspotProbe = finder(source, fixed).probe()

    private fun choice(
        interfaceName: String,
        address: String? = null,
    ): HotspotInterfaceChoice.Selected = HotspotInterfaceChoice.Selected(
        interfaceName = interfaceName,
        address = address?.let { InetAddress.getByName(it) },
    )

    private fun choiceFinder(
        source: InterfaceSource,
        fixed: NetworkInterfaceObservation,
        selected: HotspotInterfaceChoice,
    ) = NetworkInterfaceHotspotAddressFinder(
        source,
        { fixed },
        choiceSource = HotspotInterfaceChoiceSource { selected },
    )

    private fun choiceFinder(
        source: InterfaceSource,
        selected: HotspotInterfaceChoice,
        vararg networks: ObservedNetwork,
    ) = NetworkInterfaceHotspotAddressFinder(
        source,
        { observation(*networks) },
        choiceSource = HotspotInterfaceChoiceSource { selected },
    )

    private fun assertChoiceRejected(
        source: InterfaceSource,
        fixed: NetworkInterfaceObservation,
        selected: HotspotInterfaceChoice,
        expected: HotspotChoiceOutcome,
    ) {
        val result = choiceFinder(source, fixed, selected).probe()
        assertTrue(result is HotspotProbe.Observed)
        val observed = result as HotspotProbe.Observed
        assertTrue(observed.candidates.isEmpty())
        assertEquals(expected, observed.choiceOutcome)
        assertNull(choiceFinder(source, fixed, selected).findHotspotAddress())
    }

    @Test
    fun findsTheHotspotNextToTheWifiClientInterface() {
        val source = FakeSource(
            listOf(
                snapshot("wlan0", "192.168.1.24"),
                snapshot("ap0", "192.168.43.1"),
                snapshot("rmnet_data0", "10.44.0.9"),
            ),
        )

        val address = finder(
            source,
            observed("wlan0", wifiClient),
            observed("rmnet_data0", cellular),
        ).findHotspotAddress()

        assertEquals(InetAddress.getByName("192.168.43.1"), address)
    }

    @Test
    fun prefersANamedTetheringInterfaceOverAGenericPrivateInterface() {
        val source = FakeSource(
            listOf(
                snapshot("eth0", "10.0.2.15"),
                snapshot("rndis0", "192.168.42.129"),
            ),
        )

        assertEquals(
            InetAddress.getByName("192.168.42.129"),
            finder(source).findHotspotAddress(),
        )
    }

    @Test
    fun prefersTheWifiHotspotOverUsbTethering() {
        val source = FakeSource(
            listOf(
                snapshot("rndis0", "192.168.42.129"),
                snapshot("swlan0", "192.168.43.1"),
            ),
        )

        assertEquals(
            InetAddress.getByName("192.168.43.1"),
            finder(source).findHotspotAddress(),
        )
    }

    @Test
    fun usesTheUnconfirmedWlanAccessPointWhenAnUnambiguousStationIsConfirmed() {
        val source = FakeSource(
            listOf(
                snapshot("wifi0", "192.168.1.24"),
                snapshot("wlan1", "192.168.43.1"),
            ),
        )

        // wifi0 is an unambiguous Wi-Fi station. wlan1 is the access point.
        assertEquals(
            InetAddress.getByName("192.168.43.1"),
            finder(
                source,
                observed("wifi0", wifiClient),
                observed("rmnet_data0", cellular),
            ).findHotspotAddress(),
        )
    }

    @Test
    fun aReportedTetherRoleDoesNotConfirmAnUnreportedWlan() {
        val tetherNames = listOf(
            "ap0",
            "softap0",
            "swlan0",
            "rndis0",
            "bt-pan0",
            "usb0",
            "ncm0",
            "eth0",
            "p2p0",
        )
        for (tetherName in tetherNames) {
            val source = FakeSource(
                listOf(
                    snapshot(tetherName, "192.168.1.24"),
                    snapshot("wlan1", "192.168.43.1"),
                ),
            )

            // The reported Wi-Fi network is a tether role, not a station. It
            // cannot serve as proof that a separate wlan is the hotspot.
            assertNull(
                "$tetherName must not confirm wlan1",
                finder(
                    source,
                    observed(tetherName, wifiClient),
                    observed("rmnet_data0", cellular),
                ).findHotspotAddress(),
            )
        }
    }

    @Test
    fun aReportedWlanDoesNotConfirmADifferentUnreportedWlan() {
        val source = FakeSource(
            listOf(
                snapshot("wlan0", "192.168.1.24"),
                snapshot("wlan1", "192.168.43.1"),
            ),
        )

        // A reported wlan name is ambiguous: it can be the station or the
        // access point. It is not proof that the other wlan is tethering.
        assertNull(
            finder(
                source,
                observed("wlan0", wifiClient),
                observed("rmnet_data0", cellular),
            ).findHotspotAddress(),
        )
    }

    @Test
    fun aReportedWlanAndAStationStillConfirmAnUnreportedWlan() {
        val source = FakeSource(
            listOf(
                snapshot("wlan0", "192.168.1.24"),
                snapshot("wifi0", "192.168.1.25"),
                snapshot("wlan1", "192.168.43.1"),
            ),
        )

        // The ambiguous wlan0 is excluded and is not evidence. The separate
        // wifi0 station is unambiguous evidence for wlan1.
        assertEquals(
            InetAddress.getByName("192.168.43.1"),
            finder(
                source,
                observed("wlan0", wifiClient),
                observed("wifi0", wifiClient),
                observed("rmnet_data0", cellular),
            ).findHotspotAddress(),
        )
    }

    @Test
    fun aHandBuiltObservationCannotUseAnAmbiguousWlanAsEvidence() {
        val source = FakeSource(listOf(snapshot("wlan1", "192.168.43.1")))
        val complete = NetworkInterfaceObservation.Complete(
            excludedNames = setOf("wlan0"),
            wifiClientNames = setOf("wlan0"),
        )

        // A caller can build an observation in a test or a future adapter.
        // The finder still refuses an ambiguous wlan as client evidence.
        assertNull(finder(source, complete).findHotspotAddress())
    }

    @Test
    fun aHandBuiltObservationIsNormalizedBeforeComparison() {
        val address = InetAddress.getByName("192.168.43.1")
        val source = FakeSource(
            listOf(
                snapshot("WLAN0", "192.168.1.24"),
                snapshot("AP0", "192.168.43.1"),
            ),
        )
        val complete = NetworkInterfaceObservation.Complete(
            excludedNames = setOf(" WLAN0 "),
            wifiClientNames = setOf(" WLAN0 "),
        )

        // The uppercase reported name excludes the uppercase snapshot. The
        // ambiguous WLAN0 name is not evidence, but the strong AP0 name is.
        assertEquals(address, finder(source, complete).findHotspotAddress())
        val options = selectableHotspotInterfaces(source.interfaces, complete)
        assertTrue(options.none { it.interfaceName == "wlan0" })
    }

    @Test
    fun doesNotUseWlanWhenOnlyACellularNetworkIsObserved() {
        val source = FakeSource(
            listOf(
                snapshot("wlan0", "192.168.1.24"),
                snapshot("wlan1", "192.168.43.1"),
                snapshot("rmnet_data0", "10.44.0.9"),
            ),
        )

        // The platform reports the cellular network and hides the Wi-Fi
        // client. The finder cannot tell the access point from the client.
        assertNull(
            finder(source, observed("rmnet_data0", cellular)).findHotspotAddress(),
        )
    }

    @Test
    fun doesNotUseWlanWhenTheObservationIsUnknown() {
        val source = FakeSource(
            listOf(
                snapshot("wlan0", "192.168.43.1"),
                snapshot("wlan1", "192.168.1.24"),
            ),
        )

        assertNull(
            finder(source, NetworkInterfaceObservation.Unknown).findHotspotAddress(),
        )
    }

    @Test
    fun doesNotUseWlanWhenTheObservationIsPartial() {
        val source = FakeSource(listOf(snapshot("wlan1", "192.168.43.1")))

        val partial = observation(
            observed("rmnet_data0", cellular),
            FakeNetwork({ null }, { "wlan0" }),
        )

        assertNull(finder(source, partial).findHotspotAddress())
    }

    @Test
    fun doesNotUseEitherWlanWhenTwoUnconfirmedInterfacesTie() {
        val source = FakeSource(
            listOf(
                snapshot("wifi0", "192.168.1.24"),
                snapshot("wlan1", "192.168.43.1"),
                snapshot("wlan2", "192.168.44.1"),
            ),
        )

        // Both remaining wlan interfaces look like access points. The finder
        // cannot tell which one is the hotspot.
        assertNull(
            finder(
                source,
                observed("wifi0", wifiClient),
                observed("rmnet_data0", cellular),
            ).findHotspotAddress(),
        )
    }

    @Test
    fun doesNotUseAWifiClientInterface() {
        val source = FakeSource(
            listOf(
                snapshot("wlan0", "192.168.1.24"),
                snapshot("wlan1", "192.168.1.25"),
            ),
        )

        assertNull(
            finder(
                source,
                observed("wlan0", wifiClient),
                observed("wlan1", wifiClient),
            ).findHotspotAddress(),
        )
    }

    @Test
    fun doesNotUseTheWlan1ClientInterface() {
        val source = FakeSource(
            listOf(
                snapshot("wlan0", "192.168.43.1"),
                snapshot("wlan1", "192.168.1.24"),
            ),
        )

        // wlan0 is the access point. wlan1 is the Wi-Fi client. The reported
        // wlan1 name is ambiguous, so it cannot confirm wlan0 either.
        assertNull(finder(source, observed("wlan1", wifiClient)).findHotspotAddress())
        assertNull(
            finder(
                FakeSource(listOf(snapshot("wlan1", "192.168.1.24"))),
                observed("wlan1", wifiClient),
            ).findHotspotAddress(),
        )
    }

    @Test
    fun anUnambiguousStationConfirmsTheWlan0AccessPoint() {
        val source = FakeSource(
            listOf(
                snapshot("wlan0", "192.168.43.1"),
                snapshot("wifi0", "192.168.1.24"),
            ),
        )

        assertEquals(
            InetAddress.getByName("192.168.43.1"),
            finder(source, observed("wifi0", wifiClient)).findHotspotAddress(),
        )
    }

    @Test
    fun doesNotUseAWlanInterfaceWhenTheClientListIsEmpty() {
        val source = FakeSource(
            listOf(
                snapshot("wlan0", "192.168.43.1"),
                snapshot("wlan1", "192.168.1.24"),
            ),
        )

        assertNull(finder(source).findHotspotAddress())
    }

    @Test
    fun doesNotTreatSilenceAsProofOfAWlanHotspot() {
        val source = FakeSource(
            listOf(
                snapshot("wlan0", "192.168.1.24"),
                snapshot("wlan1", "192.168.43.1"),
            ),
        )

        // A complete observation with no Wi-Fi client is silence, not proof
        // that either wlan interface is tethering.
        val silent = probe(source, NetworkInterfaceObservation.Complete(emptySet(), emptySet()))
        assertTrue(silent is HotspotProbe.Observed)
        assertTrue((silent as HotspotProbe.Observed).candidates.isEmpty())
        assertNull(finder(source, NetworkInterfaceObservation.Complete(emptySet(), emptySet()))
            .findHotspotAddress())
    }

    @Test
    fun doesNotUseAGenericEthernetInterface() {
        val source = FakeSource(listOf(snapshot("eth0", "10.0.2.15")))

        assertNull(finder(source).findHotspotAddress())
        assertNull(
            finder(source, observed("wlan0", wifiClient)).findHotspotAddress(),
        )
    }

    @Test
    fun doesNotUseAWireGuardInterface() {
        val source = FakeSource(listOf(snapshot("wg0", "10.8.0.2")))

        assertNull(finder(source).findHotspotAddress())
    }

    @Test
    fun confirmsAStrongTetheringNameWithoutTheClientList() {
        val source = FakeSource(listOf(snapshot("ap0", "192.168.43.1")))

        assertEquals(
            InetAddress.getByName("192.168.43.1"),
            finder(source).findHotspotAddress(),
        )
        assertEquals(
            InetAddress.getByName("192.168.43.1"),
            finder(source, NetworkInterfaceObservation.Unknown).findHotspotAddress(),
        )
    }

    @Test
    fun ignoresCellularInterfacesEvenWhenTheyHoldAPrivateAddress() {
        val source = FakeSource(
            listOf(
                snapshot("rmnet_data0", "10.44.0.9"),
                snapshot("ccmni1", "10.12.0.4"),
                snapshot("clat4", "192.0.0.4"),
            ),
        )

        assertNull(
            finder(
                source,
                observed("rmnet_data0", cellular),
                observed("ccmni1", cellular),
                observed("clat4", cellular),
            ).findHotspotAddress(),
        )
    }

    @Test
    fun ignoresDownAndLoopbackInterfaces() {
        val source = FakeSource(
            listOf(
                snapshot("ap0", "192.168.43.1", up = false),
                snapshot("lo", "127.0.0.1", loopback = true),
            ),
        )

        assertNull(finder(source).findHotspotAddress())
    }

    @Test
    fun ignoresPublicAndUnspecifiedAddresses() {
        val source = FakeSource(
            listOf(
                snapshot("ap0", "8.8.8.8"),
                snapshot("rndis0", "0.0.0.0"),
                snapshot("eth0", "169.254.3.4"),
            ),
        )

        assertNull(finder(source).findHotspotAddress())
    }

    @Test
    fun ignoresVpnInterfaces() {
        val source = FakeSource(
            listOf(
                snapshot("tun0", "10.8.0.2"),
                snapshot("ppp0", "10.9.0.2"),
                snapshot("wg0", "10.10.0.2"),
            ),
        )

        assertNull(
            finder(
                source,
                observed("tun0", vpn),
                observed("ppp0", vpn),
                observed("wg0", vpn),
            ).findHotspotAddress(),
        )
    }

    @Test
    fun returnsNullWhenTheDeviceHasNoHotspot() {
        val source = FakeSource(
            listOf(
                snapshot("wlan0", "192.168.1.24"),
                snapshot("rmnet_data0", "10.44.0.9"),
            ),
        )

        assertNull(
            finder(
                source,
                observed("wlan0", wifiClient),
                observed("rmnet_data0", cellular),
            ).findHotspotAddress(),
        )
    }

    @Test
    fun ignoresTheExcludedNamesWithoutCase() {
        val source = FakeSource(
            listOf(
                snapshot("WLAN0", "192.168.1.24"),
                snapshot("AP0", "192.168.43.1"),
            ),
        )

        assertEquals(
            InetAddress.getByName("192.168.43.1"),
            finder(source, observed("WLAN0", wifiClient)).findHotspotAddress(),
        )
    }

    @Test
    fun aBluetoothPanClientIsNotAHotspot() {
        val clientAddress = InetAddress.getByName("192.168.44.2")
        val source = FakeSource(listOf(snapshot("bt-pan0", "192.168.44.2")))

        assertNull(
            finder(source, observed("bt-pan0", bluetoothClient)).findHotspotAddress(),
        )
        val result = probe(source, observed("bt-pan0", bluetoothClient))
        assertTrue(result is HotspotProbe.Observed)
        val observedResult = result as HotspotProbe.Observed
        assertTrue(observedResult.candidates.isEmpty())
        assertTrue(clientAddress in observedResult.excludedAddresses)
    }

    @Test
    fun anUnlistedBtPanNameIsNotAHotspot() {
        // Android uses bt-pan* for a Bluetooth tether and for a Bluetooth PAN
        // client. The name alone is not proof of either role.
        val source = FakeSource(listOf(snapshot("bt-pan0", "192.168.44.2")))

        assertNull(finder(source).findHotspotAddress())
        assertNull(
            finder(source, NetworkInterfaceObservation.Unknown).findHotspotAddress(),
        )
    }

    @Test
    fun aStrongNameReportedAsANetworkIsExcluded() {
        val address = InetAddress.getByName("192.168.43.1")
        val source = FakeSource(listOf(snapshot("ap0", "192.168.43.1")))

        // An OEM build can report the access point as a network. A reported
        // name is an upstream or client interface, so the finder fails closed
        // instead of binding it.
        assertNull(finder(source, observed("ap0", wifiClient)).findHotspotAddress())
        val result = probe(source, observed("ap0", wifiClient))
        assertTrue(result is HotspotProbe.Observed)
        assertTrue(address in (result as HotspotProbe.Observed).excludedAddresses)
    }

    @Test
    fun aCandidateAddressThatAReportedNetworkHoldsIsRejected() {
        val shared = InetAddress.getByName("192.168.43.1")
        val source = FakeSource(
            listOf(
                snapshot("wlan0", "192.168.1.24", "192.168.43.1"),
                snapshot("ap0", "192.168.43.1"),
            ),
        )

        // ap0 has a strong name, but its only private address is also held by
        // the reported wlan0 interface. The finder must not bind it.
        assertNull(finder(source, observed("wlan0", wifiClient)).findHotspotAddress())
        val result = probe(source, observed("wlan0", wifiClient))
        assertTrue(result is HotspotProbe.Observed)
        val observedResult = result as HotspotProbe.Observed
        assertTrue(observedResult.candidates.isEmpty())
        assertTrue(shared in observedResult.excludedAddresses)
    }

    @Test
    fun aCandidatePicksASafeAddressWhenAnotherAddressIsReported() {
        val source = FakeSource(
            listOf(
                snapshot("wlan0", "192.168.1.24", "192.168.43.1"),
                snapshot("ap0", "192.168.43.1", "192.168.44.1"),
            ),
        )

        assertEquals(
            InetAddress.getByName("192.168.44.1"),
            finder(source, observed("wlan0", wifiClient)).findHotspotAddress(),
        )
    }

    @Test
    fun anAutomaticCandidateSurfacesEveryPrivateAddressAndFailsClosedOnTheTie() {
        val first = InetAddress.getByName("192.168.43.1")
        val second = InetAddress.getByName("192.168.44.1")
        val source = FakeSource(
            listOf(snapshot("ap0", "192.168.44.1", "192.168.43.1")),
        )

        val result = probe(source)
        assertTrue(result is HotspotProbe.Observed)
        // The addresses are sorted by value even when the platform lists them
        // in another order. Both have the best rank, so a new start has no
        // unique address and fails closed.
        assertEquals(
            listOf(HotspotCandidate(1, first), HotspotCandidate(1, second)),
            (result as HotspotProbe.Observed).candidates,
        )
        assertNull(finder(source).findHotspotAddress())
    }

    @Test
    fun anAutomaticCandidateUsesTheOnlyPrivateAddressThatStaysSafe() {
        val safe = InetAddress.getByName("192.168.44.1")
        val source = FakeSource(
            listOf(
                snapshot("wlan0", "192.168.43.1"),
                snapshot("ap0", "192.168.43.1", "192.168.44.1"),
            ),
        )

        val result = probe(source, observed("wlan0", wifiClient))
        assertTrue(result is HotspotProbe.Observed)
        assertEquals(
            listOf(HotspotCandidate(1, safe)),
            (result as HotspotProbe.Observed).candidates,
        )
        assertEquals(
            safe,
            finder(source, observed("wlan0", wifiClient)).findHotspotAddress(),
        )
    }

    @Test
    fun reportedNamesAreNormalizedBeforeExclusionAndMatching() {
        val source = FakeSource(
            listOf(
                snapshot(" WLAN0 ", "192.168.1.24"),
                snapshot(" AP0 ", "192.168.43.1"),
            ),
        )

        // The reported name is trimmed and lowercased. It excludes the
        // snapshot with surrounding space. The candidate name is normalized
        // too, so the strong name still applies.
        val finder = finder(source, observed(" WLAN0 ", wifiClient))
        assertEquals(
            InetAddress.getByName("192.168.43.1"),
            finder.findHotspotAddress(),
        )
        val options = finder.selectableInterfaces()
        assertTrue(options.none { it.interfaceName == "wlan0" })
        assertTrue(options.any { it.interfaceName == "ap0" })
    }

    @Test
    fun normalizationChangesTheAutomaticCandidateOutput() {
        val address = InetAddress.getByName("192.168.43.1")
        val source = FakeSource(listOf(snapshot(" AP0 ", "192.168.43.1")))
        val complete = NetworkInterfaceObservation.Complete(emptySet(), emptySet())

        // The padded uppercase name matches the ap prefix only after the
        // snapshot name is normalized.
        assertEquals(
            listOf(HotspotCandidate(1, address)),
            (probe(source, complete) as HotspotProbe.Observed).candidates,
        )
        assertEquals(address, finder(source, complete).findHotspotAddress())
    }

    @Test
    fun normalizationExcludesTheAddressesOfAReportedInterface() {
        val shared = InetAddress.getByName("192.168.43.1")
        val source = FakeSource(
            listOf(
                snapshot(" WLAN0 ", "192.168.1.24", "192.168.43.1"),
                snapshot(" AP0 ", "192.168.43.1"),
            ),
        )

        val result = probe(source, observed(" WLAN0 ", wifiClient))
        assertTrue(result is HotspotProbe.Observed)
        val observedResult = result as HotspotProbe.Observed
        // The reported name and the snapshot name differ in case and space.
        // Without normalizing the snapshot name, the shared address would stay
        // a candidate for the strong ap0 name.
        assertTrue(shared in observedResult.excludedAddresses)
        assertTrue(observedResult.candidates.isEmpty())
        assertNull(
            finder(source, observed(" WLAN0 ", wifiClient)).findHotspotAddress(),
        )
    }

    @Test
    fun aMalformedReportedNameDoesNotConfirmAWlanCandidate() {
        val ap = InetAddress.getByName("192.168.43.1")
        val result = probe(
            FakeSource(
                listOf(
                    snapshot("ap0", "192.168.43.1"),
                    snapshot("wlan1", "192.168.44.1"),
                ),
            ),
            FakeNetwork({ wifiClient }, { "wlan 0" }),
        )

        // The malformed reported name makes the read partial. The strong
        // ap0 name still confirms itself, but the partial read never confirms
        // the unreported wlan1.
        assertTrue(result is HotspotProbe.Observed)
        assertEquals(
            listOf(HotspotCandidate(1, ap)),
            (result as HotspotProbe.Observed).candidates,
        )
    }

    @Test
    fun ignoresInterfacesThatThePlatformMarksVirtualOrPointToPoint() {
        val source = FakeSource(
            listOf(
                snapshot("ap0", "192.168.43.1", virtual = true),
                snapshot("rndis0", "192.168.42.129", pointToPoint = true),
                snapshot("swlan0", "192.168.44.1", virtual = true),
            ),
        )

        assertNull(finder(source).findHotspotAddress())
    }

    @Test
    fun ignoresVirtualAndPointToPointInterfacesFromPlatformEvidence() {
        val source = FakeSource(
            listOf(
                snapshot("ap0", "192.168.43.1", virtual = true),
                snapshot("rndis0", "192.168.42.129", pointToPoint = true),
            ),
        )
        val finder = NetworkInterfaceHotspotAddressFinder(
            source,
            { NetworkInterfaceObservation.Complete(emptySet(), emptySet()) },
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
        val result = finder.probe()
        assertTrue(result is HotspotProbe.Observed)
        assertTrue((result as HotspotProbe.Observed).candidates.isEmpty())
    }

    @Test
    fun rejectsVirtualAndPointToPointInterfacesFromTheChoiceList() {
        val source = FakeSource(
            listOf(
                snapshot("ap0", "192.168.43.1", virtual = true),
                snapshot("rndis0", "192.168.42.129", pointToPoint = true),
                snapshot("wlan1", "192.168.44.1"),
            ),
        )
        val complete = NetworkInterfaceObservation.Complete(emptySet(), emptySet())

        assertEquals(
            listOf(
                HotspotInterfaceOption("wlan1", InetAddress.getByName("192.168.44.1")),
            ),
            selectableHotspotInterfaces(source.interfaces, complete),
        )
    }

    @Test
    fun aPartialObservationKeepsAKnownClientExcluded() {
        val clientAddress = InetAddress.getByName("192.168.1.24")
        val source = FakeSource(
            listOf(
                snapshot("wlan0", "192.168.1.24"),
                snapshot("wlan1", "192.168.43.1"),
            ),
        )
        val partial = observation(
            observed("wlan0", wifiClient),
            FakeNetwork({ null }, { "wlan1" }),
        )

        assertNull(finder(source, partial).findHotspotAddress())
        val result = probe(source, partial)
        assertTrue(result is HotspotProbe.Observed)
        val observedResult = result as HotspotProbe.Observed
        assertTrue(observedResult.candidates.isEmpty())
        assertTrue(clientAddress in observedResult.excludedAddresses)
    }

    @Test
    fun aVpnOverWifiDoesNotConfirmAnotherWlan() {
        val vpnOverWifi = ObservedTransports(isCellular = false, isWifi = true, isVpn = true)
        val source = FakeSource(
            listOf(
                snapshot("wlan0", "192.168.43.1"),
                snapshot("wlan1", "192.168.1.24"),
            ),
        )

        assertNull(
            finder(source, observed("wlan1", vpnOverWifi)).findHotspotAddress(),
        )
    }

    @Test
    fun aWifiStationOverVpnOrCellularDoesNotConfirmAWlan() {
        val vpnOverWifi = ObservedTransports(isCellular = false, isWifi = true, isVpn = true)
        val cellularWifi = ObservedTransports(isCellular = true, isWifi = true, isVpn = false)
        val source = FakeSource(
            listOf(
                snapshot("wifi0", "192.168.1.24"),
                snapshot("wlan1", "192.168.43.1"),
            ),
        )

        // wifi0 has an unambiguous station name, so only the transport guards
        // can reject it. A VPN or cellular view is not a plain Wi-Fi client.
        assertNull(
            finder(source, observed("wifi0", vpnOverWifi)).findHotspotAddress(),
        )
        assertNull(
            finder(source, observed("wifi0", cellularWifi)).findHotspotAddress(),
        )

        // The same name with a plain Wi-Fi transport is the positive control.
        assertEquals(
            InetAddress.getByName("192.168.43.1"),
            finder(source, observed("wifi0", wifiClient)).findHotspotAddress(),
        )
    }

    @Test
    fun probeReportsEveryCandidateEvenWhenOneOutranksAnother() {
        val source = FakeSource(
            listOf(
                snapshot("rndis0", "192.168.42.129"),
                snapshot("swlan0", "192.168.43.1"),
            ),
        )

        val result = probe(source)
        assertTrue(result is HotspotProbe.Observed)
        assertEquals(
            setOf(
                HotspotCandidate(0, InetAddress.getByName("192.168.43.1")),
                HotspotCandidate(3, InetAddress.getByName("192.168.42.129")),
            ),
            (result as HotspotProbe.Observed).candidates.toSet(),
        )
    }

    @Test
    fun nameRanksKeepStrongAccessPointsAboveUsbAndUsbAboveInferredWlan() {
        val source = FakeSource(
            listOf(
                snapshot("wifi0", "192.168.1.24"),
                snapshot("wlan1", "192.168.44.1"),
                snapshot("rndis0", "192.168.43.129"),
                snapshot("ap0", "192.168.42.1"),
                snapshot("softap0", "192.168.45.1"),
                snapshot("swlan0", "192.168.46.1"),
            ),
        )
        val observation = observation(observed("wifi0", wifiClient))

        val result = probe(source, observation)
        assertTrue(result is HotspotProbe.Observed)
        assertEquals(
            setOf(
                HotspotCandidate(0, InetAddress.getByName("192.168.46.1")),
                HotspotCandidate(1, InetAddress.getByName("192.168.42.1")),
                HotspotCandidate(2, InetAddress.getByName("192.168.45.1")),
                HotspotCandidate(3, InetAddress.getByName("192.168.43.129")),
                HotspotCandidate(4, InetAddress.getByName("192.168.44.1")),
            ),
            (result as HotspotProbe.Observed).candidates.toSet(),
        )

        // A strong access point name wins over the USB tether name.
        assertEquals(
            InetAddress.getByName("192.168.42.1"),
            finder(
                FakeSource(
                    listOf(
                        snapshot("ap0", "192.168.42.1"),
                        snapshot("rndis0", "192.168.43.129"),
                    ),
                ),
                observation,
            ).findHotspotAddress(),
        )

        // The strong USB tether name wins over the weak wlan inference.
        assertEquals(
            InetAddress.getByName("192.168.43.129"),
            finder(
                FakeSource(
                    listOf(
                        snapshot("rndis0", "192.168.43.129"),
                        snapshot("wlan1", "192.168.44.1"),
                    ),
                ),
                observation,
            ).findHotspotAddress(),
        )
    }

    @Test
    fun probeReportsAnExcludedAddressEvenWhenTheInterfaceIsDown() {
        val address = InetAddress.getByName("192.168.1.24")
        val source = FakeSource(
            listOf(snapshot("wlan0", "192.168.1.24", up = false)),
        )

        val result = probe(source, observed("wlan0", wifiClient))
        assertTrue(result is HotspotProbe.Observed)
        val observedResult = result as HotspotProbe.Observed
        assertTrue(observedResult.candidates.isEmpty())
        assertTrue(address in observedResult.excludedAddresses)
    }

    @Test
    fun probeReportsUnknownWhenTheInterfaceListFails() {
        assertEquals(
            HotspotProbe.Unknown,
            probe(BrokenSource()),
        )
    }

    // --- Android 15 and earlier: explicit choice ----------------------------

    @Test
    fun anExplicitChoiceSelectsABluetoothTether() {
        val address = InetAddress.getByName("192.168.44.1")
        val source = FakeSource(listOf(snapshot("bt-pan0", "192.168.44.1")))
        val complete = NetworkInterfaceObservation.Complete(emptySet(), emptySet())

        val result = choiceFinder(source, complete, choice("bt-pan0", "192.168.44.1")).probe()

        assertTrue(result is HotspotProbe.Observed)
        val observed = result as HotspotProbe.Observed
        assertEquals(HotspotChoiceOutcome.APPLIED, observed.choiceOutcome)
        assertEquals(listOf(HotspotCandidate(-1, address)), observed.candidates)
        assertEquals(
            address,
            choiceFinder(source, complete, choice("bt-pan0")).findHotspotAddress(),
        )
    }

    @Test
    fun anExplicitChoiceSelectsAGenericUsbTetherWithoutCaseOrSpace() {
        val address = InetAddress.getByName("192.168.42.129")
        val source = FakeSource(listOf(snapshot("USB0", "192.168.42.129")))
        val complete = NetworkInterfaceObservation.Complete(emptySet(), emptySet())

        assertEquals(
            address,
            choiceFinder(source, complete, choice(" usb0 ")).findHotspotAddress(),
        )
    }

    @Test
    fun anExplicitChoiceSelectsAWlanAccessPointWithoutClientEvidence() {
        val address = InetAddress.getByName("192.168.43.1")
        val source = FakeSource(listOf(snapshot("wlan1", "192.168.43.1")))
        val complete = NetworkInterfaceObservation.Complete(emptySet(), emptySet())

        // The automatic rule rejects this name because no Wi-Fi client is
        // reported. The person selected the access point, so the finder accepts
        // the one private address on that interface.
        assertNull(finder(source, complete).findHotspotAddress())
        assertEquals(
            address,
            choiceFinder(source, complete, choice("wlan1")).findHotspotAddress(),
        )
    }

    @Test
    fun anExplicitChoiceCannotOverrideAReportedNetwork() {
        val clientAddress = InetAddress.getByName("192.168.1.24")
        val source = FakeSource(
            listOf(
                snapshot("wlan0", "192.168.1.24"),
                snapshot("wlan1", "192.168.43.1"),
            ),
        )
        val complete = NetworkInterfaceObservation.Complete(
            excludedNames = setOf("wlan0"),
            wifiClientNames = setOf("wlan0"),
        )

        val result = choiceFinder(source, complete, choice("wlan0", "192.168.1.24")).probe()

        assertTrue(result is HotspotProbe.Observed)
        val observed = result as HotspotProbe.Observed
        assertTrue(observed.candidates.isEmpty())
        assertEquals(HotspotChoiceOutcome.REPORTED_NETWORK, observed.choiceOutcome)
        assertTrue(clientAddress in observed.excludedAddresses)
        // The selected path never falls back to the other wlan interface.
        assertNull(choiceFinder(source, complete, choice("wlan0")).findHotspotAddress())
    }

    @Test
    fun anExplicitChoiceDoesNotFallBackWhenTheInterfaceIsGone() {
        val source = FakeSource(listOf(snapshot("ap0", "192.168.43.1")))
        val complete = NetworkInterfaceObservation.Complete(emptySet(), emptySet())

        // The automatic rule would accept ap0. A stale explicit choice must not
        // silently bind that different interface.
        assertChoiceRejected(
            source,
            complete,
            choice("wlan9"),
            HotspotChoiceOutcome.INTERFACE_MISSING,
        )
    }

    @Test
    fun anExplicitChoiceRejectsCellularAndVirtualNames() {
        val complete = NetworkInterfaceObservation.Complete(emptySet(), emptySet())

        assertChoiceRejected(
            FakeSource(listOf(snapshot("rmnet_data0", "10.44.0.9"))),
            complete,
            choice("rmnet_data0"),
            HotspotChoiceOutcome.UNSAFE_INTERFACE,
        )
        assertChoiceRejected(
            FakeSource(listOf(snapshot("wg0", "10.8.0.2"))),
            complete,
            choice("wg0"),
            HotspotChoiceOutcome.UNSAFE_INTERFACE,
        )
    }

    @Test
    fun anExplicitChoiceRejectsDownAndLoopbackInterfaces() {
        val complete = NetworkInterfaceObservation.Complete(emptySet(), emptySet())

        assertChoiceRejected(
            FakeSource(listOf(snapshot("ap0", "192.168.43.1", up = false))),
            complete,
            choice("ap0"),
            HotspotChoiceOutcome.UNSAFE_INTERFACE,
        )
        assertChoiceRejected(
            FakeSource(listOf(snapshot("lo", "127.0.0.1", loopback = true))),
            complete,
            choice("lo"),
            HotspotChoiceOutcome.UNSAFE_INTERFACE,
        )
    }

    @Test
    fun anExplicitChoiceRejectsAVirtualOrPointToPointInterface() {
        val complete = NetworkInterfaceObservation.Complete(emptySet(), emptySet())

        assertChoiceRejected(
            FakeSource(listOf(snapshot("ap0", "192.168.43.1", virtual = true))),
            complete,
            choice("ap0"),
            HotspotChoiceOutcome.UNSAFE_INTERFACE,
        )
        assertChoiceRejected(
            FakeSource(listOf(snapshot("ap0", "192.168.43.1", pointToPoint = true))),
            complete,
            choice("ap0"),
            HotspotChoiceOutcome.UNSAFE_INTERFACE,
        )
    }

    @Test
    fun anExplicitChoiceRejectsAnAddressThatAReportedNetworkHolds() {
        val shared = "192.168.43.1"
        val source = FakeSource(
            listOf(
                snapshot("wlan0", "192.168.1.24", shared),
                snapshot("ap0", shared),
            ),
        )
        val complete = observation(observed("wlan0", wifiClient))

        assertChoiceRejected(
            source,
            complete,
            choice("ap0", shared),
            HotspotChoiceOutcome.UNSAFE_ADDRESS,
        )
        // Without a pinned address, the only private address is unsafe, so
        // the choice cannot bind it either.
        assertChoiceRejected(
            source,
            complete,
            choice("ap0"),
            HotspotChoiceOutcome.UNSAFE_ADDRESS,
        )
    }

    @Test
    fun anExplicitChoiceRejectsPublicAndLinkLocalAddresses() {
        val complete = NetworkInterfaceObservation.Complete(emptySet(), emptySet())

        assertChoiceRejected(
            FakeSource(listOf(snapshot("ap0", "8.8.8.8"))),
            complete,
            choice("ap0"),
            HotspotChoiceOutcome.UNSAFE_ADDRESS,
        )
        assertChoiceRejected(
            FakeSource(listOf(snapshot("ap0", "169.254.3.4"))),
            complete,
            choice("ap0"),
            HotspotChoiceOutcome.UNSAFE_ADDRESS,
        )
        assertChoiceRejected(
            FakeSource(listOf(snapshot("ap0", "8.8.8.8"))),
            complete,
            choice("ap0", "8.8.8.8"),
            HotspotChoiceOutcome.UNSAFE_ADDRESS,
        )
    }

    @Test
    fun anExplicitChoiceRejectsAPinnedAddressFromAnotherInterface() {
        val source = FakeSource(listOf(snapshot("ap0", "192.168.43.1")))
        val complete = NetworkInterfaceObservation.Complete(emptySet(), emptySet())

        assertChoiceRejected(
            source,
            complete,
            choice("ap0", "192.168.44.1"),
            HotspotChoiceOutcome.ADDRESS_MISMATCH,
        )
    }

    @Test
    fun anExplicitChoiceAcceptsAPinnedAddressOnAMultiAddressInterface() {
        val pinned = InetAddress.getByName("192.168.44.1")
        val source = FakeSource(
            listOf(snapshot("ap0", "192.168.43.1", "192.168.44.1")),
        )
        val complete = NetworkInterfaceObservation.Complete(emptySet(), emptySet())

        val result = choiceFinder(source, complete, choice("ap0", "192.168.44.1")).probe()

        assertTrue(result is HotspotProbe.Observed)
        val observed = result as HotspotProbe.Observed
        assertEquals(HotspotChoiceOutcome.APPLIED, observed.choiceOutcome)
        assertEquals(listOf(HotspotCandidate(-1, pinned)), observed.candidates)

        // Without a pinned address the two private addresses are ambiguous.
        assertChoiceRejected(
            source,
            complete,
            choice("ap0"),
            HotspotChoiceOutcome.ADDRESS_AMBIGUOUS,
        )
    }

    @Test
    fun anExplicitChoiceRequiresACompleteNetworkRead() {
        val source = FakeSource(listOf(snapshot("wlan1", "192.168.43.1")))
        val partial = NetworkInterfaceObservation.Partial(setOf("rmnet_data0"))

        assertChoiceRejected(
            source,
            partial,
            choice("wlan1"),
            HotspotChoiceOutcome.EVIDENCE_INCOMPLETE,
        )
        assertChoiceRejected(
            source,
            NetworkInterfaceObservation.Unknown,
            choice("wlan1"),
            HotspotChoiceOutcome.EVIDENCE_INCOMPLETE,
        )
    }

    @Test
    fun anExplicitChoiceStillRejectsAKnownNetworkFromAPartialRead() {
        val source = FakeSource(listOf(snapshot("wlan0", "192.168.1.24")))
        val partial = NetworkInterfaceObservation.Partial(setOf("wlan0"))

        assertChoiceRejected(
            source,
            partial,
            choice("wlan0"),
            HotspotChoiceOutcome.REPORTED_NETWORK,
        )
    }

    @Test
    fun anUnreadableChoiceStoreFailsClosed() {
        val source = FakeSource(listOf(snapshot("ap0", "192.168.43.1")))
        val complete = NetworkInterfaceObservation.Complete(emptySet(), emptySet())
        val finder = NetworkInterfaceHotspotAddressFinder(
            source,
            { complete },
            choiceSource = HotspotInterfaceChoiceSource {
                error("The choice store failed.")
            },
        )

        val result = finder.probe()
        assertTrue(result is HotspotProbe.Observed)
        val observed = result as HotspotProbe.Observed
        assertTrue(observed.candidates.isEmpty())
        assertEquals(HotspotChoiceOutcome.UNREADABLE, observed.choiceOutcome)
        assertNull(finder.findHotspotAddress())
    }

    @Test
    fun anExplicitChoiceRejectsABlankName() {
        val source = FakeSource(listOf(snapshot("ap0", "192.168.43.1")))
        val complete = NetworkInterfaceObservation.Complete(emptySet(), emptySet())

        assertChoiceRejected(
            source,
            complete,
            choice("   "),
            HotspotChoiceOutcome.UNSAFE_INTERFACE,
        )
    }

    @Test
    fun anExplicitChoiceRejectsDuplicateInterfaceNames() {
        val source = FakeSource(
            listOf(
                snapshot("wlan1", "192.168.43.1"),
                snapshot("wlan1", "192.168.44.1"),
            ),
        )
        val complete = NetworkInterfaceObservation.Complete(emptySet(), emptySet())

        assertChoiceRejected(
            source,
            complete,
            choice("wlan1"),
            HotspotChoiceOutcome.INTERFACE_AMBIGUOUS,
        )
    }

    @Test
    fun theExplicitChoiceIsReadAgainOnEveryProbe() {
        val source = FakeSource(
            listOf(
                snapshot("bt-pan0", "192.168.44.1"),
                snapshot("wlan1", "192.168.43.1"),
                snapshot("ap0", "192.168.45.1"),
            ),
        )
        val complete = NetworkInterfaceObservation.Complete(emptySet(), emptySet())
        var selected: HotspotInterfaceChoice = choice("bt-pan0", "192.168.44.1")
        val finder = NetworkInterfaceHotspotAddressFinder(
            source,
            { complete },
            choiceSource = HotspotInterfaceChoiceSource { selected },
        )

        assertEquals(
            InetAddress.getByName("192.168.44.1"),
            finder.findHotspotAddress(),
        )

        selected = choice("wlan1", "192.168.43.1")
        assertEquals(
            InetAddress.getByName("192.168.43.1"),
            finder.findHotspotAddress(),
        )

        selected = HotspotInterfaceChoice.Automatic
        assertEquals(
            InetAddress.getByName("192.168.45.1"),
            finder.findHotspotAddress(),
        )
    }

    @Test
    fun anAutomaticChoiceKeepsTheNameRules() {
        val address = InetAddress.getByName("192.168.43.1")
        val source = FakeSource(listOf(snapshot("ap0", "192.168.43.1")))
        val complete = NetworkInterfaceObservation.Complete(emptySet(), emptySet())
        val finder = choiceFinder(source, complete, HotspotInterfaceChoice.Automatic)

        val result = finder.probe()
        assertTrue(result is HotspotProbe.Observed)
        val observed = result as HotspotProbe.Observed
        assertEquals(HotspotChoiceOutcome.AUTOMATIC, observed.choiceOutcome)
        assertEquals(listOf(HotspotCandidate(1, address)), observed.candidates)
    }

    @Test
    fun platformEvidenceRejectsAnAddressThatAReportedNetworkHolds() {
        val shared = InetAddress.getByName("192.168.43.1")
        val source = FakeSource(
            listOf(
                snapshot("wlan0", "192.168.1.24", "192.168.43.1"),
                snapshot("ap0", "192.168.43.1"),
            ),
        )
        val finder = NetworkInterfaceHotspotAddressFinder(
            source,
            { observation(observed("wlan0", wifiClient)) },
            TetheredInterfaceEvidenceSource {
                TetheredInterfaceState.Known(
                    mapOf("ap0" to TetheredInterfaceKind.WIFI),
                )
            },
        )

        assertNull(finder.findHotspotAddress())
        val result = finder.probe()
        assertTrue(result is HotspotProbe.Observed)
        val observed = result as HotspotProbe.Observed
        assertTrue(observed.candidates.isEmpty())
        assertTrue(shared in observed.excludedAddresses)
    }

    @Test
    fun platformEvidenceSurfacesEveryPrivateAddressAndFailsClosedOnTheTie() {
        val first = InetAddress.getByName("10.42.0.1")
        val second = InetAddress.getByName("10.42.0.2")
        val source = FakeSource(
            listOf(snapshot("rndis0", "10.42.0.2", "10.42.0.1")),
        )
        val finder = NetworkInterfaceHotspotAddressFinder(
            source,
            { NetworkInterfaceObservation.Complete(emptySet(), emptySet()) },
            TetheredInterfaceEvidenceSource {
                TetheredInterfaceState.Known(
                    mapOf("rndis0" to TetheredInterfaceKind.USB),
                )
            },
        )

        val result = finder.probe()
        assertTrue(result is HotspotProbe.Observed)
        // The named interface has two safe private IPv4 addresses. The finder
        // surfaces both in numeric order and leaves the best rank tied.
        assertEquals(
            listOf(
                HotspotCandidate(TetheredInterfaceKind.USB.rank, first),
                HotspotCandidate(TetheredInterfaceKind.USB.rank, second),
            ),
            (result as HotspotProbe.Observed).candidates,
        )
        assertNull(finder.findHotspotAddress())
    }

    @Test
    fun platformEvidenceWinsAndDoesNotReadTheChoice() {
        val address = InetAddress.getByName("192.168.43.1")
        val source = FakeSource(
            listOf(
                snapshot("ap0", "192.168.44.1"),
                snapshot("wlan1", "192.168.43.1"),
            ),
        )
        val complete = NetworkInterfaceObservation.Complete(emptySet(), emptySet())
        val finder = NetworkInterfaceHotspotAddressFinder(
            source,
            { complete },
            TetheredInterfaceEvidenceSource {
                TetheredInterfaceState.Known(setOf("wlan1"))
            },
            HotspotInterfaceChoiceSource {
                error("The API 36 path must not read the explicit choice.")
            },
        )

        val result = finder.probe()
        assertTrue(result is HotspotProbe.Observed)
        val observed = result as HotspotProbe.Observed
        assertEquals(HotspotChoiceOutcome.PLATFORM_EVIDENCE, observed.choiceOutcome)
        assertEquals(listOf(HotspotCandidate(0, address)), observed.candidates)
    }

    @Test
    fun platformEvidenceReturnsTheSoleNamedCandidateAndIgnoresAnUnnamedStrongName() {
        val address = InetAddress.getByName("192.168.42.129")
        val source = FakeSource(
            listOf(
                snapshot(" AP0 ", "192.168.43.1"),
                snapshot(" RNDIS0 ", "192.168.42.129"),
            ),
        )
        val finder = NetworkInterfaceHotspotAddressFinder(
            source,
            { NetworkInterfaceObservation.Complete(emptySet(), emptySet()) },
            TetheredInterfaceEvidenceSource {
                TetheredInterfaceState.Known(
                    mapOf(" RNDIS0 " to TetheredInterfaceKind.USB),
                )
            },
            HotspotInterfaceChoiceSource {
                error("The API 36 path must not read the explicit choice.")
            },
        )

        val result = finder.probe()
        assertTrue(result is HotspotProbe.Observed)
        val observed = result as HotspotProbe.Observed
        assertEquals(HotspotChoiceOutcome.PLATFORM_EVIDENCE, observed.choiceOutcome)
        // The platform named only rndis0, and both the map key and the local
        // name are normalized. The unnamed strong ap0 name must not appear.
        assertEquals(
            listOf(HotspotCandidate(TetheredInterfaceKind.USB.rank, address)),
            observed.candidates,
        )
        assertEquals(address, finder.findHotspotAddress())
    }

    @Test
    fun knownEmptyPlatformEvidenceReturnsNoCandidateAndDoesNotReadTheChoice() {
        val source = FakeSource(listOf(snapshot("ap0", "192.168.43.1")))
        var choiceRead = false
        val finder = NetworkInterfaceHotspotAddressFinder(
            source,
            { NetworkInterfaceObservation.Complete(emptySet(), emptySet()) },
            TetheredInterfaceEvidenceSource {
                TetheredInterfaceState.Known(emptyMap())
            },
            HotspotInterfaceChoiceSource {
                choiceRead = true
                error("The API 36 empty set must not read the explicit choice.")
            },
        )

        val result = finder.probe()
        assertTrue(result is HotspotProbe.Observed)
        val observed = result as HotspotProbe.Observed
        // An empty known set is authoritative. The name rules would accept
        // ap0, so a fallback would be visible here.
        assertTrue(observed.candidates.isEmpty())
        assertEquals(HotspotChoiceOutcome.PLATFORM_EVIDENCE, observed.choiceOutcome)
        assertNull(finder.findHotspotAddress())
        assertTrue(!choiceRead)
    }

    @Test
    fun aPendingPlatformReadStaysPendingAndDoesNotReadTheChoice() {
        val source = FakeSource(listOf(snapshot("ap0", "192.168.43.1")))
        val complete = NetworkInterfaceObservation.Complete(emptySet(), emptySet())
        var choiceRead = false
        val finder = NetworkInterfaceHotspotAddressFinder(
            source,
            { complete },
            TetheredInterfaceEvidenceSource {
                TetheredInterfaceState.AwaitingFirstReading
            },
            HotspotInterfaceChoiceSource {
                choiceRead = true
                choice("ap0")
            },
        )

        assertEquals(HotspotProbe.Pending, finder.probe())
        assertTrue(!choiceRead)
    }

    @Test
    fun aBlankSavedChoiceMeansAutomatic() {
        val address = InetAddress.getByName("192.168.43.1")

        assertEquals(
            HotspotInterfaceChoice.Automatic,
            savedHotspotInterfaceChoice(null),
        )
        assertEquals(
            HotspotInterfaceChoice.Automatic,
            savedHotspotInterfaceChoice("   "),
        )
        assertEquals(
            HotspotInterfaceChoice.Selected("wlan1", address),
            savedHotspotInterfaceChoice("wlan1", address),
        )
    }

    // --- Choice list for a settings screen ----------------------------------

    @Test
    fun selectableOptionsExposeOnlySafeInterfacesWithPrivateAddresses() {
        val source = FakeSource(
            listOf(
                snapshot("wlan0", "192.168.1.24"),
                snapshot("wlan1", "192.168.43.1"),
                snapshot("bt-pan0", "192.168.44.1"),
                snapshot("rmnet_data0", "10.44.0.9"),
                snapshot("wg0", "10.8.0.2"),
                snapshot("ap0", "192.168.45.1", up = false),
                snapshot("eth0", "10.0.2.15"),
                snapshot("wlan2", "8.8.8.8"),
                snapshot("wlan3", "169.254.3.4"),
            ),
        )
        val complete = observation(
            observed("wlan0", wifiClient),
            observed("rmnet_data0", cellular),
        )

        assertEquals(
            listOf(
                HotspotInterfaceOption("bt-pan0", InetAddress.getByName("192.168.44.1")),
                HotspotInterfaceOption("eth0", InetAddress.getByName("10.0.2.15")),
                HotspotInterfaceOption("wlan1", InetAddress.getByName("192.168.43.1")),
            ),
            selectableHotspotInterfaces(source.interfaces, complete),
        )
    }

    @Test
    fun theFinderOffersTheSameSafeChoiceList() {
        val source = FakeSource(
            listOf(
                snapshot("wlan0", "192.168.1.24"),
                snapshot("wlan1", "192.168.43.1"),
                snapshot("bt-pan0", "192.168.44.1"),
            ),
        )
        val finder = finder(
            source,
            observed("wlan0", wifiClient),
            observed("rmnet_data0", cellular),
        )

        assertEquals(
            listOf(
                HotspotInterfaceOption("bt-pan0", InetAddress.getByName("192.168.44.1")),
                HotspotInterfaceOption("wlan1", InetAddress.getByName("192.168.43.1")),
            ),
            finder.selectableInterfaces(),
        )
    }

    @Test
    fun selectableChoicesAreEmptyWhenAPlatformReadFails() {
        val brokenInterfaces = NetworkInterfaceHotspotAddressFinder(
            BrokenSource(),
            { NetworkInterfaceObservation.Complete(emptySet(), emptySet()) },
        )
        assertEquals(
            emptyList<HotspotInterfaceOption>(),
            brokenInterfaces.selectableInterfaces(),
        )

        val brokenObservation = NetworkInterfaceHotspotAddressFinder(
            FakeSource(listOf(snapshot("wlan1", "192.168.43.1"))),
            { error("The network read failed.") },
        )
        assertEquals(
            emptyList<HotspotInterfaceOption>(),
            brokenObservation.selectableInterfaces(),
        )
    }

    @Test
    fun selectableOptionsNeedACompleteNetworkRead() {
        val source = FakeSource(listOf(snapshot("wlan1", "192.168.43.1")))

        assertEquals(
            emptyList<HotspotInterfaceOption>(),
            selectableHotspotInterfaces(
                source.interfaces,
                NetworkInterfaceObservation.Partial(emptySet()),
            ),
        )
        assertEquals(
            emptyList<HotspotInterfaceOption>(),
            selectableHotspotInterfaces(
                source.interfaces,
                NetworkInterfaceObservation.Unknown,
            ),
        )
    }

    @Test
    fun selectableOptionsListEveryPrivateAddressForPinning() {
        val source = FakeSource(
            listOf(snapshot("ap0", "192.168.43.1", "192.168.44.1")),
        )
        val complete = NetworkInterfaceObservation.Complete(emptySet(), emptySet())

        assertEquals(
            listOf(
                HotspotInterfaceOption("ap0", InetAddress.getByName("192.168.43.1")),
                HotspotInterfaceOption("ap0", InetAddress.getByName("192.168.44.1")),
            ),
            selectableHotspotInterfaces(source.interfaces, complete),
        )
    }

    @Test
    fun selectableOptionsRejectDuplicateInterfaceNames() {
        val source = FakeSource(
            listOf(
                snapshot("wlan1", "192.168.43.1"),
                snapshot("wlan1", "192.168.44.1"),
            ),
        )

        assertEquals(
            emptyList<HotspotInterfaceOption>(),
            selectableHotspotInterfaces(
                source.interfaces,
                NetworkInterfaceObservation.Complete(emptySet(), emptySet()),
            ),
        )
    }

    @Test
    fun selectableOptionsRejectAddressesThatAReportedNetworkHolds() {
        val source = FakeSource(
            listOf(
                snapshot("wlan0", "192.168.1.24", "192.168.43.1"),
                snapshot("ap0", "192.168.43.1", "192.168.44.1"),
            ),
        )
        val complete = observation(observed("wlan0", wifiClient))

        assertEquals(
            listOf(
                HotspotInterfaceOption("ap0", InetAddress.getByName("192.168.44.1")),
            ),
            selectableHotspotInterfaces(source.interfaces, complete),
        )
    }

    @Test
    fun selectableOptionsUseNormalizedInterfaceNames() {
        val source = FakeSource(listOf(snapshot(" AP0 ", "192.168.43.1")))
        val complete = NetworkInterfaceObservation.Complete(emptySet(), emptySet())

        assertEquals(
            listOf(
                HotspotInterfaceOption("ap0", InetAddress.getByName("192.168.43.1")),
            ),
            selectableHotspotInterfaces(source.interfaces, complete),
        )
    }
}
