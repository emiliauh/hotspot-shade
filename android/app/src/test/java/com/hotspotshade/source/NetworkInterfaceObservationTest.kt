package com.hotspotshade.source

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests for the network observation.
 *
 * Every reported name is excluded because it can be an upstream network, a
 * client network, or a vendor-reported access point. A reported Wi-Fi network
 * is not automatically a station: an OEM build can report the access point,
 * and a `wlan*` name is ambiguous. Only a reported Wi-Fi name outside the
 * tether name prefixes is kept as client evidence. A missing platform value
 * makes the read partial. A partial read keeps the names that it read and
 * never confirms a Wi-Fi client, because one missing name could hide the
 * station interface.
 */
class NetworkInterfaceObservationTest {
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

    private fun network(name: String, transports: ObservedTransports) =
        FakeNetwork({ transports }, { name })

    private fun read(vararg networks: ObservedNetwork): NetworkInterfaceObservation =
        NetworkInterfaceObservationReader { networks.toList() }.read()

    @Test
    fun anEmptyListIsComplete() {
        assertEquals(
            NetworkInterfaceObservation.Complete(emptySet(), emptySet()),
            read(),
        )
    }

    @Test
    fun everyReportedNameIsExcluded() {
        val observation = read(
            network("rmnet_data0", cellular),
            network("wlan0", wifiClient),
            network("wifi0", wifiClient),
            network("tun0", vpn),
            network("eth0", ObservedTransports(false, false, false)),
            network("bt-pan0", ObservedTransports(false, false, false)),
        )

        assertEquals(
            NetworkInterfaceObservation.Complete(
                excludedNames = setOf(
                    "rmnet_data0",
                    "wlan0",
                    "wifi0",
                    "tun0",
                    "eth0",
                    "bt-pan0",
                ),
                // wlan0 is ambiguous: it can be the station or the access
                // point. wifi0 is an unambiguous station name.
                wifiClientNames = setOf("wifi0"),
            ),
            observation,
        )
    }

    @Test
    fun aReportedAccessPointIsExcludedButIsNotClientEvidence() {
        val observation = read(
            network("ap0", wifiClient),
            network("softap0", wifiClient),
            network("swlan0", wifiClient),
            network("rndis0", wifiClient),
        )

        assertTrue(observation is NetworkInterfaceObservation.Complete)
        val complete = observation as NetworkInterfaceObservation.Complete
        assertEquals(
            setOf("ap0", "softap0", "swlan0", "rndis0"),
            complete.excludedNames,
        )
        assertTrue(complete.wifiClientNames.isEmpty())
    }

    @Test
    fun aReportedWlanIsAmbiguousAndIsNotClientEvidence() {
        val observation = read(network("wlan0", wifiClient))

        assertEquals(
            NetworkInterfaceObservation.Complete(
                excludedNames = setOf("wlan0"),
                wifiClientNames = emptySet(),
            ),
            observation,
        )
    }

    @Test
    fun aReportedStationOutsideTheHotspotNamespaceIsClientEvidence() {
        val observation = read(
            network("wifi0", wifiClient),
            network("wl0", wifiClient),
        )

        assertEquals(
            NetworkInterfaceObservation.Complete(
                excludedNames = setOf("wifi0", "wl0"),
                wifiClientNames = setOf("wifi0", "wl0"),
            ),
            observation,
        )
    }

    @Test
    fun reportedNamesAreTrimmedBeforeComparison() {
        val observation = read(
            network(" WLAN0 ", wifiClient),
            network(" WIFI0 ", wifiClient),
        )

        assertEquals(
            NetworkInterfaceObservation.Complete(
                excludedNames = setOf("wlan0", "wifi0"),
                wifiClientNames = setOf("wifi0"),
            ),
            observation,
        )
    }

    @Test
    fun aMalformedReportedNameMakesTheObservationPartial() {
        val observation = read(
            network("wlan0", wifiClient),
            network("wlan 1", wifiClient),
        )

        assertEquals(
            NetworkInterfaceObservation.Partial(excludedNames = setOf("wlan0")),
            observation,
        )
    }

    @Test
    fun anAliasOrPathSeparatorMakesTheNameMalformed() {
        assertEquals(
            NetworkInterfaceObservation.Partial(emptySet()),
            read(network("wlan0@if2", wifiClient)),
        )
        assertEquals(
            NetworkInterfaceObservation.Partial(emptySet()),
            read(network("wlan0/1", wifiClient)),
        )
    }

    @Test
    fun aMissingCapabilityKeepsTheNameExcluded() {
        val observation = read(
            network("rmnet_data0", cellular),
            FakeNetwork({ null }, { "wlan0" }),
        )

        assertEquals(
            NetworkInterfaceObservation.Partial(
                excludedNames = setOf("rmnet_data0", "wlan0"),
            ),
            observation,
        )
    }

    @Test
    fun aThrownCapabilityCallKeepsTheNameExcluded() {
        val observation = read(
            network("rmnet_data0", cellular),
            FakeNetwork({ error("The platform refused the capability read.") }, { "wlan0" }),
        )

        assertEquals(
            NetworkInterfaceObservation.Partial(
                excludedNames = setOf("rmnet_data0", "wlan0"),
            ),
            observation,
        )
    }

    @Test
    fun aMissingInterfaceNameMakesTheObservationPartial() {
        val observation = read(
            FakeNetwork({ wifiClient }, { null }),
        )

        assertEquals(NetworkInterfaceObservation.Partial(emptySet()), observation)
    }

    @Test
    fun aBlankInterfaceNameMakesTheObservationPartial() {
        val observation = read(
            FakeNetwork({ wifiClient }, { " " }),
        )

        assertEquals(NetworkInterfaceObservation.Partial(emptySet()), observation)
    }

    @Test
    fun aThrownInterfaceNameCallMakesTheObservationPartial() {
        val observation = read(
            FakeNetwork({ cellular }, { error("The platform refused the link read.") }),
        )

        assertEquals(NetworkInterfaceObservation.Partial(emptySet()), observation)
    }

    @Test
    fun aThrownNetworkListMakesTheObservationUnknown() {
        val observation = NetworkInterfaceObservationReader {
            throw IllegalStateException("The platform refused the network list.")
        }.read()

        assertEquals(NetworkInterfaceObservation.Unknown, observation)
    }

    @Test
    fun oneIncompleteEntryKeepsTheNamesThatWereRead() {
        val observation = read(
            network("wlan0", wifiClient),
            network("rmnet_data0", cellular),
            FakeNetwork({ wifiClient }, { "wlan1" }),
            FakeNetwork({ wifiClient }, { null }),
        )

        assertEquals(
            NetworkInterfaceObservation.Partial(
                excludedNames = setOf("wlan0", "rmnet_data0", "wlan1"),
            ),
            observation,
        )
    }

    @Test
    fun aPartialReadHasNoWifiClientEvidence() {
        val observation = read(
            network("wifi0", wifiClient),
            FakeNetwork({ null }, { "wlan1" }),
        )

        assertTrue(observation is NetworkInterfaceObservation.Partial)
        val partial = observation as NetworkInterfaceObservation.Partial
        assertTrue("wifi0" in partial.excludedNames)
        assertTrue("wlan1" in partial.excludedNames)
        assertTrue(partial.wifiClientNames.isEmpty())
    }

    @Test
    fun aVpnOverWifiIsNotPositiveWifiClientEvidence() {
        val vpnOverWifi = ObservedTransports(isCellular = false, isWifi = true, isVpn = true)
        val observation = read(
            network("rmnet_data0", cellular),
            network("tun0", vpnOverWifi),
        )

        assertTrue(observation is NetworkInterfaceObservation.Complete)
        val complete = observation as NetworkInterfaceObservation.Complete
        assertTrue(complete.wifiClientNames.isEmpty())
        assertTrue("tun0" in complete.excludedNames)
    }

    @Test
    fun aWifiVpnNameIsExcludedAndNotAClient() {
        // Some VPNs report the underlying Wi-Fi interface on a network that
        // also carries the VPN transport. It is still an upstream network.
        val vpnOverWifi = ObservedTransports(isCellular = false, isWifi = true, isVpn = true)
        val observation = read(network("wlan0", vpnOverWifi))

        assertEquals(
            NetworkInterfaceObservation.Complete(
                excludedNames = setOf("wlan0"),
                wifiClientNames = emptySet(),
            ),
            observation,
        )
    }

    @Test
    fun aCellularNetworkIsNotPositiveWifiClientEvidence() {
        val cellularAndWifi = ObservedTransports(
            isCellular = true,
            isWifi = true,
            isVpn = false,
        )
        val observation = read(network("wlan0", cellularAndWifi))

        assertTrue(observation is NetworkInterfaceObservation.Complete)
        val complete = observation as NetworkInterfaceObservation.Complete
        assertTrue(complete.wifiClientNames.isEmpty())
        assertTrue("wlan0" in complete.excludedNames)
    }

    @Test
    fun namesCompareWithoutCase() {
        val observation = read(network("WIFI0", wifiClient))

        assertEquals(
            NetworkInterfaceObservation.Complete(
                excludedNames = setOf("wifi0"),
                wifiClientNames = setOf("wifi0"),
            ),
            observation,
        )
    }
}
