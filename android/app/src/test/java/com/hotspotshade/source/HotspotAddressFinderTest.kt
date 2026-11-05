package com.hotspotshade.source

import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class HotspotAddressFinderTest {
    private class FakeSource(var interfaces: List<InterfaceSnapshot>) : InterfaceSource {
        override fun read(): List<InterfaceSnapshot> = interfaces
    }

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

    private fun finder(
        source: InterfaceSource,
        excluded: Set<String> = emptySet(),
    ) = NetworkInterfaceHotspotAddressFinder(source) { excluded }

    @Test
    fun findsTheHotspotNextToTheWifiClientInterface() {
        val source = FakeSource(
            listOf(
                snapshot("wlan0", "192.168.1.24"),
                snapshot("ap0", "192.168.43.1"),
                snapshot("rmnet_data0", "10.44.0.9"),
            ),
        )

        val address = finder(source, setOf("wlan0", "rmnet_data0")).findHotspotAddress()

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

        val address = finder(source).findHotspotAddress()

        assertEquals(InetAddress.getByName("192.168.42.129"), address)
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
    fun usesAWlanInterfaceWithANonZeroIndex() {
        val source = FakeSource(
            listOf(
                snapshot("wlan0", "192.168.1.24"),
                snapshot("wlan1", "192.168.43.1"),
            ),
        )

        assertEquals(
            InetAddress.getByName("192.168.43.1"),
            finder(source).findHotspotAddress(),
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

        assertNull(finder(source).findHotspotAddress())
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
            ),
        )

        assertNull(finder(source).findHotspotAddress())
    }

    @Test
    fun returnsNullWhenTheDeviceHasNoHotspot() {
        val source = FakeSource(
            listOf(
                snapshot("wlan0", "192.168.1.24"),
                snapshot("rmnet_data0", "10.44.0.9"),
            ),
        )

        assertNull(finder(source, setOf("wlan0", "rmnet_data0")).findHotspotAddress())
    }

    @Test
    fun findsAGenericPrivateInterfaceWhenItIsTheOnlyCandidate() {
        val source = FakeSource(listOf(snapshot("eth0", "10.0.2.15")))

        assertEquals(
            InetAddress.getByName("10.0.2.15"),
            finder(source).findHotspotAddress(),
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
            finder(source, setOf("wlan0")).findHotspotAddress(),
        )
    }

    @Test
    fun findsTheHotspotWhenTheExclusionCallFails() {
        val source = FakeSource(listOf(snapshot("ap0", "192.168.43.1")))
        val finder = NetworkInterfaceHotspotAddressFinder(source) {
            throw IllegalStateException("The connectivity service is gone.")
        }

        assertTrue(finder.findHotspotAddress() != null)
    }
}
