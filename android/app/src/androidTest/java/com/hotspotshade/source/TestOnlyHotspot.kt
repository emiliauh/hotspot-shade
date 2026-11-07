package com.hotspotshade.source

import java.net.InetAddress

/**
 * Test-only hotspot values for the emulator.
 *
 * This file is in the `androidTest` source set. Gradle compiles it only for
 * the debug instrumented test APK. The release app does not compile it, so a
 * release build cannot get a test hotspot address.
 *
 * The emulator has no tethering interface. A test that needs a hotspot address
 * names one here. It does not change the production finder.
 */
internal object TestOnlyHotspot {
    /** The loopback address. A pairing test binds it directly. */
    val LOOPBACK: InetAddress = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))

    /** The emulator's own non-loopback address, for the service test. */
    val EMULATOR_ADDRESS: InetAddress =
        InetAddress.getByAddress(byteArrayOf(10, 0, 2, 15))
}

/** Report one test-only tethering address. */
internal class TestOnlyHotspotFinder(
    private val address: InetAddress = TestOnlyHotspot.LOOPBACK,
) : HotspotAddressFinder {
    override fun probe(): HotspotProbe = HotspotProbe.Observed(
        candidates = listOf(HotspotCandidate(rank = 0, address = address)),
        excludedAddresses = emptySet(),
    )
}
