package com.hotspotshade.source

import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Tests for the explicit hotspot interface choice codec.
 *
 * The SharedPreferences-backed store delegates to this codec, so the round
 * trip between the stored strings and the choice is covered here on the JVM
 * without Android.
 */
class HotspotInterfaceChoiceStoreTest {
    @Test
    fun aBlankNameDecodesToAutomatic() {
        assertEquals(
            HotspotInterfaceChoice.Automatic,
            HotspotInterfaceChoiceCodec.decode(null, null),
        )
        assertEquals(
            HotspotInterfaceChoice.Automatic,
            HotspotInterfaceChoiceCodec.decode("   ", null),
        )
    }

    @Test
    fun aNameWithoutAnAddressDecodesToSelected() {
        assertEquals(
            HotspotInterfaceChoice.Selected("wlan1"),
            HotspotInterfaceChoiceCodec.decode("wlan1", null),
        )
    }

    @Test
    fun aNameAndAddressRoundTripThroughTheCodec() {
        val address = InetAddress.getByName("192.168.43.1")
        val choice = HotspotInterfaceChoice.Selected("wlan1", address)

        assertEquals("wlan1", HotspotInterfaceChoiceCodec.encodeName(choice))
        assertEquals("192.168.43.1", HotspotInterfaceChoiceCodec.encodeAddress(choice))
        assertEquals(
            choice,
            HotspotInterfaceChoiceCodec.decode(
                HotspotInterfaceChoiceCodec.encodeName(choice),
                HotspotInterfaceChoiceCodec.encodeAddress(choice),
            ),
        )
    }

    @Test
    fun anAutomaticChoiceRoundTripsToNulls() {
        assertNull(HotspotInterfaceChoiceCodec.encodeName(HotspotInterfaceChoice.Automatic))
        assertNull(HotspotInterfaceChoiceCodec.encodeAddress(HotspotInterfaceChoice.Automatic))
        assertEquals(
            HotspotInterfaceChoice.Automatic,
            HotspotInterfaceChoiceCodec.decode(
                HotspotInterfaceChoiceCodec.encodeName(HotspotInterfaceChoice.Automatic),
                HotspotInterfaceChoiceCodec.encodeAddress(HotspotInterfaceChoice.Automatic),
            ),
        )
    }

    @Test
    fun aMalformedAddressDecodesToASelectedNameWithoutAnAddress() {
        // A bad stored address must never cause a DNS lookup or a crash. It is
        // dropped, leaving a name-only selection.
        assertEquals(
            HotspotInterfaceChoice.Selected("wlan1"),
            HotspotInterfaceChoiceCodec.decode("wlan1", "not-an-address"),
        )
        assertEquals(
            HotspotInterfaceChoice.Selected("wlan1"),
            HotspotInterfaceChoiceCodec.decode("wlan1", "999.1.1.1"),
        )
    }
}
