package com.hotspotshade.source

import android.annotation.SuppressLint
import android.content.SharedPreferences
import com.hotspotshade.source.pairing.PeerAddress

/**
 * Serialize an explicit hotspot interface choice to and from the two strings
 * that [SharedPreferences] holds.
 *
 * The codec is pure and JVM-testable. It reads a numeric IPv4 literal only, so
 * it never performs a DNS lookup. A blank name means
 * [HotspotInterfaceChoice.Automatic], exactly as [savedHotspotInterfaceChoice]
 * defines it.
 */
internal object HotspotInterfaceChoiceCodec {
    /** Decode the two stored strings into a choice. */
    fun decode(name: String?, address: String?): HotspotInterfaceChoice {
        val pinned = address?.let(PeerAddress::parseIpv4)
        return savedHotspotInterfaceChoice(name, pinned)
    }

    /** The name string for one choice, or null for Automatic. */
    fun encodeName(choice: HotspotInterfaceChoice): String? = when (choice) {
        HotspotInterfaceChoice.Automatic -> null
        is HotspotInterfaceChoice.Selected -> choice.interfaceName
    }

    /** The address string for one choice, or null when none is pinned. */
    fun encodeAddress(choice: HotspotInterfaceChoice): String? = when (choice) {
        HotspotInterfaceChoice.Automatic -> null
        is HotspotInterfaceChoice.Selected -> choice.address?.hostAddress
    }
}

/**
 * Store the person's explicit hotspot interface choice.
 *
 * The stored value is a name and, optionally, a pinned private IPv4 address.
 * It is not secret. A blank name clears the choice back to Automatic. The
 * finder revalidates the stored choice on every probe, so a stale name fails
 * closed instead of binding a different interface.
 */
internal class HotspotInterfaceChoiceStore(
    private val preferences: SharedPreferences,
) {
    /** Read the stored choice. A missing or blank name is Automatic. */
    fun load(): HotspotInterfaceChoice = HotspotInterfaceChoiceCodec.decode(
        preferences.getString(KEY_NAME, null),
        preferences.getString(KEY_ADDRESS, null),
    )

    /**
     * Persist one choice. A null or blank [name] clears the stored choice.
     *
     * The write commits synchronously so the choice is durable for the next
     * proxy start. A failed write throws, and the caller reports it instead of
     * pretending the choice was saved.
     */
    @SuppressLint("ApplySharedPref")
    fun save(name: String?, address: String? = null) {
        val editor = preferences.edit()
        val trimmed = name?.trim()
        if (trimmed.isNullOrEmpty()) {
            editor.remove(KEY_NAME)
            editor.remove(KEY_ADDRESS)
        } else {
            editor.putString(KEY_NAME, trimmed)
            if (address.isNullOrBlank()) {
                editor.remove(KEY_ADDRESS)
            } else {
                editor.putString(KEY_ADDRESS, address)
            }
        }
        val saved = try {
            editor.commit()
        } catch (_: Exception) {
            false
        }
        if (!saved) throw IllegalStateException("The hotspot interface choice could not be saved.")
    }

    private companion object {
        const val KEY_NAME = "hotspot-interface-name"
        const val KEY_ADDRESS = "hotspot-interface-address"
    }
}
