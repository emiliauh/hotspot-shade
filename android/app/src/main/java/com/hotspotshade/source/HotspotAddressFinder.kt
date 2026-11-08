package com.hotspotshade.source

import java.net.Inet4Address
import java.net.InetAddress
import java.net.NetworkInterface
import java.util.Locale

/**
 * One local network interface and its addresses. A JVM test supplies these.
 *
 * [isVirtual] and [isPointToPoint] come from [NetworkInterface]. They are
 * platform hints, not proof: a vendor interface can report neither flag and
 * still be a tunnel or a bridge. The finder also applies a name guard.
 */
internal class InterfaceSnapshot(
    val name: String,
    val isUp: Boolean,
    val isLoopback: Boolean,
    val addresses: List<InetAddress>,
    val isVirtual: Boolean = false,
    val isPointToPoint: Boolean = false,
)

/** Read the local network interfaces. */
internal fun interface InterfaceSource {
    fun read(): List<InterfaceSnapshot>
}

/** Read the local interfaces with java.net.NetworkInterface. */
internal class PlatformInterfaceSource : InterfaceSource {
    override fun read(): List<InterfaceSnapshot> {
        val result = mutableListOf<InterfaceSnapshot>()
        val interfaces = try {
            NetworkInterface.getNetworkInterfaces()
        } catch (_: Exception) {
            return result
        } ?: return result
        for (networkInterface in interfaces) {
            try {
                result += InterfaceSnapshot(
                    name = networkInterface.name,
                    isUp = networkInterface.isUp,
                    isLoopback = networkInterface.isLoopback,
                    addresses = networkInterface.interfaceAddresses.map { it.address },
                    isVirtual = networkInterface.isVirtual,
                    isPointToPoint = networkInterface.isPointToPoint,
                )
            } catch (_: Exception) {
                // An interface can vanish while it is read. Skip it.
            }
        }
        return result
    }
}

/**
 * The transports that ConnectivityManager reports for one network.
 *
 * The transport flags do not decide exclusion. Every network that the platform
 * reports is an upstream or client network, so its interface name is excluded
 * whatever the transports are. A Wi-Fi flag does not prove a client role: an
 * OEM build can report the access point on a Wi-Fi network, and a `wlan*` name
 * is ambiguous. Only a reported Wi-Fi network on a name outside the tether
 * name prefixes becomes station evidence.
 */
internal class ObservedTransports(
    val isCellular: Boolean,
    val isWifi: Boolean,
    val isVpn: Boolean,
)

/**
 * One network from ConnectivityManager. A JVM test supplies a fake.
 *
 * A method returns null when the platform does not report the value, and it
 * may throw when the platform call fails. The observation reader keeps every
 * name that it did read and marks the rest of the read incomplete.
 */
internal interface ObservedNetwork {
    /** Return the transports, or null when the platform does not report them. */
    fun transports(): ObservedTransports?

    /** Return the interface name, or null when the platform does not report one. */
    fun interfaceName(): String?
}

/** Read every network that the platform reports. */
internal fun interface NetworkListSource {
    /** Return every reported network. Throw when the platform cannot list them. */
    fun read(): List<ObservedNetwork>
}

/**
 * The networks that one observation read.
 *
 * Exclusion is monotonic. A name that the reader read stays excluded, even
 * when another platform value was missing. A name that the reader did not read
 * is not excluded, and the finder never treats that absence as proof that an
 * interface is tethering.
 */
internal sealed interface NetworkInterfaceObservation {
    /**
     * Every interface name that a reported network holds.
     *
     * The platform normally reports upstream and client networks. An OEM build
     * can also report the tethering access point. Two platform views then
     * disagree, so the finder fails closed and excludes every reported name
     * rather than choosing one view. This includes cellular, Wi-Fi, VPN,
     * Ethernet, and Bluetooth PAN client networks.
     */
    val excludedNames: Set<String>

    /**
     * Unambiguous Wi-Fi station interface names from one complete read.
     *
     * A reported Wi-Fi network is not automatically a client. An OEM build can
     * report the access point as a Wi-Fi network, and a `wlan*` name is
     * ambiguous between the station and the access point. Only a reported
     * Wi-Fi name outside the tether name prefixes, such as `wifi0` or `wl0`,
     * is kept here. Even that is evidence for a separate `wlan*` candidate,
     * not proof that the candidate is tethering. Only [Complete] holds a
     * value.
     */
    val wifiClientNames: Set<String>

    /** The platform reported every network in full. */
    data class Complete(
        override val excludedNames: Set<String>,
        override val wifiClientNames: Set<String>,
    ) : NetworkInterfaceObservation

    /**
     * The platform missed at least one value.
     *
     * The names that were read stay excluded. A partial read never confirms a
     * `wlan*` name, because one missing client name could hide the station.
     */
    data class Partial(
        override val excludedNames: Set<String>,
    ) : NetworkInterfaceObservation {
        override val wifiClientNames: Set<String> get() = emptySet()
    }

    /** The platform did not report any usable network. */
    data object Unknown : NetworkInterfaceObservation {
        override val excludedNames: Set<String> get() = emptySet()
        override val wifiClientNames: Set<String> get() = emptySet()
    }
}

/**
 * Build one network observation.
 *
 * The reader reads a network name before its transports. A name that it reads
 * is always excluded. A missing, blank, or malformed value makes the
 * observation [NetworkInterfaceObservation.Partial], and the read continues,
 * so a later complete entry still adds its evidence. The reader never invents
 * a value.
 *
 * Names are trimmed and lowercased with [Locale.ROOT] before they are
 * compared. A reported Wi-Fi network becomes station evidence only when its
 * name is outside the tether name prefixes. A reported `wlan*`, `ap*`,
 * `softap*`, `swlan*`, `rndis*`, `bt-pan*`, `usb*`, `ncm*`, `eth*`, or `p2p*`
 * name is excluded but is not treated as a client, because that name can
 * belong to the access point or another tether role.
 */
internal class NetworkInterfaceObservationReader(
    private val networks: NetworkListSource,
) {
    fun read(): NetworkInterfaceObservation {
        val reported = try {
            networks.read()
        } catch (_: Exception) {
            return NetworkInterfaceObservation.Unknown
        }
        val excluded = mutableSetOf<String>()
        val wifiClients = mutableSetOf<String>()
        var complete = true
        for (network in reported) {
            val name = try {
                network.interfaceName()
            } catch (_: Exception) {
                null
            }
            val lower = normalizeInterfaceName(name)
            if (lower == null) {
                complete = false
                continue
            }
            // Every reported network is an upstream or client network. None of
            // them can be the hotspot interface, whatever its transport is.
            excluded += lower
            val transports = try {
                network.transports()
            } catch (_: Exception) {
                null
            }
            if (transports == null) {
                complete = false
                continue
            }
            if (transports.isWifi &&
                !transports.isVpn &&
                !transports.isCellular &&
                isUnambiguousWifiClientName(lower)
            ) {
                wifiClients += lower
            }
        }
        return if (complete) {
            NetworkInterfaceObservation.Complete(excluded, wifiClients)
        } else {
            NetworkInterfaceObservation.Partial(excluded)
        }
    }
}

/** One interface that the finder confirms as a tethering candidate. */
internal data class HotspotCandidate(
    /** Lower is a better candidate. */
    val rank: Int,
    val address: InetAddress,
)

/**
 * An explicit hotspot interface choice.
 *
 * Android 15 and earlier have no public API that names the tethering
 * interface, and the automatic name rules fail closed when a vendor ROM uses
 * an unexpected name or hides the Wi-Fi client. The selection UI lets a person
 * name the interface that the hotspot settings show. It is a statement about
 * which interface is tethering, not proof, and it never overrides a reported
 * client or upstream network.
 *
 * The Settings page stores one [Selected] name (with no pinned address) or
 * [Automatic]. The finder defaults to [Automatic] when nothing is stored.
 */
internal sealed interface HotspotInterfaceChoice {
    /** Use the automatic name rules. This is the default. */
    data object Automatic : HotspotInterfaceChoice

    /**
     * The person selected one interface.
     *
     * [interfaceName] is matched without case. [address] is the private IPv4
     * address that the selection screen showed, when the screen pinned one. A
     * name with no pinned address is accepted only when the interface has
     * exactly one private IPv4 address.
     */
    data class Selected(
        val interfaceName: String,
        val address: InetAddress? = null,
    ) : HotspotInterfaceChoice
}

/** Read the stored explicit choice. A JVM test supplies a fake. */
internal fun interface HotspotInterfaceChoiceSource {
    /**
     * Return the current choice.
     *
     * Return [HotspotInterfaceChoice.Automatic] when no choice is stored. The
     * call must not block, because the finder calls it on the probe thread. It
     * may throw when the storage read fails; the finder then fails closed
     * instead of guessing.
     */
    fun read(): HotspotInterfaceChoice
}

/**
 * Build a choice from the two values that a settings screen saves.
 *
 * A null or blank name means that no choice is stored. The UI stores the name
 * and the address that it showed, and passes both back on the next launch.
 */
internal fun savedHotspotInterfaceChoice(
    interfaceName: String?,
    address: InetAddress? = null,
): HotspotInterfaceChoice = if (interfaceName.isNullOrBlank()) {
    HotspotInterfaceChoice.Automatic
} else {
    HotspotInterfaceChoice.Selected(interfaceName, address)
}

/** How the finder chose the view that one probe returned. */
internal enum class HotspotChoiceOutcome {
    /** No explicit choice is stored. The automatic name rules ran. */
    AUTOMATIC,

    /** The explicit choice selected the returned candidate. */
    APPLIED,

    /** The API 36 tethering evidence supplied the result. The choice was not read. */
    PLATFORM_EVIDENCE,

    /** The choice storage read failed. The finder did not guess. */
    UNREADABLE,

    /** The selected interface is not in the current interface list. */
    INTERFACE_MISSING,

    /** More than one interface entry has the selected name. */
    INTERFACE_AMBIGUOUS,

    /** The selected interface is held by a reported network. */
    REPORTED_NETWORK,

    /** The selected interface is down, loopback, cellular, virtual, or point-to-point. */
    UNSAFE_INTERFACE,

    /**
     * The selected interface has no safe private IPv4 address, or the pinned
     * or only address is also held by a reported network.
     */
    UNSAFE_ADDRESS,

    /** The pinned address does not belong to the selected interface. */
    ADDRESS_MISMATCH,

    /** The selected interface has more than one safe private IPv4 and no address is pinned. */
    ADDRESS_AMBIGUOUS,

    /**
     * The network read did not see every reported name, so it cannot prove
     * that the selected interface is not a client or upstream network.
     */
    EVIDENCE_INCOMPLETE,
}

/** One interface and address that a settings screen may offer as a choice. */
internal data class HotspotInterfaceOption(
    val interfaceName: String,
    val address: InetAddress,
)

/** The result of one hotspot probe. The watch decides whether it is a loss. */
internal sealed interface HotspotProbe {
    /** The finder could not read the local interface list. */
    data object Unknown : HotspotProbe

    /**
     * The API 36 tethering callback is registered but has not delivered its
     * first reading. The finder has no safe address and must not fall back to
     * the name rules before the platform speaks.
     */
    data object Pending : HotspotProbe

    /**
     * One successful read of the local interface list.
     *
     * [candidates] holds every confirmed tethering address. More than one
     * candidate can belong to one interface. Two safe private IPv4 addresses on
     * one interface share a rank and make
     * [HotspotAddressFinder.findHotspotAddress] return null. A candidate
     * address is never also present in [excludedAddresses]. [excludedAddresses]
     * holds every address of an interface that a reported network holds. An
     * address in that set is a client or upstream address that no later check
     * can turn into a hotspot. [choiceOutcome] explains which view produced the
     * candidates, so the UI can tell an automatic result from a stored choice
     * that no longer applies.
     */
    data class Observed(
        val candidates: List<HotspotCandidate>,
        val excludedAddresses: Set<InetAddress>,
        val choiceOutcome: HotspotChoiceOutcome = HotspotChoiceOutcome.AUTOMATIC,
    ) : HotspotProbe
}

/**
 * Find the hotspot (tethering) IPv4 address of this device.
 *
 * The service binds the source listener to this address only. It never binds
 * the any-local address. A finder returns null when it cannot confirm a
 * tethering interface. A JVM test supplies a fake finder.
 */
internal interface HotspotAddressFinder {
    /** Read the current hotspot state. */
    fun probe(): HotspotProbe

    /**
     * Return the best confirmed hotspot address, or null.
     *
     * A tie between two candidates of the best rank returns null, because the
     * finder cannot tell them apart. Two safe private IPv4 addresses on one
     * confirmed interface share one rank, so they are a tie too.
     */
    fun findHotspotAddress(): InetAddress? {
        val observed = probe() as? HotspotProbe.Observed ?: return null
        val best = observed.candidates.minByOrNull { it.rank } ?: return null
        if (observed.candidates.count { it.rank == best.rank } != 1) return null
        return best.address
    }

    /**
     * Return the interfaces that the settings screen offers as explicit
     * choices.
     *
     * The default returns an empty list. The network finder overrides it and
     * applies [selectableHotspotInterfaces]. The settings screen calls this
     * method off the main thread, because it reads platform state.
     */
    fun selectableInterfaces(): List<HotspotInterfaceOption> = emptyList()
}

/**
 * Find the hotspot address from the interface list, one network observation,
 * and the API 36 tethering callback when it is available.
 *
 * Every interface that a reported network holds is excluded. A reported name
 * is treated as a client or upstream interface, never as the hotspot. The rule
 * covers every transport: cellular, Wi-Fi, VPN, Ethernet, and Bluetooth PAN.
 *
 * ## Reported Wi-Fi is not client proof
 *
 * A reported Wi-Fi network is not automatically a station. An OEM build can
 * report the access point as a Wi-Fi network, and a reported `wlan*` name is
 * ambiguous between the station and the access point. The observation therefore
 * keeps only an unambiguous station name outside the tether name prefixes,
 * such as `wifi0` or `wl0`, as client evidence. A reported tether-style name
 * such as `wlan*`, `ap*`, `softap*`, `swlan*`, `rndis*`, `bt-pan*`, `usb*`,
 * `ncm*`, `eth*`, or `p2p*` is excluded, but it cannot prove that a separate
 * unreported `wlan*` interface is the hotspot.
 *
 * ## API 36 and later
 *
 * When [tetheredEvidence] returns [TetheredInterfaceState.Known], the platform
 * has named the current tethered interfaces and their types. That positive,
 * specific evidence replaces the name rules:
 *
 * - An empty map is authoritative. The finder returns no candidate and does
 *   not fall back to the name rules.
 * - A non-empty map admits only those interface names. A name that the
 *   platform did not name is never a candidate, even when its prefix looks
 *   like a hotspot.
 * - A named interface is ranked by its platform type, not by its name. A
 *   Wi-Fi access point wins over USB or NCM, and a Bluetooth or Ethernet link
 *   comes later.
 * - A named interface that a reported network also holds is a conflict between
 *   two platform views. The finder fails closed and returns no candidate.
 * - A named interface that is down, loopback, cellular, virtual, or
 *   point-to-point, or has no private IPv4 address, is not a candidate. A
 *   candidate address that a reported network also holds is rejected before it
 *   can be returned.
 * - The platform `TETHERING_VIRTUAL` type is the authoritative virtual
 *   rejection. The finder also checks `NetworkInterface.isVirtual` and
 *   `isPointToPoint`, plus a small name prefix guard. Those are defense in
 *   depth, not a guarantee for every OEM build. Real OEM behavior is
 *   unverified.
 *
 * When [tetheredEvidence] returns
 * [TetheredInterfaceState.AwaitingFirstReading], the callback is registered
 * but has not delivered its first reading. The finder returns
 * [HotspotProbe.Pending] and does not use the name rules, because a guess
 * before the first delivery could bind a client interface. It does not block.
 * The evidence bounds this wait. After its pending timeout the state becomes
 * [TetheredInterfaceState.Unavailable], so a callback that never fires cannot
 * keep the finder or the watch waiting forever. A late reading still becomes
 * [TetheredInterfaceState.Known] and supersedes the fallback.
 *
 * When [tetheredEvidence] returns [TetheredInterfaceState.Unavailable], the
 * platform did not deliver a complete set. The finder uses the name rules
 * below, exactly as Android 15 and earlier do. An unavailable reading is never
 * treated as an empty set, so a missing callback does not hide a hotspot. The
 * reading also never confirms a client interface, because the network
 * observation still excludes every reported name.
 *
 * ## Android 15 and earlier
 *
 * A strong tether name is admitted as a candidate: `swlan*`, `ap*`, `softap*`,
 * and `rndis*`. The name does not prove the tethering role. `bt-pan*` is not a
 * strong name. Android uses the same prefix for a Bluetooth tether and a
 * Bluetooth PAN client, and the public API before Android 16 does not say
 * which one is active. The finder does not guess.
 *
 * A `wlan*` name is a weak candidate. It is admitted at the inferred rank when
 * a complete observation names an unambiguous Wi-Fi station outside the tether
 * name prefixes, such as `wifi0` or `wl0`, and the candidate itself must not be
 * a reported network. A reported `wlan*` or access point name does not count,
 * because the platform can report the access point under that name. This is a
 * narrow concurrency inference, not proof.
 *
 * When no such station evidence exists, an unreported `wlan*` name is admitted
 * instead at the fail-closed fallback rank (see the rank order below) when the
 * observation is complete and the interface has exactly one safe private IPv4
 * address. Many devices name the station `wlan0`, so an access point named
 * `wlan1` gets no station evidence; the fallback covers that common case. It is
 * an inference from one private address, not proof. A partial or unknown read
 * never admits the fallback, and neither does a second unreported private
 * interface, which ties at the fallback rank. A vendor ROM can still expose a
 * station name while it keeps the access point hidden or gives it a tether-like
 * name, so the finder can infer the wrong `wlan*` interface. This residual risk
 * is why a strong name and the API 36 callback are preferred.
 *
 * ## Automatic rank order
 *
 * The automatic name rules use one explicit order, lower first:
 *
 * 1. `swlan*`
 * 2. `ap*`
 * 3. `softap*`
 * 4. `rndis*`
 * 5. `wlan*`, only with the separate station evidence above
 * 6. any remaining unreported, non-virtual, non-cellular interface with exactly
 *    one safe private IPv4 address (the fail-closed fallback)
 *
 * A strong access point name therefore wins over a USB tether name, and a
 * strong USB tether name wins over the weak `wlan*` inference, which in turn
 * wins over the fallback. The order is a product choice, not a platform fact.
 * `rndis*` names a USB tether role more narrowly than `wlan*`, which can be
 * either the station or the access point. The fallback covers a `wlan*` access
 * point on a ROM that names the station `wlan0` or leaves the Wi-Fi client off,
 * and also a generic `usb*`, `ncm*`, or `eth*` name that is unreported and has
 * one private IPv4 address. It is the weakest automatic evidence and is never a
 * strong claim. The API 36 path does not use these numbers. It ranks by the
 * validated platform type in [TetheredInterfaceKind], and the two rank scales
 * are never compared.
 *
 * ## Multiple private addresses
 *
 * A confirmed interface can hold more than one safe private IPv4 address. The
 * finder does not pick one. It surfaces every address at the same rank, in
 * numeric order, so the probe output is stable. A new start then sees a tie at
 * the best rank and fails closed. A tunnel that is already bound to one of the
 * addresses stays valid while that address remains a candidate.
 *
 * The finder skips loopback, down, cellular, virtual, point-to-point, and
 * excluded interfaces. A candidate address that a reported network also holds
 * is rejected before the address can be returned. It returns null for a
 * virtual or cellular name such as `wg*` or `rmnet*`. When more than one
 * interface holds the best rank, it returns null because it cannot tell them
 * apart. A strong Wi-Fi access point name wins over a USB tether name, and any
 * named rank wins over the fallback rank.
 *
 * An interface name alone does not prove that the interface is tethering. A
 * vendor ROM can name the hotspot interface `wlan*` while hiding the Wi-Fi
 * client network, or it can give both roles the same name prefix, or it can
 * report the access point as a network. The finder can return null or infer
 * the wrong interface, so binding the address does not prove
 * that the interface is tethering either.
 *
 * ## Android 15 and earlier: stored explicit choice
 *
 * Manual interface selection is wired. The Settings page offers a "Hotspot
 * network adapter" picker that lists the safe interface names and stores one
 * name as [HotspotInterfaceChoice.Selected], or stores
 * [HotspotInterfaceChoice.Automatic] when the person clears the choice. The
 * picker shows interface names only. The selection UI states the limitation
 * and warns that the proxy will be reachable at the selected address.
 *
 * The finder validates a stored choice supplied through
 * [HotspotInterfaceChoiceSource]. The source is read only when
 * [tetheredEvidence] is [TetheredInterfaceState.Unavailable]; API 36 evidence
 * stays authoritative. A source that throws makes the finder fail closed
 * instead of guessing.
 *
 * A selected interface is a name and, optionally, the private IPv4 address
 * that the selection screen showed. The finder reads the interface list again
 * on every probe and revalidates the choice:
 *
 * - The network observation must be [NetworkInterfaceObservation.Complete].
 *   Every reported name was read, so the finder can show that the selected
 *   name is not a reported client or upstream network. A partial or unknown
 *   read fails closed.
 * - A selected name that a reported network holds is rejected. The choice
 *   never overrides the exclusion rule.
 * - A selected address that a reported network also holds is rejected before
 *   it can be returned.
 * - A selected interface that is reported, down, loopback, cellular, virtual,
 *   point-to-point, or has no private IPv4 address is rejected. A pinned
 *   address must belong to the interface and be a private IPv4 address.
 * - When no address is pinned, the interface must have exactly one safe
 *   private IPv4 address. More than one address is ambiguous.
 * - If the choice cannot be applied, the finder returns no candidate. It does
 *   not fall back to the name rules, so a stale choice cannot silently bind a
 *   different interface.
 *
 * The choice records that a person identified the hotspot interface when the
 * platform exposes no safe answer. It is not proof. The selection UI shows the
 * interface name and states the limitation, and warns that the proxy will be
 * reachable at that address. It builds its list with
 * [selectableHotspotInterfaces] and saves the selected name. The caller owns
 * that storage and passes [HotspotInterfaceChoice.Automatic] when the person
 * clears the choice.
 */
internal class NetworkInterfaceHotspotAddressFinder(
    private val source: InterfaceSource,
    private val observation: () -> NetworkInterfaceObservation,
    private val tetheredEvidence: TetheredInterfaceEvidenceSource =
        TetheredInterfaceEvidenceSource { TetheredInterfaceState.Unavailable },
    private val choiceSource: HotspotInterfaceChoiceSource =
        HotspotInterfaceChoiceSource { HotspotInterfaceChoice.Automatic },
) : HotspotAddressFinder {
    override fun selectableInterfaces(): List<HotspotInterfaceOption> {
        val snapshots = try {
            source.read()
        } catch (_: Exception) {
            return emptyList()
        }
        val observed = try {
            observation()
        } catch (_: Exception) {
            return emptyList()
        }
        return selectableHotspotInterfaces(snapshots, observed)
    }

    override fun probe(): HotspotProbe {
        // Read the evidence before the interface list. A callback that arrives
        // after this point is used by the next probe. The network observation
        // is read last, so a client that starts during the read is excluded.
        val evidence = try {
            tetheredEvidence.snapshot()
        } catch (_: Exception) {
            TetheredInterfaceState.Unavailable
        }
        if (evidence == TetheredInterfaceState.AwaitingFirstReading) {
            // The callback is registered but has not delivered its first
            // reading. Do not guess from names and do not block the caller.
            return HotspotProbe.Pending
        }
        val snapshots = try {
            source.read()
        } catch (_: Exception) {
            return HotspotProbe.Unknown
        }
        val observed = normalizeNetworkObservation(
            try {
                observation()
            } catch (_: Exception) {
                NetworkInterfaceObservation.Unknown
            },
        )
        val excludedAddresses = excludedAddressesOf(snapshots, observed)
        return when (evidence) {
            is TetheredInterfaceState.Known ->
                HotspotProbe.Observed(
                    candidates = evidencedCandidates(
                        snapshots,
                        observed,
                        evidence.interfaces,
                        excludedAddresses,
                    ),
                    excludedAddresses = excludedAddresses,
                    choiceOutcome = HotspotChoiceOutcome.PLATFORM_EVIDENCE,
                )
            TetheredInterfaceState.Unavailable ->
                automaticOrSelected(snapshots, observed, excludedAddresses)
            TetheredInterfaceState.AwaitingFirstReading ->
                // The early return above handles this state.
                HotspotProbe.Pending
        }
    }

    /**
     * Apply the stored choice, or the name rules when there is none.
     *
     * A failed choice read returns no candidate instead of falling back to the
     * name rules. A fallback could bind a different interface than the person
     * selected without telling anyone.
     */
    private fun automaticOrSelected(
        snapshots: List<InterfaceSnapshot>,
        observation: NetworkInterfaceObservation,
        excludedAddresses: Set<InetAddress>,
    ): HotspotProbe.Observed {
        val choice = try {
            choiceSource.read()
        } catch (_: Exception) {
            return HotspotProbe.Observed(
                candidates = emptyList(),
                excludedAddresses = excludedAddresses,
                choiceOutcome = HotspotChoiceOutcome.UNREADABLE,
            )
        }
        return when (choice) {
            HotspotInterfaceChoice.Automatic ->
                HotspotProbe.Observed(
                    candidates = heuristicCandidates(
                        snapshots,
                        observation,
                        excludedAddresses,
                    ),
                    excludedAddresses = excludedAddresses,
                    choiceOutcome = HotspotChoiceOutcome.AUTOMATIC,
                )
            is HotspotInterfaceChoice.Selected -> {
                val result = selectedCandidate(
                    snapshots,
                    observation,
                    choice,
                    excludedAddresses,
                )
                HotspotProbe.Observed(
                    candidates = result.candidate?.let { listOf(it) } ?: emptyList(),
                    excludedAddresses = excludedAddresses,
                    choiceOutcome = result.outcome,
                )
            }
        }
    }

    /**
     * Return the candidates that the platform named as tethered.
     *
     * A conflict between the callback and the network observation fails
     * closed. Returning a second named interface while one named interface is
     * also a reported network would hide the disagreement from the watch.
     *
     * The rank comes from the validated platform type. The name is used only
     * to find the local interface and to apply the safety filters for
     * cellular and virtual names. A named address that a reported network also
     * holds is rejected, and the other named interfaces can still be used.
     */
    private fun evidencedCandidates(
        snapshots: List<InterfaceSnapshot>,
        observation: NetworkInterfaceObservation,
        interfaces: Map<String, TetheredInterfaceKind>,
        excludedAddresses: Set<InetAddress>,
    ): List<HotspotCandidate> {
        if (interfaces.isEmpty()) return emptyList()
        val named = LinkedHashMap<String, TetheredInterfaceKind>(interfaces.size)
        for ((rawName, kind) in interfaces) {
            val name = normalizeInterfaceName(rawName) ?: return emptyList()
            if (named.put(name, kind) != null) return emptyList()
        }
        if (named.keys.any { it in observation.excludedNames }) return emptyList()
        return snapshots
            .asSequence()
            .filter { !isUnsafeInterface(it) }
            .flatMap { snapshot ->
                val lower = normalizeInterfaceName(snapshot.name)
                    ?: return@flatMap emptySequence()
                val kind = named[lower] ?: return@flatMap emptySequence()
                if (lower in observation.excludedNames) return@flatMap emptySequence()
                if (hasVirtualNamePrefix(lower)) return@flatMap emptySequence()
                if (hasCellularNamePrefix(lower)) return@flatMap emptySequence()
                safePrivateIpv4Addresses(snapshot.addresses, excludedAddresses)
                    .asSequence()
                    .map { HotspotCandidate(kind.rank, it) }
            }
            .toList()
    }

    /**
     * Validate and apply one explicit choice.
     *
     * The method never falls back to the name rules. A choice that cannot be
     * applied returns no candidate and a fixed outcome for the UI.
     */
    private fun selectedCandidate(
        snapshots: List<InterfaceSnapshot>,
        observation: NetworkInterfaceObservation,
        choice: HotspotInterfaceChoice.Selected,
        excludedAddresses: Set<InetAddress>,
    ): SelectedResult {
        val name = normalizeInterfaceName(choice.interfaceName)
            ?: return SelectedResult(null, HotspotChoiceOutcome.UNSAFE_INTERFACE)
        // A reported name is a client or upstream interface. The choice must
        // never override that evidence, even when the person selected it.
        if (name in observation.excludedNames) {
            return SelectedResult(null, HotspotChoiceOutcome.REPORTED_NETWORK)
        }
        if (hasVirtualNamePrefix(name)) {
            return SelectedResult(null, HotspotChoiceOutcome.UNSAFE_INTERFACE)
        }
        if (hasCellularNamePrefix(name)) {
            return SelectedResult(null, HotspotChoiceOutcome.UNSAFE_INTERFACE)
        }
        val matches = snapshots.filter { normalizeInterfaceName(it.name) == name }
        if (matches.isEmpty()) {
            return SelectedResult(null, HotspotChoiceOutcome.INTERFACE_MISSING)
        }
        if (matches.size != 1) {
            return SelectedResult(null, HotspotChoiceOutcome.INTERFACE_AMBIGUOUS)
        }
        val snapshot = matches.single()
        if (isUnsafeInterface(snapshot)) {
            return SelectedResult(null, HotspotChoiceOutcome.UNSAFE_INTERFACE)
        }
        // A partial or unknown read cannot show that the selected name is not
        // one of the reported client or upstream interfaces that were missed.
        if (observation !is NetworkInterfaceObservation.Complete) {
            return SelectedResult(null, HotspotChoiceOutcome.EVIDENCE_INCOMPLETE)
        }
        val pinned = choice.address
        if (pinned != null) {
            if (snapshot.addresses.none { it == pinned }) {
                return SelectedResult(null, HotspotChoiceOutcome.ADDRESS_MISMATCH)
            }
            if (!isPrivateIpv4(pinned) || pinned in excludedAddresses) {
                return SelectedResult(null, HotspotChoiceOutcome.UNSAFE_ADDRESS)
            }
            return SelectedResult(
                HotspotCandidate(USER_CHOICE_RANK, pinned),
                HotspotChoiceOutcome.APPLIED,
            )
        }
        val privateAddresses = snapshot.addresses.filter {
            isPrivateIpv4(it) && it !in excludedAddresses
        }
        if (privateAddresses.isEmpty()) {
            return SelectedResult(null, HotspotChoiceOutcome.UNSAFE_ADDRESS)
        }
        if (privateAddresses.size != 1) {
            // The person selected a name but not an address. Binding one of
            // several addresses would be an arbitrary choice.
            return SelectedResult(null, HotspotChoiceOutcome.ADDRESS_AMBIGUOUS)
        }
        return SelectedResult(
            HotspotCandidate(USER_CHOICE_RANK, privateAddresses.single()),
            HotspotChoiceOutcome.APPLIED,
        )
    }

    private data class SelectedResult(
        val candidate: HotspotCandidate?,
        val outcome: HotspotChoiceOutcome,
    )

    private fun heuristicCandidates(
        snapshots: List<InterfaceSnapshot>,
        observation: NetworkInterfaceObservation,
        excludedAddresses: Set<InetAddress>,
    ): List<HotspotCandidate> = snapshots
        .asSequence()
        .filter { !isUnsafeInterface(it) }
        .flatMap { snapshot ->
            heuristicCandidatesFor(snapshot, observation, excludedAddresses).asSequence()
        }
        .toList()

    private fun heuristicCandidatesFor(
        snapshot: InterfaceSnapshot,
        observation: NetworkInterfaceObservation,
        excludedAddresses: Set<InetAddress>,
    ): List<HotspotCandidate> {
        val lower = normalizeInterfaceName(snapshot.name) ?: return emptyList()
        if (lower in observation.excludedNames) return emptyList()
        val safeAddresses = safePrivateIpv4Addresses(snapshot.addresses, excludedAddresses)
        val rank = rankOf(lower, observation)
            ?: fallbackRankOf(lower, observation, safeAddresses)
            ?: return emptyList()
        return safeAddresses.map { HotspotCandidate(rank, it) }
    }

    /**
     * Admit one unreported, otherwise-unranked interface at the fallback rank.
     *
     * The name rules return null for a name that proves neither a tether role
     * nor a Wi-Fi station. The common case is a `wlan*` access point on a ROM
     * that names the station `wlan0` or leaves the Wi-Fi client off, so no
     * unambiguous station evidence exists. Instead of always failing closed, the
     * finder admits the interface at [PRIVATE_IPV4_FALLBACK_RANK] when the
     * evidence is complete and the interface is unreported, non-virtual,
     * non-cellular, and has exactly one safe private IPv4 address. That is an
     * inference from the presence of one private address, not proof of a
     * tethering role. Two such interfaces tie at the fallback rank, so the
     * existing best-rank rule keeps them failing closed.
     */
    private fun fallbackRankOf(
        name: String,
        observation: NetworkInterfaceObservation,
        safeAddresses: List<InetAddress>,
    ): Int? {
        if (observation !is NetworkInterfaceObservation.Complete) return null
        if (hasVirtualNamePrefix(name)) return null
        if (hasCellularNamePrefix(name)) return null
        if (safeAddresses.size != 1) return null
        return PRIVATE_IPV4_FALLBACK_RANK
    }

    private fun rankOf(
        name: String,
        observation: NetworkInterfaceObservation,
    ): Int? {
        if (hasVirtualNamePrefix(name)) return null
        if (hasCellularNamePrefix(name)) return null
        return when {
            name.startsWith("swlan") -> SWLAN_RANK
            name.startsWith("ap") -> AP_RANK
            name.startsWith("softap") -> SOFTAP_RANK
            name.startsWith("rndis") -> USB_TETHER_RANK
            name.startsWith("wlan") -> {
                val complete = observation as? NetworkInterfaceObservation.Complete
                if (complete == null ||
                    complete.wifiClientNames.none { isUnambiguousWifiClientName(it) }
                ) {
                    null
                } else {
                    INFERRED_WLAN_RANK
                }
            }
            else -> null
        }
    }

    private companion object {
        // A selected interface is the only candidate on its path, so the rank
        // only records that the person supplied the choice.
        const val USER_CHOICE_RANK = -1

        // The automatic name ranks. A strong access point wins over a USB
        // tether, and a strong USB tether name wins over the weak inferred
        // wlan. See the class KDoc for the reason.
        const val SWLAN_RANK = 0
        const val AP_RANK = 1
        const val SOFTAP_RANK = 2
        const val USB_TETHER_RANK = 3
        const val INFERRED_WLAN_RANK = 4

        // The fail-closed last resort. An unreported, non-virtual, non-cellular
        // interface with exactly one safe private IPv4 address is admitted here
        // when the name rules cannot rank it. The common case is a `wlan*`
        // access point on a ROM that names the station `wlan0` or leaves the
        // Wi-Fi client off, so no unambiguous station evidence exists. This is
        // an inference from one private address, not proof of tethering. Two
        // such interfaces tie here, so the best-rank rule still fails closed.
        const val PRIVATE_IPV4_FALLBACK_RANK = 5
    }
}

/**
 * Return interface choices that the settings screen offers.
 *
 * The function applies the same safety filters as the finder: a complete
 * network observation, no reported client or upstream name, no address that a
 * reported network holds, no cellular or virtual name, an up non-loopback
 * interface, and a private IPv4 address. It also rejects interfaces that
 * `NetworkInterface` marks as virtual or point-to-point. One option is returned
 * per safe private IPv4 address, so a caller can tell how many addresses an
 * interface holds. An interface with several safe addresses therefore offers
 * several options; the settings screen shows one row per interface name.
 *
 * The settings screen builds its picker from this list and saves the selected
 * name. The finder validates a stored choice again on every probe; an option
 * list is never proof that an interface is tethering.
 */
internal fun selectableHotspotInterfaces(
    snapshots: List<InterfaceSnapshot>,
    observation: NetworkInterfaceObservation,
): List<HotspotInterfaceOption> {
    val normalized = normalizeNetworkObservation(observation)
    if (normalized !is NetworkInterfaceObservation.Complete) return emptyList()
    val excludedAddresses = excludedAddressesOf(snapshots, normalized)
    val duplicateNames = snapshots
        .mapNotNull { normalizeInterfaceName(it.name) }
        .groupingBy { it }
        .eachCount()
        .filterValues { it > 1 }
        .keys
    return snapshots
        .asSequence()
        .filter { !isUnsafeInterface(it) }
        .flatMap { snapshot ->
            val name = normalizeInterfaceName(snapshot.name) ?: return@flatMap emptySequence()
            if (name in duplicateNames) return@flatMap emptySequence()
            if (name in normalized.excludedNames) return@flatMap emptySequence()
            if (hasVirtualNamePrefix(name)) return@flatMap emptySequence()
            if (hasCellularNamePrefix(name)) return@flatMap emptySequence()
            snapshot.addresses
                .asSequence()
                .filter { isPrivateIpv4(it) && it !in excludedAddresses }
                .map { HotspotInterfaceOption(name, it) }
        }
        .distinct()
        .sortedWith(compareBy({ it.interfaceName }, { it.address.hostAddress ?: "" }))
        .toList()
}

/**
 * Normalize the names in one observation before the finder compares them.
 *
 * The reader already normalizes every name. This second pass keeps a hand-built
 * observation or a future adapter from bypassing the comparison with
 * uppercase, whitespace, or a malformed name.
 */
private fun normalizeNetworkObservation(
    observation: NetworkInterfaceObservation,
): NetworkInterfaceObservation = when (observation) {
    is NetworkInterfaceObservation.Complete -> NetworkInterfaceObservation.Complete(
        excludedNames = observation.excludedNames
            .mapNotNull { normalizeInterfaceName(it) }
            .toSet(),
        wifiClientNames = observation.wifiClientNames
            .mapNotNull { normalizeInterfaceName(it) }
            .toSet(),
    )
    is NetworkInterfaceObservation.Partial -> NetworkInterfaceObservation.Partial(
        excludedNames = observation.excludedNames
            .mapNotNull { normalizeInterfaceName(it) }
            .toSet(),
    )
    NetworkInterfaceObservation.Unknown -> NetworkInterfaceObservation.Unknown
}

/**
 * Return every address of an interface that a reported network holds.
 *
 * The name comparison is normalized on both sides. A caller must not return a
 * candidate address from this set, even when the candidate interface has a
 * different name.
 */
private fun excludedAddressesOf(
    snapshots: List<InterfaceSnapshot>,
    observation: NetworkInterfaceObservation,
): Set<InetAddress> = snapshots
    .asSequence()
    .filter { snapshot ->
        val name = normalizeInterfaceName(snapshot.name)
        name != null && name in observation.excludedNames
    }
    .flatMap { it.addresses.asSequence() }
    .toSet()

/** True when the name is not a safe candidate interface. */
private fun isUnsafeInterface(snapshot: InterfaceSnapshot): Boolean =
    !snapshot.isUp ||
        snapshot.isLoopback ||
        snapshot.isVirtual ||
        snapshot.isPointToPoint

/**
 * Normalize one interface name for comparison.
 *
 * Returns null for a missing, blank, or malformed name. A malformed name makes
 * the observation partial; it must never be treated as an excluded name or as
 * evidence. [Locale.ROOT] keeps the result independent of the device locale.
 */
private fun normalizeInterfaceName(raw: String?): String? {
    val trimmed = raw?.trim() ?: return null
    if (trimmed.isEmpty()) return null
    val lower = trimmed.lowercase(Locale.ROOT)
    val malformed = lower.any { character ->
        character.isWhitespace() ||
            character.isISOControl() ||
            character == '/' ||
            character == '\\' ||
            character == ':' ||
            character == '@'
    }
    if (malformed) return null
    return lower
}

/**
 * True when the name can be a Wi-Fi station without being mistaken for a
 * tether role. Every tether prefix is deliberately absent: `wlan*` is
 * ambiguous, and the others can belong to an access point or another tether.
 */
private fun isUnambiguousWifiClientName(name: String): Boolean =
    name.isNotEmpty() &&
        !TETHER_PREFIXES.any { name.startsWith(it) } &&
        !hasVirtualNamePrefix(name) &&
        !hasCellularNamePrefix(name)

private fun hasVirtualNamePrefix(name: String): Boolean =
    VIRTUAL_PREFIXES.any { name.startsWith(it) }

private fun hasCellularNamePrefix(name: String): Boolean =
    CELLULAR_PREFIXES.any { name.startsWith(it) }

private fun isPrivateIpv4(address: InetAddress): Boolean =
    address is Inet4Address &&
        !address.isAnyLocalAddress &&
        !address.isLoopbackAddress &&
        !address.isLinkLocalAddress &&
        address.isSiteLocalAddress

/**
 * Return every safe private IPv4 address in stable numeric order.
 *
 * A confirmed interface can hold more than one private IPv4 address. The
 * finder surfaces every address at the same rank instead of picking one. Two
 * addresses on one interface then tie under the existing best-rank rule, so a
 * new start fails closed. The order keeps probe output stable when the
 * platform lists the addresses in a different sequence.
 */
private fun safePrivateIpv4Addresses(
    addresses: List<InetAddress>,
    excludedAddresses: Set<InetAddress>,
): List<InetAddress> = addresses
    .asSequence()
    .filter { isPrivateIpv4(it) && it !in excludedAddresses }
    .distinct()
    .sortedWith(compareBy { ipv4SortKey(it) })
    .toList()

/** Return the unsigned 32-bit value of an IPv4 address for stable sorting. */
private fun ipv4SortKey(address: InetAddress): Long {
    val bytes = address.address
    return ((bytes[0].toLong() and 0xffL) shl 24) or
        ((bytes[1].toLong() and 0xffL) shl 16) or
        ((bytes[2].toLong() and 0xffL) shl 8) or
        (bytes[3].toLong() and 0xffL)
}

private val CELLULAR_PREFIXES = listOf("rmnet", "ccmni", "pdp", "clat", "radio", "wwan")

// The tether name prefixes can belong to an access point, a USB or Ethernet
// tether, a Bluetooth PAN link, or a Wi-Fi P2P link. None of them can prove a
// Wi-Fi infrastructure station role. An OEM build can also report the access
// point under one of these names.
private val TETHER_PREFIXES = listOf(
    "swlan",
    "softap",
    "ap",
    "rndis",
    "bt-pan",
    "wlan",
    "usb",
    "ncm",
    "eth",
    "p2p",
)

// The platform type `TETHERING_VIRTUAL` is the authoritative rejection for the
// AVF tap. These prefixes and the `NetworkInterface` flags are second guards
// for a broken, partial, or older platform read. They do not cover every
// vendor interface.
private val VIRTUAL_PREFIXES = listOf(
    "tun",
    "utun",
    "tap",
    "ppp",
    "ipsec",
    "dummy",
    "wg",
    "avf",
    "veth",
    "br",
    "bond",
    "vlan",
    "ifb",
    "gre",
    "sit",
    "ip6tnl",
    "erspan",
    "nfy",
)
