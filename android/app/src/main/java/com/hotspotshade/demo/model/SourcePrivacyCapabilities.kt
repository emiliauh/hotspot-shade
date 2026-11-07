package com.hotspotshade.demo.model

/**
 * One destination-privacy mode from `docs/SNI_HIDING_PLAN.md` section 4.
 *
 * Off, shape, hide, and cover are the four shared schema names from section 6
 * of the plan. Terminate is the plan's out-of-scope mode, kept here so a person
 * can read that the project excluded it. The names do not change any wire
 * label, and they do not assert that a mode runs on this platform. Only [OFF]
 * is the default of this build.
 *
 * Section 2.4 of the plan leaves the client boundary for `hide` unresolved.
 * Ordinary applications originate their own TLS, so `hide` is a proposal and
 * not a feature of any engine.
 */
enum class PrivacyMode(val title: String) {
    /**
     * TTL normalization only. The relay adds no name concealment, so a
     * destination name can stay visible unless an application hides it itself.
     */
    OFF("Off"),

    /** Proposed. Byte-preserving TLS record re-framing on the relay socket. */
    SHAPE("Shape the TLS handshake"),

    /**
     * Proposed. ECH and DNS over HTTPS for a TLS client that the product
     * owns. Ordinary applications originate their own TLS, and no client
     * boundary is settled, so this mode is unavailable.
     */
    HIDE("Hide the destination name"),

    /** Deferred. One TLS tunnel to an endpoint that the person owns. */
    COVER("Cover with an endpoint you own"),

    /**
     * Out of scope. A certificate authority on the target device makes that
     * device the TLS client.
     */
    TERMINATE("Terminate TLS on this device"),
    ;

    companion object {
        /** Every mode, in display order. */
        val all: List<PrivacyMode> = entries.toList()
    }
}

/**
 * What this build provides for one mode.
 *
 * The report holds no service, proxy, or tunnel state. Only [DEFAULT] is
 * available in this build, and that value is a build default, not a live
 * indicator. Every other value must render as its plain state words, and the
 * page must not offer a switch for it. A mode is not [DEFAULT] merely because
 * its code exists somewhere in the project, on this platform or another one.
 */
enum class PrivacyAvailability(val valueText: String) {
    /**
     * The default mode of this build. It says nothing about a running proxy or
     * tunnel, and the page reports no such state.
     */
    DEFAULT(
        "Default. This is the default mode of this build. It is not a running " +
            "state, and this page reports no proxy or tunnel state.",
    ),

    /** The mode is proposed. No switch and no relay path in this app apply it. */
    PROPOSED("Unavailable. Proposed, not built."),

    /** The mode is deferred until the owner has an endpoint for it. */
    DEFERRED("Unavailable. Deferred. No endpoint is configured."),

    /** The project decided not to build the mode. */
    OUT_OF_SCOPE("Excluded. Out of scope for this project."),
    ;

    /**
     * True only when this build provides the mode. It is a build fact, not a
     * running state.
     */
    val availableInBuild: Boolean get() = this == DEFAULT
}

/**
 * One capability fact that the settings page reports.
 *
 * The facts follow the flags in `docs/SNI_HIDING_PLAN.md` section 6. A report
 * says what this build does, not what a platform could do for another app.
 */
enum class CapabilityFact(val title: String) {
    /** The Android version is reported to expose an ECH API to a TLS client. */
    ECH_PLATFORM("ECH in the Android platform"),

    /** The byte relay itself uses ECH. */
    ECH_RELAY("ECH in the byte relay"),

    /** The relay can set the TLS server name. */
    SNI_CONTROL("SNI control in the relay"),

    /** The proxy keeps running while the app is not in front. */
    BACKGROUND_RELAY("Background relay"),
}

/** One mode row for the settings page. */
data class PrivacyModeRow(
    val mode: PrivacyMode,
    val availability: PrivacyAvailability,
    val detail: String,
) {
    /** The row title. It is the shared mode name, not a local label. */
    val title: String get() = mode.title

    /**
     * The state line. It always names the state in words, not in color. It
     * reports build availability, never a running proxy or tunnel.
     */
    val stateText: String get() = availability.valueText

    /** True only when this build provides the mode. It reports no run state. */
    val availableInBuild: Boolean get() = availability.availableInBuild
}

/** One capability fact row for the settings page. */
data class CapabilityFactRow(
    val fact: CapabilityFact,
    val valueText: String,
    val detail: String,
) {
    /** The row title. */
    val title: String get() = fact.title
}

/**
 * The truthful source device capability report.
 *
 * The report is built from fixed text and the platform level. It holds no
 * host, address, name, key, or token, and it is never written to storage. It
 * holds no service, proxy, or tunnel state either, so no row can claim that a
 * mode is running. Nothing in the app can set a mode through this report, so
 * the settings page cannot show a mode as on while no relay path applies it.
 * The page is a read-only report, it offers no switch, and it saves nothing.
 */
data class SourcePrivacyReport(
    val defaultMode: PrivacyMode,
    val modes: List<PrivacyModeRow>,
    val facts: List<CapabilityFactRow>,
    val intro: String,
    val limits: List<String>,
    val storageNote: String,
) {
    /** The default mode line. It is not a runtime or tunnel state. */
    val defaultModeText: String get() = defaultMode.title

    /** The mode rows that this build does not provide. */
    val unavailableModes: List<PrivacyModeRow> get() = modes.filter { !it.availableInBuild }

    /** A fixed summary. It holds no name, address, key, or token. */
    override fun toString(): String =
        "SourcePrivacyReport(default_mode=${defaultMode.name.lowercase()}, " +
            "modes=${modes.size}, facts=${facts.size})"
}

/**
 * Build the capability report for this source device app.
 *
 * The report is a pure function of the platform level. It reads no interface,
 * no address, no token, and no service or tunnel state. It changes no proxy
 * setting and saves nothing, so the page stays honest while shape, hide, and
 * cover are proposals. `hide` is unavailable and its client boundary is
 * unresolved: this app cannot add ECH to a TLS handshake that another
 * application builds.
 */
object SourcePrivacyCapabilities {
    /**
     * The Android release that the plan credits with a platform ECH setting for
     * apps that open TLS themselves.
     *
     * That credit comes from vendor documentation, not from a check made here.
     * This app compiles against API 36, opens no TLS session for a target flow,
     * and does not call that setting. The value is a plain number so the report
     * works on a build that cannot name the newer platform class.
     */
    const val PLATFORM_ECH_API = 37

    /**
     * The default mode of this build.
     *
     * It is a build fact, not a running state. The report has no service or
     * tunnel state, so it cannot say that the proxy runs.
     */
    private val DEFAULT_MODE = PrivacyMode.OFF

    /** The paragraph above the mode rows. */
    const val INTRO =
        "No destination-privacy mode is built in. The relay copies bytes and " +
            "never reads TLS, so it conceals no destination name. A " +
            "destination name can still be visible to the carrier, in DNS and " +
            "in the TLS handshake, unless an application hides it with its own " +
            "ECH or encrypted DNS."

    /**
     * What the off mode does not hide.
     *
     * These lines are the product claim. They must stay accurate when a new
     * mode ships. They describe what the relay does, not what every application
     * on the device does, because an application can conceal its own name.
     */
    val LIMITS: List<String> = listOf(
        "Off hides nothing in the relay. For a flow that the application does " +
            "not conceal itself, the carrier can see the TLS server name, the " +
            "destination address and network, DNS names, the TLS fingerprint, " +
            "and the flow size and timing.",
        "An application can use its own ECH or encrypted DNS. That work happens " +
            "outside this relay, and this build neither provides it nor prevents " +
            "it. It is not a mode of this app.",
        "Tethering detection also uses the TCP and operating-system fingerprint " +
            "and volume patterns. No mode on this page changes those.",
        "The source relay is not a TLS tunnel, so it adds no nested handshake " +
            "to detect. That is a property of the existing relay, not of a mode.",
    )

    /** The line that states that this page saves nothing and reports no run. */
    const val STORAGE_NOTE =
        "This page is a report, not a control. Nothing here is a switch, the " +
            "app saves no mode, the page does not change the proxy, and it " +
            "reports no proxy or tunnel state."

    /** Build one report for the given platform level. */
    fun report(sdkInt: Int): SourcePrivacyReport = SourcePrivacyReport(
        defaultMode = DEFAULT_MODE,
        modes = listOf(
            PrivacyModeRow(
                mode = PrivacyMode.OFF,
                // The default of this build. The report holds no run state, so
                // this row cannot say that the relay runs.
                availability = PrivacyAvailability.DEFAULT,
                detail = "TTL normalization only. The relay opens one cellular " +
                    "socket per flow and copies the payload unchanged. It hides " +
                    "no destination name.",
            ),
            PrivacyModeRow(
                mode = PrivacyMode.SHAPE,
                // Shaping is a proposal. The Android relay copies every byte,
                // and other work owns any relay change. Change this row only
                // with a tested relay change and a real switch, never on its
                // own.
                availability = PrivacyAvailability.PROPOSED,
                detail = "Proposed, not built. The Android relay copies every " +
                    "byte of each flow, so it cannot re-cut the first TLS " +
                    "records. It would not hide the server name, the destination " +
                    "address, DNS names, the TLS fingerprint, or the flow size, " +
                    "and it cannot pad the handshake.",
            ),
            PrivacyModeRow(
                mode = PrivacyMode.HIDE,
                // Proposed and unavailable. Ordinary applications originate
                // their own TLS, and no client boundary is settled, so this is
                // not a feature of the target engine or of this relay today.
                availability = PrivacyAvailability.PROPOSED,
                detail = "Proposed, not built. It needs a TLS client that the " +
                    "product owns, because an ordinary application builds its " +
                    "own handshake and a relay cannot add ECH to it. No client " +
                    "boundary is settled and no code exists in this build, so " +
                    "no name is hidden. If it were built, it would cover only " +
                    "destinations that publish an ECH config, and it would not " +
                    "hide the destination address, the TLS fingerprint, or the " +
                    "flow size.",
            ),
            PrivacyModeRow(
                mode = PrivacyMode.COVER,
                availability = PrivacyAvailability.DEFERRED,
                detail = "Deferred. It needs one TLS endpoint that you own. The " +
                    "project keeps no external relay or VPS, so this build " +
                    "offers no switch and no code depends on it. Presenting " +
                    "another service's name stays out of scope.",
            ),
            PrivacyModeRow(
                mode = PrivacyMode.TERMINATE,
                availability = PrivacyAvailability.OUT_OF_SCOPE,
                detail = "Excluded. It would need a certificate authority " +
                    "trusted on the target device, break certificate pinning, " +
                    "and add a second TLS session. The project does not build " +
                    "it.",
            ),
        ),
        facts = listOf(
            CapabilityFactRow(
                fact = CapabilityFact.ECH_PLATFORM,
                // The version number is an API-presence hint, not proof that a
                // device, an OS build, or a network supports or uses ECH.
                valueText = if (sdkInt >= PLATFORM_ECH_API) {
                    "Reported API surface, unverified"
                } else {
                    "No API surface on this Android version"
                },
                detail = "Android 17 (API 37) is reported to add an ECH " +
                    "setting for apps that open TLS themselves. This row reads " +
                    "the version number only. It checks no SDK header, device, " +
                    "or network, and an API that is present is not proof that a " +
                    "device or a network supports or uses ECH. This app compiles " +
                    "against API 36, opens no TLS session for a target flow, and " +
                    "the relay does not use ECH.",
            ),
            CapabilityFactRow(
                fact = CapabilityFact.ECH_RELAY,
                valueText = "Never used",
                detail = "ECH hides a server name inside a TLS handshake that an " +
                    "app opens. The byte relay opens no TLS session, so ECH " +
                    "cannot apply to a relayed flow, and the relay conceals no " +
                    "name.",
            ),
            CapabilityFactRow(
                fact = CapabilityFact.SNI_CONTROL,
                valueText = "Not available in the relay",
                detail = "A relay cannot change the ClientHello, because the " +
                    "destination checks the whole handshake. Android's TLS " +
                    "client can set a server name for a connection that this " +
                    "app opens, and this app opens none for a target flow.",
            ),
            CapabilityFactRow(
                fact = CapabilityFact.BACKGROUND_RELAY,
                valueText = "Foreground service, not guaranteed",
                detail = "The proxy runs as a foreground service with a " +
                    "notification. Android can still stop it, for example when " +
                    "memory is short, and the app does not restart it by " +
                    "itself. No background operation is promised.",
            ),
        ),
        intro = INTRO,
        limits = LIMITS,
        storageNote = STORAGE_NOTE,
    )
}
