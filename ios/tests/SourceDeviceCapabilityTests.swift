import Foundation

/// Hermetic tests for the source device capability model and its place in the
/// diagnostics report. No socket, device, route, or network is used.
@main
struct SourceDeviceCapabilityTests {
    static func check(_ condition: Bool, _ message: String, line: Int = #line) {
        if !condition {
            print("FAIL line \(line): \(message)")
            exit(1)
        }
    }

    static func main() {
        let capabilities = SourceDeviceCapabilities.iosSource

        // One row for each mechanism, in a fixed order, with a stable id.
        check(capabilities.rows.count == 7, "seven capability rows")
        check(capabilities.rows.map(\.id) == [
            SourceDeviceCapabilities.Row.byteRelay,
            SourceDeviceCapabilities.Row.destinationNames,
            SourceDeviceCapabilities.Row.ech,
            SourceDeviceCapabilities.Row.serverNameOverride,
            SourceDeviceCapabilities.Row.handshakeShaping,
            SourceDeviceCapabilities.Row.relayLifetime,
            SourceDeviceCapabilities.Row.tlsTermination
        ], "the rows keep their fixed order")
        check(Set(capabilities.rows.map(\.title)).count == capabilities.rows.count,
              "each row has one title")
        for row in capabilities.rows {
            check(!row.title.isEmpty && !row.detail.isEmpty, "row \(row.id) has text")
            check(!row.symbol.isEmpty, "row \(row.id) has a symbol")
        }

        // Only the byte relay runs now. Every other row must stay off, so the
        // screen never suggests that an inactive mechanism works.
        let onRows = capabilities.rows.filter { $0.state.isOn }
        check(onRows.map(\.id) == [SourceDeviceCapabilities.Row.byteRelay],
              "only the byte relay is on: \(onRows.map(\.id))")
        check(capabilities.isOn(SourceDeviceCapabilities.Row.byteRelay),
              "the byte relay is the active mechanism")

        // ECH and a server name override are not available in a byte relay. No
        // row may claim them as on, and the ECH row must leave room for an
        // application that conceals its own name.
        check(capabilities.row(SourceDeviceCapabilities.Row.ech)?.state == .notAvailable,
              "ECH is not available in the relay")
        check(!capabilities.isOn(SourceDeviceCapabilities.Row.ech), "ECH is never on")
        check(capabilities.row(SourceDeviceCapabilities.Row.ech)?.detail.contains("no TLS session") == true,
              "the ECH detail says that the relay opens no TLS session")
        check(capabilities.row(SourceDeviceCapabilities.Row.ech)?.detail.contains("on its own") == true,
              "the ECH detail leaves application-side ECH outside the relay")
        check(capabilities.row(SourceDeviceCapabilities.Row.serverNameOverride)?.state == .notAvailable,
              "no server name override")
        check(!capabilities.isOn(SourceDeviceCapabilities.Row.serverNameOverride),
              "a server name override is never on")

        // Handshake shaping is not integrated yet. The row says so and offers
        // no control.
        let shaping = capabilities.row(SourceDeviceCapabilities.Row.handshakeShaping)
        check(shaping?.state == .notIntegrated, "shaping is not integrated")
        check(shaping?.state.label == "Not available in this build", "the shaping state word")
        check(shaping?.detail.contains("does not re-frame") == true,
              "the shaping detail names the missing relay work")
        check(shaping?.detail.contains("no control") == true,
              "the shaping detail offers no control")

        // The relay lifetime is not guaranteed in the background. The detail
        // names the platform reason and the optional keep-awake, and it does
        // not promise a background relay.
        let lifetime = capabilities.row(SourceDeviceCapabilities.Row.relayLifetime)
        check(lifetime?.state == .notGuaranteed, "the relay lifetime is not guaranteed")
        check(lifetime?.state.label == "Not guaranteed", "the lifetime state word")
        check(lifetime?.detail.contains("not guaranteed") == true,
              "the lifetime detail says that a sustained relay is not guaranteed")
        check(lifetime?.detail.contains("Network Extension") == true,
              "the lifetime detail names the missing entitlement")
        check(lifetime?.detail.contains("keep-awake") == true,
              "the lifetime detail names the background keep-awake option")
        check(lifetime?.detail.lowercased().contains("foreground only") == false,
              "the lifetime detail is not a categorical foreground-only claim")

        // TLS termination is not used. The app must not describe a certificate
        // path that it does not have.
        let termination = capabilities.row(SourceDeviceCapabilities.Row.tlsTermination)
        check(termination?.state == .notUsed, "TLS termination is not used")
        check(termination?.detail.contains("does not end TLS") == true,
              "the termination detail denies TLS interception")

        // The destination metadata may stay visible. The row states a limit,
        // and it does not claim that every TLS destination name is visible,
        // because an application can conceal its own name with ECH.
        let names = capabilities.row(SourceDeviceCapabilities.Row.destinationNames)
        check(names?.state == .mayStayVisible, "destination names may stay visible")
        check(names?.state.label == "May be visible", "the names state word")
        check(names?.detail.contains("adds no concealment") == true,
              "the names detail says that the relay adds no concealment")
        check(names?.detail.contains("may see the destination name") == true,
              "the names detail is conditional, not categorical")
        check(names?.detail.contains("Encrypted Client Hello") == true,
              "the names detail names the application-side exception")
        check(names?.detail.contains("can see the destination name") == false,
              "the names detail never claims that every name is visible")

        // The flags line matches the cross-platform contract and reports every
        // mechanism as no.
        check(!capabilities.echEnabled && !capabilities.serverNameOverrideEnabled
                && !capabilities.backgroundRelayEnabled
                && !capabilities.handshakeShapingEnabled
                && !capabilities.tlsTerminationEnabled,
              "every capability flag is off")
        check(capabilities.flagsLine
                == "Capability flags: ECH no. Server name override no. "
                + "Background relay no. Handshake shaping no. TLS termination no.",
              "the capability flags: \(capabilities.flagsLine)")

        // Each row has one diagnostics line plus the flags line.
        let lines = capabilities.diagnosticsLines
        check(lines.count == capabilities.rows.count + 1,
              "one line for each row and one flags line")
        for row in capabilities.rows {
            let expected = "Source capability - \(row.title): \(row.state.label). \(row.detail)"
            check(lines.contains(expected), "the report line for \(row.id)")
        }
        check(lines.last == capabilities.flagsLine, "the flags line comes last")

        // The Settings footer says there is no control. No row is a toggle.
        check(SourceDeviceCapabilities.settingsNote.contains("No setting on this screen"),
              "the Settings note says that no control exists")

        // The text holds no destination value and no credential.
        let capabilityText = lines.joined(separator: "\n")
        for banned in ["://", "172.20.10.1", "127.0.0.1", "@", "hotspot IP"] {
            check(!capabilityText.contains(banned), "no \(banned) in the capability text")
        }
        check(!capabilityText.lowercased().contains("token"),
              "no token in the capability text")
        check(!capabilityText.contains("Password"), "no credential in the capability text")

        // The diagnostics report keeps its old text when no capability lines
        // are supplied. The app supplies the iOS lines.
        var plain = DiagnosticsReport()
        check(!plain.text().contains("Source capability"),
              "a report without capability lines holds none")
        plain.capabilityLines = lines
        let reportText = plain.text()
        check(reportText.split(separator: "\n").first == Substring(DiagnosticsReport.header),
              "the report keeps its header")
        for line in lines {
            check(reportText.contains(line), "the report carries: \(line)")
        }
        check(!reportText.contains("://"), "the report holds no address")
        check(!reportText.lowercased().contains("token"), "the report holds no token")

        // The state words are plain and stable. A new state needs a label.
        check(SourceCapability.State.on.label == "On", "on label")
        check(SourceCapability.State.notAvailable.label == "Not available",
              "not available label")
        check(SourceCapability.State.notIntegrated.label == "Not available in this build",
              "not integrated label")
        check(SourceCapability.State.notGuaranteed.label == "Not guaranteed",
              "not guaranteed label")
        check(SourceCapability.State.mayStayVisible.label == "May be visible",
              "may be visible label")
        check(SourceCapability.State.notUsed.label == "Not used", "not used label")

        print("Source device capability tests passed")
    }
}
