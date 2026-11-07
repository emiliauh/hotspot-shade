using System;
using System.Collections.Generic;

namespace HotspotShade.WinUI2.Core
{
    // One destination-privacy mode from docs/SNI_HIDING_PLAN.md section 4.
    // The names match the shared cross-platform schema. They do not claim that
    // a mode runs on this platform.
    public enum WindowsPrivacyMode
    {
        Off,
        Shape,
        Hide,
        Cover
    }

    // What a person can do with one mode in this build.
    public enum WindowsPrivacyAvailability
    {
        // The mode is the current choice, but no service applies it.
        NotRunning,
        // Reserved for a connected service: the mode needs a source device
        // relay and none is connected. This build uses NotImplemented instead.
        NoRelay,
        // Reserved for a connected service: the mode needs the target device
        // engine and none is connected. This build uses NotImplemented instead.
        NoEngine,
        // The build has no implementation of the mode, so no connection makes
        // it usable.
        NotImplemented,
        // The mode needs one TLS endpoint that the person owns.
        Deferred
    }

    // One mode row for the Settings card. The state is always a sentence, not
    // only a color. No row can turn a mode on in this prototype.
    public sealed class WindowsPrivacyModeRow
    {
        public WindowsPrivacyModeRow(
            WindowsPrivacyMode mode,
            string title,
            WindowsPrivacyAvailability availability,
            string detail)
        {
            Mode = mode;
            Title = title ?? "";
            Availability = availability;
            Detail = detail ?? "";
        }

        public WindowsPrivacyMode Mode { get; private set; }

        public string Title { get; private set; }

        public WindowsPrivacyAvailability Availability { get; private set; }

        public string StateText
        {
            get { return WindowsPrivacyText.AvailabilityText(Availability); }
        }

        // No mode has a working control in this build.
        public bool CanEnable
        {
            get { return false; }
        }

        public bool IsCurrent
        {
            get { return Mode == WindowsPrivacyMode.Off; }
        }

        public string Detail { get; private set; }

        public string AccessibilityLabel
        {
            get { return Title + ". " + StateText + " " + Detail; }
        }
    }

    // One capability fact. The identifiers follow the cross-platform flags in
    // docs/SNI_HIDING_PLAN.md section 6.
    public sealed class WindowsPrivacyFact
    {
        public WindowsPrivacyFact(string id, string title, string valueText, string detail)
        {
            Id = id ?? "";
            Title = title ?? "";
            ValueText = valueText ?? "";
            Detail = detail ?? "";
        }

        public string Id { get; private set; }

        public string Title { get; private set; }

        public string ValueText { get; private set; }

        public string Detail { get; private set; }

        public string AccessibilityLabel
        {
            get { return Title + ". " + ValueText + " " + Detail; }
        }
    }

    // The truthful destination-privacy report for the Windows target UI.
    // Every value is fixed text. The report holds no host, address, name,
    // token, or key, and it is never written to storage.
    public sealed class WindowsPrivacyReport
    {
        public WindowsPrivacyReport(
            WindowsPrivacyMode selectedMode,
            string intro,
            IReadOnlyList<WindowsPrivacyModeRow> modes,
            IReadOnlyList<WindowsPrivacyFact> facts,
            IReadOnlyList<string> limits,
            string outOfScopeNote,
            string storageNote)
        {
            SelectedMode = selectedMode;
            Intro = intro ?? "";
            Modes = modes ?? Array.Empty<WindowsPrivacyModeRow>();
            Facts = facts ?? Array.Empty<WindowsPrivacyFact>();
            Limits = limits ?? Array.Empty<string>();
            OutOfScopeNote = outOfScopeNote ?? "";
            StorageNote = storageNote ?? "";
        }

        public WindowsPrivacyMode SelectedMode { get; private set; }

        public string ModeText
        {
            get { return WindowsPrivacyText.ModeTitle(SelectedMode); }
        }

        public string ModeStateText
        {
            get
            {
                for (int index = 0; index < Modes.Count; index++)
                {
                    if (Modes[index].Mode == SelectedMode)
                    {
                        return Modes[index].StateText;
                    }
                }
                return "";
            }
        }

        public string Intro { get; private set; }

        public IReadOnlyList<WindowsPrivacyModeRow> Modes { get; private set; }

        public IReadOnlyList<WindowsPrivacyFact> Facts { get; private set; }

        // The lines that say what no mode here changes.
        public IReadOnlyList<string> Limits { get; private set; }

        // The line that keeps TLS termination outside this product.
        public string OutOfScopeNote { get; private set; }

        // The line that says this page saves nothing.
        public string StorageNote { get; private set; }

        // True only if a connected service applies the selected mode. This
        // prototype has no service, so the value is always false.
        public bool AppliesAnyMode
        {
            get { return false; }
        }

        // True only if a person can choose a mode. No control is offered while
        // no service backs one, so the value is always false.
        public bool CanSelectMode
        {
            get { return false; }
        }

        // The capability flags that the plan asks every report to state.
        public string FlagsLine
        {
            get { return WindowsPrivacyText.FlagsLine; }
        }
    }

    // Fixed text for the destination-privacy report. Every sentence says what
    // this build does now. No sentence promises a future mode.
    public static class WindowsPrivacyText
    {
        public const string Intro =
            "No destination-privacy mode is on. This prototype has no engine, so "
            + "it does not normalize TTL, reshape a handshake, or encrypt a name "
            + "lookup. A carrier can still see destination names unless an "
            + "application uses its own ECH or encrypted DNS. This product adds "
            + "neither protection.";

        public const string NotRunning =
            "Not in force. No service is connected.";

        public const string NoRelay =
            "Unavailable. No source device relay is connected.";

        public const string NoEngine =
            "Unavailable. No engine is connected.";

        public const string NotImplemented =
            "Unavailable. This build does not implement the mode.";

        public const string Deferred =
            "Deferred. Needs an endpoint you own.";

        public const string OutOfScopeNote =
            "TLS termination is out of scope. This app ends no TLS, presents no "
            + "certificate, and installs no certificate authority on your devices.";

        public const string StorageNote =
            "Nothing on this page is a switch. This prototype saves no mode, "
            + "applies no mode, and has no engine.";

        public const string FlagsLine =
            "Capability flags: ech no. sni_override no. background_relay no.";

        public static string AvailabilityText(WindowsPrivacyAvailability availability)
        {
            switch (availability)
            {
                case WindowsPrivacyAvailability.NoRelay:
                    return NoRelay;
                case WindowsPrivacyAvailability.NoEngine:
                    return NoEngine;
                case WindowsPrivacyAvailability.NotImplemented:
                    return NotImplemented;
                case WindowsPrivacyAvailability.Deferred:
                    return Deferred;
                default:
                    return NotRunning;
            }
        }

        public static string ModeTitle(WindowsPrivacyMode mode)
        {
            switch (mode)
            {
                case WindowsPrivacyMode.Shape:
                    return "Shape the TLS handshake";
                case WindowsPrivacyMode.Hide:
                    return "Hide the destination name";
                case WindowsPrivacyMode.Cover:
                    return "Cover with an endpoint you own";
                default:
                    return "Off";
            }
        }
    }

    // Build the destination-privacy report for this build. The method is a
    // pure function of fixed text. It reads no interface, address, or token,
    // and it changes no setting.
    //
    // This app is a demo with no service. When a service reports a mode, this
    // report must take its capability data and its availability. Do not change
    // a row to available on UI work alone. An engine change alone cannot enable
    // a mode that needs another application's TLS handshake.
    public static class WindowsPrivacyCapabilities
    {
        public static WindowsPrivacyReport Build()
        {
            return new WindowsPrivacyReport(
                WindowsPrivacyMode.Off,
                WindowsPrivacyText.Intro,
                new WindowsPrivacyModeRow[]
                {
                    new WindowsPrivacyModeRow(
                        WindowsPrivacyMode.Off,
                        "Off",
                        WindowsPrivacyAvailability.NotRunning,
                        "Not in force. Off describes a running tunnel that "
                        + "normalizes TTL and pins outer connections. This prototype "
                        + "has no engine, so no traffic is normalized. Off adds no "
                        + "name concealment. Unless an application uses its own "
                        + "ECH or encrypted DNS, a carrier can see the TLS server "
                        + "name and DNS names. The destination address and "
                        + "network, the TLS fingerprint, and the flow size and "
                        + "timing can remain visible. This product adds no such "
                        + "protection."),
                    new WindowsPrivacyModeRow(
                        WindowsPrivacyMode.Shape,
                        "Shape the TLS handshake",
                        WindowsPrivacyAvailability.NotImplemented,
                        "Not implemented in this build. The engine does not "
                        + "re-cut TLS records, and a connected relay would not "
                        + "enable the mode. A future shape would split the "
                        + "plaintext ClientHello records without changing a byte. "
                        + "It would not hide the server name, the destination "
                        + "address or network, the TLS fingerprint, or the flow "
                        + "size and timing. It could not pad the handshake or "
                        + "force TLS 1.3."),
                    new WindowsPrivacyModeRow(
                        WindowsPrivacyMode.Hide,
                        "Hide the destination name",
                        WindowsPrivacyAvailability.NotImplemented,
                        "Unavailable under the current design. The engine copies each application's TLS "
                        + "bytes without opening a TLS session. Adding a TLS "
                        + "client to the engine would not change another "
                        + "application's ClientHello, so it could not add ECH for "
                        + "relayed traffic. This build has no engine and no ECH, "
                        + "so the mode is unavailable. An application may use ECH "
                        + "or encrypted DNS on its own; this product adds no such "
                        + "protection, and destination address, TLS fingerprint, "
                        + "and flow size and timing can remain visible."),
                    new WindowsPrivacyModeRow(
                        WindowsPrivacyMode.Cover,
                        "Cover with an endpoint you own",
                        WindowsPrivacyAvailability.Deferred,
                        "It needs one TLS endpoint that you own. The project "
                        + "includes no external relay or VPS, so this mode is "
                        + "deferred. It would add an extra hop that this product "
                        + "avoids. Naming another service's site is out of scope.")
                },
                new WindowsPrivacyFact[]
                {
                    new WindowsPrivacyFact(
                        "service",
                        "Engine and service",
                        "None. No service is connected.",
                        "This prototype has no service client. It cannot read or "
                        + "change a mode, and it cannot start a tunnel."),
                    new WindowsPrivacyFact(
                        "ech",
                        "Encrypted Client Hello (ECH)",
                        "No. Not provided by this build.",
                        "The cross-platform flag is ech no. The engine copies "
                        + "application TLS bytes without opening a TLS session, so "
                        + "adding a TLS library to it cannot add ECH to another "
                        + "application's ClientHello. This app opens no TLS session "
                        + "and provides no ECH."),
                    new WindowsPrivacyFact(
                        "sni_override",
                        "Server name override",
                        "No. Not provided by this build.",
                        "The cross-platform flag is sni_override no. The engine "
                        + "would have to own the TLS client for a flow. It relays "
                        + "bytes and owns no application TLS session, so it cannot "
                        + "set the name."),
                    new WindowsPrivacyFact(
                        "background_relay",
                        "Background relay",
                        "Not applicable on a target device.",
                        "The cross-platform flag is background_relay no. A relay "
                        + "runs on the source device. This app is the target "
                        + "device UI, starts no relay, and makes no promise about "
                        + "source device background operation.")
                },
                new string[]
                {
                    "Off hides no destination name. Unless an application uses "
                        + "its own ECH or encrypted DNS, a carrier can see the TLS "
                        + "server name and DNS names. The destination address and "
                        + "network, the TLS fingerprint, and the flow size and "
                        + "timing can remain visible even then. This product does "
                        + "not add those protections.",
                    "Tethering detection is a separate problem. It can use more "
                        + "than TTL, such as TCP and operating-system fingerprints "
                        + "or volume patterns, and no mode on this page addresses "
                        + "it.",
                    "No mode on this page makes a claim about your plan, its "
                        + "terms, or its billing. Use your own plan and read its "
                        + "terms.",
                    "This is the target device UI. It is not a source device relay "
                        + "and does not end TLS."
                },
                WindowsPrivacyText.OutOfScopeNote,
                WindowsPrivacyText.StorageNote);
        }
    }
}
