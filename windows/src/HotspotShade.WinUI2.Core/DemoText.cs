using System;
using System.Globalization;

namespace HotspotShade.WinUI2.Core
{
    // Every text that a person can read in the Windows prototype. Keep the
    // sentences short. Use "source device" and "target device". Every data
    // label says that the data is simulated.
    public static class DemoText
    {
        public const string AppName = "HotspotShade";
        public const string WindowTitle = "HotspotShade (simulated)";
        public const string PrototypeVersion = "0.1.0 (prototype)";
        public const string DemoBannerTitle = "Demo mode. All data is simulated.";
        public const string DemoBannerMessage = "No tunnel, routes, network listener, or credentials. This prototype is not production ready.";
        public const string SimulatedData = "Simulated data. This prototype has no engine.";
        public const string SimulatedActivity = "Simulated activity. No engine logs.";
        public const string SimulatedFailures = "Simulated. This data stays in the prototype session.";

        public const string NotPaired = "Not paired";
        public const string Paired = "Paired";
        public const string NotTrusted = "Not trusted";
        public const string Waiting = "Waiting for your source device";
        public const string Ready = "Ready";
        public const string On = "On";
        public const string Pairing = "Pairing";
        public const string PairingFailed = "Pairing failed";
        public const string NeedsAttention = "Needs attention";
        public const string StatusUnavailable = "Status unavailable";
        public const string StartingTunnel = "Starting the tunnel";
        public const string TurningOff = "Turning off";
        public const string Checking = "Checking...";
        public const string TunnelOn = "Tunnel on";
        public const string TunnelOff = "Tunnel off";
        public const string StartingValue = "Starting";
        public const string TurningOffValue = "Turning off";
        public const string NoConnectionYet = "No connection yet.";
        public const string StatusUnavailableLine = "The status is unavailable.";
        public const string CheckStatusAgain = "Check the status again.";
        public const string PairWhenReady = "Pair when you are ready.";
        public const string PairingIsSaved = "The pairing is saved.";
        public const string PairToRestoreTrust = "Pair again to restore trust.";
        public const string PairAfterTurnOff = "Turn off the tunnel, then pair again.";
        public const string TunnelUsesSourceDevice = "The tunnel uses this source device.";
        public const string LookingForSourceDevice = "The app is looking for the source device.";
        public const string ChecksEverySecond = "The app checks for the source device every second.";
        public const string ReadTheMessageAbove = "Read the message above.";
        public const string OpenSourceDeviceApp = "Open HotspotShade on your source device.";
        public const string ProxyOffSubtitle = "Start the proxy on your source device.";
        public const string UnpairedSubtitle = "Pair with your source device to use it.";
        public const string NotTrustedSubtitle = "The source device does not know this target device.";
        public const string PairingSubtitle = "Connecting to your source device.";
        public const string ReadySubtitle = "The source device is ready.";
        public const string OnSubtitle = "The tunnel is on.";
        public const string NoHotspotSubtitle = "Connect this target device to the source device hotspot.";
        public const string NotRunningSubtitle = "Open HotspotShade on your source device.";
        public const string NotRespondingSubtitle = "Open HotspotShade on your source device and keep it open.";
        public const string UnknownSubtitle = "The simulated engine sent a status that this app does not know.";
        public const string TakesAMoment = "This can take a moment.";
        public const string StartingPairing = "Connecting to the simulated source device.";
        public const string WaitingForCode = "Waiting for the code.";
        public const string CheckBothScreens = "Check both screens.";
        public const string SourceDevice = "Source device";
        public const string Connection = "Connection";
        public const string NeedsAttentionTitle = "Needs attention";
        public const string PairingTitle = "Pair your source device";
        public const string Pair = "Pair with source device";
        public const string PairAgain = "Pair again";
        public const string TurnOn = "Turn on";
        public const string TurnOff = "Turn off";
        public const string TryAgain = "Try again";
        public const string CheckNow = "Check now";
        public const string Forget = "Forget this source device";
        public const string TurnOffAndForget = "Turn off and forget";
        public const string Cancel = "Cancel";
        public const string CopyCode = "Copy code";
        public const string SimulateApproval = "Simulate approval";
        public const string SimulateFailure = "Simulate a failed pairing";
        public const string PairingSimulatedNote = "The source device is simulated. No device is contacted.";
        public const string PairingCodeDisplay = "482 193";
        public const string PairingCodePlain = "482193";
        public const string PairingCodeAccessibility = "Pairing code 4 8 2 1 9 3";
        public const string PingOn = "Ping is on.";
        public const string PingOff = "Ping is off.";
        public const string PingSettingNote = "The setting applies the next time you turn the simulated tunnel on.";
        public const string StaleStatus = "The simulated engine did not answer. This status may be out of date.";
        public const string SourceStopped = "The source device stopped answering. New connections fail.";
        public const string NotTrustedWhileRunning = "The source device forgot this target device. The tunnel keeps running until you turn it off.";
        public const string ForgetBlocked = "Turn off the tunnel to forget this source device.";
        public const string ForgetPending = "Forgetting this source device.";
        public const string ForgetConfirmed = "Forgotten. The source device removed this target device.";
        public const string ForgetNotDelivered = "The source device did not answer. This target device forgot the pairing, but the source device may still trust it.";
        public const string PairingFailedMessage = "The simulated source device did not accept the code. Try again.";
        public const string ErrorSubtitle = "The source device could not be reached. This is simulated.";
        public const string CheckingSubtitle = "Reading the simulated status.";
        public const string ActivityTitle = "Activity";
        public const string ActivityEmptyTitle = "No activity yet.";
        public const string ActivityEmptyDetail = "Turn on the simulated tunnel to add entries.";
        public const string ActivityLoading = "Loading activity...";
        public const string ActivityUnavailable = "The app cannot read simulated activity now.";
        public const string ActivityDetailsNote = "Details add the level and the sequence number.";
        public const string Refresh = "Refresh";
        public const string Details = "Details";
        public const string SettingsTitle = "Settings";
        public const string SettingsSubtitle = "These settings affect the simulated prototype only.";
        public const string General = "General";
        public const string PairingTab = "Pairing";
        public const string Advanced = "Advanced";
        public const string LetPingWork = "Let ping work";
        public const string Appearance = "Appearance";
        public const string Theme = "Theme";
        public const string ThemeSystem = "Use system setting";
        public const string ThemeLight = "Light";
        public const string ThemeDark = "Dark";
        public const string Notifications = "Notifications";
        public const string NotificationsText = "Notifications are not implemented in this prototype.";
        public const string NotificationsDetail = "Toast notifications need package identity and a manifest declaration. This prototype does not request them.";
        public const string LaunchAtLogin = "Launch at login";
        public const string LoginText = "Launch at login is not available in this prototype.";
        public const string RecentFailures = "Recent failures";
        public const string FailureStage = "Stage";
        public const string FailurePhaseNotReported = "Not reported";
        public const string FailurePhaseConnect = "Source connection";
        public const string FailurePhaseGreeting = "Greeting";
        public const string FailurePhaseAuth = "Sign-in";
        public const string FailurePhaseRequest = "Destination request";
        public const string FailurePhaseUnknown = "Unknown stage";
        public const string FailureNoAnswer = "No answer in time";
        public const string FailuresTunnelOff = "Turn the simulated tunnel on to see failures.";
        public const string FailuresIdle = "Press Refresh to read simulated failures.";
        public const string FailuresLoading = "Loading simulated failures...";
        public const string FailuresEmpty = "No failed connections yet.";
        public const string FailuresUnavailable = "This prototype cannot list failures.";
        public const string FailuresError = "The simulated failure list could not be read.";
        public const string FailuresHint = "The simulated data stays in this target device session.";
        public const string CopyReport = "Copy report";
        public const string ClearFailures = "Clear simulated failures";
        public const string ReportCopied = "The report is copied.";
        public const string CopyFailed = "The report could not be copied.";
        public const string CodeCopied = "The code is copied.";
        public const string CodeCopyFailed = "The code could not be copied.";
        public const string WiFi = "Wi-Fi";
        public const string NoWiFiAdvice = "This prototype does not read the network. No Wi-Fi advice.";
        public const string AppDetails = "App details";
        public const string AppVersion = "App version";
        public const string Platform = "Platform";
        public const string Mode = "Mode";
        public const string ModeDemo = "Demo. Data is simulated.";
        public const string Engine = "Engine";
        public const string EngineNone = "None. This prototype has no service and no tunnel.";
        public const string Status = "Status";
        public const string CopyDiagnostics = "Copy diagnostics";
        public const string DiagnosticsCopied = "The diagnostics report is copied.";
        public const string DemoLab = "Demo lab (prototype only)";
        public const string DemoLabHint = "Select a simulated state. No engine is contacted.";
        public const string Scenario = "Scenario";
        public const string ResetDemo = "Reset demo";
        public const string ResetDemoTitle = "Reset the demo?";
        public const string ResetDemoMessage = "This clears the simulated pairing, tunnel, activity, and failures.";
        public const string Reset = "Reset";
        public const string LimitationsTitle = "Prototype limits";
        public const string LimitationsText = "This is a WinUI 2 user interface prototype. It has no tunnel, no routes, no engine, no network listener, and no credentials. It is not production ready.";
        public const string AboutTitle = "About HotspotShade";
        public const string AboutText = "HotspotShade Windows UI prototype. WinUI 2 for UWP. All data is simulated. No engine is present.";
        public const string Close = "Close";
        public const string Step1 = "Open HotspotShade on your source device.";
        public const string Step2 = "Check that both screens show the same code.";
        public const string Step3 = "Tap Allow on the source device.";

        public static string PrimaryActionLabel(DemoPrimaryAction action)
        {
            switch (action)
            {
                case DemoPrimaryAction.Pair:
                    return Pair;
                case DemoPrimaryAction.PairAgain:
                    return PairAgain;
                case DemoPrimaryAction.TurnOn:
                    return TurnOn;
                case DemoPrimaryAction.TurnOff:
                    return TurnOff;
                case DemoPrimaryAction.Retry:
                    return TryAgain;
                case DemoPrimaryAction.CheckNow:
                    return CheckNow;
                default:
                    return "";
            }
        }

        public static string SecondaryActionLabel(DemoSecondaryAction action)
        {
            switch (action)
            {
                case DemoSecondaryAction.Forget:
                    return Forget;
                case DemoSecondaryAction.TurnOffAndForget:
                    return TurnOffAndForget;
                case DemoSecondaryAction.CheckNow:
                    return CheckNow;
                default:
                    return "";
            }
        }

        public static string AttentionActionLabel(DemoAttentionAction action)
        {
            switch (action)
            {
                case DemoAttentionAction.CheckNow:
                    return CheckNow;
                case DemoAttentionAction.TurnOff:
                    return TurnOff;
                case DemoAttentionAction.TurnOffAndForget:
                    return TurnOffAndForget;
                default:
                    return "";
            }
        }

        public static string ForgetMessage(DemoForgetState state)
        {
            switch (state)
            {
                case DemoForgetState.Pending:
                    return ForgetPending;
                case DemoForgetState.Confirmed:
                    return ForgetConfirmed;
                case DemoForgetState.NotDelivered:
                    return ForgetNotDelivered;
                default:
                    return "";
            }
        }

        // Read the fixed phase word. A missing word is not an error. A word
        // that this app does not know becomes a safe fixed label.
        public static DemoFailurePhase DecodeFailurePhase(string raw)
        {
            string value = (raw ?? "").Trim().ToLowerInvariant();
            if (value.Length == 0)
            {
                return DemoFailurePhase.NotReported;
            }
            switch (value)
            {
                case "connect":
                    return DemoFailurePhase.Connect;
                case "greeting":
                    return DemoFailurePhase.Greeting;
                case "auth":
                    return DemoFailurePhase.Auth;
                case "request":
                    return DemoFailurePhase.Request;
                default:
                    return DemoFailurePhase.Unknown;
            }
        }

        public static string FailurePhaseLabel(DemoFailurePhase phase)
        {
            switch (phase)
            {
                case DemoFailurePhase.Connect:
                    return FailurePhaseConnect;
                case DemoFailurePhase.Greeting:
                    return FailurePhaseGreeting;
                case DemoFailurePhase.Auth:
                    return FailurePhaseAuth;
                case DemoFailurePhase.Request:
                    return FailurePhaseRequest;
                case DemoFailurePhase.Unknown:
                    return FailurePhaseUnknown;
                default:
                    return FailurePhaseNotReported;
            }
        }

        public static string FailurePhaseWord(DemoFailurePhase phase)
        {
            switch (phase)
            {
                case DemoFailurePhase.Connect:
                    return "connect";
                case DemoFailurePhase.Greeting:
                    return "greeting";
                case DemoFailurePhase.Auth:
                    return "auth";
                case DemoFailurePhase.Request:
                    return "request";
                case DemoFailurePhase.Unknown:
                    return "unknown";
                default:
                    return "-";
            }
        }

        public static string PingLine(bool enabled)
        {
            return enabled ? PingOn : PingOff;
        }

        public static string Connections(int count)
        {
            int value = count < 0 ? 0 : count;
            return "The source device reports " + value.ToString(CultureInfo.InvariantCulture)
                + " active connection" + (value == 1 ? "" : "s") + ".";
        }

        public static string CheckedText(DateTimeOffset? checkedAt, DateTimeOffset now)
        {
            if (!checkedAt.HasValue)
            {
                return "";
            }
            TimeSpan elapsed = now - checkedAt.Value;
            double age = elapsed.TotalSeconds;
            if (age < 0)
            {
                age = 0;
            }
            if (age < 10)
            {
                return "Checked just now";
            }
            if (age < 60)
            {
                int seconds = (int)age;
                return "Checked " + seconds.ToString(CultureInfo.InvariantCulture)
                    + (seconds == 1 ? " second ago" : " seconds ago");
            }
            long minutes = elapsed.Ticks / TimeSpan.TicksPerMinute;
            return "Checked " + minutes.ToString(CultureInfo.InvariantCulture)
                + (minutes == 1 ? " minute ago" : " minutes ago");
        }

        public static string LastStop(string phrase, DateTimeOffset? at)
        {
            if (string.IsNullOrEmpty(phrase))
            {
                return "";
            }
            string text = "Last stop: " + phrase;
            if (!at.HasValue)
            {
                return text;
            }
            return text + " " + at.Value.ToLocalTime().ToString("t", CultureInfo.CurrentCulture) + ".";
        }
    }
}
