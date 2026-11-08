using System;
using System.Globalization;

namespace HotspotShade.WinUI2.Core.App
{
    // Every text that a person can read in the Windows app. The sentences
    // follow the macOS app (Strings.swift and UIStrings.swift) so both apps
    // say the same thing. Use "source device" and "target device".
    public static class AppText
    {
        public const string App = "HotspotShade";
        public const string WindowTitle = "HotspotShade";

        // Dashboard titles and subtitles.
        public const string TurnOn = "Turn on";
        public const string TurnOff = "Turn off";
        public const string Waiting = "Waiting for your source device";
        public const string On = "On";
        public const string Stopping = "Turning off";
        public const string Attention = "Needs attention";
        public const string StartingEngine = "Starting HotspotShade";
        public const string StartingEngineSubtitle = "Starting the engine.";
        public const string StartingTunnel = "Starting the tunnel";
        public const string Ready = "Ready";
        public const string Paired = "Paired";
        public const string NotPaired = "Not paired";
        public const string NotTrustedTitle = "Not trusted";
        public const string Pair = "Pair with source device";
        public const string PairAgain = "Pair again";
        public const string UnpairedSubtitle = "Pair with your source device to use it.";
        public const string NotTrustedSubtitle = "The source device does not know this target device.";
        public const string Pairing = "Pairing";
        public const string PairingSubtitle = "Connecting to your source device.";
        public const string ProxyOffSubtitle = "Start the proxy on your source device.";
        public const string ReadySubtitle = "The source device is ready.";
        public const string OnSubtitle = "The tunnel is on.";
        public const string TakesAMinute = "This can take a minute.";
        public const string NotRespondingSubtitle = "Open HotspotShade on your source device and keep it open.";
        public const string OpenSourceDeviceApp = "Open HotspotShade on your source device.";
        public const string NoHotspotSubtitle = "Connect this target device to the source device hotspot.";
        public const string NotRunningSubtitle = "Open HotspotShade on your source device.";
        public const string CheckingSubtitle = "HotspotShade is checking the source device.";
        public const string UnknownTitle = "Status unavailable";
        public const string UnknownSubtitle = "HotspotShade received a status that it does not understand.";

        public const string ServiceStateUnknownTitle = "Status unknown";
        public const string ServiceStateUnknownBody = "The service state is unavailable after an interrupted operation. Inspect routes, devices, and the start record before restarting.";
        public const string ServiceStateUnknownHint = "HotspotShade cannot tell whether the tunnel is on. Turn on and Turn off stay disabled until the target device is checked.";
        public const string CleanupBlockedTitle = "Tunnel cleanup did not finish";
        public const string CleanupBlockedBody = "The tunnel is off, but cleanup did not finish. Inspect routes, devices, and the start record before restarting.";
        public const string CleanupBlockedHint = "Turn on stays disabled until the target device is checked.";
        public const string SourceStoppedTitle = "The source device stopped answering. New connections fail.";

        public const string Close = "Close";
        public const string PairingCode = "Pairing code";
        public const string PairingTitle = "Pair your source device";
        public const string Allow = "Tap Allow on the source device.";
        public const string Cancel = "Cancel";
        public const string Settings = "Settings";
        public const string Forget = "Forget this source device";
        public const string Advanced = "Advanced";
        public const string NoLogs = "No activity yet.";
        public const string TryAgain = "Try again";
        public const string LetPingWork = "Let ping work";
        public const string LetPingWorkHint = "Uses an experimental echo relay on the source device. Applies the next time you turn the tunnel on.";
        public const string PingOn = "Ping is on.";
        public const string PingOff = "Ping is off.";
        public const string RecentFailures = "Recent failures";
        public const string Refresh = "Refresh";
        public const string CopyReport = "Copy report";
        public const string LoadingFailures = "Loading failures...";
        public const string FailuresNotLoaded = "Press Refresh to read failures.";
        public const string NoFailures = "No failed connections yet.";
        public const string FailuresUnavailable = "This engine cannot list failures.";
        public const string FailuresHint = "The data stays on this target device.";
        public const string ReportCopied = "The report is copied.";
        public const string CopyFailed = "The text could not be copied.";

        public const string ForgetBlocked = "Turn off the tunnel to forget this source device.";
        public const string TurnOffAndForget = "Turn off and forget";
        public const string AlreadyPaired = "This target device is already paired.";
        public const string ForgetPending = "Forgetting...";
        public const string ForgetResult = "Could not confirm that the source device removed this pairing. This target device forgot the pairing, but the source device may still trust it.";
        public const string TrustedBySource = "The source device still knows this target device. Press Pair to continue.";
        public const string NotTrustedWhileRunning = "The source device forgot this target device. The tunnel keeps running until you turn it off.";
        public const string PhoneTokenRejected = "The source device changed its token. Open HotspotShade on your source device, then pair again.";

        // The fixed engine text for a refused gateway check
        // (source_gateway_unproven in rust/src/gui.rs). The window shows the
        // text that the engine sends; this copy is for the checks.
        public const string GatewayUnproven = "The source device must be the default gateway of a physical hotspot adapter. Turn off any VPN, connect to the source device hotspot, then try again.";
        public const string StaleStatus = "HotspotShade did not answer. This status may be out of date.";
        public const string StatusUnavailableSubtitle = "HotspotShade did not answer.";
        public const string TestDataEngine = "The engine sent an answer that HotspotShade cannot read: it holds test data, which this app never shows. If this happens again, reinstall HotspotShade.";
        public const string CheckNow = "Check now";
        public const string CheckedJustNow = "Checked just now";
        public const string WaitForAction = "Wait for the current action to finish.";
        public const string CancelingPairing = "Canceling pairing.";
        public const string PairingNeedsAttention = "Check the code on your source device.";
        public const string DiagnosticsCopied = "The diagnostics report is copied.";

        // Windows privilege and engine text. The administrator approval is a
        // UAC prompt at Turn on, never at app open.
        public const string AdminAuthorization = "Windows asks for administrator approval when you turn on the tunnel.";
        public const string ElevatedSource = "The tunnel engine runs with administrator rights. It stops when you turn the tunnel off or quit HotspotShade.";
        public const string StopUnconfirmed = "HotspotShade could not confirm that the tunnel stopped. Turn off again. If that fails, quit HotspotShade and run route print to check the routes.";
        public const string ElevatedLost = "The administrator engine exited without a confirmed stop. Its routes are not verified. Run route print in a console to check the routes on this target device. Turn on stays disabled until HotspotShade restarts.";
        public const string BrokerMissing = "HotspotShade could not start its engine helper. Reinstall HotspotShade.";
        public const string BrokerNeverConnected = "HotspotShade started its engine helper, but the helper never connected. Press Try again.";
        public const string BrokerLost = "HotspotShade lost its engine helper after it connected. Press Try again.";

        // Cards and sections.
        public const string Dashboard = "Dashboard";
        public const string Activity = "Activity";
        public const string General = "General";
        public const string PairingTab = "Pairing";
        public const string SourceDevice = "Source device";
        public const string Connection = "Connection";
        public const string NoConnectionYet = "No connection yet.";
        public const string StatusUnavailableLine = "The status is unavailable.";
        public const string UnknownValue = "Unknown";
        public const string UnknownCardHint = "Inspect routes, devices, and the start record before restarting.";
        public const string TunnelOn = "Tunnel on";
        public const string TunnelOff = "Tunnel off";
        public const string ConnectionStarting = "Starting";
        public const string PairToRestoreTrust = "Pair again to restore trust.";
        public const string PressPairToContinue = "Press Pair to continue.";
        public const string PairingIsSaved = "The pairing is saved.";
        public const string LookingForSourceDevice = "The app is looking for the source device.";
        public const string ChecksEverySecond = "The app checks for the source device every second.";
        public const string TunnelUsesSourceDevice = "The tunnel uses this source device.";
        public const string ReadTheMessageAbove = "Read the message above.";
        public const string CheckStatusAgain = "Check the status again.";

        public const string CheckBothScreens = "Check both screens.";
        public const string PairWhenReady = "Pair when you are ready.";
        public const string WaitingForCode = "Waiting for the code.";
        public const string PairingStepOpen = "Open HotspotShade on your source device.";
        public const string PairingStepCompare = "Check that both screens show the same code.";
        public const string PairingStepAllow = "Tap Allow on the source device.";
        public const string CopyCode = "Copy code";
        public const string CodeCopied = "The code is copied.";

        public const string Details = "Details";
        public const string ActivityEmpty = NoLogs;
        public const string ActivityUnavailable = "The app cannot read activity now.";
        public const string LoadingActivity = "Loading activity...";
        public const string ActivityDetailsNote = "Details add the level and the sequence number.";

        public const string ForgetHint = "Forget removes this pairing from this target device.";
        public const string AppDetails = "App details";
        public const string AppVersion = "App version";
        public const string WindowsVersion = "Windows";
        public const string Status = "Status";
        public const string EngineRole = "Engine";
        public const string EngineRoleUser = "Standard user engine";
        public const string EngineRoleElevated = "Administrator engine";
        public const string EngineRoleNone = "Not running";
        public const string CopyDiagnostics = "Copy diagnostics";
        public const string Appearance = "Appearance";
        public const string AppearanceSystem = "Use the Windows setting";
        public const string AppearanceLight = "Light";
        public const string AppearanceDark = "Dark";

        // Features that this build does not have. They are not offered and
        // are listed here so a person knows they are missing.
        public const string UnavailableHeading = "Not available on Windows yet";
        public const string UnavailableNotifications = "Notifications.";
        public const string UnavailableLaunchAtLogin = "Launch at login.";
        public const string UnavailableTray = "A notification area icon.";
        public const string UnavailableDirect = "Direct mode without the source device app.";

        public const string CountColumn = "Count";
        public const string KindColumn = "Kind";
        public const string TargetColumn = "Target";
        public const string StageColumn = "Stage";
        public const string ReasonColumn = "Reason";

        public static string CheckedSeconds(int count)
        {
            return "Checked " + count.ToString(CultureInfo.InvariantCulture) + " second" + (count == 1 ? "" : "s") + " ago";
        }

        public static string CheckedMinutes(int count)
        {
            return "Checked " + count.ToString(CultureInfo.InvariantCulture) + " minute" + (count == 1 ? "" : "s") + " ago";
        }

        public static string Connections(int count)
        {
            return "The source device reports " + count.ToString(CultureInfo.InvariantCulture) + " active connection" + (count == 1 ? "" : "s") + ".";
        }

        public static string LastStop(string message)
        {
            return "Last stop: " + message;
        }

        public static string TtlAudit(long count)
        {
            return "The TTL check found " + count.ToString(CultureInfo.InvariantCulture) + " outgoing connection" + (count == 1 ? "" : "s") + " with the wrong TTL. Turn the tunnel off and copy diagnostics.";
        }

        // The engine can come from an older build. Hide the old product name.
        public static string Sanitized(string message)
        {
            if (string.IsNullOrEmpty(message))
            {
                return null;
            }
            int at = message.IndexOf("Hotspot Proxy", StringComparison.OrdinalIgnoreCase);
            while (at >= 0)
            {
                message = message.Substring(0, at) + App + message.Substring(at + "Hotspot Proxy".Length);
                at = message.IndexOf("Hotspot Proxy", StringComparison.OrdinalIgnoreCase);
            }
            return message;
        }

        // One sentence for each fixed broker code. The text never names a
        // path, a port, a handle, or a secret.
        public static string BrokerMessage(string code)
        {
            switch (code)
            {
                case BrokerCodes.Busy:
                    return WaitForAction;
                case BrokerCodes.EngineStarting:
                    return StartingEngineSubtitle;
                case BrokerCodes.EngineMissing:
                    return "The engine is missing from this install. Reinstall HotspotShade.";
                case BrokerCodes.EngineExited:
                    return "The engine stopped. Press Try again to start it again.";
                case BrokerCodes.ListenerNotOwned:
                    return "Another program uses the engine port, so HotspotShade sent nothing to it. Press Try again.";
                case BrokerCodes.ListenerUnknown:
                    return "HotspotShade could not check the engine port, so it sent nothing. Press Try again.";
                case BrokerCodes.Timeout:
                    return "The engine did not answer in time.";
                case BrokerCodes.BadResponse:
                case BrokerCodes.ReplyTooLarge:
                    return "The engine sent an answer that HotspotShade cannot read.";
                case BrokerCodes.ElevatedActive:
                    return "Turn off the tunnel first.";
                case BrokerCodes.NotPaired:
                    return UnpairedSubtitle;
                case BrokerCodes.TunnelRunning:
                    return "The tunnel is already on.";
                case BrokerCodes.HandoffUnsupported:
                    return "The engine did not accept the pairing handoff pipe at launch, so Turn on is unavailable. Rebuild the engine from the current source. If it still happens, copy diagnostics and report it.";
                case BrokerCodes.HandoffFailed:
                    return "The engine could not pass the pairing to the administrator engine, so the tunnel did not start. Try again.";
                case BrokerCodes.AdapterDllMissing:
                    return "wintun.dll is missing from this install, so Turn on is unavailable. Add the official wintun.dll and reinstall HotspotShade.";
                case BrokerCodes.InstallUntrusted:
                    return "This copy of HotspotShade is not installed from a package in a protected Windows apps folder, so Turn on is unavailable. Install the HotspotShade package, then try again.";
                case BrokerCodes.ElevationCancelled:
                    return "The administrator prompt was cancelled, so the tunnel did not start.";
                case BrokerCodes.ElevationFailed:
                    return "Windows did not start the administrator engine, so the tunnel did not start.";
                case BrokerCodes.ElevationTimeout:
                    return "The administrator prompt was not answered in time, so the tunnel did not start.";
                case BrokerCodes.ElevationOtherAccount:
                    return "Turn on needs an administrator account that is signed in to this Windows session. Approval with a different account is not supported.";
                case BrokerCodes.ElevatedEngineFailed:
                    return "The administrator engine did not start correctly, so the tunnel did not start.";
                case BrokerCodes.StopUnconfirmed:
                    return StopUnconfirmed;
                case BrokerCodes.ElevatedLost:
                    return ElevatedLost;
                case BrokerCodes.Closed:
                    return BrokerLost;
                case BrokerCodes.NotConnected:
                    return BrokerNeverConnected;
                case BrokerCodes.EngineUnavailable:
                    return StatusUnavailableSubtitle;
                default:
                    return "HotspotShade could not finish the action.";
            }
        }
    }
}
