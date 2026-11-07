using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using HotspotShade.WinUI2.Core.App;
using HotspotShade.WinUI2.Core.Engine;

namespace HotspotShade.WinUI2.Core.Tests
{
    // Checks for the real window state: engine JSON in the shape that
    // rust/src/service.rs and rust/src/gui_backend.rs write, through the Core
    // session and presenter, to the visible dashboard. The broker channel is
    // a recording stand-in that returns those answers; nothing here starts a
    // process, a pipe, or a socket.
    internal static class AppSessionTests
    {
        private static readonly DateTimeOffset Start = new DateTimeOffset(2026, 11, 6, 12, 0, 0, TimeSpan.Zero);

        public static void Run(TestRunner runner)
        {
            runner.Check("json: the reader accepts engine objects and refuses odd documents", delegate
            {
                JsonValue value;
                AssertEx.True(JsonValue.TryParseObject("{\"a\":[1,2.5,-3e2],\"b\":{\"c\":\"x\\u0041\\n\"},\"d\":null,\"e\":true}", out value), "valid object");
                AssertEx.Equal("xA\n", value.GetObject("b").GetString("c"), "escapes");
                AssertEx.Equal(3, value.GetArray("a").Count, "array");
                AssertEx.True(value.GetBool("e") == true, "bool");
                AssertEx.True(value.GetString("missing") == null, "missing field");
                AssertEx.True(value.GetInt("e") == null, "wrong type reads as missing");
                AssertEx.False(JsonValue.TryParseObject("{\"a\":1,\"a\":2}", out value), "duplicate key");
                AssertEx.False(JsonValue.TryParseObject("[1]", out value), "array root");
                AssertEx.False(JsonValue.TryParseObject("{\"a\":1} x", out value), "trailing text");
                AssertEx.False(JsonValue.TryParseObject("{\"a\":01x}", out value), "bad number");
                AssertEx.False(JsonValue.TryParseObject(new string('[', 40) + new string(']', 40), out value), "depth");
                AssertEx.False(JsonValue.TryParseObject("", out value), "empty");
            });

            runner.Check("status: real engine JSON maps every field the window uses", delegate
            {
                EngineStatusSnapshot status;
                AssertEx.True(EngineStatusSnapshot.TryParse(RunningStatus(3, 0), out status), "parse");
                AssertEx.True(status.IsRunning, "running");
                AssertEx.Equal("phone", status.Mode, "mode");
                AssertEx.True(status.Paired, "paired");
                AssertEx.Equal(PhoneState.Connected, status.Phone, "phone state");
                AssertEx.True(status.PhoneConnections == 3, "connections");
                AssertEx.True(status.IcmpEnabled == true, "ping");
                AssertEx.True(status.Elevated == true, "elevated engine");
                AssertEx.True(status.TtlBad == 0, "ttl audit");
                AssertEx.Equal(EngineHealth.Normal, status.Health, "health");
                AssertEx.Equal(ForgetPhase.None, status.Forget, "forget");
                AssertEx.True(status.TrustedBySource == true, "trusted by source");
            });

            runner.Check("status: the engine guard shapes map to unknown and cleanup blocked", delegate
            {
                EngineStatusSnapshot status;
                AssertEx.True(EngineStatusSnapshot.TryParse(UnknownStatus(), out status), "parse unknown");
                AssertEx.Equal(EngineHealth.StateUnknown, status.Health, "unknown service state");
                AssertEx.True(EngineStatusSnapshot.TryParse(
                    "{\"running\":false,\"cleanup_blocked\":true,\"phone\":{\"state\":\"ready\"},\"paired\":true}", out status), "parse blocked");
                AssertEx.Equal(EngineHealth.CleanupBlocked, status.Health, "cleanup blocked");
                AssertEx.Equal(EngineHealth.StateUnknown, EngineStatusSnapshot.ResolveHealth(null, null, true), "missing running with a block");
                AssertEx.Equal(EngineHealth.StateUnknown, EngineStatusSnapshot.ResolveHealth("recovering", false, false), "any other state");
            });

            runner.Check("window: before the first answer the app claims nothing", delegate
            {
                Harness h = new Harness();
                DashboardModel model = h.Session.Dashboard();
                AssertEx.Equal(AppText.StartingEngine, model.Title, "starting title");
                AssertEx.Equal(DashboardAction.None, model.Primary, "no action");
                AssertEx.False(model.CanTurnOn, "no Turn on");
                AssertEx.False(model.CanPair, "no Pair");
            });

            runner.Check("window: an unpaired standard-user engine shows Pair and no admin note", delegate
            {
                Harness h = new Harness();
                h.Channel.Status = IdleStatus(false, "unpaired");
                h.Refresh();
                DashboardModel model = h.Session.Dashboard();
                AssertEx.Equal(AppText.NotPaired, model.Title, "title");
                AssertEx.Equal(DashboardAction.Pair, model.Primary, "primary");
                AssertEx.True(model.CanPair, "pair enabled");
                AssertEx.False(model.ShowAdminNote, "no admin note without Turn on");
                AssertEx.True(model.ShowPairHint, "pair hint");
                AssertEx.Equal(AppText.EngineRoleUser, h.Session.EngineRoleText(), "standard user engine");
            });

            runner.Check("window: a paired ready engine offers Turn on with the UAC note", delegate
            {
                Harness h = new Harness();
                h.Channel.Status = IdleStatus(true, "ready");
                h.Refresh();
                DashboardModel model = h.Session.Dashboard();
                AssertEx.Equal(AppText.Ready, model.Title, "title");
                AssertEx.Equal(DashboardAction.TurnOn, model.Primary, "primary");
                AssertEx.True(model.CanTurnOn, "turn on");
                AssertEx.True(model.ShowAdminNote, "UAC note");
                AssertEx.Equal(DashboardAction.Forget, model.Secondary, "forget");
                AssertEx.Equal(AppText.Paired, model.SourceCard.Value, "source card");
                AssertEx.Equal(AppText.TunnelOff, model.ConnectionCard.Value, "connection card");
            });

            runner.Check("window: a running elevated engine shows On, its counts, and the no-auto-stop line", delegate
            {
                Harness h = new Harness();
                h.Channel.Source = BrokerSources.Elevated;
                h.Channel.Phase = BrokerPhases.Elevated;
                h.Channel.Status = RunningStatus(2, 0);
                h.Refresh();
                DashboardModel model = h.Session.Dashboard();
                AssertEx.Equal(AppText.On, model.Title, "title");
                AssertEx.Equal(StatusKind.On, model.Kind, "kind");
                AssertEx.Equal(DashboardAction.TurnOff, model.Primary, "primary");
                AssertEx.True(model.CanTurnOff, "turn off");
                AssertEx.False(model.CanTurnOn, "no second start");
                AssertEx.False(model.CanPair, "no pairing while elevated");
                AssertEx.False(model.CanForget, "no forget while elevated");
                AssertEx.True(model.ConnectionCard.Details.Contains(AppText.PingOn), "ping line");
                AssertEx.True(model.ConnectionCard.Details.Contains(AppText.Connections(2)), "count line");
                AssertEx.True(model.ConnectionCard.Details.Contains(AppText.ElevatedSource), "elevated line");
                AssertEx.Equal(AppText.EngineRoleElevated, h.Session.EngineRoleText(), "engine role");
            });

            runner.Check("window: a TTL audit failure is attention beside On", delegate
            {
                Harness h = new Harness();
                h.Channel.Source = BrokerSources.Elevated;
                h.Channel.Status = RunningStatus(1, 4);
                h.Refresh();
                DashboardModel model = h.Session.Dashboard();
                AssertEx.Equal(AppText.On, model.Title, "still on");
                AssertEx.True(model.Attention.Any(a => a.Text == AppText.TtlAudit(4)), "audit line");
            });

            runner.Check("window: freshness goes stale at 3 s and unavailable at 10 s", delegate
            {
                Harness h = new Harness();
                h.Channel.Status = IdleStatus(true, "ready");
                h.Refresh();
                h.Channel.Fail = BrokerCodes.Timeout;
                h.Clock.Advance(4);
                h.Refresh();
                DashboardModel stale = h.Session.Dashboard();
                AssertEx.Equal(AppText.Ready, stale.Title, "stale keeps the last screen");
                AssertEx.Equal(DashboardAction.CheckNow, stale.Secondary, "check now");
                AssertEx.True(stale.Attention.Any(a => a.Text == AppText.StaleStatus), "stale line");
                h.Clock.Advance(7);
                h.Refresh();
                DashboardModel gone = h.Session.Dashboard();
                AssertEx.Equal(AppText.UnknownTitle, gone.Title, "unavailable");
                AssertEx.False(gone.CanTurnOn, "no start");
                AssertEx.False(gone.CanPair, "no pair");
                AssertEx.False(gone.CanForget, "no forget");
                AssertEx.Equal(AppText.StatusUnavailableLine, gone.SourceCard.Value, "no stale card");
            });

            runner.Check("window: the unknown service state shows no On, Off, or start", delegate
            {
                Harness h = new Harness();
                h.Channel.Status = UnknownStatus();
                h.Refresh();
                DashboardModel model = h.Session.Dashboard();
                AssertEx.Equal(AppText.ServiceStateUnknownTitle, model.Title, "title");
                AssertEx.Equal(AppText.UnknownValue, model.ConnectionCard.Value, "no off claim");
                AssertEx.False(model.CanTurnOn, "no start");
                AssertEx.False(model.CanTurnOff, "no stop");
            });

            runner.Check("window: a refused gateway check at Turn on shows the engine text and Try again", delegate
            {
                Harness h = new Harness();
                h.Channel.Status = IdleStatus(true, "ready");
                h.Refresh();
                h.Channel.TurnOnReply = new BrokerReply(false, 400, BrokerCodes.StartRefused,
                    "{\"error\":\"" + AppText.GatewayUnproven + "\"}",
                    BrokerSources.User, BrokerPhases.Idle, BrokerTurnOn.Available);
                h.Run(h.Session.TurnOnAsync());
                DashboardModel model = h.Session.Dashboard();
                AssertEx.Equal(AppText.Attention, model.Title, "title");
                AssertEx.Equal(AppText.GatewayUnproven, model.Subtitle, "engine gate text");
                AssertEx.Equal(DashboardAction.Retry, model.Primary, "try again");
                AssertEx.True(model.ShowAdminNote, "the retry explains the UAC prompt");
            });

            runner.Check("window: an automatic stop shows the engine stop reason and allows Turn on again", delegate
            {
                Harness h = new Harness();
                h.Channel.Status = IdleStatus(true, "ready").Replace(
                    "\"last_stop\":{\"reason\":null,\"at\":null}",
                    "\"last_stop\":{\"reason\":\"hotspot_lost\",\"at\":1762430400}").Replace(
                    "\"last_stop_message\":null",
                    "\"last_stop_message\":\"The hotspot turned off, so HotspotShade turned the tunnel off.\"");
                h.Refresh();
                DashboardModel model = h.Session.Dashboard();
                AssertEx.True(model.ConnectionCard.Details.Contains(AppText.LastStop("The hotspot turned off, so HotspotShade turned the tunnel off.")), "stop reason");
                AssertEx.True(model.CanTurnOn, "turn on again");
            });

            runner.Check("status: the retired source_proxy_unavailable state is an unknown state", delegate
            {
                AssertEx.Equal(PhoneState.Unknown, EngineStatusSnapshot.ParsePhone("source_proxy_unavailable"), "unknown");
            });

            runner.Check("window: a missing handoff, adapter DLL, or package install hides Turn on with the reason", delegate
            {
                string[] codes = { BrokerCodes.HandoffUnsupported, BrokerCodes.AdapterDllMissing, BrokerCodes.InstallUntrusted };
                for (int index = 0; index < codes.Length; index++)
                {
                    Harness h = new Harness();
                    h.Channel.TurnOn = codes[index];
                    h.Channel.Status = IdleStatus(true, "ready");
                    h.Refresh();
                    DashboardModel model = h.Session.Dashboard();
                    AssertEx.Equal(AppText.Ready, model.Title, "title " + codes[index]);
                    AssertEx.Equal(DashboardAction.None, model.Primary, "no Turn on button " + codes[index]);
                    AssertEx.False(model.CanTurnOn, "no Turn on " + codes[index]);
                    AssertEx.Equal(AppText.BrokerMessage(codes[index]), model.Subtitle, "reason " + codes[index]);
                    h.Run(h.Session.TurnOnAsync());
                    AssertEx.Equal(0, h.Channel.Count(BrokerOps.TurnOn), "no turn_on request " + codes[index]);
                }
            });

            runner.Check("pairing: the real pairing answers drive the code panel and the result", delegate
            {
                Harness h = new Harness();
                h.Channel.Status = IdleStatus(false, "unpaired");
                h.Refresh();
                h.Channel.Pair = "{\"state\":\"connecting\",\"code\":null,\"host\":null,\"port\":null,\"error\":null}";
                h.Run(h.Session.PairAsync());
                AssertEx.True(h.Session.PairingActive, "pairing runs");
                AssertEx.Equal(AppText.Pairing, h.Session.Dashboard().Title, "pairing title");
                AssertEx.Equal("", h.Session.PairingCode, "no code yet");
                h.Channel.Pair = "{\"state\":\"confirm\",\"code\":\"482193\",\"host\":\"172.20.10.1\",\"port\":null,\"error\":null}";
                h.Run(h.Session.PollPairingAsync());
                AssertEx.Equal("482 193", h.Session.PairingCode, "grouped code");
                WindowState state = WindowState.Build(h.Session);
                AssertEx.True(state.IsPairing && state.PairingCodeReady, "code panel");
                AssertEx.Equal("Pairing code 4 8 2 1 9 3", state.PairingCodeAccessibility, "narrator code");
                h.Channel.Pair = "{\"state\":\"paired\",\"code\":null,\"host\":null,\"port\":null,\"error\":null}";
                h.Channel.Status = IdleStatus(true, "ready");
                h.Run(h.Session.PollPairingAsync());
                AssertEx.False(h.Session.PairingActive, "pairing ended");
                AssertEx.True(h.Channel.Count(BrokerOps.Probe) >= 1, "probe after pairing");
                AssertEx.Equal(AppText.Ready, h.Session.Dashboard().Title, "ready after pairing");
                AssertEx.Equal(0, h.Channel.Count(BrokerOps.TurnOn), "pairing never starts the tunnel");
            });

            runner.Check("pairing: a failed pairing keeps the engine reason on Not paired", delegate
            {
                Harness h = new Harness();
                h.Channel.Status = IdleStatus(false, "unpaired");
                h.Refresh();
                h.Channel.Pair = "{\"state\":\"connecting\"}";
                h.Run(h.Session.PairAsync());
                h.Channel.Pair = "{\"state\":\"failed\",\"error\":\"The source device declined the pairing.\"}";
                h.Run(h.Session.PollPairingAsync());
                DashboardModel model = h.Session.Dashboard();
                AssertEx.Equal(AppText.NotPaired, model.Title, "title");
                AssertEx.Equal("The source device declined the pairing.", model.Subtitle, "reason");
                AssertEx.True(model.CanPair, "pair again");
            });

            runner.Check("forget: a 409 from the engine shows Turn off and forget", delegate
            {
                Harness h = new Harness();
                h.Channel.Status = IdleStatus(true, "ready");
                h.Refresh();
                h.Channel.ForgetHttp = 409;
                h.Run(h.Session.ForgetAsync());
                h.Channel.Status = RunningStatus(1, 0);
                h.Refresh();
                DashboardModel model = h.Session.Dashboard();
                AssertEx.Equal(DashboardAction.TurnOffAndForget, model.Secondary, "turn off and forget");
                AssertEx.True(model.Attention.Any(a => a.Text == AppText.ForgetBlocked), "blocked line");
            });

            runner.Check("forget: the engine forget state shows the cautious result", delegate
            {
                Harness h = new Harness();
                h.Channel.Status = IdleStatus(true, "ready");
                h.Refresh();
                h.Channel.Status = "{\"running\":false,\"paired\":false,\"phone\":{\"state\":\"unpaired\"},\"forget\":{\"state\":\"not_delivered\",\"attempts\":3}}";
                h.Run(h.Session.ForgetAsync());
                DashboardModel model = h.Session.Dashboard();
                AssertEx.Equal(1, h.Channel.Count(BrokerOps.Forget), "one forget");
                AssertEx.Equal(AppText.NotPaired, model.Title, "title");
                AssertEx.Equal(AppText.ForgetResult, model.Subtitle, "cautious result");
            });

            runner.Check("turn on: one request with the ping choice, and a cancelled UAC prompt is a plain error", delegate
            {
                Harness h = new Harness();
                h.Channel.Status = IdleStatus(true, "ready");
                h.Refresh();
                h.Session.PingEnabled = false;
                h.Channel.TurnOnReply = BrokerReply.Failure(BrokerCodes.ElevationCancelled);
                h.Run(h.Session.TurnOnAsync());
                AssertEx.Equal(1, h.Channel.Count(BrokerOps.TurnOn), "one turn_on");
                Dictionary<string, string> sent = h.Channel.Last(BrokerOps.TurnOn);
                AssertEx.Equal("off", sent[BrokerProtocol.PingField], "ping choice");
                AssertEx.Equal(2, sent.Count, "only op and ping");
                DashboardModel model = h.Session.Dashboard();
                AssertEx.Equal(AppText.Attention, model.Title, "attention");
                AssertEx.Equal(AppText.BrokerMessage(BrokerCodes.ElevationCancelled), model.Subtitle, "cancelled text");
                AssertEx.Equal(DashboardAction.Retry, model.Primary, "try again");
                AssertEx.True(model.ShowAdminNote, "retry explains the UAC prompt");
            });

            runner.Check("turn on: a rejected token from the elevated engine asks to pair again", delegate
            {
                Harness h = new Harness();
                h.Channel.Status = IdleStatus(true, "ready");
                h.Refresh();
                h.Channel.TurnOnReply = new BrokerReply(false, 409, BrokerCodes.StartRefused,
                    "{\"ok\":false,\"code\":\"phone_token_rejected\",\"error\":\"The source device changed its token. Open HotspotShade on your source device, then pair again.\"}",
                    BrokerSources.User, BrokerPhases.Idle, BrokerTurnOn.Available);
                h.Run(h.Session.TurnOnAsync());
                DashboardModel model = h.Session.Dashboard();
                AssertEx.Equal(AppText.PairAgain, model.Title, "title");
                AssertEx.Equal(DashboardAction.PairAgain, model.Primary, "pair again");
            });

            runner.Check("turn off: an unconfirmed stop keeps the elevated status and allows a retry", delegate
            {
                Harness h = new Harness();
                h.Channel.Source = BrokerSources.Elevated;
                h.Channel.Phase = BrokerPhases.Elevated;
                h.Channel.Status = RunningStatus(1, 0);
                h.Refresh();
                h.Channel.Phase = BrokerPhases.StopUnconfirmed;
                h.Channel.TurnOffReply = new BrokerReply(false, 0, BrokerCodes.StopUnconfirmed, "", BrokerSources.Elevated, BrokerPhases.StopUnconfirmed, BrokerTurnOn.Available);
                h.Run(h.Session.TurnOffAsync());
                DashboardModel model = h.Session.Dashboard();
                AssertEx.Equal(AppText.CleanupBlockedTitle, model.Title, "not a clean Off");
                AssertEx.Equal(AppText.StopUnconfirmed, model.Subtitle, "unconfirmed text");
                AssertEx.False(model.CanTurnOn, "no new start");
                AssertEx.True(model.CanTurnOff, "turn off again");
                AssertEx.False(model.CanForget, "no forget");
            });

            runner.Check("turn off: a lost elevated engine is final and keeps Turn on disabled", delegate
            {
                Harness h = new Harness();
                h.Channel.Phase = BrokerPhases.ElevatedLost;
                h.Channel.Status = IdleStatus(true, "ready");
                h.Refresh();
                DashboardModel model = h.Session.Dashboard();
                AssertEx.Equal(AppText.CleanupBlockedTitle, model.Title, "title");
                AssertEx.Equal(DashboardAction.None, model.Primary, "no endless retry");
                AssertEx.False(model.CanTurnOn, "no start");
                AssertEx.True(model.Subtitle.Contains("route print"), "route check guidance");
            });

            runner.Check("turn off and forget: a failed stop does not send forget", delegate
            {
                Harness h = new Harness();
                h.Channel.Source = BrokerSources.Elevated;
                h.Channel.Status = RunningStatus(1, 0);
                h.Refresh();
                h.Channel.TurnOffReply = BrokerReply.Failure(BrokerCodes.Timeout);
                h.Run(h.Session.TurnOffAndForgetAsync());
                AssertEx.Equal(1, h.Channel.Count(BrokerOps.TurnOff), "one stop");
                AssertEx.Equal(0, h.Channel.Count(BrokerOps.Forget), "no forget");
            });

            runner.Check("elevation: administrator approval is requested only by Turn on", delegate
            {
                for (int index = 0; index < BrokerProtocol.AllOps.Length; index++)
                {
                    string op = BrokerProtocol.AllOps[index];
                    AssertEx.Equal(op == BrokerOps.TurnOn, ElevationPolicy.RequiresElevation(op), "elevation for " + op);
                }

                // Open the app, read everything, pair, forget, change
                // settings: no turn_on request leaves the window.
                Harness h = new Harness();
                h.Channel.Status = IdleStatus(true, "ready");
                h.Refresh();
                h.Run(h.Session.CheckNowAsync());
                h.Run(h.Session.LoadActivityAsync(true));
                h.Run(h.Session.LoadFailuresAsync());
                h.Run(h.Session.DiagnosticsReportAsync("1.0", "10.0"));
                h.Session.PingEnabled = false;
                h.Run(h.Session.TurnOffAsync());
                h.Run(h.Session.ForgetAsync());
                AssertEx.Equal(0, h.Channel.Count(BrokerOps.TurnOn), "no elevation outside Turn on");

                string root = FindWindowsRoot();
                AssertEx.True(root != null, "windows root");
                string service = SourceText.Read(Path.Combine(root, "src", "HotspotShade.WinUI2.Broker", "BrokerService.cs"));
                AssertEx.Equal(1, Occurrences(service, "ElevatedEngineLauncher.Launch("), "one launcher call");
                int turnOn = service.IndexOf("private BrokerReply TurnOn(", StringComparison.Ordinal);
                int turnOff = service.IndexOf("private BrokerReply AbortStart(", StringComparison.Ordinal);
                int call = service.IndexOf("ElevatedEngineLauncher.Launch(", StringComparison.Ordinal);
                AssertEx.True(turnOn > 0 && call > turnOn && call < turnOff, "the launcher runs inside TurnOn only");
                string launcher = SourceText.Read(Path.Combine(root, "src", "HotspotShade.WinUI2.Broker", "ElevatedEngineLauncher.cs"));
                AssertEx.Equal(1, Occurrences(launcher, "info.lpVerb = \"runas\";"), "one elevation verb");
                foreach (string manifest in new[]
                {
                    Path.Combine(root, "src", "HotspotShade.WinUI2.Broker", "app.manifest"),
                    Path.Combine(root, "src", "HotspotShade.WinUI2.Elevate", "app.manifest"),
                    Path.Combine(root, "src", "HotspotShade.WinUI2.TestLauncher", "app.manifest")
                })
                {
                    XDocument doc = XDocument.Load(manifest);
                    XElement level = doc.Descendants().Single(e => e.Name.LocalName == "requestedExecutionLevel");
                    AssertEx.Equal("asInvoker", (string)level.Attribute("level"), "no elevation at start: " + manifest);
                }
            });

            runner.Check("secret: the bearer secret and the pairing are never in argv or the environment", delegate
            {
                EngineLaunchPlan plan;
                EngineLaunchFailure failure;
                AssertEx.True(EngineLaunchPlan.TryCreateTrustedWithPairing(
                    @"C:\Program Files\WindowsApps\HotspotShade\Engine\hotspotshade.exe",
                    @"C:\Program Files\WindowsApps\HotspotShade",
                    40000, 1100, 1104, EnginePairingDescriptor.Credentials, 1108, out plan, out failure), "plan");
                using (EngineLaunchSecret secret = EngineLaunchSecret.CreateRandom())
                {
                    AssertEx.False(plan.DisclosesSecret(secret), "secret not in the plan");
                }
                string[] expected = { "gui", "--no-open", "--port", "40000", "--token-fd", "1100", "--parent-fd", "1104", "--credentials-fd", "1108" };
                AssertEx.Equal(string.Join(" ", expected), string.Join(" ", plan.Arguments), "fixed argument list");
                AssertEx.False(plan.Arguments.Contains("--demo"), "no demo engine");
                AssertEx.False(EngineLaunchPlan.TryCreateTrustedWithPairing(
                    @"C:\Program Files\WindowsApps\HotspotShade\Engine\hotspotshade.exe",
                    @"C:\Program Files\WindowsApps\HotspotShade",
                    40000, 1100, 1104, EnginePairingDescriptor.Handoff, 1104, out plan, out failure), "pairing handle must be separate");
                AssertEx.Equal(EngineLaunchFailure.HandleInvalid, failure, "fixed failure");

                string root = FindWindowsRoot();
                string host = SourceText.Read(Path.Combine(root, "src", "HotspotShade.WinUI2.Broker", "Win32EngineHost.cs"));
                string starter = SourceText.Read(Path.Combine(root, "src", "HotspotShade.WinUI2.Elevate", "Program.cs"));
                string launcher = SourceText.Read(Path.Combine(root, "src", "HotspotShade.WinUI2.Broker", "ElevatedEngineLauncher.cs"));
                foreach (string text in new[] { host, starter })
                {
                    AssertEx.Contains(text, "ProcThreadAttributeHandleList", "explicit inherited-handle list");
                    // The user engine inherits the broker environment. The
                    // elevated engine gets the starter's fixed block, built
                    // from the Windows directory. Neither holds a secret.
                    string expectedEnvironment = text == starter ? "environment" : "IntPtr.Zero";
                    int at = text.IndexOf("CreateProcessW(\n", StringComparison.Ordinal);
                    if (at < 0)
                    {
                        at = text.IndexOf("CreateProcessW(\r\n", StringComparison.Ordinal);
                    }
                    AssertEx.True(at > 0, "process creation call");
                    string call = text.Substring(at, Math.Min(600, text.Length - at));
                    string[] arguments = call.Split(',');
                    AssertEx.True(arguments.Length > 7 && arguments[6].Trim() == expectedEnvironment, "environment argument");
                }
                AssertEx.Contains(starter, "environment = Marshal.StringToHGlobalUni(EnvironmentBlock());", "fixed environment block");
                AssertEx.Contains(starter, "GetWindowsDirectoryW", "values from the Windows directory");
                AssertEx.DoesNotContain(starter, "GetEnvironmentVariable", "no value from the user environment");
                AssertEx.DoesNotContain(starter, "WindowsPrincipal", "elevation from the token, not a role lookup");
                string starterProject = SourceText.Read(Path.Combine(root, "src", "HotspotShade.WinUI2.Elevate", "HotspotShade.WinUI2.Elevate.csproj"));
                AssertEx.Contains(starterProject, "<PublishAot>true</PublishAot>", "the elevated starter has no .NET host");
                string stage = SourceText.Read(Path.Combine(root, "tools", "stage_payload.ps1"));
                // PublishAot comes from the starter project. A global -p property
                // would also reach the netstandard2.0 Core reference (NETSDK1207).
                AssertEx.DoesNotContain(stage, "-p:PublishAot", "no global PublishAot property");
                AssertEx.Contains(stage, "the NativeAOT publish did not produce a single native program", "the payload checks the starter is native");
                string pipe = SourceText.Read(Path.Combine(root, "src", "HotspotShade.WinUI2.Broker", "RendezvousPipe.cs"));
                AssertEx.Contains(pipe, "(A;;RC;;;OW)", "the pipe owner cannot take WRITE_DAC");
                AssertEx.Contains(launcher, "SetApartmentState(System.Threading.ApartmentState.STA)", "ShellExecuteEx runs on an STA thread");
                // The only ShellExecuteEx parameter is the rendezvous token.
                AssertEx.Contains(launcher, "info.lpParameters = token;", "parameters are the pipe token");
                AssertEx.DoesNotContain(launcher, "lpParameters = secret", "no secret parameter");
                AssertEx.Contains(starter, "SecurityIdentification", "the pipe server cannot impersonate the elevated token");
                AssertEx.DoesNotContain(starter, "ReadFile(tokenHandle", "the starter never reads the secret");
            });

            runner.Check("broker protocol: requests are strict strings with fixed fields", delegate
            {
                BrokerRequest request;
                string code;
                AssertEx.True(BrokerProtocol.TryValidate(Pairs("op", "turn_on", "ping", "on"), out request, out code), "turn on");
                AssertEx.True(request.Ping, "ping on");
                AssertEx.False(BrokerProtocol.TryValidate(Pairs("op", "turn_on"), out request, out code), "turn on needs ping");
                AssertEx.False(BrokerProtocol.TryValidate(Pairs("op", "status", "token", "abc"), out request, out code), "credential field");
                AssertEx.False(BrokerProtocol.TryValidate(Pairs("op", "start"), out request, out code), "unknown op");
                AssertEx.Equal(BrokerCodes.UnknownOp, code, "unknown op code");
                AssertEx.False(BrokerProtocol.TryValidate(Pairs("op", "logs", "since", "-1"), out request, out code), "negative cursor");
                AssertEx.True(BrokerProtocol.TryValidate(Pairs("op", "logs", "since", "42"), out request, out code), "cursor");
                AssertEx.True(request.Since == 42, "cursor value");
                List<KeyValuePair<string, object>> boxed = new List<KeyValuePair<string, object>>();
                boxed.Add(new KeyValuePair<string, object>("op", "hello"));
                boxed.Add(new KeyValuePair<string, object>("pid", 42));
                AssertEx.False(BrokerProtocol.TryValidate(boxed, out request, out code), "non-string value");
            });

            runner.Check("elevation protocol: frames round-trip and odd frames are refused", delegate
            {
                ElevationRequest request = new ElevationRequest(40000, 0x1A4, 0x1B8, 0x2C0);
                byte[] frame = ElevationProtocol.EncodeRequest(request);
                ElevationRequest decoded;
                AssertEx.True(ElevationProtocol.TryDecodeRequest(frame, frame.Length, out decoded), "decode");
                AssertEx.True(decoded.Port == 40000 && decoded.TokenHandle == 0x1A4 && decoded.ParentHandle == 0x1B8 && decoded.CredentialsHandle == 0x2C0, "values");
                frame[4] = 9;
                AssertEx.False(ElevationProtocol.TryDecodeRequest(frame, frame.Length, out decoded), "version");
                AssertEx.False(new ElevationRequest(80, 1, 2, 3).IsValid, "low port");
                AssertEx.False(new ElevationRequest(40000, 1, 1, 3).IsValid, "shared handle");
                byte[] reply = ElevationProtocol.EncodeReply(ElevationReplyCode.Started, 4242);
                ElevationReplyCode replyCode;
                int pid;
                AssertEx.True(ElevationProtocol.TryDecodeReply(reply, reply.Length, out replyCode, out pid), "reply");
                AssertEx.True(replyCode == ElevationReplyCode.Started && pid == 4242, "reply values");
                reply = ElevationProtocol.EncodeReply(ElevationReplyCode.OtherAccount, 4242);
                AssertEx.True(ElevationProtocol.TryDecodeReply(reply, reply.Length, out replyCode, out pid) && pid == 0, "a failure carries no pid");
                AssertEx.True(ElevationProtocol.IsRendezvousToken("0123456789abcdef0123456789abcdef"), "token");
                AssertEx.False(ElevationProtocol.IsRendezvousToken("0123456789ABCDEF0123456789abcdef"), "lowercase only");
                AssertEx.False(ElevationProtocol.IsRendezvousToken("..\\pipe\\x"), "no path");
            });

            runner.Check("install: the text pre-filter admits only package store paths", delegate
            {
                AssertEx.True(InstallRules.IsPackageStorePath(@"C:\Program Files\WindowsApps\HotspotShade.Windows_0.2.0.0_x64__abc", @"C:\Program Files"), "installed package");
                AssertEx.False(InstallRules.IsPackageStorePath(@"C:\Users\me\source\repos\windows\src\HotspotShade.WinUI2\bin\x64\Debug\AppX", @"C:\Program Files"), "loose deployment");
                AssertEx.False(InstallRules.IsPackageStorePath(@"C:\Program Files\WindowsAppsEvil\x", @"C:\Program Files"), "prefix trick");
                AssertEx.False(InstallRules.IsPackageStorePath(@"C:\Program Files\WindowsApps", @"C:\Program Files"), "the folder itself");
                AssertEx.False(InstallRules.IsPackageStorePath(@"D:\Users\me\WindowsApps\x", @"C:\Program Files"), "a user folder named WindowsApps");
                AssertEx.False(InstallRules.IsPackageStorePath(@"D:\WindowsApps\..\x", @"C:\Program Files"), "traversal");
            });

            runner.Check("install: a WindowsApps folder on another drive is not trusted by text alone", delegate
            {
                // The path passes the pre-filter, so the broker offers Turn
                // on, but the starter trusts only what the owner and DACL say.
                // A standard user who creates D:\WindowsApps owns it.
                string root = @"D:\WindowsApps\HotspotShade.Windows_0.2.0.0_x64__abc";
                AssertEx.True(InstallRules.IsPackageStorePath(root, @"C:\Program Files"), "location pre-filter only");
                const string user = "S-1-5-21-1004336348-1177238915-682003330-1001";
                List<InstallAce> userFolder = new List<InstallAce>
                {
                    new InstallAce(InstallSecurity.AccessAllowed, 0x03, 0x001F01FF, user),
                    new InstallAce(InstallSecurity.AccessAllowed, 0x03, InstallSecurity.ReadAndExecute, InstallSecurity.UsersSid)
                };
                AssertEx.Equal(InstallCheck.OwnerUntrusted, InstallSecurity.Evaluate(user, true, userFolder), "user-created store");
                List<InstallAce> rootLike = new List<InstallAce>
                {
                    new InstallAce(InstallSecurity.AccessAllowed, 0x03, 0x001F01FF, InstallSecurity.SystemSid),
                    new InstallAce(InstallSecurity.AccessAllowed, 0x0B, InstallSecurity.GenericWrite | InstallSecurity.Delete, InstallSecurity.AuthenticatedUsersSid)
                };
                AssertEx.Equal(InstallCheck.WritableByOthers, InstallSecurity.Evaluate(InstallSecurity.SystemSid, true, rootLike), "a drive-root style DACL");
                List<InstallAce> store = new List<InstallAce>
                {
                    new InstallAce(InstallSecurity.AccessAllowed, 0x03, 0x001F01FF, InstallSecurity.TrustedInstallerSid),
                    new InstallAce(InstallSecurity.AccessAllowed, 0x03, InstallSecurity.ReadAndExecute, InstallSecurity.UsersSid)
                };
                AssertEx.Equal(InstallCheck.Trusted, InstallSecurity.Evaluate(InstallSecurity.TrustedInstallerSid, true, store), "a real package store");
            });

            runner.Check("reports: failures and diagnostics come from engine answers", delegate
            {
                Harness h = new Harness();
                h.Channel.Status = IdleStatus(true, "ready");
                h.Refresh();
                h.Channel.Failures = "{\"since\":1,\"total\":5,\"dropped\":0,\"demo\":false,\"groups\":[{\"proto\":\"tcp\",\"family\":\"ipv4\",\"port\":443,\"reason\":\"refused\",\"phase\":\"connect\",\"count\":5,\"name\":null,\"example_ip\":\"203.0.113.9\",\"code\":5}],\"recent\":[]}";
                h.Run(h.Session.LoadFailuresAsync());
                AssertEx.Equal(ListState.Loaded, h.Session.FailuresState, "loaded");
                string report = h.Session.FailureReport();
                AssertEx.Contains(report, "5\ttcp ipv4\t203.0.113.9:443\tconnect\trefused (5)", "row");
                h.Channel.Failures = "{\"demo\":true,\"groups\":[]}";
                h.Run(h.Session.LoadFailuresAsync());
                AssertEx.Equal(ListState.Unavailable, h.Session.FailuresState, "test data is not shown");
                h.Channel.Diagnostics = "{\"engine\":{\"version\":\"0.9\"},\"tcp\":{\"flows_active\":2}}";
                string diag = h.Run(h.Session.DiagnosticsReportAsync("0.2.0.0", "10.0.26100.1"));
                AssertEx.Contains(diag, "\"flows_active\":2", "engine counters");
                AssertEx.Contains(diag, AppText.EngineRoleUser, "engine role");
                AssertEx.DoesNotContain(diag, "token", "no token word");
            });

            runner.Check("activity: engine log lines append by sequence", delegate
            {
                Harness h = new Harness();
                h.Channel.Logs = "{\"logs\":[{\"seq\":1,\"level\":\"info\",\"msg\":\"engine started\",\"ts\":1762430400}],\"next\":1}";
                h.Run(h.Session.LoadActivityAsync(true));
                AssertEx.Equal(1, h.Session.Activity.Count, "one line");
                h.Channel.Logs = "{\"logs\":[{\"seq\":2,\"level\":\"warn\",\"msg\":\"source device slow\",\"ts\":1762430401}],\"next\":2}";
                h.Run(h.Session.LoadActivityAsync(false));
                AssertEx.Equal(2, h.Session.Activity.Count, "two lines");
                AssertEx.Equal("1", h.Channel.Last(BrokerOps.Logs)[BrokerProtocol.SinceField], "cursor sent");
                h.Channel.Logs = "{\"logs\":[],\"next\":2}";
                h.Run(h.Session.LoadActivityAsync(true));
                AssertEx.Equal(ListState.Empty, h.Session.ActivityState, "empty");
            });

            runner.Check("activity: Turn on starts the log cursor again for the elevated engine", delegate
            {
                Harness h = new Harness();
                h.Channel.Status = IdleStatus(true, "ready");
                h.Refresh();
                h.Channel.Logs = Logs(1, 3);
                h.Run(h.Session.LoadActivityAsync(true));
                AssertEx.Equal(3, h.Session.Activity.Count, "user engine lines");
                h.Channel.Logs = Logs(4, 4);
                h.Run(h.Session.LoadActivityAsync(false));
                AssertEx.Equal("3", h.Channel.Last(BrokerOps.Logs)[BrokerProtocol.SinceField], "cursor continues");
                AssertEx.Equal(4, h.Session.Activity.Count, "one more line");

                // Turn on: a new elevated engine whose sequence starts at 1.
                h.Channel.Source = BrokerSources.Elevated;
                h.Channel.Status = RunningStatus(1, 0);
                h.Refresh();
                h.Channel.Logs = Logs(1, 2);
                h.Run(h.Session.LoadActivityAsync(false));
                AssertEx.Equal("0", h.Channel.Last(BrokerOps.Logs)[BrokerProtocol.SinceField], "cursor reset for the new engine");
                AssertEx.Equal(2, h.Session.Activity.Count, "the elevated engine's lines");
                AssertEx.Equal(ListState.Loaded, h.Session.ActivityState, "not empty");

                // The same run again keeps the cursor.
                h.Refresh();
                h.Channel.Logs = Logs(3, 3);
                h.Run(h.Session.LoadActivityAsync(false));
                AssertEx.Equal("2", h.Channel.Last(BrokerOps.Logs)[BrokerProtocol.SinceField], "same run keeps the cursor");
                AssertEx.Equal(3, h.Session.Activity.Count, "appended");

                // A new started_at from the same source is a new run too.
                h.Channel.Status = RunningStatus(1, 0).Replace("\"started_at\":", "\"started_at\":17");
                h.Refresh();
                h.Channel.Logs = Logs(1, 3);
                h.Run(h.Session.LoadActivityAsync(false));
                AssertEx.Equal("0", h.Channel.Last(BrokerOps.Logs)[BrokerProtocol.SinceField], "cursor reset for a new run");
                AssertEx.Equal(3, h.Session.Activity.Count, "no line shown twice");
            });

            runner.Check("activity: a log answer from before a run change is dropped", delegate
            {
                Harness h = new Harness();
                h.Channel.Status = IdleStatus(true, "ready");
                h.Refresh();
                h.Channel.Logs = Logs(1, 2);
                h.Run(h.Session.LoadActivityAsync(true));
                h.Channel.Logs = Logs(3, 5);
                h.Channel.BeforeLogs = delegate
                {
                    h.Channel.BeforeLogs = null;
                    h.Channel.Source = BrokerSources.Elevated;
                    h.Channel.Status = RunningStatus(1, 0);
                    h.Refresh();
                };
                h.Run(h.Session.LoadActivityAsync(false));
                AssertEx.Equal(2, h.Session.Activity.Count, "old-run answer dropped");
                h.Channel.Logs = Logs(1, 1);
                h.Run(h.Session.LoadActivityAsync(false));
                AssertEx.Equal("0", h.Channel.Last(BrokerOps.Logs)[BrokerProtocol.SinceField], "next load starts the new run");
                AssertEx.Equal(1, h.Session.Activity.Count, "new run only");
            });

            runner.Check("window: a test-data status shows at once as an unreadable answer with Try again", delegate
            {
                Harness h = new Harness();
                h.Channel.Status = IdleStatus(true, "ready").Replace("\"demo\":false", "\"demo\":true");
                h.Refresh();
                DashboardModel model = h.Session.Dashboard();
                AssertEx.Equal(AppText.Attention, model.Title, "not the starting screen");
                AssertEx.Equal(AppText.TestDataEngine, model.Subtitle, "unreadable answer");
                AssertEx.Contains(AppText.TestDataEngine, "cannot read", "plain reason");
                AssertEx.Equal(DashboardAction.Retry, model.Primary, "Try again");
                AssertEx.True(h.Session.HasBrokerFailure, "Try again restarts the broker path");
                AssertEx.False(model.CanTurnOn, "no Turn on");
                AssertEx.False(model.CanPair, "no Pair");

                h.Channel.Status = IdleStatus(true, "ready");
                h.Refresh();
                AssertEx.Equal(AppText.Ready, h.Session.Dashboard().Title, "a real status replaces it");

                h.Channel.Status = IdleStatus(true, "ready").Replace("\"demo\":false", "\"demo\":true");
                h.Refresh();
                DashboardModel later = h.Session.Dashboard();
                AssertEx.Equal(AppText.UnknownTitle, later.Title, "unavailable at once after a real status");
                AssertEx.Equal(AppText.TestDataEngine, later.Subtitle, "same reason");
                AssertEx.False(later.CanTurnOn, "no Turn on");
            });

            runner.Check("window: Turn off stays available when the status is lost while running", delegate
            {
                Harness h = new Harness();
                h.Channel.Source = BrokerSources.Elevated;
                h.Channel.Status = RunningStatus(2, 0);
                h.Refresh();
                h.Channel.Fail = BrokerCodes.Timeout;
                h.Clock.Advance(11);
                h.Refresh();
                DashboardModel gone = h.Session.Dashboard();
                AssertEx.Equal(AppText.UnknownTitle, gone.Title, "unavailable");
                AssertEx.True(gone.CanTurnOff, "Turn off allowed");
                AssertEx.False(gone.CanTurnOn, "Turn on stays blocked");
                AssertEx.Equal(DashboardAction.TurnOff, gone.Secondary, "Turn off offered");
                AssertEx.True(WindowState.Build(h.Session).CanTurnOff, "the Turn off menu is enabled");
                h.Channel.Fail = null;
                h.Channel.Status = null;
                h.Run(h.Session.TurnOffAsync());
                AssertEx.Equal(1, h.Channel.Count(BrokerOps.TurnOff), "the stop is sent");

                Harness idle = new Harness();
                idle.Channel.Status = IdleStatus(true, "ready");
                idle.Refresh();
                idle.Channel.Fail = BrokerCodes.Timeout;
                idle.Clock.Advance(11);
                idle.Refresh();
                DashboardModel idleGone = idle.Session.Dashboard();
                AssertEx.False(idleGone.CanTurnOff, "nothing to stop when it was last seen off");
                AssertEx.Equal(DashboardAction.None, idleGone.Secondary, "no Turn off offered");
                idle.Run(idle.Session.TurnOffAsync());
                AssertEx.Equal(0, idle.Channel.Count(BrokerOps.TurnOff), "no stop sent");
            });
        }

        private static string Logs(int first, int last)
        {
            StringBuilder lines = new StringBuilder();
            for (int seq = first; seq <= last; seq++)
            {
                if (lines.Length > 0)
                {
                    lines.Append(',');
                }
                lines.Append("{\"seq\":" + seq + ",\"level\":\"info\",\"msg\":\"line " + seq + "\",\"ts\":1762430400}");
            }
            return "{\"logs\":[" + lines + "],\"next\":" + last + "}";
        }

        // MARK: - Engine answers in the shape that the Rust engine writes.

        private static string IdleStatus(bool paired, string phone)
        {
            return "{\"running\":false,\"mode\":null,\"started_at\":null,\"icmp_enabled\":false,\"cleanup_blocked\":false,"
                + "\"iface\":null,\"last_stop\":{\"reason\":null,\"at\":null},\"stats\":{},\"error\":null,\"demo\":false,"
                + "\"platform\":{\"admin\":false,\"default_iface_name\":\"Wi-Fi\"},\"forget\":{\"state\":\"none\",\"attempts\":0},"
                + "\"last_stop_message\":null,\"api\":1,"
                + "\"phone\":{\"state\":\"" + phone + "\",\"message\":null,\"port_changed\":false,\"connections\":null,\"checked_at\":null,\"trusted_by_source\":null},"
                + "\"paired\":" + (paired ? "true" : "false") + ",\"phone_host\":null,\"phone_port\":null}";
        }

        private static string RunningStatus(int connections, int ttlBad)
        {
            double now = (Start.UtcDateTime - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
            return "{\"running\":true,\"mode\":\"phone\",\"started_at\":" + (now - 60).ToString(System.Globalization.CultureInfo.InvariantCulture)
                + ",\"icmp_enabled\":true,\"cleanup_blocked\":false,\"iface\":\"Wi-Fi\",\"last_stop\":{\"reason\":null,\"at\":null},"
                + "\"stats\":{\"ttl_bad\":" + ttlBad + ",\"ipv6_dropped\":0,\"fragments_dropped\":0},\"error\":null,\"demo\":false,"
                + "\"platform\":{\"admin\":true,\"default_iface_name\":\"Wi-Fi\"},\"forget\":{\"state\":\"none\",\"attempts\":0},"
                + "\"last_stop_message\":null,\"api\":1,"
                + "\"phone\":{\"state\":\"connected\",\"message\":null,\"port_changed\":false,\"connections\":" + connections
                + ",\"checked_at\":" + now.ToString(System.Globalization.CultureInfo.InvariantCulture) + ",\"trusted_by_source\":true},"
                + "\"paired\":true,\"phone_host\":\"172.20.10.1\",\"phone_port\":41000}";
        }

        private static string UnknownStatus()
        {
            return "{\"running\":true,\"mode\":null,\"started_at\":null,\"icmp_enabled\":false,\"cleanup_blocked\":true,\"state\":\"unknown\","
                + "\"iface\":null,\"last_stop\":{\"reason\":null,\"at\":null},\"stats\":{},"
                + "\"error\":\"The service state is unavailable after an interrupted operation. Inspect routes, devices, and the start record before restarting.\","
                + "\"demo\":false,\"phone\":{\"state\":\"ready\"},\"paired\":true}";
        }

        private static List<KeyValuePair<string, object>> Pairs(params string[] values)
        {
            List<KeyValuePair<string, object>> pairs = new List<KeyValuePair<string, object>>();
            for (int index = 0; index + 1 < values.Length; index += 2)
            {
                pairs.Add(new KeyValuePair<string, object>(values[index], values[index + 1]));
            }
            return pairs;
        }

        private static int Occurrences(string text, string value)
        {
            int count = 0;
            int at = text.IndexOf(value, StringComparison.Ordinal);
            while (at >= 0)
            {
                count++;
                at = text.IndexOf(value, at + value.Length, StringComparison.Ordinal);
            }
            return count;
        }

        private static string FindWindowsRoot()
        {
            DirectoryInfo directory = new DirectoryInfo(AppContext.BaseDirectory);
            while (directory != null)
            {
                string candidate = Path.Combine(directory.FullName, "windows");
                if (Directory.Exists(candidate) && File.Exists(Path.Combine(candidate, "README.md")))
                {
                    return candidate;
                }
                directory = directory.Parent;
            }
            return null;
        }

        private sealed class Harness
        {
            public Harness()
            {
                Clock = new FakeClock(Start);
                Channel = new RecordingChannel();
                Session = new AppSession(Channel, Clock.UtcNow);
            }

            public FakeClock Clock { get; private set; }

            public RecordingChannel Channel { get; private set; }

            public AppSession Session { get; private set; }

            public void Refresh()
            {
                Run(Session.RefreshAsync());
            }

            public void Run(Task task)
            {
                task.GetAwaiter().GetResult();
            }

            public T Run<T>(Task<T> task)
            {
                return task.GetAwaiter().GetResult();
            }
        }

        // Returns recorded engine answers and records every request.
        private sealed class RecordingChannel : IBrokerChannel
        {
            private readonly List<Dictionary<string, string>> sent = new List<Dictionary<string, string>>();

            public RecordingChannel()
            {
                Source = BrokerSources.User;
                Phase = BrokerPhases.Idle;
                TurnOn = BrokerTurnOn.Available;
                ForgetHttp = 200;
                Pair = "{\"state\":\"idle\"}";
                Failures = "{\"total\":0,\"groups\":[]}";
                Diagnostics = "{}";
                Logs = "{\"logs\":[],\"next\":0}";
            }

            public string Status { get; set; }
            public string Pair { get; set; }
            public string Failures { get; set; }
            public string Diagnostics { get; set; }
            public string Logs { get; set; }
            public string Source { get; set; }
            public string Phase { get; set; }
            public string TurnOn { get; set; }
            public string Fail { get; set; }
            public int ForgetHttp { get; set; }
            public BrokerReply TurnOnReply { get; set; }
            public BrokerReply TurnOffReply { get; set; }
            // Runs while a logs request is out, before its answer returns.
            public Action BeforeLogs { get; set; }

            public int Count(string op)
            {
                return sent.Count(fields => fields[BrokerProtocol.OpField] == op);
            }

            public Dictionary<string, string> Last(string op)
            {
                return sent.Last(fields => fields[BrokerProtocol.OpField] == op);
            }

            public Task<BrokerReply> SendAsync(IDictionary<string, string> fields)
            {
                Dictionary<string, string> copy = new Dictionary<string, string>(fields, StringComparer.Ordinal);
                sent.Add(copy);
                string op = copy[BrokerProtocol.OpField];
                if (Fail != null)
                {
                    return Task.FromResult(BrokerReply.Failure(Fail));
                }
                switch (op)
                {
                    case BrokerOps.Status:
                        return Ok(Status);
                    case BrokerOps.PairStatus:
                    case BrokerOps.Pair:
                        return Ok(op == BrokerOps.Pair ? "{\"ok\":true}" : Pair);
                    case BrokerOps.Forget:
                        return Task.FromResult(new BrokerReply(ForgetHttp == 200, ForgetHttp, "",
                            ForgetHttp == 200 ? "{\"ok\":true,\"forget\":{\"state\":\"pending\"}}" : "{\"error\":\"Turn off the tunnel first.\"}",
                            Source, Phase, TurnOn));
                    case BrokerOps.Failures:
                        return Ok(Failures);
                    case BrokerOps.Diagnostics:
                        return Ok(Diagnostics);
                    case BrokerOps.Logs:
                        if (BeforeLogs != null)
                        {
                            BeforeLogs();
                        }
                        return Ok(Logs);
                    case BrokerOps.TurnOn:
                        return Task.FromResult(TurnOnReply ?? new BrokerReply(true, 200, "", "{\"ok\":true}", Source, Phase, TurnOn));
                    case BrokerOps.TurnOff:
                        return Task.FromResult(TurnOffReply ?? new BrokerReply(true, 200, "", "{\"ok\":true}", Source, Phase, TurnOn));
                    default:
                        return Ok("{\"ok\":true}");
                }
            }

            private Task<BrokerReply> Ok(string body)
            {
                if (body == null)
                {
                    return Task.FromResult(BrokerReply.Failure(BrokerCodes.EngineStarting));
                }
                return Task.FromResult(new BrokerReply(true, 200, "", body, Source, Phase, TurnOn));
            }
        }
    }
}
