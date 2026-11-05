using System;
using System.Collections.Generic;
using System.Text;

namespace HotspotShade.WinUI2.Core.Tests
{
    internal static class CoreTests
    {
        public static void Run(TestRunner runner)
        {
            runner.Check("initial state is unpaired and makes no claim", delegate
            {
                DemoSession session = NewSession(NewClock());
                DemoDashboardContent dashboard = session.BuildDashboard();
                AssertEx.Equal(DemoText.NotPaired, dashboard.Title, "title");
                AssertEx.Equal(DemoPrimaryAction.Pair, dashboard.PrimaryAction, "primary action");
                AssertEx.Equal(DemoStatusKind.Off, dashboard.StatusKind, "status kind");
                AssertEx.Equal(DemoText.NotPaired, dashboard.SourceDevice.Value, "source device value");
                AssertEx.Equal(DemoText.TunnelOff, dashboard.Connection.Value, "connection value");
                AssertEx.False(dashboard.HasAttention, "attention must be empty");
                AssertEx.False(session.HasPendingAction, "no pending action");
            });

            runner.Check("pairing start shows loading and then a code", delegate
            {
                DemoSession session = NewSession(NewClock());
                session.BeginPairing();
                DemoDashboardContent dashboard = session.BuildDashboard();
                AssertEx.True(dashboard.IsPairing, "pairing view is shown");
                AssertEx.Equal(DemoStatusKind.Pairing, dashboard.StatusKind, "status kind");
                AssertEx.False(dashboard.PairingCodeReady, "code is not ready");
                AssertEx.Equal("", dashboard.PairingCode, "code is empty");
                AssertEx.True(session.HasPendingAction, "pairing start is pending");
                AssertEx.Equal(DemoText.Pairing, session.BuildSettings().PairingStateText, "settings pairing state");
                session.CompletePending();
                dashboard = session.BuildDashboard();
                AssertEx.True(dashboard.PairingCodeReady, "code is ready");
                AssertEx.Equal(DemoText.PairingCodeDisplay, dashboard.PairingCode, "pairing code");
                AssertEx.Equal(DemoText.Pairing, dashboard.Title, "title");
                AssertEx.False(session.HasPendingAction, "no pending action");
            });

            runner.Check("pairing approval reaches ready", delegate
            {
                DemoSession session = NewSession(NewClock());
                session.BeginPairing();
                session.CompletePending();
                session.ApprovePairing();
                DemoDashboardContent dashboard = session.BuildDashboard();
                AssertEx.Equal(DemoText.Ready, dashboard.Title, "title");
                AssertEx.Equal(DemoText.Paired, dashboard.SourceDevice.Value, "source device value");
                AssertEx.Equal(DemoPrimaryAction.TurnOn, dashboard.PrimaryAction, "primary action");
                AssertEx.Equal(DemoStatusKind.Off, dashboard.StatusKind, "status kind");
                AssertEx.True(session.BuildSettings().Paired, "settings says paired");
                AssertEx.True(session.BuildSettings().PairActionEnabled, "pair again is enabled");
                session.BeginTurnOn();
                AssertEx.True(session.HasPendingAction, "start after approval");
                session.CompletePending();
                AssertEx.Equal(DemoText.On, session.BuildDashboard().Title, "on after approval");
            });

            runner.Check("cancel pairing returns to unpaired", delegate
            {
                DemoSession session = NewSession(NewClock());
                session.BeginPairing();
                session.CompletePending();
                session.CancelPairing();
                DemoDashboardContent dashboard = session.BuildDashboard();
                AssertEx.Equal(DemoText.NotPaired, dashboard.Title, "title");
                AssertEx.False(dashboard.IsPairing, "pairing view is hidden");
                AssertEx.Equal("", dashboard.PairingCode, "code is empty");
                AssertEx.Equal(DemoPrimaryAction.Pair, dashboard.PrimaryAction, "primary action");
            });

            runner.Check("pairing failure is actionable", delegate
            {
                DemoSession session = NewSession(NewClock());
                session.BeginPairing();
                session.CompletePending();
                session.SimulatePairingFailure();
                DemoDashboardContent dashboard = session.BuildDashboard();
                AssertEx.Equal(DemoText.PairingFailed, dashboard.Title, "title");
                AssertEx.Equal(DemoStatusKind.Attention, dashboard.StatusKind, "status kind");
                AssertEx.Equal(DemoPrimaryAction.PairAgain, dashboard.PrimaryAction, "primary action");
                AssertEx.False(session.HasPendingAction, "no pending action");
            });

            runner.Check("turn on shows loading and then on", delegate
            {
                DemoSession session = NewSession(NewClock());
                session.ApplyScenario(DemoScenario.Ready);
                session.BeginTurnOn();
                DemoDashboardContent dashboard = session.BuildDashboard();
                AssertEx.Equal(DemoText.StartingTunnel, dashboard.Title, "busy title");
                AssertEx.Equal(DemoStatusKind.Busy, dashboard.StatusKind, "busy status");
                AssertEx.Equal(DemoPrimaryAction.None, dashboard.PrimaryAction, "no primary action");
                AssertEx.True(session.HasPendingAction, "start is pending");
                session.CompletePending();
                dashboard = session.BuildDashboard();
                AssertEx.Equal(DemoText.On, dashboard.Title, "title");
                AssertEx.Equal(DemoStatusKind.On, dashboard.StatusKind, "status kind");
                AssertEx.Equal(DemoPrimaryAction.TurnOff, dashboard.PrimaryAction, "primary action");
                AssertEx.Equal(DemoText.TunnelOn, dashboard.Connection.Value, "connection value");
                string details = string.Join(" ", dashboard.Connection.Details);
                AssertEx.Contains(details, DemoText.PingOn, "ping line");
                AssertEx.Contains(details, "3 active connections", "connection count");
                AssertEx.NotEmpty(dashboard.CheckedText, "checked text");
            });

            runner.Check("turn off records a last stop", delegate
            {
                DemoSession session = NewSession(NewClock());
                session.ApplyScenario(DemoScenario.On);
                session.BeginTurnOff();
                DemoDashboardContent dashboard = session.BuildDashboard();
                AssertEx.Equal(DemoText.TurningOff, dashboard.Title, "busy title");
                AssertEx.Equal(DemoStatusKind.Busy, dashboard.StatusKind, "busy status");
                session.CompletePending();
                dashboard = session.BuildDashboard();
                AssertEx.Equal(DemoText.Ready, dashboard.Title, "title");
                AssertEx.Equal(DemoStatusKind.Off, dashboard.StatusKind, "status kind");
                AssertEx.Equal(DemoPrimaryAction.TurnOn, dashboard.PrimaryAction, "primary action");
                string details = string.Join(" ", dashboard.Connection.Details);
                AssertEx.Contains(details, "Last stop:", "last stop line");
                AssertEx.Contains(details, "You turned the tunnel off.", "last stop reason");
            });

            runner.Check("forget is blocked while running", delegate
            {
                DemoSession session = NewSession(NewClock());
                session.ApplyScenario(DemoScenario.On);
                AssertEx.False(session.Forget(), "forget must be blocked");
                DemoDashboardContent dashboard = session.BuildDashboard();
                AssertEx.True(dashboard.HasAttention, "attention line");
                AssertEx.Equal(DemoSecondaryAction.TurnOffAndForget, dashboard.SecondaryAction, "secondary action");
                DemoAttentionItem item = FindAttention(dashboard, DemoText.ForgetBlocked);
                AssertEx.Equal(DemoAttentionAction.TurnOffAndForget, item.Action, "attention action");
            });

            runner.Check("turn off and forget reaches the forgotten state", delegate
            {
                DemoSession session = NewSession(NewClock());
                session.ApplyScenario(DemoScenario.On);
                session.TurnOffAndForget();
                AssertEx.True(session.HasPendingAction, "stop is pending");
                AssertEx.Equal(DemoText.TurningOff, session.BuildDashboard().Title, "busy title");
                session.CompletePending();
                DemoDashboardContent dashboard = session.BuildDashboard();
                AssertEx.Equal(DemoText.NotPaired, dashboard.Title, "title");
                AssertEx.Contains(dashboard.Subtitle, "Forgotten.", "subtitle");
                AssertEx.Equal(DemoPrimaryAction.Pair, dashboard.PrimaryAction, "primary action");
                AssertEx.False(session.BuildSettings().Paired, "settings says unpaired");
                AssertEx.Contains(session.BuildSettings().ForgetMessage, "Forgotten.", "settings forget message");
            });

            runner.Check("stale status offers check now and recovers", delegate
            {
                DemoSession session = NewSession(NewClock());
                session.ApplyScenario(DemoScenario.Stale);
                DemoDashboardContent dashboard = session.BuildDashboard();
                AssertEx.Equal(DemoText.On, dashboard.Title, "title");
                AssertEx.Equal(DemoStatusKind.On, dashboard.StatusKind, "status kind");
                AssertEx.Equal(DemoSecondaryAction.CheckNow, dashboard.SecondaryAction, "secondary action");
                DemoAttentionItem item = FindAttention(dashboard, DemoText.StaleStatus);
                AssertEx.Equal(DemoAttentionAction.CheckNow, item.Action, "attention action");
                session.BeginCheckNow();
                dashboard = session.BuildDashboard();
                AssertEx.Equal(DemoText.Checking, dashboard.Title, "checking title");
                AssertEx.Equal(DemoStatusKind.Busy, dashboard.StatusKind, "busy status");
                session.CompletePending();
                dashboard = session.BuildDashboard();
                AssertEx.Equal(DemoText.On, dashboard.Title, "recovered title");
                AssertEx.Equal(DemoPrimaryAction.TurnOff, dashboard.PrimaryAction, "primary action");
                AssertEx.False(ContainsAttention(dashboard, DemoText.StaleStatus), "stale line is gone");
            });

            runner.Check("unavailable status makes no on or off claim", delegate
            {
                DemoSession session = NewSession(NewClock());
                session.ApplyScenario(DemoScenario.Unavailable);
                DemoDashboardContent dashboard = session.BuildDashboard();
                AssertEx.Equal(DemoText.StatusUnavailable, dashboard.Title, "title");
                AssertEx.Equal(DemoStatusKind.Attention, dashboard.StatusKind, "status kind");
                AssertEx.Equal(DemoPrimaryAction.CheckNow, dashboard.PrimaryAction, "primary action");
                AssertEx.Equal(DemoText.StatusUnavailableLine, dashboard.SourceDevice.Value, "source value");
                AssertEx.Equal(DemoText.StatusUnavailableLine, dashboard.Connection.Value, "connection value");
                session.BeginCheckNow();
                session.CompletePending();
                dashboard = session.BuildDashboard();
                AssertEx.Equal(DemoText.On, dashboard.Title, "restored title");
                AssertEx.Equal(DemoStatusKind.On, dashboard.StatusKind, "restored status");
            });

            runner.Check("error retries back to ready", delegate
            {
                DemoSession session = NewSession(NewClock());
                session.ApplyScenario(DemoScenario.Error);
                DemoDashboardContent dashboard = session.BuildDashboard();
                AssertEx.Equal(DemoText.NeedsAttention, dashboard.Title, "title");
                AssertEx.Equal(DemoPrimaryAction.Retry, dashboard.PrimaryAction, "primary action");
                AssertEx.Contains(dashboard.Subtitle, "simulated", "subtitle");
                session.BeginCheckNow();
                session.CompletePending();
                dashboard = session.BuildDashboard();
                AssertEx.Equal(DemoText.Ready, dashboard.Title, "recovered title");
                AssertEx.Equal(DemoPrimaryAction.TurnOn, dashboard.PrimaryAction, "primary action");
            });

            runner.Check("not trusted state pairs again", delegate
            {
                DemoSession session = NewSession(NewClock());
                session.ApplyScenario(DemoScenario.NotTrusted);
                DemoDashboardContent dashboard = session.BuildDashboard();
                AssertEx.Equal(DemoText.NotTrusted, dashboard.Title, "title");
                AssertEx.Equal(DemoText.NotTrusted, dashboard.SourceDevice.Value, "source value");
                AssertEx.Equal(DemoPrimaryAction.PairAgain, dashboard.PrimaryAction, "primary action");
                AssertEx.Equal(DemoStatusKind.Attention, dashboard.StatusKind, "status kind");
            });

            runner.Check("on and not trusted keeps running with attention", delegate
            {
                DemoSession session = NewSession(NewClock());
                session.ApplyScenario(DemoScenario.OnNotTrusted);
                DemoDashboardContent dashboard = session.BuildDashboard();
                AssertEx.Equal(DemoText.On, dashboard.Title, "title");
                AssertEx.Equal(DemoStatusKind.On, dashboard.StatusKind, "status kind");
                AssertEx.Equal(DemoText.NotTrusted, dashboard.SourceDevice.Value, "source value");
                AssertEx.Equal(DemoPrimaryAction.TurnOff, dashboard.PrimaryAction, "primary action");
                DemoAttentionItem item = FindAttention(dashboard, DemoText.NotTrustedWhileRunning);
                AssertEx.Equal(DemoAttentionAction.TurnOff, item.Action, "attention action");
                AssertEx.Equal(DemoText.NotTrusted, session.BuildSettings().PairingStateText, "settings state");
                AssertEx.False(session.BuildSettings().PairActionEnabled, "pair disabled while running");
            });

            runner.Check("waiting state has no primary action", delegate
            {
                DemoSession session = NewSession(NewClock());
                session.ApplyScenario(DemoScenario.Waiting);
                DemoDashboardContent dashboard = session.BuildDashboard();
                AssertEx.Equal(DemoText.Waiting, dashboard.Title, "title");
                AssertEx.Equal(DemoPrimaryAction.None, dashboard.PrimaryAction, "primary action");
                AssertEx.Equal(DemoSecondaryAction.Forget, dashboard.SecondaryAction, "secondary action");
            });

            runner.Check("activity empty and refresh states", delegate
            {
                DemoSession session = NewSession(NewClock());
                session.ApplyScenario(DemoScenario.ActivityEmpty);
                DemoActivityContent activity = session.BuildActivity();
                AssertEx.True(activity.IsEmpty, "activity is empty");
                AssertEx.False(activity.HasLines, "no lines");
                session.RefreshActivity();
                activity = session.BuildActivity();
                AssertEx.True(activity.IsLoading, "activity is loading");
                session.CompletePending();
                activity = session.BuildActivity();
                AssertEx.True(activity.IsEmpty, "activity is empty again");
            });

            runner.Check("activity loaded and details are available", delegate
            {
                DemoSession session = NewSession(NewClock());
                session.ApplyScenario(DemoScenario.Ready);
                DemoActivityContent activity = session.BuildActivity();
                AssertEx.True(activity.HasLines, "activity has lines");
                session.SetActivityDetails(true);
                AssertEx.True(session.ShowActivityDetails, "details flag");
                DemoLogLine line = activity.Lines[0];
                AssertEx.NotEmpty(line.TimeText, "time");
                AssertEx.Contains(line.DetailsText, "seq", "details");
                AssertEx.Contains(line.AccessibilityText(true), line.Message, "accessibility text");
                session.RefreshActivity();
                AssertEx.True(session.BuildActivity().IsLoading, "loading");
                session.CompletePending();
                AssertEx.True(session.BuildActivity().HasLines, "loaded");
            });

            runner.Check("failures need a running tunnel and support empty", delegate
            {
                DemoSession session = NewSession(NewClock());
                session.ApplyScenario(DemoScenario.Ready);
                DemoFailuresContent failures = session.BuildFailures();
                AssertEx.Equal(DemoFailuresState.Idle, failures.State, "idle state");
                AssertEx.True(failures.TunnelOff, "tunnel off hint");
                AssertEx.False(failures.CanRefresh, "refresh disabled while off");
                session.BeginTurnOn();
                session.CompletePending();
                session.LoadFailures();
                failures = session.BuildFailures();
                AssertEx.True(failures.IsLoading, "loading");
                session.CompletePending();
                failures = session.BuildFailures();
                AssertEx.Equal(DemoFailuresState.Loaded, failures.State, "loaded state");
                AssertEx.Equal(5, failures.Rows.Count, "row count");
                AssertEx.Equal(14, failures.Total, "total count");
                AssertEx.True(failures.CanRefresh, "refresh enabled");
                session.ClearFailures();
                failures = session.BuildFailures();
                AssertEx.True(failures.IsEmpty, "empty state");
                AssertEx.False(failures.HasRows, "no rows");
                session.LoadFailures();
                session.CompletePending();
                AssertEx.True(session.BuildFailures().IsEmpty, "empty state stays");
                session.BeginTurnOff();
                session.CompletePending();
                failures = session.BuildFailures();
                AssertEx.True(failures.TunnelOff, "tunnel off after stop");
                AssertEx.False(failures.HasRows, "no stale rows after stop");
            });

            runner.Check("failure stages decode and keep groups apart", delegate
            {
                DemoFailureRow connect = new DemoFailureRow(2, "TCP IPv4", "example.com:443", "No answer in time", " connect ");
                DemoFailureRow request = new DemoFailureRow(2, "TCP IPv4", "example.com:443", "No answer in time", "request");
                AssertEx.Equal(DemoFailurePhase.Connect, connect.Phase, "connect phase");
                AssertEx.Equal("Source connection", connect.PhaseLabel, "connect label");
                AssertEx.Equal("connect", connect.PhaseWord, "connect word");
                AssertEx.Equal(DemoFailurePhase.Request, request.Phase, "request phase");
                AssertEx.Equal("Destination request", request.PhaseLabel, "request label");
                AssertEx.False(connect.GroupKey == request.GroupKey, "different stages must not share a group key");
                AssertEx.Contains(connect.AccessibilityLabel, "Stage: Source connection", "connect accessibility");
                AssertEx.Contains(request.AccessibilityLabel, "Stage: Destination request", "request accessibility");

                DemoFailureRow missing = new DemoFailureRow(1, "TCP IPv4", "missing.example:443", "Failed", null);
                AssertEx.Equal(DemoFailurePhase.NotReported, missing.Phase, "missing phase");
                AssertEx.Equal("Not reported", missing.PhaseLabel, "missing label");
                AssertEx.Equal("-", missing.PhaseWord, "missing word");

                DemoFailureRow invalid = new DemoFailureRow(1, "TCP IPv4", "future.example:443", "Failed", "future");
                AssertEx.Equal(DemoFailurePhase.Unknown, invalid.Phase, "unknown phase");
                AssertEx.Equal("Unknown stage", invalid.PhaseLabel, "unknown label");
                AssertEx.Equal("unknown", invalid.PhaseWord, "unknown word");

                DemoFailureRow mixedCase = new DemoFailureRow(1, "TCP IPv4", "auth.example:443", "Failed", " AUTH ");
                AssertEx.Equal(DemoFailurePhase.Auth, mixedCase.Phase, "case and whitespace");
                AssertEx.Equal("Sign-in", mixedCase.PhaseLabel, "auth label");

                List<DemoFailureRow> rows = DemoReports.CreateFailureRows();
                int sameTarget = 0;
                DemoFailureRow firstStage = null;
                DemoFailureRow secondStage = null;
                for (int index = 0; index < rows.Count; index++)
                {
                    DemoFailureRow row = rows[index];
                    if (row.Target == "example.com:443" && row.Reason == "No answer in time")
                    {
                        sameTarget++;
                        if (firstStage == null)
                        {
                            firstStage = row;
                        }
                        else
                        {
                            secondStage = row;
                        }
                    }
                }
                AssertEx.Equal(2, sameTarget, "same target and reason rows");
                AssertEx.True(firstStage != null && secondStage != null, "both stage rows are present");
                AssertEx.False(firstStage.GroupKey == secondStage.GroupKey, "stage rows have distinct keys");
                AssertEx.True(firstStage.PhaseWord != secondStage.PhaseWord, "stage rows have distinct words");
            });

            runner.Check("ping setting applies to the next start", delegate
            {
                DemoSession session = NewSession(NewClock());
                session.ApplyScenario(DemoScenario.On);
                DemoDashboardContent dashboard = session.BuildDashboard();
                AssertEx.Contains(string.Join(" ", dashboard.Connection.Details), DemoText.PingOn, "ping on");
                AssertEx.Equal(DemoText.PingOn, session.BuildSettings().PingStateText, "settings ping on");
                session.SetPingEnabled(false);
                dashboard = session.BuildDashboard();
                AssertEx.Contains(string.Join(" ", dashboard.Connection.Details), DemoText.PingOn, "running ping stays on");
                session.BeginTurnOff();
                session.CompletePending();
                session.BeginTurnOn();
                session.CompletePending();
                dashboard = session.BuildDashboard();
                AssertEx.Contains(string.Join(" ", dashboard.Connection.Details), DemoText.PingOff, "ping off next start");
                AssertEx.Equal(DemoText.PingOff, session.BuildSettings().PingStateText, "settings ping off");
            });

            runner.Check("reports are labeled simulated and hold no secret", delegate
            {
                DemoSession session = NewSession(NewClock());
                session.ApplyScenario(DemoScenario.On);
                session.LoadFailures();
                session.CompletePending();
                string failureReport = session.FailureReport();
                AssertEx.Contains(failureReport, "simulated", "failure report label");
                AssertEx.Contains(failureReport, "example.com", "failure report target");
                AssertEx.Contains(failureReport, "No answer in time", "neutral timeout wording");
                AssertEx.Contains(failureReport, "6 x TCP IPv4 example.com:443. No answer in time. Stage: Destination request.", "failure report request line");
                AssertEx.Contains(failureReport, "3 x TCP IPv4 example.com:443. No answer in time. Stage: Source connection.", "failure report connect line");
                AssertEx.Contains(failureReport, "Stage: Not reported", "failure report missing stage");
                AssertEx.DoesNotContain(failureReport, "token", "failure report token");
                AssertEx.DoesNotContain(failureReport, "password", "failure report password");
                AssertEx.DoesNotContain(failureReport, "secret", "failure report secret");
                string diagnostics = session.DiagnosticsReport();
                AssertEx.Contains(diagnostics, "simulated", "diagnostics label");
                AssertEx.Contains(diagnostics, "No engine", "diagnostics engine");
                AssertEx.Contains(diagnostics, "No route", "diagnostics route");
                AssertEx.DoesNotContain(diagnostics, "token", "diagnostics token");
                AssertEx.DoesNotContain(diagnostics, "password", "diagnostics password");
                AssertEx.DoesNotContain(diagnostics, "secret", "diagnostics secret");
            });

            runner.Check("every scenario builds complete text", delegate
            {
                DemoSession session = NewSession(NewClock());
                AssertEx.Equal(14, DemoScenarios.All.Count, "scenario count");
                for (int index = 0; index < DemoScenarios.All.Count; index++)
                {
                    DemoScenarioInfo info = DemoScenarios.All[index];
                    AssertEx.NotEmpty(info.Title, "scenario title");
                    AssertEx.NotEmpty(info.Description, "scenario description");
                    session.ApplyScenario(info.Scenario);
                    DemoDashboardContent dashboard = session.BuildDashboard();
                    AssertEx.NotEmpty(dashboard.Title, "dashboard title for " + info.Title);
                    AssertEx.NotEmpty(dashboard.Subtitle, "dashboard subtitle for " + info.Title);
                    if (dashboard.HasPrimaryAction)
                    {
                        AssertEx.NotEmpty(dashboard.PrimaryActionLabel, "primary label for " + info.Title);
                    }
                    if (dashboard.HasSecondaryAction)
                    {
                        AssertEx.NotEmpty(dashboard.SecondaryActionLabel, "secondary label for " + info.Title);
                    }
                    for (int item = 0; item < dashboard.Attention.Count; item++)
                    {
                        AssertEx.NotEmpty(dashboard.Attention[item].Text, "attention text for " + info.Title);
                        if (dashboard.Attention[item].HasAction)
                        {
                            AssertEx.NotEmpty(dashboard.Attention[item].ActionLabel, "attention label for " + info.Title);
                        }
                    }
                    AssertAsciiStyle(CollectText(session), "scenario " + info.Title);
                }
            });

            runner.Check("activity logging stays bounded", delegate
            {
                DemoSession session = NewSession(NewClock());
                session.ApplyScenario(DemoScenario.Ready);
                for (int index = 0; index < 40; index++)
                {
                    session.BeginTurnOn();
                    session.CompletePending();
                    session.BeginTurnOff();
                    session.CompletePending();
                }
                DemoActivityContent activity = session.BuildActivity();
                AssertEx.True(activity.Lines.Count <= 50, "activity list is bounded");
                AssertEx.True(activity.Lines.Count > 0, "activity list has entries");
            });

            runner.Check("checked text ages with the clock", delegate
            {
                FakeClock clock = NewClock();
                DemoSession session = new DemoSession(clock);
                session.ApplyScenario(DemoScenario.Ready);
                AssertEx.Contains(session.BuildDashboard().CheckedText, "Checked just now", "fresh text");
                clock.Advance(15);
                AssertEx.Contains(session.BuildDashboard().CheckedText, "seconds ago", "seconds text");
                clock.Advance(120);
                AssertEx.Contains(session.BuildDashboard().CheckedText, "minutes ago", "minutes text");
                AssertEx.Contains(DemoText.CheckedText(DateTimeOffset.MinValue, DateTimeOffset.MaxValue),
                    "5258964959 minutes ago", "large timestamp text");
            });

            runner.Check("theme and ping defaults are explicit", delegate
            {
                DemoSession session = NewSession(NewClock());
                AssertEx.Equal(DemoTheme.System, session.Theme, "theme default");
                AssertEx.True(session.PingEnabled, "ping default");
                AssertEx.False(session.ShowActivityDetails, "details default");
                session.SetTheme(DemoTheme.Light);
                AssertEx.Equal(DemoTheme.Light, session.BuildSettings().Theme, "light theme");
                session.SetTheme(DemoTheme.Dark);
                AssertEx.Equal(DemoTheme.Dark, session.BuildSettings().Theme, "dark theme");
            });

            runner.Check("turn on requires a pairing", delegate
            {
                DemoSession session = NewSession(NewClock());
                session.ApplyScenario(DemoScenario.Unpaired);
                session.BeginTurnOn();
                AssertEx.False(session.HasPendingAction, "no start");
                AssertEx.Equal(DemoText.NotPaired, session.BuildDashboard().Title, "title");
            });

            runner.Check("pair is disabled while the tunnel runs", delegate
            {
                DemoSession session = NewSession(NewClock());
                session.ApplyScenario(DemoScenario.On);
                DemoSettingsContent settings = session.BuildSettings();
                AssertEx.False(settings.PairActionEnabled, "pair disabled");
                AssertEx.Contains(settings.PairActionReason, "Turn off the tunnel first.", "pair reason");
                AssertEx.True(settings.ForgetBlocked, "forget blocked");
            });

            runner.Check("attention actions map to real demo actions", delegate
            {
                DemoSession session = NewSession(NewClock());
                session.ApplyScenario(DemoScenario.Stale);
                DemoAttentionItem stale = FindAttention(session.BuildDashboard(), DemoText.StaleStatus);
                AssertEx.Equal(DemoAttentionAction.CheckNow, stale.Action, "stale action");
                session.ApplyScenario(DemoScenario.On);
                session.Forget();
                DemoAttentionItem blocked = FindAttention(session.BuildDashboard(), DemoText.ForgetBlocked);
                AssertEx.Equal(DemoAttentionAction.TurnOffAndForget, blocked.Action, "blocked action");
            });

            runner.Check("after forget state is calm", delegate
            {
                DemoSession session = NewSession(NewClock());
                session.ApplyScenario(DemoScenario.ForgetConfirmed);
                DemoDashboardContent dashboard = session.BuildDashboard();
                AssertEx.Equal(DemoText.NotPaired, dashboard.Title, "title");
                AssertEx.Contains(dashboard.Subtitle, "Forgotten.", "subtitle");
                AssertEx.Equal(DemoPrimaryAction.Pair, dashboard.PrimaryAction, "primary action");
                AssertEx.Contains(session.BuildSettings().ForgetMessage, "Forgotten.", "settings message");
            });

            runner.Check("completing with no pending action is harmless", delegate
            {
                DemoSession session = NewSession(NewClock());
                session.CompletePending();
                AssertEx.False(session.HasPendingAction, "no pending action");
                AssertEx.Equal(DemoText.NotPaired, session.BuildDashboard().Title, "title");
            });

            runner.Check("applying a scenario clears a pending action", delegate
            {
                DemoSession session = NewSession(NewClock());
                session.ApplyScenario(DemoScenario.Ready);
                session.BeginTurnOn();
                AssertEx.True(session.HasPendingAction, "start pending");
                session.ApplyScenario(DemoScenario.Unpaired);
                AssertEx.False(session.HasPendingAction, "pending cleared");
                AssertEx.Equal(DemoText.NotPaired, session.BuildDashboard().Title, "title");
            });
        }

        private static FakeClock NewClock()
        {
            return new FakeClock(new DateTimeOffset(2026, 11, 4, 12, 0, 0, TimeSpan.Zero));
        }

        private static DemoSession NewSession(FakeClock clock)
        {
            return new DemoSession(clock);
        }

        private static bool ContainsAttention(DemoDashboardContent content, string text)
        {
            for (int index = 0; index < content.Attention.Count; index++)
            {
                if (content.Attention[index].Text.IndexOf(text, StringComparison.Ordinal) >= 0)
                {
                    return true;
                }
            }
            return false;
        }

        private static DemoAttentionItem FindAttention(DemoDashboardContent content, string text)
        {
            for (int index = 0; index < content.Attention.Count; index++)
            {
                if (content.Attention[index].Text.IndexOf(text, StringComparison.Ordinal) >= 0)
                {
                    return content.Attention[index];
                }
            }
            throw new Exception("attention line not found: " + text);
        }

        private static string CollectText(DemoSession session)
        {
            DemoDashboardContent dashboard = session.BuildDashboard();
            DemoActivityContent activity = session.BuildActivity();
            DemoSettingsContent settings = session.BuildSettings();
            DemoFailuresContent failures = session.BuildFailures();
            StringBuilder text = new StringBuilder();
            text.AppendLine(dashboard.Title);
            text.AppendLine(dashboard.Subtitle);
            text.AppendLine(dashboard.CheckedText);
            text.AppendLine(dashboard.PairingTitle);
            text.AppendLine(dashboard.PairingSubtitle);
            text.AppendLine(dashboard.PairingStatus);
            text.AppendLine(dashboard.PairingCode);
            text.AppendLine(dashboard.SourceDevice.Title);
            text.AppendLine(dashboard.SourceDevice.Value);
            AppendLines(text, dashboard.SourceDevice.Details);
            text.AppendLine(dashboard.Connection.Title);
            text.AppendLine(dashboard.Connection.Value);
            AppendLines(text, dashboard.Connection.Details);
            for (int index = 0; index < dashboard.Attention.Count; index++)
            {
                text.AppendLine(dashboard.Attention[index].Text);
                text.AppendLine(dashboard.Attention[index].ActionLabel);
            }
            text.AppendLine(activity.Message);
            text.AppendLine(activity.Detail);
            for (int index = 0; index < activity.Lines.Count; index++)
            {
                text.AppendLine(activity.Lines[index].Message);
                text.AppendLine(activity.Lines[index].DetailsText);
            }
            text.AppendLine(settings.PairingStateText);
            text.AppendLine(settings.PairActionReason);
            text.AppendLine(settings.ForgetMessage);
            text.AppendLine(settings.PingStateText);
            text.AppendLine(settings.NotificationsText);
            text.AppendLine(settings.LoginText);
            text.AppendLine(settings.EngineText);
            text.AppendLine(settings.ModeText);
            text.AppendLine(settings.StatusText);
            text.AppendLine(failures.Message);
            for (int index = 0; index < failures.Rows.Count; index++)
            {
                text.AppendLine(failures.Rows[index].Kind);
                text.AppendLine(failures.Rows[index].Target);
                text.AppendLine(failures.Rows[index].PhaseLabel);
                text.AppendLine(failures.Rows[index].Reason);
            }
            text.AppendLine(session.FailureReport());
            text.AppendLine(session.DiagnosticsReport());
            return text.ToString();
        }

        private static void AppendLines(StringBuilder text, System.Collections.Generic.IReadOnlyList<string> lines)
        {
            for (int index = 0; index < lines.Count; index++)
            {
                text.AppendLine(lines[index]);
            }
        }

        private static void AssertAsciiStyle(string text, string what)
        {
            char[] forbidden = new char[] { '\u2014', '\u2013', '\u2018', '\u2019', '\u201C', '\u201D' };
            for (int index = 0; index < text.Length; index++)
            {
                for (int check = 0; check < forbidden.Length; check++)
                {
                    if (text[index] == forbidden[check])
                    {
                        throw new Exception(what + ": forbidden punctuation U+"
                            + ((int)text[index]).ToString("X4") + ".");
                    }
                }
            }
        }
    }
}
