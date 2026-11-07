using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.Core.Tests
{
    // Hermetic checks for the display boundary. They use a fake broker and a
    // fake clock. They open no pipe, process, adapter, or route. The checks
    // guard the rule that the app never shows On without a fresh, confirmed
    // status.
    internal static class EngineBoundaryTests
    {
        public static void Run(TestRunner runner)
        {
            runner.Check("boundary: the initial view is not checked and claims nothing", delegate
            {
                TestClock clock = new TestClock();
                EngineBoundary boundary = new EngineBoundary(
                    new UnavailableEngineBroker(),
                    clock,
                    TimeSpan.FromMilliseconds(500));
                EngineBoundaryContent content = boundary.Content;

                AssertEx.Equal(EngineBoundaryKind.NotChecked, content.Kind, "kind");
                AssertEx.Equal("Engine: not checked", content.Title, "title");
                AssertEx.Equal("Not checked", content.StatusText, "status");
                AssertEx.Contains(content.Message, "unknown", "message");
                AssertEx.False(content.IsRunning, "no on claim");
                AssertEx.False(content.IsEngineAvailable, "not available");
                AssertEx.True(content.IsStatusUnknown, "unknown state");
                AssertEx.False(content.CanStart, "no start");
                AssertEx.False(content.CanStop, "no stop");
                AssertEx.False(content.CanForget, "no forget");
                AssertEx.True(content.CanCheck, "a check is possible");
                AssertEx.Equal("Not checked.", content.CheckedText, "checked text");
            });

            runner.Check("boundary: a missing helper is unavailable and never on", delegate
            {
                TestClock clock = new TestClock();
                EngineBoundary boundary = new EngineBoundary(
                    new UnavailableEngineBroker(),
                    clock,
                    TimeSpan.FromMilliseconds(500));
                EngineCommandResult result = Wait(boundary.ConnectAsync());
                EngineBoundaryContent content = boundary.Content;

                AssertEx.False(result.Ok, "connect fails");
                AssertEx.Equal(EngineProtocol.ErrorCodes.HelperMissing, result.Code, "code");
                AssertEx.Equal(EngineBoundaryKind.Unavailable, content.Kind, "kind");
                AssertEx.Equal("Engine: not available", content.Title, "title");
                AssertEx.Equal("Unavailable", content.StatusText, "status");
                AssertEx.Contains(content.Message, "not installed", "message");
                AssertEx.Contains(content.ActionText, "not installed", "action text");
                AssertEx.False(content.IsRunning, "no on claim");
                AssertEx.False(content.IsEngineAvailable, "not available");
                AssertEx.True(content.IsStatusUnknown, "unknown state");
                AssertEx.False(content.CanStart, "no start");
                AssertEx.True(content.CanCheck, "a later check is possible");
                AssertEx.Equal("Pairing: unknown.", content.PairingText, "no stale pairing claim");
            });

            runner.Check("boundary: a ready engine shows off and allows an explicit start", delegate
            {
                ScriptedBroker broker = new ScriptedBroker();
                EngineBoundary boundary = NewBoundary(broker);
                EngineCommandResult result = Wait(boundary.ConnectAsync());
                EngineBoundaryContent content = boundary.Content;

                AssertEx.True(result.Ok, "connect succeeds");
                AssertEx.Equal(EngineBoundaryKind.Ready, content.Kind, "kind");
                AssertEx.Equal("Engine: tunnel off", content.Title, "title");
                AssertEx.Equal("Off", content.StatusText, "status");
                AssertEx.False(content.IsRunning, "no on claim");
                AssertEx.True(content.IsEngineAvailable, "available");
                AssertEx.False(content.IsStatusUnknown, "known state");
                AssertEx.True(content.CanStart, "start is allowed");
                AssertEx.True(content.CanForget, "forget is allowed while off");
                AssertEx.Equal("Pairing: paired.", content.PairingText, "pairing");
                AssertEx.Equal("Source device: present.", content.SourceText, "source");
                AssertEx.Contains(content.TrustText, "trusts", "trust");
                AssertEx.Equal("Connections: 0.", content.ConnectionText, "connections");
                AssertEx.Contains(content.CheckedText, "Checked at", "checked text");
            });

            runner.Check("boundary: a confirmed running status is the only on claim", delegate
            {
                ScriptedBroker broker = new ScriptedBroker();
                broker.Running = true;
                broker.Connections = 3;
                broker.Ping = true;
                EngineBoundary boundary = NewBoundary(broker);
                Wait(boundary.ConnectAsync());
                EngineBoundaryContent content = boundary.Content;

                AssertEx.Equal(EngineBoundaryKind.On, content.Kind, "kind");
                AssertEx.Equal("Engine: tunnel on", content.Title, "title");
                AssertEx.Equal("On", content.StatusText, "status");
                AssertEx.True(content.IsRunning, "on claim");
                AssertEx.Equal("Connections: 3.", content.ConnectionText, "connections");
                AssertEx.Equal("Ping is on.", content.PingText, "ping");
                AssertEx.False(content.CanStart, "no start while on");
                AssertEx.True(content.CanStop, "stop is allowed");
                AssertEx.True(content.CanForget == false, "forget is refused while on");
            });

            runner.Check("boundary: a stale running status keeps a stale on claim", delegate
            {
                TestClock clock = new TestClock();
                ScriptedBroker broker = new ScriptedBroker();
                broker.Running = true;
                EngineBoundary boundary = new EngineBoundary(
                    broker,
                    clock,
                    TimeSpan.FromMilliseconds(500));
                Wait(boundary.ConnectAsync());
                AssertEx.True(boundary.Content.IsRunning, "fresh on claim");

                clock.Advance(4);
                boundary.RefreshView();
                EngineBoundaryContent stale = boundary.Content;
                AssertEx.Equal(EngineBoundaryKind.Attention, stale.Kind, "stale kind");
                AssertEx.Equal("On, stale", stale.StatusText, "stale status");
                AssertEx.True(stale.IsRunning, "last known on");
                AssertEx.True(stale.IsStatusStale, "stale flag");
                AssertEx.Contains(stale.Message, "out of date", "stale message");

                clock.Advance(7);
                boundary.RefreshView();
                EngineBoundaryContent unknown = boundary.Content;
                AssertEx.Equal(EngineBoundaryKind.Attention, unknown.Kind, "unknown kind");
                AssertEx.Equal("Unknown", unknown.StatusText, "unknown status");
                AssertEx.False(unknown.IsRunning, "no on claim after the window");
                AssertEx.True(unknown.IsStatusUnknown, "unknown flag");
                AssertEx.Contains(unknown.Message, "unknown", "unknown message");
            });

            runner.Check("boundary: an unpaired status cannot claim a source", delegate
            {
                ScriptedBroker broker = new ScriptedBroker();
                broker.Paired = false;
                broker.SourcePresent = false;
                broker.Trusted = false;
                EngineBoundary boundary = NewBoundary(broker);
                Wait(boundary.ConnectAsync());
                EngineBoundaryContent content = boundary.Content;

                AssertEx.Equal(EngineBoundaryKind.Ready, content.Kind, "kind");
                AssertEx.Equal("Pairing: not paired.", content.PairingText, "pairing");
                AssertEx.Equal("Source device: not paired.", content.SourceText, "source");
                AssertEx.Equal("", content.TrustText, "no trust claim");
                AssertEx.False(content.CanStart, "start needs a source");
                AssertEx.False(content.CanForget, "forget needs a pairing");
            });

            runner.Check("boundary: a pending stop is not an off claim", delegate
            {
                ScriptedBroker broker = new ScriptedBroker();
                broker.Running = true;
                EngineBoundary boundary = NewBoundary(broker);
                Wait(boundary.ConnectAsync());
                AssertEx.True(boundary.Content.IsRunning, "on before the stop");

                EngineCommandResult result = Wait(boundary.StopAsync());
                EngineBoundaryContent content = boundary.Content;
                AssertEx.True(result.Ok, "the stop request was accepted");
                AssertEx.False(result.Confirmed, "the request alone is not a confirmation");
                AssertEx.Equal(EngineBoundaryKind.Checking, content.Kind, "waiting kind");
                AssertEx.False(content.IsRunning, "no on claim while pending");
                AssertEx.False(content.StatusText == "Off", "no off claim while pending");
                AssertEx.True(content.IsBusy, "the stop is pending");

                broker.Running = false;
                broker.Stop = EngineStopReason.User;
                Wait(boundary.PollAsync());
                EngineBoundaryContent stopped = boundary.Content;
                AssertEx.Equal("Off", stopped.StatusText, "fresh status confirms off");
                AssertEx.Contains(stopped.StopText, "You turned the tunnel off", "stop text");
            });

            runner.Check("boundary: a start waits for the start budget and ends unknown", delegate
            {
                // The start budget must reach the broker unchanged. A single
                // short budget would abort a start the service is still
                // completing, and a timeout is never a clean refusal.
                BudgetedBroker broker = new BudgetedBroker();
                broker.HangStart = true;
                EngineServiceCallBudgets budgets = EngineServiceCallBudgets.Create(
                    TimeSpan.FromMilliseconds(100),
                    TimeSpan.FromMilliseconds(1200),
                    TimeSpan.FromMilliseconds(800));
                EngineBoundary boundary = new EngineBoundary(
                    broker,
                    new TestClock(),
                    budgets);
                EngineCommandResult connected = Wait(boundary.ConnectAsync());
                AssertEx.True(connected.Ok, "connected: " + connected.Code);

                Stopwatch watch = Stopwatch.StartNew();
                EngineCommandResult result = Wait(boundary.StartAsync(true));
                watch.Stop();

                AssertEx.False(result.Ok, "the start is not a success");
                AssertEx.True(result.OutcomeUnknown, "the start may already be applied");
                AssertEx.Equal(EngineProtocol.ErrorCodes.Timeout, result.Code, "code");
                AssertEx.True(
                    watch.ElapsedMilliseconds >= 900,
                    "the start waited for the start budget, not the short budget");
                AssertEx.True(broker.StartCanceled, "the broker was canceled at the start budget");
                AssertEx.True(boundary.Session.HasPendingAction, "the start is still pending");
                AssertEx.False(boundary.Content.IsRunning, "no on claim while pending");
                AssertEx.Equal(EngineBoundaryKind.Checking, boundary.Content.Kind, "waiting kind");
                AssertEx.Contains(
                    boundary.Content.Message,
                    "no confirmation",
                    "the message does not claim a clean refusal");

                broker.HangStart = false;
                EngineCommandResult refresh = Wait(boundary.PollAsync());
                AssertEx.True(refresh.Ok, "status read: " + refresh.Code);
                AssertEx.False(boundary.Session.HasPendingAction, "a status cleared the pending start");
                AssertEx.Equal("Off", boundary.Content.StatusText, "fresh off");
            });

            runner.Check("boundary: a broker unknown start is preserved through the boundary", delegate
            {
                BudgetedBroker broker = new BudgetedBroker();
                broker.StartUnknown = true;
                EngineBoundary boundary = NewBoundary(broker);
                Wait(boundary.ConnectAsync());

                EngineCommandResult result = Wait(boundary.StartAsync(false));

                AssertEx.False(result.Ok, "not a success");
                AssertEx.True(result.OutcomeUnknown, "the broker could not confirm the start");
                AssertEx.Equal(EngineProtocol.ErrorCodes.EngineUnavailable, result.Code, "code");
                AssertEx.True(boundary.Session.HasPendingAction, "the start stays pending");
                AssertEx.False(boundary.Content.IsRunning, "no on claim");
                AssertEx.Contains(boundary.Content.Message, "no confirmation", "honest message");

                EngineCommandResult refresh = Wait(boundary.PollAsync());
                AssertEx.True(refresh.Ok, "status read: " + refresh.Code);
                AssertEx.False(boundary.Session.HasPendingAction, "a status cleared the pending start");
                AssertEx.Equal("Off", boundary.Content.StatusText, "fresh off");

                // A validated timeout reply is also ambiguous. The service
                // uses it for a canceled start whose work may still have run.
                broker.StartUnknown = false;
                broker.StartTimeoutReply = true;
                EngineCommandResult timeoutReply = Wait(boundary.StartAsync(false));
                AssertEx.False(timeoutReply.Ok, "the timeout reply is not a success");
                AssertEx.True(
                    timeoutReply.OutcomeUnknown,
                    "a validated timeout reply is still ambiguous");
                AssertEx.True(boundary.Session.HasPendingAction, "the start stays pending");
            });

            runner.Check("boundary: a broker unknown stop is preserved and blocks an off claim", delegate
            {
                BudgetedBroker broker = new BudgetedBroker();
                broker.Running = true;
                broker.StopUnknown = true;
                EngineBoundary boundary = NewBoundary(broker);
                Wait(boundary.ConnectAsync());
                AssertEx.True(boundary.Content.IsRunning, "on before the stop");

                EngineCommandResult result = Wait(boundary.StopAsync());

                AssertEx.False(result.Ok, "not a success");
                AssertEx.True(result.OutcomeUnknown, "the stop may have run");
                AssertEx.Equal(EngineProtocol.ErrorCodes.Timeout, result.Code, "code");
                AssertEx.True(boundary.Session.HasPendingAction, "the stop is still pending");
                AssertEx.False(boundary.Content.IsRunning, "no on claim while pending");
                AssertEx.False(boundary.Content.StatusText == "Off", "no off claim while pending");

                broker.StopUnknown = false;
                broker.Running = false;
                broker.Stop = EngineStopReason.User;
                EngineCommandResult refresh = Wait(boundary.PollAsync());
                AssertEx.True(refresh.Ok, "status read: " + refresh.Code);
                AssertEx.Equal("Off", boundary.Content.StatusText, "fresh off");
            });

            runner.Check("boundary: the session keeps the reviewed per-operation budgets", delegate
            {
                EngineSession session = new EngineSession(
                    new UnavailableEngineBroker(),
                    new TestClock());
                AssertEx.Equal(
                    TimeSpan.FromSeconds(5),
                    session.Budgets.For(EngineProtocol.Operations.Hello),
                    "hello short budget");
                AssertEx.Equal(
                    TimeSpan.FromSeconds(35),
                    session.Budgets.For(EngineProtocol.Operations.Start),
                    "start budget");
                AssertEx.Equal(
                    TimeSpan.FromSeconds(25),
                    session.Budgets.For(EngineProtocol.Operations.Stop),
                    "stop budget");

                EngineSession uniform = new EngineSession(
                    new UnavailableEngineBroker(),
                    new TestClock(),
                    TimeSpan.FromMilliseconds(700));
                AssertEx.Equal(
                    TimeSpan.FromMilliseconds(700),
                    uniform.Budgets.For(EngineProtocol.Operations.Start),
                    "the uniform form is for diagnostics only");
            });

            runner.Check("boundary: an automatic stop reason is shown without a restart", delegate
            {
                ScriptedBroker broker = new ScriptedBroker();
                broker.Running = true;
                EngineBoundary boundary = NewBoundary(broker);
                Wait(boundary.ConnectAsync());
                AssertEx.True(boundary.Content.IsRunning, "on before the loss");

                broker.Running = false;
                broker.Stop = EngineStopReason.HotspotLost;
                Wait(boundary.PollAsync());
                EngineBoundaryContent content = boundary.Content;

                AssertEx.Equal("Off", content.StatusText, "fresh off");
                AssertEx.Contains(content.StopText, "hotspot link was lost", "reason");
                AssertEx.False(content.IsRunning, "no on claim");
                AssertEx.Equal(0, broker.StartCount, "the poll did not start a tunnel");
                AssertEx.Equal(0, broker.StopCount, "the poll did not send a stop");
            });

            runner.Check("boundary: an engine restart drops the on claim", delegate
            {
                ScriptedBroker broker = new ScriptedBroker();
                broker.Running = true;
                EngineBoundary boundary = NewBoundary(broker);
                Wait(boundary.ConnectAsync());
                AssertEx.True(boundary.Content.IsRunning, "on before the restart");

                broker.Instance = "engine-0002";
                EngineCommandResult result = Wait(boundary.PollAsync());
                EngineBoundaryContent content = boundary.Content;

                AssertEx.False(result.Ok, "the restart is refused");
                AssertEx.Equal(EngineProtocol.ErrorCodes.EngineRestarted, result.Code, "code");
                AssertEx.Equal(EngineBoundaryKind.Unavailable, content.Kind, "kind");
                AssertEx.Equal("Unavailable", content.StatusText, "status");
                AssertEx.False(content.IsRunning, "no on claim after a restart");
                AssertEx.False(content.IsEngineAvailable, "not available");
            });

            runner.Check("boundary: the view text carries no credential or address", delegate
            {
                ScriptedBroker broker = new ScriptedBroker();
                broker.Running = true;
                broker.Connections = 2;
                EngineBoundary boundary = NewBoundary(broker);
                Wait(boundary.ConnectAsync());
                string text = boundary.Content.AccessibilityText;

                AssertEx.NotEmpty(text, "accessibility text");
                AssertEx.DoesNotContain(text, "token", "no token");
                AssertEx.DoesNotContain(text, "secret", "no secret");
                AssertEx.DoesNotContain(text, "key", "no key");
                AssertEx.DoesNotContain(text, "127.0.0.1", "no address");
                AssertEx.Contains(text, "Engine: tunnel on", "the status is present");
            });

            runner.Check("poll: the retry policy is slower when no engine answers", delegate
            {
                AssertEx.Equal(
                    EngineTiming.VisiblePoll,
                    EnginePollPolicy.NextDelay(EngineConnectionState.Available, true),
                    "available visible");
                AssertEx.Equal(
                    EngineTiming.HiddenPoll,
                    EnginePollPolicy.NextDelay(EngineConnectionState.Available, false),
                    "available hidden");
                AssertEx.Equal(
                    EngineTiming.VisiblePoll,
                    EnginePollPolicy.NextDelay(EngineConnectionState.Connecting, true),
                    "connecting visible");
                AssertEx.Equal(
                    EngineTiming.VisibleRetry,
                    EnginePollPolicy.NextDelay(EngineConnectionState.Unavailable, true),
                    "unavailable visible");
                AssertEx.Equal(
                    EngineTiming.HiddenRetry,
                    EnginePollPolicy.NextDelay(EngineConnectionState.Unavailable, false),
                    "unavailable hidden");
                AssertEx.False(
                    EnginePollPolicy.ShouldPoll(EngineConnectionState.Closed, true),
                    "closed never polls");
                AssertEx.True(
                    EnginePollPolicy.ShouldPoll(EngineConnectionState.Available, false),
                    "available polls");
            });

            runner.Check("status: an unpaired source or trust is a bad response", delegate
            {
                EngineStatus status;
                string code;
                AssertEx.False(
                    EngineStatus.TryParse(
                        StatusReply("engine-0001", true, false, true, false, 0, EngineStopReason.None),
                        DateTimeOffset.UtcNow,
                        out status,
                        out code),
                    "unpaired source is refused");
                AssertEx.Equal(EngineProtocol.ErrorCodes.BadResponse, code, "source code");
                AssertEx.False(
                    EngineStatus.TryParse(
                        StatusReply("engine-0001", false, false, false, true, 0, EngineStopReason.None),
                        DateTimeOffset.UtcNow,
                        out status,
                        out code),
                    "unpaired trust is refused");
                AssertEx.Equal(EngineProtocol.ErrorCodes.BadResponse, code, "trust code");
            });

            runner.Check("status: an off status cannot report connections", delegate
            {
                EngineStatus status;
                string code;
                AssertEx.False(
                    EngineStatus.TryParse(
                        StatusReply("engine-0001", false, true, true, true, 1, EngineStopReason.None),
                        DateTimeOffset.UtcNow,
                        out status,
                        out code),
                    "an off count is refused");
                AssertEx.Equal(EngineProtocol.ErrorCodes.BadResponse, code, "code");
                AssertEx.False(
                    EngineStatus.TryParse(
                        StatusReply("engine-0001", true, true, true, true, 2, EngineStopReason.User),
                        DateTimeOffset.UtcNow,
                        out status,
                        out code),
                    "an on status with a stop reason is refused");
                AssertEx.Equal(EngineProtocol.ErrorCodes.BadResponse, code, "running stop code");
            });
        }

        private static EngineBoundary NewBoundary(IEngineBroker broker)
        {
            return new EngineBoundary(
                broker,
                new TestClock(),
                TimeSpan.FromMilliseconds(500));
        }

        private static EngineReply StatusReply(
            string instance,
            bool running,
            bool paired,
            bool source,
            bool trusted,
            int connections,
            EngineStopReason stop)
        {
            Dictionary<string, string> fields = new Dictionary<string, string>(StringComparer.Ordinal);
            fields[EngineProtocol.Keys.Instance] = instance;
            fields[EngineProtocol.Keys.Engine] = running
                ? EngineProtocol.EngineStates.Running
                : EngineProtocol.EngineStates.Ready;
            fields[EngineProtocol.Keys.Paired] = paired ? "1" : "0";
            fields[EngineProtocol.Keys.Running] = running ? "1" : "0";
            fields[EngineProtocol.Keys.Source] = source ? "1" : "0";
            fields[EngineProtocol.Keys.Trusted] = trusted ? "1" : "0";
            fields[EngineProtocol.Keys.Ping] = running ? "1" : "0";
            fields[EngineProtocol.Keys.Connections] = connections.ToString(CultureInfo.InvariantCulture);
            fields[EngineProtocol.Keys.Stop] = EngineRules.StopWord(stop);
            return EngineReply.Success(fields);
        }

        private static T Wait<T>(Task<T> task)
        {
            return task.GetAwaiter().GetResult();
        }

        private sealed class TestClock : IEngineClock
        {
            public TestClock()
            {
                Now = new DateTimeOffset(2026, 11, 5, 9, 0, 0, TimeSpan.Zero);
            }

            public DateTimeOffset Now { get; set; }

            public void Advance(double seconds)
            {
                Now = Now.AddSeconds(seconds);
            }
        }

        // One broker that answers hello and status at once and can hold a
        // start or a stop until the session cancels it. It also models a broker
        // that returns the ambiguous outcome directly.
        private sealed class BudgetedBroker : IEngineBroker
        {
            public string Instance = "engine-0001";
            public bool Paired = true;
            public bool SourcePresent = true;
            public bool Trusted = true;
            public bool Running;
            public EngineStopReason Stop = EngineStopReason.None;
            public bool HangStart;
            public bool StartUnknown;
            public bool StartTimeoutReply;
            public bool StopUnknown;
            public int StartCount;
            public int StopCount;
            public volatile bool StartCanceled;

            public Task<EngineReply> SendAsync(
                EngineRequest request,
                CancellationToken cancellationToken)
            {
                switch (request.Operation)
                {
                    case EngineProtocol.Operations.Hello:
                        return Task.FromResult(EngineReply.Success(
                            new Dictionary<string, string>
                            {
                                { EngineProtocol.Keys.Instance, Instance },
                                { EngineProtocol.Keys.Engine, Running
                                    ? EngineProtocol.EngineStates.Running
                                    : EngineProtocol.EngineStates.Ready }
                            }));
                    case EngineProtocol.Operations.Status:
                        return Task.FromResult(StatusReply(
                            Instance,
                            Running,
                            Paired,
                            SourcePresent,
                            Trusted,
                            Running ? 1 : 0,
                            Stop));
                    case EngineProtocol.Operations.Start:
                        if (StartUnknown)
                        {
                            return Task.FromResult(EngineReply.UnknownOutcome(
                                EngineProtocol.ErrorCodes.EngineUnavailable));
                        }
                        if (StartTimeoutReply)
                        {
                            return Task.FromResult(EngineReply.Failure(
                                EngineProtocol.ErrorCodes.Timeout));
                        }
                        if (HangStart)
                        {
                            TaskCompletionSource<EngineReply> completion =
                                new TaskCompletionSource<EngineReply>(
                                    TaskCreationOptions.RunContinuationsAsynchronously);
                            cancellationToken.Register(delegate
                            {
                                StartCanceled = true;
                                completion.TrySetResult(EngineReply.Failure(
                                    EngineProtocol.ErrorCodes.Timeout));
                            });
                            return completion.Task;
                        }
                        StartCount++;
                        return Task.FromResult(EngineReply.Success(null));
                    case EngineProtocol.Operations.Stop:
                        if (StopUnknown)
                        {
                            return Task.FromResult(EngineReply.UnknownOutcome(
                                EngineProtocol.ErrorCodes.Timeout));
                        }
                        StopCount++;
                        Running = false;
                        Stop = EngineStopReason.User;
                        return Task.FromResult(EngineReply.Success(null));
                    case EngineProtocol.Operations.Forget:
                        Paired = false;
                        SourcePresent = false;
                        Trusted = false;
                        return Task.FromResult(EngineReply.Success(null));
                    case EngineProtocol.Operations.Shutdown:
                        return Task.FromResult(EngineReply.Success(null));
                    default:
                        return Task.FromResult(EngineReply.Failure(
                            EngineProtocol.ErrorCodes.Unsupported));
                }
            }

            public Task CloseAsync()
            {
                return Task.CompletedTask;
            }
        }

        // One scripted broker. It records each operation and returns a reply
        // that the same validation path accepts. It never opens a connection.
        private sealed class ScriptedBroker : IEngineBroker
        {
            public string Instance = "engine-0001";
            public bool Paired = true;
            public bool SourcePresent = true;
            public bool Trusted = true;
            public bool Running;
            public bool Ping;
            public int Connections;
            public EngineStopReason Stop = EngineStopReason.None;
            public string FailureCode = "";
            public int StartCount;
            public int StopCount;

            public Task<EngineReply> SendAsync(EngineRequest request, CancellationToken cancellationToken)
            {
                if (!string.IsNullOrEmpty(FailureCode))
                {
                    return Task.FromResult(EngineReply.Failure(FailureCode));
                }
                switch (request.Operation)
                {
                    case EngineProtocol.Operations.Hello:
                        return Task.FromResult(EngineReply.Success(new Dictionary<string, string>
                        {
                            { EngineProtocol.Keys.Instance, Instance },
                            { EngineProtocol.Keys.Engine, Running
                                ? EngineProtocol.EngineStates.Running
                                : EngineProtocol.EngineStates.Ready }
                        }));
                    case EngineProtocol.Operations.Status:
                        return Task.FromResult(StatusReply(
                            Instance,
                            Running,
                            Paired,
                            SourcePresent,
                            Trusted,
                            Running ? Connections : 0,
                            Stop));
                    case EngineProtocol.Operations.Start:
                        StartCount++;
                        return Task.FromResult(EngineReply.Success(null));
                    case EngineProtocol.Operations.Stop:
                        StopCount++;
                        return Task.FromResult(EngineReply.Success(null));
                    case EngineProtocol.Operations.Forget:
                        Paired = false;
                        SourcePresent = false;
                        Trusted = false;
                        return Task.FromResult(EngineReply.Success(null));
                    case EngineProtocol.Operations.Shutdown:
                        return Task.FromResult(EngineReply.Success(null));
                    default:
                        return Task.FromResult(EngineReply.Failure(
                            EngineProtocol.ErrorCodes.Unsupported));
                }
            }

            public Task CloseAsync()
            {
                return Task.CompletedTask;
            }
        }
    }
}
