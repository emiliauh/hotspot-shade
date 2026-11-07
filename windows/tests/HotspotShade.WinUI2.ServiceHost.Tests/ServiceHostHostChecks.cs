using System;
using System.Threading;
using System.Threading.Tasks;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.ServiceHost.Tests
{
    internal static class ServiceHostHostChecks
    {
        public static void Run(ServiceHostCheckRunner runner)
        {
            runner.Check("host: a clean start reports pending, running, stopping, and stopped once", delegate
            {
                HostFixture fixture = NewFixture();
                // Keep the listener alive until Running is reported, so this
                // check still exercises a live generation. A listener that
                // has already finished must not produce Running.
                fixture.Control.Observer = delegate(EngineServiceHostState state)
                {
                    if (state == EngineServiceHostState.Running)
                    {
                        fixture.Listener.Complete(EngineServiceListenerResult.Success(
                            EngineServiceCleanup.Ok,
                            EngineServiceStopReason.ParentLost,
                            0));
                    }
                };
                EngineServiceHostResult result = ServiceHostAssert.Wait(
                    fixture.Host.RunAsync(CancellationToken.None),
                    5000,
                    "host");

                ServiceHostAssert.True(result.Ok, "host ok: " + result.Code);
                ServiceHostAssert.Equal(EngineServiceHostState.Stopped, result.FinalState, "stopped");
                ServiceHostAssert.False(result.AutoRestarted, "no restart");
                ServiceHostAssert.Equal(1, fixture.Control.Count(EngineServiceHostState.StartPending), "start pending");
                ServiceHostAssert.Equal(1, fixture.Control.Count(EngineServiceHostState.Running), "running");
                ServiceHostAssert.Equal(1, fixture.Control.Count(EngineServiceHostState.StopPending), "stop pending");
                ServiceHostAssert.Equal(1, fixture.Control.Count(EngineServiceHostState.Stopped), "stopped");
                ServiceHostAssert.Equal(1, fixture.ListenerFactory.Calls, "one listener");
                ServiceHostAssert.True(fixture.Listener.DisposeCalled, "listener disposed");
                ServiceHostAssert.Equal(1, fixture.Inspector.Calls, "installed account checked");
            });

            runner.Check("host: a configured group account is refused before a listener exists", delegate
            {
                HostFixture fixture = NewFixture();
                fixture.Inspector.Type = EngineServiceAccountType.Group;
                EngineServiceHostResult result = ServiceHostAssert.Wait(
                    fixture.Host.RunAsync(CancellationToken.None),
                    5000,
                    "host");

                ServiceHostAssert.False(result.Ok, "group denied");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.BoundaryAuthFailed, result.Code, "code");
                ServiceHostAssert.Equal(0, fixture.ListenerFactory.Calls, "no listener");
                ServiceHostAssert.Equal(0, fixture.Control.Count(EngineServiceHostState.Running), "never running");
                ServiceHostAssert.True(
                    fixture.Events.Contains(EngineServiceEventCodes.CallerAccountTypeNotUser),
                    "event");
            });

            runner.Check("host: an inconclusive installed account lookup is refused before a listener exists", delegate
            {
                HostFixture fixture = NewFixture();
                fixture.Inspector.Fail = true;
                EngineServiceHostResult result = ServiceHostAssert.Wait(
                    fixture.Host.RunAsync(CancellationToken.None),
                    5000,
                    "host");
                ServiceHostAssert.False(result.Ok, "lookup failure denied");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.BoundaryAuthFailed, result.Code, "code");
                ServiceHostAssert.Equal(0, fixture.ListenerFactory.Calls, "no listener");
            });

            runner.Check("host: cancellation during account lookup stops before a listener exists", delegate
            {
                HostFixture fixture = NewFixture();
                fixture.Inspector.WaitForCancellation = true;
                using (CancellationTokenSource stop = new CancellationTokenSource())
                {
                    Task<EngineServiceHostResult> pending = fixture.Host.RunAsync(stop.Token);
                    ServiceHostAssert.Equal(1, fixture.Inspector.Calls, "account lookup started");
                    stop.Cancel();
                    EngineServiceHostResult result = ServiceHostAssert.Wait(pending, 5000, "host cancellation");
                    ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Closed, result.Code, "closed by stop");
                    ServiceHostAssert.Equal(0, fixture.ListenerFactory.Calls, "no listener");
                    ServiceHostAssert.Equal(0, fixture.Control.Count(EngineServiceHostState.Running), "never running");
                }
            });

            runner.Check("host: a missing durable record stops before a listener exists", delegate
            {
                HostFixture fixture = NewFixture();
                fixture.Store.Ok = false;
                EngineServiceHostResult result = ServiceHostAssert.Wait(
                    fixture.Host.RunAsync(CancellationToken.None),
                    5000,
                    "host");
                ServiceHostAssert.False(result.Ok, "missing record");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.CleanupUnknown, result.Code, "code");
                ServiceHostAssert.Equal(0, fixture.ListenerFactory.Calls, "no listener");
                ServiceHostAssert.Equal(0, fixture.Control.Count(EngineServiceHostState.Running), "never running");
            });

            runner.Check("host: a listener creation failure stops before Running", delegate
            {
                HostFixture fixture = NewFixture();
                fixture.ListenerFactory.CreateOk = false;
                EngineServiceHostResult result = ServiceHostAssert.Wait(
                    fixture.Host.RunAsync(CancellationToken.None),
                    5000,
                    "host");
                ServiceHostAssert.False(result.Ok, "listener failure");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.EngineUnavailable, result.Code, "code");
                ServiceHostAssert.Equal(0, fixture.Control.Count(EngineServiceHostState.Running), "never running");
                ServiceHostAssert.Equal(1, fixture.Control.Count(EngineServiceHostState.Stopped), "stopped");
            });

            runner.Check("host: Running waits for listener readiness", delegate
            {
                HostFixture fixture = NewFixture();
                fixture.Listener.AutoReady = false;
                bool runningBeforeReady = false;
                fixture.Control.Observer = delegate(EngineServiceHostState state)
                {
                    if (state == EngineServiceHostState.Running)
                    {
                        if (!fixture.Listener.IsReady)
                        {
                            runningBeforeReady = true;
                        }
                        fixture.Listener.Complete(EngineServiceListenerResult.Success(
                            EngineServiceCleanup.Ok,
                            EngineServiceStopReason.ParentLost,
                            0));
                    }
                };

                Task<EngineServiceHostResult> run = fixture.Host.RunAsync(CancellationToken.None);
                ServiceHostAssert.Equal(1, fixture.Listener.RunCalls, "listener started");
                ServiceHostAssert.Equal(
                    0,
                    fixture.Control.Count(EngineServiceHostState.Running),
                    "no Running before readiness");
                ServiceHostAssert.False(run.IsCompleted, "host waits for readiness");

                fixture.Listener.MarkReady();
                EngineServiceHostResult result = ServiceHostAssert.Wait(run, 5000, "host");

                ServiceHostAssert.True(result.Ok, "host ok: " + result.Code);
                ServiceHostAssert.Equal(1, fixture.Control.Count(EngineServiceHostState.Running), "one Running");
                ServiceHostAssert.False(runningBeforeReady, "Running observed only after readiness");
            });

            runner.Check("host: a listener that ends before readiness never reports Running", delegate
            {
                HostFixture fixture = NewFixture();
                fixture.Listener.AutoReady = false;
                fixture.Listener.Complete(EngineServiceListenerResult.Failure(
                    EngineProtocol.ErrorCodes.EngineUnavailable,
                    EngineServiceCleanup.Unknown,
                    EngineServiceStopReason.None));
                EngineServiceHostResult result = ServiceHostAssert.Wait(
                    fixture.Host.RunAsync(CancellationToken.None),
                    5000,
                    "host");

                ServiceHostAssert.False(result.Ok, "listener failed before ready");
                ServiceHostAssert.Equal(
                    EngineProtocol.ErrorCodes.EngineUnavailable,
                    result.Code,
                    "code");
                ServiceHostAssert.Equal(0, fixture.Control.Count(EngineServiceHostState.Running), "never Running");
                ServiceHostAssert.Equal(0, fixture.Control.Count(EngineServiceHostState.StopPending), "no stop claim");
                ServiceHostAssert.Equal(1, fixture.Control.Count(EngineServiceHostState.Stopped), "stopped once");
                ServiceHostAssert.True(
                    fixture.Events.Contains(EngineServiceEventCodes.ListenerNotReady),
                    "not-ready event");
            });

            runner.Check("host: a listener that finishes after readiness never reports Running", delegate
            {
                HostFixture fixture = NewFixture();
                fixture.Listener.AutoReady = false;
                fixture.Listener.Complete(EngineServiceListenerResult.Success(
                    EngineServiceCleanup.Ok,
                    EngineServiceStopReason.ParentLost,
                    0));
                fixture.Listener.MarkReady();
                EngineServiceHostResult result = ServiceHostAssert.Wait(
                    fixture.Host.RunAsync(CancellationToken.None),
                    5000,
                    "host");

                ServiceHostAssert.True(result.Ok, "finished listener result: " + result.Code);
                ServiceHostAssert.Equal(
                    0,
                    fixture.Control.Count(EngineServiceHostState.Running),
                    "never Running after finish");
                ServiceHostAssert.Equal(
                    1,
                    fixture.Control.Count(EngineServiceHostState.Stopped),
                    "stopped once");
                ServiceHostAssert.Equal(
                    0,
                    fixture.Control.Count(EngineServiceHostState.StopPending),
                    "no stop claim for a finished listener");
            });

            runner.Check("host: a success result without readiness fails closed", delegate
            {
                HostFixture fixture = NewFixture();
                fixture.Listener.AutoReady = false;
                fixture.Listener.Complete(EngineServiceListenerResult.Success(
                    EngineServiceCleanup.Ok,
                    EngineServiceStopReason.ParentLost,
                    0));
                EngineServiceHostResult result = ServiceHostAssert.Wait(
                    fixture.Host.RunAsync(CancellationToken.None),
                    5000,
                    "host");

                ServiceHostAssert.False(result.Ok, "unready success refused");
                ServiceHostAssert.Equal(
                    EngineProtocol.ErrorCodes.EngineUnavailable,
                    result.Code,
                    "code");
                ServiceHostAssert.Equal(0, fixture.Control.Count(EngineServiceHostState.Running), "never Running");
                ServiceHostAssert.True(
                    fixture.Events.Contains(EngineServiceEventCodes.ListenerNotReady),
                    "not-ready event");
            });

            runner.Check("host: a readiness timeout never reports Running and stops", delegate
            {
                HostFixture fixture = NewFixture();
                fixture.Listener.AutoReady = false;
                fixture.Options.StartBudget = TimeSpan.FromMilliseconds(100);
                fixture.Options.CheckpointInterval = TimeSpan.FromMilliseconds(25);
                fixture.Options.StopBudget = TimeSpan.FromMilliseconds(150);
                fixture.Options.StopWaitHint = TimeSpan.FromMilliseconds(25);
                EngineServiceHostResult result = ServiceHostAssert.Wait(
                    fixture.Host.RunAsync(CancellationToken.None),
                    5000,
                    "host");

                ServiceHostAssert.False(result.Ok, "readiness timeout");
                ServiceHostAssert.Equal(
                    EngineProtocol.ErrorCodes.EngineStopTimeout,
                    result.Code,
                    "stop timeout");
                ServiceHostAssert.Equal(
                    EngineServiceHostState.StopPending,
                    result.FinalState,
                    "stop pending");
                ServiceHostAssert.Equal(0, fixture.Control.Count(EngineServiceHostState.Running), "never Running");
                ServiceHostAssert.True(
                    fixture.Events.Contains(EngineServiceEventCodes.StopTimeout),
                    "stop timeout event");
            });

            runner.Check("host: a readiness proof at the final budget check is accepted", delegate
            {
                ServiceHostFakeMonotonicClock clock = new ServiceHostFakeMonotonicClock();
                clock.Now = 0;
                clock.TickFrequency = 1000;
                HostFixture fixture = NewFixture(clock);
                fixture.Listener.AutoReady = false;
                fixture.Options.StartBudget = TimeSpan.FromMilliseconds(100);
                fixture.Options.CheckpointInterval = TimeSpan.FromMilliseconds(25);
                bool proofAtBoundary = false;
                clock.OnRead = delegate
                {
                    // The first read creates the deadline. The next read is
                    // the budget check. Complete readiness and move the
                    // monotonic clock past the deadline in the same instant.
                    if (clock.Reads >= 2)
                    {
                        clock.Now = 150;
                        fixture.Listener.MarkReady();
                        proofAtBoundary = true;
                    }
                };
                fixture.Control.Observer = delegate(EngineServiceHostState state)
                {
                    if (state == EngineServiceHostState.Running)
                    {
                        fixture.Listener.Complete(EngineServiceListenerResult.Success(
                            EngineServiceCleanup.Ok,
                            EngineServiceStopReason.ParentLost,
                            0));
                    }
                };

                EngineServiceHostResult result = ServiceHostAssert.Wait(
                    fixture.Host.RunAsync(CancellationToken.None),
                    5000,
                    "host");

                ServiceHostAssert.True(result.Ok, "host ok: " + result.Code);
                ServiceHostAssert.True(proofAtBoundary, "readiness landed at the budget check");
                ServiceHostAssert.Equal(
                    1,
                    fixture.Control.Count(EngineServiceHostState.Running),
                    "Running after the final readiness check");
            });

            runner.Check("host: a fatal listener result disables the host and refuses a later run", delegate
            {
                HostFixture fixture = NewFixture();
                fixture.Listener.Complete(EngineServiceListenerResult.FatalFailure(
                    EngineProtocol.ErrorCodes.EngineUnavailable));
                EngineServiceHostResult first = ServiceHostAssert.Wait(
                    fixture.Host.RunAsync(CancellationToken.None),
                    5000,
                    "first");
                EngineServiceHostResult second = ServiceHostAssert.Wait(
                    fixture.Host.RunAsync(CancellationToken.None),
                    5000,
                    "second");

                ServiceHostAssert.False(first.Ok, "fatal failure");
                ServiceHostAssert.True(first.Disabled, "first disabled");
                ServiceHostAssert.Equal(
                    EngineProtocol.ErrorCodes.BoundaryAuthFailed,
                    first.Code,
                    "disabled code");
                ServiceHostAssert.False(second.Ok, "second refused");
                ServiceHostAssert.True(second.Disabled, "second disabled");
                ServiceHostAssert.Equal(1, fixture.ListenerFactory.Calls, "no later listener");
            });

            runner.Check("host: a stop timeout keeps StopPending, does not report Stopped, and leaves the run alive", delegate
            {
                HostFixture fixture = NewFixture();
                fixture.Options.StopBudget = TimeSpan.FromMilliseconds(200);
                fixture.Options.CheckpointInterval = TimeSpan.FromMilliseconds(50);
                fixture.Options.StopWaitHint = TimeSpan.FromMilliseconds(50);
                CancellationTokenSource cancellation = new CancellationTokenSource();
                Task<EngineServiceHostResult> run = fixture.Host.RunAsync(cancellation.Token);
                cancellation.CancelAfter(50);
                EngineServiceHostResult result = ServiceHostAssert.Wait(run, 5000, "host");

                ServiceHostAssert.False(result.Ok, "timeout");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.EngineStopTimeout, result.Code, "code");
                ServiceHostAssert.Equal(EngineServiceHostState.StopPending, result.FinalState, "pending");
                ServiceHostAssert.Equal(0, fixture.Control.Count(EngineServiceHostState.Stopped), "no stopped claim");
                ServiceHostAssert.False(fixture.Listener.DisposeCalled, "run not disposed while active");
                ServiceHostAssert.True(
                    fixture.Events.Contains(EngineServiceEventCodes.StopTimeout),
                    "timeout event");
                cancellation.Dispose();
            });

            runner.Check("host: a stop completion at the final budget check is accepted", delegate
            {
                ServiceHostFakeMonotonicClock clock = new ServiceHostFakeMonotonicClock();
                clock.Now = 0;
                clock.TickFrequency = 1000;
                HostFixture fixture = NewFixture(clock);
                fixture.Options.StopBudget = TimeSpan.FromMilliseconds(100);
                fixture.Options.CheckpointInterval = TimeSpan.FromMilliseconds(25);
                CancellationTokenSource cancellation = new CancellationTokenSource();
                clock.OnRead = delegate
                {
                    // The first read creates the readiness deadline. The
                    // second creates the stop deadline. The third is the stop
                    // budget check, where the listener finishes.
                    if (clock.Reads >= 3)
                    {
                        clock.Now = 150;
                        fixture.Listener.Complete(EngineServiceListenerResult.Success(
                            EngineServiceCleanup.Ok,
                            EngineServiceStopReason.ServiceStop,
                            0));
                    }
                };
                fixture.Control.Observer = delegate(EngineServiceHostState state)
                {
                    if (state == EngineServiceHostState.Running)
                    {
                        cancellation.Cancel();
                    }
                };

                EngineServiceHostResult result = ServiceHostAssert.Wait(
                    fixture.Host.RunAsync(cancellation.Token),
                    5000,
                    "host");

                ServiceHostAssert.True(result.Ok, "host ok: " + result.Code);
                ServiceHostAssert.Equal(EngineServiceHostState.Stopped, result.FinalState, "stopped");
                ServiceHostAssert.Equal(1, fixture.Control.Count(EngineServiceHostState.StopPending), "one stop claim");
                ServiceHostAssert.Equal(1, fixture.Control.Count(EngineServiceHostState.Stopped), "stopped once");
                ServiceHostAssert.False(
                    fixture.Events.Contains(EngineServiceEventCodes.StopTimeout),
                    "the final completion is not a stop timeout");
                cancellation.Dispose();
            });

            runner.Check("host: a listener cleanup failure is a failed stop", delegate
            {
                HostFixture fixture = NewFixture();
                fixture.Listener.Complete(EngineServiceListenerResult.Failure(
                    EngineProtocol.ErrorCodes.CleanupBlocked,
                    EngineServiceCleanup.Failed,
                    EngineServiceStopReason.ParentLost));
                EngineServiceHostResult result = ServiceHostAssert.Wait(
                    fixture.Host.RunAsync(CancellationToken.None),
                    5000,
                    "host");
                ServiceHostAssert.False(result.Ok, "cleanup failure");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.CleanupBlocked, result.Code, "code");
                ServiceHostAssert.Equal(EngineServiceHostState.Stopped, result.FinalState, "stopped");
            });

            runner.Check("host: a second run is refused and the first generation never restarts", delegate
            {
                HostFixture fixture = NewFixture();
                fixture.Listener.Complete(EngineServiceListenerResult.Success(
                    EngineServiceCleanup.Ok,
                    EngineServiceStopReason.ParentLost,
                    0));
                EngineServiceHostResult first = ServiceHostAssert.Wait(
                    fixture.Host.RunAsync(CancellationToken.None),
                    5000,
                    "first");
                EngineServiceHostResult second = ServiceHostAssert.Wait(
                    fixture.Host.RunAsync(CancellationToken.None),
                    5000,
                    "second");
                ServiceHostAssert.True(first.Ok, "first ok");
                ServiceHostAssert.False(second.Ok, "second refused");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Busy, second.Code, "busy");
                ServiceHostAssert.Equal(1, fixture.ListenerFactory.Calls, "one listener");
            });

            runner.Check("host: a canceled start reports nothing and creates no listener", delegate
            {
                HostFixture fixture = NewFixture();
                using (CancellationTokenSource canceled = new CancellationTokenSource())
                {
                    canceled.Cancel();
                    EngineServiceHostResult result = ServiceHostAssert.Wait(
                        fixture.Host.RunAsync(canceled.Token),
                        5000,
                        "host");
                    ServiceHostAssert.False(result.Ok, "canceled");
                    ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Closed, result.Code, "closed");
                    ServiceHostAssert.Equal(0, fixture.Control.Reports.Count, "no reports");
                    ServiceHostAssert.Equal(0, fixture.ListenerFactory.Calls, "no listener");
                }
            });
        }

        private sealed class HostFixture
        {
            public ServiceHostFakeEvents Events;
            public ServiceHostFakeHostControl Control;
            public ServiceHostFakeStatusSource Status;
            public ServiceHostFakeStateStore Store;
            public ServiceHostFakeProcessProof ProcessProof;
            public ServiceHostFakeAccountInspector Inspector;
            public ServiceHostFakeListener Listener;
            public ServiceHostFakeListenerFactory ListenerFactory;
            public EngineServiceHostOptions Options;
            public EngineServiceHost Host;
        }

        private static HostFixture NewFixture()
        {
            return NewFixture(null);
        }

        private static HostFixture NewFixture(IEngineServiceHostMonotonicClock clock)
        {
            DateTimeOffset now = ServiceHostTestData.Now();
            HostFixture fixture = new HostFixture();
            fixture.Events = new ServiceHostFakeEvents();
            fixture.Control = new ServiceHostFakeHostControl();
            fixture.Status = new ServiceHostFakeStatusSource();
            fixture.Status.Status = ServiceHostTestData.ReadyStatus(now);
            fixture.Status.ReadAt = now;
            fixture.Store = new ServiceHostFakeStateStore();
            fixture.Store.Gate = EngineServiceStateGate.FromRecord(
                ServiceHostTestData.CleanRecord(now));
            fixture.ProcessProof = new ServiceHostFakeProcessProof();
            fixture.Inspector = new ServiceHostFakeAccountInspector();
            fixture.Listener = new ServiceHostFakeListener();
            fixture.ListenerFactory = new ServiceHostFakeListenerFactory();
            fixture.ListenerFactory.Listener = fixture.Listener;
            fixture.Options = new EngineServiceHostOptions();
            fixture.Options.StartWaitHint = TimeSpan.FromMilliseconds(50);
            fixture.Options.StartBudget = TimeSpan.FromMilliseconds(500);
            fixture.Options.StopWaitHint = TimeSpan.FromMilliseconds(50);
            fixture.Options.StopBudget = TimeSpan.FromMilliseconds(500);
            fixture.Options.CheckpointInterval = TimeSpan.FromMilliseconds(50);

            EngineServiceInstalledAccountGate installed = new EngineServiceInstalledAccountGate(
                ServiceHostTestData.UserSid,
                fixture.Inspector,
                TimeSpan.FromSeconds(1));
            EngineServiceDurableStateGate state = new EngineServiceDurableStateGate(
                fixture.Store,
                fixture.Events,
                ServiceHostTestData.EngineImage,
                fixture.ProcessProof);
            if (clock == null)
            {
                fixture.Host = new EngineServiceHost(
                    fixture.Options,
                    installed,
                    state,
                    fixture.ListenerFactory,
                    fixture.Control,
                    fixture.Events);
            }
            else
            {
                fixture.Host = new EngineServiceHost(
                    fixture.Options,
                    installed,
                    state,
                    fixture.ListenerFactory,
                    fixture.Control,
                    fixture.Events,
                    clock);
            }
            return fixture;
        }
    }
}
