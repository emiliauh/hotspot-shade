using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.ServiceHost.Tests
{
    // Hermetic checks for the bounded idle policy and the one-stop claim. They
    // use a fake pipe, a fake backend, and a fake monotonic clock. They open no
    // pipe, call no Win32 function, and create no service, process, route, or
    // device.
    internal static class ServiceHostIdlePolicyChecks
    {
        public static void Run(ServiceHostCheckRunner runner)
        {
            runner.Check("idle policy: boundary and frame defaults stay separate", delegate
            {
                EngineServiceTransportOptions options = ServiceHostTestData.TransportOptions();
                ServiceHostAssert.Equal(TimeSpan.FromSeconds(60), options.IdleTimeout, "idle timeout");
                ServiceHostAssert.Equal(TimeSpan.FromSeconds(5), options.RequestTimeout, "frame/write timeout");
                ServiceHostAssert.Equal(TimeSpan.FromSeconds(5), options.HandshakeTimeout, "handshake timeout");
                ServiceHostAssert.False(EngineServiceTransportLimits.StartTimeoutEnforced, "start budget reserved");
            });

            runner.Check("idle guard: reads share the deadline and only a completed request resets it", delegate
            {
                ServiceHostFakeMonotonicClock clock = new ServiceHostFakeMonotonicClock();
                clock.TickFrequency = 1000;
                EngineServiceIdleGuard guard = new EngineServiceIdleGuard(clock, TimeSpan.FromSeconds(30));
                ServiceHostAssert.Equal(TimeSpan.Zero,
                    guard.CreateReadDeadline(TimeSpan.FromSeconds(5)).Remaining, "no credit before hello completes");
                guard.MarkRequestCompleted();
                clock.Now = 29000;
                ServiceHostAssert.Equal(TimeSpan.FromSeconds(1),
                    guard.CreateReadDeadline(TimeSpan.FromSeconds(5)).Remaining, "remaining idle budget");
                clock.Now = 30000;
                ServiceHostAssert.True(guard.CreateReadDeadline(TimeSpan.FromSeconds(5)).TryExpire(), "absolute expiry");
                guard.MarkRequestCompleted();
                clock.Now = 59999;
                ServiceHostAssert.False(guard.CreateReadDeadline(TimeSpan.FromSeconds(5)).TryExpire(), "before reset horizon");
                clock.Now = 60000;
                ServiceHostAssert.True(guard.CreateReadDeadline(TimeSpan.FromSeconds(5)).TryExpire(), "reset horizon");
            });

            runner.Check("listener: boundary expiry closes once without retry or a zero-byte claim", delegate
            {
                ServiceHostFakePipe pipe = NewPipe();
                pipe.Inbound.Enqueue(ServiceHostTestData.Encode(ServiceHostTestData.HelloFields()));
                ServiceHostFakeMonotonicClock clock = new ServiceHostFakeMonotonicClock();
                clock.TickFrequency = 1000;
                pipe.OnReadDeadline = delegate(EngineServiceReadDeadline deadline)
                {
                    if (pipe.Inbound.Count == 0)
                    {
                        ServiceHostAssert.Equal(TimeSpan.FromSeconds(60), deadline.Remaining, "full boundary budget");
                        clock.Now = 60000;
                        ServiceHostAssert.True(deadline.TryExpire(), "expiry recorded");
                    }
                };
                pipe.ReadOutcome = EngineServiceFrameReadOutcome.Unknown;
                ServiceHostFakeBackend backend = NewBackend();
                List<string> order = new List<string>();
                pipe.Order = order;
                backend.Order = order;
                EngineServiceSessionGate gate = NewGate(backend, TimeSpan.FromSeconds(2));
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                EngineServicePipeListener listener = NewListener(pipe, gate, events, clock);
                EngineServiceListenerResult result = ServiceHostAssert.Wait(listener.RunAsync(CancellationToken.None), 5000, "listener");
                ServiceHostAssert.True(result.Ok, "cleanup succeeds");
                ServiceHostAssert.Equal(EngineServiceStopReason.ParentLost, result.StopReason, "parent loss");
                ServiceHostAssert.Equal(1, backend.Stops, "one stop");
                ServiceHostAssert.Equal(2, CountCalls(pipe.Calls, "read"), "hello and one boundary read");
                ServiceHostAssert.Equal(1, pipe.DisposeCalls, "one dispose");
                ServiceHostAssert.True(events.Contains(EngineServiceEventCodes.BoundaryReadTimeout), "boundary expiry");
                ServiceHostAssert.True(events.Contains(EngineServiceEventCodes.PipeReadFailed), "unknown transfer diagnostic");
                ServiceHostAssert.False(events.Contains(EngineServiceEventCodes.IdleTimeout), "no proven idle claim");
                ServiceHostAssert.True(IndexOf(order, "backend_stop") < IndexOf(order, "pipe_dispose"), "stop before dispose");
                listener.Dispose();
            });

            runner.Check("listener: even an immediate proven idle result closes without a retry loop", delegate
            {
                ServiceHostFakePipe pipe = NewPipe();
                pipe.Inbound.Enqueue(ServiceHostTestData.Encode(ServiceHostTestData.HelloFields()));
                pipe.ReadOutcome = EngineServiceFrameReadOutcome.Idle;
                ServiceHostFakeMonotonicClock clock = new ServiceHostFakeMonotonicClock();
                clock.TickFrequency = 1000;
                ServiceHostFakeBackend backend = NewBackend();
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                EngineServicePipeListener listener = NewListener(pipe, NewGate(backend, TimeSpan.FromSeconds(2)), events, clock);
                ServiceHostAssert.Wait(listener.RunAsync(CancellationToken.None), 5000, "listener");
                ServiceHostAssert.Equal(2, CountCalls(pipe.Calls, "read"), "no immediate-idle spin");
                ServiceHostAssert.Equal(1, backend.Stops, "one stop");
                listener.Dispose();
            });

            runner.Check("listener: validated hello and request receive a full interval after their replies", delegate
            {
                ServiceHostFakePipe pipe = NewPipe();
                pipe.Inbound.Enqueue(ServiceHostTestData.Encode(ServiceHostTestData.HelloFields()));
                pipe.Inbound.Enqueue(ServiceHostTestData.Encode(ServiceHostTestData.StatusRequestFields()));
                ServiceHostFakeMonotonicClock clock = new ServiceHostFakeMonotonicClock();
                clock.TickFrequency = 1000;
                pipe.OnWrite = delegate { clock.Now += 1000; };
                int read = 0;
                pipe.OnReadDeadline = delegate(EngineServiceReadDeadline deadline)
                {
                    read++;
                    if (read == 2 || read == 3)
                    {
                        ServiceHostAssert.Equal(TimeSpan.FromSeconds(60), deadline.Remaining, "completed request credit excludes reply time");
                    }
                };
                ServiceHostFakeBackend backend = NewBackend();
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                EngineServicePipeListener listener = NewListener(pipe, NewGate(backend, TimeSpan.FromSeconds(2)), events, clock);
                EngineServiceListenerResult result = ServiceHostAssert.Wait(listener.RunAsync(CancellationToken.None), 5000, "listener");
                ServiceHostAssert.Equal(2, result.HandledRequests, "hello and status validated");
                ServiceHostAssert.Equal(1, backend.Stops, "one stop");
                listener.Dispose();
            });

            foreach (string scenario in new[] { "delayed_hello", "invalid", "not_hello", "denied", "failed_reply", "cancel_frame", "cancel_write", "expired_write", "expired_policy", "expired_pid" })
            {
                runner.Check("hello request credit: " + scenario, delegate
                {
                    ServiceHostFakePipe pipe = NewPipe();
                    byte[] hello = scenario == "invalid" ? new byte[] { 0, 0, 0, 1, 0xff }
                        : ServiceHostTestData.Encode(scenario == "not_hello" ? ServiceHostTestData.StatusRequestFields() : ServiceHostTestData.HelloFields());
                    pipe.Inbound.Enqueue(hello);
                    ServiceHostFakeMonotonicClock clock = new ServiceHostFakeMonotonicClock();
                    EngineServiceIdleGuard idle = new EngineServiceIdleGuard(clock, TimeSpan.FromSeconds(1));
                    ServiceHostFakeBackend backend = NewBackend();
                    EngineServiceSessionGate gate = NewGate(backend, TimeSpan.FromSeconds(2));
                    ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                    ServiceHostFakeAccountInspector inspector = new ServiceHostFakeAccountInspector();
                    if (scenario == "denied") { inspector.Type = EngineServiceAccountType.Group; }
                    if (scenario == "expired_policy") { inspector.OnInspect = delegate { clock.Now = 5000; }; }
                    if (scenario == "expired_pid") { pipe.OnClientProcessId = delegate { clock.Now = 5000; }; }
                    int credits = 0;
                    using (CancellationTokenSource stop = new CancellationTokenSource())
                    {
                        pipe.OnReadDeadline = delegate
                        {
                            if (scenario == "cancel_frame") { clock.Now = 5000; stop.Cancel(); }
                        };
                        pipe.OnWrite = delegate
                        {
                            clock.Now = scenario == "expired_write" ? 5000 : 2000;
                            if (scenario == "failed_reply") { pipe.WriteOk = false; }
                            if (scenario == "cancel_write") { clock.Now = 5000; stop.Cancel(); }
                            ServiceHostAssert.Equal(0, credits, "no credit before write completes");
                        };
                        EngineServicePipeServerHandshake handshake = new EngineServicePipeServerHandshake(pipe, gate,
                            new WindowsServiceCallerPolicy(ServiceHostTestData.UserSid, inspector, TimeSpan.FromSeconds(1)),
                            new EngineServiceCleanThreadDispatcher(), new ServiceHostFakeFatalBoundary(), events,
                            TimeSpan.FromSeconds(5), clock, delegate
                            {
                                ServiceHostAssert.Equal(1, pipe.WrittenCount, "credit follows successful reply");
                                credits++;
                                idle.MarkRequestCompleted();
                            });
                        EngineServiceHandshakeResult result = ServiceHostAssert.Wait(handshake.RunAsync(stop.Token), 5000, "hello");
                        bool success = scenario == "delayed_hello";
                        bool canceled = scenario == "cancel_frame" || scenario == "cancel_write";
                        bool expired = scenario.StartsWith("expired_", StringComparison.Ordinal);
                        ServiceHostAssert.Equal(success, result.Ok, "handshake outcome");
                        ServiceHostAssert.Equal(success ? 1 : 0, credits, "only completed validated hello earns credit");
                        ServiceHostAssert.Equal(success ? TimeSpan.FromSeconds(1) : TimeSpan.Zero,
                            idle.CreateReadDeadline(TimeSpan.FromSeconds(5)).Remaining, "full interval follows delayed valid hello only");
                        ServiceHostAssert.Equal(expired, events.Contains(EngineServiceEventCodes.FrameTimeout), "stop wins over competing deadline diagnostics");
                        ServiceHostAssert.Equal(success || scenario == "cancel_write" || scenario == "expired_write" || scenario == "expired_pid" ? 1 : 0,
                            pipe.WrittenCount, "no write after invalid frame, failed auth, policy expiry, or stop");
                        if (canceled) { ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Closed, result.Code, "stop is closed"); }
                        ServiceHostAssert.Equal(0, backend.Stops, "handshake does not claim stop");
                    }
                    gate.Dispose();
                });
            }

            runner.Check("handshake: linked timeout before monotonic read expiry preserves unknown framing diagnostic", delegate
            {
                ServiceHostFakePipe pipe = NewPipe();
                pipe.BlockReadUntilCancelled = true;
                ServiceHostFakeMonotonicClock clock = new ServiceHostFakeMonotonicClock();
                ServiceHostFakeBackend backend = NewBackend();
                using (EngineServiceSessionGate gate = NewGate(backend, TimeSpan.FromSeconds(2)))
                {
                    ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                    EngineServicePipeServerHandshake handshake = new EngineServicePipeServerHandshake(pipe, gate,
                        NewPolicy(), new EngineServiceCleanThreadDispatcher(), new ServiceHostFakeFatalBoundary(), events,
                        TimeSpan.FromMilliseconds(20), clock, null);
                    EngineServiceHandshakeResult result = ServiceHostAssert.Wait(handshake.RunAsync(CancellationToken.None), 3000, "timer handshake");
                    ServiceHostAssert.False(result.Ok, "timeout refuses handshake");
                    ServiceHostAssert.Equal(0L, clock.Now, "monotonic fake has not expired");
                    ServiceHostAssert.True(events.Contains(EngineServiceEventCodes.FrameTimeout), "linked timer is expiry evidence");
                    ServiceHostAssert.True(events.Contains(EngineServiceEventCodes.FrameInvalid), "unknown transfer retained");
                    ServiceHostAssert.False(pipe.Calls.Contains("impersonate"), "no auth after failed read");
                }
            });

            runner.Check("session gate: a stop requested at the claim is a service stop", delegate
            {
                ServiceHostFakeBackend backend = NewBackend();
                EngineServiceSessionGate gate = NewGate(backend, TimeSpan.FromSeconds(2));
                using (CancellationTokenSource cancellation = new CancellationTokenSource())
                {
                    cancellation.Cancel();
                    // The listener's last cancellation check happened before
                    // this call. The claim itself must notice the stop.
                    EngineServiceResult result = gate.ParentLostUnlessStopRequested(
                        cancellation.Token);
                    ServiceHostAssert.True(result.Ok, "stop ok: " + result.Code);
                    ServiceHostAssert.Equal(
                        EngineServiceStopReason.ServiceStop,
                        gate.StopReason,
                        "claim reason");
                    ServiceHostAssert.Equal(
                        EngineServiceStopReason.ServiceStop,
                        backend.LastStop,
                        "backend reason");
                    ServiceHostAssert.Equal(1, backend.Stops, "one stop");
                }
                gate.Dispose();
            });

            runner.Check("session gate: a stop that lands after the claim keeps the parent-loss reason", delegate
            {
                ServiceHostFakeBackend backend = NewBackend();
                backend.BlockStop = true;
                EngineServiceSessionGate gate = NewGate(backend, TimeSpan.FromSeconds(2));
                using (CancellationTokenSource cancellation = new CancellationTokenSource())
                {
                    Task<EngineServiceResult> claim = Task.Run<EngineServiceResult>(
                        delegate
                        {
                            return gate.ParentLostUnlessStopRequested(
                                CancellationToken.None);
                        });
                    ServiceHostAssert.Wait(backend.StopEntered.Task, 2000, "stop entered");
                    cancellation.Cancel();
                    ServiceHostAssert.Equal(
                        EngineServiceStopReason.ParentLost,
                        gate.StopReason,
                        "the first claim reason is kept");

                    backend.ReleaseStop.TrySetResult(true);
                    EngineServiceResult result = ServiceHostAssert.Wait(claim, 2000, "claim");
                    ServiceHostAssert.True(result.Ok, "stop ok: " + result.Code);
                    ServiceHostAssert.Equal(
                        EngineServiceStopReason.ParentLost,
                        backend.LastStop,
                        "the first reason is the one that ran");
                    ServiceHostAssert.Equal(1, backend.Stops, "one stop");
                }
                gate.Dispose();
            });

            runner.Check("listener: the stop runs before the pipe is disposed", delegate
            {
                ServiceHostFakePipe pipe = NewPipe();
                pipe.Inbound.Enqueue(ServiceHostTestData.Encode(ServiceHostTestData.HelloFields()));
                pipe.BlockReadUntilCancelled = true;
                List<string> order = new List<string>();
                pipe.Order = order;
                ServiceHostFakePipeFactory factory = new ServiceHostFakePipeFactory();
                factory.Pipe = pipe;
                ServiceHostFakeBackend backend = NewBackend();
                backend.Order = order;
                EngineServiceSessionGate gate = NewGate(backend, TimeSpan.FromSeconds(2));
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                EngineServiceTransportOptions options = ServiceHostTestData.TransportOptions();
                options.ConnectTimeout = TimeSpan.FromSeconds(1);
                options.HandshakeTimeout = TimeSpan.FromSeconds(1);
                options.RequestTimeout = TimeSpan.FromSeconds(1);

                EngineServicePipeListener listener = new EngineServicePipeListener(
                    factory,
                    gate,
                    NewPolicy(),
                    new EngineServiceCleanThreadDispatcher(),
                    new ServiceHostFakeFatalBoundary(),
                    events,
                    options);
                using (CancellationTokenSource cancellation = new CancellationTokenSource())
                {
                    Task<EngineServiceListenerResult> run = listener.RunAsync(cancellation.Token);
                    cancellation.CancelAfter(100);
                    EngineServiceListenerResult result = ServiceHostAssert.Wait(run, 5000, "listener");
                    ServiceHostAssert.True(result.Ok, "clean service stop: " + result.Code);
                }

                ServiceHostAssert.Equal(1, backend.Stops, "one stop");
                ServiceHostAssert.Equal(1, pipe.DisposeCalls, "one pipe dispose");
                ServiceHostAssert.Equal(2, order.Count, "one stop and one dispose");
                ServiceHostAssert.True(
                    IndexOf(order, "backend_stop") < IndexOf(order, "pipe_dispose"),
                    "the stop runs before the pipe is disposed");
                listener.Dispose();
            });

            runner.Check("event buffer: the real bounded buffer accepts idle_timeout", delegate
            {
                EngineServiceEventBuffer buffer = new EngineServiceEventBuffer();
                buffer.Record(EngineServiceEventCodes.IdleTimeout);
                ServiceHostAssert.Equal(1, buffer.Count, "one record");
                ServiceHostAssert.True(buffer.Contains(EngineServiceEventCodes.IdleTimeout), "idle token kept");
                string[] snapshot = buffer.Snapshot();
                ServiceHostAssert.Equal(1, snapshot.Length, "snapshot length");
                ServiceHostAssert.Equal("idle_timeout", snapshot[0], "fixed idle token");
                ServiceHostAssert.False(
                    buffer.Contains(EngineServiceEventCodes.EventCodeInvalid),
                    "a known token is not replaced");
            });
        }

        private static EngineServicePipeListener NewListener(
            ServiceHostFakePipe pipe, EngineServiceSessionGate gate,
            ServiceHostFakeEvents events, ServiceHostFakeMonotonicClock clock)
        {
            ServiceHostFakePipeFactory factory = new ServiceHostFakePipeFactory();
            factory.Pipe = pipe;
            return new EngineServicePipeListener(factory, gate, NewPolicy(),
                new EngineServiceCleanThreadDispatcher(), new ServiceHostFakeFatalBoundary(),
                events, ServiceHostTestData.TransportOptions(), clock);
        }

        private static ServiceHostFakeBackend NewBackend()
        {
            return new ServiceHostFakeBackend(
                ServiceHostTestData.ReadyStatus(ServiceHostTestData.Now()));
        }

        private static EngineServiceSessionGate NewGate(
            ServiceHostFakeBackend backend,
            TimeSpan stopWait)
        {
            ServiceHostFakeClock clock = new ServiceHostFakeClock(ServiceHostTestData.Now());
            EngineServiceSession session = new EngineServiceSession(
                ServiceHostTestData.ServiceInstance,
                backend,
                clock,
                EngineServiceStateGate.FromRecord(
                    ServiceHostTestData.CleanRecord(clock.Now)),
                TimeSpan.FromSeconds(2));
            return new EngineServiceSessionGate(session, backend, stopWait);
        }

        private static WindowsServiceCallerPolicy NewPolicy()
        {
            return new WindowsServiceCallerPolicy(
                ServiceHostTestData.UserSid,
                new ServiceHostFakeAccountInspector(),
                TimeSpan.FromSeconds(1));
        }

        private static ServiceHostFakePipe NewPipe()
        {
            ServiceHostFakePipe pipe = new ServiceHostFakePipe();
            pipe.Token.Identity = new EngineServiceCallerIdentity(
                ServiceHostTestData.UserSid,
                2,
                EngineServiceImpersonationLevel.Identification,
                "",
                false);
            return pipe;
        }

        private static int CountCalls(List<string> calls, string value)
        {
            int count = 0;
            for (int index = 0; index < calls.Count; index++)
            {
                if (string.Equals(calls[index], value, StringComparison.Ordinal))
                {
                    count++;
                }
            }
            return count;
        }

        private static int IndexOf(List<string> steps, string value)
        {
            for (int index = 0; index < steps.Count; index++)
            {
                if (string.Equals(steps[index], value, StringComparison.Ordinal))
                {
                    return index;
                }
            }
            return int.MaxValue;
        }
    }
}
