using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.ServiceHost.Tests
{
    // Hermetic checks for the service host lifecycle review. They use fake
    // pipes, fake backends, and a fake fatal boundary. They open no pipe, call
    // no Win32 function, and create no service, process, route, or device.
    internal static class ServiceHostLifecycleChecks
    {
        public static void Run(ServiceHostCheckRunner runner)
        {
            runner.Check("lifecycle: a normal stop during impersonation waits for the checked revert", delegate
            {
                ServiceHostFakePipe pipe = NewPipe();
                pipe.Inbound.Enqueue(ServiceHostTestData.Encode(ServiceHostTestData.HelloFields()));
                ServiceHostFakeBackend backend = NewBackend();
                EngineServiceSessionGate gate = NewGate(backend, TimeSpan.FromSeconds(2));
                ServiceHostReleasableCleanThreadRunner runnerThread =
                    new ServiceHostReleasableCleanThreadRunner();
                ServiceHostFakeFatalBoundary fatal = new ServiceHostFakeFatalBoundary();
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                EngineServicePipeServerHandshake handshake = new EngineServicePipeServerHandshake(
                    pipe,
                    gate,
                    NewPolicy(),
                    runnerThread,
                    fatal,
                    events,
                    TimeSpan.FromSeconds(2));
                using (CancellationTokenSource cancellation = new CancellationTokenSource())
                {
                    Task<EngineServiceHandshakeResult> run = handshake.RunAsync(cancellation.Token);
                    ServiceHostAssert.True(
                        runnerThread.Started.Wait(2000),
                        "the probe thread started");
                    cancellation.Cancel();

                    ServiceHostAssert.False(
                        run.Wait(150),
                        "normal cancellation waited for the probe revert");
                    ServiceHostAssert.Equal(0, fatal.Calls, "no fatal boundary on a normal stop");

                    runnerThread.Release.Set();
                    EngineServiceHandshakeResult result = ServiceHostAssert.Wait(
                        run,
                        5000,
                        "handshake");
                    ServiceHostAssert.False(result.Ok, "canceled handshake");
                    ServiceHostAssert.False(result.Fatal, "not fatal");
                    ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Closed, result.Code, "requested stop code");
                    ServiceHostAssert.Equal(0, pipe.Written.Count, "no reply after a canceled handshake");
                    ServiceHostAssert.Equal(0, fatal.Calls, "still no fatal boundary");
                    ServiceHostAssert.Equal(0, backend.Stops, "no stop on the probe thread");
                    ServiceHostAssert.Equal(1, CountCalls(pipe.Calls, "revert"), "checked revert ran");
                    ServiceHostAssert.True(pipe.Token.Disposed, "token disposed");
                    ServiceHostAssert.False(
                        events.Contains(EngineServiceEventCodes.FrameTimeout),
                        "requested stop is not timeout evidence");
                }
                gate.Dispose();
            });

            runner.Check("lifecycle: a listener treats a stop during impersonation as a service stop", delegate
            {
                ServiceHostFakePipe pipe = NewPipe();
                pipe.Inbound.Enqueue(ServiceHostTestData.Encode(ServiceHostTestData.HelloFields()));
                ServiceHostFakeBackend backend = NewBackend();
                EngineServiceSessionGate gate = NewGate(backend, TimeSpan.FromSeconds(2));
                ServiceHostFakeFatalBoundary fatal = new ServiceHostFakeFatalBoundary();
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                ServiceHostReleasableCleanThreadRunner runnerThread =
                    new ServiceHostReleasableCleanThreadRunner();
                EngineServiceTransportOptions options = ServiceHostTestData.TransportOptions();
                options.ConnectTimeout = TimeSpan.FromSeconds(1);
                options.HandshakeTimeout = TimeSpan.FromSeconds(2);
                options.RequestTimeout = TimeSpan.FromSeconds(1);
                ServiceHostFakePipeFactory factory = new ServiceHostFakePipeFactory();
                factory.Pipe = pipe;
                EngineServicePipeListener listener = new EngineServicePipeListener(
                    factory,
                    gate,
                    NewPolicy(),
                    runnerThread,
                    fatal,
                    events,
                    options);
                using (CancellationTokenSource cancellation = new CancellationTokenSource())
                {
                    Task<EngineServiceListenerResult> run = listener.RunAsync(cancellation.Token);
                    ServiceHostAssert.True(
                        runnerThread.Started.Wait(2000),
                        "the probe thread started");
                    cancellation.Cancel();
                    ServiceHostAssert.False(run.Wait(150), "the listener waits for the probe revert");
                    ServiceHostAssert.Equal(0, fatal.Calls, "no fatal boundary");

                    runnerThread.Release.Set();
                    EngineServiceListenerResult result = ServiceHostAssert.Wait(run, 5000, "listener");
                    ServiceHostAssert.True(result.Ok, "clean service stop: " + result.Code);
                    ServiceHostAssert.Equal(
                        EngineServiceStopReason.ServiceStop,
                        result.StopReason,
                        "service stop reason");
                    ServiceHostAssert.Equal(1, backend.Stops, "one stop");
                    ServiceHostAssert.Equal(0, fatal.Calls, "still no fatal boundary");
                    ServiceHostAssert.Equal(0, pipe.WrittenCount, "no reply after a stopped probe");
                    ServiceHostAssert.Equal(1, pipe.DisposeCalls, "pipe disposed after the probe");
                    ServiceHostAssert.False(events.Contains(EngineServiceEventCodes.ParentLost), "no parent loss");
                }
                listener.Dispose();
            });

            runner.Check("lifecycle: a deadline with a running probe defers pipe disposal", delegate
            {
                ServiceHostFakePipe pipe = NewPipe();
                pipe.Inbound.Enqueue(ServiceHostTestData.Encode(ServiceHostTestData.HelloFields()));
                ServiceHostFakeBackend backend = NewBackend();
                EngineServiceSessionGate gate = NewGate(backend, TimeSpan.FromSeconds(2));
                ServiceHostFakeFatalBoundary fatal = new ServiceHostFakeFatalBoundary();
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                ServiceHostReleasableCleanThreadRunner runnerThread =
                    new ServiceHostReleasableCleanThreadRunner();
                EngineServiceTransportOptions options = ServiceHostTestData.TransportOptions();
                options.ConnectTimeout = TimeSpan.FromSeconds(1);
                options.HandshakeTimeout = TimeSpan.FromMilliseconds(100);
                options.RequestTimeout = TimeSpan.FromSeconds(1);
                ServiceHostFakePipeFactory factory = new ServiceHostFakePipeFactory();
                factory.Pipe = pipe;
                EngineServicePipeListener listener = new EngineServicePipeListener(
                    factory,
                    gate,
                    NewPolicy(),
                    runnerThread,
                    fatal,
                    events,
                    options);

                Task<EngineServiceListenerResult> run = listener.RunAsync(CancellationToken.None);
                ServiceHostAssert.True(
                    ServiceHostAssert.Wait(listener.Ready, 2000, "listener ready"),
                    "ready");
                ServiceHostAssert.True(
                    runnerThread.Started.Wait(2000),
                    "the probe thread started");
                EngineServiceListenerResult result = ServiceHostAssert.Wait(run, 5000, "listener");

                ServiceHostAssert.False(result.Ok, "unverified probe fails closed");
                ServiceHostAssert.True(result.Fatal, "fatal result");
                ServiceHostAssert.Equal(1, fatal.Calls, "fatal boundary called once");
                ServiceHostAssert.Equal(0, pipe.DisposeCalls, "pipe kept open for the probe thread");
                ServiceHostAssert.True(
                    events.Contains(EngineServiceEventCodes.CallerRevertUnverified),
                    "unverified event");

                runnerThread.Release.Set();
                ServiceHostAssert.True(
                    SpinWait.SpinUntil(
                        delegate { return Volatile.Read(ref pipe.DisposeCalls) == 1; },
                        5000),
                    "pipe disposed after the probe exited");
                ServiceHostAssert.Equal(1, pipe.DisposeCalls, "one pipe dispose");
                ServiceHostAssert.Equal(1, CountCalls(pipe.Calls, "revert"), "checked revert ran");
                listener.Dispose();
            });

            runner.Check("lifecycle: a stop during connect is a service stop", delegate
            {
                ServiceHostFakePipe pipe = NewPipe();
                pipe.ConnectOk = false;
                ServiceHostFakeBackend backend = NewBackend();
                EngineServiceSessionGate gate = NewGate(backend, TimeSpan.FromSeconds(2));
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                ServiceHostFakePipeFactory factory = new ServiceHostFakePipeFactory();
                factory.Pipe = pipe;
                EngineServicePipeListener listener = new EngineServicePipeListener(
                    factory,
                    gate,
                    NewPolicy(),
                    new EngineServiceCleanThreadDispatcher(),
                    new ServiceHostFakeFatalBoundary(),
                    events,
                    ServiceHostTestData.TransportOptions());
                using (CancellationTokenSource cancellation = new CancellationTokenSource())
                {
                    cancellation.Cancel();
                    EngineServiceListenerResult result = ServiceHostAssert.Wait(
                        listener.RunAsync(cancellation.Token),
                        5000,
                        "listener");
                    ServiceHostAssert.True(result.Ok, "clean service stop: " + result.Code);
                    ServiceHostAssert.Equal(
                        EngineServiceStopReason.ServiceStop,
                        result.StopReason,
                        "service stop reason");
                    ServiceHostAssert.Equal(1, backend.Stops, "one stop");
                    ServiceHostAssert.False(events.Contains(EngineServiceEventCodes.ParentLost), "no parent loss");
                    ServiceHostAssert.False(
                        events.Contains(EngineServiceEventCodes.PipeConnectFailed),
                        "no pipe failure event");
                }
                listener.Dispose();
            });

            runner.Check("lifecycle: a connect failure without cancellation is a parent loss", delegate
            {
                ServiceHostFakePipe pipe = NewPipe();
                pipe.ConnectOk = false;
                ServiceHostFakeBackend backend = NewBackend();
                EngineServiceSessionGate gate = NewGate(backend, TimeSpan.FromSeconds(2));
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                ServiceHostFakePipeFactory factory = new ServiceHostFakePipeFactory();
                factory.Pipe = pipe;
                EngineServicePipeListener listener = new EngineServicePipeListener(
                    factory,
                    gate,
                    NewPolicy(),
                    new EngineServiceCleanThreadDispatcher(),
                    new ServiceHostFakeFatalBoundary(),
                    events,
                    ServiceHostTestData.TransportOptions());

                EngineServiceListenerResult result = ServiceHostAssert.Wait(
                    listener.RunAsync(CancellationToken.None),
                    5000,
                    "listener");
                ServiceHostAssert.False(result.Ok, "connect failure");
                ServiceHostAssert.Equal(
                    EngineProtocol.ErrorCodes.EngineUnavailable,
                    result.Code,
                    "engine unavailable");
                ServiceHostAssert.Equal(
                    EngineServiceStopReason.ParentLost,
                    result.StopReason,
                    "parent loss reason");
                ServiceHostAssert.Equal(1, backend.Stops, "one stop");
                ServiceHostAssert.Equal(EngineServiceStopReason.ParentLost, backend.LastStop, "stop reason");
                ServiceHostAssert.True(
                    events.Contains(EngineServiceEventCodes.PipeConnectFailed),
                    "pipe connect event");
                ServiceHostAssert.True(
                    events.Contains(EngineServiceEventCodes.ParentLost),
                    "parent loss event");
                listener.Dispose();
            });

            runner.Check("lifecycle: a stop during the handshake read is a service stop", delegate
            {
                ServiceHostFakePipe pipe = NewPipe();
                pipe.BlockReadUntilCancelled = true;
                ServiceHostFakeBackend backend = NewBackend();
                EngineServiceSessionGate gate = NewGate(backend, TimeSpan.FromSeconds(2));
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                ServiceHostFakePipeFactory factory = new ServiceHostFakePipeFactory();
                factory.Pipe = pipe;
                EngineServiceTransportOptions options = ServiceHostTestData.TransportOptions();
                options.ConnectTimeout = TimeSpan.FromSeconds(1);
                options.HandshakeTimeout = TimeSpan.FromSeconds(2);
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
                    ServiceHostAssert.Equal(
                        EngineServiceStopReason.ServiceStop,
                        result.StopReason,
                        "service stop reason");
                    ServiceHostAssert.Equal(1, backend.Stops, "one stop");
                    ServiceHostAssert.False(events.Contains(EngineServiceEventCodes.ParentLost), "no parent loss");
                }
                listener.Dispose();
            });

            runner.Check("lifecycle: a forbidden shutdown does not stop the service", delegate
            {
                ServiceHostFakePipe pipe = NewPipe();
                pipe.Inbound.Enqueue(ServiceHostTestData.Encode(ServiceHostTestData.HelloFields()));
                Dictionary<string, string> forbidden = ServiceHostTestData.HelloFields();
                forbidden[EngineProtocol.Keys.Operation] = EngineProtocol.Operations.Shutdown;
                forbidden[EngineProtocol.Keys.Session] = new string('b', 32);
                pipe.Inbound.Enqueue(ServiceHostTestData.Encode(forbidden));
                pipe.BlockReadUntilCancelled = true;
                ServiceHostFakeBackend backend = NewBackend();
                EngineServiceSessionGate gate = NewGate(backend, TimeSpan.FromSeconds(2));
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                ServiceHostFakePipeFactory factory = new ServiceHostFakePipeFactory();
                factory.Pipe = pipe;
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
                    ServiceHostAssert.True(
                        SpinWait.SpinUntil(
                            delegate { return pipe.WrittenCount >= 2; },
                            2000),
                        "hello and forbidden shutdown replies written");
                    ServiceHostAssert.Equal(0, backend.Stops, "forbidden shutdown ran no stop");
                    ServiceHostAssert.False(events.Contains(EngineServiceEventCodes.ParentLost), "no parent loss");

                    cancellation.Cancel();
                    EngineServiceListenerResult result = ServiceHostAssert.Wait(run, 5000, "listener");
                    ServiceHostAssert.True(result.Ok, "clean service stop: " + result.Code);
                    ServiceHostAssert.Equal(
                        EngineServiceStopReason.ServiceStop,
                        result.StopReason,
                        "service stop after the caller stop");
                    ServiceHostAssert.Equal(1, backend.Stops, "one stop after cancellation");
                }
                listener.Dispose();
            });

            runner.Check("lifecycle: dispose before any stop refuses a later stop", delegate
            {
                ServiceHostFakeBackend backend = NewBackend();
                EngineServiceSessionGate gate = NewGate(backend, TimeSpan.FromSeconds(1));
                gate.Dispose();
                EngineServiceResult stop = gate.ParentLost();
                ServiceHostAssert.False(stop.Ok, "no stop after dispose");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Closed, stop.Code, "closed code");
                ServiceHostAssert.Equal(0, backend.Stops, "no backend stop");
                ServiceHostAssert.True(gate.IsClosed, "closed");
            });

            runner.Check("lifecycle: dispose during a claimed stop does not drop it", delegate
            {
                ServiceHostFakeBackend backend = NewBackend();
                backend.BlockStart = true;
                EngineServiceSessionGate gate = NewGate(backend, TimeSpan.FromMilliseconds(200));
                gate.Session.SetCredentialHeld(true);
                Hello(gate);

                Task<EngineReply> start = Task.Run<EngineReply>(
                    delegate
                    {
                        return gate.HandleAsync(
                            ServiceHostTestData.StartFields(true),
                            CancellationToken.None);
                    });
                ServiceHostAssert.Wait(backend.StartEntered.Task, 2000, "start entered");

                Task<EngineServiceResult> claimed = Task.Run<EngineServiceResult>(
                    delegate { return gate.ParentLost(); });
                ServiceHostAssert.True(
                    SpinWait.SpinUntil(
                        delegate { return gate.StopClaimed; },
                        2000),
                    "stop claimed");
                gate.Dispose();

                EngineServiceResult first = ServiceHostAssert.Wait(claimed, 5000, "claimed stop");
                ServiceHostAssert.False(first.Ok, "the first caller still sees the timeout");
                ServiceHostAssert.Equal(
                    EngineProtocol.ErrorCodes.EngineStopTimeout,
                    first.Code,
                    "the claim is not turned into a closed result");

                backend.ReleaseStart.TrySetResult(true);
                EngineReply startReply = ServiceHostAssert.Wait(start, 5000, "start reply");
                ServiceHostAssert.False(startReply.Ok, "start refused after the stop claim");
                ServiceHostAssert.True(
                    SpinWait.SpinUntil(
                        delegate { return Volatile.Read(ref backend.Stops) == 1; },
                        5000),
                    "the claimed stop ran after the request left");
                ServiceHostAssert.Equal(1, backend.Stops, "one stop");

                EngineServiceResult shared = gate.ParentLost();
                ServiceHostAssert.True(shared.Ok, "later trigger sees the one stop result");
                ServiceHostAssert.Equal(
                    EngineServiceStopReason.ParentLost,
                    gate.StopReason,
                    "the first reason is kept");
                ServiceHostAssert.Equal(1, backend.Stops, "still one stop");
            });
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

        private static void Hello(EngineServiceSessionGate gate)
        {
            EngineReply hello = ServiceHostAssert.Wait(
                gate.HandleAsync(
                    ServiceHostTestData.HelloFields(),
                    CancellationToken.None),
                5000,
                "hello");
            ServiceHostAssert.True(hello.Ok, "hello");
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
    }
}
