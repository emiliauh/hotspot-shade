using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.ServiceHost.Tests
{
    internal static class ServiceHostSessionChecks
    {
        public static void Run(ServiceHostCheckRunner runner)
        {
            runner.Check("session gate: parent loss closes the gate and refuses a later start", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                ServiceHostFakeBackend backend = new ServiceHostFakeBackend(
                    ServiceHostTestData.ReadyStatus(now));
                EngineServiceSessionGate gate = NewGate(backend, TimeSpan.FromSeconds(2));
                gate.Session.SetCredentialHeld(true);

                EngineServiceResult lost = gate.ParentLost();
                ServiceHostAssert.True(lost.Ok, "parent loss");
                ServiceHostAssert.Equal(1, backend.Stops, "one stop");
                ServiceHostAssert.Equal(EngineServiceStopReason.ParentLost, backend.LastStop, "reason");
                ServiceHostAssert.True(gate.IsClosed, "closed");
                ServiceHostAssert.True(gate.Session.IsClosed, "session closed");

                EngineReply late = Wait(gate.HandleAsync(
                    ServiceHostTestData.StartFields(true),
                    CancellationToken.None));
                ServiceHostAssert.False(late.Ok, "late start refused");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Closed, late.Code, "closed code");
                ServiceHostAssert.Equal(0, backend.Starts, "no start after parent loss");
            });

            runner.Check("session gate: a start in flight cannot launch after parent loss", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                ServiceHostFakeBackend backend = new ServiceHostFakeBackend(
                    ServiceHostTestData.ReadyStatus(now));
                backend.BlockStart = true;
                EngineServiceSessionGate gate = NewGate(backend, TimeSpan.FromSeconds(2));
                gate.Session.SetCredentialHeld(true);
                Hello(gate);

                Task<EngineReply> start = StartInFlight(gate);
                ServiceHostAssert.Wait(backend.StartEntered.Task, 2000, "start entered");

                Task<EngineServiceResult> parent = Task.Run<EngineServiceResult>(
                    delegate { return gate.ParentLost(); });
                Thread.Sleep(50);
                ServiceHostAssert.False(parent.IsCompleted, "parent loss waits for the in-flight call");

                backend.ReleaseStart.TrySetResult(true);
                EngineReply startReply = ServiceHostAssert.Wait(start, 2000, "start reply");
                EngineServiceResult parentResult = ServiceHostAssert.Wait(parent, 2000, "parent loss");

                ServiceHostAssert.False(startReply.Ok, "in-flight start refused");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Closed, startReply.Code, "closed code");
                ServiceHostAssert.True(parentResult.Ok, "parent loss");
                ServiceHostAssert.Equal(1, backend.Starts, "one backend start attempt");
                ServiceHostAssert.Equal(1, backend.Stops, "one stop");
                ServiceHostAssert.True(gate.IsClosed, "closed");

                EngineReply after = Wait(gate.HandleAsync(
                    ServiceHostTestData.StartFields(true),
                    CancellationToken.None));
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Closed, after.Code, "after closed");
                ServiceHostAssert.Equal(1, backend.Starts, "no second start");
            });

            runner.Check("session gate: a stop timeout is a failed stop, not a clean one", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                ServiceHostFakeBackend backend = new ServiceHostFakeBackend(
                    ServiceHostTestData.ReadyStatus(now));
                backend.BlockStart = true;
                EngineServiceSessionGate gate = NewGate(backend, TimeSpan.FromMilliseconds(50));
                gate.Session.SetCredentialHeld(true);
                Hello(gate);

                Task<EngineReply> start = StartInFlight(gate);
                ServiceHostAssert.Wait(backend.StartEntered.Task, 2000, "start entered");

                EngineServiceResult lost = gate.ParentLost();
                ServiceHostAssert.False(lost.Ok, "stop timeout");
                ServiceHostAssert.Equal(
                    EngineProtocol.ErrorCodes.EngineStopTimeout,
                    lost.Code,
                    "timeout code");
                ServiceHostAssert.True(gate.StopClaimed, "one stop claimed");
                ServiceHostAssert.True(gate.IsClosed, "closed");

                EngineServiceResult second = gate.ParentLost();
                ServiceHostAssert.False(second.Ok, "second trigger shares the timeout");
                ServiceHostAssert.Equal(
                    EngineProtocol.ErrorCodes.EngineStopTimeout,
                    second.Code,
                    "timeout code shared");

                backend.ReleaseStart.TrySetResult(true);
                EngineReply startReply = ServiceHostAssert.Wait(start, 2000, "start reply");
                ServiceHostAssert.False(startReply.Ok, "start refused after stop request");
                ServiceHostAssert.True(
                    SpinWait.SpinUntil(
                        delegate { return Volatile.Read(ref backend.Stops) == 1; },
                        2000),
                    "the claimed stop runs after the in-flight request leaves");
                EngineServiceResult eventual = gate.ParentLost();
                ServiceHostAssert.True(eventual.Ok, "later trigger sees the one stop result");
                ServiceHostAssert.Equal(1, backend.Stops, "still one stop");
            });

            runner.Check("session gate: a claimed stop that times out still runs once the gate is free", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                ServiceHostFakeBackend backend = new ServiceHostFakeBackend(
                    ServiceHostTestData.ReadyStatus(now));
                backend.BlockStart = true;
                EngineServiceSessionGate gate = NewGate(backend, TimeSpan.FromMilliseconds(100));
                gate.Session.SetCredentialHeld(true);
                Hello(gate);

                Task<EngineReply> start = StartInFlight(gate);
                ServiceHostAssert.Wait(backend.StartEntered.Task, 2000, "start entered");

                EngineServiceResult lost = gate.ParentLost();
                ServiceHostAssert.False(lost.Ok, "stop timeout");
                ServiceHostAssert.Equal(
                    EngineProtocol.ErrorCodes.EngineStopTimeout,
                    lost.Code,
                    "timeout code");
                ServiceHostAssert.True(gate.StopClaimed, "stop is claimed");
                ServiceHostAssert.Equal(
                    EngineServiceStopReason.ParentLost,
                    gate.StopReason,
                    "first reason is kept");
                ServiceHostAssert.Equal(0, backend.Stops, "stop waits for the request");

                EngineServiceResult second = gate.ServiceStopped(
                    EngineServiceStopReason.ServiceStop);
                ServiceHostAssert.False(second.Ok, "second trigger still waits");
                ServiceHostAssert.Equal(
                    EngineServiceStopReason.ParentLost,
                    gate.StopReason,
                    "second reason does not replace the first");

                backend.ReleaseStart.TrySetResult(true);
                EngineReply startReply = ServiceHostAssert.Wait(start, 2000, "start reply");
                ServiceHostAssert.False(startReply.Ok, "start refused after stop request");
                ServiceHostAssert.True(
                    SpinWait.SpinUntil(
                        delegate { return Volatile.Read(ref backend.Stops) == 1; },
                        2000),
                    "claimed stop ran");
                ServiceHostAssert.Equal(1, backend.Stops, "one stop");
                ServiceHostAssert.Equal(
                    EngineServiceStopReason.ParentLost,
                    backend.LastStop,
                    "the first reason is the one that ran");
            });

            runner.Check("session gate: shutdown keeps the first reason across a parent-loss race", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                ServiceHostFakeBackend backend = new ServiceHostFakeBackend(
                    ServiceHostTestData.ReadyStatus(now));
                backend.BlockStop = true;
                EngineServiceSessionGate gate = NewGate(backend, TimeSpan.FromSeconds(2));
                Task<EngineServiceResult> first = Task.Run<EngineServiceResult>(
                    delegate { return gate.ServiceStopped(EngineServiceStopReason.Shutdown); });
                ServiceHostAssert.Wait(backend.StopEntered.Task, 2000, "stop entered");
                Task<EngineServiceResult> second = Task.Run<EngineServiceResult>(
                    delegate { return gate.ParentLost(); });
                Thread.Sleep(50);
                ServiceHostAssert.False(second.IsCompleted, "parent loss waits for the shutdown stop");
                ServiceHostAssert.Equal(
                    EngineServiceStopReason.Shutdown,
                    gate.StopReason,
                    "shutdown reason wins the claim");

                backend.ReleaseStop.TrySetResult(true);
                EngineServiceResult firstResult = ServiceHostAssert.Wait(first, 2000, "shutdown stop");
                EngineServiceResult secondResult = ServiceHostAssert.Wait(second, 2000, "parent loss");
                ServiceHostAssert.True(firstResult.Ok, "shutdown stop");
                ServiceHostAssert.True(secondResult.Ok, "parent loss sees the shared result");
                ServiceHostAssert.Equal(1, backend.Stops, "one stop");
                ServiceHostAssert.Equal(EngineServiceStopReason.Shutdown, backend.LastStop, "first reason");
                ServiceHostAssert.Equal(
                    EngineServiceStopReason.Shutdown,
                    gate.StopReason,
                    "first reason after both triggers");
            });

            runner.Check("session gate: a second trigger shares the first stop failure", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                ServiceHostFakeBackend backend = new ServiceHostFakeBackend(
                    ServiceHostTestData.ReadyStatus(now));
                backend.StopOk = false;
                EngineServiceSessionGate gate = NewGate(backend, TimeSpan.FromSeconds(2));
                EngineServiceResult parent = gate.ParentLost();
                EngineServiceResult service = gate.ServiceStopped(
                    EngineServiceStopReason.ServiceStop);
                ServiceHostAssert.False(parent.Ok, "first stop failed");
                ServiceHostAssert.Equal(
                    EngineProtocol.ErrorCodes.EngineStopTimeout,
                    parent.Code,
                    "first code");
                ServiceHostAssert.False(service.Ok, "second trigger sees the failure");
                ServiceHostAssert.Equal(parent.Code, service.Code, "shared code");
                ServiceHostAssert.Equal(1, backend.Stops, "one stop");
            });

            runner.Check("session gate: a second trigger waits for the first stop result", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                ServiceHostFakeBackend backend = new ServiceHostFakeBackend(
                    ServiceHostTestData.ReadyStatus(now));
                backend.BlockStop = true;
                EngineServiceSessionGate gate = NewGate(backend, TimeSpan.FromSeconds(2));
                Task<EngineServiceResult> first = Task.Run<EngineServiceResult>(
                    delegate { return gate.ParentLost(); });
                ServiceHostAssert.Wait(backend.StopEntered.Task, 2000, "stop entered");
                Task<EngineServiceResult> second = Task.Run<EngineServiceResult>(
                    delegate { return gate.ServiceStopped(EngineServiceStopReason.ServiceStop); });
                Thread.Sleep(50);
                ServiceHostAssert.False(second.IsCompleted, "second trigger waits");
                backend.ReleaseStop.TrySetResult(true);
                EngineServiceResult firstResult = ServiceHostAssert.Wait(first, 2000, "first stop");
                EngineServiceResult secondResult = ServiceHostAssert.Wait(second, 2000, "second stop");
                ServiceHostAssert.True(firstResult.Ok, "first stop");
                ServiceHostAssert.True(secondResult.Ok, "second sees the same success");
                ServiceHostAssert.Equal(1, backend.Stops, "one stop");
            });

            runner.Check("session gate: a failed stop boundary still runs the stop", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                ServiceHostFakeBackend backend = new ServiceHostFakeBackend(
                    ServiceHostTestData.ReadyStatus(now));
                backend.MarkStopThrows = true;
                EngineServiceSessionGate gate = NewGate(backend, TimeSpan.FromSeconds(2));
                EngineServiceResult lost = gate.ParentLost();
                ServiceHostAssert.False(lost.Ok, "boundary failure is reported");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Internal, lost.Code, "code");
                ServiceHostAssert.Equal(1, backend.Stops, "the stop still ran");
                ServiceHostAssert.Equal(EngineServiceStopReason.ParentLost, backend.LastStop, "stop reason");
            });

            runner.Check("session gate: a user stop remains the first reason after a later parent loss", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                ServiceHostFakeBackend backend = new ServiceHostFakeBackend(
                    ServiceHostTestData.ReadyStatus(now));
                EngineServiceSessionGate gate = NewGate(backend, TimeSpan.FromSeconds(2));
                Hello(gate);

                EngineReply stop = Wait(gate.HandleAsync(
                    ServiceHostTestData.StopFields(),
                    CancellationToken.None));
                ServiceHostAssert.True(stop.Ok, "user stop");
                ServiceHostAssert.Equal(EngineServiceStopReason.User, backend.LastStop, "user reason");
                ServiceHostAssert.Equal(1, backend.Stops, "one stop");

                EngineServiceResult lost = gate.ParentLost();
                ServiceHostAssert.True(lost.Ok, "parent loss shares the user stop");
                ServiceHostAssert.Equal(
                    EngineServiceStopReason.User,
                    gate.StopReason,
                    "the first actual reason is kept");
                ServiceHostAssert.Equal(1, backend.Stops, "no second stop");
                ServiceHostAssert.Equal(EngineServiceStopReason.User, backend.LastStop, "still user");
            });

            runner.Check("session gate: a canceled request is a timeout and does not reach the backend", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                ServiceHostFakeBackend backend = new ServiceHostFakeBackend(
                    ServiceHostTestData.ReadyStatus(now));
                EngineServiceSessionGate gate = NewGate(backend, TimeSpan.FromSeconds(2));
                using (CancellationTokenSource canceled = new CancellationTokenSource())
                {
                    canceled.Cancel();
                    EngineReply reply = Wait(gate.HandleAsync(
                        ServiceHostTestData.StatusRequestFields(),
                        canceled.Token));
                    ServiceHostAssert.False(reply.Ok, "canceled");
                    ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Timeout, reply.Code, "timeout code");
                    ServiceHostAssert.Equal(0, backend.Starts, "no start");
                }
            });

            runner.Check("session gate: parent loss and service stop run exactly one stop", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                ServiceHostFakeBackend backend = new ServiceHostFakeBackend(
                    ServiceHostTestData.ReadyStatus(now));
                EngineServiceSessionGate gate = NewGate(backend, TimeSpan.FromSeconds(2));
                EngineServiceResult parent = gate.ParentLost();
                EngineServiceResult service = gate.ServiceStopped(EngineServiceStopReason.ServiceStop);
                ServiceHostAssert.True(parent.Ok, "parent stop");
                ServiceHostAssert.True(service.Ok, "second claim is a no-op");
                ServiceHostAssert.Equal(1, backend.Stops, "one stop");
                ServiceHostAssert.Equal(EngineServiceStopReason.ParentLost, backend.LastStop, "first reason wins");
            });

            runner.Check("session gate: an invalid service stop reason is refused", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                ServiceHostFakeBackend backend = new ServiceHostFakeBackend(
                    ServiceHostTestData.ReadyStatus(now));
                EngineServiceSessionGate gate = NewGate(backend, TimeSpan.FromSeconds(2));
                ServiceHostAssert.Throws<ArgumentException>(
                    delegate { gate.ServiceStopped(EngineServiceStopReason.User); },
                    "user is not a service stop reason");
            });

            runner.Check("session gate: dispose is idempotent and closes the gate", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                ServiceHostFakeBackend backend = new ServiceHostFakeBackend(
                    ServiceHostTestData.ReadyStatus(now));
                EngineServiceSessionGate gate = NewGate(backend, TimeSpan.FromSeconds(2));
                gate.Dispose();
                gate.Dispose();
                ServiceHostAssert.True(gate.IsClosed, "closed");
                EngineReply reply = Wait(gate.HandleAsync(
                    ServiceHostTestData.StatusRequestFields(),
                    CancellationToken.None));
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Closed, reply.Code, "closed code");
            });
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

        private static EngineReply Wait(Task<EngineReply> task)
        {
            return ServiceHostAssert.Wait(task, 5000, "reply");
        }

        private static Task<EngineReply> StartInFlight(EngineServiceSessionGate gate)
        {
            // HandleAsync runs the synchronous fake backend on its caller
            // thread. Use another thread so the test can observe the request
            // while the backend holds it.
            return Task.Run<EngineReply>(
                delegate { return gate.HandleAsync(
                    ServiceHostTestData.StartFields(true),
                    CancellationToken.None); });
        }

        private static void Hello(EngineServiceSessionGate gate)
        {
            EngineReply hello = Wait(gate.HandleAsync(
                ServiceHostTestData.HelloFields(),
                CancellationToken.None));
            ServiceHostAssert.True(hello.Ok, "hello");
        }
    }
}
