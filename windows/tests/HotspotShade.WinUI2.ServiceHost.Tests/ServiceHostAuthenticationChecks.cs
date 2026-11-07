using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.ServiceHost.Tests
{
    internal static class ServiceHostAuthenticationChecks
    {
        public static void Run(ServiceHostCheckRunner runner)
        {
            runner.Check("caller policy: only a user account with the installed SID is allowed", delegate
            {
                ServiceHostFakeAccountInspector inspector = new ServiceHostFakeAccountInspector();
                WindowsServiceCallerPolicy policy = new WindowsServiceCallerPolicy(
                    ServiceHostTestData.UserSid,
                    inspector,
                    TimeSpan.FromSeconds(2));

                EngineServiceCallerVerdict allowed = Wait(policy.EvaluateAsync(
                    Identity(ServiceHostTestData.UserSid, EngineServiceImpersonationLevel.Identification),
                    CancellationToken.None));
                ServiceHostAssert.True(allowed.Allowed, "same user allowed");
                ServiceHostAssert.Equal(EngineServiceEventCodes.SameUserCaller, allowed.EventCode, "event");

                EngineServiceCallerVerdict other = Wait(policy.EvaluateAsync(
                    Identity("S-1-5-21-1111111111-2222222222-3333333333-1002",
                        EngineServiceImpersonationLevel.Identification),
                    CancellationToken.None));
                ServiceHostAssert.False(other.Allowed, "other user denied");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.BoundaryAuthFailed, other.Code, "code");

                EngineServiceCallerVerdict low = Wait(policy.EvaluateAsync(
                    Identity(ServiceHostTestData.UserSid, EngineServiceImpersonationLevel.Anonymous),
                    CancellationToken.None));
                ServiceHostAssert.False(low.Allowed, "anonymous denied");

                EngineServiceCallerVerdict badSession = Wait(policy.EvaluateAsync(
                    new EngineServiceCallerIdentity(
                        ServiceHostTestData.UserSid,
                        0,
                        EngineServiceImpersonationLevel.Identification,
                        "",
                        false),
                    CancellationToken.None));
                ServiceHostAssert.False(badSession.Allowed, "session zero denied");

                inspector.Type = EngineServiceAccountType.Group;
                EngineServiceCallerVerdict group = Wait(policy.EvaluateAsync(
                    Identity(ServiceHostTestData.GroupSid, EngineServiceImpersonationLevel.Identification),
                    CancellationToken.None));
                ServiceHostAssert.False(group.Allowed, "group denied");
                ServiceHostAssert.Equal(
                    EngineServiceEventCodes.CallerAccountTypeNotUser,
                    group.EventCode,
                    "group event");

                EngineServiceCallerVerdict everyone = Wait(policy.EvaluateAsync(
                    Identity("S-1-1-0", EngineServiceImpersonationLevel.Identification),
                    CancellationToken.None));
                ServiceHostAssert.False(everyone.Allowed, "Everyone denied");
                ServiceHostAssert.Equal(EngineServiceEventCodes.CallerSidRejected, everyone.EventCode, "everyone event");

                EngineServiceCallerVerdict system = Wait(policy.EvaluateAsync(
                    Identity("S-1-5-18", EngineServiceImpersonationLevel.Identification),
                    CancellationToken.None));
                ServiceHostAssert.False(system.Allowed, "SYSTEM denied");

                inspector.Fail = true;
                EngineServiceCallerVerdict unknown = Wait(policy.EvaluateAsync(
                    Identity(ServiceHostTestData.UserSid, EngineServiceImpersonationLevel.Identification),
                    CancellationToken.None));
                ServiceHostAssert.False(unknown.Allowed, "account lookup failure denied");
                ServiceHostAssert.Equal(
                    EngineServiceEventCodes.CallerAccountTypeFailed,
                    unknown.EventCode,
                    "lookup event");
            });

            runner.Check("caller policy: a well-known non-user SID cannot be installed", delegate
            {
                ServiceHostFakeAccountInspector inspector = new ServiceHostFakeAccountInspector();
                string[] refused =
                {
                    "S-1-1-0",
                    "S-1-5-11",
                    "S-1-5-18",
                    "S-1-5-32-544",
                    "S-1-16-12288",
                    "S-1-5"
                };
                for (int index = 0; index < refused.Length; index++)
                {
                    bool threw = false;
                    try
                    {
                        new WindowsServiceCallerPolicy(
                            refused[index],
                            inspector,
                            TimeSpan.FromSeconds(1));
                    }
                    catch (ArgumentException)
                    {
                        threw = true;
                    }
                    ServiceHostAssert.True(threw, "refused " + refused[index]);
                }

                WindowsServiceCallerPolicy allowed = new WindowsServiceCallerPolicy(
                    ServiceHostTestData.UserSid,
                    inspector,
                    TimeSpan.FromSeconds(1));
                ServiceHostAssert.Equal(ServiceHostTestData.UserSid, allowed.InstalledUserSid, "installed SID");
            });

            runner.Check("caller policy: Win32 impersonation levels map through the reviewed core table", delegate
            {
                EngineServiceImpersonationLevel level;
                ServiceHostAssert.True(
                    EngineServiceCallerPolicy.TryMapWin32ImpersonationLevel(0, out level),
                    "anonymous");
                ServiceHostAssert.Equal(EngineServiceImpersonationLevel.Anonymous, level, "anonymous value");
                ServiceHostAssert.True(
                    EngineServiceCallerPolicy.TryMapWin32ImpersonationLevel(1, out level),
                    "identification");
                ServiceHostAssert.Equal(EngineServiceImpersonationLevel.Identification, level, "identification value");
                ServiceHostAssert.True(
                    EngineServiceCallerPolicy.TryMapWin32ImpersonationLevel(2, out level),
                    "impersonation");
                ServiceHostAssert.Equal(EngineServiceImpersonationLevel.Impersonation, level, "impersonation value");
                ServiceHostAssert.True(
                    EngineServiceCallerPolicy.TryMapWin32ImpersonationLevel(3, out level),
                    "delegation");
                ServiceHostAssert.Equal(EngineServiceImpersonationLevel.Delegation, level, "delegation value");
                ServiceHostAssert.False(
                    EngineServiceCallerPolicy.TryMapWin32ImpersonationLevel(4, out level),
                    "value four refused");
                ServiceHostAssert.Equal(EngineServiceImpersonationLevel.Unreadable, level, "unreadable");
                ServiceHostAssert.False(
                    EngineServiceCallerPolicy.TryMapWin32ImpersonationLevel(-1, out level),
                    "negative refused");
            });

            runner.Check("handshake: read, impersonate, token, checked revert, then parse and reply", delegate
            {
                ServiceHostFakePipe pipe = NewPipe();
                pipe.Inbound.Enqueue(ServiceHostTestData.Encode(ServiceHostTestData.HelloFields()));
                ServiceHostFakeBackend backend = new ServiceHostFakeBackend(
                    ServiceHostTestData.ReadyStatus(ServiceHostTestData.Now()));
                EngineServiceSessionGate gate = NewGate(backend);
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                WindowsServiceCallerPolicy policy = NewPolicy();

                EngineServicePipeServerHandshake handshake = NewHandshake(
                    pipe,
                    gate,
                    policy,
                    events);
                EngineServiceHandshakeResult result = Wait(
                    handshake.RunAsync(CancellationToken.None),
                    5000);

                ServiceHostAssert.True(result.Ok, "handshake ok");
                ServiceHostAssert.True(result.HelloReplyOk, "hello reply ok");
                ServiceHostAssert.Equal(ServiceHostTestData.Session, result.CallerSessionId, "caller session");
                ServiceHostAssert.Equal(4242, result.ClientProcessId, "client pid diagnostics");
                ServiceHostAssert.Equal(1, pipe.Written.Count, "one reply");
                ServiceHostAssert.True(pipe.Token.Disposed, "token disposed");
                ServiceHostAssert.Equal(1, pipe.Token.Reads, "token read once");
                ServiceHostAssert.False(pipe.ImpersonateThreadPool, "impersonation is not on a pool thread");
                ServiceHostAssert.False(pipe.RevertThreadPool, "revert is not on a pool thread");
                ServiceHostAssert.Equal(pipe.ImpersonateThreadId, pipe.RevertThreadId, "one clean thread");
                ServiceHostAssert.True(events.Contains(EngineServiceEventCodes.SameUserCaller), "event");
                ServiceHostAssert.True(
                    Position(pipe.Calls, "read") < Position(pipe.Calls, "impersonate"),
                    "read before impersonate");
                ServiceHostAssert.True(
                    Position(pipe.Calls, "impersonate") < Position(pipe.Calls, "open_token"),
                    "impersonate before token");
                ServiceHostAssert.True(
                    Position(pipe.Calls, "open_token") < Position(pipe.Calls, "revert"),
                    "token before revert");
                ServiceHostAssert.True(
                    Position(pipe.Calls, "revert") < Position(pipe.Calls, "write"),
                    "revert before parse and reply");
                ServiceHostAssert.True(
                    Position(pipe.Calls, "revert") < Position(pipe.Calls, "client_pid"),
                    "revert before diagnostics");

                Dictionary<string, string> reply;
                string code;
                ServiceHostAssert.True(
                    EngineServiceFrame.TryDecode(
                        pipe.Written[0],
                        pipe.Written[0].Length,
                        out reply,
                        out code),
                    "reply decode: " + code);
                ServiceHostAssert.Equal("1", reply[EngineProtocol.Keys.Ok], "reply ok field");
                ServiceHostAssert.Equal(
                    ServiceHostTestData.ServiceInstance,
                    reply[EngineServiceStatusKeys.Instance],
                    "instance");
                gate.Dispose();
            });

            runner.Check("handshake: a denied account gets no reply and the thread is reverted", delegate
            {
                ServiceHostFakePipe pipe = NewPipe();
                pipe.Token.Identity = Identity(
                    ServiceHostTestData.GroupSid,
                    EngineServiceImpersonationLevel.Identification);
                pipe.Inbound.Enqueue(ServiceHostTestData.Encode(ServiceHostTestData.HelloFields()));
                ServiceHostFakeBackend backend = new ServiceHostFakeBackend(
                    ServiceHostTestData.ReadyStatus(ServiceHostTestData.Now()));
                EngineServiceSessionGate gate = NewGate(backend);
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                ServiceHostFakeAccountInspector inspector = new ServiceHostFakeAccountInspector();
                inspector.Type = EngineServiceAccountType.Group;
                WindowsServiceCallerPolicy policy = new WindowsServiceCallerPolicy(
                    ServiceHostTestData.UserSid,
                    inspector,
                    TimeSpan.FromSeconds(1));

                EngineServicePipeServerHandshake handshake = NewHandshake(
                    pipe,
                    gate,
                    policy,
                    events);
                EngineServiceHandshakeResult result = Wait(
                    handshake.RunAsync(CancellationToken.None),
                    5000);

                ServiceHostAssert.False(result.Ok, "denied");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.BoundaryAuthFailed, result.Code, "code");
                ServiceHostAssert.Equal(0, pipe.Written.Count, "no reply");
                ServiceHostAssert.Equal(1, CountCalls(pipe.Calls, "revert"), "revert called");
                ServiceHostAssert.True(pipe.Token.Disposed, "token disposed");
                ServiceHostAssert.True(
                    events.Contains(EngineServiceEventCodes.CallerAccountTypeNotUser),
                    "denial event");
                gate.Dispose();
            });

            runner.Check("handshake: impersonation, token, and token read failures revert and send no reply", delegate
            {
                AssertHandshakeFailure(
                    delegate(ServiceHostFakePipe pipe) { pipe.ImpersonateOk = false; },
                    EngineServiceEventCodes.CallerImpersonationFailed,
                    true,
                    false);
                AssertHandshakeFailure(
                    delegate(ServiceHostFakePipe pipe) { pipe.OpenTokenOk = false; },
                    EngineServiceEventCodes.CallerTokenFailed,
                    true,
                    false);
                AssertHandshakeFailure(
                    delegate(ServiceHostFakePipe pipe) { pipe.Token.Fail = true; },
                    EngineServiceEventCodes.CallerTokenFailed,
                    true,
                    true);
            });

            runner.Check("handshake: a failed revert never reuses the impersonated thread for event or stop work", delegate
            {
                ServiceHostFakePipe pipe = NewPipe();
                pipe.RevertOk = false;
                pipe.Inbound.Enqueue(ServiceHostTestData.Encode(ServiceHostTestData.HelloFields()));
                ServiceHostFakeBackend backend = new ServiceHostFakeBackend(
                    ServiceHostTestData.ReadyStatus(ServiceHostTestData.Now()));
                EngineServiceSessionGate gate = NewGate(backend);
                ServiceHostFakeFatalBoundary fatal = new ServiceHostFakeFatalBoundary();
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                WindowsServiceCallerPolicy policy = NewPolicy();

                EngineServicePipeServerHandshake handshake = new EngineServicePipeServerHandshake(
                    pipe,
                    gate,
                    policy,
                    new EngineServiceCleanThreadDispatcher(),
                    fatal,
                    events,
                    TimeSpan.FromSeconds(1));
                EngineServiceHandshakeResult result = Wait(
                    handshake.RunAsync(CancellationToken.None),
                    5000);

                ServiceHostAssert.False(result.Ok, "revert failure");
                ServiceHostAssert.True(result.Fatal, "fatal result");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.EngineUnavailable, result.Code, "code");
                ServiceHostAssert.Equal(0, pipe.Written.Count, "no reply");
                ServiceHostAssert.False(pipe.Calls.Contains("client_pid"), "no diagnostics after revert failure");
                ServiceHostAssert.True(
                    events.Contains(EngineServiceEventCodes.CallerRevertFailed),
                    "revert event");
                ServiceHostAssert.False(pipe.ImpersonateThreadPool, "impersonation is not on a pool thread");
                ServiceHostAssert.False(pipe.RevertThreadPool, "revert is not on a pool thread");
                ServiceHostAssert.Equal(pipe.ImpersonateThreadId, pipe.RevertThreadId, "one clean thread");
                ServiceHostAssert.True(
                    events.ThreadIdOf(EngineServiceEventCodes.CallerRevertFailed)
                        != pipe.RevertThreadId,
                    "event is not recorded on the possibly impersonated thread");
                ServiceHostAssert.Equal(1, fatal.Calls, "fatal boundary called once");
                ServiceHostAssert.True(
                    fatal.ThreadId != pipe.RevertThreadId,
                    "fatal boundary is not called on the possibly impersonated thread");
                ServiceHostAssert.Equal(0, backend.Stops, "no stop fallback after a failed revert");
                ServiceHostAssert.Equal(0, backend.Starts, "no start after a failed revert");
                gate.Dispose();
            });

            runner.Check("handshake: an unverified impersonation thread times out and fails closed", delegate
            {
                ServiceHostFakePipe pipe = NewPipe();
                pipe.Inbound.Enqueue(ServiceHostTestData.Encode(ServiceHostTestData.HelloFields()));
                ServiceHostFakeBackend backend = new ServiceHostFakeBackend(
                    ServiceHostTestData.ReadyStatus(ServiceHostTestData.Now()));
                EngineServiceSessionGate gate = NewGate(backend);
                ServiceHostBlockingCleanThreadRunner blocking =
                    new ServiceHostBlockingCleanThreadRunner();
                ServiceHostFakeFatalBoundary fatal = new ServiceHostFakeFatalBoundary();
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();

                EngineServicePipeServerHandshake handshake = new EngineServicePipeServerHandshake(
                    pipe,
                    gate,
                    NewPolicy(),
                    blocking,
                    fatal,
                    events,
                    TimeSpan.FromMilliseconds(100));
                EngineServiceHandshakeResult result = Wait(
                    handshake.RunAsync(CancellationToken.None),
                    5000);

                ServiceHostAssert.False(result.Ok, "unverified thread");
                ServiceHostAssert.True(result.Fatal, "fatal result");
                ServiceHostAssert.Equal(1, blocking.Calls, "one clean-thread start");
                ServiceHostAssert.Equal(1, fatal.Calls, "fatal boundary called once");
                ServiceHostAssert.Equal(0, pipe.Written.Count, "no reply");
                ServiceHostAssert.Equal(0, backend.Stops, "no stop fallback");
                ServiceHostAssert.True(
                    events.Contains(EngineServiceEventCodes.CallerRevertUnverified),
                    "unverified event");
                gate.Dispose();
            });

            runner.Check("handshake: a runner failure after the probe starts fails closed and keeps the pipe open", delegate
            {
                ServiceHostFakePipe pipe = NewPipe();
                pipe.Inbound.Enqueue(ServiceHostTestData.Encode(ServiceHostTestData.HelloFields()));
                ServiceHostFakeBackend backend = new ServiceHostFakeBackend(
                    ServiceHostTestData.ReadyStatus(ServiceHostTestData.Now()));
                EngineServiceSessionGate gate = NewGate(backend);
                ServiceHostThrowingCleanThreadRunner runnerThread =
                    new ServiceHostThrowingCleanThreadRunner();
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
                EngineServiceHandshakeResult result = Wait(
                    handshake.RunAsync(CancellationToken.None),
                    5000);

                ServiceHostAssert.False(result.Ok, "runner failure");
                ServiceHostAssert.True(result.Fatal, "fatal result");
                ServiceHostAssert.True(result.PipeDisposalDeferred, "pipe disposal deferred");
                ServiceHostAssert.Equal(1, runnerThread.Calls, "one clean-thread start");
                ServiceHostAssert.Equal(1, fatal.Calls, "fatal boundary called once");
                ServiceHostAssert.Equal(0, pipe.Written.Count, "no reply");
                ServiceHostAssert.Equal(0, backend.Stops, "no stop fallback");
                ServiceHostAssert.Equal(0, pipe.DisposeCalls, "the pipe is not closed under a possible probe");
                ServiceHostAssert.True(
                    events.Contains(EngineServiceEventCodes.CallerRevertUnverified),
                    "unverified event");

                runnerThread.Release.Set();
                ServiceHostAssert.True(
                    SpinWait.SpinUntil(
                        delegate { return CountCalls(pipe.Calls, "revert") == 1; },
                        5000),
                    "the probe reached its checked revert");
                ServiceHostAssert.Equal(0, pipe.DisposeCalls, "no completion proof, so the pipe stays open");
                gate.Dispose();
            });

            runner.Check("handshake: a throwing fatal boundary still fails closed", delegate
            {
                ServiceHostFakePipe pipe = NewPipe();
                pipe.RevertThrows = true;
                pipe.Inbound.Enqueue(ServiceHostTestData.Encode(ServiceHostTestData.HelloFields()));
                ServiceHostFakeBackend backend = new ServiceHostFakeBackend(
                    ServiceHostTestData.ReadyStatus(ServiceHostTestData.Now()));
                EngineServiceSessionGate gate = NewGate(backend);
                ServiceHostFakeFatalBoundary fatal = new ServiceHostFakeFatalBoundary();
                fatal.Result = false;
                fatal.Throw = true;
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();

                EngineServicePipeServerHandshake handshake = new EngineServicePipeServerHandshake(
                    pipe,
                    gate,
                    NewPolicy(),
                    new EngineServiceCleanThreadDispatcher(),
                    fatal,
                    events,
                    TimeSpan.FromSeconds(1));
                EngineServiceHandshakeResult result = Wait(
                    handshake.RunAsync(CancellationToken.None),
                    5000);

                ServiceHostAssert.False(result.Ok, "revert failure");
                ServiceHostAssert.True(result.Fatal, "fatal result");
                ServiceHostAssert.Equal(1, fatal.Calls, "fatal boundary called once");
                ServiceHostAssert.Equal(0, backend.Stops, "no stop fallback");
                ServiceHostAssert.True(
                    events.Contains(EngineServiceEventCodes.CallerRevertFailed),
                    "revert event");
                gate.Dispose();
            });

            runner.Check("handshake: a valid frame that is not hello is refused after authentication", delegate
            {
                ServiceHostFakePipe pipe = NewPipe();
                pipe.Inbound.Enqueue(ServiceHostTestData.Encode(ServiceHostTestData.StatusRequestFields()));
                ServiceHostFakeBackend backend = new ServiceHostFakeBackend(
                    ServiceHostTestData.ReadyStatus(ServiceHostTestData.Now()));
                EngineServiceSessionGate gate = NewGate(backend);
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                WindowsServiceCallerPolicy policy = NewPolicy();

                EngineServicePipeServerHandshake handshake = NewHandshake(
                    pipe,
                    gate,
                    policy,
                    events);
                EngineServiceHandshakeResult result = Wait(
                    handshake.RunAsync(CancellationToken.None),
                    5000);

                ServiceHostAssert.False(result.Ok, "not hello");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.BadRequest, result.Code, "code");
                ServiceHostAssert.Equal(0, pipe.Written.Count, "no reply");
                ServiceHostAssert.Equal(1, CountCalls(pipe.Calls, "revert"), "revert called");
                ServiceHostAssert.True(
                    events.Contains(EngineServiceEventCodes.FirstFrameNotHello),
                    "event");
                gate.Dispose();
            });

            runner.Check("handshake: an invalid first frame is refused after authentication", delegate
            {
                ServiceHostFakePipe pipe = NewPipe();
                byte[] invalid = new byte[] { 0, 0, 0, 5, (byte)'{', (byte)'x', (byte)'}', (byte)' ', (byte)' ' };
                pipe.Inbound.Enqueue(invalid);
                ServiceHostFakeBackend backend = new ServiceHostFakeBackend(
                    ServiceHostTestData.ReadyStatus(ServiceHostTestData.Now()));
                EngineServiceSessionGate gate = NewGate(backend);
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                WindowsServiceCallerPolicy policy = NewPolicy();

                EngineServicePipeServerHandshake handshake = NewHandshake(
                    pipe,
                    gate,
                    policy,
                    events);
                EngineServiceHandshakeResult result = Wait(
                    handshake.RunAsync(CancellationToken.None),
                    5000);

                ServiceHostAssert.False(result.Ok, "invalid");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.BadResponse, result.Code, "code");
                ServiceHostAssert.Equal(0, pipe.Written.Count, "no reply");
                ServiceHostAssert.True(
                    events.Contains(EngineServiceEventCodes.FirstFrameInvalid),
                    "event");
                gate.Dispose();
            });

            runner.Check("handshake: a proven idle first-frame read is a timeout diagnostic", delegate
            {
                ServiceHostFakePipe pipe = NewPipe();
                pipe.ReadOutcome = EngineServiceFrameReadOutcome.Idle;
                pipe.ReadCode = EngineProtocol.ErrorCodes.Timeout;
                ServiceHostFakeBackend backend = new ServiceHostFakeBackend(
                    ServiceHostTestData.ReadyStatus(ServiceHostTestData.Now()));
                EngineServiceSessionGate gate = NewGate(backend);
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();

                EngineServicePipeServerHandshake handshake = NewHandshake(
                    pipe,
                    gate,
                    NewPolicy(),
                    events);
                EngineServiceHandshakeResult result = Wait(
                    handshake.RunAsync(CancellationToken.None),
                    5000);

                ServiceHostAssert.False(result.Ok, "idle handshake");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Timeout, result.Code, "timeout code");
                ServiceHostAssert.Equal(0, pipe.Written.Count, "no reply");
                ServiceHostAssert.Equal(0, CountCalls(pipe.Calls, "revert"), "no impersonation");
                ServiceHostAssert.True(
                    events.Contains(EngineServiceEventCodes.FrameTimeout),
                    "timeout diagnostic");
                ServiceHostAssert.False(
                    events.Contains(EngineServiceEventCodes.FrameInvalid),
                    "a proven idle is not a framing failure");
                gate.Dispose();
            });

            runner.Check("handshake: a partial read with a timeout code is a framing diagnostic", delegate
            {
                ServiceHostFakePipe pipe = NewPipe();
                pipe.ReadOutcome = EngineServiceFrameReadOutcome.Partial;
                pipe.ReadCode = EngineProtocol.ErrorCodes.Timeout;
                ServiceHostFakeBackend backend = new ServiceHostFakeBackend(
                    ServiceHostTestData.ReadyStatus(ServiceHostTestData.Now()));
                EngineServiceSessionGate gate = NewGate(backend);
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();

                EngineServicePipeServerHandshake handshake = NewHandshake(
                    pipe,
                    gate,
                    NewPolicy(),
                    events);
                EngineServiceHandshakeResult result = Wait(
                    handshake.RunAsync(CancellationToken.None),
                    5000);

                ServiceHostAssert.False(result.Ok, "partial handshake");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Timeout, result.Code, "transport code");
                ServiceHostAssert.Equal(0, pipe.Written.Count, "no reply");
                ServiceHostAssert.Equal(0, CountCalls(pipe.Calls, "revert"), "no impersonation");
                ServiceHostAssert.True(
                    events.Contains(EngineServiceEventCodes.FrameInvalid),
                    "a partial first frame is a framing diagnostic");
                ServiceHostAssert.False(
                    events.Contains(EngineServiceEventCodes.FrameTimeout),
                    "a consumed byte is not an idle timeout");
                gate.Dispose();
            });

            runner.Check("handshake: an unknown read with a timeout code is a framing diagnostic", delegate
            {
                ServiceHostFakePipe pipe = NewPipe();
                pipe.ReadOutcome = EngineServiceFrameReadOutcome.Unknown;
                pipe.ReadCode = EngineProtocol.ErrorCodes.Timeout;
                ServiceHostFakeBackend backend = new ServiceHostFakeBackend(
                    ServiceHostTestData.ReadyStatus(ServiceHostTestData.Now()));
                EngineServiceSessionGate gate = NewGate(backend);
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();

                EngineServicePipeServerHandshake handshake = NewHandshake(
                    pipe,
                    gate,
                    NewPolicy(),
                    events);
                EngineServiceHandshakeResult result = Wait(
                    handshake.RunAsync(CancellationToken.None),
                    5000);

                ServiceHostAssert.False(result.Ok, "unknown handshake");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Timeout, result.Code, "transport code");
                ServiceHostAssert.Equal(0, pipe.Written.Count, "no reply");
                ServiceHostAssert.Equal(0, CountCalls(pipe.Calls, "revert"), "no impersonation");
                ServiceHostAssert.True(
                    events.Contains(EngineServiceEventCodes.FrameInvalid),
                    "an unknown first frame is a framing diagnostic");
                ServiceHostAssert.False(
                    events.Contains(EngineServiceEventCodes.FrameTimeout),
                    "unknown completion is not an idle timeout");
                gate.Dispose();
            });

            runner.Check("listener: hello, status, then a pipe break runs one parent-loss stop", delegate
            {
                ServiceHostFakePipe pipe = NewPipe();
                pipe.Inbound.Enqueue(ServiceHostTestData.Encode(ServiceHostTestData.HelloFields()));
                pipe.Inbound.Enqueue(ServiceHostTestData.Encode(ServiceHostTestData.StatusRequestFields()));
                // A broken pipe is a hard transport failure. A timeout is an
                // idle read and is covered by its own check.
                pipe.ReadCode = EngineProtocol.ErrorCodes.EngineUnavailable;
                ServiceHostFakePipeFactory factory = new ServiceHostFakePipeFactory();
                factory.Pipe = pipe;
                ServiceHostFakeBackend backend = new ServiceHostFakeBackend(
                    ServiceHostTestData.ReadyStatus(ServiceHostTestData.Now()));
                EngineServiceSessionGate gate = NewGate(backend);
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
                EngineServiceListenerResult result = Wait(
                    listener.RunAsync(CancellationToken.None),
                    5000);

                ServiceHostAssert.True(result.Ok, "listener ok: " + result.Code);
                ServiceHostAssert.Equal(EngineServiceCleanup.Ok, result.Cleanup, "cleanup");
                ServiceHostAssert.Equal(EngineServiceStopReason.ParentLost, result.StopReason, "parent lost");
                ServiceHostAssert.Equal(2, result.HandledRequests, "two requests");
                ServiceHostAssert.Equal(2, pipe.Written.Count, "hello and status replies");
                ServiceHostAssert.Equal(1, backend.Stops, "one stop");
                ServiceHostAssert.Equal(EngineServiceStopReason.ParentLost, backend.LastStop, "stop reason");
                ServiceHostAssert.Equal(1, pipe.DisposeCalls, "pipe disposed");
                listener.Dispose();
            });

            foreach (EngineServiceFrameReadOutcome readOutcome in new[] {
                EngineServiceFrameReadOutcome.Idle, EngineServiceFrameReadOutcome.Partial,
                EngineServiceFrameReadOutcome.Unknown, EngineServiceFrameReadOutcome.Failed })
            {
                runner.Check("listener: no failed request read is replayed: " + readOutcome, delegate
                {
                    ServiceHostFakePipe pipe = NewPipe();
                    pipe.Inbound.Enqueue(ServiceHostTestData.Encode(ServiceHostTestData.HelloFields()));
                    pipe.ReadOutcome = readOutcome;
                    ServiceHostFakePipeFactory factory = new ServiceHostFakePipeFactory();
                    factory.Pipe = pipe;
                    ServiceHostFakeBackend backend = new ServiceHostFakeBackend(
                        ServiceHostTestData.ReadyStatus(ServiceHostTestData.Now()));
                    EngineServiceSessionGate gate = NewGate(backend);
                    ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                    EngineServicePipeListener listener = NewListener(factory, gate, events,
                        ServiceHostTestData.TransportOptions(), EngineServiceHostStopwatchClock.Instance);
                    EngineServiceListenerResult result = Wait(listener.RunAsync(CancellationToken.None), 5000);
                    ServiceHostAssert.Equal(EngineServiceStopReason.ParentLost, result.StopReason, "parent loss");
                    ServiceHostAssert.Equal(2, CountCalls(pipe.Calls, "read"), "no retry");
                    ServiceHostAssert.Equal(1, backend.Stops, "one stop");
                    ServiceHostAssert.Equal(1, pipe.DisposeCalls, "one dispose");
                    ServiceHostAssert.Equal(readOutcome != EngineServiceFrameReadOutcome.Idle,
                        events.Contains(EngineServiceEventCodes.PipeReadFailed), "transfer evidence diagnostic");
                    listener.Dispose();
                });
            }

            runner.Check("listener: a partial frame read closes the pipe as a parent loss", delegate
            {
                ServiceHostFakePipe pipe = NewPipe();
                pipe.Inbound.Enqueue(ServiceHostTestData.Encode(ServiceHostTestData.HelloFields()));
                pipe.ReadCode = EngineProtocol.ErrorCodes.Timeout;
                pipe.ReadOutcome = EngineServiceFrameReadOutcome.Partial;
                ServiceHostFakePipeFactory factory = new ServiceHostFakePipeFactory();
                factory.Pipe = pipe;
                ServiceHostFakeBackend backend = new ServiceHostFakeBackend(
                    ServiceHostTestData.ReadyStatus(ServiceHostTestData.Now()));
                EngineServiceSessionGate gate = NewGate(backend);
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
                EngineServiceListenerResult result = Wait(
                    listener.RunAsync(CancellationToken.None),
                    5000);

                ServiceHostAssert.True(result.Ok, "listener ok: " + result.Code);
                ServiceHostAssert.Equal(EngineServiceCleanup.Ok, result.Cleanup, "cleanup");
                ServiceHostAssert.Equal(EngineServiceStopReason.ParentLost, result.StopReason, "parent lost");
                ServiceHostAssert.Equal(1, result.HandledRequests, "one handled request");
                ServiceHostAssert.Equal(1, pipe.Written.Count, "one reply before the partial read");
                ServiceHostAssert.Equal(1, backend.Stops, "one stop");
                ServiceHostAssert.Equal(EngineServiceStopReason.ParentLost, backend.LastStop, "stop reason");
                ServiceHostAssert.Equal(1, pipe.DisposeCalls, "pipe disposed");
                // A second read proves the listener did not re-arm the read.
                ServiceHostAssert.Equal(2, CountCalls(pipe.Calls, "read"), "no idle re-arm");
                ServiceHostAssert.True(
                    events.Contains(EngineServiceEventCodes.PipeReadFailed),
                    "read failure event");
                ServiceHostAssert.True(
                    events.Contains(EngineServiceEventCodes.ParentLost),
                    "parent loss event");
                listener.Dispose();
            });

            runner.Check("listener: an unknown read outcome is a parent loss, not an idle re-arm", delegate
            {
                ServiceHostFakePipe pipe = NewPipe();
                pipe.Inbound.Enqueue(ServiceHostTestData.Encode(ServiceHostTestData.HelloFields()));
                pipe.ReadCode = EngineProtocol.ErrorCodes.Timeout;
                pipe.ReadOutcome = EngineServiceFrameReadOutcome.Unknown;
                ServiceHostFakePipeFactory factory = new ServiceHostFakePipeFactory();
                factory.Pipe = pipe;
                ServiceHostFakeBackend backend = new ServiceHostFakeBackend(
                    ServiceHostTestData.ReadyStatus(ServiceHostTestData.Now()));
                EngineServiceSessionGate gate = NewGate(backend);
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
                EngineServiceListenerResult result = Wait(
                    listener.RunAsync(CancellationToken.None),
                    5000);

                ServiceHostAssert.True(result.Ok, "listener ok: " + result.Code);
                ServiceHostAssert.Equal(EngineServiceStopReason.ParentLost, result.StopReason, "parent lost");
                ServiceHostAssert.Equal(1, result.HandledRequests, "one handled request");
                ServiceHostAssert.Equal(1, backend.Stops, "one stop");
                ServiceHostAssert.Equal(1, pipe.DisposeCalls, "pipe disposed");
                // A second read proves the listener did not re-arm the read.
                ServiceHostAssert.Equal(2, CountCalls(pipe.Calls, "read"), "no idle re-arm");
                ServiceHostAssert.True(
                    events.Contains(EngineServiceEventCodes.PipeReadFailed),
                    "read failure event");
                listener.Dispose();
            });

            runner.Check("listener: a stop during an unknown read is a service stop", delegate
            {
                ServiceHostFakePipe pipe = NewPipe();
                pipe.Inbound.Enqueue(ServiceHostTestData.Encode(ServiceHostTestData.HelloFields()));
                pipe.BlockReadUntilCancelled = true;
                ServiceHostFakePipeFactory factory = new ServiceHostFakePipeFactory();
                factory.Pipe = pipe;
                ServiceHostFakeBackend backend = new ServiceHostFakeBackend(
                    ServiceHostTestData.ReadyStatus(ServiceHostTestData.Now()));
                EngineServiceSessionGate gate = NewGate(backend);
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
                    ServiceHostAssert.True(
                        SpinWait.SpinUntil(
                            delegate { return pipe.WrittenCount >= 1; },
                            2000),
                        "the hello reply was written");
                    cancellation.Cancel();
                    EngineServiceListenerResult result = Wait(run, 5000);
                    ServiceHostAssert.True(result.Ok, "clean service stop: " + result.Code);
                    ServiceHostAssert.Equal(
                        EngineServiceStopReason.ServiceStop,
                        result.StopReason,
                        "service stop reason");
                    ServiceHostAssert.Equal(1, backend.Stops, "one stop");
                    ServiceHostAssert.False(
                        events.Contains(EngineServiceEventCodes.ParentLost),
                        "no parent loss on a requested stop");
                }
                listener.Dispose();
            });

            runner.Check("listener: a shutdown stops once and does not run a second stop", delegate
            {
                ServiceHostFakePipe pipe = NewPipe();
                pipe.Inbound.Enqueue(ServiceHostTestData.Encode(ServiceHostTestData.HelloFields()));
                Dictionary<string, string> shutdown = ServiceHostTestData.HelloFields();
                shutdown[EngineProtocol.Keys.Operation] = EngineProtocol.Operations.Shutdown;
                pipe.Inbound.Enqueue(ServiceHostTestData.Encode(shutdown));
                ServiceHostFakePipeFactory factory = new ServiceHostFakePipeFactory();
                factory.Pipe = pipe;
                ServiceHostFakeBackend backend = new ServiceHostFakeBackend(
                    ServiceHostTestData.ReadyStatus(ServiceHostTestData.Now()));
                EngineServiceSessionGate gate = NewGate(backend);
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
                    new ServiceHostFakeEvents(),
                    options);
                EngineServiceListenerResult result = Wait(
                    listener.RunAsync(CancellationToken.None),
                    5000);

                ServiceHostAssert.True(result.Ok, "listener ok: " + result.Code);
                ServiceHostAssert.Equal(EngineServiceStopReason.ServiceStop, result.StopReason, "service stop");
                ServiceHostAssert.Equal(1, backend.Stops, "one stop");
                ServiceHostAssert.Equal(EngineServiceStopReason.ServiceStop, backend.LastStop, "backend stop reason");
                listener.Dispose();
            });

            runner.Check("listener: a service cancellation runs one service stop", delegate
            {
                ServiceHostFakePipe pipe = NewPipe();
                pipe.Inbound.Enqueue(ServiceHostTestData.Encode(ServiceHostTestData.HelloFields()));
                pipe.BlockReadUntilCancelled = true;
                ServiceHostFakePipeFactory factory = new ServiceHostFakePipeFactory();
                factory.Pipe = pipe;
                ServiceHostFakeBackend backend = new ServiceHostFakeBackend(
                    ServiceHostTestData.ReadyStatus(ServiceHostTestData.Now()));
                EngineServiceSessionGate gate = NewGate(backend);
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
                    new ServiceHostFakeEvents(),
                    options);
                CancellationTokenSource cancellation = new CancellationTokenSource();
                Task<EngineServiceListenerResult> run = listener.RunAsync(cancellation.Token);
                cancellation.CancelAfter(50);
                EngineServiceListenerResult result = Wait(run, 5000);

                ServiceHostAssert.True(result.Ok, "listener ok: " + result.Code);
                ServiceHostAssert.Equal(EngineServiceStopReason.ServiceStop, result.StopReason, "service stop");
                ServiceHostAssert.Equal(1, backend.Stops, "one stop");
                listener.Dispose();
                cancellation.Dispose();
            });

            runner.Check("listener: a failed revert is fatal and runs no parent-loss stop", delegate
            {
                ServiceHostFakePipe pipe = NewPipe();
                pipe.RevertOk = false;
                pipe.Inbound.Enqueue(ServiceHostTestData.Encode(ServiceHostTestData.HelloFields()));
                ServiceHostFakePipeFactory factory = new ServiceHostFakePipeFactory();
                factory.Pipe = pipe;
                ServiceHostFakeBackend backend = new ServiceHostFakeBackend(
                    ServiceHostTestData.ReadyStatus(ServiceHostTestData.Now()));
                EngineServiceSessionGate gate = NewGate(backend);
                ServiceHostFakeFatalBoundary fatal = new ServiceHostFakeFatalBoundary();
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
                    fatal,
                    events,
                    options);
                Task<EngineServiceListenerResult> run = listener.RunAsync(CancellationToken.None);
                ServiceHostAssert.True(
                    ServiceHostAssert.Wait(listener.Ready, 2000, "listener ready"),
                    "ready before the client connects");
                EngineServiceListenerResult result = Wait(run, 5000);

                ServiceHostAssert.False(result.Ok, "fatal listener result");
                ServiceHostAssert.True(result.Fatal, "fatal flag");
                ServiceHostAssert.Equal(EngineServiceCleanup.Unknown, result.Cleanup, "cleanup unknown");
                ServiceHostAssert.Equal(EngineServiceStopReason.None, result.StopReason, "no stop reason");
                ServiceHostAssert.Equal(0, backend.Stops, "no parent-loss stop");
                ServiceHostAssert.Equal(1, fatal.Calls, "fatal boundary called once");
                ServiceHostAssert.True(
                    events.Contains(EngineServiceEventCodes.CallerRevertFailed),
                    "revert event");
                ServiceHostAssert.False(
                    events.Contains(EngineServiceEventCodes.ParentLost),
                    "no parent-loss event");
                listener.Dispose();
            });

            runner.Check("listener: a pipe creation failure is fail-closed", delegate
            {
                ServiceHostFakePipeFactory factory = new ServiceHostFakePipeFactory();
                factory.CreateOk = false;
                factory.Code = EngineProtocol.ErrorCodes.BoundaryBusy;
                ServiceHostFakeBackend backend = new ServiceHostFakeBackend(
                    ServiceHostTestData.ReadyStatus(ServiceHostTestData.Now()));
                EngineServiceSessionGate gate = NewGate(backend);
                EngineServiceTransportOptions options = ServiceHostTestData.TransportOptions();
                EngineServicePipeListener listener = new EngineServicePipeListener(
                    factory,
                    gate,
                    NewPolicy(),
                    new EngineServiceCleanThreadDispatcher(),
                    new ServiceHostFakeFatalBoundary(),
                    new ServiceHostFakeEvents(),
                    options);
                EngineServiceListenerResult result = Wait(
                    listener.RunAsync(CancellationToken.None),
                    5000);
                ServiceHostAssert.False(result.Ok, "listener failed");
                ServiceHostAssert.Equal(EngineServiceCleanup.Unknown, result.Cleanup, "cleanup unknown");
                ServiceHostAssert.Equal(1, factory.Calls, "one create attempt");
                ServiceHostAssert.False(
                    ServiceHostAssert.Wait(listener.Ready, 2000, "listener ready"),
                    "never ready");
                listener.Dispose();
            });

            runner.Check("listener: a long request budget does not widen the handshake deadline", delegate
            {
                // The handshake and the request loop share one native read
                // call. The handshake keeps its own shorter deadline. A long
                // request read budget must not extend it.
                ServiceHostFakePipe pipe = NewPipe();
                pipe.BlockReadUntilCancelled = true;
                ServiceHostFakePipeFactory factory = new ServiceHostFakePipeFactory();
                factory.Pipe = pipe;
                ServiceHostFakeBackend backend = new ServiceHostFakeBackend(
                    ServiceHostTestData.ReadyStatus(ServiceHostTestData.Now()));
                EngineServiceSessionGate gate = NewGate(backend);
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                EngineServiceTransportOptions options = ServiceHostTestData.TransportOptions();
                options.ConnectTimeout = TimeSpan.FromSeconds(1);
                options.HandshakeTimeout = TimeSpan.FromMilliseconds(250);
                options.RequestTimeout = TimeSpan.FromSeconds(5);

                EngineServicePipeListener listener = new EngineServicePipeListener(
                    factory,
                    gate,
                    NewPolicy(),
                    new EngineServiceCleanThreadDispatcher(),
                    new ServiceHostFakeFatalBoundary(),
                    events,
                    options);
                System.Diagnostics.Stopwatch watch =
                    System.Diagnostics.Stopwatch.StartNew();
                EngineServiceListenerResult result = Wait(
                    listener.RunAsync(CancellationToken.None),
                    5000);
                watch.Stop();

                ServiceHostAssert.True(result.Ok, "listener ok: " + result.Code);
                ServiceHostAssert.Equal(
                    EngineServiceStopReason.ParentLost,
                    result.StopReason,
                    "the handshake timeout is a parent loss");
                ServiceHostAssert.True(
                    watch.ElapsedMilliseconds < 1800,
                    "the handshake ended at its own deadline, not the long request budget");
                ServiceHostAssert.Equal(1, backend.Stops, "one stop");
                listener.Dispose();
            });
        }

        private static void AssertHandshakeFailure(
            Action<ServiceHostFakePipe> configure,
            string expectedEvent,
            bool expectRevert,
            bool expectTokenRead)
        {
            ServiceHostFakePipe pipe = NewPipe();
            configure(pipe);
            pipe.Inbound.Enqueue(ServiceHostTestData.Encode(ServiceHostTestData.HelloFields()));
            ServiceHostFakeBackend backend = new ServiceHostFakeBackend(
                ServiceHostTestData.ReadyStatus(ServiceHostTestData.Now()));
            EngineServiceSessionGate gate = NewGate(backend);
            ServiceHostFakeEvents events = new ServiceHostFakeEvents();
            WindowsServiceCallerPolicy policy = NewPolicy();

            EngineServicePipeServerHandshake handshake = NewHandshake(
                pipe,
                gate,
                policy,
                events);
            EngineServiceHandshakeResult result = Wait(
                handshake.RunAsync(CancellationToken.None),
                5000);

            ServiceHostAssert.False(result.Ok, "failure");
            ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.BoundaryAuthFailed, result.Code, "code");
            ServiceHostAssert.Equal(0, pipe.Written.Count, "no reply");
            ServiceHostAssert.Equal(expectRevert ? 1 : 0, CountCalls(pipe.Calls, "revert"), "revert");
            ServiceHostAssert.Equal(expectTokenRead ? 1 : 0, pipe.Token.Reads, "token reads");
            ServiceHostAssert.True(events.Contains(expectedEvent), "event " + expectedEvent);
            gate.Dispose();
        }

        private static int Position(List<string> calls, string value)
        {
            for (int index = 0; index < calls.Count; index++)
            {
                if (calls[index] == value)
                {
                    return index;
                }
            }
            return int.MaxValue;
        }

        private static int CountCalls(List<string> calls, string value)
        {
            int count = 0;
            for (int index = 0; index < calls.Count; index++)
            {
                if (calls[index] == value)
                {
                    count++;
                }
            }
            return count;
        }

        private static EngineServicePipeListener NewListener(
            ServiceHostFakePipeFactory factory,
            EngineServiceSessionGate gate,
            IEngineServiceEventSink events,
            EngineServiceTransportOptions options,
            IEngineServiceHostMonotonicClock clock)
        {
            return new EngineServicePipeListener(
                factory,
                gate,
                NewPolicy(),
                new EngineServiceCleanThreadDispatcher(),
                new ServiceHostFakeFatalBoundary(),
                events,
                options,
                clock);
        }

        private static EngineServicePipeServerHandshake NewHandshake(
            ServiceHostFakePipe pipe,
            EngineServiceSessionGate gate,
            WindowsServiceCallerPolicy policy,
            IEngineServiceEventSink events)
        {
            return new EngineServicePipeServerHandshake(
                pipe,
                gate,
                policy,
                new EngineServiceCleanThreadDispatcher(),
                new ServiceHostFakeFatalBoundary(),
                events,
                TimeSpan.FromSeconds(2));
        }

        private static ServiceHostFakePipe NewPipe()
        {
            ServiceHostFakePipe pipe = new ServiceHostFakePipe();
            pipe.Token.Identity = Identity(
                ServiceHostTestData.UserSid,
                EngineServiceImpersonationLevel.Identification);
            return pipe;
        }

        private static EngineServiceCallerIdentity Identity(
            string sid,
            EngineServiceImpersonationLevel level)
        {
            return new EngineServiceCallerIdentity(sid, 2, level, "", false);
        }

        private static WindowsServiceCallerPolicy NewPolicy()
        {
            return new WindowsServiceCallerPolicy(
                ServiceHostTestData.UserSid,
                new ServiceHostFakeAccountInspector(),
                TimeSpan.FromSeconds(1));
        }

        private static EngineServiceSessionGate NewGate(ServiceHostFakeBackend backend)
        {
            ServiceHostFakeClock clock = new ServiceHostFakeClock(ServiceHostTestData.Now());
            EngineServiceSession session = new EngineServiceSession(
                ServiceHostTestData.ServiceInstance,
                backend,
                clock,
                EngineServiceStateGate.FromRecord(
                    ServiceHostTestData.CleanRecord(clock.Now)),
                TimeSpan.FromSeconds(2));
            return new EngineServiceSessionGate(
                session,
                backend,
                TimeSpan.FromSeconds(2));
        }

        private static T Wait<T>(Task<T> task)
        {
            return ServiceHostAssert.Wait(task, 5000, "async check");
        }

        private static T Wait<T>(Task<T> task, int timeoutMilliseconds)
        {
            return ServiceHostAssert.Wait(task, timeoutMilliseconds, "async check");
        }
    }
}
