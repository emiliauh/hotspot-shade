using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.ServiceHost.Tests
{
    // Virtual time drives the production frame source and overlapped wait. No
    // native API, real pipe, service, device, route, or network is used.
    internal static class ServiceHostReadLivenessChecks
    {
        public static void Run(ServiceHostCheckRunner runner)
        {
            runner.Check("read liveness: a healthy first byte after five seconds is not canceled", delegate
            {
                Rig rig = new Rig();
                byte[] expected = ServiceHostTestData.Encode(ServiceHostTestData.StatusRequestFields());
                rig.Native.Add(6000, expected);
                EngineServiceReadDeadline deadline = rig.RequestDeadline();
                byte[] frame;
                EngineServiceFrameReadOutcome outcome;
                string code;
                ServiceHostAssert.True(rig.Read(deadline, CancellationToken.None, out frame, out outcome, out code), "complete frame");
                ServiceHostAssert.Equal(6000L, rig.Clock.Now, "healthy six second boundary wait");
                ServiceHostAssert.Equal(expected.Length, frame.Length, "full payload");
                ServiceHostAssert.Equal(0, rig.Native.CancelCalls, "no five second cancellation");
                ServiceHostAssert.Equal(EngineServiceReadExpiry.None, deadline.Expiry, "not expired");
                ServiceHostAssert.Equal(0, rig.Quarantine.HeldCount, "completion proved");
                ServiceHostAssert.Equal(1, rig.Native.RequestedCounts[0], "one byte boundary read");
            });

            runner.Check("read liveness: frame can finish beyond idle horizon within first-byte budget", delegate
            {
                Rig rig = new Rig();
                byte[] expected = ServiceHostTestData.Encode(ServiceHostTestData.StatusRequestFields());
                rig.Native.Add(59999, new byte[] { expected[0] });
                rig.Native.Add(64000, Slice(expected, 1, expected.Length - 1));
                byte[] frame;
                EngineServiceFrameReadOutcome outcome;
                string code;
                ServiceHostAssert.True(rig.Read(rig.RequestDeadline(), CancellationToken.None, out frame, out outcome, out code), "frame completes");
                ServiceHostAssert.Equal(64000L, rig.Clock.Now, "frame phase crossed original horizon");
                ServiceHostAssert.Equal(0, rig.Native.CancelCalls, "no premature boundary abort");
            });

            foreach (long wallJump in new long[] { 86400000, -86400000 })
            {
                runner.Check("read liveness: wall-clock step cannot change boundary expiry: " + wallJump, delegate
                {
                    Rig rig = new Rig();
                    rig.Native.OnWait = delegate { rig.Wall = rig.Wall.AddMilliseconds(wallJump); };
                    EngineServiceReadDeadline deadline = rig.RequestDeadline();
                    AssertFailed(rig, deadline, EngineServiceFrameReadOutcome.Unknown, EngineServiceReadExpiry.Boundary);
                    ServiceHostAssert.Equal(60000L, rig.Clock.Now, "absolute monotonic sixty seconds");
                    ServiceHostAssert.Equal(0, rig.WallReads, "server read never consulted UTC");
                    ServiceHostAssert.Equal(1, rig.Native.ReadCalls, "no cancellation/replay loop");
                    ServiceHostAssert.Equal(1, rig.Native.CancelCalls, "one deadline cancellation");
                    ServiceHostAssert.Equal(0, rig.Quarantine.HeldCount, "failed completion proves lifetime only");
                });
            }

            foreach (int prefixBytes in new int[] { 1, 4, 7 })
            {
                runner.Check("read liveness: partial prefix/body has one fixed deadline: " + prefixBytes, delegate
                {
                    Rig rig = new Rig();
                    byte[] expected = ServiceHostTestData.Encode(ServiceHostTestData.StatusRequestFields());
                    rig.Native.Add(6000, Slice(expected, 0, prefixBytes));
                    EngineServiceReadDeadline deadline = rig.RequestDeadline();
                    AssertFailed(rig, deadline, EngineServiceFrameReadOutcome.Partial, EngineServiceReadExpiry.Frame);
                    ServiceHostAssert.Equal(11000L, rig.Clock.Now, "five seconds from first byte");
                    ServiceHostAssert.Equal(1, rig.Native.CancelCalls, "one frame cancellation");
                });
            }

            runner.Check("read liveness: trickle cannot re-arm the frame deadline", delegate
            {
                Rig rig = new Rig();
                byte[] expected = ServiceHostTestData.Encode(ServiceHostTestData.StatusRequestFields());
                for (int i = 0; i < 7; i++) { rig.Native.Add(6000 + 1000 * i, new byte[] { expected[i] }); }
                AssertFailed(rig, rig.RequestDeadline(), EngineServiceFrameReadOutcome.Partial, EngineServiceReadExpiry.Frame);
                ServiceHostAssert.Equal(11000L, rig.Clock.Now, "trickle stops at original frame horizon");
            });

            foreach (uint? transferred in new uint?[] { null, 0, 1 })
            {
                runner.Check("read liveness: deadline cancellation race never replays: " + transferred, delegate
                {
                    Rig rig = new Rig();
                    rig.Native.CancelTransfer = transferred;
                    EngineServiceReadDeadline deadline = rig.RequestDeadline();
                    AssertFailed(rig, deadline,
                        transferred == 0 ? EngineServiceFrameReadOutcome.Idle : EngineServiceFrameReadOutcome.Unknown,
                        EngineServiceReadExpiry.Boundary);
                    ServiceHostAssert.Equal(1, rig.Native.CancelCalls, "one cancel");
                    ServiceHostAssert.Equal(1, rig.Native.CloseCalls, "proven completion releases event");
                    ServiceHostAssert.Equal(0, rig.Quarantine.ReservedCount, "reservation released");
                });
            }

            runner.Check("read liveness: a ready byte exactly at the boundary loses to deadline", delegate
            {
                Rig rig = new Rig();
                rig.Native.Add(60000, new byte[] { 0 });
                rig.Native.CancelTransfer = 1;
                AssertFailed(rig, rig.RequestDeadline(), EngineServiceFrameReadOutcome.Unknown, EngineServiceReadExpiry.Boundary);
                ServiceHostAssert.Equal(1, rig.Native.ReadCalls, "no replay after successful racing transfer");
            });

            foreach (bool incomplete in new[] { false, true })
            {
                runner.Check("read liveness: unproven cancellation quarantines: " + incomplete, delegate
                {
                    Rig rig = new Rig();
                    rig.Native.ProofMissing = !incomplete;
                    rig.Native.CompletionIncomplete = incomplete;
                    AssertFailed(rig, rig.RequestDeadline(), EngineServiceFrameReadOutcome.Unknown, EngineServiceReadExpiry.Boundary);
                    ServiceHostAssert.Equal(1, rig.Quarantine.HeldCount, "one context held");
                    ServiceHostAssert.Equal(0, rig.Native.CloseCalls, "event is not freed");
                    ServiceHostAssert.Equal(WindowsOverlappedQuarantine.DiagnosticCompletionUnproven,
                        rig.Quarantine.LastDiagnostic, "fixed quarantine diagnostic");
                    // The retained allocation is still writable by the fake kernel.
                    Marshal.WriteByte(rig.Native.Buffer, 0, 0x5a);
                    ServiceHostAssert.Equal((byte)0x5a, Marshal.ReadByte(rig.Native.Buffer), "buffer retained");
                });
            }

            runner.Check("read liveness: handshake uses its own fixed budget despite a late first byte", delegate
            {
                Rig rig = new Rig();
                byte[] expected = ServiceHostTestData.Encode(ServiceHostTestData.HelloFields());
                rig.Native.Add(4000, new byte[] { expected[0] });
                rig.Native.Add(6000, Slice(expected, 1, expected.Length - 1));
                AssertFailed(rig, EngineServiceReadDeadline.Handshake(rig.Clock, TimeSpan.FromSeconds(5)),
                    EngineServiceFrameReadOutcome.Partial, EngineServiceReadExpiry.Handshake);
                ServiceHostAssert.Equal(5000L, rig.Clock.Now, "first byte did not extend handshake");
            });

            runner.Check("read cross-layer: silent handshake reports expiry and unknown transfer separately", delegate
            {
                Rig rig = new Rig();
                ServiceHostFakeBackend backend = new ServiceHostFakeBackend(ServiceHostTestData.ReadyStatus(ServiceHostTestData.Now()));
                ServiceHostFakeClock coreClock = new ServiceHostFakeClock(ServiceHostTestData.Now());
                EngineServiceSession core = new EngineServiceSession(ServiceHostTestData.ServiceInstance, backend, coreClock,
                    EngineServiceStateGate.FromRecord(ServiceHostTestData.CleanRecord(coreClock.Now)), TimeSpan.FromSeconds(2));
                using (EngineServiceSessionGate gate = new EngineServiceSessionGate(core, backend, TimeSpan.FromSeconds(2)))
                {
                    NativeServerPipe pipe = new NativeServerPipe(rig, new List<string>());
                    EngineServiceEventBuffer events = new EngineServiceEventBuffer();
                    EngineServicePipeServerHandshake handshake = new EngineServicePipeServerHandshake(pipe, gate,
                        new WindowsServiceCallerPolicy(ServiceHostTestData.UserSid, new ServiceHostFakeAccountInspector(), TimeSpan.FromSeconds(1)),
                        new EngineServiceCleanThreadDispatcher(), new ServiceHostFakeFatalBoundary(), events,
                        TimeSpan.FromSeconds(5), rig.Clock, null);
                    EngineServiceHandshakeResult result = ServiceHostAssert.Wait(handshake.RunAsync(CancellationToken.None), 5000, "handshake");
                    ServiceHostAssert.False(result.Ok, "handshake refused");
                    ServiceHostAssert.True(events.Contains(EngineServiceEventCodes.FrameTimeout), "deadline expiry");
                    ServiceHostAssert.True(events.Contains(EngineServiceEventCodes.FrameInvalid), "unknown transfer");
                    ServiceHostAssert.Equal(5000L, rig.Clock.Now, "fixed handshake budget");
                    ServiceHostAssert.Equal(0, pipe.Auth.WrittenCount, "no reply");
                    ServiceHostAssert.False(pipe.Auth.Calls.Contains("impersonate"), "no authentication after failed read");
                }
            });

            runner.Check("read liveness: stop racing synchronous completion wins without claiming idle", delegate
            {
                Rig rig = new Rig();
                rig.Native.Add(0, new byte[] { 0 });
                using (CancellationTokenSource stop = new CancellationTokenSource())
                {
                    rig.Native.OnCompletion = delegate { stop.Cancel(); };
                    byte[] frame;
                    EngineServiceFrameReadOutcome outcome;
                    string code;
                    ServiceHostAssert.False(rig.Read(rig.RequestDeadline(), stop.Token, out frame, out outcome, out code), "stop wins");
                    ServiceHostAssert.Equal(EngineServiceFrameReadOutcome.Unknown, outcome, "consumed racing byte is not idle");
                    ServiceHostAssert.Equal(0, rig.Quarantine.HeldCount, "completion still proved");
                    ServiceHostAssert.Equal(1, rig.Native.CloseCalls, "event released after proof");
                }
            });

            runner.Check("read liveness: stop cancellation wins before boundary expiry", delegate
            {
                Rig rig = new Rig();
                using (CancellationTokenSource stop = new CancellationTokenSource())
                {
                    rig.Native.OnWait = delegate { stop.Cancel(); };
                    EngineServiceReadDeadline deadline = rig.RequestDeadline();
                    byte[] frame;
                    EngineServiceFrameReadOutcome outcome;
                    string code;
                    ServiceHostAssert.False(rig.Read(deadline, stop.Token, out frame, out outcome, out code), "stop closes read");
                    ServiceHostAssert.Equal(EngineServiceFrameReadOutcome.Unknown, outcome, "no idle claim");
                    ServiceHostAssert.Equal(EngineServiceReadExpiry.None, deadline.Expiry, "no boundary expiry");
                    ServiceHostAssert.Equal(1, rig.Native.CancelCalls, "one cancel");
                }
            });

            foreach (string scenario in new[] { "poll", "valid_failure", "silent", "invalid", "failed_reply", "cancel_backend", "cancel_write", "stop_after_frame" })
            {
                runner.Check("read cross-layer: long backend outcome and next boundary: " + scenario, delegate
                {
                    Rig rig = new Rig();
                    rig.Native.Add(0, ServiceHostTestData.Encode(ServiceHostTestData.HelloFields()));
                    rig.Native.Add(0, ServiceHostTestData.Encode(ServiceHostTestData.StartFields(true)));
                    byte[] next = scenario == "invalid"
                        ? ServiceHostTestData.Encode(new Dictionary<string, string> { { "invalid", "request" } })
                        : ServiceHostTestData.Encode(ServiceHostTestData.StatusRequestFields());
                    if (scenario != "silent") { rig.Native.Add(61000, next); }
                    ServiceHostFakeBackend backend = new ServiceHostFakeBackend(ServiceHostTestData.ReadyStatus(ServiceHostTestData.Now()));
                    backend.BlockStart = true;
                    backend.StartOk = scenario != "valid_failure";
                    List<string> order = new List<string>();
                    backend.Order = order;
                    NativeServerPipe pipe = new NativeServerPipe(rig, order);
                    ServiceHostFakeClock coreClock = new ServiceHostFakeClock(ServiceHostTestData.Now());
                    EngineServiceSession core = new EngineServiceSession(ServiceHostTestData.ServiceInstance, backend, coreClock,
                        EngineServiceStateGate.FromRecord(ServiceHostTestData.CleanRecord(coreClock.Now)), TimeSpan.FromSeconds(2));
                    core.SetCredentialHeld(true);
                    EngineServiceSessionGate gate = new EngineServiceSessionGate(core, backend, TimeSpan.FromSeconds(2));
                    EngineServiceEventBuffer events = new EngineServiceEventBuffer();
                    ServiceHostFakePipeFactory factory = new ServiceHostFakePipeFactory();
                    factory.Pipe = pipe;
                    using (CancellationTokenSource stop = new CancellationTokenSource())
                    {
                        pipe.Auth.OnWrite = delegate
                        {
                            if (pipe.Auth.WrittenCount > 0)
                            {
                                rig.Clock.Now += 1000;
                                if (scenario == "failed_reply") { pipe.Auth.WriteOk = false; }
                                if (scenario == "cancel_write") { stop.Cancel(); }
                            }
                        };
                        pipe.AfterRead = delegate
                        {
                            if (scenario == "stop_after_frame" && rig.Clock.Now == 62000) { stop.Cancel(); }
                        };
                        EngineServicePipeListener listener = new EngineServicePipeListener(factory, gate,
                            new WindowsServiceCallerPolicy(ServiceHostTestData.UserSid, new ServiceHostFakeAccountInspector(), TimeSpan.FromSeconds(1)),
                            new EngineServiceCleanThreadDispatcher(), new ServiceHostFakeFatalBoundary(), events,
                            ServiceHostTestData.TransportOptions(), rig.Clock);
                        Task<EngineServiceListenerResult> run = listener.RunAsync(stop.Token);
                        ServiceHostAssert.Wait(backend.StartEntered.Task, 2000, "backend entered");
                        int readsBefore = rig.Native.ReadCalls;
                        rig.Clock.Now = 61000;
                        ServiceHostAssert.False(run.IsCompleted, "backend remains in progress beyond idle budget");
                        ServiceHostAssert.Equal(1, pipe.Auth.WrittenCount, "no reply or in-progress credit");
                        ServiceHostAssert.Equal(readsBefore, rig.Native.ReadCalls, "no concurrent boundary read");
                        if (scenario == "cancel_backend") { stop.Cancel(); }
                        backend.ReleaseStart.TrySetResult(true);
                        EngineServiceListenerResult result = ServiceHostAssert.Wait(run, 5000, "listener");
                        bool poll = scenario == "poll" || scenario == "valid_failure";
                        bool boundary = poll || scenario == "silent";
                        bool canceled = scenario == "cancel_backend" || scenario == "cancel_write" || scenario == "stop_after_frame";
                        ServiceHostAssert.True(result.Ok, "one clean cleanup");
                        ServiceHostAssert.Equal(poll ? 3 : scenario == "cancel_backend" || scenario == "failed_reply" || scenario == "cancel_write" ? 1 : 2,
                            result.HandledRequests, "only completed requests counted before stop");
                        ServiceHostAssert.Equal(poll ? 3 : scenario == "cancel_backend" || scenario == "failed_reply" ? 1 : 2,
                            pipe.Auth.WrittenCount, "only permitted replies written");
                        ServiceHostAssert.Equal(canceled ? EngineServiceStopReason.ServiceStop : EngineServiceStopReason.ParentLost,
                            result.StopReason, "stop reason follows outcome");
                        ServiceHostAssert.Equal(boundary, events.Contains(EngineServiceEventCodes.BoundaryReadTimeout), "only silence after a completed request reaches expiry");
                        ServiceHostAssert.Equal(scenario == "invalid", events.Contains(EngineServiceEventCodes.FrameInvalid), "invalid frame closes without reply");
                        ServiceHostAssert.Equal(scenario == "failed_reply", events.Contains(EngineServiceEventCodes.PipeWriteFailed), "failed write closes before next read");
                        ServiceHostAssert.Equal(poll ? 123000L : scenario == "silent" ? 122000L : scenario == "cancel_backend" ? 61000L : 62000L,
                            rig.Clock.Now, "silence is bounded from final response; failures do not wait again");
                        if (scenario == "failed_reply" || scenario == "cancel_backend" || scenario == "cancel_write")
                        {
                            ServiceHostAssert.Equal(readsBefore, rig.Native.ReadCalls, "no queued poll read after failure or stop");
                        }
                        if (scenario == "valid_failure")
                        {
                            Dictionary<string, string> replyFields;
                            string code;
                            EngineReply reply;
                            ServiceHostAssert.True(EngineServiceFrame.TryDecode(pipe.Auth.Written[1], pipe.Auth.Written[1].Length, out replyFields, out code), "decode failure reply");
                            ServiceHostAssert.True(EngineWire.TryReadReply(replyFields, out reply, out code), "validated failure reply");
                            ServiceHostAssert.False(reply.Ok, "backend refusal still completed a validated request");
                        }
                        ServiceHostAssert.Equal(1, backend.Starts, "one backend start");
                        ServiceHostAssert.Equal(1, backend.Stops, "one backend stop");
                        ServiceHostAssert.Equal(1, pipe.DisposeCalls, "one pipe disposal");
                        ServiceHostAssert.Equal("backend_stop", order[0], "stop first");
                        ServiceHostAssert.Equal("pipe_dispose", order[1], "dispose after stop");
                        listener.Dispose();
                        ServiceHostAssert.Equal(1, backend.Stops, "no duplicate stop on dispose");
                    }
                });
            }

            foreach (bool pending in new[] { false, true })
            {
                foreach (bool atFirstByte in new[] { false, true })
                {
                    runner.Check("read liveness: collection crossing deadline closes: " + pending + "/" + atFirstByte, delegate
                    {
                        Rig rig = new Rig();
                        byte[] expected = ServiceHostTestData.Encode(ServiceHostTestData.StatusRequestFields());
                        if (atFirstByte) { rig.Native.Add(pending ? 1 : 0, expected); }
                        else
                        {
                            rig.Native.Add(0, Slice(expected, 0, 4));
                            rig.Native.Add(pending ? 1 : 0, Slice(expected, 4, expected.Length - 4));
                        }
                        int completion = 0;
                        rig.Native.OnCompletion = delegate
                        {
                            completion++;
                            if (completion == (atFirstByte ? 1 : 3)) { rig.Clock.Now = atFirstByte ? 60000 : 5000; }
                        };
                        AssertFailed(rig, rig.RequestDeadline(), atFirstByte ? EngineServiceFrameReadOutcome.Unknown : EngineServiceFrameReadOutcome.Partial,
                            atFirstByte ? EngineServiceReadExpiry.Boundary : EngineServiceReadExpiry.Frame);
                        ServiceHostAssert.Equal(0, rig.Native.CancelCalls, "completed operation needs no cancellation");
                        ServiceHostAssert.Equal(0, rig.Quarantine.HeldCount, "completion proof still frees memory");
                    });
                }
            }

            foreach (bool cancelAtBoundary in new[] { false, true })
            {
                foreach (bool quarantine in new[] { false, true })
                {
                    runner.Check("read cross-layer: hidden cadence, silence, stop and disposal: " + cancelAtBoundary + "/" + quarantine, delegate
                    {
                        Rig rig = new Rig();
                        rig.Native.ProofMissing = quarantine;
                        rig.Native.Add(0, ServiceHostTestData.Encode(ServiceHostTestData.HelloFields()));
                        rig.Native.Add(6000, ServiceHostTestData.Encode(ServiceHostTestData.StatusRequestFields()));
                        rig.Native.Add(12000, ServiceHostTestData.Encode(ServiceHostTestData.StatusRequestFields()));
                        ServiceHostFakeBackend backend = new ServiceHostFakeBackend(ServiceHostTestData.ReadyStatus(ServiceHostTestData.Now()));
                        List<string> order = new List<string>();
                        backend.Order = order;
                        NativeServerPipe pipe = new NativeServerPipe(rig, order);
                        ServiceHostFakePipeFactory factory = new ServiceHostFakePipeFactory();
                        factory.Pipe = pipe;
                        ServiceHostFakeClock coreClock = new ServiceHostFakeClock(ServiceHostTestData.Now());
                        EngineServiceSession core = new EngineServiceSession(ServiceHostTestData.ServiceInstance, backend, coreClock,
                            EngineServiceStateGate.FromRecord(ServiceHostTestData.CleanRecord(coreClock.Now)), TimeSpan.FromSeconds(2));
                        EngineServiceSessionGate gate = new EngineServiceSessionGate(core, backend, TimeSpan.FromSeconds(2));
                        EngineServiceEventBuffer events = new EngineServiceEventBuffer();
                        using (CancellationTokenSource stop = new CancellationTokenSource())
                        {
                            if (cancelAtBoundary)
                            {
                                rig.Native.OnWait = delegate { if (rig.Clock.Now >= 72000) { stop.Cancel(); } };
                            }
                            EngineServicePipeListener listener = new EngineServicePipeListener(factory, gate,
                                new WindowsServiceCallerPolicy(ServiceHostTestData.UserSid, new ServiceHostFakeAccountInspector(), TimeSpan.FromSeconds(1)),
                                new EngineServiceCleanThreadDispatcher(), new ServiceHostFakeFatalBoundary(), events,
                                ServiceHostTestData.TransportOptions(), rig.Clock);
                            EngineServiceListenerResult result = ServiceHostAssert.Wait(listener.RunAsync(stop.Token), 5000, "listener");
                            ServiceHostAssert.True(result.Ok, "cleanup succeeds: " + result.Code);
                            ServiceHostAssert.Equal(3, result.HandledRequests, "hello and two healthy hidden polls");
                            ServiceHostAssert.Equal(3, pipe.Auth.WrittenCount, "all replies written before silence");
                            ServiceHostAssert.Equal(1, backend.Stops, "single backend stop");
                            ServiceHostAssert.Equal(cancelAtBoundary ? EngineServiceStopReason.ServiceStop : EngineServiceStopReason.ParentLost,
                                result.StopReason, "claim reason");
                            ServiceHostAssert.Equal(1, pipe.DisposeCalls, "single disposal");
                            ServiceHostAssert.Equal("backend_stop", order[0], "stop first");
                            ServiceHostAssert.Equal("pipe_dispose", order[1], "pipe disposal follows stop");
                            ServiceHostAssert.Equal(!cancelAtBoundary, events.Contains(EngineServiceEventCodes.BoundaryReadTimeout), "expiry diagnostic");
                            ServiceHostAssert.False(events.Contains(EngineServiceEventCodes.IdleTimeout), "unknown is never proven idle");
                            ServiceHostAssert.Equal(quarantine ? 1 : 0, rig.Quarantine.HeldCount, "quarantine preserved through disposal");
                            ServiceHostAssert.Equal(72000L + (quarantine ? 5000 : 0), rig.Clock.Now, "deadline plus proof wait only");
                            listener.Dispose();
                            ServiceHostAssert.Equal(1, backend.Stops, "dispose never duplicates stop");
                        }
                    });
                }
            }
        }

        private static void AssertFailed(Rig rig, EngineServiceReadDeadline deadline,
            EngineServiceFrameReadOutcome expected, EngineServiceReadExpiry expiry)
        {
            byte[] frame;
            EngineServiceFrameReadOutcome outcome;
            string code;
            ServiceHostAssert.False(rig.Read(deadline, CancellationToken.None, out frame, out outcome, out code), "frame rejected");
            ServiceHostAssert.Equal(expected, outcome, "transfer evidence");
            ServiceHostAssert.Equal(expiry, deadline.Expiry, "expiry cause");
            ServiceHostAssert.True(frame == null, "no frame returned");
        }

        private static byte[] Slice(byte[] bytes, int offset, int count)
        {
            byte[] part = new byte[count];
            Buffer.BlockCopy(bytes, offset, part, 0, count);
            return part;
        }

        private sealed class Rig
        {
            public readonly ServiceHostFakeMonotonicClock Clock = new ServiceHostFakeMonotonicClock();
            public readonly WindowsOverlappedQuarantine Quarantine = new WindowsOverlappedQuarantine(4);
            public readonly ScheduledNative Native;
            public readonly WindowsPipeIoEnvironment Environment;
            public DateTimeOffset Wall = ServiceHostTestData.Now();
            public int WallReads;

            public Rig()
            {
                Native = new ScheduledNative(Clock);
                Environment = new WindowsPipeIoEnvironment(Native, Quarantine, delegate { WallReads++; return Wall; });
            }

            public EngineServiceReadDeadline RequestDeadline()
            {
                EngineServiceIdleGuard guard = new EngineServiceIdleGuard(Clock, TimeSpan.FromSeconds(60));
                guard.MarkRequestCompleted();
                return guard.CreateReadDeadline(TimeSpan.FromSeconds(5));
            }

            public bool Read(EngineServiceReadDeadline deadline, CancellationToken stop,
                out byte[] frame, out EngineServiceFrameReadOutcome outcome, out string code)
            {
                return WindowsNamedPipeIo.TryReadFrame(new IntPtr(1), deadline, stop,
                    out frame, out outcome, out code, Environment);
            }
        }

        private sealed class NativeServerPipe : IEngineServicePipeConnection
        {
            private readonly Rig rig;
            private readonly List<string> order;
            public readonly ServiceHostFakePipe Auth = new ServiceHostFakePipe();
            public int DisposeCalls;
            public Action AfterRead;

            public NativeServerPipe(Rig rig, List<string> order)
            {
                this.rig = rig;
                this.order = order;
                Auth.Token.Identity = new EngineServiceCallerIdentity(ServiceHostTestData.UserSid, 2,
                    EngineServiceImpersonationLevel.Identification, "", false);
            }
            public bool TryConnect(CancellationToken token, out string code) { code = ""; return true; }
            public bool TryReadFrame(EngineServiceReadDeadline deadline, CancellationToken token,
                out byte[] frame, out EngineServiceFrameReadOutcome outcome, out string code)
            {
                bool ok = rig.Read(deadline, token, out frame, out outcome, out code);
                if (AfterRead != null) { AfterRead(); }
                return ok;
            }
            public bool TryWriteFrame(byte[] frame, CancellationToken token, out string code) { return Auth.TryWriteFrame(frame, token, out code); }
            public bool TryImpersonateClient(out string code) { return Auth.TryImpersonateClient(out code); }
            public bool TryOpenThreadToken(out IEngineServiceCallerToken token, out string code) { return Auth.TryOpenThreadToken(out token, out code); }
            public bool TryRevertToSelfAndVerify(out string code) { return Auth.TryRevertToSelfAndVerify(out code); }
            public bool TryGetClientProcessId(out int id) { return Auth.TryGetClientProcessId(out id); }
            public void Disconnect() { }
            public void Dispose() { DisposeCalls++; order.Add("pipe_dispose"); }
        }

        private sealed class ScheduledNative : IWindowsPipeNative
        {
            private sealed class Chunk
            {
                public long At;
                public byte[] Bytes;
                public int Offset;
            }
            private readonly ServiceHostFakeMonotonicClock clock;
            private readonly Queue<Chunk> chunks = new Queue<Chunk>();
            private int requested;
            private bool canceled;
            public IntPtr Buffer;
            public Action OnWait;
            public Action OnCompletion;
            public bool ProofMissing;
            public bool CompletionIncomplete;
            public uint? CancelTransfer;
            public int ReadCalls;
            public int CancelCalls;
            public int CloseCalls;
            public readonly List<int> RequestedCounts = new List<int>();

            public ScheduledNative(ServiceHostFakeMonotonicClock clock) { this.clock = clock; }
            public void Add(long at, byte[] bytes) { chunks.Enqueue(new Chunk { At = at, Bytes = bytes }); }
            public IntPtr CreateEventW(IntPtr attributes, int manual, int initial, string name) { return new IntPtr(7); }
            public bool ConnectNamedPipe(IntPtr pipe, IntPtr overlapped) { throw new InvalidOperationException("not used"); }
            public bool WriteFile(IntPtr file, IntPtr buffer, uint count, IntPtr overlapped) { throw new InvalidOperationException("not used"); }
            public int GetLastError() { return WindowsPipeNativeMethods.ErrorIoPending; }
            public bool ReadFile(IntPtr file, IntPtr buffer, uint count, IntPtr overlapped)
            {
                ReadCalls++;
                RequestedCounts.Add((int)count);
                Buffer = buffer;
                requested = (int)count;
                canceled = false;
                return chunks.Count > 0 && chunks.Peek().At <= clock.Now;
            }
            public uint WaitForSingleObject(IntPtr handle, uint milliseconds)
            {
                if (canceled)
                {
                    if (ProofMissing) { clock.Now += milliseconds; return WindowsPipeNativeMethods.WaitTimeout; }
                    return WindowsPipeNativeMethods.WaitObject0;
                }
                long next = chunks.Count > 0 ? chunks.Peek().At : long.MaxValue;
                clock.Now = Math.Min(clock.Now + milliseconds, next);
                if (OnWait != null) { OnWait(); }
                return next <= clock.Now ? WindowsPipeNativeMethods.WaitObject0 : WindowsPipeNativeMethods.WaitTimeout;
            }
            public bool CancelIoEx(IntPtr file, IntPtr overlapped) { CancelCalls++; canceled = true; return false; }
            public WindowsPipeNativeResult GetOverlappedResult(IntPtr file, IntPtr overlapped, bool wait)
            {
                if (canceled)
                {
                    return new WindowsPipeNativeResult {
                        Ok = CancelTransfer.HasValue && !CompletionIncomplete,
                        CountKnown = true, Transferred = CancelTransfer ?? 0,
                        Error = CompletionIncomplete ? WindowsPipeNativeMethods.ErrorIoIncomplete : WindowsPipeNativeMethods.ErrorOperationAborted
                    };
                }
                if (OnCompletion != null) { OnCompletion(); }
                Chunk chunk = chunks.Peek();
                int count = Math.Min(requested, chunk.Bytes.Length - chunk.Offset);
                Marshal.Copy(chunk.Bytes, chunk.Offset, Buffer, count);
                chunk.Offset += count;
                if (chunk.Offset == chunk.Bytes.Length) { chunks.Dequeue(); }
                return new WindowsPipeNativeResult { Ok = true, CountKnown = true, Transferred = (uint)count };
            }
            public bool CloseHandle(IntPtr handle) { CloseCalls++; return true; }
        }
    }
}
