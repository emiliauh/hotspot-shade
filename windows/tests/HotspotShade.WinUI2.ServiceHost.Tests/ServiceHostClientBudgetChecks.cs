using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.ServiceHost.Tests
{
    // Hermetic checks for the per-operation client budget and the ambiguous
    // reply-read outcome. They use a fake client pipe and a fake SCM. They open
    // no pipe, create no process, and call no Win32 function.
    internal static class ServiceHostClientBudgetChecks
    {
        public static void Run(ServiceHostCheckRunner runner)
        {
            runner.Check("budgets: the client start and stop budgets outlive the service budgets", delegate
            {
                // The service start path can take the full service start
                // budget, and the client must not abort the reply before that
                // budget ends. One short budget also has to pay for the connect,
                // the server proof, and the reply write. A change to either
                // table must keep this relation.
                EngineServiceCallBudgets budgets = EngineServiceCallBudgets.Default;
                TimeSpan shortBudget = TimeSpan.FromMilliseconds(
                    EngineServiceCallBudgets.ShortMilliseconds);
                TimeSpan serviceStart = TimeSpan.FromMilliseconds(
                    EngineServiceTransportLimits.StartTimeoutMilliseconds);
                TimeSpan serviceStop = TimeSpan.FromMilliseconds(
                    EngineServiceTransportLimits.StopTimeoutMilliseconds);

                ServiceHostAssert.True(
                    budgets.StartBudget > serviceStart + shortBudget,
                    "the start budget outlives the service start budget");
                ServiceHostAssert.True(
                    budgets.StopBudget > serviceStop + shortBudget,
                    "the stop budget outlives the service stop budget");
                ServiceHostAssert.Equal(
                    TimeSpan.FromMilliseconds(EngineServiceTransportLimits.RequestTimeoutMilliseconds),
                    shortBudget,
                    "the short budget is the request-read budget");
                ServiceHostAssert.Equal(
                    TimeSpan.FromSeconds(5),
                    budgets.For(EngineProtocol.Operations.Hello),
                    "hello uses the short budget");
                ServiceHostAssert.Equal(
                    TimeSpan.FromSeconds(35),
                    budgets.For(EngineProtocol.Operations.Start),
                    "start uses the start budget");
                ServiceHostAssert.Equal(
                    TimeSpan.FromSeconds(25),
                    budgets.For(EngineProtocol.Operations.Stop),
                    "stop uses the stop budget");
            });

            runner.Check("budgets: the service start and stop timeouts are reserved, not enforced", delegate
            {
                // There is no reviewed launch seam to bound and the guarded
                // backend refuses every start. The stop path is bounded by the
                // session gate stop wait and the host stop budget. Both flags
                // are pinned so enabling one is a deliberate change with new
                // evidence.
                ServiceHostAssert.False(
                    EngineServiceTransportLimits.StartTimeoutEnforced,
                    "the start timeout is reserved");
                ServiceHostAssert.False(
                    EngineServiceTransportLimits.StopTimeoutEnforced,
                    "the stop timeout is reserved");
                ServiceHostAssert.Equal(
                    25000,
                    EngineServiceTransportLimits.StartTimeoutMilliseconds,
                    "reserved start literal");
                ServiceHostAssert.Equal(
                    15000,
                    EngineServiceTransportLimits.StopTimeoutMilliseconds,
                    "reserved stop literal");
            });

            runner.Check("channel: the per-operation budget reaches the client pipe unchanged", delegate
            {
                Fixture fixture = new Fixture();
                fixture.Pipe.Responses.Enqueue(SuccessFrame(EngineProtocol.Operations.Hello));
                fixture.Pipe.Responses.Enqueue(SuccessFrame(EngineProtocol.Operations.Start));

                EngineServiceChannelAnswer hello = Exchange(
                    fixture.Channel,
                    EngineProtocol.Operations.Hello,
                    TimeSpan.FromSeconds(5));
                ServiceHostAssert.True(hello.Frame != null, "hello answered");
                ServiceHostAssert.Equal(
                    TimeSpan.FromSeconds(5),
                    fixture.Pipe.LastReadBudget,
                    "hello read budget");
                ServiceHostAssert.Equal(
                    TimeSpan.FromSeconds(5),
                    fixture.Pipe.LastWriteBudget,
                    "hello write budget");

                EngineServiceChannelAnswer start = Exchange(
                    fixture.Channel,
                    EngineProtocol.Operations.Start,
                    TimeSpan.FromSeconds(35));
                ServiceHostAssert.True(start.Frame != null, "start answered");
                ServiceHostAssert.Equal(
                    TimeSpan.FromSeconds(35),
                    fixture.Pipe.LastReadBudget,
                    "the start reply is not cut at the short budget");
                ServiceHostAssert.Equal(
                    TimeSpan.FromSeconds(35),
                    fixture.Pipe.LastWriteBudget,
                    "start write budget");
                ServiceHostAssert.Equal(1, fixture.Factory.Calls, "one open for both frames");
                fixture.Channel.Dispose();
            });

            runner.Check("channel: the base channel form uses the short budget", delegate
            {
                Fixture fixture = new Fixture();
                fixture.Pipe.Responses.Enqueue(SuccessFrame(EngineProtocol.Operations.Hello));
                IEngineServiceChannel baseChannel = fixture.Channel;
                byte[] answer = ServiceHostAssert.Wait(
                    baseChannel.ExchangeAsync(
                        ServiceHostTestData.Encode(ServiceHostTestData.HelloFields()),
                        CancellationToken.None),
                    5000,
                    "base exchange");
                ServiceHostAssert.True(answer != null, "base answer");
                ServiceHostAssert.Equal(
                    TimeSpan.FromMilliseconds(EngineServiceCallBudgets.ShortMilliseconds),
                    fixture.Pipe.LastReadBudget,
                    "base read budget");
                fixture.Channel.Dispose();
            });

            runner.Check("channel: a partial reply read is ambiguous and closes the pipe", delegate
            {
                Fixture fixture = new Fixture();
                fixture.Pipe.ReadOk = false;
                fixture.Pipe.ReadOutcome = EngineServiceFrameReadOutcome.Partial;
                fixture.Pipe.ReadCode = EngineProtocol.ErrorCodes.EngineUnavailable;

                EngineServiceChannelAnswer answer = Exchange(
                    fixture.Channel,
                    EngineProtocol.Operations.Start,
                    TimeSpan.FromSeconds(35));

                ServiceHostAssert.True(answer.Frame == null, "no reply");
                ServiceHostAssert.True(answer.OutcomeUnknown, "the start may have been applied");
                ServiceHostAssert.True(answer.RequestWritten, "the request frame reached the pipe");
                ServiceHostAssert.False(answer.Transient, "not transient");
                ServiceHostAssert.Equal(
                    EngineServiceReplyReadProof.Partial,
                    answer.ReplyReadProof,
                    "the consumed byte is recorded");
                ServiceHostAssert.Equal(
                    EngineProtocol.ErrorCodes.EngineUnavailable,
                    answer.Code,
                    "code");
                ServiceHostAssert.True(fixture.Pipe.DisposeCalled, "the pipe is closed");
                ServiceHostAssert.Equal(1, fixture.Pipe.Writes.Count, "no replay");
                ServiceHostAssert.Equal(
                    EngineProtocol.ErrorCodes.EngineUnavailable,
                    fixture.Channel.LastFailureCode,
                    "failure code kept");

                EngineServiceChannelAnswer second = Exchange(
                    fixture.Channel,
                    EngineProtocol.Operations.Status,
                    TimeSpan.FromSeconds(5));
                ServiceHostAssert.True(second.Frame == null, "a failed channel refuses later calls");
                ServiceHostAssert.False(second.OutcomeUnknown, "a refused call sent nothing");
                ServiceHostAssert.Equal(1, fixture.Pipe.Writes.Count, "no second write");
                ServiceHostAssert.Equal(1, Count(fixture.Pipe.Calls, "read"), "no second read");
                fixture.Channel.Dispose();
            });

            runner.Check("channel: every failed reply read keeps its evidence", delegate
            {
                Fixture unknownFixture = new Fixture();
                unknownFixture.Pipe.ReadOk = false;
                unknownFixture.Pipe.ReadOutcome = EngineServiceFrameReadOutcome.Unknown;
                EngineServiceChannelAnswer unknown = Exchange(
                    unknownFixture.Channel,
                    EngineProtocol.Operations.Stop,
                    TimeSpan.FromSeconds(25));
                ServiceHostAssert.True(unknown.OutcomeUnknown, "an unproven read is ambiguous");
                ServiceHostAssert.Equal(
                    EngineServiceReplyReadProof.Unproven,
                    unknown.ReplyReadProof,
                    "unproven evidence");
                unknownFixture.Channel.Dispose();

                Fixture idleFixture = new Fixture();
                idleFixture.Pipe.ReadOk = false;
                idleFixture.Pipe.ReadOutcome = EngineServiceFrameReadOutcome.Idle;
                idleFixture.Pipe.ReadCode = EngineProtocol.ErrorCodes.Timeout;
                EngineServiceChannelAnswer idle = Exchange(
                    idleFixture.Channel,
                    EngineProtocol.Operations.Stop,
                    TimeSpan.FromSeconds(25));
                ServiceHostAssert.True(
                    idle.OutcomeUnknown,
                    "a zero-byte reply read still leaves a delivered stop ambiguous");
                ServiceHostAssert.Equal(
                    EngineServiceReplyReadProof.Missing,
                    idle.ReplyReadProof,
                    "no reply byte arrived");
                idleFixture.Channel.Dispose();

                Fixture failedFixture = new Fixture();
                failedFixture.Pipe.ReadOk = false;
                failedFixture.Pipe.ReadOutcome = EngineServiceFrameReadOutcome.Failed;
                EngineServiceChannelAnswer failed = Exchange(
                    failedFixture.Channel,
                    EngineProtocol.Operations.Status,
                    TimeSpan.FromSeconds(5));
                ServiceHostAssert.True(failed.OutcomeUnknown, "a refused read is not a clean refusal");
                ServiceHostAssert.Equal(
                    EngineServiceReplyReadProof.Unproven,
                    failed.ReplyReadProof,
                    "a refused read proves nothing");
                failedFixture.Channel.Dispose();
            });

            runner.Check("channel: a reply inside the budget is a validated success", delegate
            {
                Fixture fixture = new Fixture();
                fixture.Pipe.Responses.Enqueue(SuccessFrame(EngineProtocol.Operations.Start));
                EngineServiceChannelAnswer answer = Exchange(
                    fixture.Channel,
                    EngineProtocol.Operations.Start,
                    TimeSpan.FromSeconds(35));
                ServiceHostAssert.True(answer.Frame != null, "reply frame");
                ServiceHostAssert.False(answer.OutcomeUnknown, "not ambiguous");
                ServiceHostAssert.False(answer.Transient, "not transient");
                ServiceHostAssert.True(answer.RequestWritten, "written");
                ServiceHostAssert.Equal(
                    EngineServiceReplyReadProof.NoReplyRead,
                    answer.ReplyReadProof,
                    "no failed read");
                ServiceHostAssert.Equal("", fixture.Channel.LastFailureCode, "no failure");
                ServiceHostAssert.False(fixture.Pipe.DisposeCalled, "the pipe stays open");
                fixture.Channel.Dispose();
            });

            runner.Check("channel: a partial request write is ambiguous and closes the pipe", delegate
            {
                Fixture fixture = new Fixture();
                fixture.Pipe.WriteOk = false;
                fixture.Pipe.WriteCode = EngineProtocol.ErrorCodes.EngineUnavailable;
                EngineServiceChannelAnswer answer = Exchange(
                    fixture.Channel,
                    EngineProtocol.Operations.Start,
                    TimeSpan.FromSeconds(35));
                ServiceHostAssert.True(answer.Frame == null, "no reply");
                ServiceHostAssert.True(answer.OutcomeUnknown, "part of the frame may have arrived");
                ServiceHostAssert.False(answer.RequestWritten, "the whole frame did not arrive");
                ServiceHostAssert.Equal(
                    EngineServiceReplyReadProof.NoReplyRead,
                    answer.ReplyReadProof,
                    "no reply read ran");
                ServiceHostAssert.True(fixture.Pipe.DisposeCalled, "the pipe is closed");
                ServiceHostAssert.Equal(0, Count(fixture.Pipe.Calls, "read"), "no reply read");
                fixture.Channel.Dispose();
            });

            runner.Check("channel: a canceled write with no delivery evidence is unproven", delegate
            {
                // A pipe without the write-evidence seam cannot prove that a
                // failed write started no kernel operation. A cancellation
                // that lands inside the write must never become a clean
                // refusal.
                NoEvidenceClientPipe pipe = new NoEvidenceClientPipe();
                ServiceHostFakeClientPipeFactory factory = new ServiceHostFakeClientPipeFactory();
                factory.Pipe = pipe;
                EngineServiceServerProof proof = new EngineServiceServerProof(
                    RunningScm(),
                    new ServiceHostFakeEvents(),
                    ServiceHostTestData.ServiceImage);
                WindowsEngineServiceChannel channel = new WindowsEngineServiceChannel(
                    factory,
                    proof);
                try
                {
                    CancellationTokenSource canceled = new CancellationTokenSource();
                    pipe.OnWrite = delegate { canceled.Cancel(); };
                    EngineServiceChannelAnswer answer = ServiceHostAssert.Wait(
                        channel.ExchangeAsync(
                            RequestFrame(EngineProtocol.Operations.Start),
                            TimeSpan.FromSeconds(35),
                            canceled.Token),
                        5000,
                        "canceled write");
                    ServiceHostAssert.True(answer.Frame == null, "no reply");
                    ServiceHostAssert.True(answer.OutcomeUnknown, "the start may have been delivered");
                    ServiceHostAssert.False(answer.RequestWritten, "the whole frame is not known delivered");
                    ServiceHostAssert.True(pipe.DisposeCalled, "the pipe is closed");
                    ServiceHostAssert.Equal(0, Count(pipe.Calls, "read"), "no reply read");
                    canceled.Dispose();
                }
                finally
                {
                    channel.Dispose();
                }
            });

            runner.Check("channel: a write that provably started nothing is transient", delegate
            {
                // The pipe proves that no kernel write ran. Nothing reached the
                // pipe and the channel stays usable.
                Fixture fixture = new Fixture();
                fixture.Pipe.WriteOk = false;
                fixture.Pipe.WriteProof = EngineServiceRequestWriteProof.NotStarted;
                fixture.Pipe.WriteCode = EngineProtocol.ErrorCodes.Timeout;
                fixture.Pipe.Responses.Enqueue(SuccessFrame(EngineProtocol.Operations.Hello));

                EngineServiceChannelAnswer refused = Exchange(
                    fixture.Channel,
                    EngineProtocol.Operations.Start,
                    TimeSpan.FromSeconds(35));
                ServiceHostAssert.True(refused.Frame == null, "no reply");
                ServiceHostAssert.False(refused.OutcomeUnknown, "nothing was delivered");
                ServiceHostAssert.True(refused.Transient, "no pipe operation ran");
                ServiceHostAssert.False(fixture.Pipe.DisposeCalled, "the pipe stays usable");
                ServiceHostAssert.Equal(0, Count(fixture.Pipe.Calls, "read"), "no reply read");

                fixture.Pipe.WriteOk = true;
                EngineServiceChannelAnswer retry = Exchange(
                    fixture.Channel,
                    EngineProtocol.Operations.Hello,
                    TimeSpan.FromSeconds(5));
                ServiceHostAssert.True(retry.Frame != null, "the retry succeeded");
                ServiceHostAssert.Equal(1, fixture.Pipe.Writes.Count, "one delivered write");
                fixture.Channel.Dispose();
            });

            runner.Check("channel: a write that provably delivered nothing is a clean refusal", delegate
            {
                Fixture fixture = new Fixture();
                fixture.Pipe.WriteOk = false;
                fixture.Pipe.WriteProof = EngineServiceRequestWriteProof.NotDelivered;
                fixture.Pipe.WriteCode = EngineProtocol.ErrorCodes.Busy;
                EngineServiceChannelAnswer answer = Exchange(
                    fixture.Channel,
                    EngineProtocol.Operations.Start,
                    TimeSpan.FromSeconds(35));
                ServiceHostAssert.True(answer.Frame == null, "no reply");
                ServiceHostAssert.False(
                    answer.OutcomeUnknown,
                    "a proven zero-delivery write is a clean refusal");
                ServiceHostAssert.False(answer.RequestWritten, "the frame was not delivered");
                ServiceHostAssert.True(fixture.Pipe.DisposeCalled, "the failed transport is closed");
                ServiceHostAssert.Equal(0, Count(fixture.Pipe.Calls, "read"), "no reply read");
                fixture.Channel.Dispose();
            });

            runner.Check("channel: a write that may have delivered is never a clean refusal", delegate
            {
                Fixture fixture = new Fixture();
                fixture.Pipe.WriteOk = false;
                fixture.Pipe.WriteProof = EngineServiceRequestWriteProof.Unproven;
                fixture.Pipe.WriteCode = EngineProtocol.ErrorCodes.Timeout;
                CancellationTokenSource canceled = new CancellationTokenSource();
                fixture.Pipe.OnWrite = delegate { canceled.Cancel(); };
                EngineServiceChannelAnswer answer = ServiceHostAssert.Wait(
                    fixture.Channel.ExchangeAsync(
                        RequestFrame(EngineProtocol.Operations.Start),
                        TimeSpan.FromSeconds(35),
                        canceled.Token),
                    5000,
                    "canceled write");
                ServiceHostAssert.True(answer.OutcomeUnknown, "the start may already be applied");
                ServiceHostAssert.False(answer.RequestWritten, "the whole frame is not known delivered");
                ServiceHostAssert.True(fixture.Pipe.DisposeCalled, "the pipe is closed");
                canceled.Dispose();
                fixture.Channel.Dispose();
            });

            runner.Check("channel: an expired budget starts no pipe call", delegate
            {
                Fixture fixture = new Fixture();
                EngineServiceChannelAnswer answer = Exchange(
                    fixture.Channel,
                    EngineProtocol.Operations.Start,
                    TimeSpan.Zero);
                ServiceHostAssert.True(answer.Frame == null, "no reply");
                ServiceHostAssert.True(answer.Transient, "no pipe operation ran");
                ServiceHostAssert.False(answer.OutcomeUnknown, "nothing was delivered");
                ServiceHostAssert.Equal(
                    EngineProtocol.ErrorCodes.Timeout,
                    answer.Code,
                    "timeout code");
                ServiceHostAssert.Equal(0, fixture.Factory.Calls, "no pipe opened");
                ServiceHostAssert.Equal(0, fixture.Pipe.Calls.Count, "no pipe call");
                fixture.Channel.Dispose();
            });

            runner.Check("channel: a failed proof after the reply is ambiguous", delegate
            {
                Fixture fixture = new Fixture();
                fixture.Scm.States.Enqueue(new EngineServiceScmState(
                    EngineServiceBoundary.ServiceName,
                    700,
                    4,
                    ServiceHostTestData.ServiceCommand));
                fixture.Scm.States.Enqueue(new EngineServiceScmState(
                    EngineServiceBoundary.ServiceName,
                    700,
                    1,
                    ServiceHostTestData.ServiceCommand));
                fixture.Pipe.Responses.Enqueue(SuccessFrame(EngineProtocol.Operations.Stop));
                EngineServiceChannelAnswer answer = Exchange(
                    fixture.Channel,
                    EngineProtocol.Operations.Stop,
                    TimeSpan.FromSeconds(25));
                ServiceHostAssert.True(answer.Frame == null, "the unproven reply is not used");
                ServiceHostAssert.True(answer.OutcomeUnknown, "the stop may already have run");
                ServiceHostAssert.True(answer.RequestWritten, "written");
                ServiceHostAssert.True(fixture.Pipe.DisposeCalled, "the pipe is closed");
                fixture.Channel.Dispose();
            });

            runner.Check("channel: a busy gate is transient and keeps the pipe", delegate
            {
                Fixture fixture = new Fixture();
                fixture.Pipe.Responses.Enqueue(SuccessFrame(EngineProtocol.Operations.Hello));
                fixture.Pipe.ReadEntered = new ManualResetEventSlim(false);
                fixture.Pipe.ReadGate = new ManualResetEventSlim(false);

                Task<EngineServiceChannelAnswer> first = Task.Run(delegate
                {
                    return fixture.Channel.ExchangeAsync(
                        RequestFrame(EngineProtocol.Operations.Hello),
                        TimeSpan.FromSeconds(5),
                        CancellationToken.None);
                });
                ServiceHostAssert.True(
                    fixture.Pipe.ReadEntered.Wait(2000),
                    "the first exchange reached the reply read");

                EngineServiceChannelAnswer busy = Exchange(
                    fixture.Channel,
                    EngineProtocol.Operations.Status,
                    TimeSpan.FromSeconds(5));
                ServiceHostAssert.True(busy.Frame == null, "busy");
                ServiceHostAssert.True(busy.Transient, "a busy gate is transient");
                ServiceHostAssert.False(busy.OutcomeUnknown, "nothing was written");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Busy, busy.Code, "busy code");

                fixture.Pipe.ReadGate.Set();
                EngineServiceChannelAnswer completed = ServiceHostAssert.Wait(
                    first,
                    5000,
                    "first exchange");
                ServiceHostAssert.True(completed.Frame != null, "the first exchange finished");
                ServiceHostAssert.Equal(1, fixture.Pipe.Writes.Count, "one write");
                ServiceHostAssert.False(fixture.Pipe.DisposeCalled, "the pipe survives a busy gate");
                fixture.Channel.Dispose();
            });

            runner.Check("channel: a caller that stops before the gate is transient", delegate
            {
                Fixture fixture = new Fixture();
                CancellationTokenSource canceled = new CancellationTokenSource();
                canceled.Cancel();
                EngineServiceChannelAnswer answer = ServiceHostAssert.Wait(
                    fixture.Channel.ExchangeAsync(
                        RequestFrame(EngineProtocol.Operations.Status),
                        TimeSpan.FromSeconds(5),
                        canceled.Token),
                    2000,
                    "canceled exchange");
                ServiceHostAssert.True(answer.Frame == null, "no reply");
                ServiceHostAssert.True(answer.Transient, "the gate was never entered");
                ServiceHostAssert.False(answer.OutcomeUnknown, "nothing was written");
                ServiceHostAssert.Equal(0, fixture.Pipe.Writes.Count, "no write");
                ServiceHostAssert.False(fixture.Pipe.DisposeCalled, "the pipe stays usable");
                fixture.Channel.Dispose();
            });

            runner.Check("channel: a caller that stops after the write leaves an ambiguous outcome", delegate
            {
                Fixture fixture = new Fixture();
                CancellationTokenSource canceled = new CancellationTokenSource();
                fixture.Pipe.OnRead = delegate { canceled.Cancel(); };
                fixture.Pipe.ReadWaitsForCancellation = true;
                EngineServiceChannelAnswer answer = ServiceHostAssert.Wait(
                    fixture.Channel.ExchangeAsync(
                        RequestFrame(EngineProtocol.Operations.Stop),
                        TimeSpan.FromSeconds(25),
                        canceled.Token),
                    5000,
                    "canceled exchange");
                ServiceHostAssert.True(answer.Frame == null, "no reply");
                ServiceHostAssert.True(answer.OutcomeUnknown, "the stop may have run");
                ServiceHostAssert.True(answer.RequestWritten, "the stop request was delivered");
                ServiceHostAssert.True(fixture.Pipe.DisposeCalled, "the pipe is closed");
                ServiceHostAssert.Equal(1, fixture.Pipe.Writes.Count, "one write");
                fixture.Channel.Dispose();
            });

            runner.Check("channel: a failed hello reply keeps the pipe so a retry can bind", delegate
            {
                // The bound-hello rule lives in the core session. This check
                // proves the transport layer does not close the pipe after a
                // valid failure reply, so the same session can retry.
                Fixture fixture = new Fixture();
                fixture.Pipe.Responses.Enqueue(FailureFrame(EngineProtocol.ErrorCodes.Forbidden));
                fixture.Pipe.Responses.Enqueue(SuccessFrame(EngineProtocol.Operations.Hello));

                EngineServiceChannelAnswer first = Exchange(
                    fixture.Channel,
                    EngineProtocol.Operations.Hello,
                    TimeSpan.FromSeconds(5));
                ServiceHostAssert.True(first.Frame != null, "the failure reply arrived");
                ServiceHostAssert.False(fixture.Pipe.DisposeCalled, "the pipe stays open");

                EngineServiceChannelAnswer second = Exchange(
                    fixture.Channel,
                    EngineProtocol.Operations.Hello,
                    TimeSpan.FromSeconds(5));
                ServiceHostAssert.True(second.Frame != null, "the retry was answered");
                ServiceHostAssert.Equal(2, fixture.Pipe.Writes.Count, "two hellos");
                ServiceHostAssert.Equal(1, fixture.Factory.Calls, "one pipe for the retry");
                ServiceHostAssert.False(second.OutcomeUnknown, "the retry is not ambiguous");
                fixture.Channel.Dispose();
            });

            runner.Check("client: a start reply inside the long budget succeeds over the channel", delegate
            {
                Fixture fixture = new Fixture();
                fixture.Pipe.Responses.Enqueue(SuccessFrame(EngineProtocol.Operations.Start));
                EngineServiceClient client = new EngineServiceClient(
                    fixture.Channel,
                    EngineServiceCallBudgets.Default);
                EngineReply reply = ServiceHostAssert.Wait(
                    client.SendAsync(
                        new EngineRequest(
                            EngineProtocol.Operations.Start,
                            ServiceHostTestData.Session,
                            true),
                        CancellationToken.None),
                    5000,
                    "start");
                ServiceHostAssert.True(reply.Ok, "start ok: " + reply.Code);
                ServiceHostAssert.False(reply.OutcomeUnknown, "not ambiguous");
                ServiceHostAssert.Equal(
                    TimeSpan.FromSeconds(35),
                    fixture.Pipe.LastReadBudget,
                    "the client passed the start budget to the channel");
                ServiceHostAssert.Equal(
                    TimeSpan.FromSeconds(35),
                    fixture.Pipe.LastWriteBudget,
                    "the client passed the start budget to the write");
                ServiceHostAssert.Wait(client.CloseAsync(), 2000, "close");
                fixture.Channel.Dispose();
            });

            runner.Check("client: a reply that reaches the budget is an ambiguous timeout", delegate
            {
                Fixture fixture = new Fixture();
                fixture.Pipe.ReadWaitsForCancellation = true;
                EngineServiceClient client = new EngineServiceClient(
                    fixture.Channel,
                    EngineServiceCallBudgets.Uniform(TimeSpan.FromMilliseconds(60)));
                EngineReply reply = ServiceHostAssert.Wait(
                    client.SendAsync(
                        new EngineRequest(
                            EngineProtocol.Operations.Start,
                            ServiceHostTestData.Session,
                            true),
                        CancellationToken.None),
                    5000,
                    "bounded start");
                ServiceHostAssert.False(reply.Ok, "the start is not a success");
                ServiceHostAssert.True(reply.OutcomeUnknown, "the start may have been applied");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Timeout, reply.Code, "code");
                ServiceHostAssert.True(fixture.Pipe.DisposeCalled, "the pipe is closed");
                ServiceHostAssert.Equal(1, fixture.Pipe.Writes.Count, "no replay");
                ServiceHostAssert.Wait(client.CloseAsync(), 2000, "close");
                fixture.Channel.Dispose();
            });

            runner.Check("client: a failed status read is not reported as a clean stop", delegate
            {
                Fixture fixture = new Fixture();
                fixture.Pipe.ReadOk = false;
                fixture.Pipe.ReadOutcome = EngineServiceFrameReadOutcome.Partial;
                EngineServiceClient client = new EngineServiceClient(
                    fixture.Channel,
                    EngineServiceCallBudgets.Default);
                EngineReply reply = ServiceHostAssert.Wait(
                    client.SendAsync(
                        new EngineRequest(
                            EngineProtocol.Operations.Stop,
                            ServiceHostTestData.Session,
                            false),
                        CancellationToken.None),
                    5000,
                    "stop");
                ServiceHostAssert.False(reply.Ok, "the stop is not confirmed");
                ServiceHostAssert.True(reply.OutcomeUnknown, "the stop may have run");
                ServiceHostAssert.Equal(
                    EngineProtocol.ErrorCodes.EngineUnavailable,
                    reply.Code,
                    "code");
                ServiceHostAssert.Wait(client.CloseAsync(), 2000, "close");
                fixture.Channel.Dispose();
            });
        }

        private static EngineServiceChannelAnswer Exchange(
            WindowsEngineServiceChannel channel,
            string operation,
            TimeSpan budget)
        {
            return ServiceHostAssert.Wait(
                channel.ExchangeAsync(RequestFrame(operation), budget, CancellationToken.None),
                5000,
                "exchange " + operation);
        }

        private static ServiceHostFakeScmInspector RunningScm()
        {
            ServiceHostFakeScmInspector scm = new ServiceHostFakeScmInspector();
            scm.State = new EngineServiceScmState(
                EngineServiceBoundary.ServiceName,
                700,
                4,
                ServiceHostTestData.ServiceCommand);
            return scm;
        }

        private static byte[] RequestFrame(string operation)
        {
            Dictionary<string, string> fields = new Dictionary<string, string>(StringComparer.Ordinal);
            fields[EngineProtocol.Keys.Version] = "1";
            fields[EngineProtocol.Keys.Operation] = operation;
            fields[EngineProtocol.Keys.Session] = ServiceHostTestData.Session;
            return ServiceHostTestData.Encode(fields);
        }

        private static byte[] SuccessFrame(string operation)
        {
            Dictionary<string, string> fields = new Dictionary<string, string>(StringComparer.Ordinal);
            fields[EngineProtocol.Keys.Version] = "1";
            fields[EngineProtocol.Keys.Ok] = "1";
            if (operation == EngineProtocol.Operations.Hello)
            {
                fields[EngineServiceStatusKeys.Instance] = ServiceHostTestData.ServiceInstance;
                fields[EngineServiceStatusKeys.Engine] = "ready";
            }
            return ServiceHostTestData.Encode(fields);
        }

        private static byte[] FailureFrame(string code)
        {
            Dictionary<string, string> fields = new Dictionary<string, string>(StringComparer.Ordinal);
            fields[EngineProtocol.Keys.Version] = "1";
            fields[EngineProtocol.Keys.Ok] = "0";
            fields[EngineProtocol.Keys.Code] = code;
            return ServiceHostTestData.Encode(fields);
        }

        private static int Count(List<string> values, string value)
        {
            int total = 0;
            for (int index = 0; index < values.Count; index++)
            {
                if (string.Equals(values[index], value, StringComparison.Ordinal))
                {
                    total++;
                }
            }
            return total;
        }

        // One channel over a fake client pipe and a fake SCM. Nothing in this
        // fixture opens a pipe or queries a service.
        private sealed class Fixture
        {
            public readonly ServiceHostFakeClientPipe Pipe = new ServiceHostFakeClientPipe();
            public readonly ServiceHostFakeClientPipeFactory Factory =
                new ServiceHostFakeClientPipeFactory();
            public readonly ServiceHostFakeScmInspector Scm = new ServiceHostFakeScmInspector();
            public readonly WindowsEngineServiceChannel Channel;

            public Fixture()
            {
                Scm.State = new EngineServiceScmState(
                    EngineServiceBoundary.ServiceName,
                    700,
                    4,
                    ServiceHostTestData.ServiceCommand);
                Pipe.ServerProcessId = 700;
                Pipe.OwnerSid = EngineServiceBoundary.SystemSid;
                Factory.Pipe = Pipe;
                EngineServiceServerProof proof = new EngineServiceServerProof(
                    Scm,
                    new ServiceHostFakeEvents(),
                    ServiceHostTestData.ServiceImage);
                Channel = new WindowsEngineServiceChannel(Factory, proof);
            }
        }

        // A client pipe with no write-evidence seam. It models an older
        // transport that reports only success or failure.
        private sealed class NoEvidenceClientPipe : IEngineServiceClientPipe
        {
            public readonly List<string> Calls = new List<string>();
            public bool DisposeCalled;
            public Action OnWrite;

            public bool TryReadFrame(
                TimeSpan budget,
                CancellationToken cancellationToken,
                out byte[] frame,
                out EngineServiceFrameReadOutcome outcome,
                out string code)
            {
                Calls.Add("read");
                frame = null;
                outcome = EngineServiceFrameReadOutcome.Failed;
                code = EngineProtocol.ErrorCodes.EngineUnavailable;
                return false;
            }

            public bool TryWriteFrame(
                byte[] frame,
                TimeSpan budget,
                CancellationToken cancellationToken,
                out string code)
            {
                Calls.Add("write");
                Action onWrite = OnWrite;
                if (onWrite != null)
                {
                    onWrite();
                }
                code = EngineProtocol.ErrorCodes.Timeout;
                return false;
            }

            public bool TryGetServerProcessId(out int processId)
            {
                processId = 700;
                return true;
            }

            public bool TryGetOwnerSid(out string sid)
            {
                sid = EngineServiceBoundary.SystemSid;
                return true;
            }

            public void Dispose()
            {
                DisposeCalled = true;
            }
        }
    }
}
