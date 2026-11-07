using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.ServiceHost.Tests
{
    internal static class ServiceHostServerProofChecks
    {
        public static void Run(ServiceHostCheckRunner runner)
        {
            runner.Check("server proof: SCM image parser requires an explicit executable name", delegate
            {
                string image;
                ServiceHostAssert.True(WindowsServicePathPolicy.TryScmExecutable(
                    "  C:\\HotspotShade\\service.EXE --instance sample", out image), "unquoted image");
                ServiceHostAssert.Equal("C:\\HotspotShade\\service.EXE", image, "first token");
                ServiceHostAssert.True(WindowsServicePathPolicy.TryScmExecutable(
                    "\"C:\\Program Files\\service.exe\"\t--instance sample", out image), "quoted image");
                ServiceHostAssert.Equal("C:\\Program Files\\service.exe", image, "quoted token");
                ServiceHostAssert.False(WindowsServicePathPolicy.TryScmExecutable(
                    "C:\\Program --instance sample", out image), "extensionless image refused");
                ServiceHostAssert.False(WindowsServicePathPolicy.TryScmExecutable(
                    "\"C:\\Program\"", out image), "quoted extensionless image refused");
            });

            runner.Check("server proof: SCM command line identifies only its executable", delegate
            {
                ServiceHostFakeScmInspector scm = RunningScm();
                EngineServiceServerProof proof = new EngineServiceServerProof(
                    scm, new ServiceHostFakeEvents(), ServiceHostTestData.ServiceImage);
                int processId;
                string code;
                ServiceHostAssert.True(proof.TryVerifyBeforeConnect(out processId, out code),
                    "quoted image and service arguments: " + code);
                string[] rejected =
                {
                    ServiceHostTestData.ServiceImage + " --instance sample",
                    "\"" + ServiceHostTestData.ServiceImage + "\"suffix --instance sample",
                    "\"" + ServiceHostTestData.ServiceImage,
                    "\"C:\\Other\\service.exe\" --service-binary \"" + ServiceHostTestData.ServiceImage + "\"",
                    "\"" + ServiceHostTestData.ServiceImage + " \" --instance sample",
                    "\"" + ServiceHostTestData.ServiceImage + "\u00A0\" --instance sample",
                    "\"" + ServiceHostTestData.ServiceImage + "\"\n--instance sample"
                };
                foreach (string command in rejected)
                {
                    scm.State = new EngineServiceScmState(EngineServiceBoundary.ServiceName, 700, 4, command);
                    ServiceHostAssert.False(proof.TryVerifyBeforeConnect(out processId, out code),
                        "unsafe or mismatched SCM command must be refused");
                }
            });

            runner.Check("server proof: running service, matching pid, SYSTEM owner, and exact path pass", delegate
            {
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                ServiceHostFakeScmInspector scm = RunningScm();
                EngineServiceServerProof proof = new EngineServiceServerProof(
                    scm,
                    events,
                    ServiceHostTestData.ServiceImage);
                int processId;
                string code;
                ServiceHostAssert.True(
                    proof.TryVerifyBeforeConnect(out processId, out code),
                    "before connect: " + code);
                ServiceHostAssert.Equal(700, processId, "scm pid");

                ServiceHostFakeClientPipe pipe = new ServiceHostFakeClientPipe();
                ServiceHostAssert.True(
                    proof.TryVerifyConnectedServer(pipe, processId, out code),
                    "connected: " + code);
                ServiceHostAssert.True(
                    proof.TryVerifyAfterExchange(processId, out code),
                    "recheck: " + code);
                ServiceHostAssert.Equal(2, scm.Calls, "two scm queries");
                ServiceHostAssert.True(pipe.Calls.Contains("server_pid"), "pid checked");
                ServiceHostAssert.True(pipe.Calls.Contains("owner_sid"), "owner checked");
            });

            runner.Check("server proof: not running, no pid, a path mismatch, and an owner mismatch fail closed", delegate
            {
                ServiceHostFakeScmInspector scm = RunningScm();
                EngineServiceServerProof proof = new EngineServiceServerProof(
                    scm,
                    new ServiceHostFakeEvents(),
                    ServiceHostTestData.ServiceImage);
                int processId;
                string code;

                scm.State = new EngineServiceScmState(
                    EngineServiceBoundary.ServiceName,
                    700,
                    1,
                    ServiceHostTestData.ServiceCommand);
                ServiceHostAssert.False(
                    proof.TryVerifyBeforeConnect(out processId, out code),
                    "not running");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.EngineUnavailable, code, "running code");

                scm.State = new EngineServiceScmState(
                    EngineServiceBoundary.ServiceName,
                    0,
                    4,
                    ServiceHostTestData.ServiceCommand);
                ServiceHostAssert.False(
                    proof.TryVerifyBeforeConnect(out processId, out code),
                    "no pid");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.EngineUnavailable, code, "pid code");

                scm.State = new EngineServiceScmState(
                    EngineServiceBoundary.ServiceName,
                    700,
                    4,
                    "D:\\Other\\service.exe");
                ServiceHostAssert.False(
                    proof.TryVerifyBeforeConnect(out processId, out code),
                    "path mismatch");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.BoundaryAuthFailed, code, "path code");

                scm.State = new EngineServiceScmState(
                    EngineServiceBoundary.ServiceName,
                    700,
                    4,
                    ServiceHostTestData.ServiceCommand);
                ServiceHostFakeClientPipe pipe = new ServiceHostFakeClientPipe();
                pipe.ServerProcessId = 701;
                ServiceHostAssert.False(
                    proof.TryVerifyConnectedServer(pipe, 700, out code),
                    "pid mismatch");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.BoundaryAuthFailed, code, "server pid code");

                pipe = new ServiceHostFakeClientPipe();
                pipe.OwnerSid = "S-1-5-32-544";
                ServiceHostAssert.False(
                    proof.TryVerifyConnectedServer(pipe, 700, out code),
                    "owner mismatch");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.BoundaryAuthFailed, code, "owner code");

                ServiceHostAssert.False(
                    proof.TryVerifyConnectedServer(null, 700, out code),
                    "null pipe");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.BoundaryAuthFailed, code, "null code");
            });

            runner.Check("server proof: a stopped service after the connection fails closed", delegate
            {
                ServiceHostFakeScmInspector scm = RunningScm();
                EngineServiceServerProof proof = new EngineServiceServerProof(
                    scm,
                    new ServiceHostFakeEvents(),
                    ServiceHostTestData.ServiceImage);
                scm.State = new EngineServiceScmState(
                    EngineServiceBoundary.ServiceName,
                    700,
                    1,
                    ServiceHostTestData.ServiceCommand);
                string code;
                ServiceHostAssert.False(
                    proof.TryVerifyAfterExchange(700, out code),
                    "stopped after exchange");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.EngineUnavailable, code, "code");
            });

            runner.Check("channel: a proven connection writes and reads one frame", delegate
            {
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                ServiceHostFakeScmInspector scm = RunningScm();
                ServiceHostFakeClientPipe pipe = new ServiceHostFakeClientPipe();
                byte[] response = FailureFrame(EngineProtocol.ErrorCodes.EngineUnavailable);
                pipe.Responses.Enqueue(response);
                ServiceHostFakeClientPipeFactory factory = new ServiceHostFakeClientPipeFactory();
                factory.Pipe = pipe;
                EngineServiceServerProof proof = new EngineServiceServerProof(
                    scm,
                    events,
                    ServiceHostTestData.ServiceImage);
                WindowsEngineServiceChannel channel = new WindowsEngineServiceChannel(factory, proof);

                byte[] request = ServiceHostTestData.Encode(ServiceHostTestData.HelloFields());
                byte[] answer = ServiceHostAssert.Wait(
                    channel.ExchangeAsync(request, CancellationToken.None),
                    5000,
                    "exchange");
                ServiceHostAssert.True(answer != null, "answer");
                ServiceHostAssert.Equal(1, factory.Calls, "one open");
                ServiceHostAssert.Equal(1, pipe.Writes.Count, "one write");
                ServiceHostAssert.Equal(1, Count(pipe.Calls, "read"), "one read");
                ServiceHostAssert.Equal(2, scm.Calls, "proof before and after");
                ServiceHostAssert.Equal("", channel.LastFailureCode, "no failure");
                ServiceHostAssert.Wait(channel.CloseAsync(), 2000, "close");
                ServiceHostAssert.True(pipe.DisposeCalled, "closed");
                channel.Dispose();
            });

            runner.Check("channel: a failed server proof sends no frame and does not open the pipe", delegate
            {
                ServiceHostFakeScmInspector scm = RunningScm();
                scm.State = new EngineServiceScmState(
                    EngineServiceBoundary.ServiceName,
                    700,
                    1,
                    ServiceHostTestData.ServiceCommand);
                ServiceHostFakeClientPipeFactory factory = new ServiceHostFakeClientPipeFactory();
                ServiceHostFakeClientPipe pipe = new ServiceHostFakeClientPipe();
                factory.Pipe = pipe;
                EngineServiceServerProof proof = new EngineServiceServerProof(
                    scm,
                    new ServiceHostFakeEvents(),
                    ServiceHostTestData.ServiceImage);
                WindowsEngineServiceChannel channel = new WindowsEngineServiceChannel(factory, proof);
                byte[] answer = ServiceHostAssert.Wait(
                    channel.ExchangeAsync(
                        ServiceHostTestData.Encode(ServiceHostTestData.HelloFields()),
                        CancellationToken.None),
                    5000,
                    "exchange");
                ServiceHostAssert.True(answer == null, "no answer");
                ServiceHostAssert.Equal(0, factory.Calls, "no open");
                ServiceHostAssert.Equal(0, pipe.Writes.Count, "no write");
                ServiceHostAssert.Equal(
                    EngineProtocol.ErrorCodes.EngineUnavailable,
                    channel.LastFailureCode,
                    "failure code");
                channel.Dispose();
            });

            runner.Check("channel: a server pid mismatch sends no frame and closes the pipe", delegate
            {
                ServiceHostFakeScmInspector scm = RunningScm();
                ServiceHostFakeClientPipe pipe = new ServiceHostFakeClientPipe();
                pipe.ServerProcessId = 701;
                ServiceHostFakeClientPipeFactory factory = new ServiceHostFakeClientPipeFactory();
                factory.Pipe = pipe;
                EngineServiceServerProof proof = new EngineServiceServerProof(
                    scm,
                    new ServiceHostFakeEvents(),
                    ServiceHostTestData.ServiceImage);
                WindowsEngineServiceChannel channel = new WindowsEngineServiceChannel(factory, proof);
                byte[] answer = ServiceHostAssert.Wait(
                    channel.ExchangeAsync(
                        ServiceHostTestData.Encode(ServiceHostTestData.HelloFields()),
                        CancellationToken.None),
                    5000,
                    "exchange");
                ServiceHostAssert.True(answer == null, "no answer");
                ServiceHostAssert.Equal(1, factory.Calls, "opened");
                ServiceHostAssert.Equal(0, pipe.Writes.Count, "no write");
                ServiceHostAssert.True(pipe.DisposeCalled, "pipe closed");
                ServiceHostAssert.Equal(
                    EngineProtocol.ErrorCodes.BoundaryAuthFailed,
                    channel.LastFailureCode,
                    "failure code");
                channel.Dispose();
            });

            runner.Check("channel: a failed recheck closes the pipe and refuses later requests", delegate
            {
                ServiceHostFakeScmInspector scm = RunningScm();
                scm.States.Enqueue(new EngineServiceScmState(
                    EngineServiceBoundary.ServiceName,
                    700,
                    4,
                    ServiceHostTestData.ServiceCommand));
                scm.States.Enqueue(new EngineServiceScmState(
                    EngineServiceBoundary.ServiceName,
                    700,
                    1,
                    ServiceHostTestData.ServiceCommand));
                ServiceHostFakeClientPipe pipe = new ServiceHostFakeClientPipe();
                pipe.Responses.Enqueue(FailureFrame(EngineProtocol.ErrorCodes.EngineUnavailable));
                ServiceHostFakeClientPipeFactory factory = new ServiceHostFakeClientPipeFactory();
                factory.Pipe = pipe;
                EngineServiceServerProof proof = new EngineServiceServerProof(
                    scm,
                    new ServiceHostFakeEvents(),
                    ServiceHostTestData.ServiceImage);
                WindowsEngineServiceChannel channel = new WindowsEngineServiceChannel(factory, proof);
                byte[] answer = ServiceHostAssert.Wait(
                    channel.ExchangeAsync(
                        ServiceHostTestData.Encode(ServiceHostTestData.HelloFields()),
                        CancellationToken.None),
                    5000,
                    "first");
                ServiceHostAssert.True(answer == null, "first failed");
                ServiceHostAssert.Equal(1, pipe.Writes.Count, "frame sent before recheck");
                ServiceHostAssert.True(pipe.DisposeCalled, "pipe closed");
                ServiceHostAssert.Equal(
                    EngineProtocol.ErrorCodes.EngineUnavailable,
                    channel.LastFailureCode,
                    "failure code");

                byte[] second = ServiceHostAssert.Wait(
                    channel.ExchangeAsync(
                        ServiceHostTestData.Encode(ServiceHostTestData.HelloFields()),
                        CancellationToken.None),
                    5000,
                    "second");
                ServiceHostAssert.True(second == null, "second refused");
                ServiceHostAssert.Equal(1, pipe.Writes.Count, "no second frame");
                channel.Dispose();
            });

            runner.Check("channel: the core client reads a framed failure through the channel", delegate
            {
                ServiceHostFakeScmInspector scm = RunningScm();
                ServiceHostFakeClientPipe pipe = new ServiceHostFakeClientPipe();
                pipe.Responses.Enqueue(FailureFrame(EngineProtocol.ErrorCodes.NotPaired));
                ServiceHostFakeClientPipeFactory factory = new ServiceHostFakeClientPipeFactory();
                factory.Pipe = pipe;
                EngineServiceServerProof proof = new EngineServiceServerProof(
                    scm,
                    new ServiceHostFakeEvents(),
                    ServiceHostTestData.ServiceImage);
                WindowsEngineServiceChannel channel = new WindowsEngineServiceChannel(factory, proof);
                EngineServiceClient client = new EngineServiceClient(channel, TimeSpan.FromSeconds(2));
                EngineReply reply = ServiceHostAssert.Wait(
                    client.SendAsync(
                        new EngineRequest(EngineProtocol.Operations.Hello, ServiceHostTestData.Session, false),
                        CancellationToken.None),
                    5000,
                    "client");
                ServiceHostAssert.False(reply.Ok, "failure reply");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.NotPaired, reply.Code, "code");
                ServiceHostAssert.Wait(client.CloseAsync(), 2000, "client close");
                channel.Dispose();
            });
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

        private static int Count(List<string> values, string value)
        {
            int count = 0;
            for (int index = 0; index < values.Count; index++)
            {
                if (values[index] == value)
                {
                    count++;
                }
            }
            return count;
        }

        private static byte[] FailureFrame(string code)
        {
            Dictionary<string, string> fields = new Dictionary<string, string>(StringComparer.Ordinal);
            fields[EngineProtocol.Keys.Version] = "1";
            fields[EngineProtocol.Keys.Ok] = "0";
            fields[EngineProtocol.Keys.Code] = code;
            return ServiceHostTestData.Encode(fields);
        }
    }
}
