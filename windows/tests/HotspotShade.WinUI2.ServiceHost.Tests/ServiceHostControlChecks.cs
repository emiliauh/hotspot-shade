using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;
using HotspotShade.WinUI2.ServiceHost;

namespace HotspotShade.WinUI2.ServiceHost.Tests
{
    internal static class ServiceHostControlChecks
    {
        public static void Run(ServiceHostCheckRunner runner)
        {
            runner.Check("control: the session key descriptor is exactly 64 hex bytes and one newline", delegate
            {
                string text = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
                EngineControlSessionKey key;
                string code;
                ServiceHostAssert.True(
                    EngineControlSessionKey.TryReadFrom(
                        new MemoryStream(Encoding.ASCII.GetBytes(text + "\n")),
                        out key,
                        out code),
                    "lower case");
                ServiceHostAssert.Equal(EngineControlLimits.SessionKeyBytes, key.CopyBytes().Length, "length");
                ServiceHostAssert.Contains(key.ToString(), "redacted", "redacted text");
                ServiceHostAssert.DoesNotContain(key.ToString(), text.Substring(0, 8), "no key bytes");

                MemoryStream written = new MemoryStream();
                ServiceHostAssert.True(key.TryWriteTo(written), "key write");
                byte[] writtenBytes = written.ToArray();
                ServiceHostAssert.Equal(65, writtenBytes.Length, "key text length");
                ServiceHostAssert.Equal((byte)'\n', writtenBytes[64], "key newline");
                ServiceHostAssert.Equal(
                    text,
                    Encoding.ASCII.GetString(writtenBytes, 0, 64),
                    "key text round trip");
                EngineControlSessionKey roundTrip;
                ServiceHostAssert.True(
                    EngineControlSessionKey.TryReadFrom(
                        new MemoryStream(writtenBytes),
                        out roundTrip,
                        out code),
                    "key descriptor round trip");
                ServiceHostAssert.True(
                    EngineControlProof.FixedTimeEquals(
                        key.CopyBytes(),
                        roundTrip.CopyBytes()),
                    "key bytes round trip");
                roundTrip.Dispose();

                key.Dispose();
                ServiceHostAssert.Equal(0, key.CopyBytes().Length, "disposed key");
                ServiceHostAssert.False(key.TryWriteTo(new MemoryStream()), "disposed key write");

                ServiceHostAssert.True(
                    EngineControlSessionKey.TryReadFrom(
                        new MemoryStream(Encoding.ASCII.GetBytes(text.ToUpperInvariant() + "\n")),
                        out key,
                        out code),
                    "upper case");
                key.Dispose();

                ServiceHostAssert.False(
                    EngineControlSessionKey.TryReadFrom(
                        new MemoryStream(Encoding.ASCII.GetBytes(text)),
                        out key,
                        out code),
                    "missing newline");
                ServiceHostAssert.False(
                    EngineControlSessionKey.TryReadFrom(
                        new MemoryStream(Encoding.ASCII.GetBytes(text.Substring(1) + "\n")),
                        out key,
                        out code),
                    "short line");
                ServiceHostAssert.False(
                    EngineControlSessionKey.TryReadFrom(
                        new MemoryStream(Encoding.ASCII.GetBytes(text + "0\n")),
                        out key,
                        out code),
                    "long line");
                ServiceHostAssert.False(
                    EngineControlSessionKey.TryReadFrom(
                        new MemoryStream(Encoding.ASCII.GetBytes("z" + text.Substring(1) + "\n")),
                        out key,
                        out code),
                    "non-hex");
                ServiceHostAssert.False(
                    EngineControlSessionKey.TryReadFrom(null, out key, out code),
                    "null source");
            });

            runner.Check("control: the frame header is 16 bytes, big-endian, and bounded", delegate
            {
                MemoryStream stream = new MemoryStream();
                string fault;
                ServiceHostAssert.True(
                    EngineControlFrame.TryWrite(
                        stream,
                        EngineControlFrameKind.Request,
                        0x01020304,
                        new byte[] { 9, 8, 7 },
                        out fault),
                    "write: " + fault);
                byte[] bytes = stream.ToArray();
                ServiceHostAssert.Equal(19, bytes.Length, "frame length");
                ServiceHostAssert.Equal((byte)'H', bytes[0], "magic H");
                ServiceHostAssert.Equal((byte)'S', bytes[1], "magic S");
                ServiceHostAssert.Equal((byte)'D', bytes[2], "magic D");
                ServiceHostAssert.Equal((byte)'C', bytes[3], "magic C");
                ServiceHostAssert.Equal((byte)1, bytes[4], "version");
                ServiceHostAssert.Equal((byte)4, bytes[5], "kind");
                ServiceHostAssert.Equal((byte)0, bytes[6], "flags");
                ServiceHostAssert.Equal((byte)0, bytes[7], "reserved");
                ServiceHostAssert.Equal((byte)1, bytes[8], "id 1");
                ServiceHostAssert.Equal((byte)2, bytes[9], "id 2");
                ServiceHostAssert.Equal((byte)3, bytes[10], "id 3");
                ServiceHostAssert.Equal((byte)4, bytes[11], "id 4");
                ServiceHostAssert.Equal((byte)0, bytes[12], "length 1");
                ServiceHostAssert.Equal((byte)0, bytes[13], "length 2");
                ServiceHostAssert.Equal((byte)0, bytes[14], "length 3");
                ServiceHostAssert.Equal((byte)3, bytes[15], "length 4");

                EngineControlFrameKind kind;
                uint id;
                byte[] payload;
                EngineControlFrameReadResult result = EngineControlFrame.TryRead(
                    new MemoryStream(bytes),
                    EngineControlLimits.MaxRequestPayload,
                    out kind,
                    out id,
                    out payload,
                    out fault);
                ServiceHostAssert.Equal(EngineControlFrameReadResult.Frame, result, "read result");
                ServiceHostAssert.Equal(EngineControlFrameKind.Request, kind, "kind round trip");
                ServiceHostAssert.Equal((uint)0x01020304, id, "id round trip");
                ServiceHostAssert.Equal(3, payload.Length, "payload length");
                ServiceHostAssert.Equal((byte)9, payload[0], "payload 1");
                ServiceHostAssert.Equal((byte)8, payload[1], "payload 2");
                ServiceHostAssert.Equal((byte)7, payload[2], "payload 3");

                result = EngineControlFrame.TryRead(
                    new MemoryStream(bytes),
                    2,
                    out kind,
                    out id,
                    out payload,
                    out fault);
                ServiceHostAssert.Equal(EngineControlFrameReadResult.Fault, result, "bounded read");
                ServiceHostAssert.Equal(EngineControlFault.OversizedFrame, fault, "oversized fault");

                byte[] badMagic = (byte[])bytes.Clone();
                badMagic[0] = (byte)'X';
                result = EngineControlFrame.TryRead(
                    new MemoryStream(badMagic),
                    EngineControlLimits.MaxRequestPayload,
                    out kind,
                    out id,
                    out payload,
                    out fault);
                ServiceHostAssert.Equal(EngineControlFault.BadMagic, fault, "magic fault");

                byte[] badVersion = (byte[])bytes.Clone();
                badVersion[4] = 2;
                result = EngineControlFrame.TryRead(
                    new MemoryStream(badVersion),
                    EngineControlLimits.MaxRequestPayload,
                    out kind,
                    out id,
                    out payload,
                    out fault);
                ServiceHostAssert.Equal(EngineControlFault.BadVersion, fault, "version fault");

                byte[] badFlags = (byte[])bytes.Clone();
                badFlags[6] = 1;
                result = EngineControlFrame.TryRead(
                    new MemoryStream(badFlags),
                    EngineControlLimits.MaxRequestPayload,
                    out kind,
                    out id,
                    out payload,
                    out fault);
                ServiceHostAssert.Equal(EngineControlFault.BadFlags, fault, "flags fault");

                byte[] truncated = new byte[16];
                Array.Copy(bytes, truncated, 16);
                result = EngineControlFrame.TryRead(
                    new MemoryStream(truncated),
                    EngineControlLimits.MaxRequestPayload,
                    out kind,
                    out id,
                    out payload,
                    out fault);
                ServiceHostAssert.Equal(EngineControlFrameReadResult.Fault, result, "truncated read");
                ServiceHostAssert.Equal(EngineControlFault.TruncatedFrame, fault, "truncated fault");

                result = EngineControlFrame.TryRead(
                    new MemoryStream(new byte[0]),
                    EngineControlLimits.MaxRequestPayload,
                    out kind,
                    out id,
                    out payload,
                    out fault);
                ServiceHostAssert.Equal(EngineControlFrameReadResult.Closed, result, "closed read");
            });

            runner.Check("control: the handshake and status read use the real transport", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                ServiceHostFakeStateStore store = new ServiceHostFakeStateStore();
                store.Gate = EngineServiceStateGate.FromRecord(
                    ServiceHostTestData.CleanRecord(now));
                Dictionary<string, string> fields =
                    ServiceHostControlData.EngineStatusFields();

                EngineControlSessionKey key;
                EngineControlSession session;
                ServiceHostFakeEnginePeer peer;
                NewWire(events, fields, out key, out session, out peer);
                try
                {
                    EngineControlStatusSource source = new EngineControlStatusSource(
                        session,
                        ServiceHostTestData.ServiceInstance,
                        store,
                        events);
                    EngineServiceStatus status;
                    DateTimeOffset readAt;
                    string code;
                    ServiceHostAssert.True(
                        source.TryRead(now, out status, out readAt, out code),
                        "status read: " + code);
                    ServiceHostAssert.True(peer.HandshakePassed, "handshake passed");
                    ServiceHostAssert.Equal(1, peer.Requests, "one status request");
                    ServiceHostAssert.Equal(
                        ServiceHostTestData.ServiceInstance,
                        status.InstanceId,
                        "service instance");
                    ServiceHostAssert.Equal(EngineRunState.Ready, status.Engine, "engine state");
                    ServiceHostAssert.False(status.Running, "not running");
                    ServiceHostAssert.Equal(EngineServiceCleanup.Unknown, status.Cleanup, "a static clean record is not process-exit proof");
                    EngineServiceStatusGate statusGate = new EngineServiceStatusGate(
                        ServiceHostTestData.ServiceInstance, events, TimeSpan.FromSeconds(3), TimeSpan.FromSeconds(2));
                    ServiceHostAssert.True(statusGate.TryAccept(status, readAt, now, out code),
                        "real source status remains visible with unknown cleanup: " + code);
                    EngineServiceDurableStateGate durableGate = new EngineServiceDurableStateGate(
                        store, events, ServiceHostTestData.EngineImage, null);
                    GuardedEngineServiceBackend backend = new GuardedEngineServiceBackend(
                        source, statusGate, durableGate, new ServiceHostFakeClock(now), events, session);
                    ServiceHostAssert.True(backend.ReadStatus() != null, "backend exposes the real status");
                    EngineServiceSession serviceSession = new EngineServiceSession(
                        ServiceHostTestData.ServiceInstance, backend, new ServiceHostFakeClock(now), store.Gate);
                    EngineReply hello = ServiceHostAssert.Wait(
                        serviceSession.HandleAsync(ServiceHostTestData.HelloFields(), CancellationToken.None),
                        3000, "hello");
                    ServiceHostAssert.True(hello.Ok, "hello accepts an honest unknown status");
                    EngineServiceResult start = backend.Start(true);
                    ServiceHostAssert.False(start.Ok, "unknown cleanup blocks start");
                    ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.CleanupUnknown, start.Code, "start refusal");
                    ServiceHostAssert.Equal(4, peer.Requests, "only four status reads reached the peer");
                    ServiceHostAssert.Equal((byte)1, peer.Commands[3][0], "last frame is status, not start");
                    ServiceHostAssert.Equal(now, readAt, "read time");
                    ServiceHostAssert.Equal(0, status.TtlBad, "ttl audited");
                    ServiceHostAssert.Equal(EngineServiceMode.Phone, status.Mode, "mode");
                }
                finally
                {
                    session.Dispose();
                    ServiceHostAssert.True(peer.Join(2000), "peer stopped");
                }
            });

            runner.Check("control: a wrong session key is refused before any request", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                Dictionary<string, string> fields =
                    ServiceHostControlData.EngineStatusFields();

                EngineControlSession session;
                ServiceHostFakeEnginePeer peer;
                NewWireWrongKey(events, fields, out session, out peer);
                try
                {
                    IReadOnlyDictionary<string, string> status;
                    string code;
                    ServiceHostAssert.False(session.TryReadStatus(out status, out code), "refused");
                    ServiceHostAssert.Equal(
                        EngineProtocol.ErrorCodes.BoundaryAuthFailed,
                        code,
                        "auth code");
                    ServiceHostAssert.Equal(0, peer.Requests, "no request");
                }
                finally
                {
                    session.Dispose();
                    peer.Join(2000);
                }
            });

            runner.Check("control: a wrong engine ready proof is refused", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                Dictionary<string, string> fields =
                    ServiceHostControlData.EngineStatusFields();

                EngineControlSessionKey key;
                EngineControlSession session;
                ServiceHostFakeEnginePeer peer;
                NewWire(events, fields, out key, out session, out peer);
                peer.SendWrongReadyProof = true;
                try
                {
                    IReadOnlyDictionary<string, string> status;
                    string code;
                    ServiceHostAssert.False(session.TryReadStatus(out status, out code), "refused");
                    ServiceHostAssert.Equal(
                        EngineProtocol.ErrorCodes.BoundaryAuthFailed,
                        code,
                        "auth code");
                    ServiceHostAssert.Equal(0, peer.Requests, "no request");
                }
                finally
                {
                    session.Dispose();
                    peer.Join(2000);
                }
            });

            runner.Check("control: a replayed response id is refused and never retried", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                Dictionary<string, string> fields =
                    ServiceHostControlData.EngineStatusFields();

                EngineControlSessionKey key;
                EngineControlSession session;
                ServiceHostFakeEnginePeer peer;
                NewWire(events, fields, out key, out session, out peer);
                peer.ReplayPreviousResponse = true;
                try
                {
                    IReadOnlyDictionary<string, string> status;
                    string code;
                    ServiceHostAssert.False(session.TryReadStatus(out status, out code), "refused");
                    ServiceHostAssert.Equal(
                        EngineProtocol.ErrorCodes.BoundaryAuthFailed,
                        code,
                        "protocol code");
                    ServiceHostAssert.Equal(1, peer.Requests, "one request");
                    ServiceHostAssert.True(
                        events.Contains(EngineServiceEventCodes.ControlProtocolFailed),
                        "protocol failure event");
                    ServiceHostAssert.False(session.TryReadStatus(out status, out code), "closed");
                    ServiceHostAssert.Equal(1, peer.Requests, "no second request");
                }
                finally
                {
                    session.Dispose();
                    peer.Join(2000);
                }
            });

            runner.Check("control: a failed request write is ambiguous and never replayed", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                Dictionary<string, string> fields =
                    ServiceHostControlData.EngineStatusFields();

                ServiceHostMemoryPipe fromClient = new ServiceHostMemoryPipe();
                ServiceHostMemoryPipe toClient = new ServiceHostMemoryPipe();
                ServiceHostMemoryPipe liveness = new ServiceHostMemoryPipe();
                ServiceHostWriteScriptStream scripted =
                    new ServiceHostWriteScriptStream(fromClient, 3);
                EngineControlSessionKey key = EngineControlSessionKey.CreateRandom();
                ServiceHostFakeEnginePeer peer = new ServiceHostFakeEnginePeer(
                    key,
                    fromClient,
                    toClient,
                    fields);
                EngineControlSession session = new EngineControlSession(
                    new EngineControlStartup(toClient, scripted, liveness, key),
                    events);
                peer.Start();
                try
                {
                    IReadOnlyDictionary<string, string> status;
                    string code;
                    ServiceHostAssert.False(session.TryReadStatus(out status, out code), "refused");
                    ServiceHostAssert.Equal(
                        EngineProtocol.ErrorCodes.Closed,
                        code,
                        "write failure code");
                    int writes = scripted.WriteCalls;
                    ServiceHostAssert.False(session.TryReadStatus(out status, out code), "closed");
                    ServiceHostAssert.Equal(writes, scripted.WriteCalls, "no replay");
                }
                finally
                {
                    session.Dispose();
                    peer.Join(2000);
                }
            });

            runner.Check("control: the engine cannot supply the service instance or cleanup", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                ServiceHostFakeStateStore store = new ServiceHostFakeStateStore();
                store.Gate = EngineServiceStateGate.FromRecord(
                    ServiceHostTestData.CleanRecord(now));
                Dictionary<string, string> fields =
                    ServiceHostControlData.EngineStatusFields();
                fields[EngineServiceStatusKeys.Instance] = "service-0002";

                EngineControlSessionKey key;
                EngineControlSession session;
                ServiceHostFakeEnginePeer peer;
                NewWire(events, fields, out key, out session, out peer);
                try
                {
                    EngineControlStatusSource source = new EngineControlStatusSource(
                        session,
                        ServiceHostTestData.ServiceInstance,
                        store,
                        events);
                    EngineServiceStatus status;
                    DateTimeOffset readAt;
                    string code;
                    ServiceHostAssert.False(
                        source.TryRead(now, out status, out readAt, out code),
                        "reserved field refused");
                    ServiceHostAssert.Equal(
                        EngineProtocol.ErrorCodes.BadResponse,
                        code,
                        "bad response");
                    ServiceHostAssert.True(
                        events.Contains(EngineServiceEventCodes.ControlStatusInvalid),
                        "invalid status event");
                }
                finally
                {
                    session.Dispose();
                    peer.Join(2000);
                }
            });

            runner.Check("control: a missing engine field is a bad response", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                ServiceHostFakeStateStore store = new ServiceHostFakeStateStore();
                store.Gate = EngineServiceStateGate.FromRecord(
                    ServiceHostTestData.CleanRecord(now));
                Dictionary<string, string> fields =
                    ServiceHostControlData.EngineStatusFields();
                fields.Remove(EngineServiceStatusKeys.Admin);

                EngineControlSessionKey key;
                EngineControlSession session;
                ServiceHostFakeEnginePeer peer;
                NewWire(events, fields, out key, out session, out peer);
                try
                {
                    EngineControlStatusSource source = new EngineControlStatusSource(
                        session,
                        ServiceHostTestData.ServiceInstance,
                        store,
                        events);
                    EngineServiceStatus status;
                    DateTimeOffset readAt;
                    string code;
                    ServiceHostAssert.False(
                        source.TryRead(now, out status, out readAt, out code),
                        "missing field refused");
                    ServiceHostAssert.Equal(
                        EngineProtocol.ErrorCodes.BadResponse,
                        code,
                        "bad response");
                }
                finally
                {
                    session.Dispose();
                    peer.Join(2000);
                }
            });

            runner.Check("control: an ok field is accepted only with value one", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                ServiceHostFakeStateStore store = new ServiceHostFakeStateStore();
                store.Gate = EngineServiceStateGate.FromRecord(
                    ServiceHostTestData.CleanRecord(now));

                ServiceHostFakeEvents goodEvents = new ServiceHostFakeEvents();
                Dictionary<string, string> good =
                    ServiceHostControlData.EngineStatusFields();
                good[EngineServiceStatusKeys.Ok] = "1";
                EngineControlSessionKey goodKey;
                EngineControlSession goodSession;
                ServiceHostFakeEnginePeer goodPeer;
                NewWire(goodEvents, good, out goodKey, out goodSession, out goodPeer);
                try
                {
                    EngineControlStatusSource source = new EngineControlStatusSource(
                        goodSession,
                        ServiceHostTestData.ServiceInstance,
                        store,
                        goodEvents);
                    EngineServiceStatus status;
                    DateTimeOffset readAt;
                    string code;
                    ServiceHostAssert.True(
                        source.TryRead(now, out status, out readAt, out code),
                        "ok=1: " + code);
                }
                finally
                {
                    goodSession.Dispose();
                    goodPeer.Join(2000);
                }

                ServiceHostFakeEvents badEvents = new ServiceHostFakeEvents();
                Dictionary<string, string> bad =
                    ServiceHostControlData.EngineStatusFields();
                bad[EngineServiceStatusKeys.Ok] = "0";
                EngineControlSessionKey badKey;
                EngineControlSession badSession;
                ServiceHostFakeEnginePeer badPeer;
                NewWire(badEvents, bad, out badKey, out badSession, out badPeer);
                try
                {
                    EngineControlStatusSource source = new EngineControlStatusSource(
                        badSession,
                        ServiceHostTestData.ServiceInstance,
                        store,
                        badEvents);
                    EngineServiceStatus status;
                    DateTimeOffset readAt;
                    string code;
                    ServiceHostAssert.False(
                        source.TryRead(now, out status, out readAt, out code),
                        "ok=0 refused");
                    ServiceHostAssert.Equal(
                        EngineProtocol.ErrorCodes.BadResponse,
                        code,
                        "bad response");
                }
                finally
                {
                    badSession.Dispose();
                    badPeer.Join(2000);
                }
            });

            runner.Check("control: the closed start gate sends no frame and stop sends one", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                Dictionary<string, string> fields =
                    ServiceHostControlData.EngineStatusFields();

                EngineControlSessionKey key;
                EngineControlSession session;
                ServiceHostFakeEnginePeer peer;
                NewWire(events, fields, out key, out session, out peer);
                try
                {
                    string code;
                    ServiceHostAssert.False(session.TryStart(true, out code), "start refused");
                    ServiceHostAssert.Equal(
                        EngineProtocol.ErrorCodes.Unsupported,
                        code,
                        "start refusal code");
                    ServiceHostAssert.False(session.TryStart(false, out code), "second start refused");
                    ServiceHostAssert.True(session.TryStop(out code), "stop accepted");
                    ServiceHostAssert.Equal("", code, "stop code");
                    ServiceHostAssert.Equal(1, peer.Requests, "only stop reached the engine");
                    ServiceHostAssert.Equal(1, peer.Commands[0].Length, "stop payload");
                    ServiceHostAssert.Equal((byte)11, peer.Commands[0][0], "stop command");
                    ServiceHostAssert.Equal((uint)1, peer.RequestIds[0], "id one");
                }
                finally
                {
                    session.Dispose();
                    peer.Join(2000);
                }
            });

            runner.Check("control: a validated status failure keeps the session and is not replayed", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                Dictionary<string, string> fields =
                    ServiceHostControlData.EngineStatusFields();

                EngineControlSessionKey key;
                EngineControlSession session;
                ServiceHostFakeEnginePeer peer;
                NewWire(events, fields, out key, out session, out peer);
                peer.StatusFailureWireCode = 3;
                try
                {
                    IReadOnlyDictionary<string, string> status;
                    string code;
                    ServiceHostAssert.False(session.TryReadStatus(out status, out code), "failure");
                    ServiceHostAssert.Equal(
                        EngineProtocol.ErrorCodes.EngineUnavailable,
                        code,
                        "unavailable code");
                    ServiceHostAssert.False(session.TryReadStatus(out status, out code), "second failure");
                    ServiceHostAssert.Equal(2, peer.Requests, "two separate requests");
                    ServiceHostAssert.Equal((uint)1, peer.RequestIds[0], "id one");
                    ServiceHostAssert.Equal((uint)2, peer.RequestIds[1], "id two");
                }
                finally
                {
                    session.Dispose();
                    peer.Join(2000);
                }
            });

            runner.Check("control: a running status always carries cleanup unknown", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                ServiceHostFakeStateStore store = new ServiceHostFakeStateStore();
                store.Gate = EngineServiceStateGate.FromRecord(
                    ServiceHostTestData.CleanRecord(now));
                Dictionary<string, string> fields =
                    ServiceHostControlData.EngineRunningStatusFields(now);

                EngineControlSessionKey key;
                EngineControlSession session;
                ServiceHostFakeEnginePeer peer;
                NewWire(events, fields, out key, out session, out peer);
                try
                {
                    EngineControlStatusSource source = new EngineControlStatusSource(
                        session,
                        ServiceHostTestData.ServiceInstance,
                        store,
                        events);
                    EngineServiceStatus status;
                    DateTimeOffset readAt;
                    string code;
                    ServiceHostAssert.True(
                        source.TryRead(now, out status, out readAt, out code),
                        "running read: " + code);
                    ServiceHostAssert.True(status.Running, "running");
                    ServiceHostAssert.Equal(
                        EngineServiceCleanup.Unknown,
                        status.Cleanup,
                        "running cleanup");
                    ServiceHostAssert.Equal(3, status.PhoneConnections.Value, "source count");
                    ServiceHostAssert.Equal(7, status.RelayTcpFlowsActive.Value, "relay gauge");
                }
                finally
                {
                    session.Dispose();
                    peer.Join(2000);
                }
            });

            runner.Check("control: a missing durable record is cleanup unknown, never ok", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                ServiceHostFakeStateStore store = new ServiceHostFakeStateStore();
                store.Gate = EngineServiceStateGate.Missing;
                Dictionary<string, string> fields =
                    ServiceHostControlData.EngineStatusFields();

                EngineControlSessionKey key;
                EngineControlSession session;
                ServiceHostFakeEnginePeer peer;
                NewWire(events, fields, out key, out session, out peer);
                try
                {
                    EngineControlStatusSource source = new EngineControlStatusSource(
                        session,
                        ServiceHostTestData.ServiceInstance,
                        store,
                        events);
                    EngineServiceStatus status;
                    DateTimeOffset readAt;
                    string code;
                    ServiceHostAssert.True(
                        source.TryRead(now, out status, out readAt, out code),
                        "status read: " + code);
                    ServiceHostAssert.Equal(
                        EngineServiceCleanup.Unknown,
                        status.Cleanup,
                        "missing record cleanup");
                }
                finally
                {
                    session.Dispose();
                    peer.Join(2000);
                }
            });

            runner.Check("control: dispose releases a handshake blocked on an empty fake pipe", delegate
            {
                ServiceHostMemoryPipe input = new ServiceHostMemoryPipe();
                ServiceHostMemoryPipe output = new ServiceHostMemoryPipe();
                ServiceHostMemoryPipe parent = new ServiceHostMemoryPipe();
                EngineControlSession session = new EngineControlSession(
                    new EngineControlStartup(input, output, parent, EngineControlSessionKey.CreateRandom()),
                    new ServiceHostFakeEvents());
                Task<bool> read = Task.Run<bool>(delegate
                {
                    IReadOnlyDictionary<string, string> fields;
                    string code;
                    return session.TryReadStatus(out fields, out code);
                });
                ServiceHostAssert.True(input.ReadWaiting.Wait(3000), "handshake is waiting");
                Task dispose = Task.Run(delegate { session.Dispose(); });
                ServiceHostAssert.Wait(dispose, 3000, "dispose");
                ServiceHostAssert.False(ServiceHostAssert.Wait(read, 3000, "read"), "closed handshake fails");
            });

            runner.Check("control: dispose releases a request after a peer stops responding", delegate
            {
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                EngineControlSessionKey key;
                EngineControlSession session;
                ServiceHostFakeEnginePeer peer;
                NewWire(events, ServiceHostControlData.EngineStatusFields(), out key, out session, out peer);
                peer.DropReply = true;
                Task<bool> read = Task.Run<bool>(delegate
                {
                    IReadOnlyDictionary<string, string> fields;
                    string code;
                    return session.TryReadStatus(out fields, out code);
                });
                ServiceHostAssert.True(peer.Join(3000), "peer received request and stopped answering");
                ServiceHostAssert.True(peer.HandshakePassed, "handshake passed");
                ServiceHostAssert.Equal(1, peer.Requests, "one request");
                Task dispose = Task.Run(delegate { session.Dispose(); });
                ServiceHostAssert.Wait(dispose, 3000, "dispose");
                ServiceHostAssert.False(ServiceHostAssert.Wait(read, 3000, "read"), "unanswered request fails");
            });

            runner.Check("control: a stop acknowledgement without cleanup proof remains unknown", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                ServiceHostFakeControlSession control = new ServiceHostFakeControlSession();
                GuardedEngineServiceBackend backend = NewBackend(now, events, control);

                EngineServiceResult result = backend.Stop(EngineServiceStopReason.User);
                ServiceHostAssert.False(result.Ok, "acknowledgement is not cleanup proof");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.CleanupUnknown, result.Code, "cleanup unknown");
                ServiceHostAssert.Equal(1, control.StopCalls, "one stop");
                ServiceHostAssert.False(
                    events.Contains(EngineServiceEventCodes.ControlStopFailed),
                    "no failure event");
            });

            runner.Check("control: a missing control session cannot prove a clean stop", delegate
            {
                GuardedEngineServiceBackend backend = NewBackend(
                    ServiceHostTestData.Now(), new ServiceHostFakeEvents(), null);
                EngineServiceResult result = backend.Stop(EngineServiceStopReason.User);
                ServiceHostAssert.False(result.Ok, "missing session is not cleanup proof");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.CleanupUnknown, result.Code, "cleanup unknown");
            });

            runner.Check("control: a failed stop is cleanup unknown, never success", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                ServiceHostFakeControlSession control = new ServiceHostFakeControlSession();
                control.StopOk = false;
                control.StopCode = EngineProtocol.ErrorCodes.Closed;
                GuardedEngineServiceBackend backend = NewBackend(now, events, control);

                EngineServiceResult result = backend.Stop(EngineServiceStopReason.User);
                ServiceHostAssert.False(result.Ok, "not success");
                ServiceHostAssert.Equal(
                    EngineProtocol.ErrorCodes.CleanupUnknown,
                    result.Code,
                    "cleanup unknown");
                ServiceHostAssert.Equal(1, control.StopCalls, "one stop");
                ServiceHostAssert.True(
                    events.Contains(EngineServiceEventCodes.ControlStopFailed),
                    "failure event");
            });

            runner.Check("control: every start stays refused and sends no start", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                ServiceHostFakeControlSession control = new ServiceHostFakeControlSession();
                control.StartOk = true;
                GuardedEngineServiceBackend backend = NewBackend(now, events, control);

                EngineServiceResult result = backend.Start(true);
                ServiceHostAssert.False(result.Ok, "refused");
                ServiceHostAssert.Equal(
                    EngineProtocol.ErrorCodes.Unsupported,
                    result.Code,
                    "guard code");
                ServiceHostAssert.Equal(0, control.StartCalls, "no start request");
                ServiceHostAssert.True(
                    events.Contains(EngineServiceEventCodes.SourceProxyGuardClosed),
                    "guard event");
            });

            runner.Check("control: dispose closes liveness before the control channels", delegate
            {
                List<string> order = new List<string>();
                ServiceHostMemoryPipe livenessPipe = new ServiceHostMemoryPipe();
                ServiceHostMemoryPipe outputPipe = new ServiceHostMemoryPipe();
                ServiceHostMemoryPipe inputPipe = new ServiceHostMemoryPipe();
                EngineControlSessionKey key = EngineControlSessionKey.CreateRandom();
                EngineControlStartup startup = new EngineControlStartup(
                    new ServiceHostDisposeOrderStream(inputPipe, "input", order),
                    new ServiceHostDisposeOrderStream(outputPipe, "output", order),
                    new ServiceHostDisposeOrderStream(livenessPipe, "liveness", order),
                    key);
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                EngineControlSession session = new EngineControlSession(startup, events);
                session.Dispose();
                ServiceHostAssert.Equal(3, order.Count, "three closes");
                ServiceHostAssert.Equal("liveness", order[0], "liveness first");
                ServiceHostAssert.Equal("output", order[1], "output second");
                ServiceHostAssert.Equal("input", order[2], "input third");
            });

            runner.Check("control: the default channel factory is unavailable and creates nothing", delegate
            {
                EngineControlChannelFactoryProbe probe = new EngineControlChannelFactoryProbe();
                ServiceHostAssert.False(probe.Result, "unavailable");
                ServiceHostAssert.Equal(
                    EngineProtocol.ErrorCodes.EngineUnavailable,
                    probe.Code,
                    "code");
                ServiceHostAssert.True(probe.Startup == null, "no startup");
            });

            runner.Check("control: the service composition keeps the launcher seam", delegate
            {
                string root = RepoRoot();
                ServiceHostAssert.True(root != null, "repo root");
                string composition = File.ReadAllText(Path.Combine(
                    root,
                    "windows",
                    "src",
                    "HotspotShade.WinUI2.Service",
                    "EngineServiceComposition.cs"));
                ServiceHostAssert.Contains(
                    composition,
                    "IEngineControlChannelFactory",
                    "factory seam");
                ServiceHostAssert.Contains(
                    composition,
                    "UnavailableEngineControlChannelFactory",
                    "unavailable default");
                ServiceHostAssert.Contains(
                    composition,
                    "EngineControlStatusSource",
                    "status source");
                ServiceHostAssert.Contains(
                    composition,
                    "controlSession.Dispose()",
                    "parent-loss close");
                ServiceHostAssert.Contains(
                    composition,
                    "GuardedEngineServiceBackend",
                    "guard reference");
            });

            runner.Check("control: the Rust transport constants still match this client", delegate
            {
                string root = RepoRoot();
                ServiceHostAssert.True(root != null, "repo root");
                string rust = File.ReadAllText(
                    Path.Combine(root, "rust", "src", "desktop_control.rs"));
                ServiceHostAssert.Contains(rust, "*b\"HSDC\"", "magic");
                ServiceHostAssert.Contains(rust, "const VERSION: u8 = 1;", "version");
                ServiceHostAssert.Contains(rust, "const HEADER_LEN: usize = 16;", "header");
                ServiceHostAssert.Contains(rust, "const NONCE_LEN: usize = 32;", "nonce");
                ServiceHostAssert.Contains(rust, "const PROOF_LEN: usize = 32;", "proof");
                ServiceHostAssert.Contains(rust, "MAX_REQUEST_PAYLOAD: usize = 64;", "request cap");
                ServiceHostAssert.Contains(rust, "MAX_RESPONSE_PAYLOAD: usize = 64 * 1024;", "response cap");
                ServiceHostAssert.Contains(
                    rust,
                    "b\"hotspotshade-desktop-control-v1/hello\"",
                    "hello label");
                ServiceHostAssert.Contains(
                    rust,
                    "b\"hotspotshade-desktop-control-v1/ready\"",
                    "ready label");
                ServiceHostAssert.Contains(rust, "Challenge = 1,", "challenge kind");
                ServiceHostAssert.Contains(rust, "Hello = 2,", "hello kind");
                ServiceHostAssert.Contains(rust, "Ready = 3,", "ready kind");
                ServiceHostAssert.Contains(rust, "Request = 4,", "request kind");
                ServiceHostAssert.Contains(rust, "Response = 5,", "response kind");
                ServiceHostAssert.Contains(rust, "Fatal = 6,", "fatal kind");
                ServiceHostAssert.Contains(rust, "CMD_STATUS: u8 = 1;", "status command");
                ServiceHostAssert.Contains(rust, "CMD_START: u8 = 10;", "start command");
                ServiceHostAssert.Contains(rust, "CMD_STOP: u8 = 11;", "stop command");
                ServiceHostAssert.Contains(rust, "CMD_SHUTDOWN: u8 = 12;", "shutdown command");
                ServiceHostAssert.Contains(rust, "Unauthorized = 1,", "auth error");
                ServiceHostAssert.Contains(rust, "Protocol = 2,", "protocol error");
                ServiceHostAssert.Contains(rust, "Unavailable = 3,", "unavailable error");
                ServiceHostAssert.Contains(rust, "Busy = 4,", "busy error");
                ServiceHostAssert.Contains(rust, "Refused = 5,", "refused error");
                ServiceHostAssert.Contains(rust, "Unsupported = 6,", "unsupported error");
                ServiceHostAssert.Contains(rust, "Internal = 7,", "internal error");
                ServiceHostAssert.Contains(rust, "TooLarge = 8,", "too large error");
                ServiceHostAssert.Contains(rust, "next_id.wrapping_add(1)", "monotonic request id");
                ServiceHostAssert.Contains(rust, "read_session_key", "key descriptor reader");
            });
        }

        private static void NewWire(
            ServiceHostFakeEvents events,
            Dictionary<string, string> fields,
            out EngineControlSessionKey key,
            out EngineControlSession session,
            out ServiceHostFakeEnginePeer peer)
        {
            ServiceHostMemoryPipe fromClient = new ServiceHostMemoryPipe();
            ServiceHostMemoryPipe toClient = new ServiceHostMemoryPipe();
            ServiceHostMemoryPipe liveness = new ServiceHostMemoryPipe();
            key = EngineControlSessionKey.CreateRandom();
            peer = new ServiceHostFakeEnginePeer(key, fromClient, toClient, fields);
            session = new EngineControlSession(
                new EngineControlStartup(toClient, fromClient, liveness, key),
                events);
            peer.Start();
        }

        private static void NewWireWrongKey(
            ServiceHostFakeEvents events,
            Dictionary<string, string> fields,
            out EngineControlSession session,
            out ServiceHostFakeEnginePeer peer)
        {
            ServiceHostMemoryPipe fromClient = new ServiceHostMemoryPipe();
            ServiceHostMemoryPipe toClient = new ServiceHostMemoryPipe();
            ServiceHostMemoryPipe liveness = new ServiceHostMemoryPipe();
            EngineControlSessionKey clientKey = EngineControlSessionKey.CreateRandom();
            EngineControlSessionKey peerKey = EngineControlSessionKey.CreateRandom();
            peer = new ServiceHostFakeEnginePeer(peerKey, fromClient, toClient, fields);
            session = new EngineControlSession(
                new EngineControlStartup(toClient, fromClient, liveness, clientKey),
                events);
            peer.Start();
        }

        private static GuardedEngineServiceBackend NewBackend(
            DateTimeOffset now,
            ServiceHostFakeEvents events,
            IEngineControlSession control)
        {
            ServiceHostFakeStatusSource status = new ServiceHostFakeStatusSource();
            status.Status = ServiceHostTestData.ReadyStatus(now);
            status.ReadAt = now;
            ServiceHostFakeStateStore store = new ServiceHostFakeStateStore();
            store.Gate = EngineServiceStateGate.FromRecord(
                ServiceHostTestData.CleanRecord(now));
            ServiceHostFakeClock clock = new ServiceHostFakeClock(now);
            EngineServiceDurableStateGate state = new EngineServiceDurableStateGate(
                store,
                events,
                ServiceHostTestData.EngineImage,
                null);
            EngineServiceStatusGate statusGate = new EngineServiceStatusGate(
                ServiceHostTestData.ServiceInstance,
                events,
                TimeSpan.FromSeconds(3),
                TimeSpan.FromSeconds(2));
            return new GuardedEngineServiceBackend(
                status,
                statusGate,
                state,
                clock,
                events,
                control);
        }

        private static string RepoRoot()
        {
            string configured = Environment.GetEnvironmentVariable("HOTSPOTSHADE_REPO_ROOT");
            if (!string.IsNullOrEmpty(configured)
                && Directory.Exists(Path.Combine(configured, "windows")))
            {
                return configured;
            }
            string directory = Directory.GetCurrentDirectory();
            while (!string.IsNullOrEmpty(directory))
            {
                if (Directory.Exists(Path.Combine(directory, "rust"))
                    && Directory.Exists(Path.Combine(directory, "windows")))
                {
                    return directory;
                }
                DirectoryInfo parent = Directory.GetParent(directory);
                directory = parent == null ? null : parent.FullName;
            }
            return null;
        }

        // The unavailable factory is sealed, so this probe records its result
        // without adding a test-only implementation to production code.
        private sealed class EngineControlChannelFactoryProbe
        {
            public bool Result;
            public string Code;
            public EngineControlStartup Startup;

            public EngineControlChannelFactoryProbe()
            {
                IEngineControlChannelFactory factory =
                    new UnavailableEngineControlChannelFactory();
                Result = factory.TryCreate(out Startup, out Code);
            }
        }
    }
}
