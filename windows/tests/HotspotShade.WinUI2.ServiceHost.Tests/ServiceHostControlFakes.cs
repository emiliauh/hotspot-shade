using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.ServiceHost.Tests
{
    // A one-way in-memory byte pipe. One object serves both ends: `Write`
    // appends and `Read` consumes. `Dispose` closes the pipe and wakes a
    // blocked reader. It creates no operating-system handle.
    internal sealed class ServiceHostMemoryPipe : Stream
    {
        private readonly object gate = new object();
        private readonly Queue<byte[]> chunks = new Queue<byte[]>();
        private byte[] current;
        private int offset;
        private bool closed;

        public int WriteCalls;
        public readonly ManualResetEventSlim ReadWaiting = new ManualResetEventSlim(false);

        public int BufferedChunks
        {
            get
            {
                lock (gate)
                {
                    return chunks.Count;
                }
            }
        }

        public override bool CanRead
        {
            get { return true; }
        }

        public override bool CanSeek
        {
            get { return false; }
        }

        public override bool CanWrite
        {
            get { return true; }
        }

        public override long Length
        {
            get { throw new NotSupportedException(); }
        }

        public override long Position
        {
            get { throw new NotSupportedException(); }
            set { throw new NotSupportedException(); }
        }

        public override int Read(byte[] buffer, int index, int count)
        {
            if (buffer == null || index < 0 || count < 0 || index + count > buffer.Length)
            {
                throw new ArgumentOutOfRangeException("count");
            }
            lock (gate)
            {
                while (true)
                {
                    if (current == null || offset >= current.Length)
                    {
                        if (chunks.Count > 0)
                        {
                            current = chunks.Dequeue();
                            offset = 0;
                        }
                        else if (closed)
                        {
                            return 0;
                        }
                        else
                        {
                            ReadWaiting.Set();
                            Monitor.Wait(gate);
                            continue;
                        }
                    }
                    int take = Math.Min(count, current.Length - offset);
                    Buffer.BlockCopy(current, offset, buffer, index, take);
                    offset += take;
                    return take;
                }
            }
        }

        public override void Write(byte[] buffer, int index, int count)
        {
            if (buffer == null || index < 0 || count < 0 || index + count > buffer.Length)
            {
                throw new ArgumentOutOfRangeException("count");
            }
            Interlocked.Increment(ref WriteCalls);
            byte[] copy = new byte[count];
            Buffer.BlockCopy(buffer, index, copy, 0, count);
            lock (gate)
            {
                if (closed)
                {
                    throw new IOException("the test pipe is closed");
                }
                chunks.Enqueue(copy);
                Monitor.PulseAll(gate);
            }
        }

        public override void Flush()
        {
        }

        public override long Seek(long offsetValue, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public void ClosePipe()
        {
            lock (gate)
            {
                closed = true;
                Monitor.PulseAll(gate);
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                ClosePipe();
            }
            base.Dispose(disposing);
        }
    }

    // A write-forwarding stream that fails one selected write call. The frame
    // writer writes a header and then a payload, so a fail-on-third-write
    // stream lets the handshake complete and fails the first request header.
    internal sealed class ServiceHostWriteScriptStream : Stream
    {
        private readonly Stream inner;
        private readonly int failOnWriteCall;
        private int writeCalls;

        public ServiceHostWriteScriptStream(Stream inner, int failOnWriteCall)
        {
            this.inner = inner;
            this.failOnWriteCall = failOnWriteCall;
        }

        public int WriteCalls
        {
            get { return Volatile.Read(ref writeCalls); }
        }

        public override bool CanRead
        {
            get { return inner.CanRead; }
        }

        public override bool CanSeek
        {
            get { return false; }
        }

        public override bool CanWrite
        {
            get { return inner.CanWrite; }
        }

        public override long Length
        {
            get { throw new NotSupportedException(); }
        }

        public override long Position
        {
            get { throw new NotSupportedException(); }
            set { throw new NotSupportedException(); }
        }

        public override int Read(byte[] buffer, int index, int count)
        {
            return inner.Read(buffer, index, count);
        }

        public override void Write(byte[] buffer, int index, int count)
        {
            int call = Interlocked.Increment(ref writeCalls);
            if (call == failOnWriteCall)
            {
                throw new IOException("the test stream refuses this write");
            }
            inner.Write(buffer, index, count);
        }

        public override void Flush()
        {
            inner.Flush();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                inner.Dispose();
            }
            base.Dispose(disposing);
        }
    }

    // Records the order of channel closes. The startup must close the
    // liveness channel before the control channels.
    internal sealed class ServiceHostDisposeOrderStream : Stream
    {
        private readonly Stream inner;
        private readonly string name;
        private readonly List<string> order;
        private bool disposed;

        public ServiceHostDisposeOrderStream(Stream inner, string name, List<string> order)
        {
            this.inner = inner;
            this.name = name;
            this.order = order;
        }

        public override bool CanRead
        {
            get { return inner.CanRead; }
        }

        public override bool CanSeek
        {
            get { return false; }
        }

        public override bool CanWrite
        {
            get { return inner.CanWrite; }
        }

        public override long Length
        {
            get { throw new NotSupportedException(); }
        }

        public override long Position
        {
            get { throw new NotSupportedException(); }
            set { throw new NotSupportedException(); }
        }

        public override int Read(byte[] buffer, int index, int count)
        {
            return inner.Read(buffer, index, count);
        }

        public override void Write(byte[] buffer, int index, int count)
        {
            inner.Write(buffer, index, count);
        }

        public override void Flush()
        {
            inner.Flush();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && !disposed)
            {
                disposed = true;
                lock (order)
                {
                    order.Add(name);
                }
            }
            if (disposing)
            {
                inner.Dispose();
            }
            base.Dispose(disposing);
        }
    }

    internal static class ServiceHostControlData
    {
        public static Dictionary<string, string> EngineStatusFields()
        {
            Dictionary<string, string> fields = ServiceHostTestData.BaseStatusFields();
            fields.Remove(EngineServiceStatusKeys.Version);
            fields.Remove(EngineServiceStatusKeys.Instance);
            fields.Remove(EngineServiceStatusKeys.Cleanup);
            return fields;
        }

        public static Dictionary<string, string> EngineRunningStatusFields(DateTimeOffset now)
        {
            Dictionary<string, string> fields = EngineStatusFields();
            fields[EngineServiceStatusKeys.Engine] = "running";
            fields[EngineServiceStatusKeys.Running] = "1";
            fields[EngineServiceStatusKeys.Paired] = "1";
            fields[EngineServiceStatusKeys.PairedScope] = "identity";
            fields[EngineServiceStatusKeys.Source] = "1";
            fields[EngineServiceStatusKeys.Trusted] = "1";
            fields[EngineServiceStatusKeys.CheckedAt] = ServiceHostTestData.Unix(now);
            fields[EngineServiceStatusKeys.Ping] = "1";
            fields[EngineServiceStatusKeys.IcmpEnabled] = "1";
            fields[EngineServiceStatusKeys.PhoneConnections] = "3";
            fields[EngineServiceStatusKeys.PhoneConnectionsKnown] = "1";
            fields[EngineServiceStatusKeys.RelayTcpFlowsActive] = "7";
            fields[EngineServiceStatusKeys.RelayTcpFlowsActiveKnown] = "1";
            fields[EngineServiceStatusKeys.Stop] = "none";
            fields[EngineServiceStatusKeys.StopAt] = "";
            fields[EngineServiceStatusKeys.Admin] = "0";
            return fields;
        }

        public static byte[] SuccessBody()
        {
            Dictionary<string, string> fields = new Dictionary<string, string>(StringComparer.Ordinal);
            fields["ok"] = "1";
            byte[] frame;
            string code;
            if (!EngineServiceFrame.TryEncode(fields, out frame, out code))
            {
                throw new InvalidOperationException("success fixture failed: " + code);
            }
            byte[] payload = new byte[frame.Length - EngineServiceFrame.LengthPrefixBytes];
            Buffer.BlockCopy(
                frame,
                EngineServiceFrame.LengthPrefixBytes,
                payload,
                0,
                payload.Length);
            Array.Clear(frame, 0, frame.Length);
            return payload;
        }

        public static byte[] StatusResponse(Dictionary<string, string> fields)
        {
            byte[] frame;
            string code;
            if (!EngineServiceFrame.TryEncode(fields, out frame, out code))
            {
                throw new InvalidOperationException("status fixture failed: " + code);
            }
            byte[] payload = new byte[1 + frame.Length - EngineServiceFrame.LengthPrefixBytes];
            Buffer.BlockCopy(
                frame,
                EngineServiceFrame.LengthPrefixBytes,
                payload,
                1,
                payload.Length - 1);
            payload[0] = 0;
            Array.Clear(frame, 0, frame.Length);
            return payload;
        }
    }

    // A hermetic engine peer for the control transport. It speaks the exact
    // Rust `desktop_control` frame format and handshake. It creates no pipe,
    // process, service, route, adapter, or endpoint.
    internal sealed class ServiceHostFakeEnginePeer
    {
        private readonly EngineControlSessionKey key;
        private readonly ServiceHostMemoryPipe fromClient;
        private readonly ServiceHostMemoryPipe toClient;
        private readonly Thread thread;

        public readonly List<uint> RequestIds = new List<uint>();
        public readonly List<byte[]> Commands = new List<byte[]>();
        public Dictionary<string, string> StatusFields;
        public bool SendWrongReadyProof;
        public bool ReplayPreviousResponse;
        public bool DropReply;
        public bool StopOk = true;
        public int StatusFailureWireCode = -1;
        public Exception Error;
        public volatile bool HandshakePassed;
        public volatile bool Done;

        public ServiceHostFakeEnginePeer(
            EngineControlSessionKey key,
            ServiceHostMemoryPipe fromClient,
            ServiceHostMemoryPipe toClient,
            Dictionary<string, string> statusFields)
        {
            this.key = key;
            this.fromClient = fromClient;
            this.toClient = toClient;
            StatusFields = statusFields;
            thread = new Thread(new ThreadStart(Run));
            thread.IsBackground = true;
            thread.Name = "control peer";
        }

        public int Requests
        {
            get
            {
                lock (RequestIds)
                {
                    return RequestIds.Count;
                }
            }
        }

        public void Start()
        {
            thread.Start();
        }

        public bool Join(int milliseconds)
        {
            return thread.Join(milliseconds);
        }

        private void Run()
        {
            try
            {
                byte[] serverNonce = EngineControlProof.RandomNonce();
                string fault;
                if (!EngineControlFrame.TryWrite(
                    toClient,
                    EngineControlFrameKind.Challenge,
                    0,
                    serverNonce,
                    out fault))
                {
                    return;
                }

                EngineControlFrameKind kind;
                uint id;
                byte[] payload;
                EngineControlFrameReadResult read = EngineControlFrame.TryRead(
                    fromClient,
                    EngineControlLimits.HelloBytes,
                    out kind,
                    out id,
                    out payload,
                    out fault);
                if (read != EngineControlFrameReadResult.Frame
                    || kind != EngineControlFrameKind.Hello
                    || id != 0
                    || payload.Length != EngineControlLimits.HelloBytes)
                {
                    return;
                }
                byte[] clientNonce = new byte[EngineControlLimits.NonceBytes];
                byte[] clientProof = new byte[EngineControlLimits.ProofBytes];
                Buffer.BlockCopy(payload, 0, clientNonce, 0, clientNonce.Length);
                Buffer.BlockCopy(
                    payload,
                    clientNonce.Length,
                    clientProof,
                    0,
                    clientProof.Length);
                byte[] expected = EngineControlProof.Compute(
                    key,
                    EngineControlProof.HelloLabel,
                    serverNonce,
                    clientNonce);
                if (expected.Length != clientProof.Length
                    || !EngineControlProof.FixedTimeEquals(expected, clientProof))
                {
                    EngineControlFrame.TryWrite(
                        toClient,
                        EngineControlFrameKind.Fatal,
                        0,
                        new byte[] { 1 },
                        out fault);
                    return;
                }
                HandshakePassed = true;

                byte[] ready = EngineControlProof.Compute(
                    key,
                    EngineControlProof.ReadyLabel,
                    serverNonce,
                    clientNonce);
                if (SendWrongReadyProof)
                {
                    ready[0] = (byte)(ready[0] ^ 0xFF);
                }
                if (!EngineControlFrame.TryWrite(
                    toClient,
                    EngineControlFrameKind.Ready,
                    0,
                    ready,
                    out fault))
                {
                    return;
                }

                uint lastId = 0;
                while (true)
                {
                    read = EngineControlFrame.TryRead(
                        fromClient,
                        EngineControlLimits.MaxRequestPayload,
                        out kind,
                        out id,
                        out payload,
                        out fault);
                    if (read != EngineControlFrameReadResult.Frame)
                    {
                        return;
                    }
                    if (kind != EngineControlFrameKind.Request
                        || id == 0
                        || (lastId != 0 && id <= lastId)
                        || payload == null
                        || payload.Length == 0)
                    {
                        EngineControlFrame.TryWrite(
                            toClient,
                            EngineControlFrameKind.Fatal,
                            0,
                            new byte[] { 2 },
                            out fault);
                        return;
                    }
                    lastId = id;
                    lock (RequestIds)
                    {
                        RequestIds.Add(id);
                        Commands.Add((byte[])payload.Clone());
                    }

                    if (DropReply)
                    {
                        // Keep the reply pipe open and never send an answer.
                        return;
                    }

                    if (ReplayPreviousResponse)
                    {
                        byte[] replay = ServiceHostControlData.SuccessBody();
                        byte[] replayed = new byte[replay.Length + 1];
                        Buffer.BlockCopy(replay, 0, replayed, 1, replay.Length);
                        replayed[0] = 0;
                        EngineControlFrame.TryWrite(
                            toClient,
                            EngineControlFrameKind.Response,
                            id - 1,
                            replayed,
                            out fault);
                        return;
                    }

                    byte[] response;
                    if (payload[0] == 1)
                    {
                        if (StatusFailureWireCode >= 0)
                        {
                            response = new byte[] { 1, (byte)StatusFailureWireCode };
                        }
                        else
                        {
                            response = ServiceHostControlData.StatusResponse(StatusFields);
                        }
                    }
                    else if (payload[0] == 10)
                    {
                        response = new byte[] { 1, 6 };
                    }
                    else if (payload[0] == 11)
                    {
                        response = StopOk
                            ? SuccessResponse()
                            : new byte[] { 1, 7 };
                    }
                    else if (payload[0] == 12)
                    {
                        response = SuccessResponse();
                        EngineControlFrame.TryWrite(
                            toClient,
                            EngineControlFrameKind.Response,
                            id,
                            response,
                            out fault);
                        return;
                    }
                    else
                    {
                        EngineControlFrame.TryWrite(
                            toClient,
                            EngineControlFrameKind.Fatal,
                            0,
                            new byte[] { 2 },
                            out fault);
                        return;
                    }

                    if (!EngineControlFrame.TryWrite(
                        toClient,
                        EngineControlFrameKind.Response,
                        id,
                        response,
                        out fault))
                    {
                        return;
                    }
                }
            }
            catch (Exception error)
            {
                Error = error;
            }
            finally
            {
                Done = true;
            }
        }

        private static byte[] SuccessResponse()
        {
            byte[] body = ServiceHostControlData.SuccessBody();
            byte[] response = new byte[body.Length + 1];
            Buffer.BlockCopy(body, 0, response, 1, body.Length);
            response[0] = 0;
            return response;
        }
    }

    internal sealed class ServiceHostFakeControlSession : IEngineControlSession
    {
        public int StatusCalls;
        public int StartCalls;
        public int StopCalls;
        public bool StartOk;
        public bool StopOk = true;
        public bool LastPing;
        public string StatusCode = EngineProtocol.ErrorCodes.EngineUnavailable;
        public string StartCode = EngineProtocol.ErrorCodes.Unsupported;
        public string StopCode = EngineProtocol.ErrorCodes.CleanupUnknown;
        public bool Disposed;

        public bool TryReadStatus(
            out IReadOnlyDictionary<string, string> fields,
            out string code)
        {
            StatusCalls++;
            fields = null;
            code = StatusCode;
            return false;
        }

        public bool TryStart(bool ping, out string code)
        {
            StartCalls++;
            LastPing = ping;
            code = StartOk ? "" : StartCode;
            return StartOk;
        }

        public bool TryStop(out string code)
        {
            StopCalls++;
            code = StopOk ? "" : StopCode;
            return StopOk;
        }

        public void Dispose()
        {
            Disposed = true;
        }
    }
}
