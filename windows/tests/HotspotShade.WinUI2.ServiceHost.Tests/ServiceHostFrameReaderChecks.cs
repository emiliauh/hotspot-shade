using System;
using System.Collections.Generic;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.ServiceHost.Tests
{
    internal sealed class ServiceHostScriptedFrameSource : IEngineServiceFrameSource
    {
        public Queue<byte[]> Chunks = new Queue<byte[]>();
        public Queue<EngineServiceFrameSourceResult> Results =
            new Queue<EngineServiceFrameSourceResult>();
        public List<int> Requests = new List<int>();
        public int MaxRequest;
        public bool Fail;
        public string FailCode = EngineProtocol.ErrorCodes.Forbidden;
        public bool ReturnTooMuch;
        public bool Throw;

        public EngineServiceFrameSourceRead Read(
            byte[] buffer,
            int offset,
            int count,
            out string code)
        {
            Requests.Add(count);
            if (count > MaxRequest)
            {
                MaxRequest = count;
            }
            if (Throw)
            {
                throw new InvalidOperationException("source failed");
            }
            if (Fail)
            {
                code = FailCode;
                return FailCode == EngineProtocol.ErrorCodes.Timeout
                    ? EngineServiceFrameSourceRead.Idle()
                    : EngineServiceFrameSourceRead.Failed();
            }
            if (ReturnTooMuch)
            {
                code = "";
                return EngineServiceFrameSourceRead.Data(count + 1);
            }
            if (Chunks.Count > 0)
            {
                byte[] chunk = Chunks.Dequeue();
                if (chunk.Length > count)
                {
                    throw new InvalidOperationException("test chunk is larger than the request");
                }
                Array.Copy(chunk, 0, buffer, offset, chunk.Length);
                code = "";
                return EngineServiceFrameSourceRead.Data(chunk.Length);
            }
            if (Results.Count > 0)
            {
                EngineServiceFrameSourceResult result = Results.Dequeue();
                code = "";
                if (result == EngineServiceFrameSourceResult.Idle)
                {
                    return EngineServiceFrameSourceRead.Idle();
                }
                if (result == EngineServiceFrameSourceResult.Interrupted)
                {
                    return EngineServiceFrameSourceRead.Interrupted();
                }
                if (result == EngineServiceFrameSourceResult.EndOfStream)
                {
                    return EngineServiceFrameSourceRead.EndOfStream();
                }
                if (result == EngineServiceFrameSourceResult.Data)
                {
                    return EngineServiceFrameSourceRead.Data(0);
                }
                return EngineServiceFrameSourceRead.Failed();
            }
            code = EngineProtocol.ErrorCodes.BadResponse;
            return EngineServiceFrameSourceRead.EndOfStream();
        }
    }

    internal static class ServiceHostFrameReaderChecks
    {
        public static void Run(ServiceHostCheckRunner runner)
        {
            runner.Check("frame reader: one frame is read across partial reads", delegate
            {
                byte[] frame = ServiceHostTestData.Encode(ServiceHostTestData.HelloFields());
                ServiceHostScriptedFrameSource source = new ServiceHostScriptedFrameSource();
                source.Chunks.Enqueue(new byte[] { frame[0], frame[1] });
                source.Chunks.Enqueue(new byte[] { frame[2], frame[3] });
                int payload = frame.Length - 4;
                int first = payload / 3;
                int second = payload / 3;
                int third = payload - first - second;
                source.Chunks.Enqueue(Slice(frame, 4, first));
                source.Chunks.Enqueue(Slice(frame, 4 + first, second));
                source.Chunks.Enqueue(Slice(frame, 4 + first + second, third));

                byte[] decoded;
                string code;
                EngineServiceFrameReadOutcome outcome;
                ServiceHostAssert.True(
                    EngineServiceBoundedFrameReader.TryReadFrame(
                        source,
                        out decoded,
                        out outcome,
                        out code),
                    "read: " + code);
                ServiceHostAssert.Equal(EngineServiceFrameReadOutcome.Frame, outcome, "outcome");
                ServiceHostAssert.Equal(frame.Length, decoded.Length, "length");
                for (int index = 0; index < frame.Length; index++)
                {
                    if (frame[index] != decoded[index])
                    {
                        throw new Exception("frame byte mismatch at " + index);
                    }
                }
                ServiceHostAssert.True(source.MaxRequest <= EngineServiceFrame.MaxPayloadBytes, "bounded request");
            });

            runner.Check("frame reader: a zero length and an oversized length are refused before payload allocation", delegate
            {
                ServiceHostScriptedFrameSource zero = new ServiceHostScriptedFrameSource();
                zero.Chunks.Enqueue(new byte[] { 0, 0, 0, 0 });
                byte[] frame;
                string code;
                EngineServiceFrameReadOutcome outcome;
                ServiceHostAssert.False(
                    EngineServiceBoundedFrameReader.TryReadFrame(
                        zero,
                        out frame,
                        out outcome,
                        out code),
                    "zero");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.BadResponse, code, "zero code");
                ServiceHostAssert.Equal(EngineServiceFrameReadOutcome.Failed, outcome, "zero outcome");
                ServiceHostAssert.Equal(1, zero.Requests.Count, "no payload request");

                ServiceHostScriptedFrameSource huge = new ServiceHostScriptedFrameSource();
                int oversized = EngineServiceFrame.MaxPayloadBytes + 1;
                huge.Chunks.Enqueue(new byte[]
                {
                    (byte)(oversized >> 24),
                    (byte)(oversized >> 16),
                    (byte)(oversized >> 8),
                    (byte)oversized
                });
                ServiceHostAssert.False(
                    EngineServiceBoundedFrameReader.TryReadFrame(
                        huge,
                        out frame,
                        out outcome,
                        out code),
                    "oversized");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.BadResponse, code, "oversized code");
                ServiceHostAssert.Equal(EngineServiceFrameReadOutcome.Failed, outcome, "oversized outcome");
                ServiceHostAssert.Equal(1, huge.Requests.Count, "no oversized payload request");
            });

            runner.Check("frame reader: a maximum size payload is accepted", delegate
            {
                int length = EngineServiceFrame.MaxPayloadBytes;
                byte[] raw = new byte[4 + length];
                raw[0] = (byte)(length >> 24);
                raw[1] = (byte)(length >> 16);
                raw[2] = (byte)(length >> 8);
                raw[3] = (byte)length;
                raw[4] = (byte)'{';
                raw[raw.Length - 1] = (byte)'}';
                ServiceHostScriptedFrameSource source = new ServiceHostScriptedFrameSource();
                source.Chunks.Enqueue(Slice(raw, 0, 4));
                source.Chunks.Enqueue(Slice(raw, 4, length));
                byte[] frame;
                string code;
                EngineServiceFrameReadOutcome outcome;
                ServiceHostAssert.True(
                    EngineServiceBoundedFrameReader.TryReadFrame(
                        source,
                        out frame,
                        out outcome,
                        out code),
                    "max frame: " + code);
                ServiceHostAssert.Equal(EngineServiceFrameReadOutcome.Frame, outcome, "max frame outcome");
                ServiceHostAssert.Equal(raw.Length, frame.Length, "max frame length");
            });

            runner.Check("frame reader: a short read, EOF, and an invalid length are refused", delegate
            {
                byte[] frame = ServiceHostTestData.Encode(ServiceHostTestData.HelloFields());
                ServiceHostScriptedFrameSource shortRead = new ServiceHostScriptedFrameSource();
                shortRead.Chunks.Enqueue(Slice(frame, 0, 4));
                shortRead.Chunks.Enqueue(Slice(frame, 4, 1));
                byte[] decoded;
                string code;
                EngineServiceFrameReadOutcome outcome;
                ServiceHostAssert.False(
                    EngineServiceBoundedFrameReader.TryReadFrame(
                        shortRead,
                        out decoded,
                        out outcome,
                        out code),
                    "short");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.BadResponse, code, "short code");
                ServiceHostAssert.Equal(EngineServiceFrameReadOutcome.Partial, outcome, "short outcome");

                ServiceHostScriptedFrameSource eof = new ServiceHostScriptedFrameSource();
                eof.Chunks.Enqueue(Slice(frame, 0, 2));
                ServiceHostAssert.False(
                    EngineServiceBoundedFrameReader.TryReadFrame(
                        eof,
                        out decoded,
                        out outcome,
                        out code),
                    "eof");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.BadResponse, code, "eof code");
                ServiceHostAssert.Equal(EngineServiceFrameReadOutcome.Partial, outcome, "eof outcome");
            });

            runner.Check("frame reader: a deadline, a source failure, an exception, and an over-return are refused", delegate
            {
                byte[] frame;
                string code;
                EngineServiceFrameReadOutcome outcome;
                ServiceHostScriptedFrameSource deadline = new ServiceHostScriptedFrameSource();
                deadline.Chunks.Enqueue(new byte[] { 0, 0, 0, 20 });
                deadline.Chunks.Enqueue(new byte[] { 1, 2, 3 });
                deadline.Results.Enqueue(EngineServiceFrameSourceResult.Idle);
                ServiceHostAssert.False(
                    EngineServiceBoundedFrameReader.TryReadFrame(
                        deadline,
                        out frame,
                        out outcome,
                        out code),
                    "deadline");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.EngineUnavailable, code, "deadline code");
                ServiceHostAssert.Equal(
                    EngineServiceFrameReadOutcome.Partial,
                    outcome,
                    "a timeout after consumed bytes is partial");

                ServiceHostScriptedFrameSource failure = new ServiceHostScriptedFrameSource();
                failure.Fail = true;
                failure.FailCode = EngineProtocol.ErrorCodes.Forbidden;
                ServiceHostAssert.False(
                    EngineServiceBoundedFrameReader.TryReadFrame(
                        failure,
                        out frame,
                        out outcome,
                        out code),
                    "failure");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Forbidden, code, "failure code");
                ServiceHostAssert.Equal(EngineServiceFrameReadOutcome.Failed, outcome, "failure outcome");

                ServiceHostScriptedFrameSource throwing = new ServiceHostScriptedFrameSource();
                throwing.Throw = true;
                ServiceHostAssert.False(
                    EngineServiceBoundedFrameReader.TryReadFrame(
                        throwing,
                        out frame,
                        out outcome,
                        out code),
                    "exception");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.BadResponse, code, "exception code");
                ServiceHostAssert.Equal(EngineServiceFrameReadOutcome.Failed, outcome, "exception outcome");

                ServiceHostScriptedFrameSource tooMuch = new ServiceHostScriptedFrameSource();
                tooMuch.ReturnTooMuch = true;
                ServiceHostAssert.False(
                    EngineServiceBoundedFrameReader.TryReadFrame(
                        tooMuch,
                        out frame,
                        out outcome,
                        out code),
                    "over-return");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.BadResponse, code, "over-return code");
                ServiceHostAssert.Equal(EngineServiceFrameReadOutcome.Failed, outcome, "over-return outcome");
            });

            runner.Check("frame reader: a null source is refused", delegate
            {
                byte[] frame;
                string code;
                EngineServiceFrameReadOutcome outcome;
                ServiceHostAssert.False(
                    EngineServiceBoundedFrameReader.TryReadFrame(
                        null,
                        out frame,
                        out outcome,
                        out code),
                    "null source");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.BadResponse, code, "null code");
                ServiceHostAssert.Equal(EngineServiceFrameReadOutcome.Failed, outcome, "null outcome");
            });

            runner.Check("frame reader: a proven zero-byte idle is not a frame", delegate
            {
                ServiceHostScriptedFrameSource idle = new ServiceHostScriptedFrameSource();
                idle.Results.Enqueue(EngineServiceFrameSourceResult.Idle);
                byte[] frame;
                string code;
                EngineServiceFrameReadOutcome outcome;
                ServiceHostAssert.False(
                    EngineServiceBoundedFrameReader.TryReadFrame(
                        idle,
                        out frame,
                        out outcome,
                        out code),
                    "idle");
                ServiceHostAssert.Equal(EngineServiceFrameReadOutcome.Idle, outcome, "idle outcome");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Timeout, code, "idle code");
                ServiceHostAssert.True(frame == null, "no frame");
                ServiceHostAssert.Equal(1, idle.Requests.Count, "one prefix request");
            });

            runner.Check("frame reader: a partial header is never an idle read", delegate
            {
                byte[] frame = ServiceHostTestData.Encode(ServiceHostTestData.HelloFields());
                ServiceHostScriptedFrameSource partial = new ServiceHostScriptedFrameSource();
                partial.Chunks.Enqueue(Slice(frame, 0, 2));
                partial.Results.Enqueue(EngineServiceFrameSourceResult.Idle);

                byte[] decoded;
                string code;
                EngineServiceFrameReadOutcome outcome;
                ServiceHostAssert.False(
                    EngineServiceBoundedFrameReader.TryReadFrame(
                        partial,
                        out decoded,
                        out outcome,
                        out code),
                    "partial header");
                ServiceHostAssert.Equal(
                    EngineServiceFrameReadOutcome.Partial,
                    outcome,
                    "partial header outcome");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.EngineUnavailable, code, "code");
                ServiceHostAssert.True(decoded == null, "no frame");
            });

            runner.Check("frame reader: a complete header with no body is partial", delegate
            {
                byte[] frame = ServiceHostTestData.Encode(ServiceHostTestData.HelloFields());
                ServiceHostScriptedFrameSource headerOnly = new ServiceHostScriptedFrameSource();
                headerOnly.Chunks.Enqueue(Slice(frame, 0, 4));
                headerOnly.Results.Enqueue(EngineServiceFrameSourceResult.Idle);

                byte[] decoded;
                string code;
                EngineServiceFrameReadOutcome outcome;
                ServiceHostAssert.False(
                    EngineServiceBoundedFrameReader.TryReadFrame(
                        headerOnly,
                        out decoded,
                        out outcome,
                        out code),
                    "header only");
                ServiceHostAssert.Equal(
                    EngineServiceFrameReadOutcome.Partial,
                    outcome,
                    "header only outcome");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.EngineUnavailable, code, "code");
            });

            runner.Check("frame reader: a partial body is partial", delegate
            {
                byte[] frame = ServiceHostTestData.Encode(ServiceHostTestData.HelloFields());
                ServiceHostScriptedFrameSource partialBody = new ServiceHostScriptedFrameSource();
                partialBody.Chunks.Enqueue(Slice(frame, 0, 4));
                partialBody.Chunks.Enqueue(Slice(frame, 4, 2));
                partialBody.Results.Enqueue(EngineServiceFrameSourceResult.Idle);

                byte[] decoded;
                string code;
                EngineServiceFrameReadOutcome outcome;
                ServiceHostAssert.False(
                    EngineServiceBoundedFrameReader.TryReadFrame(
                        partialBody,
                        out decoded,
                        out outcome,
                        out code),
                    "partial body");
                ServiceHostAssert.Equal(
                    EngineServiceFrameReadOutcome.Partial,
                    outcome,
                    "partial body outcome");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.EngineUnavailable, code, "code");
            });

            runner.Check("frame reader: an interrupted read before any byte is unknown", delegate
            {
                ServiceHostScriptedFrameSource interrupted = new ServiceHostScriptedFrameSource();
                interrupted.Results.Enqueue(EngineServiceFrameSourceResult.Interrupted);

                byte[] decoded;
                string code;
                EngineServiceFrameReadOutcome outcome;
                ServiceHostAssert.False(
                    EngineServiceBoundedFrameReader.TryReadFrame(
                        interrupted,
                        out decoded,
                        out outcome,
                        out code),
                    "interrupted");
                ServiceHostAssert.Equal(
                    EngineServiceFrameReadOutcome.Unknown,
                    outcome,
                    "interrupted outcome");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.EngineUnavailable, code, "code");
            });
        }

        private static byte[] Slice(byte[] source, int offset, int count)
        {
            byte[] value = new byte[count];
            Array.Copy(source, offset, value, 0, count);
            return value;
        }
    }
}
