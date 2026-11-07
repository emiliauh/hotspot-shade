using System;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.ServiceHost
{
    // One bounded read result from a frame source.
    //
    // Data reports a positive count of bytes that the source consumed.
    // EndOfStream reports a clean peer end with no bytes.
    // Idle reports a proven zero-byte transfer. A source must report Idle only
    // when the kernel operation ended and its transfer count is zero. It must
    // never report Idle after it copied bytes, while a stop is requested, or
    // when a completed operation's byte count is unknown.
    // Interrupted reports a failed read that may have consumed bytes. The
    // stream position is unknown.
    // Failed reports a read that consumed no byte or a refused request.
    public enum EngineServiceFrameSourceResult
    {
        Data = 0,
        EndOfStream = 1,
        Idle = 2,
        Interrupted = 3,
        Failed = 4
    }

    // One bounded read. Count is meaningful only for Data.
    public struct EngineServiceFrameSourceRead
    {
        private readonly EngineServiceFrameSourceResult result;
        private readonly int count;

        private EngineServiceFrameSourceRead(EngineServiceFrameSourceResult result, int count)
        {
            this.result = result;
            this.count = count;
        }

        public EngineServiceFrameSourceResult Result
        {
            get { return result; }
        }

        public int Count
        {
            get { return count; }
        }

        public static EngineServiceFrameSourceRead Data(int count)
        {
            return new EngineServiceFrameSourceRead(EngineServiceFrameSourceResult.Data, count);
        }

        public static EngineServiceFrameSourceRead EndOfStream()
        {
            return new EngineServiceFrameSourceRead(EngineServiceFrameSourceResult.EndOfStream, 0);
        }

        public static EngineServiceFrameSourceRead Idle()
        {
            return new EngineServiceFrameSourceRead(EngineServiceFrameSourceResult.Idle, 0);
        }

        public static EngineServiceFrameSourceRead Interrupted()
        {
            return new EngineServiceFrameSourceRead(EngineServiceFrameSourceResult.Interrupted, 0);
        }

        public static EngineServiceFrameSourceRead Failed()
        {
            return new EngineServiceFrameSourceRead(EngineServiceFrameSourceResult.Failed, 0);
        }
    }

    // A bounded byte source for one pipe. A source must never return more than
    // the requested count.
    public interface IEngineServiceFrameSource
    {
        EngineServiceFrameSourceRead Read(
            byte[] buffer,
            int offset,
            int count,
            out string code);
    }

    // The outcome of one frame read.
    //
    // Frame is a complete frame.
    // Idle is a proven zero-byte transfer before any byte of this frame. The
    // stream remains at a frame boundary. This is transfer evidence only;
    // the service listener still closes the session on every failed read.
    // Partial means at least one byte of this frame was consumed, then the
    // read failed. The rest of the pipe is not a frame boundary and the pipe
    // must close.
    // Unknown means no byte of this frame is known to be consumed, but a
    // failed read could not prove a zero-byte transfer. The pipe must close.
    // Failed is a refused request, a clean end of stream, or a malformed
    // frame. The pipe must close.
    public enum EngineServiceFrameReadOutcome
    {
        Failed = 0,
        Frame = 1,
        Idle = 2,
        Partial = 3,
        Unknown = 4
    }

    // Reads exactly one frame: a 4 byte big-endian length and exactly that
    // many payload bytes. A zero length, a value above the 65536 byte cap, a
    // short read, a clean end in the middle, or a malformed source result is
    // refused before any reply or parse. The reader allocates the prefix and
    // exactly one payload buffer.
    //
    // The reader reports Idle only for a proven zero-byte transfer at the
    // start of a frame. Every other failed read that might have consumed bytes
    // reports Partial or Unknown, so the caller closes the pipe instead of
    // reinterpreting the remaining bytes as a new frame.
    public static class EngineServiceBoundedFrameReader
    {
        public static bool TryReadFrame(
            IEngineServiceFrameSource source,
            out byte[] frame,
            out string code)
        {
            EngineServiceFrameReadOutcome outcome;
            return TryReadFrame(source, out frame, out outcome, out code);
        }

        public static bool TryReadFrame(
            IEngineServiceFrameSource source,
            out byte[] frame,
            out EngineServiceFrameReadOutcome outcome,
            out string code)
        {
            frame = null;
            outcome = EngineServiceFrameReadOutcome.Failed;
            if (source == null)
            {
                code = EngineProtocol.ErrorCodes.BadResponse;
                return false;
            }

            int consumed = 0;
            byte[] prefix = new byte[EngineServiceFrame.LengthPrefixBytes];
            FrameReadStep step = ReadExactly(
                source,
                prefix,
                0,
                prefix.Length,
                ref consumed,
                out code);
            if (step == FrameReadStep.Idle && consumed == 0)
            {
                outcome = EngineServiceFrameReadOutcome.Idle;
                code = EngineProtocol.ErrorCodes.Timeout;
                return false;
            }
            if (step != FrameReadStep.Complete)
            {
                outcome = Classify(step, consumed);
                if (outcome != EngineServiceFrameReadOutcome.Failed
                    && code == EngineProtocol.ErrorCodes.Timeout)
                {
                    // A deadline is a transport failure once any byte of the
                    // frame was consumed. A clean end or a refused source keeps
                    // its own code.
                    code = EngineProtocol.ErrorCodes.EngineUnavailable;
                }
                return false;
            }

            int length;
            if (!EngineServiceFrame.TryReadLength(prefix, out length))
            {
                code = EngineProtocol.ErrorCodes.BadResponse;
                return false;
            }

            byte[] payload = new byte[length];
            try
            {
                step = ReadExactly(
                    source,
                    payload,
                    0,
                    payload.Length,
                    ref consumed,
                    out code);
                if (step != FrameReadStep.Complete)
                {
                    // The prefix is already consumed. Whatever remains in the
                    // pipe is not a new frame boundary.
                    outcome = EngineServiceFrameReadOutcome.Partial;
                    if (code == EngineProtocol.ErrorCodes.Timeout)
                    {
                        code = EngineProtocol.ErrorCodes.EngineUnavailable;
                    }
                    return false;
                }

                frame = new byte[EngineServiceFrame.LengthPrefixBytes + length];
                Buffer.BlockCopy(prefix, 0, frame, 0, prefix.Length);
                Buffer.BlockCopy(payload, 0, frame, EngineServiceFrame.LengthPrefixBytes, length);
                outcome = EngineServiceFrameReadOutcome.Frame;
                code = "";
                return true;
            }
            finally
            {
                Array.Clear(payload, 0, payload.Length);
            }
        }

        private static FrameReadStep ReadExactly(
            IEngineServiceFrameSource source,
            byte[] buffer,
            int offset,
            int count,
            ref int consumed,
            out string code)
        {
            int written = 0;
            while (written < count)
            {
                EngineServiceFrameSourceRead read;
                string readCode;
                try
                {
                    read = source.Read(buffer, offset + written, count - written, out readCode);
                }
                catch (Exception)
                {
                    code = EngineProtocol.ErrorCodes.BadResponse;
                    return FrameReadStep.Failed;
                }

                if (read.Result == EngineServiceFrameSourceResult.Data)
                {
                    if (read.Count <= 0 || read.Count > count - written)
                    {
                        code = EngineProtocol.ErrorCodes.BadResponse;
                        return FrameReadStep.Failed;
                    }
                    written += read.Count;
                    consumed += read.Count;
                    continue;
                }
                if (read.Result == EngineServiceFrameSourceResult.EndOfStream)
                {
                    code = EngineProtocol.ErrorCodes.BadResponse;
                    return FrameReadStep.EndOfStream;
                }
                if (read.Result == EngineServiceFrameSourceResult.Idle)
                {
                    code = EngineProtocol.ErrorCodes.Timeout;
                    return FrameReadStep.Idle;
                }
                if (read.Result == EngineServiceFrameSourceResult.Interrupted)
                {
                    code = EngineProtocol.IsKnownErrorCode(readCode)
                        ? readCode
                        : EngineProtocol.ErrorCodes.EngineUnavailable;
                    return FrameReadStep.Interrupted;
                }
                code = EngineProtocol.IsKnownErrorCode(readCode)
                    ? readCode
                    : EngineProtocol.ErrorCodes.BadResponse;
                return FrameReadStep.Failed;
            }
            code = "";
            return FrameReadStep.Complete;
        }

        // A consumed byte makes every later failure partial. Without a
        // consumed byte, only an interrupted source leaves the transfer
        // unknown. A clean end or a refusal is a plain failure.
        private static EngineServiceFrameReadOutcome Classify(
            FrameReadStep step,
            int consumed)
        {
            if (consumed > 0)
            {
                return EngineServiceFrameReadOutcome.Partial;
            }
            if (step == FrameReadStep.Interrupted)
            {
                return EngineServiceFrameReadOutcome.Unknown;
            }
            return EngineServiceFrameReadOutcome.Failed;
        }

        private enum FrameReadStep
        {
            Complete = 0,
            Idle = 1,
            EndOfStream = 2,
            Interrupted = 3,
            Failed = 4
        }
    }
}
