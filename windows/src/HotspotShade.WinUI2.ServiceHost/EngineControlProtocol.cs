using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.ServiceHost
{
    // The service side of the engine control transport in
    // rust/src/desktop_control.rs. The engine is the server. The service is the
    // shell. One private control channel carries fixed binary commands. One
    // separate private liveness channel is held open for the life of the
    // service. One private descriptor carries a 32-byte session key.
    //
    // The key never crosses the control channel. The engine sends a challenge.
    // The service answers with one HMAC. The engine answers with its own HMAC.
    // Every request then uses the same channel. There is no port, no bearer
    // request, and no second listener. A process that reuses a handle cannot
    // join the session.
    //
    // This file implements the client only. It creates no pipe, process,
    // service, route, adapter, or tunnel. A reviewed launcher supplies
    // the streams and the key. The Windows channel factory in this build is
    // unavailable, so no session starts.
    public static class EngineControlLimits
    {
        public const int HeaderBytes = 16;
        public const int NonceBytes = 32;
        public const int ProofBytes = 32;
        public const int HelloBytes = NonceBytes + ProofBytes;
        public const int SessionKeyBytes = 32;
        public const int SessionKeyTextBytes = 64;
        public const int MaxRequestPayload = 64;
        public const int MaxResponsePayload = 64 * 1024;
    }

    internal enum EngineControlFrameKind
    {
        Challenge = 1,
        Hello = 2,
        Ready = 3,
        Request = 4,
        Response = 5,
        Fatal = 6
    }

    internal enum EngineControlFrameReadResult
    {
        Frame,
        Closed,
        Fault
    }

    // Fixed transport fault words. They carry no input bytes and no backend
    // text.
    internal static class EngineControlFault
    {
        internal const string BadMagic = "bad_magic";
        internal const string BadVersion = "bad_version";
        internal const string UnknownFrameKind = "unknown_frame_kind";
        internal const string BadFlags = "bad_flags";
        internal const string OversizedFrame = "oversized_frame";
        internal const string TruncatedFrame = "truncated_frame";
        internal const string Io = "io";
    }

    internal static class EngineControlFrame
    {
        private static readonly byte[] Magic = new byte[] { (byte)'H', (byte)'S', (byte)'D', (byte)'C' };
        private const byte Version = 1;

        internal static bool TryWrite(
            Stream output,
            EngineControlFrameKind kind,
            uint id,
            byte[] payload,
            out string fault)
        {
            fault = "";
            if (output == null || payload == null || payload.Length > EngineControlLimits.MaxResponsePayload)
            {
                fault = EngineControlFault.OversizedFrame;
                return false;
            }
            byte[] header = new byte[EngineControlLimits.HeaderBytes];
            header[0] = Magic[0];
            header[1] = Magic[1];
            header[2] = Magic[2];
            header[3] = Magic[3];
            header[4] = Version;
            header[5] = (byte)kind;
            header[6] = 0;
            header[7] = 0;
            header[8] = (byte)(id >> 24);
            header[9] = (byte)(id >> 16);
            header[10] = (byte)(id >> 8);
            header[11] = (byte)id;
            int length = payload.Length;
            header[12] = (byte)(length >> 24);
            header[13] = (byte)(length >> 16);
            header[14] = (byte)(length >> 8);
            header[15] = (byte)length;
            try
            {
                output.Write(header, 0, header.Length);
                if (payload.Length > 0)
                {
                    output.Write(payload, 0, payload.Length);
                }
                output.Flush();
                return true;
            }
            catch (Exception)
            {
                fault = EngineControlFault.Io;
                return false;
            }
        }

        internal static EngineControlFrameReadResult TryRead(
            Stream input,
            int maxPayload,
            out EngineControlFrameKind kind,
            out uint id,
            out byte[] payload,
            out string fault)
        {
            kind = EngineControlFrameKind.Fatal;
            id = 0;
            payload = null;
            fault = "";
            if (input == null || maxPayload < 0 || maxPayload > EngineControlLimits.MaxResponsePayload)
            {
                fault = EngineControlFault.OversizedFrame;
                return EngineControlFrameReadResult.Fault;
            }

            byte[] header = new byte[EngineControlLimits.HeaderBytes];
            int filled = 0;
            while (filled < header.Length)
            {
                int count;
                try
                {
                    count = input.Read(header, filled, header.Length - filled);
                }
                catch (Exception)
                {
                    fault = EngineControlFault.Io;
                    return EngineControlFrameReadResult.Fault;
                }
                if (count == 0)
                {
                    return filled == 0
                        ? EngineControlFrameReadResult.Closed
                        : Fault(EngineControlFault.TruncatedFrame, out fault);
                }
                filled += count;
            }

            if (header[0] != Magic[0]
                || header[1] != Magic[1]
                || header[2] != Magic[2]
                || header[3] != Magic[3])
            {
                return Fault(EngineControlFault.BadMagic, out fault);
            }
            if (header[4] != Version)
            {
                return Fault(EngineControlFault.BadVersion, out fault);
            }
            EngineControlFrameKind parsedKind;
            if (!TryParseKind(header[5], out parsedKind))
            {
                return Fault(EngineControlFault.UnknownFrameKind, out fault);
            }
            if (header[6] != 0 || header[7] != 0)
            {
                return Fault(EngineControlFault.BadFlags, out fault);
            }

            id = ((uint)header[8] << 24)
                | ((uint)header[9] << 16)
                | ((uint)header[10] << 8)
                | header[11];
            int length = ((int)header[12] << 24)
                | ((int)header[13] << 16)
                | ((int)header[14] << 8)
                | header[15];
            if (length < 0 || length > maxPayload)
            {
                return Fault(EngineControlFault.OversizedFrame, out fault);
            }

            byte[] body = new byte[length];
            filled = 0;
            while (filled < length)
            {
                int count;
                try
                {
                    count = input.Read(body, filled, length - filled);
                }
                catch (Exception)
                {
                    fault = EngineControlFault.Io;
                    return EngineControlFrameReadResult.Fault;
                }
                if (count == 0)
                {
                    return Fault(EngineControlFault.TruncatedFrame, out fault);
                }
                filled += count;
            }

            kind = parsedKind;
            payload = body;
            return EngineControlFrameReadResult.Frame;
        }

        private static EngineControlFrameReadResult Fault(string value, out string fault)
        {
            fault = value;
            return EngineControlFrameReadResult.Fault;
        }

        private static bool TryParseKind(byte value, out EngineControlFrameKind kind)
        {
            switch (value)
            {
                case 1:
                    kind = EngineControlFrameKind.Challenge;
                    return true;
                case 2:
                    kind = EngineControlFrameKind.Hello;
                    return true;
                case 3:
                    kind = EngineControlFrameKind.Ready;
                    return true;
                case 4:
                    kind = EngineControlFrameKind.Request;
                    return true;
                case 5:
                    kind = EngineControlFrameKind.Response;
                    return true;
                case 6:
                    kind = EngineControlFrameKind.Fatal;
                    return true;
                default:
                    kind = EngineControlFrameKind.Fatal;
                    return false;
            }
        }
    }

    // One 32-byte per-launch session key. The key never crosses the control
    // channel. `ToString` is redacted. `Dispose` wipes the managed buffer.
    // A copy of managed memory can remain in the runtime, so this is not a
    // guarantee against a memory disclosure. It only removes the long-lived
    // copy that this class owns.
    public sealed class EngineControlSessionKey : IDisposable
    {
        private byte[] bytes;
        private bool disposed;

        private EngineControlSessionKey(byte[] value)
        {
            bytes = value;
        }

        public static EngineControlSessionKey CreateRandom()
        {
            byte[] value = new byte[EngineControlLimits.SessionKeyBytes];
            using (RandomNumberGenerator random = RandomNumberGenerator.Create())
            {
                random.GetBytes(value);
            }
            return new EngineControlSessionKey(value);
        }

        // Read exactly 64 hex bytes and one newline from a private descriptor.
        // A short line, a missing newline, or a non-hex byte is refused. The
        // temporary buffer is wiped on every path.
        public static bool TryReadFrom(
            Stream source,
            out EngineControlSessionKey key,
            out string code)
        {
            key = null;
            code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
            if (source == null)
            {
                return false;
            }

            byte[] text = new byte[EngineControlLimits.SessionKeyTextBytes + 1];
            try
            {
                int filled = 0;
                while (filled < text.Length)
                {
                    int count = source.Read(text, filled, text.Length - filled);
                    if (count == 0)
                    {
                        break;
                    }
                    filled += count;
                }
                if (filled != text.Length || text[EngineControlLimits.SessionKeyTextBytes] != (byte)'\n')
                {
                    return false;
                }

                byte[] value = new byte[EngineControlLimits.SessionKeyBytes];
                for (int index = 0; index < value.Length; index++)
                {
                    int high = HexValue(text[index * 2]);
                    int low = HexValue(text[(index * 2) + 1]);
                    if (high < 0 || low < 0)
                    {
                        Wipe(value);
                        return false;
                    }
                    value[index] = (byte)((high << 4) | low);
                }
                key = new EngineControlSessionKey(value);
                code = "";
                return true;
            }
            catch (Exception)
            {
                return false;
            }
            finally
            {
                Wipe(text);
            }
        }

        // Write the key to a private descriptor as 64 lowercase hex bytes and
        // one newline. A reviewed launcher calls this after it creates the
        // child key descriptor and before it starts the engine. The temporary
        // buffer is wiped on every path.
        public bool TryWriteTo(Stream destination)
        {
            if (disposed || destination == null)
            {
                return false;
            }
            byte[] text = new byte[EngineControlLimits.SessionKeyTextBytes + 1];
            for (int index = 0; index < bytes.Length; index++)
            {
                int value = bytes[index];
                text[index * 2] = HexDigit(value >> 4);
                text[(index * 2) + 1] = HexDigit(value & 0x0F);
            }
            text[EngineControlLimits.SessionKeyTextBytes] = (byte)'\n';
            try
            {
                destination.Write(text, 0, text.Length);
                destination.Flush();
                return true;
            }
            catch (Exception)
            {
                return false;
            }
            finally
            {
                Wipe(text);
            }
        }

        private static byte HexDigit(int value)
        {
            return value < 10
                ? (byte)('0' + value)
                : (byte)('a' + (value - 10));
        }

        internal static EngineControlSessionKey FromBytes(byte[] value)
        {
            if (value == null || value.Length != EngineControlLimits.SessionKeyBytes)
            {
                throw new ArgumentException("a session key is exactly 32 bytes", "value");
            }
            byte[] copy = new byte[value.Length];
            Buffer.BlockCopy(value, 0, copy, 0, value.Length);
            return new EngineControlSessionKey(copy);
        }

        internal byte[] CopyBytes()
        {
            if (disposed)
            {
                return new byte[0];
            }
            byte[] copy = new byte[bytes.Length];
            Buffer.BlockCopy(bytes, 0, copy, 0, bytes.Length);
            return copy;
        }

        public override string ToString()
        {
            return "EngineControlSessionKey([redacted])";
        }

        public void Dispose()
        {
            if (disposed)
            {
                return;
            }
            disposed = true;
            Wipe(bytes);
            bytes = new byte[0];
        }

        private static int HexValue(byte value)
        {
            if (value >= (byte)'0' && value <= (byte)'9')
            {
                return value - (byte)'0';
            }
            if (value >= (byte)'a' && value <= (byte)'f')
            {
                return value - (byte)'a' + 10;
            }
            if (value >= (byte)'A' && value <= (byte)'F')
            {
                return value - (byte)'A' + 10;
            }
            return -1;
        }

        private static void Wipe(byte[] value)
        {
            if (value == null)
            {
                return;
            }
            for (int index = 0; index < value.Length; index++)
            {
                value[index] = 0;
            }
        }
    }

    internal static class EngineControlProof
    {
        internal const string HelloLabel = "hotspotshade-desktop-control-v1/hello";
        internal const string ReadyLabel = "hotspotshade-desktop-control-v1/ready";

        internal static byte[] Compute(
            EngineControlSessionKey key,
            string label,
            byte[] serverNonce,
            byte[] clientNonce)
        {
            if (key == null || serverNonce == null || clientNonce == null
                || serverNonce.Length != EngineControlLimits.NonceBytes
                || clientNonce.Length != EngineControlLimits.NonceBytes)
            {
                return new byte[0];
            }
            byte[] keyBytes = key.CopyBytes();
            try
            {
                using (HMACSHA256 mac = new HMACSHA256(keyBytes))
                {
                    byte[] labelBytes = Encoding.ASCII.GetBytes(label);
                    byte[] input = new byte[labelBytes.Length + serverNonce.Length + clientNonce.Length];
                    Buffer.BlockCopy(labelBytes, 0, input, 0, labelBytes.Length);
                    Buffer.BlockCopy(serverNonce, 0, input, labelBytes.Length, serverNonce.Length);
                    Buffer.BlockCopy(
                        clientNonce,
                        0,
                        input,
                        labelBytes.Length + serverNonce.Length,
                        clientNonce.Length);
                    byte[] proof = mac.ComputeHash(input);
                    Array.Clear(input, 0, input.Length);
                    return proof;
                }
            }
            finally
            {
                Array.Clear(keyBytes, 0, keyBytes.Length);
            }
        }

        internal static byte[] RandomNonce()
        {
            byte[] nonce = new byte[EngineControlLimits.NonceBytes];
            using (RandomNumberGenerator random = RandomNumberGenerator.Create())
            {
                random.GetBytes(nonce);
            }
            return nonce;
        }

        internal static bool FixedTimeEquals(byte[] left, byte[] right)
        {
            if (left == null || right == null || left.Length != right.Length)
            {
                return false;
            }
            int difference = 0;
            for (int index = 0; index < left.Length; index++)
            {
                difference |= left[index] ^ right[index];
            }
            return difference == 0;
        }
    }

    // The client half of the authenticated engine control handshake and one
    // request/response exchange. It is not thread-safe. The session serializes
    // calls and owns the streams.
    internal sealed class EngineControlClient : IDisposable
    {
        private readonly Stream input;
        private readonly Stream output;
        private uint nextId;
        private bool closed;

        private EngineControlClient(Stream input, Stream output)
        {
            this.input = input;
            this.output = output;
            nextId = 1;
        }

        internal static bool TryConnect(
            Stream input,
            Stream output,
            EngineControlSessionKey key,
            out EngineControlClient client,
            out string code)
        {
            client = null;
            code = EngineProtocol.ErrorCodes.EngineUnavailable;
            if (input == null || output == null || key == null)
            {
                code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                return false;
            }

            EngineControlFrameKind kind;
            uint id;
            byte[] payload;
            string fault;
            EngineControlFrameReadResult read = EngineControlFrame.TryRead(
                input,
                EngineControlLimits.HelloBytes,
                out kind,
                out id,
                out payload,
                out fault);
            if (read == EngineControlFrameReadResult.Closed)
            {
                code = EngineProtocol.ErrorCodes.Closed;
                return false;
            }
            if (read != EngineControlFrameReadResult.Frame)
            {
                code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                return false;
            }
            if (kind != EngineControlFrameKind.Challenge
                || id != 0
                || payload.Length != EngineControlLimits.NonceBytes)
            {
                code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                return false;
            }
            byte[] serverNonce = payload;
            byte[] clientNonce = EngineControlProof.RandomNonce();
            byte[] helloProof = EngineControlProof.Compute(
                key,
                EngineControlProof.HelloLabel,
                serverNonce,
                clientNonce);
            if (helloProof.Length != EngineControlLimits.ProofBytes)
            {
                code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                return false;
            }
            byte[] hello = new byte[EngineControlLimits.HelloBytes];
            Buffer.BlockCopy(clientNonce, 0, hello, 0, clientNonce.Length);
            Buffer.BlockCopy(helloProof, 0, hello, clientNonce.Length, helloProof.Length);
            bool sent = EngineControlFrame.TryWrite(
                output,
                EngineControlFrameKind.Hello,
                0,
                hello,
                out fault);
            Array.Clear(hello, 0, hello.Length);
            Array.Clear(helloProof, 0, helloProof.Length);
            if (!sent)
            {
                code = EngineProtocol.ErrorCodes.Closed;
                return false;
            }

            read = EngineControlFrame.TryRead(
                input,
                EngineControlLimits.ProofBytes,
                out kind,
                out id,
                out payload,
                out fault);
            if (read == EngineControlFrameReadResult.Closed)
            {
                code = EngineProtocol.ErrorCodes.Closed;
                return false;
            }
            if (read != EngineControlFrameReadResult.Frame)
            {
                code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                return false;
            }
            if (kind == EngineControlFrameKind.Fatal)
            {
                code = MapFatal(payload);
                return false;
            }
            if (kind != EngineControlFrameKind.Ready
                || id != 0
                || payload.Length != EngineControlLimits.ProofBytes)
            {
                code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                return false;
            }
            byte[] expected = EngineControlProof.Compute(
                key,
                EngineControlProof.ReadyLabel,
                serverNonce,
                clientNonce);
            bool matches = expected.Length == payload.Length
                && EngineControlProof.FixedTimeEquals(expected, payload);
            Array.Clear(expected, 0, expected.Length);
            if (!matches)
            {
                code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                return false;
            }

            client = new EngineControlClient(input, output);
            code = "";
            return true;
        }

        internal bool TryStatus(out Dictionary<string, string> fields, out string code)
        {
            fields = null;
            byte[] response;
            if (!TryExchange(new byte[] { 1 }, out response, out code))
            {
                return false;
            }
            if (!TryDecodeStatus(response, out fields, out code))
            {
                Close();
                return false;
            }
            return true;
        }

        internal bool TryStart(bool ping, out string code)
        {
            byte pingCode = ping ? (byte)1 : (byte)2;
            byte[] response;
            if (!TryExchange(new byte[] { 10, 1, pingCode }, out response, out code))
            {
                return false;
            }
            if (!TryDecodeSuccess(response, out code))
            {
                Close();
                return false;
            }
            return true;
        }

        internal bool TryStop(out string code)
        {
            byte[] response;
            if (!TryExchange(new byte[] { 11 }, out response, out code))
            {
                return false;
            }
            if (!TryDecodeSuccess(response, out code))
            {
                Close();
                return false;
            }
            return true;
        }

        internal bool TryShutdown(out string code)
        {
            byte[] response;
            if (!TryExchange(new byte[] { 12 }, out response, out code))
            {
                return false;
            }
            if (!TryDecodeSuccess(response, out code))
            {
                Close();
                return false;
            }
            return true;
        }

        // One request and one response. The request identifier is allocated
        // before the write and never reused. A write or read failure closes
        // the client and is never retried. A validated failure reply keeps the
        // channel open.
        private bool TryExchange(byte[] command, out byte[] response, out string code)
        {
            response = null;
            code = EngineProtocol.ErrorCodes.Closed;
            if (closed || command == null || command.Length == 0
                || command.Length > EngineControlLimits.MaxRequestPayload)
            {
                code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                return false;
            }
            if (nextId == 0)
            {
                Close();
                code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                return false;
            }

            uint requestId = nextId;
            nextId = nextId + 1;
            string fault;
            if (!EngineControlFrame.TryWrite(
                output,
                EngineControlFrameKind.Request,
                requestId,
                command,
                out fault))
            {
                Close();
                code = EngineProtocol.ErrorCodes.Closed;
                return false;
            }

            EngineControlFrameKind kind;
            uint responseId;
            byte[] payload;
            EngineControlFrameReadResult read = EngineControlFrame.TryRead(
                input,
                EngineControlLimits.MaxResponsePayload,
                out kind,
                out responseId,
                out payload,
                out fault);
            if (read == EngineControlFrameReadResult.Closed)
            {
                Close();
                code = EngineProtocol.ErrorCodes.Closed;
                return false;
            }
            if (read != EngineControlFrameReadResult.Frame)
            {
                Close();
                code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                return false;
            }
            if (kind == EngineControlFrameKind.Fatal)
            {
                Close();
                code = MapFatal(payload);
                return false;
            }
            if (kind != EngineControlFrameKind.Response || responseId != requestId)
            {
                Close();
                code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                return false;
            }
            if (payload == null || payload.Length < 1)
            {
                Close();
                code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                return false;
            }
            if (payload[0] == 1)
            {
                if (payload.Length != 2)
                {
                    Close();
                    code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                    return false;
                }
                code = MapWireError(payload[1]);
                return false;
            }
            if (payload[0] != 0)
            {
                Close();
                code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                return false;
            }
            response = payload;
            code = "";
            return true;
        }

        internal bool IsClosed
        {
            get { return closed; }
        }

        internal void Close()
        {
            closed = true;
        }

        public void Dispose()
        {
            Close();
        }

        private static bool TryDecodeStatus(
            byte[] payload,
            out Dictionary<string, string> fields,
            out string code)
        {
            fields = null;
            code = EngineProtocol.ErrorCodes.BadResponse;
            if (payload == null || payload.Length < 3 || payload[0] != 0)
            {
                return false;
            }
            int jsonLength = payload.Length - 1;
            if (jsonLength > EngineServiceFrame.MaxFrameBytes - EngineServiceFrame.LengthPrefixBytes)
            {
                return false;
            }
            byte[] frame = new byte[EngineServiceFrame.LengthPrefixBytes + jsonLength];
            frame[0] = (byte)(jsonLength >> 24);
            frame[1] = (byte)(jsonLength >> 16);
            frame[2] = (byte)(jsonLength >> 8);
            frame[3] = (byte)jsonLength;
            Buffer.BlockCopy(payload, 1, frame, EngineServiceFrame.LengthPrefixBytes, jsonLength);
            bool decoded = EngineServiceFrame.TryDecode(
                frame,
                frame.Length,
                out fields,
                out code);
            Array.Clear(frame, 0, frame.Length);
            if (!decoded)
            {
                fields = null;
                code = EngineProtocol.ErrorCodes.BadResponse;
                return false;
            }
            return true;
        }

        private static bool TryDecodeSuccess(byte[] payload, out string code)
        {
            code = EngineProtocol.ErrorCodes.BadResponse;
            if (payload == null || payload.Length < 2 || payload[0] != 0)
            {
                return false;
            }
            // The engine returns one JSON object after the status byte. Start,
            // stop, and shutdown only need a validated success, so the shape
            // check is bounded and does not keep or interpret the body.
            int start = 1;
            int end = payload.Length - 1;
            while (start < end && IsJsonSpace(payload[start]))
            {
                start++;
            }
            while (end > start && IsJsonSpace(payload[end]))
            {
                end--;
            }
            if (payload[start] != (byte)'{' || payload[end] != (byte)'}')
            {
                return false;
            }
            code = "";
            return true;
        }

        private static bool IsJsonSpace(byte value)
        {
            return value == (byte)' ' || value == (byte)'\t'
                || value == (byte)'\r' || value == (byte)'\n';
        }

        private static string MapFatal(byte[] payload)
        {
            if (payload == null || payload.Length != 1)
            {
                return EngineProtocol.ErrorCodes.BoundaryAuthFailed;
            }
            return MapWireError(payload[0]);
        }

        private static string MapWireError(byte value)
        {
            switch (value)
            {
                case 1:
                    return EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                case 2:
                    return EngineProtocol.ErrorCodes.ProtocolMismatch;
                case 3:
                    return EngineProtocol.ErrorCodes.EngineUnavailable;
                case 4:
                    return EngineProtocol.ErrorCodes.Busy;
                case 5:
                    return EngineProtocol.ErrorCodes.Forbidden;
                case 6:
                    return EngineProtocol.ErrorCodes.Unsupported;
                case 7:
                    return EngineProtocol.ErrorCodes.Internal;
                case 8:
                    return EngineProtocol.ErrorCodes.BadResponse;
                default:
                    return EngineProtocol.ErrorCodes.BoundaryAuthFailed;
            }
        }
    }
}
