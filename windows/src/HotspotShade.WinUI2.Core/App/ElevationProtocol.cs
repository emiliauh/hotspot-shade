using System;

namespace HotspotShade.WinUI2.Core.App
{
    // The private protocol between the broker and the elevated starter.
    //
    // At Turn on, the broker starts HotspotShade.WinUI2.Elevate.exe with the
    // Windows runas verb, which shows one UAC prompt. The only argument is a
    // random rendezvous token that names one named pipe. The token is not a
    // secret: the pipe allows one instance, rejects remote clients, and the
    // broker accepts only the process id that the UAC start returned.
    //
    // The broker sends one request frame with the values of three of its own
    // handles: the token pipe read end, the parent-liveness read end, and the
    // pairing handoff read end. The starter duplicates them from the broker
    // into itself, starts the elevated engine with an explicit inherited
    // handle list, and answers with the engine process id. The starter never
    // reads the secret or the pairing bytes. The broker writes the secret and
    // keeps the parent-liveness write end, so the elevated engine stops when
    // the broker exits.
    public static class ElevationProtocol
    {
        public const int TokenHexLength = 32;
        public const string PipePrefix = "HotspotShade.Elevate.";
        public const string StarterFileName = "HotspotShade.WinUI2.Elevate.exe";
        public const int RequestLength = 31;
        public const int ReplyLength = 9;
        public const byte Version = 1;
        // A handle value above this bound is not a handle that Windows hands
        // out to a process, so the frame is refused.
        public const long MaxHandle = 0xFFFFFFFFL;

        private static readonly byte[] Magic = { (byte)'H', (byte)'S', (byte)'E', (byte)'1' };

        public static bool IsRendezvousToken(string value)
        {
            if (value == null || value.Length != TokenHexLength)
            {
                return false;
            }
            for (int index = 0; index < value.Length; index++)
            {
                char c = value[index];
                bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
                if (!hex)
                {
                    return false;
                }
            }
            return true;
        }

        public static string PipeName(string token)
        {
            if (!IsRendezvousToken(token))
            {
                throw new ArgumentException("token");
            }
            return PipePrefix + token;
        }

        public static byte[] EncodeRequest(ElevationRequest request)
        {
            if (request == null || !request.IsValid)
            {
                throw new ArgumentException("request");
            }
            byte[] frame = new byte[RequestLength];
            Array.Copy(Magic, frame, Magic.Length);
            frame[4] = Version;
            frame[5] = (byte)(request.Port & 0xFF);
            frame[6] = (byte)((request.Port >> 8) & 0xFF);
            WriteUInt64(frame, 7, request.TokenHandle);
            WriteUInt64(frame, 15, request.ParentHandle);
            WriteUInt64(frame, 23, request.CredentialsHandle);
            return frame;
        }

        public static bool TryDecodeRequest(byte[] frame, int length, out ElevationRequest request)
        {
            request = null;
            if (frame == null || length != RequestLength || frame.Length < RequestLength || !HasMagic(frame))
            {
                return false;
            }
            if (frame[4] != Version)
            {
                return false;
            }
            int port = frame[5] | (frame[6] << 8);
            ElevationRequest parsed = new ElevationRequest(
                port,
                ReadUInt64(frame, 7),
                ReadUInt64(frame, 15),
                ReadUInt64(frame, 23));
            if (!parsed.IsValid)
            {
                return false;
            }
            request = parsed;
            return true;
        }

        public static byte[] EncodeReply(ElevationReplyCode code, int processId)
        {
            byte[] frame = new byte[ReplyLength];
            Array.Copy(Magic, frame, Magic.Length);
            frame[4] = (byte)code;
            uint pid = code == ElevationReplyCode.Started ? unchecked((uint)processId) : 0U;
            frame[5] = (byte)(pid & 0xFF);
            frame[6] = (byte)((pid >> 8) & 0xFF);
            frame[7] = (byte)((pid >> 16) & 0xFF);
            frame[8] = (byte)((pid >> 24) & 0xFF);
            return frame;
        }

        public static bool TryDecodeReply(byte[] frame, int length, out ElevationReplyCode code, out int processId)
        {
            code = ElevationReplyCode.Failed;
            processId = 0;
            if (frame == null || length != ReplyLength || frame.Length < ReplyLength || !HasMagic(frame))
            {
                return false;
            }
            if (!Enum.IsDefined(typeof(ElevationReplyCode), (int)frame[4]))
            {
                return false;
            }
            ElevationReplyCode parsed = (ElevationReplyCode)frame[4];
            uint pid = (uint)(frame[5] | (frame[6] << 8) | (frame[7] << 16) | (frame[8] << 24));
            if (parsed == ElevationReplyCode.Started)
            {
                if (pid == 0 || pid > int.MaxValue)
                {
                    return false;
                }
            }
            else if (pid != 0)
            {
                return false;
            }
            code = parsed;
            processId = (int)pid;
            return true;
        }

        private static bool HasMagic(byte[] frame)
        {
            for (int index = 0; index < Magic.Length; index++)
            {
                if (frame[index] != Magic[index])
                {
                    return false;
                }
            }
            return true;
        }

        private static void WriteUInt64(byte[] frame, int offset, long value)
        {
            ulong bits = unchecked((ulong)value);
            for (int index = 0; index < 8; index++)
            {
                frame[offset + index] = (byte)((bits >> (8 * index)) & 0xFF);
            }
        }

        private static long ReadUInt64(byte[] frame, int offset)
        {
            ulong bits = 0;
            for (int index = 7; index >= 0; index--)
            {
                bits = (bits << 8) | frame[offset + index];
            }
            return unchecked((long)bits);
        }
    }

    // The starter answer. The value is one byte on the wire.
    public enum ElevationReplyCode
    {
        Started = 0,
        // The starter is not elevated. Nothing was started.
        NotElevated = 1,
        // The pipe server is not the packaged broker.
        BrokerRejected = 2,
        // The broker process could not be opened for handle duplication.
        // This happens when the approving account is not the signed-in one.
        OtherAccount = 3,
        // A duplicated handle is not a pipe, or a duplication failed.
        HandleRejected = 4,
        // The engine file is missing from the package.
        EngineMissing = 5,
        // wintun.dll is missing next to the engine.
        AdapterDllMissing = 6,
        // The engine process could not be created.
        Failed = 7,
        // The package is not installed under Program Files\WindowsApps.
        InstallUntrusted = 8
    }

    // One request frame. The handles are values in the broker process.
    public sealed class ElevationRequest
    {
        public ElevationRequest(int port, long tokenHandle, long parentHandle, long credentialsHandle)
        {
            Port = port;
            TokenHandle = tokenHandle;
            ParentHandle = parentHandle;
            CredentialsHandle = credentialsHandle;
        }

        public int Port { get; private set; }

        public long TokenHandle { get; private set; }

        public long ParentHandle { get; private set; }

        public long CredentialsHandle { get; private set; }

        public bool IsValid
        {
            get
            {
                if (Port < 1024 || Port > 65535)
                {
                    return false;
                }
                if (!IsHandle(TokenHandle) || !IsHandle(ParentHandle) || !IsHandle(CredentialsHandle))
                {
                    return false;
                }
                return TokenHandle != ParentHandle
                    && TokenHandle != CredentialsHandle
                    && ParentHandle != CredentialsHandle;
            }
        }

        private static bool IsHandle(long value)
        {
            return value > 0 && value <= ElevationProtocol.MaxHandle;
        }
    }
}
