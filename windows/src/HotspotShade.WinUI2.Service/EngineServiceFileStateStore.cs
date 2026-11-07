using System;
using System.Collections.Generic;
using System.IO;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;
using HotspotShade.WinUI2.ServiceHost;

namespace HotspotShade.WinUI2.Service
{
    // A bounded, read-only durable state store. The installer writes one
    // EngineServiceFrame object with the never-launched record. This class
    // never creates, replaces, or deletes the file.
    //
    // Fail closed:
    //   - a missing, empty, oversized, or unreadable file is refused,
    //   - a leaf reparse point is refused,
    //   - a short read, a file that grows during the read, or trailing bytes
    //     are refused,
    //   - the frame decoder and the core state parser apply the field rules.
    //
    // This is not the complete protected store from the design. A parent
    // directory reparse, an ACL that lets another account write the file, a
    // write path, a flush, and an atomic replace are not implemented here.
    // The service never starts an engine in this build, so a forged clean
    // record cannot launch anything, but an independent review must treat
    // the file as untrusted input.
    public sealed class EngineServiceFileStateStore : IEngineServiceDurableStateStore
    {
        public const int MaxStateBytes = EngineServiceFrame.MaxFrameBytes;

        private readonly string path;

        public EngineServiceFileStateStore(string path)
            : this(path, false)
        {
        }

        // The normalized form is used by the product path. A hermetic check
        // on a non-Windows host supplies a host-native temporary path so the
        // read, frame, and gate rules can be exercised without a Windows
        // service.
        internal EngineServiceFileStateStore(string path, bool pathAlreadyNormalized)
        {
            if (pathAlreadyNormalized)
            {
                if (string.IsNullOrEmpty(path))
                {
                    throw new ArgumentException("the state path is empty", "path");
                }
                this.path = path;
                return;
            }
            string normalized;
            if (!EngineServiceConfiguration.TryNormalizeStatePath(path, out normalized))
            {
                throw new ArgumentException(
                    "the state path must be an absolute local drive file path",
                    "path");
            }
            this.path = normalized;
        }

        public string Path
        {
            get { return path; }
        }

        public bool TryRead(out EngineServiceStateGate gate, out string code)
        {
            gate = EngineServiceStateGate.Missing;
            code = EngineProtocol.ErrorCodes.CleanupUnknown;
            try
            {
                FileAttributes attributes = File.GetAttributes(path);
                if ((attributes & FileAttributes.ReparsePoint) != 0
                    || (attributes & FileAttributes.Directory) != 0)
                {
                    return false;
                }

                FileInfo info = new FileInfo(path);
                if (!info.Exists || info.Length <= 0 || info.Length > MaxStateBytes)
                {
                    return false;
                }

                byte[] frame = new byte[(int)info.Length];
                using (FileStream stream = new FileStream(
                    path,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read,
                    4096,
                    FileOptions.SequentialScan))
                {
                    int total = 0;
                    while (total < frame.Length)
                    {
                        int read = stream.Read(frame, total, frame.Length - total);
                        if (read <= 0)
                        {
                            return false;
                        }
                        total += read;
                    }
                    if (stream.ReadByte() != -1)
                    {
                        // The file grew after the length check. Do not parse a
                        // prefix as if it were the whole record.
                        return false;
                    }
                }

                Dictionary<string, string> fields;
                string decodeCode;
                if (!EngineServiceFrame.TryDecode(frame, frame.Length, out fields, out decodeCode))
                {
                    return false;
                }

                EngineServiceStateGate loaded;
                string loadCode;
                if (!EngineServiceStateGate.TryLoad(
                    true,
                    true,
                    fields,
                    out loaded,
                    out loadCode)
                    || loaded == null
                    || !loaded.HasRecord)
                {
                    return false;
                }

                gate = loaded;
                code = "";
                return true;
            }
            catch (Exception)
            {
                gate = EngineServiceStateGate.Missing;
                code = EngineProtocol.ErrorCodes.CleanupUnknown;
                return false;
            }
        }
    }
}
