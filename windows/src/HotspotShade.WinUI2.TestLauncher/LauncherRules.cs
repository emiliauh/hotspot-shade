using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;

namespace HotspotShade.WinUI2.TestLauncher
{
    // The result of one check of the loopback listener table.
    internal enum ListenerOwnership
    {
        // Exactly the launched engine listens on the port.
        Owned,
        // No process listens on the port yet.
        Missing,
        // Another process also listens on the port, or holds it alone.
        Foreign,
        // The listener table could not be read. Nothing is sent.
        Unknown
    }

    // One IPv4 listener row: the local port in host order and the owning
    // process id.
    internal struct ListenerRow
    {
        public ListenerRow(int port, int processId)
        {
            Port = port;
            ProcessId = processId;
        }

        public int Port;
        public int ProcessId;
    }

    // Pure rules for the test launcher. Nothing here opens a process, a
    // network connection, a pipe, or a file. The hermetic test project compiles this file.
    internal static class LauncherRules
    {
        public const int MaximumTokenLength = 255;
        public const int MaximumBody = 2048;

        // MIB_TCPROW_OWNER_PID stores the port in network byte order in the low
        // 16 bits of a 32-bit field.
        public static int PortFromRowField(uint value)
        {
            return (int)(((value & 0xFF) << 8) | ((value >> 8) & 0xFF));
        }

        // The listener is owned only when the engine listens on the port and no
        // other process listens on the same port on any IPv4 address. A second
        // listener can take loopback connections on Windows, so it makes the
        // port untrusted.
        public static ListenerOwnership Classify(IList<ListenerRow> rows, int port, int processId)
        {
            if (rows == null || processId <= 0)
            {
                return ListenerOwnership.Foreign;
            }
            bool engine = false;
            for (int index = 0; index < rows.Count; index++)
            {
                if (rows[index].Port != port)
                {
                    continue;
                }
                if (rows[index].ProcessId != processId)
                {
                    return ListenerOwnership.Foreign;
                }
                engine = true;
            }
            return engine ? ListenerOwnership.Owned : ListenerOwnership.Missing;
        }

        // An elevated engine loads wintun.dll from its own directory, so that
        // directory must not be writable by a standard user. The launcher
        // accepts only a directory inside Program Files when it is elevated. A
        // standard-user engine cannot change routes, so any directory works.
        public static bool IsTrustedInstallDirectory(string directory, string programFiles, bool elevated)
        {
            if (!elevated)
            {
                return true;
            }
            if (string.IsNullOrEmpty(directory) || string.IsNullOrEmpty(programFiles))
            {
                return false;
            }
            string full;
            string root;
            try
            {
                full = Path.GetFullPath(directory).TrimEnd('\\', '/');
                root = Path.GetFullPath(programFiles).TrimEnd('\\', '/');
            }
            catch (Exception)
            {
                return false;
            }
            if (full.IndexOf("..", StringComparison.Ordinal) >= 0 || root.Length < 3)
            {
                return false;
            }
            return full.StartsWith(root + "\\", StringComparison.OrdinalIgnoreCase);
        }

        // A source device token must be printable ASCII without a space. The
        // source device apps generate such tokens. A token outside this set is
        // refused before it reaches a buffer.
        public static bool IsTokenCharacter(char value)
        {
            return value > ' ' && value < (char)0x7F;
        }

        public static bool TryParseAddress(string text, out byte[] address)
        {
            address = null;
            if (text == null)
            {
                return false;
            }
            string[] parts = text.Trim().Split('.');
            if (parts.Length != 4)
            {
                return false;
            }
            byte[] value = new byte[4];
            for (int index = 0; index < 4; index++)
            {
                int part;
                if (parts[index].Length == 0
                    || parts[index].Length > 3
                    || (parts[index].Length > 1 && parts[index][0] == '0')
                    || !int.TryParse(parts[index], NumberStyles.None, CultureInfo.InvariantCulture, out part)
                    || part > 255)
                {
                    return false;
                }
                value[index] = (byte)part;
            }
            if (value[0] == 0 || value[0] == 127 || value[0] >= 224)
            {
                return false;
            }
            address = value;
            return true;
        }

        public static bool TryParsePort(string text, out int port)
        {
            port = 0;
            if (text == null)
            {
                return false;
            }
            int value;
            if (!int.TryParse(text.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out value))
            {
                return false;
            }
            if (value < 1 || value > 65535)
            {
                return false;
            }
            port = value;
            return true;
        }

        // Build {"mode":"phone","options":{...}} for /api/start, or
        // {"options":{...}} for /api/phone/check. Only a start carries the
        // ping choice. A null address and a null token send neither field, so
        // the engine uses the target that it already holds. A null token
        // field, so the engine uses the target that it already holds. The
        // body is written into one fixed buffer. The caller clears it after
        // the request.
        public static byte[] BuildPhoneBody(
            bool start,
            byte[] address,
            int port,
            char[] token,
            int tokenLength,
            bool ping)
        {
            byte[] buffer = new byte[MaximumBody];
            int at = 0;
            try
            {
                if (start)
                {
                    at = Append(buffer, at, "{\"mode\":\"phone\",\"options\":{");
                }
                else
                {
                    at = Append(buffer, at, "{\"options\":{");
                }
                bool comma = false;
                if (address != null)
                {
                    if (address.Length != 4)
                    {
                        throw new ArgumentException("address");
                    }
                    at = Append(buffer, at, "\"host\":\"");
                    for (int index = 0; index < 4; index++)
                    {
                        if (index > 0)
                        {
                            at = Append(buffer, at, ".");
                        }
                        at = Append(buffer, at, address[index].ToString(CultureInfo.InvariantCulture));
                    }
                    at = Append(buffer, at, "\",\"port\":");
                    if (port < 1 || port > 65535)
                    {
                        throw new ArgumentException("port");
                    }
                    at = Append(buffer, at, port.ToString(CultureInfo.InvariantCulture));
                    comma = true;
                }
                if (token != null)
                {
                    if (tokenLength < 1 || tokenLength > MaximumTokenLength || tokenLength > token.Length)
                    {
                        throw new ArgumentException("token");
                    }
                    if (comma)
                    {
                        at = Append(buffer, at, ",");
                    }
                    at = Append(buffer, at, "\"token\":\"");
                    for (int index = 0; index < tokenLength; index++)
                    {
                        char value = token[index];
                        if (!IsTokenCharacter(value))
                        {
                            throw new ArgumentException("token");
                        }
                        if (value == '"' || value == '\\')
                        {
                            at = Put(buffer, at, (byte)'\\');
                        }
                        at = Put(buffer, at, (byte)value);
                    }
                    at = Append(buffer, at, "\"");
                    comma = true;
                }
                if (start)
                {
                    if (comma)
                    {
                        at = Append(buffer, at, ",");
                    }
                    at = Append(buffer, at, ping ? "\"experimental_icmp\":true" : "\"experimental_icmp\":false");
                }
                at = Append(buffer, at, "}}");
                byte[] body = new byte[at];
                Buffer.BlockCopy(buffer, 0, body, 0, at);
                return body;
            }
            finally
            {
                Array.Clear(buffer, 0, buffer.Length);
            }
        }

        private static int Append(byte[] buffer, int at, string text)
        {
            for (int index = 0; index < text.Length; index++)
            {
                at = Put(buffer, at, (byte)text[index]);
            }
            return at;
        }

        private static int Put(byte[] buffer, int at, byte value)
        {
            if (at >= buffer.Length)
            {
                throw new ArgumentException("body too large");
            }
            buffer[at] = value;
            return at + 1;
        }
    }
}
