using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace HotspotShade.WinUI2.TestLauncher
{
    // Read the IPv4 and IPv6 TCP listener tables with the owning process ids.
    // The launcher sends the bearer secret only to a port that the launched
    // engine holds alone. The check is repeated before every request. The
    // engine also binds its listener with SO_EXCLUSIVEADDRUSE, so a second
    // listener cannot share the IPv4 port. This check is still not an atomic
    // proof: the table can change after the read.
    internal static class ListenerTable
    {
        private const int AfInet = 2;
        private const int AfInet6 = 23;
        private const int TcpTableOwnerPidListener = 3;
        private const uint NoError = 0;
        private const uint ErrorInsufficientBuffer = 122;
        // With IPv6 disabled the AF_INET6 table is not readable. That means
        // there is no IPv6 listener, so the table counts as empty.
        private const uint ErrorFileNotFound = 2;
        private const uint ErrorNotSupported = 50;
        // MIB_TCPROW_OWNER_PID: state, local address, local port, remote
        // address, remote port, owning pid.
        private const int Row4Size = 24;
        private const int Row4PortOffset = 8;
        private const int Row4PidOffset = 20;
        // MIB_TCP6ROW_OWNER_PID: local address[16], local scope id, local
        // port, remote address[16], remote scope id, remote port, state,
        // owning pid.
        private const int Row6Size = 56;
        private const int Row6PortOffset = 20;
        private const int Row6PidOffset = 52;

        public static ListenerOwnership Check(int port, int processId)
        {
            List<ListenerRow> rows = new List<ListenerRow>();
            uint error4;
            uint error6;
            if (!TryRead(AfInet, Row4Size, Row4PortOffset, Row4PidOffset, rows, out error4)
                || (!TryRead(AfInet6, Row6Size, Row6PortOffset, Row6PidOffset, rows, out error6)
                    && !Ipv6Unavailable(error6)))
            {
                return ListenerOwnership.Unknown;
            }
            return LauncherRules.Classify(rows, port, processId);
        }

        public static bool Ipv6Unavailable(uint error)
        {
            return error == ErrorNotSupported || error == ErrorFileNotFound;
        }

        private static bool TryRead(int family, int rowSize, int portOffset, int pidOffset, List<ListenerRow> rows, out uint error)
        {
            error = NoError;
            int size = 0;
            for (int attempt = 0; attempt < 4; attempt++)
            {
                IntPtr table = IntPtr.Zero;
                try
                {
                    if (size > 0)
                    {
                        table = Marshal.AllocHGlobal(size);
                    }
                    uint result = GetExtendedTcpTable(table, ref size, false, family, TcpTableOwnerPidListener, 0);
                    if (result == ErrorInsufficientBuffer)
                    {
                        continue;
                    }
                    if (result != NoError || table == IntPtr.Zero || size < 4)
                    {
                        error = result != NoError ? result : ErrorInsufficientBuffer;
                        return false;
                    }
                    int count = Marshal.ReadInt32(table, 0);
                    if (count < 0 || (long)count * rowSize + 4 > size)
                    {
                        return false;
                    }
                    for (int index = 0; index < count; index++)
                    {
                        int offset = 4 + index * rowSize;
                        uint localPort = unchecked((uint)Marshal.ReadInt32(table, offset + portOffset));
                        int owner = Marshal.ReadInt32(table, offset + pidOffset);
                        rows.Add(new ListenerRow(LauncherRules.PortFromRowField(localPort), owner));
                    }
                    return true;
                }
                finally
                {
                    if (table != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(table);
                    }
                }
            }
            return false;
        }

        [DllImport("iphlpapi.dll", SetLastError = false)]
        private static extern uint GetExtendedTcpTable(
            IntPtr table,
            ref int size,
            bool order,
            int addressFamily,
            int tableClass,
            uint reserved);
    }
}
