using System;
using System.Runtime.InteropServices;

namespace HotspotShade.WinUI2.Broker
{
    // The server side of the one-instance named pipe that the elevated
    // starter connects to. Every operation has a deadline. The OVERLAPPED
    // block, the event, and the buffer are unmanaged, and a timed-out
    // operation is cancelled and drained before the memory is freed.
    internal sealed class RendezvousPipe : IDisposable
    {
        private const int BufferSize = 64;

        // Only an elevated process can open the pipe: the access list grants
        // read and write to the Administrators group, which a filtered
        // standard token has only as a deny entry. SYSTEM has full access.
        // The OWNER RIGHTS entry limits the owner (this user, also at medium
        // integrity) to READ_CONTROL, so a same-user process cannot take
        // WRITE_DAC and open the one instance first.
        private const string Sddl = "D:P(A;;GRGW;;;BA)(A;;GA;;;SY)(A;;RC;;;OW)";

        private IntPtr pipe;
        private IntPtr ioEvent;
        private IntPtr overlapped;
        private IntPtr buffer;

        private RendezvousPipe()
        {
        }

        public static RendezvousPipe Create(string name)
        {
            RendezvousPipe created = new RendezvousPipe();
            IntPtr descriptor = IntPtr.Zero;
            try
            {
                if (!BrokerNative.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    Sddl,
                    BrokerNative.SddlRevision1,
                    out descriptor,
                    IntPtr.Zero))
                {
                    return null;
                }
                BrokerNative.SECURITY_ATTRIBUTES attributes = new BrokerNative.SECURITY_ATTRIBUTES();
                attributes.nLength = Marshal.SizeOf(typeof(BrokerNative.SECURITY_ATTRIBUTES));
                attributes.lpSecurityDescriptor = descriptor;
                attributes.bInheritHandle = false;
                IntPtr handle = BrokerNative.CreateNamedPipeW(
                    @"\\.\pipe\" + name,
                    BrokerNative.PipeAccessDuplex | BrokerNative.FileFlagFirstPipeInstance | BrokerNative.FileFlagOverlapped,
                    BrokerNative.PipeTypeByte | BrokerNative.PipeReadModeByte | BrokerNative.PipeWait | BrokerNative.PipeRejectRemoteClients,
                    1,
                    BufferSize,
                    BufferSize,
                    0,
                    ref attributes);
                if (handle == IntPtr.Zero || handle == new IntPtr(-1))
                {
                    return null;
                }
                created.pipe = handle;
                // Auto-reset: one wait consumes the signal. ResetOverlapped also clears it
                // before every operation so a stale signal never ends a wait early.
                created.ioEvent = BrokerNative.CreateEventW(IntPtr.Zero, false, false, null);
                created.overlapped = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(BrokerNative.OVERLAPPED)));
                created.buffer = Marshal.AllocHGlobal(BufferSize);
                if (created.ioEvent == IntPtr.Zero)
                {
                    created.Dispose();
                    return null;
                }
                return created;
            }
            finally
            {
                if (descriptor != IntPtr.Zero)
                {
                    BrokerNative.LocalFree(descriptor);
                }
            }
        }

        public IntPtr Handle
        {
            get { return pipe; }
        }

        // Wait for the client. A second handle (the starter process) ends the
        // wait when that process exits first.
        public bool WaitForClient(IntPtr process, uint milliseconds)
        {
            ResetOverlapped();
            if (BrokerNative.ConnectNamedPipe(pipe, overlapped))
            {
                return true;
            }
            int error = Marshal.GetLastWin32Error();
            if (error == BrokerNative.ErrorPipeConnected)
            {
                return true;
            }
            if (error != BrokerNative.ErrorIoPending)
            {
                return false;
            }
            IntPtr[] handles = process == IntPtr.Zero ? new[] { ioEvent } : new[] { ioEvent, process };
            uint wait = BrokerNative.WaitForMultipleObjects((uint)handles.Length, handles, false, milliseconds);
            if (wait == BrokerNative.WaitObject0)
            {
                int ignored;
                return BrokerNative.GetOverlappedResult(pipe, overlapped, out ignored, true);
            }
            Cancel();
            return false;
        }

        public bool Write(byte[] data, uint milliseconds)
        {
            if (data == null || data.Length == 0 || data.Length > BufferSize)
            {
                return false;
            }
            Marshal.Copy(data, 0, buffer, data.Length);
            try
            {
                ResetOverlapped();
                int transferred;
                if (!BrokerNative.WriteFile(pipe, buffer, data.Length, IntPtr.Zero, overlapped))
                {
                    if (Marshal.GetLastWin32Error() != BrokerNative.ErrorIoPending)
                    {
                        return false;
                    }
                    if (BrokerNative.WaitForSingleObject(ioEvent, milliseconds) != BrokerNative.WaitObject0)
                    {
                        Cancel();
                        return false;
                    }
                }
                return BrokerNative.GetOverlappedResult(pipe, overlapped, out transferred, true)
                    && transferred == data.Length;
            }
            finally
            {
                Clear();
            }
        }

        // Read exactly count bytes, or fail at the deadline.
        public byte[] Read(int count, uint milliseconds)
        {
            if (count <= 0 || count > BufferSize)
            {
                return null;
            }
            DateTime deadline = DateTime.UtcNow.AddMilliseconds(milliseconds);
            byte[] result = new byte[count];
            int have = 0;
            try
            {
                while (have < count)
                {
                    double left = (deadline - DateTime.UtcNow).TotalMilliseconds;
                    if (left <= 0)
                    {
                        return null;
                    }
                    ResetOverlapped();
                    int transferred;
                    if (!BrokerNative.ReadFile(pipe, buffer, count - have, IntPtr.Zero, overlapped))
                    {
                        if (Marshal.GetLastWin32Error() != BrokerNative.ErrorIoPending)
                        {
                            return null;
                        }
                        if (BrokerNative.WaitForSingleObject(ioEvent, (uint)left) != BrokerNative.WaitObject0)
                        {
                            Cancel();
                            return null;
                        }
                    }
                    if (!BrokerNative.GetOverlappedResult(pipe, overlapped, out transferred, true) || transferred <= 0)
                    {
                        return null;
                    }
                    Marshal.Copy(buffer, result, have, transferred);
                    have += transferred;
                }
                return result;
            }
            finally
            {
                Clear();
            }
        }

        public int ClientProcessId()
        {
            uint id;
            if (!BrokerNative.GetNamedPipeClientProcessId(pipe, out id) || id == 0 || id > int.MaxValue)
            {
                return 0;
            }
            return (int)id;
        }

        public void Dispose()
        {
            if (pipe != IntPtr.Zero)
            {
                BrokerNative.CloseHandle(pipe);
                pipe = IntPtr.Zero;
            }
            if (ioEvent != IntPtr.Zero)
            {
                BrokerNative.CloseHandle(ioEvent);
                ioEvent = IntPtr.Zero;
            }
            if (overlapped != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(overlapped);
                overlapped = IntPtr.Zero;
            }
            if (buffer != IntPtr.Zero)
            {
                Clear();
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
            }
        }

        private void ResetOverlapped()
        {
            BrokerNative.ResetEvent(ioEvent);
            BrokerNative.OVERLAPPED value = new BrokerNative.OVERLAPPED();
            value.hEvent = ioEvent;
            Marshal.StructureToPtr(value, overlapped, false);
        }

        // Cancel the pending operation and wait until Windows no longer uses
        // the OVERLAPPED block or the buffer.
        private void Cancel()
        {
            BrokerNative.CancelIoEx(pipe, overlapped);
            int ignored;
            BrokerNative.GetOverlappedResult(pipe, overlapped, out ignored, true);
        }

        private void Clear()
        {
            if (buffer == IntPtr.Zero)
            {
                return;
            }
            for (int index = 0; index < BufferSize; index++)
            {
                Marshal.WriteByte(buffer, index, 0);
            }
        }
    }
}
