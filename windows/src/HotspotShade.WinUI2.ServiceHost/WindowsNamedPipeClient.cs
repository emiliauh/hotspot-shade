using System;
using System.Runtime.InteropServices;
using System.Threading;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.ServiceHost
{
    internal sealed class WindowsClientPipeConnection :
        IEngineServiceClientPipe,
        IEngineServiceClientPipeWriteEvidence
    {
        private readonly object ioLock = new object();
        private IntPtr handle;
        private bool disposed;

        public WindowsClientPipeConnection(IntPtr handle)
        {
            this.handle = handle;
        }

        public bool TryReadFrame(
            TimeSpan budget,
            CancellationToken cancellationToken,
            out byte[] frame,
            out EngineServiceFrameReadOutcome outcome,
            out string code)
        {
            // The lock keeps CloseHandle behind an active ReadFile or
            // WriteFile. Closing a handle cancels its I/O, but the kernel can
            // still touch the OVERLAPPED and the pinned buffer until that
            // cancellation completes.
            lock (ioLock)
            {
                frame = null;
                outcome = EngineServiceFrameReadOutcome.Failed;
                if (disposed || handle == IntPtr.Zero)
                {
                    code = EngineProtocol.ErrorCodes.EngineUnavailable;
                    return false;
                }
                if (budget <= TimeSpan.Zero)
                {
                    // An expired budget starts no kernel operation and
                    // consumes no reply byte.
                    code = EngineProtocol.ErrorCodes.Timeout;
                    return false;
                }
                // The outcome is kept, so the caller can tell a proven
                // zero-byte reply read from a read that consumed a byte or
                // could not prove a zero transfer. It is never a clean
                // refusal.
                return WindowsNamedPipeIo.TryReadFrame(
                    handle,
                    budget,
                    cancellationToken,
                    out frame,
                    out outcome,
                    out code);
            }
        }

        public bool TryWriteFrame(
            byte[] frame,
            TimeSpan budget,
            CancellationToken cancellationToken,
            out string code)
        {
            EngineServiceRequestWriteProof ignoredProof;
            return TryWriteFrame(
                frame,
                budget,
                cancellationToken,
                out ignoredProof,
                out code);
        }

        public bool TryWriteFrame(
            byte[] frame,
            TimeSpan budget,
            CancellationToken cancellationToken,
            out EngineServiceRequestWriteProof proof,
            out string code)
        {
            lock (ioLock)
            {
                if (disposed || handle == IntPtr.Zero)
                {
                    proof = EngineServiceRequestWriteProof.NotStarted;
                    code = EngineProtocol.ErrorCodes.EngineUnavailable;
                    return false;
                }
                if (budget <= TimeSpan.Zero)
                {
                    // An expired budget starts no kernel write, so no part of
                    // the request frame reached the pipe.
                    proof = EngineServiceRequestWriteProof.NotStarted;
                    code = EngineProtocol.ErrorCodes.Timeout;
                    return false;
                }
                return WindowsNamedPipeIo.TryWriteFrame(
                    handle,
                    frame,
                    budget,
                    cancellationToken,
                    out code,
                    out proof,
                    WindowsPipeIoEnvironment.Shared);
            }
        }

        public bool TryGetServerProcessId(out int processId)
        {
            lock (ioLock)
            {
                if (disposed || handle == IntPtr.Zero)
                {
                    processId = 0;
                    return false;
                }
                return WindowsNamedPipeIo.TryGetServerProcessId(handle, out processId);
            }
        }

        public bool TryGetOwnerSid(out string sid)
        {
            lock (ioLock)
            {
                if (disposed || handle == IntPtr.Zero)
                {
                    sid = "";
                    return false;
                }
                string code;
                return WindowsPipeSecurity.TryGetOwnerSid(handle, out sid, out code);
            }
        }

        public void Dispose()
        {
            // Dispose waits for the active frame call. The channel also waits
            // for its whole exchange before it calls this method.
            lock (ioLock)
            {
                if (disposed)
                {
                    return;
                }
                disposed = true;
                IntPtr current = handle;
                handle = IntPtr.Zero;
                if (current != IntPtr.Zero)
                {
                    WindowsPipeNativeMethods.CloseHandle(current);
                }
            }
        }
    }

    // Opens the fixed pipe name with exactly 0x00120183, share mode zero,
    // OPEN_EXISTING, and SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION. It
    // does not request GENERIC_READ or GENERIC_WRITE, which would ask for the
    // create-instance bit. An access denial is boundary_auth_failed. There is
    // no fallback mask and no second name.
    //
    // The factory holds no read or write budget. Every frame call passes the
    // per-operation budget from the channel, so a start reply is not cut at
    // the short budget that serves hello and status.
    public sealed class WindowsNamedPipeClientFactory : IEngineServiceClientPipeFactory
    {
        private readonly IEngineServiceEventSink events;

        public WindowsNamedPipeClientFactory(IEngineServiceEventSink events)
        {
            if (events == null)
            {
                throw new ArgumentNullException("events");
            }
            this.events = events;
        }

        public bool TryOpen(out IEngineServiceClientPipe pipe, out string code)
        {
            pipe = null;
            if (!EngineServicePlatform.IsWindows)
            {
                code = EngineProtocol.ErrorCodes.Unsupported;
                return false;
            }
            string validation;
            if (!EngineServiceBoundary.TryValidatePipeClientAccess(
                EngineServiceBoundary.PipeClientAccess,
                out validation))
            {
                code = EngineProtocol.ErrorCodes.Forbidden;
                events.Record(EngineServiceEventCodes.ClientAccessRefused);
                return false;
            }

            uint flags = WindowsPipeNativeMethods.FileFlagOverlapped
                | WindowsPipeNativeMethods.SecuritySqosPresent
                | WindowsPipeNativeMethods.SecurityIdentification;
            IntPtr handle = WindowsPipeNativeMethods.CreateFileW(
                EngineServiceBoundary.PipeName,
                EngineServiceBoundary.PipeClientAccess,
                0,
                IntPtr.Zero,
                WindowsPipeNativeMethods.OpenExisting,
                flags,
                IntPtr.Zero);
            if (handle == IntPtr.Zero || handle == new IntPtr(-1))
            {
                int error = Marshal.GetLastWin32Error();
                if (error == WindowsPipeNativeMethods.ErrorAccessDenied)
                {
                    events.Record(EngineServiceEventCodes.ClientAccessRefused);
                    code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                    return false;
                }
                if (error == WindowsPipeNativeMethods.ErrorPipeBusy)
                {
                    events.Record(EngineServiceEventCodes.ClientBusy);
                    code = EngineProtocol.ErrorCodes.BoundaryBusy;
                    return false;
                }
                events.Record(EngineServiceEventCodes.ClientOpenFailed);
                code = EngineProtocol.ErrorCodes.EngineUnavailable;
                return false;
            }

            pipe = new WindowsClientPipeConnection(handle);
            code = "";
            return true;
        }
    }

    // Reads only the SCM state and the configured binary path. It does not
    // install, start, change, or delete a service. The service must already be
    // running for the app-side proof to pass.
    public sealed class WindowsScmInspector : IEngineServiceScmInspector
    {
        public bool TryQuery(out EngineServiceScmState state, out string code)
        {
            state = null;
            if (!EngineServicePlatform.IsWindows)
            {
                code = EngineProtocol.ErrorCodes.Unsupported;
                return false;
            }

            IntPtr manager = WindowsPipeNativeMethods.OpenSCManagerW(
                null,
                null,
                WindowsPipeNativeMethods.ScManagerConnect);
            if (manager == IntPtr.Zero)
            {
                code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                return false;
            }

            IntPtr service = IntPtr.Zero;
            try
            {
                service = WindowsPipeNativeMethods.OpenServiceW(
                    manager,
                    EngineServiceBoundary.ServiceName,
                    WindowsPipeNativeMethods.ServiceQueryStatus
                        | WindowsPipeNativeMethods.ServiceQueryConfig);
                if (service == IntPtr.Zero)
                {
                    code = Marshal.GetLastWin32Error() == WindowsPipeNativeMethods.ErrorAccessDenied
                        ? EngineProtocol.ErrorCodes.BoundaryAuthFailed
                        : EngineProtocol.ErrorCodes.EngineUnavailable;
                    return false;
                }

                WindowsPipeNativeMethods.ServiceStatusProcess status;
                if (!TryReadStatus(service, out status))
                {
                    code = EngineProtocol.ErrorCodes.EngineUnavailable;
                    return false;
                }

                string binaryPath;
                if (!TryReadBinaryPath(service, out binaryPath))
                {
                    code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                    return false;
                }

                state = new EngineServiceScmState(
                    EngineServiceBoundary.ServiceName,
                    status.ProcessId > int.MaxValue ? 0 : (int)status.ProcessId,
                    status.CurrentState,
                    binaryPath);
                code = "";
                return true;
            }
            finally
            {
                if (service != IntPtr.Zero)
                {
                    WindowsPipeNativeMethods.CloseServiceHandle(service);
                }
                WindowsPipeNativeMethods.CloseServiceHandle(manager);
            }
        }

        private static bool TryReadStatus(
            IntPtr service,
            out WindowsPipeNativeMethods.ServiceStatusProcess status)
        {
            status = new WindowsPipeNativeMethods.ServiceStatusProcess();
            int size = Marshal.SizeOf(typeof(WindowsPipeNativeMethods.ServiceStatusProcess));
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                uint needed;
                if (!WindowsPipeNativeMethods.QueryServiceStatusEx(
                    service,
                    WindowsPipeNativeMethods.ScStatusProcessInfo,
                    buffer,
                    (uint)size,
                    out needed))
                {
                    return false;
                }
                status = (WindowsPipeNativeMethods.ServiceStatusProcess)
                    Marshal.PtrToStructure(
                        buffer,
                        typeof(WindowsPipeNativeMethods.ServiceStatusProcess));
                return true;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static bool TryReadBinaryPath(IntPtr service, out string binaryPath)
        {
            binaryPath = "";
            uint needed;
            WindowsPipeNativeMethods.QueryServiceConfigW(
                service,
                IntPtr.Zero,
                0,
                out needed);
            if (needed == 0 || needed > 65536)
            {
                return false;
            }

            IntPtr buffer = Marshal.AllocHGlobal((int)needed);
            try
            {
                uint second;
                if (!WindowsPipeNativeMethods.QueryServiceConfigW(
                    service,
                    buffer,
                    needed,
                    out second))
                {
                    return false;
                }
                WindowsPipeNativeMethods.QueryServiceConfig config =
                    (WindowsPipeNativeMethods.QueryServiceConfig)
                    Marshal.PtrToStructure(
                        buffer,
                        typeof(WindowsPipeNativeMethods.QueryServiceConfig));
                if (config.BinaryPathName == IntPtr.Zero)
                {
                    return false;
                }
                binaryPath = Marshal.PtrToStringUni(config.BinaryPathName) ?? "";
                return binaryPath.Length > 0;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }
}
