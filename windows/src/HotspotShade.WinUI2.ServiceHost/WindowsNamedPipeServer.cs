using System;
using System.Runtime.InteropServices;
using System.Threading;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.ServiceHost
{
    internal sealed class WindowsServerPipeConnection : IEngineServicePipeConnection
    {
        private readonly EngineServiceTransportOptions options;
        private IntPtr handle;
        private int disposed;

        public WindowsServerPipeConnection(IntPtr handle, EngineServiceTransportOptions options)
        {
            this.handle = handle;
            this.options = options;
        }

        public bool TryConnect(CancellationToken cancellationToken, out string code)
        {
            if (Volatile.Read(ref disposed) != 0)
            {
                code = EngineProtocol.ErrorCodes.EngineUnavailable;
                return false;
            }
            return WindowsNamedPipeIo.TryConnect(
                handle,
                options.ConnectTimeout,
                cancellationToken,
                out code);
        }

        public bool TryReadFrame(
            EngineServiceReadDeadline deadline,
            CancellationToken cancellationToken,
            out byte[] frame,
            out EngineServiceFrameReadOutcome outcome,
            out string code)
        {
            if (Volatile.Read(ref disposed) != 0)
            {
                frame = null;
                outcome = EngineServiceFrameReadOutcome.Failed;
                code = EngineProtocol.ErrorCodes.EngineUnavailable;
                return false;
            }
            return WindowsNamedPipeIo.TryReadFrame(
                handle,
                deadline,
                cancellationToken,
                out frame,
                out outcome,
                out code,
                WindowsPipeIoEnvironment.Shared);
        }

        public bool TryWriteFrame(
            byte[] frame,
            CancellationToken cancellationToken,
            out string code)
        {
            if (Volatile.Read(ref disposed) != 0)
            {
                code = EngineProtocol.ErrorCodes.EngineUnavailable;
                return false;
            }
            return WindowsNamedPipeIo.TryWriteFrame(
                handle,
                frame,
                options.RequestTimeout,
                cancellationToken,
                out code);
        }

        public bool TryImpersonateClient(out string code)
        {
            if (Volatile.Read(ref disposed) != 0)
            {
                code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                return false;
            }
            return WindowsNamedPipeIo.TryImpersonateClient(handle, out code);
        }

        public bool TryOpenThreadToken(out IEngineServiceCallerToken token, out string code)
        {
            if (Volatile.Read(ref disposed) != 0)
            {
                token = null;
                code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                return false;
            }
            return WindowsNamedPipeIo.TryOpenThreadToken(out token, out code);
        }

        public bool TryRevertToSelfAndVerify(out string code)
        {
            return WindowsNamedPipeIo.TryRevertToSelfAndVerify(out code);
        }

        public bool TryGetClientProcessId(out int processId)
        {
            return WindowsNamedPipeIo.TryGetClientProcessId(handle, out processId);
        }

        public void Disconnect()
        {
            if (Volatile.Read(ref disposed) != 0 || handle == IntPtr.Zero)
            {
                return;
            }
            WindowsPipeNativeMethods.DisconnectNamedPipe(handle);
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0)
            {
                return;
            }
            IntPtr current = handle;
            handle = IntPtr.Zero;
            if (current != IntPtr.Zero)
            {
                // DisconnectNamedPipe flushes all buffered data for the client.
                // It is best effort; CloseHandle is the authoritative release.
                WindowsPipeNativeMethods.DisconnectNamedPipe(current);
                WindowsPipeNativeMethods.CloseHandle(current);
            }
        }
    }

    // Creates exactly one first-instance pipe. The open mode, pipe mode, and
    // maximum instance count come from the reviewed core policy. The security
    // descriptor comes from the reviewed SDDL builder. There is no second
    // name and no fallback if the name already exists.
    public sealed class WindowsNamedPipeServerFactory : IEngineServicePipeFactory
    {
        private readonly EngineServiceTransportOptions options;

        public WindowsNamedPipeServerFactory(EngineServiceTransportOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }
            options.Validate();
            this.options = options;
        }

        public bool TryCreateFirstInstance(
            out IEngineServicePipeConnection pipe,
            out string code)
        {
            pipe = null;
            if (!EngineServicePlatform.IsWindows)
            {
                code = EngineProtocol.ErrorCodes.Unsupported;
                return false;
            }
            if (!EngineServiceSidPolicy.IsUsableInstalledUserSid(options.InstalledUserSid))
            {
                code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                return false;
            }
            if (!EngineServiceBoundary.TryValidatePipeServerCreate(
                EngineServiceBoundary.PipeServerOpenMode,
                EngineServiceBoundary.PipeServerMode,
                EngineServiceBoundary.PipeServerMaxInstances,
                out code))
            {
                return false;
            }

            string sddl;
            if (!EngineServiceBoundary.TryBuildPipeSddl(options.InstalledUserSid, out sddl))
            {
                code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                return false;
            }

            WindowsSecurityDescriptor descriptor;
            if (!WindowsPipeSecurity.TryCreateDescriptor(sddl, out descriptor, out code))
            {
                return false;
            }

            IntPtr handle = IntPtr.Zero;
            try
            {
                WindowsPipeNativeMethods.SecurityAttributes attributes =
                    new WindowsPipeNativeMethods.SecurityAttributes();
                attributes.Length = (uint)Marshal.SizeOf(
                    typeof(WindowsPipeNativeMethods.SecurityAttributes));
                attributes.SecurityDescriptor = descriptor.Pointer;
                attributes.InheritHandle = 0;
                handle = WindowsPipeNativeMethods.CreateNamedPipeW(
                    EngineServiceBoundary.PipeName,
                    EngineServiceBoundary.PipeServerOpenMode,
                    EngineServiceBoundary.PipeServerMode,
                    EngineServiceBoundary.PipeServerMaxInstances,
                    EngineServiceTransportLimits.PipeBufferBytes,
                    EngineServiceTransportLimits.PipeBufferBytes,
                    0,
                    ref attributes);
            }
            finally
            {
                descriptor.Dispose();
            }

            if (handle == IntPtr.Zero || handle == new IntPtr(-1))
            {
                int error = Marshal.GetLastWin32Error();
                if (error == WindowsPipeNativeMethods.ErrorAccessDenied
                    || error == WindowsPipeNativeMethods.ErrorPipeBusy
                    || error == WindowsPipeNativeMethods.ErrorAlreadyExists)
                {
                    code = EngineProtocol.ErrorCodes.BoundaryBusy;
                    return false;
                }
                code = EngineProtocol.ErrorCodes.EngineUnavailable;
                return false;
            }

            pipe = new WindowsServerPipeConnection(handle, options);
            code = "";
            return true;
        }
    }
}
