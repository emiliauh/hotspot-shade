using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.ServiceHost
{
    internal sealed class WindowsSecurityDescriptor : IDisposable
    {
        private IntPtr pointer;
        private int disposed;

        public WindowsSecurityDescriptor(IntPtr pointer)
        {
            this.pointer = pointer;
        }

        public IntPtr Pointer
        {
            get { return pointer; }
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0)
            {
                return;
            }
            if (pointer != IntPtr.Zero)
            {
                WindowsPipeNativeMethods.LocalFree(pointer);
                pointer = IntPtr.Zero;
            }
        }
    }

    internal static class WindowsPipeSecurity
    {
        public static bool TryCreateDescriptor(
            string sddl,
            out WindowsSecurityDescriptor descriptor,
            out string code)
        {
            descriptor = null;
            if (string.IsNullOrEmpty(sddl))
            {
                code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                return false;
            }
            IntPtr pointer;
            uint size;
            if (!WindowsPipeNativeMethods.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl,
                WindowsPipeNativeMethods.SddlRevision1,
                out pointer,
                out size)
                || pointer == IntPtr.Zero)
            {
                code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                return false;
            }
            descriptor = new WindowsSecurityDescriptor(pointer);
            code = "";
            return true;
        }

        public static bool TryGetOwnerSid(IntPtr handle, out string sid, out string code)
        {
            sid = "";
            IntPtr owner;
            IntPtr group;
            IntPtr dacl;
            IntPtr sacl;
            IntPtr descriptor;
            if (!WindowsPipeNativeMethods.GetSecurityInfo(
                handle,
                WindowsPipeNativeMethods.SeKernelObject,
                WindowsPipeNativeMethods.OwnerSecurityInformation,
                out owner,
                out group,
                out dacl,
                out sacl,
                out descriptor)
                || descriptor == IntPtr.Zero)
            {
                code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                return false;
            }

            try
            {
                IntPtr descriptorOwner;
                int defaulted;
                if (!WindowsPipeNativeMethods.GetSecurityDescriptorOwner(
                    descriptor,
                    out descriptorOwner,
                    out defaulted)
                    || descriptorOwner == IntPtr.Zero)
                {
                    code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                    return false;
                }

                IntPtr stringSid;
                if (!WindowsPipeNativeMethods.ConvertSidToStringSidW(descriptorOwner, out stringSid)
                    || stringSid == IntPtr.Zero)
                {
                    code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                    return false;
                }
                try
                {
                    sid = Marshal.PtrToStringUni(stringSid) ?? "";
                    code = "";
                    return sid.Length > 0;
                }
                finally
                {
                    WindowsPipeNativeMethods.LocalFree(stringSid);
                }
            }
            finally
            {
                WindowsPipeNativeMethods.LocalFree(descriptor);
            }
        }
    }

    internal sealed class WindowsCallerToken : IEngineServiceCallerToken
    {
        private IntPtr handle;
        private int disposed;

        public WindowsCallerToken(IntPtr handle)
        {
            this.handle = handle;
        }

        public bool TryRead(out EngineServiceCallerIdentity identity, out string code)
        {
            identity = null;
            if (handle == IntPtr.Zero || Volatile.Read(ref disposed) != 0)
            {
                code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                return false;
            }

            string userSid;
            if (!TryReadTokenUser(handle, out userSid))
            {
                code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                return false;
            }

            int sessionId;
            if (!TryReadDwordTokenInformation(
                handle,
                WindowsPipeNativeMethods.TokenSessionId,
                out sessionId))
            {
                code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                return false;
            }

            int nativeImpersonation;
            if (!TryReadDwordTokenInformation(
                handle,
                WindowsPipeNativeMethods.TokenImpersonationLevel,
                out nativeImpersonation))
            {
                code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                return false;
            }
            EngineServiceImpersonationLevel impersonation;
            if (!EngineServiceCallerPolicy.TryMapWin32ImpersonationLevel(
                nativeImpersonation,
                out impersonation))
            {
                code = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                return false;
            }

            int elevationType;
            bool elevated = TryReadDwordTokenInformation(
                handle,
                WindowsPipeNativeMethods.TokenElevationType,
                out elevationType)
                && elevationType == 2;

            identity = new EngineServiceCallerIdentity(
                userSid,
                sessionId,
                impersonation,
                "",
                elevated);
            code = "";
            return true;
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0)
            {
                return;
            }
            if (handle != IntPtr.Zero)
            {
                WindowsPipeNativeMethods.CloseHandle(handle);
                handle = IntPtr.Zero;
            }
        }

        private static bool TryReadTokenUser(IntPtr token, out string sid)
        {
            sid = "";
            int needed;
            bool first = WindowsPipeNativeMethods.GetTokenInformation(
                token,
                WindowsPipeNativeMethods.TokenUser,
                IntPtr.Zero,
                0,
                out needed);
            if (!first && Marshal.GetLastWin32Error() != WindowsPipeNativeMethods.ErrorInsufficientBuffer)
            {
                return false;
            }
            if (needed <= 0 || needed > 65536)
            {
                return false;
            }

            IntPtr buffer = Marshal.AllocHGlobal(needed);
            try
            {
                int returned;
                if (!WindowsPipeNativeMethods.GetTokenInformation(
                    token,
                    WindowsPipeNativeMethods.TokenUser,
                    buffer,
                    needed,
                    out returned))
                {
                    return false;
                }
                // TOKEN_USER starts with SID_AND_ATTRIBUTES. Its first field
                // is the SID pointer on both x86 and x64.
                IntPtr userSid = Marshal.ReadIntPtr(buffer);
                if (userSid == IntPtr.Zero)
                {
                    return false;
                }
                IntPtr stringSid;
                if (!WindowsPipeNativeMethods.ConvertSidToStringSidW(userSid, out stringSid)
                    || stringSid == IntPtr.Zero)
                {
                    return false;
                }
                try
                {
                    sid = Marshal.PtrToStringUni(stringSid) ?? "";
                    return sid.Length > 0;
                }
                finally
                {
                    WindowsPipeNativeMethods.LocalFree(stringSid);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static bool TryReadDwordTokenInformation(
            IntPtr token,
            int informationClass,
            out int value)
        {
            value = 0;
            int needed;
            bool first = WindowsPipeNativeMethods.GetTokenInformation(
                token,
                informationClass,
                IntPtr.Zero,
                0,
                out needed);
            if (!first && Marshal.GetLastWin32Error() != WindowsPipeNativeMethods.ErrorInsufficientBuffer)
            {
                return false;
            }
            if (needed <= 0 || needed > 64)
            {
                return false;
            }

            IntPtr buffer = Marshal.AllocHGlobal(needed);
            try
            {
                int returned;
                if (!WindowsPipeNativeMethods.GetTokenInformation(
                    token,
                    informationClass,
                    buffer,
                    needed,
                    out returned))
                {
                    return false;
                }
                value = Marshal.ReadInt32(buffer);
                return true;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }

    public sealed class WindowsAccountTypeInspector : IEngineServiceAccountTypeInspector
    {
        public Task<EngineServiceAccountTypeResult> InspectAsync(
            string sid,
            CancellationToken cancellationToken)
        {
            if (!EngineServicePlatform.IsWindows)
            {
                return Task.FromResult(EngineServiceAccountTypeResult.Failure(
                    EngineProtocol.ErrorCodes.Unsupported));
            }
            return Task.Run<EngineServiceAccountTypeResult>(
                delegate { return Inspect(sid); },
                cancellationToken);
        }

        private static EngineServiceAccountTypeResult Inspect(string sid)
        {
            if (!EngineServiceBoundary.IsValidUserSid(sid))
            {
                return EngineServiceAccountTypeResult.Failure(
                    EngineProtocol.ErrorCodes.BoundaryAuthFailed);
            }

            IntPtr sidPointer;
            if (!WindowsPipeNativeMethods.ConvertStringSidToSidW(sid, out sidPointer)
                || sidPointer == IntPtr.Zero)
            {
                return EngineServiceAccountTypeResult.Failure(
                    EngineProtocol.ErrorCodes.BoundaryAuthFailed);
            }
            try
            {
                int nameLength = 0;
                int domainLength = 0;
                int accountType;
                bool first = WindowsPipeNativeMethods.LookupAccountSidW(
                    null,
                    sidPointer,
                    null,
                    ref nameLength,
                    null,
                    ref domainLength,
                    out accountType);
                if (!first && Marshal.GetLastWin32Error() == WindowsPipeNativeMethods.ErrorNoneMapped)
                {
                    return EngineServiceAccountTypeResult.Success(EngineServiceAccountType.Unknown);
                }
                if (first)
                {
                    return EngineServiceAccountTypeResult.Failure(
                        EngineProtocol.ErrorCodes.BoundaryAuthFailed);
                }
                if (Marshal.GetLastWin32Error() != WindowsPipeNativeMethods.ErrorInsufficientBuffer)
                {
                    return EngineServiceAccountTypeResult.Failure(
                        EngineProtocol.ErrorCodes.BoundaryAuthFailed);
                }
                if (nameLength <= 0 || nameLength > 1024
                    || domainLength <= 0 || domainLength > 1024)
                {
                    return EngineServiceAccountTypeResult.Failure(
                        EngineProtocol.ErrorCodes.BoundaryAuthFailed);
                }

                StringBuilder name = new StringBuilder(nameLength);
                StringBuilder domain = new StringBuilder(domainLength);
                int secondNameLength = nameLength;
                int secondDomainLength = domainLength;
                if (!WindowsPipeNativeMethods.LookupAccountSidW(
                    null,
                    sidPointer,
                    name,
                    ref secondNameLength,
                    domain,
                    ref secondDomainLength,
                    out accountType))
                {
                    if (Marshal.GetLastWin32Error() == WindowsPipeNativeMethods.ErrorNoneMapped)
                    {
                        return EngineServiceAccountTypeResult.Success(
                            EngineServiceAccountType.Unknown);
                    }
                    return EngineServiceAccountTypeResult.Failure(
                        EngineProtocol.ErrorCodes.BoundaryAuthFailed);
                }

                return EngineServiceAccountTypeResult.Success(
                    EngineServiceSidPolicy.MapAccountType(accountType));
            }
            finally
            {
                WindowsPipeNativeMethods.LocalFree(sidPointer);
            }
        }
    }
}
