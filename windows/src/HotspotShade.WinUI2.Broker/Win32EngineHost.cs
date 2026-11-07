using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using HotspotShade.WinUI2.Core.Engine;
using Microsoft.Win32.SafeHandles;

namespace HotspotShade.WinUI2.Broker
{
    // The full-trust engine host. It creates two anonymous pipes, passes only
    // their read handles to the child through one explicit inheritance list,
    // and starts the installed engine binary by its absolute path. The bearer
    // secret travels on the token pipe and never on the command line. The
    // broker keeps the parent-liveness write handle open and closes it to stop
    // the engine. The stop path never forces a process termination, because
    // the engine removes its adapter and routes on its own exit path.
    internal sealed class Win32EngineHost : IEngineHost
    {
        private const uint HandleFlagInherit = 0x00000001;
        private const uint WaitObject0 = 0x00000000;
        private const uint ExtendedStartupInfoPresent = 0x00080000;
        private const uint CreateUnicodeEnvironment = 0x00000400;
        private const uint CreateNoWindow = 0x08000000;
        private const uint ProcThreadAttributeHandleList = 0x00020002;
        private const int MaximumSecretLength = 64;
        // The pairing handoff pipe holds a few frames of at most 331 bytes.
        // A larger buffer keeps an unread frame from blocking the engine.
        private const int HandoffPipeBuffer = 65536;

        private readonly object gate = new object();
        private readonly int port;
        private readonly EngineLaunchPlan plan;
        private readonly bool requireAdministrator;

        private IntPtr tokenRead;
        private IntPtr tokenWrite;
        private IntPtr parentRead;
        private IntPtr parentWrite;
        private IntPtr handoffRead;
        private IntPtr handoffWrite;
        private IntPtr processHandle;
        // The handle of a process that CloseAsync has asked to stop. It stays
        // open while the process may still run, so HasExited tells the truth
        // and the exit code stays readable. Release closes it.
        private IntPtr closingProcess;
        private byte[] secret;
        private DateTime startedAtUtc;
        private bool launched;
        private bool closed;
        private Task<bool> closeTask;

        private Win32EngineHost(
            EngineLaunchPlan plan,
            int port,
            IntPtr tokenRead,
            IntPtr tokenWrite,
            IntPtr parentRead,
            IntPtr parentWrite,
            IntPtr handoffRead,
            IntPtr handoffWrite,
            bool requireAdministrator)
        {
            this.handoffRead = handoffRead;
            this.handoffWrite = handoffWrite;
            this.plan = plan;
            this.port = port;
            this.requireAdministrator = requireAdministrator;
            this.tokenRead = tokenRead;
            this.tokenWrite = tokenWrite;
            this.parentRead = parentRead;
            this.parentWrite = parentWrite;
        }

        public EngineLaunchPlan Plan
        {
            get { return plan; }
        }

        // Create the two pipes and the fixed launch plan. The pipes are created
        // before the launch so the plan carries real handle values. A failure
        // closes every handle it created.
        public static bool TryCreate(
            string executablePath,
            string trustedRoot,
            int port,
            out Win32EngineHost host,
            out EngineLaunchPlan plan,
            out EngineLaunchFailure failure)
        {
            return TryCreate(
                executablePath,
                trustedRoot,
                port,
                true,
                out host,
                out plan,
                out failure);
        }

        // The same pipes and plan. A caller that passes false for
        // requireAdministrator lets a standard-user engine serve status and
        // settings. That engine still refuses a tunnel start on its own token
        // check, so the flag never grants a privilege. The packaged broker
        // keeps the administrator requirement.
        public static bool TryCreate(
            string executablePath,
            string trustedRoot,
            int port,
            bool requireAdministrator,
            out Win32EngineHost host,
            out EngineLaunchPlan plan,
            out EngineLaunchFailure failure)
        {
            return TryCreate(
                executablePath,
                trustedRoot,
                port,
                requireAdministrator,
                false,
                out host,
                out plan,
                out failure);
        }

        // The same plan with a third pipe for the pairing handoff. The child
        // inherits only the write end (--handoff-fd). The broker keeps the
        // read end and never reads it: at Turn on the elevated starter
        // duplicates it into the elevated engine (--credentials-fd).
        public static bool TryCreate(
            string executablePath,
            string trustedRoot,
            int port,
            bool requireAdministrator,
            bool withHandoff,
            out Win32EngineHost host,
            out EngineLaunchPlan plan,
            out EngineLaunchFailure failure)
        {
            host = null;
            plan = null;
            failure = EngineLaunchFailure.None;
            if (executablePath == null || executablePath.IndexOf('"') >= 0)
            {
                failure = EngineLaunchFailure.PathInvalid;
                return false;
            }

            IntPtr tokenRead = IntPtr.Zero;
            IntPtr tokenWrite = IntPtr.Zero;
            IntPtr parentRead = IntPtr.Zero;
            IntPtr parentWrite = IntPtr.Zero;
            if (!CreateInheritablePipe(out tokenRead, out tokenWrite))
            {
                failure = EngineLaunchFailure.BrokerRefused;
                return false;
            }
            if (!CreateInheritablePipe(out parentRead, out parentWrite))
            {
                CloseHandle(tokenRead);
                CloseHandle(tokenWrite);
                failure = EngineLaunchFailure.BrokerRefused;
                return false;
            }

            IntPtr handoffRead = IntPtr.Zero;
            IntPtr handoffWrite = IntPtr.Zero;
            if (withHandoff && !CreateWriterInheritablePipe(out handoffRead, out handoffWrite))
            {
                CloseHandle(tokenRead);
                CloseHandle(tokenWrite);
                CloseHandle(parentRead);
                CloseHandle(parentWrite);
                failure = EngineLaunchFailure.BrokerRefused;
                return false;
            }

            EngineLaunchPlan created;
            EngineLaunchFailure createdFailure;
            if (!EngineLaunchPlan.TryCreateTrustedWithPairing(
                executablePath,
                trustedRoot,
                port,
                tokenRead.ToInt64(),
                parentRead.ToInt64(),
                withHandoff ? EnginePairingDescriptor.Handoff : EnginePairingDescriptor.None,
                withHandoff ? handoffWrite.ToInt64() : 0,
                out created,
                out createdFailure))
            {
                CloseHandle(tokenRead);
                CloseHandle(tokenWrite);
                CloseHandle(parentRead);
                CloseHandle(parentWrite);
                if (withHandoff)
                {
                    CloseHandle(handoffRead);
                    CloseHandle(handoffWrite);
                }
                failure = createdFailure;
                return false;
            }

            plan = created;
            host = new Win32EngineHost(
                created,
                port,
                tokenRead,
                tokenWrite,
                parentRead,
                parentWrite,
                handoffRead,
                handoffWrite,
                requireAdministrator);
            return true;
        }

        // The process id of the launched engine. A caller uses it to prove
        // that the loopback listener belongs to this child before it sends
        // the bearer secret.
        public bool TryGetProcessId(out int processId)
        {
            lock (gate)
            {
                processId = 0;
                if (!launched || closed || processHandle == IntPtr.Zero)
                {
                    return false;
                }
                processId = GetProcessId(processHandle);
                return processId != 0;
            }
        }

        // The read end of the pairing handoff pipe, or zero. The handle stays
        // owned by this host and is closed with it. A caller passes only its
        // value to the elevated starter, which duplicates it.
        public IntPtr HandoffReadHandle
        {
            get
            {
                lock (gate)
                {
                    return closed ? IntPtr.Zero : handoffRead;
                }
            }
        }

        // True when the launched engine has exited. The exit code is set only
        // when it could be read.
        public bool HasExited(out int exitCode)
        {
            lock (gate)
            {
                exitCode = 0;
                IntPtr watched = processHandle != IntPtr.Zero ? processHandle : closingProcess;
                if (watched == IntPtr.Zero)
                {
                    return launched || closed;
                }
                if (WaitForSingleObject(watched, 0) != WaitObject0)
                {
                    return false;
                }
                uint code;
                if (GetExitCodeProcess(watched, out code))
                {
                    exitCode = unchecked((int)code);
                }
                return true;
            }
        }

        public Task<EngineLaunchOutcome> LaunchAsync(
            EngineLaunchRequest request,
            CancellationToken cancellationToken)
        {
            if (request == null)
            {
                return Task.FromResult(EngineLaunchOutcome.Failed(EngineLaunchFailure.BrokerRefused));
            }

            // Copy the secret before the task starts. The caller may clear its
            // own copy as soon as this call returns or times out; the host must
            // not read a cleared buffer from another thread.
            byte[] secretCopy;
            try
            {
                secretCopy = CopySecret(request.Secret);
            }
            catch (Exception)
            {
                return Task.FromResult(EngineLaunchOutcome.Failed(EngineLaunchFailure.BrokerRefused));
            }

            // Do not pass the token to Task.Run. A task that is cancelled
            // before it starts would otherwise leave the only copy uncleared.
            // Launch observes the token itself and clears the copy on every
            // failure path.
            return Task.Run(delegate
            {
                return Launch(request, secretCopy, cancellationToken);
            });
        }

        public Task<bool> CloseAsync(TimeSpan grace)
        {
            lock (gate)
            {
                if (closeTask == null)
                {
                    closeTask = Task.Run(delegate
                    {
                        return CloseCore(grace);
                    });
                }
                return closeTask;
            }
        }

        // Return a fresh copy of the loopback endpoint for one request. The
        // caller clears the copy. The host keeps its own copy until close.
        public bool TryGetEndpoint(out EngineHttpEndpoint endpoint)
        {
            lock (gate)
            {
                if (!launched || closed || secret == null || processHandle == IntPtr.Zero)
                {
                    endpoint = null;
                    return false;
                }
                endpoint = new EngineHttpEndpoint(port, secret, startedAtUtc);
                return true;
            }
        }

        private EngineLaunchOutcome Launch(
            EngineLaunchRequest request,
            byte[] secretCopy,
            CancellationToken cancellationToken)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                ClearSecret(secretCopy);
                return EngineLaunchOutcome.Failed(EngineLaunchFailure.LaunchTimeout);
            }

            lock (gate)
            {
                try
                {
                    return LaunchLocked(request, secretCopy, cancellationToken);
                }
                catch (Exception)
                {
                    ClearSecret(secretCopy);
                    ClosePending();
                    CloseParentAndWait();
                    return EngineLaunchOutcome.Failed(EngineLaunchFailure.BrokerRefused);
                }
            }
        }

        private EngineLaunchOutcome LaunchLocked(
            EngineLaunchRequest request,
            byte[] secretCopy,
            CancellationToken cancellationToken)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                ClearSecret(secretCopy);
                return EngineLaunchOutcome.Failed(EngineLaunchFailure.LaunchTimeout);
            }
            if (closed)
            {
                ClearSecret(secretCopy);
                return EngineLaunchOutcome.Failed(EngineLaunchFailure.Closed);
            }
            if (launched)
            {
                ClearSecret(secretCopy);
                return EngineLaunchOutcome.Failed(EngineLaunchFailure.AlreadyStarted);
            }
            if (!request.Plan.IsSameAs(plan))
            {
                ClearSecret(secretCopy);
                ClosePending();
                return EngineLaunchOutcome.Failed(EngineLaunchFailure.HandleInvalid);
            }
            if (requireAdministrator && !IsElevated())
            {
                // The engine needs an administrator token for the adapter and
                // the routes. This process never asks for elevation.
                ClearSecret(secretCopy);
                ClosePending();
                return EngineLaunchOutcome.Failed(EngineLaunchFailure.AdminRequired);
            }
            if (secret != null)
            {
                Array.Clear(secret, 0, secret.Length);
                secret = null;
            }

            StringBuilder command = BuildCommandLine(request.Plan);
            STARTUPINFOEX startup = new STARTUPINFOEX();
            startup.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
            IntPtr attributeList = IntPtr.Zero;
            IntPtr size = IntPtr.Zero;
            GCHandle handles = default(GCHandle);
            PROCESS_INFORMATION process = new PROCESS_INFORMATION();
            bool created = false;
            int error = 0;

            try
            {
                IntPtr[] inherited = handoffWrite != IntPtr.Zero
                    ? new IntPtr[] { tokenRead, parentRead, handoffWrite }
                    : new IntPtr[] { tokenRead, parentRead };
                handles = GCHandle.Alloc(inherited, GCHandleType.Pinned);
                InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
                if (size == IntPtr.Zero)
                {
                    ClearSecret(secretCopy);
                    ClosePending();
                    return EngineLaunchOutcome.Failed(EngineLaunchFailure.BrokerRefused);
                }
                attributeList = Marshal.AllocHGlobal(size);
                if (!InitializeProcThreadAttributeList(attributeList, 1, 0, ref size))
                {
                    ClearSecret(secretCopy);
                    ClosePending();
                    return EngineLaunchOutcome.Failed(EngineLaunchFailure.BrokerRefused);
                }
                if (!UpdateProcThreadAttribute(
                    attributeList,
                    0,
                    (IntPtr)ProcThreadAttributeHandleList,
                    handles.AddrOfPinnedObject(),
                    (IntPtr)(inherited.Length * IntPtr.Size),
                    IntPtr.Zero,
                    IntPtr.Zero))
                {
                    ClearSecret(secretCopy);
                    ClosePending();
                    return EngineLaunchOutcome.Failed(EngineLaunchFailure.BrokerRefused);
                }

                startup.lpAttributeList = attributeList;
                created = CreateProcessW(
                    request.Plan.ExecutablePath,
                    command,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    true,
                    ExtendedStartupInfoPresent | CreateUnicodeEnvironment | CreateNoWindow,
                    IntPtr.Zero,
                    Path.GetDirectoryName(request.Plan.ExecutablePath),
                    ref startup,
                    out process);
                if (!created)
                {
                    error = Marshal.GetLastWin32Error();
                }
            }
            finally
            {
                if (attributeList != IntPtr.Zero)
                {
                    DeleteProcThreadAttributeList(attributeList);
                    Marshal.FreeHGlobal(attributeList);
                }
                if (handles.IsAllocated)
                {
                    handles.Free();
                }
            }

            if (!created)
            {
                ClearSecret(secretCopy);
                ClosePending();
                return EngineLaunchOutcome.Failed(
                    error == 2 || error == 3
                        ? EngineLaunchFailure.BrokerMissing
                        : EngineLaunchFailure.BrokerRefused);
            }

            CloseHandle(process.hThread);
            processHandle = process.hProcess;
            CloseHandle(tokenRead);
            tokenRead = IntPtr.Zero;
            CloseHandle(parentRead);
            parentRead = IntPtr.Zero;
            if (handoffWrite != IntPtr.Zero)
            {
                // The engine holds its own copy of the write end now.
                CloseHandle(handoffWrite);
                handoffWrite = IntPtr.Zero;
            }

            IntPtr token = tokenWrite;
            tokenWrite = IntPtr.Zero;
            try
            {
                using (SafeFileHandle handle = new SafeFileHandle(token, true))
                using (FileStream stream = new FileStream(handle, FileAccess.Write, 1, false))
                {
                    WriteSecret(secretCopy, stream);
                }
            }
            catch (Exception)
            {
                ClearSecret(secretCopy);
                CloseParentAndWait();
                return EngineLaunchOutcome.Failed(EngineLaunchFailure.BrokerRefused);
            }

            secret = secretCopy;
            startedAtUtc = DateTime.UtcNow;
            launched = true;
            return EngineLaunchOutcome.Success();
        }

        private bool CloseCore(TimeSpan grace)
        {
            IntPtr parent;
            IntPtr process;
            lock (gate)
            {
                closed = true;
                parent = parentWrite;
                parentWrite = IntPtr.Zero;
                process = processHandle;
                processHandle = IntPtr.Zero;
                closingProcess = process;
                ClosePending();
                if (handoffRead != IntPtr.Zero)
                {
                    CloseHandle(handoffRead);
                    handoffRead = IntPtr.Zero;
                }
                if (secret != null)
                {
                    Array.Clear(secret, 0, secret.Length);
                    secret = null;
                }
                launched = false;
            }

            if (parent != IntPtr.Zero)
            {
                // The engine sees the end of the parent-liveness pipe and runs
                // its own stop path. Nothing is written to this pipe.
                CloseHandle(parent);
            }
            if (process == IntPtr.Zero)
            {
                return true;
            }

            int milliseconds = (int)Math.Min(30000D, Math.Max(0D, grace.TotalMilliseconds));
            uint wait = WaitForSingleObject(process, (uint)milliseconds);
            bool exited = wait == WaitObject0;
            if (exited)
            {
                Release();
            }
            // On a timeout the handle stays open: the process may still run,
            // and HasExited keeps reporting false until it ends.
            return exited;
        }

        // Close the handle of a closed engine after it exited. Safe to call
        // again, and safe while no close is running.
        public void Release()
        {
            lock (gate)
            {
                if (closingProcess != IntPtr.Zero)
                {
                    CloseHandle(closingProcess);
                    closingProcess = IntPtr.Zero;
                }
            }
        }

        private void CloseParentAndWait()
        {
            IntPtr parent = parentWrite;
            parentWrite = IntPtr.Zero;
            if (parent != IntPtr.Zero)
            {
                CloseHandle(parent);
            }
            IntPtr process = processHandle;
            processHandle = IntPtr.Zero;
            if (process != IntPtr.Zero)
            {
                WaitForSingleObject(process, 2000);
                CloseHandle(process);
            }
        }

        private void ClosePending()
        {
            if (tokenRead != IntPtr.Zero)
            {
                CloseHandle(tokenRead);
                tokenRead = IntPtr.Zero;
            }
            if (tokenWrite != IntPtr.Zero)
            {
                CloseHandle(tokenWrite);
                tokenWrite = IntPtr.Zero;
            }
            if (parentRead != IntPtr.Zero)
            {
                CloseHandle(parentRead);
                parentRead = IntPtr.Zero;
            }
            if (parentWrite != IntPtr.Zero)
            {
                CloseHandle(parentWrite);
                parentWrite = IntPtr.Zero;
            }
            if (handoffWrite != IntPtr.Zero)
            {
                CloseHandle(handoffWrite);
                handoffWrite = IntPtr.Zero;
            }
        }

        private static StringBuilder BuildCommandLine(EngineLaunchPlan plan)
        {
            StringBuilder command = new StringBuilder();
            command.Append('"');
            command.Append(plan.ExecutablePath);
            command.Append('"');
            for (int index = 0; index < plan.Arguments.Count; index++)
            {
                command.Append(' ');
                command.Append(plan.Arguments[index]);
            }
            return command;
        }

        private static byte[] CopySecret(EngineLaunchSecret value)
        {
            using (MemoryStream memory = new MemoryStream())
            {
                try
                {
                    value.WriteTo(memory);
                    byte[] copy = new byte[MaximumSecretLength];
                    Array.Copy(memory.GetBuffer(), copy, copy.Length);
                    return copy;
                }
                finally
                {
                    // Clear a partial write too. A failed copy must not leave
                    // the secret in the memory stream.
                    byte[] buffer = memory.GetBuffer();
                    Array.Clear(buffer, 0, buffer.Length);
                }
            }
        }

        // Write the 64-character secret and one newline from the host-owned
        // copy. The pipe buffer is cleared after the write.
        private static void WriteSecret(byte[] secret, Stream stream)
        {
            byte[] buffer = new byte[EngineLaunchRules.SecretWriteLength];
            try
            {
                Buffer.BlockCopy(secret, 0, buffer, 0, EngineLaunchRules.SecretHexLength);
                buffer[EngineLaunchRules.SecretHexLength] = EngineLaunchRules.SecretTerminator;
                stream.Write(buffer, 0, buffer.Length);
            }
            finally
            {
                Array.Clear(buffer, 0, buffer.Length);
            }
        }

        private static void ClearSecret(byte[] secret)
        {
            if (secret != null)
            {
                Array.Clear(secret, 0, secret.Length);
            }
        }

        private static bool IsElevated()
        {
            try
            {
                using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                {
                    WindowsPrincipal principal = new WindowsPrincipal(identity);
                    return principal.IsInRole(WindowsBuiltInRole.Administrator);
                }
            }
            catch (Exception)
            {
                return false;
            }
        }

        private static bool CreateInheritablePipe(out IntPtr read, out IntPtr write)
        {
            read = IntPtr.Zero;
            write = IntPtr.Zero;
            SECURITY_ATTRIBUTES attributes = new SECURITY_ATTRIBUTES();
            attributes.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
            attributes.lpSecurityDescriptor = IntPtr.Zero;
            attributes.bInheritHandle = true;
            if (!CreatePipe(out read, out write, ref attributes, 0))
            {
                read = IntPtr.Zero;
                write = IntPtr.Zero;
                return false;
            }
            if (!SetHandleInformation(write, HandleFlagInherit, 0))
            {
                CloseHandle(read);
                CloseHandle(write);
                read = IntPtr.Zero;
                write = IntPtr.Zero;
                return false;
            }
            return true;
        }

        // A pipe whose write end the child inherits and whose read end stays
        // private to this process.
        private static bool CreateWriterInheritablePipe(out IntPtr read, out IntPtr write)
        {
            read = IntPtr.Zero;
            write = IntPtr.Zero;
            SECURITY_ATTRIBUTES attributes = new SECURITY_ATTRIBUTES();
            attributes.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
            attributes.lpSecurityDescriptor = IntPtr.Zero;
            attributes.bInheritHandle = true;
            if (!CreatePipe(out read, out write, ref attributes, HandoffPipeBuffer))
            {
                read = IntPtr.Zero;
                write = IntPtr.Zero;
                return false;
            }
            if (!SetHandleInformation(read, HandleFlagInherit, 0))
            {
                CloseHandle(read);
                CloseHandle(write);
                read = IntPtr.Zero;
                write = IntPtr.Zero;
                return false;
            }
            return true;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CreatePipe(
            out IntPtr read,
            out IntPtr write,
            ref SECURITY_ATTRIBUTES attributes,
            int size);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int GetProcessId(IntPtr process);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool InitializeProcThreadAttributeList(
            IntPtr attributeList,
            int attributeCount,
            int flags,
            ref IntPtr size);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool UpdateProcThreadAttribute(
            IntPtr attributeList,
            uint flags,
            IntPtr attribute,
            IntPtr value,
            IntPtr size,
            IntPtr previousValue,
            IntPtr returnSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern void DeleteProcThreadAttributeList(IntPtr attributeList);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CreateProcessW(
            string applicationName,
            StringBuilder commandLine,
            IntPtr processAttributes,
            IntPtr threadAttributes,
            bool inheritHandles,
            uint creationFlags,
            IntPtr environment,
            string currentDirectory,
            ref STARTUPINFOEX startupInfo,
            out PROCESS_INFORMATION processInformation);
    }
}
