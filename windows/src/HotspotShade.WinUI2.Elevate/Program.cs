using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using HotspotShade.WinUI2.Core.App;
using HotspotShade.WinUI2.Core.Engine;

// Load kernel32, kernelbase, and advapi32 from System32 only.
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

namespace HotspotShade.WinUI2.Elevate
{
    // The elevated starter. The broker starts it with the runas verb at
    // Turn on, so Windows shows one UAC prompt. It:
    // 1. Accepts exactly one argument: the 32-character rendezvous token.
    // 2. Refuses to run unless it is elevated.
    // 3. Opens the broker pipe with identification-level impersonation only,
    //    so the pipe server cannot act with this elevated token.
    // 4. Finds the package root from the final path of its own image, then
    //    checks that the pipe server is the packaged broker before it reads
    //    any byte: by process id, the final path of its image, and its
    //    package full name, which must be the root folder's name. This
    //    rejects another program; it cannot reject malware that runs as the
    //    same user inside the broker. The trust anchor for starting at all
    //    is the person's UAC approval, so the elevated engine must treat
    //    the port, the pipes, and the pairing frame as untrusted input.
    // 5. Reads the request, then verifies the install location before it
    //    duplicates any handle or creates any process: the root must be the
    //    path that Windows reports for that package, on a fixed local disk,
    //    below a WindowsApps package store; the package root, the Engine
    //    folder, the engine, wintun.dll, and its own image are each opened,
    //    their final paths must be where the package puts them, and their
    //    owner and DACL must pass InstallSecurity. The handles ask for read
    //    access (so their share modes take effect) and share neither write
    //    nor delete, so until the engine process exists none of these
    //    objects can be renamed, replaced, or written.
    // 6. Duplicates the three pipe handles that the broker named into itself
    //    as inheritable handles, and checks that each one is a pipe and that
    //    no two are the same object.
    // 7. Starts the packaged engine by its verified path, while the checked
    //    handles are still held, with a fixed argument list and an explicit
    //    inherited-handle list, and answers with its process id. The engine
    //    loads wintun.dll after the starter exits, so only the DACL rule
    //    protects that file at load time.
    // It never reads the bearer secret or the pairing frame: the engine
    // reads them from the inherited pipes. A watchdog ends the program if
    // any step stalls; it and any unexpected failure first send a failure
    // reply, so the broker does not wait for its own timeout.
    //
    // The starter is published with NativeAOT, so it loads no .NET host,
    // startup hook, or profiler that the user environment could name. The
    // elevated engine gets a fixed environment block built from the Windows
    // directory, not the inherited user environment.
    internal static class Program
    {
        private const uint GenericRead = 0x80000000;
        private const uint GenericWrite = 0x40000000;
        private const uint OpenExisting = 3;
        private const uint SecurityIdentification = 0x00010000;
        private const uint SecuritySqosPresent = 0x00100000;
        private const uint ProcessDupHandle = 0x00000040;
        private const uint ProcessQueryLimitedInformation = 0x00001000;
        private const uint DuplicateSameAccess = 0x00000002;
        private const uint FileTypePipe = 3;
        private const uint ExtendedStartupInfoPresent = 0x00080000;
        private const uint CreateUnicodeEnvironment = 0x00000400;
        private const uint CreateNoWindow = 0x08000000;
        private const uint ProcThreadAttributeHandleList = 0x00020002;
        private const int ErrorFileNotFound = 2;
        private const int ErrorPathNotFound = 3;
        private const int ErrorAccessDenied = 5;
        private const int WatchdogMilliseconds = 45000;
        private const int WatchdogReplyMilliseconds = 2000;
        private const uint TokenQuery = 0x0008;
        private const int TokenElevationClass = 20;
        private const uint ThreadTerminate = 0x0001;

        private const int ErrorInsufficientBuffer = 122;

        // The install-location check opens each object with these rights
        // only: its final path, owner, and DACL, plus read data (list
        // directory for a folder). Windows applies share modes only to an
        // open that asks for data access, so read data is what makes the
        // held handles block a rename, a replacement, or a write.
        private const uint FileReadData = 0x00000001;
        private const uint FileReadAttributes = 0x00000080;
        private const uint ReadControl = 0x00020000;
        private const uint FileShareRead = 0x00000001;
        private const uint FileShareWrite = 0x00000002;
        private const uint FileShareDelete = 0x00000004;
        private const uint FileFlagBackupSemantics = 0x02000000;
        private const uint FileAttributeDirectory = 0x00000010;
        private const uint VolumeNameDos = 0;
        private const int SeFileObject = 1;
        private const uint OwnerSecurityInformation = 0x00000001;
        private const uint DaclSecurityInformation = 0x00000004;

        private const string BrokerFolder = "Broker";
        private const string BrokerFileName = "HotspotShade.WinUI2.Broker.exe";
        private const string EngineFolder = "Engine";
        private const string AdapterFileName = "wintun.dll";

        // The pipe handle that a failure reply may still use. The main thread
        // clears it under the gate before it closes the handle, so the
        // watchdog never writes to a closed or reused handle value.
        private static readonly object replyGate = new object();
        private static IntPtr replyPipe;
        // Set once a reply was written, so the broker never sees two.
        private static int replied;
        private static IntPtr mainThread;
        // Set by the watchdog; the main thread starts no new pipe read.
        private static int stopping;
        private static Timer watchdog;

        [STAThread]
        private static int Main(string[] args)
        {
            if (args == null || args.Length != 1 || !ElevationProtocol.IsRendezvousToken(args[0]))
            {
                return (int)ElevationReplyCode.Failed;
            }
            if (!IsElevated())
            {
                return (int)ElevationReplyCode.NotElevated;
            }
            mainThread = OpenThread(ThreadTerminate, false, GetCurrentThreadId());
            watchdog = new Timer(OnWatchdog, null, WatchdogMilliseconds, Timeout.Infinite);
            try
            {
                return Run(args[0]);
            }
            catch (Exception)
            {
                SendFailure();
                return (int)ElevationReplyCode.Failed;
            }
        }

        // The watchdog sends a best-effort failure reply and ends the
        // program. A synchronous read on the same pipe would hold the write
        // back, so it stops new reads and cancels the main thread's blocking
        // call (several times, for a read that starts just after a cancel)
        // first, and it waits for the write only briefly.
        private static void OnWatchdog(object state)
        {
            try
            {
                Thread writer = new Thread(WatchdogReply);
                writer.IsBackground = true;
                writer.Start();
                writer.Join(WatchdogReplyMilliseconds);
            }
            catch (Exception)
            {
            }
            Environment.Exit((int)ElevationReplyCode.Failed);
        }

        private static void WatchdogReply()
        {
            Volatile.Write(ref stopping, 1);
            for (int attempt = 0; attempt < 10 && mainThread != IntPtr.Zero; attempt++)
            {
                CancelSynchronousIo(mainThread);
                Thread.Sleep(20);
            }
            SendFailure();
        }

        private static void SendFailure()
        {
            lock (replyGate)
            {
                if (replyPipe != IntPtr.Zero)
                {
                    TryReply(replyPipe, ElevationReplyCode.Failed, 0);
                }
            }
        }

        private static int Run(string token)
        {
            IntPtr pipe = CreateFileW(
                @"\\.\pipe\" + ElevationProtocol.PipeName(token),
                GenericRead | GenericWrite,
                0,
                IntPtr.Zero,
                OpenExisting,
                SecuritySqosPresent | SecurityIdentification,
                IntPtr.Zero);
            if (pipe == IntPtr.Zero || pipe == new IntPtr(-1))
            {
                return (int)ElevationReplyCode.Failed;
            }
            lock (replyGate)
            {
                replyPipe = pipe;
            }
            List<IntPtr> held = new List<IntPtr>();
            IntPtr broker = IntPtr.Zero;
            try
            {
                // The package root comes from the final path of this
                // program's own image, never from a path that the caller or
                // the environment can name.
                IntPtr self;
                string selfFinal;
                ElevationReplyCode opened = OpenChecked(ImagePath(GetCurrentProcess()), false, held, out self, out selfFinal);
                string root = opened == ElevationReplyCode.Started ? InstallSecurity.RootFromStarter(selfFinal) : null;
                if (root == null)
                {
                    return Answer(
                        pipe,
                        opened == ElevationReplyCode.Started || opened == ElevationReplyCode.InstallUntrusted ? ElevationReplyCode.InstallUntrusted : ElevationReplyCode.Failed,
                        0);
                }

                // The pipe server must be the packaged broker. This is
                // checked before the starter reads any byte from the pipe.
                uint serverId;
                if (!GetNamedPipeServerProcessId(pipe, out serverId) || serverId == 0 || serverId > int.MaxValue)
                {
                    return Answer(pipe, ElevationReplyCode.BrokerRejected, 0);
                }
                broker = OpenProcess(ProcessDupHandle | ProcessQueryLimitedInformation, false, (int)serverId);
                if (broker == IntPtr.Zero)
                {
                    // An approval with another account cannot open the
                    // signed-in account's broker.
                    return Answer(
                        pipe,
                        Marshal.GetLastWin32Error() == ErrorAccessDenied ? ElevationReplyCode.OtherAccount : ElevationReplyCode.BrokerRejected,
                        0);
                }
                string brokerPath = root + "\\" + BrokerFolder + "\\" + BrokerFileName;
                if (!InstallSecurity.SameFinalPath(FinalPathOf(ImagePath(broker)), brokerPath))
                {
                    return Answer(pipe, ElevationReplyCode.BrokerRejected, 0);
                }
                // The broker runs with the package identity. Its package full
                // name must be the name of the folder this starter runs from.
                string packageName = PackageFullNameOf(broker);
                if (!InstallSecurity.RootNamesPackage(root, packageName))
                {
                    return Answer(pipe, ElevationReplyCode.BrokerRejected, 0);
                }

                byte[] frame = ReadExact(pipe, ElevationProtocol.RequestLength);
                ElevationRequest request;
                if (frame == null || !ElevationProtocol.TryDecodeRequest(frame, frame.Length, out request))
                {
                    return Answer(pipe, ElevationReplyCode.Failed, 0);
                }

                string enginePath = root + "\\" + EngineFolder + "\\" + EngineLaunchRules.ExecutableName;
                ElevationReplyCode verdict = VerifyInstall(root, packageName, self, enginePath, held);
                if (verdict != ElevationReplyCode.Started)
                {
                    return Answer(pipe, verdict, 0);
                }

                IntPtr tokenHandle = IntPtr.Zero;
                IntPtr parentHandle = IntPtr.Zero;
                IntPtr credentialsHandle = IntPtr.Zero;
                try
                {
                    if (!Duplicate(broker, request.TokenHandle, out tokenHandle)
                        || !Duplicate(broker, request.ParentHandle, out parentHandle)
                        || !Duplicate(broker, request.CredentialsHandle, out credentialsHandle))
                    {
                        return Answer(pipe, ElevationReplyCode.HandleRejected, 0);
                    }
                    // Three different handle values can still name one
                    // pipe. The engine needs three different pipes.
                    if (CompareObjectHandles(tokenHandle, parentHandle)
                        || CompareObjectHandles(tokenHandle, credentialsHandle)
                        || CompareObjectHandles(parentHandle, credentialsHandle))
                    {
                        return Answer(pipe, ElevationReplyCode.HandleRejected, 0);
                    }
                    EngineLaunchPlan plan;
                    EngineLaunchFailure failure;
                    if (!EngineLaunchPlan.TryCreateTrustedWithPairing(
                        enginePath,
                        root,
                        request.Port,
                        tokenHandle.ToInt64(),
                        parentHandle.ToInt64(),
                        EnginePairingDescriptor.Credentials,
                        credentialsHandle.ToInt64(),
                        out plan,
                        out failure))
                    {
                        return Answer(pipe, ElevationReplyCode.Failed, 0);
                    }
                    int engineId = Start(plan, new[] { tokenHandle, parentHandle, credentialsHandle });
                    if (engineId <= 0)
                    {
                        return Answer(pipe, ElevationReplyCode.Failed, 0);
                    }
                    return Answer(pipe, ElevationReplyCode.Started, engineId);
                }
                finally
                {
                    // The engine holds its own inherited copies now.
                    CloseIfSet(tokenHandle);
                    CloseIfSet(parentHandle);
                    CloseIfSet(credentialsHandle);
                }
            }
            catch (Exception)
            {
                return Answer(pipe, ElevationReplyCode.Failed, 0);
            }
            finally
            {
                for (int index = 0; index < held.Count; index++)
                {
                    CloseIfSet(held[index]);
                }
                CloseIfSet(broker);
                lock (replyGate)
                {
                    replyPipe = IntPtr.Zero;
                    CloseHandle(pipe);
                }
            }
        }

        // The install-location check. The root must be the install folder
        // that Windows reports for the broker's package, on a fixed local
        // disk, below a WindowsApps package store. Each object is opened by
        // the path that the verified root implies, its final path must be
        // that same path (so no link leads out of the package), and its owner
        // and DACL must pass InstallSecurity. The handles go into held and
        // stay open until the engine process exists.
        private static ElevationReplyCode VerifyInstall(string root, string packageName, IntPtr self, string enginePath, List<IntPtr> held)
        {
            string programFiles = FinalPathOf(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
            if (!InstallSecurity.IsPackageStoreLocation(root, programFiles))
            {
                return ElevationReplyCode.InstallUntrusted;
            }
            if (!InstallSecurity.MatchesPackage(root, packageName, FinalPathOf(PackagePathOf(packageName))))
            {
                return ElevationReplyCode.InstallUntrusted;
            }
            if (!InstallSecurity.IsTrustedDriveType(DriveTypeOf(root)))
            {
                return ElevationReplyCode.InstallUntrusted;
            }
            IntPtr ignored;
            ElevationReplyCode result = CheckObject(root, true, ElevationReplyCode.InstallUntrusted, held, out ignored);
            if (result != ElevationReplyCode.Started)
            {
                return result;
            }
            result = CheckObject(root + "\\" + EngineFolder, true, ElevationReplyCode.EngineMissing, held, out ignored);
            if (result != ElevationReplyCode.Started)
            {
                return result;
            }
            result = CheckObject(enginePath, false, ElevationReplyCode.EngineMissing, held, out ignored);
            if (result != ElevationReplyCode.Started)
            {
                return result;
            }
            result = CheckObject(root + "\\" + EngineFolder + "\\" + AdapterFileName, false, ElevationReplyCode.AdapterDllMissing, held, out ignored);
            if (result != ElevationReplyCode.Started)
            {
                return result;
            }
            // The starter's own image is below the root (RootFromStarter);
            // it must be protected the same way.
            return InstallSecurity.ReplyFor(SecurityOf(self), ElevationReplyCode.InstallUntrusted);
        }

        private static ElevationReplyCode CheckObject(string path, bool directory, ElevationReplyCode missing, List<IntPtr> held, out IntPtr handle)
        {
            string final;
            ElevationReplyCode opened = OpenChecked(path, directory, held, out handle, out final);
            if (opened == ElevationReplyCode.EngineMissing)
            {
                return missing;
            }
            if (opened != ElevationReplyCode.Started)
            {
                return opened;
            }
            if (!InstallSecurity.SameFinalPath(final, path))
            {
                return ElevationReplyCode.InstallUntrusted;
            }
            return InstallSecurity.ReplyFor(SecurityOf(handle), ElevationReplyCode.InstallUntrusted);
        }

        // The package full name of a process, or null when it has no package
        // identity.
        private static string PackageFullNameOf(IntPtr process)
        {
            char[] buffer = new char[130];
            int length = buffer.Length;
            int status = GetPackageFullName(process, ref length, buffer);
            if (status != 0 || length <= 1 || length > buffer.Length)
            {
                return null;
            }
            return new string(buffer, 0, length - 1);
        }

        // The install folder that Windows reports for a package, or null.
        private static string PackagePathOf(string packageName)
        {
            if (!InstallSecurity.IsPackageFullName(packageName))
            {
                return null;
            }
            char[] buffer = new char[1024];
            int length = buffer.Length;
            int status = GetPackagePathByFullName(packageName, ref length, buffer);
            if (status == ErrorInsufficientBuffer && length > buffer.Length && length < 32768)
            {
                buffer = new char[length];
                status = GetPackagePathByFullName(packageName, ref length, buffer);
            }
            if (status != 0 || length <= 1 || length > buffer.Length)
            {
                return null;
            }
            return new string(buffer, 0, length - 1);
        }

        // The drive type of the volume that holds path (through any mount
        // point), or 0 when it cannot be read.
        private static uint DriveTypeOf(string path)
        {
            string normalized = InstallSecurity.NormalizeFinalPath(path);
            if (normalized == null)
            {
                return 0;
            }
            char[] volume = new char[1024];
            if (!GetVolumePathNameW(normalized, volume, (uint)volume.Length))
            {
                return 0;
            }
            int end = Array.IndexOf(volume, '\0');
            if (end <= 0)
            {
                return 0;
            }
            return GetDriveTypeW(new string(volume, 0, end));
        }

        // Opens path for its attributes, security, and read data (list
        // directory for a folder), checks that it is a folder or a file as
        // expected, and reads its final path. The handle goes into held. The
        // read-data right makes Windows apply the share mode: a folder is
        // shared for read and write and a file for read only, and neither
        // allows delete, so nothing can rename, replace, remove, or (for a
        // file) write it while the handle is open. Returns Started on
        // success, EngineMissing when the path does not exist,
        // InstallUntrusted when the object has the wrong kind, and Failed
        // for any other open failure.
        private static ElevationReplyCode OpenChecked(string path, bool directory, List<IntPtr> held, out IntPtr handle, out string final)
        {
            handle = IntPtr.Zero;
            final = null;
            string normalized = InstallSecurity.NormalizeFinalPath(path);
            if (normalized == null)
            {
                return ElevationReplyCode.InstallUntrusted;
            }
            IntPtr opened = CreateFileW(
                @"\\?\" + normalized,
                FileReadAttributes | ReadControl | FileReadData,
                directory ? FileShareRead | FileShareWrite : FileShareRead,
                IntPtr.Zero,
                OpenExisting,
                FileFlagBackupSemantics,
                IntPtr.Zero);
            if (opened == IntPtr.Zero || opened == new IntPtr(-1))
            {
                int error = Marshal.GetLastWin32Error();
                return error == ErrorFileNotFound || error == ErrorPathNotFound
                    ? ElevationReplyCode.EngineMissing
                    : ElevationReplyCode.Failed;
            }
            held.Add(opened);
            BY_HANDLE_FILE_INFORMATION info;
            if (!GetFileInformationByHandle(opened, out info))
            {
                return ElevationReplyCode.Failed;
            }
            if (((info.dwFileAttributes & FileAttributeDirectory) != 0) != directory)
            {
                return ElevationReplyCode.InstallUntrusted;
            }
            final = FinalPath(opened);
            if (final == null)
            {
                return ElevationReplyCode.Failed;
            }
            handle = opened;
            return ElevationReplyCode.Started;
        }

        // The final path of a file or folder, or null. Used for the broker
        // image and Program Files, which the starter does not hold open.
        private static string FinalPathOf(string path)
        {
            string normalized = InstallSecurity.NormalizeFinalPath(path);
            if (normalized == null)
            {
                return null;
            }
            IntPtr opened = CreateFileW(
                @"\\?\" + normalized,
                FileReadAttributes,
                FileShareRead | FileShareWrite | FileShareDelete,
                IntPtr.Zero,
                OpenExisting,
                FileFlagBackupSemantics,
                IntPtr.Zero);
            if (opened == IntPtr.Zero || opened == new IntPtr(-1))
            {
                return null;
            }
            try
            {
                return FinalPath(opened);
            }
            finally
            {
                CloseHandle(opened);
            }
        }

        private static string FinalPath(IntPtr handle)
        {
            char[] buffer = new char[1024];
            uint length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Length, VolumeNameDos);
            if (length >= buffer.Length && length < 32768)
            {
                buffer = new char[length + 1];
                length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Length, VolumeNameDos);
            }
            if (length == 0 || length >= buffer.Length)
            {
                return null;
            }
            return new string(buffer, 0, (int)length);
        }

        // The owner and DACL of an open object, judged by InstallSecurity.
        private static InstallCheck SecurityOf(IntPtr handle)
        {
            IntPtr owner;
            IntPtr group;
            IntPtr dacl;
            IntPtr sacl;
            IntPtr descriptor;
            uint status = GetSecurityInfo(
                handle,
                SeFileObject,
                OwnerSecurityInformation | DaclSecurityInformation,
                out owner,
                out group,
                out dacl,
                out sacl,
                out descriptor);
            if (status != 0)
            {
                return InstallCheck.Malformed;
            }
            try
            {
                if (owner == IntPtr.Zero || !IsValidSid(owner))
                {
                    return InstallCheck.Malformed;
                }
                int ownerLength = GetLengthSid(owner);
                if (ownerLength < 8 || ownerLength > 68)
                {
                    return InstallCheck.Malformed;
                }
                byte[] ownerBytes = new byte[ownerLength];
                Marshal.Copy(owner, ownerBytes, 0, ownerLength);
                byte[] daclBytes = null;
                if (dacl != IntPtr.Zero)
                {
                    int size = Marshal.ReadInt16(dacl, 2) & 0xFFFF;
                    if (size < 8)
                    {
                        return InstallCheck.Malformed;
                    }
                    daclBytes = new byte[size];
                    Marshal.Copy(dacl, daclBytes, 0, size);
                }
                return InstallSecurity.Evaluate(ownerBytes, daclBytes);
            }
            finally
            {
                if (descriptor != IntPtr.Zero)
                {
                    LocalFree(descriptor);
                }
            }
        }

        // Writes the reply and reports the exit code. A Started reply that
        // could not be written is a failure: the broker then closes the
        // parent-liveness pipe, which stops the engine.
        private static int Answer(IntPtr pipe, ElevationReplyCode code, int processId)
        {
            bool sent = TryReply(pipe, code, processId);
            if (code == ElevationReplyCode.Started)
            {
                return sent ? 0 : (int)ElevationReplyCode.Failed;
            }
            return (int)code;
        }

        private static bool TryReply(IntPtr pipe, ElevationReplyCode code, int processId)
        {
            if (Interlocked.Exchange(ref replied, 1) != 0)
            {
                return false;
            }
            byte[] reply = ElevationProtocol.EncodeReply(code, processId);
            int written;
            return WriteFile(pipe, reply, reply.Length, out written, IntPtr.Zero) && written == reply.Length;
        }

        private static bool Duplicate(IntPtr broker, long value, out IntPtr copy)
        {
            copy = IntPtr.Zero;
            IntPtr duplicated;
            if (!DuplicateHandle(broker, new IntPtr(value), GetCurrentProcess(), out duplicated, 0, true, DuplicateSameAccess))
            {
                return false;
            }
            if (GetFileType(duplicated) != FileTypePipe)
            {
                CloseHandle(duplicated);
                return false;
            }
            copy = duplicated;
            return true;
        }

        private static int Start(EngineLaunchPlan plan, IntPtr[] inherited)
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

            STARTUPINFOEX startup = new STARTUPINFOEX();
            startup.StartupInfo.cb = Marshal.SizeOf<STARTUPINFOEX>();
            IntPtr attributeList = IntPtr.Zero;
            IntPtr size = IntPtr.Zero;
            GCHandle handles = default(GCHandle);
            IntPtr environment = IntPtr.Zero;
            PROCESS_INFORMATION process = new PROCESS_INFORMATION();
            try
            {
                handles = GCHandle.Alloc(inherited, GCHandleType.Pinned);
                InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
                if (size == IntPtr.Zero)
                {
                    return 0;
                }
                attributeList = Marshal.AllocHGlobal(size);
                if (!InitializeProcThreadAttributeList(attributeList, 1, 0, ref size))
                {
                    Marshal.FreeHGlobal(attributeList);
                    attributeList = IntPtr.Zero;
                    return 0;
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
                    return 0;
                }
                startup.lpAttributeList = attributeList;
                // A fixed environment block. It holds no secret: the secret
                // travels on the token pipe only.
                environment = Marshal.StringToHGlobalUni(EnvironmentBlock());
                if (!CreateProcessW(
                    plan.ExecutablePath,
                    command,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    true,
                    ExtendedStartupInfoPresent | CreateUnicodeEnvironment | CreateNoWindow,
                    environment,
                    Path.GetDirectoryName(plan.ExecutablePath),
                    ref startup,
                    out process))
                {
                    return 0;
                }
                CloseHandle(process.hThread);
                CloseHandle(process.hProcess);
                return process.dwProcessId;
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
                if (environment != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(environment);
                }
            }
        }

        // The environment of the elevated engine. Every value comes from the
        // Windows directory that the system reports, never from a variable
        // that the signed-in user can set. The engine's child tools need
        // SystemRoot and PATH. The block is sorted by name and ends with two
        // null characters.
        internal static string EnvironmentBlock()
        {
            StringBuilder directory = new StringBuilder(260);
            uint length = GetWindowsDirectoryW(directory, (uint)directory.Capacity);
            string windows = length > 0 && length < directory.Capacity ? directory.ToString() : @"C:\Windows";
            string drive = windows.Length >= 2 && windows[1] == ':' ? windows.Substring(0, 2) : "C:";
            string system = windows + @"\System32";
            string[] entries =
            {
                "ComSpec=" + system + @"\cmd.exe",
                "NUMBER_OF_PROCESSORS=" + Environment.ProcessorCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
                "OS=Windows_NT",
                "PATH=" + system + ";" + windows + ";" + system + @"\Wbem",
                "PATHEXT=.COM;.EXE;.BAT;.CMD",
                "PROCESSOR_ARCHITECTURE=AMD64",
                "SystemDrive=" + drive,
                "SystemRoot=" + windows,
                "TEMP=" + windows + @"\Temp",
                "TMP=" + windows + @"\Temp",
                "windir=" + windows
            };
            Array.Sort(entries, StringComparer.OrdinalIgnoreCase);
            return string.Join("\0", entries) + "\0\0";
        }

        private static byte[] ReadExact(IntPtr pipe, int count)
        {
            byte[] result = new byte[count];
            byte[] chunk = new byte[count];
            int have = 0;
            while (have < count)
            {
                if (Volatile.Read(ref stopping) != 0)
                {
                    return null;
                }
                int read;
                if (!ReadFile(pipe, chunk, count - have, out read, IntPtr.Zero) || read <= 0)
                {
                    return null;
                }
                Array.Copy(chunk, 0, result, have, read);
                have += read;
            }
            return result;
        }

        private static string ImagePath(IntPtr process)
        {
            StringBuilder name = new StringBuilder(1024);
            int size = name.Capacity;
            if (!QueryFullProcessImageNameW(process, 0, name, ref size) || size <= 0)
            {
                return null;
            }
            return name.ToString(0, size);
        }

        // True when this process holds an elevated token (TokenElevation).
        private static bool IsElevated()
        {
            IntPtr token;
            if (!OpenProcessToken(GetCurrentProcess(), TokenQuery, out token))
            {
                return false;
            }
            try
            {
                int elevation;
                int returned;
                return GetTokenInformation(token, TokenElevationClass, out elevation, 4, out returned)
                    && returned == 4
                    && elevation != 0;
            }
            finally
            {
                CloseHandle(token);
            }
        }

        private static void CloseIfSet(IntPtr handle)
        {
            if (handle != IntPtr.Zero)
            {
                CloseHandle(handle);
            }
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

        [StructLayout(LayoutKind.Sequential)]
        private struct BY_HANDLE_FILE_INFORMATION
        {
            public uint dwFileAttributes;
            public uint ftCreationTimeLow;
            public uint ftCreationTimeHigh;
            public uint ftLastAccessTimeLow;
            public uint ftLastAccessTimeHigh;
            public uint ftLastWriteTimeLow;
            public uint ftLastWriteTimeHigh;
            public uint dwVolumeSerialNumber;
            public uint nFileSizeHigh;
            public uint nFileSizeLow;
            public uint nNumberOfLinks;
            public uint nFileIndexHigh;
            public uint nFileIndexLow;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateFileW(
            string name,
            uint access,
            uint share,
            IntPtr security,
            uint disposition,
            uint flags,
            IntPtr template);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadFile(IntPtr file, byte[] buffer, int count, out int read, IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteFile(IntPtr file, byte[] buffer, int count, out int written, IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetNamedPipeServerProcessId(IntPtr pipe, out uint processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint access, bool inherit, int processId);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool QueryFullProcessImageNameW(IntPtr process, uint flags, StringBuilder name, ref int size);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DuplicateHandle(
            IntPtr sourceProcess,
            IntPtr sourceHandle,
            IntPtr targetProcess,
            out IntPtr targetHandle,
            uint access,
            bool inherit,
            uint options);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint GetFileType(IntPtr file);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern uint GetWindowsDirectoryW(StringBuilder buffer, uint size);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(IntPtr token, int infoClass, out int value, int length, out int returned);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenThread(uint access, bool inherit, uint threadId);

        [DllImport("kernel32.dll")]
        private static extern uint GetCurrentThreadId();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CancelSynchronousIo(IntPtr thread);

        // Windows 10 1607 and later; the package needs 10.0.19041.
        [DllImport("kernelbase.dll")]
        private static extern bool CompareObjectHandles(IntPtr first, IntPtr second);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(IntPtr file, out BY_HANDLE_FILE_INFORMATION information);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern uint GetFinalPathNameByHandleW(IntPtr file, [Out] char[] path, uint size, uint flags);

        // Returns a Win32 error code; it does not set the last error.
        [DllImport("advapi32.dll")]
        private static extern uint GetSecurityInfo(
            IntPtr handle,
            int objectType,
            uint securityInfo,
            out IntPtr owner,
            out IntPtr group,
            out IntPtr dacl,
            out IntPtr sacl,
            out IntPtr securityDescriptor);

        [DllImport("advapi32.dll")]
        private static extern bool IsValidSid(IntPtr sid);

        [DllImport("advapi32.dll")]
        private static extern int GetLengthSid(IntPtr sid);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr memory);

        // Returns a Win32 error code. The length counts the final null.
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetPackageFullName(IntPtr process, ref int length, [Out] char[] name);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetPackagePathByFullName(string packageFullName, ref int length, [Out] char[] path);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool GetVolumePathNameW(string path, [Out] char[] volume, uint length);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern uint GetDriveTypeW(string root);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool InitializeProcThreadAttributeList(IntPtr attributeList, int count, int flags, ref IntPtr size);

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
