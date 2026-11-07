using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using HotspotShade.WinUI2.Core.App;
using HotspotShade.WinUI2.Core.Engine;

// Load kernel32 and advapi32 from System32 only.
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

namespace HotspotShade.WinUI2.Elevate
{
    // The elevated starter. The broker starts it with the runas verb at
    // Turn on, so Windows shows one UAC prompt. It:
    // 1. Accepts exactly one argument: the 32-character rendezvous token.
    // 2. Refuses to run unless it is elevated.
    // 3. Opens the broker pipe with identification-level impersonation only,
    //    so the pipe server cannot act with this elevated token.
    // 4. Checks that the pipe server is the packaged broker, by image path.
    // 5. Duplicates the three pipe handles that the broker named into itself
    //    as inheritable handles, and checks that each one is a pipe.
    // 6. Starts the packaged engine with a fixed argument list and an
    //    explicit inherited-handle list, and answers with its process id.
    // It never reads the bearer secret or the pairing frame: the engine
    // reads them from the inherited pipes. A watchdog ends the program if
    // any step stalls.
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
        private const int ErrorAccessDenied = 5;
        private const int WatchdogMilliseconds = 45000;
        private const uint TokenQuery = 0x0008;
        private const int TokenElevationClass = 20;

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
            watchdog = new Timer(delegate { Environment.Exit((int)ElevationReplyCode.Failed); }, null, WatchdogMilliseconds, Timeout.Infinite);
            try
            {
                return Run(args[0]);
            }
            catch (Exception)
            {
                return (int)ElevationReplyCode.Failed;
            }
        }

        private static int Run(string token)
        {
            string here = AppContext.BaseDirectory.TrimEnd('\\', '/');
            string root = Path.GetDirectoryName(here);
            if (string.IsNullOrEmpty(root))
            {
                return (int)ElevationReplyCode.Failed;
            }
            string brokerPath = Path.Combine(root, "Broker", "HotspotShade.WinUI2.Broker.exe");
            string enginePath = Path.Combine(root, "Engine", EngineLaunchRules.ExecutableName);

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
            IntPtr broker = IntPtr.Zero;
            try
            {
                byte[] frame = ReadExact(pipe, ElevationProtocol.RequestLength);
                ElevationRequest request;
                if (frame == null || !ElevationProtocol.TryDecodeRequest(frame, frame.Length, out request))
                {
                    return Answer(pipe, ElevationReplyCode.Failed, 0);
                }

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
                if (!SamePath(ImagePath(broker), brokerPath))
                {
                    return Answer(pipe, ElevationReplyCode.BrokerRejected, 0);
                }
                if (!InstallRules.IsProtectedPackageRoot(root, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)))
                {
                    return Answer(pipe, ElevationReplyCode.InstallUntrusted, 0);
                }
                if (!File.Exists(enginePath))
                {
                    return Answer(pipe, ElevationReplyCode.EngineMissing, 0);
                }
                if (!File.Exists(Path.Combine(root, "Engine", "wintun.dll")))
                {
                    return Answer(pipe, ElevationReplyCode.AdapterDllMissing, 0);
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
            finally
            {
                CloseIfSet(broker);
                CloseHandle(pipe);
            }
        }

        private static int Answer(IntPtr pipe, ElevationReplyCode code, int processId)
        {
            byte[] reply = ElevationProtocol.EncodeReply(code, processId);
            int written;
            WriteFile(pipe, reply, reply.Length, out written, IntPtr.Zero);
            return code == ElevationReplyCode.Started ? 0 : (int)code;
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

        private static bool SamePath(string left, string right)
        {
            if (string.IsNullOrEmpty(left) || string.IsNullOrEmpty(right))
            {
                return false;
            }
            try
            {
                return string.Equals(
                    Path.GetFullPath(left).TrimEnd('\\'),
                    Path.GetFullPath(right).TrimEnd('\\'),
                    StringComparison.OrdinalIgnoreCase);
            }
            catch (Exception)
            {
                return false;
            }
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
