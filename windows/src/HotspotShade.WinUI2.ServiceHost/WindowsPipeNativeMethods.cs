using System;
using System.Runtime.InteropServices;
using System.Text;

namespace HotspotShade.WinUI2.ServiceHost
{
    // Documented Win32 declarations for the service host foundation. These
    // calls are made only on Windows. The pure tests never call this class.
    internal static class WindowsPipeNativeMethods
    {
        public const uint PipeAccessDuplex = 0x00000003;
        public const uint FileFlagFirstPipeInstance = 0x00080000;
        public const uint FileFlagOverlapped = 0x40000000;
        public const uint PipeTypeByte = 0x00000000;
        public const uint PipeReadModeByte = 0x00000000;
        public const uint PipeWait = 0x00000000;
        public const uint PipeRejectRemoteClients = 0x00000008;
        public const uint PipeUnlimitedInstances = 255;

        public const uint OpenExisting = 3;
        public const uint SecuritySqosPresent = 0x00100000;
        public const uint SecurityIdentification = 0x00010000;

        public const uint TokenQuery = 0x0008;
        public const int TokenUser = 1;
        public const int TokenSessionId = 12;
        public const int TokenImpersonationLevel = 9;
        public const int TokenElevationType = 18;

        public const int SeKernelObject = 6;
        public const uint OwnerSecurityInformation = 0x00000001;

        public const uint ScManagerConnect = 0x0001;
        public const uint ServiceQueryStatus = 0x0004;
        public const uint ServiceQueryConfig = 0x0001;
        public const int ScStatusProcessInfo = 0;
        public const uint ServiceRunning = 4;

        public const int ErrorSuccess = 0;
        public const int ErrorFileNotFound = 2;
        public const int ErrorAccessDenied = 5;
        public const int ErrorInvalidHandle = 6;
        public const int ErrorHandleEof = 38;
        public const int ErrorBrokenPipe = 109;
        public const int ErrorSemTimeout = 121;
        public const int ErrorInsufficientBuffer = 122;
        public const int ErrorAlreadyExists = 183;
        public const int ErrorPipeBusy = 231;
        public const int ErrorNoData = 232;
        public const int ErrorPipeNotConnected = 233;
        public const int ErrorNotFound = 1168;
        public const int ErrorIoPending = 997;
        public const int ErrorIoIncomplete = 996;
        public const int ErrorOperationAborted = 995;
        public const int ErrorPipeConnected = 535;
        public const int ErrorNoToken = 1008;
        public const int ErrorNoneMapped = 1332;
        public const int ErrorCannotImpersonate = 1368;

        public const uint WaitObject0 = 0;
        public const uint WaitTimeout = 258;
        public const uint WaitFailed = 0xFFFFFFFF;
        public const uint Infinite = 0xFFFFFFFF;
        public const uint SddlRevision1 = 1;

        // A sentinel for a GetOverlappedResult byte count that the call did not
        // write. One pipe operation is bounded far below four gigabytes, so a
        // real completion can never report this value.

        [StructLayout(LayoutKind.Sequential)]
        internal struct SecurityAttributes
        {
            public uint Length;
            public IntPtr SecurityDescriptor;
            public int InheritHandle;
        }

        // Matches the native OVERLAPPED record. The struct is only a layout
        // definition. A live operation uses one unmanaged copy so the kernel
        // never holds a pointer into the managed heap.
        [StructLayout(LayoutKind.Sequential)]
        internal struct NativeOverlapped
        {
            public IntPtr Internal;
            public IntPtr InternalHigh;
            public uint Offset;
            public uint OffsetHigh;
            public IntPtr Event;
        }

#pragma warning disable 0649
        [StructLayout(LayoutKind.Sequential)]
        internal struct ServiceStatusProcess
        {
            public uint ServiceType;
            public uint CurrentState;
            public uint ControlsAccepted;
            public uint Win32ExitCode;
            public uint ServiceSpecificExitCode;
            public uint CheckPoint;
            public uint WaitHint;
            public uint ProcessId;
            public uint ServiceFlags;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct QueryServiceConfig
        {
            public uint ServiceType;
            public uint StartType;
            public uint ErrorControl;
            public IntPtr BinaryPathName;
            public IntPtr LoadOrderGroup;
            public uint TagId;
            public IntPtr Dependencies;
            public IntPtr ServiceStartName;
            public IntPtr DisplayName;
        }
#pragma warning restore 0649

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        internal static extern IntPtr CreateNamedPipeW(
            string name,
            uint openMode,
            uint pipeMode,
            uint maxInstances,
            uint outBufferSize,
            uint inBufferSize,
            uint defaultTimeout,
            ref SecurityAttributes securityAttributes);

        // The overlapped parameter is an unmanaged OVERLAPPED address. Passing
        // a managed struct by ref is unsafe here because the kernel keeps the
        // pointer after ERROR_IO_PENDING returns and the GC can move it.
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool ConnectNamedPipe(
            IntPtr pipe,
            IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool DisconnectNamedPipe(IntPtr pipe);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool ReadFile(
            IntPtr file,
            IntPtr buffer,
            uint bytesToRead,
            IntPtr bytesRead,
            IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool WriteFile(
            IntPtr file,
            IntPtr buffer,
            uint bytesToWrite,
            IntPtr bytesWritten,
            IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetOverlappedResult(
            IntPtr file,
            IntPtr overlapped,
            out uint transferred,
            [MarshalAs(UnmanagedType.Bool)] bool wait);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CancelIoEx(
            IntPtr file,
            IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        internal static extern IntPtr CreateEventW(
            IntPtr eventAttributes,
            int manualReset,
            int initialState,
            string name);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        internal static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        internal static extern IntPtr CreateFileW(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetNamedPipeServerProcessId(
            IntPtr pipe,
            out uint serverProcessId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetNamedPipeClientProcessId(
            IntPtr pipe,
            out uint clientProcessId);

        [DllImport("kernel32.dll", ExactSpelling = true)]
        internal static extern IntPtr GetCurrentThread();

        [DllImport("kernel32.dll", ExactSpelling = true)]
        internal static extern uint GetCurrentThreadId();

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        internal static extern IntPtr LocalFree(IntPtr memory);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(
            string stringSecurityDescriptor,
            uint stringSddlRevision,
            out IntPtr securityDescriptor,
            out uint securityDescriptorSize);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool ConvertStringSidToSidW(
            string stringSid,
            out IntPtr sid);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool ConvertSidToStringSidW(
            IntPtr sid,
            out IntPtr stringSid);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool LookupAccountSidW(
            string systemName,
            IntPtr sid,
            StringBuilder name,
            ref int nameLength,
            StringBuilder domainName,
            ref int domainNameLength,
            out int accountType);

        [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool ImpersonateNamedPipeClient(IntPtr pipe);

        [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool RevertToSelf();

        [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool OpenThreadToken(
            IntPtr thread,
            uint desiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool openAsSelf,
            out IntPtr token);

        [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetTokenInformation(
            IntPtr token,
            int tokenInformationClass,
            IntPtr tokenInformation,
            int tokenInformationLength,
            out int returnLength);

        [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetSecurityInfo(
            IntPtr handle,
            int objectType,
            uint securityInfo,
            out IntPtr owner,
            out IntPtr group,
            out IntPtr dacl,
            out IntPtr sacl,
            out IntPtr securityDescriptor);

        [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetSecurityDescriptorOwner(
            IntPtr securityDescriptor,
            out IntPtr owner,
            out int ownerDefaulted);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        internal static extern IntPtr OpenSCManagerW(
            string machineName,
            string databaseName,
            uint desiredAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        internal static extern IntPtr OpenServiceW(
            IntPtr serviceControlManager,
            string serviceName,
            uint desiredAccess);

        [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool QueryServiceStatusEx(
            IntPtr service,
            int infoLevel,
            IntPtr buffer,
            uint bufferSize,
            out uint bytesNeeded);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool QueryServiceConfigW(
            IntPtr service,
            IntPtr config,
            uint bufferSize,
            out uint bytesNeeded);

        [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseServiceHandle(IntPtr handle);

        // Only a documented completed result proves that the kernel has stopped
        // using the OVERLAPPED record and the data buffer. ERROR_IO_PENDING, a
        // not-yet-complete result, a closed handle, and every unknown error are
        // not completion proof.
        internal static bool IsOverlappedCompletionError(int error)
        {
            return error == ErrorOperationAborted
                || error == ErrorBrokenPipe
                || error == ErrorPipeNotConnected
                || error == ErrorNoData
                || error == ErrorHandleEof;
        }

    }
}
