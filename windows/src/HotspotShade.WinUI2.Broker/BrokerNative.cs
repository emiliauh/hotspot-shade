using System;
using System.Runtime.InteropServices;
using System.Text;

namespace HotspotShade.WinUI2.Broker
{
    // Win32 declarations for the broker. Every DLL loads from System32 only
    // (see BrokerAssembly.cs).
    internal static class BrokerNative
    {
        public const uint WaitObject0 = 0x00000000;
        public const uint WaitTimeout = 0x00000102;
        public const uint Synchronize = 0x00100000;
        public const uint ProcessQueryLimitedInformation = 0x00001000;

        public const uint PipeAccessDuplex = 0x00000003;
        public const uint FileFlagFirstPipeInstance = 0x00080000;
        public const uint FileFlagOverlapped = 0x40000000;
        public const uint PipeTypeByte = 0x00000000;
        public const uint PipeReadModeByte = 0x00000000;
        public const uint PipeWait = 0x00000000;
        public const uint PipeRejectRemoteClients = 0x00000008;

        public const int ErrorIoPending = 997;
        public const int ErrorPipeConnected = 535;
        public const int ErrorCancelled = 1223;
        public const int ErrorFileNotFound = 2;
        public const int ErrorPathNotFound = 3;

        public const uint SeeMaskNoCloseProcess = 0x00000040;
        public const uint SeeMaskNoAsync = 0x00000100;
        public const uint SeeMaskFlagNoUi = 0x00000400;
        public const int SwHide = 0;

        public const uint SddlRevision1 = 1;

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct OVERLAPPED
        {
            public IntPtr Internal;
            public IntPtr InternalHigh;
            public uint Offset;
            public uint OffsetHigh;
            public IntPtr hEvent;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SHELLEXECUTEINFO
        {
            public int cbSize;
            public uint fMask;
            public IntPtr hwnd;
            public string lpVerb;
            public string lpFile;
            public string lpParameters;
            public string lpDirectory;
            public int nShow;
            public IntPtr hInstApp;
            public IntPtr lpIDList;
            public string lpClass;
            public IntPtr hkeyClass;
            public uint dwHotKey;
            public IntPtr hIconOrMonitor;
            public IntPtr hProcess;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CreatePipe(out IntPtr read, out IntPtr write, IntPtr attributes, int size);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint WaitForMultipleObjects(uint count, IntPtr[] handles, bool waitAll, uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int GetProcessId(IntPtr process);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int GetCurrentProcessId();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint access, bool inherit, int processId);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool QueryFullProcessImageNameW(IntPtr process, uint flags, StringBuilder name, ref int size);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr CreateNamedPipeW(
            string name,
            uint openMode,
            uint pipeMode,
            uint maxInstances,
            uint outBufferSize,
            uint inBufferSize,
            uint defaultTimeout,
            ref SECURITY_ATTRIBUTES attributes);

        // The overlapped calls take unmanaged memory only. A managed buffer
        // could move while the I/O is pending.
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ConnectNamedPipe(IntPtr pipe, IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetNamedPipeClientProcessId(IntPtr pipe, out uint processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadFile(IntPtr file, IntPtr buffer, int count, IntPtr read, IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteFile(IntPtr file, IntPtr buffer, int count, IntPtr written, IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteFile(IntPtr file, byte[] buffer, int count, out int written, IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetOverlappedResult(IntPtr file, IntPtr overlapped, out int transferred, bool wait);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ResetEvent(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CancelIoEx(IntPtr file, IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr CreateEventW(IntPtr attributes, bool manualReset, bool initialState, string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LocalFree(IntPtr memory);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(
            string descriptor,
            uint revision,
            out IntPtr securityDescriptor,
            IntPtr size);

        [DllImport("shell32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool ShellExecuteExW(ref SHELLEXECUTEINFO info);

        // The full image path of a process, or null.
        public static string ImagePath(IntPtr process)
        {
            StringBuilder name = new StringBuilder(1024);
            int size = name.Capacity;
            if (!QueryFullProcessImageNameW(process, 0, name, ref size) || size <= 0)
            {
                return null;
            }
            return name.ToString(0, size);
        }

        public static bool SamePath(string left, string right)
        {
            if (string.IsNullOrEmpty(left) || string.IsNullOrEmpty(right))
            {
                return false;
            }
            try
            {
                string a = System.IO.Path.GetFullPath(left).TrimEnd('\\');
                string b = System.IO.Path.GetFullPath(right).TrimEnd('\\');
                return string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}
