using System;
using System.Runtime.InteropServices;

namespace HotspotShade.WinUI2.Service
{
    // Documented Win32 declarations for the Windows Service Control Manager
    // adapter. These calls are made only on Windows. There is no install,
    // create, start, change, or delete call here. This code only receives the
    // SCM dispatch, registers one control handler, and reports status.
    internal static class WindowsServiceControlNativeMethods
    {
        public const uint ServiceWin32OwnProcess = 0x00000010;
        public const uint ServiceAcceptStop = 0x00000001;
        public const uint ServiceAcceptShutdown = 0x00000004;

        public const uint ServiceStopped = 1;
        public const uint ServiceStartPending = 2;
        public const uint ServiceStopPending = 3;
        public const uint ServiceRunning = 4;
        public const uint ServiceContinuePending = 7;
        public const uint ServicePausePending = 5;
        public const uint ServicePaused = 6;

        public const uint ControlStop = 1;
        public const uint ControlPause = 2;
        public const uint ControlContinue = 3;
        public const uint ControlInterrogate = 4;
        public const uint ControlShutdown = 5;

        public const int ErrorSuccess = 0;
        public const int ErrorCallNotImplemented = 120;
        public const int ErrorFailedServiceControlConnect = 1063;
        public const int ErrorServiceSpecificError = 1066;

        [StructLayout(LayoutKind.Sequential)]
        internal struct ServiceStatus
        {
            public uint ServiceType;
            public uint CurrentState;
            public uint ControlsAccepted;
            public uint Win32ExitCode;
            public uint ServiceSpecificExitCode;
            public uint Checkpoint;
            public uint WaitHint;
        }

        // The SCM passes the service name and the service main function. The
        // table is terminated by an entry with a null name and a null
        // function. The name is ignored for SERVICE_WIN32_OWN_PROCESS, but the
        // fixed name is supplied so the table is readable.
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct ServiceTableEntry
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string ServiceName;

            [MarshalAs(UnmanagedType.FunctionPtr)]
            public ServiceMainFunction ServiceProc;
        }

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        internal delegate void ServiceMainFunction(uint argumentCount, IntPtr argumentValues);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        internal delegate uint ServiceControlHandler(
            uint control,
            uint eventType,
            IntPtr eventData,
            IntPtr context);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool StartServiceCtrlDispatcherW(
            [In] ServiceTableEntry[] serviceTable);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        internal static extern IntPtr RegisterServiceCtrlHandlerExW(
            string serviceName,
            ServiceControlHandler handler,
            IntPtr context);

        [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetServiceStatus(
            IntPtr serviceStatusHandle,
            ref ServiceStatus serviceStatus);
    }

    // Builds and runs the one-entry SCM dispatch table. It never installs or
    // starts a service. ERROR_FAILED_SERVICE_CONTROLLER_CONNECT means the
    // caller was not the SCM, which is the honest result for a console run.
    internal static class WindowsServiceScmDispatcher
    {
        public static bool TryRun(
            WindowsServiceControlNativeMethods.ServiceMainFunction serviceMain,
            string serviceName,
            out int error)
        {
            if (serviceMain == null || string.IsNullOrEmpty(serviceName))
            {
                error = WindowsServiceControlNativeMethods.ErrorCallNotImplemented;
                return false;
            }

            WindowsServiceControlNativeMethods.ServiceTableEntry[] table =
                new WindowsServiceControlNativeMethods.ServiceTableEntry[2];
            table[0].ServiceName = serviceName;
            table[0].ServiceProc = serviceMain;
            table[1].ServiceName = null;
            table[1].ServiceProc = null;

            if (!WindowsServiceControlNativeMethods.StartServiceCtrlDispatcherW(table))
            {
                error = Marshal.GetLastWin32Error();
                return false;
            }
            error = WindowsServiceControlNativeMethods.ErrorSuccess;
            return true;
        }
    }
}
