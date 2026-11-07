using System;
using System.Threading;
using HotspotShade.WinUI2.ServiceHost;

namespace HotspotShade.WinUI2.Service
{
    // The native seam for the SCM status path. A fake supplies one in the
    // hermetic checks. The production sink is a thin P/Invoke wrapper.
    internal interface IEngineServiceScmStatusSink
    {
        bool TryRegister(
            string serviceName,
            WindowsServiceControlNativeMethods.ServiceControlHandler handler,
            out IntPtr handle,
            out int error);

        bool TrySetStatus(
            IntPtr handle,
            WindowsServiceControlNativeMethods.ServiceStatus status,
            out int error);
    }

    internal sealed class WindowsServiceScmStatusSink : IEngineServiceScmStatusSink
    {
        public bool TryRegister(
            string serviceName,
            WindowsServiceControlNativeMethods.ServiceControlHandler handler,
            out IntPtr handle,
            out int error)
        {
            handle = WindowsServiceControlNativeMethods.RegisterServiceCtrlHandlerExW(
                serviceName,
                handler,
                IntPtr.Zero);
            if (handle == IntPtr.Zero)
            {
                error = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                return false;
            }
            error = WindowsServiceControlNativeMethods.ErrorSuccess;
            return true;
        }

        public bool TrySetStatus(
            IntPtr handle,
            WindowsServiceControlNativeMethods.ServiceStatus status,
            out int error)
        {
            if (handle == IntPtr.Zero)
            {
                error = WindowsServiceControlNativeMethods.ErrorCallNotImplemented;
                return false;
            }
            if (!WindowsServiceControlNativeMethods.SetServiceStatus(handle, ref status))
            {
                error = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                return false;
            }
            error = WindowsServiceControlNativeMethods.ErrorSuccess;
            return true;
        }
    }

    // Maps the host state to the documented SERVICE_STATUS values. Pending
    // states carry a nonzero checkpoint and the caller's wait hint. Running
    // accepts stop and shutdown. Stopped accepts no control.
    internal static class EngineServiceScmStatusMapping
    {
        public static WindowsServiceControlNativeMethods.ServiceStatus ForState(
            EngineServiceHostState state,
            int checkpoint,
            TimeSpan waitHint)
        {
            bool pending = state == EngineServiceHostState.StartPending
                || state == EngineServiceHostState.StopPending
                || state == EngineServiceHostState.PausePending
                || state == EngineServiceHostState.ContinuePending;

            WindowsServiceControlNativeMethods.ServiceStatus status =
                new WindowsServiceControlNativeMethods.ServiceStatus();
            status.ServiceType = WindowsServiceControlNativeMethods.ServiceWin32OwnProcess;
            status.CurrentState = MapState(state);
            status.ControlsAccepted = state == EngineServiceHostState.Running
                ? WindowsServiceControlNativeMethods.ServiceAcceptStop
                    | WindowsServiceControlNativeMethods.ServiceAcceptShutdown
                : 0;
            status.Win32ExitCode = 0;
            status.ServiceSpecificExitCode = 0;
            status.Checkpoint = pending
                ? ToUInt(checkpoint < 1 ? 1 : checkpoint)
                : 0;
            status.WaitHint = pending
                ? Math.Max(1u, ToUInt(waitHint))
                : 0;
            return status;
        }

        public static WindowsServiceControlNativeMethods.ServiceStatus Stopped(
            int serviceSpecificExitCode)
        {
            WindowsServiceControlNativeMethods.ServiceStatus status =
                new WindowsServiceControlNativeMethods.ServiceStatus();
            status.ServiceType = WindowsServiceControlNativeMethods.ServiceWin32OwnProcess;
            status.CurrentState = WindowsServiceControlNativeMethods.ServiceStopped;
            status.ControlsAccepted = 0;
            status.Win32ExitCode = serviceSpecificExitCode == 0
                ? 0
                : (uint)WindowsServiceControlNativeMethods.ErrorServiceSpecificError;
            status.ServiceSpecificExitCode = serviceSpecificExitCode == 0
                ? 0
                : ToUInt(serviceSpecificExitCode);
            status.Checkpoint = 0;
            status.WaitHint = 0;
            return status;
        }

        private static uint MapState(EngineServiceHostState state)
        {
            if (state == EngineServiceHostState.StartPending)
            {
                return WindowsServiceControlNativeMethods.ServiceStartPending;
            }
            if (state == EngineServiceHostState.StopPending)
            {
                return WindowsServiceControlNativeMethods.ServiceStopPending;
            }
            if (state == EngineServiceHostState.Running)
            {
                return WindowsServiceControlNativeMethods.ServiceRunning;
            }
            if (state == EngineServiceHostState.PausePending)
            {
                return WindowsServiceControlNativeMethods.ServicePausePending;
            }
            if (state == EngineServiceHostState.Paused)
            {
                return WindowsServiceControlNativeMethods.ServicePaused;
            }
            if (state == EngineServiceHostState.ContinuePending)
            {
                return WindowsServiceControlNativeMethods.ServiceContinuePending;
            }
            return WindowsServiceControlNativeMethods.ServiceStopped;
        }

        private static uint ToUInt(int value)
        {
            return value <= 0 ? 0u : (uint)value;
        }

        private static uint ToUInt(TimeSpan value)
        {
            if (value <= TimeSpan.Zero)
            {
                return 0;
            }
            double milliseconds = value.TotalMilliseconds;
            if (milliseconds >= uint.MaxValue)
            {
                return uint.MaxValue;
            }
            return (uint)milliseconds;
        }
    }

    // Reports service state to the SCM. A stop that arrives before the host
    // reports Running must not produce a backwards StartPending or Running
    // transition, so those states become StopPending after a stop request.
    // The final Stopped record is held until TryFinalize, so the one stopped
    // record carries the real service-specific exit code.
    internal sealed class EngineServiceScmStatusReporter : IEngineServiceHostControl
    {
        private readonly object sync = new object();
        private readonly IEngineServiceScmStatusSink sink;
        private readonly IEngineServiceEventSink events;
        private IntPtr handle;
        private bool registered;
        private bool failed;
        private int stopRequested;
        private bool stoppedPending;
        private bool finalized;
        private int lastError;
        private uint lastCheckpoint;
        private uint lastPendingState;
        private uint lastPendingWaitHint;

        public EngineServiceScmStatusReporter(
            IEngineServiceScmStatusSink sink,
            IEngineServiceEventSink events)
        {
            if (sink == null)
            {
                throw new ArgumentNullException("sink");
            }
            if (events == null)
            {
                throw new ArgumentNullException("events");
            }
            this.sink = sink;
            this.events = events;
        }

        public bool Failed
        {
            get
            {
                lock (sync)
                {
                    return failed;
                }
            }
        }

        public int LastError
        {
            get
            {
                lock (sync)
                {
                    return lastError;
                }
            }
        }

        public bool TryRegister(
            string serviceName,
            WindowsServiceControlNativeMethods.ServiceControlHandler handler)
        {
            if (string.IsNullOrEmpty(serviceName) || handler == null)
            {
                return false;
            }
            lock (sync)
            {
                if (registered)
                {
                    return !failed;
                }
                IntPtr native;
                int error;
                if (!sink.TryRegister(serviceName, handler, out native, out error)
                    || native == IntPtr.Zero)
                {
                    failed = true;
                    lastError = error;
                    return false;
                }
                handle = native;
                registered = true;
                lastError = 0;
                return true;
            }
        }

        public void MarkStopRequested()
        {
            System.Threading.Interlocked.Exchange(ref stopRequested, 1);
        }

        public void ReportState(
            EngineServiceHostState state,
            int checkpoint,
            TimeSpan waitHint)
        {
            lock (sync)
            {
                if (failed || finalized || stoppedPending)
                {
                    return;
                }
                if (!registered)
                {
                    failed = true;
                    lastError = WindowsServiceControlNativeMethods.ErrorCallNotImplemented;
                    return;
                }

                EngineServiceHostState effective = state;
                if (System.Threading.Volatile.Read(ref stopRequested) != 0
                    && (state == EngineServiceHostState.StartPending
                        || state == EngineServiceHostState.Running))
                {
                    // A stop that won before Running must not produce a
                    // backwards transition that the SCM could reject.
                    effective = EngineServiceHostState.StopPending;
                }

                if (effective == EngineServiceHostState.Stopped)
                {
                    // The one stopped record is sent by TryFinalize with the
                    // real exit code. A stopped record without an exit code
                    // would hide a failed startup.
                    stoppedPending = true;
                    return;
                }

                int proposedCheckpoint = checkpoint;
                uint pendingState = 0;
                if (effective == EngineServiceHostState.StartPending
                    || effective == EngineServiceHostState.StopPending)
                {
                    pendingState = effective == EngineServiceHostState.StartPending
                        ? WindowsServiceControlNativeMethods.ServiceStartPending
                        : WindowsServiceControlNativeMethods.ServiceStopPending;
                    uint candidate = proposedCheckpoint < 1
                        ? 1u
                        : (uint)proposedCheckpoint;
                    if (pendingState == lastPendingState && candidate <= lastCheckpoint)
                    {
                        candidate = lastCheckpoint + 1;
                    }
                    lastCheckpoint = candidate;
                    proposedCheckpoint = candidate > int.MaxValue
                        ? int.MaxValue
                        : (int)candidate;
                }

                WindowsServiceControlNativeMethods.ServiceStatus status =
                    EngineServiceScmStatusMapping.ForState(
                        effective,
                        proposedCheckpoint,
                        waitHint);
                if (pendingState != 0)
                {
                    // A later pending report must not shorten the wait hint
                    // that an earlier report gave the SCM.
                    if (pendingState == lastPendingState
                        && status.WaitHint < lastPendingWaitHint)
                    {
                        status.WaitHint = lastPendingWaitHint;
                    }
                    lastPendingState = pendingState;
                    lastPendingWaitHint = status.WaitHint;
                }
                int error;
                if (!TrySetStatus(status, out error))
                {
                    failed = true;
                    lastError = error;
                    events.Record(EngineServiceEventCodes.ServiceStatusReportFailed);
                    return;
                }
            }
        }

        // Sends exactly one stopped record. A zero code is a clean stop. A
        // nonzero code uses ERROR_SERVICE_SPECIFIC_ERROR, so a person or the
        // SCM recovery policy can see the fixed startup failure class.
        public bool TryFinalize(int serviceSpecificExitCode)
        {
            lock (sync)
            {
                if (failed)
                {
                    return false;
                }
                if (finalized)
                {
                    return true;
                }
                if (!registered)
                {
                    failed = true;
                    lastError = WindowsServiceControlNativeMethods.ErrorCallNotImplemented;
                    return false;
                }

                int normalized = serviceSpecificExitCode < 0 ? 0 : serviceSpecificExitCode;
                WindowsServiceControlNativeMethods.ServiceStatus status =
                    EngineServiceScmStatusMapping.Stopped(normalized);
                int error;
                if (!TrySetStatus(status, out error))
                {
                    failed = true;
                    lastError = error;
                    events.Record(EngineServiceEventCodes.ServiceStatusReportFailed);
                    return false;
                }
                finalized = true;
                stoppedPending = false;
                return true;
            }
        }

        private bool TrySetStatus(
            WindowsServiceControlNativeMethods.ServiceStatus status,
            out int error)
        {
            try
            {
                return sink.TrySetStatus(handle, status, out error);
            }
            catch (Exception)
            {
                error = WindowsServiceControlNativeMethods.ErrorCallNotImplemented;
                return false;
            }
        }
    }
}
