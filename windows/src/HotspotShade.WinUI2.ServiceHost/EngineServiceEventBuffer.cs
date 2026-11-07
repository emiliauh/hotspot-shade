using System;
using System.Collections.Generic;

namespace HotspotShade.WinUI2.ServiceHost
{
    // Fixed event tokens for the service event record. A record never holds a
    // SID, process id, path, address, error text, or token.
    public static class EngineServiceEventCodes
    {
        public const string CallerMissing = "caller_missing";
        public const string CallerAccountMismatch = "caller_account_mismatch";
        public const string CallerImpersonationTooLow = "caller_impersonation_too_low";
        public const string CallerImpersonationUnreadable = "caller_impersonation_unreadable";
        public const string CallerImpersonationInvalid = "caller_impersonation_invalid";
        public const string CallerSessionInvalid = "caller_session_invalid";
        public const string CallerPackageMismatch = "caller_package_mismatch";
        public const string ElevatedCaller = "elevated_caller";
        public const string SameUserCaller = "same_user_caller";
        public const string CallerSidRejected = "caller_sid_rejected";
        public const string CallerAccountTypeFailed = "caller_account_type_failed";
        public const string CallerAccountTypeNotUser = "caller_account_type_not_user";
        public const string CallerImpersonationFailed = "caller_impersonation_failed";
        public const string CallerTokenFailed = "caller_token_failed";
        public const string CallerRevertFailed = "caller_revert_failed";
        public const string CallerRevertUnverified = "caller_revert_unverified";
        public const string FirstFrameNotHello = "first_frame_not_hello";
        public const string FirstFrameInvalid = "first_frame_invalid";
        public const string FrameTimeout = "frame_timeout";
        public const string FrameInvalid = "frame_invalid";
        public const string BoundaryReadTimeout = "boundary_read_timeout";
        public const string IdleTimeout = "idle_timeout";
        public const string PipeNameInUse = "pipe_name_in_use";
        public const string PipeCreateFailed = "pipe_create_failed";
        public const string PipeConnectFailed = "pipe_connect_failed";
        public const string PipeReadFailed = "pipe_read_failed";
        public const string PipeWriteFailed = "pipe_write_failed";
        public const string ServerNotRunning = "server_not_running";
        public const string ServerProcessMismatch = "server_process_mismatch";
        public const string ServerOwnerMismatch = "server_owner_mismatch";
        public const string ServerPathMismatch = "server_path_mismatch";
        public const string ServerQueryFailed = "server_query_failed";
        public const string ServerRecheckFailed = "server_recheck_failed";
        public const string ClientOpenFailed = "client_open_failed";
        public const string ClientAccessRefused = "client_access_refused";
        public const string ClientBusy = "client_busy";
        public const string StateReadFailed = "state_read_failed";
        public const string StateImageMismatch = "state_image_mismatch";
        public const string StateStartRefused = "state_start_refused";
        public const string StateProcessNotProven = "state_process_not_proven";
        public const string StatusInstanceMismatch = "status_instance_mismatch";
        public const string StatusStale = "status_stale";
        public const string StatusFuture = "status_future";
        public const string StatusInconsistent = "status_inconsistent";
        public const string SourceProxyGuardClosed = "source_proxy_guard_closed";
        public const string ControlChannelUnavailable = "control_channel_unavailable";
        public const string ControlHandshakeFailed = "control_handshake_failed";
        public const string ControlProtocolFailed = "control_protocol_failed";
        public const string ControlStatusInvalid = "control_status_invalid";
        public const string ControlStopFailed = "control_stop_failed";
        public const string ParentLost = "parent_lost";
        public const string ServiceStop = "service_stop";
        public const string SessionClosed = "session_closed";
        public const string SessionBusy = "session_busy";
        public const string SessionStopFailed = "session_stop_failed";
        public const string PlatformNotWindows = "platform_not_windows";
        public const string ListenerCreateFailed = "listener_create_failed";
        public const string ListenerNotReady = "listener_not_ready";
        public const string ListenerStopped = "listener_stopped";
        public const string StopTimeout = "stop_timeout";
        public const string SecondStartRefused = "second_start_refused";
        public const string ServiceHandlerRegisterFailed = "service_handler_register_failed";
        public const string ServiceStatusReportFailed = "service_status_report_failed";
        public const string ServiceConfigurationInvalid = "service_configuration_invalid";
        public const string ServiceStopControl = "service_stop_control";
        public const string ServiceStopCancellationFailed = "service_stop_cancellation_failed";
        public const string ServiceShutdownControl = "service_shutdown_control";
        public const string ServiceControlRefused = "service_control_refused";
        public const string EventCodeInvalid = "event_code_invalid";

        private static readonly HashSet<string> Known = BuildKnown();

        public static bool IsKnown(string eventCode)
        {
            return !string.IsNullOrEmpty(eventCode) && Known.Contains(eventCode);
        }

        private static HashSet<string> BuildKnown()
        {
            HashSet<string> values = new HashSet<string>(StringComparer.Ordinal);
            values.Add(CallerMissing);
            values.Add(CallerAccountMismatch);
            values.Add(CallerImpersonationTooLow);
            values.Add(CallerImpersonationUnreadable);
            values.Add(CallerImpersonationInvalid);
            values.Add(CallerSessionInvalid);
            values.Add(CallerPackageMismatch);
            values.Add(ElevatedCaller);
            values.Add(SameUserCaller);
            values.Add(CallerSidRejected);
            values.Add(CallerAccountTypeFailed);
            values.Add(CallerAccountTypeNotUser);
            values.Add(CallerImpersonationFailed);
            values.Add(CallerTokenFailed);
            values.Add(CallerRevertFailed);
            values.Add(CallerRevertUnverified);
            values.Add(FirstFrameNotHello);
            values.Add(FirstFrameInvalid);
            values.Add(FrameTimeout);
            values.Add(FrameInvalid);
            values.Add(IdleTimeout);
            values.Add(BoundaryReadTimeout);
            values.Add(PipeNameInUse);
            values.Add(PipeCreateFailed);
            values.Add(PipeConnectFailed);
            values.Add(PipeReadFailed);
            values.Add(PipeWriteFailed);
            values.Add(ServerNotRunning);
            values.Add(ServerProcessMismatch);
            values.Add(ServerOwnerMismatch);
            values.Add(ServerPathMismatch);
            values.Add(ServerQueryFailed);
            values.Add(ServerRecheckFailed);
            values.Add(ClientOpenFailed);
            values.Add(ClientAccessRefused);
            values.Add(ClientBusy);
            values.Add(StateReadFailed);
            values.Add(StateImageMismatch);
            values.Add(StateStartRefused);
            values.Add(StateProcessNotProven);
            values.Add(StatusInstanceMismatch);
            values.Add(StatusStale);
            values.Add(StatusFuture);
            values.Add(StatusInconsistent);
            values.Add(SourceProxyGuardClosed);
            values.Add(ControlChannelUnavailable);
            values.Add(ControlHandshakeFailed);
            values.Add(ControlProtocolFailed);
            values.Add(ControlStatusInvalid);
            values.Add(ControlStopFailed);
            values.Add(ParentLost);
            values.Add(ServiceStop);
            values.Add(SessionClosed);
            values.Add(SessionBusy);
            values.Add(SessionStopFailed);
            values.Add(PlatformNotWindows);
            values.Add(ListenerCreateFailed);
            values.Add(ListenerNotReady);
            values.Add(ListenerStopped);
            values.Add(StopTimeout);
            values.Add(SecondStartRefused);
            values.Add(ServiceHandlerRegisterFailed);
            values.Add(ServiceStatusReportFailed);
            values.Add(ServiceConfigurationInvalid);
            values.Add(ServiceStopControl);
            values.Add(ServiceStopCancellationFailed);
            values.Add(ServiceShutdownControl);
            values.Add(ServiceControlRefused);
            values.Add(EventCodeInvalid);
            return values;
        }
    }

    // A bounded in-memory event record. It is never written to disk and never
    // sent to the source device. An unknown token is replaced by the fixed
    // event_code_invalid token, so free text cannot enter the record.
    public sealed class EngineServiceEventBuffer : IEngineServiceEventSink
    {
        private readonly object sync = new object();
        private readonly Queue<string> records = new Queue<string>();
        private readonly int capacity;

        public EngineServiceEventBuffer()
            : this(EngineServiceTransportLimits.MaxEventRecords)
        {
        }

        public EngineServiceEventBuffer(int capacity)
        {
            if (capacity < 1 || capacity > 1024)
            {
                throw new ArgumentOutOfRangeException("capacity");
            }
            this.capacity = capacity;
        }

        public int Count
        {
            get
            {
                lock (sync)
                {
                    return records.Count;
                }
            }
        }

        public void Record(string eventCode)
        {
            string fixedCode = EngineServiceEventCodes.IsKnown(eventCode)
                ? eventCode
                : EngineServiceEventCodes.EventCodeInvalid;
            lock (sync)
            {
                while (records.Count >= capacity)
                {
                    records.Dequeue();
                }
                records.Enqueue(fixedCode);
            }
        }

        public string[] Snapshot()
        {
            lock (sync)
            {
                return records.ToArray();
            }
        }

        public bool Contains(string eventCode)
        {
            if (string.IsNullOrEmpty(eventCode))
            {
                return false;
            }
            lock (sync)
            {
                foreach (string value in records)
                {
                    if (string.Equals(value, eventCode, StringComparison.Ordinal))
                    {
                        return true;
                    }
                }
            }
            return false;
        }
    }
}
