using System;

namespace HotspotShade.WinUI2.Core.Engine
{
    // The versioned contract between the WinUI app and the full-trust Windows
    // engine broker. The contract carries no source device token and no
    // identity key. The broker holds credentials and sends non-secret state
    // only. One inner flow maps to one outer connection inside the engine; this
    // boundary never moves traffic.
    public static class EngineProtocol
    {
        public const int Version = 1;
        public const string ServiceName = "hotspotshade.engine";
        public const int MaxFieldCount = 24;
        public const int MaxKeyLength = 32;
        public const int MaxValueLength = 512;
        public const int MaxTextLength = 8192;
        public const int SessionIdLength = 32;

        public static class Operations
        {
            public const string Hello = "hello";
            public const string Status = "status";
            public const string Start = "start";
            public const string Stop = "stop";
            public const string Forget = "forget";
            public const string Shutdown = "shutdown";

            // Defined for a later version. The version 1 broker returns the
            // fixed unsupported code for these operations. The app must not
            // show a pairing or diagnostic screen until they are implemented.
            public const string PairBegin = "pair.begin";
            public const string PairStatus = "pair.status";
            public const string PairCancel = "pair.cancel";
            public const string Probe = "probe";
            public const string Diagnostics = "diagnostics";
            public const string Failures = "failures";
        }

        public static class Keys
        {
            public const string Version = "v";
            public const string Operation = "op";
            public const string Session = "sid";
            public const string Ping = "ping";
            public const string Ok = "ok";
            public const string Code = "code";
            public const string Instance = "instance";
            public const string Engine = "engine";
            public const string Paired = "paired";
            public const string Running = "running";
            public const string Source = "source";
            public const string Trusted = "trusted";
            public const string Connections = "connections";
            public const string Stop = "stop";

            // Optional evidence on a status from the Windows engine service.
            // The old broker never sent them, so a missing value keeps the
            // version 1 meaning. A service status uses them to carry the
            // source check time, an unknown connection count, the cleanup
            // gate, and the TTL audit count.
            public const string CheckedAt = "checked_at";
            public const string ConnectionsKnown = "connections_known";
            public const string Cleanup = "cleanup";
            public const string TtlBad = "ttl_bad";
        }

        public static class ErrorCodes
        {
            public const string BadRequest = "bad_request";
            public const string BadVersion = "bad_version";
            public const string BadOperation = "bad_operation";
            public const string BadResponse = "bad_response";
            public const string Forbidden = "forbidden";
            public const string Busy = "busy";
            public const string NotConnected = "not_connected";
            public const string NoStatus = "no_status";
            public const string StaleStatus = "stale_status";
            public const string NotPaired = "not_paired";
            public const string SourceMissing = "source_missing";
            public const string NotReady = "not_ready";
            public const string AlreadyRunning = "already_running";
            public const string ForgetWhileRunning = "forget_while_running";
            public const string EngineUnavailable = "engine_unavailable";
            public const string HelperMissing = "helper_missing";
            public const string EngineRestarted = "engine_restarted";
            public const string Timeout = "timeout";
            public const string Closed = "closed";
            public const string Unsupported = "unsupported";
            public const string Internal = "internal";
            public const string NotDelivered = "not_delivered";

            // Service boundary codes. They are additive to version 1 and are
            // used only by the Windows engine service contract. A code from
            // the old broker remains valid.
            public const string BoundaryAuthFailed = "boundary_auth_failed";
            public const string BoundaryBusy = "boundary_busy";
            public const string CleanupBlocked = "cleanup_blocked";
            public const string CleanupUnknown = "cleanup_unknown";
            public const string CleanupPending = "cleanup_pending";
            public const string AdminRequired = "admin_required";
            public const string ManualPhone = "manual_phone";
            public const string RouteSetup = "route_setup";
            public const string TunnelSetup = "tunnel_setup";
            public const string ProtocolMismatch = "protocol_mismatch";
            public const string LaunchTimeout = "launch_timeout";
            public const string EngineStopTimeout = "engine_stop_timeout";
            public const string EngineLost = "engine_lost";
            public const string SourceDeviceGone = "source_device_gone";
            public const string ObservationUnavailable = "observation_unavailable";
            public const string GatewayChanged = "gateway_changed";
            public const string LinkChanged = "link_changed";
            public const string LinkUnknown = "link_unknown";
            public const string ServiceStop = "service_stop";
            public const string Shutdown = "shutdown";
            public const string SessionLogoff = "session_logoff";
            public const string Starting = "starting";
        }

        public static class StopReasons
        {
            public const string None = "none";
            public const string User = "user";
            public const string HotspotLost = "hotspot_lost";
            public const string SourceLost = "source_lost";
            public const string EngineLost = "engine_lost";
            public const string StartFailed = "start_failed";
            public const string ParentLost = "parent_lost";
            public const string Unknown = "unknown";

            // The Windows engine service names a source device loss, an
            // unobservable source, a hotspot identity change, and a service
            // stop precisely. The old broker words stay valid.
            public const string SourceDeviceGone = "source_device_gone";
            public const string ObservationUnavailable = "observation_unavailable";
            public const string GatewayChanged = "gateway_changed";
            public const string LinkChanged = "link_changed";
            public const string ServiceStop = "service_stop";
            public const string Shutdown = "shutdown";
            public const string SessionLogoff = "session_logoff";
        }

        public static class EngineStates
        {
            public const string Unavailable = "unavailable";
            public const string Starting = "starting";
            public const string Ready = "ready";
            public const string Running = "running";
        }

        public static bool IsKnownOperation(string operation)
        {
            switch (operation)
            {
                case Operations.Hello:
                case Operations.Status:
                case Operations.Start:
                case Operations.Stop:
                case Operations.Forget:
                case Operations.Shutdown:
                case Operations.PairBegin:
                case Operations.PairStatus:
                case Operations.PairCancel:
                case Operations.Probe:
                case Operations.Diagnostics:
                case Operations.Failures:
                    return true;
                default:
                    return false;
            }
        }

        public static bool IsKnownErrorCode(string code)
        {
            switch (code)
            {
                case ErrorCodes.BadRequest:
                case ErrorCodes.BadVersion:
                case ErrorCodes.BadOperation:
                case ErrorCodes.BadResponse:
                case ErrorCodes.Forbidden:
                case ErrorCodes.Busy:
                case ErrorCodes.NotConnected:
                case ErrorCodes.NoStatus:
                case ErrorCodes.StaleStatus:
                case ErrorCodes.NotPaired:
                case ErrorCodes.SourceMissing:
                case ErrorCodes.NotReady:
                case ErrorCodes.AlreadyRunning:
                case ErrorCodes.ForgetWhileRunning:
                case ErrorCodes.EngineUnavailable:
                case ErrorCodes.HelperMissing:
                case ErrorCodes.EngineRestarted:
                case ErrorCodes.Timeout:
                case ErrorCodes.Closed:
                case ErrorCodes.Unsupported:
                case ErrorCodes.Internal:
                case ErrorCodes.NotDelivered:
                case ErrorCodes.BoundaryAuthFailed:
                case ErrorCodes.BoundaryBusy:
                case ErrorCodes.CleanupBlocked:
                case ErrorCodes.CleanupUnknown:
                case ErrorCodes.CleanupPending:
                case ErrorCodes.AdminRequired:
                case ErrorCodes.ManualPhone:
                case ErrorCodes.RouteSetup:
                case ErrorCodes.TunnelSetup:
                case ErrorCodes.ProtocolMismatch:
                case ErrorCodes.LaunchTimeout:
                case ErrorCodes.EngineStopTimeout:
                case ErrorCodes.EngineLost:
                case ErrorCodes.SourceDeviceGone:
                case ErrorCodes.ObservationUnavailable:
                case ErrorCodes.GatewayChanged:
                case ErrorCodes.LinkChanged:
                case ErrorCodes.LinkUnknown:
                case ErrorCodes.ServiceStop:
                case ErrorCodes.Shutdown:
                case ErrorCodes.SessionLogoff:
                case ErrorCodes.Starting:
                    return true;
                default:
                    return false;
            }
        }

        public static bool IsKnownStopReason(string reason)
        {
            switch (reason)
            {
                case StopReasons.None:
                case StopReasons.User:
                case StopReasons.HotspotLost:
                case StopReasons.SourceLost:
                case StopReasons.EngineLost:
                case StopReasons.StartFailed:
                case StopReasons.ParentLost:
                case StopReasons.Unknown:
                case StopReasons.SourceDeviceGone:
                case StopReasons.ObservationUnavailable:
                case StopReasons.GatewayChanged:
                case StopReasons.LinkChanged:
                case StopReasons.ServiceStop:
                case StopReasons.Shutdown:
                case StopReasons.SessionLogoff:
                    return true;
                default:
                    return false;
            }
        }

        public static bool IsKnownEngineState(string state)
        {
            switch (state)
            {
                case EngineStates.Unavailable:
                case EngineStates.Starting:
                case EngineStates.Ready:
                case EngineStates.Running:
                    return true;
                default:
                    return false;
            }
        }

        public static string ErrorText(string code)
        {
            switch (code)
            {
                case ErrorCodes.HelperMissing:
                    return "The Windows engine broker is not installed. This build has no tunnel.";
                case ErrorCodes.EngineUnavailable:
                    return "The app cannot reach the engine. The tunnel state is unknown.";
                case ErrorCodes.Timeout:
                    return "The engine did not answer in time. The tunnel state is unknown.";
                case ErrorCodes.NotConnected:
                    return "The app is not connected to the engine.";
                case ErrorCodes.NoStatus:
                    return "The app has no engine status yet.";
                case ErrorCodes.StaleStatus:
                    return "The engine status is out of date. Check the status again.";
                case ErrorCodes.NotPaired:
                    return "Pair a source device before you turn on the tunnel.";
                case ErrorCodes.SourceMissing:
                    return "The source device is not present.";
                case ErrorCodes.NotReady:
                    return "The source device is not ready.";
                case ErrorCodes.AlreadyRunning:
                    return "The tunnel is already on.";
                case ErrorCodes.ForgetWhileRunning:
                    return "Turn off the tunnel before you forget the source device.";
                case ErrorCodes.EngineRestarted:
                    return "The engine restarted. The tunnel state is unknown.";
                case ErrorCodes.BadResponse:
                    return "The engine sent a status that this app does not know. The tunnel state is unknown.";
                case ErrorCodes.BadVersion:
                    return "The engine protocol does not match this app.";
                case ErrorCodes.Busy:
                    return "Wait for the current action to finish.";
                case ErrorCodes.Closed:
                    return "The engine connection is closed.";
                case ErrorCodes.Unsupported:
                    return "This engine does not support that action.";
                case ErrorCodes.NotDelivered:
                    return "The source device did not answer. This target device forgot the pairing, but the source device may still trust it.";
                case ErrorCodes.Forbidden:
                    return "The engine refused this request.";
                case ErrorCodes.Internal:
                    return "The engine reported an internal error. The tunnel state is unknown.";
                case ErrorCodes.BoundaryAuthFailed:
                    return "The app and the engine service do not trust each other. Restart the service.";
                case ErrorCodes.BoundaryBusy:
                    return "Another app is using the tunnel service.";
                case ErrorCodes.CleanupBlocked:
                    return "An earlier tunnel did not clean up its routes. Check the routes, then try again.";
                case ErrorCodes.CleanupUnknown:
                    return "The last tunnel did not report a clean stop. Check the routes before you start again.";
                case ErrorCodes.CleanupPending:
                    return "The last tunnel is still cleaning up. Wait, then check again.";
                case ErrorCodes.AdminRequired:
                    return "The engine service is not running with administrator rights.";
                case ErrorCodes.ManualPhone:
                    return "Enter the source device address and token.";
                case ErrorCodes.RouteSetup:
                    return "The tunnel could not configure its routes.";
                case ErrorCodes.TunnelSetup:
                    return "The tunnel could not create its virtual interface.";
                case ErrorCodes.ProtocolMismatch:
                    return "The engine service protocol does not match this app.";
                case ErrorCodes.LaunchTimeout:
                    return "The engine did not finish starting.";
                case ErrorCodes.EngineStopTimeout:
                    return "The engine is still cleaning up.";
                case ErrorCodes.EngineLost:
                    return "The engine stopped answering.";
                case ErrorCodes.SourceDeviceGone:
                    return "The source device stopped answering.";
                case ErrorCodes.ObservationUnavailable:
                    return "The tunnel stopped because it could not check the source device for 5 minutes. This does not mean the hotspot or the source device is gone.";
                case ErrorCodes.GatewayChanged:
                    return "The hotspot changed. Enter the source device address and token again.";
                case ErrorCodes.LinkChanged:
                    return "The hotspot changed. Enter the source device address and token again.";
                case ErrorCodes.LinkUnknown:
                    return "The hotspot could not be identified. Check the connection and try again.";
                case ErrorCodes.ServiceStop:
                    return "The tunnel service stopped.";
                case ErrorCodes.Shutdown:
                    return "Windows is shutting down.";
                case ErrorCodes.SessionLogoff:
                    return "The tunnel stopped because you signed out.";
                case ErrorCodes.Starting:
                    return "Starting the engine.";
                default:
                    return "The engine refused this request.";
            }
        }

        public static string StopText(string reason)
        {
            switch (reason)
            {
                case StopReasons.User:
                    return "You turned the tunnel off.";
                case StopReasons.HotspotLost:
                    return "The hotspot link was lost.";
                case StopReasons.SourceLost:
                    return "The source device stopped answering.";
                case StopReasons.EngineLost:
                    return "The engine stopped answering.";
                case StopReasons.StartFailed:
                    return "The tunnel did not start.";
                case StopReasons.ParentLost:
                    return "The app closed. The tunnel stopped.";
                case StopReasons.Unknown:
                    return "The tunnel stopped.";
                case StopReasons.SourceDeviceGone:
                    return "The source device stopped answering.";
                case StopReasons.ObservationUnavailable:
                    return "The tunnel stopped because it could not check the source device for 5 minutes. This does not mean the hotspot or the source device is gone.";
                case StopReasons.GatewayChanged:
                    return "The hotspot changed. Enter the source device address and token again.";
                case StopReasons.LinkChanged:
                    return "The hotspot changed. Enter the source device address and token again.";
                case StopReasons.ServiceStop:
                    return "The tunnel service stopped.";
                case StopReasons.Shutdown:
                    return "Windows is shutting down.";
                case StopReasons.SessionLogoff:
                    return "The tunnel stopped because you signed out.";
                default:
                    return "";
            }
        }

        public static bool IsValidSessionId(string value)
        {
            if (value == null || value.Length != SessionIdLength)
            {
                return false;
            }
            for (int index = 0; index < value.Length; index++)
            {
                char character = value[index];
                bool digit = character >= '0' && character <= '9';
                bool lower = character >= 'a' && character <= 'f';
                if (!digit && !lower)
                {
                    return false;
                }
            }
            return true;
        }

        public static bool IsValidInstanceId(string value)
        {
            if (value == null || value.Length < 8 || value.Length > 64)
            {
                return false;
            }
            for (int index = 0; index < value.Length; index++)
            {
                char character = value[index];
                bool letter = (character >= 'a' && character <= 'z')
                    || (character >= 'A' && character <= 'Z');
                bool digit = character >= '0' && character <= '9';
                bool mark = character == '.' || character == '-' || character == '_';
                if (!letter && !digit && !mark)
                {
                    return false;
                }
            }
            return true;
        }

        public static bool IsSafeFieldName(string name)
        {
            if (name == null || name.Length < 1 || name.Length > MaxKeyLength)
            {
                return false;
            }
            for (int index = 0; index < name.Length; index++)
            {
                char character = name[index];
                bool letter = character >= 'a' && character <= 'z';
                bool digit = character >= '0' && character <= '9';
                bool mark = character == '.' || character == '-' || character == '_';
                if (!letter && !digit && !mark)
                {
                    return false;
                }
            }
            return true;
        }

        public static bool IsSafeFieldValue(string value)
        {
            if (value == null || value.Length > MaxValueLength)
            {
                return false;
            }
            for (int index = 0; index < value.Length; index++)
            {
                char character = value[index];
                if (character < ' ' || character == (char)0x7F)
                {
                    return false;
                }
            }
            return true;
        }

        // A credential field is always refused, even from the trusted broker.
        // The app has no use for one and a reply that carries one is a bug.
        public static bool IsCredentialKey(string name)
        {
            if (string.IsNullOrEmpty(name))
            {
                return false;
            }
            string value = name.ToLowerInvariant();
            if (value == "key"
                || value.EndsWith("_key", StringComparison.Ordinal)
                || value.EndsWith(".key", StringComparison.Ordinal))
            {
                return true;
            }
            string[] denied =
            {
                "token",
                "secret",
                "password",
                "passphrase",
                "credential",
                "authorization",
                "bearer",
                "private",
                "identity",
                "cookie",
                "apikey",
                "api_key",
                "psk"
            };
            for (int index = 0; index < denied.Length; index++)
            {
                if (value.IndexOf(denied[index], StringComparison.Ordinal) >= 0)
                {
                    return true;
                }
            }
            return false;
        }

        public static bool TryParseEngineState(string value, out EngineRunState state)
        {
            switch (value)
            {
                case EngineStates.Unavailable:
                    state = EngineRunState.Unavailable;
                    return true;
                case EngineStates.Starting:
                    state = EngineRunState.Starting;
                    return true;
                case EngineStates.Ready:
                    state = EngineRunState.Ready;
                    return true;
                case EngineStates.Running:
                    state = EngineRunState.Running;
                    return true;
                default:
                    state = EngineRunState.Unavailable;
                    return false;
            }
        }

        public static bool TryParseStopReason(string value, out EngineStopReason reason)
        {
            switch (value)
            {
                case StopReasons.None:
                    reason = EngineStopReason.None;
                    return true;
                case StopReasons.User:
                    reason = EngineStopReason.User;
                    return true;
                case StopReasons.HotspotLost:
                    reason = EngineStopReason.HotspotLost;
                    return true;
                case StopReasons.SourceLost:
                    reason = EngineStopReason.SourceLost;
                    return true;
                case StopReasons.EngineLost:
                    reason = EngineStopReason.EngineLost;
                    return true;
                case StopReasons.StartFailed:
                    reason = EngineStopReason.StartFailed;
                    return true;
                case StopReasons.ParentLost:
                    reason = EngineStopReason.ParentLost;
                    return true;
                case StopReasons.Unknown:
                    reason = EngineStopReason.Unknown;
                    return true;
                case StopReasons.SourceDeviceGone:
                    reason = EngineStopReason.SourceDeviceGone;
                    return true;
                case StopReasons.ObservationUnavailable:
                    reason = EngineStopReason.ObservationUnavailable;
                    return true;
                case StopReasons.GatewayChanged:
                    reason = EngineStopReason.GatewayChanged;
                    return true;
                case StopReasons.LinkChanged:
                    reason = EngineStopReason.LinkChanged;
                    return true;
                case StopReasons.ServiceStop:
                    reason = EngineStopReason.ServiceStop;
                    return true;
                case StopReasons.Shutdown:
                    reason = EngineStopReason.Shutdown;
                    return true;
                case StopReasons.SessionLogoff:
                    reason = EngineStopReason.SessionLogoff;
                    return true;
                default:
                    reason = EngineStopReason.Unknown;
                    return false;
            }
        }
    }
}
