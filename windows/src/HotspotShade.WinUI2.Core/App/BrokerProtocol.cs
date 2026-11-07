using System;
using System.Collections.Generic;
using System.Globalization;

namespace HotspotShade.WinUI2.Core.App
{
    // The app-service protocol between the UWP window and the full-trust
    // broker. Every request names one fixed operation. The broker maps it to
    // one fixed engine request, so the window can never choose a path, a
    // host, a port, a header, or a body. Every value is a string. The bearer
    // secret, the source device token, and the pairing identity never cross
    // this boundary: the engine status and the pairing answers hold none of
    // them, and the broker never adds one.
    public static class BrokerProtocol
    {
        public const string ServiceName = "hotspotshade.engine";

        public const string OpField = "op";
        public const string PingField = "ping";
        public const string SinceField = "since";
        public const string ProcessField = "pid";
        // The window handle of the app, used only as the owner of the UAC
        // prompt so that Windows shows it in front of the app.
        public const string WindowField = "hwnd";

        public const string OkField = "ok";
        public const string HttpField = "http";
        public const string CodeField = "code";
        public const string BodyField = "body";
        public const string SourceField = "source";
        public const string PhaseField = "phase";
        public const string TurnOnField = "turn_on";

        public const int MaxRequestFields = 4;
        public const int MaxFieldChars = 64;
        // The broker trims the engine status and the logs so one reply stays
        // well inside the app-service message limit.
        public const int MaxBodyChars = 45056;
        public const int MaxLogLines = 200;

        public static readonly string[] AllOps =
        {
            BrokerOps.Hello,
            BrokerOps.Status,
            BrokerOps.PairStatus,
            BrokerOps.Pair,
            BrokerOps.PairCancel,
            BrokerOps.Forget,
            BrokerOps.Probe,
            BrokerOps.Logs,
            BrokerOps.Diagnostics,
            BrokerOps.Failures,
            BrokerOps.TurnOn,
            BrokerOps.TurnOff
        };

        public static bool IsKnownOp(string op)
        {
            return Array.IndexOf(AllOps, op) >= 0;
        }

        // The fields that one operation may carry besides "op".
        public static bool IsAllowedField(string op, string field)
        {
            if (field == OpField)
            {
                return true;
            }
            switch (op)
            {
                case BrokerOps.Hello:
                    return field == ProcessField;
                case BrokerOps.TurnOn:
                    return field == PingField || field == WindowField;
                case BrokerOps.Logs:
                    return field == SinceField;
                default:
                    return false;
            }
        }

        // Check one request from the window. Every value must be a short
        // string. Unknown fields, unknown operations, and odd values are
        // refused with a fixed code before any engine request.
        public static bool TryValidate(IList<KeyValuePair<string, object>> fields, out BrokerRequest request, out string code)
        {
            request = null;
            code = BrokerCodes.BadRequest;
            if (fields == null || fields.Count == 0 || fields.Count > MaxRequestFields)
            {
                return false;
            }
            Dictionary<string, string> values = new Dictionary<string, string>(StringComparer.Ordinal);
            for (int index = 0; index < fields.Count; index++)
            {
                string key = fields[index].Key;
                string text = fields[index].Value as string;
                if (key == null || text == null || key.Length > MaxFieldChars || text.Length > MaxFieldChars)
                {
                    return false;
                }
                if (values.ContainsKey(key))
                {
                    return false;
                }
                values.Add(key, text);
            }
            string op;
            if (!values.TryGetValue(OpField, out op) || !IsKnownOp(op))
            {
                code = BrokerCodes.UnknownOp;
                return false;
            }
            foreach (KeyValuePair<string, string> pair in values)
            {
                if (!IsAllowedField(op, pair.Key))
                {
                    return false;
                }
            }
            BrokerRequest parsed = new BrokerRequest(op);
            string value;
            if (op == BrokerOps.TurnOn)
            {
                if (!values.TryGetValue(PingField, out value) || (value != "on" && value != "off"))
                {
                    return false;
                }
                parsed.Ping = value == "on";
                long window = 0;
                if (values.TryGetValue(WindowField, out value)
                    && (!long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out window) || window < 0))
                {
                    return false;
                }
                parsed.OwnerWindow = window;
            }
            if (op == BrokerOps.Logs)
            {
                long since = 0;
                if (values.TryGetValue(SinceField, out value)
                    && (!long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out since) || since < 0))
                {
                    return false;
                }
                parsed.Since = since;
            }
            if (op == BrokerOps.Hello)
            {
                int pid;
                if (!values.TryGetValue(ProcessField, out value)
                    || !int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out pid)
                    || pid <= 0)
                {
                    return false;
                }
                parsed.ProcessId = pid;
            }
            request = parsed;
            code = "";
            return true;
        }

        public static string FormatSince(long since)
        {
            return since.ToString(CultureInfo.InvariantCulture);
        }
    }

    public static class BrokerOps
    {
        // The window names its own process. The broker keeps running while
        // that process lives, so a suspended window does not stop a tunnel,
        // and a closed window does.
        public const string Hello = "hello";
        public const string Status = "status";
        public const string PairStatus = "pair_status";
        public const string Pair = "pair";
        public const string PairCancel = "pair_cancel";
        public const string Forget = "forget";
        public const string Probe = "probe";
        public const string Logs = "logs";
        public const string Diagnostics = "diagnostics";
        public const string Failures = "failures";
        // The only operation that asks Windows for administrator approval.
        public const string TurnOn = "turn_on";
        public const string TurnOff = "turn_off";
    }

    // One checked request.
    public sealed class BrokerRequest
    {
        public BrokerRequest(string op)
        {
            Op = op;
        }

        public string Op { get; private set; }

        public bool Ping { get; set; }

        public long Since { get; set; }

        public int ProcessId { get; set; }

        public long OwnerWindow { get; set; }
    }

    // The fixed broker reply codes. A code is a word, never a path, a port, a
    // handle, or a secret. AppText maps each one to a sentence.
    public static class BrokerCodes
    {
        public const string None = "";
        public const string BadRequest = "bad_request";
        public const string UnknownOp = "unknown_op";
        public const string Busy = "busy";
        public const string Closed = "closed";
        public const string EngineStarting = "engine_starting";
        public const string EngineUnavailable = "engine_unavailable";
        public const string EngineExited = "engine_exited";
        public const string EngineMissing = "engine_missing";
        public const string ListenerNotOwned = "listener_not_owned";
        public const string ListenerUnknown = "listener_unknown";
        public const string Timeout = "timeout";
        public const string BadResponse = "bad_response";
        public const string ReplyTooLarge = "reply_too_large";
        public const string ElevatedActive = "elevated_active";
        public const string NotPaired = "not_paired";
        public const string TunnelRunning = "tunnel_running";
        public const string HandoffUnsupported = "handoff_unsupported";
        public const string HandoffFailed = "handoff_failed";
        public const string AdapterDllMissing = "wintun_missing";
        public const string InstallUntrusted = "install_untrusted";
        public const string ElevationCancelled = "elevation_cancelled";
        public const string ElevationFailed = "elevation_failed";
        public const string ElevationTimeout = "elevation_timeout";
        public const string ElevationOtherAccount = "elevation_other_account";
        public const string ElevatedEngineFailed = "elevated_engine_failed";
        public const string StartRefused = "start_refused";
        public const string StopUnconfirmed = "stop_unconfirmed";
        public const string ElevatedLost = "elevated_lost";
    }

    // Which engine answers status now.
    public static class BrokerSources
    {
        public const string None = "none";
        public const string User = "user";
        public const string Elevated = "elevated";
    }

    // The broker tunnel phase. The window shows it together with the engine
    // status. Only "idle" with the user engine allows pairing and forget.
    public static class BrokerPhases
    {
        public const string Idle = "idle";
        public const string Starting = "starting";
        public const string Elevated = "elevated";
        public const string Stopping = "stopping";
        // A stop that the broker could not confirm. The elevated engine stays
        // the status source and Turn on stays disabled.
        public const string StopUnconfirmed = "stop_unconfirmed";
        // The elevated engine exited without a confirmed stop. Its routes
        // are not verified. Turn on stays disabled until the broker restarts.
        public const string ElevatedLost = "elevated_lost";
    }

    // Whether Turn on can work with this install. A value other than
    // "available" is a fixed reason code.
    public static class BrokerTurnOn
    {
        public const string Available = "available";
    }

    // The single rule for administrator approval. Only Turn on starts the
    // elevated engine. Opening the app, status, pairing, Forget, Settings,
    // Activity, diagnostics, failures, and Turn off never ask.
    public static class ElevationPolicy
    {
        public static bool RequiresElevation(string op)
        {
            return op == BrokerOps.TurnOn;
        }
    }
}
