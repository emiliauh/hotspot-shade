using System;
using System.Collections.Generic;

namespace HotspotShade.WinUI2.Core.App
{
    // The source device state from the engine. An unknown string is a safe
    // case that keeps the engine message visible.
    public enum PhoneState
    {
        NoHotspot,
        NotRunning,
        NotResponding,
        ProxyOff,
        Ready,
        Connected,
        Unpaired,
        NotTrusted,
        Checking,
        Unknown
    }

    // The state of the last FORGET request.
    public enum ForgetPhase
    {
        None,
        Pending,
        Confirmed,
        NotDelivered,
        Unknown
    }

    // How far the app can trust the engine's running flag. This mirrors
    // EngineHealth in the macOS app.
    public enum EngineHealth
    {
        Normal,
        CleanupBlocked,
        StateUnknown
    }

    // One status answer from GET /api/status. Every field is optional. A
    // missing value keeps the meaning of an older engine.
    public sealed class EngineStatusSnapshot
    {
        public bool Demo { get; private set; }

        public bool? Running { get; private set; }

        public string Mode { get; private set; }

        public string Error { get; private set; }

        public bool Paired { get; private set; }

        public PhoneState Phone { get; private set; }

        public string PhoneStateRaw { get; private set; }

        public string PhoneMessage { get; private set; }

        public int? PhoneConnections { get; private set; }

        public double? PhoneCheckedAt { get; private set; }

        public bool? TrustedBySource { get; private set; }

        public bool PortChanged { get; private set; }

        public bool? IcmpEnabled { get; private set; }

        public string Interface { get; private set; }

        public ForgetPhase Forget { get; private set; }

        public string LastStopReason { get; private set; }

        public double? LastStopAt { get; private set; }

        public string LastStopMessage { get; private set; }

        public string ServiceState { get; private set; }

        public bool? CleanupBlocked { get; private set; }

        // True when the engine reports an administrator token. A standard
        // user engine reports false.
        public bool? Elevated { get; private set; }

        public long? TtlBad { get; private set; }

        public EngineHealth Health
        {
            get { return ResolveHealth(ServiceState, Running, CleanupBlocked); }
        }

        public bool IsRunning
        {
            get { return Running == true; }
        }

        public static EngineHealth ResolveHealth(string state, bool? running, bool? cleanupBlocked)
        {
            string value = state == null ? "" : state.Trim().ToLowerInvariant();
            if (value.Length != 0 && value != "ready")
            {
                return EngineHealth.StateUnknown;
            }
            if (cleanupBlocked != true)
            {
                return EngineHealth.Normal;
            }
            return running == false ? EngineHealth.CleanupBlocked : EngineHealth.StateUnknown;
        }

        public static PhoneState ParsePhone(string raw)
        {
            switch (raw)
            {
                case "no_hotspot":
                    return PhoneState.NoHotspot;
                case "not_running":
                    return PhoneState.NotRunning;
                case "not_responding":
                    return PhoneState.NotResponding;
                case "proxy_off":
                    return PhoneState.ProxyOff;
                case "ready":
                    return PhoneState.Ready;
                case "connected":
                    return PhoneState.Connected;
                case "unpaired":
                    return PhoneState.Unpaired;
                case "not_trusted":
                    return PhoneState.NotTrusted;
                case "checking":
                    return PhoneState.Checking;
                default:
                    return PhoneState.Unknown;
            }
        }

        public static ForgetPhase ParseForget(string raw)
        {
            if (string.IsNullOrEmpty(raw))
            {
                return ForgetPhase.None;
            }
            switch (raw)
            {
                case "none":
                    return ForgetPhase.None;
                case "pending":
                    return ForgetPhase.Pending;
                case "confirmed":
                    return ForgetPhase.Confirmed;
                case "not_delivered":
                    return ForgetPhase.NotDelivered;
                default:
                    return ForgetPhase.Unknown;
            }
        }

        public static bool TryParse(string json, out EngineStatusSnapshot snapshot)
        {
            snapshot = null;
            JsonValue root;
            if (!JsonValue.TryParseObject(json, out root))
            {
                return false;
            }
            snapshot = From(root);
            return true;
        }

        public static EngineStatusSnapshot From(JsonValue root)
        {
            EngineStatusSnapshot value = new EngineStatusSnapshot();
            value.Demo = root.GetBool("demo") == true;
            value.Running = root.GetBool("running");
            value.Mode = root.GetString("mode");
            value.Error = root.GetString("error");
            value.Paired = root.GetBool("paired") == true;
            value.IcmpEnabled = root.GetBool("icmp_enabled");
            value.Interface = root.GetString("iface");
            value.LastStopMessage = root.GetString("last_stop_message");
            value.ServiceState = root.GetString("state");
            value.CleanupBlocked = root.GetBool("cleanup_blocked");

            JsonValue phone = root.GetObject("phone");
            if (phone != null)
            {
                value.PhoneStateRaw = phone.GetString("state");
                value.Phone = ParsePhone(value.PhoneStateRaw);
                value.PhoneMessage = phone.GetString("message");
                int? connections = phone.GetInt("connections");
                value.PhoneConnections = connections.HasValue && connections.Value >= 0 ? connections : null;
                value.PhoneCheckedAt = phone.GetNumber("checked_at");
                value.TrustedBySource = phone.GetBool("trusted_by_source");
                value.PortChanged = phone.GetBool("port_changed") == true;
            }
            else
            {
                value.Phone = PhoneState.Unknown;
            }

            JsonValue forget = root.GetObject("forget");
            value.Forget = forget == null ? ForgetPhase.None : ParseForget(forget.GetString("state"));

            JsonValue lastStop = root.GetObject("last_stop");
            if (lastStop != null)
            {
                value.LastStopReason = lastStop.GetString("reason");
                value.LastStopAt = lastStop.GetNumber("at");
            }

            JsonValue platform = root.GetObject("platform");
            if (platform != null)
            {
                value.Elevated = platform.GetBool("admin");
            }

            JsonValue stats = root.GetObject("stats");
            if (stats != null)
            {
                long? ttlBad = stats.GetLong("ttl_bad");
                value.TtlBad = ttlBad.HasValue && ttlBad.Value >= 0 ? ttlBad : null;
            }
            return value;
        }
    }

    public enum PairingPhase
    {
        Idle,
        Connecting,
        Confirm,
        Paired,
        Failed
    }

    // One answer from GET /api/phone/pair. The code is a short pairing
    // secret for the person to compare. It is shown and never logged.
    public sealed class PairingSnapshot
    {
        public PairingPhase Phase { get; private set; }

        public string Code { get; private set; }

        public string Error { get; private set; }

        public static PairingSnapshot Idle()
        {
            PairingSnapshot value = new PairingSnapshot();
            value.Phase = PairingPhase.Idle;
            return value;
        }

        public static PairingSnapshot Failed(string error)
        {
            PairingSnapshot value = new PairingSnapshot();
            value.Phase = PairingPhase.Failed;
            value.Error = error;
            return value;
        }

        public static bool TryParse(string json, out PairingSnapshot snapshot)
        {
            snapshot = null;
            JsonValue root;
            if (!JsonValue.TryParseObject(json, out root))
            {
                return false;
            }
            PairingSnapshot value = new PairingSnapshot();
            switch (root.GetString("state"))
            {
                case "connecting":
                    value.Phase = PairingPhase.Connecting;
                    break;
                case "confirm":
                    value.Phase = PairingPhase.Confirm;
                    break;
                case "paired":
                    value.Phase = PairingPhase.Paired;
                    break;
                case "failed":
                    value.Phase = PairingPhase.Failed;
                    break;
                default:
                    value.Phase = PairingPhase.Idle;
                    break;
            }
            value.Code = PairingCodeFormat.Digits(root.GetString("code"));
            value.Error = root.GetString("error");
            snapshot = value;
            return true;
        }
    }

    // The six-digit pairing code in two groups, for example "482 193".
    public static class PairingCodeFormat
    {
        public static string Digits(string code)
        {
            if (code == null)
            {
                return null;
            }
            System.Text.StringBuilder digits = new System.Text.StringBuilder();
            for (int index = 0; index < code.Length; index++)
            {
                char c = code[index];
                if (c >= '0' && c <= '9')
                {
                    digits.Append(c);
                }
                else if (c != ' ')
                {
                    return null;
                }
            }
            return digits.Length == 0 || digits.Length > 12 ? null : digits.ToString();
        }

        public static string Grouped(string code)
        {
            string digits = Digits(code);
            if (digits == null)
            {
                return "";
            }
            if (digits.Length != 6)
            {
                return digits;
            }
            return digits.Substring(0, 3) + " " + digits.Substring(3, 3);
        }
    }

    // One activity line from GET /api/logs.
    public sealed class LogLine
    {
        public LogLine(long seq, string level, string message, double? timestamp)
        {
            Seq = seq;
            Level = level ?? "";
            Message = message ?? "";
            Timestamp = timestamp;
        }

        public long Seq { get; private set; }

        public string Level { get; private set; }

        public string Message { get; private set; }

        public double? Timestamp { get; private set; }
    }

    public sealed class LogBatch
    {
        public LogBatch(IList<LogLine> lines, long next)
        {
            Lines = lines;
            Next = next;
        }

        public IList<LogLine> Lines { get; private set; }

        public long Next { get; private set; }

        public static bool TryParse(string json, out LogBatch batch)
        {
            batch = null;
            JsonValue root;
            if (!JsonValue.TryParseObject(json, out root))
            {
                return false;
            }
            List<LogLine> lines = new List<LogLine>();
            JsonValue logs = root.GetArray("logs");
            if (logs != null)
            {
                for (int index = 0; index < logs.Count; index++)
                {
                    JsonValue entry = logs[index];
                    if (!entry.IsObject)
                    {
                        continue;
                    }
                    long? seq = entry.GetLong("seq");
                    if (!seq.HasValue)
                    {
                        continue;
                    }
                    lines.Add(new LogLine(seq.Value, entry.GetString("level"), entry.GetString("msg"), entry.GetNumber("ts")));
                }
            }
            long? next = root.GetLong("next");
            batch = new LogBatch(lines, next.HasValue ? next.Value : 0);
            return true;
        }
    }

    // One failure group from GET /api/failures.
    public sealed class FailureGroup
    {
        public string Protocol { get; set; }

        public string Family { get; set; }

        public int? Port { get; set; }

        public string Reason { get; set; }

        public string Phase { get; set; }

        public int Count { get; set; }

        public string Name { get; set; }

        public string ExampleAddress { get; set; }

        public int? Code { get; set; }
    }

    public sealed class FailureSnapshot
    {
        public FailureSnapshot()
        {
            Groups = new List<FailureGroup>();
        }

        public bool Demo { get; private set; }

        public int Total { get; private set; }

        public int Dropped { get; private set; }

        public List<FailureGroup> Groups { get; private set; }

        public static bool TryParse(string json, out FailureSnapshot snapshot)
        {
            snapshot = null;
            JsonValue root;
            if (!JsonValue.TryParseObject(json, out root))
            {
                return false;
            }
            FailureSnapshot value = new FailureSnapshot();
            value.Demo = root.GetBool("demo") == true;
            int? total = root.GetInt("total");
            int? dropped = root.GetInt("dropped");
            value.Total = total.HasValue && total.Value > 0 ? total.Value : 0;
            value.Dropped = dropped.HasValue && dropped.Value > 0 ? dropped.Value : 0;
            JsonValue groups = root.GetArray("groups");
            if (groups != null)
            {
                for (int index = 0; index < groups.Count && index < 200; index++)
                {
                    JsonValue group = groups[index];
                    if (!group.IsObject)
                    {
                        continue;
                    }
                    int? count = group.GetInt("count");
                    value.Groups.Add(new FailureGroup
                    {
                        Protocol = group.GetString("proto"),
                        Family = group.GetString("family"),
                        Port = group.GetInt("port"),
                        Reason = group.GetString("reason"),
                        Phase = group.GetString("phase"),
                        Count = count.HasValue && count.Value > 0 ? count.Value : 0,
                        Name = group.GetString("name"),
                        ExampleAddress = group.GetString("example_ip"),
                        Code = group.GetInt("code")
                    });
                }
            }
            snapshot = value;
            return true;
        }
    }
}
