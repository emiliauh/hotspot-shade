using System;
using System.Collections.Generic;
using System.Globalization;

namespace HotspotShade.WinUI2.Core.Engine.Service
{
    public enum EngineServiceMode
    {
        None,
        Phone
    }

    public enum EngineServicePairedScope
    {
        None,
        Session,
        Identity
    }

    public enum EngineServiceCleanup
    {
        Ok,
        Failed,
        Pending,
        Unknown
    }

    // The stop vocabulary of the service status. It is separate from the old
    // broker stop enum because the service names automatic stops precisely and
    // must not turn an unknown observation into a hotspot-loss claim.
    public enum EngineServiceStopReason
    {
        None,
        User,
        SourceDeviceGone,
        ObservationUnavailable,
        GatewayChanged,
        LinkChanged,
        EngineLost,
        StartFailed,
        ParentLost,
        ServiceStop,
        Shutdown,
        SessionLogoff,
        Unknown
    }

    public static class EngineServiceStatusKeys
    {
        public const string Version = "v";
        public const string Ok = "ok";
        public const string Instance = "instance";
        public const string Engine = "engine";
        public const string Running = "running";
        public const string Mode = "mode";
        public const string Paired = "paired";
        public const string PairedScope = "paired_scope";
        public const string Source = "source";
        public const string Trusted = "trusted";
        public const string CheckedAt = "checked_at";
        public const string Ping = "ping";
        public const string IcmpEnabled = "icmp_enabled";
        public const string PhoneConnections = "phone.connections";
        public const string PhoneConnectionsKnown = "phone.connections_known";
        public const string RelayTcpFlowsActive = "relay.tcp_flows_active";
        public const string RelayTcpFlowsActiveKnown = "relay.tcp_flows_active_known";
        public const string TtlBad = "ttl_bad";
        public const string Ipv6Dropped = "ipv6_dropped";
        public const string FragmentsDropped = "fragments_dropped";
        public const string Stop = "stop";
        public const string StopAt = "stop_at";
        public const string Cleanup = "cleanup";
        public const string Admin = "admin";

        public static IReadOnlyList<string> StatusFields()
        {
            List<string> keys = new List<string>();
            keys.Add(Instance);
            keys.Add(Engine);
            keys.Add(Running);
            keys.Add(Mode);
            keys.Add(Paired);
            keys.Add(PairedScope);
            keys.Add(Source);
            keys.Add(Trusted);
            keys.Add(CheckedAt);
            keys.Add(Ping);
            keys.Add(IcmpEnabled);
            keys.Add(PhoneConnections);
            keys.Add(PhoneConnectionsKnown);
            keys.Add(RelayTcpFlowsActive);
            keys.Add(RelayTcpFlowsActiveKnown);
            keys.Add(TtlBad);
            keys.Add(Ipv6Dropped);
            keys.Add(FragmentsDropped);
            keys.Add(Stop);
            keys.Add(StopAt);
            keys.Add(Cleanup);
            keys.Add(Admin);
            return keys.AsReadOnly();
        }

        public static bool IsStatusKey(string key)
        {
            IReadOnlyList<string> keys = StatusFields();
            for (int index = 0; index < keys.Count; index++)
            {
                if (keys[index] == key)
                {
                    return true;
                }
            }
            return false;
        }
    }

    // One redacted status from the service. It is a closed schema: every field
    // is required, an unknown field is a bad response, and no free text, path,
    // host, address, port, or credential crosses the boundary.
    public sealed class EngineServiceStatus
    {
        // The only accepted clock skew for checked_at and stop_at. A status
        // timestamp more than this many seconds in the future is refused. One
        // named value keeps the parser and its tests from drifting apart.
        public const int MaxFutureSkewSeconds = 300;

        private EngineServiceStatus(
            string instanceId,
            EngineRunState engine,
            bool running,
            EngineServiceMode mode,
            bool paired,
            EngineServicePairedScope pairedScope,
            bool sourcePresent,
            bool trustedBySource,
            DateTimeOffset? checkedAt,
            bool pingEnabled,
            bool icmpEnabled,
            int? phoneConnections,
            int? relayTcpFlowsActive,
            int ttlBad,
            int ipv6Dropped,
            int fragmentsDropped,
            EngineServiceStopReason stop,
            DateTimeOffset? stopAt,
            EngineServiceCleanup cleanup,
            bool administrator,
            DateTimeOffset observedAt)
        {
            InstanceId = instanceId;
            Engine = engine;
            Running = running;
            Mode = mode;
            Paired = paired;
            PairedScope = pairedScope;
            SourcePresent = sourcePresent;
            TrustedBySource = trustedBySource;
            CheckedAt = checkedAt;
            PingEnabled = pingEnabled;
            IcmpEnabled = icmpEnabled;
            PhoneConnections = phoneConnections;
            RelayTcpFlowsActive = relayTcpFlowsActive;
            TtlBad = ttlBad;
            Ipv6Dropped = ipv6Dropped;
            FragmentsDropped = fragmentsDropped;
            Stop = stop;
            StopAt = stopAt;
            Cleanup = cleanup;
            Administrator = administrator;
            ObservedAt = observedAt;
        }

        public string InstanceId { get; private set; }

        public EngineRunState Engine { get; private set; }

        public bool Running { get; private set; }

        public EngineServiceMode Mode { get; private set; }

        public bool Paired { get; private set; }

        public EngineServicePairedScope PairedScope { get; private set; }

        public bool SourcePresent { get; private set; }

        public bool TrustedBySource { get; private set; }

        public DateTimeOffset? CheckedAt { get; private set; }

        public bool PingEnabled { get; private set; }

        public bool IcmpEnabled { get; private set; }

        // The source device count from an authenticated pairing answer. Null
        // when the answer is unavailable, which is the normal phase 1 state.
        public int? PhoneConnections { get; private set; }

        // The target-side live relay gauge. It is not a source device count.
        public int? RelayTcpFlowsActive { get; private set; }

        public int TtlBad { get; private set; }

        public int Ipv6Dropped { get; private set; }

        public int FragmentsDropped { get; private set; }

        public EngineServiceStopReason Stop { get; private set; }

        public DateTimeOffset? StopAt { get; private set; }

        public EngineServiceCleanup Cleanup { get; private set; }

        public bool Administrator { get; private set; }

        public DateTimeOffset ObservedAt { get; private set; }

        public EngineFreshness FreshnessAt(DateTimeOffset now)
        {
            // A sample is only as fresh as its oldest input. The engine
            // sample time comes from the status read. When a source device
            // answer is present, checked_at is the age of that answer and the
            // start gate must use it. A missing checked_at with a present
            // source is already refused by the consistency rules, but it is
            // also unavailable here so no caller can treat it as fresh.
            EngineFreshness sample = EngineTiming.Freshness(ObservedAt, now);
            if (!SourcePresent)
            {
                return sample;
            }
            if (!CheckedAt.HasValue)
            {
                return EngineFreshness.Unavailable;
            }
            EngineFreshness source = EngineTiming.Freshness(CheckedAt.Value, now);
            // EngineFreshness is ordered Fresh, Stale, Unavailable, so the
            // larger value is the more conservative result.
            return (EngineFreshness)Math.Max((int)sample, (int)source);
        }

        public bool InstanceMatches(string instanceId)
        {
            return !string.IsNullOrEmpty(instanceId)
                && string.Equals(InstanceId, instanceId, StringComparison.Ordinal);
        }

        // A phase-one stop clears the in-memory credential and therefore
        // clears the session pairing. The engine status can still arrive from
        // a stale read, so the session must not forward paired=1 after that
        // stop. A phase-two identity pairing is kept. A running sample cannot
        // be unpaired, so this returns false and the caller must fail closed.
        public bool TryWithoutSessionPairing(out EngineServiceStatus status)
        {
            status = this;
            if (PairedScope != EngineServicePairedScope.Session)
            {
                return true;
            }
            if (Running)
            {
                return false;
            }
            status = new EngineServiceStatus(
                InstanceId,
                Engine,
                false,
                Mode,
                false,
                EngineServicePairedScope.None,
                false,
                false,
                null,
                PingEnabled,
                false,
                null,
                null,
                TtlBad,
                Ipv6Dropped,
                FragmentsDropped,
                Stop,
                StopAt,
                Cleanup,
                Administrator,
                ObservedAt);
            return true;
        }

        public Dictionary<string, string> ToFields()
        {
            Dictionary<string, string> fields = new Dictionary<string, string>(StringComparer.Ordinal);
            fields[EngineServiceStatusKeys.Instance] = InstanceId;
            fields[EngineServiceStatusKeys.Engine] = EngineRules.EngineWord(Engine);
            fields[EngineServiceStatusKeys.Running] = BoolWord(Running);
            fields[EngineServiceStatusKeys.Mode] = ModeWord(Mode);
            fields[EngineServiceStatusKeys.Paired] = BoolWord(Paired);
            fields[EngineServiceStatusKeys.PairedScope] = ScopeWord(PairedScope);
            fields[EngineServiceStatusKeys.Source] = BoolWord(SourcePresent);
            fields[EngineServiceStatusKeys.Trusted] = BoolWord(TrustedBySource);
            fields[EngineServiceStatusKeys.CheckedAt] = TimeWord(CheckedAt);
            fields[EngineServiceStatusKeys.Ping] = BoolWord(PingEnabled);
            fields[EngineServiceStatusKeys.IcmpEnabled] = BoolWord(IcmpEnabled);
            fields[EngineServiceStatusKeys.PhoneConnections] =
                PhoneConnections.HasValue ? CountWord(PhoneConnections.Value) : "";
            fields[EngineServiceStatusKeys.PhoneConnectionsKnown] =
                BoolWord(PhoneConnections.HasValue);
            fields[EngineServiceStatusKeys.RelayTcpFlowsActive] =
                RelayTcpFlowsActive.HasValue ? CountWord(RelayTcpFlowsActive.Value) : "";
            fields[EngineServiceStatusKeys.RelayTcpFlowsActiveKnown] =
                BoolWord(RelayTcpFlowsActive.HasValue);
            fields[EngineServiceStatusKeys.TtlBad] = CountWord(TtlBad);
            fields[EngineServiceStatusKeys.Ipv6Dropped] = CountWord(Ipv6Dropped);
            fields[EngineServiceStatusKeys.FragmentsDropped] = CountWord(FragmentsDropped);
            fields[EngineServiceStatusKeys.Stop] = StopWord(Stop);
            fields[EngineServiceStatusKeys.StopAt] = TimeWord(StopAt);
            fields[EngineServiceStatusKeys.Cleanup] = CleanupWord(Cleanup);
            fields[EngineServiceStatusKeys.Admin] = BoolWord(Administrator);
            return fields;
        }

        public static bool TryParse(
            IReadOnlyDictionary<string, string> fields,
            DateTimeOffset now,
            out EngineServiceStatus status,
            out string code)
        {
            status = null;
            code = EngineProtocol.ErrorCodes.BadResponse;
            if (fields == null)
            {
                return false;
            }

            string version;
            if (!fields.TryGetValue(EngineServiceStatusKeys.Version, out version)
                || version != "1")
            {
                code = EngineProtocol.ErrorCodes.BadVersion;
                return false;
            }

            // A status object is the body of a successful reply. A failure
            // body has ok=0 and a code, so it must never be accepted as a
            // status just because it also carries every status field.
            string ok;
            if (fields.TryGetValue(EngineServiceStatusKeys.Ok, out ok)
                && ok != "1")
            {
                return false;
            }

            foreach (string key in fields.Keys)
            {
                if (key == EngineServiceStatusKeys.Version
                    || key == EngineServiceStatusKeys.Ok
                    || EngineServiceStatusKeys.IsStatusKey(key))
                {
                    continue;
                }
                return false;
            }

            string instance;
            string engineText;
            string runningText;
            string modeText;
            string pairedText;
            string scopeText;
            string sourceText;
            string trustedText;
            string checkedText;
            string pingText;
            string icmpText;
            string phoneText;
            string phoneKnownText;
            string relayText;
            string relayKnownText;
            string ttlText;
            string ipv6Text;
            string fragmentsText;
            string stopText;
            string stopAtText;
            string cleanupText;
            string adminText;
            if (!fields.TryGetValue(EngineServiceStatusKeys.Instance, out instance)
                || !fields.TryGetValue(EngineServiceStatusKeys.Engine, out engineText)
                || !fields.TryGetValue(EngineServiceStatusKeys.Running, out runningText)
                || !fields.TryGetValue(EngineServiceStatusKeys.Mode, out modeText)
                || !fields.TryGetValue(EngineServiceStatusKeys.Paired, out pairedText)
                || !fields.TryGetValue(EngineServiceStatusKeys.PairedScope, out scopeText)
                || !fields.TryGetValue(EngineServiceStatusKeys.Source, out sourceText)
                || !fields.TryGetValue(EngineServiceStatusKeys.Trusted, out trustedText)
                || !fields.TryGetValue(EngineServiceStatusKeys.CheckedAt, out checkedText)
                || !fields.TryGetValue(EngineServiceStatusKeys.Ping, out pingText)
                || !fields.TryGetValue(EngineServiceStatusKeys.IcmpEnabled, out icmpText)
                || !fields.TryGetValue(EngineServiceStatusKeys.PhoneConnections, out phoneText)
                || !fields.TryGetValue(EngineServiceStatusKeys.PhoneConnectionsKnown, out phoneKnownText)
                || !fields.TryGetValue(EngineServiceStatusKeys.RelayTcpFlowsActive, out relayText)
                || !fields.TryGetValue(EngineServiceStatusKeys.RelayTcpFlowsActiveKnown, out relayKnownText)
                || !fields.TryGetValue(EngineServiceStatusKeys.TtlBad, out ttlText)
                || !fields.TryGetValue(EngineServiceStatusKeys.Ipv6Dropped, out ipv6Text)
                || !fields.TryGetValue(EngineServiceStatusKeys.FragmentsDropped, out fragmentsText)
                || !fields.TryGetValue(EngineServiceStatusKeys.Stop, out stopText)
                || !fields.TryGetValue(EngineServiceStatusKeys.StopAt, out stopAtText)
                || !fields.TryGetValue(EngineServiceStatusKeys.Cleanup, out cleanupText)
                || !fields.TryGetValue(EngineServiceStatusKeys.Admin, out adminText))
            {
                return false;
            }

            if (!EngineProtocol.IsValidInstanceId(instance))
            {
                return false;
            }

            EngineRunState engine;
            if (!EngineProtocol.TryParseEngineState(engineText, out engine))
            {
                return false;
            }

            bool running;
            bool paired;
            bool source;
            bool trusted;
            bool ping;
            bool icmp;
            bool phoneKnown;
            bool relayKnown;
            bool admin;
            if (!TryReadBool(runningText, out running)
                || !TryReadBool(pairedText, out paired)
                || !TryReadBool(sourceText, out source)
                || !TryReadBool(trustedText, out trusted)
                || !TryReadBool(pingText, out ping)
                || !TryReadBool(icmpText, out icmp)
                || !TryReadBool(phoneKnownText, out phoneKnown)
                || !TryReadBool(relayKnownText, out relayKnown)
                || !TryReadBool(adminText, out admin))
            {
                return false;
            }

            EngineServiceMode mode;
            if (!TryParseMode(modeText, out mode))
            {
                return false;
            }

            EngineServicePairedScope scope;
            if (!TryParseScope(scopeText, out scope))
            {
                return false;
            }

            EngineServiceStopReason stop;
            if (!TryParseStop(stopText, out stop))
            {
                return false;
            }

            EngineServiceCleanup cleanup;
            if (!TryParseCleanup(cleanupText, out cleanup))
            {
                return false;
            }
            if (running && cleanup != EngineServiceCleanup.Unknown)
            {
                return false;
            }

            int? phone;
            if (!TryReadOptionalCount(phoneText, phoneKnown, out phone))
            {
                return false;
            }

            int? relay;
            if (!TryReadOptionalCount(relayText, relayKnown, out relay))
            {
                return false;
            }

            int ttlBad;
            int ipv6Dropped;
            int fragmentsDropped;
            if (!EngineWire.TryParseCount(ttlText, out ttlBad)
                || !EngineWire.TryParseCount(ipv6Text, out ipv6Dropped)
                || !EngineWire.TryParseCount(fragmentsText, out fragmentsDropped))
            {
                return false;
            }

            DateTimeOffset? checkedAt;
            if (!TryReadOptionalTime(checkedText, now, out checkedAt))
            {
                return false;
            }

            DateTimeOffset? stopAt;
            if (!TryReadOptionalTime(stopAtText, now, out stopAt))
            {
                return false;
            }

            string consistency;
            if (!IsConsistent(
                engine,
                running,
                mode,
                paired,
                scope,
                source,
                trusted,
                checkedAt,
                ping,
                icmp,
                phone,
                relay,
                stop,
                stopAt,
                out consistency))
            {
                code = consistency;
                return false;
            }

            status = new EngineServiceStatus(
                instance,
                engine,
                running,
                mode,
                paired,
                scope,
                source,
                trusted,
                checkedAt,
                ping,
                icmp,
                phone,
                relay,
                ttlBad,
                ipv6Dropped,
                fragmentsDropped,
                stop,
                stopAt,
                cleanup,
                admin,
                now);
            code = "";
            return true;
        }

        public static bool IsConsistent(
            EngineRunState engine,
            bool running,
            EngineServiceMode mode,
            bool paired,
            EngineServicePairedScope scope,
            bool sourcePresent,
            bool trustedBySource,
            DateTimeOffset? checkedAt,
            bool ping,
            bool icmp,
            int? phoneConnections,
            int? relayTcpFlowsActive,
            EngineServiceStopReason stop,
            DateTimeOffset? stopAt,
            out string code)
        {
            code = EngineProtocol.ErrorCodes.BadResponse;
            if (!Enum.IsDefined(typeof(EngineRunState), engine)
                || !Enum.IsDefined(typeof(EngineServiceMode), mode)
                || !Enum.IsDefined(typeof(EngineServicePairedScope), scope)
                || !Enum.IsDefined(typeof(EngineServiceStopReason), stop))
            {
                return false;
            }
            if (running && engine != EngineRunState.Running)
            {
                return false;
            }
            if (engine == EngineRunState.Running && !running)
            {
                return false;
            }
            if (running && !paired)
            {
                return false;
            }
            if (running && mode != EngineServiceMode.Phone)
            {
                return false;
            }
            if (running && stop != EngineServiceStopReason.None)
            {
                return false;
            }
            if (!paired && scope != EngineServicePairedScope.None)
            {
                return false;
            }
            if (paired && scope == EngineServicePairedScope.None)
            {
                return false;
            }
            if (!paired && sourcePresent)
            {
                return false;
            }
            if (!paired && trustedBySource)
            {
                return false;
            }
            if (trustedBySource && !sourcePresent)
            {
                return false;
            }
            if (stop != EngineServiceStopReason.None
                && paired
                && scope == EngineServicePairedScope.Session)
            {
                // Every phase-one stop clears the in-memory credential and
                // the session pairing. A stopped phase-one status that still
                // claims a pairing is stale or wrong. A phase-two identity
                // pairing is allowed to survive.
                return false;
            }
            if (sourcePresent && !checkedAt.HasValue)
            {
                return false;
            }
            if (icmp && mode != EngineServiceMode.Phone)
            {
                return false;
            }
            if (mode == EngineServiceMode.None && running)
            {
                return false;
            }
            if (phoneConnections.HasValue
                && (!running || !paired || scope != EngineServicePairedScope.Identity))
            {
                return false;
            }
            if (relayTcpFlowsActive.HasValue && !running)
            {
                return false;
            }
            if (!running && (phoneConnections.HasValue || relayTcpFlowsActive.HasValue))
            {
                return false;
            }
            if (phoneConnections.HasValue && (phoneConnections.Value < 0 || phoneConnections.Value > 100000))
            {
                return false;
            }
            if (relayTcpFlowsActive.HasValue
                && (relayTcpFlowsActive.Value < 0 || relayTcpFlowsActive.Value > 100000))
            {
                return false;
            }
            if (stop == EngineServiceStopReason.None && stopAt.HasValue)
            {
                return false;
            }
            if (stop != EngineServiceStopReason.None && !stopAt.HasValue)
            {
                return false;
            }
            code = "";
            return true;
        }

        public static string StopWord(EngineServiceStopReason reason)
        {
            switch (reason)
            {
                case EngineServiceStopReason.User:
                    return "user";
                case EngineServiceStopReason.SourceDeviceGone:
                    return "source_device_gone";
                case EngineServiceStopReason.ObservationUnavailable:
                    return "observation_unavailable";
                case EngineServiceStopReason.GatewayChanged:
                    return "gateway_changed";
                case EngineServiceStopReason.LinkChanged:
                    return "link_changed";
                case EngineServiceStopReason.EngineLost:
                    return "engine_lost";
                case EngineServiceStopReason.StartFailed:
                    return "start_failed";
                case EngineServiceStopReason.ParentLost:
                    return "parent_lost";
                case EngineServiceStopReason.ServiceStop:
                    return "service_stop";
                case EngineServiceStopReason.Shutdown:
                    return "shutdown";
                case EngineServiceStopReason.SessionLogoff:
                    return "session_logoff";
                case EngineServiceStopReason.Unknown:
                    return "unknown";
                default:
                    return "none";
            }
        }

        public static string StopText(EngineServiceStopReason reason)
        {
            switch (reason)
            {
                case EngineServiceStopReason.User:
                    return "You turned the tunnel off.";
                case EngineServiceStopReason.SourceDeviceGone:
                    return "The source device stopped answering.";
                case EngineServiceStopReason.ObservationUnavailable:
                    return "The tunnel stopped because it could not check the source device for 5 minutes. This does not mean the hotspot or the source device is gone.";
                case EngineServiceStopReason.GatewayChanged:
                    return "The hotspot changed. Enter the source device address and token again.";
                case EngineServiceStopReason.LinkChanged:
                    return "The hotspot changed. Enter the source device address and token again.";
                case EngineServiceStopReason.EngineLost:
                    return "The engine stopped answering.";
                case EngineServiceStopReason.StartFailed:
                    return "The tunnel did not start.";
                case EngineServiceStopReason.ParentLost:
                    return "The app closed. The tunnel stopped.";
                case EngineServiceStopReason.ServiceStop:
                    return "The tunnel service stopped.";
                case EngineServiceStopReason.Shutdown:
                    return "Windows is shutting down.";
                case EngineServiceStopReason.SessionLogoff:
                    return "The tunnel stopped because you signed out.";
                case EngineServiceStopReason.Unknown:
                    return "The tunnel stopped.";
                default:
                    return "";
            }
        }

        private static bool TryReadBool(string value, out bool result)
        {
            if (value == "0")
            {
                result = false;
                return true;
            }
            if (value == "1")
            {
                result = true;
                return true;
            }
            result = false;
            return false;
        }

        private static bool TryReadOptionalCount(string value, bool known, out int? count)
        {
            count = null;
            if (!known)
            {
                return value.Length == 0;
            }
            int parsed;
            if (!EngineWire.TryParseCount(value, out parsed))
            {
                return false;
            }
            count = parsed;
            return true;
        }

        private static bool TryReadOptionalTime(string value, DateTimeOffset now, out DateTimeOffset? result)
        {
            result = null;
            if (value.Length == 0)
            {
                return true;
            }
            long seconds;
            long nowSeconds = now.ToUnixTimeSeconds();
            long latest = nowSeconds > long.MaxValue - MaxFutureSkewSeconds
                ? long.MaxValue
                : nowSeconds + MaxFutureSkewSeconds;
            if (!long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out seconds)
                || seconds < 0
                || seconds > latest)
            {
                return false;
            }
            try
            {
                result = DateTimeOffset.FromUnixTimeSeconds(seconds);
                return true;
            }
            catch (ArgumentOutOfRangeException)
            {
                return false;
            }
        }

        private static bool TryParseMode(string value, out EngineServiceMode mode)
        {
            if (value == "phone")
            {
                mode = EngineServiceMode.Phone;
                return true;
            }
            if (value == "none")
            {
                mode = EngineServiceMode.None;
                return true;
            }
            mode = EngineServiceMode.None;
            return false;
        }

        private static bool TryParseScope(string value, out EngineServicePairedScope scope)
        {
            if (value == "none")
            {
                scope = EngineServicePairedScope.None;
                return true;
            }
            if (value == "session")
            {
                scope = EngineServicePairedScope.Session;
                return true;
            }
            if (value == "identity")
            {
                scope = EngineServicePairedScope.Identity;
                return true;
            }
            scope = EngineServicePairedScope.None;
            return false;
        }

        private static bool TryParseStop(string value, out EngineServiceStopReason reason)
        {
            if (value == "none")
            {
                reason = EngineServiceStopReason.None;
                return true;
            }
            if (value == "user")
            {
                reason = EngineServiceStopReason.User;
                return true;
            }
            if (value == "source_device_gone")
            {
                reason = EngineServiceStopReason.SourceDeviceGone;
                return true;
            }
            if (value == "observation_unavailable")
            {
                reason = EngineServiceStopReason.ObservationUnavailable;
                return true;
            }
            if (value == "gateway_changed")
            {
                reason = EngineServiceStopReason.GatewayChanged;
                return true;
            }
            if (value == "link_changed")
            {
                reason = EngineServiceStopReason.LinkChanged;
                return true;
            }
            if (value == "engine_lost")
            {
                reason = EngineServiceStopReason.EngineLost;
                return true;
            }
            if (value == "start_failed")
            {
                reason = EngineServiceStopReason.StartFailed;
                return true;
            }
            if (value == "parent_lost")
            {
                reason = EngineServiceStopReason.ParentLost;
                return true;
            }
            if (value == "service_stop")
            {
                reason = EngineServiceStopReason.ServiceStop;
                return true;
            }
            if (value == "shutdown")
            {
                reason = EngineServiceStopReason.Shutdown;
                return true;
            }
            if (value == "session_logoff")
            {
                reason = EngineServiceStopReason.SessionLogoff;
                return true;
            }
            if (value == "unknown")
            {
                reason = EngineServiceStopReason.Unknown;
                return true;
            }
            reason = EngineServiceStopReason.None;
            return false;
        }

        private static bool TryParseCleanup(string value, out EngineServiceCleanup cleanup)
        {
            if (value == "ok")
            {
                cleanup = EngineServiceCleanup.Ok;
                return true;
            }
            if (value == "failed")
            {
                cleanup = EngineServiceCleanup.Failed;
                return true;
            }
            if (value == "pending")
            {
                cleanup = EngineServiceCleanup.Pending;
                return true;
            }
            if (value == "unknown")
            {
                cleanup = EngineServiceCleanup.Unknown;
                return true;
            }
            cleanup = EngineServiceCleanup.Unknown;
            return false;
        }

        private static string ModeWord(EngineServiceMode mode)
        {
            return mode == EngineServiceMode.Phone ? "phone" : "none";
        }

        private static string ScopeWord(EngineServicePairedScope scope)
        {
            switch (scope)
            {
                case EngineServicePairedScope.Session:
                    return "session";
                case EngineServicePairedScope.Identity:
                    return "identity";
                default:
                    return "none";
            }
        }

        private static string CleanupWord(EngineServiceCleanup cleanup)
        {
            switch (cleanup)
            {
                case EngineServiceCleanup.Ok:
                    return "ok";
                case EngineServiceCleanup.Failed:
                    return "failed";
                case EngineServiceCleanup.Pending:
                    return "pending";
                default:
                    return "unknown";
            }
        }

        private static string BoolWord(bool value)
        {
            return value ? "1" : "0";
        }

        private static string CountWord(int value)
        {
            return value.ToString(CultureInfo.InvariantCulture);
        }

        private static string TimeWord(DateTimeOffset? value)
        {
            return value.HasValue
                ? value.Value.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)
                : "";
        }
    }

    // Strict reply reader for the service contract. It is separate from the
    // old broker reader because the service status adds fields that version 1
    // of the old broker never sent. A reply is accepted only for the operation
    // that produced it, so a status cannot hide in a hello shape.
    public static class EngineServiceReply
    {
        public static bool TryRead(
            IReadOnlyDictionary<string, string> fields,
            string operation,
            out EngineReply reply,
            out string code)
        {
            reply = null;
            if (!EngineWire.TryValidateFields(fields, out code))
            {
                return false;
            }

            string version;
            if (!fields.TryGetValue(EngineServiceStatusKeys.Version, out version)
                || version != "1")
            {
                code = EngineProtocol.ErrorCodes.BadVersion;
                return false;
            }

            string ok;
            if (!fields.TryGetValue(EngineServiceStatusKeys.Ok, out ok)
                || (ok != "0" && ok != "1"))
            {
                code = EngineProtocol.ErrorCodes.BadResponse;
                return false;
            }

            if (ok == "0")
            {
                string failure;
                if (fields.Count != 3
                    || !fields.TryGetValue(EngineProtocol.Keys.Code, out failure)
                    || !EngineProtocol.IsKnownErrorCode(failure))
                {
                    code = EngineProtocol.ErrorCodes.BadResponse;
                    return false;
                }
                reply = EngineReply.Failure(failure);
                code = "";
                return true;
            }

            if (fields.ContainsKey(EngineProtocol.Keys.Code))
            {
                code = EngineProtocol.ErrorCodes.BadResponse;
                return false;
            }

            if (operation == EngineProtocol.Operations.Hello)
            {
                string instance;
                string engine;
                if (fields.Count != 4
                    || !fields.TryGetValue(EngineServiceStatusKeys.Instance, out instance)
                    || !EngineProtocol.IsValidInstanceId(instance)
                    || !fields.TryGetValue(EngineServiceStatusKeys.Engine, out engine)
                    || !EngineProtocol.IsKnownEngineState(engine))
                {
                    code = EngineProtocol.ErrorCodes.BadResponse;
                    return false;
                }
            }
            else if (operation == EngineProtocol.Operations.Status)
            {
                IReadOnlyList<string> statusKeys = EngineServiceStatusKeys.StatusFields();
                if (fields.Count != statusKeys.Count + 2)
                {
                    code = EngineProtocol.ErrorCodes.BadResponse;
                    return false;
                }
                for (int index = 0; index < statusKeys.Count; index++)
                {
                    if (!fields.ContainsKey(statusKeys[index]))
                    {
                        code = EngineProtocol.ErrorCodes.BadResponse;
                        return false;
                    }
                }
            }
            else if (operation == EngineProtocol.Operations.Start
                || operation == EngineProtocol.Operations.Stop
                || operation == EngineProtocol.Operations.Forget
                || operation == EngineProtocol.Operations.Shutdown)
            {
                if (fields.Count != 2)
                {
                    code = EngineProtocol.ErrorCodes.BadResponse;
                    return false;
                }
            }
            else
            {
                code = EngineProtocol.ErrorCodes.Unsupported;
                return false;
            }

            foreach (string key in fields.Keys)
            {
                if (key == EngineServiceStatusKeys.Version || key == EngineServiceStatusKeys.Ok)
                {
                    continue;
                }
                if (operation == EngineProtocol.Operations.Hello)
                {
                    if (key != EngineServiceStatusKeys.Instance && key != EngineServiceStatusKeys.Engine)
                    {
                        code = EngineProtocol.ErrorCodes.BadResponse;
                        return false;
                    }
                }
                else if (operation == EngineProtocol.Operations.Status)
                {
                    if (!EngineServiceStatusKeys.IsStatusKey(key))
                    {
                        code = EngineProtocol.ErrorCodes.BadResponse;
                        return false;
                    }
                }
                else
                {
                    code = EngineProtocol.ErrorCodes.BadResponse;
                    return false;
                }
            }

            reply = EngineReply.Success(Copy(fields));
            code = "";
            return true;
        }

        private static Dictionary<string, string> Copy(IReadOnlyDictionary<string, string> fields)
        {
            Dictionary<string, string> copy = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (KeyValuePair<string, string> pair in fields)
            {
                copy[pair.Key] = pair.Value;
            }
            return copy;
        }
    }
}
