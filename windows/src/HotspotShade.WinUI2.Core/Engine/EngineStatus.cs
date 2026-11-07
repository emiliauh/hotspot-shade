using System;
using System.Collections.Generic;
using System.Globalization;

namespace HotspotShade.WinUI2.Core.Engine
{
    public enum EngineRunState
    {
        Unavailable,
        Starting,
        Ready,
        Running
    }

    public enum EngineStopReason
    {
        None,
        User,
        HotspotLost,
        SourceLost,
        EngineLost,
        StartFailed,
        ParentLost,
        Unknown,

        // The Windows engine service names these stops precisely. They are
        // appended so the existing version 1 values keep their numbers.
        SourceDeviceGone,
        ObservationUnavailable,
        GatewayChanged,
        LinkChanged,
        ServiceStop,
        Shutdown,
        SessionLogoff
    }

    // The cleanup gate of the previous run, as the service reports it. The old
    // broker has no cleanup concept, so a missing field means Ok.
    public enum EngineCleanup
    {
        Ok,
        Failed,
        Pending,
        Unknown
    }

    public enum EngineFreshness
    {
        Fresh,
        Stale,
        Unavailable
    }

    public interface IEngineClock
    {
        DateTimeOffset Now { get; }
    }

    public sealed class SystemEngineClock : IEngineClock
    {
        public DateTimeOffset Now
        {
            get { return DateTimeOffset.Now; }
        }
    }

    // The timing values match the macOS target app: one second while the page
    // is visible, five seconds while it is hidden, three seconds to stale, and
    // ten seconds to unavailable. A slow or missing engine never receives a
    // success claim from this app.
    public static class EngineTiming
    {
        public static readonly TimeSpan VisiblePoll = TimeSpan.FromSeconds(1);
        public static readonly TimeSpan HiddenPoll = TimeSpan.FromSeconds(5);
        public static readonly TimeSpan StaleAfter = TimeSpan.FromSeconds(3);
        public static readonly TimeSpan UnavailableAfter = TimeSpan.FromSeconds(10);
        public static readonly TimeSpan SourceWarningAfter = TimeSpan.FromSeconds(10);
        public static readonly TimeSpan VisibleRetry = TimeSpan.FromSeconds(10);
        public static readonly TimeSpan HiddenRetry = TimeSpan.FromSeconds(30);

        public static EngineFreshness Freshness(DateTimeOffset? observedAt, DateTimeOffset now)
        {
            if (!observedAt.HasValue)
            {
                return EngineFreshness.Unavailable;
            }
            TimeSpan age = now - observedAt.Value;
            if (age < TimeSpan.Zero)
            {
                age = TimeSpan.Zero;
            }
            if (age < StaleAfter)
            {
                return EngineFreshness.Fresh;
            }
            if (age < UnavailableAfter)
            {
                return EngineFreshness.Stale;
            }
            return EngineFreshness.Unavailable;
        }

        public static TimeSpan PollDelay(bool visible)
        {
            return visible ? VisiblePoll : HiddenPoll;
        }
    }

    // One validated engine status. Every field is required. A missing or
    // ambiguous field is a bad response, not a false "off" or "on".
    public sealed class EngineStatus
    {
        internal EngineStatus(
            string instanceId,
            EngineRunState engine,
            bool paired,
            bool running,
            bool sourcePresent,
            bool trustedBySource,
            bool pingEnabled,
            int connections,
            bool connectionsKnown,
            EngineStopReason stop,
            EngineCleanup cleanup,
            DateTimeOffset? checkedAt,
            int ttlBad,
            DateTimeOffset observedAt)
        {
            InstanceId = instanceId;
            Engine = engine;
            Paired = paired;
            Running = running;
            SourcePresent = sourcePresent;
            TrustedBySource = trustedBySource;
            PingEnabled = pingEnabled;
            Connections = connections;
            ConnectionsKnown = connectionsKnown;
            Stop = stop;
            Cleanup = cleanup;
            CheckedAt = checkedAt;
            TtlBad = ttlBad;
            ObservedAt = observedAt;
        }

        public string InstanceId { get; private set; }

        public EngineRunState Engine { get; private set; }

        public bool Paired { get; private set; }

        public bool Running { get; private set; }

        public bool SourcePresent { get; private set; }

        public bool TrustedBySource { get; private set; }

        public bool PingEnabled { get; private set; }

        public int Connections { get; private set; }

        // False when the source of the status has no connection count. The
        // value is never turned into a measured zero.
        public bool ConnectionsKnown { get; private set; }

        public EngineStopReason Stop { get; private set; }

        public EngineCleanup Cleanup { get; private set; }

        // The count of outer connections whose TTL read-back did not match, as
        // the service reports it. Zero for the old broker, which has no audit
        // field. A running tunnel with a non-zero count is shown as attention.
        public int TtlBad { get; private set; }

        // The time the source device answer was checked, when the service
        // reports one. Null for the old broker, whose status is sampled when
        // the app reads it.
        public DateTimeOffset? CheckedAt { get; private set; }

        public DateTimeOffset ObservedAt { get; private set; }

        public EngineFreshness FreshnessAt(DateTimeOffset now)
        {
            EngineFreshness sample = EngineTiming.Freshness(ObservedAt, now);
            if (!SourcePresent || !CheckedAt.HasValue)
            {
                return sample;
            }
            // A sample is only as fresh as its oldest input. A status read now
            // must not make an old source device answer look fresh.
            EngineFreshness source = EngineTiming.Freshness(CheckedAt.Value, now);
            return (EngineFreshness)Math.Max((int)sample, (int)source);
        }

        public static bool TryParse(
            EngineReply reply,
            DateTimeOffset observedAt,
            out EngineStatus status,
            out string code)
        {
            status = null;
            if (reply == null)
            {
                code = EngineProtocol.ErrorCodes.BadResponse;
                return false;
            }
            if (!reply.Ok)
            {
                code = string.IsNullOrEmpty(reply.Code)
                    ? EngineProtocol.ErrorCodes.BadResponse
                    : reply.Code;
                return false;
            }

            IReadOnlyDictionary<string, string> fields = reply.Fields;
            if (fields == null || fields.Count < 1)
            {
                code = EngineProtocol.ErrorCodes.BadResponse;
                return false;
            }

            string instance;
            string engineText;
            string pairedText;
            string runningText;
            string sourceText;
            string trustedText;
            string pingText;
            string connectionsText;
            string stopText;
            if (!fields.TryGetValue(EngineProtocol.Keys.Instance, out instance)
                || !fields.TryGetValue(EngineProtocol.Keys.Engine, out engineText)
                || !fields.TryGetValue(EngineProtocol.Keys.Paired, out pairedText)
                || !fields.TryGetValue(EngineProtocol.Keys.Running, out runningText)
                || !fields.TryGetValue(EngineProtocol.Keys.Source, out sourceText)
                || !fields.TryGetValue(EngineProtocol.Keys.Trusted, out trustedText)
                || !fields.TryGetValue(EngineProtocol.Keys.Ping, out pingText)
                || !fields.TryGetValue(EngineProtocol.Keys.Connections, out connectionsText)
                || !fields.TryGetValue(EngineProtocol.Keys.Stop, out stopText))
            {
                code = EngineProtocol.ErrorCodes.BadResponse;
                return false;
            }

            // The optional evidence fields are optional. A missing value keeps
            // the old broker meaning: a known count, no source check time, a
            // clean cleanup gate, and no TTL audit failures.
            string connectionsKnownText;
            bool connectionsKnown = true;
            if (fields.TryGetValue(EngineProtocol.Keys.ConnectionsKnown, out connectionsKnownText)
                && !TryReadBool(connectionsKnownText, out connectionsKnown))
            {
                code = EngineProtocol.ErrorCodes.BadResponse;
                return false;
            }

            string checkedAtText;
            DateTimeOffset? checkedAt = null;
            if (fields.TryGetValue(EngineProtocol.Keys.CheckedAt, out checkedAtText)
                && !EngineWire.TryParseCheckedAt(checkedAtText, observedAt, out checkedAt))
            {
                code = EngineProtocol.ErrorCodes.BadResponse;
                return false;
            }

            string cleanupText;
            EngineCleanup cleanup = EngineCleanup.Ok;
            if (fields.TryGetValue(EngineProtocol.Keys.Cleanup, out cleanupText)
                && !EngineRules.TryParseCleanup(cleanupText, out cleanup))
            {
                code = EngineProtocol.ErrorCodes.BadResponse;
                return false;
            }

            string ttlText;
            int ttlBad = 0;
            if (fields.TryGetValue(EngineProtocol.Keys.TtlBad, out ttlText)
                && !EngineWire.TryParseCount(ttlText, out ttlBad))
            {
                code = EngineProtocol.ErrorCodes.BadResponse;
                return false;
            }

            if (!EngineProtocol.IsValidInstanceId(instance))
            {
                code = EngineProtocol.ErrorCodes.BadResponse;
                return false;
            }

            EngineRunState engine;
            if (!EngineProtocol.TryParseEngineState(engineText, out engine))
            {
                code = EngineProtocol.ErrorCodes.BadResponse;
                return false;
            }

            bool paired;
            bool running;
            bool source;
            bool trusted;
            bool ping;
            if (!TryReadBool(pairedText, out paired)
                || !TryReadBool(runningText, out running)
                || !TryReadBool(sourceText, out source)
                || !TryReadBool(trustedText, out trusted)
                || !TryReadBool(pingText, out ping))
            {
                code = EngineProtocol.ErrorCodes.BadResponse;
                return false;
            }

            int connections;
            if (!EngineWire.TryParseCount(connectionsText, out connections))
            {
                code = EngineProtocol.ErrorCodes.BadResponse;
                return false;
            }

            EngineStopReason stop;
            if (!EngineProtocol.TryParseStopReason(stopText, out stop))
            {
                code = EngineProtocol.ErrorCodes.BadResponse;
                return false;
            }

            string consistency;
            if (!EngineRules.IsConsistent(
                engine,
                paired,
                running,
                source,
                trusted,
                connections,
                connectionsKnown,
                stop,
                cleanup,
                ttlBad,
                out consistency))
            {
                code = consistency;
                return false;
            }

            foreach (string key in fields.Keys)
            {
                bool allowed = key == EngineProtocol.Keys.Version
                    || key == EngineProtocol.Keys.Ok
                    || key == EngineProtocol.Keys.Instance
                    || key == EngineProtocol.Keys.Engine
                    || key == EngineProtocol.Keys.Paired
                    || key == EngineProtocol.Keys.Running
                    || key == EngineProtocol.Keys.Source
                    || key == EngineProtocol.Keys.Trusted
                    || key == EngineProtocol.Keys.Ping
                    || key == EngineProtocol.Keys.Connections
                    || key == EngineProtocol.Keys.Stop
                    || key == EngineProtocol.Keys.ConnectionsKnown
                    || key == EngineProtocol.Keys.CheckedAt
                    || key == EngineProtocol.Keys.Cleanup
                    || key == EngineProtocol.Keys.TtlBad;
                if (!allowed)
                {
                    code = EngineProtocol.ErrorCodes.BadResponse;
                    return false;
                }
            }

            status = new EngineStatus(
                instance,
                engine,
                paired,
                running,
                source,
                trusted,
                ping,
                connections,
                connectionsKnown,
                stop,
                cleanup,
                checkedAt,
                ttlBad,
                observedAt);
            code = "";
            return true;
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
    }

    public static class EngineRules
    {
        // The version 1 form. A caller that has no evidence for the optional
        // fields gets the old meaning: a known count and a clean cleanup gate.
        public static bool IsConsistent(
            EngineRunState engine,
            bool paired,
            bool running,
            bool sourcePresent,
            bool trustedBySource,
            int connections,
            EngineStopReason stop,
            out string code)
        {
            return IsConsistent(
                engine,
                paired,
                running,
                sourcePresent,
                trustedBySource,
                connections,
                true,
                stop,
                EngineCleanup.Ok,
                0,
                out code);
        }

        public static bool IsConsistent(
            EngineRunState engine,
            bool paired,
            bool running,
            bool sourcePresent,
            bool trustedBySource,
            int connections,
            bool connectionsKnown,
            EngineStopReason stop,
            EngineCleanup cleanup,
            int ttlBad,
            out string code)
        {
            code = EngineProtocol.ErrorCodes.BadResponse;
            if (!Enum.IsDefined(typeof(EngineRunState), engine)
                || !Enum.IsDefined(typeof(EngineStopReason), stop)
                || !Enum.IsDefined(typeof(EngineCleanup), cleanup))
            {
                return false;
            }
            if (connections < 0 || connections > 100000)
            {
                return false;
            }
            if (ttlBad < 0 || ttlBad > 100000)
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
            if (running && stop != EngineStopReason.None)
            {
                return false;
            }
            if (running && engine == EngineRunState.Unavailable)
            {
                return false;
            }
            if (running && engine == EngineRunState.Starting)
            {
                return false;
            }
            if (running && engine == EngineRunState.Ready)
            {
                return false;
            }
            // A source device cannot be present or trusted before this target
            // device has credentials. A broker that reports either one without
            // a pairing is inconsistent, so the app refuses the status.
            if (!paired && sourcePresent)
            {
                return false;
            }
            if (!paired && trustedBySource)
            {
                return false;
            }
            // Connections belong to an open tunnel. A stale count beside an
            // off tunnel is not a state that this app will display as truth.
            if (!running && connections != 0)
            {
                return false;
            }
            // A count that is not known carries no measured value. The app
            // must not turn it into a zero beside an open tunnel.
            if (!connectionsKnown && connections != 0)
            {
                return false;
            }
            code = "";
            return true;
        }

        public static string EngineWord(EngineRunState engine)
        {
            switch (engine)
            {
                case EngineRunState.Starting:
                    return EngineProtocol.EngineStates.Starting;
                case EngineRunState.Ready:
                    return EngineProtocol.EngineStates.Ready;
                case EngineRunState.Running:
                    return EngineProtocol.EngineStates.Running;
                default:
                    return EngineProtocol.EngineStates.Unavailable;
            }
        }

        public static string StopWord(EngineStopReason stop)
        {
            switch (stop)
            {
                case EngineStopReason.User:
                    return EngineProtocol.StopReasons.User;
                case EngineStopReason.HotspotLost:
                    return EngineProtocol.StopReasons.HotspotLost;
                case EngineStopReason.SourceLost:
                    return EngineProtocol.StopReasons.SourceLost;
                case EngineStopReason.EngineLost:
                    return EngineProtocol.StopReasons.EngineLost;
                case EngineStopReason.StartFailed:
                    return EngineProtocol.StopReasons.StartFailed;
                case EngineStopReason.ParentLost:
                    return EngineProtocol.StopReasons.ParentLost;
                case EngineStopReason.Unknown:
                    return EngineProtocol.StopReasons.Unknown;
                case EngineStopReason.SourceDeviceGone:
                    return EngineProtocol.StopReasons.SourceDeviceGone;
                case EngineStopReason.ObservationUnavailable:
                    return EngineProtocol.StopReasons.ObservationUnavailable;
                case EngineStopReason.GatewayChanged:
                    return EngineProtocol.StopReasons.GatewayChanged;
                case EngineStopReason.LinkChanged:
                    return EngineProtocol.StopReasons.LinkChanged;
                case EngineStopReason.ServiceStop:
                    return EngineProtocol.StopReasons.ServiceStop;
                case EngineStopReason.Shutdown:
                    return EngineProtocol.StopReasons.Shutdown;
                case EngineStopReason.SessionLogoff:
                    return EngineProtocol.StopReasons.SessionLogoff;
                default:
                    return EngineProtocol.StopReasons.None;
            }
        }

        public static string CleanupWord(EngineCleanup cleanup)
        {
            switch (cleanup)
            {
                case EngineCleanup.Failed:
                    return "failed";
                case EngineCleanup.Pending:
                    return "pending";
                case EngineCleanup.Unknown:
                    return "unknown";
                default:
                    return "ok";
            }
        }

        public static bool TryParseCleanup(string value, out EngineCleanup cleanup)
        {
            switch (value)
            {
                case "ok":
                    cleanup = EngineCleanup.Ok;
                    return true;
                case "failed":
                    cleanup = EngineCleanup.Failed;
                    return true;
                case "pending":
                    cleanup = EngineCleanup.Pending;
                    return true;
                case "unknown":
                    cleanup = EngineCleanup.Unknown;
                    return true;
                default:
                    cleanup = EngineCleanup.Ok;
                    return false;
            }
        }
    }
}
