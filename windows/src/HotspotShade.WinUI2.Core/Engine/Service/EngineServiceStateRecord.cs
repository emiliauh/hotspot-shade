using System;
using System.Collections.Generic;
using System.Globalization;

namespace HotspotShade.WinUI2.Core.Engine.Service
{
    public enum EngineServicePhase
    {
        NeverLaunched,
        Launching,
        Launched,
        AdapterReady,
        Running,
        Stopping,
        Stopped,
        CleanupFailed,
        CleanupUnknown
    }

    public enum EngineServiceIdentitySource
    {
        Missing,
        Planned,
        Observed
    }

    public static class EngineServiceStateKeys
    {
        public const string Version = "v";
        public const string Sequence = "seq";
        public const string Phase = "phase";
        public const string IntentId = "intent_id";

        // launch_nonce is correlation data, not a bearer secret and not an
        // authentication factor. It is deliberately in the non-secret state
        // schema and never in a control reply. Do not reuse it as a token,
        // password, identity key, or service bearer. A future store must
        // treat the whole record as readable by the service account and by
        // administrators.
        public const string LaunchNonce = "launch_nonce";
        public const string LaunchStarted100ns = "launch_started_100ns";
        public const string Pid = "pid";
        public const string Created100ns = "created_100ns";
        public const string EngineImage = "engine.image";
        public const string AdapterName = "adapter.name";
        public const string PlannedGuid = "adapter.guid_planned";
        public const string AdapterLuid = "adapter.luid";
        public const string AdapterGuid = "adapter.guid";
        public const string IdentitySource = "adapter.evidence";
        public const string Routes = "routes";
        public const string RoutesMayExist = "routes_may_exist";
        public const string Cleanup = "cleanup";
        public const string Stop = "stop";
        public const string UpdatedAt = "updated_at";

        public const string ManagedRoutes = "0.0.0.0/1,128.0.0.0/1,2000::/3";

        public static IReadOnlyList<string> AllFields()
        {
            List<string> keys = new List<string>();
            keys.Add(Version);
            keys.Add(Sequence);
            keys.Add(Phase);
            keys.Add(IntentId);
            keys.Add(LaunchNonce);
            keys.Add(LaunchStarted100ns);
            keys.Add(Pid);
            keys.Add(Created100ns);
            keys.Add(EngineImage);
            keys.Add(AdapterName);
            keys.Add(PlannedGuid);
            keys.Add(AdapterLuid);
            keys.Add(AdapterGuid);
            keys.Add(IdentitySource);
            keys.Add(Routes);
            keys.Add(RoutesMayExist);
            keys.Add(Cleanup);
            keys.Add(Stop);
            keys.Add(UpdatedAt);
            return keys.AsReadOnly();
        }
    }

    // One durable service state record. It holds no token, bearer, identity
    // key, credential, or free text. It exists so a restarted service can
    // refuse a second engine and refuse a start while a previous cleanup is
    // unknown. This class performs no file input or output. The future store
    // owns the protected directory, the reparse checks, the flush, and the
    // atomic replace.
    public sealed class EngineServiceStateRecord
    {
        private EngineServiceStateRecord(
            long sequence,
            EngineServicePhase phase,
            string intentId,
            string launchNonce,
            long launchStarted100ns,
            int pid,
            long created100ns,
            string engineImage,
            string adapterName,
            string plannedGuid,
            ulong adapterLuid,
            string adapterGuid,
            EngineServiceIdentitySource identitySource,
            bool routesMayExist,
            EngineServiceCleanup cleanup,
            EngineServiceStopReason stop,
            long updatedAtUnix)
        {
            Sequence = sequence;
            Phase = phase;
            IntentId = intentId ?? "";
            LaunchNonce = launchNonce ?? "";
            LaunchStarted100ns = launchStarted100ns;
            Pid = pid;
            Created100ns = created100ns;
            EngineImage = engineImage ?? "";
            AdapterName = adapterName ?? "";
            PlannedGuid = plannedGuid ?? "";
            AdapterLuid = adapterLuid;
            AdapterGuid = adapterGuid ?? "";
            IdentitySource = identitySource;
            RoutesMayExist = routesMayExist;
            Cleanup = cleanup;
            Stop = stop;
            UpdatedAtUnix = updatedAtUnix;
        }

        public long Sequence { get; private set; }

        public EngineServicePhase Phase { get; private set; }

        public string IntentId { get; private set; }

        // This value travels only on a descriptor. It is never a command line
        // argument and is never shown in status, diagnostics, or a report.
        public string LaunchNonce { get; private set; }

        public long LaunchStarted100ns { get; private set; }

        // Zero means no process id was recorded.
        public int Pid { get; private set; }

        // Zero means no creation time was recorded.
        public long Created100ns { get; private set; }

        public string EngineImage { get; private set; }

        public string AdapterName { get; private set; }

        // A fresh intent marker. It is not ownership proof.
        public string PlannedGuid { get; private set; }

        public ulong AdapterLuid { get; private set; }

        public string AdapterGuid { get; private set; }

        public EngineServiceIdentitySource IdentitySource { get; private set; }

        // True once a route may exist for this intent. A false value is the
        // only value that can contribute to a clean start gate.
        public bool RoutesMayExist { get; private set; }

        public EngineServiceCleanup Cleanup { get; private set; }

        public EngineServiceStopReason Stop { get; private set; }

        public long UpdatedAtUnix { get; private set; }

        public static EngineServiceStateRecord CreateNeverLaunched(DateTimeOffset now)
        {
            return CreateNeverLaunched(now, "");
        }

        public static EngineServiceStateRecord CreateNeverLaunched(
            DateTimeOffset now,
            string engineImage)
        {
            EngineServiceStateRecord record = new EngineServiceStateRecord(
                0,
                EngineServicePhase.NeverLaunched,
                "",
                "",
                0,
                0,
                0,
                engineImage ?? "",
                "",
                "",
                0,
                "",
                EngineServiceIdentitySource.Missing,
                false,
                EngineServiceCleanup.Ok,
                EngineServiceStopReason.None,
                now.ToUnixTimeSeconds());
            string code;
            if (!record.Validate(out code))
            {
                throw new InvalidOperationException("invalid initial state record: " + code);
            }
            return record;
        }

        // Structural start check only. A clean stopped record can name a
        // previous process, so the caller must use EngineServiceStateGate and
        // its injected process identity proof before it starts a new engine.
        public bool CanStart(out string code)
        {
            string validation;
            if (!Validate(out validation))
            {
                code = validation;
                return false;
            }
            if (Cleanup == EngineServiceCleanup.Failed)
            {
                code = EngineProtocol.ErrorCodes.CleanupBlocked;
                return false;
            }
            if (Cleanup == EngineServiceCleanup.Unknown)
            {
                code = EngineProtocol.ErrorCodes.CleanupUnknown;
                return false;
            }
            if (Cleanup == EngineServiceCleanup.Pending)
            {
                code = EngineProtocol.ErrorCodes.CleanupPending;
                return false;
            }
            if (RoutesMayExist)
            {
                code = EngineProtocol.ErrorCodes.CleanupBlocked;
                return false;
            }
            if (Phase != EngineServicePhase.NeverLaunched
                && Phase != EngineServicePhase.Stopped)
            {
                code = EngineProtocol.ErrorCodes.NotReady;
                return false;
            }
            code = "";
            return true;
        }

        public EngineServiceStateRecord BeginLaunch(
            string intentId,
            string launchNonce,
            string adapterName,
            string plannedGuid,
            long launchStarted100ns,
            DateTimeOffset now)
        {
            string code;
            if (!CanStart(out code)
                || !EngineProtocol.IsValidInstanceId(intentId)
                || !IsValidNonce(launchNonce)
                || !IsValidAdapterName(adapterName)
                || !IsValidGuid(plannedGuid)
                || EngineImage.Length < 1
                || launchStarted100ns < 0)
            {
                throw new InvalidOperationException("the launch intent is not valid");
            }
            EngineServiceStateRecord next = new EngineServiceStateRecord(
                Sequence + 1,
                EngineServicePhase.Launching,
                intentId,
                launchNonce,
                launchStarted100ns,
                0,
                0,
                EngineImage,
                adapterName,
                plannedGuid,
                0,
                "",
                EngineServiceIdentitySource.Planned,
                false,
                EngineServiceCleanup.Unknown,
                EngineServiceStopReason.None,
                now.ToUnixTimeSeconds());
            EnsureValid(next);
            return next;
        }

        public EngineServiceStateRecord MarkLaunched(
            int pid,
            long created100ns,
            DateTimeOffset now)
        {
            if (Phase != EngineServicePhase.Launching || pid <= 0 || created100ns <= 0)
            {
                throw new InvalidOperationException("the launched transition is not valid");
            }
            EngineServiceStateRecord next = new EngineServiceStateRecord(
                Sequence + 1,
                EngineServicePhase.Launched,
                IntentId,
                LaunchNonce,
                LaunchStarted100ns,
                pid,
                created100ns,
                EngineImage,
                AdapterName,
                PlannedGuid,
                0,
                "",
                EngineServiceIdentitySource.Planned,
                false,
                EngineServiceCleanup.Unknown,
                EngineServiceStopReason.None,
                now.ToUnixTimeSeconds());
            EnsureValid(next);
            return next;
        }

        public EngineServiceStateRecord MarkAdapterReady(
            ulong adapterLuid,
            string adapterGuid,
            DateTimeOffset now)
        {
            if (Phase != EngineServicePhase.Launched
                || adapterLuid == 0
                || !IsValidGuid(adapterGuid))
            {
                throw new InvalidOperationException("the adapter transition is not valid");
            }
            EngineServiceStateRecord next = new EngineServiceStateRecord(
                Sequence + 1,
                EngineServicePhase.AdapterReady,
                IntentId,
                LaunchNonce,
                LaunchStarted100ns,
                Pid,
                Created100ns,
                EngineImage,
                AdapterName,
                PlannedGuid,
                adapterLuid,
                adapterGuid,
                EngineServiceIdentitySource.Observed,
                true,
                EngineServiceCleanup.Unknown,
                EngineServiceStopReason.None,
                now.ToUnixTimeSeconds());
            EnsureValid(next);
            return next;
        }

        public EngineServiceStateRecord MarkRunning(DateTimeOffset now)
        {
            if (Phase != EngineServicePhase.AdapterReady)
            {
                throw new InvalidOperationException("the running transition is not valid");
            }
            EngineServiceStateRecord next = new EngineServiceStateRecord(
                Sequence + 1,
                EngineServicePhase.Running,
                IntentId,
                LaunchNonce,
                LaunchStarted100ns,
                Pid,
                Created100ns,
                EngineImage,
                AdapterName,
                PlannedGuid,
                AdapterLuid,
                AdapterGuid,
                EngineServiceIdentitySource.Observed,
                true,
                EngineServiceCleanup.Unknown,
                EngineServiceStopReason.None,
                now.ToUnixTimeSeconds());
            EnsureValid(next);
            return next;
        }

        public EngineServiceStateRecord BeginStopping(DateTimeOffset now)
        {
            if (Phase != EngineServicePhase.AdapterReady
                && Phase != EngineServicePhase.Running)
            {
                throw new InvalidOperationException("the stopping transition is not valid");
            }
            EngineServiceStateRecord next = new EngineServiceStateRecord(
                Sequence + 1,
                EngineServicePhase.Stopping,
                IntentId,
                LaunchNonce,
                LaunchStarted100ns,
                Pid,
                Created100ns,
                EngineImage,
                AdapterName,
                PlannedGuid,
                AdapterLuid,
                AdapterGuid,
                IdentitySource,
                RoutesMayExist,
                EngineServiceCleanup.Pending,
                EngineServiceStopReason.None,
                now.ToUnixTimeSeconds());
            EnsureValid(next);
            return next;
        }

        public EngineServiceStateRecord MarkStopped(
            EngineServiceStopReason reason,
            EngineServiceCleanup cleanup,
            DateTimeOffset now)
        {
            if (Phase != EngineServicePhase.Stopping
                || reason == EngineServiceStopReason.None
                || cleanup == EngineServiceCleanup.Pending)
            {
                throw new InvalidOperationException("the stopped transition is not valid");
            }

            EngineServicePhase phase;
            bool routesMayExist;
            if (cleanup == EngineServiceCleanup.Ok)
            {
                phase = EngineServicePhase.Stopped;
                routesMayExist = false;
            }
            else if (cleanup == EngineServiceCleanup.Failed)
            {
                phase = EngineServicePhase.CleanupFailed;
                routesMayExist = true;
            }
            else
            {
                phase = EngineServicePhase.CleanupUnknown;
                routesMayExist = true;
            }

            EngineServiceStateRecord next = new EngineServiceStateRecord(
                Sequence + 1,
                phase,
                IntentId,
                LaunchNonce,
                LaunchStarted100ns,
                Pid,
                Created100ns,
                EngineImage,
                AdapterName,
                PlannedGuid,
                AdapterLuid,
                AdapterGuid,
                IdentitySource,
                routesMayExist,
                cleanup,
                reason,
                now.ToUnixTimeSeconds());
            EnsureValid(next);
            return next;
        }

        // A launcher calls this only after it proves that CreateProcess did
        // not create a process. That is the one launch failure that has no
        // effect and a clean gate. A Launching record alone is not proof: the
        // PID write can fail after the process exists.
        public EngineServiceStateRecord MarkLaunchNotStarted(DateTimeOffset now)
        {
            if (Phase != EngineServicePhase.Launching)
            {
                throw new InvalidOperationException("the not-started transition is not valid");
            }
            EngineServiceStateRecord next = new EngineServiceStateRecord(
                Sequence + 1,
                EngineServicePhase.Stopped,
                IntentId,
                LaunchNonce,
                LaunchStarted100ns,
                0,
                0,
                EngineImage,
                AdapterName,
                PlannedGuid,
                0,
                "",
                EngineServiceIdentitySource.Planned,
                false,
                EngineServiceCleanup.Ok,
                EngineServiceStopReason.StartFailed,
                now.ToUnixTimeSeconds());
            EnsureValid(next);
            return next;
        }

        // Any failure after the durable launch intent was written is unknown
        // unless the launcher proved that no process was created. A
        // Launching record can be left behind by a crash between
        // CreateProcess and the PID write, so it is not a clean state. A
        // Launched record had a process and may have passed the launch gate.
        // Keep the recorded process facts when they exist.
        public EngineServiceStateRecord MarkLaunchFailed(DateTimeOffset now)
        {
            if (Phase != EngineServicePhase.Launching
                && Phase != EngineServicePhase.Launched)
            {
                throw new InvalidOperationException("the launch failure transition is not valid");
            }
            bool processRecorded = Phase == EngineServicePhase.Launched;
            EngineServiceStateRecord unknown = new EngineServiceStateRecord(
                Sequence + 1,
                EngineServicePhase.CleanupUnknown,
                IntentId,
                LaunchNonce,
                LaunchStarted100ns,
                processRecorded ? Pid : 0,
                processRecorded ? Created100ns : 0,
                EngineImage,
                AdapterName,
                PlannedGuid,
                0,
                "",
                EngineServiceIdentitySource.Planned,
                processRecorded,
                EngineServiceCleanup.Unknown,
                EngineServiceStopReason.StartFailed,
                now.ToUnixTimeSeconds());
            EnsureValid(unknown);
            return unknown;
        }

        public EngineServiceStateRecord MarkCleanupUnknown(DateTimeOffset now)
        {
            if (Phase == EngineServicePhase.NeverLaunched)
            {
                throw new InvalidOperationException("a never-launched record is clean");
            }
            EngineServiceStopReason reason = Stop == EngineServiceStopReason.None
                ? EngineServiceStopReason.Unknown
                : Stop;
            EngineServiceStateRecord next = new EngineServiceStateRecord(
                Sequence + 1,
                EngineServicePhase.CleanupUnknown,
                IntentId,
                LaunchNonce,
                LaunchStarted100ns,
                Pid,
                Created100ns,
                EngineImage,
                AdapterName,
                PlannedGuid,
                AdapterLuid,
                AdapterGuid,
                IdentitySource,
                RoutesMayExist,
                EngineServiceCleanup.Unknown,
                reason,
                now.ToUnixTimeSeconds());
            EnsureValid(next);
            return next;
        }

        public bool Validate(out string code)
        {
            code = EngineProtocol.ErrorCodes.Internal;
            if (!Enum.IsDefined(typeof(EngineServicePhase), Phase)
                || !Enum.IsDefined(typeof(EngineServiceIdentitySource), IdentitySource)
                || !Enum.IsDefined(typeof(EngineServiceCleanup), Cleanup)
                || !Enum.IsDefined(typeof(EngineServiceStopReason), Stop))
            {
                return false;
            }
            if (Sequence < 0 || LaunchStarted100ns < 0 || UpdatedAtUnix < 0)
            {
                return false;
            }
            if (Pid < 0 || Created100ns < 0)
            {
                return false;
            }
            if ((Pid == 0) != (Created100ns == 0))
            {
                return false;
            }
            if (IdentitySource == EngineServiceIdentitySource.Missing)
            {
                if (Phase != EngineServicePhase.NeverLaunched)
                {
                    return false;
                }
            }
            else
            {
                if (!EngineProtocol.IsValidInstanceId(IntentId)
                    || !IsValidNonce(LaunchNonce)
                    || !IsValidAdapterName(AdapterName)
                    || !IsValidGuid(PlannedGuid)
                    || EngineImage.Length < 1)
                {
                    return false;
                }
            }
            if (IdentitySource == EngineServiceIdentitySource.Observed)
            {
                if (AdapterLuid == 0
                    || !IsValidGuid(AdapterGuid)
                    || (Phase != EngineServicePhase.AdapterReady
                        && Phase != EngineServicePhase.Running
                        && Phase != EngineServicePhase.Stopping
                        && Phase != EngineServicePhase.Stopped
                        && Phase != EngineServicePhase.CleanupFailed
                        && Phase != EngineServicePhase.CleanupUnknown))
                {
                    return false;
                }
            }
            else if (AdapterLuid != 0 || AdapterGuid.Length != 0)
            {
                return false;
            }

            switch (Phase)
            {
                case EngineServicePhase.NeverLaunched:
                    return Cleanup == EngineServiceCleanup.Ok
                        && !RoutesMayExist
                        && Stop == EngineServiceStopReason.None
                        && Pid == 0;
                case EngineServicePhase.Launching:
                    return Cleanup == EngineServiceCleanup.Unknown
                        && !RoutesMayExist
                        && Stop == EngineServiceStopReason.None
                        && Pid == 0
                        && IdentitySource == EngineServiceIdentitySource.Planned;
                case EngineServicePhase.Launched:
                    return Cleanup == EngineServiceCleanup.Unknown
                        && !RoutesMayExist
                        && Stop == EngineServiceStopReason.None
                        && Pid > 0
                        && IdentitySource == EngineServiceIdentitySource.Planned;
                case EngineServicePhase.AdapterReady:
                    return Cleanup == EngineServiceCleanup.Unknown
                        && RoutesMayExist
                        && Stop == EngineServiceStopReason.None
                        && Pid > 0
                        && IdentitySource == EngineServiceIdentitySource.Observed;
                case EngineServicePhase.Running:
                    return Cleanup == EngineServiceCleanup.Unknown
                        && RoutesMayExist
                        && Stop == EngineServiceStopReason.None
                        && Pid > 0
                        && IdentitySource == EngineServiceIdentitySource.Observed;
                case EngineServicePhase.Stopping:
                    return (Cleanup == EngineServiceCleanup.Unknown
                            || Cleanup == EngineServiceCleanup.Pending)
                        && RoutesMayExist
                        && Stop == EngineServiceStopReason.None
                        && Pid > 0
                        && IdentitySource == EngineServiceIdentitySource.Observed;
                case EngineServicePhase.Stopped:
                    return Cleanup == EngineServiceCleanup.Ok
                        && !RoutesMayExist
                        && Stop != EngineServiceStopReason.None;
                case EngineServicePhase.CleanupFailed:
                    return Cleanup == EngineServiceCleanup.Failed
                        && RoutesMayExist
                        && Stop != EngineServiceStopReason.None;
                case EngineServicePhase.CleanupUnknown:
                    return Cleanup == EngineServiceCleanup.Unknown
                        && Stop != EngineServiceStopReason.None;
                default:
                    return false;
            }
        }

        public Dictionary<string, string> ToFields()
        {
            Dictionary<string, string> fields = new Dictionary<string, string>(StringComparer.Ordinal);
            fields[EngineServiceStateKeys.Version] = "1";
            fields[EngineServiceStateKeys.Sequence] = Sequence.ToString(CultureInfo.InvariantCulture);
            fields[EngineServiceStateKeys.Phase] = PhaseWord(Phase);
            if (IntentId.Length > 0)
            {
                fields[EngineServiceStateKeys.IntentId] = IntentId;
            }
            if (LaunchNonce.Length > 0)
            {
                fields[EngineServiceStateKeys.LaunchNonce] = LaunchNonce;
            }
            if (LaunchStarted100ns > 0)
            {
                fields[EngineServiceStateKeys.LaunchStarted100ns] =
                    LaunchStarted100ns.ToString(CultureInfo.InvariantCulture);
            }
            if (Pid > 0)
            {
                fields[EngineServiceStateKeys.Pid] = Pid.ToString(CultureInfo.InvariantCulture);
                fields[EngineServiceStateKeys.Created100ns] =
                    Created100ns.ToString(CultureInfo.InvariantCulture);
            }
            if (EngineImage.Length > 0)
            {
                fields[EngineServiceStateKeys.EngineImage] = EngineImage;
            }
            if (AdapterName.Length > 0)
            {
                fields[EngineServiceStateKeys.AdapterName] = AdapterName;
            }
            if (PlannedGuid.Length > 0)
            {
                fields[EngineServiceStateKeys.PlannedGuid] = PlannedGuid;
            }
            if (AdapterLuid > 0)
            {
                fields[EngineServiceStateKeys.AdapterLuid] = AdapterLuid.ToString(CultureInfo.InvariantCulture);
            }
            if (AdapterGuid.Length > 0)
            {
                fields[EngineServiceStateKeys.AdapterGuid] = AdapterGuid;
            }
            fields[EngineServiceStateKeys.IdentitySource] = IdentitySourceWord(IdentitySource);
            fields[EngineServiceStateKeys.RoutesMayExist] = RoutesMayExist ? "1" : "0";
            if (RoutesMayExist)
            {
                fields[EngineServiceStateKeys.Routes] = EngineServiceStateKeys.ManagedRoutes;
            }
            fields[EngineServiceStateKeys.Cleanup] = CleanupWord(Cleanup);
            fields[EngineServiceStateKeys.Stop] = EngineServiceStatus.StopWord(Stop);
            fields[EngineServiceStateKeys.UpdatedAt] = UpdatedAtUnix.ToString(CultureInfo.InvariantCulture);

            // A bearer, token, or credential must never be serialized into
            // the durable state. The field set above is fixed and non-secret,
            // but this check makes a later field addition fail at the writer
            // instead of reaching the file.
            EnsureNoCredentialField(fields);
            return fields;
        }

        public static bool HasCredentialField(IReadOnlyDictionary<string, string> fields)
        {
            if (fields == null)
            {
                return false;
            }
            foreach (KeyValuePair<string, string> pair in fields)
            {
                if (EngineProtocol.IsCredentialKey(pair.Key))
                {
                    return true;
                }
            }
            return false;
        }

        private static void EnsureNoCredentialField(
            IReadOnlyDictionary<string, string> fields)
        {
            if (HasCredentialField(fields))
            {
                throw new InvalidOperationException(
                    "a credential field cannot be serialized into the state record");
            }
        }

        public static bool TryParse(
            IReadOnlyDictionary<string, string> fields,
            out EngineServiceStateRecord record,
            out string code)
        {
            record = null;
            if (!EngineWire.TryValidateFields(fields, out code))
            {
                return false;
            }
            if (fields == null)
            {
                code = EngineProtocol.ErrorCodes.BadRequest;
                return false;
            }

            IReadOnlyList<string> allowed = EngineServiceStateKeys.AllFields();
            foreach (string key in fields.Keys)
            {
                bool known = false;
                for (int index = 0; index < allowed.Count; index++)
                {
                    if (allowed[index] == key)
                    {
                        known = true;
                        break;
                    }
                }
                if (!known)
                {
                    code = EngineProtocol.ErrorCodes.BadRequest;
                    return false;
                }
            }

            string version;
            string sequenceText;
            string phaseText;
            string cleanupText;
            string stopText;
            string routesMayExistText;
            string updatedText;
            if (!fields.TryGetValue(EngineServiceStateKeys.Version, out version)
                || !fields.TryGetValue(EngineServiceStateKeys.Sequence, out sequenceText)
                || !fields.TryGetValue(EngineServiceStateKeys.Phase, out phaseText)
                || !fields.TryGetValue(EngineServiceStateKeys.Cleanup, out cleanupText)
                || !fields.TryGetValue(EngineServiceStateKeys.Stop, out stopText)
                || !fields.TryGetValue(EngineServiceStateKeys.RoutesMayExist, out routesMayExistText)
                || !fields.TryGetValue(EngineServiceStateKeys.UpdatedAt, out updatedText))
            {
                code = EngineProtocol.ErrorCodes.BadRequest;
                return false;
            }
            if (version != "1")
            {
                code = EngineProtocol.ErrorCodes.BadVersion;
                return false;
            }

            long sequence;
            long updated;
            if (!TryParseLong(sequenceText, out sequence)
                || !TryParseLong(updatedText, out updated))
            {
                code = EngineProtocol.ErrorCodes.BadRequest;
                return false;
            }

            EngineServicePhase phase;
            EngineServiceCleanup cleanup;
            EngineServiceStopReason stop;
            EngineServiceIdentitySource identity;
            if (!TryParsePhase(phaseText, out phase)
                || !TryParseCleanup(cleanupText, out cleanup)
                || !TryParseStop(stopText, out stop))
            {
                code = EngineProtocol.ErrorCodes.BadRequest;
                return false;
            }
            string identityText;
            if (!fields.TryGetValue(EngineServiceStateKeys.IdentitySource, out identityText)
                || !TryParseIdentity(identityText, out identity))
            {
                code = EngineProtocol.ErrorCodes.BadRequest;
                return false;
            }

            bool routesMayExist;
            if (routesMayExistText == "1")
            {
                routesMayExist = true;
            }
            else if (routesMayExistText == "0")
            {
                routesMayExist = false;
            }
            else
            {
                code = EngineProtocol.ErrorCodes.BadRequest;
                return false;
            }

            string routes;
            bool hasRoutes = fields.TryGetValue(EngineServiceStateKeys.Routes, out routes);
            if (hasRoutes && routes != EngineServiceStateKeys.ManagedRoutes)
            {
                code = EngineProtocol.ErrorCodes.BadRequest;
                return false;
            }
            if (routesMayExist != hasRoutes)
            {
                code = EngineProtocol.ErrorCodes.BadRequest;
                return false;
            }

            long launchStarted;
            long created;
            int pid;
            ulong luid;
            if (!TryParseOptionalLong(fields, EngineServiceStateKeys.LaunchStarted100ns, out launchStarted)
                || !TryParseOptionalLong(fields, EngineServiceStateKeys.Created100ns, out created)
                || !TryParseOptionalInt(fields, EngineServiceStateKeys.Pid, out pid)
                || !TryParseOptionalUlong(fields, EngineServiceStateKeys.AdapterLuid, out luid))
            {
                code = EngineProtocol.ErrorCodes.BadRequest;
                return false;
            }

            EngineServiceStateRecord parsed = new EngineServiceStateRecord(
                sequence,
                phase,
                Optional(fields, EngineServiceStateKeys.IntentId),
                Optional(fields, EngineServiceStateKeys.LaunchNonce),
                launchStarted,
                pid,
                created,
                Optional(fields, EngineServiceStateKeys.EngineImage),
                Optional(fields, EngineServiceStateKeys.AdapterName),
                Optional(fields, EngineServiceStateKeys.PlannedGuid),
                luid,
                Optional(fields, EngineServiceStateKeys.AdapterGuid),
                identity,
                routesMayExist,
                cleanup,
                stop,
                updated);
            string validation;
            if (!parsed.Validate(out validation))
            {
                code = validation;
                return false;
            }
            record = parsed;
            code = "";
            return true;
        }

        public static string PhaseWord(EngineServicePhase phase)
        {
            switch (phase)
            {
                case EngineServicePhase.Launching:
                    return "launching";
                case EngineServicePhase.Launched:
                    return "launched";
                case EngineServicePhase.AdapterReady:
                    return "adapter_ready";
                case EngineServicePhase.Running:
                    return "running";
                case EngineServicePhase.Stopping:
                    return "stopping";
                case EngineServicePhase.Stopped:
                    return "stopped";
                case EngineServicePhase.CleanupFailed:
                    return "cleanup_failed";
                case EngineServicePhase.CleanupUnknown:
                    return "cleanup_unknown";
                default:
                    return "never_launched";
            }
        }

        private static void EnsureValid(EngineServiceStateRecord record)
        {
            string code;
            if (!record.Validate(out code))
            {
                throw new InvalidOperationException("invalid state record: " + code);
            }
        }

        private static bool TryParseLong(string value, out long result)
        {
            return long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out result)
                && result >= 0;
        }

        private static bool TryParseOptionalLong(
            IReadOnlyDictionary<string, string> fields,
            string key,
            out long value)
        {
            string text;
            if (!fields.TryGetValue(key, out text) || text.Length == 0)
            {
                value = 0;
                return true;
            }
            return TryParseLong(text, out value);
        }

        private static bool TryParseOptionalInt(
            IReadOnlyDictionary<string, string> fields,
            string key,
            out int value)
        {
            value = 0;
            string text;
            if (!fields.TryGetValue(key, out text) || text.Length == 0)
            {
                return true;
            }
            return int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out value)
                && value >= 0;
        }

        private static bool TryParseOptionalUlong(
            IReadOnlyDictionary<string, string> fields,
            string key,
            out ulong value)
        {
            value = 0;
            string text;
            if (!fields.TryGetValue(key, out text) || text.Length == 0)
            {
                return true;
            }
            return ulong.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out value);
        }

        private static string Optional(IReadOnlyDictionary<string, string> fields, string key)
        {
            string value;
            return fields.TryGetValue(key, out value) ? value : "";
        }

        private static bool TryParsePhase(string value, out EngineServicePhase phase)
        {
            if (value == "never_launched")
            {
                phase = EngineServicePhase.NeverLaunched;
                return true;
            }
            if (value == "launching")
            {
                phase = EngineServicePhase.Launching;
                return true;
            }
            if (value == "launched")
            {
                phase = EngineServicePhase.Launched;
                return true;
            }
            if (value == "adapter_ready")
            {
                phase = EngineServicePhase.AdapterReady;
                return true;
            }
            if (value == "running")
            {
                phase = EngineServicePhase.Running;
                return true;
            }
            if (value == "stopping")
            {
                phase = EngineServicePhase.Stopping;
                return true;
            }
            if (value == "stopped")
            {
                phase = EngineServicePhase.Stopped;
                return true;
            }
            if (value == "cleanup_failed")
            {
                phase = EngineServicePhase.CleanupFailed;
                return true;
            }
            if (value == "cleanup_unknown")
            {
                phase = EngineServicePhase.CleanupUnknown;
                return true;
            }
            phase = EngineServicePhase.NeverLaunched;
            return false;
        }

        private static bool TryParseIdentity(string value, out EngineServiceIdentitySource source)
        {
            if (value == "missing")
            {
                source = EngineServiceIdentitySource.Missing;
                return true;
            }
            if (value == "planned")
            {
                source = EngineServiceIdentitySource.Planned;
                return true;
            }
            if (value == "observed")
            {
                source = EngineServiceIdentitySource.Observed;
                return true;
            }
            source = EngineServiceIdentitySource.Missing;
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

        private static bool TryParseStop(string value, out EngineServiceStopReason reason)
        {
            IReadOnlyList<EngineServiceStopReason> reasons = new List<EngineServiceStopReason>
            {
                EngineServiceStopReason.None,
                EngineServiceStopReason.User,
                EngineServiceStopReason.SourceDeviceGone,
                EngineServiceStopReason.ObservationUnavailable,
                EngineServiceStopReason.GatewayChanged,
                EngineServiceStopReason.LinkChanged,
                EngineServiceStopReason.EngineLost,
                EngineServiceStopReason.StartFailed,
                EngineServiceStopReason.ParentLost,
                EngineServiceStopReason.ServiceStop,
                EngineServiceStopReason.Shutdown,
                EngineServiceStopReason.SessionLogoff,
                EngineServiceStopReason.Unknown
            };
            for (int index = 0; index < reasons.Count; index++)
            {
                if (EngineServiceStatus.StopWord(reasons[index]) == value)
                {
                    reason = reasons[index];
                    return true;
                }
            }
            reason = EngineServiceStopReason.None;
            return false;
        }

        private static string IdentitySourceWord(EngineServiceIdentitySource source)
        {
            switch (source)
            {
                case EngineServiceIdentitySource.Planned:
                    return "planned";
                case EngineServiceIdentitySource.Observed:
                    return "observed";
                default:
                    return "missing";
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

        private static bool IsValidNonce(string value)
        {
            if (value == null || value.Length < 32 || value.Length > 64)
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

        private static bool IsValidAdapterName(string value)
        {
            if (string.IsNullOrEmpty(value) || value.Length > 128)
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

        private static bool IsValidGuid(string value)
        {
            Guid parsed;
            return !string.IsNullOrEmpty(value) && Guid.TryParse(value, out parsed);
        }
    }

    // The result of checking the exact process identity that a stopped record
    // named. Gone means the recorded process id and creation time no longer
    // name a live process. Alive means they still do. Unknown means the check
    // could not prove either answer.
    public enum EngineServiceRecordedProcessState
    {
        Unknown,
        Gone,
        Alive
    }

    // The injected identity and liveness proof for a process recorded in a
    // stopped state record. A clean stopped record is not proof by itself.
    // The host must open the recorded process id and compare the recorded
    // creation time before it can report Gone. A pid alone is not identity.
    public interface IEngineServiceRecordedProcessProof
    {
        EngineServiceRecordedProcessState Check(
            int processId,
            long created100ns,
            out string code);
    }

    // The load gate for the one durable state record. It performs no file
    // input or output. A future store reads the bytes and calls TryLoad.
    // A missing, unreadable, damaged, or version-mismatched record is
    // cleanup_unknown. It never becomes a never-launched clean record. A
    // fresh install must create and write a never-launched record first, then
    // load that written record. A missing file is a failure, not a default.
    //
    // A clean stopped record that names a process is not enough to allow a
    // start. The gate needs the injected proof above. Without it the safe
    // answer is cleanup_unknown, even when every other field is clean.
    public sealed class EngineServiceStateGate
    {
        private static readonly EngineServiceStateGate MissingGate =
            new EngineServiceStateGate(null, null);

        private readonly EngineServiceStateRecord record;
        private readonly IEngineServiceRecordedProcessProof processProof;

        private EngineServiceStateGate(
            EngineServiceStateRecord record,
            IEngineServiceRecordedProcessProof processProof)
        {
            this.record = record;
            this.processProof = processProof;
        }

        public bool HasRecord
        {
            get { return record != null; }
        }

        public EngineServiceStateRecord Record
        {
            get { return record; }
        }

        public bool HasProcessProof
        {
            get { return processProof != null; }
        }

        // The safe default for a session that was given no durable store.
        // Every start fails with cleanup_unknown.
        public static EngineServiceStateGate Missing
        {
            get { return MissingGate; }
        }

        public static EngineServiceStateGate FromRecord(EngineServiceStateRecord record)
        {
            return FromRecord(record, null);
        }

        public static EngineServiceStateGate FromRecord(
            EngineServiceStateRecord record,
            IEngineServiceRecordedProcessProof processProof)
        {
            if (record == null)
            {
                return MissingGate;
            }
            string code;
            if (!record.Validate(out code))
            {
                return MissingGate;
            }
            return new EngineServiceStateGate(record, processProof);
        }

        public static bool TryLoad(
            bool exists,
            bool readable,
            IReadOnlyDictionary<string, string> fields,
            out EngineServiceStateGate gate,
            out string code)
        {
            return TryLoad(exists, readable, fields, null, out gate, out code);
        }

        public static bool TryLoad(
            bool exists,
            bool readable,
            IReadOnlyDictionary<string, string> fields,
            IEngineServiceRecordedProcessProof processProof,
            out EngineServiceStateGate gate,
            out string code)
        {
            gate = MissingGate;
            code = EngineProtocol.ErrorCodes.CleanupUnknown;
            if (!exists || !readable || fields == null)
            {
                return false;
            }
            EngineServiceStateRecord record;
            string parseCode;
            if (!EngineServiceStateRecord.TryParse(fields, out record, out parseCode))
            {
                // The parse code is not forwarded. A damaged record and a
                // version mismatch both mean the durable state cannot be
                // trusted, and the fixed code is cleanup_unknown.
                return false;
            }
            gate = new EngineServiceStateGate(record, processProof);
            code = "";
            return true;
        }

        public bool CanStart(out string code)
        {
            if (record == null)
            {
                code = EngineProtocol.ErrorCodes.CleanupUnknown;
                return false;
            }
            if (!record.CanStart(out code))
            {
                return false;
            }
            return TryProveRecordedProcessGone(out code);
        }

        // A stopped record with a recorded process is only clean when the
        // injected proof says the exact recorded identity is gone. An alive
        // process is cleanup_pending. A missing or inconclusive proof is
        // cleanup_unknown. A never-launched record and a proven not-started
        // launch have no process and need no proof.
        private bool TryProveRecordedProcessGone(out string code)
        {
            if (record.Phase != EngineServicePhase.Stopped || record.Pid <= 0)
            {
                code = "";
                return true;
            }
            if (processProof == null)
            {
                code = EngineProtocol.ErrorCodes.CleanupUnknown;
                return false;
            }

            EngineServiceRecordedProcessState state;
            try
            {
                string proofCode;
                state = processProof.Check(record.Pid, record.Created100ns, out proofCode);
            }
            catch (Exception)
            {
                code = EngineProtocol.ErrorCodes.CleanupUnknown;
                return false;
            }

            if (state == EngineServiceRecordedProcessState.Gone)
            {
                code = "";
                return true;
            }
            code = state == EngineServiceRecordedProcessState.Alive
                ? EngineProtocol.ErrorCodes.CleanupPending
                : EngineProtocol.ErrorCodes.CleanupUnknown;
            return false;
        }
    }
}
