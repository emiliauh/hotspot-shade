using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Threading.Tasks;

namespace HotspotShade.WinUI2.Core.App
{
    // One broker answer, read from the string fields of the app-service reply.
    public sealed class BrokerReply
    {
        public BrokerReply(bool ok, int http, string code, string body, string source, string phase, string turnOn)
        {
            Ok = ok;
            Http = http;
            Code = code ?? "";
            Body = body ?? "";
            Source = source ?? BrokerSources.None;
            Phase = phase ?? BrokerPhases.Idle;
            TurnOn = turnOn ?? BrokerTurnOn.Available;
        }

        public bool Ok { get; private set; }

        // The engine HTTP status, or 0 when the request did not reach it.
        public int Http { get; private set; }

        public string Code { get; private set; }

        public string Body { get; private set; }

        public string Source { get; private set; }

        public string Phase { get; private set; }

        public string TurnOn { get; private set; }

        public static BrokerReply Failure(string code)
        {
            return new BrokerReply(false, 0, code, "", null, null, null);
        }

        public static BrokerReply FromFields(IDictionary<string, string> fields)
        {
            if (fields == null)
            {
                return Failure(BrokerCodes.Closed);
            }
            string ok;
            string http;
            string code;
            string body;
            string source;
            string phase;
            string turnOn;
            fields.TryGetValue(BrokerProtocol.OkField, out ok);
            fields.TryGetValue(BrokerProtocol.HttpField, out http);
            fields.TryGetValue(BrokerProtocol.CodeField, out code);
            fields.TryGetValue(BrokerProtocol.BodyField, out body);
            fields.TryGetValue(BrokerProtocol.SourceField, out source);
            fields.TryGetValue(BrokerProtocol.PhaseField, out phase);
            fields.TryGetValue(BrokerProtocol.TurnOnField, out turnOn);
            int status;
            if (!int.TryParse(http, NumberStyles.None, CultureInfo.InvariantCulture, out status))
            {
                status = 0;
            }
            if (body != null && body.Length > BrokerProtocol.MaxBodyChars)
            {
                return Failure(BrokerCodes.ReplyTooLarge);
            }
            return new BrokerReply(ok == "true", status, code, body, source, phase, turnOn);
        }

        public Dictionary<string, string> ToFields()
        {
            Dictionary<string, string> fields = new Dictionary<string, string>(StringComparer.Ordinal);
            fields[BrokerProtocol.OkField] = Ok ? "true" : "false";
            fields[BrokerProtocol.HttpField] = Http.ToString(CultureInfo.InvariantCulture);
            fields[BrokerProtocol.CodeField] = Code;
            fields[BrokerProtocol.BodyField] = Body;
            fields[BrokerProtocol.SourceField] = Source;
            fields[BrokerProtocol.PhaseField] = Phase;
            fields[BrokerProtocol.TurnOnField] = TurnOn;
            return fields;
        }

        // The "error" text of an engine refusal, or null.
        public string EngineError()
        {
            JsonValue root;
            if (!JsonValue.TryParseObject(Body, out root))
            {
                return null;
            }
            return root.GetString("error");
        }

        public string EngineErrorCode()
        {
            JsonValue root;
            if (!JsonValue.TryParseObject(Body, out root))
            {
                return null;
            }
            return root.GetString("code");
        }
    }

    // The window side of the broker. The UWP app implements it over its
    // app-service connection. Tests implement it with recorded engine
    // answers; the app has no other implementation.
    public interface IBrokerChannel
    {
        Task<BrokerReply> SendAsync(IDictionary<string, string> fields);
    }

    public enum ListState
    {
        Idle,
        Loading,
        Loaded,
        Empty,
        Unavailable
    }

    // The state of the window. Every visible value comes from a real broker
    // answer. The session runs on one thread (the UWP dispatcher); it does
    // not lock.
    public sealed class AppSession
    {
        public static readonly TimeSpan StaleAfter = TimeSpan.FromSeconds(3);
        public static readonly TimeSpan UnavailableAfter = TimeSpan.FromSeconds(10);
        public static readonly TimeSpan SourceWarningAfter = TimeSpan.FromSeconds(10);
        public const int MaxActivityLines = 800;

        private enum RetryTarget
        {
            Refresh,
            Start,
            Stop,
            Pair
        }

        private readonly IBrokerChannel channel;
        private readonly Func<DateTime> utcNow;
        private readonly List<LogLine> activity = new List<LogLine>();
        private readonly DateTime createdAt;

        private EngineStatusSnapshot status;
        private DateTime? lastStatusAt;
        private DateTime? sourceTroubleSince;
        private bool everAnswered;
        private string brokerFailure;
        private string source = BrokerSources.None;
        private string phase = BrokerPhases.Idle;
        private string turnOn = BrokerTurnOn.Available;
        private bool testData;
        private string lastFailureCode;

        private TunnelOperation operation = TunnelOperation.None;
        private string error;
        private RetryTarget retry = RetryTarget.Refresh;
        private string tokenRejected;
        private bool forgetBlocked;
        private bool forgetInFlight;
        private bool pairStartInFlight;
        private bool pairCancelInFlight;
        private PairingSnapshot pairing = PairingSnapshot.Idle();
        private bool pairingActive;
        private string pairingFailure;
        private long activityNext;
        // Which engine run the activity cursor belongs to. The engine's log
        // sequence starts again in a new engine process, and /api/logs never
        // answers with a `next` below the cursor it was sent, so the cursor
        // is reset from the status: when the status source (user or
        // elevated engine) or started_at changes.
        private bool logRunKnown;
        private string logRunSource;
        private double? logRunStartedAt;
        private bool logResetPending;
        private int logRun;

        public AppSession(IBrokerChannel channel, Func<DateTime> utcNow)
        {
            if (channel == null)
            {
                throw new ArgumentNullException("channel");
            }
            if (utcNow == null)
            {
                throw new ArgumentNullException("utcNow");
            }
            this.channel = channel;
            this.utcNow = utcNow;
            createdAt = utcNow();
            PingEnabled = true;
            ActivityState = ListState.Idle;
            FailuresState = ListState.Idle;
            Failures = new FailureSnapshot();
        }

        public bool PingEnabled { get; set; }

        public EngineStatusSnapshot Status
        {
            get { return status; }
        }

        // The window reads the broker startup log through this seam, so the
        // failure screen and Copy diagnostics can show the real stop point.
        public IBrokerLogSource BrokerLog { get; set; }

        public string Source
        {
            get { return source; }
        }

        public string Phase
        {
            get { return phase; }
        }

        public bool PairingActive
        {
            get { return pairingActive; }
        }

        public string PairingCode
        {
            get { return pairing == null ? "" : PairingCodeFormat.Grouped(pairing.Code); }
        }

        public bool HasPendingAction
        {
            get { return operation != TunnelOperation.None || forgetInFlight || pairStartInFlight || pairCancelInFlight; }
        }

        public IList<LogLine> Activity
        {
            get { return activity.AsReadOnly(); }
        }

        public ListState ActivityState { get; private set; }

        public FailureSnapshot Failures { get; private set; }

        public ListState FailuresState { get; private set; }

        // The broker could not be started or reached. The view model sets it
        // from the app-service connection; Retry clears it.
        public void SetBrokerFailure(string message)
        {
            brokerFailure = message;
            if (message == null)
            {
                lastFailureCode = null;
            }
        }

        // True when the window shows the broker failure screen. Try again then
        // starts the broker again instead of repeating an engine action.
        public bool HasBrokerFailure
        {
            get { return BuildInput().BrokerFailure != null; }
        }

        public StatusFreshness Freshness()
        {
            if (!lastStatusAt.HasValue)
            {
                return everAnswered ? StatusFreshness.Unavailable : StatusFreshness.Fresh;
            }
            TimeSpan age = utcNow() - lastStatusAt.Value;
            if (age >= UnavailableAfter)
            {
                return StatusFreshness.Unavailable;
            }
            if (age >= StaleAfter)
            {
                return StatusFreshness.Stale;
            }
            return StatusFreshness.Fresh;
        }

        public async Task RefreshAsync()
        {
            BrokerReply reply = await Send(BrokerOps.Status, null).ConfigureAwait(true);
            ApplyBrokerState(reply);
            if (reply.Ok && reply.Http == 200)
            {
                EngineStatusSnapshot parsed;
                if (EngineStatusSnapshot.TryParse(reply.Body, out parsed))
                {
                    if (parsed.Demo)
                    {
                        // Test data is never a status that this app shows.
                        // The window shows it at once as an engine answer
                        // that HotspotShade cannot use (BuildInput).
                        testData = true;
                        return;
                    }
                    testData = false;
                    status = parsed;
                    TrackLogRun(source, parsed.StartedAt);
                    lastStatusAt = utcNow();
                    everAnswered = true;
                    brokerFailure = null;
                    TrackSourceTrouble();
                    if (parsed.IsRunning && tokenRejected != null && parsed.Phone == PhoneState.Ready)
                    {
                        tokenRejected = null;
                    }
                }
            }
            else if (reply.Code == BrokerCodes.Closed)
            {
                brokerFailure = AppText.BrokerLost;
            }
            else if (reply.Code == BrokerCodes.NotConnected)
            {
                brokerFailure = AppText.BrokerNeverConnected;
            }
            else
            {
                lastFailureCode = reply.Code.Length == 0 ? BrokerCodes.EngineUnavailable : reply.Code;
            }
        }

        // How long the window waits for the first engine answer before it
        // shows the failure instead of the starting screen.
        public static readonly TimeSpan FirstAnswerBudget = TimeSpan.FromSeconds(20);

        public async Task CheckNowAsync()
        {
            await Send(BrokerOps.Probe, null).ConfigureAwait(true);
            await RefreshAsync().ConfigureAwait(true);
        }

        // Try again runs the action that failed.
        public async Task RetryAsync()
        {
            RetryTarget target = retry;
            error = null;
            retry = RetryTarget.Refresh;
            switch (target)
            {
                case RetryTarget.Start:
                    await TurnOnAsync().ConfigureAwait(true);
                    break;
                case RetryTarget.Stop:
                    await TurnOffAsync().ConfigureAwait(true);
                    break;
                case RetryTarget.Pair:
                    await PairAsync().ConfigureAwait(true);
                    break;
                default:
                    await RefreshAsync().ConfigureAwait(true);
                    break;
            }
        }

        public async Task PairAsync()
        {
            if (!Dashboard().CanPair)
            {
                return;
            }
            pairStartInFlight = true;
            pairingFailure = null;
            error = null;
            tokenRejected = null;
            try
            {
                BrokerReply reply = await Send(BrokerOps.Pair, null).ConfigureAwait(true);
                ApplyBrokerState(reply);
                if (reply.Ok && reply.Http == 200)
                {
                    pairingActive = true;
                    pairing = PairingSnapshot.Idle();
                }
                else
                {
                    error = ReplyMessage(reply);
                    retry = RetryTarget.Pair;
                }
            }
            finally
            {
                pairStartInFlight = false;
            }
            if (pairingActive)
            {
                await PollPairingAsync().ConfigureAwait(true);
            }
        }

        // The view model calls this every 700 ms while pairing runs.
        public async Task PollPairingAsync()
        {
            if (!pairingActive)
            {
                return;
            }
            BrokerReply reply = await Send(BrokerOps.PairStatus, null).ConfigureAwait(true);
            if (!pairingActive)
            {
                return;
            }
            PairingSnapshot parsed;
            if (!reply.Ok || reply.Http != 200 || !PairingSnapshot.TryParse(reply.Body, out parsed))
            {
                pairingActive = false;
                pairingFailure = ReplyMessage(reply);
                await BestEffortCancel().ConfigureAwait(true);
                return;
            }
            pairing = parsed;
            if (parsed.Phase == PairingPhase.Paired)
            {
                pairingActive = false;
                pairingFailure = null;
                await CheckNowAsync().ConfigureAwait(true);
            }
            else if (parsed.Phase == PairingPhase.Failed)
            {
                pairingActive = false;
                pairingFailure = AppText.Sanitized(parsed.Error) ?? AppText.PairingNeedsAttention;
            }
            else if (parsed.Phase == PairingPhase.Idle)
            {
                pairingActive = false;
            }
        }

        public async Task CancelPairingAsync()
        {
            if (!pairingActive)
            {
                return;
            }
            pairCancelInFlight = true;
            try
            {
                pairingActive = false;
                pairing = PairingSnapshot.Idle();
                await Send(BrokerOps.PairCancel, null).ConfigureAwait(true);
            }
            finally
            {
                pairCancelInFlight = false;
            }
            await RefreshAsync().ConfigureAwait(true);
        }

        public async Task ForgetAsync()
        {
            if (!Dashboard().CanForget)
            {
                if (status != null && status.IsRunning)
                {
                    forgetBlocked = true;
                }
                return;
            }
            forgetInFlight = true;
            try
            {
                BrokerReply reply = await Send(BrokerOps.Forget, null).ConfigureAwait(true);
                ApplyBrokerState(reply);
                if (reply.Http == 409 || reply.Code == BrokerCodes.ElevatedActive)
                {
                    forgetBlocked = true;
                }
                else if (!reply.Ok || reply.Http != 200)
                {
                    error = ReplyMessage(reply);
                    retry = RetryTarget.Refresh;
                }
                else
                {
                    forgetBlocked = false;
                    pairingFailure = null;
                    tokenRejected = null;
                }
            }
            finally
            {
                forgetInFlight = false;
            }
            await RefreshAsync().ConfigureAwait(true);
        }

        // Turn on is the only action that asks Windows for administrator
        // approval. The broker shows the UAC prompt.
        public async Task TurnOnAsync()
        {
            if (!Dashboard().CanTurnOn)
            {
                return;
            }
            operation = TunnelOperation.Starting;
            error = null;
            try
            {
                Dictionary<string, string> extra = new Dictionary<string, string>(StringComparer.Ordinal);
                extra[BrokerProtocol.PingField] = PingEnabled ? "on" : "off";
                BrokerReply reply = await Send(BrokerOps.TurnOn, extra).ConfigureAwait(true);
                ApplyBrokerState(reply);
                if (!reply.Ok)
                {
                    if (reply.Http == 409 && reply.EngineErrorCode() == "phone_token_rejected")
                    {
                        tokenRejected = AppText.Sanitized(reply.EngineError()) ?? AppText.PhoneTokenRejected;
                    }
                    else
                    {
                        error = ReplyMessage(reply);
                        retry = RetryTarget.Start;
                    }
                }
            }
            finally
            {
                operation = TunnelOperation.None;
            }
            await RefreshAsync().ConfigureAwait(true);
        }

        public async Task TurnOffAsync()
        {
            if (!Dashboard().CanTurnOff)
            {
                return;
            }
            await StopCore().ConfigureAwait(true);
        }

        private async Task<bool> StopCore()
        {
            operation = TunnelOperation.Stopping;
            error = null;
            bool stopped;
            try
            {
                BrokerReply reply = await Send(BrokerOps.TurnOff, null).ConfigureAwait(true);
                ApplyBrokerState(reply);
                stopped = reply.Ok;
                if (!reply.Ok && reply.Code != BrokerCodes.StopUnconfirmed && reply.Code != BrokerCodes.ElevatedLost)
                {
                    error = ReplyMessage(reply);
                    retry = RetryTarget.Stop;
                }
            }
            finally
            {
                operation = TunnelOperation.None;
            }
            await RefreshAsync().ConfigureAwait(true);
            return stopped;
        }

        // Stop the tunnel, wait for a confirmed stop, then forget. A failed
        // stop is shown and Forget is not sent.
        public async Task TurnOffAndForgetAsync()
        {
            if (!Dashboard().CanTurnOff)
            {
                return;
            }
            bool stopped = await StopCore().ConfigureAwait(true);
            if (!stopped || phase != BrokerPhases.Idle || (status != null && status.IsRunning))
            {
                return;
            }
            forgetBlocked = false;
            await ForgetAsync().ConfigureAwait(true);
        }

        public async Task LoadActivityAsync(bool reset)
        {
            if (reset || logResetPending)
            {
                // A new engine run: read its log from the start. The old
                // lines are dropped, so a run in the same engine process
                // (whose sequence continues) is not shown twice.
                activity.Clear();
                activityNext = 0;
                logResetPending = false;
            }
            int run = logRun;
            if (activity.Count == 0)
            {
                ActivityState = ListState.Loading;
            }
            Dictionary<string, string> extra = new Dictionary<string, string>(StringComparer.Ordinal);
            extra[BrokerProtocol.SinceField] = BrokerProtocol.FormatSince(activityNext);
            BrokerReply reply = await Send(BrokerOps.Logs, extra).ConfigureAwait(true);
            if (run != logRun)
            {
                // The engine run changed while this request was out. The
                // answer may come from the old run; the next load reads the
                // new run from the start.
                ActivityState = activity.Count == 0 ? ListState.Loading : ListState.Loaded;
                return;
            }
            LogBatch batch;
            if (!reply.Ok || reply.Http != 200 || !LogBatch.TryParse(reply.Body, out batch))
            {
                ActivityState = activity.Count == 0 ? ListState.Unavailable : ListState.Loaded;
                return;
            }
            for (int index = 0; index < batch.Lines.Count; index++)
            {
                if (batch.Lines[index].Seq > activityNext || activityNext == 0)
                {
                    activity.Add(batch.Lines[index]);
                }
            }
            // The engine answers next = max(since, newest seq), so it never
            // moves the cursor back. A new engine run is found from the
            // status instead (TrackLogRun).
            activityNext = Math.Max(activityNext, batch.Next);
            if (activity.Count > MaxActivityLines)
            {
                activity.RemoveRange(0, activity.Count - MaxActivityLines);
            }
            ActivityState = activity.Count == 0 ? ListState.Empty : ListState.Loaded;
        }

        public async Task LoadFailuresAsync()
        {
            FailuresState = ListState.Loading;
            BrokerReply reply = await Send(BrokerOps.Failures, null).ConfigureAwait(true);
            FailureSnapshot parsed;
            if (!reply.Ok || reply.Http != 200 || !FailureSnapshot.TryParse(reply.Body, out parsed) || parsed.Demo)
            {
                Failures = new FailureSnapshot();
                FailuresState = ListState.Unavailable;
                return;
            }
            Failures = parsed;
            FailuresState = parsed.Groups.Count == 0 ? ListState.Empty : ListState.Loaded;
        }

        // Build the Copy diagnostics text from real engine answers. The
        // engine diagnostics hold no address, host, token, or key.
        public Task<string> DiagnosticsReportAsync(string appVersion, string windowsVersion)
        {
            return DiagnosticsReportCoreAsync(appVersion, windowsVersion);
        }

        private async Task<string> DiagnosticsReportCoreAsync(string appVersion, string windowsVersion)
        {
            BrokerReply diagnostics = await Send(BrokerOps.Diagnostics, null).ConfigureAwait(true);
            StringBuilder report = new StringBuilder();
            report.AppendLine("HotspotShade for Windows diagnostics");
            report.AppendLine(AppText.AppVersion + ": " + (appVersion ?? "unknown"));
            report.AppendLine(AppText.WindowsVersion + ": " + (windowsVersion ?? "unknown"));
            report.AppendLine(AppText.EngineRole + ": " + EngineRoleText());
            report.AppendLine("Broker phase: " + phase);
            DashboardModel model = Dashboard();
            report.AppendLine(AppText.Status + ": " + model.Title + ". " + model.Subtitle);
            if (status != null)
            {
                report.AppendLine("Running: " + (status.IsRunning ? "yes" : "no"));
                report.AppendLine("Paired: " + (status.Paired ? "yes" : "no"));
                report.AppendLine("Source device state: " + (status.PhoneStateRaw ?? "unknown"));
                report.AppendLine("Service state: " + (status.ServiceState ?? "ready"));
                report.AppendLine("Cleanup blocked: " + (status.CleanupBlocked == true ? "yes" : "no"));
                report.AppendLine("TTL audit failures: " + (status.TtlBad.HasValue ? status.TtlBad.Value.ToString(CultureInfo.InvariantCulture) : "unknown"));
            }
            if (diagnostics.Ok && diagnostics.Http == 200 && JsonValue.TryParseObject(diagnostics.Body, out _))
            {
                report.AppendLine("Engine diagnostics:");
                report.AppendLine(diagnostics.Body);
            }
            else
            {
                report.AppendLine("Engine diagnostics: unavailable (" + (diagnostics.Code.Length == 0 ? "http " + diagnostics.Http.ToString(CultureInfo.InvariantCulture) : diagnostics.Code) + ")");
            }
            // The broker log stays readable after the helper exits. Copy
            // diagnostics carries its tail, so a helper that stopped before
            // the app service connected still explains itself.
            BrokerLogSnapshot log = ReadBrokerLog(40);
            report.AppendLine("Engine helper log (last 40 lines):");
            if (log.Lines.Count == 0)
            {
                report.AppendLine("No engine helper log is present.");
            }
            else
            {
                for (int index = 0; index < log.Lines.Count; index++)
                {
                    report.AppendLine(log.Lines[index]);
                }
            }
            return report.ToString();
        }

        private BrokerLogSnapshot ReadBrokerLog(int maxLines)
        {
            try
            {
                if (BrokerLog == null)
                {
                    return BrokerLogSnapshot.Empty;
                }
                return BrokerLog.Read(maxLines) ?? BrokerLogSnapshot.Empty;
            }
            catch (Exception)
            {
                return BrokerLogSnapshot.Empty;
            }
        }

        public string FailureReport()
        {
            StringBuilder report = new StringBuilder();
            report.AppendLine("HotspotShade recent failures");
            report.AppendLine("Total: " + Failures.Total.ToString(CultureInfo.InvariantCulture)
                + ". Dropped: " + Failures.Dropped.ToString(CultureInfo.InvariantCulture) + ".");
            report.AppendLine(AppText.CountColumn + "\t" + AppText.KindColumn + "\t" + AppText.TargetColumn + "\t" + AppText.StageColumn + "\t" + AppText.ReasonColumn);
            for (int index = 0; index < Failures.Groups.Count; index++)
            {
                FailureGroup group = Failures.Groups[index];
                report.AppendLine(group.Count.ToString(CultureInfo.InvariantCulture) + "\t"
                    + FailureKind(group) + "\t" + FailureTarget(group) + "\t"
                    + (group.Phase ?? "-") + "\t" + FailureReason(group));
            }
            return report.ToString();
        }

        public static string FailureKind(FailureGroup group)
        {
            string proto = string.IsNullOrEmpty(group.Protocol) ? "-" : group.Protocol;
            return string.IsNullOrEmpty(group.Family) ? proto : proto + " " + group.Family;
        }

        public static string FailureTarget(FailureGroup group)
        {
            string host = !string.IsNullOrEmpty(group.Name) ? group.Name : (group.ExampleAddress ?? "-");
            return group.Port.HasValue ? host + ":" + group.Port.Value.ToString(CultureInfo.InvariantCulture) : host;
        }

        public static string FailureReason(FailureGroup group)
        {
            string reason = string.IsNullOrEmpty(group.Reason) ? "-" : group.Reason;
            return group.Code.HasValue ? reason + " (" + group.Code.Value.ToString(CultureInfo.InvariantCulture) + ")" : reason;
        }

        public string EngineRoleText()
        {
            if (source == BrokerSources.Elevated)
            {
                return AppText.EngineRoleElevated;
            }
            if (source == BrokerSources.User)
            {
                return AppText.EngineRoleUser;
            }
            return AppText.EngineRoleNone;
        }

        public DashboardInput BuildInput()
        {
            DashboardInput input = new DashboardInput();
            input.BrokerFailure = brokerFailure;
            if (input.BrokerFailure == null && !everAnswered && testData)
            {
                // The engine answered, but with test data. Waiting longer
                // will not help, so show it at once with Try again.
                input.BrokerFailure = AppText.TestDataEngine;
            }
            if (input.BrokerFailure == null && !everAnswered && lastFailureCode != null
                && (lastFailureCode == BrokerCodes.EngineMissing || utcNow() - createdAt >= FirstAnswerBudget))
            {
                input.BrokerFailure = AppText.BrokerMessage(lastFailureCode);
            }
            if (!string.IsNullOrEmpty(input.BrokerFailure))
            {
                BrokerLogSnapshot log = ReadBrokerLog(40);
                input.BrokerLogNote = BrokerLogText.StopLine(log);
            }
            input.EngineStarting = input.BrokerFailure == null && !everAnswered;
            input.TestDataEngine = testData;
            // Test data after a real status makes the status unavailable at
            // once instead of after UnavailableAfter.
            input.Freshness = testData && everAnswered ? StatusFreshness.Unavailable : Freshness();
            input.Operation = operation;
            if (input.Operation == TunnelOperation.None)
            {
                if (phase == BrokerPhases.Starting)
                {
                    input.Operation = TunnelOperation.Starting;
                }
                else if (phase == BrokerPhases.Stopping)
                {
                    input.Operation = TunnelOperation.Stopping;
                }
            }
            input.Error = error;
            input.RetryStartsTunnel = error != null && retry == RetryTarget.Start;
            input.TokenRejected = tokenRejected;
            input.ForgetBlocked = forgetBlocked;
            input.ForgetInFlight = forgetInFlight;
            input.PairingStartInFlight = pairStartInFlight;
            input.PairingCancelInFlight = pairCancelInFlight;
            input.PairingFailure = pairingFailure;
            input.ElevatedSource = source == BrokerSources.Elevated;
            if (pairingActive)
            {
                input.Pairing = pairing.Phase == PairingPhase.Confirm ? PairingView.Confirming : PairingView.Starting;
            }
            else if (pairing.Phase == PairingPhase.Paired)
            {
                input.Pairing = PairingView.Paired;
            }
            else if (pairing.Phase == PairingPhase.Failed)
            {
                input.Pairing = PairingView.Failed;
            }
            if (phase == BrokerPhases.StopUnconfirmed)
            {
                input.CleanupPending = AppText.StopUnconfirmed;
                input.Cleanup = CleanupKind.Retryable;
            }
            else if (phase == BrokerPhases.ElevatedLost)
            {
                input.CleanupPending = AppText.ElevatedLost;
                input.Cleanup = CleanupKind.Final;
            }
            if (turnOn != BrokerTurnOn.Available)
            {
                input.TurnOnUnavailable = AppText.BrokerMessage(turnOn);
            }
            if (status != null)
            {
                input.Running = status.IsRunning;
                input.Paired = status.Paired;
                input.Phone = status.Phone;
                input.PhoneMessage = status.PhoneMessage;
                input.TrustedBySource = status.TrustedBySource;
                input.Forget = status.Forget;
                input.Health = status.Health;
                if (status.IsRunning)
                {
                    if (status.IcmpEnabled.HasValue)
                    {
                        input.PingLine = status.IcmpEnabled.Value ? AppText.PingOn : AppText.PingOff;
                    }
                    if (status.PhoneConnections.HasValue)
                    {
                        input.ConnectionsLabel = AppText.Connections(status.PhoneConnections.Value);
                    }
                    if (status.TtlBad.HasValue && status.TtlBad.Value > 0)
                    {
                        input.TtlAuditLine = AppText.TtlAudit(status.TtlBad.Value);
                    }
                }
                string stop = AppText.Sanitized(status.LastStopMessage);
                if (!string.IsNullOrEmpty(stop))
                {
                    input.LastStopLine = AppText.LastStop(stop);
                }
                input.LastCheckedText = CheckedText(status.PhoneCheckedAt);
                input.SourceDeviceWarning = sourceTroubleSince.HasValue
                    && utcNow() - sourceTroubleSince.Value >= SourceWarningAfter;
            }
            return input;
        }

        public DashboardModel Dashboard()
        {
            return DashboardPresenter.Build(BuildInput());
        }

        private string CheckedText(double? checkedAt)
        {
            if (!checkedAt.HasValue)
            {
                return null;
            }
            double now = (utcNow() - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
            double age = now - checkedAt.Value;
            if (age < 0)
            {
                age = 0;
            }
            if (age < 5)
            {
                return AppText.CheckedJustNow;
            }
            if (age < 60)
            {
                return AppText.CheckedSeconds((int)age);
            }
            if (age < 3600 * 24)
            {
                return AppText.CheckedMinutes((int)(age / 60));
            }
            return null;
        }

        // Marks a new engine run when the status source or started_at
        // changes. The next activity load then starts again from 0.
        private void TrackLogRun(string runSource, double? startedAt)
        {
            if (logRunKnown && (runSource != logRunSource || startedAt != logRunStartedAt))
            {
                logResetPending = true;
                logRun++;
            }
            logRunKnown = true;
            logRunSource = runSource;
            logRunStartedAt = startedAt;
        }

        private void TrackSourceTrouble()
        {
            bool trouble = status != null && status.IsRunning
                && (status.Phone == PhoneState.NotResponding || status.Phone == PhoneState.NotRunning || status.Phone == PhoneState.NoHotspot);
            if (!trouble)
            {
                sourceTroubleSince = null;
            }
            else if (!sourceTroubleSince.HasValue)
            {
                sourceTroubleSince = utcNow();
            }
        }

        private void ApplyBrokerState(BrokerReply reply)
        {
            if (reply.Code == BrokerCodes.Closed || reply.Code == BrokerCodes.NotConnected)
            {
                return;
            }
            source = reply.Source;
            phase = reply.Phase;
            turnOn = reply.TurnOn;
        }

        private async Task BestEffortCancel()
        {
            try
            {
                await Send(BrokerOps.PairCancel, null).ConfigureAwait(true);
            }
            catch (Exception)
            {
            }
        }

        private static string ReplyMessage(BrokerReply reply)
        {
            if (reply.Http >= 400)
            {
                string engine = AppText.Sanitized(reply.EngineError());
                if (!string.IsNullOrEmpty(engine))
                {
                    return engine;
                }
            }
            return AppText.BrokerMessage(reply.Code);
        }

        private async Task<BrokerReply> Send(string op, IDictionary<string, string> extra)
        {
            Dictionary<string, string> fields = new Dictionary<string, string>(StringComparer.Ordinal);
            fields[BrokerProtocol.OpField] = op;
            if (extra != null)
            {
                foreach (KeyValuePair<string, string> pair in extra)
                {
                    fields[pair.Key] = pair.Value;
                }
            }
            BrokerReply reply;
            try
            {
                reply = await channel.SendAsync(fields).ConfigureAwait(true);
            }
            catch (Exception)
            {
                reply = BrokerReply.Failure(BrokerCodes.Closed);
            }
            return reply ?? BrokerReply.Failure(BrokerCodes.Closed);
        }
    }
}
