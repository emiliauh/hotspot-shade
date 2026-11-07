using System;
using System.Threading;
using System.Threading.Tasks;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.Core.Engine
{
    public enum EngineConnectionState
    {
        NotConnected,
        Connecting,
        Available,
        Unavailable,
        Closed
    }

    public sealed class EngineCommandResult
    {
        private EngineCommandResult(
            bool ok,
            bool confirmed,
            bool outcomeUnknown,
            string code,
            string message,
            EngineStatus status)
        {
            Ok = ok;
            Confirmed = confirmed;
            OutcomeUnknown = outcomeUnknown;
            Code = code ?? "";
            Message = message ?? "";
            Status = status;
        }

        public bool Ok { get; private set; }

        public bool Confirmed { get; private set; }

        // True when the request may have reached the engine but no reply was
        // validated. The operation is not reported as applied and not reported
        // as cleanly refused. A later status read is the only way to learn the
        // result.
        public bool OutcomeUnknown { get; private set; }

        public string Code { get; private set; }

        public string Message { get; private set; }

        public EngineStatus Status { get; private set; }

        internal static EngineCommandResult Success(EngineStatus status, bool confirmed, string message)
        {
            return new EngineCommandResult(true, confirmed, false, "", message, status);
        }

        internal static EngineCommandResult Failure(string code, EngineStatus status)
        {
            string fixedCode = EngineProtocol.IsKnownErrorCode(code)
                ? code
                : EngineProtocol.ErrorCodes.Internal;
            return new EngineCommandResult(
                false,
                false,
                false,
                fixedCode,
                EngineProtocol.ErrorText(fixedCode),
                status);
        }

        // A failure that needs a more specific sentence than the wire code
        // carries. The launch path uses it, because a launch failure is not a
        // broker reply. The code is still one fixed known code.
        internal static EngineCommandResult FailureWithText(string code, string message, EngineStatus status)
        {
            string fixedCode = EngineProtocol.IsKnownErrorCode(code)
                ? code
                : EngineProtocol.ErrorCodes.Internal;
            return new EngineCommandResult(
                false,
                false,
                false,
                fixedCode,
                string.IsNullOrEmpty(message) ? EngineProtocol.ErrorText(fixedCode) : message,
                status);
        }

        // An ambiguous outcome. The request may already have been applied. The
        // result is never a success and never a clean refusal.
        internal static EngineCommandResult Unknown(string code, EngineStatus status)
        {
            string fixedCode = EngineProtocol.IsKnownErrorCode(code)
                ? code
                : EngineProtocol.ErrorCodes.Internal;
            return new EngineCommandResult(
                false,
                false,
                true,
                fixedCode,
                UnknownOutcomeText,
                status);
        }

        private const string UnknownOutcomeText =
            "The engine may have received this request, but the app got no confirmation. Check the status before you try again.";
    }

    // The transport seam. A UWP AppServiceConnection adapter, a test fake, and
    // the future full-trust broker all implement the same request and reply
    // object. No transport detail leaks into the state machine.
    public interface IEngineBroker
    {
        Task<EngineReply> SendAsync(EngineRequest request, CancellationToken cancellationToken);

        Task CloseAsync();
    }

    // The honest default for this build. The package has no app service
    // extension and no full-trust helper, so every request fails closed.
    public sealed class UnavailableEngineBroker : IEngineBroker
    {
        public Task<EngineReply> SendAsync(EngineRequest request, CancellationToken cancellationToken)
        {
            return Task.FromResult(EngineReply.Failure(EngineProtocol.ErrorCodes.HelperMissing));
        }

        public Task CloseAsync()
        {
            return Task.CompletedTask;
        }
    }

    // The app-side engine state machine. It never claims a tunnel state from a
    // request acknowledgement alone. A start or stop becomes visible only
    // after a fresh status confirms it. A missing, stale, malformed, or
    // restarted broker never produces an On claim and never restarts a tunnel.
    public sealed class EngineSession
    {
        private readonly IEngineBroker broker;
        private readonly IEngineClock clock;
        private readonly EngineServiceCallBudgets budgets;
        private readonly string sessionId;

        private int busy;
        private int closed;
        private int closeNotified;
        private EngineConnectionState connection = EngineConnectionState.NotConnected;
        private string instanceId;
        private EngineStatus status;
        private string lastCode = "";
        private EngineStopReason lastStop = EngineStopReason.None;
        private DateTimeOffset? lastStopAt;
        private bool controlLost;
        private bool pendingStart;
        private bool pendingStop;
        private bool pendingForget;
        private bool startedByApp;

        public EngineSession(IEngineBroker broker, IEngineClock clock)
            : this(broker, clock, EngineServiceCallBudgets.Default)
        {
        }

        // One budget for every operation. This keeps the diagnostic and test
        // form. Production uses the per-operation table.
        public EngineSession(IEngineBroker broker, IEngineClock clock, TimeSpan callTimeout)
            : this(broker, clock, EngineServiceCallBudgets.Uniform(callTimeout))
        {
        }

        // One app-side call budget per operation. A start and a stop outlive
        // the short request budget, so the app never aborts a long operation
        // that the service is still completing.
        public EngineSession(
            IEngineBroker broker,
            IEngineClock clock,
            EngineServiceCallBudgets budgets)
        {
            if (broker == null)
            {
                throw new ArgumentNullException("broker");
            }
            if (clock == null)
            {
                throw new ArgumentNullException("clock");
            }
            if (budgets == null)
            {
                throw new ArgumentNullException("budgets");
            }
            this.broker = broker;
            this.clock = clock;
            this.budgets = budgets;
            sessionId = Guid.NewGuid().ToString("N");
        }

        public EngineServiceCallBudgets Budgets
        {
            get { return budgets; }
        }

        public string SessionId
        {
            get { return sessionId; }
        }

        public EngineConnectionState Connection
        {
            get { return connection; }
        }

        public EngineStatus Status
        {
            get { return status; }
        }

        public bool HasStatus
        {
            get { return status != null; }
        }

        public bool IsClosed
        {
            get { return Volatile.Read(ref closed) != 0; }
        }

        public bool IsBusy
        {
            get { return Volatile.Read(ref busy) != 0; }
        }

        public bool ControlLost
        {
            get { return controlLost; }
        }

        public string LastFailureCode
        {
            get { return lastCode; }
        }

        public string LastFailureMessage
        {
            get
            {
                return string.IsNullOrEmpty(lastCode)
                    ? ""
                    : EngineProtocol.ErrorText(lastCode);
            }
        }

        public EngineStopReason LastStopReason
        {
            get { return lastStop; }
        }

        public DateTimeOffset? LastStopAt
        {
            get { return lastStopAt; }
        }

        public bool StartedByApp
        {
            get { return startedByApp; }
        }

        public bool HasPendingAction
        {
            get { return pendingStart || pendingStop || pendingForget; }
        }

        // A running tunnel is shown only when the app holds a recent status
        // and no start, stop, or control failure is outstanding.
        public bool CanClaimRunning
        {
            get
            {
                return !IsClosed
                    && !controlLost
                    && !pendingStart
                    && !pendingStop
                    && !pendingForget
                    && status != null
                    && status.Running
                    && Freshness != EngineFreshness.Unavailable;
            }
        }

        public EngineFreshness Freshness
        {
            get
            {
                if (IsClosed || controlLost || status == null)
                {
                    return EngineFreshness.Unavailable;
                }
                return status.FreshnessAt(clock.Now);
            }
        }

        public bool CanStart
        {
            get
            {
                return !IsClosed
                    && connection == EngineConnectionState.Available
                    && !controlLost
                    && !pendingStart
                    && !pendingStop
                    && !pendingForget
                    && status != null
                    && Freshness == EngineFreshness.Fresh
                    && !status.Running
                    && status.Cleanup == EngineCleanup.Ok
                    && status.Paired
                    && status.SourcePresent
                    && status.Engine == EngineRunState.Ready;
            }
        }

        public bool CanStop
        {
            get
            {
                return !IsClosed
                    && (connection == EngineConnectionState.Available
                        || connection == EngineConnectionState.Unavailable);
            }
        }

        public bool CanRefresh
        {
            get
            {
                return !IsClosed
                    && connection != EngineConnectionState.NotConnected
                    && connection != EngineConnectionState.Closed;
            }
        }

        public bool CanForget
        {
            get
            {
                return !IsClosed
                    && connection == EngineConnectionState.Available
                    && !controlLost
                    && !pendingStart
                    && !pendingStop
                    && !pendingForget
                    && status != null
                    && Freshness == EngineFreshness.Fresh
                    && !status.Running
                    && status.Paired;
            }
        }

        public async Task<EngineCommandResult> ConnectAsync()
        {
            if (IsClosed)
            {
                return ClosedResult();
            }
            if (!TryEnter())
            {
                return BusyResult();
            }
            try
            {
                connection = EngineConnectionState.Connecting;
                lastCode = "";
                EngineReply hello = await SendAsync(
                    new EngineRequest(EngineProtocol.Operations.Hello, sessionId, false))
                    .ConfigureAwait(false);
                if (IsClosed)
                {
                    return ClosedResult();
                }
                if (!hello.Ok)
                {
                    return MarkUnavailable(hello.Code, hello.OutcomeUnknown);
                }

                string helloInstance;
                string helloCode;
                if (!EngineWire.TryReadHello(hello, out helloInstance, out helloCode))
                {
                    return MarkUnavailable(helloCode);
                }

                EngineReply reply = await SendAsync(
                    new EngineRequest(EngineProtocol.Operations.Status, sessionId, false))
                    .ConfigureAwait(false);
                if (IsClosed)
                {
                    return ClosedResult();
                }
                if (!reply.Ok)
                {
                    return MarkUnavailable(reply.Code, reply.OutcomeUnknown);
                }

                EngineStatus next;
                string statusCode;
                if (!EngineStatus.TryParse(reply, clock.Now, out next, out statusCode))
                {
                    return MarkUnavailable(statusCode, false);
                }
                if (next.InstanceId != helloInstance)
                {
                    return MarkUnavailable(EngineProtocol.ErrorCodes.EngineRestarted, false);
                }

                instanceId = helloInstance;
                AdoptStatus(next);
                connection = EngineConnectionState.Available;
                controlLost = false;
                lastCode = "";
                return EngineCommandResult.Success(status, true, "Connected to the engine.");
            }
            finally
            {
                Exit();
            }
        }

        public async Task<EngineCommandResult> RefreshAsync()
        {
            if (IsClosed)
            {
                return ClosedResult();
            }
            if (connection == EngineConnectionState.NotConnected)
            {
                return EngineCommandResult.Failure(EngineProtocol.ErrorCodes.NotConnected, status);
            }
            if (!TryEnter())
            {
                return BusyResult();
            }
            try
            {
                EngineReply reply = await SendAsync(
                    new EngineRequest(EngineProtocol.Operations.Status, sessionId, false))
                    .ConfigureAwait(false);
                if (IsClosed)
                {
                    return ClosedResult();
                }
                if (!reply.Ok)
                {
                    return MarkUnavailable(reply.Code, reply.OutcomeUnknown);
                }

                EngineStatus next;
                string statusCode;
                if (!EngineStatus.TryParse(reply, clock.Now, out next, out statusCode))
                {
                    return MarkUnavailable(statusCode, false);
                }
                if (instanceId != null && next.InstanceId != instanceId)
                {
                    return MarkUnavailable(EngineProtocol.ErrorCodes.EngineRestarted, false);
                }

                instanceId = next.InstanceId;
                AdoptStatus(next);
                connection = EngineConnectionState.Available;
                controlLost = false;
                lastCode = "";
                return EngineCommandResult.Success(status, true, "Status read.");
            }
            finally
            {
                Exit();
            }
        }

        public async Task<EngineCommandResult> StartAsync(bool ping)
        {
            if (IsClosed)
            {
                return ClosedResult();
            }
            if (!TryEnter())
            {
                return BusyResult();
            }
            try
            {
                EngineCommandResult refusal = StartRefusal();
                if (refusal != null)
                {
                    return refusal;
                }

                EngineReply reply = await SendAsync(
                    new EngineRequest(EngineProtocol.Operations.Start, sessionId, ping))
                    .ConfigureAwait(false);
                if (IsClosed)
                {
                    return ClosedResult();
                }
                if (!reply.Ok)
                {
                    lastCode = reply.Code;
                    if (IsAmbiguousReply(reply))
                    {
                        // The start may already be applied. Keep the action
                        // pending so no view claims a running or idle tunnel
                        // before a fresh status read.
                        pendingStart = true;
                        pendingStop = false;
                        pendingForget = false;
                        return EngineCommandResult.Unknown(reply.Code, status);
                    }
                    return EngineCommandResult.Failure(reply.Code, status);
                }

                pendingStart = true;
                pendingStop = false;
                pendingForget = false;
                lastCode = "";
                return EngineCommandResult.Success(
                    status,
                    false,
                    "Start requested. Waiting for the engine status.");
            }
            finally
            {
                Exit();
            }
        }

        public async Task<EngineCommandResult> StopAsync()
        {
            if (IsClosed)
            {
                return ClosedResult();
            }
            if (connection == EngineConnectionState.NotConnected)
            {
                return EngineCommandResult.Failure(EngineProtocol.ErrorCodes.NotConnected, status);
            }
            if (!TryEnter())
            {
                return BusyResult();
            }
            try
            {
                EngineReply reply = await SendAsync(
                    new EngineRequest(EngineProtocol.Operations.Stop, sessionId, false))
                    .ConfigureAwait(false);
                if (IsClosed)
                {
                    return ClosedResult();
                }
                if (!reply.Ok)
                {
                    lastCode = reply.Code;
                    if (IsAmbiguousReply(reply))
                    {
                        // The stop may already be applied. Keep the action
                        // pending so no view claims a running or idle tunnel
                        // before a fresh status read.
                        pendingStop = true;
                        pendingStart = false;
                        pendingForget = false;
                        return EngineCommandResult.Unknown(reply.Code, status);
                    }
                    return EngineCommandResult.Failure(reply.Code, status);
                }

                connection = EngineConnectionState.Available;
                controlLost = false;
                pendingStop = true;
                pendingStart = false;
                pendingForget = false;
                lastCode = "";
                return EngineCommandResult.Success(
                    status,
                    false,
                    "Stop requested. Waiting for the engine status.");
            }
            finally
            {
                Exit();
            }
        }

        public async Task<EngineCommandResult> ForgetAsync()
        {
            if (IsClosed)
            {
                return ClosedResult();
            }
            if (!TryEnter())
            {
                return BusyResult();
            }
            try
            {
                if (connection != EngineConnectionState.Available || controlLost)
                {
                    return EngineCommandResult.Failure(
                        controlLost
                            ? EngineProtocol.ErrorCodes.EngineUnavailable
                            : EngineProtocol.ErrorCodes.NotConnected,
                        status);
                }
                if (status == null)
                {
                    return EngineCommandResult.Failure(EngineProtocol.ErrorCodes.NoStatus, status);
                }
                if (status.Running || pendingStart || pendingStop || pendingForget)
                {
                    return EngineCommandResult.Failure(
                        EngineProtocol.ErrorCodes.ForgetWhileRunning,
                        status);
                }
                if (Freshness != EngineFreshness.Fresh)
                {
                    return EngineCommandResult.Failure(EngineProtocol.ErrorCodes.StaleStatus, status);
                }
                if (!status.Paired)
                {
                    return EngineCommandResult.Failure(EngineProtocol.ErrorCodes.NotPaired, status);
                }

                EngineReply reply = await SendAsync(
                    new EngineRequest(EngineProtocol.Operations.Forget, sessionId, false))
                    .ConfigureAwait(false);
                if (IsClosed)
                {
                    return ClosedResult();
                }
                if (!reply.Ok)
                {
                    lastCode = reply.Code;
                    if (IsAmbiguousReply(reply))
                    {
                        pendingForget = true;
                        return EngineCommandResult.Unknown(reply.Code, status);
                    }
                    return EngineCommandResult.Failure(reply.Code, status);
                }

                lastCode = "";
                pendingForget = true;
                return EngineCommandResult.Success(
                    status,
                    false,
                    "Forget requested. Waiting for the engine status.");
            }
            finally
            {
                Exit();
            }
        }

        // Ask the broker to stop the engine before the app exits. The broker
        // also watches parent liveness; this call is a fast path, not the
        // safety boundary. The result never claims that the tunnel is off.
        public async Task<EngineCommandResult> ShutdownAsync()
        {
            if (IsClosed)
            {
                return ClosedResult();
            }
            if (!TryEnter())
            {
                return BusyResult();
            }
            try
            {
                if (connection == EngineConnectionState.NotConnected)
                {
                    Close();
                    return EngineCommandResult.Success(
                        status,
                        true,
                        "The engine connection is closed.");
                }

                EngineReply reply = await SendAsync(
                    new EngineRequest(EngineProtocol.Operations.Shutdown, sessionId, false))
                    .ConfigureAwait(false);
                Close();
                if (!reply.Ok)
                {
                    lastCode = reply.Code;
                    return IsAmbiguousReply(reply)
                        ? EngineCommandResult.Unknown(reply.Code, status)
                        : EngineCommandResult.Failure(reply.Code, status);
                }
                lastCode = "";
                return EngineCommandResult.Success(
                    status,
                    false,
                    "Exit requested. The broker stops the engine when the app exits.");
            }
            finally
            {
                Exit();
            }
        }

        // The synchronous close path. It always works, even when the engine
        // does not answer. It never sends a request and never claims a stop.
        public void Close()
        {
            Volatile.Write(ref closed, 1);
            connection = EngineConnectionState.Closed;
            if (Interlocked.Exchange(ref closeNotified, 1) == 0)
            {
                try
                {
                    Task closing = broker.CloseAsync();
                    Observe(closing);
                }
                catch (Exception)
                {
                    // A transport that throws while closing cannot change the
                    // local closed state. The broker still owns the tunnel.
                }
            }
        }

        // A timeout is the one validated failure that does not prove the
        // request was refused. The service can answer timeout for a canceled
        // start or stop whose work may still have run. Treat it, and every
        // broker-reported unknown outcome, as ambiguous for an operation that
        // changes state.
        private static bool IsAmbiguousReply(EngineReply reply)
        {
            return reply.OutcomeUnknown
                || string.Equals(
                    reply.Code,
                    EngineProtocol.ErrorCodes.Timeout,
                    StringComparison.Ordinal);
        }

        private EngineCommandResult StartRefusal()
        {
            if (connection == EngineConnectionState.Unavailable)
            {
                return EngineCommandResult.Failure(
                    EngineProtocol.ErrorCodes.EngineUnavailable,
                    status);
            }
            if (connection != EngineConnectionState.Available)
            {
                return EngineCommandResult.Failure(
                    EngineProtocol.ErrorCodes.NotConnected,
                    status);
            }
            if (controlLost)
            {
                return EngineCommandResult.Failure(
                    EngineProtocol.ErrorCodes.EngineUnavailable,
                    status);
            }
            if (pendingStart || pendingStop || pendingForget)
            {
                return EngineCommandResult.Failure(EngineProtocol.ErrorCodes.Busy, status);
            }
            if (status == null)
            {
                return EngineCommandResult.Failure(EngineProtocol.ErrorCodes.NoStatus, status);
            }
            if (Freshness != EngineFreshness.Fresh)
            {
                return EngineCommandResult.Failure(
                    EngineProtocol.ErrorCodes.StaleStatus,
                    status);
            }
            if (status.Running)
            {
                return EngineCommandResult.Failure(
                    EngineProtocol.ErrorCodes.AlreadyRunning,
                    status);
            }
            // The service refuses a start on an unconfirmed cleanup gate. The
            // app must not offer the action while the gate blocks it, and it
            // must show the same fixed reason the service would return.
            if (status.Cleanup == EngineCleanup.Failed)
            {
                return EngineCommandResult.Failure(
                    EngineProtocol.ErrorCodes.CleanupBlocked,
                    status);
            }
            if (status.Cleanup == EngineCleanup.Pending)
            {
                return EngineCommandResult.Failure(
                    EngineProtocol.ErrorCodes.CleanupPending,
                    status);
            }
            if (status.Cleanup == EngineCleanup.Unknown)
            {
                return EngineCommandResult.Failure(
                    EngineProtocol.ErrorCodes.CleanupUnknown,
                    status);
            }
            if (!status.Paired)
            {
                return EngineCommandResult.Failure(EngineProtocol.ErrorCodes.NotPaired, status);
            }
            if (!status.SourcePresent)
            {
                return EngineCommandResult.Failure(
                    EngineProtocol.ErrorCodes.SourceMissing,
                    status);
            }
            if (status.Engine != EngineRunState.Ready)
            {
                return EngineCommandResult.Failure(EngineProtocol.ErrorCodes.NotReady, status);
            }
            return null;
        }

        private void AdoptStatus(EngineStatus next)
        {
            DateTimeOffset now = clock.Now;
            if (status != null && status.Running && !next.Running)
            {
                EngineStopReason reason = next.Stop;
                if (reason == EngineStopReason.None)
                {
                    reason = pendingStop ? EngineStopReason.User : EngineStopReason.Unknown;
                }
                lastStop = reason;
                lastStopAt = now;
            }
            else if (status == null && next.Stop != EngineStopReason.None)
            {
                // The first status of this app run can already report the stop
                // that ended the previous run. Show the same sentence the
                // service reports instead of dropping it until the next
                // running-to-stopped change.
                lastStop = next.Stop;
                lastStopAt = now;
            }

            if (next.Running && pendingStart)
            {
                startedByApp = true;
            }
            if (!next.Running)
            {
                startedByApp = false;
            }

            pendingStart = false;
            pendingStop = false;
            pendingForget = false;
            status = next;
        }

        private EngineCommandResult MarkUnavailable(string code)
        {
            return MarkUnavailable(code, false);
        }

        private EngineCommandResult MarkUnavailable(string code, bool outcomeUnknown)
        {
            connection = EngineConnectionState.Unavailable;
            controlLost = true;
            pendingStart = false;
            pendingStop = false;
            pendingForget = false;
            lastCode = EngineProtocol.IsKnownErrorCode(code)
                ? code
                : EngineProtocol.ErrorCodes.BadResponse;
            return outcomeUnknown
                ? EngineCommandResult.Unknown(lastCode, status)
                : EngineCommandResult.Failure(lastCode, status);
        }

        private async Task<EngineReply> SendAsync(EngineRequest request)
        {
            TimeSpan budget = budgets.For(request.Operation);
            using (CancellationTokenSource timeout = new CancellationTokenSource())
            {
                Task<EngineReply> call;
                try
                {
                    call = broker.SendAsync(request, timeout.Token);
                }
                catch (Exception)
                {
                    // The request was handed to the broker but the broker threw.
                    // It may have been delivered, so this is never a clean
                    // refusal.
                    return EngineReply.UnknownOutcome(EngineProtocol.ErrorCodes.EngineUnavailable);
                }

                if (call == null)
                {
                    // A broker that returns no task may already have sent the
                    // request. It cannot prove a clean refusal.
                    return EngineReply.UnknownOutcome(EngineProtocol.ErrorCodes.BadResponse);
                }

                Task delay = Task.Delay(budget, timeout.Token);
                Task completed = await Task.WhenAny(call, delay).ConfigureAwait(false);
                if (completed != call)
                {
                    // The broker gets a cancelled token so a transport can end
                    // the call. Do not wait for it and do not trust a late
                    // reply. The request may already have reached the engine,
                    // so the outcome is unknown, never a clean timeout refusal.
                    timeout.Cancel();
                    Observe(call);
                    return EngineReply.UnknownOutcome(EngineProtocol.ErrorCodes.Timeout);
                }

                timeout.Cancel();
                try
                {
                    EngineReply reply = await call.ConfigureAwait(false);
                    if (reply == null)
                    {
                        return EngineReply.UnknownOutcome(EngineProtocol.ErrorCodes.BadResponse);
                    }
                    // Every reply crosses the same strict boundary. A reply
                    // with an unknown field, a credential key, a bad value, or
                    // an inconsistent success or failure shape becomes a
                    // fixed error and is never shown as engine state.
                    EngineReply checkedReply;
                    string checkedCode;
                    if (!EngineWire.TryReadReply(reply.Fields, out checkedReply, out checkedCode))
                    {
                        // The request was sent and a reply arrived that the
                        // session cannot trust. The outcome stays unknown.
                        return EngineReply.UnknownOutcome(checkedCode);
                    }
                    // The wire shape carries no ambiguity flag. Copy it from
                    // the broker reply so a validated failure does not become
                    // a clean refusal at this second validation.
                    return reply.OutcomeUnknown
                        ? checkedReply.KeepOutcomeUnknown()
                        : checkedReply;
                }
                catch (Exception)
                {
                    // The broker task failed after the request was handed to
                    // it. It cannot prove a clean refusal.
                    return EngineReply.UnknownOutcome(
                        EngineProtocol.ErrorCodes.EngineUnavailable);
                }
            }
        }

        private static void Observe(Task task)
        {
            if (task == null)
            {
                return;
            }
            task.ContinueWith(
                delegate(Task finished)
                {
                    Exception error = finished.Exception;
                    if (error != null)
                    {
                        GC.KeepAlive(error);
                    }
                },
                CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted,
                TaskScheduler.Default);
        }

        private bool TryEnter()
        {
            if (IsClosed)
            {
                return false;
            }
            return Interlocked.CompareExchange(ref busy, 1, 0) == 0;
        }

        private void Exit()
        {
            Interlocked.Exchange(ref busy, 0);
        }

        private EngineCommandResult BusyResult()
        {
            lastCode = EngineProtocol.ErrorCodes.Busy;
            return EngineCommandResult.Failure(EngineProtocol.ErrorCodes.Busy, status);
        }

        private EngineCommandResult ClosedResult()
        {
            lastCode = EngineProtocol.ErrorCodes.Closed;
            return EngineCommandResult.Failure(EngineProtocol.ErrorCodes.Closed, status);
        }
    }
}
