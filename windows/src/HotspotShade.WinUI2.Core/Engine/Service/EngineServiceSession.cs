using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace HotspotShade.WinUI2.Core.Engine.Service
{
    public sealed class EngineServiceResult
    {
        private EngineServiceResult(bool ok, string code)
        {
            Ok = ok;
            Code = ok ? "" : (EngineProtocol.IsKnownErrorCode(code)
                ? code
                : EngineProtocol.ErrorCodes.Internal);
        }

        public bool Ok { get; private set; }

        public string Code { get; private set; }

        public static EngineServiceResult Success()
        {
            return new EngineServiceResult(true, "");
        }

        public static EngineServiceResult Failure(string code)
        {
            return new EngineServiceResult(false, code);
        }

        // A start or stop whose outcome could not be confirmed. The caller
        // must keep or set the durable cleanup latch instead of treating the
        // operation as a clean success.
        public static EngineServiceResult CleanupUnknown()
        {
            return new EngineServiceResult(false, EngineProtocol.ErrorCodes.CleanupUnknown);
        }
    }

    // The service seam to the engine supervisor. A future host implements it
    // with the launch gate, the process handle, and the final-frame reader. A
    // test fake implements it here. It starts no process and opens no pipe.
    public interface IEngineServiceBackend
    {
        EngineServiceStatus ReadStatus();

        EngineServiceResult Start(bool ping);

        EngineServiceResult Stop(EngineServiceStopReason reason);
    }

    // Optional status contract for backends that can name a refusal without
    // returning an unverified status sample.
    public interface IEngineServiceStatusErrorSource
    {
        bool TryReadStatus(out EngineServiceStatus status, out string code);
    }

    // An optional backend seam for a start or stop that can observe
    // cancellation. The synchronous interface above stays valid so existing
    // hosts keep compiling. A host that implements this interface must return
    // only when it knows whether the launch or stop took effect. If the token
    // cancels while the result is unknown it must throw
    // OperationCanceledException or return a timeout failure; the session turns
    // either answer into cleanup_unknown, never success. The host still owns
    // the durable record and must set its cleanup latch to unknown for that
    // answer.
    public interface IEngineServiceCancellableBackend
    {
        EngineServiceResult Start(bool ping, CancellationToken cancellationToken);

        EngineServiceResult Stop(
            EngineServiceStopReason reason,
            CancellationToken cancellationToken);
    }

    public enum EngineServiceSessionState
    {
        NoSession,
        Active,
        Stopped,
        Closed
    }

    // The service-side session state machine. It binds one session on a successful hello,
    // never launches an engine for hello or status, refuses a second session,
    // runs one stop with an explicit reason on parent loss, service stop,
    // logoff, or shutdown, and never restarts anything on its own.
    //
    // Requests are serialized by one gate. A request that is waiting for the
    // gate can be cancelled by its caller and returns timeout. The backend
    // call is synchronous and owns its own bound. A backend that implements
    // IEngineServiceCancellableBackend also receives the caller token and the
    // optional session timeout; a cancelled or timed-out start or stop is
    // cleanup_unknown, never success. Within one started
    // generation, the first stop trigger wins and no later trigger calls the
    // backend again. A successful new start begins a new generation and resets
    // that stop latch.
    //
    // This is a foundation. The credential is represented by one held flag.
    // The token itself is not stored here. A future credential.set path owns
    // the token buffer and clears it with this session. A new session is not
    // phase-one paired until a credential is held. A session built without a
    // durable state gate refuses every start with cleanup_unknown.
    public sealed class EngineServiceSession
    {
        private readonly string instanceId;
        private readonly IEngineServiceBackend backend;
        private readonly IEngineClock clock;
        private readonly EngineServiceStateGate stateGate;
        private readonly TimeSpan backendTimeout;
        private readonly SemaphoreSlim gate = new SemaphoreSlim(1, 1);
        private volatile EngineServiceSessionState state = EngineServiceSessionState.NoSession;
        private volatile string sessionId;
        private volatile bool credentialHeld;
        private volatile bool pairingCleared = true;
        private volatile bool stopRan;
        private volatile EngineServiceResult stopResult;
        private volatile EngineServiceStopReason lastStop = EngineServiceStopReason.None;

        public EngineServiceSession(
            string instanceId,
            IEngineServiceBackend backend,
            IEngineClock clock)
            : this(instanceId, backend, clock, EngineServiceStateGate.Missing)
        {
        }

        public EngineServiceSession(
            string instanceId,
            IEngineServiceBackend backend,
            IEngineClock clock,
            EngineServiceStateGate stateGate)
            : this(instanceId, backend, clock, stateGate, Timeout.InfiniteTimeSpan)
        {
        }

        public EngineServiceSession(
            string instanceId,
            IEngineServiceBackend backend,
            IEngineClock clock,
            EngineServiceStateGate stateGate,
            TimeSpan backendTimeout)
        {
            if (!EngineProtocol.IsValidInstanceId(instanceId))
            {
                throw new ArgumentException("invalid instance id", "instanceId");
            }
            if (backend == null)
            {
                throw new ArgumentNullException("backend");
            }
            if (clock == null)
            {
                throw new ArgumentNullException("clock");
            }
            if (backendTimeout != Timeout.InfiniteTimeSpan && backendTimeout <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException("backendTimeout");
            }
            this.instanceId = instanceId;
            this.backend = backend;
            this.clock = clock;
            this.stateGate = stateGate ?? EngineServiceStateGate.Missing;
            this.backendTimeout = backendTimeout;
        }

        public string InstanceId
        {
            get { return instanceId; }
        }

        public EngineServiceStateGate StateGate
        {
            get { return stateGate; }
        }

        public EngineServiceSessionState State
        {
            get { return state; }
        }

        public string BoundSessionId
        {
            get { return sessionId; }
        }

        public bool CredentialHeld
        {
            get { return credentialHeld; }
        }

        // True after a stop, forget, or credential clear. A phase-one status
        // must not report paired after this point. A phase-two identity
        // pairing is unaffected.
        public bool PairingCleared
        {
            get { return pairingCleared; }
        }

        public EngineServiceStopReason LastStop
        {
            get { return lastStop; }
        }

        public bool IsClosed
        {
            get { return state == EngineServiceSessionState.Closed; }
        }

        // The future credential.set path calls this after it validates and
        // stores the token. The token buffer stays outside this class. A held
        // credential re-arms phase-one pairing. A cleared credential clears
        // the phase-one pairing claim.
        public void SetCredentialHeld(bool held)
        {
            gate.Wait();
            try
            {
                if (state == EngineServiceSessionState.Closed)
                {
                    return;
                }
                credentialHeld = held;
                pairingCleared = !held;
            }
            finally
            {
                gate.Release();
            }
        }

        public async Task<EngineReply> HandleAsync(
            IReadOnlyDictionary<string, string> fields,
            CancellationToken cancellationToken)
        {
            EngineRequest request;
            string code;
            if (!EngineWire.TryReadRequest(fields, out request, out code))
            {
                return EngineReply.Failure(code);
            }

            // Wait for the gate before any state read. The state fields are
            // volatile, but the request order must be serialized. The caller
            // token is observed before the request runs. A closed session is
            // refused inside the gate, so a queued request can still cancel.
            try
            {
                await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return EngineReply.Failure(EngineProtocol.ErrorCodes.Timeout);
            }

            try
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    return EngineReply.Failure(EngineProtocol.ErrorCodes.Timeout);
                }
                return HandleLocked(request, cancellationToken);
            }
            finally
            {
                gate.Release();
            }
        }

        // The pipe broke. The session ends with no grace and one stop path.
        public EngineServiceResult ParentLost()
        {
            return CloseWithStop(EngineServiceStopReason.ParentLost);
        }

        // The SCM stop wins over a pipe break. The caller must not run a second
        // stop for the same transition. If a stop already ran with another
        // reason, this returns that result and the first reason is kept.
        public EngineServiceResult ServiceStopped(EngineServiceStopReason reason)
        {
            if (reason != EngineServiceStopReason.ServiceStop
                && reason != EngineServiceStopReason.Shutdown
                && reason != EngineServiceStopReason.SessionLogoff)
            {
                throw new ArgumentException("invalid service stop reason", "reason");
            }
            return CloseWithStop(reason);
        }

        private EngineReply HandleLocked(
            EngineRequest request,
            CancellationToken cancellationToken)
        {
            if (state == EngineServiceSessionState.Closed)
            {
                return EngineReply.Failure(EngineProtocol.ErrorCodes.Closed);
            }

            if (sessionId == null)
            {
                if (request.Operation != EngineProtocol.Operations.Hello)
                {
                    return EngineReply.Failure(EngineProtocol.ErrorCodes.NotConnected);
                }
            }
            else if (!string.Equals(sessionId, request.SessionId, StringComparison.Ordinal))
            {
                return EngineReply.Failure(EngineProtocol.ErrorCodes.Forbidden);
            }

            try
            {
                switch (request.Operation)
                {
                    case EngineProtocol.Operations.Hello:
                        EngineReply hello = Hello();
                        if (hello.Ok && sessionId == null)
                        {
                            sessionId = request.SessionId;
                            state = EngineServiceSessionState.Active;
                        }
                        return hello;
                    case EngineProtocol.Operations.Status:
                        return Status();
                    case EngineProtocol.Operations.Start:
                        return Start(request.Ping, cancellationToken);
                    case EngineProtocol.Operations.Stop:
                        return StopUser(cancellationToken);
                    case EngineProtocol.Operations.Forget:
                        return Forget();
                    case EngineProtocol.Operations.Shutdown:
                        return Shutdown(cancellationToken);
                    default:
                        return EngineReply.Failure(EngineProtocol.ErrorCodes.Unsupported);
                }
            }
            catch (Exception)
            {
                return EngineReply.Failure(EngineProtocol.ErrorCodes.Internal);
            }
        }

        // A backend status describes this service instance, not a previous
        // one. A mismatch discards the sample and fails closed. The source
        // freshness check uses checked_at, so a status read now cannot make an
        // old source answer look fresh.
        private EngineServiceStatus ReadStatusForSession(out EngineReply failure)
        {
            failure = null;
            EngineServiceStatus status;
            IEngineServiceStatusErrorSource detailed = backend as IEngineServiceStatusErrorSource;
            if (detailed != null)
            {
                string code;
                if (!detailed.TryReadStatus(out status, out code))
                {
                    failure = EngineReply.Failure(EngineProtocol.IsKnownErrorCode(code)
                        ? code : EngineProtocol.ErrorCodes.EngineUnavailable);
                    return null;
                }
            }
            else
            {
                status = backend.ReadStatus();
            }
            if (status == null)
            {
                failure = EngineReply.Failure(EngineProtocol.ErrorCodes.EngineUnavailable);
                return null;
            }
            if (!status.InstanceMatches(instanceId))
            {
                failure = EngineReply.Failure(EngineProtocol.ErrorCodes.EngineRestarted);
                return null;
            }
            if (pairingCleared)
            {
                EngineServiceStatus cleared;
                if (!status.TryWithoutSessionPairing(out cleared))
                {
                    failure = EngineReply.Failure(EngineProtocol.ErrorCodes.EngineStopTimeout);
                    return null;
                }
                status = cleared;
            }
            return status;
        }

        private EngineReply Hello()
        {
            EngineReply failure;
            EngineServiceStatus status = ReadStatusForSession(out failure);
            if (status == null)
            {
                return failure;
            }
            Dictionary<string, string> fields = new Dictionary<string, string>(StringComparer.Ordinal);
            fields[EngineServiceStatusKeys.Instance] = instanceId;
            fields[EngineServiceStatusKeys.Engine] = EngineRules.EngineWord(status.Engine);
            return EngineReply.Success(fields);
        }

        private EngineReply Status()
        {
            EngineReply failure;
            EngineServiceStatus status = ReadStatusForSession(out failure);
            if (status == null)
            {
                return failure;
            }
            return EngineReply.Success(status.ToFields());
        }

        private EngineReply Start(bool ping, CancellationToken cancellationToken)
        {
            if (!credentialHeld)
            {
                return EngineReply.Failure(EngineProtocol.ErrorCodes.ManualPhone);
            }
            EngineReply failure;
            EngineServiceStatus status = ReadStatusForSession(out failure);
            if (status == null)
            {
                return failure;
            }
            if (status.Running)
            {
                return EngineReply.Failure(EngineProtocol.ErrorCodes.AlreadyRunning);
            }
            if (status.Cleanup == EngineServiceCleanup.Failed)
            {
                return EngineReply.Failure(EngineProtocol.ErrorCodes.CleanupBlocked);
            }
            if (status.Cleanup == EngineServiceCleanup.Unknown)
            {
                return EngineReply.Failure(EngineProtocol.ErrorCodes.CleanupUnknown);
            }
            if (status.Cleanup == EngineServiceCleanup.Pending)
            {
                return EngineReply.Failure(EngineProtocol.ErrorCodes.CleanupPending);
            }
            if (status.FreshnessAt(clock.Now) != EngineFreshness.Fresh)
            {
                return EngineReply.Failure(EngineProtocol.ErrorCodes.StaleStatus);
            }
            if (!status.Paired)
            {
                return EngineReply.Failure(EngineProtocol.ErrorCodes.NotPaired);
            }
            if (status.Mode != EngineServiceMode.Phone)
            {
                return EngineReply.Failure(EngineProtocol.ErrorCodes.ManualPhone);
            }
            if (status.Engine == EngineRunState.Unavailable)
            {
                return EngineReply.Failure(EngineProtocol.ErrorCodes.EngineUnavailable);
            }
            if (status.Engine != EngineRunState.Ready)
            {
                return EngineReply.Failure(EngineProtocol.ErrorCodes.NotReady);
            }
            if (!status.SourcePresent)
            {
                return EngineReply.Failure(EngineProtocol.ErrorCodes.SourceMissing);
            }

            // The durable record is written before a process is created. A
            // session with no readable record must not launch anything. This
            // check is after the status checks so the person still sees the
            // specific live engine reason first, and before backend.Start so
            // no process can be created from an unknown cleanup state.
            string gateCode;
            if (!stateGate.CanStart(out gateCode))
            {
                return EngineReply.Failure(gateCode);
            }

            // A start attempt that reaches the backend begins a new
            // generation even if the launch fails. Clear the previous stop
            // latch first so a later stop can clean up a partially started
            // engine. Status refusals before this point do not call the
            // backend and leave the previous stop result in place.
            stopRan = false;
            stopResult = null;
            lastStop = EngineServiceStopReason.None;
            EngineServiceResult result = RunStartBackend(ping, cancellationToken);
            if (result == null || !result.Ok)
            {
                return EngineReply.Failure(result == null
                    ? EngineProtocol.ErrorCodes.CleanupUnknown
                    : result.Code);
            }

            return EngineReply.Success(null);
        }

        private EngineReply StopUser(CancellationToken cancellationToken)
        {
            EngineServiceResult result = StopOnce(
                EngineServiceStopReason.User,
                cancellationToken);
            state = result.Ok
                ? EngineServiceSessionState.Stopped
                : EngineServiceSessionState.Closed;
            if (!result.Ok)
            {
                return EngineReply.Failure(result.Code);
            }
            return EngineReply.Success(null);
        }

        private EngineReply Forget()
        {
            EngineReply failure;
            EngineServiceStatus status = ReadStatusForSession(out failure);
            if (status == null)
            {
                return failure;
            }
            if (status.Running)
            {
                return EngineReply.Failure(EngineProtocol.ErrorCodes.ForgetWhileRunning);
            }
            credentialHeld = false;
            pairingCleared = true;
            return EngineReply.Success(null);
        }

        private EngineReply Shutdown(CancellationToken cancellationToken)
        {
            EngineServiceResult result = StopOnce(
                EngineServiceStopReason.ServiceStop,
                cancellationToken);
            state = EngineServiceSessionState.Closed;
            if (!result.Ok)
            {
                return EngineReply.Failure(result.Code);
            }
            return EngineReply.Success(null);
        }

        private EngineServiceResult CloseWithStop(EngineServiceStopReason reason)
        {
            // A close trigger is part of the same serialized state machine. It
            // waits for an in-flight request to leave the gate, then runs the
            // one stop. The host must not call this from the request thread
            // that already holds the gate.
            gate.Wait();
            try
            {
                EngineServiceResult result = StopOnce(reason, CancellationToken.None);
                state = EngineServiceSessionState.Closed;
                return result.Ok
                    ? EngineServiceResult.Success()
                    : result;
            }
            finally
            {
                gate.Release();
            }
        }

        // Within one started generation, the first stop trigger calls the
        // backend once. Every later trigger returns the same result and keeps
        // the first reason. A successful new start resets this latch. The
        // credential and phase-one pairing are cleared even when the stop
        // reports a failure, so a failed stop cannot be followed by a start
        // with the old credential in this session.
        private EngineServiceResult StopOnce(
            EngineServiceStopReason reason,
            CancellationToken cancellationToken)
        {
            // A stop trigger always ends this session's credential use and
            // its phase-one pairing claim, even when the one backend stop
            // already ran. The first reason is kept.
            credentialHeld = false;
            pairingCleared = true;
            if (stopRan)
            {
                return stopResult ?? EngineServiceResult.CleanupUnknown();
            }
            stopRan = true;
            lastStop = reason;
            EngineServiceResult result = RunStopBackend(reason, cancellationToken);
            stopResult = result;
            return result;
        }

        // The backend is the owner of the launch and stop bounds. This
        // adapter passes the caller cancellation token and the optional
        // session timeout to a backend that can observe them. A cancellation,
        // a timeout, an exception, or a null result after the point of no
        // return is cleanup_unknown. It is never success because the session
        // cannot prove that no process or route is left behind.
        private EngineServiceResult RunStartBackend(
            bool ping,
            CancellationToken cancellationToken)
        {
            using (CancellationTokenSource timeout =
                CreateBackendCancellation(cancellationToken))
            {
                CancellationToken token = timeout.Token;
                try
                {
                    IEngineServiceCancellableBackend cancellable =
                        backend as IEngineServiceCancellableBackend;
                    EngineServiceResult result = cancellable != null
                        ? cancellable.Start(ping, token)
                        : backend.Start(ping);
                    return NormalizeStartResult(result, token);
                }
                catch (OperationCanceledException)
                {
                    return EngineServiceResult.CleanupUnknown();
                }
                catch (TimeoutException)
                {
                    return EngineServiceResult.CleanupUnknown();
                }
                catch (Exception)
                {
                    return EngineServiceResult.CleanupUnknown();
                }
            }
        }

        private EngineServiceResult RunStopBackend(
            EngineServiceStopReason reason,
            CancellationToken cancellationToken)
        {
            using (CancellationTokenSource timeout =
                CreateBackendCancellation(cancellationToken))
            {
                CancellationToken token = timeout.Token;
                try
                {
                    IEngineServiceCancellableBackend cancellable =
                        backend as IEngineServiceCancellableBackend;
                    EngineServiceResult result = cancellable != null
                        ? cancellable.Stop(reason, token)
                        : backend.Stop(reason);
                    return NormalizeStopResult(result, token);
                }
                catch (OperationCanceledException)
                {
                    return EngineServiceResult.CleanupUnknown();
                }
                catch (TimeoutException)
                {
                    return EngineServiceResult.CleanupUnknown();
                }
                catch (Exception)
                {
                    return EngineServiceResult.CleanupUnknown();
                }
            }
        }

        private CancellationTokenSource CreateBackendCancellation(
            CancellationToken cancellationToken)
        {
            CancellationTokenSource timeout =
                CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            if (backendTimeout != Timeout.InfiniteTimeSpan)
            {
                timeout.CancelAfter(backendTimeout);
            }
            return timeout;
        }

        private static EngineServiceResult NormalizeStartResult(
            EngineServiceResult result,
            CancellationToken token)
        {
            if (token.IsCancellationRequested)
            {
                return EngineServiceResult.CleanupUnknown();
            }
            if (result == null)
            {
                return EngineServiceResult.CleanupUnknown();
            }
            if (!result.Ok
                && (result.Code == EngineProtocol.ErrorCodes.Timeout
                    || result.Code == EngineProtocol.ErrorCodes.LaunchTimeout))
            {
                return EngineServiceResult.CleanupUnknown();
            }
            return result;
        }

        private static EngineServiceResult NormalizeStopResult(
            EngineServiceResult result,
            CancellationToken token)
        {
            if (token.IsCancellationRequested)
            {
                return EngineServiceResult.CleanupUnknown();
            }
            if (result == null)
            {
                return EngineServiceResult.CleanupUnknown();
            }
            if (!result.Ok && result.Code == EngineProtocol.ErrorCodes.Timeout)
            {
                return EngineServiceResult.CleanupUnknown();
            }
            return result;
        }
    }
}
