using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.ServiceHost
{
    public sealed class EngineServiceHandshakeResult
    {
        private EngineServiceHandshakeResult(
            bool ok,
            bool helloReplyOk,
            string code,
            string eventCode,
            string callerSessionId,
            int clientProcessId,
            bool fatal,
            bool pipeDisposalDeferred)
        {
            Ok = ok;
            HelloReplyOk = helloReplyOk;
            Code = EngineProtocol.IsKnownErrorCode(code) ? code : (ok ? "" : EngineProtocol.ErrorCodes.Internal);
            EventCode = EngineEventSafe(eventCode);
            CallerSessionId = callerSessionId ?? "";
            ClientProcessId = clientProcessId;
            Fatal = fatal;
            PipeDisposalDeferred = pipeDisposalDeferred;
        }

        public bool Ok { get; private set; }

        public bool HelloReplyOk { get; private set; }

        public string Code { get; private set; }

        public string EventCode { get; private set; }

        public string CallerSessionId { get; private set; }

        // Diagnostics only. It is never an authorization input.
        public int ClientProcessId { get; private set; }

        // True only after a failed or unverified revert. The caller must not
        // run another session or stop operation on the worker thread.
        public bool Fatal { get; private set; }

        // True when a fatal unverified probe still owns the pipe. The
        // handshake keeps the pipe open until that probe thread exits, then
        // disposes it. The listener must not dispose the pipe in this case.
        public bool PipeDisposalDeferred { get; private set; }

        public static EngineServiceHandshakeResult Success(
            bool helloReplyOk,
            string callerSessionId,
            int clientProcessId)
        {
            return new EngineServiceHandshakeResult(
                true,
                helloReplyOk,
                "",
                "",
                callerSessionId,
                clientProcessId,
                false,
                false);
        }

        public static EngineServiceHandshakeResult Failure(
            string code,
            string eventCode)
        {
            return new EngineServiceHandshakeResult(
                false,
                false,
                code,
                eventCode,
                "",
                0,
                false,
                false);
        }

        public static EngineServiceHandshakeResult FatalFailure(
            string code,
            bool pipeDisposalDeferred)
        {
            return new EngineServiceHandshakeResult(
                false,
                false,
                code,
                EngineServiceEventCodes.CallerRevertFailed,
                "",
                0,
                true,
                pipeDisposalDeferred);
        }

        private static string EngineEventSafe(string eventCode)
        {
            return EngineServiceEventCodes.IsKnown(eventCode) ? eventCode : "";
        }
    }

    // The process-level response to a failed or unverified revert. It runs on
    // a thread that never impersonated. A conforming implementation must
    // either terminate the process or place the service in an explicit
    // disabled state that refuses every later start. It must not throw.
    //
    // The foundation cannot prove termination on a host it does not own, so
    // the listener requires this seam. Tests use a fake. The host sets its own
    // Disabled result when it receives a fatal listener result.
    public interface IEngineServiceFatalBoundary
    {
        bool TryTerminateOrDisable(out string code);
    }

    // The real fail-closed response. It terminates the process before the
    // potentially impersonated worker thread can return to a pool. The test
    // host never calls this implementation because it would end the test
    // process.
    public sealed class EngineServiceProcessTerminator : IEngineServiceFatalBoundary
    {
        public bool TryTerminateOrDisable(out string code)
        {
            code = EngineServiceEventCodes.CallerRevertFailed;
            try
            {
                Environment.FailFast("HotspotShade service caller revert failed");
            }
            catch (Exception)
            {
                // FailFast is expected not to return. If it cannot run, the
                // caller still disables the host generation.
                return false;
            }
            return false;
        }
    }

    // The one-time server handshake for a connection. Order:
    //   1. read exactly one bounded frame and do not parse it,
    //   2. on a dedicated clean thread: ImpersonateNamedPipeClient,
    //   3. on that same thread: OpenThreadToken with OpenAsSelf and token fields,
    //   4. on that same thread: call and verify RevertToSelf on every path,
    //   5. end that thread, so a thread that may hold a caller token never
    //      returns to the thread pool,
    //   6. only on the clean caller thread: require a user account and the
    //      installed account SID,
    //   7. parse the buffered frame and require hello.
    //
    // A denied caller receives no reply. A failed or unverified revert sends no
    // reply, parses nothing, records one fixed event on the clean thread, and
    // asks the fatal boundary to terminate the process or disable the service.
    // The failed-revert path never records an event or runs a stop fallback on
    // the thread that may still be impersonating. A normal stop during the
    // probe is not an unverified revert: the handshake waits for that thread's
    // checked revert and reports closed without asking the fatal boundary.
    public sealed class EngineServicePipeServerHandshake
    {
        private readonly IEngineServicePipeConnection pipe;
        private readonly EngineServiceSessionGate sessionGate;
        private readonly WindowsServiceCallerPolicy callerPolicy;
        private readonly IEngineServiceCleanThreadRunner cleanThreadRunner;
        private readonly IEngineServiceFatalBoundary fatalBoundary;
        private readonly IEngineServiceEventSink events;
        private readonly TimeSpan timeout;
        private readonly IEngineServiceHostMonotonicClock clock;
        private readonly Action completedHelloRequest;

        public EngineServicePipeServerHandshake(
            IEngineServicePipeConnection pipe,
            EngineServiceSessionGate sessionGate,
            WindowsServiceCallerPolicy callerPolicy,
            IEngineServiceCleanThreadRunner cleanThreadRunner,
            IEngineServiceFatalBoundary fatalBoundary,
            IEngineServiceEventSink events,
            TimeSpan timeout)
            : this(pipe, sessionGate, callerPolicy, cleanThreadRunner, fatalBoundary, events,
                timeout, EngineServiceHostStopwatchClock.Instance, null)
        {
        }

        internal EngineServicePipeServerHandshake(
            IEngineServicePipeConnection pipe, EngineServiceSessionGate sessionGate,
            WindowsServiceCallerPolicy callerPolicy, IEngineServiceCleanThreadRunner cleanThreadRunner,
            IEngineServiceFatalBoundary fatalBoundary, IEngineServiceEventSink events,
            TimeSpan timeout, IEngineServiceHostMonotonicClock clock, Action completedHelloRequest)
        {
            if (pipe == null)
            {
                throw new ArgumentNullException("pipe");
            }
            if (sessionGate == null)
            {
                throw new ArgumentNullException("sessionGate");
            }
            if (callerPolicy == null)
            {
                throw new ArgumentNullException("callerPolicy");
            }
            if (cleanThreadRunner == null)
            {
                throw new ArgumentNullException("cleanThreadRunner");
            }
            if (fatalBoundary == null)
            {
                throw new ArgumentNullException("fatalBoundary");
            }
            if (events == null)
            {
                throw new ArgumentNullException("events");
            }
            if (timeout <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException("timeout");
            }
            this.pipe = pipe;
            this.sessionGate = sessionGate;
            this.callerPolicy = callerPolicy;
            this.cleanThreadRunner = cleanThreadRunner;
            this.fatalBoundary = fatalBoundary;
            this.events = events;
            this.timeout = timeout;
            if (clock == null || clock.Frequency <= 0)
            {
                throw new ArgumentException("invalid monotonic clock", "clock");
            }
            this.clock = clock;
            this.completedHelloRequest = completedHelloRequest;
        }

        public async Task<EngineServiceHandshakeResult> RunAsync(CancellationToken cancellationToken)
        {
            using (CancellationTokenSource deadline =
                CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                deadline.CancelAfter(timeout);
                return await RunBoundedAsync(
                    deadline.Token, cancellationToken, EngineServiceReadDeadline.Handshake(clock, timeout))
                    .ConfigureAwait(false);
            }
        }

        private async Task<EngineServiceHandshakeResult> RunBoundedAsync(
            CancellationToken cancellationToken,
            CancellationToken stopToken,
            EngineServiceReadDeadline readDeadline)
        {
            byte[] frame;
            EngineServiceFrameReadOutcome outcome;
            string code;
            if (!pipe.TryReadFrame(readDeadline, cancellationToken, out frame, out outcome, out code))
            {
                if (stopToken.IsCancellationRequested)
                {
                    return EngineServiceHandshakeResult.Failure(EngineProtocol.ErrorCodes.Closed, "");
                }
                // The linked handshake timer can cancel before the native
                // deadline check runs. Keep timeout and transfer evidence
                // separate, whichever deadline mechanism is observed first.
                bool timedOut = cancellationToken.IsCancellationRequested || readDeadline.TryExpire();
                // The diagnostic follows the read outcome, not only the error
                // code. A partial or unknown read is a framing failure even
                // when the underlying code is timeout. Deadline expiry also
                // records timeout independently of that transfer evidence.
                // No failed read permits a reply or impersonation.
                bool framingFailure = outcome == EngineServiceFrameReadOutcome.Partial
                    || outcome == EngineServiceFrameReadOutcome.Unknown;
                string eventCode = !framingFailure
                    && code == EngineProtocol.ErrorCodes.Timeout
                    ? EngineServiceEventCodes.FrameTimeout
                    : EngineServiceEventCodes.FrameInvalid;
                if (timedOut
                    && eventCode != EngineServiceEventCodes.FrameTimeout)
                {
                    // The deadline expired, but completion did not prove an
                    // idle stream. Keep both facts in fixed diagnostics.
                    events.Record(EngineServiceEventCodes.FrameTimeout);
                }
                events.Record(eventCode);
                return EngineServiceHandshakeResult.Failure(code, eventCode);
            }

            try
            {
                return await AuthenticateAndReplyAsync(frame, cancellationToken, stopToken, readDeadline)
                    .ConfigureAwait(false);
            }
            finally
            {
                if (frame != null)
                {
                    Array.Clear(frame, 0, frame.Length);
                }
            }
        }

        private async Task<EngineServiceHandshakeResult> AuthenticateAndReplyAsync(
            byte[] frame,
            CancellationToken cancellationToken,
            CancellationToken stopToken,
            EngineServiceReadDeadline readDeadline)
        {
            EngineServiceHandshakeResult interrupted = Interrupted(stopToken, cancellationToken, readDeadline);
            if (interrupted != null) { return interrupted; }

            CallerProbe probe;
            Task<CallerProbe> probeTask = null;
            bool probeStartRequested = false;
            try
            {
                // The clean-thread runner starts a new thread, never a pool
                // thread. The action cannot be cancelled, because an
                // interrupted impersonation could skip the checked revert.
                // A handshake deadline with a running probe fails closed. A
                // normal stop waits for the probe's own checked revert and
                // only then reports closed. The probe thread never
                // returns to the pool.
                probeStartRequested = true;
                probeTask = cleanThreadRunner.RunAsync<CallerProbe>(
                    ProbeCaller,
                    CancellationToken.None);
                Task finished = await Task.WhenAny(
                    probeTask,
                    Task.Delay(Timeout.Infinite, cancellationToken)).ConfigureAwait(false);
                if (finished != probeTask && !probeTask.IsCompleted)
                {
                    if (!stopToken.IsCancellationRequested)
                    {
                        // The handshake deadline expired while the probe
                        // thread still ran. Its checked revert cannot be
                        // proven, so fail closed.
                        return FailClosedAfterRevert(
                            EngineServiceEventCodes.CallerRevertUnverified,
                            probeTask);
                    }

                    // A normal service stop is not a failed revert. The probe
                    // action is not cancellable, because an interrupted
                    // impersonation could skip the checked revert. Wait for
                    // that thread to finish its own revert. This does not
                    // fail the process, and the listener keeps the pipe open
                    // until the wait returns.
                    probe = await probeTask.ConfigureAwait(false);
                    if (probe != null && probe.RevertFailed)
                    {
                        return FailClosedAfterRevert(
                            EngineServiceEventCodes.CallerRevertFailed,
                            null);
                    }
                    return Interrupted(stopToken, cancellationToken, readDeadline);
                }
                probe = await probeTask.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // A runner can fail after it has started the probe. Without a
                // completion proof the thread may still hold a caller token,
                // so the pipe must stay open and the process must fail closed.
                EngineServiceHandshakeResult running = FailClosedForRunningProbe(
                    probeStartRequested,
                    probeTask,
                    EngineServiceEventCodes.CallerRevertUnverified);
                if (running != null)
                {
                    return running;
                }
                interrupted = Interrupted(stopToken, cancellationToken, readDeadline);
                if (interrupted != null) { return interrupted; }
                events.Record(EngineServiceEventCodes.FrameTimeout);
                return EngineServiceHandshakeResult.Failure(
                    EngineProtocol.ErrorCodes.Timeout,
                    EngineServiceEventCodes.FrameTimeout);
            }
            catch (Exception)
            {
                EngineServiceHandshakeResult running = FailClosedForRunningProbe(
                    probeStartRequested,
                    probeTask,
                    EngineServiceEventCodes.CallerRevertUnverified);
                if (running != null)
                {
                    return running;
                }
                events.Record(EngineServiceEventCodes.CallerTokenFailed);
                return EngineServiceHandshakeResult.Failure(
                    EngineProtocol.ErrorCodes.BoundaryAuthFailed,
                    EngineServiceEventCodes.CallerTokenFailed);
            }

            if (probe == null)
            {
                events.Record(EngineServiceEventCodes.CallerTokenFailed);
                return EngineServiceHandshakeResult.Failure(
                    EngineProtocol.ErrorCodes.BoundaryAuthFailed,
                    EngineServiceEventCodes.CallerTokenFailed);
            }

            if (probe.RevertFailed)
            {
                // The impersonation thread has returned from the probe and
                // exited. This callback runs on the clean caller. No event,
                // stop, parse, or reply runs on the possibly impersonated
                // thread.
                return FailClosedAfterRevert(EngineServiceEventCodes.CallerRevertFailed, null);
            }

            interrupted = Interrupted(stopToken, cancellationToken, readDeadline);
            if (interrupted != null) { return interrupted; }

            if (!probe.ImpersonationStarted || !probe.IdentityRead || probe.Identity == null)
            {
                string eventCode = string.IsNullOrEmpty(probe.EventCode)
                    ? EngineServiceEventCodes.CallerTokenFailed
                    : probe.EventCode;
                events.Record(eventCode);
                return EngineServiceHandshakeResult.Failure(
                    EngineProtocol.ErrorCodes.BoundaryAuthFailed,
                    eventCode);
            }

            EngineServiceCallerVerdict verdict;
            try
            {
                verdict = await callerPolicy.EvaluateAsync(probe.Identity, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (Exception)
            {
                verdict = EngineServiceCallerVerdict.Deny(
                    EngineProtocol.ErrorCodes.BoundaryAuthFailed,
                    EngineServiceEventCodes.CallerAccountTypeFailed);
            }
            interrupted = Interrupted(stopToken, cancellationToken, readDeadline);
            if (interrupted != null) { return interrupted; }
            if (verdict == null || !verdict.Allowed)
            {
                events.Record(verdict == null
                    ? EngineServiceEventCodes.CallerAccountTypeFailed
                    : verdict.EventCode);
                return EngineServiceHandshakeResult.Failure(
                    verdict == null
                        ? EngineProtocol.ErrorCodes.BoundaryAuthFailed
                        : verdict.Code,
                    verdict == null ? "" : verdict.EventCode);
            }

            // The caller identity is settled and the thread is reverted. Parse
            // only now, on the clean caller thread.
            Dictionary<string, string> fields;
            string code;
            if (!EngineServiceFrame.TryDecode(frame, frame.Length, out fields, out code))
            {
                events.Record(EngineServiceEventCodes.FirstFrameInvalid);
                return EngineServiceHandshakeResult.Failure(
                    EngineProtocol.ErrorCodes.BadResponse,
                    EngineServiceEventCodes.FirstFrameInvalid);
            }

            EngineRequest request;
            if (!EngineWire.TryReadRequest(fields, out request, out code)
                || request.Operation != EngineProtocol.Operations.Hello)
            {
                events.Record(EngineServiceEventCodes.FirstFrameNotHello);
                return EngineServiceHandshakeResult.Failure(
                    EngineProtocol.ErrorCodes.BadRequest,
                    EngineServiceEventCodes.FirstFrameNotHello);
            }

            interrupted = Interrupted(stopToken, cancellationToken, readDeadline);
            if (interrupted != null) { return interrupted; }
            EngineReply reply = await sessionGate.HandleAsync(fields, cancellationToken)
                .ConfigureAwait(false);
            interrupted = Interrupted(stopToken, cancellationToken, readDeadline);
            if (interrupted != null) { return interrupted; }
            byte[] replyFrame;
            if (!EngineServiceFrame.TryEncode(reply.Fields, out replyFrame, out code))
            {
                events.Record(EngineServiceEventCodes.FrameInvalid);
                return EngineServiceHandshakeResult.Failure(
                    EngineProtocol.ErrorCodes.Internal,
                    EngineServiceEventCodes.FrameInvalid);
            }

            try
            {
                if (!pipe.TryWriteFrame(replyFrame, cancellationToken, out code))
                {
                    interrupted = Interrupted(stopToken, cancellationToken, readDeadline);
                    if (interrupted != null) { return interrupted; }
                    events.Record(EngineServiceEventCodes.PipeWriteFailed);
                    return EngineServiceHandshakeResult.Failure(
                        EngineProtocol.ErrorCodes.EngineUnavailable,
                        EngineServiceEventCodes.PipeWriteFailed);
                }
            }
            finally
            {
                Array.Clear(replyFrame, 0, replyFrame.Length);
            }

            interrupted = Interrupted(stopToken, cancellationToken, readDeadline);
            if (interrupted != null) { return interrupted; }
            int clientProcessId = 0;
            try
            {
                int processId;
                if (pipe.TryGetClientProcessId(out processId))
                {
                    clientProcessId = processId;
                }
            }
            catch (Exception)
            {
                clientProcessId = 0;
            }

            interrupted = Interrupted(stopToken, cancellationToken, readDeadline);
            if (interrupted != null) { return interrupted; }
            if (sessionGate.IsClosed || sessionGate.Session.IsClosed)
            {
                return EngineServiceHandshakeResult.Failure(EngineProtocol.ErrorCodes.Closed, "");
            }
            events.Record(verdict.EventCode);
            // Authentication and hello validation preceded backend processing
            // and a successful write. Credit that completed request once. The
            // fixed handshake deadline still applies through this point.
            if (completedHelloRequest != null) { completedHelloRequest(); }
            return EngineServiceHandshakeResult.Success(
                reply.Ok,
                request.SessionId,
                clientProcessId);
        }

        private EngineServiceHandshakeResult Interrupted(
            CancellationToken stopToken, CancellationToken deadlineToken,
            EngineServiceReadDeadline readDeadline)
        {
            // Requested service stop wins over competing timeout diagnostics.
            // Revert failures are handled before this check and remain fatal.
            if (stopToken.IsCancellationRequested)
            {
                return EngineServiceHandshakeResult.Failure(EngineProtocol.ErrorCodes.Closed, "");
            }
            if (deadlineToken.IsCancellationRequested || readDeadline.TryExpire())
            {
                events.Record(EngineServiceEventCodes.FrameTimeout);
                return EngineServiceHandshakeResult.Failure(
                    EngineProtocol.ErrorCodes.Timeout, EngineServiceEventCodes.FrameTimeout);
            }
            return null;
        }

        private EngineServiceHandshakeResult FailClosedForRunningProbe(
            bool probeStartRequested,
            Task<CallerProbe> probeTask,
            string eventCode)
        {
            if (!probeStartRequested)
            {
                return null;
            }
            if (probeTask == null)
            {
                // The runner threw after the start request but never returned
                // a task. The service cannot prove that no probe thread runs,
                // so it keeps the pipe open for the life of the process and
                // fails closed. A leaked handle is safer than closing a pipe
                // under an impersonated thread.
                return FailClosedWithUnverifiableProbe(eventCode);
            }
            if (!probeTask.IsCompleted)
            {
                return FailClosedAfterRevert(eventCode, probeTask);
            }
            return null;
        }

        private EngineServiceHandshakeResult FailClosedWithUnverifiableProbe(string eventCode)
        {
            events.Record(eventCode);
            RequestFatalBoundary();
            return EngineServiceHandshakeResult.FatalFailure(
                EngineProtocol.ErrorCodes.EngineUnavailable,
                true);
        }

        private EngineServiceHandshakeResult FailClosedAfterRevert(
            string eventCode,
            Task<CallerProbe> pendingProbe)
        {
            events.Record(eventCode);
            bool deferred = false;
            if (pendingProbe != null && !pendingProbe.IsCompleted)
            {
                // The probe thread may still hold a caller token and may
                // still use the pipe. Keep the pipe open until that action
                // returns and exits. A leaked handle is safer than a close
                // under an impersonated thread.
                deferred = DeferPipeDisposal(pendingProbe);
            }
            RequestFatalBoundary();
            return EngineServiceHandshakeResult.FatalFailure(
                EngineProtocol.ErrorCodes.EngineUnavailable,
                deferred);
        }

        private void RequestFatalBoundary()
        {
            try
            {
                string fatalCode;
                fatalBoundary.TryTerminateOrDisable(out fatalCode);
            }
            catch (Exception)
            {
                // The fatal boundary is not allowed to throw. Even when it
                // does, the listener still reports Fatal and the host disables
                // the generation.
            }
        }

        private bool DeferPipeDisposal(Task<CallerProbe> pendingProbe)
        {
            try
            {
                pendingProbe.ContinueWith(
                    delegate
                    {
                        try
                        {
                            pipe.Dispose();
                        }
                        catch (Exception)
                        {
                            // The process is already failing closed. A failed
                            // dispose cannot make the probe thread safe again.
                        }
                    },
                    CancellationToken.None,
                    TaskContinuationOptions.ExecuteSynchronously,
                    TaskScheduler.Default);
                return true;
            }
            catch (Exception)
            {
                // The handshake still owns the pipe. The listener must not
                // dispose it while the probe thread may still use it.
                return true;
            }
        }

        private CallerProbe ProbeCaller()
        {
            CallerProbe probe = new CallerProbe();
            bool impersonationAttempted = false;
            try
            {
                // ImpersonateNamedPipeClient needs data to have been read. Mark
                // the attempt before the call so a partial success still
                // reaches RevertToSelf.
                impersonationAttempted = true;
                string code;
                if (!pipe.TryImpersonateClient(out code))
                {
                    probe.EventCode = EngineServiceEventCodes.CallerImpersonationFailed;
                }
                else
                {
                    probe.ImpersonationStarted = true;
                    IEngineServiceCallerToken token = null;
                    try
                    {
                        if (!pipe.TryOpenThreadToken(out token, out code))
                        {
                            probe.EventCode = EngineServiceEventCodes.CallerTokenFailed;
                        }
                        else if (token == null)
                        {
                            probe.EventCode = EngineServiceEventCodes.CallerTokenFailed;
                        }
                        else
                        {
                            EngineServiceCallerIdentity identity;
                            if (!token.TryRead(out identity, out code) || identity == null)
                            {
                                probe.EventCode = EngineServiceEventCodes.CallerTokenFailed;
                            }
                            else
                            {
                                probe.Identity = identity;
                                probe.IdentityRead = true;
                            }
                        }
                    }
                    finally
                    {
                        if (token != null)
                        {
                            token.Dispose();
                        }
                    }
                }
            }
            catch (Exception)
            {
                probe.EventCode = EngineServiceEventCodes.CallerTokenFailed;
                probe.Identity = null;
                probe.IdentityRead = false;
            }
            finally
            {
                if (impersonationAttempted)
                {
                    bool revertOk = false;
                    try
                    {
                        string revertCode;
                        revertOk = pipe.TryRevertToSelfAndVerify(out revertCode);
                    }
                    catch (Exception)
                    {
                        revertOk = false;
                    }

                    if (!revertOk)
                    {
                        // This thread must run nothing else. The action
                        // returns immediately and the thread exits. The clean
                        // caller handles the fatal result.
                        probe.RevertFailed = true;
                        probe.Identity = null;
                        probe.IdentityRead = false;
                    }
                }
            }
            return probe;
        }

        private sealed class CallerProbe
        {
            public EngineServiceCallerIdentity Identity;
            public string EventCode = "";
            public bool ImpersonationStarted;
            public bool IdentityRead;
            public bool RevertFailed;
        }
    }
}
