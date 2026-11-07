using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.ServiceHost
{
    // One pipe, one session, no reconnect grace, and no auto-restart. The
    // listener returns after the first session ends. A service host that wants
    // another session must create a new generation explicitly.
    public sealed class EngineServicePipeListener : IEngineServiceListener
    {
        private readonly IEngineServicePipeFactory pipeFactory;
        private readonly EngineServiceSessionGate sessionGate;
        private readonly WindowsServiceCallerPolicy callerPolicy;
        private readonly IEngineServiceCleanThreadRunner cleanThreadRunner;
        private readonly IEngineServiceFatalBoundary fatalBoundary;
        private readonly IEngineServiceEventSink events;
        private readonly EngineServiceTransportOptions options;
        private readonly IEngineServiceHostMonotonicClock clock;
        private readonly TaskCompletionSource<bool> ready =
            new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        public EngineServicePipeListener(
            IEngineServicePipeFactory pipeFactory,
            EngineServiceSessionGate sessionGate,
            WindowsServiceCallerPolicy callerPolicy,
            IEngineServiceCleanThreadRunner cleanThreadRunner,
            IEngineServiceFatalBoundary fatalBoundary,
            IEngineServiceEventSink events,
            EngineServiceTransportOptions options)
            : this(
                pipeFactory,
                sessionGate,
                callerPolicy,
                cleanThreadRunner,
                fatalBoundary,
                events,
                options,
                EngineServiceHostStopwatchClock.Instance)
        {
        }

        internal EngineServicePipeListener(
            IEngineServicePipeFactory pipeFactory,
            EngineServiceSessionGate sessionGate,
            WindowsServiceCallerPolicy callerPolicy,
            IEngineServiceCleanThreadRunner cleanThreadRunner,
            IEngineServiceFatalBoundary fatalBoundary,
            IEngineServiceEventSink events,
            EngineServiceTransportOptions options,
            IEngineServiceHostMonotonicClock clock)
        {
            if (pipeFactory == null)
            {
                throw new ArgumentNullException("pipeFactory");
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
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }
            if (clock == null)
            {
                throw new ArgumentNullException("clock");
            }
            if (clock.Frequency <= 0)
            {
                throw new ArgumentOutOfRangeException("clock");
            }
            options.Validate();
            this.pipeFactory = pipeFactory;
            this.sessionGate = sessionGate;
            this.callerPolicy = callerPolicy;
            this.cleanThreadRunner = cleanThreadRunner;
            this.fatalBoundary = fatalBoundary;
            this.events = events;
            this.options = options;
            this.clock = clock;
        }

        public Task<bool> Ready
        {
            get { return ready.Task; }
        }

        public Task<EngineServiceListenerResult> RunAsync(CancellationToken cancellationToken)
        {
            // The Win32 calls are synchronous and bounded by their own
            // deadlines. The dedicated task keeps that wait off the caller's
            // thread and off the service host's start path.
            return Task.Run<EngineServiceListenerResult>(
                delegate { return RunCoreAsync(cancellationToken); },
                CancellationToken.None);
        }

        public void Dispose()
        {
            sessionGate.Dispose();
            ready.TrySetResult(false);
        }

        private async Task<EngineServiceListenerResult> RunCoreAsync(
            CancellationToken cancellationToken)
        {
            try
            {
                return await RunCoreInnerAsync(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                // Ready is a proof of the first pipe instance. A listener that
                // ends before proving it must complete false, never leave the
                // host waiting for the start budget.
                ready.TrySetResult(false);
            }
        }

        private async Task<EngineServiceListenerResult> RunCoreInnerAsync(
            CancellationToken cancellationToken)
        {
            IEngineServicePipeConnection pipe;
            string code;
            if (!pipeFactory.TryCreateFirstInstance(out pipe, out code))
            {
                string eventCode = code == EngineProtocol.ErrorCodes.BoundaryBusy
                    || code == EngineServiceEventCodes.PipeNameInUse
                    ? EngineServiceEventCodes.PipeNameInUse
                    : EngineServiceEventCodes.PipeCreateFailed;
                events.Record(eventCode);
                return EngineServiceListenerResult.Failure(
                    EngineProtocol.ErrorCodes.EngineUnavailable,
                    EngineServiceCleanup.Unknown,
                    EngineServiceStopReason.None);
            }
            if (pipe == null)
            {
                events.Record(EngineServiceEventCodes.PipeCreateFailed);
                return EngineServiceListenerResult.Failure(
                    EngineProtocol.ErrorCodes.EngineUnavailable,
                    EngineServiceCleanup.Unknown,
                    EngineServiceStopReason.None);
            }

            bool pipeDisposalDeferred = false;
            try
            {
                // The first instance now exists, so the listener can accept a
                // client. The host may report Running only after this proof.
                ready.TrySetResult(true);

                if (!pipe.TryConnect(cancellationToken, out code))
                {
                    if (cancellationToken.IsCancellationRequested)
                    {
                        // A requested stop during the client wait is a clean
                        // service stop, not a failed pipe or a parent loss.
                        return FinishServiceStop(0, EngineServiceStopReason.ServiceStop);
                    }
                    events.Record(EngineServiceEventCodes.PipeConnectFailed);
                    EngineServiceListenerResult connectFailure =
                        FinishParentLoss(0, cancellationToken);
                    return connectFailure.Ok
                        ? EngineServiceListenerResult.Failure(
                            EngineProtocol.ErrorCodes.EngineUnavailable,
                            EngineServiceCleanup.Ok,
                            EngineServiceStopReason.ParentLost)
                        : connectFailure;
                }

                EngineServiceIdleGuard idleGuard = new EngineServiceIdleGuard(clock, options.IdleTimeout);
                EngineServicePipeServerHandshake handshake =
                    new EngineServicePipeServerHandshake(
                        pipe,
                        sessionGate,
                        callerPolicy,
                        cleanThreadRunner,
                        fatalBoundary,
                        events,
                        options.HandshakeTimeout,
                        clock,
                        idleGuard.MarkRequestCompleted);
                EngineServiceHandshakeResult handshakeResult =
                    await handshake.RunAsync(cancellationToken).ConfigureAwait(false);
                if (!handshakeResult.Ok)
                {
                    if (handshakeResult.Fatal)
                    {
                        // A failed revert already asked the fatal boundary to
                        // terminate or disable. No stop fallback runs on the
                        // caller, and the host disables this generation. The
                        // handshake keeps the pipe open while an unverified
                        // probe thread may still use it.
                        pipeDisposalDeferred = handshakeResult.PipeDisposalDeferred;
                        return EngineServiceListenerResult.FatalFailure(handshakeResult.Code);
                    }
                    if (cancellationToken.IsCancellationRequested)
                    {
                        // A stop during the handshake is a service stop. Do
                        // not report a client loss or an engine failure.
                        return FinishServiceStop(0, EngineServiceStopReason.ServiceStop);
                    }
                    return FinishParentLoss(0, cancellationToken);
                }

                int handled = 1;
                while (true)
                {
                    if (cancellationToken.IsCancellationRequested)
                    {
                        return FinishServiceStop(
                            handled,
                            EngineServiceStopReason.ServiceStop);
                    }

                    byte[] frame;
                    EngineServiceFrameReadOutcome outcome;
                    EngineServiceReadDeadline readDeadline = idleGuard.CreateReadDeadline(options.RequestTimeout);
                    if (!pipe.TryReadFrame(readDeadline, cancellationToken, out frame, out outcome, out code))
                    {
                        if (cancellationToken.IsCancellationRequested)
                        {
                            return FinishServiceStop(
                                handled,
                                EngineServiceStopReason.ServiceStop);
                        }
                        // Expiry names the exhausted budget. It does not
                        // assert zero transfer. Unknown and Partial still
                        // record a read failure and are never replayed.
                        if (readDeadline.Expiry == EngineServiceReadExpiry.Boundary)
                        {
                            events.Record(EngineServiceEventCodes.BoundaryReadTimeout);
                        }
                        else if (readDeadline.Expiry == EngineServiceReadExpiry.Frame)
                        {
                            events.Record(EngineServiceEventCodes.FrameTimeout);
                        }
                        if (outcome != EngineServiceFrameReadOutcome.Idle)
                        {
                            events.Record(EngineServiceEventCodes.PipeReadFailed);
                        }
                        return FinishParentLoss(handled, cancellationToken);
                    }
                    if (cancellationToken.IsCancellationRequested)
                    {
                        if (frame != null)
                        {
                            Array.Clear(frame, 0, frame.Length);
                        }
                        return FinishServiceStop(handled, EngineServiceStopReason.ServiceStop);
                    }
                    if (frame == null)
                    {
                        return FinishFailure(
                            handled,
                            cancellationToken,
                            EngineServiceEventCodes.FrameInvalid);
                    }

                    Dictionary<string, string> fields;
                    if (!EngineServiceFrame.TryDecode(frame, frame.Length, out fields, out code))
                    {
                        Array.Clear(frame, 0, frame.Length);
                        return FinishFailure(
                            handled,
                            cancellationToken,
                            EngineServiceEventCodes.FrameInvalid);
                    }
                    Array.Clear(frame, 0, frame.Length);

                    EngineRequest request;
                    if (!EngineWire.TryReadRequest(fields, out request, out code))
                    {
                        return FinishFailure(
                            handled,
                            cancellationToken,
                            EngineServiceEventCodes.FrameInvalid);
                    }

                    EngineReply reply = await sessionGate.HandleAsync(fields, cancellationToken)
                        .ConfigureAwait(false);
                    if (cancellationToken.IsCancellationRequested)
                    {
                        return FinishServiceStop(handled, EngineServiceStopReason.ServiceStop);
                    }
                    byte[] replyFrame;
                    if (!EngineServiceFrame.TryEncode(reply.Fields, out replyFrame, out code))
                    {
                        return FinishFailure(
                            handled,
                            cancellationToken,
                            EngineServiceEventCodes.FrameInvalid);
                    }

                    try
                    {
                        if (!pipe.TryWriteFrame(replyFrame, cancellationToken, out code))
                        {
                            return FinishFailure(
                                handled,
                                cancellationToken,
                                EngineServiceEventCodes.PipeWriteFailed);
                        }
                    }
                    finally
                    {
                        Array.Clear(replyFrame, 0, replyFrame.Length);
                    }

                    if (cancellationToken.IsCancellationRequested)
                    {
                        return FinishServiceStop(handled, EngineServiceStopReason.ServiceStop);
                    }
                    // This validated request is now processed and its reply
                    // was written. Credit it once, even for a valid failure
                    // reply. Long backend work cannot exhaust the next read's
                    // interval. A reply alone never reaches this point.
                    if (!sessionGate.IsClosed && !sessionGate.Session.IsClosed)
                    {
                        idleGuard.MarkRequestCompleted();
                    }

                    handled++;
                    if (request.Operation == EngineProtocol.Operations.Shutdown)
                    {
                        // Only an accepted shutdown, or one whose stop the
                        // session already claimed, stops the service. A
                        // forbidden or unconnected shutdown got a failure
                        // reply and must leave the live session and its
                        // engine alone.
                        bool shutdownAccepted = reply.Ok
                            || sessionGate.Session.IsClosed
                            || sessionGate.StopClaimed;
                        if (shutdownAccepted)
                        {
                            // The core session records its shutdown stop as a
                            // service stop. Use the same reason here so the
                            // listener result cannot disagree with the
                            // backend.
                            return FinishServiceStop(
                                handled,
                                EngineServiceStopReason.ServiceStop);
                        }
                    }
                }
            }
            finally
            {
                if (!pipeDisposalDeferred)
                {
                    pipe.Dispose();
                }
            }
        }

        private EngineServiceListenerResult FinishFailure(
            int handled,
            CancellationToken cancellationToken,
            string eventCode)
        {
            // A requested stop wins over a broken pipe or an invalid frame.
            // The first claimed reason is kept by the session gate.
            if (cancellationToken.IsCancellationRequested)
            {
                return FinishServiceStop(handled, EngineServiceStopReason.ServiceStop);
            }
            events.Record(eventCode);
            return FinishParentLoss(handled, cancellationToken);
        }

        private EngineServiceListenerResult FinishParentLoss(
            int handled,
            CancellationToken cancellationToken)
        {
            // The claim reads the cancellation state and the first stop reason
            // together. A stop requested just before the claim is a service
            // stop, not a parent loss. A stop requested after the claim keeps
            // the parent-loss reason because the pipe break was observed first.
            EngineServiceResult result =
                sessionGate.ParentLostUnlessStopRequested(cancellationToken);
            EngineServiceStopReason reason = sessionGate.StopReason;
            RecordStopEvent(reason);
            if (result == null || !result.Ok)
            {
                return EngineServiceListenerResult.Failure(
                    result == null ? EngineProtocol.ErrorCodes.Internal : result.Code,
                    EngineServiceCleanup.Failed,
                    reason);
            }
            return EngineServiceListenerResult.Success(
                EngineServiceCleanup.Ok,
                reason,
                handled);
        }

        private EngineServiceListenerResult FinishServiceStop(
            int handled,
            EngineServiceStopReason requestedReason)
        {
            EngineServiceResult result = sessionGate.ServiceStopped(requestedReason);
            EngineServiceStopReason reason = sessionGate.StopReason;
            RecordStopEvent(reason);
            if (result == null || !result.Ok)
            {
                return EngineServiceListenerResult.Failure(
                    result == null ? EngineProtocol.ErrorCodes.Internal : result.Code,
                    EngineServiceCleanup.Failed,
                    reason);
            }
            return EngineServiceListenerResult.Success(
                EngineServiceCleanup.Ok,
                reason,
                handled);
        }

        private void RecordStopEvent(EngineServiceStopReason reason)
        {
            if (reason == EngineServiceStopReason.ParentLost)
            {
                events.Record(EngineServiceEventCodes.ParentLost);
                return;
            }
            if (reason == EngineServiceStopReason.None)
            {
                events.Record(EngineServiceEventCodes.SessionStopFailed);
                return;
            }
            events.Record(EngineServiceEventCodes.ServiceStop);
        }
    }
}
