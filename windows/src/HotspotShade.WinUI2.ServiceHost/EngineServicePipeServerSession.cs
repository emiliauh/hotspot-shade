using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.ServiceHost
{
    // The backend side of the parent-loss boundary. The guard is set before
    // the session gate waits, so a start that reaches the backend after parent
    // loss is refused instead of launching.
    public interface IEngineServiceStopBoundary
    {
        void MarkStopRequested();
    }

    // Proves that a process id and creation time from a previous clean stop no
    // longer name a live process. A pid alone is never enough because it can
    // be reused. This foundation has no real implementation.
    public interface IEngineServiceProcessIdentityProof
    {
        bool TryProveGone(int processId, long created100ns, out string code);
    }

    // One outer session gate. The repaired core session already serializes
    // its own calls and passes a token to a cancellable backend. This gate
    // adds the pipe-side boundary: it closes before a parent loss or service
    // stop waits, refuses new calls after close, marks the backend so a start
    // cannot pass the parent-loss boundary, and shares the one stop result
    // with every later trigger.
    //
    // A stop claim is never dropped. If the budget expires while a request
    // still holds the gate, the first caller reports engine_stop_timeout and
    // a clean-thread continuation keeps waiting for the gate. When the request
    // leaves, the continuation runs exactly one stop with the first reason.
    // Dispose refuses a new claim but keeps the gate alive for a claim that
    // already happened, until that one stop result is set.
    //
    // The gate does not store a credential and does not expose a credential
    // setter. The source-proxy start guard stays closed in this foundation.
    public sealed class EngineServiceSessionGate : IDisposable
    {
        private readonly EngineServiceSession session;
        private readonly IEngineServiceStopBoundary stopBoundary;
        private readonly SemaphoreSlim gate;
        private readonly TimeSpan stopWait;
        private readonly object stopSync = new object();
        private readonly object disposeSync = new object();
        private TaskCompletionSource<EngineServiceResult> stopCompletion;
        private EngineServiceStopReason stopReason;
        private bool stopServiceStop;
        private int closed;
        private int disposed;
        private int stopContinuationStarted;
        private bool gateDisposed;
        private bool stopOwnerRunning;
        private bool acceptingStops = true;

        public EngineServiceSessionGate(
            EngineServiceSession session,
            IEngineServiceStopBoundary stopBoundary,
            TimeSpan stopWait)
        {
            if (session == null)
            {
                throw new ArgumentNullException("session");
            }
            if (stopWait <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException("stopWait");
            }
            this.session = session;
            this.stopBoundary = stopBoundary;
            this.stopWait = stopWait;
            this.gate = new SemaphoreSlim(1, 1);
        }

        public EngineServiceSession Session
        {
            get { return session; }
        }

        public bool IsClosed
        {
            get { return Volatile.Read(ref closed) != 0; }
        }

        public bool StopClaimed
        {
            get
            {
                lock (stopSync)
                {
                    return stopCompletion != null;
                }
            }
        }

        // The first claimed stop reason. A later parent loss, cancellation,
        // shutdown, or logoff never replaces it.
        public EngineServiceStopReason StopReason
        {
            get
            {
                lock (stopSync)
                {
                    return stopCompletion == null
                        ? EngineServiceStopReason.None
                        : stopReason;
                }
            }
        }

        public async Task<EngineReply> HandleAsync(
            IReadOnlyDictionary<string, string> fields,
            CancellationToken cancellationToken)
        {
            if (IsClosed)
            {
                return EngineReply.Failure(EngineProtocol.ErrorCodes.Closed);
            }

            try
            {
                await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return EngineReply.Failure(EngineProtocol.ErrorCodes.Timeout);
            }
            catch (ObjectDisposedException)
            {
                return EngineReply.Failure(EngineProtocol.ErrorCodes.Closed);
            }

            try
            {
                if (IsClosed)
                {
                    return EngineReply.Failure(EngineProtocol.ErrorCodes.Closed);
                }
                // The core session passes this token to a cancellable
                // backend and turns an unconfirmed cancellation into
                // cleanup_unknown. The guarded backend implements that seam.
                return await session.HandleAsync(fields, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return EngineReply.Failure(EngineProtocol.ErrorCodes.Timeout);
            }
            catch (ObjectDisposedException)
            {
                return EngineReply.Failure(EngineProtocol.ErrorCodes.Closed);
            }
            catch (Exception)
            {
                return EngineReply.Failure(EngineProtocol.ErrorCodes.Internal);
            }
            finally
            {
                ReleaseGate();
            }
        }

        // The pipe broke. The gate is marked closed before it waits for an
        // in-flight request, and the backend stop boundary is set first. Only
        // one parent-loss or service-stop path runs.
        public EngineServiceResult ParentLost()
        {
            return RunOneStop(EngineServiceStopReason.ParentLost, false, CancellationToken.None);
        }

        // The pipe broke while a service stop may already be requested. The
        // cancellation state and the one stop claim are read together under
        // the stop lock, so a stop that lands after the listener's last check
        // but before this claim is reported as a service stop instead of a
        // parent loss. A cancellation that lands after the claim is too late:
        // the pipe break was observed first and the first reason is kept.
        public EngineServiceResult ParentLostUnlessStopRequested(
            CancellationToken cancellationToken)
        {
            return RunOneStop(EngineServiceStopReason.ParentLost, false, cancellationToken);
        }

        public EngineServiceResult ServiceStopped(EngineServiceStopReason reason)
        {
            if (reason != EngineServiceStopReason.ServiceStop
                && reason != EngineServiceStopReason.Shutdown
                && reason != EngineServiceStopReason.SessionLogoff)
            {
                throw new ArgumentException("invalid service stop reason", "reason");
            }
            return RunOneStop(reason, true, CancellationToken.None);
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0)
            {
                return;
            }
            Interlocked.Exchange(ref closed, 1);
            bool stopMustFinish;
            lock (stopSync)
            {
                // Refuse a new stop claim from now on. A claim that already
                // happened is not dropped: its owner keeps the gate alive
                // until the one stop result is set.
                acceptingStops = false;
                stopMustFinish = stopOwnerRunning
                    || (stopCompletion != null && !stopCompletion.Task.IsCompleted);
            }
            if (!stopMustFinish)
            {
                lock (disposeSync)
                {
                    DisposeGateLocked();
                }
            }
        }

        private EngineServiceResult RunOneStop(
            EngineServiceStopReason reason,
            bool serviceStop,
            CancellationToken stopRequested)
        {
            TaskCompletionSource<EngineServiceResult> completion;
            EngineServiceStopReason claimedReason;
            bool claimedServiceStop;
            bool owner = false;
            lock (stopSync)
            {
                if (!acceptingStops && stopCompletion == null)
                {
                    // Dispose already ran and no stop was claimed before it.
                    // A later trigger has no live generation to stop.
                    return EngineServiceResult.Failure(EngineProtocol.ErrorCodes.Closed);
                }
                if (stopCompletion == null)
                {
                    // A pipe break is a parent loss unless a service stop was
                    // already requested at the instant of this claim. Reading
                    // the token here closes the gap between the caller's check
                    // and the claim.
                    EngineServiceStopReason claimReason =
                        !serviceStop && stopRequested.IsCancellationRequested
                            ? EngineServiceStopReason.ServiceStop
                            : reason;
                    bool claimServiceStop =
                        serviceStop || claimReason == EngineServiceStopReason.ServiceStop;
                    stopCompletion = new TaskCompletionSource<EngineServiceResult>(
                        TaskCreationOptions.RunContinuationsAsynchronously);
                    stopReason = claimReason;
                    stopServiceStop = claimServiceStop;
                    stopOwnerRunning = true;
                    owner = true;
                }
                completion = stopCompletion;
                claimedReason = stopReason;
                claimedServiceStop = stopServiceStop;
            }

            if (!owner)
            {
                return WaitForSharedStop(completion);
            }

            Interlocked.Exchange(ref closed, 1);
            bool boundaryFailed = false;
            try
            {
                if (stopBoundary != null)
                {
                    stopBoundary.MarkStopRequested();
                }
            }
            catch (Exception)
            {
                // The stop still runs. A failed boundary mark is reported as
                // a failure, but it cannot be allowed to drop the stop.
                boundaryFailed = true;
            }

            bool entered;
            EngineServiceResult result = RunStopWithBudget(
                claimedReason,
                claimedServiceStop,
                out entered);
            if (!entered)
            {
                // The claim is kept even when Dispose runs now, because the
                // claimed owner keeps the gate alive until this one stop
                // completes. A request still holds the gate, so a later
                // continuation runs the stop with the first reason instead of
                // dropping it. The first caller still sees the timeout.
                ScheduleStopContinuation(
                    claimedReason,
                    claimedServiceStop,
                    boundaryFailed,
                    completion);
                return WithBoundaryFailure(result, boundaryFailed);
            }

            result = WithBoundaryFailure(result, boundaryFailed);
            completion.TrySetResult(result);
            SettleStopOwner();
            return result;
        }

        private EngineServiceResult RunStopWithBudget(
            EngineServiceStopReason reason,
            bool serviceStop,
            out bool entered)
        {
            entered = false;
            try
            {
                entered = gate.Wait(stopWait);
            }
            catch (ObjectDisposedException)
            {
                return EngineServiceResult.Failure(EngineProtocol.ErrorCodes.Closed);
            }
            catch (Exception)
            {
                return EngineServiceResult.Failure(EngineProtocol.ErrorCodes.Internal);
            }

            if (!entered)
            {
                return EngineServiceResult.Failure(
                    EngineProtocol.ErrorCodes.EngineStopTimeout);
            }

            try
            {
                return RunSessionStop(reason, serviceStop);
            }
            finally
            {
                ReleaseGate();
            }
        }

        private void ScheduleStopContinuation(
            EngineServiceStopReason reason,
            bool serviceStop,
            bool boundaryFailed,
            TaskCompletionSource<EngineServiceResult> completion)
        {
            if (Interlocked.CompareExchange(ref stopContinuationStarted, 1, 0) != 0)
            {
                return;
            }

            try
            {
                Task.Run(delegate
                {
                    EngineServiceResult result = RunStopContinuation(reason, serviceStop);
                    result = WithBoundaryFailure(result, boundaryFailed);
                    completion.TrySetResult(result);
                    SettleStopContinuation();
                });
            }
            catch (Exception)
            {
                completion.TrySetResult(
                    EngineServiceResult.Failure(EngineProtocol.ErrorCodes.Internal));
                SettleStopContinuation();
            }
        }

        private EngineServiceResult RunStopContinuation(
            EngineServiceStopReason reason,
            bool serviceStop)
        {
            bool entered = false;
            try
            {
                gate.Wait();
                entered = true;
                return RunSessionStop(reason, serviceStop);
            }
            catch (ObjectDisposedException)
            {
                return EngineServiceResult.Failure(EngineProtocol.ErrorCodes.Closed);
            }
            catch (Exception)
            {
                return EngineServiceResult.Failure(EngineProtocol.ErrorCodes.Internal);
            }
            finally
            {
                if (entered)
                {
                    ReleaseGate();
                }
            }
        }

        private static EngineServiceResult WithBoundaryFailure(
            EngineServiceResult result,
            bool boundaryFailed)
        {
            if (boundaryFailed && (result == null || result.Ok))
            {
                return EngineServiceResult.Failure(EngineProtocol.ErrorCodes.Internal);
            }
            return result;
        }

        private EngineServiceResult RunSessionStop(
            EngineServiceStopReason reason,
            bool serviceStop)
        {
            try
            {
                EngineServiceResult result = serviceStop
                    ? session.ServiceStopped(reason)
                    : session.ParentLost();
                // The core session can carry the first reason from an earlier
                // user stop or shutdown. Keep that reason instead of the
                // wrapper trigger that arrived later.
                EngineServiceStopReason actual = session.LastStop;
                if (actual != EngineServiceStopReason.None)
                {
                    lock (stopSync)
                    {
                        stopReason = actual;
                    }
                }
                return result;
            }
            catch (Exception)
            {
                return EngineServiceResult.Failure(EngineProtocol.ErrorCodes.Internal);
            }
        }

        private EngineServiceResult WaitForSharedStop(
            TaskCompletionSource<EngineServiceResult> completion)
        {
            // Every later trigger shares the first stop result. It must not
            // report success while the first stop is still running, timed out,
            // or failed.
            try
            {
                if (!completion.Task.Wait(stopWait))
                {
                    return EngineServiceResult.Failure(
                        EngineProtocol.ErrorCodes.EngineStopTimeout);
                }
                return completion.Task.Result;
            }
            catch (Exception)
            {
                return EngineServiceResult.Failure(EngineProtocol.ErrorCodes.Internal);
            }
        }

        private void SettleStopOwner()
        {
            lock (stopSync)
            {
                stopOwnerRunning = false;
            }
            lock (disposeSync)
            {
                if (Volatile.Read(ref disposed) != 0)
                {
                    DisposeGateLocked();
                }
            }
        }

        private void SettleStopContinuation()
        {
            lock (stopSync)
            {
                stopOwnerRunning = false;
            }
            lock (disposeSync)
            {
                if (Volatile.Read(ref disposed) != 0)
                {
                    DisposeGateLocked();
                }
            }
        }

        private void ReleaseGate()
        {
            try
            {
                gate.Release();
            }
            catch (ObjectDisposedException)
            {
                // Dispose already released the semaphore after this request
                // left the stop path. The request result still stands.
            }
        }

        private void DisposeGateLocked()
        {
            if (gateDisposed)
            {
                return;
            }
            gateDisposed = true;
            try
            {
                gate.Dispose();
            }
            catch (ObjectDisposedException)
            {
                // Dispose is idempotent for this gate.
            }
        }
    }
}
