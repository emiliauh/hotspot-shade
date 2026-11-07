using System;
using System.Threading;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.ServiceHost
{
    // The service-side backend foundation. It performs the durable-record and
    // status preconditions, then refuses every start because the Windows
    // source-proxy engine guard is closed. It has no process, route, adapter,
    // or launch path. A future reviewed host must not add one until the guard
    // opens and the design gates pass.
    //
    // The backend implements the core cancellable seam. A canceled or
    // unconfirmed start or stop is cleanup_unknown, never success. The
    // foundation has no blocking launch or stop work to cancel; a future
    // implementation must keep its own work bounded by the token.
    public sealed class GuardedEngineServiceBackend :
        IEngineServiceBackend,
        IEngineServiceStatusErrorSource,
        IEngineServiceCancellableBackend,
        IEngineServiceStopBoundary
    {
        private readonly IEngineServiceStatusSource statusSource;
        private readonly EngineServiceStatusGate statusGate;
        private readonly EngineServiceDurableStateGate stateGate;
        private readonly IEngineClock clock;
        private readonly IEngineServiceEventSink events;
        private readonly IEngineControlSession control;
        private int stopRequested;

        public GuardedEngineServiceBackend(
            IEngineServiceStatusSource statusSource,
            EngineServiceStatusGate statusGate,
            EngineServiceDurableStateGate stateGate,
            IEngineClock clock,
            IEngineServiceEventSink events)
            : this(statusSource, statusGate, stateGate, clock, events, null)
        {
        }

        public GuardedEngineServiceBackend(
            IEngineServiceStatusSource statusSource,
            EngineServiceStatusGate statusGate,
            EngineServiceDurableStateGate stateGate,
            IEngineClock clock,
            IEngineServiceEventSink events,
            IEngineControlSession control)
        {
            if (statusSource == null)
            {
                throw new ArgumentNullException("statusSource");
            }
            if (statusGate == null)
            {
                throw new ArgumentNullException("statusGate");
            }
            if (stateGate == null)
            {
                throw new ArgumentNullException("stateGate");
            }
            if (clock == null)
            {
                throw new ArgumentNullException("clock");
            }
            if (events == null)
            {
                throw new ArgumentNullException("events");
            }
            this.statusSource = statusSource;
            this.statusGate = statusGate;
            this.stateGate = stateGate;
            this.clock = clock;
            this.events = events;
            this.control = control;
        }

        // Always false in this foundation. Do not replace this property with a
        // constant that the compiler can fold away, and do not add a launch
        // delegate behind it.
        public static bool SourceProxyStartEnabled
        {
            get { return false; }
        }

        public EngineServiceStatus ReadStatus()
        {
            EngineServiceStatus status;
            string code;
            return TryReadStatus(out status, out code) ? status : null;
        }

        public bool TryReadStatus(out EngineServiceStatus status, out string code)
        {
            status = null;
            DateTimeOffset readAt;
            try
            {
                if (!statusSource.TryRead(clock.Now, out status, out readAt, out code))
                {
                    status = null;
                    return false;
                }
            }
            catch (Exception)
            {
                status = null;
                code = EngineProtocol.ErrorCodes.EngineUnavailable;
                return false;
            }
            if (!statusGate.TryAccept(status, readAt, clock.Now, out code))
            {
                status = null;
                return false;
            }
            return true;
        }

        public EngineServiceResult Start(bool ping)
        {
            return Start(ping, CancellationToken.None);
        }

        public EngineServiceResult Start(bool ping, CancellationToken cancellationToken)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                return EngineServiceResult.CleanupUnknown();
            }
            if (Volatile.Read(ref stopRequested) != 0)
            {
                return EngineServiceResult.Failure(EngineProtocol.ErrorCodes.Closed);
            }

            EngineServiceStateRecord record;
            string code;
            if (!stateGate.TryRead(out record, out code))
            {
                return EngineServiceResult.Failure(code);
            }
            if (cancellationToken.IsCancellationRequested)
            {
                return EngineServiceResult.CleanupUnknown();
            }

            EngineServiceStatus status;
            if (!TryReadStatus(out status, out code) || status == null)
            {
                return EngineServiceResult.Failure(
                    cancellationToken.IsCancellationRequested
                        ? EngineProtocol.ErrorCodes.CleanupUnknown
                        : (EngineProtocol.IsKnownErrorCode(code)
                            ? code : EngineProtocol.ErrorCodes.EngineUnavailable));
            }
            if (status.Running)
            {
                return EngineServiceResult.Failure(EngineProtocol.ErrorCodes.AlreadyRunning);
            }
            if (status.Cleanup == EngineServiceCleanup.Failed)
            {
                return EngineServiceResult.Failure(EngineProtocol.ErrorCodes.CleanupBlocked);
            }
            if (status.Cleanup == EngineServiceCleanup.Unknown)
            {
                return EngineServiceResult.Failure(EngineProtocol.ErrorCodes.CleanupUnknown);
            }
            if (status.Cleanup == EngineServiceCleanup.Pending)
            {
                return EngineServiceResult.Failure(EngineProtocol.ErrorCodes.CleanupPending);
            }
            if (status.FreshnessAt(clock.Now) != EngineFreshness.Fresh)
            {
                return EngineServiceResult.Failure(EngineProtocol.ErrorCodes.StaleStatus);
            }
            if (!status.Paired)
            {
                return EngineServiceResult.Failure(EngineProtocol.ErrorCodes.NotPaired);
            }
            if (status.Mode != EngineServiceMode.Phone)
            {
                return EngineServiceResult.Failure(EngineProtocol.ErrorCodes.ManualPhone);
            }
            if (status.Engine == EngineRunState.Unavailable)
            {
                return EngineServiceResult.Failure(EngineProtocol.ErrorCodes.EngineUnavailable);
            }
            if (status.Engine != EngineRunState.Ready)
            {
                return EngineServiceResult.Failure(EngineProtocol.ErrorCodes.NotReady);
            }
            if (!status.SourcePresent)
            {
                return EngineServiceResult.Failure(EngineProtocol.ErrorCodes.SourceMissing);
            }
            if (Volatile.Read(ref stopRequested) != 0)
            {
                return EngineServiceResult.Failure(EngineProtocol.ErrorCodes.Closed);
            }
            if (cancellationToken.IsCancellationRequested)
            {
                return EngineServiceResult.CleanupUnknown();
            }

            // The token destination proof on Windows still returns
            // ErrorKind::Unsupported. No caller may start source-proxy mode
            // from this foundation. A control session can read status and run
            // one stop, but this guard keeps every start refusal.
            if (!SourceProxyStartEnabled)
            {
                events.Record(EngineServiceEventCodes.SourceProxyGuardClosed);
                return EngineServiceResult.Failure(EngineProtocol.ErrorCodes.Unsupported);
            }

            // Unreachable in this build. It exists so a future change must
            // replace this method, add a reviewed launch path, and pass the
            // design gates before any process can start.
            events.Record(EngineServiceEventCodes.SourceProxyGuardClosed);
            return EngineServiceResult.Failure(EngineProtocol.ErrorCodes.Unsupported);
        }

        public EngineServiceResult Stop(EngineServiceStopReason reason)
        {
            return Stop(reason, CancellationToken.None);
        }

        public EngineServiceResult Stop(
            EngineServiceStopReason reason,
            CancellationToken cancellationToken)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                return EngineServiceResult.CleanupUnknown();
            }

            // A missing channel does not prove that a previous engine is
            // absent or that a failed launcher left no engine behind.
            if (control == null)
            {
                return EngineServiceResult.CleanupUnknown();
            }

            // One authenticated stop request. The engine stop is idempotent.
            // The acknowledgement alone does not prove that the engine exited
            // or that cleanup completed. Until that proof is connected, both
            // an acknowledgement and a failure leave cleanup unknown. Do not
            // replay the request.
            string code;
            if (control.TryStop(out code))
            {
                return EngineServiceResult.CleanupUnknown();
            }
            events.Record(EngineServiceEventCodes.ControlStopFailed);
            return EngineServiceResult.Failure(EngineProtocol.ErrorCodes.CleanupUnknown);
        }

        public void MarkStopRequested()
        {
            Interlocked.Exchange(ref stopRequested, 1);
        }
    }
}
