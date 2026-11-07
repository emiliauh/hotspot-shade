using System;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.ServiceHost
{
    // Accepts one service status read. The core status parser already checks
    // the field schema and many consistency rules. This gate adds the checks
    // the service host must not leave to a cached status object:
    //   - the instance id must be the current service instance,
    //   - the read time and the parse time must be recent and not future,
    //   - a running status must have unknown cleanup and no stop,
    //   - an unconfirmed cleanup remains visible but cannot authorize a start.
    public sealed class EngineServiceStatusGate
    {
        private readonly string serviceInstanceId;
        private readonly IEngineServiceEventSink events;
        private readonly TimeSpan maxAge;
        private readonly TimeSpan maxSkew;

        public EngineServiceStatusGate(
            string serviceInstanceId,
            IEngineServiceEventSink events,
            TimeSpan maxAge,
            TimeSpan maxSkew)
        {
            if (!EngineProtocol.IsValidInstanceId(serviceInstanceId))
            {
                throw new ArgumentException("invalid service instance id", "serviceInstanceId");
            }
            if (events == null)
            {
                throw new ArgumentNullException("events");
            }
            if (maxAge <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException("maxAge");
            }
            if (maxSkew < TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException("maxSkew");
            }
            this.serviceInstanceId = serviceInstanceId;
            this.events = events;
            this.maxAge = maxAge;
            this.maxSkew = maxSkew;
        }

        public bool TryAccept(
            EngineServiceStatus status,
            DateTimeOffset readAt,
            DateTimeOffset now,
            out string code)
        {
            if (status == null)
            {
                code = EngineProtocol.ErrorCodes.EngineUnavailable;
                return false;
            }

            if (!string.Equals(status.InstanceId, serviceInstanceId, StringComparison.Ordinal))
            {
                events.Record(EngineServiceEventCodes.StatusInstanceMismatch);
                code = EngineProtocol.ErrorCodes.EngineRestarted;
                return false;
            }

            if (readAt > now + maxSkew || status.ObservedAt > now + maxSkew)
            {
                events.Record(EngineServiceEventCodes.StatusFuture);
                code = EngineProtocol.ErrorCodes.StaleStatus;
                return false;
            }
            if (now - readAt > maxAge || now - status.ObservedAt > maxAge)
            {
                events.Record(EngineServiceEventCodes.StatusStale);
                code = EngineProtocol.ErrorCodes.StaleStatus;
                return false;
            }

            if (status.Running)
            {
                if (status.Engine != EngineRunState.Running
                    || status.Cleanup != EngineServiceCleanup.Unknown
                    || status.Stop != EngineServiceStopReason.None
                    || status.StopAt.HasValue)
                {
                    events.Record(EngineServiceEventCodes.StatusInconsistent);
                    code = EngineProtocol.ErrorCodes.BadResponse;
                    return false;
                }
            }
            else
            {
                if (status.Engine == EngineRunState.Running)
                {
                    events.Record(EngineServiceEventCodes.StatusInconsistent);
                    code = EngineProtocol.ErrorCodes.BadResponse;
                    return false;
                }
                if (status.Stop == EngineServiceStopReason.None)
                {
                    // No stop reason does not prove a clean state. An unknown
                    // cleanup is a valid status and is separately refused by
                    // both start gates; it must not hide the whole status.
                    if (status.Cleanup != EngineServiceCleanup.Ok
                        && status.Cleanup != EngineServiceCleanup.Unknown)
                    {
                        events.Record(EngineServiceEventCodes.StatusInconsistent);
                        code = status.Cleanup == EngineServiceCleanup.Pending
                            ? EngineProtocol.ErrorCodes.CleanupPending
                            : EngineProtocol.ErrorCodes.CleanupBlocked;
                        return false;
                    }
                }
                else if (!status.StopAt.HasValue)
                {
                    events.Record(EngineServiceEventCodes.StatusInconsistent);
                    code = EngineProtocol.ErrorCodes.BadResponse;
                    return false;
                }
            }

            code = "";
            return true;
        }
    }
}
