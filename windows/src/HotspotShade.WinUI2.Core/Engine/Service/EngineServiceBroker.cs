using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;

namespace HotspotShade.WinUI2.Core.Engine.Service
{
    // The app-side bridge from the authenticated engine service to the app
    // engine state machine.
    //
    // The service speaks its own status dialect. It names a source check time,
    // an unknown connection count, the cleanup gate, the TTL audit count, and
    // precise stop reasons. The version 1 broker dialect has no field for the
    // first four and names fewer stops. Passing the service fields straight
    // through would be refused as a bad response, and mapping them into a
    // false known count or a generic stop would weaken what the person sees.
    // This adapter therefore reads the service status with the service parser
    // and writes the app dialect with the evidence fields the app needs.
    //
    // It sends whole service frames through EngineServiceClient, so the
    // per-operation budgets, the strict reply reader, and the ambiguous
    // outcome handling are the same as every other service caller. It opens no
    // endpoint by itself: the caller supplies an IEngineServiceChannel. The
    // Windows named-pipe channel is WindowsEngineServiceChannel. A test
    // supplies a framed loopback to a real service session.
    //
    // The adapter never claims a tunnel state. Only EngineSession and
    // EngineBoundary may show On, and only from a fresh status that the app
    // state machine accepted.
    public sealed class EngineServiceBroker : IEngineBroker
    {
        private readonly EngineServiceClient client;
        private readonly IEngineClock clock;

        public EngineServiceBroker(IEngineServiceChannel channel, IEngineClock clock)
            : this(channel, clock, EngineServiceCallBudgets.Default)
        {
        }

        public EngineServiceBroker(IEngineServiceChannel channel, IEngineClock clock, TimeSpan callTimeout)
            : this(channel, clock, EngineServiceCallBudgets.Uniform(callTimeout))
        {
        }

        public EngineServiceBroker(
            IEngineServiceChannel channel,
            IEngineClock clock,
            EngineServiceCallBudgets budgets)
        {
            if (channel == null)
            {
                throw new ArgumentNullException("channel");
            }
            if (clock == null)
            {
                throw new ArgumentNullException("clock");
            }
            if (budgets == null)
            {
                throw new ArgumentNullException("budgets");
            }
            this.clock = clock;
            client = new EngineServiceClient(channel, budgets);
        }

        public EngineServiceCallBudgets Budgets
        {
            get { return client.Budgets; }
        }

        public async Task<EngineReply> SendAsync(
            EngineRequest request,
            CancellationToken cancellationToken)
        {
            if (request == null)
            {
                return EngineReply.Failure(EngineProtocol.ErrorCodes.BadRequest);
            }

            EngineReply reply = await client.SendAsync(request, cancellationToken)
                .ConfigureAwait(false);
            if (reply == null)
            {
                // A client that returns no reply cannot prove a clean refusal.
                return EngineReply.UnknownOutcome(EngineProtocol.ErrorCodes.BadResponse);
            }
            if (!reply.Ok)
            {
                // A validated failure and an ambiguous outcome both pass
                // through unchanged. The app state machine decides what a
                // failed start, stop, or forget means.
                return reply;
            }
            if (request.Operation != EngineProtocol.Operations.Status)
            {
                // Hello, start, and stop carry no status body. The service
                // reply is already in the app dialect.
                return reply;
            }

            EngineServiceStatus status;
            string code;
            if (!EngineServiceStatus.TryParse(reply.Fields, clock.Now, out status, out code))
            {
                // The reply arrived and failed the service schema. A status
                // read changes no state, so this is a clean refusal and the
                // app must not show a tunnel state from it.
                return EngineReply.Failure(code);
            }

            return EngineReply.Success(MapStatus(status));
        }

        public Task CloseAsync()
        {
            return client.CloseAsync();
        }

        // Translate one validated service status into the app dialect. The
        // optional fields carry evidence instead of invented values:
        // checked_at is the source check time, connections_known is false when
        // no count exists, cleanup carries the previous run gate, and ttl_bad
        // carries the audit count.
        public static Dictionary<string, string> MapStatus(EngineServiceStatus status)
        {
            if (status == null)
            {
                throw new ArgumentNullException("status");
            }

            Dictionary<string, string> fields =
                new Dictionary<string, string>(StringComparer.Ordinal);
            fields[EngineProtocol.Keys.Instance] = status.InstanceId;
            fields[EngineProtocol.Keys.Engine] = EngineRules.EngineWord(status.Engine);
            fields[EngineProtocol.Keys.Paired] = BoolWord(status.Paired);
            fields[EngineProtocol.Keys.Running] = BoolWord(status.Running);
            fields[EngineProtocol.Keys.Source] = BoolWord(status.SourcePresent);
            fields[EngineProtocol.Keys.Trusted] = BoolWord(status.TrustedBySource);
            // The app displays the active relay state, not the requested
            // preference. The service reports those as separate fields.
            fields[EngineProtocol.Keys.Ping] = BoolWord(status.IcmpEnabled);

            // The target-side relay gauge is the analogue of the old broker
            // connection count. The source device answer is a second choice.
            int? count = status.RelayTcpFlowsActive ?? status.PhoneConnections;
            bool connectionsKnown = count.HasValue;
            int connections = count.HasValue ? count.Value : 0;
            if (!status.Running)
            {
                // A stopped tunnel has no open connection. The count is zero,
                // not unknown, and EngineRules refuses a non-zero stopped
                // count.
                connections = 0;
                connectionsKnown = true;
            }
            fields[EngineProtocol.Keys.Connections] =
                connections.ToString(CultureInfo.InvariantCulture);
            fields[EngineProtocol.Keys.ConnectionsKnown] = BoolWord(connectionsKnown);

            fields[EngineProtocol.Keys.Stop] = EngineRules.StopWord(MapStop(status.Stop));
            fields[EngineProtocol.Keys.Cleanup] =
                EngineRules.CleanupWord(MapCleanup(status.Cleanup, status.Running));
            fields[EngineProtocol.Keys.TtlBad] =
                status.TtlBad.ToString(CultureInfo.InvariantCulture);

            if (status.CheckedAt.HasValue)
            {
                fields[EngineProtocol.Keys.CheckedAt] =
                    status.CheckedAt.Value.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
            }

            return fields;
        }

        // A running service status has no previous run to clean up, so the
        // cleanup gate is Ok while the tunnel runs. A stopped status keeps the
        // service word so the app can refuse a start for the same reason the
        // service would.
        private static EngineCleanup MapCleanup(EngineServiceCleanup cleanup, bool running)
        {
            if (running)
            {
                return EngineCleanup.Ok;
            }
            switch (cleanup)
            {
                case EngineServiceCleanup.Failed:
                    return EngineCleanup.Failed;
                case EngineServiceCleanup.Pending:
                    return EngineCleanup.Pending;
                case EngineServiceCleanup.Unknown:
                    return EngineCleanup.Unknown;
                default:
                    return EngineCleanup.Ok;
            }
        }

        private static EngineStopReason MapStop(EngineServiceStopReason stop)
        {
            switch (stop)
            {
                case EngineServiceStopReason.User:
                    return EngineStopReason.User;
                case EngineServiceStopReason.SourceDeviceGone:
                    return EngineStopReason.SourceDeviceGone;
                case EngineServiceStopReason.ObservationUnavailable:
                    return EngineStopReason.ObservationUnavailable;
                case EngineServiceStopReason.GatewayChanged:
                    return EngineStopReason.GatewayChanged;
                case EngineServiceStopReason.LinkChanged:
                    return EngineStopReason.LinkChanged;
                case EngineServiceStopReason.EngineLost:
                    return EngineStopReason.EngineLost;
                case EngineServiceStopReason.StartFailed:
                    return EngineStopReason.StartFailed;
                case EngineServiceStopReason.ParentLost:
                    return EngineStopReason.ParentLost;
                case EngineServiceStopReason.ServiceStop:
                    return EngineStopReason.ServiceStop;
                case EngineServiceStopReason.Shutdown:
                    return EngineStopReason.Shutdown;
                case EngineServiceStopReason.SessionLogoff:
                    return EngineStopReason.SessionLogoff;
                case EngineServiceStopReason.Unknown:
                    return EngineStopReason.Unknown;
                default:
                    return EngineStopReason.None;
            }
        }

        private static string BoolWord(bool value)
        {
            return value ? "1" : "0";
        }
    }
}
