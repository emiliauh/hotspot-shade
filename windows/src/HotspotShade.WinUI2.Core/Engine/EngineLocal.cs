using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace HotspotShade.WinUI2.Core.Engine
{
    // One bounded, non-secret view of the local Rust engine. The full-trust
    // broker fills this from the engine status it already redacts. It never
    // holds a source device token, an identity key, a file path, a host, or an
    // address.
    public sealed class EngineLocalStatus
    {
        private EngineLocalStatus(
            bool reachable,
            bool wellFormed,
            string failureCode,
            bool administrator,
            bool running,
            bool paired,
            bool sourcePresent,
            bool trustedBySource,
            bool pingEnabled,
            bool connectionsKnown,
            int connections,
            EngineStopReason stop)
        {
            Reachable = reachable;
            WellFormed = wellFormed;
            FailureCode = failureCode ?? "";
            Administrator = administrator;
            Running = running;
            Paired = paired;
            SourcePresent = sourcePresent;
            TrustedBySource = trustedBySource;
            PingEnabled = pingEnabled;
            ConnectionsKnown = connectionsKnown;
            Connections = connections;
            Stop = stop;
        }

        public bool Reachable { get; private set; }

        public bool WellFormed { get; private set; }

        // One fixed protocol code when the read failed. It is empty for a
        // well-formed status.
        public string FailureCode { get; private set; }

        // True only when the engine process reports an elevated token. A
        // non-elevated engine cannot create an adapter or a route, so the
        // broker refuses a start.
        public bool Administrator { get; private set; }

        public bool Running { get; private set; }

        public bool Paired { get; private set; }

        public bool SourcePresent { get; private set; }

        public bool TrustedBySource { get; private set; }

        public bool PingEnabled { get; private set; }

        public bool ConnectionsKnown { get; private set; }

        public int Connections { get; private set; }

        public EngineStopReason Stop { get; private set; }

        public static EngineLocalStatus Unreachable(string code)
        {
            string fixedCode = EngineProtocol.IsKnownErrorCode(code)
                ? code
                : EngineProtocol.ErrorCodes.EngineUnavailable;
            return new EngineLocalStatus(
                false,
                false,
                fixedCode,
                false,
                false,
                false,
                false,
                false,
                false,
                true,
                0,
                EngineStopReason.None);
        }

        // The engine answered with text that this broker does not understand.
        // The tunnel state is unknown; the app must not show an off claim.
        public static EngineLocalStatus Malformed()
        {
            return new EngineLocalStatus(
                true,
                false,
                EngineProtocol.ErrorCodes.BadResponse,
                false,
                false,
                false,
                false,
                false,
                false,
                false,
                0,
                EngineStopReason.None);
        }

        public static EngineLocalStatus Status(
            bool administrator,
            bool running,
            bool paired,
            bool sourcePresent,
            bool trustedBySource,
            bool pingEnabled,
            bool connectionsKnown,
            int connections,
            EngineStopReason stop)
        {
            if (!Enum.IsDefined(typeof(EngineStopReason), stop)
                || connections < 0
                || connections > 100000
                || (!connectionsKnown && connections != 0))
            {
                return Malformed();
            }
            return new EngineLocalStatus(
                true,
                true,
                "",
                administrator,
                running,
                paired,
                paired && sourcePresent,
                paired && trustedBySource,
                pingEnabled,
                connectionsKnown,
                connections,
                stop);
        }
    }

    // One fixed result from a start or stop request to the local engine.
    public sealed class EngineLocalResult
    {
        private EngineLocalResult(bool ok, string code)
        {
            Ok = ok;
            Code = ok ? "" : (EngineProtocol.IsKnownErrorCode(code)
                ? code
                : EngineProtocol.ErrorCodes.EngineUnavailable);
        }

        public bool Ok { get; private set; }

        public string Code { get; private set; }

        public static EngineLocalResult Success()
        {
            return new EngineLocalResult(true, "");
        }

        public static EngineLocalResult Failure(string code)
        {
            return new EngineLocalResult(false, code);
        }
    }

    // The broker-side seam to the local engine. The Windows implementation
    // speaks to 127.0.0.1 with the per-launch bearer secret. A test fake
    // supplies fixed values and opens no endpoint.
    public interface IEngineLocalClient
    {
        Task<EngineLocalStatus> ReadStatusAsync(CancellationToken cancellationToken);

        Task<EngineLocalResult> StartAsync(bool ping, CancellationToken cancellationToken);

        Task<EngineLocalResult> StopAsync(CancellationToken cancellationToken);

        Task CloseAsync();
    }

    // The broker-side IEngineBroker. It turns the local engine status into the
    // version 1 wire fields. It adds no network address and no credential.
    // The app session still validates every reply, so a bad status becomes a
    // fixed error and never an On claim.
    public sealed class EngineLocalBroker : IEngineBroker
    {
        private readonly IEngineLocalClient client;
        private readonly string instanceId;
        private readonly TimeSpan callTimeout;

        public EngineLocalBroker(
            IEngineLocalClient client,
            string instanceId,
            TimeSpan callTimeout)
        {
            if (client == null)
            {
                throw new ArgumentNullException("client");
            }
            if (!EngineProtocol.IsValidInstanceId(instanceId))
            {
                throw new ArgumentException("invalid instance id", "instanceId");
            }
            if (callTimeout <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException("callTimeout");
            }
            this.client = client;
            this.instanceId = instanceId;
            this.callTimeout = callTimeout;
        }

        public string InstanceId
        {
            get { return instanceId; }
        }

        public async Task<EngineReply> SendAsync(
            EngineRequest request,
            CancellationToken cancellationToken)
        {
            if (request == null)
            {
                return EngineReply.Failure(EngineProtocol.ErrorCodes.BadRequest);
            }

            using (CancellationTokenSource timeout = new CancellationTokenSource())
            {
                using (CancellationTokenSource linked = CancellationTokenSource.CreateLinkedTokenSource(
                    cancellationToken,
                    timeout.Token))
                {
                    timeout.CancelAfter(callTimeout);
                    try
                    {
                        switch (request.Operation)
                        {
                            case EngineProtocol.Operations.Hello:
                                return await HelloAsync(linked.Token).ConfigureAwait(false);
                            case EngineProtocol.Operations.Status:
                                return await StatusAsync(linked.Token).ConfigureAwait(false);
                            case EngineProtocol.Operations.Start:
                                return await StartAsync(request.Ping, linked.Token).ConfigureAwait(false);
                            case EngineProtocol.Operations.Stop:
                                return await StopAsync(linked.Token).ConfigureAwait(false);
                            case EngineProtocol.Operations.Shutdown:
                                // The host closes the parent-liveness handle. The
                                // engine removes what it created on its own exit
                                // path, so this request has no engine endpoint.
                                return EngineReply.Success(null);
                            default:
                                return EngineReply.Failure(EngineProtocol.ErrorCodes.Unsupported);
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        return EngineReply.Failure(EngineProtocol.ErrorCodes.Timeout);
                    }
                    catch (Exception)
                    {
                        return EngineReply.Failure(EngineProtocol.ErrorCodes.EngineUnavailable);
                    }
                }
            }
        }

        public async Task CloseAsync()
        {
            try
            {
                await client.CloseAsync().ConfigureAwait(false);
            }
            catch (Exception)
            {
                // A close path that throws cannot leave the broker with an
                // engine claim. The host still owns the process.
            }
        }

        private async Task<EngineReply> HelloAsync(CancellationToken cancellationToken)
        {
            EngineLocalStatus status = await client.ReadStatusAsync(cancellationToken)
                .ConfigureAwait(false);
            if (status == null)
            {
                return EngineReply.Failure(EngineProtocol.ErrorCodes.BadResponse);
            }
            if (!status.WellFormed)
            {
                return EngineReply.Failure(status.FailureCode);
            }
            return EngineReply.Success(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                { EngineProtocol.Keys.Instance, instanceId },
                { EngineProtocol.Keys.Engine, EngineWord(status) }
            });
        }

        private async Task<EngineReply> StatusAsync(CancellationToken cancellationToken)
        {
            EngineLocalStatus status = await client.ReadStatusAsync(cancellationToken)
                .ConfigureAwait(false);
            if (status == null)
            {
                return EngineReply.Failure(EngineProtocol.ErrorCodes.BadResponse);
            }
            if (!status.WellFormed)
            {
                return EngineReply.Failure(status.FailureCode);
            }
            if (status.Running && !status.ConnectionsKnown)
            {
                // A running tunnel with no connection count would be a false
                // value. The app must show an unknown state instead.
                return EngineReply.Failure(EngineProtocol.ErrorCodes.BadResponse);
            }

            EngineRunState engine = status.Running
                ? EngineRunState.Running
                : EngineRunState.Ready;
            string consistency;
            if (!EngineRules.IsConsistent(
                engine,
                status.Paired,
                status.Running,
                status.SourcePresent,
                status.TrustedBySource,
                status.Running ? status.Connections : 0,
                status.Stop,
                out consistency))
            {
                return EngineReply.Failure(EngineProtocol.ErrorCodes.BadResponse);
            }

            return EngineReply.Success(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                { EngineProtocol.Keys.Instance, instanceId },
                { EngineProtocol.Keys.Engine, EngineRules.EngineWord(engine) },
                { EngineProtocol.Keys.Paired, BoolWord(status.Paired) },
                { EngineProtocol.Keys.Running, BoolWord(status.Running) },
                { EngineProtocol.Keys.Source, BoolWord(status.SourcePresent) },
                { EngineProtocol.Keys.Trusted, BoolWord(status.TrustedBySource) },
                { EngineProtocol.Keys.Ping, BoolWord(status.PingEnabled) },
                { EngineProtocol.Keys.Connections, CountWord(status.Running ? status.Connections : 0) },
                { EngineProtocol.Keys.Stop, EngineRules.StopWord(status.Stop) }
            });
        }

        private async Task<EngineReply> StartAsync(bool ping, CancellationToken cancellationToken)
        {
            EngineLocalResult result = await client.StartAsync(ping, cancellationToken)
                .ConfigureAwait(false);
            if (result == null)
            {
                return EngineReply.Failure(EngineProtocol.ErrorCodes.BadResponse);
            }
            return result.Ok
                ? EngineReply.Success(null)
                : EngineReply.Failure(result.Code);
        }

        private async Task<EngineReply> StopAsync(CancellationToken cancellationToken)
        {
            EngineLocalResult result = await client.StopAsync(cancellationToken)
                .ConfigureAwait(false);
            if (result == null)
            {
                return EngineReply.Failure(EngineProtocol.ErrorCodes.BadResponse);
            }
            return result.Ok
                ? EngineReply.Success(null)
                : EngineReply.Failure(result.Code);
        }

        private string EngineWord(EngineLocalStatus status)
        {
            if (!status.Reachable)
            {
                return EngineProtocol.EngineStates.Unavailable;
            }
            return status.Running
                ? EngineProtocol.EngineStates.Running
                : EngineProtocol.EngineStates.Ready;
        }

        private static string BoolWord(bool value)
        {
            return value ? "1" : "0";
        }

        private static string CountWord(int value)
        {
            return value.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }
    }
}
