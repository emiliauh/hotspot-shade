using System;
using System.Collections.Generic;

namespace HotspotShade.WinUI2.Core.Engine
{
    // Fixed broker constants. The loopback port is chosen once per broker
    // launch from the dynamic range. It is not a secret; the per-launch bearer
    // secret authenticates every request to the engine.
    public static class EngineBrokerRules
    {
        public const int FirstPort = 49152;
        public const int LastPort = 65535;
        public const int MaxConcurrentRequests = 4;

        // The browser GUI default and the pairing port must never be used by a
        // broker-started engine.
        public const int BrowserGuiPort = 8787;
        public const int PairingPort = 18090;

        public static bool IsBrokerPort(int port)
        {
            return port >= FirstPort
                && port <= LastPort
                && port != BrowserGuiPort
                && port != PairingPort
                && EngineLaunchRules.IsValidPort(port);
        }

        // One random port in the dynamic range. The caller passes it to the
        // engine and connects to the same port. A collision is not retried: a
        // second engine launch is not allowed.
        public static int PickPort()
        {
            byte[] bytes = new byte[2];
            try
            {
                using (System.Security.Cryptography.RandomNumberGenerator generator =
                    System.Security.Cryptography.RandomNumberGenerator.Create())
                {
                    generator.GetBytes(bytes);
                }
                int value = (bytes[0] << 8) | bytes[1];
                return FirstPort + (value % (LastPort - FirstPort + 1));
            }
            finally
            {
                Array.Clear(bytes, 0, bytes.Length);
            }
        }
    }

    // The strict app-service to engine request mapping. Every value from the
    // app service ValueSet must be a string. No nested value, credential key,
    // duplicate key, or oversized field crosses the boundary.
    public static class EngineBrokerFields
    {
        public static bool TryConvert(
            IEnumerable<KeyValuePair<string, object>> pairs,
            out Dictionary<string, string> fields,
            out string code)
        {
            fields = null;
            code = EngineProtocol.ErrorCodes.BadRequest;
            if (pairs == null)
            {
                return false;
            }

            Dictionary<string, string> values =
                new Dictionary<string, string>(StringComparer.Ordinal);
            int total = 0;
            foreach (KeyValuePair<string, object> pair in pairs)
            {
                if (values.Count >= EngineProtocol.MaxFieldCount)
                {
                    return false;
                }
                string value = pair.Value as string;
                if (value == null)
                {
                    return false;
                }
                if (!EngineProtocol.IsSafeFieldName(pair.Key)
                    || !EngineProtocol.IsSafeFieldValue(value))
                {
                    return false;
                }
                if (EngineProtocol.IsCredentialKey(pair.Key))
                {
                    code = EngineProtocol.ErrorCodes.Forbidden;
                    return false;
                }
                if (values.ContainsKey(pair.Key))
                {
                    return false;
                }
                total += pair.Key.Length + value.Length;
                if (total > EngineProtocol.MaxTextLength)
                {
                    return false;
                }
                values[pair.Key] = value;
            }

            if (values.Count < 1)
            {
                return false;
            }
            fields = values;
            code = "";
            return true;
        }
    }

    // The version 1 broker core. It is transport free so the same code serves
    // the app service and the hermetic checks. It never starts a tunnel on its
    // own: every start is one explicit app request, and the app session still
    // waits for a fresh status before it shows On.
    public sealed class EngineBrokerService
    {
        private readonly EngineStartup startup;
        private readonly EngineLaunchPlan plan;
        private readonly TimeSpan callTimeout;
        private readonly System.Threading.SemaphoreSlim gate =
            new System.Threading.SemaphoreSlim(1, 1);

        private string sessionId;
        private int shutdownRequested;

        public EngineBrokerService(
            EngineStartup startup,
            EngineLaunchPlan plan,
            TimeSpan callTimeout)
        {
            if (startup == null)
            {
                throw new ArgumentNullException("startup");
            }
            if (callTimeout <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException("callTimeout");
            }
            this.startup = startup;
            this.plan = plan;
            this.callTimeout = callTimeout;
        }

        public bool ShutdownRequested
        {
            get { return System.Threading.Volatile.Read(ref shutdownRequested) != 0; }
        }

        public string BoundSessionId
        {
            get { return sessionId; }
        }

        public async System.Threading.Tasks.Task<EngineReply> HandleAsync(
            IReadOnlyDictionary<string, string> fields,
            System.Threading.CancellationToken cancellationToken)
        {
            EngineRequest request;
            string code;
            if (!EngineWire.TryReadRequest(fields, out request, out code))
            {
                return EngineReply.Failure(code);
            }

            bool entered = false;
            try
            {
                entered = await gate.WaitAsync(callTimeout, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return EngineReply.Failure(EngineProtocol.ErrorCodes.Timeout);
            }
            catch (ObjectDisposedException)
            {
                return EngineReply.Failure(EngineProtocol.ErrorCodes.Closed);
            }
            if (!entered)
            {
                return EngineReply.Failure(EngineProtocol.ErrorCodes.Timeout);
            }

            try
            {
                if (System.Threading.Volatile.Read(ref shutdownRequested) != 0)
                {
                    return EngineReply.Failure(EngineProtocol.ErrorCodes.Closed);
                }

                string bound = sessionId;
                if (bound == null)
                {
                    // The first request must connect. A status, start, stop, or
                    // shutdown from an unbound session is refused.
                    if (request.Operation != EngineProtocol.Operations.Hello)
                    {
                        return EngineReply.Failure(EngineProtocol.ErrorCodes.NotConnected);
                    }
                    sessionId = request.SessionId;
                }
                else if (!string.Equals(bound, request.SessionId, StringComparison.Ordinal))
                {
                    // One broker serves one app session. A second session id
                    // cannot take over the engine.
                    return EngineReply.Failure(EngineProtocol.ErrorCodes.Forbidden);
                }

                switch (request.Operation)
                {
                    case EngineProtocol.Operations.Hello:
                        return await HelloAsync().ConfigureAwait(false);
                    case EngineProtocol.Operations.Status:
                        return await StatusAsync().ConfigureAwait(false);
                    case EngineProtocol.Operations.Start:
                        return await StartAsync(request.Ping).ConfigureAwait(false);
                    case EngineProtocol.Operations.Stop:
                        return await StopAsync().ConfigureAwait(false);
                    case EngineProtocol.Operations.Shutdown:
                        return await ShutdownAsync().ConfigureAwait(false);
                    default:
                        // Pairing, probe, diagnostics, and failures are part of
                        // the version 1 vocabulary but not implemented on
                        // Windows. The app must not show those screens.
                        return EngineReply.Failure(EngineProtocol.ErrorCodes.Unsupported);
                }
            }
            catch (Exception)
            {
                return EngineReply.Failure(EngineProtocol.ErrorCodes.Internal);
            }
            finally
            {
                gate.Release();
            }
        }

        private async System.Threading.Tasks.Task<EngineReply> HelloAsync()
        {
            EngineCommandResult result = await startup.EnsureStartedAsync(plan)
                .ConfigureAwait(false);
            if (!result.Ok)
            {
                return EngineReply.Failure(result.Code);
            }
            EngineStatus status = startup.Boundary.Session.Status;
            if (status == null)
            {
                return EngineReply.Failure(EngineProtocol.ErrorCodes.NoStatus);
            }
            return EngineReply.Success(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                { EngineProtocol.Keys.Instance, status.InstanceId },
                { EngineProtocol.Keys.Engine, EngineRules.EngineWord(status.Engine) }
            });
        }

        private async System.Threading.Tasks.Task<EngineReply> StatusAsync()
        {
            EngineCommandResult ensure = await startup.EnsureStartedAsync(plan)
                .ConfigureAwait(false);
            if (!ensure.Ok)
            {
                return EngineReply.Failure(ensure.Code);
            }
            EngineCommandResult result = await startup.Boundary.PollAsync()
                .ConfigureAwait(false);
            if (!result.Ok)
            {
                return EngineReply.Failure(result.Code);
            }
            EngineStatus status = startup.Boundary.Session.Status;
            if (status == null)
            {
                return EngineReply.Failure(EngineProtocol.ErrorCodes.NoStatus);
            }
            return EngineReply.Success(StatusFields(status));
        }

        private async System.Threading.Tasks.Task<EngineReply> StartAsync(bool ping)
        {
            EngineCommandResult result = await startup.StartTunnelAsync(plan, ping)
                .ConfigureAwait(false);
            return result.Ok
                ? EngineReply.Success(null)
                : EngineReply.Failure(result.Code);
        }

        private async System.Threading.Tasks.Task<EngineReply> StopAsync()
        {
            EngineCommandResult result = await startup.StopTunnelAsync()
                .ConfigureAwait(false);
            return result.Ok
                ? EngineReply.Success(null)
                : EngineReply.Failure(result.Code);
        }

        private async System.Threading.Tasks.Task<EngineReply> ShutdownAsync()
        {
            System.Threading.Volatile.Write(ref shutdownRequested, 1);
            EngineCommandResult result = await startup.ShutdownAsync()
                .ConfigureAwait(false);
            return result.Ok
                ? EngineReply.Success(null)
                : EngineReply.Failure(result.Code);
        }

        private static Dictionary<string, string> StatusFields(EngineStatus status)
        {
            return new Dictionary<string, string>(StringComparer.Ordinal)
            {
                { EngineProtocol.Keys.Instance, status.InstanceId },
                { EngineProtocol.Keys.Engine, EngineRules.EngineWord(status.Engine) },
                { EngineProtocol.Keys.Paired, status.Paired ? "1" : "0" },
                { EngineProtocol.Keys.Running, status.Running ? "1" : "0" },
                { EngineProtocol.Keys.Source, status.SourcePresent ? "1" : "0" },
                { EngineProtocol.Keys.Trusted, status.TrustedBySource ? "1" : "0" },
                { EngineProtocol.Keys.Ping, status.PingEnabled ? "1" : "0" },
                {
                    EngineProtocol.Keys.Connections,
                    status.Connections.ToString(System.Globalization.CultureInfo.InvariantCulture)
                },
                { EngineProtocol.Keys.Stop, EngineRules.StopWord(status.Stop) }
            };
        }
    }
}
