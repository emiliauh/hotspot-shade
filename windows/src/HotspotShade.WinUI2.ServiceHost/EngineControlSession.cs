using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.ServiceHost
{
    // One private control channel, one parent-liveness channel, and the
    // per-launch session key. A reviewed launcher creates these channels and
    // passes the child ends to the engine. The service keeps the ends in this
    // object for the life of the session.
    //
    // This type creates no pipe and starts no process. `Dispose` closes the
    // liveness channel first, so the engine sees parent loss before the
    // control channel closes. The engine then runs its normal stop path.
    public sealed class EngineControlStartup : IDisposable
    {
        private readonly Stream controlInput;
        private readonly Stream controlOutput;
        private readonly Stream parentLiveness;
        private readonly EngineControlSessionKey key;
        private int disposed;

        public EngineControlStartup(
            Stream controlInput,
            Stream controlOutput,
            Stream parentLiveness,
            EngineControlSessionKey key)
        {
            if (controlInput == null)
            {
                throw new ArgumentNullException("controlInput");
            }
            if (controlOutput == null)
            {
                throw new ArgumentNullException("controlOutput");
            }
            if (parentLiveness == null)
            {
                throw new ArgumentNullException("parentLiveness");
            }
            if (key == null)
            {
                throw new ArgumentNullException("key");
            }
            this.controlInput = controlInput;
            this.controlOutput = controlOutput;
            this.parentLiveness = parentLiveness;
            this.key = key;
        }

        internal Stream ControlInput
        {
            get { return controlInput; }
        }

        internal Stream ControlOutput
        {
            get { return controlOutput; }
        }

        internal EngineControlSessionKey Key
        {
            get { return key; }
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0)
            {
                return;
            }
            // Parent loss is the stop signal. Close it before the control
            // channel so the engine cannot treat a control close as the only
            // evidence that the service is gone.
            CloseQuietly(parentLiveness);
            CloseQuietly(controlOutput);
            CloseQuietly(controlInput);
            key.Dispose();
        }

        private static void CloseQuietly(Stream stream)
        {
            try
            {
                stream.Dispose();
            }
            catch (Exception)
            {
                // A close failure cannot make the session usable.
            }
        }
    }

    // The approved launcher seam. A reviewed Windows launcher creates the
    // three private channels, generates the 32-byte key, writes the 64 hex
    // bytes and one newline to the child key descriptor, starts the installed
    // engine image with the child handles, and returns the service ends.
    // This build supplies no launcher, so the default factory is unavailable.
    public interface IEngineControlChannelFactory
    {
        bool TryCreate(out EngineControlStartup startup, out string code);
    }

    public sealed class UnavailableEngineControlChannelFactory : IEngineControlChannelFactory
    {
        public bool TryCreate(out EngineControlStartup startup, out string code)
        {
            startup = null;
            code = EngineProtocol.ErrorCodes.EngineUnavailable;
            return false;
        }
    }

    // The service-side engine control session. It connects once, serializes
    // requests, allocates one increasing request identifier per request, and
    // never retries a write or reads a second reply. A protocol, write, or read
    // failure closes the session. A validated failure reply keeps the session
    // open because the engine is still there and the failure is an answer, not
    // a lost frame.
    public interface IEngineControlSession : IDisposable
    {
        bool TryReadStatus(out IReadOnlyDictionary<string, string> fields, out string code);

        bool TryStart(bool ping, out string code);

        bool TryStop(out string code);
    }

    public sealed class EngineControlSession : IEngineControlSession
    {
        private readonly object gate = new object();
        private readonly EngineControlStartup startup;
        private readonly IEngineServiceEventSink events;
        private EngineControlClient client;
        private bool closed;

        public EngineControlSession(
            EngineControlStartup startup,
            IEngineServiceEventSink events)
        {
            if (startup == null)
            {
                throw new ArgumentNullException("startup");
            }
            if (events == null)
            {
                throw new ArgumentNullException("events");
            }
            this.startup = startup;
            this.events = events;
        }

        public bool TryReadStatus(
            out IReadOnlyDictionary<string, string> fields,
            out string code)
        {
            fields = null;
            lock (gate)
            {
                EngineControlClient active;
                if (!EnsureConnected(out active, out code))
                {
                    return false;
                }
                Dictionary<string, string> decoded;
                if (!active.TryStatus(out decoded, out code))
                {
                    if (active.IsClosed)
                    {
                        events.Record(EngineServiceEventCodes.ControlProtocolFailed);
                        CloseLocked();
                    }
                    return false;
                }
                fields = decoded;
                return true;
            }
        }

        public bool TryStart(bool ping, out string code)
        {
            // The Windows source-proxy start gate is closed. Keep the wire
            // codec separate, but do not let a caller bypass the backend gate
            // by sending a start directly through this session.
            code = EngineProtocol.ErrorCodes.Unsupported;
            return false;
        }

        public bool TryStop(out string code)
        {
            lock (gate)
            {
                EngineControlClient active;
                if (!EnsureConnected(out active, out code))
                {
                    return false;
                }
                if (!active.TryStop(out code))
                {
                    if (active.IsClosed)
                    {
                        events.Record(EngineServiceEventCodes.ControlProtocolFailed);
                        CloseLocked();
                    }
                    return false;
                }
                return true;
            }
        }

        public void Dispose()
        {
            // Close the channels before waiting for the request lock. A read
            // in progress holds that lock and must be able to observe closure.
            // A future native launcher must also bound the stream operations;
            // Stream.Dispose alone does not guarantee native I/O cancellation.
            startup.Dispose();
            lock (gate)
            {
                CloseLocked();
            }
        }

        private bool EnsureConnected(out EngineControlClient active, out string code)
        {
            active = null;
            code = EngineProtocol.ErrorCodes.Closed;
            if (closed)
            {
                return false;
            }
            if (client != null)
            {
                active = client;
                code = "";
                return true;
            }

            EngineControlClient created;
            try
            {
                if (!EngineControlClient.TryConnect(
                    startup.ControlInput,
                    startup.ControlOutput,
                    startup.Key,
                    out created,
                    out code))
                {
                    events.Record(EngineServiceEventCodes.ControlHandshakeFailed);
                    CloseLocked();
                    return false;
                }
            }
            catch (Exception)
            {
                events.Record(EngineServiceEventCodes.ControlHandshakeFailed);
                CloseLocked();
                code = EngineProtocol.ErrorCodes.EngineUnavailable;
                return false;
            }
            client = created;
            active = created;
            code = "";
            return true;
        }

        private void CloseLocked()
        {
            if (closed)
            {
                return;
            }
            closed = true;
            if (client != null)
            {
                client.Dispose();
                client = null;
            }
            startup.Dispose();
        }

    }

    // Reads one engine status over the authenticated control session and
    // composes the service status schema. The engine answer is one flat JSON
    // object with these keys: engine, running, mode, paired, paired_scope,
    // source, trusted, checked_at, ping, icmp_enabled, phone.connections,
    // phone.connections_known, relay.tcp_flows_active,
    // relay.tcp_flows_active_known, ttl_bad, ipv6_dropped,
    // fragments_dropped, stop, stop_at, admin. It may also carry ok=1.
    // Values use the service field words: 0 or 1 for booleans, unix seconds
    // for times, and the fixed engine, mode, scope, stop, and cleanup words.
    // The service supplies v=1, its own instance id, and the cleanup gate from
    // its durable record. The engine cannot override any of those three.
    //
    // A running engine status always carries cleanup=unknown. A raw durable
    // record cannot prove that the current engine has exited cleanly, so an
    // apparently clean record also remains unknown until a process-exit proof
    // and a durable writer are connected. Pending and failed stay visible.
    //
    // The Rust engine control handler is the other side of this contract. It
    // is not wired in this build. The remaining path is to map the Rust
    // ControlCommand::Status handler to the stored pairing state and these
    // fields, then supply a reviewed launcher to the channel factory.
    public sealed class EngineControlStatusSource : IEngineServiceStatusSource
    {
        private readonly IEngineControlSession session;
        private readonly string serviceInstanceId;
        private readonly IEngineServiceDurableStateStore store;
        private readonly IEngineServiceEventSink events;

        public EngineControlStatusSource(
            IEngineControlSession session,
            string serviceInstanceId,
            IEngineServiceDurableStateStore store,
            IEngineServiceEventSink events)
        {
            if (session == null)
            {
                throw new ArgumentNullException("session");
            }
            if (!EngineProtocol.IsValidInstanceId(serviceInstanceId))
            {
                throw new ArgumentException("invalid service instance id", "serviceInstanceId");
            }
            if (events == null)
            {
                throw new ArgumentNullException("events");
            }
            this.session = session;
            this.serviceInstanceId = serviceInstanceId;
            this.store = store;
            this.events = events;
        }

        public bool TryRead(
            DateTimeOffset now,
            out EngineServiceStatus status,
            out DateTimeOffset readAt,
            out string code)
        {
            status = null;
            readAt = now;
            code = EngineProtocol.ErrorCodes.EngineUnavailable;

            IReadOnlyDictionary<string, string> engineFields;
            if (!session.TryReadStatus(out engineFields, out code))
            {
                return false;
            }
            if (engineFields == null)
            {
                code = EngineProtocol.ErrorCodes.BadResponse;
                return false;
            }

            Dictionary<string, string> fields =
                new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (KeyValuePair<string, string> pair in engineFields)
            {
                if (IsReserved(pair.Key))
                {
                    events.Record(EngineServiceEventCodes.ControlStatusInvalid);
                    code = EngineProtocol.ErrorCodes.BadResponse;
                    return false;
                }
                fields[pair.Key] = pair.Value;
            }

            fields[EngineServiceStatusKeys.Version] = "1";
            fields[EngineServiceStatusKeys.Instance] = serviceInstanceId;
            EngineServiceCleanup cleanup = ReadCleanup();
            fields[EngineServiceStatusKeys.Cleanup] = CleanupWord(
                cleanup == EngineServiceCleanup.Ok ? EngineServiceCleanup.Unknown : cleanup);

            bool running;
            if (!TryReadRunning(fields, out running))
            {
                events.Record(EngineServiceEventCodes.ControlStatusInvalid);
                code = EngineProtocol.ErrorCodes.BadResponse;
                return false;
            }
            if (running)
            {
                fields[EngineServiceStatusKeys.Cleanup] = "unknown";
            }

            string parseCode;
            if (!EngineServiceStatus.TryParse(fields, now, out status, out parseCode))
            {
                events.Record(EngineServiceEventCodes.ControlStatusInvalid);
                code = EngineProtocol.IsKnownErrorCode(parseCode)
                    ? parseCode
                    : EngineProtocol.ErrorCodes.BadResponse;
                status = null;
                return false;
            }
            code = "";
            return true;
        }

        private static bool IsReserved(string key)
        {
            return key == EngineServiceStatusKeys.Version
                || key == EngineServiceStatusKeys.Instance
                || key == EngineServiceStatusKeys.Cleanup
                || key == EngineProtocol.Keys.Code
                || key == EngineProtocol.Keys.Operation
                || key == EngineProtocol.Keys.Session;
        }

        private static bool TryReadRunning(
            IReadOnlyDictionary<string, string> fields,
            out bool running)
        {
            running = false;
            string value;
            if (!fields.TryGetValue(EngineServiceStatusKeys.Running, out value))
            {
                return false;
            }
            if (value == "0")
            {
                return true;
            }
            if (value == "1")
            {
                running = true;
                return true;
            }
            return false;
        }

        private EngineServiceCleanup ReadCleanup()
        {
            if (store == null)
            {
                return EngineServiceCleanup.Unknown;
            }
            try
            {
                EngineServiceStateGate gate;
                string code;
                if (!store.TryRead(out gate, out code) || gate == null || !gate.HasRecord)
                {
                    return EngineServiceCleanup.Unknown;
                }
                EngineServiceStateRecord record = gate.Record;
                if (record == null)
                {
                    return EngineServiceCleanup.Unknown;
                }
                return record.Cleanup;
            }
            catch (Exception)
            {
                return EngineServiceCleanup.Unknown;
            }
        }

        private static string CleanupWord(EngineServiceCleanup cleanup)
        {
            switch (cleanup)
            {
                case EngineServiceCleanup.Ok:
                    return "ok";
                case EngineServiceCleanup.Failed:
                    return "failed";
                case EngineServiceCleanup.Pending:
                    return "pending";
                default:
                    return "unknown";
            }
        }
    }
}
