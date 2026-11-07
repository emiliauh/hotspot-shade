using System;
using System.Threading;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;
using HotspotShade.WinUI2.ServiceHost;

namespace HotspotShade.WinUI2.Service
{
    // The only product of one service generation. The SCM adapter calls this
    // once. It never restarts a generation, never launches an engine, and
    // never changes a route.
    public interface IEngineServiceGenerationRunner
    {
        EngineServiceHostResult Run(
            IEngineServiceHostControl control,
            CancellationToken cancellationToken);
    }

    internal interface IEngineServiceGenerationFactory
    {
        IEngineServiceGenerationRunner Create(EngineServiceConfiguration configuration);
    }

    // The production factory. It holds the in-memory event record shared by
    // the SCM adapter and the host.
    internal sealed class EngineServiceComposition : IEngineServiceGenerationFactory
    {
        private readonly IEngineServiceEventSink events;
        private readonly IEngineControlChannelFactory controlChannels;

        public EngineServiceComposition(IEngineServiceEventSink events)
            : this(events, new UnavailableEngineControlChannelFactory())
        {
        }

        internal EngineServiceComposition(
            IEngineServiceEventSink events,
            IEngineControlChannelFactory controlChannels)
        {
            if (events == null)
            {
                throw new ArgumentNullException("events");
            }
            if (controlChannels == null)
            {
                throw new ArgumentNullException("controlChannels");
            }
            this.events = events;
            this.controlChannels = controlChannels;
        }

        public IEngineServiceGenerationRunner Create(
            EngineServiceConfiguration configuration)
        {
            return new EngineServiceHostRunner(configuration, events, controlChannels);
        }
    }

    // The default channel factory supplies no launcher, so no control session
    // exists. The service therefore has no status to report, and the guarded
    // backend refuses a start with engine_unavailable. That is an honest
    // failure, not a simulated success. A reviewed launcher can inject a
    // factory that returns the private channels and the per-launch key.
    internal sealed class EngineServiceStatusSourceUnavailable : IEngineServiceStatusSource
    {
        public bool TryRead(
            DateTimeOffset now,
            out EngineServiceStatus status,
            out DateTimeOffset readAt,
            out string code)
        {
            status = null;
            readAt = now;
            code = EngineProtocol.ErrorCodes.EngineUnavailable;
            return false;
        }
    }

    // Builds the real seams for one generation and runs the existing host.
    // The source-proxy engine guard stays closed inside the guarded backend.
    internal sealed class EngineServiceHostRunner : IEngineServiceGenerationRunner
    {
        private readonly EngineServiceConfiguration configuration;
        private readonly IEngineServiceAccountTypeInspector accountTypes;
        private readonly IEngineServiceDurableStateStore store;
        private readonly IEngineServiceStatusSource statusSource;
        private readonly IEngineServicePipeFactory pipeFactory;
        private readonly IEngineServiceEventSink events;
        private readonly IEngineControlChannelFactory controlChannels;

        public EngineServiceHostRunner(
            EngineServiceConfiguration configuration,
            IEngineServiceEventSink events)
            : this(
                configuration,
                new WindowsAccountTypeInspector(),
                new EngineServiceFileStateStore(configuration.StateFilePath),
                null,
                new WindowsNamedPipeServerFactory(configuration.Transport),
                events,
                new UnavailableEngineControlChannelFactory())
        {
        }

        internal EngineServiceHostRunner(
            EngineServiceConfiguration configuration,
            IEngineServiceEventSink events,
            IEngineControlChannelFactory controlChannels)
            : this(
                configuration,
                new WindowsAccountTypeInspector(),
                new EngineServiceFileStateStore(configuration.StateFilePath),
                null,
                new WindowsNamedPipeServerFactory(configuration.Transport),
                events,
                controlChannels)
        {
        }

        internal EngineServiceHostRunner(
            EngineServiceConfiguration configuration,
            IEngineServiceAccountTypeInspector accountTypes,
            IEngineServiceDurableStateStore store,
            IEngineServiceStatusSource statusSource,
            IEngineServicePipeFactory pipeFactory,
            IEngineServiceEventSink events)
            : this(
                configuration,
                accountTypes,
                store,
                statusSource,
                pipeFactory,
                events,
                new UnavailableEngineControlChannelFactory())
        {
        }

        internal EngineServiceHostRunner(
            EngineServiceConfiguration configuration,
            IEngineServiceAccountTypeInspector accountTypes,
            IEngineServiceDurableStateStore store,
            IEngineServiceStatusSource statusSource,
            IEngineServicePipeFactory pipeFactory,
            IEngineServiceEventSink events,
            IEngineControlChannelFactory controlChannels)
        {
            if (configuration == null)
            {
                throw new ArgumentNullException("configuration");
            }
            if (accountTypes == null)
            {
                throw new ArgumentNullException("accountTypes");
            }
            if (store == null)
            {
                throw new ArgumentNullException("store");
            }
            if (pipeFactory == null)
            {
                throw new ArgumentNullException("pipeFactory");
            }
            if (events == null)
            {
                throw new ArgumentNullException("events");
            }
            if (controlChannels == null)
            {
                throw new ArgumentNullException("controlChannels");
            }
            this.configuration = configuration;
            this.accountTypes = accountTypes;
            this.store = store;
            this.statusSource = statusSource;
            this.pipeFactory = pipeFactory;
            this.events = events;
            this.controlChannels = controlChannels;
        }

        public EngineServiceHostResult Run(
            IEngineServiceHostControl control,
            CancellationToken cancellationToken)
        {
            if (control == null)
            {
                throw new ArgumentNullException("control");
            }

            EngineServiceTransportOptions transport = configuration.Transport;
            SystemEngineClock clock = new SystemEngineClock();

            EngineServiceDurableStateGate durableState =
                new EngineServiceDurableStateGate(
                    store,
                    events,
                    transport.EngineImagePath,
                    null);
            EngineServiceInstalledAccountGate accountGate =
                new EngineServiceInstalledAccountGate(
                    transport.InstalledUserSid,
                    accountTypes,
                    transport.AccountTypeTimeout);
            EngineServiceStatusGate statusGate = new EngineServiceStatusGate(
                transport.ServiceInstanceId,
                events,
                TimeSpan.FromMilliseconds(EngineServiceTransportLimits.StatusMaxAgeMilliseconds),
                TimeSpan.FromMilliseconds(EngineServiceTransportLimits.ClockSkewMilliseconds));

            // The default composition has no engine control channel. A
            // reviewed launcher can inject one. The session is lazy: it
            // connects on the first status read, so a missing engine does not
            // block the listener. No launch, pipe create, or route happens
            // here.
            IEngineServiceStatusSource effectiveStatus = statusSource;
            IEngineControlSession controlSession = null;
            if (effectiveStatus == null)
            {
                EngineControlStartup startup;
                string channelCode;
                if (controlChannels.TryCreate(out startup, out channelCode) && startup != null)
                {
                    try
                    {
                        controlSession = new EngineControlSession(startup, events);
                        effectiveStatus = new EngineControlStatusSource(
                            controlSession,
                            transport.ServiceInstanceId,
                            store,
                            events);
                    }
                    catch (Exception)
                    {
                        if (controlSession != null)
                        {
                            controlSession.Dispose();
                        }
                        else
                        {
                            startup.Dispose();
                        }
                        throw;
                    }
                }
                else
                {
                    // A failed factory can still return partially created
                    // channels. Close those handles before refusing startup.
                    if (startup != null)
                    {
                        startup.Dispose();
                    }
                    events.Record(EngineServiceEventCodes.ControlChannelUnavailable);
                    effectiveStatus = new EngineServiceStatusSourceUnavailable();
                }
            }

            try
            {
                GuardedEngineServiceBackend backend = new GuardedEngineServiceBackend(
                    effectiveStatus,
                    statusGate,
                    durableState,
                    clock,
                    events,
                    controlSession);
                WindowsServiceCallerPolicy callerPolicy = new WindowsServiceCallerPolicy(
                    transport.InstalledUserSid,
                    accountTypes,
                    transport.AccountTypeTimeout);
                EngineServiceCleanThreadDispatcher cleanThread =
                    new EngineServiceCleanThreadDispatcher();
                EngineServiceProcessTerminator fatalBoundary =
                    new EngineServiceProcessTerminator();
                EngineServicePipeListenerFactory listenerFactory =
                    new EngineServicePipeListenerFactory(
                        transport,
                        backend,
                        pipeFactory,
                        store,
                        callerPolicy,
                        cleanThread,
                        fatalBoundary,
                        events);

                EngineServiceHost host = new EngineServiceHost(
                    new EngineServiceHostOptions(),
                    accountGate,
                    durableState,
                    listenerFactory,
                    control,
                    events);
                return host.RunAsync(cancellationToken).GetAwaiter().GetResult();
            }
            finally
            {
                // Parent loss is the engine stop signal. Close the liveness
                // channel before the control channel and never restart.
                if (controlSession != null)
                {
                    controlSession.Dispose();
                }
            }
        }
    }

    // Creates one fresh session, gate, and listener for the one generation.
    // The session keeps the durable state gate, so a missing or unreadable
    // record refuses every start in the session as well as in the host.
    internal sealed class EngineServicePipeListenerFactory : IEngineServiceListenerFactory
    {
        private readonly EngineServiceTransportOptions transport;
        private readonly IEngineServiceBackend backend;
        private readonly IEngineServiceStopBoundary stopBoundary;
        private readonly IEngineServicePipeFactory pipeFactory;
        private readonly IEngineServiceDurableStateStore store;
        private readonly WindowsServiceCallerPolicy callerPolicy;
        private readonly IEngineServiceCleanThreadRunner cleanThread;
        private readonly IEngineServiceFatalBoundary fatalBoundary;
        private readonly IEngineServiceEventSink events;

        public EngineServicePipeListenerFactory(
            EngineServiceTransportOptions transport,
            IEngineServiceBackend backend,
            IEngineServicePipeFactory pipeFactory,
            IEngineServiceDurableStateStore store,
            WindowsServiceCallerPolicy callerPolicy,
            IEngineServiceCleanThreadRunner cleanThread,
            IEngineServiceFatalBoundary fatalBoundary,
            IEngineServiceEventSink events)
        {
            if (transport == null)
            {
                throw new ArgumentNullException("transport");
            }
            if (backend == null)
            {
                throw new ArgumentNullException("backend");
            }
            if (!(backend is IEngineServiceStopBoundary))
            {
                throw new ArgumentException(
                    "the backend must own the stop boundary",
                    "backend");
            }
            if (pipeFactory == null)
            {
                throw new ArgumentNullException("pipeFactory");
            }
            if (store == null)
            {
                throw new ArgumentNullException("store");
            }
            if (callerPolicy == null)
            {
                throw new ArgumentNullException("callerPolicy");
            }
            if (cleanThread == null)
            {
                throw new ArgumentNullException("cleanThread");
            }
            if (fatalBoundary == null)
            {
                throw new ArgumentNullException("fatalBoundary");
            }
            if (events == null)
            {
                throw new ArgumentNullException("events");
            }
            this.transport = transport;
            this.backend = backend;
            this.stopBoundary = (IEngineServiceStopBoundary)backend;
            this.pipeFactory = pipeFactory;
            this.store = store;
            this.callerPolicy = callerPolicy;
            this.cleanThread = cleanThread;
            this.fatalBoundary = fatalBoundary;
            this.events = events;
        }

        public bool TryCreate(out IEngineServiceListener listener, out string code)
        {
            IEngineServiceListener created = null;
            try
            {
                EngineServiceStateGate sessionState = EngineServiceStateGate.Missing;
                EngineServiceStateGate loaded;
                string storeCode;
                if (store.TryRead(out loaded, out storeCode) && loaded != null)
                {
                    sessionState = loaded;
                }

                EngineServiceSession session = new EngineServiceSession(
                    transport.ServiceInstanceId,
                    backend,
                    new SystemEngineClock(),
                    sessionState,
                    Timeout.InfiniteTimeSpan);
                EngineServiceSessionGate gate = new EngineServiceSessionGate(
                    session,
                    stopBoundary,
                    TimeSpan.FromMilliseconds(
                        EngineServiceTransportLimits.StopTimeoutMilliseconds));
                created = new EngineServicePipeListener(
                    pipeFactory,
                    gate,
                    callerPolicy,
                    cleanThread,
                    fatalBoundary,
                    events,
                    transport);
            }
            catch (Exception)
            {
                listener = null;
                code = EngineProtocol.ErrorCodes.Internal;
                return false;
            }

            listener = created;
            code = "";
            return true;
        }
    }
}
