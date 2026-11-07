using System;
using System.Threading;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;
using HotspotShade.WinUI2.ServiceHost;

namespace HotspotShade.WinUI2.Service
{
    // The service main body. It registers one control handler with the SCM,
    // parses the install-time configuration, runs exactly one host
    // generation, and sends one final stopped record with a fixed exit code.
    //
    // It never installs, starts, changes, or deletes a service. It never
    // launches an engine in this build, because the guarded backend keeps the
    // Windows source-proxy guard closed.
    internal sealed class EngineServiceScmService
    {
        private static readonly WindowsServiceControlNativeMethods.ServiceControlHandler
            HandlerDelegate = HandleControl;
        private static EngineServiceScmService activeService;

        private readonly IEngineServiceGenerationFactory factory;
        private readonly EngineServiceScmStatusReporter reporter;
        private readonly IEngineServiceEventSink events;
        private readonly TimeSpan stopWaitHint;
        private readonly CancellationTokenSource stop = new CancellationTokenSource();
        private int stopRequested;
        private int lastControl;

        public EngineServiceScmService(
            IEngineServiceGenerationFactory factory,
            EngineServiceScmStatusReporter reporter,
            IEngineServiceEventSink events,
            TimeSpan stopWaitHint)
        {
            if (factory == null)
            {
                throw new ArgumentNullException("factory");
            }
            if (reporter == null)
            {
                throw new ArgumentNullException("reporter");
            }
            if (events == null)
            {
                throw new ArgumentNullException("events");
            }
            if (stopWaitHint <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException("stopWaitHint");
            }
            this.factory = factory;
            this.reporter = reporter;
            this.events = events;
            this.stopWaitHint = stopWaitHint;
        }

        public bool IsStopRequested
        {
            get { return Volatile.Read(ref stopRequested) != 0; }
        }

        public bool IsShutdownRequested
        {
            get { return Volatile.Read(ref lastControl) == (int)WindowsServiceControlNativeMethods.ControlShutdown; }
        }

        // Runs the service. The caller is the SCM service main thread. A
        // requested stop is a clean stop. A missing or unreadable durable
        // record, a rejected installed account, an unavailable listener, and
        // a stop timeout are fixed failures.
        public int Run(string[] arguments)
        {
            Volatile.Write(ref activeService, this);
            try
            {
                if (!reporter.TryRegister(
                    EngineServiceBoundary.ServiceName,
                    HandlerDelegate)
                    || reporter.Failed)
                {
                    events.Record(EngineServiceEventCodes.ServiceHandlerRegisterFailed);
                    return EngineServiceScmExitCodes.Internal;
                }

                EngineServiceConfiguration configuration;
                string configurationError;
                if (!EngineServiceCommandLine.TryParse(
                    arguments,
                    out configuration,
                    out configurationError))
                {
                    events.Record(EngineServiceEventCodes.ServiceConfigurationInvalid);
                    reporter.TryFinalize(EngineServiceScmExitCodes.Configuration);
                    return reporter.Failed
                        ? EngineServiceScmExitCodes.Internal
                        : EngineServiceScmExitCodes.Configuration;
                }

                IEngineServiceGenerationRunner runner;
                try
                {
                    runner = factory.Create(configuration);
                }
                catch (Exception)
                {
                    reporter.TryFinalize(EngineServiceScmExitCodes.Configuration);
                    return reporter.Failed
                        ? EngineServiceScmExitCodes.Internal
                        : EngineServiceScmExitCodes.Configuration;
                }

                if (runner == null)
                {
                    reporter.TryFinalize(EngineServiceScmExitCodes.Internal);
                    return reporter.Failed
                        ? EngineServiceScmExitCodes.Internal
                        : EngineServiceScmExitCodes.Internal;
                }

                EngineServiceHostResult result = null;
                try
                {
                    result = runner.Run(reporter, stop.Token);
                }
                catch (OperationCanceledException)
                {
                    result = null;
                }
                catch (Exception)
                {
                    result = null;
                }

                int exitCode = EngineServiceScmExitCodes.ForHostResult(
                    result,
                    IsStopRequested);
                bool finalized = reporter.TryFinalize(exitCode);
                if (!finalized || reporter.Failed)
                {
                    return EngineServiceScmExitCodes.Internal;
                }
                return exitCode;
            }
            catch (Exception)
            {
                // The SCM dispatcher must always receive a final record when
                // the handler is already registered. A failure after
                // registration is an internal fault, never a clean stop.
                try
                {
                    reporter.TryFinalize(EngineServiceScmExitCodes.Internal);
                }
                catch (Exception)
                {
                    // The process exits and the SCM marks the service stopped.
                }
                return EngineServiceScmExitCodes.Internal;
            }
            finally
            {
                Volatile.Write(ref activeService, null);
            }
        }

        // Called by the SCM on a control thread while Run is active. It only
        // cancels one linked token, reports StopPending, and records a fixed
        // event. Cancellation callbacks run on this thread and must not block.
        // It never impersonates and never calls the backend.
        public uint HandleControl(uint control, uint eventType)
        {
            try
            {
                if (control == WindowsServiceControlNativeMethods.ControlStop
                    || control == WindowsServiceControlNativeMethods.ControlShutdown)
                {
                    Volatile.Write(ref lastControl, (int)control);
                    try
                    {
                        RequestStop();
                    }
                    catch (Exception)
                    {
                        // Cancellation precedes reporting the pending state.
                    }
                    try
                    {
                        events.Record(control == WindowsServiceControlNativeMethods.ControlStop
                            ? EngineServiceEventCodes.ServiceStopControl
                            : EngineServiceEventCodes.ServiceShutdownControl);
                    }
                    catch (Exception)
                    {
                        // Diagnostics cannot turn an accepted stop into a refusal.
                    }
                    return (uint)WindowsServiceControlNativeMethods.ErrorSuccess;
                }
                if (control == WindowsServiceControlNativeMethods.ControlInterrogate)
                {
                    // The last reported status is already available to the
                    // SCM. No state change is needed.
                    return (uint)WindowsServiceControlNativeMethods.ErrorSuccess;
                }

                // Pause, continue, and custom controls are not supported.
                // The SCM maps ERROR_CALL_NOT_IMPLEMENTED to a refused
                // control, and the live session is not changed.
                events.Record(EngineServiceEventCodes.ServiceControlRefused);
                return (uint)WindowsServiceControlNativeMethods.ErrorCallNotImplemented;
            }
            catch (Exception)
            {
                return (uint)WindowsServiceControlNativeMethods.ErrorCallNotImplemented;
            }
        }

        private void RequestStop()
        {
            if (Interlocked.CompareExchange(ref stopRequested, 1, 0) != 0)
            {
                return;
            }
            reporter.MarkStopRequested();
            try
            {
                stop.Cancel();
            }
            catch (ObjectDisposedException)
            {
                // The process is already leaving Run.
            }
            catch (AggregateException)
            {
                // Cancel has signaled the token even if a callback threw.
                // Record the failure without letting diagnostics skip status.
                try { events.Record(EngineServiceEventCodes.ServiceStopCancellationFailed); }
                catch (Exception) { }
            }
            reporter.ReportState(
                EngineServiceHostState.StopPending,
                1,
                stopWaitHint);
        }

        private static uint HandleControl(
            uint control,
            uint eventType,
            IntPtr eventData,
            IntPtr context)
        {
            EngineServiceScmService service = Volatile.Read(ref activeService);
            if (service == null)
            {
                return (uint)WindowsServiceControlNativeMethods.ErrorCallNotImplemented;
            }
            return service.HandleControl(control, eventType);
        }
    }

    // Builds the production seams and runs one service generation. The event
    // record stays in memory. It is never written to disk and never sent to
    // the source device.
    internal static class EngineServiceScmEntryPoint
    {
        internal static TimeSpan StopWaitHint
        {
            get
            {
                EngineServiceHostOptions host = new EngineServiceHostOptions();
                return host.StopBudget + host.StopWaitHint + TimeSpan.FromSeconds(5);
            }
        }

        public static int Run(string[] arguments)
        {
            EngineServiceEventBuffer events = new EngineServiceEventBuffer();
            WindowsServiceScmStatusSink sink = new WindowsServiceScmStatusSink();
            EngineServiceScmStatusReporter reporter =
                new EngineServiceScmStatusReporter(sink, events);
            EngineServiceComposition composition =
                new EngineServiceComposition(events);
            // Leave margin for the host stop decision and status reporting.
            EngineServiceScmService service = new EngineServiceScmService(
                composition,
                reporter,
                events,
                StopWaitHint);
            return service.Run(arguments);
        }
    }
}
