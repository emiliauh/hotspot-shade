using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;
using HotspotShade.WinUI2.Service;
using HotspotShade.WinUI2.ServiceHost;

namespace HotspotShade.WinUI2.ServiceHost.Tests
{
    internal sealed class ServiceScmFakeSink : IEngineServiceScmStatusSink
    {
        public bool RegisterOk = true;
        public bool SetOk = true;
        public bool ThrowOnStopPending;
        public Action OnStopPending;
        public int RegisterError = 5;
        public int SetError = 6;
        public IntPtr Handle = new IntPtr(77);
        public int RegisterCalls;
        public int SetCalls;
        public List<WindowsServiceControlNativeMethods.ServiceStatus> Statuses =
            new List<WindowsServiceControlNativeMethods.ServiceStatus>();

        public bool TryRegister(
            string serviceName,
            WindowsServiceControlNativeMethods.ServiceControlHandler handler,
            out IntPtr handle,
            out int error)
        {
            RegisterCalls++;
            if (!RegisterOk)
            {
                handle = IntPtr.Zero;
                error = RegisterError;
                return false;
            }
            handle = Handle;
            error = 0;
            return true;
        }

        public bool TrySetStatus(
            IntPtr handle,
            WindowsServiceControlNativeMethods.ServiceStatus status,
            out int error)
        {
            SetCalls++;
            if (status.CurrentState == WindowsServiceControlNativeMethods.ServiceStopPending
                && OnStopPending != null)
            {
                OnStopPending();
            }
            if (ThrowOnStopPending
                && status.CurrentState == WindowsServiceControlNativeMethods.ServiceStopPending)
            {
                throw new InvalidOperationException("status reporting failed");
            }
            if (!SetOk)
            {
                error = SetError;
                return false;
            }
            Statuses.Add(status);
            error = 0;
            return true;
        }
    }

    internal sealed class ServiceScmFakeFactory : IEngineServiceGenerationFactory
    {
        public IEngineServiceGenerationRunner Runner;
        public bool Throw;
        public int Calls;
        public EngineServiceConfiguration LastConfiguration;

        public IEngineServiceGenerationRunner Create(
            EngineServiceConfiguration configuration)
        {
            Calls++;
            LastConfiguration = configuration;
            if (Throw)
            {
                throw new InvalidOperationException("factory failed");
            }
            return Runner;
        }
    }

    internal sealed class ServiceScmFakeRunner : IEngineServiceGenerationRunner
    {
        public EngineServiceHostResult Result =
            EngineServiceHostResult.Success(EngineServiceHostState.Stopped, 1);
        public bool ReportStates = true;
        public bool WaitForCancellation;
        public bool ThrowOnCancel;
        public bool Throw;
        public int Calls;
        public bool SawCancellation;
        public CancellationToken ReceivedToken;
        public ManualResetEventSlim CompletionGate;
        public readonly ManualResetEventSlim Running =
            new ManualResetEventSlim(false);

        public EngineServiceHostResult Run(
            IEngineServiceHostControl control,
            CancellationToken cancellationToken)
        {
            Calls++;
            ReceivedToken = cancellationToken;
            if (ThrowOnCancel)
            {
                cancellationToken.Register(delegate { throw new InvalidOperationException("cancel callback"); });
            }
            if (Throw)
            {
                throw new InvalidOperationException("generation failed");
            }
            if (ReportStates)
            {
                control.ReportState(
                    EngineServiceHostState.StartPending,
                    1,
                    TimeSpan.FromSeconds(1));
                control.ReportState(
                    EngineServiceHostState.Running,
                    0,
                    TimeSpan.Zero);
                Running.Set();
            }
            if (WaitForCancellation)
            {
                cancellationToken.WaitHandle.WaitOne(5000);
                SawCancellation = cancellationToken.IsCancellationRequested;
                if (CompletionGate != null)
                {
                    CompletionGate.Wait(5000);
                }
                return EngineServiceHostResult.Failure(
                    EngineProtocol.ErrorCodes.Closed,
                    EngineServiceHostState.Stopped,
                    2);
            }
            if (ReportStates)
            {
                control.ReportState(
                    EngineServiceHostState.Stopped,
                    0,
                    TimeSpan.Zero);
            }
            return Result;
        }
    }

    internal static class WindowsServiceScmChecks
    {
        public static void Run(ServiceHostCheckRunner runner)
        {
            runner.Check("scm: a clean generation reports start pending, running, and one stopped record", delegate
            {
                ServiceScmFakeSink sink = new ServiceScmFakeSink();
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                ServiceScmFakeRunner generation = new ServiceScmFakeRunner();
                ServiceScmFakeFactory factory = new ServiceScmFakeFactory();
                factory.Runner = generation;
                EngineServiceScmService service = NewService(sink, events, factory);

                int exit = service.Run(ValidArguments());

                ServiceHostAssert.Equal(0, exit, "clean exit code");
                ServiceHostAssert.Equal(1, factory.Calls, "one generation");
                ServiceHostAssert.Equal(3, sink.Statuses.Count, "three status records");
                ServiceHostAssert.Equal(
                    WindowsServiceControlNativeMethods.ServiceStartPending,
                    sink.Statuses[0].CurrentState,
                    "start pending");
                ServiceHostAssert.Equal(
                    WindowsServiceControlNativeMethods.ServiceRunning,
                    sink.Statuses[1].CurrentState,
                    "running");
                ServiceHostAssert.Equal(
                    WindowsServiceControlNativeMethods.ServiceStopped,
                    sink.Statuses[2].CurrentState,
                    "stopped");
                ServiceHostAssert.Equal(
                    WindowsServiceControlNativeMethods.ServiceAcceptStop
                        | WindowsServiceControlNativeMethods.ServiceAcceptShutdown,
                    sink.Statuses[1].ControlsAccepted,
                    "running accepts stop and shutdown");
                ServiceHostAssert.Equal(0u, sink.Statuses[0].ControlsAccepted, "pending accepts no control");
                ServiceHostAssert.Equal(0u, sink.Statuses[2].ControlsAccepted, "stopped accepts no control");
                ServiceHostAssert.Equal(0u, sink.Statuses[2].Win32ExitCode, "clean win32 code");
                ServiceHostAssert.Equal(0u, sink.Statuses[2].ServiceSpecificExitCode, "clean specific code");
                ServiceHostAssert.True(sink.Statuses[0].Checkpoint >= 1, "pending checkpoint");
                ServiceHostAssert.True(sink.Statuses[0].WaitHint > 0, "pending wait hint");
            });

            runner.Check("scm: a bad configuration is refused before a generation and reports code 1", delegate
            {
                ServiceScmFakeSink sink = new ServiceScmFakeSink();
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                ServiceScmFakeFactory factory = new ServiceScmFakeFactory();
                factory.Runner = new ServiceScmFakeRunner();
                EngineServiceScmService service = NewService(sink, events, factory);

                int exit = service.Run(new string[0]);

                ServiceHostAssert.Equal(1, exit, "configuration exit code");
                ServiceHostAssert.Equal(0, factory.Calls, "no generation");
                ServiceHostAssert.Equal(1, sink.Statuses.Count, "one stopped record");
                ServiceHostAssert.Equal(
                    WindowsServiceControlNativeMethods.ServiceStopped,
                    sink.Statuses[0].CurrentState,
                    "stopped");
                ServiceHostAssert.Equal(
                    (uint)WindowsServiceControlNativeMethods.ErrorServiceSpecificError,
                    sink.Statuses[0].Win32ExitCode,
                    "service specific error");
                ServiceHostAssert.Equal(1u, sink.Statuses[0].ServiceSpecificExitCode, "configuration code");
                ServiceHostAssert.True(
                    events.Contains(EngineServiceEventCodes.ServiceConfigurationInvalid),
                    "configuration event");
            });

            runner.Check("scm: a factory failure is a configuration failure", delegate
            {
                ServiceScmFakeSink sink = new ServiceScmFakeSink();
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                ServiceScmFakeFactory factory = new ServiceScmFakeFactory();
                factory.Throw = true;
                EngineServiceScmService service = NewService(sink, events, factory);

                int exit = service.Run(ValidArguments());

                ServiceHostAssert.Equal(1, exit, "configuration exit code");
                ServiceHostAssert.Equal(1, factory.Calls, "factory attempted");
                ServiceHostAssert.Equal(
                    (uint)EngineServiceScmExitCodes.Configuration,
                    sink.Statuses[0].ServiceSpecificExitCode,
                    "configuration specific code");
            });

            runner.Check("scm: a handler registration failure returns internal and sends no status", delegate
            {
                ServiceScmFakeSink sink = new ServiceScmFakeSink();
                sink.RegisterOk = false;
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                ServiceScmFakeFactory factory = new ServiceScmFakeFactory();
                factory.Runner = new ServiceScmFakeRunner();
                EngineServiceScmService service = NewService(sink, events, factory);

                int exit = service.Run(ValidArguments());

                ServiceHostAssert.Equal(
                    EngineServiceScmExitCodes.Internal,
                    exit,
                    "internal exit code");
                ServiceHostAssert.Equal(0, sink.SetCalls, "no status call");
                ServiceHostAssert.True(
                    events.Contains(EngineServiceEventCodes.ServiceHandlerRegisterFailed),
                    "register event");
            });

            runner.Check("scm: a stop control reports stop pending and cancels one token", delegate
            {
                ServiceScmFakeSink sink = new ServiceScmFakeSink();
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                ServiceScmFakeRunner generation = new ServiceScmFakeRunner();
                generation.WaitForCancellation = true;
                ServiceScmFakeFactory factory = new ServiceScmFakeFactory();
                factory.Runner = generation;
                EngineServiceScmService service = NewService(sink, events, factory);

                Task<int> task = Task.Run<int>(delegate { return service.Run(ValidArguments()); });
                ServiceHostAssert.True(generation.Running.Wait(3000), "running reported");
                uint controlResult = service.HandleControl(
                    WindowsServiceControlNativeMethods.ControlStop,
                    0);
                int exit = ServiceHostAssert.Wait(task, 5000, "service run");

                ServiceHostAssert.Equal(0u, controlResult, "stop accepted");
                ServiceHostAssert.Equal(0, exit, "requested stop is a clean exit");
                ServiceHostAssert.True(service.IsStopRequested, "stop requested");
                ServiceHostAssert.False(service.IsShutdownRequested, "not a shutdown");
                ServiceHostAssert.True(generation.SawCancellation, "token canceled");
                ServiceHostAssert.Equal(4, sink.Statuses.Count, "start, running, stop pending, stopped");
                ServiceHostAssert.Equal(
                    WindowsServiceControlNativeMethods.ServiceStopPending,
                    sink.Statuses[2].CurrentState,
                    "stop pending");
                ServiceHostAssert.Equal(
                    WindowsServiceControlNativeMethods.ServiceStopped,
                    sink.Statuses[3].CurrentState,
                    "stopped");
                ServiceHostAssert.True(
                    events.Contains(EngineServiceEventCodes.ServiceStopControl),
                    "stop event");
            });

            runner.Check("scm: stop wait hint exceeds the host budget", delegate
            {
                EngineServiceHostOptions options = new EngineServiceHostOptions();
                ServiceHostAssert.True(EngineServiceScmEntryPoint.StopWaitHint > options.StopBudget,
                    "SCM hint includes host budget and reporting margin");
            });

            runner.Check("scm: throwing cancellation callback still reports stop pending", delegate
            {
                ServiceScmFakeSink sink = new ServiceScmFakeSink();
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                ServiceScmFakeRunner generation = new ServiceScmFakeRunner();
                generation.WaitForCancellation = true;
                generation.ThrowOnCancel = true;
                generation.CompletionGate = new ManualResetEventSlim(false);
                ServiceScmFakeFactory factory = new ServiceScmFakeFactory();
                factory.Runner = generation;
                EngineServiceScmService service = NewService(sink, events, factory);
                Task<int> task = Task.Run<int>(delegate { return service.Run(ValidArguments()); });
                try
                {
                    ServiceHostAssert.True(generation.Running.Wait(3000), "running reported");
                    ServiceHostAssert.Equal(0u, service.HandleControl(WindowsServiceControlNativeMethods.ControlStop, 0), "stop accepted");
                    ServiceHostAssert.Equal(WindowsServiceControlNativeMethods.ServiceStopPending,
                        sink.Statuses[sink.Statuses.Count - 1].CurrentState, "stop pending reported");
                    ServiceHostAssert.True(events.Contains(EngineServiceEventCodes.ServiceStopCancellationFailed), "callback failure recorded");
                }
                finally { generation.CompletionGate.Set(); }
                ServiceHostAssert.Wait(task, 5000, "service run");
            });

            runner.Check("scm: cancellation precedes stop status reporting", delegate
            {
                ServiceScmFakeSink sink = new ServiceScmFakeSink();
                ServiceScmFakeRunner generation = new ServiceScmFakeRunner();
                generation.WaitForCancellation = true;
                generation.CompletionGate = new ManualResetEventSlim(false);
                ServiceScmFakeFactory factory = new ServiceScmFakeFactory();
                factory.Runner = generation;
                EngineServiceScmService service = NewService(sink, new ServiceHostFakeEvents(), factory);
                bool cancelledWhenReported = false;
                sink.OnStopPending = delegate { cancelledWhenReported = generation.ReceivedToken.IsCancellationRequested; };
                Task<int> task = Task.Run<int>(delegate { return service.Run(ValidArguments()); });
                try
                {
                    ServiceHostAssert.True(generation.Running.Wait(3000), "running reported");
                    service.HandleControl(WindowsServiceControlNativeMethods.ControlStop, 0);
                    ServiceHostAssert.True(cancelledWhenReported, "cancel before status sink");
                }
                finally
                {
                    generation.CompletionGate.Set();
                }
                ServiceHostAssert.Wait(task, 5000, "service run");
            });

            runner.Check("scm: a status reporting exception cannot prevent stop cancellation", delegate
            {
                ServiceScmFakeSink sink = new ServiceScmFakeSink();
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                ServiceScmFakeRunner generation = new ServiceScmFakeRunner();
                generation.WaitForCancellation = true;
                ServiceScmFakeFactory factory = new ServiceScmFakeFactory();
                factory.Runner = generation;
                EngineServiceScmService service = NewService(sink, events, factory);

                Task<int> task = Task.Run<int>(delegate { return service.Run(ValidArguments()); });
                ServiceHostAssert.True(generation.Running.Wait(3000), "running reported");
                sink.ThrowOnStopPending = true;
                uint result = service.HandleControl(WindowsServiceControlNativeMethods.ControlStop, 0);
                int exit = ServiceHostAssert.Wait(task, 5000, "service run");

                ServiceHostAssert.True(service.IsStopRequested, "stop requested");
                ServiceHostAssert.Equal(0u, result, "stop accepted despite reporting failure");
                ServiceHostAssert.True(generation.SawCancellation, "token canceled despite reporting failure");
                ServiceHostAssert.Equal(EngineServiceScmExitCodes.Internal, exit, "report failure is internal");
                ServiceHostAssert.True(events.Contains(EngineServiceEventCodes.ServiceStatusReportFailed),
                    "report failure recorded");
            });

            runner.Check("scm: a shutdown control is a distinct clean stop", delegate
            {
                ServiceScmFakeSink sink = new ServiceScmFakeSink();
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                ServiceScmFakeRunner generation = new ServiceScmFakeRunner();
                generation.WaitForCancellation = true;
                ServiceScmFakeFactory factory = new ServiceScmFakeFactory();
                factory.Runner = generation;
                EngineServiceScmService service = NewService(sink, events, factory);

                Task<int> task = Task.Run<int>(delegate { return service.Run(ValidArguments()); });
                ServiceHostAssert.True(generation.Running.Wait(3000), "running reported");
                uint controlResult = service.HandleControl(
                    WindowsServiceControlNativeMethods.ControlShutdown,
                    0);
                int exit = ServiceHostAssert.Wait(task, 5000, "service run");

                ServiceHostAssert.Equal(0u, controlResult, "shutdown accepted");
                ServiceHostAssert.Equal(0, exit, "shutdown is a clean exit");
                ServiceHostAssert.True(service.IsShutdownRequested, "shutdown recorded");
                ServiceHostAssert.True(
                    events.Contains(EngineServiceEventCodes.ServiceShutdownControl),
                    "shutdown event");
            });

            runner.Check("scm: interrogate is accepted and pause or a custom control is refused", delegate
            {
                ServiceScmFakeSink sink = new ServiceScmFakeSink();
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                ServiceScmFakeFactory factory = new ServiceScmFakeFactory();
                factory.Runner = new ServiceScmFakeRunner();
                EngineServiceScmService service = NewService(sink, events, factory);

                ServiceHostAssert.Equal(
                    0u,
                    service.HandleControl(
                        WindowsServiceControlNativeMethods.ControlInterrogate,
                        0),
                    "interrogate accepted");
                ServiceHostAssert.False(service.IsStopRequested, "interrogate does not stop");
                ServiceHostAssert.Equal(
                    (uint)WindowsServiceControlNativeMethods.ErrorCallNotImplemented,
                    service.HandleControl(
                        WindowsServiceControlNativeMethods.ControlPause,
                        0),
                    "pause refused");
                ServiceHostAssert.Equal(
                    (uint)WindowsServiceControlNativeMethods.ErrorCallNotImplemented,
                    service.HandleControl(99, 0),
                    "custom refused");
                ServiceHostAssert.False(service.IsStopRequested, "refused controls do not stop");
                ServiceHostAssert.Equal(0, sink.SetCalls, "no status from refused controls");
                ServiceHostAssert.True(
                    events.Contains(EngineServiceEventCodes.ServiceControlRefused),
                    "refused event");
            });

            runner.Check("scm: a stop before the first host report converts start and running to stop pending", delegate
            {
                ServiceScmFakeSink sink = new ServiceScmFakeSink();
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                EngineServiceScmStatusReporter reporter =
                    new EngineServiceScmStatusReporter(sink, events);
                WindowsServiceControlNativeMethods.ServiceControlHandler handler =
                    delegate(uint control, uint eventType, IntPtr data, IntPtr context)
                    {
                        return 0;
                    };
                ServiceHostAssert.True(reporter.TryRegister("HotspotShadeEngineSvc", handler), "register");
                reporter.MarkStopRequested();
                reporter.ReportState(
                    EngineServiceHostState.StartPending,
                    1,
                    TimeSpan.FromSeconds(1));
                reporter.ReportState(
                    EngineServiceHostState.Running,
                    0,
                    TimeSpan.Zero);

                ServiceHostAssert.Equal(2, sink.Statuses.Count, "two pending records");
                ServiceHostAssert.Equal(
                    WindowsServiceControlNativeMethods.ServiceStopPending,
                    sink.Statuses[0].CurrentState,
                    "start becomes stop pending");
                ServiceHostAssert.Equal(
                    WindowsServiceControlNativeMethods.ServiceStopPending,
                    sink.Statuses[1].CurrentState,
                    "running becomes stop pending");
                ServiceHostAssert.True(
                    sink.Statuses[1].Checkpoint > sink.Statuses[0].Checkpoint,
                    "pending checkpoint advances");
                ServiceHostAssert.True(
                    sink.Statuses[1].WaitHint >= sink.Statuses[0].WaitHint,
                    "pending wait hint is not shortened");
                ServiceHostAssert.Equal(
                    0u,
                    sink.Statuses[0].ControlsAccepted,
                    "stop pending accepts no control");
            });

            runner.Check("scm: a status report failure marks the run as internal", delegate
            {
                ServiceScmFakeSink sink = new ServiceScmFakeSink();
                sink.SetOk = false;
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                ServiceScmFakeRunner generation = new ServiceScmFakeRunner();
                ServiceScmFakeFactory factory = new ServiceScmFakeFactory();
                factory.Runner = generation;
                EngineServiceScmService service = NewService(sink, events, factory);

                int exit = service.Run(ValidArguments());

                ServiceHostAssert.Equal(
                    EngineServiceScmExitCodes.Internal,
                    exit,
                    "internal exit code");
                ServiceHostAssert.True(
                    events.Contains(EngineServiceEventCodes.ServiceStatusReportFailed),
                    "report event");
            });

            runner.Check("scm: a failed host result uses ERROR_SERVICE_SPECIFIC_ERROR", delegate
            {
                ServiceScmFakeSink sink = new ServiceScmFakeSink();
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                ServiceScmFakeRunner generation = new ServiceScmFakeRunner();
                generation.ReportStates = false;
                generation.Result = EngineServiceHostResult.Failure(
                    EngineProtocol.ErrorCodes.CleanupUnknown,
                    EngineServiceHostState.Stopped,
                    0);
                ServiceScmFakeFactory factory = new ServiceScmFakeFactory();
                factory.Runner = generation;
                EngineServiceScmService service = NewService(sink, events, factory);

                int exit = service.Run(ValidArguments());

                ServiceHostAssert.Equal(
                    EngineServiceScmExitCodes.StateNotTrusted,
                    exit,
                    "state exit code");
                ServiceHostAssert.Equal(1, sink.Statuses.Count, "one stopped record");
                ServiceHostAssert.Equal(
                    (uint)WindowsServiceControlNativeMethods.ErrorServiceSpecificError,
                    sink.Statuses[0].Win32ExitCode,
                    "service specific win32 code");
                ServiceHostAssert.Equal(
                    (uint)EngineServiceScmExitCodes.StateNotTrusted,
                    sink.Statuses[0].ServiceSpecificExitCode,
                    "state specific code");
            });

            runner.Check("scm: a thrown generation is a fixed generation failure", delegate
            {
                ServiceScmFakeSink sink = new ServiceScmFakeSink();
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                ServiceScmFakeRunner generation = new ServiceScmFakeRunner();
                generation.Throw = true;
                ServiceScmFakeFactory factory = new ServiceScmFakeFactory();
                factory.Runner = generation;
                EngineServiceScmService service = NewService(sink, events, factory);

                int exit = service.Run(ValidArguments());

                ServiceHostAssert.Equal(
                    EngineServiceScmExitCodes.GenerationFailed,
                    exit,
                    "generation exit code");
                ServiceHostAssert.Equal(
                    (uint)EngineServiceScmExitCodes.GenerationFailed,
                    sink.Statuses[0].ServiceSpecificExitCode,
                    "generation specific code");
            });

            runner.Check("scm: a control after the final stopped record does not change status", delegate
            {
                ServiceScmFakeSink sink = new ServiceScmFakeSink();
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                ServiceScmFakeRunner generation = new ServiceScmFakeRunner();
                ServiceScmFakeFactory factory = new ServiceScmFakeFactory();
                factory.Runner = generation;
                EngineServiceScmService service = NewService(sink, events, factory);

                ServiceHostAssert.Equal(0, service.Run(ValidArguments()), "clean run");
                int statuses = sink.Statuses.Count;
                uint result = service.HandleControl(
                    WindowsServiceControlNativeMethods.ControlStop,
                    0);

                ServiceHostAssert.Equal(0u, result, "late stop acknowledged");
                ServiceHostAssert.Equal(statuses, sink.Statuses.Count, "no status after final stop");
            });

            runner.Check("scm: exit codes map each fixed failure class", delegate
            {
                ServiceHostAssert.Equal(
                    0,
                    EngineServiceScmExitCodes.ForHostResult(
                        EngineServiceHostResult.Success(EngineServiceHostState.Stopped, 1),
                        false),
                    "success");
                ServiceHostAssert.Equal(
                    3,
                    EngineServiceScmExitCodes.ForHostResult(
                        EngineServiceHostResult.Failure(
                            EngineProtocol.ErrorCodes.BoundaryAuthFailed,
                            EngineServiceHostState.Stopped,
                            1),
                        false),
                    "account");
                ServiceHostAssert.Equal(
                    4,
                    EngineServiceScmExitCodes.ForHostResult(
                        EngineServiceHostResult.Failure(
                            EngineProtocol.ErrorCodes.CleanupBlocked,
                            EngineServiceHostState.Stopped,
                            1),
                        false),
                    "state");
                ServiceHostAssert.Equal(
                    5,
                    EngineServiceScmExitCodes.ForHostResult(
                        EngineServiceHostResult.Failure(
                            EngineProtocol.ErrorCodes.BoundaryBusy,
                            EngineServiceHostState.Stopped,
                            1),
                        false),
                    "listener");
                ServiceHostAssert.Equal(
                    6,
                    EngineServiceScmExitCodes.ForHostResult(
                        EngineServiceHostResult.Failure(
                            EngineProtocol.ErrorCodes.EngineStopTimeout,
                            EngineServiceHostState.StopPending,
                            1),
                        false),
                    "stop timeout");
                ServiceHostAssert.Equal(
                    7,
                    EngineServiceScmExitCodes.ForHostResult(
                        EngineServiceHostResult.Failure(
                            EngineProtocol.ErrorCodes.Internal,
                            EngineServiceHostState.Stopped,
                            1),
                        false),
                    "internal");
                ServiceHostAssert.Equal(
                    8,
                    EngineServiceScmExitCodes.ForHostResult(
                        EngineServiceHostResult.Failure(
                            EngineProtocol.ErrorCodes.EngineUnavailable,
                            EngineServiceHostState.Stopped,
                            1),
                        false),
                    "engine");
                ServiceHostAssert.Equal(
                    9,
                    EngineServiceScmExitCodes.ForHostResult(
                        EngineServiceHostResult.DisabledFailure(
                            EngineProtocol.ErrorCodes.BoundaryAuthFailed,
                            EngineServiceHostState.Stopped,
                            1),
                        false),
                    "disabled");
                ServiceHostAssert.Equal(
                    0,
                    EngineServiceScmExitCodes.ForHostResult(
                        EngineServiceHostResult.Failure(
                            EngineProtocol.ErrorCodes.Closed,
                            EngineServiceHostState.Stopped,
                            0),
                        true),
                    "closed after a requested stop");
                ServiceHostAssert.Equal(
                    10,
                    EngineServiceScmExitCodes.ForHostResult(
                        EngineServiceHostResult.Failure(
                            EngineProtocol.ErrorCodes.Closed,
                            EngineServiceHostState.Stopped,
                            0),
                        false),
                    "closed without a stop");
                ServiceHostAssert.Equal(
                    10,
                    EngineServiceScmExitCodes.ForHostResult(null, false),
                    "missing result");
            });

            runner.Check("scm: the dispatcher connection error is a platform failure", delegate
            {
                ServiceHostAssert.Equal(
                    EngineServiceScmExitCodes.Platform,
                    EngineServiceScmExitCodes.ForDispatcherError(
                        WindowsServiceControlNativeMethods.ErrorFailedServiceControlConnect),
                    "controller connect");
                ServiceHostAssert.Equal(
                    EngineServiceScmExitCodes.Internal,
                    EngineServiceScmExitCodes.ForDispatcherError(87),
                    "other dispatcher error");
            });

            runner.Check("scm: the executable has no install, launch, route, or network call", delegate
            {
                string root = RepoRoot();
                ServiceHostAssert.True(root != null, "repo root");
                string folder = Path.Combine(
                    root,
                    "windows",
                    "src",
                    "HotspotShade.WinUI2.Service");
                string[] files = Directory.GetFiles(folder, "*.cs", SearchOption.TopDirectoryOnly);
                ServiceHostAssert.True(files.Length > 0, "service source files");
                string[] forbidden =
                {
                    "Create" + "Service",
                    "Delete" + "Service",
                    "Change" + "Service" + "Config",
                    "Open" + "SCManager",
                    "Process" + ".Start",
                    "Create" + "Process",
                    "Terminate" + "Process",
                    "Win" + "tun",
                    "net" + "sh",
                    "route" + ".exe",
                    "Sock" + "et",
                    "Tcp" + "Client",
                    "Http" + "Client"
                };
                for (int fileIndex = 0; fileIndex < files.Length; fileIndex++)
                {
                    string text = SourceText.Read(files[fileIndex]);
                    for (int wordIndex = 0; wordIndex < forbidden.Length; wordIndex++)
                    {
                        ServiceHostAssert.DoesNotContain(
                            text,
                            forbidden[wordIndex],
                            Path.GetFileName(files[fileIndex]) + " has " + forbidden[wordIndex]);
                    }
                }
            });

            runner.Check("scm: the executable is not in the solution or app", delegate
            {
                string root = RepoRoot();
                ServiceHostAssert.True(root != null, "repo root");
                string solution = SourceText.Read(
                    Path.Combine(root, "windows", "HotspotShade.WinUI2.sln"));
                ServiceHostAssert.DoesNotContain(
                    solution,
                    "HotspotShade.WinUI2.Service",
                    "not in the solution");
                string appProject = SourceText.Read(
                    Path.Combine(
                        root,
                        "windows",
                        "src",
                        "HotspotShade.WinUI2",
                        "HotspotShade.WinUI2.csproj"));
                ServiceHostAssert.DoesNotContain(
                    appProject,
                    "HotspotShade.WinUI2.Service",
                    "not in the app");
            });
        }

        private static string RepoRoot()
        {
            string configured = Environment.GetEnvironmentVariable("HOTSPOTSHADE_REPO_ROOT");
            if (!string.IsNullOrEmpty(configured)
                && Directory.Exists(Path.Combine(configured, "windows")))
            {
                return configured;
            }
            string directory = Directory.GetCurrentDirectory();
            while (!string.IsNullOrEmpty(directory))
            {
                if (Directory.Exists(Path.Combine(directory, "rust"))
                    && Directory.Exists(Path.Combine(directory, "windows")))
                {
                    return directory;
                }
                DirectoryInfo parent = Directory.GetParent(directory);
                directory = parent == null ? null : parent.FullName;
            }
            return null;
        }

        private static EngineServiceScmService NewService(
            ServiceScmFakeSink sink,
            ServiceHostFakeEvents events,
            ServiceScmFakeFactory factory)
        {
            EngineServiceScmStatusReporter reporter =
                new EngineServiceScmStatusReporter(sink, events);
            return new EngineServiceScmService(
                factory,
                reporter,
                events,
                TimeSpan.FromSeconds(1));
        }

        private static string[] ValidArguments()
        {
            return new string[]
            {
                EngineServiceCommandLine.InstanceOption,
                ServiceHostTestData.ServiceInstance,
                EngineServiceCommandLine.InstalledUserSidOption,
                ServiceHostTestData.UserSid,
                EngineServiceCommandLine.ServiceBinaryOption,
                ServiceHostTestData.ServiceImage,
                EngineServiceCommandLine.EngineImageOption,
                ServiceHostTestData.EngineImage,
                EngineServiceCommandLine.StateFileOption,
                "C:\\ProgramData\\HotspotShade\\state.bin"
            };
        }
    }
}
