using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.ServiceHost.Tests
{
    internal static class ServiceHostGuardChecks
    {
        public static void Run(ServiceHostCheckRunner runner)
        {
            runner.Check("guard: every start is refused with the source-proxy guard closed", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                GuardedEngineServiceBackend backend = NewBackend(now, events, true);
                ServiceHostAssert.False(GuardedEngineServiceBackend.SourceProxyStartEnabled, "guard closed");
                EngineServiceResult result = backend.Start(true);
                ServiceHostAssert.False(result.Ok, "start refused");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Unsupported, result.Code, "code");
                ServiceHostAssert.True(
                    events.Contains(EngineServiceEventCodes.SourceProxyGuardClosed),
                    "guard event");
            });

            runner.Check("guard: a missing record, a running status, and a cleanup failure precede the guard", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                GuardedEngineServiceBackend missing = NewBackend(now, events, false);
                EngineServiceResult result = missing.Start(true);
                ServiceHostAssert.False(result.Ok, "missing");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.CleanupUnknown, result.Code, "missing code");
                ServiceHostAssert.False(
                    events.Contains(EngineServiceEventCodes.SourceProxyGuardClosed),
                    "guard not reached");

                ServiceHostFakeStatusSource runningSource = new ServiceHostFakeStatusSource();
                runningSource.Status = ServiceHostTestData.RunningStatus(now);
                runningSource.ReadAt = now;
                GuardedEngineServiceBackend running = NewBackend(
                    now,
                    new ServiceHostFakeEvents(),
                    true,
                    runningSource);
                result = running.Start(true);
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.AlreadyRunning, result.Code, "running code");

                ServiceHostFakeStatusSource cleanupSource = new ServiceHostFakeStatusSource();
                cleanupSource.Status = ServiceHostTestData.CleanupFailedStatus(now);
                cleanupSource.ReadAt = now;
                GuardedEngineServiceBackend cleanup = NewBackend(
                    now,
                    new ServiceHostFakeEvents(),
                    true,
                    cleanupSource);
                result = cleanup.Start(true);
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.CleanupBlocked, result.Code, "cleanup code");
            });

            runner.Check("guard: a stop request and a canceled start are refused before the guard", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                GuardedEngineServiceBackend stopped = NewBackend(now, events, true);
                stopped.MarkStopRequested();
                EngineServiceResult result = stopped.Start(true);
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Closed, result.Code, "stop requested");
                ServiceHostAssert.False(events.Contains(EngineServiceEventCodes.SourceProxyGuardClosed), "no guard");

                GuardedEngineServiceBackend canceled = NewBackend(
                    now,
                    new ServiceHostFakeEvents(),
                    true);
                using (CancellationTokenSource source = new CancellationTokenSource())
                {
                    source.Cancel();
                    result = canceled.Start(true, source.Token);
                    ServiceHostAssert.Equal(
                        EngineProtocol.ErrorCodes.CleanupUnknown,
                        result.Code,
                        "canceled");
                }

                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.CleanupUnknown,
                    stopped.Stop(EngineServiceStopReason.User).Code, "first stop is unproven");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.CleanupUnknown,
                    stopped.Stop(EngineServiceStopReason.User).Code, "repeat remains unproven");
            });

            runner.Check("guard: stale status and wrong instance fail before the guard", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                ServiceHostFakeStatusSource staleSource = new ServiceHostFakeStatusSource();
                staleSource.Status = ServiceHostTestData.ReadyStatus(now.AddSeconds(-10));
                staleSource.ReadAt = now.AddSeconds(-10);
                GuardedEngineServiceBackend stale = NewBackend(
                    now,
                    new ServiceHostFakeEvents(),
                    true,
                    staleSource);
                EngineServiceResult result = stale.Start(true);
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.StaleStatus, result.Code, "stale status");

                ServiceHostFakeStatusSource otherSource = new ServiceHostFakeStatusSource();
                Dictionary<string, string> fields = ServiceHostTestData.BaseStatusFields();
                fields[EngineServiceStatusKeys.Instance] = "service-0002";
                otherSource.Status = ServiceHostTestData.ParseStatus(fields, now);
                otherSource.ReadAt = now;
                GuardedEngineServiceBackend other = NewBackend(
                    now,
                    new ServiceHostFakeEvents(),
                    true,
                    otherSource);
                result = other.Start(true);
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.EngineRestarted, result.Code, "wrong instance");

                ServiceHostFakeStatusSource throwingSource = new ServiceHostFakeStatusSource();
                throwingSource.Throw = true;
                GuardedEngineServiceBackend throwing = NewBackend(
                    now,
                    new ServiceHostFakeEvents(),
                    true,
                    throwingSource);
                result = throwing.Start(true);
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.EngineUnavailable, result.Code, "throwing source");
            });

            runner.Check("guard: cleanup refusal reaches the service session", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                foreach (string cleanup in new string[] { "pending", "failed" })
                {
                    Dictionary<string, string> fields = ServiceHostTestData.BaseStatusFields();
                    fields[EngineServiceStatusKeys.Cleanup] = cleanup;
                    ServiceHostFakeStatusSource source = new ServiceHostFakeStatusSource();
                    source.Status = ServiceHostTestData.ParseStatus(fields, now);
                    source.ReadAt = now;
                    GuardedEngineServiceBackend backend = NewBackend(now, new ServiceHostFakeEvents(), true, source);
                    string expected = cleanup == "pending"
                        ? EngineProtocol.ErrorCodes.CleanupPending : EngineProtocol.ErrorCodes.CleanupBlocked;
                    ServiceHostAssert.Equal(expected, backend.Start(true).Code, "start refusal");
                    EngineServiceSession session = new EngineServiceSession(
                        ServiceHostTestData.ServiceInstance, backend, new ServiceHostFakeClock(now));
                    EngineReply hello = ServiceHostAssert.Wait(
                        session.HandleAsync(ServiceHostTestData.HelloFields(), CancellationToken.None), 3000, "hello");
                    ServiceHostAssert.False(hello.Ok, "unverified status refused");
                    ServiceHostAssert.Equal(expected, hello.Code, "refusal reaches client");
                }
            });

            runner.Check("clean-thread dispatcher: the stop action runs on a different thread", delegate
            {
                EngineServiceCleanThreadDispatcher dispatcher = new EngineServiceCleanThreadDispatcher();
                int callingThread = Thread.CurrentThread.ManagedThreadId;
                int actionThread = callingThread;
                Task task = dispatcher.DispatchAsync(
                    delegate { actionThread = Thread.CurrentThread.ManagedThreadId; },
                    CancellationToken.None);
                ServiceHostAssert.Wait(task, 2000, "dispatch");
                ServiceHostAssert.True(actionThread != callingThread, "different thread");
            });

            runner.Check("clean-thread dispatcher: a throwing action faults the task", delegate
            {
                EngineServiceCleanThreadDispatcher dispatcher = new EngineServiceCleanThreadDispatcher();
                Task task = dispatcher.DispatchAsync(
                    delegate { throw new InvalidOperationException("stop failed"); },
                    CancellationToken.None);
                ServiceHostAssert.Throws<AggregateException>(
                    delegate { task.Wait(2000); },
                    "faulted");
            });

            // The owner decision of 2026-11-06 enables Windows token use behind the
            // physical adapter and default gateway gate.
            runner.Check("contract: the Rust source-proxy token gate is present", delegate
            {
                string root = RepoRoot();
                ServiceHostAssert.True(root != null, "repo root");
                string guard = File.ReadAllText(Path.Combine(root, "rust", "src", "windows_route_verify.rs"));
                ServiceHostAssert.Contains(guard, "require_token_destination_proof", "guard function");
                ServiceHostAssert.Contains(guard, "observe_token_destination", "physical adapter and gateway observation");
                ServiceHostAssert.Contains(guard, "TOKEN_DESTINATION_REFUSED", "fixed refusal");
            });

            runner.Check("contract: the new host has no install, launch, route, or tunnel call", delegate
            {
                string root = RepoRoot();
                ServiceHostAssert.True(root != null, "repo root");
                string folder = Path.Combine(root, "windows", "src", "HotspotShade.WinUI2.ServiceHost");
                string[] files = Directory.GetFiles(folder, "*.cs", SearchOption.TopDirectoryOnly);
                ServiceHostAssert.True(files.Length > 0, "host source files");
                string[] forbidden =
                {
                    "Create" + "Process",
                    "Terminate" + "Process",
                    "Win" + "tun",
                    "net" + "sh",
                    "route" + ".exe",
                    "Process" + ".Start",
                    "Create" + "Service",
                    "Start" + "Service",
                    "Sock" + "et",
                    "Http" + "Client",
                    "Tcp" + "Client",
                    "FullTrust" + "ProcessLauncher",
                    "sc" + ".exe",
                    "source_device_" + "token",
                    "Bear" + "er "
                };
                for (int fileIndex = 0; fileIndex < files.Length; fileIndex++)
                {
                    string text = File.ReadAllText(files[fileIndex]);
                    for (int wordIndex = 0; wordIndex < forbidden.Length; wordIndex++)
                    {
                        ServiceHostAssert.DoesNotContain(
                            text,
                            forbidden[wordIndex],
                            Path.GetFileName(files[fileIndex]) + " has " + forbidden[wordIndex]);
                    }
                }
            });

            runner.Check("contract: the host is not in the solution, app, or installer", delegate
            {
                string root = RepoRoot();
                ServiceHostAssert.True(root != null, "repo root");
                string solution = File.ReadAllText(
                    Path.Combine(root, "windows", "HotspotShade.WinUI2.sln"));
                ServiceHostAssert.DoesNotContain(
                    solution,
                    "HotspotShade.WinUI2.ServiceHost",
                    "not in the solution");
                string appProject = File.ReadAllText(
                    Path.Combine(
                        root,
                        "windows",
                        "src",
                        "HotspotShade.WinUI2",
                        "HotspotShade.WinUI2.csproj"));
                ServiceHostAssert.DoesNotContain(
                    appProject,
                    "HotspotShade.WinUI2.ServiceHost",
                    "not in the app");
                ServiceHostAssert.True(
                    File.Exists(Path.Combine(
                        root,
                        "windows",
                        "src",
                        "HotspotShade.WinUI2.ServiceHost",
                        "HotspotShade.WinUI2.ServiceHost.csproj")),
                    "project exists");
            });

            runner.Check("contract: the pipe and client paths use the reviewed core policy", delegate
            {
                string root = RepoRoot();
                ServiceHostAssert.True(root != null, "repo root");
                string server = File.ReadAllText(Path.Combine(
                    root,
                    "windows",
                    "src",
                    "HotspotShade.WinUI2.ServiceHost",
                    "WindowsNamedPipeServer.cs"));
                ServiceHostAssert.Contains(server, "EngineServiceBoundary.PipeServerOpenMode", "server open mode");
                ServiceHostAssert.Contains(server, "EngineServiceBoundary.PipeServerMode", "server mode");
                ServiceHostAssert.Contains(server, "EngineServiceBoundary.PipeServerMaxInstances", "one instance");
                ServiceHostAssert.Contains(server, "TryValidatePipeServerCreate", "server validate");
                ServiceHostAssert.Contains(server, "TryBuildPipeSddl", "sddl");

                string client = File.ReadAllText(Path.Combine(
                    root,
                    "windows",
                    "src",
                    "HotspotShade.WinUI2.ServiceHost",
                    "WindowsNamedPipeClient.cs"));
                ServiceHostAssert.Contains(client, "EngineServiceBoundary.PipeClientAccess", "client mask");
                ServiceHostAssert.Contains(client, "SecurityIdentification", "identification");
                ServiceHostAssert.Contains(client, "TryValidatePipeClientAccess", "client validate");

                string handshake = File.ReadAllText(Path.Combine(
                    root,
                    "windows",
                    "src",
                    "HotspotShade.WinUI2.ServiceHost",
                    "EngineServicePipeServerHandshake.cs"));
                ServiceHostAssert.True(
                    handshake.IndexOf("TryReadFrame", StringComparison.Ordinal)
                        < handshake.IndexOf("TryImpersonateClient", StringComparison.Ordinal),
                    "read before impersonate");
                ServiceHostAssert.Contains(handshake, "TryRevertToSelfAndVerify", "checked revert");
            });

            runner.Check("contract: the host README states the unintegrated limits", delegate
            {
                string root = RepoRoot();
                ServiceHostAssert.True(root != null, "repo root");
                string readme = File.ReadAllText(Path.Combine(
                    root,
                    "windows",
                    "src",
                    "HotspotShade.WinUI2.ServiceHost",
                    "README.md"));
                ServiceHostAssert.Contains(readme, "UNAPPROVED", "unapproved");
                ServiceHostAssert.Contains(readme, "NOT WIRED", "not wired");
                ServiceHostAssert.Contains(readme, "no Windows host", "no host");
                ServiceHostAssert.Contains(readme, "No service installation", "no install");
                ServiceHostAssert.Contains(readme, "source-proxy", "source proxy");
            });
        }

        private static GuardedEngineServiceBackend NewBackend(
            DateTimeOffset now,
            ServiceHostFakeEvents events,
            bool cleanRecord)
        {
            ServiceHostFakeStatusSource status = new ServiceHostFakeStatusSource();
            status.Status = ServiceHostTestData.ReadyStatus(now);
            status.ReadAt = now;
            return NewBackend(now, events, cleanRecord, status);
        }

        private static GuardedEngineServiceBackend NewBackend(
            DateTimeOffset now,
            ServiceHostFakeEvents events,
            bool cleanRecord,
            ServiceHostFakeStatusSource status)
        {
            ServiceHostFakeStateStore store = new ServiceHostFakeStateStore();
            store.Gate = cleanRecord
                ? EngineServiceStateGate.FromRecord(ServiceHostTestData.CleanRecord(now))
                : EngineServiceStateGate.Missing;
            ServiceHostFakeClock clock = new ServiceHostFakeClock(now);
            EngineServiceDurableStateGate state = new EngineServiceDurableStateGate(
                store,
                events,
                ServiceHostTestData.EngineImage,
                null);
            EngineServiceStatusGate statusGate = new EngineServiceStatusGate(
                ServiceHostTestData.ServiceInstance,
                events,
                TimeSpan.FromSeconds(3),
                TimeSpan.FromSeconds(2));
            return new GuardedEngineServiceBackend(
                status,
                statusGate,
                state,
                clock,
                events);
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
    }
}
