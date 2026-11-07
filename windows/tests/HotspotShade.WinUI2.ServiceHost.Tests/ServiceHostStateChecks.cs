using System;
using System.Collections.Generic;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.ServiceHost.Tests
{
    internal static class ServiceHostStateChecks
    {
        public static void Run(ServiceHostCheckRunner runner)
        {
            runner.Check("durable state: missing, unreadable, and throwing stores are cleanup_unknown", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                ServiceHostFakeStateStore missing = new ServiceHostFakeStateStore();
                missing.Ok = false;
                EngineServiceDurableStateGate missingGate = new EngineServiceDurableStateGate(
                    missing,
                    events,
                    ServiceHostTestData.EngineImage,
                    null);
                EngineServiceStateRecord record;
                string code;
                ServiceHostAssert.False(missingGate.TryRead(out record, out code), "missing");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.CleanupUnknown, code, "missing code");
                ServiceHostAssert.True(events.Contains(EngineServiceEventCodes.StateReadFailed), "missing event");

                ServiceHostFakeStateStore throwing = new ServiceHostFakeStateStore();
                throwing.Throw = true;
                EngineServiceDurableStateGate throwingGate = new EngineServiceDurableStateGate(
                    throwing,
                    new ServiceHostFakeEvents(),
                    ServiceHostTestData.EngineImage,
                    null);
                ServiceHostAssert.False(throwingGate.TryRead(out record, out code), "throwing");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.CleanupUnknown, code, "throwing code");

                ServiceHostFakeStateStore empty = new ServiceHostFakeStateStore();
                empty.Gate = EngineServiceStateGate.Missing;
                EngineServiceDurableStateGate emptyGate = new EngineServiceDurableStateGate(
                    empty,
                    new ServiceHostFakeEvents(),
                    ServiceHostTestData.EngineImage,
                    null);
                ServiceHostAssert.False(emptyGate.TryRead(out record, out code), "empty");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.CleanupUnknown, code, "empty code");
            });

            runner.Check("durable state: only a valid clean record passes the start gate", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                ServiceHostFakeStateStore store = new ServiceHostFakeStateStore();
                store.Gate = EngineServiceStateGate.FromRecord(ServiceHostTestData.CleanRecord(now));
                ServiceHostFakeProcessProof processProof = new ServiceHostFakeProcessProof();
                // The core gate proves the recorded process first. The host
                // gate then proves it again with its own injected seam.
                ServiceHostFakeRecordedProcessProof coreProof = new ServiceHostFakeRecordedProcessProof();
                EngineServiceDurableStateGate gate = new EngineServiceDurableStateGate(
                    store,
                    new ServiceHostFakeEvents(),
                    ServiceHostTestData.EngineImage,
                    processProof);
                EngineServiceStateRecord record;
                string code;
                ServiceHostAssert.True(gate.TryRead(out record, out code), "clean: " + code);
                ServiceHostAssert.True(record != null, "record");
                ServiceHostAssert.Equal(EngineServicePhase.NeverLaunched, record.Phase, "phase");

                store.Gate = EngineServiceStateGate.FromRecord(
                    ServiceHostTestData.CleanStoppedRecord(now),
                    coreProof);
                ServiceHostAssert.True(gate.TryRead(out record, out code), "clean stopped: " + code);
                ServiceHostAssert.Equal(EngineServicePhase.Stopped, record.Phase, "stopped phase");
                ServiceHostAssert.Equal(1, coreProof.Calls, "core process proof used");
                ServiceHostAssert.Equal(1, processProof.Calls, "process proof used");
                ServiceHostAssert.Equal(1234, processProof.LastProcessId, "pid");
                ServiceHostAssert.Equal(5678, processProof.LastCreated100ns, "creation time");
            });

            runner.Check("durable state: a clean stopped record needs a process-gone proof", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                ServiceHostFakeStateStore store = new ServiceHostFakeStateStore();
                ServiceHostFakeRecordedProcessProof coreProof = new ServiceHostFakeRecordedProcessProof();
                store.Gate = EngineServiceStateGate.FromRecord(
                    ServiceHostTestData.CleanStoppedRecord(now),
                    coreProof);
                EngineServiceStateRecord record;
                string code;

                EngineServiceDurableStateGate noProof = new EngineServiceDurableStateGate(
                    store,
                    new ServiceHostFakeEvents(),
                    ServiceHostTestData.EngineImage,
                    null);
                ServiceHostAssert.False(noProof.TryRead(out record, out code), "no proof");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.CleanupUnknown, code, "no proof code");

                ServiceHostFakeProcessProof alive = new ServiceHostFakeProcessProof();
                alive.Gone = false;
                EngineServiceDurableStateGate aliveGate = new EngineServiceDurableStateGate(
                    store,
                    new ServiceHostFakeEvents(),
                    ServiceHostTestData.EngineImage,
                    alive);
                ServiceHostAssert.False(aliveGate.TryRead(out record, out code), "process alive");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.CleanupUnknown, code, "alive code");

                ServiceHostFakeProcessProof throwing = new ServiceHostFakeProcessProof();
                throwing.Throw = true;
                EngineServiceDurableStateGate throwingGate = new EngineServiceDurableStateGate(
                    store,
                    new ServiceHostFakeEvents(),
                    ServiceHostTestData.EngineImage,
                    throwing);
                ServiceHostAssert.False(throwingGate.TryRead(out record, out code), "proof throws");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.CleanupUnknown, code, "throw code");
            });

            runner.Check("durable state: cleanup failure, unknown cleanup, pending cleanup, and a wrong image block a start", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                ServiceHostFakeStateStore store = new ServiceHostFakeStateStore();
                EngineServiceDurableStateGate gate = new EngineServiceDurableStateGate(
                    store,
                    events,
                    ServiceHostTestData.EngineImage,
                    null);
                EngineServiceStateRecord record;
                string code;

                store.Gate = EngineServiceStateGate.FromRecord(ServiceHostTestData.CleanupFailedRecord(now));
                ServiceHostAssert.False(gate.TryRead(out record, out code), "failed cleanup");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.CleanupBlocked, code, "failed code");

                store.Gate = EngineServiceStateGate.FromRecord(ServiceHostTestData.CleanupUnknownRecord(now));
                ServiceHostAssert.False(gate.TryRead(out record, out code), "unknown cleanup");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.CleanupUnknown, code, "unknown code");

                store.Gate = EngineServiceStateGate.FromRecord(ServiceHostTestData.CleanupPendingRecord(now));
                ServiceHostAssert.False(gate.TryRead(out record, out code), "pending cleanup");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.CleanupPending, code, "pending code");

                store.Gate = EngineServiceStateGate.FromRecord(
                    EngineServiceStateRecord.CreateNeverLaunched(
                        now,
                        "D:\\Other\\hotspotshade.exe"));
                ServiceHostAssert.False(gate.TryRead(out record, out code), "wrong image");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.BoundaryAuthFailed, code, "image code");
                ServiceHostAssert.True(events.Contains(EngineServiceEventCodes.StateImageMismatch), "image event");
            });

            runner.Check("status gate: instance mismatch, stale read, future read, and bad cleanup are refused", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                EngineServiceStatusGate gate = new EngineServiceStatusGate(
                    ServiceHostTestData.ServiceInstance,
                    events,
                    TimeSpan.FromSeconds(3),
                    TimeSpan.FromSeconds(2));

                EngineServiceStatus ready = ServiceHostTestData.ReadyStatus(now);
                string code;
                ServiceHostAssert.True(
                    gate.TryAccept(ready, now, now, out code),
                    "ready: " + code);

                Dictionary<string, string> other = ServiceHostTestData.BaseStatusFields();
                other[EngineServiceStatusKeys.Instance] = "service-0002";
                EngineServiceStatus otherStatus = ServiceHostTestData.ParseStatus(other, now);
                ServiceHostAssert.False(
                    gate.TryAccept(otherStatus, now, now, out code),
                    "other instance");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.EngineRestarted, code, "instance code");

                EngineServiceStatus old = ServiceHostTestData.ReadyStatus(now.AddSeconds(-10));
                ServiceHostAssert.False(
                    gate.TryAccept(old, now.AddSeconds(-10), now, out code),
                    "stale");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.StaleStatus, code, "stale code");

                EngineServiceStatus future = ServiceHostTestData.ReadyStatus(now.AddSeconds(5));
                ServiceHostAssert.False(
                    gate.TryAccept(future, now.AddSeconds(5), now, out code),
                    "future");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.StaleStatus, code, "future code");

                Dictionary<string, string> badCleanup = ServiceHostTestData.BaseStatusFields();
                badCleanup[EngineServiceStatusKeys.Cleanup] = "unknown";
                EngineServiceStatus badCleanupStatus = ServiceHostTestData.ParseStatus(badCleanup, now);
                ServiceHostAssert.True(
                    gate.TryAccept(badCleanupStatus, now, now, out code),
                    "unknown cleanup is visible without claiming it is clean");

                Dictionary<string, string> pending = ServiceHostTestData.BaseStatusFields();
                pending[EngineServiceStatusKeys.Cleanup] = "pending";
                EngineServiceStatus pendingStatus = ServiceHostTestData.ParseStatus(pending, now);
                ServiceHostAssert.False(
                    gate.TryAccept(pendingStatus, now, now, out code),
                    "stopped pending cleanup with no stop");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.CleanupPending, code, "pending code");
            });

            runner.Check("status gate: a running status has unknown cleanup and no stop", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                EngineServiceStatusGate gate = new EngineServiceStatusGate(
                    ServiceHostTestData.ServiceInstance,
                    new ServiceHostFakeEvents(),
                    TimeSpan.FromSeconds(3),
                    TimeSpan.FromSeconds(2));
                EngineServiceStatus running = ServiceHostTestData.RunningStatus(now);
                string code;
                ServiceHostAssert.True(
                    gate.TryAccept(running, now, now, out code),
                    "running: " + code);
            });

            runner.Check("event buffer: capacity is bounded and an unknown token becomes a fixed code", delegate
            {
                EngineServiceEventBuffer buffer = new EngineServiceEventBuffer(2);
                buffer.Record(EngineServiceEventCodes.SameUserCaller);
                buffer.Record(EngineServiceEventCodes.ParentLost);
                buffer.Record(EngineServiceEventCodes.ServiceStop);
                ServiceHostAssert.Equal(2, buffer.Count, "capacity");
                string[] snapshot = buffer.Snapshot();
                ServiceHostAssert.Equal(2, snapshot.Length, "snapshot length");
                ServiceHostAssert.Equal(EngineServiceEventCodes.ParentLost, snapshot[0], "first retained");
                ServiceHostAssert.Equal(EngineServiceEventCodes.ServiceStop, snapshot[1], "second retained");

                buffer.Record("free text with a SID S-1-5-18");
                ServiceHostAssert.True(buffer.Contains(EngineServiceEventCodes.EventCodeInvalid), "unknown fixed");
                snapshot[0] = "mutated";
                ServiceHostAssert.False(buffer.Contains("mutated"), "snapshot is a copy");
                ServiceHostAssert.True(
                    EngineServiceEventCodes.IsKnown("caller_impersonation_unreadable"),
                    "core unreadable event is known");
                ServiceHostAssert.True(
                    EngineServiceEventCodes.IsKnown("caller_impersonation_invalid"),
                    "core invalid event is known");
            });

            runner.Check("path policy: a quoted or case-varied installed path is normalized, aliases are refused", delegate
            {
                string normalized;
                ServiceHostAssert.True(
                    WindowsServicePathPolicy.TryNormalize(
                        "\"C:\\Program Files\\HotspotShade\\hotspotshade.exe\"",
                        out normalized),
                    "quoted");
                ServiceHostAssert.Equal(
                    "C:\\Program Files\\HotspotShade\\hotspotshade.exe",
                    normalized,
                    "quoted value");
                ServiceHostAssert.True(
                    WindowsServicePathPolicy.EqualsInstalled(
                        "c:/PROGRAM FILES/HotspotShade/hotspotshade.exe",
                        "C:\\Program Files\\HotspotShade\\hotspotshade.exe"),
                    "case and slash");

                string[] refused =
                {
                    "",
                    "hotspotshade.exe",
                    "C:hotspotshade.exe",
                    "C:\\Program Files\\..\\hotspotshade.exe",
                    "C:\\Program Files\\hotspotshade.exe:stream",
                    "C:\\Program Files\\hotspotshade.exe.",
                    "\\\\server\\share",
                    "\\\\?\\C:\\Program Files\\hotspotshade.exe",
                    "C:\\Program Files\\bad\u0001name.exe"
                };
                for (int index = 0; index < refused.Length; index++)
                {
                    ServiceHostAssert.False(
                        WindowsServicePathPolicy.TryNormalize(refused[index], out normalized),
                        "refused " + refused[index]);
                }
            });

            runner.Check("transport options: the installed account and paths are validated", delegate
            {
                ServiceHostAssert.Throws<ArgumentException>(
                    delegate
                    {
                        new EngineServiceTransportOptions(
                            ServiceHostTestData.ServiceInstance,
                            "S-1-5-18",
                            ServiceHostTestData.ServiceImage,
                            ServiceHostTestData.EngineImage);
                    },
                    "SYSTEM account");
                ServiceHostAssert.Throws<ArgumentException>(
                    delegate
                    {
                        new EngineServiceTransportOptions(
                            ServiceHostTestData.ServiceInstance,
                            ServiceHostTestData.UserSid,
                            "relative.exe",
                            ServiceHostTestData.EngineImage);
                    },
                    "relative service path");
                ServiceHostAssert.Throws<ArgumentException>(
                    delegate
                    {
                        new EngineServiceTransportOptions(
                            "bad",
                            ServiceHostTestData.UserSid,
                            ServiceHostTestData.ServiceImage,
                            ServiceHostTestData.EngineImage);
                    },
                    "bad instance");
                EngineServiceTransportOptions options = ServiceHostTestData.TransportOptions();
                options.Validate();
                ServiceHostAssert.Equal(
                    ServiceHostTestData.ServiceImage,
                    options.InstalledServiceBinaryPath,
                    "service path");

                EngineServiceHostOptions hostOptions = new EngineServiceHostOptions();
                hostOptions.Validate();
                hostOptions.StartBudget = TimeSpan.Zero;
                ServiceHostAssert.Throws<ArgumentOutOfRangeException>(
                    delegate { hostOptions.Validate(); },
                    "zero start readiness budget");
            });

            runner.Check("platform: native factories fail closed off Windows and are not called on Windows", delegate
            {
                if (EngineServicePlatform.IsWindows)
                {
                    // Do not create a pipe or open a service on a real host.
                    return;
                }
                EngineServiceTransportOptions options = ServiceHostTestData.TransportOptions();
                WindowsNamedPipeServerFactory server = new WindowsNamedPipeServerFactory(options);
                IEngineServicePipeConnection pipe;
                string code;
                ServiceHostAssert.False(server.TryCreateFirstInstance(out pipe, out code), "server");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Unsupported, code, "server code");
                ServiceHostAssert.True(pipe == null, "no server pipe");

                WindowsNamedPipeClientFactory client = new WindowsNamedPipeClientFactory(
                    new ServiceHostFakeEvents());
                IEngineServiceClientPipe clientPipe;
                ServiceHostAssert.False(client.TryOpen(out clientPipe, out code), "client");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.Unsupported, code, "client code");
                ServiceHostAssert.True(clientPipe == null, "no client pipe");
            });
        }
    }
}
