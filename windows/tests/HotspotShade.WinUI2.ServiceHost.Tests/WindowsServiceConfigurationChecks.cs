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
    internal static class WindowsServiceConfigurationChecks
    {
        private const string StatePath = "C:\\ProgramData\\HotspotShade\\state.bin";

        public static void Run(ServiceHostCheckRunner runner)
        {
            runner.Check("service config: every required option parses once", delegate
            {
                EngineServiceConfiguration configuration;
                string error;
                ServiceHostAssert.True(
                    EngineServiceCommandLine.TryParse(ValidArguments(), out configuration, out error),
                    "parse: " + error);
                ServiceHostAssert.Equal(
                    ServiceHostTestData.ServiceInstance,
                    configuration.Transport.ServiceInstanceId,
                    "instance");
                ServiceHostAssert.Equal(
                    ServiceHostTestData.UserSid,
                    configuration.Transport.InstalledUserSid,
                    "installed sid");
                ServiceHostAssert.Equal(
                    "C:\\ProgramData\\HotspotShade\\state.bin",
                    configuration.StateFilePath,
                    "state path");
            });

            runner.Check("service config: a missing, odd, or oversized argument list is refused", delegate
            {
                EngineServiceConfiguration configuration;
                string error;
                string[] missing = new string[8];
                Array.Copy(ValidArguments(), missing, 8);
                ServiceHostAssert.False(
                    EngineServiceCommandLine.TryParse(missing, out configuration, out error),
                    "missing option");
                ServiceHostAssert.False(
                    EngineServiceCommandLine.TryParse(null, out configuration, out error),
                    "null");
                ServiceHostAssert.False(
                    EngineServiceCommandLine.TryParse(new string[0], out configuration, out error),
                    "empty");
                ServiceHostAssert.False(
                    EngineServiceCommandLine.TryParse(
                        new string[] { EngineServiceCommandLine.InstanceOption },
                        out configuration,
                        out error),
                    "odd count");
                string[] oversized = new string[34];
                for (int index = 0; index < oversized.Length; index++)
                {
                    oversized[index] = "x";
                }
                ServiceHostAssert.False(
                    EngineServiceCommandLine.TryParse(oversized, out configuration, out error),
                    "oversized");
            });

            runner.Check("service config: a duplicate, unknown, or missing value is refused", delegate
            {
                EngineServiceConfiguration configuration;
                string error;

                string[] duplicate = ValidArguments();
                duplicate[1] = ServiceHostTestData.ServiceInstance;
                duplicate[3] = ServiceHostTestData.UserSid;
                duplicate[0] = EngineServiceCommandLine.InstalledUserSidOption;
                duplicate[2] = EngineServiceCommandLine.InstalledUserSidOption;
                ServiceHostAssert.False(
                    EngineServiceCommandLine.TryParse(duplicate, out configuration, out error),
                    "duplicate");

                string[] unknown = ValidArguments();
                unknown[0] = "--token";
                ServiceHostAssert.False(
                    EngineServiceCommandLine.TryParse(unknown, out configuration, out error),
                    "unknown option");
                ServiceHostAssert.Equal("unknown option", error, "fixed unknown error");

                string[] missingValue = ValidArguments();
                missingValue[1] = "--instance";
                ServiceHostAssert.False(
                    EngineServiceCommandLine.TryParse(missingValue, out configuration, out error),
                    "option as a value");
            });

            runner.Check("service config: the state path is an absolute local drive path", delegate
            {
                string normalized;
                ServiceHostAssert.True(
                    EngineServiceConfiguration.TryNormalizeStatePath(StatePath, out normalized),
                    "absolute");
                ServiceHostAssert.False(
                    EngineServiceConfiguration.TryNormalizeStatePath("state.bin", out normalized),
                    "relative");
                ServiceHostAssert.False(
                    EngineServiceConfiguration.TryNormalizeStatePath(
                        "\\\\server\\share\\state.bin",
                        out normalized),
                    "unc");
                ServiceHostAssert.False(
                    EngineServiceConfiguration.TryNormalizeStatePath(
                        "C:\\ProgramData\\..\\state.bin",
                        out normalized),
                    "dot segment");
                ServiceHostAssert.False(
                    EngineServiceConfiguration.TryNormalizeStatePath(
                        "C:\\ProgramData \\state.bin",
                        out normalized),
                    "trailing space in a component");
            });

            runner.Check("service config: a non-user SID or an invalid image path is refused", delegate
            {
                EngineServiceConfiguration configuration;
                string error;

                string[] groupSid = ValidArguments();
                groupSid[3] = "S-1-5-32-544";
                ServiceHostAssert.False(
                    EngineServiceCommandLine.TryParse(groupSid, out configuration, out error),
                    "group sid");

                string[] relativeService = ValidArguments();
                relativeService[5] = "HotspotShadeEngineSvc.exe";
                ServiceHostAssert.False(
                    EngineServiceCommandLine.TryParse(relativeService, out configuration, out error),
                    "relative service image");

                string[] uncEngine = ValidArguments();
                uncEngine[7] = "\\\\server\\share\\hotspotshade.exe";
                ServiceHostAssert.False(
                    EngineServiceCommandLine.TryParse(uncEngine, out configuration, out error),
                    "unc engine image");
            });

            runner.Check("state store: a missing, empty, or oversized file is cleanup_unknown", delegate
            {
                WithTempDirectory(delegate(string directory)
                {
                    string path = Path.Combine(directory, "state.bin");
                    EngineServiceFileStateStore store =
                        new EngineServiceFileStateStore(path, true);
                    EngineServiceStateGate gate;
                    string code;
                    ServiceHostAssert.False(store.TryRead(out gate, out code), "missing");
                    ServiceHostAssert.Equal(
                        EngineProtocol.ErrorCodes.CleanupUnknown,
                        code,
                        "missing code");

                    File.WriteAllBytes(path, new byte[0]);
                    ServiceHostAssert.False(store.TryRead(out gate, out code), "empty");

                    File.WriteAllBytes(
                        path,
                        new byte[EngineServiceFileStateStore.MaxStateBytes + 1]);
                    ServiceHostAssert.False(store.TryRead(out gate, out code), "oversized");
                });
            });

            runner.Check("state store: a valid never-launched frame loads and a trailing byte is refused", delegate
            {
                WithTempDirectory(delegate(string directory)
                {
                    string path = Path.Combine(directory, "state.bin");
                    byte[] frame = EncodeState(
                        EngineServiceStateRecord.CreateNeverLaunched(
                            ServiceHostTestData.Now(),
                            ServiceHostTestData.EngineImage));
                    File.WriteAllBytes(path, frame);

                    EngineServiceFileStateStore store =
                        new EngineServiceFileStateStore(path, true);
                    EngineServiceStateGate gate;
                    string code;
                    ServiceHostAssert.True(store.TryRead(out gate, out code), "valid frame");
                    ServiceHostAssert.True(gate.HasRecord, "record");
                    ServiceHostAssert.Equal(
                        EngineServicePhase.NeverLaunched,
                        gate.Record.Phase,
                        "phase");

                    byte[] trailing = new byte[frame.Length + 1];
                    Array.Copy(frame, trailing, frame.Length);
                    File.WriteAllBytes(path, trailing);
                    ServiceHostAssert.False(store.TryRead(out gate, out code), "trailing byte");
                });
            });

            runner.Check("state store: a directory or a leaf reparse point is refused", delegate
            {
                WithTempDirectory(delegate(string directory)
                {
                    byte[] frame = EncodeState(
                        EngineServiceStateRecord.CreateNeverLaunched(
                            ServiceHostTestData.Now(),
                            ServiceHostTestData.EngineImage));
                    string target = Path.Combine(directory, "target.bin");
                    File.WriteAllBytes(target, frame);

                    EngineServiceFileStateStore directoryStore =
                        new EngineServiceFileStateStore(directory, true);
                    EngineServiceStateGate gate;
                    string code;
                    ServiceHostAssert.False(directoryStore.TryRead(out gate, out code), "directory");

                    string link = Path.Combine(directory, "link.bin");
                    try
                    {
                        File.CreateSymbolicLink(link, target);
                    }
                    catch (Exception)
                    {
                        // The host filesystem does not support symlinks. The
                        // leaf reparse check is still source-reviewed and the
                        // field rule is exercised by the directory case.
                        return;
                    }
                    EngineServiceFileStateStore linkStore =
                        new EngineServiceFileStateStore(link, true);
                    ServiceHostAssert.False(linkStore.TryRead(out gate, out code), "leaf reparse");
                });
            });

            runner.Check("composition: the configured runner stops with cleanup unknown without an engine proof", delegate
            {
                DateTimeOffset now = ServiceHostTestData.Now();
                EngineServiceConfiguration configuration = new EngineServiceConfiguration(
                    ServiceHostTestData.ServiceInstance,
                    ServiceHostTestData.UserSid,
                    ServiceHostTestData.ServiceImage,
                    ServiceHostTestData.EngineImage,
                    StatePath);

                ServiceHostFakeAccountInspector account = new ServiceHostFakeAccountInspector();
                ServiceHostFakeStateStore store = new ServiceHostFakeStateStore();
                store.Gate = EngineServiceStateGate.FromRecord(
                    ServiceHostTestData.CleanRecord(now));
                ServiceHostFakeStatusSource status = new ServiceHostFakeStatusSource();
                status.Status = ServiceHostTestData.ReadyStatus(now);
                status.ReadAt = now;
                ServiceHostFakePipe pipe = new ServiceHostFakePipe();
                pipe.BlockReadUntilCancelled = true;
                ServiceHostFakePipeFactory pipeFactory = new ServiceHostFakePipeFactory();
                pipeFactory.Pipe = pipe;
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                ServiceHostFakeHostControl control = new ServiceHostFakeHostControl();

                EngineServiceHostRunner generation = new EngineServiceHostRunner(
                    configuration,
                    account,
                    store,
                    status,
                    pipeFactory,
                    events);
                CancellationTokenSource stop = new CancellationTokenSource();
                ManualResetEventSlim running = new ManualResetEventSlim(false);
                control.Observer = delegate(EngineServiceHostState state)
                {
                    if (state == EngineServiceHostState.Running)
                    {
                        running.Set();
                    }
                };
                Task<EngineServiceHostResult> task = Task.Run<EngineServiceHostResult>(
                    delegate { return generation.Run(control, stop.Token); });
                ServiceHostAssert.True(running.Wait(3000), "running reported");
                stop.Cancel();
                EngineServiceHostResult result = ServiceHostAssert.Wait(task, 5000, "runner");

                ServiceHostAssert.False(result.Ok, "cleanup is not proven");
                ServiceHostAssert.Equal(EngineProtocol.ErrorCodes.CleanupUnknown, result.Code, "cleanup result");
                ServiceHostAssert.Equal(1, pipeFactory.Calls, "one pipe");
                ServiceHostAssert.Equal(1, pipe.DisposeCalls, "pipe disposed");
                ServiceHostAssert.Equal(1, control.Count(EngineServiceHostState.Running), "running");
                ServiceHostAssert.Equal(1, control.Count(EngineServiceHostState.Stopped), "stopped");
                ServiceHostAssert.True(account.Calls > 0, "account checked");
            });

            runner.Check("composition: a failed channel factory closes partial channels", delegate
            {
                EngineServiceConfiguration configuration = new EngineServiceConfiguration(
                    ServiceHostTestData.ServiceInstance, ServiceHostTestData.UserSid,
                    ServiceHostTestData.ServiceImage, ServiceHostTestData.EngineImage, StatePath);
                PartialChannelFactory factory = new PartialChannelFactory();
                EngineServiceHostRunner generation = new EngineServiceHostRunner(
                    configuration, new ServiceHostFakeAccountInspector(),
                    new ServiceHostFakeStateStore(), null, new ServiceHostFakePipeFactory(),
                    new ServiceHostFakeEvents(), factory);
                using (CancellationTokenSource stop = new CancellationTokenSource())
                {
                    stop.Cancel();
                    generation.Run(new ServiceHostFakeHostControl(), stop.Token);
                }
                ServiceHostAssert.False(factory.Input.CanRead, "input closed");
                ServiceHostAssert.False(factory.Output.CanWrite, "output closed");
                ServiceHostAssert.False(factory.Parent.CanWrite, "liveness closed");
            });

            // This case verifies the non-Windows refusal. On Windows the real
            // runner could reach native service and pipe operations, so do not
            // invoke it as part of the hermetic test suite there.
            if (!System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(
                System.Runtime.InteropServices.OSPlatform.Windows))
            {
            runner.Check("composition: the production runner refuses off Windows before a pipe exists", delegate
            {
                EngineServiceConfiguration configuration = new EngineServiceConfiguration(
                    ServiceHostTestData.ServiceInstance,
                    ServiceHostTestData.UserSid,
                    ServiceHostTestData.ServiceImage,
                    ServiceHostTestData.EngineImage,
                    StatePath);
                ServiceHostFakeEvents events = new ServiceHostFakeEvents();
                ServiceHostFakeHostControl control = new ServiceHostFakeHostControl();
                EngineServiceHostRunner generation =
                    new EngineServiceHostRunner(configuration, events);

                EngineServiceHostResult result = generation.Run(
                    control,
                    CancellationToken.None);

                ServiceHostAssert.False(result.Ok, "not Windows");
                ServiceHostAssert.Equal(
                    EngineProtocol.ErrorCodes.BoundaryAuthFailed,
                    result.Code,
                    "account gate");
                ServiceHostAssert.Equal(0, control.Count(EngineServiceHostState.Running), "never running");
            });
            }
        }

        private sealed class PartialChannelFactory : IEngineControlChannelFactory
        {
            public readonly MemoryStream Input = new MemoryStream();
            public readonly MemoryStream Output = new MemoryStream();
            public readonly MemoryStream Parent = new MemoryStream();

            public bool TryCreate(out EngineControlStartup startup, out string code)
            {
                startup = new EngineControlStartup(Input, Output, Parent, EngineControlSessionKey.CreateRandom());
                code = EngineProtocol.ErrorCodes.EngineUnavailable;
                return false;
            }
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
                StatePath
            };
        }

        private static byte[] EncodeState(EngineServiceStateRecord record)
        {
            byte[] frame;
            string code;
            if (!EngineServiceFrame.TryEncode(record.ToFields(), out frame, out code))
            {
                throw new InvalidOperationException("state frame failed: " + code);
            }
            return frame;
        }

        private static void WithTempDirectory(Action<string> body)
        {
            string directory = Path.Combine(
                Path.GetTempPath(),
                "hotspotshade-service-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            try
            {
                body(directory);
            }
            finally
            {
                try
                {
                    Directory.Delete(directory, true);
                }
                catch (Exception)
                {
                    // A failed cleanup must not hide the check result.
                }
            }
        }
    }
}
