using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using HotspotShade.WinUI2.Core.Engine;

namespace HotspotShade.WinUI2.Core.Tests
{
    // Hermetic checks for the app service broker core. They create no pipe,
    // process, adapter, route, or endpoint. The Windows host seam is a fake.
    // The test owner registers this class with
    // BrokerBoundaryTests.Run(runner) in Program.cs.
    internal static class BrokerBoundaryTests
    {
        private const string TrustedRoot = "C:\\Program Files\\HotspotShade";
        private const string EnginePath = TrustedRoot + "\\hotspotshade.exe";
        private const string SessionA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        private const string SessionB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        private const string Instance = "broker-0001";

        public static void Run(TestRunner runner)
        {
            runner.Check("broker: hello launches the engine once and reports the instance", delegate
            {
                BrokerStack stack = NewStack();
                EngineReply reply = Wait(stack.Service.HandleAsync(
                    Fields(EngineProtocol.Operations.Hello, SessionA),
                    CancellationToken.None));

                AssertEx.True(reply.Ok, "hello succeeds");
                string instance;
                string code;
                AssertEx.True(EngineWire.TryReadHello(reply, out instance, out code), "hello shape");
                AssertEx.Equal(Instance, instance, "instance");
                AssertEx.Equal(
                    EngineProtocol.EngineStates.Ready,
                    reply.Fields[EngineProtocol.Keys.Engine],
                    "engine word");
                AssertEx.Equal(1, stack.Host.Launches, "one launch");
                AssertEx.Equal(0, stack.Local.StartCalls, "no start");
                AssertEx.Equal(SessionA, stack.Service.BoundSessionId, "session bound");
                AssertEx.False(stack.Service.ShutdownRequested, "no shutdown");
            });

            runner.Check("broker: status before hello is refused", delegate
            {
                BrokerStack stack = NewStack();
                EngineReply reply = Wait(stack.Service.HandleAsync(
                    Fields(EngineProtocol.Operations.Status, SessionA),
                    CancellationToken.None));

                AssertEx.False(reply.Ok, "status is refused");
                AssertEx.Equal(EngineProtocol.ErrorCodes.NotConnected, reply.Code, "code");
                AssertEx.Equal(0, stack.Host.Launches, "no launch");
            });

            runner.Check("broker: a different session id is refused", delegate
            {
                BrokerStack stack = NewStack();
                Wait(stack.Service.HandleAsync(
                    Fields(EngineProtocol.Operations.Hello, SessionA),
                    CancellationToken.None));

                EngineReply reply = Wait(stack.Service.HandleAsync(
                    Fields(EngineProtocol.Operations.Status, SessionB),
                    CancellationToken.None));

                AssertEx.False(reply.Ok, "the second session is refused");
                AssertEx.Equal(EngineProtocol.ErrorCodes.Forbidden, reply.Code, "code");
                AssertEx.Equal(SessionA, stack.Service.BoundSessionId, "the first session stays bound");
            });

            runner.Check("broker: a start without pairing is refused before the engine", delegate
            {
                BrokerStack stack = NewStack();
                Wait(stack.Service.HandleAsync(
                    Fields(EngineProtocol.Operations.Hello, SessionA),
                    CancellationToken.None));

                EngineReply reply = Wait(stack.Service.HandleAsync(
                    Fields(EngineProtocol.Operations.Start, SessionA, true),
                    CancellationToken.None));

                AssertEx.False(reply.Ok, "start is refused");
                AssertEx.Equal(EngineProtocol.ErrorCodes.NotPaired, reply.Code, "code");
                AssertEx.Equal(0, stack.Local.StartCalls, "no start request");
                AssertEx.Equal(1, stack.Host.Launches, "no second launch");
            });

            runner.Check("broker: a running status without a connection count is a bad response", delegate
            {
                BrokerStack stack = NewStack();
                Wait(stack.Service.HandleAsync(
                    Fields(EngineProtocol.Operations.Hello, SessionA),
                    CancellationToken.None));
                stack.Local.Status = EngineLocalStatus.Status(
                    true,
                    true,
                    true,
                    true,
                    true,
                    true,
                    false,
                    0,
                    EngineStopReason.None);

                EngineReply reply = Wait(stack.Service.HandleAsync(
                    Fields(EngineProtocol.Operations.Status, SessionA),
                    CancellationToken.None));

                AssertEx.False(reply.Ok, "the status is refused");
                AssertEx.Equal(EngineProtocol.ErrorCodes.BadResponse, reply.Code, "code");
            });

            runner.Check("broker: a running status without pairing is a bad response", delegate
            {
                BrokerStack stack = NewStack();
                Wait(stack.Service.HandleAsync(
                    Fields(EngineProtocol.Operations.Hello, SessionA),
                    CancellationToken.None));
                stack.Local.Status = EngineLocalStatus.Status(
                    true,
                    true,
                    false,
                    false,
                    false,
                    true,
                    true,
                    0,
                    EngineStopReason.None);

                EngineReply reply = Wait(stack.Service.HandleAsync(
                    Fields(EngineProtocol.Operations.Status, SessionA),
                    CancellationToken.None));

                AssertEx.False(reply.Ok, "the status is refused");
                AssertEx.Equal(EngineProtocol.ErrorCodes.BadResponse, reply.Code, "code");
            });

            runner.Check("broker: unsupported operations stay unsupported", delegate
            {
                BrokerStack stack = NewStack();
                Wait(stack.Service.HandleAsync(
                    Fields(EngineProtocol.Operations.Hello, SessionA),
                    CancellationToken.None));

                string[] operations =
                {
                    EngineProtocol.Operations.PairBegin,
                    EngineProtocol.Operations.PairStatus,
                    EngineProtocol.Operations.PairCancel,
                    EngineProtocol.Operations.Probe,
                    EngineProtocol.Operations.Diagnostics,
                    EngineProtocol.Operations.Failures,
                    EngineProtocol.Operations.Forget
                };
                for (int index = 0; index < operations.Length; index++)
                {
                    EngineReply reply = Wait(stack.Service.HandleAsync(
                        Fields(operations[index], SessionA),
                        CancellationToken.None));
                    AssertEx.False(reply.Ok, operations[index] + " is refused");
                    AssertEx.Equal(
                        EngineProtocol.ErrorCodes.Unsupported,
                        reply.Code,
                        operations[index] + " code");
                }
            });

            runner.Check("broker: a credential field is refused before dispatch", delegate
            {
                List<KeyValuePair<string, object>> pairs = new List<KeyValuePair<string, object>>
                {
                    new KeyValuePair<string, object>("v", "1"),
                    new KeyValuePair<string, object>("op", EngineProtocol.Operations.Status),
                    new KeyValuePair<string, object>("sid", SessionA),
                    new KeyValuePair<string, object>("source_device_token", "abcd")
                };
                Dictionary<string, string> fields;
                string code;
                AssertEx.False(EngineBrokerFields.TryConvert(pairs, out fields, out code), "refused");
                AssertEx.Equal(EngineProtocol.ErrorCodes.Forbidden, code, "code");
            });

            runner.Check("broker: app service values must be strings", delegate
            {
                Dictionary<string, string> fields;
                string code;

                List<KeyValuePair<string, object>> number = new List<KeyValuePair<string, object>>
                {
                    new KeyValuePair<string, object>("v", 1)
                };
                AssertEx.False(EngineBrokerFields.TryConvert(number, out fields, out code), "number value");
                AssertEx.Equal(EngineProtocol.ErrorCodes.BadRequest, code, "number code");

                List<KeyValuePair<string, object>> missing = new List<KeyValuePair<string, object>>
                {
                    new KeyValuePair<string, object>("v", null)
                };
                AssertEx.False(EngineBrokerFields.TryConvert(missing, out fields, out code), "null value");

                List<KeyValuePair<string, object>> empty = new List<KeyValuePair<string, object>>();
                AssertEx.False(EngineBrokerFields.TryConvert(empty, out fields, out code), "empty value set");

                List<KeyValuePair<string, object>> many = new List<KeyValuePair<string, object>>();
                for (int index = 0; index < EngineProtocol.MaxFieldCount + 1; index++)
                {
                    many.Add(new KeyValuePair<string, object>("k" + index, "v"));
                }
                AssertEx.False(EngineBrokerFields.TryConvert(many, out fields, out code), "too many fields");

                List<KeyValuePair<string, object>> valid = new List<KeyValuePair<string, object>>
                {
                    new KeyValuePair<string, object>("v", "1"),
                    new KeyValuePair<string, object>("op", EngineProtocol.Operations.Hello),
                    new KeyValuePair<string, object>("sid", SessionA)
                };
                AssertEx.True(EngineBrokerFields.TryConvert(valid, out fields, out code), "valid fields");
                AssertEx.Equal(3, fields.Count, "field count");
                AssertEx.Equal("", code, "no code");
            });

            runner.Check("broker: shutdown closes once and refuses later requests", delegate
            {
                BrokerStack stack = NewStack();
                Wait(stack.Service.HandleAsync(
                    Fields(EngineProtocol.Operations.Hello, SessionA),
                    CancellationToken.None));

                EngineReply shutdown = Wait(stack.Service.HandleAsync(
                    Fields(EngineProtocol.Operations.Shutdown, SessionA),
                    CancellationToken.None));

                AssertEx.True(shutdown.Ok, "shutdown succeeds");
                AssertEx.True(stack.Service.ShutdownRequested, "shutdown flag");
                AssertEx.Equal(1, stack.Host.Closes, "one close");

                EngineReply late = Wait(stack.Service.HandleAsync(
                    Fields(EngineProtocol.Operations.Status, SessionA),
                    CancellationToken.None));
                AssertEx.False(late.Ok, "a later request is refused");
                AssertEx.Equal(EngineProtocol.ErrorCodes.Closed, late.Code, "closed code");
                AssertEx.Equal(1, stack.Host.Closes, "no second close");
            });

            runner.Check("broker: a failed launch is a fixed code without a path or secret", delegate
            {
                BrokerStack stack = NewStack();
                stack.Host.Outcome = EngineLaunchOutcome.Failed(EngineLaunchFailure.AdminRequired);

                EngineReply reply = Wait(stack.Service.HandleAsync(
                    Fields(EngineProtocol.Operations.Hello, SessionA),
                    CancellationToken.None));

                AssertEx.False(reply.Ok, "hello fails closed");
                AssertEx.Equal(EngineProtocol.ErrorCodes.EngineUnavailable, reply.Code, "code");
                string text = Join(reply.Fields.Values);
                AssertEx.DoesNotContain(text, TrustedRoot, "no install path");
                AssertEx.DoesNotContain(text, EnginePath, "no engine path");
                AssertEx.DoesNotContain(text, "8787", "no port");
                AssertEx.DoesNotContain(text, stack.Host.SecretText, "no secret");
                AssertEx.Equal(1, stack.Host.Launches, "one attempt");
                AssertEx.Equal(1, stack.Host.Closes, "one cleanup");
            });

            runner.Check("broker: the chosen port avoids the GUI and pairing ports", delegate
            {
                for (int index = 0; index < 64; index++)
                {
                    int port = EngineBrokerRules.PickPort();
                    AssertEx.True(EngineBrokerRules.IsBrokerPort(port), "broker port range");
                    AssertEx.True(port != EngineBrokerRules.BrowserGuiPort, "not the GUI port");
                    AssertEx.True(port != EngineBrokerRules.PairingPort, "not the pairing port");
                    AssertEx.True(port >= EngineBrokerRules.FirstPort, "above the dynamic start");
                    AssertEx.True(port <= EngineBrokerRules.LastPort, "below the dynamic end");
                }
                AssertEx.False(EngineBrokerRules.IsBrokerPort(EngineBrokerRules.BrowserGuiPort), "GUI refused");
                AssertEx.False(EngineBrokerRules.IsBrokerPort(EngineBrokerRules.PairingPort), "pairing refused");
                AssertEx.False(EngineBrokerRules.IsBrokerPort(80), "privileged port refused");
            });

            runner.Check("broker: every reply passes the strict wire reader", delegate
            {
                BrokerStack stack = NewStack();
                List<EngineReply> replies = new List<EngineReply>();
                replies.Add(Wait(stack.Service.HandleAsync(
                    Fields(EngineProtocol.Operations.Hello, SessionA), CancellationToken.None)));
                replies.Add(Wait(stack.Service.HandleAsync(
                    Fields(EngineProtocol.Operations.Status, SessionA), CancellationToken.None)));
                replies.Add(Wait(stack.Service.HandleAsync(
                    Fields(EngineProtocol.Operations.Start, SessionA, true), CancellationToken.None)));
                replies.Add(Wait(stack.Service.HandleAsync(
                    Fields(EngineProtocol.Operations.Stop, SessionA), CancellationToken.None)));
                replies.Add(Wait(stack.Service.HandleAsync(
                    Fields(EngineProtocol.Operations.Forget, SessionA), CancellationToken.None)));

                for (int index = 0; index < replies.Count; index++)
                {
                    EngineReply checkedReply;
                    string code;
                    AssertEx.True(
                        EngineWire.TryReadReply(replies[index].Fields, out checkedReply, out code),
                        "reply " + index + " is valid: " + code);
                    foreach (string key in replies[index].Fields.Keys)
                    {
                        AssertEx.False(EngineProtocol.IsCredentialKey(key), "credential key " + key);
                    }
                }
            });

            runner.Check("broker: the app package declares the broker, the app service, and two capabilities", delegate
            {
                string root = FindWindowsRoot();
                AssertEx.True(root != null, "windows root");
                string manifest = Path.Combine(root, "src", "HotspotShade.WinUI2", "Package.appxmanifest");
                XDocument package = XDocument.Load(manifest);
                XElement service = package.Descendants()
                    .FirstOrDefault(e => e.Name.LocalName == "AppService");
                AssertEx.True(service != null, "app service declaration");
                AssertEx.Equal(
                    HotspotShade.WinUI2.Core.App.BrokerProtocol.ServiceName,
                    (string)service.Attribute("Name"),
                    "app service name");
                AssertEx.True(service.Attribute("EntryPoint") == null, "the app service is hosted in the window process");
                XElement fullTrust = package.Descendants()
                    .FirstOrDefault(e => e.Name.LocalName == "Extension"
                        && (string)e.Attribute("Category") == "windows.fullTrustProcess");
                AssertEx.True(fullTrust != null, "full-trust process declaration");
                AssertEx.Equal(
                    "Broker\\HotspotShade.WinUI2.Broker.exe",
                    (string)fullTrust.Attribute("Executable"),
                    "broker executable");
                List<string> capabilities = package.Descendants()
                    .Where(e => e.Name.LocalName == "Capability")
                    .Select(e => (string)e.Attribute("Name"))
                    .OrderBy(name => name, StringComparer.Ordinal)
                    .ToList();
                AssertEx.Equal(2, capabilities.Count, "capability count");
                AssertEx.Equal("allowElevation", capabilities[0], "elevation capability");
                AssertEx.Equal("runFullTrust", capabilities[1], "full-trust capability");
                AssertEx.False(
                    File.Exists(Path.Combine(root, "src", "HotspotShade.WinUI2.Broker", "Package.broker.fragment.xml")),
                    "the old inactive fragment is gone");
            });

            runner.Check("broker: the rendezvous pipe resets its event before every overlapped operation", delegate
            {
                string root = FindWindowsRoot();
                AssertEx.True(root != null, "windows root");
                string pipe = ReadBrokerSource(root, "RendezvousPipe.cs");
                // The event is auto-reset, and ResetOverlapped clears it, so a
                // signal left by the connect never ends a later wait early.
                AssertEx.Contains(pipe, "CreateEventW(IntPtr.Zero, false, false, null)", "auto-reset event");
                int resetAt = pipe.IndexOf("private void ResetOverlapped()", StringComparison.Ordinal);
                AssertEx.True(resetAt >= 0, "ResetOverlapped exists");
                int endAt = pipe.IndexOf("Marshal.StructureToPtr", resetAt, StringComparison.Ordinal);
                AssertEx.True(
                    endAt > resetAt && pipe.Substring(resetAt, endAt - resetAt).Contains("ResetEvent(ioEvent)"),
                    "ResetOverlapped calls ResetEvent");
                AssertEx.DoesNotContain(pipe, "out ignored, false)", "the connect result is read with wait true");
                AssertEx.DoesNotContain(pipe, "out transferred, false)", "read and write results are read with wait true");
                int ops = 0;
                int index = 0;
                while ((index = pipe.IndexOf("ResetOverlapped();", index, StringComparison.Ordinal)) >= 0)
                {
                    ops++;
                    index++;
                }
                AssertEx.True(ops >= 3, "connect, write, and read each reset before the call");
            });

            runner.Check("broker: the app service connection retries inside the window with a fresh connection", delegate
            {
                string root = FindWindowsRoot();
                AssertEx.True(root != null, "windows root");
                string transport = ReadBrokerSource(root, "AppServiceBrokerTransport.cs");
                AssertEx.Contains(transport, "bool thrown = false;", "an exception is a retryable failure");
                AssertEx.DoesNotContain(
                    transport,
                    "status = AppServiceConnectionStatus.Unknown;\n                }\n                if (status == AppServiceConnectionStatus.Success)",
                    "an exception no longer maps to a final Unknown");
                int loopAt = transport.IndexOf("while (true)", StringComparison.Ordinal);
                int newAt = transport.IndexOf("new AppServiceConnection()", StringComparison.Ordinal);
                AssertEx.True(loopAt >= 0 && newAt > loopAt, "the connection is created inside the retry loop");
            });

            runner.Check("broker: an unreadable IPv6 listener table is empty, an IPv4 one is Unknown", delegate
            {
                string root = FindWindowsRoot();
                AssertEx.True(root != null, "windows root");
                string table = SourceText.Read(Path.Combine(
                    root,
                    "src",
                    "HotspotShade.WinUI2.TestLauncher",
                    "ListenerTable.cs"));
                AssertEx.Contains(table, "ErrorNotSupported = 50", "ERROR_NOT_SUPPORTED");
                AssertEx.Contains(table, "ErrorFileNotFound = 2", "ERROR_FILE_NOT_FOUND");
                AssertEx.Contains(table, "!Ipv6Unavailable(error6)", "only the IPv6 read tolerates those errors");
                AssertEx.DoesNotContain(table, "Ipv6Unavailable(error4)", "the IPv4 read does not");
            });

            runner.Check("broker: a timed-out engine close keeps the handle and reports not exited", delegate
            {
                string root = FindWindowsRoot();
                AssertEx.True(root != null, "windows root");
                string host = ReadBrokerSource(root, "Win32EngineHost.cs");
                AssertEx.Contains(host, "closingProcess", "the handle is kept while the process may run");
                AssertEx.Contains(host, "public void Release()", "Release closes the handle after the exit");
                AssertEx.DoesNotContain(host, "Math.Min(8000D", "the caller's grace is not capped at 8 seconds");
                int closeAt = host.IndexOf("private bool CloseCore(TimeSpan grace)", StringComparison.Ordinal);
                int endAt = host.IndexOf("private void CloseParentAndWait()", StringComparison.Ordinal);
                AssertEx.True(closeAt >= 0 && endAt > closeAt, "CloseCore found");
                string close = host.Substring(closeAt, endAt - closeAt);
                int waitAt = close.IndexOf("WaitForSingleObject(process", StringComparison.Ordinal);
                AssertEx.True(waitAt >= 0, "CloseCore waits");
                AssertEx.True(
                    close.IndexOf("CloseHandle(process)", StringComparison.Ordinal) < 0,
                    "CloseCore never closes the handle itself");
                string endpoints = ReadBrokerSource(root, "EngineEndpoints.cs");
                AssertEx.Contains(endpoints, "host.Release();", "the user engine releases through its host");
            });

            runner.Check("broker: shutdown serializes with in-flight actions and stops the elevated engine by the confirmed path", delegate
            {
                string root = FindWindowsRoot();
                AssertEx.True(root != null, "windows root");
                string service = ReadBrokerSource(root, "BrokerService.cs");
                int shutdownAt = service.IndexOf("public void Shutdown()", StringComparison.Ordinal);
                AssertEx.True(shutdownAt >= 0, "Shutdown found");
                string shutdown = service.Substring(shutdownAt, 1800);
                int flagAt = shutdown.IndexOf("shuttingDown = true", StringComparison.Ordinal);
                int waitAt = shutdown.IndexOf("actions.Wait(ShutdownActionWait)", StringComparison.Ordinal);
                int takeAt = shutdown.IndexOf("elevated = null", StringComparison.Ordinal);
                AssertEx.True(flagAt >= 0 && waitAt > flagAt && takeAt > waitAt, "flag, bounded wait, then take the engines");
                AssertEx.Contains(service, "StopElevatedForExit(engine)", "quit uses the confirmed stop");
                AssertEx.True(
                    service.Split(new[] { "IsShuttingDown()" }, StringSplitOptions.None).Length >= 4,
                    "TurnOn, TurnOff and the user actions refuse once shutdown starts");
            });

            runner.Check("broker: the full-trust extension has its entry point and a reply bound under the message cap", delegate
            {
                string root = FindWindowsRoot();
                AssertEx.True(root != null, "windows root");
                string manifest = SourceText.Read(Path.Combine(root, "src", "HotspotShade.WinUI2", "Package.appxmanifest"));
                AssertEx.Contains(manifest, "EntryPoint=\"Windows.FullTrustApplication\"", "full-trust entry point");
                // 2 bytes per UTF-16 character stays well under ~100 KB.
                AssertEx.True(
                    HotspotShade.WinUI2.Core.App.BrokerProtocol.MaxBodyChars * 2 <= 92160,
                    "the body bound leaves headroom under the app service cap");
            });

            runner.Check("broker: the host keeps the secret on a pipe and never forces a stop", delegate
            {
                string root = FindWindowsRoot();
                AssertEx.True(root != null, "windows root");
                string host = SourceText.Read(Path.Combine(
                    root,
                    "src",
                    "HotspotShade.WinUI2.Broker",
                    "Win32EngineHost.cs"));
                // The child receives only the two listed read handles. The
                // write ends stay private to the broker.
                AssertEx.Contains(host, "ProcThreadAttributeHandleList", "explicit handle list");
                AssertEx.Contains(
                    host,
                    "SetHandleInformation(write, HandleFlagInherit, 0)",
                    "write ends are not inherited");
                AssertEx.Contains(host, "CreateProcessW", "fixed process creation call");
                AssertEx.DoesNotContain(host, "TerminateProcess", "no forced termination");
                AssertEx.DoesNotContain(host, "--demo", "no demo engine");
                int copyAt = host.IndexOf(
                    "secretCopy = CopySecret(request.Secret)",
                    StringComparison.Ordinal);
                int taskAt = host.IndexOf("return Task.Run", StringComparison.Ordinal);
                AssertEx.True(
                    copyAt >= 0 && taskAt > copyAt,
                    "the host copies the secret before the launch task starts");

                string runtime = SourceText.Read(Path.Combine(
                    root,
                    "src",
                    "HotspotShade.WinUI2.Broker",
                    "BrokerRuntime.cs"));
                AssertEx.Contains(runtime, "args.Length != 0", "no broker arguments");
                string endpoints = SourceText.Read(Path.Combine(
                    root,
                    "src",
                    "HotspotShade.WinUI2.Broker",
                    "EngineEndpoints.cs"));
                AssertEx.Contains(
                    endpoints,
                    "System.IO.Path.Combine(root, \"Engine\", EngineLaunchRules.ExecutableName)",
                    "fixed engine path");
                AssertEx.Contains(endpoints, "ListenerTable.Check(engine.Port, engine.ProcessId)", "listener owner check before every request");

                string client = SourceText.Read(Path.Combine(
                    root,
                    "src",
                    "HotspotShade.WinUI2.TestLauncher",
                    "LauncherHttp.cs"));
                AssertEx.Contains(client, "\"127.0.0.1\"", "loopback only");
                AssertEx.Contains(client, "OptionRedirectPolicy = 88", "fixed redirect policy");
                AssertEx.DoesNotContain(client, "System" + ".Net", "no managed proxy or name lookup");

                string appProject = SourceText.Read(Path.Combine(
                    root,
                    "src",
                    "HotspotShade.WinUI2",
                    "HotspotShade.WinUI2.csproj"));
                AssertEx.DoesNotContain(
                    appProject,
                    "Package.broker.fragment.xml",
                    "the active package does not merge the broker fragment");
            });

            runner.Check("broker: the solution and project carry the broker x64", delegate
            {
                string root = FindWindowsRoot();
                AssertEx.True(root != null, "windows root");
                string solution = Path.Combine(root, "HotspotShade.WinUI2.sln");
                string project = Path.Combine(
                    root,
                    "src",
                    "HotspotShade.WinUI2.Broker",
                    "HotspotShade.WinUI2.Broker.csproj");
                AssertEx.True(File.Exists(solution), "solution");
                AssertEx.True(File.Exists(project), "broker project");
                AssertEx.Contains(SourceText.Read(solution), "HotspotShade.WinUI2.Broker.csproj", "solution entry");
                string text = SourceText.Read(project);
                AssertEx.Contains(text, "net8.0-windows", "Windows target");
                AssertEx.Contains(text, "x64", "x64 target");
                AssertEx.Contains(text, "HotspotShade.WinUI2.Core.csproj", "core reference");
                AssertEx.DoesNotContain(text, "UseWPF>true", "no WPF");
            });
        }

        private static BrokerStack NewStack()
        {
            FakeLocalClient local = new FakeLocalClient();
            EngineLocalBroker broker = new EngineLocalBroker(
                local,
                Instance,
                TimeSpan.FromMilliseconds(500));
            EngineBoundary boundary = new EngineBoundary(
                broker,
                new FakeEngineClock(),
                TimeSpan.FromMilliseconds(500));
            FakeEngineHost host = new FakeEngineHost();
            EngineStartup startup = new EngineStartup(
                host,
                boundary,
                TimeSpan.FromMilliseconds(500),
                TimeSpan.FromMilliseconds(500));
            EngineLaunchPlan plan;
            EngineLaunchFailure failure;
            AssertEx.True(
                EngineLaunchPlan.TryCreateTrusted(
                    EnginePath,
                    TrustedRoot,
                    8787,
                    100,
                    200,
                    out plan,
                    out failure),
                "test plan: " + failure);
            EngineBrokerService service = new EngineBrokerService(
                startup,
                plan,
                TimeSpan.FromMilliseconds(500));
            return new BrokerStack
            {
                Local = local,
                Broker = broker,
                Boundary = boundary,
                Host = host,
                Startup = startup,
                Service = service
            };
        }

        private static Dictionary<string, string> Fields(string operation, string session, bool ping)
        {
            Dictionary<string, string> fields = new Dictionary<string, string>(StringComparer.Ordinal);
            fields[EngineProtocol.Keys.Version] = EngineProtocol.Version.ToString(CultureInfo.InvariantCulture);
            fields[EngineProtocol.Keys.Operation] = operation;
            fields[EngineProtocol.Keys.Session] = session;
            if (operation == EngineProtocol.Operations.Start)
            {
                fields[EngineProtocol.Keys.Ping] = ping ? "1" : "0";
            }
            return fields;
        }

        private static Dictionary<string, string> Fields(string operation, string session)
        {
            return Fields(operation, session, false);
        }

        private static string Join(IEnumerable<string> values)
        {
            System.Text.StringBuilder text = new System.Text.StringBuilder();
            foreach (string value in values)
            {
                if (value != null)
                {
                    text.Append(value);
                    text.Append(' ');
                }
            }
            return text.ToString();
        }

        private static string ReadBrokerSource(string root, string name)
        {
            return SourceText.Read(Path.Combine(root, "src", "HotspotShade.WinUI2.Broker", name));
        }

        private static string FindWindowsRoot()
        {
            DirectoryInfo directory = new DirectoryInfo(AppContext.BaseDirectory);
            while (directory != null)
            {
                string candidate = Path.Combine(directory.FullName, "windows");
                if (Directory.Exists(candidate) && File.Exists(Path.Combine(candidate, "README.md")))
                {
                    return candidate;
                }
                directory = directory.Parent;
            }
            return null;
        }

        private static T Wait<T>(Task<T> task)
        {
            return task.GetAwaiter().GetResult();
        }

        private sealed class BrokerStack
        {
            public FakeLocalClient Local;
            public EngineLocalBroker Broker;
            public EngineBoundary Boundary;
            public FakeEngineHost Host;
            public EngineStartup Startup;
            public EngineBrokerService Service;
        }

        private sealed class FakeEngineClock : IEngineClock
        {
            public FakeEngineClock()
            {
                Now = new DateTimeOffset(2026, 11, 5, 9, 0, 0, TimeSpan.Zero);
            }

            public DateTimeOffset Now { get; set; }
        }

        // One local client fake. It never opens an endpoint and records every
        // start and stop request.
        private sealed class FakeLocalClient : IEngineLocalClient
        {
            public FakeLocalClient()
            {
                Status = EngineLocalStatus.Status(
                    true,
                    false,
                    false,
                    false,
                    false,
                    false,
                    true,
                    0,
                    EngineStopReason.None);
            }

            public EngineLocalStatus Status;
            public EngineLocalResult StartResult = EngineLocalResult.Success();
            public EngineLocalResult StopResult = EngineLocalResult.Success();
            public int StartCalls;
            public int StopCalls;
            public int Reads;
            public bool Closed;

            public Task<EngineLocalStatus> ReadStatusAsync(CancellationToken cancellationToken)
            {
                Reads++;
                return Task.FromResult(Status);
            }

            public Task<EngineLocalResult> StartAsync(bool ping, CancellationToken cancellationToken)
            {
                StartCalls++;
                return Task.FromResult(StartResult);
            }

            public Task<EngineLocalResult> StopAsync(CancellationToken cancellationToken)
            {
                StopCalls++;
                return Task.FromResult(StopResult);
            }

            public Task CloseAsync()
            {
                Closed = true;
                return Task.CompletedTask;
            }
        }

        // One host fake. It records the secret bytes a real launcher would
        // write to the bearer pipe, and it never creates a pipe or a process.
        private sealed class FakeEngineHost : IEngineHost
        {
            public EngineLaunchOutcome Outcome = EngineLaunchOutcome.Success();
            public int Launches;
            public int Closes;
            public EngineLaunchRequest LastRequest;
            public string SecretText = "";

            public Task<EngineLaunchOutcome> LaunchAsync(
                EngineLaunchRequest request,
                CancellationToken cancellationToken)
            {
                Launches++;
                LastRequest = request;
                MemoryStream stream = new MemoryStream();
                request.Secret.WriteTo(stream);
                byte[] written = stream.ToArray();
                SecretText = System.Text.Encoding.ASCII.GetString(
                    written,
                    0,
                    EngineLaunchRules.SecretHexLength);
                return Task.FromResult(Outcome);
            }

            public Task<bool> CloseAsync(TimeSpan grace)
            {
                Closes++;
                return Task.FromResult(true);
            }
        }
    }
}
