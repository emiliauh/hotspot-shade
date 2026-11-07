using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using HotspotShade.WinUI2.Core.Engine;

namespace HotspotShade.WinUI2.Core.Tests
{
    // Hermetic checks for the engine launch contract and the startup and stop
    // lifecycle. They create no pipe, no adapter, and no tunnel. Every seam is
    // a fake, so a check never starts the Rust engine.
    internal static class EngineTests
    {
        private const string TrustedRoot = "C:\\Program Files\\HotspotShade";
        private const string EnginePath = TrustedRoot + "\\hotspotshade.exe";

        public static void Run(TestRunner runner)
        {
            runner.Check("engine launch: a generated secret is hex and one newline", delegate
            {
                using (EngineLaunchSecret secret = EngineLaunchSecret.CreateRandom())
                {
                    MemoryStream stream = new MemoryStream();
                    secret.WriteTo(stream);
                    byte[] written = stream.ToArray();
                    AssertEx.Equal(EngineLaunchRules.SecretWriteLength, written.Length, "written length");
                    AssertEx.Equal((byte)'\n', written[EngineLaunchRules.SecretHexLength], "terminator");
                    for (int index = 0; index < EngineLaunchRules.SecretHexLength; index++)
                    {
                        bool digit = written[index] >= '0' && written[index] <= '9';
                        bool lower = written[index] >= 'a' && written[index] <= 'f';
                        AssertEx.True(digit || lower, "lowercase hex at " + index);
                    }
                    string text = SecretText(secret);
                    AssertEx.True(secret.AppearsIn("keep " + text + " out"), "the secret is found in text");
                    AssertEx.False(secret.AppearsIn("nothing private here"), "an empty secret search is false");
                }
            });

            runner.Check("engine launch: a cleared secret is unreadable and never printed", delegate
            {
                EngineLaunchSecret secret = EngineLaunchSecret.CreateRandom();
                string text = SecretText(secret);
                AssertEx.DoesNotContain(secret.ToString(), text, "ToString must not hold the value");
                secret.Clear();
                AssertEx.True(secret.IsCleared, "cleared");
                AssertEx.False(secret.AppearsIn(text), "a cleared secret is not found");
                bool threw = false;
                try
                {
                    secret.WriteTo(new MemoryStream());
                }
                catch (InvalidOperationException)
                {
                    threw = true;
                }
                AssertEx.True(threw, "a cleared secret cannot be written");
            });

            runner.Check("engine launch: only 64 lowercase hex characters parse", delegate
            {
                EngineLaunchSecret secret;
                AssertEx.True(EngineLaunchSecret.TryParse(new string('a', 64), out secret), "a full value parses");
                secret.Clear();
                AssertEx.False(EngineLaunchSecret.TryParse(new string('A', 64), out secret), "uppercase is refused");
                AssertEx.False(EngineLaunchSecret.TryParse(new string('a', 63), out secret), "a short value is refused");
                AssertEx.False(EngineLaunchSecret.TryParse(new string('a', 65), out secret), "a long value is refused");
                AssertEx.False(EngineLaunchSecret.TryParse("z" + new string('a', 63), out secret), "a non-hex character is refused");
                AssertEx.False(EngineLaunchSecret.TryParse(null, out secret), "null is refused");
            });

            runner.Check("engine launch: the plan carries a fixed argument list", delegate
            {
                EngineLaunchPlan plan = NewPlan();
                IReadOnlyList<string> arguments = plan.Arguments;
                AssertEx.Equal(8, arguments.Count, "argument count");
                AssertEx.Equal("gui", arguments[0], "mode");
                AssertEx.Equal("--no-open", arguments[1], "no browser");
                AssertEx.Equal("--port", arguments[2], "port switch");
                AssertEx.Equal("8787", arguments[3], "port");
                AssertEx.Equal("--token-fd", arguments[4], "bearer switch");
                AssertEx.Equal("100", arguments[5], "bearer handle");
                AssertEx.Equal("--parent-fd", arguments[6], "parent switch");
                AssertEx.Equal("200", arguments[7], "parent handle");
                AssertEx.Equal(100L, plan.BearerHandle, "bearer handle value");
                AssertEx.Equal(200L, plan.ParentHandle, "parent handle value");
                for (int index = 0; index < arguments.Count; index++)
                {
                    AssertEx.False(arguments[index] == "--demo", "a real launch must not carry the demo switch");
                }
                AssertEx.DoesNotContain(plan.Describe(), EnginePath, "the report holds no path");
                bool threw = false;
                try
                {
                    ((IList<string>)arguments).Add("--demo");
                }
                catch (NotSupportedException)
                {
                    threw = true;
                }
                AssertEx.True(threw, "the argument list is read only");
            });

            runner.Check("engine launch: the plan refuses a bad path or port", delegate
            {
                EngineLaunchPlan plan;
                EngineLaunchFailure failure;
                AssertEx.False(
                    EngineLaunchPlan.TryCreate("hotspotshade.exe", 8787, 100, 200, out plan, out failure),
                    "a relative path is refused");
                AssertEx.Equal(EngineLaunchFailure.PathInvalid, failure, "path reason");
                AssertEx.False(
                    EngineLaunchPlan.TryCreate("C:\\Apps\\engine.exe", 8787, 100, 200, out plan, out failure),
                    "the wrong file name is refused");
                AssertEx.Equal(EngineLaunchFailure.PathInvalid, failure, "name reason");
                AssertEx.False(
                    EngineLaunchPlan.TryCreate("C:\\Apps\\..\\hotspotshade.exe", 8787, 100, 200, out plan, out failure),
                    "a traversal segment is refused");
                AssertEx.Equal(EngineLaunchFailure.PathInvalid, failure, "traversal reason");
                AssertEx.False(
                    EngineLaunchPlan.TryCreate(EnginePath, 0, 100, 200, out plan, out failure),
                    "port 0 is refused");
                AssertEx.Equal(EngineLaunchFailure.PortInvalid, failure, "port zero reason");
                AssertEx.False(
                    EngineLaunchPlan.TryCreate(EnginePath, 80, 100, 200, out plan, out failure),
                    "a reserved port is refused");
                AssertEx.False(
                    EngineLaunchPlan.TryCreate(EnginePath, 65536, 100, 200, out plan, out failure),
                    "a port above the byte range is refused");
                AssertEx.True(
                    EngineLaunchPlan.TryCreate(EnginePath, 8787, 100, 200, out plan, out failure),
                    "a valid plan is accepted");
                AssertEx.Equal(EngineLaunchFailure.None, failure, "no failure");
                AssertEx.True(plan != null, "plan");
            });

            runner.Check("engine launch: the plan refuses an engine outside the install folder", delegate
            {
                EngineLaunchPlan plan;
                EngineLaunchFailure failure;
                AssertEx.True(
                    EngineLaunchPlan.TryCreateTrusted(EnginePath, TrustedRoot, 8787, 100, 200, out plan, out failure),
                    "the install folder is accepted");
                AssertEx.False(
                    EngineLaunchPlan.TryCreateTrusted(
                        "C:\\Program Files\\HotspotShadeEvil\\hotspotshade.exe",
                        TrustedRoot,
                        8787,
                        100,
                        200,
                        out plan,
                        out failure),
                    "a shared prefix is not inside the folder");
                AssertEx.Equal(EngineLaunchFailure.PathNotTrusted, failure, "shared prefix reason");
                AssertEx.False(
                    EngineLaunchPlan.TryCreateTrusted(
                        "C:\\Users\\someone\\hotspotshade.exe",
                        TrustedRoot,
                        8787,
                        100,
                        200,
                        out plan,
                        out failure),
                    "a user folder is refused");
                AssertEx.Equal(EngineLaunchFailure.PathNotTrusted, failure, "user folder reason");
                AssertEx.False(
                    EngineLaunchPlan.TryCreateTrusted(EnginePath, "HotspotShade", 8787, 100, 200, out plan, out failure),
                    "a relative root is refused");
                AssertEx.Equal(EngineLaunchFailure.PathNotTrusted, failure, "relative root reason");
            });

            runner.Check("engine launch: the plan needs two separate handle values", delegate
            {
                EngineLaunchPlan plan;
                EngineLaunchFailure failure;
                AssertEx.False(
                    EngineLaunchPlan.TryCreate(EnginePath, 8787, 0, 200, out plan, out failure),
                    "handle zero is refused");
                AssertEx.Equal(EngineLaunchFailure.HandleInvalid, failure, "zero reason");
                AssertEx.False(
                    EngineLaunchPlan.TryCreate(EnginePath, 8787, 100, -1, out plan, out failure),
                    "a negative handle is refused");
                AssertEx.False(
                    EngineLaunchPlan.TryCreate(EnginePath, 8787, 100, 100, out plan, out failure),
                    "one handle for both channels is refused");
                AssertEx.Equal(EngineLaunchFailure.HandleInvalid, failure, "shared handle reason");
            });

            runner.Check("engine launch: a request refuses a secret in its own plan", delegate
            {
                EngineLaunchSecret secret = EngineLaunchSecret.CreateRandom();
                string text = SecretText(secret);
                EngineLaunchPlan plan;
                EngineLaunchFailure failure;
                AssertEx.True(
                    EngineLaunchPlan.TryCreateTrusted(
                        TrustedRoot + "\\" + text + "\\hotspotshade.exe",
                        TrustedRoot,
                        8787,
                        100,
                        200,
                        out plan,
                        out failure),
                    "the path is well formed");
                AssertEx.True(plan.DisclosesSecret(secret), "the secret is found in the path");
                bool threw = false;
                try
                {
                    new EngineLaunchRequest(plan, secret);
                }
                catch (ArgumentException)
                {
                    threw = true;
                }
                AssertEx.True(threw, "the request refuses a plan that discloses the secret");
                EngineLaunchRequest request = new EngineLaunchRequest(NewPlan(), secret);
                AssertEx.False(request.Plan.DisclosesSecret(secret), "a real plan discloses nothing");
                secret.Clear();
                bool cleared = false;
                try
                {
                    new EngineLaunchRequest(NewPlan(), secret);
                }
                catch (ArgumentException)
                {
                    cleared = true;
                }
                AssertEx.True(cleared, "a cleared secret cannot make a request");
            });

            runner.Check("engine wire: a reply refuses unknown, credential, and mismatched fields", delegate
            {
                EngineReply reply;
                string code;

                Dictionary<string, string> unknown = new Dictionary<string, string>
                {
                    { EngineProtocol.Keys.Version, "1" },
                    { EngineProtocol.Keys.Ok, "1" },
                    { "surprise", "value" }
                };
                AssertEx.False(EngineWire.TryReadReply(unknown, out reply, out code), "unknown field");
                AssertEx.Equal(EngineProtocol.ErrorCodes.BadResponse, code, "unknown field code");

                Dictionary<string, string> credential = new Dictionary<string, string>
                {
                    { EngineProtocol.Keys.Version, "1" },
                    { EngineProtocol.Keys.Ok, "1" },
                    { "source_device_token", "abcd" }
                };
                AssertEx.False(EngineWire.TryReadReply(credential, out reply, out code), "credential field");
                AssertEx.Equal(EngineProtocol.ErrorCodes.Forbidden, code, "credential field code");

                Dictionary<string, string> stale = new Dictionary<string, string>
                {
                    { EngineProtocol.Keys.Version, "2" },
                    { EngineProtocol.Keys.Ok, "1" }
                };
                AssertEx.False(EngineWire.TryReadReply(stale, out reply, out code), "stale version");
                AssertEx.Equal(EngineProtocol.ErrorCodes.BadVersion, code, "stale version code");

                Dictionary<string, string> codedSuccess = new Dictionary<string, string>
                {
                    { EngineProtocol.Keys.Version, "1" },
                    { EngineProtocol.Keys.Ok, "1" },
                    { EngineProtocol.Keys.Code, EngineProtocol.ErrorCodes.Internal }
                };
                AssertEx.False(EngineWire.TryReadReply(codedSuccess, out reply, out code), "success with a code");
                AssertEx.Equal(EngineProtocol.ErrorCodes.BadResponse, code, "success with a code");
            });

            runner.Check("engine wire: a request refuses a bad version, operation, session, or ping", delegate
            {
                EngineRequest request;
                string code;

                Dictionary<string, string> stale = new Dictionary<string, string>
                {
                    { EngineProtocol.Keys.Version, "2" },
                    { EngineProtocol.Keys.Operation, EngineProtocol.Operations.Status },
                    { EngineProtocol.Keys.Session, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
                };
                AssertEx.False(EngineWire.TryReadRequest(stale, out request, out code), "stale version");
                AssertEx.Equal(EngineProtocol.ErrorCodes.BadVersion, code, "stale version code");

                Dictionary<string, string> unknown = new Dictionary<string, string>
                {
                    { EngineProtocol.Keys.Version, "1" },
                    { EngineProtocol.Keys.Operation, "tunnel.everything" },
                    { EngineProtocol.Keys.Session, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
                };
                AssertEx.False(EngineWire.TryReadRequest(unknown, out request, out code), "unknown operation");
                AssertEx.Equal(EngineProtocol.ErrorCodes.BadOperation, code, "unknown operation code");

                Dictionary<string, string> session = new Dictionary<string, string>
                {
                    { EngineProtocol.Keys.Version, "1" },
                    { EngineProtocol.Keys.Operation, EngineProtocol.Operations.Status },
                    { EngineProtocol.Keys.Session, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }
                };
                AssertEx.False(EngineWire.TryReadRequest(session, out request, out code), "uppercase session");
                AssertEx.Equal(EngineProtocol.ErrorCodes.BadRequest, code, "uppercase session code");

                Dictionary<string, string> ping = new Dictionary<string, string>
                {
                    { EngineProtocol.Keys.Version, "1" },
                    { EngineProtocol.Keys.Operation, EngineProtocol.Operations.Status },
                    { EngineProtocol.Keys.Session, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
                    { EngineProtocol.Keys.Ping, "1" }
                };
                AssertEx.False(EngineWire.TryReadRequest(ping, out request, out code), "ping on status");
                AssertEx.Equal(EngineProtocol.ErrorCodes.BadRequest, code, "ping on status code");
            });

            runner.Check("engine startup: nothing starts until a person asks", delegate
            {
                FakeBroker broker = new FakeBroker();
                FakeEngineHost host = new FakeEngineHost();
                EngineStartup startup = NewStartup(broker, host);
                AssertEx.Equal(EngineStartupState.Idle, startup.State, "initial state");
                AssertEx.Equal(0, host.Launches, "no launch");
                AssertEx.Equal(0, broker.Count(EngineProtocol.Operations.Start), "no start");
                AssertEx.Contains(startup.StatusText, "not started", "idle text");
            });

            runner.Check("engine startup: the first connect launches once", delegate
            {
                FakeBroker broker = new FakeBroker();
                FakeEngineHost host = new FakeEngineHost();
                EngineBoundary boundary = NewBoundary(broker);
                EngineStartup startup = new EngineStartup(
                    host,
                    boundary,
                    TimeSpan.FromMilliseconds(500),
                    TimeSpan.FromMilliseconds(500));
                EngineLaunchPlan plan = NewPlan();

                EngineCommandResult result = Wait(startup.EnsureStartedAsync(plan));

                AssertEx.True(result.Ok, "connect result");
                AssertEx.Equal(EngineStartupState.Connected, startup.State, "state");
                AssertEx.Equal(1, host.Launches, "one launch");
                AssertEx.True(host.LastRequest.Plan == plan, "the plan travels unchanged");
                AssertEx.True(host.LastRequest.Secret.IsCleared, "the app keeps no secret after the launch");
                AssertEx.Equal(EngineLaunchRules.SecretWriteLength, host.Written.Length, "the secret was written once");
                AssertEx.Equal(0, broker.Count(EngineProtocol.Operations.Start), "connecting starts no tunnel");
                AssertEx.True(broker.Operations.Contains(EngineProtocol.Operations.Hello), "hello was sent");
                AssertEx.Equal(0, host.Closes, "no close on the happy path");
                AssertEx.False(boundary.Session.CanClaimRunning, "no on claim");
                AssertEx.True(boundary.Content.IsEngineAvailable, "the engine is available");
            });

            runner.Check("engine startup: a second connect is not a second launch", delegate
            {
                FakeBroker broker = new FakeBroker();
                FakeEngineHost host = new FakeEngineHost();
                EngineStartup startup = NewStartup(broker, host);
                EngineLaunchPlan plan = NewPlan();
                Wait(startup.EnsureStartedAsync(plan));
                Wait(startup.EnsureStartedAsync(plan));
                AssertEx.Equal(1, host.Launches, "one launch for two connects");
                AssertEx.Equal(EngineStartupState.Connected, startup.State, "state");
            });

            runner.Check("engine startup: a second plan needs an app restart", delegate
            {
                FakeBroker broker = new FakeBroker();
                FakeEngineHost host = new FakeEngineHost();
                EngineStartup startup = NewStartup(broker, host);
                Wait(startup.EnsureStartedAsync(NewPlan()));

                EngineCommandResult result = Wait(startup.EnsureStartedAsync(NewPlanWithPort(9999)));

                AssertEx.False(result.Ok, "the plan change is refused");
                AssertEx.Equal(EngineProtocol.ErrorCodes.AlreadyRunning, result.Code, "code");
                AssertEx.Contains(result.Message, "Restart the app", "text");
                AssertEx.Equal(1, host.Launches, "no second launch");
                AssertEx.Equal(EngineStartupState.Connected, startup.State, "state");
            });

            runner.Check("engine startup: a start waits for a confirming status", delegate
            {
                FakeBroker broker = new FakeBroker();
                FakeEngineHost host = new FakeEngineHost();
                EngineBoundary boundary = NewBoundary(broker);
                EngineStartup startup = NewStartup(boundary, host);
                EngineLaunchPlan plan = NewPlan();

                EngineCommandResult started = Wait(startup.StartTunnelAsync(plan, true));

                AssertEx.True(started.Ok, "the engine accepted the start");
                AssertEx.False(started.Confirmed, "the app does not confirm from the request alone");
                AssertEx.Equal(1, host.Launches, "one launch");
                AssertEx.Equal(1, broker.Count(EngineProtocol.Operations.Start), "one start request");
                AssertEx.False(boundary.Session.CanClaimRunning, "the request alone is not an on state");
                AssertEx.Equal(EngineBoundaryKind.Checking, boundary.Content.Kind, "the page waits for a status");
                AssertEx.True(boundary.Content.IsBusy, "the start is pending");

                broker.Running = true;
                broker.Connections = 3;
                EngineCommandResult polled = Wait(boundary.PollAsync());

                AssertEx.True(polled.Ok, "the status was read");
                AssertEx.True(boundary.Session.CanClaimRunning, "a fresh status confirms the tunnel");
                AssertEx.Equal("On", boundary.Content.StatusText, "status text");
            });

            runner.Check("engine startup: an unpaired engine refuses the start", delegate
            {
                FakeBroker broker = new FakeBroker();
                broker.Paired = false;
                broker.SourcePresent = false;
                broker.Trusted = false;
                FakeEngineHost host = new FakeEngineHost();
                EngineStartup startup = NewStartup(broker, host);
                EngineLaunchPlan plan = NewPlan();
                Wait(startup.EnsureStartedAsync(plan));

                EngineCommandResult started = Wait(startup.StartTunnelAsync(plan, false));

                AssertEx.False(started.Ok, "the start is refused");
                AssertEx.Equal(EngineProtocol.ErrorCodes.NotPaired, started.Code, "code");
                AssertEx.Equal(0, broker.Count(EngineProtocol.Operations.Start), "no start request");
            });

            runner.Check("engine startup: a failed launch is not retried", delegate
            {
                FakeBroker broker = new FakeBroker();
                FakeEngineHost host = new FakeEngineHost();
                host.Outcome = EngineLaunchOutcome.Failed(EngineLaunchFailure.BrokerMissing);
                EngineStartup startup = NewStartup(broker, host);
                EngineLaunchPlan plan = NewPlan();

                EngineCommandResult result = Wait(startup.EnsureStartedAsync(plan));

                AssertEx.False(result.Ok, "the connect failed");
                AssertEx.Equal(EngineProtocol.ErrorCodes.HelperMissing, result.Code, "code");
                AssertEx.Contains(result.Message, "not installed", "text");
                AssertEx.Equal(1, host.Launches, "one launch attempt");
                AssertEx.Equal(1, host.Closes, "the failed launch cleaned up");
                AssertEx.Equal(EngineStartupState.Failed, startup.State, "state");
                AssertEx.Equal(EngineLaunchFailure.BrokerMissing, startup.LastLaunchFailure, "reason");

                EngineCommandResult again = Wait(startup.StartTunnelAsync(plan, false));

                AssertEx.False(again.Ok, "a later start fails closed");
                AssertEx.Equal(1, host.Launches, "no second launch");
                AssertEx.Equal(0, broker.Count(EngineProtocol.Operations.Start), "no start request");
                AssertEx.Equal(1, host.Closes, "cleanup did not run twice");
            });

            runner.Check("engine startup: a launch timeout is bounded and cleaned up", delegate
            {
                FakeBroker broker = new FakeBroker();
                FakeEngineHost host = new FakeEngineHost();
                host.HangLaunch = true;
                EngineStartup startup = new EngineStartup(
                    host,
                    NewBoundary(broker),
                    TimeSpan.FromMilliseconds(100),
                    TimeSpan.FromMilliseconds(100));

                EngineCommandResult result = Wait(startup.EnsureStartedAsync(NewPlan()));

                AssertEx.False(result.Ok, "the launch timed out");
                AssertEx.Equal(EngineLaunchFailure.LaunchTimeout, startup.LastLaunchFailure, "reason");
                AssertEx.Equal(1, host.Launches, "one launch attempt");
                AssertEx.Equal(1, host.Closes, "the half-started host was closed");
                AssertEx.Equal(EngineStartupState.Failed, startup.State, "state");
            });

            runner.Check("engine startup: an unreachable engine fails closed", delegate
            {
                FakeBroker broker = new FakeBroker();
                broker.FailureCode = EngineProtocol.ErrorCodes.EngineUnavailable;
                FakeEngineHost host = new FakeEngineHost();
                EngineBoundary boundary = NewBoundary(broker);
                EngineStartup startup = NewStartup(boundary, host);

                EngineCommandResult result = Wait(startup.EnsureStartedAsync(NewPlan()));

                AssertEx.False(result.Ok, "the connect failed");
                AssertEx.Equal(EngineLaunchFailure.ConnectFailed, startup.LastLaunchFailure, "reason");
                AssertEx.Equal(1, host.Closes, "the host was closed");
                AssertEx.Equal(EngineConnectionState.Unavailable, boundary.Session.Connection, "connection state");
                AssertEx.Equal(EngineStartupState.Failed, startup.State, "state");
                AssertEx.False(boundary.Session.CanClaimRunning, "no on claim");
            });

            runner.Check("engine startup: an administrator requirement never elevates", delegate
            {
                FakeBroker broker = new FakeBroker();
                FakeEngineHost host = new FakeEngineHost();
                host.Outcome = EngineLaunchOutcome.Failed(EngineLaunchFailure.AdminRequired);
                EngineStartup startup = NewStartup(broker, host);

                EngineCommandResult result = Wait(startup.EnsureStartedAsync(NewPlan()));

                AssertEx.False(result.Ok, "the launch failed closed");
                AssertEx.Contains(result.Message, "does not elevate", "text");
                AssertEx.Equal(EngineLaunchFailure.AdminRequired, startup.LastLaunchFailure, "reason");
                AssertEx.Equal(1, host.Launches, "the app did not try a second path");
                AssertEx.Equal(1, host.Closes, "cleanup ran");
                MethodInfo[] methods = typeof(IEngineHost).GetMethods();
                AssertEx.Equal(2, methods.Length, "the host seam has only a launch call and a close call");
                for (int index = 0; index < methods.Length; index++)
                {
                    AssertEx.False(
                        methods[index].Name.IndexOf("elevat", StringComparison.OrdinalIgnoreCase) >= 0,
                        "the seam cannot ask for elevation");
                }
            });

            runner.Check("engine startup: shutdown asks the engine and runs once", delegate
            {
                FakeBroker broker = new FakeBroker();
                FakeEngineHost host = new FakeEngineHost();
                EngineStartup startup = NewStartup(broker, host);
                Wait(startup.EnsureStartedAsync(NewPlan()));

                EngineCommandResult result = Wait(startup.ShutdownAsync());

                AssertEx.True(result.Ok, "the shutdown was sent");
                AssertEx.Equal(1, broker.Count(EngineProtocol.Operations.Shutdown), "one shutdown request");
                AssertEx.Equal(1, host.Closes, "the host was closed once");
                AssertEx.True(broker.Closed, "the session closed its transport");
                AssertEx.Equal(EngineStartupState.Closed, startup.State, "state");
                AssertEx.Equal(EngineHostCloseState.Exited, startup.LastHostCloseState, "close state");

                EngineCommandResult second = Wait(startup.ShutdownAsync());

                AssertEx.False(second.Ok, "a second shutdown is refused");
                AssertEx.Equal(EngineProtocol.ErrorCodes.Closed, second.Code, "code");
                AssertEx.Equal(1, host.Closes, "no second close");
            });

            runner.Check("engine startup: a refused shutdown still stops on the host exit", delegate
            {
                FakeBroker broker = new FakeBroker();
                broker.RefuseShutdown = true;
                FakeEngineHost host = new FakeEngineHost();
                EngineStartup startup = NewStartup(broker, host);
                Wait(startup.EnsureStartedAsync(NewPlan()));

                EngineCommandResult result = Wait(startup.ShutdownAsync());

                AssertEx.True(result.Ok, "the observed engine exit is the stop signal");
                AssertEx.Contains(result.Message, "The engine stopped", "text");
                AssertEx.Equal(1, broker.Count(EngineProtocol.Operations.Shutdown), "the request was still sent");
                AssertEx.Equal(1, host.Closes, "the host was closed");
                AssertEx.Equal(EngineHostCloseState.Exited, startup.LastHostCloseState, "close state");
            });

            runner.Check("engine startup: a slow stop asks a person to check", delegate
            {
                FakeBroker broker = new FakeBroker();
                FakeEngineHost host = new FakeEngineHost();
                host.HangClose = true;
                EngineStartup startup = new EngineStartup(
                    host,
                    NewBoundary(broker),
                    TimeSpan.FromMilliseconds(500),
                    TimeSpan.FromMilliseconds(100));
                Wait(startup.EnsureStartedAsync(NewPlan()));

                EngineCommandResult result = Wait(startup.ShutdownAsync());

                AssertEx.False(result.Ok, "the stop did not finish");
                AssertEx.Equal(EngineHostCloseState.TimedOut, startup.LastHostCloseState, "close state");
                AssertEx.Contains(result.Message, "Check the tunnel adapter and routes", "text");
                AssertEx.Equal(1, broker.Count(EngineProtocol.Operations.Shutdown), "the engine was still asked");
                AssertEx.Equal(1, host.Closes, "one close attempt");
                AssertEx.Equal(EngineStartupState.Closed, startup.State, "state");
            });

            runner.Check("engine startup: a lost host never claims the tunnel is off", delegate
            {
                FakeBroker broker = new FakeBroker();
                FakeEngineHost host = new FakeEngineHost();
                EngineBoundary boundary = NewBoundary(broker);
                EngineStartup startup = NewStartup(boundary, host);
                EngineLaunchPlan plan = NewPlan();
                Wait(startup.EnsureStartedAsync(plan));
                broker.Running = true;
                Wait(boundary.PollAsync());
                AssertEx.True(boundary.Session.CanClaimRunning, "the tunnel was on before the loss");

                EngineCommandResult lost = startup.HostLost();

                AssertEx.False(lost.Ok, "the loss is a failure");
                AssertEx.Contains(lost.Message, "unknown", "the text does not claim an off state");
                AssertEx.Equal(EngineStartupState.Failed, startup.State, "state");
                AssertEx.True(boundary.Session.IsClosed, "the session is closed");
                AssertEx.False(boundary.Session.CanClaimRunning, "no on claim");
                AssertEx.False(boundary.Content.StatusText == "Off", "the app does not claim the tunnel is off");

                EngineCommandResult again = Wait(startup.EnsureStartedAsync(plan));

                AssertEx.False(again.Ok, "a reconnect needs a person");
                AssertEx.Equal(1, host.Launches, "no relaunch after a loss");
            });

            runner.Check("engine startup: a retry is explicit and starts once", delegate
            {
                FakeBroker broker = new FakeBroker();
                FakeEngineHost host = new FakeEngineHost();
                host.Outcome = EngineLaunchOutcome.Failed(EngineLaunchFailure.BrokerRefused);
                EngineStartup startup = NewStartup(broker, host);
                EngineLaunchPlan plan = NewPlan();
                Wait(startup.EnsureStartedAsync(plan));
                AssertEx.Equal(EngineStartupState.Failed, startup.State, "first attempt failed");

                host.Outcome = EngineLaunchOutcome.Success();
                EngineCommandResult retried = Wait(startup.RetryAsync(plan));

                AssertEx.True(retried.Ok, "the person's retry connected");
                AssertEx.Equal(2, host.Launches, "one launch per explicit attempt");
                AssertEx.Equal(EngineStartupState.Connected, startup.State, "state");
                AssertEx.Equal(0, broker.Count(EngineProtocol.Operations.Start), "a retry starts no tunnel");
            });

            runner.Check("engine startup: a start without a plan fails closed", delegate
            {
                FakeBroker broker = new FakeBroker();
                FakeEngineHost host = new FakeEngineHost();
                EngineStartup startup = NewStartup(broker, host);

                EngineCommandResult result = Wait(startup.StartTunnelAsync(null, false));

                AssertEx.False(result.Ok, "no plan means no start");
                AssertEx.Equal(EngineProtocol.ErrorCodes.Internal, result.Code, "code");
                AssertEx.Contains(result.Message, "no engine launcher", "text");
                AssertEx.Equal(0, host.Launches, "no launch");
            });

            runner.Check("engine startup: diagnostics carry no secret and no path", delegate
            {
                FakeBroker broker = new FakeBroker();
                FakeEngineHost host = new FakeEngineHost();
                EngineStartup startup = NewStartup(broker, host);
                Wait(startup.EnsureStartedAsync(NewPlan()));

                string report = startup.DescribeForDiagnostics();

                AssertEx.Contains(report, "Engine startup: connected", "report");
                AssertEx.Contains(report, "Launch: none", "launch word");
                AssertEx.DoesNotContain(report, host.WrittenText, "the secret is not in the report");
                AssertEx.DoesNotContain(report, EnginePath, "the path is not in the report");
                AssertEx.DoesNotContain(report, "8787", "the port is not in the report");
                AssertEx.DoesNotContain(report, "100", "a handle value is not in the report");
            });
        }

        private static EngineStartup NewStartup(FakeBroker broker, FakeEngineHost host)
        {
            return NewStartup(NewBoundary(broker), host);
        }

        private static EngineStartup NewStartup(EngineBoundary boundary, FakeEngineHost host)
        {
            return new EngineStartup(
                host,
                boundary,
                TimeSpan.FromMilliseconds(500),
                TimeSpan.FromMilliseconds(500));
        }

        private static EngineBoundary NewBoundary(FakeBroker broker)
        {
            return new EngineBoundary(broker, new FakeEngineClock(), TimeSpan.FromMilliseconds(500));
        }

        private static EngineLaunchPlan NewPlan()
        {
            return NewPlanWithPort(8787);
        }

        private static EngineLaunchPlan NewPlanWithPort(int port)
        {
            EngineLaunchPlan plan;
            EngineLaunchFailure failure;
            AssertEx.True(
                EngineLaunchPlan.TryCreateTrusted(EnginePath, TrustedRoot, port, 100, 200, out plan, out failure),
                "the test plan is valid: " + failure);
            return plan;
        }

        private static string SecretText(EngineLaunchSecret secret)
        {
            MemoryStream stream = new MemoryStream();
            secret.WriteTo(stream);
            byte[] written = stream.ToArray();
            return Encoding.ASCII.GetString(written, 0, EngineLaunchRules.SecretHexLength);
        }

        private static void Wait(Task task)
        {
            task.GetAwaiter().GetResult();
        }

        private static T Wait<T>(Task<T> task)
        {
            return task.GetAwaiter().GetResult();
        }

        private sealed class FakeEngineClock : IEngineClock
        {
            public FakeEngineClock()
            {
                Now = new DateTimeOffset(2026, 11, 5, 9, 0, 0, TimeSpan.Zero);
            }

            public DateTimeOffset Now { get; set; }
        }

        // One broker fake. It answers the version 1 operations and records the
        // order. It never opens a connection.
        private sealed class FakeBroker : IEngineBroker
        {
            public readonly List<string> Operations = new List<string>();
            public string Instance = "engine-0001";
            public string FailureCode = "";
            public bool Paired = true;
            public bool SourcePresent = true;
            public bool Trusted = true;
            public bool Running;
            public int Connections;
            public EngineStopReason Stop = EngineStopReason.None;
            public bool RefuseShutdown;
            public bool Closed;

            public int Count(string operation)
            {
                int count = 0;
                for (int index = 0; index < Operations.Count; index++)
                {
                    if (Operations[index] == operation)
                    {
                        count++;
                    }
                }
                return count;
            }

            public Task<EngineReply> SendAsync(EngineRequest request, CancellationToken cancellationToken)
            {
                Operations.Add(request.Operation);
                if (FailureCode.Length > 0)
                {
                    return Task.FromResult(EngineReply.Failure(FailureCode));
                }
                switch (request.Operation)
                {
                    case EngineProtocol.Operations.Hello:
                        return Task.FromResult(EngineReply.Success(new Dictionary<string, string>
                        {
                            { EngineProtocol.Keys.Instance, Instance },
                            { EngineProtocol.Keys.Engine, EngineWord() }
                        }));
                    case EngineProtocol.Operations.Status:
                        return Task.FromResult(EngineReply.Success(StatusFields()));
                    case EngineProtocol.Operations.Start:
                        return Task.FromResult(EngineReply.Success(null));
                    case EngineProtocol.Operations.Stop:
                        Running = false;
                        Stop = EngineStopReason.User;
                        return Task.FromResult(EngineReply.Success(null));
                    case EngineProtocol.Operations.Shutdown:
                        return Task.FromResult(RefuseShutdown
                            ? EngineReply.Failure(EngineProtocol.ErrorCodes.Unsupported)
                            : EngineReply.Success(null));
                    default:
                        return Task.FromResult(EngineReply.Failure(EngineProtocol.ErrorCodes.Unsupported));
                }
            }

            public Task CloseAsync()
            {
                Closed = true;
                return Task.CompletedTask;
            }

            private string EngineWord()
            {
                return Running ? EngineProtocol.EngineStates.Running : EngineProtocol.EngineStates.Ready;
            }

            private Dictionary<string, string> StatusFields()
            {
                return new Dictionary<string, string>
                {
                    { EngineProtocol.Keys.Instance, Instance },
                    { EngineProtocol.Keys.Engine, EngineWord() },
                    { EngineProtocol.Keys.Paired, Paired ? "1" : "0" },
                    { EngineProtocol.Keys.Running, Running ? "1" : "0" },
                    { EngineProtocol.Keys.Source, SourcePresent ? "1" : "0" },
                    { EngineProtocol.Keys.Trusted, Trusted ? "1" : "0" },
                    { EngineProtocol.Keys.Ping, Running ? "1" : "0" },
                    { EngineProtocol.Keys.Connections, (Running ? Connections : 0).ToString(CultureInfo.InvariantCulture) },
                    { EngineProtocol.Keys.Stop, EngineRules.StopWord(Stop) }
                };
            }
        }

        // One host fake. It records the secret bytes that a real launcher would
        // write to the bearer pipe, and it never creates a pipe.
        private sealed class FakeEngineHost : IEngineHost
        {
            public EngineLaunchOutcome Outcome = EngineLaunchOutcome.Success();
            public bool HangLaunch;
            public bool HangClose;
            public bool Exits = true;
            public int Launches;
            public int Closes;
            public EngineLaunchRequest LastRequest;
            public byte[] Written = new byte[0];
            public string WrittenText = "";

            public Task<EngineLaunchOutcome> LaunchAsync(
                EngineLaunchRequest request,
                CancellationToken cancellationToken)
            {
                Launches++;
                LastRequest = request;
                MemoryStream stream = new MemoryStream();
                request.Secret.WriteTo(stream);
                Written = stream.ToArray();
                WrittenText = Encoding.ASCII.GetString(Written, 0, EngineLaunchRules.SecretHexLength);
                if (HangLaunch)
                {
                    return new TaskCompletionSource<EngineLaunchOutcome>().Task;
                }
                return Task.FromResult(Outcome);
            }

            public Task<bool> CloseAsync(TimeSpan grace)
            {
                Closes++;
                if (HangClose)
                {
                    return new TaskCompletionSource<bool>().Task;
                }
                return Task.FromResult(Exits);
            }
        }
    }
}
