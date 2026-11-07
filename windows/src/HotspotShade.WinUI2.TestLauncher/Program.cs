using System;
using System.IO;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;
using HotspotShade.WinUI2.Broker;
using HotspotShade.WinUI2.Core.Engine;

namespace HotspotShade.WinUI2.TestLauncher
{
    // A console test launcher for the first real Windows test. It is not the
    // finished app. It starts the real engine with the per-launch bearer
    // secret on an inherited pipe and holds the parent-liveness pipe, then
    // sends fixed requests to the engine's loopback API. It never shells out
    // to the command line tool and never asks for elevation. Run it from an
    // elevated console only for a tunnel start.
    internal static class Program
    {
        private const int StatusTimeout = 5000;
        private const int StartTimeout = 60000;
        private const int ReadyMilliseconds = 10000;

        private static Win32EngineHost host;
        private static int enginePort;
        private static int engineProcess;
        private static int closing;

        private static int Main(string[] args)
        {
            if (args.Length == 1 && (args[0] == "--help" || args[0] == "-h"))
            {
                PrintUsage();
                return 0;
            }
            if (args.Length != 0)
            {
                PrintUsage();
                return 2;
            }

            bool elevated = IsElevated();
            string root = AppContext.BaseDirectory.TrimEnd('\\', '/');
            string enginePath = Path.Combine(root, "hotspotshade.exe");
            Console.WriteLine("HotspotShade for Windows, console release candidate.");
            Console.WriteLine("Every command talks to the real engine. Nothing here is simulated.");
            Console.WriteLine(elevated
                ? "This console is elevated. A tunnel start can change routes."
                : "This console is not elevated. Status works. A tunnel start needs an elevated console.");

            if (!LauncherRules.IsTrustedInstallDirectory(
                root,
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                elevated))
            {
                Console.WriteLine("Refused: an elevated launch must run from a folder inside Program Files,");
                Console.WriteLine("because the engine loads wintun.dll from its own folder.");
                return 3;
            }
            if (!File.Exists(enginePath))
            {
                Console.WriteLine("Refused: hotspotshade.exe is not next to the launcher.");
                return 3;
            }
            if (!File.Exists(Path.Combine(root, "wintun.dll")))
            {
                Console.WriteLine("Note: wintun.dll is not next to the engine. A tunnel start will fail until you add it.");
            }

            int launched = Launch(enginePath, root);
            if (launched != 0)
            {
                Close();
                return launched;
            }

            Console.CancelKeyPress += delegate(object sender, ConsoleCancelEventArgs e)
            {
                e.Cancel = true;
                Console.WriteLine("");
                Console.WriteLine("Stopping the engine.");
                Close();
                Environment.Exit(0);
            };

            Console.WriteLine("The engine is running. Type help for the commands.");
            PrintStatus();
            Loop();
            Close();
            return 0;
        }

        private static void PrintUsage()
        {
            Console.WriteLine("Usage: HotspotShade.WinUI2.TestLauncher.exe");
            Console.WriteLine("Put hotspotshade.exe and, for a tunnel start, wintun.dll next to the launcher.");
            Console.WriteLine("The launcher accepts no other arguments.");
        }

        private static int Launch(string enginePath, string root)
        {
            int port = EngineBrokerRules.PickPort();
            EngineLaunchPlan plan;
            EngineLaunchFailure failure;
            if (!Win32EngineHost.TryCreate(enginePath, root, port, false, out host, out plan, out failure))
            {
                Console.WriteLine("The engine launch plan failed: " + EngineLaunchText.Reason(failure));
                return 4;
            }
            EngineLaunchOutcome outcome;
            using (EngineLaunchSecret secret = EngineLaunchSecret.CreateRandom())
            {
                if (plan.DisclosesSecret(secret))
                {
                    Console.WriteLine("The engine launch plan would disclose the secret.");
                    return 4;
                }
                EngineLaunchRequest request = new EngineLaunchRequest(plan, secret);
                outcome = host.LaunchAsync(request, CancellationToken.None).GetAwaiter().GetResult();
            }
            if (!outcome.Launched)
            {
                Console.WriteLine("The engine did not start: " + EngineLaunchText.Reason(outcome.Failure));
                return 4;
            }
            int processId;
            if (!host.TryGetProcessId(out processId))
            {
                Console.WriteLine("The engine process id is unavailable.");
                return 4;
            }
            enginePort = port;
            engineProcess = processId;

            DateTime deadline = DateTime.UtcNow.AddMilliseconds(ReadyMilliseconds);
            while (DateTime.UtcNow < deadline)
            {
                int exitCode;
                if (host.HasExited(out exitCode))
                {
                    Console.WriteLine("The engine exited during startup with code " + exitCode + ".");
                    Console.WriteLine("The port can be in use, or the engine refused the launch. Start the launcher again.");
                    return 5;
                }
                ListenerOwnership ownership = ListenerTable.Check(port, processId);
                if (ownership == ListenerOwnership.Owned)
                {
                    return 0;
                }
                if (ownership == ListenerOwnership.Foreign)
                {
                    Console.WriteLine("Another process listens on the engine port. The launcher sent nothing to it.");
                    return 5;
                }
                Thread.Sleep(100);
            }
            Console.WriteLine("The engine did not open its loopback listener in time, or the listener table could not be read.");
            return 5;
        }

        private static void Loop()
        {
            while (true)
            {
                Console.Write("> ");
                string line = Console.ReadLine();
                if (line == null)
                {
                    return;
                }
                string command = line.Trim().ToLowerInvariant();
                switch (command)
                {
                    case "":
                        break;
                    case "help":
                        PrintHelp();
                        break;
                    case "status":
                        PrintStatus();
                        break;
                    case "watch":
                        Watch();
                        break;
                    case "json":
                        PrintJson("GET", "/api/status");
                        break;
                    case "probe":
                        PrintJson("GET", "/api/probe");
                        break;
                    case "diag":
                        PrintJson("GET", "/api/diagnostics");
                        break;
                    case "failures":
                        PrintJson("GET", "/api/failures");
                        break;
                    case "check":
                        SendPhone(false);
                        break;
                    case "start":
                        SendPhone(true);
                        break;
                    case "stop":
                        Stop();
                        break;
                    case "quit":
                    case "exit":
                        Stop();
                        return;
                    default:
                        Console.WriteLine("Unknown command. Type help.");
                        break;
                }
            }
        }

        private static void PrintHelp()
        {
            string proxy = ProxyUnavailableReason();
            string elevation = IsElevated() ? null : "a tunnel start needs an elevated console.";
            Console.WriteLine("status    Show the real engine status.");
            Console.WriteLine("watch     Show the status every 2 seconds until you press a key.");
            Console.WriteLine("check     " + (proxy != null
                ? "Unavailable: " + proxy
                : "Check a source device address and token. The token is not shown."));
            Console.WriteLine("start     " + (proxy != null
                ? "Unavailable: " + proxy
                : elevation != null
                    ? "Unavailable: " + elevation
                    : "Start the source device proxy tunnel."));
            Console.WriteLine("stop      Stop the tunnel.");
            Console.WriteLine("probe     Show the engine capability probe.");
            Console.WriteLine("diag      Show the diagnostics counters. They hold no address or token.");
            Console.WriteLine("failures  Show the recent failures.");
            Console.WriteLine("json      Show the full status answer.");
            Console.WriteLine("quit      Stop the tunnel, stop the engine, and exit.");
        }

        // Send one request after proving that the launched engine holds the
        // port alone. Nothing is sent to a port that another process holds.
        private static LauncherResponse Request(string method, string path, byte[] body, int timeout)
        {
            int exitCode;
            if (host == null || host.HasExited(out exitCode))
            {
                return new LauncherResponse(0, null, "engine_exited");
            }
            ListenerOwnership ownership = ListenerTable.Check(enginePort, engineProcess);
            if (ownership == ListenerOwnership.Unknown)
            {
                return new LauncherResponse(0, null, "listener_unknown");
            }
            if (ownership != ListenerOwnership.Owned)
            {
                return new LauncherResponse(0, null, "listener_not_owned");
            }
            EngineHttpEndpoint endpoint;
            if (!host.TryGetEndpoint(out endpoint))
            {
                return new LauncherResponse(0, null, "engine_unavailable");
            }
            byte[] secret = endpoint.CopySecret();
            try
            {
                return LauncherHttp.Send(endpoint.Port, secret, method, path, body, timeout);
            }
            finally
            {
                Array.Clear(secret, 0, secret.Length);
                endpoint.Clear();
            }
        }

        private static void PrintStatus()
        {
            LauncherResponse response = Request("GET", "/api/status", null, StatusTimeout);
            if (!Reached(response))
            {
                return;
            }
            try
            {
                using (JsonDocument document = JsonDocument.Parse(response.Body))
                {
                    JsonElement root = document.RootElement;
                    Console.WriteLine("Tunnel: " + (Bool(root, "running") == "true" ? "on" : "off")
                        + "   Mode: " + Text(root, "mode")
                        + "   Interface: " + Text(root, "iface"));
                    JsonElement platform;
                    if (root.TryGetProperty("platform", out platform) && platform.ValueKind == JsonValueKind.Object)
                    {
                        Console.WriteLine("Engine elevated: " + Bool(platform, "admin")
                            + "   Default interface: " + Text(platform, "default_iface_name"));
                    }
                    JsonElement phone;
                    if (root.TryGetProperty("phone", out phone) && phone.ValueKind == JsonValueKind.Object)
                    {
                        Console.WriteLine("Source device: " + Text(phone, "state") + ". " + Text(phone, "message"));
                    }
                    Console.WriteLine("Ping relay: " + Bool(root, "icmp_enabled")
                        + "   Cleanup blocked: " + Bool(root, "cleanup_blocked")
                        + "   TTL audit failures: " + StatsText(root, "ttl_bad"));
                    string stop = Text(root, "last_stop_message");
                    if (stop != "-")
                    {
                        Console.WriteLine("Last stop: " + stop);
                    }
                    string error = Text(root, "error");
                    if (error != "-")
                    {
                        Console.WriteLine("Engine error: " + error);
                    }
                }
            }
            catch (JsonException)
            {
                Console.WriteLine("The engine status could not be read.");
            }
        }

        private static void Watch()
        {
            if (Console.IsInputRedirected)
            {
                // A redirected input has no key to stop the loop. Show one status.
                PrintStatus();
                Console.WriteLine("watch needs an interactive console. One status was shown.");
                return;
            }
            Console.WriteLine("Press any key to stop watching.");
            while (true)
            {
                PrintStatus();
                for (int index = 0; index < 20; index++)
                {
                    if (Console.KeyAvailable)
                    {
                        Console.ReadKey(true);
                        return;
                    }
                    Thread.Sleep(100);
                }
                Console.WriteLine("");
            }
        }

        private static void PrintJson(string method, string path)
        {
            LauncherResponse response = Request(method, path, null, StatusTimeout);
            if (!Reached(response))
            {
                return;
            }
            Console.WriteLine("HTTP " + response.Status);
            try
            {
                using (JsonDocument document = JsonDocument.Parse(response.Body))
                using (Stream output = Console.OpenStandardOutput())
                using (Utf8JsonWriter writer = new Utf8JsonWriter(output, new JsonWriterOptions { Indented = true }))
                {
                    document.WriteTo(writer);
                }
                Console.WriteLine("");
            }
            catch (JsonException)
            {
                Console.WriteLine("The engine answer is not JSON.");
            }
        }

        // Return the reason that source device proxy use is unavailable, or
        // null when the engine status can be read. The engine gates every
        // token use with its own gateway check and refuses with a fixed
        // message (source_gateway_unproven), which PrintResult shows.
        private static string ProxyUnavailableReason()
        {
            LauncherResponse response = Request("GET", "/api/status", null, StatusTimeout);
            if (!response.Reached || response.Status != 200)
            {
                return "the engine status is unavailable.";
            }
            try
            {
                using (JsonDocument document = JsonDocument.Parse(response.Body))
                {
                    JsonElement phone;
                    if (!document.RootElement.TryGetProperty("phone", out phone)
                        || phone.ValueKind != JsonValueKind.Object)
                    {
                        return "the engine status has no source device state.";
                    }
                    return null;
                }
            }
            catch (JsonException)
            {
                return "the engine status could not be read.";
            }
        }

        private static void SendPhone(bool start)
        {
            string unavailable = ProxyUnavailableReason();
            if (unavailable == null && start && !IsElevated())
            {
                unavailable = "a tunnel start needs an elevated console.";
            }
            if (unavailable == null && Console.IsInputRedirected)
            {
                unavailable = "token entry needs an interactive console.";
            }
            if (unavailable != null)
            {
                Console.WriteLine("Unavailable: " + unavailable);
                return;
            }
            Console.WriteLine(start
                ? "Leave the token empty to use the source device that the engine already holds."
                : "The check sends the token to the source device at the hotspot gateway.");
            byte[] address = null;
            int port = 0;
            char[] token = new char[LauncherRules.MaximumTokenLength];
            int tokenLength = 0;
            byte[] body = null;
            try
            {
                tokenLength = ReadToken(token);
                if (tokenLength < 0)
                {
                    Console.WriteLine("The token has a character that a source device token cannot have.");
                    return;
                }
                if (tokenLength == 0 && !start)
                {
                    Console.WriteLine("A check needs a token.");
                    return;
                }
                if (tokenLength > 0)
                {
                    Console.Write("Source device address (the hotspot gateway, for example 172.20.10.1): ");
                    if (!LauncherRules.TryParseAddress(Console.ReadLine(), out address))
                    {
                        Console.WriteLine("That is not a numeric IPv4 address.");
                        return;
                    }
                    Console.Write("Source device proxy port: ");
                    if (!LauncherRules.TryParsePort(Console.ReadLine(), out port))
                    {
                        Console.WriteLine("That is not a port from 1 to 65535.");
                        return;
                    }
                }
                bool ping = true;
                if (start)
                {
                    Console.Write("Let ping work? [Y/n]: ");
                    string answer = (Console.ReadLine() ?? "").Trim().ToLowerInvariant();
                    ping = answer != "n" && answer != "no";
                }
                body = LauncherRules.BuildPhoneBody(
                    start,
                    address,
                    port,
                    tokenLength > 0 ? token : null,
                    tokenLength,
                    ping);
            }
            finally
            {
                Array.Clear(token, 0, token.Length);
            }

            try
            {
                Console.WriteLine(start ? "Starting. This can take up to a minute." : "Checking.");
                LauncherResponse response = Request(
                    "POST",
                    start ? "/api/start" : "/api/phone/check",
                    body,
                    StartTimeout);
                if (!Reached(response))
                {
                    return;
                }
                PrintResult(response);
                if (start)
                {
                    PrintStatus();
                }
            }
            finally
            {
                Array.Clear(body, 0, body.Length);
            }
        }

        private static void Stop()
        {
            LauncherResponse response = Request("POST", "/api/stop", null, StartTimeout);
            if (!Reached(response))
            {
                return;
            }
            PrintResult(response);
        }

        private static void PrintResult(LauncherResponse response)
        {
            try
            {
                using (JsonDocument document = JsonDocument.Parse(response.Body))
                {
                    JsonElement root = document.RootElement;
                    if (response.Status >= 200 && response.Status <= 299)
                    {
                        Console.WriteLine("Done (HTTP " + response.Status + ").");
                        string message = Text(root, "message");
                        if (message != "-")
                        {
                            Console.WriteLine(message);
                        }
                        return;
                    }
                    Console.WriteLine("Refused (HTTP " + response.Status + "): " + Text(root, "error"));
                }
            }
            catch (JsonException)
            {
                Console.WriteLine("HTTP " + response.Status + " with an answer that is not JSON.");
            }
        }

        private static bool Reached(LauncherResponse response)
        {
            if (response.Reached)
            {
                return true;
            }
            switch (response.Code)
            {
                case "engine_exited":
                    Console.WriteLine("The engine has exited. Quit and start the launcher again.");
                    break;
                case "listener_not_owned":
                    Console.WriteLine("The engine port is not held by the launched engine alone. Nothing was sent.");
                    break;
                case "listener_unknown":
                    Console.WriteLine("The listener table could not be read. Nothing was sent.");
                    break;
                case "timeout":
                    Console.WriteLine("The engine did not answer in time.");
                    break;
                default:
                    Console.WriteLine("The engine is unavailable (" + response.Code + ").");
                    break;
            }
            return false;
        }

        // Read the token without echo. Returns the length, or -1 for a
        // character outside the token set. The caller clears the buffer.
        private static int ReadToken(char[] token)
        {
            Console.Write("Source device token (hidden): ");
            int length = 0;
            bool bad = false;
            while (true)
            {
                ConsoleKeyInfo key = Console.ReadKey(true);
                if (key.Key == ConsoleKey.Enter)
                {
                    Console.WriteLine("");
                    return bad ? -1 : length;
                }
                if (key.Key == ConsoleKey.Backspace)
                {
                    if (length > 0)
                    {
                        length--;
                        token[length] = '\0';
                    }
                    continue;
                }
                if (!LauncherRules.IsTokenCharacter(key.KeyChar) || length >= token.Length)
                {
                    bad = true;
                    continue;
                }
                token[length++] = key.KeyChar;
            }
        }

        private static string Text(JsonElement root, string name)
        {
            JsonElement value;
            if (!root.TryGetProperty(name, out value))
            {
                return "-";
            }
            switch (value.ValueKind)
            {
                case JsonValueKind.String:
                    return value.GetString();
                case JsonValueKind.Number:
                    return value.GetRawText();
                case JsonValueKind.True:
                    return "true";
                case JsonValueKind.False:
                    return "false";
                default:
                    return "-";
            }
        }

        private static string Bool(JsonElement root, string name)
        {
            string value = Text(root, name);
            return value == "true" || value == "false" ? value : "unknown";
        }

        // Close the parent-liveness pipe and wait for the engine to run its own
        // stop path. The launcher never terminates the engine.
        // CloseAsync is idempotent and returns one shared task, so the Ctrl+C
        // handler and the main thread both wait for the same close. Only the
        // first caller prints the result.
        private static void Close()
        {
            if (host == null)
            {
                return;
            }
            bool exited = host.CloseAsync(EngineLaunchTiming.HostClose).GetAwaiter().GetResult();
            if (Interlocked.Exchange(ref closing, 1) != 0)
            {
                return;
            }
            Console.WriteLine(exited
                ? "The engine has exited."
                : "The engine did not exit in time. It keeps running its own cleanup. Check route print before a new start.");
        }

        private static string StatsText(JsonElement root, string name)
        {
            JsonElement stats;
            if (!root.TryGetProperty("stats", out stats) || stats.ValueKind != JsonValueKind.Object)
            {
                return "-";
            }
            return Text(stats, name);
        }

        private static bool IsElevated()
        {
            try
            {
                using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                {
                    return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
                }
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}
