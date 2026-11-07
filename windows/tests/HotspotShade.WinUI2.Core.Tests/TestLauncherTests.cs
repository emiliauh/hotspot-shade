using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using HotspotShade.WinUI2.TestLauncher;

namespace HotspotShade.WinUI2.Core.Tests
{
    // Hermetic checks for the console test launcher. The rules are pure and
    // the source contracts read files only. No engine, process, pipe, socket,
    // route, or tunnel is used here.
    internal static class TestLauncherTests
    {
        public static void Run(TestRunner runner)
        {
            runner.Check("launcher: the listener table port is read in network order", delegate
            {
                // Port 8080 is 0x1F90. The row stores the bytes 0x1F, 0x90.
                AssertEx.Equal(8080, LauncherRules.PortFromRowField(0x0000901F), "port 8080");
                AssertEx.Equal(49152, LauncherRules.PortFromRowField(0x000000C0), "port 49152");
                AssertEx.Equal(65535, LauncherRules.PortFromRowField(0x0000FFFF), "port 65535");
            });

            runner.Check("launcher: only a port held by the engine alone is owned", delegate
            {
                List<ListenerRow> rows = new List<ListenerRow>
                {
                    new ListenerRow(135, 4),
                    new ListenerRow(50000, 700)
                };
                AssertEx.Equal(ListenerOwnership.Owned, LauncherRules.Classify(rows, 50000, 700), "engine alone");
                AssertEx.Equal(ListenerOwnership.Missing, LauncherRules.Classify(rows, 50001, 700), "no listener yet");
                AssertEx.Equal(ListenerOwnership.Foreign, LauncherRules.Classify(rows, 50000, 701), "another owner");
                rows.Add(new ListenerRow(50000, 999));
                AssertEx.Equal(ListenerOwnership.Foreign, LauncherRules.Classify(rows, 50000, 700), "a second listener");
                AssertEx.Equal(ListenerOwnership.Foreign, LauncherRules.Classify(rows, 135, 0), "no process id");
                AssertEx.Equal(ListenerOwnership.Foreign, LauncherRules.Classify(null, 50000, 700), "no table");
            });

            runner.Check("launcher: an elevated launch needs a Program Files folder", delegate
            {
                AssertEx.True(
                    LauncherRules.IsTrustedInstallDirectory("anything", null, false),
                    "a standard-user engine may run from any folder");
                AssertEx.False(
                    LauncherRules.IsTrustedInstallDirectory(null, @"C:\Program Files", true),
                    "no folder");
                if (Path.DirectorySeparatorChar != '\\')
                {
                    return;
                }
                string root = @"C:\Program Files";
                AssertEx.True(
                    LauncherRules.IsTrustedInstallDirectory(@"C:\Program Files\HotspotShade Test", root, true),
                    "inside Program Files");
                AssertEx.False(LauncherRules.IsTrustedInstallDirectory(root, root, true), "Program Files itself");
                AssertEx.False(
                    LauncherRules.IsTrustedInstallDirectory(@"C:\Program Files Evil\HotspotShade", root, true),
                    "a sibling with the same prefix");
                AssertEx.False(
                    LauncherRules.IsTrustedInstallDirectory(@"C:\Users\Person\Downloads\HotspotShade", root, true),
                    "a user folder");
                AssertEx.False(
                    LauncherRules.IsTrustedInstallDirectory(@"C:\Program Files\..\Users\Person", root, true),
                    "a traversal out of Program Files");
            });

            runner.Check("launcher: addresses and ports are strict", delegate
            {
                byte[] address;
                AssertEx.True(LauncherRules.TryParseAddress("172.20.10.1", out address), "hotspot gateway");
                AssertEx.Equal(172, (int)address[0], "first octet");
                AssertEx.True(LauncherRules.TryParseAddress(" 192.168.43.1 ", out address), "surrounding space");
                AssertEx.False(LauncherRules.TryParseAddress("172.020.10.1", out address), "leading zero");
                AssertEx.False(LauncherRules.TryParseAddress("127.0.0.1", out address), "loopback");
                AssertEx.False(LauncherRules.TryParseAddress("0.1.2.3", out address), "zero network");
                AssertEx.False(LauncherRules.TryParseAddress("224.0.0.1", out address), "multicast");
                AssertEx.False(LauncherRules.TryParseAddress("1.2.3", out address), "three parts");
                AssertEx.False(LauncherRules.TryParseAddress("1.2.3.256", out address), "large octet");
                AssertEx.False(LauncherRules.TryParseAddress("phone.local", out address), "a name");
                AssertEx.False(LauncherRules.TryParseAddress("+1.2.3.4", out address), "a sign");
                int port;
                AssertEx.True(LauncherRules.TryParsePort("20123", out port), "valid port");
                AssertEx.Equal(20123, port, "port value");
                AssertEx.False(LauncherRules.TryParsePort("0", out port), "zero port");
                AssertEx.False(LauncherRules.TryParsePort("65536", out port), "large port");
                AssertEx.False(LauncherRules.TryParsePort("-1", out port), "negative port");
            });

            runner.Check("launcher: the start body matches the engine options", delegate
            {
                char[] token = "ab\"c\\d".ToCharArray();
                byte[] body = LauncherRules.BuildPhoneBody(
                    true,
                    new byte[] { 172, 20, 10, 1 },
                    20123,
                    token,
                    token.Length,
                    true);
                AssertEx.Equal(
                    "{\"mode\":\"phone\",\"options\":{\"host\":\"172.20.10.1\",\"port\":20123,\"token\":\"ab\\\"c\\\\d\",\"experimental_icmp\":true}}",
                    Encoding.ASCII.GetString(body),
                    "start body");
                using (System.Text.Json.JsonDocument document = System.Text.Json.JsonDocument.Parse(body))
                {
                    AssertEx.Equal(
                        "ab\"c\\d",
                        document.RootElement.GetProperty("options").GetProperty("token").GetString(),
                        "the escaped token round-trips");
                }

                byte[] stored = LauncherRules.BuildPhoneBody(true, null, 0, null, 0, false);
                AssertEx.Equal(
                    "{\"mode\":\"phone\",\"options\":{\"experimental_icmp\":false}}",
                    Encoding.ASCII.GetString(stored),
                    "a start with the held target sends no token");

                char[] check = "token1".ToCharArray();
                byte[] checkBody = LauncherRules.BuildPhoneBody(
                    false,
                    new byte[] { 172, 20, 10, 1 },
                    20123,
                    check,
                    check.Length,
                    true);
                AssertEx.Equal(
                    "{\"options\":{\"host\":\"172.20.10.1\",\"port\":20123,\"token\":\"token1\"}}",
                    Encoding.ASCII.GetString(checkBody),
                    "check body carries no ping choice");
            });

            runner.Check("launcher: a token outside the token set is refused", delegate
            {
                AssertEx.False(LauncherRules.IsTokenCharacter(' '), "space");
                AssertEx.False(LauncherRules.IsTokenCharacter('\n'), "newline");
                AssertEx.False(LauncherRules.IsTokenCharacter((char)0x7F), "delete");
                AssertEx.False(LauncherRules.IsTokenCharacter('\u00e9'), "non-ASCII");
                AssertEx.True(LauncherRules.IsTokenCharacter('~'), "tilde");
                bool refused = false;
                try
                {
                    char[] bad = "a b".ToCharArray();
                    LauncherRules.BuildPhoneBody(true, new byte[] { 10, 0, 0, 1 }, 1, bad, bad.Length, true);
                }
                catch (ArgumentException)
                {
                    refused = true;
                }
                AssertEx.True(refused, "a space in a token");
                refused = false;
                try
                {
                    char[] large = new char[LauncherRules.MaximumTokenLength + 1];
                    for (int index = 0; index < large.Length; index++)
                    {
                        large[index] = 'a';
                    }
                    LauncherRules.BuildPhoneBody(true, new byte[] { 10, 0, 0, 1 }, 1, large, large.Length, true);
                }
                catch (ArgumentException)
                {
                    refused = true;
                }
                AssertEx.True(refused, "a token over 255 characters");
            });

            runner.Check("launcher: source contracts keep the engine boundary", delegate
            {
                string root = FindWindowsRoot();
                AssertEx.True(root != null, "windows root");
                string launcher = Path.Combine(root, "src", "HotspotShade.WinUI2.TestLauncher");
                string program = File.ReadAllText(Path.Combine(launcher, "Program.cs"));
                string http = File.ReadAllText(Path.Combine(launcher, "LauncherHttp.cs"));
                string manifest = File.ReadAllText(Path.Combine(launcher, "app.manifest"));
                string project = File.ReadAllText(Path.Combine(launcher, "HotspotShade.WinUI2.TestLauncher.csproj"));
                string host = File.ReadAllText(Path.Combine(root, "src", "HotspotShade.WinUI2.Broker", "Win32EngineHost.cs"));
                string runtime = File.ReadAllText(Path.Combine(root, "src", "HotspotShade.WinUI2.Broker", "BrokerRuntime.cs"));

                // The listener ownership check comes before the secret copy
                // and the send in the one request path.
                int check = program.IndexOf("ListenerTable.Check(enginePort, engineProcess)", StringComparison.Ordinal);
                int copy = program.IndexOf("endpoint.CopySecret()", StringComparison.Ordinal);
                int send = program.IndexOf("LauncherHttp.Send(", StringComparison.Ordinal);
                AssertEx.True(check >= 0 && copy > check && send > copy, "ownership check before the send");
                AssertEx.Equal(1, Count(program, "LauncherHttp.Send("), "one send path");

                AssertEx.DoesNotContain(program, "TerminateProcess", "no forced termination");
                AssertEx.DoesNotContain(program, "Process" + ".Start", "no shell out");
                AssertEx.DoesNotContain(program, "runas", "no elevation request");
                AssertEx.DoesNotContain(program, "--demo", "no demo engine");
                AssertEx.DoesNotContain(program, "Environment.GetEnvironmentVariable", "no environment input");
                AssertEx.Contains(manifest, "level=\"asInvoker\"", "no elevation in the manifest");
                AssertEx.Contains(http, "\"127.0.0.1\"", "loopback only");
                AssertEx.Contains(http, "OptionRedirectPolicy = 88", "fixed redirect policy");
                AssertEx.Contains(project, "Win32EngineHost.cs", "the reviewed engine host");
                AssertEx.Contains(
                    File.ReadAllText(Path.Combine(launcher, "LauncherAssembly.cs")),
                    "DllImportSearchPath.System32",
                    "native DLLs load from System32 only");

                // A blocked feature is shown as unavailable before any token
                // prompt. Nothing is simulated.
                int gate = program.IndexOf("string unavailable = ProxyUnavailableReason();", StringComparison.Ordinal);
                int prompt = program.IndexOf("tokenLength = ReadToken(token);", StringComparison.Ordinal);
                AssertEx.True(gate >= 0 && prompt > gate, "the unavailable check comes before the token prompt");
                AssertEx.DoesNotContain(program, "source_proxy_unavailable", "the retired guard state is not read");
                AssertEx.DoesNotContain(program.ToLowerInvariant(), "simulat" + "ed data", "no simulated data");

                // The old entry keeps its administrator requirement. The
                // packaged broker starts the user engine through the explicit
                // standard-user entry, and only the elevated starter starts
                // an engine with administrator rights.
                AssertEx.Contains(
                    Squash(host),
                    "returnTryCreate(executablePath,trustedRoot,port,true,outhost,outplan,outfailure);",
                    "the old entry keeps the administrator requirement");
                AssertEx.Contains(Squash(host), "if(requireAdministrator&&!IsElevated())", "the administrator check");
                string endpoints = File.ReadAllText(Path.Combine(root, "src", "HotspotShade.WinUI2.Broker", "EngineEndpoints.cs"));
                AssertEx.Contains(
                    Squash(endpoints),
                    "Win32EngineHost.TryCreate(path,root,port,false,handoff,outhost,outplan,outfailure)",
                    "the broker starts the standard-user engine");
                AssertEx.DoesNotContain(runtime, "Win32EngineHost.TryCreate", "the runtime starts no engine itself");
            });
        }

        private static int Count(string text, string part)
        {
            int count = 0;
            int at = 0;
            while ((at = text.IndexOf(part, at, StringComparison.Ordinal)) >= 0)
            {
                count++;
                at += part.Length;
            }
            return count;
        }

        private static string Squash(string text)
        {
            StringBuilder builder = new StringBuilder(text.Length);
            foreach (char value in text)
            {
                if (!char.IsWhiteSpace(value))
                {
                    builder.Append(value);
                }
            }
            return builder.ToString();
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
    }
}
