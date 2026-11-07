using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using HotspotShade.WinUI2.Core.Engine.Release;

namespace HotspotShade.WinUI2.Core.Tests
{
    // Hermetic checks for the Windows release probe contract. The parser,
    // policy, and report are pure. No engine, process, network endpoint, route,
    // or tunnel is used here.
    internal static class ReleaseProbeTests
    {
        private const string PrivilegeLine =
            "Route changes require Administrator rights.";

        private const string Hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        public static void Run(TestRunner runner)
        {
            runner.Check("release probe: documented output parses", delegate
            {
                EngineProbeParseResult result = EngineProbeOutput.Parse(ProbeText());
                AssertEx.True(result.Ok, "the documented output must parse");
                EngineProbeFacts facts = result.Facts;
                AssertEx.Equal(false, facts.Administrator, "administrator");
                AssertEx.Equal("Wi-Fi", facts.InterfaceName, "interface name");
                AssertEx.Equal(12, facts.InterfaceIndex, "interface index");
                AssertEx.Equal(65, facts.UdpTtl, "UDP TTL");
                AssertEx.Equal(0, facts.AuditFailures, "audit failures");
            });

            runner.Check("release probe: CRLF, blank lines, and line order are accepted", delegate
            {
                string text = "UDP TTL: 65\r\n"
                    + "\r\n"
                    + "TTL audit failures: 0\r\n"
                    + "administrator=true\r\n"
                    + "default IPv4 interface: Ethernet 2 (index 7)\r\n"
                    + PrivilegeLine + "\r\n";
                EngineProbeParseResult result = EngineProbeOutput.Parse(text);
                AssertEx.True(result.Ok, "a reordered CRLF answer must parse");
                AssertEx.Equal(true, result.Facts.Administrator, "administrator");
                AssertEx.Equal("Ethernet 2", result.Facts.InterfaceName, "interface name with a space");
                AssertEx.Equal(7, result.Facts.InterfaceIndex, "interface index");
            });

            runner.Check("release probe: every required probe line is required", delegate
            {
                string[] lines = ProbeText().Split(
                    new char[] { '\n' },
                    StringSplitOptions.RemoveEmptyEntries);
                for (int dropped = 0; dropped < lines.Length; dropped++)
                {
                    StringBuilder text = new StringBuilder();
                    for (int index = 0; index < lines.Length; index++)
                    {
                        if (index != dropped)
                        {
                            text.Append(lines[index]);
                            text.Append('\n');
                        }
                    }
                    EngineProbeParseResult result = EngineProbeOutput.Parse(text.ToString());
                    AssertEx.False(result.Ok, "a missing line must fail: " + dropped);
                }
            });

            runner.Check("release probe: a parse failure carries one fixed code", delegate
            {
                AssertEx.Equal(
                    ReleaseProbeCodes.MissingOutput,
                    EngineProbeOutput.Parse(null).Code,
                    "null");
                AssertEx.Equal(
                    ReleaseProbeCodes.UnexpectedLine,
                    EngineProbeOutput.Parse(ProbeText() + "unexpected extra line\n").Code,
                    "unexpected line");
                AssertEx.Equal(
                    ReleaseProbeCodes.DuplicateLine,
                    EngineProbeOutput.Parse(ProbeText() + "UDP TTL: 65\n").Code,
                    "duplicate line");
                AssertEx.Equal(
                    ReleaseProbeCodes.InvalidAdministrator,
                    EngineProbeOutput.Parse(ProbeText("yes")).Code,
                    "administrator");
                AssertEx.Equal(
                    ReleaseProbeCodes.InvalidTtl,
                    EngineProbeOutput.Parse(ProbeText(ttl: "256")).Code,
                    "TTL range");
                AssertEx.Equal(
                    ReleaseProbeCodes.InvalidAudit,
                    EngineProbeOutput.Parse(ProbeText(audit: "-1")).Code,
                    "audit range");
                AssertEx.Equal(
                    ReleaseProbeCodes.OutputTooLarge,
                    EngineProbeOutput.Parse(new string('a', 9000)).Code,
                    "oversized answer");
            });

            runner.Check("release probe: an interface line needs a positive index", delegate
            {
                string[] bad = { "0", "abc", "", "-1", "1000001" };
                for (int index = 0; index < bad.Length; index++)
                {
                    EngineProbeParseResult result = EngineProbeOutput.Parse(ProbeText(index: bad[index]));
                    AssertEx.False(result.Ok, "index " + bad[index] + " must fail");
                    AssertEx.Equal(ReleaseProbeCodes.InvalidInterface, result.Code, "index code");
                }
                AssertEx.False(
                    EngineProbeOutput.Parse(ProbeText().Replace(" (index 12)", "")).Ok,
                    "a missing index marker must fail");
                AssertEx.False(
                    EngineProbeOutput.Parse(ProbeText(interfaceName: "")).Ok,
                    "an empty name must fail");
            });

            runner.Check("release probe: a control character in the name fails", delegate
            {
                EngineProbeParseResult result = EngineProbeOutput.Parse(
                    ProbeText(interfaceName: "Wi\u0001Fi"));
                AssertEx.False(result.Ok, "a control character must fail");
                AssertEx.Equal(ReleaseProbeCodes.InvalidInterface, result.Code, "interface code");
            });

            runner.Check("release probe: version output is one fixed line", delegate
            {
                string version;
                AssertEx.True(EngineVersionOutput.TryParse("hotspotshade 0.1.0\n", out version), "valid");
                AssertEx.Equal("0.1.0", version, "version");
                AssertEx.True(
                    EngineVersionOutput.TryParse("\r\nhotspotshade 1.2.3-rc+4\r\n\r\n", out version),
                    "CRLF with a build suffix");
                AssertEx.Equal("1.2.3-rc+4", version, "suffix version");
                AssertEx.False(EngineVersionOutput.TryParse("0.1.0", out version), "missing program word");
                AssertEx.False(EngineVersionOutput.TryParse("hotspotshade 0.1.0\nhotspotshade 0.2.0", out version), "two lines");
                AssertEx.False(EngineVersionOutput.TryParse("hotspotshade 0.1 0", out version), "space in the version");
                AssertEx.False(EngineVersionOutput.TryParse("hotspotshade ", out version), "empty version");
                AssertEx.False(EngineVersionOutput.TryParse(null, out version), "null");
            });

            runner.Check("release probe: only read-only commands are allowed", delegate
            {
                AssertEx.True(ReleaseProbeCommandPolicy.IsAllowed("probe"), "probe");
                AssertEx.True(ReleaseProbeCommandPolicy.IsAllowed("--version"), "version");
                string[] refused =
                {
                    "tun", "gui", "phone", "--phone", "start", "stop",
                    "--secrets-fd", "--token-fd", "", null
                };
                for (int index = 0; index < refused.Length; index++)
                {
                    AssertEx.False(
                        ReleaseProbeCommandPolicy.IsAllowed(refused[index]),
                        "refused command " + index);
                }
            });

            runner.Check("release probe: a healthy answer passes with exit 0", delegate
            {
                IList<ReleaseProbeCheck> checks = ProbeChecks(ProbeText(), true, false);
                ReleaseProbeVerdict verdict = ReleaseProbeEvaluation.Decide(AsReadOnly(checks));
                AssertEx.Equal(ReleaseProbeSeverity.Pass, verdict.Severity, "severity");
                AssertEx.Equal(0, verdict.ExitCode, "exit code");
                AssertEx.True(verdict.Passed, "passed");
            });

            runner.Check("release probe: a wrong TTL fails with exit 1", delegate
            {
                IList<ReleaseProbeCheck> checks = ProbeChecks(ProbeText(ttl: "64"), true, false);
                ReleaseProbeVerdict verdict = ReleaseProbeEvaluation.Decide(AsReadOnly(checks));
                AssertEx.Equal(ReleaseProbeSeverity.Fail, verdict.Severity, "severity");
                AssertEx.Equal(1, verdict.ExitCode, "exit code");
            });

            runner.Check("release probe: an audit failure fails with exit 1", delegate
            {
                IList<ReleaseProbeCheck> checks = ProbeChecks(ProbeText(audit: "1"), true, false);
                ReleaseProbeVerdict verdict = ReleaseProbeEvaluation.Decide(AsReadOnly(checks));
                AssertEx.Equal(ReleaseProbeSeverity.Fail, verdict.Severity, "severity");
                AssertEx.Equal(1, verdict.ExitCode, "exit code");
            });

            runner.Check("release probe: a malformed answer fails and invents no facts", delegate
            {
                EngineProbeParseResult parse = EngineProbeOutput.Parse("not a probe answer");
                IList<ReleaseProbeCheck> checks = new List<ReleaseProbeCheck>();
                ReleaseProbeEvaluation.AddProbeChecks(checks, parse, true, false);
                ReleaseProbeVerdict verdict = ReleaseProbeEvaluation.Decide(AsReadOnly(checks));
                AssertEx.Equal(ReleaseProbeSeverity.Fail, verdict.Severity, "severity");
                AssertEx.Equal(1, checks.Count, "one probe failure only");
                AssertEx.Equal("engine_probe", checks[0].Name, "probe check name");
            });

            runner.Check("release probe: an elevation mismatch is a warning", delegate
            {
                IList<ReleaseProbeCheck> checks = ProbeChecks(ProbeText(), true, true);
                ReleaseProbeVerdict verdict = ReleaseProbeEvaluation.Decide(AsReadOnly(checks));
                AssertEx.Equal(ReleaseProbeSeverity.Warn, verdict.Severity, "severity");
                AssertEx.Equal(2, verdict.ExitCode, "exit code");
            });

            runner.Check("release probe: unknown process elevation is a warning", delegate
            {
                EngineProbeParseResult parse = EngineProbeOutput.Parse(ProbeText());
                IList<ReleaseProbeCheck> checks = new List<ReleaseProbeCheck>();
                ReleaseProbeEvaluation.AddProbeChecks(checks, parse, false, false);
                ReleaseProbeVerdict verdict = ReleaseProbeEvaluation.Decide(AsReadOnly(checks));
                AssertEx.Equal(ReleaseProbeSeverity.Warn, verdict.Severity, "severity");
                AssertEx.Equal(2, verdict.ExitCode, "exit code");
            });

            runner.Check("release probe: host checks keep x64 and 64-bit distinct", delegate
            {
                IList<ReleaseProbeCheck> windowsX64 = ReleaseProbeEvaluation.CheckHost(
                    true,
                    true,
                    "X64");
                AssertEx.Equal(3, windowsX64.Count, "three host checks");
                AssertEx.Equal(ReleaseProbeSeverity.Pass, windowsX64[0].Severity, "Windows");
                AssertEx.Equal(ReleaseProbeSeverity.Pass, windowsX64[1].Severity, "64-bit");
                AssertEx.Equal(ReleaseProbeSeverity.Pass, windowsX64[2].Severity, "x64");

                IList<ReleaseProbeCheck> armHost = ReleaseProbeEvaluation.CheckHost(
                    true,
                    true,
                    "Arm64");
                AssertEx.Equal(ReleaseProbeSeverity.Warn, armHost[2].Severity, "another architecture");

                IList<ReleaseProbeCheck> thirtyTwoBit = ReleaseProbeEvaluation.CheckHost(
                    true,
                    false,
                    "X64");
                AssertEx.Equal(ReleaseProbeSeverity.Fail, thirtyTwoBit[1].Severity, "32-bit Windows");

                IList<ReleaseProbeCheck> otherHost = ReleaseProbeEvaluation.CheckHost(
                    false,
                    true,
                    "X64");
                AssertEx.Equal(ReleaseProbeSeverity.Warn, otherHost[0].Severity, "another host");
            });

            runner.Check("release probe: an engine file needs a length and a hash", delegate
            {
                AssertEx.Equal(
                    ReleaseProbeSeverity.Fail,
                    ReleaseProbeEvaluation.CheckEngine(false, 0, "").Severity,
                    "missing");
                AssertEx.Equal(
                    ReleaseProbeSeverity.Fail,
                    ReleaseProbeEvaluation.CheckEngine(true, 0, Hash).Severity,
                    "empty");
                AssertEx.Equal(
                    ReleaseProbeSeverity.Fail,
                    ReleaseProbeEvaluation.CheckEngine(true, 4, "not-a-hash").Severity,
                    "bad hash");
                AssertEx.Equal(
                    ReleaseProbeSeverity.Pass,
                    ReleaseProbeEvaluation.CheckEngine(true, 4, Hash).Severity,
                    "present");
            });

            runner.Check("release probe: a command failure is fixed and bounded", delegate
            {
                ReleaseProbeCheck missing = ReleaseProbeEvaluation.CheckCommand(
                    "probe_command",
                    ReleaseProbeCommandResult.Failure(ReleaseProbeCodes.Timeout, -1));
                AssertEx.Equal(ReleaseProbeSeverity.Fail, missing.Severity, "timeout severity");
                AssertEx.Equal(ReleaseProbeCodes.Timeout, missing.Detail, "timeout code");
                AssertEx.Equal(
                    ReleaseProbeSeverity.Fail,
                    ReleaseProbeEvaluation.CheckCommand("probe_command", null).Severity,
                    "null result");
                AssertEx.Equal(
                    ReleaseProbeSeverity.Pass,
                    ReleaseProbeEvaluation.CheckCommand(
                        "probe_command",
                        ReleaseProbeCommandResult.Success(0, "answer", "")).Severity,
                    "success");
                AssertEx.Equal(
                    ReleaseProbeSeverity.Warn,
                    ReleaseProbeEvaluation.CheckErrorStream(
                        ReleaseProbeCommandResult.Success(0, "answer", "warning")).Severity,
                    "error stream");
            });

            runner.Check("release probe: a verdict takes the worst check", delegate
            {
                ReleaseProbeVerdict empty = ReleaseProbeEvaluation.Decide(
                    AsReadOnly(new List<ReleaseProbeCheck>()));
                AssertEx.Equal(ReleaseProbeSeverity.Pass, empty.Severity, "empty");
                AssertEx.Equal(0, empty.ExitCode, "empty exit");

                List<ReleaseProbeCheck> mixed = new List<ReleaseProbeCheck>();
                mixed.Add(new ReleaseProbeCheck("warn", ReleaseProbeSeverity.Warn, ""));
                mixed.Add(new ReleaseProbeCheck("fail", ReleaseProbeSeverity.Fail, ""));
                ReleaseProbeVerdict verdict = ReleaseProbeEvaluation.Decide(AsReadOnly(mixed));
                AssertEx.Equal(ReleaseProbeSeverity.Fail, verdict.Severity, "fail dominates");
                AssertEx.Equal(1, verdict.ExitCode, "fail exit");
            });

            runner.Check("release probe: text names every fact without a path", delegate
            {
                ReleaseProbeReport report = SampleReport();
                string text = ReleaseProbeText.Render(report);
                AssertEx.Contains(text, "HotspotShade Windows release probe", "title");
                AssertEx.Contains(text, "UDP TTL: 65 (expected 65)", "TTL");
                AssertEx.Contains(text, "TTL audit failures: 0", "audit");
                AssertEx.Contains(text, "Default interface: Wi-Fi (index 12)", "interface");
                AssertEx.Contains(text, "Engine SHA-256: " + Hash, "hash");
                AssertEx.Contains(text, "Result: PASS (exit 0)", "result");
                AssertEx.DoesNotContain(text, "C:\\", "a full path");
                AssertEx.DoesNotContain(text, "Users", "a home path");
            });

            runner.Check("release probe: text states unknown instead of inventing values", delegate
            {
                ReleaseProbeReport report = SampleReport();
                report.Probe = null;
                report.EngineVersion = "";
                report.EngineSha256 = "";
                string text = ReleaseProbeText.Render(report);
                AssertEx.Contains(text, "Probe administrator: unknown", "probe unknown");
                AssertEx.Contains(text, "UDP TTL: unknown", "TTL unknown");
                AssertEx.Contains(text, "Engine version: unknown", "version unknown");
                AssertEx.Contains(text, "Engine SHA-256: none", "hash none");
            });

            runner.Check("release probe: json is well formed and stable", delegate
            {
                ReleaseProbeReport report = SampleReport();
                string first = ReleaseProbeJson.Write(report);
                string second = ReleaseProbeJson.Write(report);
                AssertEx.Equal(first, second, "deterministic output");
                AssertEx.Equal(2, first.Split('\n').Length, "one content line and one newline");

                using (JsonDocument document = JsonDocument.Parse(first))
                {
                    JsonElement root = document.RootElement;
                    AssertEx.Equal(ReleaseProbeReport.Schema, root.GetProperty("schema").GetString(), "schema");
                    AssertEx.Equal(
                        "hotspotshade.exe",
                        root.GetProperty("engine").GetProperty("file_name").GetString(),
                        "engine file name");
                    AssertEx.Equal(65, root.GetProperty("probe").GetProperty("udp_ttl").GetInt32(), "TTL");
                    AssertEx.Equal(0, root.GetProperty("probe").GetProperty("audit_failures").GetInt32(), "audit");
                    AssertEx.Equal(
                        "PASS",
                        root.GetProperty("verdict").GetProperty("result").GetString(),
                        "verdict");
                    AssertEx.Equal(0, root.GetProperty("verdict").GetProperty("exit_code").GetInt32(), "exit");
                    AssertEx.Equal(
                        5,
                        root.GetProperty("checks").GetArrayLength(),
                        "probe checks");
                }
            });

            runner.Check("release probe: json escapes control and non-ASCII text", delegate
            {
                ReleaseProbeReport report = SampleReport();
                report.OsDescription = "a\"b\\c\nd\te\u00e9";
                string json = ReleaseProbeJson.Write(report);
                using (JsonDocument document = JsonDocument.Parse(json))
                {
                    AssertEx.Equal(
                        "a\"b\\c\nd\te\u00e9",
                        document.RootElement.GetProperty("host").GetProperty("os").GetString(),
                        "round trip");
                }
                AssertEx.DoesNotContain(json, "\u00e9", "non-ASCII is escaped");
            });

            runner.Check("release probe: json writes a null probe", delegate
            {
                ReleaseProbeReport report = SampleReport();
                report.Probe = null;
                using (JsonDocument document = JsonDocument.Parse(ReleaseProbeJson.Write(report)))
                {
                    AssertEx.Equal(
                        JsonValueKind.Null,
                        document.RootElement.GetProperty("probe").ValueKind,
                        "null probe");
                }
            });

            runner.Check("release probe: the project stays small and out of the app build", delegate
            {
                string root = FindWindowsRoot();
                AssertEx.True(root != null, "windows root");
                string project = Path.Combine(
                    root,
                    "src",
                    "HotspotShade.WinUI2.ReleaseProbe",
                    "HotspotShade.WinUI2.ReleaseProbe.csproj");
                AssertEx.True(File.Exists(project), "probe project exists");
                string text = SourceText.Read(project);
                AssertEx.Contains(text, "<TargetFramework>net8.0</TargetFramework>", "target");
                AssertEx.DoesNotContain(text, "PackageReference", "no package dependency");
                AssertEx.Contains(
                    text,
                    "HotspotShade.WinUI2.Core.csproj",
                    "the probe uses the shared contract");

                string solution = SourceText.Read(Path.Combine(root, "HotspotShade.WinUI2.sln"));
                AssertEx.DoesNotContain(solution, "ReleaseProbe", "the probe is not in the app build");

                string runnerSource = SourceText.Read(Path.Combine(
                    root,
                    "src",
                    "HotspotShade.WinUI2.ReleaseProbe",
                    "EngineCommandRunner.cs"));
                AssertEx.Contains(runnerSource, "UseShellExecute = false", "no shell");
                AssertEx.Contains(runnerSource, "SanitizeEnvironment", "no inherited project variable");
                AssertEx.Contains(runnerSource, "HOTSPOTSHADE_", "the project prefix is removed");
                AssertEx.DoesNotContain(runnerSource, "UseShellExecute = true", "no shell start");
            });
        }

        private static IList<ReleaseProbeCheck> ProbeChecks(
            string probeText,
            bool administratorKnown,
            bool processAdministrator)
        {
            IList<ReleaseProbeCheck> checks = new List<ReleaseProbeCheck>();
            EngineProbeParseResult parse = EngineProbeOutput.Parse(probeText);
            ReleaseProbeEvaluation.AddProbeChecks(
                checks,
                parse,
                administratorKnown,
                processAdministrator);
            return checks;
        }

        private static ReleaseProbeReport SampleReport()
        {
            EngineProbeParseResult parse = EngineProbeOutput.Parse(ProbeText());
            IList<ReleaseProbeCheck> checks = new List<ReleaseProbeCheck>();
            ReleaseProbeEvaluation.AddProbeChecks(checks, parse, true, false);
            ReleaseProbeVerdict verdict = ReleaseProbeEvaluation.Decide(AsReadOnly(checks));
            return new ReleaseProbeReport
            {
                GeneratedAtUtc = "2026-01-02T03:04:05Z",
                OsDescription = "Microsoft Windows 11 Pro",
                Architecture = "X64",
                Is64BitOperatingSystem = true,
                AdministratorKnown = true,
                ProcessAdministrator = false,
                EngineFileName = "hotspotshade.exe",
                EngineLength = 1024,
                EngineSha256 = Hash,
                EngineVersion = "0.1.0",
                Probe = parse.Facts,
                Checks = AsReadOnly(checks),
                Verdict = verdict
            };
        }

        private static IReadOnlyList<ReleaseProbeCheck> AsReadOnly(IList<ReleaseProbeCheck> checks)
        {
            return checks as IReadOnlyList<ReleaseProbeCheck>
                ?? new List<ReleaseProbeCheck>(checks);
        }

        private static string ProbeText(
            string administrator = "false",
            string interfaceName = "Wi-Fi",
            string index = "12",
            string ttl = "65",
            string audit = "0")
        {
            return "administrator=" + administrator + "\n"
                + "default IPv4 interface: " + interfaceName + " (index " + index + ")\n"
                + "UDP TTL: " + ttl + "\n"
                + "TTL audit failures: " + audit + "\n"
                + PrivilegeLine + "\n";
        }

        private static string FindWindowsRoot()
        {
            DirectoryInfo directory = new DirectoryInfo(AppContext.BaseDirectory);
            while (directory != null)
            {
                string candidate = Path.Combine(directory.FullName, "windows");
                if (Directory.Exists(candidate)
                    && File.Exists(Path.Combine(candidate, "README.md")))
                {
                    return candidate;
                }
                directory = directory.Parent;
            }
            return null;
        }
    }
}
