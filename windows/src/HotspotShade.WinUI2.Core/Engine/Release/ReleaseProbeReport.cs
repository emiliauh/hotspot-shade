using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace HotspotShade.WinUI2.Core.Engine.Release
{
    // One named check in a release probe report. The detail is a fixed code or
    // a fixed short phrase. It never holds engine output, a path, an address, a
    // token, or a key.
    public sealed class ReleaseProbeCheck
    {
        public ReleaseProbeCheck(string name, ReleaseProbeSeverity severity, string detail)
        {
            Name = name ?? "";
            Severity = severity;
            Detail = detail ?? "";
        }

        public string Name { get; private set; }

        public ReleaseProbeSeverity Severity { get; private set; }

        public string Detail { get; private set; }
    }

    public sealed class ReleaseProbeVerdict
    {
        internal ReleaseProbeVerdict(
            IReadOnlyList<ReleaseProbeCheck> checks,
            ReleaseProbeSeverity severity,
            int exitCode)
        {
            Checks = checks;
            Severity = severity;
            ExitCode = exitCode;
        }

        public IReadOnlyList<ReleaseProbeCheck> Checks { get; private set; }

        public ReleaseProbeSeverity Severity { get; private set; }

        public int ExitCode { get; private set; }

        public bool Passed
        {
            get { return Severity != ReleaseProbeSeverity.Fail; }
        }
    }

    // The release probe policy. It turns host facts and one read-only engine
    // probe answer into pass, warn, or fail checks. The expected UDP TTL is the
    // core design value: the normalizer sets 65 and reads it back, and the
    // source device NAT is expected to decrement it once to the native 64.
    public static class ReleaseProbeEvaluation
    {
        public const int ExpectedUdpTtl = 65;
        public const string ExpectedEngineFileName = "hotspotshade.exe";
        public const string WindowsArchitecture = "X64";
        public const int ExitPass = 0;
        public const int ExitWarn = 2;
        public const int ExitFail = 1;

        public static IList<ReleaseProbeCheck> CheckHost(
            bool windows,
            bool is64BitOperatingSystem,
            string architecture)
        {
            List<ReleaseProbeCheck> checks = new List<ReleaseProbeCheck>();
            checks.Add(new ReleaseProbeCheck(
                "host_windows",
                windows ? ReleaseProbeSeverity.Pass : ReleaseProbeSeverity.Warn,
                windows ? "windows" : "not_windows"));
            checks.Add(new ReleaseProbeCheck(
                "host_64_bit",
                is64BitOperatingSystem ? ReleaseProbeSeverity.Pass : ReleaseProbeSeverity.Fail,
                is64BitOperatingSystem ? "64_bit" : "not_64_bit"));
            checks.Add(new ReleaseProbeCheck(
                "host_x64",
                string.Equals(architecture, WindowsArchitecture, StringComparison.OrdinalIgnoreCase)
                    ? ReleaseProbeSeverity.Pass
                    : ReleaseProbeSeverity.Warn,
                string.Equals(architecture, WindowsArchitecture, StringComparison.OrdinalIgnoreCase)
                    ? "x64"
                    : "not_x64"));
            return checks;
        }

        public static ReleaseProbeCheck CheckEngine(
            bool exists,
            long length,
            string sha256)
        {
            if (!exists)
            {
                return new ReleaseProbeCheck(
                    "engine_file",
                    ReleaseProbeSeverity.Fail,
                    ReleaseProbeCodes.EngineMissing);
            }
            if (length <= 0)
            {
                return new ReleaseProbeCheck(
                    "engine_file",
                    ReleaseProbeSeverity.Fail,
                    "engine_empty");
            }
            if (!IsHex64(sha256))
            {
                return new ReleaseProbeCheck(
                    "engine_file",
                    ReleaseProbeSeverity.Fail,
                    "engine_hash_unavailable");
            }
            return new ReleaseProbeCheck("engine_file", ReleaseProbeSeverity.Pass, "present");
        }

        public static ReleaseProbeCheck CheckCommand(string name, ReleaseProbeCommandResult result)
        {
            if (result == null)
            {
                return new ReleaseProbeCheck(name, ReleaseProbeSeverity.Fail, ReleaseProbeCodes.StartFailed);
            }
            if (!result.Ok)
            {
                return new ReleaseProbeCheck(name, ReleaseProbeSeverity.Fail, result.Code);
            }
            return new ReleaseProbeCheck(
                name,
                ReleaseProbeSeverity.Pass,
                "exit " + result.ExitCode.ToString(CultureInfo.InvariantCulture));
        }

        public static ReleaseProbeCheck CheckErrorStream(ReleaseProbeCommandResult result)
        {
            if (result != null && result.Ok && !string.IsNullOrEmpty(result.Error))
            {
                return new ReleaseProbeCheck(
                    "engine_stderr",
                    ReleaseProbeSeverity.Warn,
                    "error_output_present");
            }
            return new ReleaseProbeCheck("engine_stderr", ReleaseProbeSeverity.Pass, "empty");
        }

        public static ReleaseProbeCheck CheckVersion(bool parsed, string version)
        {
            if (!parsed || string.IsNullOrEmpty(version))
            {
                return new ReleaseProbeCheck(
                    "engine_version",
                    ReleaseProbeSeverity.Fail,
                    ReleaseProbeCodes.InvalidVersion);
            }
            return new ReleaseProbeCheck("engine_version", ReleaseProbeSeverity.Pass, version);
        }

        // Add the probe checks. A failed parse adds one failure and no invented
        // facts, so a malformed answer cannot look like a healthy probe.
        public static void AddProbeChecks(
            IList<ReleaseProbeCheck> checks,
            EngineProbeParseResult parse,
            bool administratorKnown,
            bool processAdministrator)
        {
            if (checks == null)
            {
                throw new ArgumentNullException("checks");
            }
            if (parse == null || !parse.Ok || parse.Facts == null)
            {
                checks.Add(new ReleaseProbeCheck(
                    "engine_probe",
                    ReleaseProbeSeverity.Fail,
                    parse == null ? ReleaseProbeCodes.MissingOutput : parse.Code));
                return;
            }

            EngineProbeFacts facts = parse.Facts;
            checks.Add(new ReleaseProbeCheck("engine_probe", ReleaseProbeSeverity.Pass, "parsed"));
            checks.Add(new ReleaseProbeCheck(
                "udp_ttl",
                facts.UdpTtl == ExpectedUdpTtl ? ReleaseProbeSeverity.Pass : ReleaseProbeSeverity.Fail,
                "observed " + facts.UdpTtl.ToString(CultureInfo.InvariantCulture)
                    + ", expected " + ExpectedUdpTtl.ToString(CultureInfo.InvariantCulture)));
            checks.Add(new ReleaseProbeCheck(
                "ttl_audit",
                facts.AuditFailures == 0 ? ReleaseProbeSeverity.Pass : ReleaseProbeSeverity.Fail,
                facts.AuditFailures.ToString(CultureInfo.InvariantCulture) + " failure(s)"));
            checks.Add(new ReleaseProbeCheck(
                "default_interface",
                !string.IsNullOrEmpty(facts.InterfaceName) && facts.InterfaceIndex >= 1
                    ? ReleaseProbeSeverity.Pass
                    : ReleaseProbeSeverity.Fail,
                facts.InterfaceIndex.ToString(CultureInfo.InvariantCulture)));

            if (!administratorKnown)
            {
                checks.Add(new ReleaseProbeCheck(
                    "administrator_agreement",
                    ReleaseProbeSeverity.Warn,
                    "process_elevation_unknown"));
            }
            else if (processAdministrator == facts.Administrator)
            {
                checks.Add(new ReleaseProbeCheck(
                    "administrator_agreement",
                    ReleaseProbeSeverity.Pass,
                    facts.Administrator ? "elevated" : "not_elevated"));
            }
            else
            {
                checks.Add(new ReleaseProbeCheck(
                    "administrator_agreement",
                    ReleaseProbeSeverity.Warn,
                    "elevation_mismatch"));
            }
        }

        public static ReleaseProbeVerdict Decide(IReadOnlyList<ReleaseProbeCheck> checks)
        {
            if (checks == null)
            {
                throw new ArgumentNullException("checks");
            }
            ReleaseProbeSeverity worst = ReleaseProbeSeverity.Pass;
            for (int index = 0; index < checks.Count; index++)
            {
                ReleaseProbeSeverity severity = checks[index].Severity;
                if (severity == ReleaseProbeSeverity.Fail)
                {
                    worst = ReleaseProbeSeverity.Fail;
                    break;
                }
                if (severity == ReleaseProbeSeverity.Warn)
                {
                    worst = ReleaseProbeSeverity.Warn;
                }
            }
            int exitCode = worst == ReleaseProbeSeverity.Fail
                ? ExitFail
                : (worst == ReleaseProbeSeverity.Warn ? ExitWarn : ExitPass);
            return new ReleaseProbeVerdict(checks, worst, exitCode);
        }

        private static bool IsHex64(string text)
        {
            if (text == null || text.Length != 64)
            {
                return false;
            }
            for (int index = 0; index < text.Length; index++)
            {
                char character = text[index];
                bool digit = character >= '0' && character <= '9';
                bool lower = character >= 'a' && character <= 'f';
                if (!digit && !lower)
                {
                    return false;
                }
            }
            return true;
        }
    }

    // One report. It holds no full path, no address, no token, and no key. The
    // engine is named by file name, length, and hash only.
    public sealed class ReleaseProbeReport
    {
        public const string Schema = "hotspotshade.windows.release-probe/1";

        public string GeneratedAtUtc { get; set; }

        public string OsDescription { get; set; }

        public string Architecture { get; set; }

        public bool Is64BitOperatingSystem { get; set; }

        public bool AdministratorKnown { get; set; }

        public bool ProcessAdministrator { get; set; }

        public string EngineFileName { get; set; }

        public long EngineLength { get; set; }

        public string EngineSha256 { get; set; }

        public string EngineVersion { get; set; }

        public EngineProbeFacts Probe { get; set; }

        public IReadOnlyList<ReleaseProbeCheck> Checks { get; set; }

        public ReleaseProbeVerdict Verdict { get; set; }
    }

    public static class ReleaseProbeText
    {
        public static string ResultWord(ReleaseProbeSeverity severity)
        {
            if (severity == ReleaseProbeSeverity.Pass)
            {
                return "PASS";
            }
            if (severity == ReleaseProbeSeverity.Warn)
            {
                return "WARN";
            }
            return "FAIL";
        }

        public static string Render(ReleaseProbeReport report)
        {
            if (report == null)
            {
                throw new ArgumentNullException("report");
            }
            ReleaseProbeVerdict verdict = report.Verdict;
            StringBuilder text = new StringBuilder();
            text.AppendLine("HotspotShade Windows release probe");
            text.AppendLine("Schema: " + ReleaseProbeReport.Schema);
            text.AppendLine("Generated UTC: " + (report.GeneratedAtUtc ?? ""));
            text.AppendLine("Host: " + (report.OsDescription ?? ""));
            text.AppendLine("Architecture: " + (report.Architecture ?? ""));
            text.AppendLine("64-bit operating system: " + YesNo(report.Is64BitOperatingSystem));
            text.AppendLine("Process administrator: "
                + (report.AdministratorKnown ? YesNo(report.ProcessAdministrator) : "unknown"));
            text.AppendLine("Engine file: " + (report.EngineFileName ?? ""));
            text.AppendLine("Engine bytes: " + report.EngineLength.ToString(CultureInfo.InvariantCulture));
            text.AppendLine("Engine SHA-256: "
                + (string.IsNullOrEmpty(report.EngineSha256) ? "none" : report.EngineSha256));
            text.AppendLine("Engine version: "
                + (string.IsNullOrEmpty(report.EngineVersion) ? "unknown" : report.EngineVersion));

            EngineProbeFacts facts = report.Probe;
            if (facts == null)
            {
                text.AppendLine("Probe administrator: unknown");
                text.AppendLine("Default interface: unknown");
                text.AppendLine("UDP TTL: unknown");
                text.AppendLine("TTL audit failures: unknown");
            }
            else
            {
                text.AppendLine("Probe administrator: " + YesNo(facts.Administrator));
                text.AppendLine("Default interface: " + facts.InterfaceName
                    + " (index " + facts.InterfaceIndex.ToString(CultureInfo.InvariantCulture) + ")");
                text.AppendLine("UDP TTL: " + facts.UdpTtl.ToString(CultureInfo.InvariantCulture)
                    + " (expected "
                    + ReleaseProbeEvaluation.ExpectedUdpTtl.ToString(CultureInfo.InvariantCulture) + ")");
                text.AppendLine("TTL audit failures: "
                    + facts.AuditFailures.ToString(CultureInfo.InvariantCulture));
            }

            text.AppendLine("Checks:");
            IReadOnlyList<ReleaseProbeCheck> checks = report.Checks;
            if (checks != null)
            {
                for (int index = 0; index < checks.Count; index++)
                {
                    ReleaseProbeCheck check = checks[index];
                    string line = "  " + ResultWord(check.Severity) + " " + check.Name;
                    if (!string.IsNullOrEmpty(check.Detail))
                    {
                        line += ": " + check.Detail;
                    }
                    text.AppendLine(line);
                }
            }

            if (verdict == null)
            {
                text.AppendLine("Result: FAIL (no verdict, exit 1)");
            }
            else
            {
                text.AppendLine("Result: " + ResultWord(verdict.Severity)
                    + " (exit " + verdict.ExitCode.ToString(CultureInfo.InvariantCulture) + ")");
            }
            return text.ToString();
        }

        private static string YesNo(bool value)
        {
            return value ? "yes" : "no";
        }
    }

    // A small deterministic JSON writer. It keeps ASCII, escapes control
    // characters, and writes fixed keys in a fixed order. It takes no
    // dependency.
    public static class ReleaseProbeJson
    {
        public static string Write(ReleaseProbeReport report)
        {
            if (report == null)
            {
                throw new ArgumentNullException("report");
            }
            StringBuilder json = new StringBuilder();
            json.Append("{");
            AppendString(json, "schema", ReleaseProbeReport.Schema);
            json.Append(",");
            AppendString(json, "generated_at_utc", report.GeneratedAtUtc);

            json.Append(",");
            json.Append("\"host\":{");
            AppendString(json, "os", report.OsDescription);
            json.Append(",");
            AppendString(json, "architecture", report.Architecture);
            json.Append(",");
            AppendBool(json, "is_64_bit", report.Is64BitOperatingSystem);
            json.Append(",");
            AppendBool(json, "administrator_known", report.AdministratorKnown);
            json.Append(",");
            AppendBool(json, "process_administrator", report.ProcessAdministrator);
            json.Append("}");

            json.Append(",");
            json.Append("\"engine\":{");
            AppendString(json, "file_name", report.EngineFileName);
            json.Append(",");
            AppendNumber(json, "length", report.EngineLength);
            json.Append(",");
            AppendString(json, "sha256", report.EngineSha256);
            json.Append(",");
            AppendString(json, "version", report.EngineVersion);
            json.Append("}");

            json.Append(",");
            if (report.Probe == null)
            {
                json.Append("\"probe\":null");
            }
            else
            {
                EngineProbeFacts facts = report.Probe;
                json.Append("\"probe\":{");
                AppendBool(json, "administrator", facts.Administrator);
                json.Append(",");
                AppendString(json, "interface", facts.InterfaceName);
                json.Append(",");
                AppendNumber(json, "interface_index", facts.InterfaceIndex);
                json.Append(",");
                AppendNumber(json, "udp_ttl", facts.UdpTtl);
                json.Append(",");
                AppendNumber(json, "audit_failures", facts.AuditFailures);
                json.Append("}");
            }

            json.Append(",");
            json.Append("\"checks\":[");
            IReadOnlyList<ReleaseProbeCheck> checks = report.Checks;
            if (checks != null)
            {
                for (int index = 0; index < checks.Count; index++)
                {
                    if (index > 0)
                    {
                        json.Append(",");
                    }
                    ReleaseProbeCheck check = checks[index];
                    json.Append("{");
                    AppendString(json, "name", check.Name);
                    json.Append(",");
                    AppendString(json, "result", ResultWord(check.Severity));
                    json.Append(",");
                    AppendString(json, "detail", check.Detail);
                    json.Append("}");
                }
            }
            json.Append("]");

            json.Append(",\"verdict\":{");
            ReleaseProbeVerdict verdict = report.Verdict;
            AppendString(json, "result", verdict == null
                ? "FAIL"
                : ReleaseProbeText.ResultWord(verdict.Severity));
            json.Append(",");
            AppendNumber(json, "exit_code", verdict == null ? 1 : verdict.ExitCode);
            json.Append("}");
            json.Append("}");
            json.Append("\n");
            return json.ToString();
        }

        private static string ResultWord(ReleaseProbeSeverity severity)
        {
            return ReleaseProbeText.ResultWord(severity);
        }

        private static void AppendKey(StringBuilder json, string key)
        {
            json.Append('"');
            json.Append(key);
            json.Append("\":");
        }

        private static void AppendString(StringBuilder json, string key, string value)
        {
            AppendKey(json, key);
            AppendValue(json, value);
        }

        private static void AppendValue(StringBuilder json, string value)
        {
            json.Append('"');
            if (value != null)
            {
                for (int index = 0; index < value.Length; index++)
                {
                    char character = value[index];
                    switch (character)
                    {
                        case '"':
                            json.Append("\\\"");
                            break;
                        case '\\':
                            json.Append("\\\\");
                            break;
                        case '\b':
                            json.Append("\\b");
                            break;
                        case '\f':
                            json.Append("\\f");
                            break;
                        case '\n':
                            json.Append("\\n");
                            break;
                        case '\r':
                            json.Append("\\r");
                            break;
                        case '\t':
                            json.Append("\\t");
                            break;
                        default:
                            if (character < 0x20 || character > 0x7E)
                            {
                                json.Append("\\u");
                                json.Append(((int)character).ToString("X4", CultureInfo.InvariantCulture));
                            }
                            else
                            {
                                json.Append(character);
                            }
                            break;
                    }
                }
            }
            json.Append('"');
        }

        private static void AppendBool(StringBuilder json, string key, bool value)
        {
            AppendKey(json, key);
            json.Append(value ? "true" : "false");
        }

        private static void AppendNumber(StringBuilder json, string key, long value)
        {
            AppendKey(json, key);
            json.Append(value.ToString(CultureInfo.InvariantCulture));
        }
    }
}
