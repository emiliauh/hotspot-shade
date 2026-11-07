using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Release;

namespace HotspotShade.WinUI2.ReleaseProbe
{
    internal static class Probe
    {
        private static readonly TimeSpan VersionTimeout = TimeSpan.FromSeconds(20);
        private static readonly TimeSpan ProbeTimeout = TimeSpan.FromSeconds(30);

        public static ReleaseProbeReport Run(ProgramOptions options, IEngineCommandRunner runner)
        {
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }
            if (runner == null)
            {
                throw new ArgumentNullException("runner");
            }

            bool windows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
            bool is64Bit = Environment.Is64BitOperatingSystem;
            string architecture = RuntimeInformation.ProcessArchitecture.ToString();
            string osDescription = HostFacts.Sanitize(RuntimeInformation.OSDescription, 128);

            bool administratorKnown = HostFacts.TryIsAdministrator(out bool administrator);

            List<ReleaseProbeCheck> checks = new List<ReleaseProbeCheck>();
            checks.AddRange(ReleaseProbeEvaluation.CheckHost(windows, is64Bit, architecture));

            bool exists = File.Exists(options.EnginePath);
            long length = 0;
            string sha256 = "";
            if (exists)
            {
                try
                {
                    length = new FileInfo(options.EnginePath).Length;
                }
                catch (Exception)
                {
                    length = 0;
                }
                string hash = HostFacts.Sha256(options.EnginePath);
                sha256 = hash ?? "";
            }
            checks.Add(ReleaseProbeEvaluation.CheckEngine(exists, length, sha256));

            string version = "";
            EngineProbeParseResult parse = null;

            if (!exists)
            {
                checks.Add(new ReleaseProbeCheck(
                    "engine_commands",
                    ReleaseProbeSeverity.Warn,
                    "skipped_engine_missing"));
                ReleaseProbeEvaluation.AddProbeChecks(
                    checks,
                    null,
                    administratorKnown,
                    administrator);
            }
            else
            {
                ReleaseProbeCommandResult versionResult = runner.Run(
                    options.EnginePath,
                    ReleaseProbeCommandPolicy.VersionArgument,
                    VersionTimeout);
                checks.Add(ReleaseProbeEvaluation.CheckCommand(
                    "version_command",
                    versionResult));
                checks.Add(ReleaseProbeEvaluation.CheckErrorStream(versionResult));

                string parsedVersion = "";
                bool versionParsed = versionResult.Ok
                    && EngineVersionOutput.TryParse(versionResult.Output, out parsedVersion);
                if (versionParsed)
                {
                    version = parsedVersion;
                }
                checks.Add(ReleaseProbeEvaluation.CheckVersion(versionParsed, version));

                ReleaseProbeCommandResult probeResult = runner.Run(
                    options.EnginePath,
                    ReleaseProbeCommandPolicy.ProbeArgument,
                    ProbeTimeout);
                checks.Add(ReleaseProbeEvaluation.CheckCommand(
                    "probe_command",
                    probeResult));
                if (probeResult.Ok)
                {
                    parse = EngineProbeOutput.Parse(probeResult.Output);
                }
                ReleaseProbeEvaluation.AddProbeChecks(
                    checks,
                    parse,
                    administratorKnown,
                    administrator);
            }

            ReleaseProbeVerdict verdict = ReleaseProbeEvaluation.Decide(checks);
            return new ReleaseProbeReport
            {
                GeneratedAtUtc = DateTime.UtcNow.ToString(
                    "yyyy-MM-ddTHH:mm:ssZ",
                    CultureInfo.InvariantCulture),
                OsDescription = osDescription,
                Architecture = HostFacts.Sanitize(architecture, 32),
                Is64BitOperatingSystem = is64Bit,
                AdministratorKnown = administratorKnown,
                ProcessAdministrator = administrator,
                EngineFileName = Path.GetFileName(options.EnginePath) ?? "",
                EngineLength = length,
                EngineSha256 = sha256,
                EngineVersion = version,
                Probe = parse == null ? null : parse.Facts,
                Checks = checks,
                Verdict = verdict
            };
        }
    }
}
