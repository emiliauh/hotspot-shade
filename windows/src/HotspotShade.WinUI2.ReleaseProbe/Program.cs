using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Release;

namespace HotspotShade.WinUI2.ReleaseProbe
{
    internal sealed class ProgramOptions
    {
        public const int ExitUsage = 3;
        public const int ExitHarness = 4;

        public const string Usage =
            "Usage: HotspotShade.WinUI2.ReleaseProbe [--engine PATH] [--json] [--out PATH]\n"
            + "\n"
            + "Runs two read-only engine commands, --version and probe, and writes a report.\n"
            + "It creates no adapter, route, tunnel, or credential.\n"
            + "The engine path must be absolute and end in hotspotshade.exe. The default is\n"
            + "hotspotshade.exe next to this program.\n"
            + "Exit codes: 0 pass, 2 warning, 1 failure, 3 usage, 4 harness error.\n";

        private ProgramOptions()
        {
        }

        public string EnginePath { get; private set; }

        public bool Json { get; private set; }

        public string OutPath { get; private set; }

        public bool Help { get; private set; }

        public static bool TryParse(string[] args, out ProgramOptions options, out string error)
        {
            options = null;
            error = "";
            string engine = null;
            string outPath = null;
            bool json = false;
            bool help = false;

            if (args != null)
            {
                for (int index = 0; index < args.Length; index++)
                {
                    string argument = args[index];
                    if (string.Equals(argument, "--help", StringComparison.Ordinal)
                        || string.Equals(argument, "-h", StringComparison.Ordinal))
                    {
                        help = true;
                    }
                    else if (string.Equals(argument, "--json", StringComparison.Ordinal))
                    {
                        json = true;
                    }
                    else if (string.Equals(argument, "--engine", StringComparison.Ordinal))
                    {
                        if (index + 1 >= args.Length || string.IsNullOrEmpty(args[index + 1]))
                        {
                            error = "missing value for --engine";
                            return false;
                        }
                        engine = args[++index];
                    }
                    else if (string.Equals(argument, "--out", StringComparison.Ordinal))
                    {
                        if (index + 1 >= args.Length || string.IsNullOrEmpty(args[index + 1]))
                        {
                            error = "missing value for --out";
                            return false;
                        }
                        outPath = args[++index];
                    }
                    else
                    {
                        error = "unknown argument";
                        return false;
                    }
                }
            }

            string path = engine;
            if (path == null)
            {
                path = Path.Combine(
                    AppContext.BaseDirectory,
                    ReleaseProbeEvaluation.ExpectedEngineFileName);
            }
            if (!IsAcceptablePath(path, out error))
            {
                return false;
            }
            if (!string.IsNullOrEmpty(outPath))
            {
                try
                {
                    string fullOut = Path.GetFullPath(outPath);
                    string fullEngine = Path.GetFullPath(path);
                    StringComparison comparison = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                        ? StringComparison.OrdinalIgnoreCase
                        : StringComparison.Ordinal;
                    if (string.Equals(fullOut, fullEngine, comparison))
                    {
                        error = "the report path must not be the engine path";
                        return false;
                    }
                }
                catch (Exception)
                {
                    error = "invalid report path";
                    return false;
                }
            }

            options = new ProgramOptions
            {
                EnginePath = path,
                Json = json,
                OutPath = outPath,
                Help = help
            };
            return true;
        }

        // The Windows rule is the fixed engine rule: an absolute path with no
        // dot segment and the exact engine name. The same checks run on a
        // non-Windows host for a local plumbing check, with the host path rule.
        private static bool IsAcceptablePath(string path, out string error)
        {
            error = "";
            if (string.IsNullOrEmpty(path)
                || path.IndexOf('"') >= 0
                || !EngineLaunchRules.IsExecutableName(path)
                || EngineLaunchRules.HasTraversal(path))
            {
                error = "the engine path must be absolute and end in "
                    + ReleaseProbeEvaluation.ExpectedEngineFileName;
                return false;
            }
            bool windows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
            bool absolute = windows
                ? EngineLaunchRules.IsAbsolutePath(path)
                : Path.IsPathRooted(path);
            if (!absolute)
            {
                error = "the engine path must be absolute";
                return false;
            }
            return true;
        }
    }

    internal static class Program
    {
        private static int Main(string[] args)
        {
            ProgramOptions options;
            string error;
            if (!ProgramOptions.TryParse(args, out options, out error))
            {
                if (!string.IsNullOrEmpty(error))
                {
                    Console.Error.WriteLine("release probe: " + error);
                }
                Console.Error.WriteLine(ProgramOptions.Usage);
                return ProgramOptions.ExitUsage;
            }
            if (options.Help)
            {
                Console.WriteLine(ProgramOptions.Usage);
                return 0;
            }

            try
            {
                ReleaseProbeReport report = Probe.Run(
                    options,
                    new ProcessEngineCommandRunner());
                string json = ReleaseProbeJson.Write(report);
                if (!string.IsNullOrEmpty(options.OutPath))
                {
                    File.WriteAllText(options.OutPath, json, new UTF8Encoding(false));
                }
                Console.Write(options.Json ? json : ReleaseProbeText.Render(report));
                return report.Verdict == null
                    ? ReleaseProbeEvaluation.ExitFail
                    : report.Verdict.ExitCode;
            }
            catch (Exception failure)
            {
                // Do not print the exception text. It can hold a path.
                Console.Error.WriteLine(
                    "release probe: internal error (" + failure.GetType().Name + ")");
                return ProgramOptions.ExitHarness;
            }
        }
    }
}
