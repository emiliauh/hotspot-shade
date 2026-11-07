using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using HotspotShade.WinUI2.Core.Engine.Release;

namespace HotspotShade.WinUI2.ReleaseProbe
{
    // The only two read-only engine commands that the release probe may run.
    // Any other value is refused before a process starts.
    internal interface IEngineCommandRunner
    {
        ReleaseProbeCommandResult Run(string enginePath, string argument, TimeSpan timeout);
    }

    // Runs one read-only engine command with a fixed argument, no shell, no
    // inherited project variable, and a bounded answer. This is the only place
    // in the windows tree that starts the engine. It never runs a tunnel
    // command, never passes a token, and never sets an environment variable.
    internal sealed class ProcessEngineCommandRunner : IEngineCommandRunner
    {
        private const int MaximumOutputCharacters = 16384;
        private const int DrainMilliseconds = 5000;

        public ReleaseProbeCommandResult Run(string enginePath, string argument, TimeSpan timeout)
        {
            if (!ReleaseProbeCommandPolicy.IsAllowed(argument) || string.IsNullOrEmpty(enginePath))
            {
                return ReleaseProbeCommandResult.Failure(
                    ReleaseProbeCodes.UnsupportedCommand,
                    -1);
            }
            if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromSeconds(60))
            {
                return ReleaseProbeCommandResult.Failure(
                    ReleaseProbeCodes.Timeout,
                    -1);
            }

            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.FileName = enginePath;
            startInfo.ArgumentList.Add(argument);
            startInfo.UseShellExecute = false;
            startInfo.CreateNoWindow = true;
            startInfo.RedirectStandardInput = false;
            startInfo.RedirectStandardOutput = true;
            startInfo.RedirectStandardError = true;
            startInfo.StandardOutputEncoding = Encoding.UTF8;
            startInfo.StandardErrorEncoding = Encoding.UTF8;
            startInfo.WorkingDirectory = Path.GetDirectoryName(enginePath) ?? ".";
            // Remove any inherited project variable, including a source device
            // token. The rest of the environment stays usable for the engine.
            SanitizeEnvironment(startInfo.Environment);

            using (Process process = new Process())
            {
                process.StartInfo = startInfo;
                try
                {
                    if (!process.Start())
                    {
                        return ReleaseProbeCommandResult.Failure(
                            ReleaseProbeCodes.StartFailed,
                            -1);
                    }
                }
                catch (Exception)
                {
                    return ReleaseProbeCommandResult.Failure(
                        ReleaseProbeCodes.StartFailed,
                        -1);
                }

                Task<BoundedText> output = ReadBoundedAsync(process.StandardOutput);
                Task<BoundedText> error = ReadBoundedAsync(process.StandardError);

                bool exited;
                try
                {
                    exited = process.WaitForExit((int)Math.Min(
                        int.MaxValue,
                        Math.Max(1D, timeout.TotalMilliseconds)));
                }
                catch (Exception)
                {
                    exited = false;
                }

                if (!exited)
                {
                    // The probe command only reads a local option. Killing it
                    // cannot interrupt a tunnel or a cleanup path.
                    try
                    {
                        process.Kill(true);
                    }
                    catch (Exception)
                    {
                    }
                    try
                    {
                        process.WaitForExit(2000);
                    }
                    catch (Exception)
                    {
                    }
                    try
                    {
                        Task.WaitAll(new Task[] { output, error }, 2000);
                    }
                    catch (Exception)
                    {
                    }
                    return ReleaseProbeCommandResult.Failure(ReleaseProbeCodes.Timeout, -1);
                }

                BoundedText standardOutput;
                BoundedText standardError;
                try
                {
                    Task.WaitAll(new Task[] { output, error }, DrainMilliseconds);
                    standardOutput = output.Status == TaskStatus.RanToCompletion
                        ? output.Result
                        : BoundedText.Empty;
                    standardError = error.Status == TaskStatus.RanToCompletion
                        ? error.Result
                        : BoundedText.Empty;
                }
                catch (Exception)
                {
                    return ReleaseProbeCommandResult.Failure(
                        ReleaseProbeCodes.StartFailed,
                        process.ExitCode);
                }

                if (standardOutput.TooLarge)
                {
                    return ReleaseProbeCommandResult.Failure(
                        ReleaseProbeCodes.OutputTooLarge,
                        process.ExitCode);
                }
                if (process.ExitCode != 0)
                {
                    return ReleaseProbeCommandResult.Failure(
                        ReleaseProbeCodes.ExitNonZero,
                        process.ExitCode);
                }
                return ReleaseProbeCommandResult.Success(
                    process.ExitCode,
                    standardOutput.Text,
                    standardError.Text);
            }
        }

        // Remove every environment name that belongs to this project. A token
        // or engine override in the caller's shell must not reach the child.
        private static void SanitizeEnvironment(
            System.Collections.Generic.IDictionary<string, string> environment)
        {
            if (environment == null)
            {
                return;
            }
            System.Collections.Generic.List<string> remove =
                new System.Collections.Generic.List<string>();
            foreach (System.Collections.Generic.KeyValuePair<string, string> pair in environment)
            {
                if (pair.Key != null
                    && pair.Key.StartsWith("HOTSPOTSHADE_", StringComparison.OrdinalIgnoreCase))
                {
                    remove.Add(pair.Key);
                }
            }
            for (int index = 0; index < remove.Count; index++)
            {
                environment.Remove(remove[index]);
            }
        }

        private static async Task<BoundedText> ReadBoundedAsync(StreamReader reader)
        {
            StringBuilder text = new StringBuilder();
            char[] buffer = new char[2048];
            bool tooLarge = false;
            while (true)
            {
                int read = await reader.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
                if (read <= 0)
                {
                    break;
                }
                if (text.Length + read <= MaximumOutputCharacters)
                {
                    text.Append(buffer, 0, read);
                }
                else
                {
                    tooLarge = true;
                }
            }
            return new BoundedText(text.ToString(), tooLarge);
        }

        private sealed class BoundedText
        {
            public static readonly BoundedText Empty = new BoundedText("", false);

            public BoundedText(string text, bool tooLarge)
            {
                Text = text ?? "";
                TooLarge = tooLarge;
            }

            public string Text { get; private set; }

            public bool TooLarge { get; private set; }
        }
    }
}
