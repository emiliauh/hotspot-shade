using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using HotspotShade.WinUI2.Core.App;

namespace HotspotShade.WinUI2.Core.Tests
{
    // Checks for the broker startup log: the line shape, the sanitizing, the
    // line and byte bounds, the plain text table, and the source contract
    // that every broker exit is logged. Nothing here writes a real file.
    internal static class BrokerLogTests
    {
        private static readonly DateTime Stamp = new DateTime(2026, 11, 7, 1, 2, 3, DateTimeKind.Utc);

        public static void Run(TestRunner runner)
        {
            runner.Check("broker log: the formatter emits the fixed line and refuses odd values", delegate
            {
                string line = BrokerLogFormat.Format(
                    Stamp,
                    BrokerLogStages.Connect,
                    BrokerLogCodes.NotRetryable,
                    "Unknown",
                    3,
                    5,
                    -2147024891);
                AssertEx.Equal(
                    "2026-11-07T01:02:03Z stage=connect code=not_retryable status=Unknown attempt=3 win32=5 hresult=0x80070005",
                    line,
                    "line shape");
                AssertEx.True(Allowed(line), "only log characters");
                AssertEx.DoesNotContain(line, "\n", "one line");

                string dirty = BrokerLogFormat.Format(
                    Stamp,
                    "C:\\Users\\owner",
                    "token=abc",
                    "Bad Value",
                    -4,
                    -9,
                    null);
                AssertEx.Equal(
                    "2026-11-07T01:02:03Z stage=unknown code=unknown status=unknown attempt=0 win32=0",
                    dirty,
                    "odd values become fixed words or zero");
                AssertEx.DoesNotContain(dirty, "\\", "no path separator");
                AssertEx.DoesNotContain(dirty, "/", "no path separator");
                AssertEx.DoesNotContain(dirty, "\"", "no quote");
                AssertEx.DoesNotContain(dirty, "Users", "no path text");
                AssertEx.DoesNotContain(dirty, "token=abc", "no value set text");
                AssertEx.True(Allowed(dirty), "only log characters");
            });

            runner.Check("broker log: the bound keeps 200 lines and 16 KB", delegate
            {
                List<string> many = new List<string>();
                for (int index = 0; index < 500; index++)
                {
                    many.Add("line " + index.ToString(CultureInfo.InvariantCulture));
                }
                IList<string> bounded = BrokerLogFormat.Bound(many);
                AssertEx.True(bounded.Count <= BrokerLogFormat.MaxLines, "line bound");
                AssertEx.Equal("line 499", bounded[bounded.Count - 1], "newest line kept");
                AssertEx.True(bounded[0] != "line 0", "oldest line dropped");
                AssertEx.True(Bytes(bounded) <= BrokerLogFormat.MaxBytes, "byte bound");

                List<string> wide = new List<string>();
                for (int index = 0; index < 400; index++)
                {
                    wide.Add(new string('x', 200));
                }
                IList<string> narrow = BrokerLogFormat.Bound(wide);
                AssertEx.True(Bytes(narrow) <= BrokerLogFormat.MaxBytes, "wide byte bound");
                AssertEx.True(narrow.Count > 0, "wide lines keep a tail");

                List<string> one = new List<string>();
                one.Add(new string('x', BrokerLogFormat.MaxBytes + 10));
                AssertEx.Equal(0, BrokerLogFormat.Bound(one).Count, "one oversized line is dropped");
            });

            runner.Check("broker log: the parser finds the last stage and the exit code", delegate
            {
                List<string> lines = new List<string>();
                lines.Add(BrokerLogFormat.Format(Stamp, BrokerLogStages.Main, BrokerLogCodes.Entry, null, 0, null, null));
                lines.Add(BrokerLogFormat.Format(Stamp, BrokerLogStages.Connect, BrokerLogCodes.NotRetryable, "Unknown", 3, null, null));
                lines.Add(BrokerLogFormat.Format(Stamp, BrokerLogStages.Exit, BrokerLogCodes.ExitCode, null, 4, null, null));

                BrokerLogEntry entry;
                AssertEx.True(BrokerLogFormat.TryParse(lines[1], out entry), "parse one line");
                AssertEx.Equal(BrokerLogStages.Connect, entry.Stage, "stage");
                AssertEx.Equal(BrokerLogCodes.NotRetryable, entry.Code, "code");
                AssertEx.Equal("Unknown", entry.Status, "status");
                AssertEx.True(entry.Attempt == 3, "attempt");
                AssertEx.False(BrokerLogFormat.TryParse("not a log line", out entry), "malformed line");

                BrokerLogSnapshot snapshot = BrokerLogFormat.Snapshot(lines);
                AssertEx.Equal(3, snapshot.Lines.Count, "tail");
                AssertEx.Equal(BrokerLogStages.Connect, snapshot.Last.Stage, "last stage skips exit");
                AssertEx.Equal(BrokerLogCodes.NotRetryable, snapshot.Last.Code, "last code");
                AssertEx.True(snapshot.LastExit.Attempt == 4, "last exit code");

                List<string> nextRun = new List<string>();
                nextRun.Add(BrokerLogFormat.Format(Stamp, BrokerLogStages.Exit, BrokerLogCodes.ExitCode, null, 0, null, null));
                nextRun.Add(BrokerLogFormat.Format(Stamp, BrokerLogStages.Main, BrokerLogCodes.Entry, null, 0, null, null));
                AssertEx.True(BrokerLogFormat.Snapshot(nextRun).LastExit == null, "an older exit is not paired with a newer entry");
            });

            runner.Check("broker log: the plain text table maps known words and shows unknown", delegate
            {
                List<string> lines = new List<string>();
                lines.Add(BrokerLogFormat.Format(Stamp, BrokerLogStages.Connect, BrokerLogCodes.NotRetryable, "Unknown", 3, null, null));
                lines.Add(BrokerLogFormat.Format(Stamp, BrokerLogStages.Exit, BrokerLogCodes.ExitCode, null, 4, null, null));
                AssertEx.Equal(
                    "The engine helper stopped at app service connect (status Unknown, exit 4).",
                    BrokerLogText.StopLine(BrokerLogFormat.Snapshot(lines)),
                    "known line");
                AssertEx.Equal(
                    "app service connect",
                    BrokerLogText.StageCodePhrase(BrokerLogStages.Connect, BrokerLogCodes.NotRetryable),
                    "stage pair");
                AssertEx.Equal(
                    "could not connect",
                    BrokerLogText.CodePhrase(BrokerLogCodes.NotRetryable),
                    "code phrase");

                List<string> unknown = new List<string>();
                unknown.Add(BrokerLogFormat.Format(Stamp, "mystery", "mystery_code", null, 9, null, null));
                string text = BrokerLogText.StopLine(BrokerLogFormat.Snapshot(unknown));
                AssertEx.Contains(text, "unknown", "unknown words are named");
                AssertEx.False(BrokerLogText.StageCodePhrase("mystery", BrokerLogCodes.NotRetryable) != "unknown", "unknown stage");
                AssertEx.False(BrokerLogText.StageCodePhrase(BrokerLogStages.Connect, "mystery_code") != "unknown", "unknown code");
                AssertEx.False(BrokerLogText.CodePhrase("mystery_code") != "unknown", "unknown code text");
            });

            runner.Check("broker log: the writer shares the file, bounds it, and has a fallback", delegate
            {
                string root = FindWindowsRoot();
                AssertEx.True(root != null, "windows root");
                string source = SourceText.Read(Path.Combine(
                    root,
                    "src",
                    "HotspotShade.WinUI2.Broker",
                    "BrokerLog.cs"));
                AssertEx.Contains(source, "FileShare.ReadWrite", "the reader can read while the broker writes");
                AssertEx.Contains(source, "FileMode.OpenOrCreate", "one append file");
                AssertEx.Contains(source, "BrokerLogFormat.Bound(lines)", "bounded rewrite");
                AssertEx.Contains(source, "ApplicationData.Current.LocalFolder", "package local folder first");
                AssertEx.Contains(source, "HotspotShade", "plain local fallback");
                AssertEx.Contains(source, "catch (Exception)", "every write is guarded");

                string reader = SourceText.Read(Path.Combine(
                    root,
                    "src",
                    "HotspotShade.WinUI2",
                    "Services",
                    "BrokerLogReader.cs"));
                AssertEx.Contains(reader, "ApplicationData.Current.LocalFolder", "the window reads the same folder");
                AssertEx.Contains(reader, "FileShare.ReadWrite", "the reader shares the writer");
                AssertEx.Contains(reader, "BrokerLogSnapshot.Empty", "a missing file is empty");
            });

            runner.Check("broker log: every broker Main return path logs its exit code", delegate
            {
                string root = FindWindowsRoot();
                AssertEx.True(root != null, "windows root");
                string runtime = SourceText.Read(Path.Combine(
                    root,
                    "src",
                    "HotspotShade.WinUI2.Broker",
                    "BrokerRuntime.cs"));
                int at = runtime.IndexOf("private static int Main(string[] args)", StringComparison.Ordinal);
                AssertEx.True(at >= 0, "Main exists");
                string main = runtime.Substring(at);
                AssertEx.Contains(main, "BrokerLogStages.Main", "entry is logged");
                AssertEx.Contains(main, "BrokerLogCodes.Entry", "entry code");
                AssertEx.Contains(main, "BrokerLogStages.Exit", "exit is logged");
                AssertEx.Contains(main, "BrokerLogCodes.ExitCode", "exit code word");
                AssertEx.Contains(main, "return exitCode;", "one return");
                AssertEx.DoesNotContain(main, "return 0;", "no unlogged return 0");
                AssertEx.DoesNotContain(main, "return 1;", "no unlogged return 1");
                AssertEx.DoesNotContain(main, "return 2;", "no unlogged return 2");
                AssertEx.DoesNotContain(main, "return 3;", "no unlogged return 3");
                AssertEx.DoesNotContain(main, "return 4;", "no unlogged return 4");
                int exitAt = main.IndexOf("BrokerLogStages.Exit", StringComparison.Ordinal);
                int returnAt = main.IndexOf("return exitCode;", StringComparison.Ordinal);
                AssertEx.True(exitAt >= 0 && returnAt > exitAt, "the exit is logged before the return");
            });
        }

        private static bool Allowed(string line)
        {
            for (int index = 0; index < line.Length; index++)
            {
                char letter = line[index];
                bool known = (letter >= 'a' && letter <= 'z')
                    || (letter >= 'A' && letter <= 'Z')
                    || (letter >= '0' && letter <= '9')
                    || letter == ' '
                    || letter == '='
                    || letter == ':'
                    || letter == '-'
                    || letter == '.'
                    || letter == '_';
                if (!known)
                {
                    return false;
                }
            }
            return true;
        }

        private static int Bytes(IList<string> lines)        {
            int bytes = 0;
            for (int index = 0; index < lines.Count; index++)
            {
                bytes += Encoding.UTF8.GetByteCount(lines[index]) + 1;
            }
            return bytes;
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
