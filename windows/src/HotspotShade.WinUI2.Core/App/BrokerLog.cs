using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace HotspotShade.WinUI2.Core.App
{
    // The fixed words of the broker startup log. A stage or code outside this
    // list is written as "unknown", so a path, a port, a handle, a token, or
    // user data can never reach the log through a value.
    public static class BrokerLogStages
    {
        public const string Main = "main";
        public const string Package = "package";
        public const string Lease = "lease";
        public const string EngineStart = "engine_start";
        public const string ElevatedStart = "elevated_start";
        public const string Connect = "connect";
        public const string Hello = "hello";
        public const string Transport = "transport";
        public const string Shutdown = "shutdown";
        public const string Fatal = "fatal";
        public const string Exit = "exit";
    }

    public static class BrokerLogCodes
    {
        public const string Entry = "entry";
        public const string BadArgs = "bad_args";
        public const string ArgsIgnored = "args_ignored";
        public const string NoPackage = "no_package";
        public const string PackageOk = "package_ok";
        public const string LeaseOwned = "owned";
        public const string LeaseHeld = "held";
        public const string StartOk = "ok";
        public const string StartFailed = "failed";
        public const string CreateOk = "create_ok";
        public const string CreateFailed = "create_failed";
        public const string ShellFailed = "shell_failed";
        public const string Attempt = "attempt";
        public const string Connected = "connected";
        public const string NotRetryable = "not_retryable";
        public const string RetryExhausted = "retry_exhausted";
        public const string OpenException = "open_exception";
        public const string ConnectException = "exception";
        public const string HelloReceived = "received";
        public const string HelloTimeout = "timeout";
        public const string TransportClosed = "closed";
        public const string ClosedBeforeHello = "closed_before_hello";
        public const string WindowExited = "window_exited";
        public const string ConnectFailed = "connect_failed";
        public const string ShutdownBegin = "begin";
        public const string ShutdownEnd = "end";
        public const string ExitCode = "exit";
        public const string Unhandled = "unhandled";
    }

    // One parsed broker log line. The values are fixed words and numbers.
    public sealed class BrokerLogEntry
    {
        public string Stage { get; set; }
        public string Code { get; set; }
        public string Status { get; set; }
        public int? Attempt { get; set; }
        public int? Win32 { get; set; }
        public int? HResult { get; set; }
    }

    // The tail of the broker log, the last start point, and the last exit code.
    public sealed class BrokerLogSnapshot
    {
        public static readonly BrokerLogSnapshot Empty = new BrokerLogSnapshot(
            new List<string>(),
            null,
            null);

        public BrokerLogSnapshot(IList<string> lines, BrokerLogEntry last, BrokerLogEntry lastExit)
        {
            Lines = lines ?? new List<string>();
            Last = last;
            LastExit = lastExit;
        }

        public IList<string> Lines { get; private set; }

        // The last line outside the exit stage, or null.
        public BrokerLogEntry Last { get; private set; }

        // The last line with the exit stage, or null.
        public BrokerLogEntry LastExit { get; private set; }
    }

    // The one line shape:
    // <UTC ISO time> stage=<word> code=<word> [status=<name>]
    // [attempt=<n>] [win32=<n>] [hresult=0x<hex>]
    //
    // The formatter also bounds a log to 200 lines and 16 KB. The broker
    // writes it, the window reads it, and the checks exercise both sides.
    public static class BrokerLogFormat
    {
        public const string FileName = "broker.log";
        public const int MaxLines = 200;
        public const int MaxBytes = 16 * 1024;
        public const int MaxWordChars = 32;
        public const int MaxStatusChars = 64;

        private static readonly UTF8Encoding Utf8 = new UTF8Encoding(false);

        public static string Format(
            DateTime utc,
            string stage,
            string code,
            string status,
            int? attempt,
            int? win32,
            int? hresult)
        {
            StringBuilder text = new StringBuilder(96);
            text.Append(utc.ToUniversalTime().ToString(
                "yyyy-MM-dd'T'HH:mm:ss'Z'",
                CultureInfo.InvariantCulture));
            text.Append(" stage=");
            text.Append(Word(stage));
            text.Append(" code=");
            text.Append(Word(code));
            if (!string.IsNullOrEmpty(status))
            {
                text.Append(" status=");
                text.Append(Status(status));
            }
            if (attempt.HasValue)
            {
                text.Append(" attempt=");
                text.Append(Number(attempt.Value));
            }
            if (win32.HasValue)
            {
                text.Append(" win32=");
                text.Append(Number(win32.Value));
            }
            if (hresult.HasValue)
            {
                text.Append(" hresult=0x");
                text.Append(((uint)hresult.Value).ToString("X8", CultureInfo.InvariantCulture));
            }
            return text.ToString();
        }

        // A stage or code word. Lower-case letters, digits, and underscores
        // only, and never longer than MaxWordChars.
        public static string Word(string value)
        {
            if (string.IsNullOrEmpty(value) || value.Length > MaxWordChars)
            {
                return "unknown";
            }
            for (int index = 0; index < value.Length; index++)
            {
                char letter = value[index];
                bool start = letter >= 'a' && letter <= 'z';
                bool rest = start || (letter >= '0' && letter <= '9') || letter == '_';
                if (index == 0 ? !start : !rest)
                {
                    return "unknown";
                }
            }
            return value;
        }

        // An enum name or an exception type name. Letters, digits, and
        // underscores only, with the original case.
        public static string Status(string value)
        {
            if (string.IsNullOrEmpty(value) || value.Length > MaxStatusChars)
            {
                return "unknown";
            }
            for (int index = 0; index < value.Length; index++)
            {
                char letter = value[index];
                bool first = (letter >= 'A' && letter <= 'Z') || (letter >= 'a' && letter <= 'z');
                bool rest = first || (letter >= '0' && letter <= '9') || letter == '_';
                if (index == 0 ? !first : !rest)
                {
                    return "unknown";
                }
            }
            return value;
        }

        public static string ExceptionName(Exception error)
        {
            return error == null ? null : Status(error.GetType().Name);
        }

        public static string Number(int value)
        {
            if (value < 0)
            {
                value = 0;
            }
            if (value > 999999)
            {
                value = 999999;
            }
            return value.ToString(CultureInfo.InvariantCulture);
        }

        public static bool TryParse(string line, out BrokerLogEntry entry)
        {
            entry = null;
            if (string.IsNullOrEmpty(line) || line.Length > 512)
            {
                return false;
            }
            string[] parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 3 || parts[0].IndexOf('T') < 0)
            {
                return false;
            }
            BrokerLogEntry parsed = new BrokerLogEntry();
            for (int index = 1; index < parts.Length; index++)
            {
                int at = parts[index].IndexOf('=');
                if (at <= 0 || at == parts[index].Length - 1)
                {
                    return false;
                }
                string key = parts[index].Substring(0, at);
                string value = parts[index].Substring(at + 1);
                int number;
                switch (key)
                {
                    case "stage":
                        parsed.Stage = value;
                        break;
                    case "code":
                        parsed.Code = value;
                        break;
                    case "status":
                        parsed.Status = value;
                        break;
                    case "attempt":
                        if (!TryNumber(value, out number))
                        {
                            return false;
                        }
                        parsed.Attempt = number;
                        break;
                    case "win32":
                        if (!TryNumber(value, out number))
                        {
                            return false;
                        }
                        parsed.Win32 = number;
                        break;
                    case "hresult":
                        if (value.Length != 10 || value[0] != '0' || (value[1] != 'x' && value[1] != 'X'))
                        {
                            return false;
                        }
                        uint result;
                        if (!uint.TryParse(value.Substring(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out result))
                        {
                            return false;
                        }
                        parsed.HResult = unchecked((int)result);
                        break;
                    default:
                        return false;
                }
            }
            if (string.IsNullOrEmpty(parsed.Stage) || string.IsNullOrEmpty(parsed.Code))
            {
                return false;
            }
            entry = parsed;
            return true;
        }

        public static BrokerLogSnapshot Snapshot(IList<string> lines)
        {
            List<string> tail = new List<string>();
            BrokerLogEntry last = null;
            BrokerLogEntry lastExit = null;
            int lastIndex = -1;
            int lastExitIndex = -1;
            if (lines != null)
            {
                for (int index = 0; index < lines.Count; index++)
                {
                    string line = lines[index];
                    if (string.IsNullOrEmpty(line))
                    {
                        continue;
                    }
                    tail.Add(line);
                    BrokerLogEntry entry;
                    if (!TryParse(line, out entry))
                    {
                        continue;
                    }
                    if (entry.Stage == BrokerLogStages.Exit)
                    {
                        lastExit = entry;
                        lastExitIndex = index;
                    }
                    else
                    {
                        last = entry;
                        lastIndex = index;
                    }
                }
            }
            // An exit from an older run says nothing about the current one.
            if (lastExitIndex < lastIndex)
            {
                lastExit = null;
            }
            return new BrokerLogSnapshot(tail, last, lastExit);
        }

        public static IList<string> LastLines(IList<string> lines, int maxLines)
        {
            List<string> tail = new List<string>();
            if (lines == null || maxLines <= 0)
            {
                return tail;
            }
            int start = Math.Max(0, lines.Count - maxLines);
            for (int index = start; index < lines.Count; index++)
            {
                if (!string.IsNullOrEmpty(lines[index]))
                {
                    tail.Add(lines[index]);
                }
            }
            return tail;
        }

        // Keep the newest lines inside both bounds. A working file stays
        // small, so every read and every rewrite is bounded.
        public static IList<string> Bound(IList<string> lines)
        {
            List<string> tail = new List<string>();
            if (lines == null || lines.Count == 0)
            {
                return tail;
            }
            int bytes = 0;
            for (int index = lines.Count - 1; index >= 0; index--)
            {
                string line = lines[index];
                if (line == null)
                {
                    continue;
                }
                int size = Utf8.GetByteCount(line) + 1;
                if (tail.Count >= MaxLines || bytes + size > MaxBytes)
                {
                    break;
                }
                bytes += size;
                tail.Add(line);
            }
            tail.Reverse();
            return tail;
        }

        private static bool TryNumber(string text, out int value)
        {
            return int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out value);
        }
    }

    // One plain sentence for the last broker log point. The table uses only
    // known stage and code words. Any unknown word becomes "unknown".
    public static class BrokerLogText
    {
        public static string StageCodePhrase(string stage, string code)
        {
            switch (stage)
            {
                case BrokerLogStages.Connect:
                    switch (code)
                    {
                        case BrokerLogCodes.Attempt:
                        case BrokerLogCodes.Connected:
                        case BrokerLogCodes.NotRetryable:
                        case BrokerLogCodes.RetryExhausted:
                        case BrokerLogCodes.OpenException:
                        case BrokerLogCodes.ConnectException:
                        case BrokerLogCodes.CreateFailed:
                            return "app service connect";
                        default:
                            return "unknown";
                    }
                case BrokerLogStages.Hello:
                    switch (code)
                    {
                        case BrokerLogCodes.HelloReceived:
                        case BrokerLogCodes.HelloTimeout:
                            return "app service hello";
                        default:
                            return "unknown";
                    }
                case BrokerLogStages.Transport:
                    switch (code)
                    {
                        case BrokerLogCodes.TransportClosed:
                        case BrokerLogCodes.ClosedBeforeHello:
                        case BrokerLogCodes.WindowExited:
                        case BrokerLogCodes.ConnectFailed:
                            return "app service connection";
                        default:
                            return "unknown";
                    }
                case BrokerLogStages.Package:
                    switch (code)
                    {
                        case BrokerLogCodes.NoPackage:
                        case BrokerLogCodes.PackageOk:
                            return "package check";
                        default:
                            return "unknown";
                    }
                case BrokerLogStages.Lease:
                    switch (code)
                    {
                        case BrokerLogCodes.LeaseOwned:
                        case BrokerLogCodes.LeaseHeld:
                            return "single instance check";
                        default:
                            return "unknown";
                    }
                case BrokerLogStages.EngineStart:
                    switch (code)
                    {
                        case BrokerLogCodes.CreateOk:
                        case BrokerLogCodes.CreateFailed:
                        case BrokerLogCodes.StartOk:
                        case BrokerLogCodes.StartFailed:
                            return "engine start";
                        default:
                            return "unknown";
                    }
                case BrokerLogStages.ElevatedStart:
                    switch (code)
                    {
                        case BrokerLogCodes.ShellFailed:
                        case BrokerLogCodes.StartOk:
                        case BrokerLogCodes.StartFailed:
                        case BrokerLogCodes.CreateOk:
                            return "engine start";
                        default:
                            return "unknown";
                    }
                case BrokerLogStages.Main:
                    switch (code)
                    {
                        case BrokerLogCodes.Entry:
                        case BrokerLogCodes.BadArgs:
                        case BrokerLogCodes.ArgsIgnored:
                            return "broker start";
                        default:
                            return "unknown";
                    }
                case BrokerLogStages.Fatal:
                    switch (code)
                    {
                        case BrokerLogCodes.Unhandled:
                            return "broker start";
                        default:
                            return "unknown";
                    }
                case BrokerLogStages.Shutdown:
                    switch (code)
                    {
                        case BrokerLogCodes.ShutdownBegin:
                        case BrokerLogCodes.ShutdownEnd:
                            return "engine shutdown";
                        default:
                            return "unknown";
                    }
                case BrokerLogStages.Exit:
                    switch (code)
                    {
                        case BrokerLogCodes.ExitCode:
                            return "broker shutdown";
                        default:
                            return "unknown";
                    }
                default:
                    return "unknown";
            }
        }

        public static string CodePhrase(string code)
        {
            switch (code)
            {
                case BrokerLogCodes.Entry:
                    return "started";
                case BrokerLogCodes.BadArgs:
                    return "refused its arguments";
                case BrokerLogCodes.ArgsIgnored:
                    return "ignored its arguments";
                case BrokerLogCodes.NoPackage:
                    return "found no package";
                case BrokerLogCodes.PackageOk:
                    return "found the package";
                case BrokerLogCodes.LeaseOwned:
                    return "owns the instance";
                case BrokerLogCodes.LeaseHeld:
                    return "found another helper running";
                case BrokerLogCodes.CreateOk:
                    return "started the engine process";
                case BrokerLogCodes.CreateFailed:
                    return "could not start the engine process";
                case BrokerLogCodes.ShellFailed:
                    return "could not start the engine process";
                case BrokerLogCodes.StartOk:
                    return "started the engine";
                case BrokerLogCodes.StartFailed:
                    return "did not start the engine";
                case BrokerLogCodes.Attempt:
                    return "tried to connect";
                case BrokerLogCodes.Connected:
                    return "connected";
                case BrokerLogCodes.NotRetryable:
                    return "could not connect";
                case BrokerLogCodes.RetryExhausted:
                    return "could not connect in time";
                case BrokerLogCodes.OpenException:
                    return "connect failed";
                case BrokerLogCodes.ConnectException:
                    return "connect failed";
                case BrokerLogCodes.HelloReceived:
                    return "answered";
                case BrokerLogCodes.HelloTimeout:
                    return "did not answer in time";
                case BrokerLogCodes.TransportClosed:
                    return "the connection closed";
                case BrokerLogCodes.ClosedBeforeHello:
                    return "the connection closed before the window said hello";
                case BrokerLogCodes.WindowExited:
                    return "the window exited";
                case BrokerLogCodes.ConnectFailed:
                    return "could not connect";
                case BrokerLogCodes.ShutdownBegin:
                    return "stopping";
                case BrokerLogCodes.ShutdownEnd:
                    return "stopped";
                case BrokerLogCodes.ExitCode:
                    return "exited";
                case BrokerLogCodes.Unhandled:
                    return "stopped with an error";
                default:
                    return "unknown";
            }
        }

        // One plain line for the dashboard, for example:
        // The engine helper stopped at app service connect (status Unknown,
        // exit 4).
        public static string StopLine(BrokerLogSnapshot snapshot)
        {
            if (snapshot == null || snapshot.Lines.Count == 0)
            {
                return null;
            }
            BrokerLogEntry last = snapshot.Last;
            string phrase = last == null
                ? "unknown"
                : StageCodePhrase(last.Stage, last.Code);
            List<string> details = new List<string>();
            if (last != null && !string.IsNullOrEmpty(last.Status))
            {
                details.Add("status " + BrokerLogFormat.Status(last.Status));
            }
            if (snapshot.LastExit != null && snapshot.LastExit.Attempt.HasValue)
            {
                details.Add("exit " + BrokerLogFormat.Number(snapshot.LastExit.Attempt.Value));
            }
            StringBuilder text = new StringBuilder("The engine helper stopped at ");
            text.Append(phrase == "unknown" ? "an unknown stage" : phrase);
            if (details.Count > 0)
            {
                text.Append(" (");
                text.Append(string.Join(", ", details.ToArray()));
                text.Append(").");
            }
            else
            {
                text.Append(".");
            }
            return text.ToString();
        }
    }

    // The window reads the broker log through this seam. The UWP app uses
    // Windows.Storage; the checks use a fixed list. A read never throws at
    // the caller and never changes the broker.
    public interface IBrokerLogSource
    {
        BrokerLogSnapshot Read(int maxLines);
    }
}
