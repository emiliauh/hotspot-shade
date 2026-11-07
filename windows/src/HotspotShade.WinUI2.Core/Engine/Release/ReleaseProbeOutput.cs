using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace HotspotShade.WinUI2.Core.Engine.Release
{
    // Fixed codes for a release probe result. A code never holds a path, an
    // address, a token, or text from the engine.
    public static class ReleaseProbeCodes
    {
        public const string Ok = "";
        public const string MissingOutput = "missing_output";
        public const string OutputTooLarge = "output_too_large";
        public const string UnexpectedLine = "unexpected_line";
        public const string DuplicateLine = "duplicate_line";
        public const string InvalidAdministrator = "invalid_administrator";
        public const string InvalidInterface = "invalid_interface";
        public const string InvalidTtl = "invalid_ttl";
        public const string InvalidAudit = "invalid_audit";
        public const string MissingPrivilegeLine = "missing_privilege_line";
        public const string InvalidVersion = "invalid_version";
        public const string InvalidPath = "invalid_path";
        public const string EngineMissing = "engine_missing";
        public const string StartFailed = "start_failed";
        public const string Timeout = "timeout";
        public const string ExitNonZero = "exit_nonzero";
        public const string UnsupportedCommand = "unsupported_command";
    }

    // The only two engine commands that a release probe may run. Both are
    // read-only. No tunnel, GUI, pairing, or source device command is allowed
    // through this seam.
    public static class ReleaseProbeCommandPolicy
    {
        public const string VersionArgument = "--version";
        public const string ProbeArgument = "probe";

        public static bool IsAllowed(string argument)
        {
            return string.Equals(argument, VersionArgument, StringComparison.Ordinal)
                || string.Equals(argument, ProbeArgument, StringComparison.Ordinal);
        }
    }

    public enum ReleaseProbeSeverity
    {
        Pass,
        Warn,
        Fail
    }

    // The facts that the read-only Windows engine probe prints. The engine
    // creates one UDP handle, sets TTL 65, and reads the value back. It creates
    // no adapter and changes no route.
    public sealed class EngineProbeFacts
    {
        internal EngineProbeFacts(
            bool administrator,
            string interfaceName,
            int interfaceIndex,
            int udpTtl,
            int auditFailures)
        {
            Administrator = administrator;
            InterfaceName = interfaceName ?? "";
            InterfaceIndex = interfaceIndex;
            UdpTtl = udpTtl;
            AuditFailures = auditFailures;
        }

        public bool Administrator { get; private set; }

        public string InterfaceName { get; private set; }

        public int InterfaceIndex { get; private set; }

        public int UdpTtl { get; private set; }

        public int AuditFailures { get; private set; }
    }

    public sealed class EngineProbeParseResult
    {
        private EngineProbeParseResult(bool ok, string code, EngineProbeFacts facts)
        {
            Ok = ok;
            Code = code ?? "";
            Facts = facts;
        }

        public bool Ok { get; private set; }

        // One fixed code. It is empty for a parsed result.
        public string Code { get; private set; }

        public EngineProbeFacts Facts { get; private set; }

        public static EngineProbeParseResult Success(EngineProbeFacts facts)
        {
            if (facts == null)
            {
                return Failure(ReleaseProbeCodes.MissingOutput);
            }
            return new EngineProbeParseResult(true, ReleaseProbeCodes.Ok, facts);
        }

        public static EngineProbeParseResult Failure(string code)
        {
            return new EngineProbeParseResult(
                false,
                string.IsNullOrEmpty(code) ? ReleaseProbeCodes.MissingOutput : code,
                null);
        }
    }

    // The strict parser for `hotspotshade probe` output on Windows. It accepts
    // the documented five lines in any order, with LF or CRLF. It refuses a
    // missing, duplicated, or unrecognized line, so a format change stops the
    // evidence instead of being read as a pass.
    public static class EngineProbeOutput
    {
        public const string AdministratorPrefix = "administrator=";
        public const string InterfacePrefix = "default IPv4 interface: ";
        public const string UdpTtlPrefix = "UDP TTL: ";
        public const string AuditPrefix = "TTL audit failures: ";
        public const string PrivilegeSuffix = "Administrator rights.";

        // A probe answer is short. A larger answer is not a probe answer.
        public const int MaximumTextLength = 8192;

        // The interface line ends with " (index N)". The name may hold spaces,
        // so the last marker is the boundary.
        private const string IndexMarker = " (index ";
        private const int MaximumInterfaceNameLength = 128;
        private const int MaximumInterfaceIndex = 1000000;

        public static EngineProbeParseResult Parse(string text)
        {
            if (text == null)
            {
                return EngineProbeParseResult.Failure(ReleaseProbeCodes.MissingOutput);
            }
            if (text.Length > MaximumTextLength)
            {
                return EngineProbeParseResult.Failure(ReleaseProbeCodes.OutputTooLarge);
            }

            bool hasAdministrator = false;
            bool administrator = false;
            bool hasInterface = false;
            string interfaceName = "";
            int interfaceIndex = 0;
            bool hasTtl = false;
            int udpTtl = 0;
            bool hasAudit = false;
            int audit = 0;
            bool hasPrivilege = false;

            string[] lines = text.Split('\n');
            for (int index = 0; index < lines.Length; index++)
            {
                string line = lines[index].TrimEnd('\r').Trim();
                if (line.Length == 0)
                {
                    continue;
                }

                if (line.StartsWith(AdministratorPrefix, StringComparison.Ordinal))
                {
                    if (hasAdministrator)
                    {
                        return EngineProbeParseResult.Failure(ReleaseProbeCodes.DuplicateLine);
                    }
                    string value = line.Substring(AdministratorPrefix.Length).Trim();
                    if (string.Equals(value, "true", StringComparison.Ordinal))
                    {
                        administrator = true;
                    }
                    else if (string.Equals(value, "false", StringComparison.Ordinal))
                    {
                        administrator = false;
                    }
                    else
                    {
                        return EngineProbeParseResult.Failure(ReleaseProbeCodes.InvalidAdministrator);
                    }
                    hasAdministrator = true;
                }
                else if (line.StartsWith(InterfacePrefix, StringComparison.Ordinal))
                {
                    if (hasInterface)
                    {
                        return EngineProbeParseResult.Failure(ReleaseProbeCodes.DuplicateLine);
                    }
                    string value = line.Substring(InterfacePrefix.Length);
                    if (!TryParseInterface(value, out interfaceName, out interfaceIndex))
                    {
                        return EngineProbeParseResult.Failure(ReleaseProbeCodes.InvalidInterface);
                    }
                    hasInterface = true;
                }
                else if (line.StartsWith(UdpTtlPrefix, StringComparison.Ordinal))
                {
                    if (hasTtl)
                    {
                        return EngineProbeParseResult.Failure(ReleaseProbeCodes.DuplicateLine);
                    }
                    if (!TryParseByte(line.Substring(UdpTtlPrefix.Length), out udpTtl))
                    {
                        return EngineProbeParseResult.Failure(ReleaseProbeCodes.InvalidTtl);
                    }
                    hasTtl = true;
                }
                else if (line.StartsWith(AuditPrefix, StringComparison.Ordinal))
                {
                    if (hasAudit)
                    {
                        return EngineProbeParseResult.Failure(ReleaseProbeCodes.DuplicateLine);
                    }
                    if (!TryParseCount(line.Substring(AuditPrefix.Length), out audit))
                    {
                        return EngineProbeParseResult.Failure(ReleaseProbeCodes.InvalidAudit);
                    }
                    hasAudit = true;
                }
                else if (line.EndsWith(PrivilegeSuffix, StringComparison.Ordinal))
                {
                    if (hasPrivilege)
                    {
                        return EngineProbeParseResult.Failure(ReleaseProbeCodes.DuplicateLine);
                    }
                    hasPrivilege = true;
                }
                else
                {
                    // Do not echo the line. It can hold text from an unrelated
                    // program that happened to sit at the engine path.
                    return EngineProbeParseResult.Failure(ReleaseProbeCodes.UnexpectedLine);
                }
            }

            if (!hasAdministrator || !hasInterface || !hasTtl || !hasAudit)
            {
                return EngineProbeParseResult.Failure(ReleaseProbeCodes.MissingOutput);
            }
            if (!hasPrivilege)
            {
                return EngineProbeParseResult.Failure(ReleaseProbeCodes.MissingPrivilegeLine);
            }
            return EngineProbeParseResult.Success(new EngineProbeFacts(
                administrator,
                interfaceName,
                interfaceIndex,
                udpTtl,
                audit));
        }

        private static bool TryParseInterface(string value, out string name, out int index)
        {
            name = "";
            index = 0;
            string text = value.Trim();
            int marker = text.LastIndexOf(IndexMarker, StringComparison.Ordinal);
            if (marker <= 0 || !text.EndsWith(")", StringComparison.Ordinal))
            {
                return false;
            }
            string parsedName = text.Substring(0, marker).Trim();
            if (parsedName.Length == 0 || parsedName.Length > MaximumInterfaceNameLength)
            {
                return false;
            }
            for (int position = 0; position < parsedName.Length; position++)
            {
                char character = parsedName[position];
                if (character < 0x20 || character == 0x7F)
                {
                    return false;
                }
            }
            int numberStart = marker + IndexMarker.Length;
            int numberLength = text.Length - numberStart - 1;
            if (numberLength <= 0)
            {
                return false;
            }
            int parsedIndex;
            if (!int.TryParse(
                text.Substring(numberStart, numberLength),
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out parsedIndex))
            {
                return false;
            }
            if (parsedIndex < 1 || parsedIndex > MaximumInterfaceIndex)
            {
                return false;
            }
            name = parsedName;
            index = parsedIndex;
            return true;
        }

        private static bool TryParseByte(string value, out int result)
        {
            result = 0;
            int parsed;
            if (!int.TryParse(
                value.Trim(),
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out parsed))
            {
                return false;
            }
            if (parsed < 0 || parsed > 255)
            {
                return false;
            }
            result = parsed;
            return true;
        }

        private static bool TryParseCount(string value, out int result)
        {
            result = 0;
            int parsed;
            if (!int.TryParse(
                value.Trim(),
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out parsed))
            {
                return false;
            }
            if (parsed < 0 || parsed > 1000000)
            {
                return false;
            }
            result = parsed;
            return true;
        }
    }

    // The strict parser for `hotspotshade --version`. One non-empty line, the
    // fixed program word, and a short version token. No version text is
    // invented when the answer is not understood.
    public static class EngineVersionOutput
    {
        public const string Prefix = "hotspotshade ";
        public const int MaximumTextLength = 256;
        public const int MaximumVersionLength = 64;

        public static bool TryParse(string text, out string version)
        {
            version = "";
            if (text == null || text.Length > MaximumTextLength)
            {
                return false;
            }

            string only = null;
            string[] lines = text.Split('\n');
            for (int index = 0; index < lines.Length; index++)
            {
                string line = lines[index].TrimEnd('\r').Trim();
                if (line.Length == 0)
                {
                    continue;
                }
                if (only != null)
                {
                    return false;
                }
                only = line;
            }
            if (only == null || !only.StartsWith(Prefix, StringComparison.Ordinal))
            {
                return false;
            }

            string value = only.Substring(Prefix.Length).Trim();
            if (value.Length == 0 || value.Length > MaximumVersionLength)
            {
                return false;
            }
            for (int index = 0; index < value.Length; index++)
            {
                char character = value[index];
                bool digit = character >= '0' && character <= '9';
                bool letter = (character >= 'a' && character <= 'z')
                    || (character >= 'A' && character <= 'Z');
                if (!digit && !letter && character != '.' && character != '-' && character != '+')
                {
                    return false;
                }
            }
            version = value;
            return true;
        }
    }

    // One fixed result from one read-only engine command. The output is held
    // for the parser. A failure carries a fixed code and no output.
    public sealed class ReleaseProbeCommandResult
    {
        private ReleaseProbeCommandResult(bool ok, string code, int exitCode, string output, string error)
        {
            Ok = ok;
            Code = code ?? "";
            ExitCode = exitCode;
            Output = output ?? "";
            Error = error ?? "";
        }

        public bool Ok { get; private set; }

        public string Code { get; private set; }

        public int ExitCode { get; private set; }

        public string Output { get; private set; }

        // True only when the child wrote something to its error stream. The
        // text itself is never kept in a report.
        public string Error { get; private set; }

        public static ReleaseProbeCommandResult Success(int exitCode, string output, string error)
        {
            return new ReleaseProbeCommandResult(true, ReleaseProbeCodes.Ok, exitCode, output, error);
        }

        public static ReleaseProbeCommandResult Failure(string code, int exitCode)
        {
            return new ReleaseProbeCommandResult(
                false,
                string.IsNullOrEmpty(code) ? ReleaseProbeCodes.StartFailed : code,
                exitCode,
                "",
                "");
        }
    }
}
