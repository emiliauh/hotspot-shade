using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.ServiceHost
{
    // Strict Windows path comparison for the installed service binary. The
    // value is compiled into the app, never named by a caller. The comparison
    // does not resolve reparse points; a future review must decide whether the
    // installer ACL and the SCM process id are enough for that residual case.
    public static class WindowsServicePathPolicy
    {
        public static bool TryNormalize(string path, out string normalized)
        {
            normalized = "";
            if (string.IsNullOrEmpty(path) || path.Length > EngineServiceTransportLimits.MaxServicePathLength)
            {
                return false;
            }

            string value = path.Trim();
            if (value.Length == 0)
            {
                return false;
            }
            if (value[0] == '"' || value[value.Length - 1] == '"')
            {
                if (value.Length < 3 || value[0] != '"' || value[value.Length - 1] != '"')
                {
                    return false;
                }
                value = value.Substring(1, value.Length - 2).Trim();
            }
            if (value.Length == 0)
            {
                return false;
            }
            for (int index = 0; index < value.Length; index++)
            {
                char character = value[index];
                if (character < ' ' || character == '\u007F' || character == '"')
                {
                    return false;
                }
            }

            // SCM may report a path with either separator. Windows treats both
            // as separators, so normalize before the alias checks.
            value = value.Replace('/', '\\');

            // The installed service binary is a local drive path. A UNC path
            // can name the same file through a share, so it is not proof of
            // the installed image.
            if (value.StartsWith("\\\\", StringComparison.Ordinal))
            {
                return false;
            }
            bool drive = value.Length >= 3
                && IsAsciiLetter(value[0])
                && value[1] == ':'
                && value[2] == '\\';
            if (!drive)
            {
                return false;
            }

            string prefix = char.ToUpperInvariant(value[0]).ToString() + ":\\";
            string rest = value.Substring(3);
            if (rest.Length == 0)
            {
                return false;
            }

            string[] parts = rest.Split('\\');
            List<string> clean = new List<string>();
            for (int index = 0; index < parts.Length; index++)
            {
                string part = parts[index];
                if (part.Length == 0)
                {
                    continue;
                }
                if (part == "." || part == "..")
                {
                    return false;
                }
                if (part[part.Length - 1] == '.' || part[part.Length - 1] == ' ')
                {
                    return false;
                }
                if (part.IndexOf(':') >= 0)
                {
                    return false;
                }
                clean.Add(part);
            }
            if (clean.Count == 0)
            {
                return false;
            }

            normalized = prefix + string.Join("\\", clean.ToArray());
            return true;
        }

        public static bool EqualsInstalled(string left, string right)
        {
            string normalizedLeft;
            string normalizedRight;
            if (!TryNormalize(left, out normalizedLeft) || !TryNormalize(right, out normalizedRight))
            {
                return false;
            }
            return string.Equals(normalizedLeft, normalizedRight, StringComparison.OrdinalIgnoreCase);
        }

        // QueryServiceConfig returns the service image command line, not just
        // its executable path. Extract the first token. The caller must compare
        // it with the separately trusted installed path; an unquoted path with
        // spaces therefore cannot match that installed path.
        public static bool TryScmExecutable(string commandLine, out string normalized)
        {
            normalized = "";
            if (string.IsNullOrEmpty(commandLine)
                || commandLine.Length > EngineServiceTransportLimits.MaxServicePathLength)
            {
                return false;
            }
            for (int index = 0; index < commandLine.Length; index++)
            {
                char value = commandLine[index];
                if ((value < ' ' && value != '\t') || value == '\u007F')
                {
                    return false;
                }
            }
            string command = commandLine.Trim(' ', '\t');
            if (command.Length == 0) return false;
            string image;
            if (command[0] == '"')
            {
                int close = command.IndexOf('"', 1);
                if (close <= 1 || (close + 1 < command.Length
                    && command[close + 1] != ' ' && command[close + 1] != '\t'))
                {
                    return false;
                }
                image = command.Substring(1, close - 1);
            }
            else
            {
                int end = command.IndexOfAny(new char[] { ' ', '\t' });
                image = end < 0 ? command : command.Substring(0, end);
            }
            // TryNormalize supports forgiving user-facing path input. An SCM
            // command line is evidence of the executed image, so whitespace
            // inside its first argument must not be silently stripped.
            if (!string.Equals(image, image.Trim(), StringComparison.Ordinal)) return false;
            // Windows may append .exe to an extensionless module name.
            // Require the explicit executable suffix so a matching string
            // identifies the same image the service manager will launch.
            if (!TryNormalize(image, out normalized)) return false;
            if (!normalized.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                normalized = "";
                return false;
            }
            return true;
        }

        private static bool IsAsciiLetter(char value)
        {
            return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z');
        }
    }

    // Rejects SIDs that cannot be the installing person. Numeric SID parsing
    // alone is not enough: Everyone, SYSTEM, service accounts, builtin groups,
    // integrity labels, and claim SIDs are valid numeric SIDs but not users.
    // A custom group SID is caught by the account-type lookup in the caller
    // policy.
    public static class EngineServiceSidPolicy
    {
        private static readonly HashSet<string> NonUserSids = BuildNonUserSids();
        private static readonly string[] NonUserPrefixes =
        {
            "S-1-5-32-",
            "S-1-5-80-",
            "S-1-5-64-",
            "S-1-5-65-",
            "S-1-5-90-",
            "S-1-16-",
            "S-1-18-"
        };

        public static bool IsWellKnownNonUserSid(string sid)
        {
            if (!EngineServiceBoundary.IsValidUserSid(sid))
            {
                return true;
            }
            string upper = sid.ToUpperInvariant();
            if (NonUserSids.Contains(upper))
            {
                return true;
            }
            for (int index = 0; index < NonUserPrefixes.Length; index++)
            {
                if (upper.StartsWith(NonUserPrefixes[index], StringComparison.Ordinal))
                {
                    return true;
                }
            }
            return false;
        }

        public static bool IsUsableInstalledUserSid(string sid)
        {
            // The core form check refuses authority-only values and most
            // well-known principals. The account-type lookup in the caller
            // policy is the positive SidTypeUser proof.
            return EngineServiceBoundary.IsAllowedPipeUserSid(sid)
                && !IsWellKnownNonUserSid(sid);
        }

        public static EngineServiceAccountType MapAccountType(int nativeValue)
        {
            switch (nativeValue)
            {
                case 1:
                    return EngineServiceAccountType.User;
                case 2:
                    return EngineServiceAccountType.Group;
                case 3:
                    return EngineServiceAccountType.Domain;
                case 4:
                    return EngineServiceAccountType.Alias;
                case 5:
                    return EngineServiceAccountType.WellKnownGroup;
                case 6:
                    return EngineServiceAccountType.DeletedAccount;
                case 7:
                    return EngineServiceAccountType.Invalid;
                case 9:
                    return EngineServiceAccountType.Computer;
                case 10:
                    return EngineServiceAccountType.Label;
                case 11:
                    return EngineServiceAccountType.LogonSession;
                default:
                    return EngineServiceAccountType.Unknown;
            }
        }

        private static HashSet<string> BuildNonUserSids()
        {
            HashSet<string> values = new HashSet<string>(StringComparer.Ordinal);
            values.Add("S-1-0-0");
            values.Add("S-1-1-0");
            values.Add("S-1-2-0");
            values.Add("S-1-2-1");
            values.Add("S-1-3-0");
            values.Add("S-1-3-1");
            values.Add("S-1-3-2");
            values.Add("S-1-3-3");
            values.Add("S-1-3-4");
            values.Add("S-1-5-2");
            values.Add("S-1-5-4");
            values.Add("S-1-5-6");
            values.Add("S-1-5-7");
            values.Add("S-1-5-10");
            values.Add("S-1-5-11");
            values.Add("S-1-5-13");
            values.Add("S-1-5-14");
            values.Add("S-1-5-15");
            values.Add("S-1-5-17");
            values.Add("S-1-5-18");
            values.Add("S-1-5-19");
            values.Add("S-1-5-20");
            values.Add("S-1-5-113");
            values.Add("S-1-5-114");
            return values;
        }
    }

    // The caller policy wrapper for the service host. It adds the SID
    // prefilter and a positive account-type check before the existing core
    // policy compares the exact token user SID, the session, and the
    // impersonation level.
    public sealed class WindowsServiceCallerPolicy
    {
        private readonly EngineServiceCallerPolicy inner;
        private readonly IEngineServiceAccountTypeInspector accountTypes;
        private readonly TimeSpan accountTypeTimeout;

        public WindowsServiceCallerPolicy(
            string installedUserSid,
            IEngineServiceAccountTypeInspector accountTypes,
            TimeSpan accountTypeTimeout)
        {
            if (!EngineServiceSidPolicy.IsUsableInstalledUserSid(installedUserSid))
            {
                throw new ArgumentException(
                    "the installed account must be a user SID",
                    "installedUserSid");
            }
            if (accountTypes == null)
            {
                throw new ArgumentNullException("accountTypes");
            }
            if (accountTypeTimeout <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException("accountTypeTimeout");
            }
            this.inner = new EngineServiceCallerPolicy(installedUserSid);
            this.accountTypes = accountTypes;
            this.accountTypeTimeout = accountTypeTimeout;
        }

        public string InstalledUserSid
        {
            get { return inner.InstalledUserSid; }
        }

        public async Task<EngineServiceCallerVerdict> EvaluateAsync(
            EngineServiceCallerIdentity identity,
            CancellationToken cancellationToken)
        {
            if (identity == null)
            {
                return EngineServiceCallerVerdict.Deny(
                    EngineProtocol.ErrorCodes.BoundaryAuthFailed,
                    EngineServiceEventCodes.CallerMissing);
            }
            if (!EngineServiceSidPolicy.IsUsableInstalledUserSid(identity.UserSid))
            {
                return EngineServiceCallerVerdict.Deny(
                    EngineProtocol.ErrorCodes.BoundaryAuthFailed,
                    EngineServiceEventCodes.CallerSidRejected);
            }

            EngineServiceAccountTypeResult account;
            try
            {
                Task<EngineServiceAccountTypeResult> task =
                    accountTypes.InspectAsync(identity.UserSid, cancellationToken);
                if (task == null)
                {
                    return EngineServiceCallerVerdict.Deny(
                        EngineProtocol.ErrorCodes.BoundaryAuthFailed,
                        EngineServiceEventCodes.CallerAccountTypeFailed);
                }
                account = await WithTimeout(task, accountTypeTimeout, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return EngineServiceCallerVerdict.Deny(
                    EngineProtocol.ErrorCodes.BoundaryAuthFailed,
                    EngineServiceEventCodes.CallerAccountTypeFailed);
            }
            catch (Exception)
            {
                return EngineServiceCallerVerdict.Deny(
                    EngineProtocol.ErrorCodes.BoundaryAuthFailed,
                    EngineServiceEventCodes.CallerAccountTypeFailed);
            }

            if (account == null || !account.Ok)
            {
                return EngineServiceCallerVerdict.Deny(
                    EngineProtocol.ErrorCodes.BoundaryAuthFailed,
                    EngineServiceEventCodes.CallerAccountTypeFailed);
            }
            if (account.Type != EngineServiceAccountType.User)
            {
                return EngineServiceCallerVerdict.Deny(
                    EngineProtocol.ErrorCodes.BoundaryAuthFailed,
                    EngineServiceEventCodes.CallerAccountTypeNotUser);
            }
            return inner.Evaluate(identity);
        }

        public static string SameUserStatement()
        {
            return EngineServiceCallerPolicy.SameUserStatement();
        }

        private static async Task<EngineServiceAccountTypeResult> WithTimeout(
            Task<EngineServiceAccountTypeResult> task,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            if (task.IsCompleted)
            {
                return await task.ConfigureAwait(false);
            }
            Task completed = await Task.WhenAny(
                task,
                Task.Delay(timeout, cancellationToken)).ConfigureAwait(false);
            if (completed != task)
            {
                throw new TimeoutException();
            }
            return await task.ConfigureAwait(false);
        }
    }
}
