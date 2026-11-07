using System;

namespace HotspotShade.WinUI2.Core.Engine.Service
{
    // The impersonation level that the pipe server can read from the
    // connection token. These values match the Win32
    // SECURITY_IMPERSONATION_LEVEL constants exactly:
    // SecurityAnonymous is 0, SecurityIdentification is 1,
    // SecurityImpersonation is 2, and SecurityDelegation is 3.
    // Identification is enough to identify the caller. The server never needs
    // Impersonation to act as the person. None and Unreadable are the same
    // non-Win32 value (-1). They are the fail-closed result when the token
    // query does not complete. None is kept as a source-compatible alias for
    // the existing host code; do not use either value as a Win32 level.
    public enum EngineServiceImpersonationLevel
    {
        Unreadable = -1,
        None = -1,
        Anonymous = 0,
        Identification = 1,
        Impersonation = 2,
        Delegation = 3
    }

    // One caller identity read from the connection token after one unparsed
    // bounded frame. A process id is diagnostics only and is not part of this
    // record, because a process id can be reused.
    public sealed class EngineServiceCallerIdentity
    {
        public EngineServiceCallerIdentity(
            string userSid,
            int sessionId,
            EngineServiceImpersonationLevel impersonation,
            string packageFamilyName,
            bool elevated)
        {
            UserSid = userSid ?? "";
            SessionId = sessionId;
            Impersonation = impersonation;
            PackageFamilyName = packageFamilyName ?? "";
            Elevated = elevated;
        }

        public string UserSid { get; private set; }

        public int SessionId { get; private set; }

        public EngineServiceImpersonationLevel Impersonation { get; private set; }

        // Empty when no package identity is required or the token has none.
        public string PackageFamilyName { get; private set; }

        // Recorded for visibility. It never changes the authorization answer:
        // an elevated process of the same account is still the same principal.
        public bool Elevated { get; private set; }
    }

    public sealed class EngineServiceCallerVerdict
    {
        private EngineServiceCallerVerdict(bool allowed, string code, string eventCode)
        {
            Allowed = allowed;
            Code = code ?? "";
            EventCode = eventCode ?? "";
        }

        public bool Allowed { get; private set; }

        // One fixed protocol code. Empty when the caller is allowed.
        public string Code { get; private set; }

        // One fixed event token for the service event log. Empty when the
        // caller is allowed.
        public string EventCode { get; private set; }

        public static EngineServiceCallerVerdict Allow(string eventCode)
        {
            return new EngineServiceCallerVerdict(true, "", eventCode);
        }

        public static EngineServiceCallerVerdict Deny(string code, string eventCode)
        {
            return new EngineServiceCallerVerdict(false, code, eventCode);
        }
    }

    // The caller policy for the authenticated boundary.
    //
    // The policy authorizes the installing account, not one process of that
    // account. Any process running as the person can pass. That is the honest
    // same-user result: the boundary protects the privileged engine from other
    // accounts and from remote clients, not from the person's own processes.
    //
    // An optional package family name adds defense in depth when the app is
    // packaged. A full-trust packaged app has no AppContainer token, so package
    // identity is not required by default and never replaces the account check.
    public sealed class EngineServiceCallerPolicy
    {
        private readonly string installedUserSid;
        private readonly string requiredPackageFamilyName;

        public EngineServiceCallerPolicy(string installedUserSid)
            : this(installedUserSid, null)
        {
        }

        public EngineServiceCallerPolicy(string installedUserSid, string requiredPackageFamilyName)
        {
            // This is a form check, not an account-type proof. A custom group
            // SID can have the same S-1-5-21 form as a user. The future host
            // must resolve the SID with LookupAccountSid and require
            // SidTypeUser before it constructs this policy.
            if (!EngineServiceBoundary.IsAllowedPipeUserSid(installedUserSid))
            {
                throw new ArgumentException("invalid installed user SID", "installedUserSid");
            }
            this.installedUserSid = installedUserSid;
            this.requiredPackageFamilyName = requiredPackageFamilyName ?? "";
        }

        public string InstalledUserSid
        {
            get { return installedUserSid; }
        }

        public bool RequiresPackageFamily
        {
            get { return requiredPackageFamilyName.Length > 0; }
        }

        public EngineServiceCallerVerdict Evaluate(EngineServiceCallerIdentity identity)
        {
            if (identity == null)
            {
                return EngineServiceCallerVerdict.Deny(
                    EngineProtocol.ErrorCodes.BoundaryAuthFailed,
                    "caller_missing");
            }
            if (!EngineServiceBoundary.IsAllowedPipeUserSid(identity.UserSid)
                || !string.Equals(identity.UserSid, installedUserSid, StringComparison.OrdinalIgnoreCase))
            {
                return EngineServiceCallerVerdict.Deny(
                    EngineProtocol.ErrorCodes.BoundaryAuthFailed,
                    "caller_account_mismatch");
            }
            if (identity.Impersonation == EngineServiceImpersonationLevel.Unreadable)
            {
                return EngineServiceCallerVerdict.Deny(
                    EngineProtocol.ErrorCodes.BoundaryAuthFailed,
                    "caller_impersonation_unreadable");
            }
            if (!Enum.IsDefined(typeof(EngineServiceImpersonationLevel), identity.Impersonation))
            {
                return EngineServiceCallerVerdict.Deny(
                    EngineProtocol.ErrorCodes.BoundaryAuthFailed,
                    "caller_impersonation_invalid");
            }
            if (identity.Impersonation < EngineServiceImpersonationLevel.Identification)
            {
                return EngineServiceCallerVerdict.Deny(
                    EngineProtocol.ErrorCodes.BoundaryAuthFailed,
                    "caller_impersonation_too_low");
            }
            if (identity.SessionId <= 0)
            {
                return EngineServiceCallerVerdict.Deny(
                    EngineProtocol.ErrorCodes.BoundaryAuthFailed,
                    "caller_session_invalid");
            }
            if (requiredPackageFamilyName.Length > 0
                && !string.Equals(identity.PackageFamilyName, requiredPackageFamilyName, StringComparison.Ordinal))
            {
                return EngineServiceCallerVerdict.Deny(
                    EngineProtocol.ErrorCodes.BoundaryAuthFailed,
                    "caller_package_mismatch");
            }

            return EngineServiceCallerVerdict.Allow(
                identity.Elevated ? "elevated_caller" : "same_user_caller");
        }

        // The Win32 token query returns an integer. A host must pass it
        // through this mapping instead of casting it into the enum, so a new
        // or unknown value can never compare as Identification or above.
        public static bool TryMapWin32ImpersonationLevel(
            int value,
            out EngineServiceImpersonationLevel level)
        {
            switch (value)
            {
                case 0:
                    level = EngineServiceImpersonationLevel.Anonymous;
                    return true;
                case 1:
                    level = EngineServiceImpersonationLevel.Identification;
                    return true;
                case 2:
                    level = EngineServiceImpersonationLevel.Impersonation;
                    return true;
                case 3:
                    level = EngineServiceImpersonationLevel.Delegation;
                    return true;
                default:
                    level = EngineServiceImpersonationLevel.Unreadable;
                    return false;
            }
        }

        public static string SameUserStatement()
        {
            return "Any process running as the installing account can control the tunnel and can hold the single session. "
                + "Holding the session can deny the app a connection. "
                + "The boundary does not block a same-user process. "
                + "It cannot read the bearer secret, the source credential, or the identity key through the service protocol. "
                + "Remote clients are rejected by PIPE_REJECT_REMOTE_CLIENTS. "
                + "Other accounts are denied by the pipe DACL and the caller policy. "
                + "The boundary protects other accounts and remote clients, not one process of the account from another.";
        }
    }

    // The result of the identity step after ImpersonateNamedPipeClient. A
    // failed RevertToSelf is not a caller denial that can be retried. The
    // connection must close, no frame may be parsed or answered, and the
    // normal stop must run from a thread that never impersonated.
    public sealed class EngineServiceRevertDecision
    {
        private EngineServiceRevertDecision(
            bool allowed,
            bool closeConnection,
            bool stopTunnel,
            string code,
            string eventCode)
        {
            Allowed = allowed;
            CloseConnection = closeConnection;
            StopTunnel = stopTunnel;
            Code = code ?? "";
            EventCode = eventCode ?? "";
        }

        public bool Allowed { get; private set; }

        public bool CloseConnection { get; private set; }

        public bool StopTunnel { get; private set; }

        public string Code { get; private set; }

        public string EventCode { get; private set; }

        public static EngineServiceRevertDecision AfterRevert(bool reverted)
        {
            if (!reverted)
            {
                return new EngineServiceRevertDecision(
                    false,
                    true,
                    true,
                    EngineProtocol.ErrorCodes.EngineUnavailable,
                    "revert_failed");
            }
            return new EngineServiceRevertDecision(true, false, false, "", "");
        }

        public static string RuleText()
        {
            return "If RevertToSelf fails, close the connection, parse no frame, send no reply, "
                + "and run the stop from a thread that never impersonated.";
        }
    }
}
